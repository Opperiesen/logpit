//! `logpit ship`: reads the systemd journal and/or log files and sends them to a LogPit server.
//!
//! Nothing is lost when the server is down or the shipper is restarted: every batch is first
//! written to a spool directory, the read position is saved only after that, and a batch stays
//! spooled until the server accepts it. Delivery is at-least-once: a crash between spooling a
//! batch and saving the position can send a few entries twice.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Notify, mpsc};

use crate::webhook::{Webhook, WebhookFormat};

/// A batch is written out when it reaches this many bytes.
const MAX_BATCH_BYTES: usize = 1 << 20;
/// A line longer than this is cut (and a partial line this long is flushed as a line).
const MAX_LINE_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const READ_CHUNK: usize = 1 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub const USAGE: &str = "usage: logpit ship --url <http(s)://logpit:8080> (--journal | --file <path>...) [options]

  --url URL              LogPit server (the path /ingest is added when missing)
  --token-file PATH      file holding the write token (or LOGPIT_SHIP_TOKEN / LOGPIT_SHIP_TOKEN_FILE)
  --journal              follow the systemd journal (journalctl -o json)
  --journal-from-start   ship the existing journal too (default: only new entries)
  --journal-arg ARG      extra journalctl argument, e.g. -u (repeatable, then the value as another --journal-arg)
  --journalctl PATH      journalctl binary (default: journalctl)
  --file PATH            follow a log file, surviving rotation (repeatable)
  --from-start           read existing content of files seen for the first time (default: only new lines)
  --app NAME             application name for file lines (default: the file name)
  --host NAME            host name to send (default: the machine's)
  --spool DIR            where batches and read positions are kept (default: ./logpit-spool)
  --spool-max-mb N       drop the oldest batches beyond this size while the server is unreachable (default 256)
  --batch-lines N        lines per batch (default 500)
  --batch-ms N           longest wait before sending a partial batch (default 1000)";

#[derive(Debug, Clone)]
pub struct ShipConfig {
    pub url: String,
    pub token: Option<String>,
    pub journal: bool,
    pub journal_from_start: bool,
    pub journal_args: Vec<String>,
    pub journalctl: String,
    pub files: Vec<PathBuf>,
    pub from_start: bool,
    pub app: Option<String>,
    pub host: String,
    pub spool: PathBuf,
    pub spool_max_bytes: u64,
    pub batch_lines: usize,
    pub batch_ms: u64,
    pub retry_initial_ms: u64,
    pub retry_max_ms: u64,
}

fn machine_host() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

impl ShipConfig {
    /// Parses the arguments after `logpit ship`. `env` reads environment variables.
    pub fn from_args(
        args: &[String],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let mut cfg = ShipConfig {
            url: String::new(),
            token: None,
            journal: false,
            journal_from_start: false,
            journal_args: Vec::new(),
            journalctl: "journalctl".into(),
            files: Vec::new(),
            from_start: false,
            app: None,
            host: String::new(),
            spool: PathBuf::from("logpit-spool"),
            spool_max_bytes: 256 * 1024 * 1024,
            batch_lines: 500,
            batch_ms: 1000,
            retry_initial_ms: 1000,
            retry_max_ms: 30_000,
        };
        let mut token_file: Option<PathBuf> = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| -> anyhow::Result<String> {
                it.next()
                    .cloned()
                    .with_context(|| format!("{name} needs a value"))
            };
            let number = |name: &str, v: String| -> anyhow::Result<u64> {
                v.parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .with_context(|| format!("{name} must be a positive whole number"))
            };
            match arg.as_str() {
                "--url" => cfg.url = value("--url")?,
                "--token-file" => token_file = Some(PathBuf::from(value("--token-file")?)),
                "--journal" => cfg.journal = true,
                "--journal-from-start" => cfg.journal_from_start = true,
                "--journal-arg" => cfg.journal_args.push(value("--journal-arg")?),
                "--journalctl" => cfg.journalctl = value("--journalctl")?,
                "--file" => cfg.files.push(PathBuf::from(value("--file")?)),
                "--from-start" => cfg.from_start = true,
                "--app" => cfg.app = Some(value("--app")?),
                "--host" => cfg.host = value("--host")?,
                "--spool" => cfg.spool = PathBuf::from(value("--spool")?),
                "--spool-max-mb" => {
                    cfg.spool_max_bytes =
                        number("--spool-max-mb", value("--spool-max-mb")?)? * 1024 * 1024
                }
                "--batch-lines" => {
                    cfg.batch_lines = number("--batch-lines", value("--batch-lines")?)? as usize
                }
                "--batch-ms" => cfg.batch_ms = number("--batch-ms", value("--batch-ms")?)?,
                "--retry-ms" => {
                    cfg.retry_initial_ms = number("--retry-ms", value("--retry-ms")?)?;
                    cfg.retry_max_ms = cfg
                        .retry_initial_ms
                        .max(cfg.retry_max_ms.min(cfg.retry_initial_ms * 30));
                }
                other => bail!("unknown option {other:?}\n{USAGE}"),
            }
        }
        if cfg.url.is_empty() {
            bail!("--url is required\n{USAGE}");
        }
        if !cfg.journal && cfg.files.is_empty() {
            bail!("nothing to ship: give --journal and/or --file\n{USAGE}");
        }
        // The token never goes on the command line (it would show in `ps`).
        cfg.token = match (
            token_file,
            env("LOGPIT_SHIP_TOKEN"),
            env("LOGPIT_SHIP_TOKEN_FILE"),
        ) {
            (Some(path), _, _) => Some(read_token(&path)?),
            (None, Some(t), _) => Some(t),
            (None, None, Some(path)) => Some(read_token(Path::new(&path))?),
            (None, None, None) => None,
        };
        if cfg.host.is_empty() {
            cfg.host = machine_host();
        }
        Ok(cfg)
    }

    /// The URL batches are posted to.
    pub fn ingest_url(&self) -> String {
        let base = self.url.trim_end_matches('/');
        let after_scheme = base.split_once("://").map_or(base, |(_, rest)| rest);
        if after_scheme.contains('/') {
            base.to_string()
        } else {
            format!("{base}/ingest")
        }
    }

    fn webhook(&self) -> anyhow::Result<Webhook> {
        let headers: Vec<String> = self
            .token
            .iter()
            .map(|t| format!("Authorization: Bearer {t}"))
            .collect();
        Ok(
            Webhook::new(&self.ingest_url(), WebhookFormat::Json, &headers)?
                .with_timeout(REQUEST_TIMEOUT),
        )
    }
}

pub(crate) fn read_token(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the token file {}", path.display()))?;
    let token = text.trim_end_matches(['\r', '\n']).to_string();
    if token.is_empty() {
        bail!("the token file {} is empty", path.display());
    }
    Ok(token)
}

// ---- positions ----------------------------------------------------------------------------

/// Where a shipped line was read from, so reading can resume after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pos {
    Journal(String),
    File {
        path: String,
        inode: u64,
        offset: u64,
    },
}

pub struct Item {
    /// One NDJSON line ready to be sent.
    pub line: String,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    pub inode: u64,
    pub offset: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub journal_cursor: Option<String>,
    pub files: HashMap<String, FileState>,
}

impl State {
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable state file {}: {e}", path.display());
                State::default()
            }),
            Err(_) => State::default(),
        }
    }

    /// Writes the state atomically (a crash leaves the old or the new file, never half of one).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string(self).unwrap_or_default().as_bytes())?;
        f.sync_all()?;
        std::fs::rename(tmp, path)
    }

    pub fn apply(&mut self, pos: &Pos) {
        match pos {
            Pos::Journal(cursor) => self.journal_cursor = Some(cursor.clone()),
            Pos::File {
                path,
                inode,
                offset,
            } => {
                self.files.insert(
                    path.clone(),
                    FileState {
                        inode: *inode,
                        offset: *offset,
                    },
                );
            }
        }
    }
}

// ---- spool --------------------------------------------------------------------------------

/// Batches waiting for the server, one file each, oldest first.
pub struct Spool {
    dir: PathBuf,
    next: u64,
}

impl Spool {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let next = Self::batches(dir)
            .last()
            .and_then(|p| {
                p.file_stem()?
                    .to_str()?
                    .strip_prefix("b-")?
                    .parse::<u64>()
                    .ok()
            })
            .map_or(0, |n| n + 1);
        Ok(Self {
            dir: dir.to_path_buf(),
            next,
        })
    }

    /// The batch files in `dir`, oldest first.
    pub fn batches(dir: &Path) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "ndjson")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("b-"))
            })
            .collect();
        files.sort();
        files
    }

    /// Stores a batch durably (written, synced, then renamed into place).
    pub fn write(&mut self, body: &str) -> std::io::Result<PathBuf> {
        let name = format!("b-{:016}.ndjson", self.next);
        self.next += 1;
        let (tmp, path) = (self.dir.join(format!("{name}.tmp")), self.dir.join(&name));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(tmp, &path)?;
        Ok(path)
    }

    pub fn total_bytes(&self) -> u64 {
        Self::batches(&self.dir)
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    /// Removes the oldest batches until the spool is within `max_bytes`; returns how many went.
    pub fn enforce_cap(&self, max_bytes: u64) -> usize {
        let mut removed = 0;
        let mut total = self.total_bytes();
        for path in Self::batches(&self.dir) {
            if total <= max_bytes {
                break;
            }
            let size = std::fs::metadata(&path).map_or(0, |m| m.len());
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
                removed += 1;
            }
        }
        removed
    }
}

// ---- following files ----------------------------------------------------------------------

/// Follows one log file like `tail -F`: survives rotation (rename and recreate) and truncation,
/// and resumes from a saved position.
pub struct Tailer {
    path: PathBuf,
    file: Option<std::fs::File>,
    inode: u64,
    /// Where the next read starts.
    read_pos: u64,
    /// Bytes read that do not yet end in a newline.
    partial: Vec<u8>,
    saved: Option<FileState>,
    from_start: bool,
}

#[cfg(unix)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}
#[cfg(not(unix))]
fn inode_of(_: &std::fs::Metadata) -> u64 {
    0
}

fn clip_line(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_LINE_BYTES);
    String::from_utf8_lossy(&bytes[..end])
        .trim_end_matches('\r')
        .to_string()
}

impl Tailer {
    pub fn new(path: PathBuf, saved: Option<FileState>, from_start: bool) -> Self {
        Self {
            path,
            file: None,
            inode: 0,
            read_pos: 0,
            partial: Vec::new(),
            saved,
            from_start,
        }
    }

    /// Reads whatever the file gained since the last call and returns its complete lines, each with
    /// the offset just after it.
    pub fn poll(&mut self) -> std::io::Result<Vec<(String, u64, u64)>> {
        let mut out = Vec::new();
        let on_disk = std::fs::metadata(&self.path).ok();

        // Rotated: the path now names another file. Finish the old one first.
        if let (Some(_), Some(meta)) = (&self.file, &on_disk)
            && inode_of(meta) != self.inode
        {
            self.read_available(&mut out)?;
            self.flush_partial(&mut out);
            self.file = None;
        }
        if self.file.is_none() {
            let Some(meta) = &on_disk else {
                // Missing now: if it shows up later it was created after the shipper started, so
                // everything in it is new.
                self.from_start = true;
                return Ok(out);
            };
            let file = std::fs::File::open(&self.path)?;
            self.inode = inode_of(meta);
            self.read_pos = match self.saved.take() {
                // Resume where the previous run stopped, if it is the same file.
                Some(s) if s.inode == self.inode && s.offset <= meta.len() => s.offset,
                Some(_) => 0,
                None if self.from_start => 0,
                None => meta.len(),
            };
            // After the first open every file seen later (a rotation) is read from its start.
            self.from_start = true;
            self.partial.clear();
            self.file = Some(file);
        }
        if let Some(meta) = &on_disk {
            // Truncated in place.
            if meta.len() < self.read_pos {
                self.read_pos = 0;
                self.partial.clear();
            }
        }
        self.read_available(&mut out)?;
        Ok(out)
    }

    fn read_available(&mut self, out: &mut Vec<(String, u64, u64)>) -> std::io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        loop {
            file.seek(SeekFrom::Start(self.read_pos))?;
            let mut buf = vec![0u8; READ_CHUNK];
            let n = file.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            self.read_pos += n as u64;
            self.partial.extend_from_slice(&buf[..n]);
            // Complete lines: everything up to each newline.
            let mut start = 0;
            while let Some(i) = self.partial[start..].iter().position(|b| *b == b'\n') {
                let line = clip_line(&self.partial[start..start + i]);
                start += i + 1;
                let offset = self.read_pos - (self.partial.len() - start) as u64;
                if !line.is_empty() {
                    out.push((line, offset, self.inode));
                }
            }
            self.partial.drain(..start);
            // A "line" that never ends: send it in pieces rather than hold it forever.
            while self.partial.len() >= MAX_LINE_BYTES {
                let piece: Vec<u8> = self.partial.drain(..MAX_LINE_BYTES).collect();
                let offset = self.read_pos - self.partial.len() as u64;
                out.push((clip_line(&piece), offset, self.inode));
            }
        }
    }

    /// At the end of a rotated file, a last line without a newline is still a line.
    fn flush_partial(&mut self, out: &mut Vec<(String, u64, u64)>) {
        if !self.partial.is_empty() {
            let line = clip_line(&self.partial);
            self.partial.clear();
            if !line.is_empty() {
                out.push((line, self.read_pos, self.inode));
            }
        }
    }
}

// ---- sources ------------------------------------------------------------------------------

async fn follow_files(
    cfg: Arc<ShipConfig>,
    state: HashMap<String, FileState>,
    tx: mpsc::Sender<Item>,
) {
    let mut tailers: Vec<Tailer> = cfg
        .files
        .iter()
        .map(|p| {
            Tailer::new(
                p.clone(),
                state.get(&p.to_string_lossy().into_owned()).cloned(),
                cfg.from_start,
            )
        })
        .collect();
    let app_of = |p: &Path| {
        cfg.app.clone().unwrap_or_else(|| {
            p.file_name()
                .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned())
        })
    };
    loop {
        for t in &mut tailers {
            let lines = match t.poll() {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("cannot read {}: {e}", t.path.display());
                    continue;
                }
            };
            let app = app_of(&t.path);
            for (line, offset, inode) in lines {
                let body = serde_json::json!({
                    "host": cfg.host,
                    "app": app,
                    "message": line,
                    "ts": crate::ingest::now_ms(),
                })
                .to_string();
                let pos = Pos::File {
                    path: t.path.to_string_lossy().into_owned(),
                    inode,
                    offset,
                };
                if tx.send(Item { line: body, pos }).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The systemd cursor in a journal entry, if it has one.
fn journal_cursor(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("__CURSOR")?
        .as_str()
        .map(str::to_string)
}

async fn follow_journal(cfg: Arc<ShipConfig>, mut cursor: Option<String>, tx: mpsc::Sender<Item>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut cmd = tokio::process::Command::new(&cfg.journalctl);
        cmd.args(["-o", "json", "--no-pager", "--follow"]);
        match &cursor {
            Some(c) => {
                cmd.arg(format!("--after-cursor={c}"));
            }
            None if !cfg.journal_from_start => {
                cmd.arg("--lines=0");
            }
            None => {}
        }
        cmd.args(&cfg.journal_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(stdout) = child.stdout.take() {
                    let mut lines = BufReader::new(stdout).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        backoff = Duration::from_secs(1);
                        let Some(c) = journal_cursor(&line) else {
                            continue;
                        };
                        cursor = Some(c.clone());
                        if tx
                            .send(Item {
                                line,
                                pos: Pos::Journal(c),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                let status = child.wait().await;
                tracing::warn!(
                    "{} exited ({status:?}); restarting in {backoff:?}",
                    cfg.journalctl
                );
            }
            Err(e) => tracing::warn!(
                "cannot run {}: {e}; retrying in {backoff:?}",
                cfg.journalctl
            ),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

// ---- delivery -----------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing is waiting.
    Empty,
    Sent,
    /// The server refused the batch for good (it is moved to `rejected/`).
    Rejected(u16),
    /// Worth trying again later.
    Retry(String),
}

/// Statuses that mean the batch itself is the problem, so retrying cannot help.
fn is_permanent_rejection(status: u16) -> bool {
    matches!(status, 400 | 413 | 415 | 422)
}

/// Sends the oldest spooled batch and settles its fate.
pub async fn deliver_oldest(hook: &Webhook, dir: &Path) -> Outcome {
    let Some(path) = Spool::batches(dir).into_iter().next() else {
        return Outcome::Empty;
    };
    let body = match std::fs::read(&path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => return Outcome::Retry(format!("cannot read {}: {e}", path.display())),
    };
    match hook.post_body("application/x-ndjson", body).await {
        Ok(status) if (200..300).contains(&status) => {
            let _ = std::fs::remove_file(&path);
            Outcome::Sent
        }
        Ok(status) if is_permanent_rejection(status) => {
            let rejected = dir.join("rejected");
            let _ = std::fs::create_dir_all(&rejected);
            if let Some(name) = path.file_name() {
                let _ = std::fs::rename(&path, rejected.join(name));
            }
            Outcome::Rejected(status)
        }
        Ok(401 | 403) => Outcome::Retry("the server refused the token (HTTP 401/403)".into()),
        Ok(status) => Outcome::Retry(format!("the server answered HTTP {status}")),
        Err(e) => Outcome::Retry(format!("{e:#}")),
    }
}

async fn deliver_forever(cfg: Arc<ShipConfig>, hook: Webhook, wake: Arc<Notify>) {
    let mut wait = Duration::from_millis(cfg.retry_initial_ms);
    let mut sent = 0u64;
    loop {
        match deliver_oldest(&hook, &cfg.spool).await {
            Outcome::Sent => {
                sent += 1;
                wait = Duration::from_millis(cfg.retry_initial_ms);
                if sent == 1 || sent.is_multiple_of(100) {
                    tracing::info!("{sent} batches delivered");
                }
            }
            Outcome::Empty => {
                // Wake when a batch is spooled, and anyway now and then.
                let _ = tokio::time::timeout(Duration::from_secs(5), wake.notified()).await;
            }
            Outcome::Rejected(status) => {
                tracing::error!(
                    "batch refused with HTTP {status}; kept in {}",
                    cfg.spool.join("rejected").display()
                );
            }
            Outcome::Retry(why) => {
                tracing::warn!("delivery failed ({why}); retrying in {wait:?}");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_millis(cfg.retry_max_ms));
            }
        }
    }
}

// ---- the whole thing ----------------------------------------------------------------------

/// Runs the shipper until interrupted.
pub async fn run(cfg: ShipConfig) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let hook = cfg.webhook()?;
    let mut spool = Spool::open(&cfg.spool)
        .with_context(|| format!("cannot use the spool directory {}", cfg.spool.display()))?;
    let state_path = cfg.spool.join("state.json");
    let mut state = State::load(&state_path);
    let leftover = Spool::batches(&cfg.spool).len();
    tracing::info!(
        "shipping to {} (spool {}{})",
        cfg.ingest_url().split('?').next().unwrap_or(""),
        cfg.spool.display(),
        if leftover > 0 {
            format!(", {leftover} batches left from an earlier run will be sent first")
        } else {
            String::new()
        }
    );

    let wake = Arc::new(Notify::new());
    tokio::spawn(deliver_forever(cfg.clone(), hook, wake.clone()));

    let (tx, mut rx) = mpsc::channel::<Item>(1024);
    if cfg.journal {
        tokio::spawn(follow_journal(
            cfg.clone(),
            state.journal_cursor.clone(),
            tx.clone(),
        ));
    }
    if !cfg.files.is_empty() {
        tokio::spawn(follow_files(cfg.clone(), state.files.clone(), tx.clone()));
    }
    drop(tx);

    let mut body = String::new();
    let mut lines = 0usize;
    let mut last_pos: Vec<Pos> = Vec::new();
    let flush = |body: &mut String,
                 lines: &mut usize,
                 last_pos: &mut Vec<Pos>,
                 spool: &mut Spool,
                 state: &mut State| {
        if *lines == 0 {
            return;
        }
        match spool.write(body) {
            Ok(_) => {
                // Only now that the batch is safe on disk may the read positions move on.
                for p in last_pos.drain(..) {
                    state.apply(&p);
                }
                body.clear();
                *lines = 0;
                if let Err(e) = state.save(&state_path) {
                    tracing::warn!("cannot save the read positions: {e}");
                }
                let dropped = spool.enforce_cap(cfg.spool_max_bytes);
                if dropped > 0 {
                    tracing::warn!("spool over its limit: dropped the {dropped} oldest batches");
                }
                wake.notify_one();
            }
            // Keep the batch (and its positions) in memory and try again at the next flush.
            Err(e) => tracing::error!("cannot write a batch to the spool, will retry: {e}"),
        }
    };

    let mut tick = tokio::time::interval(Duration::from_millis(cfg.batch_ms));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        tokio::select! {
            item = rx.recv() => match item {
                Some(item) => {
                    body.push_str(&item.line);
                    body.push('\n');
                    lines += 1;
                    last_pos.push(item.pos);
                    if lines >= cfg.batch_lines || body.len() >= MAX_BATCH_BYTES {
                        flush(&mut body, &mut lines, &mut last_pos, &mut spool, &mut state);
                    }
                }
                None => break,
            },
            _ = tick.tick() => flush(&mut body, &mut lines, &mut last_pos, &mut spool, &mut state),
            _ = &mut shutdown => {
                tracing::info!("stopping");
                break;
            }
        }
    }
    flush(&mut body, &mut lines, &mut last_pos, &mut spool, &mut state);
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("logpit-ship-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn arguments_and_defaults() {
        let c = ShipConfig::from_args(
            &args(&[
                "--url",
                "http://logpit:8080",
                "--file",
                "/var/log/a.log",
                "--file",
                "/var/log/b.log",
                "--host",
                "box",
            ]),
            &no_env,
        )
        .unwrap();
        assert_eq!(
            (c.batch_lines, c.batch_ms, c.spool_max_bytes),
            (500, 1000, 256 << 20)
        );
        assert_eq!(c.files.len(), 2);
        assert!(!c.journal && !c.from_start && c.token.is_none());
        assert_eq!(c.host, "box");
        assert_eq!(c.ingest_url(), "http://logpit:8080/ingest");
        let with_path = ShipConfig::from_args(
            &args(&["--url", "https://logpit.example/api/ingest/", "--journal"]),
            &no_env,
        )
        .unwrap();
        assert_eq!(with_path.ingest_url(), "https://logpit.example/api/ingest");
        let c = ShipConfig::from_args(
            &args(&[
                "--url",
                "http://h",
                "--journal",
                "--journal-arg",
                "-u",
                "--journal-arg",
                "sshd",
                "--spool",
                "/s",
                "--batch-lines",
                "10",
                "--spool-max-mb",
                "2",
            ]),
            &no_env,
        )
        .unwrap();
        assert_eq!(
            (c.journal_args.as_slice(), c.batch_lines, c.spool_max_bytes),
            (&["-u".to_string(), "sshd".to_string()][..], 10, 2 << 20)
        );
        assert!(!c.host.is_empty(), "the host defaults to the machine's");

        for bad in [
            &["--file", "x"][..],
            &["--url", "http://h"],
            &["--url", "http://h", "--file"],
            &["--url", "http://h", "--file", "x", "--batch-lines", "0"],
            &["--url", "http://h", "--file", "x", "--batch-ms", "soon"],
            &["--url", "http://h", "--file", "x", "--bogus"],
        ] {
            assert!(
                ShipConfig::from_args(&args(bad), &no_env).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_token_comes_from_a_file_or_the_environment_never_the_command_line() {
        let dir = tmp("token");
        let file = dir.join("token");
        fs::write(&file, "s3cret\n").unwrap();
        let base = ["--url", "http://h", "--journal"];
        let with_file = ShipConfig::from_args(
            &args(&[&base[..], &["--token-file", file.to_str().unwrap()]].concat()),
            &no_env,
        )
        .unwrap();
        assert_eq!(with_file.token.as_deref(), Some("s3cret"));
        let env = |k: &str| (k == "LOGPIT_SHIP_TOKEN").then(|| "from-env".to_string());
        assert_eq!(
            ShipConfig::from_args(&args(&base), &env)
                .unwrap()
                .token
                .as_deref(),
            Some("from-env")
        );
        let env_file =
            |k: &str| (k == "LOGPIT_SHIP_TOKEN_FILE").then(|| file.to_str().unwrap().to_string());
        assert_eq!(
            ShipConfig::from_args(&args(&base), &env_file)
                .unwrap()
                .token
                .as_deref(),
            Some("s3cret")
        );
        // A `--token` option does not exist, so a secret cannot end up in `ps`.
        assert!(
            ShipConfig::from_args(&args(&[&base[..], &["--token", "x"]].concat()), &no_env)
                .is_err()
        );
        // Unreadable or empty token files are errors, not silent no-auth.
        fs::write(&file, "\n").unwrap();
        assert!(
            ShipConfig::from_args(
                &args(&[&base[..], &["--token-file", file.to_str().unwrap()]].concat()),
                &no_env
            )
            .is_err()
        );
        assert!(
            ShipConfig::from_args(
                &args(&[&base[..], &["--token-file", "/nonexistent/t"]].concat()),
                &no_env
            )
            .is_err()
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn state_round_trips_and_a_corrupt_file_is_ignored() {
        let dir = tmp("state");
        let path = dir.join("state.json");
        assert_eq!(State::load(&path), State::default());
        let mut s = State::default();
        s.apply(&Pos::Journal("s=abc".into()));
        s.apply(&Pos::File {
            path: "/var/log/a".into(),
            inode: 7,
            offset: 42,
        });
        s.apply(&Pos::File {
            path: "/var/log/a".into(),
            inode: 7,
            offset: 99,
        });
        s.save(&path).unwrap();
        assert_eq!(State::load(&path), s);
        assert_eq!(
            s.files["/var/log/a"],
            FileState {
                inode: 7,
                offset: 99
            },
            "the latest position wins"
        );
        fs::write(&path, "{ not json").unwrap();
        assert_eq!(State::load(&path), State::default());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn spool_keeps_order_survives_reopening_and_enforces_its_cap() {
        let dir = tmp("spool");
        let mut s = Spool::open(&dir).unwrap();
        let first = s.write("one\n").unwrap();
        s.write("two\n").unwrap();
        s.write("three\n").unwrap();
        assert_eq!(Spool::batches(&dir).len(), 3);
        assert_eq!(fs::read_to_string(&first).unwrap(), "one\n");
        // A leftover temp file from a crash is not a batch.
        fs::write(dir.join("b-0000000000000099.ndjson.tmp"), "half").unwrap();
        assert_eq!(Spool::batches(&dir).len(), 3);
        // Reopening continues the numbering, so order is preserved across runs.
        let mut again = Spool::open(&dir).unwrap();
        let later = again.write("four\n").unwrap();
        assert!(later > Spool::batches(&dir)[2], "{later:?}");
        assert_eq!(Spool::batches(&dir).len(), 4);
        assert_eq!(again.total_bytes(), 4 + 4 + 6 + 5);
        // Over the cap: the oldest go first.
        assert_eq!(again.enforce_cap(11), 2);
        let left: Vec<String> = Spool::batches(&dir)
            .iter()
            .map(|p| fs::read_to_string(p).unwrap())
            .collect();
        assert_eq!(left, ["three\n", "four\n"]);
        assert_eq!(again.enforce_cap(u64::MAX), 0);
        fs::remove_dir_all(dir).ok();
    }

    fn lines(t: &mut Tailer) -> Vec<String> {
        t.poll().unwrap().into_iter().map(|(l, _, _)| l).collect()
    }

    #[test]
    fn tailer_reads_new_lines_and_holds_back_partial_ones() {
        let dir = tmp("tail");
        let path = dir.join("app.log");
        fs::write(&path, "old line\n").unwrap();
        // By default only what is appended after the start is shipped.
        let mut t = Tailer::new(path.clone(), None, false);
        assert!(lines(&mut t).is_empty());
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"first\nsecond\r\npart").unwrap();
        assert_eq!(
            lines(&mut t),
            ["first", "second"],
            "CRLF is trimmed and a partial line waits"
        );
        f.write_all(b"ial\n\n\nlast\n").unwrap();
        let got = t.poll().unwrap();
        assert_eq!(
            got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(),
            ["partial", "last"],
            "blank lines are skipped"
        );
        // The offset after a line is where reading resumes: the end of the file here.
        assert_eq!(got.last().unwrap().1, fs::metadata(&path).unwrap().len());
        assert!(lines(&mut t).is_empty(), "nothing new");
        // A file that does not exist yet is fine, and is read from its start once it appears.
        let mut late = Tailer::new(dir.join("later.log"), None, false);
        assert!(lines(&mut late).is_empty());
        fs::write(dir.join("later.log"), "hello\n").unwrap();
        assert_eq!(lines(&mut late), ["hello"]);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn tailer_from_start_resume_rotation_and_truncation() {
        let dir = tmp("rotate");
        let path = dir.join("app.log");
        fs::write(&path, "a\nb\n").unwrap();
        let mut t = Tailer::new(path.clone(), None, true);
        let got = t.poll().unwrap();
        assert_eq!(
            got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(),
            ["a", "b"],
            "from_start reads existing content"
        );
        let (inode, offset) = (got[1].2, got[1].1);
        assert_eq!(offset, 4);

        // Resuming from the saved position skips what was shipped, and sees what came after.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"c\n")
            .unwrap();
        let mut resumed = Tailer::new(path.clone(), Some(FileState { inode, offset }), false);
        assert_eq!(lines(&mut resumed), ["c"]);
        // A saved position for a different file (it was rotated while we were down) starts over.
        let mut other = Tailer::new(
            path.clone(),
            Some(FileState {
                inode: inode + 1000,
                offset: 3,
            }),
            false,
        );
        assert_eq!(lines(&mut other), ["a", "b", "c"]);

        // Rotation: the old file is renamed, a new one created. The old file's last lines are
        // read before moving on to the new one, which is read from its start.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"tail of old\nno newline")
            .unwrap();
        fs::rename(&path, dir.join("app.log.1")).unwrap();
        fs::write(&path, "new 1\nnew 2\n").unwrap();
        assert_eq!(
            lines(&mut t),
            ["c", "tail of old", "no newline", "new 1", "new 2"]
        );

        // Truncation in place (copytruncate): once the file is seen shorter than the position
        // read, reading restarts from the top. (A file truncated and refilled beyond the old
        // position between two checks, 250 ms apart, cannot be told from an appended one.)
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"long enough line\n")
            .unwrap();
        assert_eq!(lines(&mut t), ["long enough line"]);
        fs::write(&path, "x\n").unwrap();
        assert_eq!(lines(&mut t), ["x"]);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"y\n")
            .unwrap();
        assert_eq!(lines(&mut t), ["y"]);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_line_that_never_ends_is_sent_in_pieces() {
        let dir = tmp("long");
        let path = dir.join("big.log");
        fs::write(&path, "").unwrap();
        let mut t = Tailer::new(path.clone(), None, true);
        fs::write(&path, "x".repeat(MAX_LINE_BYTES * 2 + 10)).unwrap();
        let got = lines(&mut t);
        assert_eq!(
            got.len(),
            2,
            "two full pieces; the 10 bytes left wait for their newline"
        );
        assert!(got.iter().all(|l| l.len() == MAX_LINE_BYTES));
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert_eq!(
            lines(&mut t),
            ["x".repeat(10)],
            "the rest follows once the line ends"
        );
        fs::remove_dir_all(dir).ok();
    }

    /// A server answering each connection with the next status; it records every request.
    async fn server(
        statuses: Vec<&'static str>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut seen = Vec::new();
            for status in statuses {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut buf = vec![0u8; 65_536];
                loop {
                    let n = s.read(&mut buf).await.unwrap();
                    data.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&data).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let want: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: ")?.trim().parse().ok())
                            .unwrap_or(0);
                        if body.len() >= want || n == 0 {
                            break;
                        }
                    } else if n == 0 {
                        break;
                    }
                }
                seen.push(String::from_utf8_lossy(&data).into_owned());
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            }
            seen
        });
        (addr, task)
    }

    fn hook(addr: std::net::SocketAddr) -> Webhook {
        Webhook::new(
            &format!("http://{addr}/ingest"),
            WebhookFormat::Json,
            &["Authorization: Bearer tok".to_string()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn each_response_status_has_its_own_fate_for_the_batch() {
        let dir = tmp("deliver");
        let mut spool = Spool::open(&dir).unwrap();
        spool.write("{\"message\":\"a\"}\n").unwrap();
        spool.write("{\"message\":\"b\"}\n").unwrap();
        let (addr, srv) = server(vec![
            "200 OK",
            "500 Internal Server Error",
            "401 Unauthorized",
            "503 Service Unavailable",
            "400 Bad Request",
        ])
        .await;
        let h = hook(addr);

        assert_eq!(deliver_oldest(&h, &dir).await, Outcome::Sent);
        assert_eq!(
            Spool::batches(&dir).len(),
            1,
            "an accepted batch is deleted"
        );
        // Server trouble and a refused token: the batch stays and is retried later.
        for expect in ["HTTP 500", "token", "HTTP 503"] {
            match deliver_oldest(&h, &dir).await {
                Outcome::Retry(why) => assert!(why.contains(expect), "{why}"),
                other => panic!("expected a retry, got {other:?}"),
            }
            assert_eq!(Spool::batches(&dir).len(), 1);
        }
        // A batch the server calls invalid can never succeed: it is set aside, not retried forever.
        assert_eq!(deliver_oldest(&h, &dir).await, Outcome::Rejected(400));
        assert!(Spool::batches(&dir).is_empty());
        assert_eq!(fs::read_dir(dir.join("rejected")).unwrap().count(), 1);
        assert_eq!(deliver_oldest(&h, &dir).await, Outcome::Empty);

        let seen = srv.await.unwrap();
        assert!(seen[0].starts_with("POST /ingest HTTP/1.1\r\n"));
        assert!(
            seen[0].contains("Authorization: Bearer tok\r\n")
                && seen[0].contains("Content-Type: application/x-ndjson\r\n")
        );
        assert!(seen[0].ends_with("{\"message\":\"a\"}\n"));
        fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn an_unreachable_server_is_a_retry_not_a_loss() {
        let dir = tmp("down");
        Spool::open(&dir).unwrap().write("x\n").unwrap();
        // Nothing listens on this port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(matches!(
            deliver_oldest(&hook(addr), &dir).await,
            Outcome::Retry(_)
        ));
        assert_eq!(Spool::batches(&dir).len(), 1);
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_journal_is_followed_and_resumed_after_the_last_cursor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("journal");
        // A fake journalctl: records its arguments, prints two entries, then exits.
        let script = dir.join("journalctl");
        let log = dir.join("args.log");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> {}\n\
                 echo '{{\"MESSAGE\":\"one\",\"__CURSOR\":\"c1\"}}'\n\
                 echo '{{\"MESSAGE\":\"two\",\"__CURSOR\":\"c2\"}}'\n\
                 echo 'not json at all'\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = ShipConfig::from_args(
            &args(&[
                "--url",
                "http://h",
                "--journal",
                "--journalctl",
                script.to_str().unwrap(),
                "--journal-arg",
                "-u",
                "--journal-arg",
                "sshd",
            ]),
            &no_env,
        )
        .unwrap();
        cfg.host = "h".into();
        let (tx, mut rx) = mpsc::channel(16);
        let task = tokio::spawn(follow_journal(Arc::new(cfg), None, tx));
        let mut got = Vec::new();
        for _ in 0..4 {
            let item = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            got.push(item.pos);
        }
        task.abort();
        assert_eq!(got[0], Pos::Journal("c1".into()));
        assert_eq!(got[1], Pos::Journal("c2".into()));
        // The script exited, so the shipper started it again, this time after the last cursor.
        let calls: Vec<String> = fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(
            calls[0], "-o json --no-pager --follow --lines=0 -u sshd",
            "first run: only new entries"
        );
        assert_eq!(
            calls[1], "-o json --no-pager --follow --after-cursor=c2 -u sshd",
            "restart: resume after c2"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn end_to_end_ship_survive_an_outage_and_a_restart() {
        let dir = tmp("e2e");
        let log = dir.join("app.log");
        fs::write(&log, "").unwrap();
        let spool = dir.join("spool");
        // The server is down at first: grab a free port and keep it closed.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let mk = || {
            let mut c = ShipConfig::from_args(
                &args(&[
                    "--url",
                    &format!("http://{addr}"),
                    "--file",
                    log.to_str().unwrap(),
                    "--from-start",
                    "--spool",
                    spool.to_str().unwrap(),
                    "--host",
                    "box",
                    "--batch-ms",
                    "30",
                    "--retry-ms",
                    "40",
                ]),
                &no_env,
            )
            .unwrap();
            c.token = Some("tok".into());
            c
        };
        let first = tokio::spawn(run(mk()));
        fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"during outage 1\nduring outage 2\n")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            !Spool::batches(&spool).is_empty(),
            "batches wait in the spool while the server is down"
        );
        first.abort(); // the shipper is killed while batches are still waiting

        // Restart, with the server now up: waiting batches go first, then new lines.
        let listener = TcpListener::bind(addr).await.unwrap();
        let received = tokio::spawn(async move {
            let mut bodies = Vec::new();
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 65_536];
                let n = s.read(&mut buf).await.unwrap();
                bodies.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
            bodies
        });
        let second = tokio::spawn(run(mk()));
        tokio::time::sleep(Duration::from_millis(400)).await;
        fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"after restart\n")
            .unwrap();
        let bodies = tokio::time::timeout(Duration::from_secs(10), received)
            .await
            .unwrap()
            .unwrap();
        second.abort();
        let all = bodies.join("\n");
        for expected in [
            "during outage 1",
            "during outage 2",
            "after restart",
            "\"host\":\"box\"",
            "\"app\":\"app.log\"",
            "Authorization: Bearer tok",
        ] {
            assert!(all.contains(expected), "missing {expected:?} in {all}");
        }
        // Nothing was sent twice, and what was delivered is gone from the spool.
        assert_eq!(all.matches("during outage 1").count(), 1);
        assert!(
            State::load(&spool.join("state.json"))
                .files
                .contains_key(log.to_str().unwrap())
        );
        fs::remove_dir_all(dir).ok();
    }
}
