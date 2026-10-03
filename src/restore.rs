//! `logpit restore`: loads archived entries (the gzip files written by the cold archive, or any
//! NDJSON in `/ingest` format) into a running LogPit through `POST /ingest`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};

use crate::webhook::{Webhook, WebhookFormat};

pub const USAGE: &str = "usage: logpit restore --url <http(s)://logpit:8080> [options] <file or directory>...

Reads LogPit archive files (logpit-YYYY-MM-DD.ndjson.gz) or plain NDJSON, directories being searched
recursively, and sends the entries to a LogPit server. Use a scratch instance (retention off) or the
entries will be purged again by the server's own retention.

  --url URL              LogPit server (the path /ingest is added when missing)
  --token-file PATH      file holding a write token (or LOGPIT_RESTORE_TOKEN / LOGPIT_RESTORE_TOKEN_FILE)
  --from YYYY-MM-DD      only archive files of this UTC day and later
  --to YYYY-MM-DD        only archive files of this UTC day and earlier
  --batch-lines N        entries per request (default 1000)
  --dry-run              count what would be sent, send nothing";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
/// Largest plain NDJSON file read whole.
const MAX_PLAIN_FILE: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RestoreConfig {
    pub url: String,
    pub token: Option<String>,
    pub paths: Vec<PathBuf>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub batch_lines: usize,
    pub dry_run: bool,
}

fn valid_day(s: &str) -> bool {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

impl RestoreConfig {
    pub fn from_args(
        args: &[String],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let mut cfg = RestoreConfig {
            url: String::new(),
            token: None,
            paths: Vec::new(),
            from: None,
            to: None,
            batch_lines: 1000,
            dry_run: false,
        };
        let mut token_file = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| -> anyhow::Result<String> {
                it.next()
                    .cloned()
                    .with_context(|| format!("{name} needs a value"))
            };
            match arg.as_str() {
                "--url" => cfg.url = value("--url")?,
                "--token-file" => token_file = Some(PathBuf::from(value("--token-file")?)),
                "--from" | "--to" => {
                    let day = value(arg)?;
                    if !valid_day(&day) {
                        bail!("{arg} must be a day like 2026-10-03");
                    }
                    if arg == "--from" {
                        cfg.from = Some(day);
                    } else {
                        cfg.to = Some(day);
                    }
                }
                "--batch-lines" => {
                    cfg.batch_lines = value("--batch-lines")?
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=10_000).contains(n))
                        .context("--batch-lines must be between 1 and 10000")?;
                }
                "--dry-run" => cfg.dry_run = true,
                other if other.starts_with("--") => bail!("unknown option {other:?}\n{USAGE}"),
                path => cfg.paths.push(PathBuf::from(path)),
            }
        }
        if cfg.url.is_empty() && !cfg.dry_run {
            bail!("--url is required\n{USAGE}");
        }
        if cfg.paths.is_empty() {
            bail!("give at least one archive file or directory\n{USAGE}");
        }
        cfg.token = match (
            token_file,
            env("LOGPIT_RESTORE_TOKEN"),
            env("LOGPIT_RESTORE_TOKEN_FILE"),
        ) {
            (Some(path), _, _) => Some(crate::shipper::read_token(&path)?),
            (None, Some(t), _) => Some(t),
            (None, None, Some(path)) => Some(crate::shipper::read_token(Path::new(&path))?),
            (None, None, None) => None,
        };
        Ok(cfg)
    }

    fn ingest_url(&self) -> String {
        let base = self.url.trim_end_matches('/');
        let after_scheme = base.split_once("://").map_or(base, |(_, rest)| rest);
        if after_scheme.contains('/') {
            base.to_string()
        } else {
            format!("{base}/ingest")
        }
    }
}

/// The UTC day in an archive file name, `logpit-YYYY-MM-DD.ndjson[.gz]`.
fn file_day(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let day = name.strip_prefix("logpit-")?.get(..10)?;
    valid_day(day).then(|| day.to_string())
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if meta.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .with_context(|| format!("cannot list {}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for e in entries {
            collect(&e, out)?;
        }
    } else if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".ndjson.gz") || n.ends_with(".ndjson") || n.ends_with(".gz"))
    {
        out.push(path.to_path_buf());
    }
    Ok(())
}

/// The files to restore, in name order, within `from..=to` where the name carries a day. A file
/// given explicitly is taken whatever its name.
pub fn plan(cfg: &RestoreConfig) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for p in &cfg.paths {
        if std::fs::metadata(p).is_ok_and(|m| m.is_file()) {
            files.push(p.clone());
        } else {
            collect(p, &mut files)?;
        }
    }
    files.retain(|f| match file_day(f) {
        Some(day) => {
            cfg.from.as_ref().is_none_or(|from| day >= *from)
                && cfg.to.as_ref().is_none_or(|to| day <= *to)
        }
        None => cfg.from.is_none() && cfg.to.is_none(),
    });
    Ok(files)
}

/// The NDJSON text of a file, one chunk at a time (one gzip member each; a plain file is one chunk).
pub fn chunks(path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_PLAIN_FILE {
        bail!("{} is larger than {MAX_PLAIN_FILE} bytes", path.display());
    }
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if crate::inflate::looks_like_gzip(&data) {
        crate::archive::split_members(&data)
            .with_context(|| format!("{}", path.display()))?
            .into_iter()
            .map(|m| crate::archive::read_member(m).with_context(|| format!("{}", path.display())))
            .collect()
    } else {
        Ok(vec![data])
    }
}

#[derive(Debug)]
pub struct Summary {
    pub files: usize,
    pub entries: u64,
    pub bad_lines: u64,
}

async fn post(hook: &Webhook, batch: &str) -> anyhow::Result<()> {
    let mut attempt = 0;
    loop {
        let result = hook
            .post_body("application/x-ndjson", batch.to_string())
            .await;
        let why = match result {
            Ok(status) if (200..300).contains(&status) => return Ok(()),
            Ok(status) if status == 408 || status == 429 || status >= 500 => {
                format!("HTTP {status}")
            }
            Ok(401) | Ok(403) => bail!("the server refused the token (use a write token)"),
            Ok(status) => bail!("the server answered HTTP {status}"),
            Err(e) => format!("{e:#}"),
        };
        if attempt >= RETRY_DELAYS.len() {
            bail!("giving up after {} attempts ({why})", attempt + 1);
        }
        eprintln!("restore: {why}, retrying");
        tokio::time::sleep(RETRY_DELAYS[attempt]).await;
        attempt += 1;
    }
}

/// Sends every file of the plan (or only counts, with `--dry-run`).
pub async fn run(cfg: RestoreConfig) -> anyhow::Result<Summary> {
    let files = plan(&cfg)?;
    if files.is_empty() {
        bail!("no archive file found in the given paths for that range");
    }
    let hook = if cfg.dry_run {
        None
    } else {
        let headers: Vec<String> = cfg
            .token
            .iter()
            .map(|t| format!("Authorization: Bearer {t}"))
            .collect();
        Some(
            Webhook::new(&cfg.ingest_url(), WebhookFormat::Json, &headers)?
                .with_timeout(REQUEST_TIMEOUT),
        )
    };
    let mut summary = Summary {
        files: 0,
        entries: 0,
        bad_lines: 0,
    };
    for file in &files {
        let mut sent_here = 0u64;
        for chunk in chunks(file)? {
            let text = String::from_utf8_lossy(&chunk);
            let mut batch = String::new();
            let mut n = 0;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if serde_json::from_str::<serde_json::Value>(line).is_err() {
                    summary.bad_lines += 1;
                    continue;
                }
                batch.push_str(line);
                batch.push('\n');
                n += 1;
                if n == cfg.batch_lines {
                    flush(&hook, &mut batch, n).await?;
                    sent_here += n as u64;
                    n = 0;
                }
            }
            if n > 0 {
                flush(&hook, &mut batch, n).await?;
                sent_here += n as u64;
            }
        }
        summary.files += 1;
        summary.entries += sent_here;
        eprintln!("restore: {} ({sent_here} entries)", file.display());
    }
    Ok(summary)
}

async fn flush(hook: &Option<Webhook>, batch: &mut String, _n: usize) -> anyhow::Result<()> {
    if let Some(hook) = hook {
        post(hook, batch).await?;
    }
    batch.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::archive::{Archiver, gzip_member};
    use crate::store::Row;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("logpit-restore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn row(ts: i64, msg: &str) -> Row {
        Row {
            id: 0,
            ts,
            host: "h".into(),
            app: "a".into(),
            severity: 6,
            message: msg.into(),
            fields: None,
        }
    }

    #[test]
    fn arguments_are_parsed_and_checked() {
        let cfg = RestoreConfig::from_args(
            &args(&[
                "--url",
                "http://x:8080",
                "--from",
                "2026-10-01",
                "--to",
                "2026-10-31",
                "--batch-lines",
                "50",
                "--dry-run",
                "a",
                "b",
            ]),
            &no_env,
        )
        .unwrap();
        assert_eq!(cfg.ingest_url(), "http://x:8080/ingest");
        assert_eq!(
            (
                cfg.from.as_deref(),
                cfg.to.as_deref(),
                cfg.batch_lines,
                cfg.dry_run
            ),
            (Some("2026-10-01"), Some("2026-10-31"), 50, true)
        );
        assert_eq!(cfg.paths.len(), 2);
        let with_token =
            RestoreConfig::from_args(&args(&["--url", "http://x/custom/path", "f"]), &|k| {
                (k == "LOGPIT_RESTORE_TOKEN").then(|| "secret".to_string())
            })
            .unwrap();
        assert_eq!(with_token.token.as_deref(), Some("secret"));
        assert_eq!(with_token.ingest_url(), "http://x/custom/path");
        for bad in [
            vec!["f"],
            vec!["--url", "http://x"],
            vec!["--url", "http://x", "--from", "yesterday", "f"],
            vec!["--url", "http://x", "--batch-lines", "0", "f"],
            vec!["--url", "http://x", "--bogus", "f"],
            vec!["--url"],
        ] {
            assert!(
                RestoreConfig::from_args(&args(&bad), &no_env).is_err(),
                "{bad:?}"
            );
        }
        // A dry run needs no server.
        assert!(RestoreConfig::from_args(&args(&["--dry-run", "f"]), &no_env).is_ok());
    }

    #[test]
    fn the_plan_walks_directories_and_filters_by_day() {
        let dir = temp_dir("plan");
        let archiver = Archiver::new(&dir).unwrap();
        // 2026-10-02, 2026-10-03, 2026-11-05 (UTC).
        for (ts, m) in [
            (1_790_899_200_000i64, "a"),
            (1_791_028_800_000, "b"),
            (1_793_880_000_000, "c"),
        ] {
            archiver.write(&[row(ts, m)]).unwrap();
        }
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let cfg = |from: Option<&str>, to: Option<&str>| RestoreConfig {
            url: String::new(),
            token: None,
            paths: vec![dir.clone()],
            from: from.map(String::from),
            to: to.map(String::from),
            batch_lines: 10,
            dry_run: true,
        };
        let names = |c: RestoreConfig| -> Vec<String> {
            plan(&c)
                .unwrap()
                .iter()
                .map(|p| file_day(p).unwrap())
                .collect()
        };
        assert_eq!(
            names(cfg(None, None)),
            ["2026-10-02", "2026-10-03", "2026-11-05"]
        );
        assert_eq!(
            names(cfg(Some("2026-10-03"), None)),
            ["2026-10-03", "2026-11-05"]
        );
        assert_eq!(
            names(cfg(None, Some("2026-10-03"))),
            ["2026-10-02", "2026-10-03"]
        );
        assert_eq!(
            names(cfg(Some("2026-10-03"), Some("2026-10-03"))),
            ["2026-10-03"]
        );
        assert!(names(cfg(Some("2027-01-01"), None)).is_empty());
        // A file named on the command line is taken even if its name carries no day.
        let odd = dir.join("whatever.dat");
        std::fs::write(&odd, b"{\"message\":\"x\"}\n").unwrap();
        let mut c = cfg(None, None);
        c.paths = vec![odd.clone()];
        assert_eq!(plan(&c).unwrap(), [odd]);
        assert!(
            plan(&RestoreConfig {
                paths: vec![dir.join("missing")],
                ..cfg(None, None)
            })
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chunks_read_members_or_plain_text() {
        let dir = temp_dir("chunks");
        let gz = dir.join("a.ndjson.gz");
        std::fs::write(
            &gz,
            [gzip_member(b"one\n"), gzip_member(b"two\nthree\n")].concat(),
        )
        .unwrap();
        assert_eq!(
            chunks(&gz).unwrap(),
            [b"one\n".to_vec(), b"two\nthree\n".to_vec()]
        );
        let plain = dir.join("b.ndjson");
        std::fs::write(&plain, b"x\ny\n").unwrap();
        assert_eq!(chunks(&plain).unwrap(), [b"x\ny\n".to_vec()]);
        let damaged = dir.join("c.ndjson.gz");
        let mut bytes = gzip_member(b"hello hello hello\n");
        let n = bytes.len();
        bytes.truncate(n - 5);
        std::fs::write(&damaged, bytes).unwrap();
        assert!(chunks(&damaged).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A server answering `statuses` in turn and keeping each request body.
    async fn server(statuses: Vec<u16>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = bodies.clone();
        tokio::spawn(async move {
            let mut n = 0;
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head, len) = loop {
                    let r = s.read(&mut chunk).await.unwrap_or(0);
                    if r == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..r]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let h = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        let len = h
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (i + 4, len);
                    }
                };
                while buf.len() < head + len {
                    let r = s.read(&mut chunk).await.unwrap_or(0);
                    if r == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..r]);
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[head..]).to_string());
                let status = statuses[n.min(statuses.len() - 1)];
                n += 1;
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        (url, bodies)
    }

    fn archive_with(dir: &Path, n: usize) {
        let archiver = Archiver::new(dir).unwrap();
        let rows: Vec<Row> = (0..n)
            .map(|i| row(1_791_028_800_000 + i as i64, &format!("msg {i}")))
            .collect();
        archiver.write(&rows).unwrap();
    }

    #[tokio::test]
    async fn entries_are_sent_in_batches_with_the_token() {
        let dir = temp_dir("run");
        archive_with(&dir, 25);
        let (url, bodies) = server(vec![200]).await;
        let cfg = RestoreConfig {
            url,
            token: Some("t".into()),
            paths: vec![dir.clone()],
            from: None,
            to: None,
            batch_lines: 10,
            dry_run: false,
        };
        let summary = run(cfg).await.unwrap();
        assert_eq!(
            (summary.files, summary.entries, summary.bad_lines),
            (1, 25, 0)
        );
        let bodies = bodies.lock().unwrap();
        assert_eq!(
            bodies.iter().map(|b| b.lines().count()).collect::<Vec<_>>(),
            [10, 10, 5]
        );
        let first: serde_json::Value =
            serde_json::from_str(bodies[0].lines().next().unwrap()).unwrap();
        assert_eq!(first["message"], "msg 0");
        assert_eq!(first["ts"], 1_791_028_800_000i64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_dry_run_sends_nothing_and_bad_lines_are_skipped() {
        let dir = temp_dir("dry");
        let file = dir.join("logpit-2026-10-03.ndjson");
        std::fs::write(
            &file,
            "{\"message\":\"ok\"}\nnot json\n\n{\"message\":\"ok2\"}\n",
        )
        .unwrap();
        let (url, bodies) = server(vec![200]).await;
        let mut cfg = RestoreConfig {
            url,
            token: None,
            paths: vec![file],
            from: None,
            to: None,
            batch_lines: 10,
            dry_run: true,
        };
        let s = run(cfg.clone()).await.unwrap();
        assert_eq!((s.entries, s.bad_lines), (2, 1));
        assert!(bodies.lock().unwrap().is_empty());
        cfg.dry_run = false;
        let s = run(cfg).await.unwrap();
        assert_eq!(s.entries, 2);
        assert_eq!(bodies.lock().unwrap()[0].lines().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn refused_tokens_stop_and_server_errors_are_retried() {
        let dir = temp_dir("err");
        archive_with(&dir, 3);
        let (url, _) = server(vec![401]).await;
        let mut cfg = RestoreConfig {
            url,
            token: Some("bad".into()),
            paths: vec![dir.clone()],
            from: None,
            to: None,
            batch_lines: 10,
            dry_run: false,
        };
        let err = run(cfg.clone()).await.unwrap_err().to_string();
        assert!(err.contains("write token"), "{err}");
        let (url, bodies) = server(vec![503, 200]).await;
        cfg.url = url;
        let s = run(cfg).await.unwrap();
        assert_eq!(s.entries, 3);
        assert_eq!(bodies.lock().unwrap().len(), 2, "retried once");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
