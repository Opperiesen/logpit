//! Forwarding entries to other systems: `[[forward]]` targets receive the entries that match
//! their filter, either as NDJSON batches over HTTP(S) (LogPit's own `/ingest` format, which a
//! second LogPit or most collectors can read) or as RFC 5424 syslog over UDP or TCP.
//!
//! Each target has a bounded in-memory queue and its own task, so a slow or unreachable target
//! never holds up ingestion: when its queue is full, entries for it are dropped and counted.
//! Failed batches are retried a few times with a growing delay, then dropped and counted. There is
//! no disk spool; use `logpit ship` where nothing may be lost.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, bail};
use regex::Regex;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};

use crate::model::LogEntry;
use crate::rules::{SeveritySpec, severity_set};
use crate::webhook::Webhook;

const DEFAULT_BATCH_LINES: usize = 200;
const DEFAULT_BATCH_MS: u64 = 1000;
const DEFAULT_QUEUE: usize = 10_000;
const MAX_QUEUE: usize = 1_000_000;
const MAX_BATCH_LINES: usize = 10_000;
const MAX_BATCH_MS: u64 = 60_000;
/// Delivery attempts for one batch, with `RETRY_DELAYS` between them.
const RETRY_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Longest syslog message written, in bytes.
const MAX_SYSLOG_MESSAGE: usize = 8192;
const SD_ID: &str = "logpit@32473";
const MAX_SD_FIELDS: usize = 32;
const MAX_SD_VALUE_CHARS: usize = 256;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// Label in metrics and logs; defaults to `forward-<position>`.
    pub name: Option<String>,
    /// `http://` or `https://` endpoint receiving NDJSON batches (one entry per line).
    pub url: Option<String>,
    /// `udp://host:port` or `tcp://host:port`: RFC 5424 syslog (TCP uses octet counting).
    pub syslog: Option<String>,
    /// Extra request headers for `url` (`"Authorization: Bearer …"`).
    #[serde(default)]
    pub headers: Vec<String>,
    /// Only entries from this host (exact match).
    pub host: Option<String>,
    /// Only entries from this app (exact match).
    pub app: Option<String>,
    /// Only entries with one of these severities (names or numbers).
    #[serde(default)]
    pub severity: Vec<SeveritySpec>,
    /// Only entries whose message matches this regular expression.
    pub pattern: Option<String>,
    /// Entries per HTTP batch at most (default 200).
    pub batch_lines: Option<usize>,
    /// Longest wait before sending a partial HTTP batch (default 1000 ms).
    pub batch_ms: Option<u64>,
    /// Entries queued for this target before new ones are dropped (default 10 000).
    pub queue: Option<usize>,
}

#[derive(Clone)]
enum Dest {
    Http(Webhook),
    Udp(String),
    Tcp(String),
}

struct Filter {
    host: Option<String>,
    app: Option<String>,
    severities: Option<[bool; 8]>,
    pattern: Option<Regex>,
}

impl Filter {
    fn matches(&self, e: &LogEntry) -> bool {
        self.host.as_ref().is_none_or(|h| *h == e.host)
            && self.app.as_ref().is_none_or(|a| *a == e.app)
            && self
                .severities
                .is_none_or(|s| s[usize::from(e.severity.min(7))])
            && self.pattern.as_ref().is_none_or(|p| p.is_match(&e.message))
    }
}

#[derive(Default)]
struct Stats {
    sent: AtomicU64,
    /// Entries not queued because the queue was full.
    dropped: AtomicU64,
    /// Entries given up on after the retries (or refused for good by the receiver).
    failed: AtomicU64,
}

struct Resolved {
    name: String,
    dest: Dest,
    filter: Filter,
    batch_lines: usize,
    batch: Duration,
    queue: usize,
}

fn resolve(configs: &[ForwardConfig]) -> anyhow::Result<Vec<Resolved>> {
    let mut names = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (i, c) in configs.iter().enumerate() {
        let name = c
            .name
            .clone()
            .unwrap_or_else(|| format!("forward-{}", i + 1));
        let ctx = || format!("forward {name:?}");
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            bail!("forward name {name:?} must be 1 to 64 letters, digits, '_', '-' or '.'");
        }
        if !names.insert(name.clone()) {
            bail!("{}: the name is used by another forward", ctx());
        }
        let dest = match (&c.url, &c.syslog) {
            (Some(url), None) => Dest::Http(
                Webhook::new(url, crate::webhook::WebhookFormat::Json, &c.headers)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "{}: {}",
                            ctx(),
                            e.to_string().replace("silence.webhook_url", "url")
                        )
                    })?
                    .with_timeout(IO_TIMEOUT),
            ),
            (None, Some(target)) => {
                if !c.headers.is_empty() {
                    bail!("{}: headers only apply to url, not syslog", ctx());
                }
                let (proto, addr) = target.split_once("://").with_context(|| {
                    format!(
                        "{}: syslog must be udp://host:port or tcp://host:port",
                        ctx()
                    )
                })?;
                let valid_addr = addr
                    .rsplit_once(':')
                    .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p > 0));
                if !valid_addr || addr.contains(char::is_whitespace) {
                    bail!("{}: syslog needs host:port after the scheme", ctx());
                }
                match proto {
                    "udp" => Dest::Udp(addr.to_string()),
                    "tcp" => Dest::Tcp(addr.to_string()),
                    other => bail!(
                        "{}: unsupported syslog scheme {other:?} (udp or tcp)",
                        ctx()
                    ),
                }
            }
            _ => bail!("{}: set exactly one of url and syslog", ctx()),
        };
        let batch_lines = c.batch_lines.unwrap_or(DEFAULT_BATCH_LINES);
        let batch_ms = c.batch_ms.unwrap_or(DEFAULT_BATCH_MS);
        let queue = c.queue.unwrap_or(DEFAULT_QUEUE);
        if batch_lines == 0 || batch_lines > MAX_BATCH_LINES {
            bail!(
                "{}: batch_lines must be between 1 and {MAX_BATCH_LINES}",
                ctx()
            );
        }
        if batch_ms == 0 || batch_ms > MAX_BATCH_MS {
            bail!("{}: batch_ms must be between 1 and {MAX_BATCH_MS}", ctx());
        }
        if queue == 0 || queue > MAX_QUEUE {
            bail!("{}: queue must be between 1 and {MAX_QUEUE}", ctx());
        }
        let pattern = match &c.pattern {
            Some(p) => Some(
                crate::filters::compile_regex(p)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("{}: pattern {p:?}", ctx()))?,
            ),
            None => None,
        };
        out.push(Resolved {
            name: name.clone(),
            dest,
            filter: Filter {
                host: c.host.clone(),
                app: c.app.clone(),
                severities: severity_set(&c.severity).with_context(ctx)?,
                pattern,
            },
            batch_lines,
            batch: Duration::from_millis(batch_ms),
            queue,
        });
    }
    Ok(out)
}

/// Checks the `[[forward]]` entries without starting anything.
pub fn validate(configs: &[ForwardConfig]) -> anyhow::Result<()> {
    resolve(configs).map(|_| ())
}

struct Target {
    name: String,
    filter: Filter,
    tx: mpsc::Sender<LogEntry>,
    stats: Arc<Stats>,
}

/// The running targets, fed by the ingestion pipeline.
#[derive(Default)]
pub struct Forwarders {
    targets: Vec<Target>,
}

impl Forwarders {
    /// Starts one delivery task per target on the current Tokio runtime.
    pub fn start(configs: &[ForwardConfig]) -> anyhow::Result<Arc<Self>> {
        let mut targets = Vec::new();
        for r in resolve(configs)? {
            let (tx, rx) = mpsc::channel(r.queue);
            let stats = Arc::new(Stats::default());
            tokio::spawn(run_target(
                r.name.clone(),
                r.dest,
                rx,
                r.batch_lines,
                r.batch,
                stats.clone(),
            ));
            targets.push(Target {
                name: r.name,
                filter: r.filter,
                tx,
                stats,
            });
        }
        Ok(Arc::new(Self { targets }))
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Queues `entry` for every target whose filter it matches; never waits.
    pub fn offer(&self, entry: &LogEntry) {
        for t in &self.targets {
            if t.filter.matches(entry) && t.tx.try_send(entry.clone()).is_err() {
                t.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn render_metrics(&self) -> String {
        if self.targets.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for (name, kind, help) in [
            ("sent_total", "counter", "Entries delivered to the target"),
            (
                "dropped_total",
                "counter",
                "Entries not queued because the target's queue was full",
            ),
            (
                "failed_total",
                "counter",
                "Entries given up on after retries or refused by the target",
            ),
            ("queued", "gauge", "Entries waiting in the target's queue"),
        ] {
            let _ = writeln!(
                out,
                "# HELP logpit_forward_{name} {help}\n# TYPE logpit_forward_{name} {kind}"
            );
            for t in &self.targets {
                let value = match name {
                    "sent_total" => t.stats.sent.load(Ordering::Relaxed),
                    "dropped_total" => t.stats.dropped.load(Ordering::Relaxed),
                    "failed_total" => t.stats.failed.load(Ordering::Relaxed),
                    _ => (t.tx.max_capacity() - t.tx.capacity()) as u64,
                };
                let _ = writeln!(
                    out,
                    "logpit_forward_{name}{{target=\"{}\"}} {value}",
                    t.name
                );
            }
        }
        out
    }
}

// ---- formats ------------------------------------------------------------------------------

/// A batch as NDJSON, in the format `/ingest` reads.
pub fn ndjson(batch: &[LogEntry]) -> String {
    let mut body = String::new();
    for e in batch {
        if let Ok(line) = serde_json::to_string(e) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    body
}

/// A syslog header field: printable ASCII without spaces, at most `max` bytes, `-` when empty.
fn header_token(text: &str, max: usize) -> String {
    let t: String = text
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .take(max)
        .collect();
    if t.is_empty() { "-".to_string() } else { t }
}

fn sd_value(v: &str) -> String {
    let mut out = String::new();
    for c in v.chars().take(MAX_SD_VALUE_CHARS) {
        if matches!(c, '\\' | '"' | ']') {
            out.push('\\');
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}

/// An entry as an RFC 5424 message (facility `user`), structured fields as one SD element.
pub fn rfc5424(e: &LogEntry) -> String {
    let ts = chrono::DateTime::from_timestamp_millis(e.ts).map_or_else(
        || "-".to_string(),
        |t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    );
    let mut sd = String::new();
    for (k, v) in e
        .fields
        .iter()
        .filter(|(k, _)| k.len() <= 32)
        .take(MAX_SD_FIELDS)
    {
        let _ = write!(sd, " {k}=\"{}\"", sd_value(v));
    }
    let sd = if sd.is_empty() {
        "-".to_string()
    } else {
        format!("[{SD_ID}{sd}]")
    };
    let mut msg = e.message.clone();
    crate::model::truncate_utf8(&mut msg, MAX_SYSLOG_MESSAGE);
    format!(
        "<{}>1 {ts} {} {} - - {sd} {msg}",
        8 + u32::from(e.severity.min(7)),
        header_token(&e.host, 255),
        header_token(&e.app, 48),
    )
}

/// RFC 6587 octet counting: `<length> <message>`.
fn octet_frame(msg: &str) -> Vec<u8> {
    let mut frame = format!("{} ", msg.len()).into_bytes();
    frame.extend_from_slice(msg.as_bytes());
    frame
}

// ---- delivery -----------------------------------------------------------------------------

enum Outcome {
    Delivered,
    /// Worth another try: a connection failure, a timeout, a server error.
    Retry(String),
    /// The receiver refused it for good (a 4xx): retrying cannot help.
    Refused(String),
}

async fn next_batch(
    rx: &mut mpsc::Receiver<LogEntry>,
    max: usize,
    wait: Duration,
) -> Option<Vec<LogEntry>> {
    let mut batch = vec![rx.recv().await?];
    let deadline = Instant::now() + wait;
    while batch.len() < max {
        match timeout_at(deadline, rx.recv()).await {
            Ok(Some(e)) => batch.push(e),
            _ => break,
        }
    }
    Some(batch)
}

async fn deliver_http(hook: &Webhook, batch: &[LogEntry]) -> Outcome {
    match hook.post_body("application/x-ndjson", ndjson(batch)).await {
        Ok(status) if (200..300).contains(&status) => Outcome::Delivered,
        Ok(status) if status == 408 || status == 425 || status == 429 || status >= 500 => {
            Outcome::Retry(format!("HTTP {status}"))
        }
        Ok(status) => Outcome::Refused(format!("HTTP {status}")),
        Err(e) => Outcome::Retry(format!("{e:#}")),
    }
}

async fn deliver_tcp(conn: &mut Option<TcpStream>, addr: &str, batch: &[LogEntry]) -> Outcome {
    let mut bytes = Vec::new();
    for e in batch {
        bytes.extend_from_slice(&octet_frame(&rfc5424(e)));
    }
    let attempt = async {
        if conn.is_none() {
            *conn = Some(timeout(IO_TIMEOUT, TcpStream::connect(addr)).await??);
        }
        let stream = conn.as_mut().expect("connected above");
        timeout(IO_TIMEOUT, stream.write_all(&bytes)).await??;
        timeout(IO_TIMEOUT, stream.flush()).await??;
        anyhow::Ok(())
    };
    match attempt.await {
        Ok(()) => Outcome::Delivered,
        Err(e) => {
            *conn = None;
            Outcome::Retry(format!("{e:#}"))
        }
    }
}

async fn deliver_udp(socket: &mut Option<UdpSocket>, addr: &str, batch: &[LogEntry]) -> Outcome {
    let attempt = async {
        if socket.is_none() {
            let target = tokio::net::lookup_host(addr)
                .await?
                .next()
                .context("no address")?;
            let bind = if target.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let s = UdpSocket::bind(bind).await?;
            s.connect(target).await?;
            *socket = Some(s);
        }
        let s = socket.as_ref().expect("bound above");
        for e in batch {
            s.send(rfc5424(e).as_bytes()).await?;
        }
        anyhow::Ok(())
    };
    match attempt.await {
        Ok(()) => Outcome::Delivered,
        Err(e) => {
            *socket = None;
            Outcome::Retry(format!("{e:#}"))
        }
    }
}

async fn run_target(
    name: String,
    dest: Dest,
    mut rx: mpsc::Receiver<LogEntry>,
    batch_lines: usize,
    batch_wait: Duration,
    stats: Arc<Stats>,
) {
    let mut tcp: Option<TcpStream> = None;
    let mut udp: Option<UdpSocket> = None;
    // Syslog goes out as soon as entries are there; only HTTP gains from batching.
    let (max, wait) = match dest {
        Dest::Http(_) => (batch_lines, batch_wait),
        Dest::Tcp(_) => (batch_lines, Duration::from_millis(50)),
        Dest::Udp(_) => (batch_lines, Duration::from_millis(5)),
    };
    while let Some(batch) = next_batch(&mut rx, max, wait).await {
        let mut attempt = 0;
        loop {
            let outcome = match &dest {
                Dest::Http(hook) => deliver_http(hook, &batch).await,
                Dest::Tcp(addr) => deliver_tcp(&mut tcp, addr, &batch).await,
                Dest::Udp(addr) => deliver_udp(&mut udp, addr, &batch).await,
            };
            match outcome {
                Outcome::Delivered => {
                    stats.sent.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    break;
                }
                Outcome::Refused(why) => {
                    tracing::warn!(
                        "forward {name}: {} entries refused ({why}), dropped",
                        batch.len()
                    );
                    stats
                        .failed
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    break;
                }
                Outcome::Retry(why) => {
                    if attempt >= RETRY_DELAYS.len() {
                        tracing::error!(
                            "forward {name}: gave up on {} entries after {} attempts ({why})",
                            batch.len(),
                            attempt + 1
                        );
                        stats
                            .failed
                            .fetch_add(batch.len() as u64, Ordering::Relaxed);
                        break;
                    }
                    if attempt == 0 {
                        tracing::warn!("forward {name}: delivery failed ({why}), retrying");
                    }
                    tokio::time::sleep(RETRY_DELAYS[attempt]).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn entry(ts: i64, host: &str, app: &str, severity: u8, message: &str) -> LogEntry {
        LogEntry {
            ts,
            host: host.into(),
            app: app.into(),
            severity,
            message: message.into(),
            ..Default::default()
        }
    }

    fn cfg(toml_text: &str) -> Vec<ForwardConfig> {
        #[derive(Deserialize)]
        struct W {
            forward: Vec<ForwardConfig>,
        }
        toml::from_str::<W>(toml_text).unwrap().forward
    }

    #[test]
    fn syslog_messages_are_rfc5424_with_one_sd_element() {
        let mut e = entry(1_791_028_800_123, "web 1", "ng\"inx", 3, "boom\nsecond");
        e.fields.insert("status".into(), "5\"00]\\".into());
        e.fields.insert("src".into(), "10.0.0.1".into());
        let m = rfc5424(&e);
        assert_eq!(
            m,
            "<11>1 2026-10-03T12:00:00.123Z web_1 ng\"inx - - \
             [logpit@32473 src=\"10.0.0.1\" status=\"5\\\"00\\]\\\\\"] boom\nsecond"
        );
        // No fields and empty names.
        assert_eq!(
            rfc5424(&entry(0, "", "", 7, "x")),
            "<15>1 1970-01-01T00:00:00.000Z - - - - - x"
        );
        // Long field names are skipped, the facility is `user`, and the message is clipped.
        let mut long = entry(0, "h", "a", 0, &"é".repeat(MAX_SYSLOG_MESSAGE));
        long.fields.insert("k".repeat(33), "v".into());
        let m = rfc5424(&long);
        assert!(m.starts_with("<8>1 "));
        assert!(!m.contains("kkkk"));
        assert!(m.len() < MAX_SYSLOG_MESSAGE + 100);
        assert_eq!(octet_frame("abc"), b"3 abc");
    }

    #[test]
    fn ndjson_is_what_ingest_reads() {
        let mut e = entry(5, "h", "a", 4, "hi \"there\"");
        e.fields = BTreeMap::from([("k".to_string(), "v".to_string())]);
        let body = ndjson(&[e.clone(), entry(6, "h2", "", 6, "second")]);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let back =
            crate::api::entry_from_json(&serde_json::from_str(lines[0]).unwrap(), 0).unwrap();
        assert_eq!(back, e);
        assert!(body.ends_with('\n'));
    }

    #[test]
    fn configuration_is_validated() {
        assert!(validate(&[]).is_ok());
        let ok = cfg(
            "[[forward]]\nurl = \"https://siem.example/ingest\"\nheaders = [\"Authorization: Bearer x\"]\n\
             [[forward]]\nname = \"sw\"\nsyslog = \"udp://10.0.0.5:514\"\nhost = \"fw\"\nseverity = [\"err\"]\npattern = \"deny\"",
        );
        assert!(validate(&ok).is_ok());
        for bad in [
            "name = \"a\"",
            "url = \"http://h/x\"\nsyslog = \"udp://h:1\"",
            "url = \"ftp://h/x\"",
            "url = \"http://h/x\"\nheaders = [\"Content-Length: 5\"]",
            "syslog = \"h:514\"",
            "syslog = \"tls://h:514\"",
            "syslog = \"udp://h\"",
            "syslog = \"udp://h:0\"",
            "syslog = \"tcp://h:514\"\nheaders = [\"X: y\"]",
            "url = \"http://h/x\"\nname = \"bad name\"",
            "url = \"http://h/x\"\nbatch_lines = 0",
            "url = \"http://h/x\"\nbatch_ms = 0",
            "url = \"http://h/x\"\nqueue = 0",
            "url = \"http://h/x\"\npattern = \"(\"",
            "url = \"http://h/x\"\nseverity = [\"loud\"]",
        ] {
            assert!(
                validate(&cfg(&format!("[[forward]]\n{bad}"))).is_err(),
                "{bad}"
            );
        }
        assert!(validate(&cfg("[[forward]]\nname = \"x\"\nurl = \"http://h/\"\n[[forward]]\nname = \"x\"\nurl = \"http://h/\"")).is_err());
        let msg = validate(&cfg("[[forward]]\nurl = \"nope\""))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("url") && !msg.contains("silence"), "{msg}");
        assert!(toml::from_str::<ForwardConfig>("bogus = 1").is_err());
    }

    /// An HTTP server that answers `statuses` in turn (then the last one forever) and records
    /// each request body.
    async fn http_server(statuses: Vec<u16>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/ingest", listener.local_addr().unwrap());
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = bodies.clone();
        tokio::spawn(async move {
            let mut n = 0;
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, len) = loop {
                    let r = s.read(&mut chunk).await.unwrap_or(0);
                    if r == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..r]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (i + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let r = s.read(&mut chunk).await.unwrap_or(0);
                    if r == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..r]);
                }
                let status = statuses[n.min(statuses.len() - 1)];
                n += 1;
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[head_end..]).to_string());
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

    async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
        for _ in 0..400 {
            if ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for {what}");
    }

    fn stat(f: &Forwarders, name: &str) -> u64 {
        let text = f.render_metrics();
        text.lines()
            .find(|l| l.starts_with(&format!("logpit_forward_{name}{{")))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(u64::MAX)
    }

    #[tokio::test]
    async fn http_targets_get_matching_entries_as_ndjson_batches() {
        let (url, bodies) = http_server(vec![200]).await;
        let f = Forwarders::start(&cfg(&format!(
            "[[forward]]\nurl = \"{url}\"\nhost = \"web1\"\nseverity = [\"err\", \"warning\"]\nbatch_ms = 100"
        )))
        .unwrap();
        f.offer(&entry(1, "web1", "a", 3, "kept 1"));
        f.offer(&entry(2, "web2", "a", 3, "other host"));
        f.offer(&entry(3, "web1", "a", 6, "wrong severity"));
        f.offer(&entry(4, "web1", "a", 4, "kept 2"));
        wait_for("delivery", || stat(&f, "sent_total") == 2).await;
        let bodies = bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1, "one batch");
        let messages: Vec<String> = bodies[0]
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["message"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(messages, ["kept 1", "kept 2"]);
        assert_eq!(
            (stat(&f, "dropped_total"), stat(&f, "failed_total")),
            (0, 0)
        );
    }

    #[tokio::test]
    async fn server_errors_are_retried_and_client_errors_are_not() {
        let (url, bodies) = http_server(vec![503, 200]).await;
        let f = Forwarders::start(&cfg(&format!(
            "[[forward]]\nurl = \"{url}\"\nbatch_ms = 10"
        )))
        .unwrap();
        f.offer(&entry(1, "h", "a", 6, "retried"));
        wait_for("retry then success", || stat(&f, "sent_total") == 1).await;
        assert_eq!(bodies.lock().unwrap().len(), 2, "the same batch twice");
        assert_eq!(stat(&f, "failed_total"), 0);

        let (url, bodies) = http_server(vec![400]).await;
        let f = Forwarders::start(&cfg(&format!(
            "[[forward]]\nurl = \"{url}\"\nbatch_ms = 10"
        )))
        .unwrap();
        f.offer(&entry(1, "h", "a", 6, "refused"));
        f.offer(&entry(2, "h", "a", 6, "refused too"));
        wait_for("refusal", || stat(&f, "failed_total") == 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(bodies.lock().unwrap().len(), 1, "a 4xx is not retried");
        assert_eq!(stat(&f, "sent_total"), 0);
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_counts_instead_of_blocking() {
        // Nothing listens there, so the first batch is stuck retrying while the queue fills.
        let f = Forwarders::start(&cfg(
            "[[forward]]\nurl = \"http://127.0.0.1:1/x\"\nqueue = 2\nbatch_ms = 1",
        ))
        .unwrap();
        for i in 0..50 {
            f.offer(&entry(i, "h", "a", 6, "x"));
            if i == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        assert!(stat(&f, "dropped_total") >= 40, "{}", f.render_metrics());
        assert!(
            f.render_metrics()
                .contains("logpit_forward_queued{target=\"forward-1\"} 2")
        );
    }

    #[tokio::test]
    async fn syslog_over_tcp_uses_octet_counting_on_one_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let (sink, accepted) = (received.clone(), Arc::new(AtomicU64::new(0)));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                let sink = sink.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        sink.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                });
            }
        });
        let f =
            Forwarders::start(&cfg(&format!("[[forward]]\nsyslog = \"tcp://{addr}\""))).unwrap();
        f.offer(&entry(1, "h", "app", 3, "first"));
        wait_for("first", || stat(&f, "sent_total") == 1).await;
        f.offer(&entry(2, "h", "app", 4, "second"));
        wait_for("second", || stat(&f, "sent_total") == 2).await;
        let data = String::from_utf8(received.lock().unwrap().clone()).unwrap();
        let mut rest = data.as_str();
        let mut messages = Vec::new();
        while !rest.is_empty() {
            let (len, tail) = rest.split_once(' ').unwrap();
            let len: usize = len.parse().unwrap();
            messages.push(tail[..len].to_string());
            rest = &tail[len..];
        }
        assert_eq!(messages.len(), 2);
        assert!(messages[0].starts_with("<11>1 1970-01-01T00:00:00.001Z h app - - - first"));
        assert!(messages[1].starts_with("<12>1 "));
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "the connection is kept"
        );
    }

    #[tokio::test]
    async fn syslog_over_udp_sends_one_datagram_per_entry() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let f =
            Forwarders::start(&cfg(&format!("[[forward]]\nsyslog = \"udp://{addr}\""))).unwrap();
        f.offer(&entry(1, "h", "app", 6, "one"));
        f.offer(&entry(2, "h", "app", 6, "two"));
        let mut got = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 2048];
            let n = timeout(Duration::from_secs(5), socket.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            got.push(String::from_utf8_lossy(&buf[..n]).to_string());
        }
        assert!(
            got[0].ends_with(" one") && got[1].ends_with(" two"),
            "{got:?}"
        );
        wait_for("counters", || stat(&f, "sent_total") == 2).await;
    }
}
