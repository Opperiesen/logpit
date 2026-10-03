//! `logpit search` and `logpit tail`: query a running server from the terminal.

use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::Value;

use crate::httpget;
use crate::webhook::{Webhook, WebhookFormat};

pub const SEARCH_USAGE: &str = "usage: logpit search --url <http(s)://logpit:8080> [filters] [options]
       logpit tail   --url <http(s)://logpit:8080> [filters] [options]

`search` prints the entries matching the filters, oldest first; `tail` prints the last few and then
follows new entries as they arrive (Ctrl-C to stop).

connection:
  --url URL              LogPit server (or LOGPIT_URL)
  --token-file PATH      file holding a read token (or LOGPIT_TOKEN / LOGPIT_TOKEN_FILE)

filters:
  -q, --query TEXT       search text: words, \"phrases\", OR, -exclusions, prefix*
  --host HOST            --app APP
  --level LEVEL          this severity and worse: emerg, alert, crit, err, warn, notice, info, debug or 0-7
  -f, --field EXPR       structured field: key:value, status>=500, act!=block, src~regex (repeatable)
  --regex REGEX          regular expression on the message
  --tag TAG              hosts with this tag (repeatable)
  --trace ID             every entry of this trace (its trace_id), across hosts
  --since WHEN           (search) 15m, 2h, 1d, an RFC 3339 time, or Unix seconds/ms (default: all)
  --until WHEN           (search) same forms

output:
  -n, --limit N          entries to print (search default 100, tail default 10)
  --format FORMAT        text (default), json (one array, search only) or ndjson
  --fields               text: also print the structured fields
  --newest-first         (search) newest entries first instead of oldest first";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Ndjson,
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub url: String,
    pub token: Option<String>,
    /// The filters as API parameters.
    pub params: Vec<(String, String)>,
    pub limit: Option<usize>,
    pub format: Format,
    pub fields: bool,
    pub newest_first: bool,
}

/// Largest `--limit` accepted.
const MAX_LIMIT: usize = 1_000_000;
const PAGE: usize = 1000;
const SEARCH_TIMEOUT: Duration = Duration::from_secs(60);

fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn query_string(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A time for `--since` / `--until`: a duration before now (`15m`), or an absolute time.
pub fn parse_when(text: &str, now_ms: i64) -> anyhow::Result<i64> {
    if let Some(ms) = crate::logql::parse_duration_ms(text) {
        return Ok(now_ms - ms);
    }
    crate::lokiapi::parse_time(text).map_err(anyhow::Error::msg)
}

impl Cli {
    pub fn from_args(
        args: &[String],
        env: &dyn Fn(&str) -> Option<String>,
        now_ms: i64,
    ) -> anyhow::Result<Self> {
        let mut cli = Cli {
            url: env("LOGPIT_URL").unwrap_or_default(),
            token: None,
            params: Vec::new(),
            limit: None,
            format: Format::Text,
            fields: false,
            newest_first: false,
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
                "--url" => cli.url = value("--url")?,
                "--token-file" => {
                    token_file = Some(std::path::PathBuf::from(value("--token-file")?))
                }
                "-q" | "--query" => cli.params.push(("q".into(), value(arg)?)),
                "--host" => cli.params.push(("host".into(), value(arg)?)),
                "--app" => cli.params.push(("app".into(), value(arg)?)),
                "--level" => {
                    let v = value(arg)?;
                    let sev = crate::model::parse_severity(&v)
                        .or_else(|| crate::model::level_severity(&v))
                        .with_context(|| format!("unknown level {v:?}"))?;
                    cli.params.push(("level".into(), sev.to_string()));
                }
                "-f" | "--field" => cli.params.push(("f".into(), value(arg)?)),
                "--regex" => cli.params.push(("re".into(), value(arg)?)),
                "--tag" => cli.params.push(("tag".into(), value(arg)?)),
                "--trace" => cli.params.push(("trace".into(), value(arg)?)),
                "--since" | "--until" => {
                    let ms = parse_when(&value(arg)?, now_ms).with_context(|| arg.to_string())?;
                    let key = if arg == "--since" { "since" } else { "until" };
                    cli.params.push((key.into(), ms.to_string()));
                }
                "-n" | "--limit" => {
                    cli.limit = Some(
                        value(arg)?
                            .parse::<usize>()
                            .ok()
                            .filter(|n| (1..=MAX_LIMIT).contains(n))
                            .with_context(|| {
                                format!("--limit must be between 1 and {MAX_LIMIT}")
                            })?,
                    );
                }
                "--format" => {
                    cli.format = match value(arg)?.as_str() {
                        "text" => Format::Text,
                        "json" => Format::Json,
                        "ndjson" => Format::Ndjson,
                        other => bail!("unknown format {other:?} (text, json or ndjson)"),
                    }
                }
                "--fields" => cli.fields = true,
                "--newest-first" => cli.newest_first = true,
                other => bail!("unknown option {other:?}\n{SEARCH_USAGE}"),
            }
        }
        if cli.url.is_empty() {
            bail!("--url is required (or set LOGPIT_URL)\n{SEARCH_USAGE}");
        }
        cli.token = match (token_file, env("LOGPIT_TOKEN"), env("LOGPIT_TOKEN_FILE")) {
            (Some(path), _, _) => Some(crate::shipper::read_token(&path)?),
            (None, Some(t), _) => Some(t),
            (None, None, Some(path)) => {
                Some(crate::shipper::read_token(std::path::Path::new(&path))?)
            }
            (None, None, None) => None,
        };
        Ok(cli)
    }

    fn hook(&self) -> anyhow::Result<Webhook> {
        let headers: Vec<String> = self
            .token
            .iter()
            .map(|t| format!("Authorization: Bearer {t}"))
            .collect();
        Ok(Webhook::new(&self.url, WebhookFormat::Json, &headers)
            .map_err(|e| {
                anyhow::anyhow!("{}", e.to_string().replace("silence.webhook_url", "--url"))
            })?
            .with_timeout(SEARCH_TIMEOUT))
    }
}

/// One entry as a line of text: time (UTC), host, app, severity, message, and optionally fields.
pub fn format_text(e: &Value, with_fields: bool) -> String {
    let ts = e["ts"].as_i64().unwrap_or(0);
    let time = chrono::DateTime::from_timestamp_millis(ts).map_or_else(String::new, |t| {
        t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    });
    let app = e["app"].as_str().filter(|a| !a.is_empty()).unwrap_or("-");
    let sev = crate::model::severity_name(e["severity"].as_u64().unwrap_or(6).min(7) as u8);
    let message = e["message"].as_str().unwrap_or("").replace('\n', "\n    ");
    let mut line = format!(
        "{time} {} {app} {sev} {message}",
        e["host"].as_str().unwrap_or("?")
    );
    if with_fields
        && let Some(fields) = e["fields"].as_object()
        && !fields.is_empty()
    {
        let pairs: Vec<String> = fields
            .iter()
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    v.as_str().map_or_else(|| v.to_string(), str::to_string)
                )
            })
            .collect();
        line.push_str(&format!("  {{{}}}", pairs.join(" ")));
    }
    line
}

fn render(entries: &[Value], cli: &Cli) -> anyhow::Result<String> {
    Ok(match cli.format {
        Format::Json => format!("{}\n", serde_json::to_string(entries)?),
        Format::Ndjson => entries.iter().map(|e| format!("{}\n", e)).collect(),
        Format::Text => entries
            .iter()
            .map(|e| format!("{}\n", format_text(e, cli.fields)))
            .collect(),
    })
}

/// Fetches up to `limit` entries, newest first, following the paging cursor.
async fn fetch(cli: &Cli, hook: &Webhook, limit: usize) -> anyhow::Result<Vec<Value>> {
    let mut entries: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    while entries.len() < limit {
        let mut params = cli.params.clone();
        params.push((
            "limit".into(),
            (limit - entries.len()).min(PAGE).to_string(),
        ));
        if let Some(c) = &cursor {
            params.push(("before".into(), c.clone()));
        }
        let mut resp = httpget::get(
            hook,
            &format!("/api/logs?{}", query_string(&params)),
            "application/json",
            Some(SEARCH_TIMEOUT),
        )
        .await?;
        let body = resp.read_all(httpget::DEFAULT_MAX_BODY).await?;
        if resp.status != 200 {
            bail!("{}", explain(resp.status, &body));
        }
        let page: Vec<Value> =
            serde_json::from_slice(&body).context("the server sent an unreadable answer")?;
        let full = page.len() >= (limit - entries.len()).min(PAGE);
        entries.extend(page);
        cursor = resp.header("x-next-cursor").map(str::to_string);
        if !full || cursor.is_none() {
            break;
        }
    }
    entries.truncate(limit);
    Ok(entries)
}

fn explain(status: u16, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    match status {
        401 => "the server refused the credentials: give a read token (--token-file)".to_string(),
        403 => "this token may not read entries".to_string(),
        _ if text.is_empty() => format!("the server answered HTTP {status}"),
        _ => format!(
            "HTTP {status}: {}",
            text.chars().take(300).collect::<String>()
        ),
    }
}

/// `logpit search`: prints the matching entries and returns how many.
pub async fn search(cli: &Cli, out: &mut dyn std::io::Write) -> anyhow::Result<usize> {
    let hook = cli.hook()?;
    let mut entries = fetch(cli, &hook, cli.limit.unwrap_or(100)).await?;
    if !cli.newest_first {
        entries.reverse();
    }
    out.write_all(render(&entries, cli)?.as_bytes())?;
    Ok(entries.len())
}

/// Pulls complete lines out of a byte stream.
#[derive(Default)]
pub struct Lines {
    buf: Vec<u8>,
}

impl Lines {
    pub fn push(&mut self, data: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(data);
        let mut lines = Vec::new();
        while let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            lines.push(
                String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            );
        }
        lines
    }
}

/// What a server-sent-events line means for `tail`.
#[derive(Debug, PartialEq)]
pub enum Sse {
    Entry(Value),
    Lagged(u64),
    Ignore,
}

/// Follows the `event:`/`data:` lines of the stream: an entry per `data:` unless the event was
/// `lagged`, whose data is how many entries were skipped.
#[derive(Default)]
pub struct SseParser {
    event: String,
}

impl SseParser {
    pub fn line(&mut self, line: &str) -> Sse {
        if let Some(name) = line.strip_prefix("event:") {
            self.event = name.trim().to_string();
            return Sse::Ignore;
        }
        let Some(data) = line.strip_prefix("data:") else {
            return Sse::Ignore;
        };
        let event = std::mem::take(&mut self.event);
        let data = data.trim_start();
        if event == "lagged" {
            return data.parse().map_or(Sse::Ignore, Sse::Lagged);
        }
        serde_json::from_str(data).map_or(Sse::Ignore, Sse::Entry)
    }
}

/// `logpit tail`: prints the last entries, then new ones until the connection is lost for good or
/// the process is interrupted. Returns after `max_entries` live entries when given (for tests).
pub async fn tail(
    cli: &Cli,
    out: &mut dyn std::io::Write,
    max_entries: Option<usize>,
) -> anyhow::Result<()> {
    if cli.format == Format::Json {
        bail!("tail prints one entry at a time: use --format text or ndjson");
    }
    let hook = cli.hook()?;
    let initial = cli.limit.unwrap_or(10);
    let mut first = true;
    let mut printed = 0usize;
    let mut delay = Duration::from_secs(1);
    loop {
        let path = format!("/api/tail?{}", query_string(&cli.params));
        // Subscribe before reading the history, so nothing falls between the two.
        match httpget::get(&hook, &path, "text/event-stream", None).await {
            Ok(mut resp) if resp.status == 200 => {
                delay = Duration::from_secs(1);
                if first {
                    first = false;
                    if initial > 0 {
                        let mut history = fetch(cli, &hook, initial).await?;
                        history.reverse();
                        out.write_all(render(&history, cli)?.as_bytes())?;
                        out.flush()?;
                    }
                }
                let (mut lines, mut parser) = (Lines::default(), SseParser::default());
                loop {
                    let chunk = match resp.next_chunk().await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("logpit: connection lost ({e:#}), reconnecting");
                            break;
                        }
                    };
                    for line in lines.push(&chunk) {
                        match parser.line(&line) {
                            Sse::Entry(e) => {
                                out.write_all(render(std::slice::from_ref(&e), cli)?.as_bytes())?;
                                out.flush()?;
                                printed += 1;
                                if max_entries.is_some_and(|m| printed >= m) {
                                    return Ok(());
                                }
                            }
                            Sse::Lagged(n) => {
                                eprintln!("logpit: {n} entries were skipped (too fast to follow)")
                            }
                            Sse::Ignore => {}
                        }
                    }
                }
            }
            Ok(mut resp) => {
                let body = resp.read_all(64 * 1024).await.unwrap_or_default();
                // A refusal will not go away by waiting; a full server (503) might.
                if resp.status != 503 {
                    bail!("{}", explain(resp.status, &body));
                }
                eprintln!("logpit: {}, retrying", explain(resp.status, &body));
            }
            Err(e) => {
                if first {
                    return Err(e);
                }
                eprintln!("logpit: {e:#}, retrying");
            }
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(15));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn parse(list: &[&str]) -> anyhow::Result<Cli> {
        Cli::from_args(&args(list), &|_| None, 1_000_000_000)
    }

    #[test]
    fn filters_become_api_parameters() {
        let cli = parse(&[
            "--url",
            "http://x:8080",
            "-q",
            "disk error",
            "--host",
            "web1",
            "--level",
            "warn",
            "-f",
            "status>=500",
            "-f",
            "act:block",
            "--regex",
            "t(im|o)e",
            "--tag",
            "prod",
            "--trace",
            "4BF9",
            "--since",
            "15m",
            "--until",
            "1000000",
            "-n",
            "25",
            "--format",
            "ndjson",
            "--fields",
            "--newest-first",
        ])
        .unwrap();
        let p: Vec<(&str, &str)> = cli
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            p,
            [
                ("q", "disk error"),
                ("host", "web1"),
                ("level", "4"),
                ("f", "status>=500"),
                ("f", "act:block"),
                ("re", "t(im|o)e"),
                ("tag", "prod"),
                ("trace", "4BF9"),
                ("since", "999100000"),
                ("until", "1000000000"),
            ]
        );
        assert_eq!(
            (cli.limit, cli.format, cli.fields, cli.newest_first),
            (Some(25), Format::Ndjson, true, true)
        );
        assert_eq!(query_string(&cli.params[..2]), "q=disk%20error&host=web1");
        assert_eq!(
            query_string(&[("f".into(), "a>=1&b".into())]),
            "f=a%3E%3D1%26b"
        );
    }

    #[test]
    fn levels_urls_tokens_and_errors() {
        assert_eq!(
            parse(&["--url", "u", "--level", "error"]).unwrap().params[0].1,
            "3"
        );
        assert_eq!(
            parse(&["--url", "u", "--level", "7"]).unwrap().params[0].1,
            "7"
        );
        let with_env = Cli::from_args(
            &args(&["-q", "x"]),
            &|k| match k {
                "LOGPIT_URL" => Some("http://env:8080".into()),
                "LOGPIT_TOKEN" => Some("sekret".into()),
                _ => None,
            },
            0,
        )
        .unwrap();
        assert_eq!(
            (with_env.url.as_str(), with_env.token.as_deref()),
            ("http://env:8080", Some("sekret"))
        );
        for bad in [
            vec!["-q", "x"],
            vec!["--url", "u", "--level", "loud"],
            vec!["--url", "u", "--limit", "0"],
            vec!["--url", "u", "--limit", "99999999"],
            vec!["--url", "u", "--format", "xml"],
            vec!["--url", "u", "--since", "yesterday"],
            vec!["--url", "u", "--bogus"],
            vec!["--url"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn when_accepts_durations_and_absolute_times() {
        let now = 1_791_028_800_000;
        assert_eq!(parse_when("2h", now).unwrap(), now - 7_200_000);
        assert_eq!(parse_when("1h30m", now).unwrap(), now - 5_400_000);
        assert_eq!(
            parse_when("2026-10-03T10:00:00Z", now).unwrap(),
            1_791_021_600_000
        );
        assert_eq!(parse_when("1791021600", now).unwrap(), 1_791_021_600_000);
        assert_eq!(parse_when("1791021600000", now).unwrap(), 1_791_021_600_000);
        assert!(parse_when("nope", now).is_err());
    }

    #[test]
    fn entries_print_as_text_with_optional_fields() {
        let e = json!({"ts": 1_791_028_800_123i64, "host": "web1", "app": "nginx", "severity": 3,
                       "message": "boom\nsecond line", "fields": {"status": "502", "n": 7}});
        assert_eq!(
            format_text(&e, false),
            "2026-10-03T12:00:00.123Z web1 nginx err boom\n    second line"
        );
        assert_eq!(
            format_text(&e, true),
            "2026-10-03T12:00:00.123Z web1 nginx err boom\n    second line  {n=7 status=502}"
        );
        let bare = json!({"ts": 0, "host": "h", "app": "", "severity": 6, "message": "m"});
        assert_eq!(
            format_text(&bare, true),
            "1970-01-01T00:00:00.000Z h - info m"
        );
        let cli = parse(&["--url", "u", "--format", "json"]).unwrap();
        assert_eq!(
            render(std::slice::from_ref(&bare), &cli).unwrap(),
            format!("[{bare}]\n")
        );
        let cli = parse(&["--url", "u", "--format", "ndjson"]).unwrap();
        assert_eq!(
            render(&[bare.clone(), bare.clone()], &cli)
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn lines_and_sse_events_are_followed() {
        let mut lines = Lines::default();
        assert!(lines.push(b"data: {\"a\"").is_empty());
        assert_eq!(
            lines.push(b":1}\r\n\r\nevent: lagged\ndata: 12\n"),
            ["data: {\"a\":1}", "", "event: lagged", "data: 12"]
        );
        let mut p = SseParser::default();
        assert_eq!(p.line("data: {\"a\":1}"), Sse::Entry(json!({"a": 1})));
        assert_eq!(p.line(""), Sse::Ignore);
        assert_eq!(p.line(": keep-alive"), Sse::Ignore);
        assert_eq!(p.line("event: lagged"), Sse::Ignore);
        assert_eq!(p.line("data: 12"), Sse::Lagged(12));
        // The event name applies to one data line only.
        assert_eq!(p.line("data: {\"b\":2}"), Sse::Entry(json!({"b": 2})));
        assert_eq!(p.line("data: not json"), Sse::Ignore);
    }

    /// A server answering `/api/logs` pages and holding `/api/tail` open with some events.
    async fn server(
        pages: Vec<(String, Option<String>)>,
        tail_events: Vec<String>,
        tail_status: u16,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let h = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut page = 0;
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                }
                let head = String::from_utf8_lossy(&seen).to_string();
                let line = head.lines().next().unwrap_or("").to_string();
                requests.push(line.clone());
                if line.contains("/api/tail") {
                    if tail_status != 200 {
                        let _ = s
                            .write_all(
                                format!(
                                    "HTTP/1.1 {tail_status} X\r\nContent-Length: 4\r\n\r\nnope"
                                )
                                .as_bytes(),
                            )
                            .await;
                        continue;
                    }
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await;
                    for ev in &tail_events {
                        let body = format!("{ev}\n\n");
                        let _ = s
                            .write_all(format!("{:x}\r\n{body}\r\n", body.len()).as_bytes())
                            .await;
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    let (body, cursor) = pages.get(page).cloned().unwrap_or(("[]".into(), None));
                    page += 1;
                    let extra = cursor
                        .map(|c| format!("X-Next-Cursor: {c}\r\n"))
                        .unwrap_or_default();
                    let _ = s
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{extra}\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            }
            requests
        });
        (url, h)
    }

    fn entries(from: i64, to: i64) -> String {
        let list: Vec<Value> = (from..=to)
            .rev()
            .map(|i| json!({"ts": i * 1000, "host": "h", "app": "a", "severity": 6, "message": format!("m{i}")}))
            .collect();
        serde_json::to_string(&list).unwrap()
    }

    #[tokio::test]
    async fn search_pages_through_the_cursor_and_prints_oldest_first() {
        let page1 = entries(1001, 2000); // 1000 entries, newest first
        let (url, server) = server(
            vec![(page1, Some("1001000:5".into())), (entries(1, 3), None)],
            vec![],
            200,
        )
        .await;
        let cli = Cli {
            url,
            ..parse(&["--url", "u", "-n", "1003", "-q", "x y"]).unwrap()
        };
        let mut out = Vec::new();
        let n = search(&cli, &mut out).await.unwrap();
        assert_eq!(n, 1003);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1003);
        assert!(
            lines[0].ends_with("m1") && lines[1002].ends_with("m2000"),
            "{} / {}",
            lines[0],
            lines[1002]
        );
        server.abort();
    }

    #[tokio::test]
    async fn search_reports_a_refused_token_and_prints_newest_first_on_request() {
        let (url, _s) = server(vec![(entries(1, 2), None)], vec![], 200).await;
        let cli = Cli {
            url,
            newest_first: true,
            ..parse(&["--url", "u"]).unwrap()
        };
        let mut out = Vec::new();
        search(&cli, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.lines().next().unwrap().ends_with("m2"));
        // A server that answers 401.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let cli = Cli {
            url,
            ..parse(&["--url", "u"]).unwrap()
        };
        let err = search(&cli, &mut Vec::new()).await.unwrap_err().to_string();
        assert!(err.contains("read token"), "{err}");
    }

    #[tokio::test]
    async fn tail_prints_the_history_then_the_live_entries() {
        let live = |i: i64| {
            format!(
                "data: {{\"ts\":{},\"host\":\"h\",\"app\":\"a\",\"severity\":4,\"message\":\"live{i}\"}}",
                i * 1000
            )
        };
        let (url, server) = server(
            vec![(entries(8, 10), None)],
            vec![
                ": hello".to_string(),
                live(11),
                "event: lagged\ndata: 3".to_string(),
                live(12),
            ],
            200,
        )
        .await;
        let cli = Cli {
            url,
            limit: Some(3),
            ..parse(&["--url", "u", "--level", "warn"]).unwrap()
        };
        let mut out = Vec::new();
        tail(&cli, &mut out, Some(2)).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        let msgs: Vec<&str> = text
            .lines()
            .map(|l| l.rsplit(' ').next().unwrap())
            .collect();
        assert_eq!(msgs, ["m8", "m9", "m10", "live11", "live12"]);
        server.abort();
    }

    #[tokio::test]
    async fn tail_gives_up_on_a_refusal_and_on_an_unreachable_server_at_first() {
        let (url, _s) = server(vec![], vec![], 403).await;
        let cli = Cli {
            url,
            ..parse(&["--url", "u"]).unwrap()
        };
        let err = tail(&cli, &mut Vec::new(), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("may not read"), "{err}");
        let cli = Cli {
            url: "http://127.0.0.1:1".into(),
            ..parse(&["--url", "u"]).unwrap()
        };
        assert!(tail(&cli, &mut Vec::new(), None).await.is_err());
    }
}
