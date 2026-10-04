//! End-to-end tests of the HTTP API: a real listener, the real router and middleware, a
//! database on disk and the writer thread, driven by plain HTTP/1.0 requests.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use logpit::api::{self, AppState};
use logpit::audit::AuditLog;
use logpit::config::Config;
use logpit::ingest::Sink;
use logpit::live::LiveSettings;
use logpit::metrics::Metrics;
use logpit::silence::Tracker;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "admin-token";
const WRITER: &str = "write-token";
const READER: &str = "read-token";
const WEB_ONLY: &str = "web-only-token";

const TOKENS: &str = r#"
[http]
token = "admin-token"

[[http.tokens]]
token = "write-token"
name = "shipper"
scopes = ["write"]

[[http.tokens]]
token = "read-token"
name = "viewer"
scopes = ["read"]

[[http.tokens]]
token = "web-only-token"
name = "web-team"
scopes = ["read"]
hosts = ["web*"]
"#;

struct Server {
    alerts: Arc<logpit::alertlog::AlertLog>,
    addr: SocketAddr,
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    writer: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start(extra_toml: &str) -> Server {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "logpit-http-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("t.db");
    let toml = format!(
        "[storage]\npath = {:?}\nflush_interval_ms = 10\n{extra_toml}",
        db.display().to_string()
    );
    let cfg: Config = toml::from_str(&toml).unwrap();
    cfg.validate().unwrap();

    let settings = Arc::new(LiveSettings::from_config(&cfg).unwrap());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = std::sync::mpsc::sync_channel(cfg.storage.queue_capacity);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (conn, metrics, stop) = (
            logpit::store::open(&db).unwrap(),
            metrics.clone(),
            stop.clone(),
        );
        let (batch, flush) = (
            cfg.storage.batch_size,
            Duration::from_millis(cfg.storage.flush_interval_ms),
        );
        std::thread::spawn(move || logpit::store::run_writer(conn, rx, batch, flush, metrics, stop))
    };
    let sink = Sink::new(
        tx,
        metrics,
        cfg.storage.max_message_bytes,
        Arc::new(Tracker::new(false)),
    )
    .with_settings(settings.clone());
    let alerts = Arc::new(logpit::alertlog::AlertLog::default());
    let state = AppState {
        sink,
        db_path: db,
        settings,
        exports: Arc::new(tokio::sync::Semaphore::new(api::MAX_EXPORTS)),
        audit: Arc::new(AuditLog::default()),
        alerts: alerts.clone(),
    };
    let app = api::router(state, cfg.http.max_body_bytes);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Server {
        alerts,
        addr,
        dir,
        stop,
        writer: Some(writer),
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// One HTTP/1.0 request (so the response is never chunked and ends when the connection closes);
/// a body is sent as JSON.
async fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.0\r\nHost: test\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    // A request refused before its body is read ends with a reset once the answer is sent: keep
    // what arrived.
    let mut raw = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response timed out");
    assert!(read.is_ok() || !raw.is_empty(), "no response: {read:?}");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Reply {
        status,
        head: head.to_string(),
        body: body.to_string(),
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn get(addr: SocketAddr, path: &str, token: &str) -> Reply {
    call(addr, "GET", path, Some(&bearer(token)), b"").await
}

/// Waits until a search with `path` returns `n` entries (the writer flushes asynchronously).
async fn wait_for(addr: SocketAddr, path: &str, n: usize) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let r = get(addr, path, ADMIN).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let v = r.json();
        if v.as_array().map(Vec::len) == Some(n) {
            return v;
        }
        assert!(Instant::now() < deadline, "expected {n} entries, got {v}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn ingest(addr: SocketAddr, ndjson: &str) -> Reply {
    call(
        addr,
        "POST",
        "/ingest",
        Some(&bearer(WRITER)),
        ndjson.as_bytes(),
    )
    .await
}

#[tokio::test]
async fn every_route_enforces_its_scope() {
    let s = start(TOKENS).await;
    let a = s.addr;
    let none = |path: &'static str, method: &'static str| async move {
        call(a, method, path, None, b"").await.status
    };
    let with = |path: &'static str, method: &'static str, token: &'static str| async move {
        call(a, method, path, Some(&bearer(token)), b"")
            .await
            .status
    };

    // Open endpoints.
    assert_eq!(none("/healthz", "GET").await, 200);
    assert_eq!(none("/metrics", "GET").await, 200);
    assert_eq!(none("/", "GET").await, 200);

    // Missing or unknown tokens are 401 everywhere else.
    for path in [
        "/api/logs",
        "/api/tail",
        "/api/audit",
        "/loki/api/v1/labels",
    ] {
        assert_eq!(none(path, "GET").await, 401, "{path}");
        assert_eq!(with(path, "GET", "wrong").await, 401, "{path}");
    }
    assert_eq!(none("/ingest", "POST").await, 401);

    // Read endpoints: read and admin tokens yes, write-only no.
    for path in [
        "/api/logs",
        "/api/stats",
        "/api/hosts",
        "/api/fields",
        "/api/patterns",
        "/api/tags",
        "/api/top?field=host",
        "/loki/api/v1/labels",
        "/loki/api/v1/label/host/values",
        "/loki/api/v1/series",
    ] {
        assert_eq!(with(path, "GET", READER).await, 200, "{path}");
        assert_eq!(with(path, "GET", ADMIN).await, 200, "{path}");
        assert_eq!(with(path, "GET", WRITER).await, 403, "{path}");
    }

    // Ingestion: write and admin tokens yes, read-only no.
    assert_eq!(ingest(a, r#"{"message":"m"}"#).await.status, 200);
    let as_reader = bearer(READER);
    let r = call(
        a,
        "POST",
        "/ingest",
        Some(&as_reader),
        br#"{"message":"m"}"#,
    )
    .await;
    assert_eq!(r.status, 403);

    // Admin endpoints: only the admin token.
    for path in ["/api/audit", "/api/tokens"] {
        assert_eq!(with(path, "GET", READER).await, 403, "{path}");
        assert_eq!(with(path, "GET", WRITER).await, 403, "{path}");
        assert_eq!(with(path, "GET", ADMIN).await, 200, "{path}");
    }

    // The token list names tokens and never shows the secrets.
    let tokens = get(a, "/api/tokens", ADMIN).await;
    assert!(tokens.body.contains("web-team"));
    for secret in [ADMIN, WRITER, READER, WEB_ONLY] {
        assert!(!tokens.body.contains(secret), "{secret} leaked");
    }

    // Loki clients authenticate with Basic credentials whose password is the token.
    let basic = "Basic dXNlcjp3cml0ZS10b2tlbg=="; // user:write-token
    let push = br#"{"streams":[{"stream":{"host":"h"},"values":[["1700000000000000000","x"]]}]}"#;
    let r = call(a, "POST", "/loki/api/v1/push", Some(basic), push).await;
    assert_eq!(r.status, 204, "{}", r.body);
}

#[tokio::test]
async fn refused_requests_reach_the_audit_trail() {
    let s = start(TOKENS).await;
    assert_eq!(get(s.addr, "/api/audit", READER).await.status, 403);
    assert_eq!(get(s.addr, "/api/logs", "nope").await.status, 401);
    let trail = get(s.addr, "/api/audit?refused=true", ADMIN).await.json();
    let events = trail.as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["path"] == "/api/audit" && e["status"] == 403 && e["token"] == "viewer"),
        "{trail}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["path"] == "/api/logs" && e["status"] == 401),
        "{trail}"
    );
}

#[tokio::test]
async fn ingested_entries_can_be_searched() {
    let s = start(TOKENS).await;
    let r = ingest(
        s.addr,
        "{\"host\":\"web1\",\"app\":\"nginx\",\"severity\":3,\"message\":\"upstream timed out\",\"fields\":{\"status\":504}}\n\
         not json\n\
         {\"_HOSTNAME\":\"db1\",\"SYSLOG_IDENTIFIER\":\"postgres\",\"MESSAGE\":\"checkpoint complete\"}\n",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({"accepted": 2, "rejected": 1}));

    let all = wait_for(s.addr, "/api/logs", 2).await;
    assert_eq!(all[0]["message"], "checkpoint complete", "newest first");

    let hits = get(
        s.addr,
        "/api/logs?q=upstream&level=3&f=status%3E%3D500",
        READER,
    )
    .await;
    assert_eq!(hits.status, 200);
    let hits = hits.json();
    assert_eq!(hits.as_array().unwrap().len(), 1, "{hits}");
    assert_eq!(hits[0]["host"], "web1");

    let paged = get(s.addr, "/api/logs?limit=1", READER).await;
    let cursor = paged
        .header("x-next-cursor")
        .expect("a full page has a cursor");
    let next = get(
        s.addr,
        &format!("/api/logs?limit=1&before={cursor}"),
        READER,
    )
    .await;
    assert_eq!(next.json()[0]["host"], "web1");

    // Malformed parameters are client errors, not server errors.
    for bad in ["level=x", "before=1", "re=(", "f=", "since=yesterday"] {
        let r = get(s.addr, &format!("/api/logs?{bad}"), READER).await;
        assert!(r.status == 400 || r.status == 200, "{bad}: {}", r.status);
    }
    assert_eq!(get(s.addr, "/api/logs?re=(", READER).await.status, 400);
}

#[tokio::test]
async fn hostile_search_text_is_never_a_server_error() {
    let s = start("").await;
    ingest(s.addr, r#"{"message":"plain message"}"#).await;
    wait_for(s.addr, "/api/logs", 1).await;
    for q in [
        "%00",
        "a%00b",
        "%22%00%22",
        "NEAR(",
        "%22",
        "*",
        "-",
        "col%3Aval",
    ] {
        let r = get(s.addr, &format!("/api/logs?q={q}"), "").await;
        assert_eq!(r.status, 200, "q={q}: {}", r.body);
    }
}

#[tokio::test]
async fn the_alert_history_is_served_and_limited_to_the_hosts_of_the_token() {
    use logpit::alertlog::AlertEntry;
    let s = start(TOKENS).await;
    let entry = |ts: i64, kind: &str, host: Option<&str>, delivered: Option<bool>| AlertEntry {
        ts,
        kind: kind.into(),
        host: host.map(String::from),
        message: format!("{kind} {ts}"),
        delivered,
        email: None,
        details: serde_json::json!({"event": kind}),
    };
    for e in [
        entry(1, "host_silent", Some("web1"), Some(true)),
        entry(2, "volume_surge", Some("db1"), Some(false)),
        entry(3, "log_alert", None, None),
        entry(4, "new_pattern", Some("web2"), None),
    ] {
        s.alerts.record(e).await;
    }
    let all = get(s.addr, "/api/alerts", READER).await;
    assert_eq!(all.status, 200, "{}", all.body);
    let kinds: Vec<String> = all
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        kinds,
        ["new_pattern", "log_alert", "volume_surge", "host_silent"]
    );
    // Delivery is reported, and absent when there was no webhook.
    let first = &all.json()[2];
    assert_eq!(first["delivered"], false);
    assert!(all.json()[0].get("delivered").is_none());
    // Filters.
    let by = |q: &str| {
        let q = q.to_string();
        let addr = s.addr;
        async move {
            get(addr, &format!("/api/alerts?{q}"), READER)
                .await
                .json()
                .as_array()
                .unwrap()
                .len()
        }
    };
    assert_eq!(by("kind=host_silent").await, 1);
    assert_eq!(by("host=db1").await, 1);
    assert_eq!(by("since=3").await, 2);
    assert_eq!(by("until=2").await, 2);
    assert_eq!(by("limit=1").await, 1);
    assert_eq!(get(s.addr, "/api/alerts?limit=0", READER).await.status, 400);
    assert_eq!(get(s.addr, "/api/alerts?since=x", READER).await.status, 400);
    // A token limited to web* sees the alerts about web hosts, and not the host-less one.
    let web = get(s.addr, "/api/alerts", WEB_ONLY).await.json();
    let hosts: Vec<&str> = web
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["host"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, ["web2", "web1"]);
    // Scopes: the write token cannot read them, a missing token is refused.
    assert_eq!(get(s.addr, "/api/alerts", WRITER).await.status, 403);
    assert_eq!(
        call(s.addr, "GET", "/api/alerts", None, b"").await.status,
        401
    );
}

#[tokio::test]
async fn a_restricted_token_only_reads_its_hosts() {
    let s = start(TOKENS).await;
    ingest(
        s.addr,
        "{\"host\":\"web1\",\"app\":\"nginx\",\"message\":\"web entry\"}\n\
         {\"host\":\"db1\",\"app\":\"postgres\",\"message\":\"db entry\"}\n",
    )
    .await;
    let all = wait_for(s.addr, "/api/logs", 2).await;
    let db_id = all
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["host"] == "db1")
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    let logs = get(s.addr, "/api/logs", WEB_ONLY).await.json();
    assert_eq!(logs.as_array().unwrap().len(), 1);
    assert_eq!(logs[0]["host"], "web1");
    // Asking for the other host explicitly does not get around the restriction.
    let other = get(s.addr, "/api/logs?host=db1", WEB_ONLY).await.json();
    assert_eq!(other.as_array().unwrap().len(), 0);

    let hosts = get(s.addr, "/api/hosts", WEB_ONLY).await.json();
    assert_eq!(hosts.as_array().unwrap().len(), 1);
    assert_eq!(hosts[0]["host"], "web1");

    let values = get(s.addr, "/loki/api/v1/label/host/values", WEB_ONLY).await;
    assert_eq!(values.json()["data"], serde_json::json!(["web1"]));

    let export = get(s.addr, "/api/export", WEB_ONLY).await;
    assert_eq!(export.status, 200);
    assert!(export.body.contains("web entry") && !export.body.contains("db entry"));

    let ctx = get(s.addr, &format!("/api/logs/{db_id}/context"), WEB_ONLY).await;
    assert_eq!(ctx.status, 404, "an entry it may not read looks absent");
    let ctx = get(s.addr, &format!("/api/logs/{db_id}/context"), READER).await;
    assert_eq!(ctx.status, 200);

    // Saved views are shared, so a restricted token neither lists nor writes them.
    assert_eq!(get(s.addr, "/api/views", WEB_ONLY).await.status, 403);
    let save = call(
        s.addr,
        "POST",
        "/api/views",
        Some(&bearer(WEB_ONLY)),
        br#"{"name":"x","query":"host=db1"}"#,
    )
    .await;
    assert_eq!(save.status, 403);
}

#[tokio::test]
async fn oversized_names_and_bodies_are_bounded() {
    let s = start("[http]\nmax_body_bytes = 4096\n").await;
    let long_host = "h".repeat(10_000);
    let r = ingest(
        s.addr,
        &format!("{{\"host\":\"{long_host}\",\"app\":\"{long_host}\",\"message\":\"m\"}}"),
    )
    .await;
    assert_eq!(r.status, 413, "the body is over max_body_bytes");

    let long_host = "h".repeat(1000);
    let r = ingest(
        s.addr,
        &format!("{{\"host\":\"{long_host}\",\"app\":\"a\",\"message\":\"m\"}}"),
    )
    .await;
    assert_eq!(r.status, 200);
    let stored = wait_for(s.addr, "/api/logs", 1).await;
    assert_eq!(
        stored[0]["host"].as_str().unwrap().len(),
        logpit::ingest::MAX_NAME_BYTES
    );
}

#[tokio::test]
async fn the_board_host_admin_and_compare_views_are_served_like_the_main_page() {
    let s = start("").await;
    for path in ["/board", "/host/pve", "/host/a%20b", "/admin", "/compare"] {
        let r = call(s.addr, "GET", path, None, b"").await;
        assert_eq!(r.status, 200, "{path}");
        assert!(
            r.body.contains("<title>LogPit</title>") && r.body.contains("</script>"),
            "{path}"
        );
        // The shared theme is put in, and the page keeps the main page's protections.
        assert!(r.body.contains("--ground:#ffffff;"), "{path}");
        let csp = r.header("content-security-policy").unwrap();
        assert!(csp.contains("default-src 'none'"), "{path}");
    }
}

#[tokio::test]
async fn the_web_ui_is_gzipped_for_browsers_that_accept_it() {
    let s = start("").await;
    let mut stream = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: test\r\nAccept-Encoding: gzip, br\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    assert!(head.contains("content-encoding: gzip"), "{head}");
    assert!(head.contains("vary: accept-encoding") && head.contains("content-security-policy"));
    let page = logpit::inflate::gunzip(&raw[split + 4..], 1 << 20).unwrap();
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("<title>LogPit</title>") && page.contains("</script>"));
}

#[tokio::test]
async fn the_web_ui_is_served_with_protective_headers() {
    let s = start("").await;
    let r = call(s.addr, "GET", "/", None, b"").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("<title>"));
    let csp = r.header("content-security-policy").unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("connect-src 'self'"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
}

#[tokio::test]
async fn extreme_numbers_are_never_a_server_error() {
    let s = start("").await;
    ingest(s.addr, r#"{"message":"m","fields":{"n":"5"}}"#).await;
    wait_for(s.addr, "/api/logs", 1).await;
    const MIN: &str = "-9223372036854775808";
    const MAX: &str = "9223372036854775807";
    let paths = [
        format!("/api/logs?since={MIN}&until={MAX}"),
        format!("/api/logs?before={MAX}:{MIN}&limit={MAX}"),
        format!("/api/stats?since={MIN}&until={MAX}"),
        format!("/api/stats?since={MIN}"),
        format!("/api/stats?until={MIN}"),
        format!("/api/stats?since={MIN}&until={MAX}&bucket=99999999999999d"),
        format!("/api/stats?since=0&until={MAX}&bucket=1d"),
        format!("/api/hosts?since={MIN}&until={MAX}&limit={MAX}"),
        format!("/api/top?field=host&since={MIN}&limit={MAX}"),
        format!("/api/patterns?since={MIN}&until={MAX}"),
        format!("/api/logs/{MAX}/context?lines={MAX}"),
        format!("/api/logs/{MIN}/context"),
        format!("/api/export?since={MIN}&limit={MAX}"),
        "/api/logs?f=n%3E1e308".to_string(),
        "/api/logs?f=n%3C-1e400".to_string(),
        format!("/loki/api/v1/query_range?query=%7Bhost%3D~%22.*%22%7D&start={MIN}&end={MAX}"),
        format!(
            "/loki/api/v1/query_range?query=count_over_time(%7Bhost%3D~%22.*%22%7D%5B5m%5D)&start=0&end={MAX}&step=1"
        ),
        format!(
            "/loki/api/v1/query_range?query=rate(%7Bhost%3D~%22.*%22%7D%5B99999999w%5D)&start={MIN}&end={MAX}&step={MAX}"
        ),
        format!(
            "/loki/api/v1/query?query=count_over_time(%7Bhost%3D~%22.*%22%7D%5B5m%5D)&time={MAX}"
        ),
        format!(
            "/loki/api/v1/query?query=count_over_time(%7Bhost%3D~%22.*%22%7D%5B5m%5D)&time={MIN}"
        ),
        format!("/loki/api/v1/labels?start={MIN}&end={MAX}"),
        format!("/loki/api/v1/series?start={MAX}&end={MIN}"),
        format!("/api/audit?since={MIN}&until={MAX}&limit={MAX}"),
    ];
    for path in paths {
        let r = get(s.addr, &path, "").await;
        assert!(r.status < 500, "{path}: {} {}", r.status, r.body);
    }
}

// ---- OTLP over gRPC -------------------------------------------------------------------------

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn pb(field: u32, payload: &[u8], out: &mut Vec<u8>) {
    varint(u64::from(field << 3 | 2), out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn string_attr(key: &str, value: &str) -> Vec<u8> {
    let mut any = Vec::new();
    pb(1, value.as_bytes(), &mut any);
    let mut kv = Vec::new();
    pb(1, key.as_bytes(), &mut kv);
    pb(2, &any, &mut kv);
    kv
}

/// An `ExportLogsServiceRequest` with one record from `host`, written independently of the decoder.
fn export_request(host: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    pb(1, message.as_bytes(), &mut body);
    let mut record = Vec::new();
    varint(2 << 3, &mut record); // severity_number
    varint(17, &mut record); // ERROR
    pb(5, &body, &mut record);
    let mut scope_logs = Vec::new();
    pb(2, &record, &mut scope_logs);
    let mut resource = Vec::new();
    pb(1, &string_attr("host.name", host), &mut resource);
    pb(1, &string_attr("service.name", "checkout"), &mut resource);
    let mut resource_logs = Vec::new();
    pb(1, &resource, &mut resource_logs);
    pb(2, &scope_logs, &mut resource_logs);
    let mut request = Vec::new();
    pb(1, &resource_logs, &mut request);
    request
}

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

struct GrpcReply {
    http: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
    trailers: Option<http::HeaderMap>,
}

impl GrpcReply {
    /// `grpc-status` from the trailers, or from the headers of a trailers-only answer.
    fn status(&self) -> Option<String> {
        let from = |h: &http::HeaderMap| {
            h.get("grpc-status")
                .map(|v| v.to_str().unwrap().to_string())
        };
        self.trailers
            .as_ref()
            .and_then(from)
            .or_else(|| from(&self.headers))
    }
}

/// One unary gRPC call over cleartext HTTP/2.
async fn grpc(
    addr: SocketAddr,
    content_type: &str,
    auth: Option<&str>,
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> GrpcReply {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut client, connection) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(connection);
    let mut req = http::Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{}", logpit::grpc::LOGS_EXPORT_PATH))
        .header("content-type", content_type)
        .header("te", "trailers");
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let (response, mut stream) = client.send_request(req.body(()).unwrap(), false).unwrap();
    stream.send_data(bytes::Bytes::from(body), true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("no response")
        .unwrap();
    let (parts, mut recv) = response.into_parts();
    let mut data = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.unwrap();
        let _ = recv.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
    }
    GrpcReply {
        http: parts.status.as_u16(),
        headers: parts.headers,
        body: data,
        trailers: recv.trailers().await.unwrap(),
    }
}

#[tokio::test]
async fn otlp_logs_arrive_over_grpc_with_a_status_in_the_trailers() {
    let s = start(TOKENS).await;
    let write = bearer(WRITER);
    let r = grpc(
        s.addr,
        "application/grpc",
        Some(&write),
        &[],
        grpc_frame(&export_request("node-7", "disk full over grpc")),
    )
    .await;
    assert_eq!(r.http, 200);
    assert_eq!(r.headers.get("content-type").unwrap(), "application/grpc");
    assert_eq!(
        r.status().as_deref(),
        Some("0"),
        "{:?} {:?}",
        r.headers,
        r.trailers
    );
    assert!(r.trailers.is_some(), "the status travels as a trailer");
    // One empty response message.
    assert_eq!(r.body, [0, 0, 0, 0, 0]);
    let logs = wait_for(s.addr, "/api/logs?q=disk", 1).await;
    assert_eq!(logs[0]["host"], "node-7");
    assert_eq!(logs[0]["app"], "checkout");
    assert_eq!(logs[0]["severity"], 3);
    // The `+proto` flavour and a gzip-compressed message are accepted as well.
    let gz = logpit::archive::gzip_member(&export_request("node-8", "second over grpc"));
    let mut framed = vec![1];
    framed.extend_from_slice(&(gz.len() as u32).to_be_bytes());
    framed.extend_from_slice(&gz);
    let r = grpc(
        s.addr,
        "application/grpc+proto",
        Some(&write),
        &[("grpc-encoding", "gzip")],
        framed,
    )
    .await;
    assert_eq!(r.status().as_deref(), Some("0"));
    wait_for(s.addr, "/api/logs?q=second", 1).await;
}

#[tokio::test]
async fn grpc_calls_are_authenticated_and_malformed_ones_say_why() {
    let s = start(TOKENS).await;
    let good = grpc_frame(&export_request("h", "never stored"));
    // No token, and a token that may only read: refused before the call, with HTTP statuses that
    // gRPC clients map to UNAUTHENTICATED and PERMISSION_DENIED.
    assert_eq!(
        grpc(s.addr, "application/grpc", None, &[], good.clone())
            .await
            .http,
        401
    );
    assert_eq!(
        grpc(
            s.addr,
            "application/grpc",
            Some(&bearer(READER)),
            &[],
            good.clone()
        )
        .await
        .http,
        403
    );
    let write = bearer(WRITER);
    // Not gRPC at all.
    assert_eq!(
        grpc(s.addr, "application/json", Some(&write), &[], good.clone())
            .await
            .http,
        415
    );
    // gRPC with something wrong inside: HTTP 200 and the reason in `grpc-status`.
    let bad = grpc(
        s.addr,
        "application/grpc",
        Some(&write),
        &[],
        vec![0, 0, 0, 0, 9, 1],
    )
    .await;
    assert_eq!((bad.http, bad.status().as_deref()), (200, Some("3")));
    assert!(bad.headers.get("grpc-message").is_some());
    let garbage = grpc(
        s.addr,
        "application/grpc",
        Some(&write),
        &[],
        grpc_frame(&[0xff, 0xff, 0xff]),
    )
    .await;
    assert_eq!(garbage.status().as_deref(), Some("3"));
    let unsupported = grpc(
        s.addr,
        "application/grpc",
        Some(&write),
        &[("grpc-encoding", "snappy")],
        {
            let mut f = vec![1, 0, 0, 0, 1, 0];
            f.truncate(6);
            f
        },
    )
    .await;
    assert_eq!(unsupported.status().as_deref(), Some("12"));
    // Nothing of that was stored, and the rejections are counted.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        get(s.addr, "/api/logs", ADMIN)
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn a_token_over_its_quota_gets_429_until_the_budget_is_back() {
    let cfg = format!(
        "{TOKENS}\n[[http.tokens]]\ntoken = \"capped-token\"\nname = \"capped\"\nscopes = [\"write\"]\nevents_per_day = 3\n"
    );
    let s = start(&cfg).await;
    let line = |m: &str| format!("{{\"host\":\"h\",\"app\":\"a\",\"message\":\"{m}\"}}\n");
    let send = |body: String| {
        let addr = s.addr;
        async move {
            call(
                addr,
                "POST",
                "/ingest",
                Some(&bearer("capped-token")),
                body.as_bytes(),
            )
            .await
        }
    };
    // Charged after the request: two events leave one in the budget, the next request of two
    // goes through and overshoots, then the token is refused.
    assert_eq!(send(line("one") + &line("two")).await.status, 200);
    assert_eq!(send(line("three") + &line("four")).await.status, 200);
    let refused = send(line("five")).await;
    assert_eq!(refused.status, 429, "{}", refused.body);
    assert!(
        refused.head.to_ascii_lowercase().contains("retry-after: "),
        "{}",
        refused.head
    );
    // Other tokens are not affected and what was accepted is searchable.
    assert_eq!(ingest(s.addr, &line("six")).await.status, 200);
    wait_for(s.addr, "/api/logs", 5).await;
    let metrics = call(s.addr, "GET", "/metrics", None, b"").await.body;
    assert!(metrics.contains("logpit_quota_rejected_total{token=\"capped\"} 1"));
    // The token list shows the quota.
    let tokens = get(s.addr, "/api/tokens", ADMIN).await.json();
    let capped = tokens
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "capped")
        .unwrap();
    assert_eq!(capped["events_per_day"], 3);
}

#[tokio::test]
async fn maintenance_windows_are_managed_by_admins() {
    let cfg = format!(
        "{TOKENS}\n[[maintenance]]\nhosts = [\"db*\"]\nreason = \"nightly\"\nbetween = \"02:00-04:00\"\ndays = [\"sun\"]\n"
    );
    let s = start(&cfg).await;
    let send = |method: &'static str, path: String, token: &'static str, body: String| {
        let addr = s.addr;
        async move { call(addr, method, &path, Some(&bearer(token)), body.as_bytes()).await }
    };
    let make = |body: &str| send("POST", "/api/maintenance".into(), ADMIN, body.into());
    // Only admins manage windows.
    for token in [READER, WRITER] {
        let r = send("GET", "/api/maintenance".into(), token, String::new()).await;
        assert_eq!(r.status, 403, "{token}");
        let r = send("POST", "/api/maintenance".into(), token, "{}".into()).await;
        assert_eq!(r.status, 403, "{token}");
    }
    let created = make(r#"{"hosts":["web*"],"minutes":30,"reason":"deploy"}"#).await;
    assert_eq!(created.status, 201, "{}", created.body);
    let window = created.json();
    assert_eq!(
        (window["source"].as_str(), window["active"].as_bool()),
        (Some("api"), Some(true))
    );
    let id = window["id"].as_u64().unwrap();
    for bad in [
        r#"{"hosts":[],"minutes":30}"#,
        r#"{"hosts":["a"],"minutes":0}"#,
        r#"{"hosts":["a"],"minutes":999999}"#,
        r#"{"hosts":["a"],"minutes":5,"extra":1}"#,
        "not json",
    ] {
        assert!(make(bad).await.status >= 400, "{bad}");
    }
    let listed = send("GET", "/api/maintenance".into(), ADMIN, String::new())
        .await
        .json();
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["source"], "config");
    assert_eq!(listed[0]["between"], "02:00-04:00");
    assert_eq!(listed[0]["days"], serde_json::json!(["sun"]));
    assert_eq!(listed[1]["id"].as_u64(), Some(id));
    let gone = send(
        "DELETE",
        format!("/api/maintenance/{id}"),
        ADMIN,
        String::new(),
    )
    .await;
    assert_eq!(gone.status, 204);
    let again = send(
        "DELETE",
        format!("/api/maintenance/{id}"),
        ADMIN,
        String::new(),
    )
    .await;
    assert_eq!(again.status, 404);
    let listed = send("GET", "/api/maintenance".into(), ADMIN, String::new())
        .await
        .json();
    assert_eq!(listed.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn one_search_finds_a_trace_across_hosts_whatever_its_id_is_called() {
    let s = start(TOKENS).await;
    let body = [
        r#"{"host":"web1","app":"nginx","message":"GET /pay","fields":{"traceId":"4BF92F3577B34DA6A3CE929D0E0E4736"}}"#,
        r#"{"host":"api1","app":"api","message":"charging","fields":{"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00F067AA0BA902B7"}}"#,
        r#"{"host":"db1","app":"pg","message":"INSERT","fields":{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}}"#,
        r#"{"host":"web2","app":"nginx","message":"other request","fields":{"traceId":"ffffffffffffffffffffffffffffffff"}}"#,
    ]
    .join("\n");
    assert_eq!(ingest(s.addr, &body).await.status, 200);
    wait_for(s.addr, "/api/logs", 4).await;
    // Case does not matter, the shorthand and the field filter agree.
    for q in [
        "trace=4bf92f3577b34da6a3ce929d0e0e4736",
        "trace=4BF92F3577B34DA6A3CE929D0E0E4736",
        "f=trace_id:4bf92f3577b34da6a3ce929d0e0e4736",
    ] {
        let hits = get(s.addr, &format!("/api/logs?{q}"), ADMIN).await.json();
        let mut hosts: Vec<&str> = hits
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["host"].as_str().unwrap())
            .collect();
        hosts.sort();
        assert_eq!(hosts, ["api1", "db1", "web1"], "{q}");
    }
    // A blank id is refused, an empty parameter is ignored like the others.
    assert_eq!(get(s.addr, "/api/logs?trace=%20", ADMIN).await.status, 400);
    assert_eq!(get(s.addr, "/api/logs?trace=", ADMIN).await.status, 200);
    // A token limited to web hosts sees only its part of the trace.
    let web = get(
        s.addr,
        "/api/logs?trace=4bf92f3577b34da6a3ce929d0e0e4736",
        WEB_ONLY,
    )
    .await
    .json();
    assert_eq!(web.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn alert_rules_are_created_listed_and_deleted_by_an_admin() {
    let s = start(&format!(
        "{TOKENS}\n[[alerts]]\nname = \"from-config\"\npattern = \"x\"\ncount = 1\nwindow_secs = 60\n"
    ))
    .await;
    let post = |token: &'static str, body: &'static str| async move {
        let auth = format!("Bearer {token}");
        call(
            s.addr,
            "POST",
            "/api/alert-rules",
            Some(&auth),
            body.as_bytes(),
        )
        .await
    };
    let rule = r#"{"name":"disk failing","pattern":"unreadable .* sectors","count":5,"window_secs":600,"per_host":true}"#;
    // Only the admin scope may change them.
    assert_eq!(post(READER, rule).await.status, 403);
    let saved = post(ADMIN, rule).await;
    assert_eq!(saved.status, 201, "{}", saved.body);
    let id = saved.json()["id"].as_i64().unwrap();
    assert_eq!(saved.json()["pattern"], "unreadable .* sectors");
    // Refused: no name, a bad regex, a count of zero, a name the configuration already uses.
    for (body, want) in [
        (r#"{"pattern":"x","count":1,"window_secs":60}"#, 400),
        (
            r#"{"name":"bad","pattern":"(","count":1,"window_secs":60}"#,
            400,
        ),
        (
            r#"{"name":"zero","pattern":"x","count":0,"window_secs":60}"#,
            400,
        ),
        (
            r#"{"name":"from-config","pattern":"x","count":1,"window_secs":60}"#,
            409,
        ),
        (
            r#"{"name":"odd","count":1,"window_secs":60,"color":"red"}"#,
            422,
        ),
    ] {
        assert_eq!(post(ADMIN, body).await.status, want, "{body}");
    }
    let list = get(s.addr, "/api/alert-rules", ADMIN).await;
    assert_eq!(list.status, 200);
    assert_eq!(list.json().as_array().unwrap().len(), 1);
    // The rule runs at once, beside the configuration's, under one metric header.
    let metrics = call(s.addr, "GET", "/metrics", None, b"").await.body;
    assert!(metrics.contains("rule=\"disk failing\"} 0"), "{metrics}");
    assert!(metrics.contains("rule=\"from-config\"} 0"));
    assert_eq!(
        metrics.matches("# TYPE logpit_alerts_fired_total").count(),
        1
    );
    let path = format!("/api/alert-rules/{id}");
    let admin = format!("Bearer {ADMIN}");
    assert_eq!(
        call(s.addr, "DELETE", &path, Some(&admin), b"")
            .await
            .status,
        204
    );
    assert_eq!(
        call(s.addr, "DELETE", &path, Some(&admin), b"")
            .await
            .status,
        404
    );
    let metrics = call(s.addr, "GET", "/metrics", None, b"").await.body;
    assert!(!metrics.contains("disk failing"));
}

#[tokio::test]
async fn alert_rules_are_muted_and_unmuted_by_an_admin() {
    let s = start(&format!(
        "{TOKENS}\n[[alerts]]\nname = \"disk\"\npattern = \"x\"\ncount = 1\nwindow_secs = 60\n"
    ))
    .await;
    let (admin, reader) = (format!("Bearer {ADMIN}"), format!("Bearer {READER}"));
    let post = |auth: String, body: &'static str| async move {
        call(s.addr, "POST", "/api/mutes", Some(&auth), body.as_bytes()).await
    };
    assert_eq!(
        post(reader.clone(), r#"{"rule":"disk","minutes":60}"#)
            .await
            .status,
        403
    );
    assert_eq!(
        post(admin.clone(), r#"{"rule":"nope","minutes":60}"#)
            .await
            .status,
        404
    );
    assert_eq!(
        post(admin.clone(), r#"{"rule":"disk","minutes":20000}"#)
            .await
            .status,
        400
    );
    let muted = post(admin.clone(), r#"{"rule":"disk","minutes":60}"#).await;
    assert_eq!(muted.status, 200, "{}", muted.body);
    assert_eq!(muted.json()["rule"], "disk");
    let list = call(s.addr, "GET", "/api/mutes", Some(&admin), b"")
        .await
        .json();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(
        post(admin.clone(), r#"{"rule":"disk","minutes":0}"#)
            .await
            .status,
        204
    );
    let list = call(s.addr, "GET", "/api/mutes", Some(&admin), b"")
        .await
        .json();
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn the_storage_summary_is_for_admins() {
    // Lines before the first table header belong to [storage].
    let s = start(&format!("retention_days = 7\n{TOKENS}")).await;
    let admin = get(s.addr, "/api/storage", ADMIN).await;
    assert_eq!(admin.status, 200, "{}", admin.body);
    let v = admin.json();
    assert_eq!(v["entries"], 0);
    assert!(v["used_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        (v["retention_days"].as_u64(), v["max_db_size_mb"].as_u64()),
        (Some(7), Some(0))
    );
    assert_eq!(get(s.addr, "/api/storage", READER).await.status, 403);
}
