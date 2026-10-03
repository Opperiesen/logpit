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
    let state = AppState {
        sink,
        db_path: db,
        settings,
        exports: Arc::new(tokio::sync::Semaphore::new(api::MAX_EXPORTS)),
        audit: Arc::new(AuditLog::default()),
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
