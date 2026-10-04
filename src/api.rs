//! HTTP API: JSON ingestion, search, metrics and the embedded web UI.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, Extension, Query as QueryParams, Request, State,
};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::audit::{self, AuditLog};
use crate::auth::{Decision, Identity, Scope};
use crate::export::Format;
use crate::ingest::{Sink, now_ms};
use crate::metrics::Metrics;
use crate::model::LogEntry;
use crate::stats;
use crate::store::{self, GroupBy, HostSort, HostSortKey, Query};

const MAX_LIMIT: usize = 1000;
/// Time bounds are clamped to ±10^15 ms (about 30,000 years either side of 1970): beyond that no
/// entry can exist, and bucket arithmetic on the bounds stays far from overflowing.
const MAX_TS: i64 = 1_000_000_000_000_000;
const DEFAULT_LIMIT: usize = 100;
const MAX_TAIL_SUBSCRIBERS: usize = 32;
const DEFAULT_TOP_VALUES: usize = 10;
const MAX_TOP_VALUES: usize = 100;
const DEFAULT_PATTERNS: usize = 25;
const MAX_PATTERNS: usize = 200;
/// Entries analysed by `/api/patterns` (the newest matches) and how much of each message is read.
const PATTERN_SCAN: usize = 20_000;
const PATTERN_MESSAGE_CHARS: usize = 400;
const MAX_FIELD_NAMES: usize = 200;
const DEFAULT_CONTEXT_LINES: usize = 5;
const MAX_CONTEXT_LINES: usize = 100;
/// Exports that may run at the same time.
pub const MAX_EXPORTS: usize = 2;
/// Formatted rows are sent to the client in chunks of about this many bytes.
const EXPORT_CHUNK_BYTES: usize = 64 * 1024;
const INDEX_HTML: &str = include_str!("web/index.html");
/// The board, host, admin and compare views: one page that shows the view its path names.
const PAGES_HTML: &str = include_str!("web/pages.html");
/// Colours, type and base controls shared by both pages, put where a page has `/*@theme*/`.
const THEME_CSS: &str = include_str!("web/theme.css");

#[derive(Clone)]
pub struct AppState {
    pub sink: Sink,
    pub db_path: PathBuf,
    /// Settings that a reload replaces while running; the API reads the tokens from here.
    pub settings: Arc<crate::live::LiveSettings>,
    /// Bounds concurrent exports, which each hold a database read transaction open.
    pub exports: Arc<tokio::sync::Semaphore>,
    /// Refused requests and reads, for `/api/audit`.
    pub audit: Arc<AuditLog>,
    /// The notifications raised, for `/api/alerts`.
    pub alerts: Arc<crate::alertlog::AlertLog>,
}

pub fn router(state: AppState, max_body_bytes: usize) -> Router {
    let write = Router::new()
        .route("/ingest", post(ingest))
        .route("/loki/api/v1/push", post(loki_push))
        .route("/gelf", post(gelf_ingest))
        .route("/v1/logs", post(otlp_logs))
        .route(crate::grpc::LOGS_EXPORT_PATH, post(otlp_grpc))
        .route("/v1/traces", post(otlp_traces))
        .route(crate::grpc::TRACES_EXPORT_PATH, post(otlp_grpc_traces))
        .route_layer(middleware::from_fn_with_state(
            (state.clone(), Scope::Write),
            require_scope,
        ))
        .layer(DefaultBodyLimit::max(max_body_bytes));
    let read = Router::new()
        .route("/api/logs", get(search))
        .route("/api/logs/{id}/context", get(log_context))
        .route("/api/tail", get(tail))
        .route("/api/stats", get(stats))
        .route("/api/hosts", get(hosts))
        .route("/api/top", get(top))
        .route("/api/views", get(list_views).post(save_view))
        .route("/api/views/{id}", axum::routing::delete(delete_view))
        .route("/api/fields", get(fields))
        .route("/api/patterns", get(patterns))
        .route("/api/tags", get(tag_list))
        .route("/api/alerts", get(alert_history))
        .route("/api/traces", get(trace_list))
        .route("/api/traces/{id}", get(trace_detail))
        .route("/api/export", get(export))
        .route(
            "/loki/api/v1/query_range",
            get(crate::lokiapi::query_range).post(crate::lokiapi::query_range),
        )
        .route(
            "/loki/api/v1/query",
            get(crate::lokiapi::query_instant).post(crate::lokiapi::query_instant),
        )
        .route("/loki/api/v1/labels", get(crate::lokiapi::labels))
        .route(
            "/loki/api/v1/label/{name}/values",
            get(crate::lokiapi::label_values),
        )
        .route(
            "/loki/api/v1/series",
            get(crate::lokiapi::series_list).post(crate::lokiapi::series_list),
        )
        .route_layer(middleware::from_fn_with_state(
            (state.clone(), Scope::Read),
            require_scope,
        ));
    let admin = Router::new()
        .route("/api/audit", get(audit_trail))
        .route("/api/tokens", get(token_list))
        .route(
            "/api/maintenance",
            get(maintenance_list).post(maintenance_add),
        )
        .route(
            "/api/maintenance/{id}",
            axum::routing::delete(maintenance_remove),
        )
        .route(
            "/api/alert-rules",
            get(alert_rules_list).post(alert_rule_save),
        )
        .route(
            "/api/alert-rules/{id}",
            axum::routing::delete(alert_rule_delete),
        )
        .route("/api/mutes", get(mute_list).post(mute_set))
        .route("/api/storage", get(storage_info))
        .route_layer(middleware::from_fn_with_state(
            (state.clone(), Scope::Admin),
            require_scope,
        ));
    let protected = write.merge(read).merge(admin);

    Router::new()
        .route("/", get(index))
        .route("/board", get(pages))
        .route("/host/{name}", get(pages))
        .route("/admin", get(pages))
        .route("/compare", get(pages))
        .route("/traces", get(pages))
        .route("/traces/{id}", get(pages))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .merge(protected)
        .with_state(state)
}

/// The page's script and styles are inline and it only talks to its own origin, so the policy
/// keeps it from loading or sending anything elsewhere, and from being framed (clickjacking).
const INDEX_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; \
    style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; \
    base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// A page as served: its source with the shared theme put in, without indentation, blank lines and
/// whole-line `//` and `/* */` comments (kept in the sources for their readers), and gzipped. The
/// scripts have no multi-line strings, so dropping whole lines and leading spaces changes no value.
fn build_page(source: &str) -> (String, Vec<u8>) {
    let source = source.replace("/*@theme*/", THEME_CSS);
    let mut page = String::with_capacity(source.len());
    for line in source.lines().map(str::trim) {
        let comment = line.starts_with("//") || (line.starts_with("/*") && line.ends_with("*/"));
        if !line.is_empty() && !comment {
            page.push_str(line);
            page.push('\n');
        }
    }
    let gzipped = crate::archive::gzip_member(page.as_bytes());
    (page, gzipped)
}

/// The main page, built once.
fn index_page() -> &'static (String, Vec<u8>) {
    static PAGE: std::sync::OnceLock<(String, Vec<u8>)> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| build_page(INDEX_HTML))
}

/// The page of the other views, built once.
fn pages_page() -> &'static (String, Vec<u8>) {
    static PAGE: std::sync::OnceLock<(String, Vec<u8>)> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| build_page(PAGES_HTML))
}

/// Whether an `Accept-Encoding` value takes gzip (listed, and not with a zero quality).
fn accepts_gzip(value: &str) -> bool {
    value.split(',').any(|coding| {
        let mut parts = coding.split(';').map(str::trim);
        let name = parts.next().unwrap_or_default();
        let refused = parts.any(|p| {
            p.strip_prefix("q=")
                .and_then(|q| q.parse::<f32>().ok())
                .is_some_and(|q| q == 0.0)
        });
        (name.eq_ignore_ascii_case("gzip") || name == "*") && !refused
    })
}

/// The web UI's main page.
async fn index(request_headers: HeaderMap) -> Response {
    serve_page(index_page(), &request_headers)
}

/// The board, host, admin and compare views (the page reads its path). The data still comes from
/// the API, so these pages need the same token as the main one, kept in the same browser storage.
async fn pages(request_headers: HeaderMap) -> Response {
    serve_page(pages_page(), &request_headers)
}

/// A page, gzipped when the browser accepts it, with headers that keep a browser from framing it or
/// sniffing other types.
fn serve_page(built: &'static (String, Vec<u8>), request_headers: &HeaderMap) -> Response {
    let (page, gzipped) = built;
    let gzip = request_headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(accepts_gzip);
    let mut response = if gzip {
        (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CONTENT_ENCODING, "gzip"),
            ],
            gzipped.as_slice(),
        )
            .into_response()
    } else {
        Html(page.as_str()).into_response()
    };
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, INDEX_CSP),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::VARY, "accept-encoding"),
    ] {
        headers.insert(name, header::HeaderValue::from_static(value));
    }
    response
}

/// Runs `job` on the blocking pool with its own connection to the database at `path`. A failure
/// is logged and becomes the 500 response naming `what`.
pub(crate) async fn with_db<T: Send + 'static>(
    path: &std::path::Path,
    what: &'static str,
    job: impl FnOnce(&rusqlite::Connection) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, (StatusCode, String)> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || job(&store::open(&path)?))
        .await
        .unwrap_or_else(|e| Err(e.into()))
        .map_err(|e| {
            tracing::error!("{what} failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{what} failed"))
        })
}

/// A `limit` parameter: a positive number, capped at `max`.
fn positive_limit(v: &str, max: usize) -> Result<usize, &'static str> {
    v.parse::<usize>()
        .ok()
        .filter(|n| *n > 0)
        .map(|n| n.min(max))
        .ok_or("invalid limit")
}

/// Standard base64 (RFC 4648, padding optional); `None` for anything else.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The token a client presented: `Authorization: Bearer <token>`, or `Basic` credentials whose
/// password is the token (the user name is ignored), which is how Promtail, Grafana Alloy and
/// other Loki clients authenticate.
fn credentials(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.to_string());
    }
    let decoded = base64_decode(value.strip_prefix("Basic ")?.trim())?;
    let text = String::from_utf8(decoded).ok()?;
    Some(text.split_once(':')?.1.to_string())
}

async fn require_scope(
    State((state, scope)): State<(AppState, Scope)>,
    mut req: Request,
    next: Next,
) -> Response {
    let presented = credentials(req.headers());
    let auth = state.settings.auth.get();
    let identity = auth.identify(presented.as_deref(), scope);
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = audit::shorten_query(req.uri().query().unwrap_or(""));
    // Plain HTTP and HTTPS connections describe their peer with different types.
    let peer = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0)
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<crate::tls::PeerAddr>>()
                .map(|c| c.0.0)
        })
        .map(|a| a.to_string());
    let (token, response) = match identity {
        Ok(id) => {
            let name = id.name.clone();
            let quotas = &state.settings.quotas;
            let refused = if scope == Scope::Write {
                quotas
                    .check(&id.name, &id.limits, now_ms(), std::time::Instant::now())
                    .err()
            } else {
                None
            };
            if let Some(wait) = refused {
                let mut r =
                    (StatusCode::TOO_MANY_REQUESTS, "ingestion quota exceeded").into_response();
                r.headers_mut().insert(header::RETRY_AFTER, wait.into());
                (Some(name), r)
            } else {
                // Handlers count the events they push; they are charged to the token afterwards.
                let charge = crate::quota::Charge::default();
                req.extensions_mut().insert(charge.clone());
                let limits = id.limits;
                req.extensions_mut().insert(id);
                let response = next.run(req).await;
                if scope == Scope::Write {
                    quotas.charge(
                        &name,
                        &limits,
                        charge.total(),
                        now_ms(),
                        std::time::Instant::now(),
                    );
                }
                (Some(name), response)
            }
        }
        Err(Decision::Forbidden) => (
            auth.name_of(presented.as_deref()).map(str::to_string),
            (StatusCode::FORBIDDEN, "this token lacks the required scope").into_response(),
        ),
        Err(_) => (
            None,
            (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response(),
        ),
    };
    let status = response.status().as_u16();
    // With authentication off every caller is anonymous and there is nobody to account for.
    if auth.enabled() && audit::wanted(&method, &path, status) {
        let refused = status == 401 || status == 403;
        tracing::info!(
            target: "logpit::audit",
            token = token.as_deref().unwrap_or("-"),
            method = %method,
            path = %path,
            query = %query,
            status,
            peer = peer.as_deref().unwrap_or("-"),
            refused,
            "api access"
        );
        state.audit.record(audit::Event {
            ts: now_ms(),
            token,
            method,
            path,
            query,
            status,
            peer,
        });
    }
    response
}

/// `limit` (default 100, at most 1000), `since` and `until` (Unix ms), `token` (a token name) and
/// `refused=true` (only 401 and 403).
fn parse_audit(params: Vec<(String, String)>) -> Result<audit::AuditQuery, String> {
    let mut q = audit::AuditQuery {
        limit: 100,
        ..Default::default()
    };
    let num = |name: &str, v: &str| v.parse::<i64>().map_err(|_| format!("invalid {name}"));
    for (k, v) in params {
        match (k.as_str(), v.as_str()) {
            (_, "") => {}
            ("limit", v) => q.limit = positive_limit(v, audit::MAX_QUERY_LIMIT)?,
            ("since", v) => q.since_ms = Some(num("since", v)?),
            ("until", v) => q.until_ms = Some(num("until", v)?),
            ("token", v) => q.token = Some(v.to_string()),
            ("refused", "true") => q.refused = true,
            ("refused", "false") => q.refused = false,
            ("refused", _) => return Err("refused must be true or false".into()),
            _ => {}
        }
    }
    Ok(q)
}

/// Audit events, newest first: from the database when the trail is kept there (surviving
/// restarts, for `audit_retention_days`), otherwise the last 1000 in memory.
async fn audit_trail(
    State(state): State<AppState>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let query = match parse_audit(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let Some(path) = state.audit.persistent_path() else {
        return Json(state.audit.search(&query)).into_response();
    };
    match with_db(path, "audit query", move |conn| {
        store::audit_events(conn, &query).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(events) => Json(events).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Serialize)]
struct TokenInfo<'a> {
    name: &'a str,
    scopes: &'a [Scope],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    hosts: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    apps: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    events_per_sec: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    events_per_day: Option<u64>,
}

/// The configured tokens by name, scopes and read restrictions; never the secrets.
async fn token_list(State(state): State<AppState>) -> Response {
    let auth = state.settings.auth.get();
    let tokens: Vec<TokenInfo> = auth
        .entries()
        .map(|e| TokenInfo {
            name: &e.name,
            scopes: &e.scopes,
            hosts: &e.access.hosts,
            apps: &e.access.apps,
            events_per_sec: e.limits.per_sec,
            events_per_day: e.limits.per_day,
        })
        .collect();
    Json(tokens).into_response()
}

/// The maintenance windows, those of the configuration and those created here.
async fn maintenance_list(State(state): State<AppState>) -> Response {
    Json(state.settings.maintenance.list(now_ms())).into_response()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceInput {
    hosts: Vec<String>,
    minutes: u32,
    #[serde(default)]
    reason: String,
}

/// Starts a window: `{"hosts": ["web*"], "minutes": 60, "reason": "kernel upgrade"}`.
async fn maintenance_add(
    State(state): State<AppState>,
    Json(input): Json<MaintenanceInput>,
) -> Response {
    match state
        .settings
        .maintenance
        .add(input.hosts, input.minutes, input.reason, now_ms())
    {
        Ok((_, info)) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
    }
}

async fn maintenance_remove(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Response {
    if state.settings.maintenance.remove(id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "no such window").into_response()
    }
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.sink.metrics().render()
            + &state.sink.silence().render_metrics()
            + &state.sink.rules().render_metrics()
            + &crate::alerts::AlertRules::render_all(&[
                &state.sink.alerts(),
                &state.sink.settings().ui_alerts.get(),
            ])
            + &state.sink.settings().watch.render_metrics()
            + &state.sink.settings().metrics.get().render()
            + &state.sink.settings().parsers.get().render_metrics()
            + &state.sink.settings().dedup.render_metrics()
            + &state.sink.settings().volume.render_metrics()
            + &state.settings.quotas.render_metrics()
            + &state
                .sink
                .settings()
                .silence
                .get()
                .email
                .as_ref()
                .map(|m| m.render_metrics())
                .unwrap_or_default()
            + &state
                .sink
                .forwarders()
                .map(|f| f.render_metrics())
                .unwrap_or_default()
            + &state.sink.limiter().render_metrics(),
    )
}

/// Maps one JSON object to an entry. Accepts LogPit's own field names as well as
/// `journalctl -o json` (`MESSAGE`, `_HOSTNAME`, `SYSLOG_IDENTIFIER`, `PRIORITY`,
/// `__REALTIME_TIMESTAMP`).
pub fn entry_from_json(v: &Value, now: i64) -> Option<LogEntry> {
    let obj = v.as_object()?;
    let text = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| obj.get(*k))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let number = |keys: &[&str]| {
        keys.iter().find_map(|k| match obj.get(*k)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        })
    };

    let message = text(&["message", "MESSAGE"]).filter(|m| !m.is_empty())?;
    let ts = number(&["ts"])
        .or_else(|| number(&["__REALTIME_TIMESTAMP"]).map(|us| us / 1000))
        .unwrap_or(now);
    let severity = number(&["severity", "PRIORITY"]).map_or(6, |s| s.clamp(0, 7) as u8);

    // Optional structured data: {"fields": {"key": "value" | number | bool}}.
    let fields = obj
        .get("fields")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter(|(k, _)| crate::store::valid_field_key(k))
                .filter_map(|(k, v)| Some((k.clone(), crate::structured::json_scalar(v)?)))
                .take(64)
                .collect()
        })
        .unwrap_or_default();

    Some(LogEntry {
        ts,
        host: text(&["host", "_HOSTNAME"]).unwrap_or_else(|| "unknown".into()),
        app: text(&["app", "SYSLOG_IDENTIFIER", "_COMM"]).unwrap_or_default(),
        severity,
        message,
        fields,
    })
}

#[derive(serde::Serialize)]
struct IngestResult {
    accepted: usize,
    rejected: usize,
}

/// The request body with its `Content-Encoding` undone: none, or gzip (and zlib's `deflate` when
/// `allow_deflate`). Anything else is a 415, a damaged stream a 400, a bomb a 413.
fn decompress_request(
    headers: &HeaderMap,
    body: Bytes,
    allow_deflate: bool,
) -> Result<Bytes, (StatusCode, String)> {
    let encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let result = match encoding.as_str() {
        "" | "identity" => return Ok(body),
        "gzip" | "x-gzip" => crate::inflate::gunzip(&body, crate::loki::MAX_DECOMPRESSED_BYTES),
        "deflate" if allow_deflate => {
            crate::inflate::zlib(&body, crate::loki::MAX_DECOMPRESSED_BYTES)
        }
        other => {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("unsupported Content-Encoding {other:?}"),
            ));
        }
    };
    match result {
        Ok(plain) => Ok(Bytes::from(plain)),
        Err(crate::inflate::Error::TooLarge) => Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "decompressed body too large".into(),
        )),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// OpenTelemetry logs over HTTP (OTLP): protobuf or JSON, optionally gzip-compressed, which is what
/// the OpenTelemetry Collector and the SDK exporters send. Resource and log attributes become the
/// host, app, level and fields. Answers 200 with an empty export response.
/// OTLP over gRPC (`LogsService/Export`), which needs HTTP/2.
async fn otlp_grpc(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::grpc::export_logs(state.sink.clone(), charge, headers, body).await
}

async fn otlp_grpc_traces(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let metrics = state.sink.metrics_arc();
    crate::grpc::export_traces(state.db_path.clone(), metrics, charge, headers, body).await
}

/// OTLP/HTTP traces (`POST /v1/traces`), protobuf or JSON like `/v1/logs`; the spans are stored
/// at once (see [`crate::spans`]).
async fn otlp_traces(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = match decompress_request(&headers, body, false) {
        Ok(b) => b,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.to_ascii_lowercase().contains("json"));
    let (db, metrics) = (state.db_path.clone(), state.sink.metrics_arc());
    let result = tokio::task::spawn_blocking(move || {
        crate::spans::store_spans(&db, &metrics, &body, is_json)
    })
    .await;
    match result {
        Ok(Ok(count)) => {
            charge.add(count);
            if is_json {
                ([(header::CONTENT_TYPE, "application/json")], "{}").into_response()
            } else {
                ([(header::CONTENT_TYPE, "application/x-protobuf")], "").into_response()
            }
        }
        Ok(Err(msg)) if msg == crate::spans::STORE_FAILED => {
            (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
        }
        Ok(Err(msg)) => {
            Metrics::inc(&state.sink.metrics().spans_rejected, 1);
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
        Err(e) => {
            tracing::error!("otlp traces task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "export failed").into_response()
        }
    }
}

async fn otlp_logs(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = match decompress_request(&headers, body, false) {
        Ok(b) => b,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.to_ascii_lowercase().contains("json"));
    let sink = state.sink.clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = now_ms();
        let entries = if is_json {
            crate::otlp::decode_json(&body, now)
        } else {
            crate::otlp::decode_protobuf(&body, now)
        }?;
        let count = entries.len();
        for entry in entries {
            sink.push(entry);
        }
        Ok::<_, &'static str>(count)
    })
    .await;
    match result {
        Ok(Ok(count)) if is_json => {
            charge.add(count);
            ([(header::CONTENT_TYPE, "application/json")], "{}").into_response()
        }
        Ok(Ok(count)) => {
            charge.add(count);
            ([(header::CONTENT_TYPE, "application/x-protobuf")], "").into_response()
        }
        Ok(Err(msg)) => {
            Metrics::inc(&state.sink.metrics().rejected, 1);
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
        Err(e) => {
            tracing::error!("otlp task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "export failed").into_response()
        }
    }
}

/// Loki's push API: JSON, or snappy-compressed protobuf (what Promtail and Grafana Alloy send).
/// Labels become the host, app, level and fields; JSON or `key=value` data inside a line is
/// extracted as well when structured parsing is on. Answers 204 like Loki.
async fn loki_push(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_snappy = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|e| e.trim().eq_ignore_ascii_case("snappy"));
    // `snappy` is how Loki's protobuf is compressed (handled below); gzip is undone here.
    let body = if is_snappy {
        body
    } else {
        match decompress_request(&headers, body, false) {
            Ok(b) => b,
            Err((status, msg)) => return (status, msg).into_response(),
        }
    };
    let is_json = content_type.contains("json");
    let sink = state.sink.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<usize, String> {
        let streams = if is_json {
            crate::loki::decode_json(&body)
        } else {
            let plain = crate::snappy::decompress(&body, crate::loki::MAX_DECOMPRESSED_BYTES)
                .map_err(|e| e.to_string())?;
            crate::loki::decode_protobuf(&plain)
        }
        .map_err(str::to_string)?;
        let extract = sink
            .settings()
            .structured
            .load(std::sync::atomic::Ordering::Relaxed);
        let now = now_ms();
        let mut lines = 0;
        for stream in &streams {
            for line in &stream.lines {
                let found = if extract {
                    crate::structured::extract(&line.line)
                } else {
                    Vec::new()
                };
                sink.push(crate::loki::to_entry(&stream.labels, line, found, now));
                lines += 1;
            }
        }
        Ok(lines)
    })
    .await;
    match result {
        Ok(Ok(lines)) => {
            charge.add(lines);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(msg)) => {
            Metrics::inc(&state.sink.metrics().rejected, 1);
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
        Err(e) => {
            tracing::error!("loki push task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "push failed").into_response()
        }
    }
}

/// GELF over HTTP: one JSON message per request. Answers 202 like Graylog.
async fn gelf_ingest(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = match decompress_request(&headers, body, true) {
        Ok(b) => b,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    match state.sink.push_gelf(&body) {
        Ok(()) => {
            charge.add(1);
            StatusCode::ACCEPTED.into_response()
        }
        Err(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
    }
}

/// Accepts NDJSON (one object per line) or a single JSON array of objects.
async fn ingest(
    State(state): State<AppState>,
    Extension(charge): Extension<crate::quota::Charge>,
    body: String,
) -> impl IntoResponse {
    let now = now_ms();
    let mut values: Vec<Value> = Vec::new();
    let mut rejected = 0usize;

    if body.trim_start().starts_with('[') {
        match serde_json::from_str::<Vec<Value>>(&body) {
            Ok(v) => values = v,
            Err(_) => rejected += 1,
        }
    } else {
        for line in body.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Value>(line) {
                Ok(v) => values.push(v),
                Err(_) => rejected += 1,
            }
        }
    }

    let mut accepted = 0usize;
    for v in &values {
        match entry_from_json(v, now) {
            Some(entry) => {
                state.sink.push(entry);
                accepted += 1;
            }
            None => rejected += 1,
        }
    }
    Metrics::inc(&state.sink.metrics().rejected, rejected as u64);
    charge.add(accepted);

    let status = if accepted == 0 && rejected > 0 {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, Json(IngestResult { accepted, rejected }))
}

/// Builds a store query from raw URL parameters. `f=key:value` may be repeated.
fn parse_search(params: Vec<(String, String)>) -> Result<Query, String> {
    let mut q = Query {
        limit: DEFAULT_LIMIT,
        ..Default::default()
    };
    let num = |name: &str, v: &str| v.parse::<i64>().map_err(|_| format!("invalid {name}"));
    for (k, v) in params {
        match k.as_str() {
            "q" => q.text = Some(v),
            "host" if !v.is_empty() => q.host = Some(v),
            "app" if !v.is_empty() => q.app = Some(v),
            // Maximum severity number (0 = emergency … 7 = debug).
            "level" if !v.is_empty() => q.max_severity = Some(num("level", &v)?.clamp(0, 7) as u8),
            "since" if !v.is_empty() => q.since_ms = Some(num("since", &v)?.clamp(-MAX_TS, MAX_TS)),
            "until" if !v.is_empty() => q.until_ms = Some(num("until", &v)?.clamp(-MAX_TS, MAX_TS)),
            // Paging cursor `ts:id`, as returned in the `X-Next-Cursor` header.
            "before" if !v.is_empty() => {
                let bad = || "before must be <ts>:<id>".to_string();
                let (ts, id) = v.split_once(':').ok_or_else(bad)?;
                q.before = Some((
                    ts.parse().map_err(|_| bad())?,
                    id.parse().map_err(|_| bad())?,
                ));
            }
            "limit" if !v.is_empty() => {
                q.limit = num("limit", &v)?.clamp(1, MAX_LIMIT as i64) as usize
            }
            // `key:value`, or a comparison or regular expression on a field (see `filters`).
            "f" if !v.is_empty() => match crate::filters::parse_expr(&v)? {
                crate::filters::Expr::Equals(key, value) => q.fields.push((key, value)),
                crate::filters::Expr::Compare(f) => q.compare.push(f),
            },
            // A regular expression the message must match.
            "re" if !v.is_empty() => q.message_re = Some(crate::filters::compile_regex(&v)?),
            // Every entry of a trace, across hosts: a shorthand for `f=trace_id:<id>`.
            "trace" if !v.is_empty() => q.fields.push((
                crate::trace::TRACE_ID.into(),
                crate::trace::normalize_id(&v).ok_or("invalid trace")?,
            )),
            // A host tag to keep (repeat for several: any of them); see `[[tags]]`.
            "tag" if !v.is_empty() => q.tags.push(v),
            _ => {}
        }
    }
    Ok(q)
}

/// `limit` (default 50, at most 1000), `since` and `until` (Unix ms), `kind` (an event name such
/// as `host_silent` or `volume_surge`) and `host`.
fn parse_alerts(params: Vec<(String, String)>) -> Result<crate::alertlog::AlertQuery, String> {
    let mut q = crate::alertlog::AlertQuery {
        limit: 50,
        ..Default::default()
    };
    let num = |name: &str, v: &str| v.parse::<i64>().map_err(|_| format!("invalid {name}"));
    for (k, v) in params {
        match (k.as_str(), v.as_str()) {
            (_, "") => {}
            ("limit", v) => q.limit = positive_limit(v, crate::alertlog::MAX_QUERY_LIMIT)?,
            ("since", v) => q.since_ms = Some(num("since", v)?),
            ("until", v) => q.until_ms = Some(num("until", v)?),
            ("kind", v) => q.kind = Some(v.to_string()),
            ("host", v) => q.host = Some(v.to_string()),
            _ => {}
        }
    }
    Ok(q)
}

/// The notifications LogPit raised, newest first, whether or not a webhook took them. A token
/// limited to some hosts sees only the alerts about those hosts, and none when it is limited by
/// app (an alert has no app to check).
async fn alert_history(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let mut query = match parse_alerts(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let wanted = query.limit;
    let access = who.access;
    // A limited token's entries are filtered after the fact, so read enough of them to fill a page.
    if !access.unrestricted() {
        query.limit = crate::alertlog::MAX_QUERY_LIMIT;
    }
    let mut entries = match state.alerts.persistent_path() {
        None => state.alerts.search_memory(&query),
        Some(path) => {
            let q = query.clone();
            match with_db(path, "alert history", move |conn| {
                Ok(store::alert_events(conn, &q)?)
            })
            .await
            {
                Ok(e) => e,
                Err(e) => return e.into_response(),
            }
        }
    };
    if !access.unrestricted() {
        entries.retain(|e| {
            access.apps.is_empty() && e.host.as_deref().is_some_and(|h| access.allows(h, ""))
        });
        entries.truncate(wanted);
    }
    Json(entries).into_response()
}

/// Turns the tags asked for (`tag=`) into host patterns, or answers 400 for an unknown one.
fn resolve_tags(state: &AppState, query: &mut Query) -> Option<Response> {
    if query.tags.is_empty() {
        return None;
    }
    match state.settings.tags.get().patterns(&query.tags) {
        Ok(patterns) => {
            query.host_globs = patterns;
            query.tags.clear();
            None
        }
        Err(msg) => Some((StatusCode::BAD_REQUEST, msg).into_response()),
    }
}

#[derive(serde::Serialize)]
struct TagInfo<'a> {
    name: &'a str,
    /// The host names and patterns; hidden from a token limited to some hosts or apps.
    #[serde(skip_serializing_if = "Option::is_none")]
    hosts: Option<&'a [String]>,
}

/// The configured host tags, to offer as filters (`tag=`).
async fn tag_list(State(state): State<AppState>, Extension(who): Extension<Identity>) -> Response {
    let tags = state.settings.tags.get();
    let show = who.access.unrestricted();
    let list: Vec<TagInfo> = tags
        .all()
        .iter()
        .map(|t| TagInfo {
            name: &t.name,
            hosts: show.then_some(t.hosts.as_slice()),
        })
        .collect();
    Json(list).into_response()
}

async fn search(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let mut query = match parse_search(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    let limit = query.limit;
    match with_db(&state.db_path, "search", move |conn| {
        store::search(conn, &query).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(rows) => {
            // A full page means there may be more: hand out the cursor for the next one.
            let next = rows
                .last()
                .filter(|_| rows.len() == limit)
                .map(|r| format!("{}:{}", r.ts, r.id));
            let mut resp = Json(rows).into_response();
            if let Some(cursor) = next.and_then(|c| c.parse().ok()) {
                resp.headers_mut().insert("x-next-cursor", cursor);
            }
            resp
        }
        Err(e) => e.into_response(),
    }
}

struct StatsRequest {
    query: Query,
    bucket_ms: Option<i64>,
    group: GroupBy,
}

/// `bucket` (`5m`, `1h`, or seconds) and `group_by` (`host`, `app`, `severity`,
/// `field:<key>`) on top of the search filters.
fn parse_stats(params: Vec<(String, String)>) -> Result<StatsRequest, String> {
    let mut bucket_ms = None;
    let mut group = GroupBy::None;
    for (k, v) in &params {
        match (k.as_str(), v.as_str()) {
            ("bucket", v) if !v.is_empty() => {
                bucket_ms =
                    Some(stats::parse_bucket_ms(v).ok_or("invalid bucket (try 30s, 5m, 1h, 1d)")?);
            }
            ("group_by", "" | "none") => {}
            ("group_by", "host") => group = GroupBy::Host,
            ("group_by", "app") => group = GroupBy::App,
            ("group_by", "severity" | "level") => group = GroupBy::Severity,
            ("group_by", v) => {
                let key = v.strip_prefix("field:").unwrap_or("");
                if !crate::store::valid_field_key(key) {
                    return Err("group_by must be host, app, severity or field:<key>".into());
                }
                group = GroupBy::Field(key.to_string());
            }
            _ => {}
        }
    }
    Ok(StatsRequest {
        query: parse_search(params)?,
        bucket_ms,
        group,
    })
}

/// Entry counts per time bucket over `since..until`. An absent `until` means now and an
/// absent `since` the oldest entry; without `bucket`, a size giving about 120 buckets is chosen.
async fn stats(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let mut req = match parse_stats(params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    req.query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut req.query) {
        return r;
    }
    match with_db(&state.db_path, "stats", move |conn| {
        let until = req.query.until_ms.unwrap_or_else(now_ms);
        let since = match req.query.since_ms {
            Some(s) => s,
            None => store::min_ts(conn)?
                .unwrap_or(until.saturating_sub(3_600_000))
                .min(until),
        };
        if since > until {
            return Ok(Err("since must not be after until".into()));
        }
        let bucket_ms = req
            .bucket_ms
            .unwrap_or_else(|| stats::auto_bucket_ms(until.saturating_sub(since)));
        if until.div_euclid(bucket_ms) - since.div_euclid(bucket_ms) >= stats::MAX_BUCKETS {
            return Ok(Err(format!(
                "range needs more than {} buckets; use a larger bucket or a shorter range",
                stats::MAX_BUCKETS
            )));
        }
        let query = Query {
            since_ms: Some(since),
            until_ms: Some(until),
            ..req.query
        };
        let mut rows = store::stats(conn, &query, bucket_ms, &req.group)?;
        if req.group == GroupBy::Severity {
            for (_, g, _) in &mut rows {
                if let Ok(n) = g.parse::<u8>() {
                    *g = crate::model::severity_name(n).to_string();
                }
            }
        }
        let grouped = req.group != GroupBy::None;
        Ok(Ok(stats::assemble(rows, since, until, bucket_ms, grouped)))
    })
    .await
    {
        Ok(Ok(s)) => Json(s).into_response(),
        Ok(Err(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `sort` (`host`, `count`, `errors`, `warnings`, `last_ts`) and `order` (`asc`, `desc`) on top
/// of the search filters. Without `order`, text sorts ascending and numbers descending.
/// Most slices `form=` may ask for in the per-host summary.
const MAX_FORM_SLICES: usize = 24;

fn parse_hosts(params: Vec<(String, String)>) -> Result<(Query, HostSort, usize), String> {
    let mut sort = HostSort::default();
    let mut order = None;
    let mut form = 0;
    for (k, v) in &params {
        match (k.as_str(), v.as_str()) {
            ("sort", "") | ("order", "") | ("form", "") => {}
            ("form", v) => {
                form = v
                    .parse()
                    .ok()
                    .filter(|n| (1..=MAX_FORM_SLICES).contains(n))
                    .ok_or(format!("form must be between 1 and {MAX_FORM_SLICES}"))?;
            }
            ("sort", v) => {
                let key = match v {
                    "host" => HostSortKey::Host,
                    "count" => HostSortKey::Count,
                    "errors" => HostSortKey::Errors,
                    "warnings" => HostSortKey::Warnings,
                    "last_ts" => HostSortKey::LastTs,
                    _ => return Err("sort must be host, count, errors, warnings or last_ts".into()),
                };
                sort = HostSort::natural(key);
            }
            ("order", "asc") => order = Some(false),
            ("order", "desc") => order = Some(true),
            ("order", _) => return Err("order must be asc or desc".into()),
            _ => {}
        }
    }
    if let Some(desc) = order {
        sort.desc = desc;
    }
    Ok((parse_search(params)?, sort, form))
}

/// Per-host totals (entries, errors, warnings, last activity, silence state) over the entries
/// matching the search filters, ordered by `sort`/`order`. `limit` caps the number of hosts
/// after sorting. With `form=N` and a `since`, each host also gets its recent form: the window
/// (up to `until`, or now) cut in N equal slices.
async fn hosts(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let (mut query, sort, form) = match parse_hosts(params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    let window = query.since_ms.filter(|_| form > 0).map(|since| {
        let until = query.until_ms.unwrap_or_else(crate::ingest::now_ms);
        (since, until.max(since))
    });
    match with_db(&state.db_path, "host summary", move |conn| {
        let mut rows = store::host_summary(conn, &query, sort)?;
        if let Some((since, until)) = window {
            let mut forms = store::host_form(conn, &query, since, until, form)?;
            for r in &mut rows {
                r.form = Some(
                    forms
                        .remove(&r.host)
                        .unwrap_or_else(|| vec![store::FormSlice::default(); form]),
                );
            }
        }
        Ok::<_, anyhow::Error>(rows)
    })
    .await
    {
        Ok(mut rows) => {
            let tags = state.settings.tags.get();
            for r in &mut rows {
                r.silent = state.sink.silence().is_silent(&r.host);
                r.tags = tags
                    .of_host(&r.host)
                    .into_iter()
                    .map(String::from)
                    .collect();
            }
            Json(rows).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Query-string keys a saved view may hold: what the web UI puts in its address bar.
const VIEW_KEYS: [&str; 11] = [
    "q", "host", "app", "level", "f", "re", "tag", "range", "since", "until", "group",
];
const MAX_VIEW_NAME_CHARS: usize = 80;
const MAX_VIEW_QUERY_BYTES: usize = 2000;
const MAX_VIEW_VALUE_BYTES: usize = 500;

/// Checks a view before it is stored: a short name, and a query string made only of the UI's own
/// parameters, so a saved view can never carry anything the page would not otherwise accept.
fn validate_view(name: &str, query: &str) -> Result<(String, String), String> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_VIEW_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(format!(
            "name must be 1 to {MAX_VIEW_NAME_CHARS} characters, without control characters"
        ));
    }
    let query = query.trim().trim_start_matches('?');
    if query.len() > MAX_VIEW_QUERY_BYTES {
        return Err(format!("query is longer than {MAX_VIEW_QUERY_BYTES} bytes"));
    }
    if query
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '#')
    {
        return Err("query must be a URL-encoded query string".into());
    }
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !VIEW_KEYS.contains(&key) {
            return Err(format!(
                "unknown parameter {key:?}; a view may use {}",
                VIEW_KEYS.join(", ")
            ));
        }
        if value.len() > MAX_VIEW_VALUE_BYTES {
            return Err(format!(
                "the value of {key} is longer than {MAX_VIEW_VALUE_BYTES} bytes"
            ));
        }
    }
    Ok((name.to_string(), query.to_string()))
}

#[derive(Deserialize)]
struct ViewInput {
    name: String,
    #[serde(default)]
    query: String,
}

/// The saved views, by name.
/// Saved views are shared by everyone and may name hosts, apps or search text, so a token
/// limited to some hosts or apps does not get them.
fn views_refused(who: &Identity) -> Option<Response> {
    (!who.access.unrestricted()).then(|| {
        (
            StatusCode::FORBIDDEN,
            "saved views are not available to a token limited to some hosts or apps",
        )
            .into_response()
    })
}

async fn list_views(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
) -> Response {
    if let Some(refused) = views_refused(&who) {
        return refused;
    }
    match with_db(&state.db_path, "listing views", move |conn| {
        store::list_views(conn).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(views) => Json(views).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Saves a view (`{"name": …, "query": "host=pve&level=3"}`), replacing the one with that name.
async fn save_view(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    Json(input): Json<ViewInput>,
) -> Response {
    if let Some(refused) = views_refused(&who) {
        return refused;
    }
    let (name, query) = match validate_view(&input.name, &input.query) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    match with_db(&state.db_path, "saving the view", move |conn| {
        store::save_view(conn, &name, &query, now_ms()).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => (
            StatusCode::CONFLICT,
            format!(
                "at most {} views can be saved; delete one first",
                store::MAX_VIEWS
            ),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn delete_view(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if let Some(refused) = views_refused(&who) {
        return refused;
    }
    match with_db(&state.db_path, "deleting the view", move |conn| {
        store::delete_view(conn, id).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such view").into_response(),
        Err(e) => e.into_response(),
    }
}

/// Alert rules created from the web UI or the API (admin scope), kept in the database beside the
/// `[[alerts]]` of the configuration: `GET` lists them, `POST` saves one (an `[[alerts]]` rule as
/// JSON, which must have a name; saving under an existing name replaces it), `DELETE` removes one.
/// Each change rebuilds the running set, so their counts start again.
const MAX_ALERT_NAME_CHARS: usize = 80;

async fn alert_rules_list(State(state): State<AppState>) -> Response {
    match with_db(&state.db_path, "listing the alert rules", |conn| {
        store::list_alert_rules(conn).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => e.into_response(),
    }
}

/// The running UI rules, rebuilt from what the database now holds.
fn apply_ui_alerts(state: &AppState, rules: &[store::StoredAlertRule]) {
    state
        .settings
        .ui_alerts
        .set(Arc::new(crate::alerts::AlertRules::from_stored(rules)));
}

async fn alert_rule_save(
    State(state): State<AppState>,
    Json(mut rule): Json<crate::alerts::AlertConfig>,
) -> Response {
    let name = rule.name.as_deref().unwrap_or("").trim().to_string();
    if name.is_empty()
        || name.chars().count() > MAX_ALERT_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return (
            StatusCode::BAD_REQUEST,
            format!("an alert rule needs a name of at most {MAX_ALERT_NAME_CHARS} characters"),
        )
            .into_response();
    }
    if state.settings.alerts.get().has(&name) {
        return (
            StatusCode::CONFLICT,
            format!("the configuration already has an alert rule named {name:?}"),
        )
            .into_response();
    }
    rule.name = Some(name);
    if let Err(e) = crate::alerts::AlertRules::from_config(std::slice::from_ref(&rule)) {
        return (StatusCode::BAD_REQUEST, format!("{e:#}")).into_response();
    }
    match with_db(&state.db_path, "saving the alert rule", move |conn| {
        let id = store::save_alert_rule(conn, &rule, now_ms())?;
        Ok((id, store::list_alert_rules(conn)?))
    })
    .await
    {
        Ok((Some(id), rules)) => {
            apply_ui_alerts(&state, &rules);
            match rules.into_iter().find(|r| r.id == id) {
                Some(saved) => (StatusCode::CREATED, Json(saved)).into_response(),
                None => StatusCode::CREATED.into_response(),
            }
        }
        Ok((None, _)) => (
            StatusCode::CONFLICT,
            format!(
                "at most {} alert rules can be saved; delete one first",
                store::MAX_ALERT_RULES
            ),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn alert_rule_delete(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    match with_db(&state.db_path, "deleting the alert rule", move |conn| {
        let gone = store::delete_alert_rule(conn, id)?;
        Ok((gone, store::list_alert_rules(conn)?))
    })
    .await
    {
        Ok((true, rules)) => {
            apply_ui_alerts(&state, &rules);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok((false, _)) => (StatusCode::NOT_FOUND, "no such alert rule").into_response(),
        Err(e) => e.into_response(),
    }
}

/// Most traces one list returns.
const MAX_TRACES: usize = 500;

/// `GET /api/traces`: the latest traces (newest first) whose spans started in `since..until` (Unix ms;
/// the last hour by default), with optional `service`, `host` and `name` (a word of a span's name)
/// that any of their spans must match, `min_duration_ms`, `errors=true` and `limit` (50, at most 500).
fn parse_traces(params: &[(String, String)], now: i64) -> Result<store::TraceQuery, String> {
    let mut q = store::TraceQuery {
        since_ms: now - 3_600_000,
        until_ms: now,
        limit: 50,
        ..Default::default()
    };
    for (k, v) in params {
        let num = || v.parse::<i64>().map_err(|_| format!("invalid {k}"));
        match k.as_str() {
            "since" => q.since_ms = num()?,
            "until" => q.until_ms = num()?,
            "service" => q.service = v.clone(),
            "host" => q.host = v.clone(),
            "name" => q.name = v.clone(),
            "min_duration_ms" => {
                let ms: f64 = v
                    .parse()
                    .map_err(|_| "invalid min_duration_ms".to_string())?;
                if !ms.is_finite() || ms < 0.0 {
                    return Err("invalid min_duration_ms".into());
                }
                q.min_duration_us = (ms * 1000.0) as i64;
            }
            "errors" => q.errors_only = matches!(v.as_str(), "true" | "1"),
            "limit" => {
                q.limit = v
                    .parse()
                    .ok()
                    .filter(|n| (1..=MAX_TRACES).contains(n))
                    .ok_or(format!("limit must be between 1 and {MAX_TRACES}"))?;
            }
            _ => {}
        }
    }
    if q.since_ms > q.until_ms {
        return Err("since must not be after until".into());
    }
    Ok(q)
}

async fn trace_list(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let q = match parse_traces(&params, now_ms()) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    match with_db(&state.db_path, "listing the traces", move |conn| {
        store::list_traces(conn, &q).map_err(anyhow::Error::from)
    })
    .await
    {
        // A token limited to some hosts or apps sees only the traces made entirely of what it may read.
        Ok(mut traces) => {
            if !who.access.unrestricted() {
                // A span with no service (or host) is checked as an empty name, never skipped.
                let or_empty = |v: &[String]| -> Vec<String> {
                    if v.is_empty() {
                        vec![String::new()]
                    } else {
                        v.to_vec()
                    }
                };
                traces.retain(|t| {
                    let services = or_empty(&t.services);
                    or_empty(&t.hosts)
                        .iter()
                        .all(|h| services.iter().all(|s| who.access.allows(h, s)))
                });
            }
            Json(traces).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// `GET /api/traces/<id>`: every span of the trace by start time (the spans of hosts or apps a limited
/// token may not read are left out); `404` when none is stored.
async fn trace_detail(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let id = id.to_ascii_lowercase();
    match with_db(&state.db_path, "reading the trace", move |conn| {
        store::trace_spans(conn, &id).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(mut spans) => {
            spans.retain(|s| who.access.allows(&s.host, &s.service));
            if spans.is_empty() {
                (StatusCode::NOT_FOUND, "no such trace").into_response()
            } else {
                Json(spans).into_response()
            }
        }
        Err(e) => e.into_response(),
    }
}

/// What the database holds (admin scope): its size, entries, their span and the last day's arrivals,
/// with `retention_days` and `max_db_size_mb`, so the page can tell where the size is heading.
async fn storage_info(State(state): State<AppState>) -> Response {
    let (retention_days, max_db_size_mb) = state.settings.storage_limits;
    match with_db(&state.db_path, "summarizing the storage", |conn| {
        store::storage_summary(conn, now_ms()).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(s) => {
            let mut v = serde_json::to_value(s).unwrap_or_default();
            v["retention_days"] = retention_days.into();
            v["max_db_size_mb"] = max_db_size_mb.into();
            Json(v).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Pattern alerts on mute (admin scope): `GET` lists the live mutes, `POST {"rule": …, "minutes": 60}`
/// mutes a rule of the configuration or of the web UI for that long (replacing an earlier mute), and
/// `"minutes": 0` ends its mute.
async fn mute_list(State(state): State<AppState>) -> Response {
    Json(state.settings.mutes.list(now_ms())).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MuteInput {
    rule: String,
    minutes: u32,
}

async fn mute_set(State(state): State<AppState>, Json(input): Json<MuteInput>) -> Response {
    let s = &state.settings;
    if !s.alerts.get().has(&input.rule) && !s.ui_alerts.get().has(&input.rule) {
        return (StatusCode::NOT_FOUND, "no alert rule with that name").into_response();
    }
    if input.minutes > crate::mute::MAX_MINUTES {
        return (
            StatusCode::BAD_REQUEST,
            format!("minutes must be at most {}", crate::mute::MAX_MINUTES),
        )
            .into_response();
    }
    let now = now_ms();
    if input.minutes == 0 {
        s.mutes.clear(&input.rule, now);
        return StatusCode::NO_CONTENT.into_response();
    }
    let until = now + i64::from(input.minutes) * 60_000;
    if !s.mutes.set(&input.rule, until, now) {
        return (
            StatusCode::CONFLICT,
            format!(
                "at most {} rules can be muted at once",
                crate::mute::MAX_MUTES
            ),
        )
            .into_response();
    }
    Json(crate::mute::Mute {
        rule: input.rule,
        until,
    })
    .into_response()
}

/// `field` (`host`, `app`, `severity`, a structured field name, or `field:<name>` for a field that
/// shares a name with a built-in one) and `limit` (default 10, at most 100), on top of the
/// search filters.
fn parse_top(params: Vec<(String, String)>) -> Result<(Query, GroupBy, usize), String> {
    let mut group = None;
    let mut limit = DEFAULT_TOP_VALUES;
    let mut rest = Vec::new();
    for (k, v) in params {
        match k.as_str() {
            "field" if !v.is_empty() => {
                group = Some(match v.as_str() {
                    "host" => GroupBy::Host,
                    "app" => GroupBy::App,
                    "severity" => GroupBy::Severity,
                    other => {
                        let name = other.strip_prefix("field:").unwrap_or(other);
                        if !crate::store::valid_field_key(name) {
                            return Err("invalid field name".into());
                        }
                        GroupBy::Field(name.to_string())
                    }
                });
            }
            "limit" if !v.is_empty() => limit = positive_limit(&v, MAX_TOP_VALUES)?,
            "field" | "limit" => {}
            _ => rest.push((k, v)),
        }
    }
    let group = group.ok_or("field is required")?;
    Ok((parse_search(rest)?, group, limit))
}

#[derive(serde::Serialize)]
struct TopResponse {
    field: String,
    #[serde(flatten)]
    top: store::TopValues,
    /// Entries with a value that are not among the listed ones.
    other: u64,
}

/// The most frequent values of a field among the entries matching the filters, for questions
/// like "which source addresses were blocked most?".
async fn top(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let (mut query, group, limit) = match parse_top(params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    let for_db = group.clone();
    match with_db(&state.db_path, "top values", move |conn| {
        store::top_values(conn, &query, &for_db, limit).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(mut top) => {
            if group == GroupBy::Severity {
                for v in &mut top.values {
                    if let Ok(n) = v.value.parse::<u8>() {
                        v.value = crate::model::severity_name(n).to_string();
                    }
                }
            }
            let listed: u64 = top.values.iter().map(|v| v.count).sum();
            let field = match &group {
                GroupBy::Host => "host".to_string(),
                GroupBy::App => "app".to_string(),
                GroupBy::Severity => "severity".to_string(),
                GroupBy::Field(name) => name.clone(),
                GroupBy::None => String::new(),
            };
            let other = top.with_field.saturating_sub(listed);
            Json(TopResponse { field, top, other }).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Serialize)]
struct FieldName {
    key: String,
    count: u64,
}

/// The structured fields present in the entries matching the filters, most common first, to
/// know what `/api/top` and `f=` can use. `limit` defaults to 50 (at most 200).
async fn fields(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let mut limit = 50usize;
    let mut rest = Vec::new();
    for (k, v) in params {
        match (k.as_str(), v.as_str()) {
            ("limit", v) if !v.is_empty() => match positive_limit(v, MAX_FIELD_NAMES) {
                Ok(n) => limit = n,
                Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
            },
            ("limit", _) => {}
            _ => rest.push((k, v)),
        }
    }
    let mut query = match parse_search(rest) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    match with_db(&state.db_path, "field names", move |conn| {
        store::field_names(conn, &query, limit).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(names) => Json(
            names
                .into_iter()
                .map(|(key, count)| FieldName { key, count })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// `limit` (default 25, at most 200) on top of the search filters.
fn parse_patterns(params: Vec<(String, String)>) -> Result<(Query, usize), String> {
    let mut limit = DEFAULT_PATTERNS;
    let mut rest = Vec::new();
    for (k, v) in params {
        match (k.as_str(), v.as_str()) {
            ("limit", "") => {}
            ("limit", v) => limit = positive_limit(v, MAX_PATTERNS)?,
            _ => rest.push((k, v)),
        }
    }
    Ok((parse_search(rest)?, limit))
}

/// Groups the newest matching entries (at most [`PATTERN_SCAN`]) into message patterns, most
/// frequent first, with the count in each half of the time window to show what is growing.
async fn patterns(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let (mut query, limit) = match parse_patterns(params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    match with_db(&state.db_path, "patterns", move |conn| {
        let (samples, truncated) =
            store::recent_samples(conn, &query, PATTERN_SCAN, PATTERN_MESSAGE_CHARS)?;
        let until = query.until_ms.unwrap_or_else(now_ms);
        anyhow::Ok(crate::patterns::analyse(
            &samples,
            truncated,
            query.since_ms,
            until,
            limit,
        ))
    })
    .await
    {
        Ok(p) => Json(p).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `lines` (default 5, at most 100) and `scope` (`host`, the default, or `all`).
fn parse_context(params: &[(String, String)]) -> Result<(usize, bool), String> {
    let (mut lines, mut same_host) = (DEFAULT_CONTEXT_LINES, true);
    for (k, v) in params {
        match (k.as_str(), v.as_str()) {
            ("lines", "") | ("scope", "") => {}
            ("lines", v) => {
                lines = v
                    .parse::<usize>()
                    .map_err(|_| "invalid lines".to_string())?
                    .min(MAX_CONTEXT_LINES);
            }
            ("scope", "host") => same_host = true,
            ("scope", "all") => same_host = false,
            ("scope", _) => return Err("scope must be host or all".into()),
            _ => {}
        }
    }
    Ok((lines, same_host))
}

/// An entry with the entries around it (the same host by default): the context needed to
/// understand a line found by a search.
async fn log_context(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let (lines, same_host) = match parse_context(&params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let access = who.access;
    match with_db(&state.db_path, "context", move |conn| {
        store::context(conn, id, lines, same_host, &access).map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(Some(ctx)) => Json(ctx).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such entry").into_response(),
        Err(e) => e.into_response(),
    }
}

/// `format` (`ndjson`, the default, or `csv`) and an optional `limit` (any size, unlike search)
/// on top of the search filters.
fn parse_export(params: Vec<(String, String)>) -> Result<(Query, Format, Option<u64>), String> {
    let mut format = Format::Ndjson;
    let mut limit = None;
    let mut rest = Vec::new();
    for (k, v) in params {
        match k.as_str() {
            "format" => format = Format::parse(&v).ok_or("format must be ndjson or csv")?,
            "limit" if !v.is_empty() => {
                limit = Some(positive_limit(&v, usize::MAX)? as u64);
            }
            // Search's own limit (capped at 1000) does not apply to exports.
            "limit" => {}
            _ => rest.push((k, v)),
        }
    }
    Ok((parse_search(rest)?, format, limit))
}

/// Streams the entries matching the search filters, oldest first, as an NDJSON or CSV download.
/// Rows are read and sent incrementally, so memory use does not depend on the export size.
async fn export(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let (mut query, format, limit) = match parse_export(params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    let Ok(permit) = state.exports.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many exports running; retry shortly",
        )
            .into_response();
    };
    let path = state.db_path.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let run = || -> anyhow::Result<()> {
            let conn = store::open(&path)?;
            let mut buf = String::from(format.header());
            let mut open = true;
            store::export_rows(&conn, &query, limit, &mut |row| {
                format.write_row(&mut buf, &row);
                if buf.len() >= EXPORT_CHUNK_BYTES {
                    // A send error means the client went away: stop reading.
                    open = tx
                        .blocking_send(Ok(Bytes::from(std::mem::take(&mut buf))))
                        .is_ok();
                }
                open
            })?;
            if open && !buf.is_empty() {
                let _ = tx.blocking_send(Ok(Bytes::from(buf)));
            }
            Ok(())
        };
        if let Err(e) = run() {
            tracing::error!("export failed: {e:#}");
            // The status line is already sent; abort the body so the client sees a truncated
            // download rather than a complete-looking one.
            let _ = tx.blocking_send(Err(std::io::Error::other("export failed")));
        }
    });
    let body = Body::from_stream(futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)));
    let disposition = format!(
        "attachment; filename=\"logpit-export.{}\"",
        format.extension()
    );
    (
        [
            (header::CONTENT_TYPE, format.content_type().to_string()),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

/// Server-sent events stream of newly ingested entries matching the search filters
/// (`q`, `host`, `app`, `level`, `f`). A `lagged` event reports entries skipped when
/// the client reads too slowly.
async fn tail(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let mut query = match parse_search(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    query.access = who.access;
    if let Some(r) = resolve_tags(&state, &mut query) {
        return r;
    }
    if state.sink.live_subscribers() >= MAX_TAIL_SUBSCRIBERS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many live tail clients",
        )
            .into_response();
    }
    let rx = state.sink.subscribe();
    let stream = futures_util::stream::unfold((rx, query), |(mut rx, query)| async move {
        loop {
            match rx.recv().await {
                Ok(entry) if query.matches(&entry) => {
                    let event = Event::default().json_data(&*entry).ok()?;
                    return Some((Ok::<_, std::convert::Infallible>(event), (rx, query)));
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let event = Event::default().event("lagged").data(n.to_string());
                    return Some((Ok(event), (rx, query)));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    // Reverse proxies such as nginx buffer responses by default, which would stall the stream.
    let mut resp = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    h.insert("x-accel-buffering", "no".parse().unwrap());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_served_pages_drop_only_layout_and_comments() {
        for (source, (page, gzipped)) in [(INDEX_HTML, index_page()), (PAGES_HTML, pages_page())] {
            let source = source.replace("/*@theme*/", THEME_CSS);
            assert!(page.len() < source.len());
            assert!(
                page.lines()
                    .all(|l| !l.is_empty() && l == l.trim() && !l.starts_with("//"))
            );
            // Every line of code survives: the page is the source's non-comment lines, trimmed.
            let kept = source
                .lines()
                .map(str::trim)
                .filter(|l| {
                    !l.is_empty()
                        && !l.starts_with("//")
                        && !(l.starts_with("/*") && l.ends_with("*/"))
                })
                .count();
            assert_eq!(page.lines().count(), kept);
            // The theme went in: its tokens are on the served page.
            assert!(page.contains("--ground:#ffffff;") && page.contains("</script>"));
            let unzipped = crate::inflate::gunzip(gzipped, 1 << 20).unwrap();
            assert_eq!(unzipped, page.as_bytes());
        }
    }

    #[test]
    fn gzip_is_sent_only_when_accepted() {
        for yes in ["gzip", "gzip, deflate, br", "br;q=1.0, GZIP;q=0.5", "*"] {
            assert!(accepts_gzip(yes), "{yes}");
        }
        for no in [
            "",
            "br",
            "deflate",
            "gzip;q=0",
            "gzip; q=0.0, br",
            "identity",
        ] {
            assert!(!accepts_gzip(no), "{no}");
        }
    }

    #[test]
    fn native_json_entry() {
        let v = json!({"ts": 5, "host": "h", "app": "a", "severity": 3, "message": "m"});
        let e = entry_from_json(&v, 99).unwrap();
        assert_eq!((e.ts, e.host.as_str(), e.severity), (5, "h", 3));
    }

    #[test]
    fn journald_json_entry() {
        let v = json!({
            "MESSAGE": "Started VM", "_HOSTNAME": "pve", "SYSLOG_IDENTIFIER": "qm",
            "PRIORITY": "4", "__REALTIME_TIMESTAMP": "1700000000123456"
        });
        let e = entry_from_json(&v, 0).unwrap();
        assert_eq!(e.ts, 1_700_000_000_123);
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.severity),
            ("pve", "qm", 4)
        );
    }

    #[test]
    fn rejects_missing_message_and_non_objects() {
        assert!(entry_from_json(&json!({"host": "h"}), 0).is_none());
        assert!(entry_from_json(&json!({"message": ""}), 0).is_none());
        assert!(entry_from_json(&json!("text"), 0).is_none());
        // journald encodes binary messages as byte arrays; they are skipped, not fatal.
        assert!(entry_from_json(&json!({"MESSAGE": [1, 2, 3]}), 0).is_none());
    }

    #[test]
    fn severity_is_clamped() {
        let e = entry_from_json(&json!({"message": "x", "severity": 42}), 0).unwrap();
        assert_eq!(e.severity, 7);
    }

    #[test]
    fn json_fields_are_flattened_and_filtered() {
        let v = json!({"message": "m", "fields": {"a": "x", "n": 5, "ok": true, "bad key": "y", "nested": {"z": 1}}});
        let e = entry_from_json(&v, 0).unwrap();
        assert_eq!(e.fields.len(), 3);
        assert_eq!(e.fields["n"], "5");
        assert_eq!(e.fields["ok"], "true");
    }

    #[test]
    fn traces_params_parse_and_validate() {
        let p = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let q = parse_traces(&p(&[]), 10_000_000).unwrap();
        assert_eq!(
            (q.since_ms, q.until_ms, q.limit),
            (6_400_000, 10_000_000, 50),
            "the last hour"
        );
        let q = parse_traces(
            &p(&[
                ("min_duration_ms", "2.5"),
                ("errors", "true"),
                ("service", "shop"),
                ("limit", "500"),
            ]),
            0,
        )
        .unwrap();
        assert_eq!(
            (
                q.min_duration_us,
                q.errors_only,
                q.service.as_str(),
                q.limit
            ),
            (2500, true, "shop", 500)
        );
        for bad in [
            &[("limit", "501")][..],
            &[("limit", "0")],
            &[("min_duration_ms", "-1")],
            &[("min_duration_ms", "NaN")],
            &[("since", "x")],
            &[("since", "5"), ("until", "4")],
        ] {
            assert!(parse_traces(&p(bad), 0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hosts_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let (q, s, form) = parse_hosts(p(&[("limit", "5")])).unwrap();
        assert_eq!(form, 0);
        assert_eq!((q.limit, s), (5, HostSort::default()));
        let (_, s, _) = parse_hosts(p(&[("sort", "host")])).unwrap();
        assert_eq!(
            s,
            HostSort {
                key: HostSortKey::Host,
                desc: false
            }
        );
        let (_, s, _) = parse_hosts(p(&[("sort", "last_ts"), ("order", "asc")])).unwrap();
        assert_eq!(
            s,
            HostSort {
                key: HostSortKey::LastTs,
                desc: false
            }
        );
        // `order` wins whichever side of `sort` it comes on.
        let (_, s, _) = parse_hosts(p(&[("order", "desc"), ("sort", "host")])).unwrap();
        assert_eq!(
            s,
            HostSort {
                key: HostSortKey::Host,
                desc: true
            }
        );
        let (_, s, _) = parse_hosts(p(&[("sort", ""), ("order", "")])).unwrap();
        assert_eq!(s, HostSort::default());
        assert!(parse_hosts(p(&[("sort", "message")])).is_err());
        assert!(parse_hosts(p(&[("order", "up")])).is_err());
        assert!(parse_hosts(p(&[("since", "x")])).is_err());
        assert_eq!(parse_hosts(p(&[("form", "5")])).unwrap().2, 5);
        assert_eq!(parse_hosts(p(&[("form", "")])).unwrap().2, 0);
        for bad in ["0", "25", "-1", "five"] {
            assert!(parse_hosts(p(&[("form", bad)])).is_err(), "{bad}");
        }
    }

    // `{"short_message":"hello"}` compressed by Python's gzip and zlib modules.
    const GZ_HELLO: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xab, 0x56, 0x2a, 0xce, 0xc8,
        0x2f, 0x2a, 0x89, 0xcf, 0x4d, 0x2d, 0x2e, 0x4e, 0x4c, 0x4f, 0x55, 0xb2, 0x52, 0xca, 0x48,
        0xcd, 0xc9, 0xc9, 0x57, 0xaa, 0x05, 0x00, 0xb5, 0x73, 0x46, 0x97, 0x19, 0x00, 0x00, 0x00,
    ];
    const ZL_HELLO: &[u8] = &[
        0x78, 0x9c, 0xab, 0x56, 0x2a, 0xce, 0xc8, 0x2f, 0x2a, 0x89, 0xcf, 0x4d, 0x2d, 0x2e, 0x4e,
        0x4c, 0x4f, 0x55, 0xb2, 0x52, 0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xaa, 0x05, 0x00, 0x7c,
        0x08, 0x09, 0x43,
    ];

    #[test]
    fn request_bodies_are_decompressed_by_content_encoding() {
        let headers = |enc: &str| {
            let mut h = HeaderMap::new();
            if !enc.is_empty() {
                h.insert(header::CONTENT_ENCODING, enc.parse().unwrap());
            }
            h
        };
        let plain = br#"{"short_message":"hello"}"#;
        let ok = |enc: &str, body: &[u8], deflate: bool| {
            decompress_request(&headers(enc), Bytes::copy_from_slice(body), deflate)
        };
        assert_eq!(ok("", plain, false).unwrap(), plain.as_slice());
        assert_eq!(ok("identity", plain, false).unwrap(), plain.as_slice());
        assert_eq!(ok("gzip", GZ_HELLO, false).unwrap(), plain.as_slice());
        assert_eq!(
            ok("GZIP", GZ_HELLO, false).unwrap(),
            plain.as_slice(),
            "case-insensitive"
        );
        assert_eq!(ok("deflate", ZL_HELLO, true).unwrap(), plain.as_slice());
        // deflate only where it is accepted; unknown encodings are a 415, damaged data a 400.
        assert_eq!(
            ok("deflate", ZL_HELLO, false).unwrap_err().0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ok("br", plain, true).unwrap_err().0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ok(
                "gzip",
                b"definitely not gzip, but long enough to pass the length check",
                false
            )
            .unwrap_err()
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ok("gzip", &GZ_HELLO[..GZ_HELLO.len() - 4], false)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn base64_and_credentials() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("dXNlcjpwYXNzMQ==").unwrap(), b"user:pass1");
        assert_eq!(
            base64_decode("dXNlcjpwYXNzMQ").unwrap(),
            b"user:pass1",
            "padding is optional"
        );
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("not base64!").is_none());
        let headers = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, v.parse().unwrap());
            h
        };
        assert_eq!(credentials(&headers("Bearer tok")).as_deref(), Some("tok"));
        // Basic: the password is the token, whatever the user name (even an empty one).
        assert_eq!(
            credentials(&headers("Basic dXNlcjp0b2s=")).as_deref(),
            Some("tok")
        );
        assert_eq!(
            credentials(&headers("Basic OnRvaw==")).as_deref(),
            Some("tok")
        );
        // A password containing a colon keeps it.
        assert_eq!(
            credentials(&headers("Basic dTpwOnE=")).as_deref(),
            Some("p:q")
        );
        for bad in [
            "Basic !!!",
            "Basic dXNlcg==",
            "Digest abc",
            "bearer tok",
            "Token tok",
        ] {
            assert!(credentials(&headers(bad)).is_none(), "{bad}");
        }
        assert!(credentials(&HeaderMap::new()).is_none());
    }

    #[test]
    fn view_validation() {
        let ok = |n: &str, q: &str| validate_view(n, q).unwrap();
        assert_eq!(
            ok("  Errors on pve ", "?host=pve&level=3&range=86400000"),
            (
                "Errors on pve".into(),
                "host=pve&level=3&range=86400000".into()
            )
        );
        assert_eq!(ok("all", "").1, "", "a view without filters is allowed");
        assert_eq!(
            ok(
                "x",
                "q=disk+error%20OR+timeout&f=src%3A10.0.0.1&group=host&since=1&until=2&app=a"
            )
            .0,
            "x"
        );
        for (name, query, why) in [
            ("", "q=x", "empty name"),
            ("   ", "q=x", "blank name"),
            (&"n".repeat(81), "q=x", "long name"),
            ("bad\nname", "q=x", "control character in the name"),
            ("v", "token=secret", "unknown parameter"),
            ("v", "q=x&live=1", "unknown parameter among valid ones"),
            ("v", "q=a b", "raw space"),
            ("v", "q=x#frag", "fragment"),
            ("v", &format!("q={}", "a".repeat(501)), "long value"),
            ("v", &format!("q=x&{}", "f=a&".repeat(600)), "long query"),
        ] {
            assert!(validate_view(name, query).is_err(), "{why}");
        }
    }

    #[test]
    fn audit_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let q = parse_audit(p(&[
            ("token", "web"),
            ("since", "5"),
            ("until", "9"),
            ("refused", "true"),
            ("limit", "7"),
        ]))
        .unwrap();
        assert_eq!(
            (
                q.token.as_deref(),
                q.since_ms,
                q.until_ms,
                q.refused,
                q.limit
            ),
            (Some("web"), Some(5), Some(9), true, 7)
        );
        assert_eq!(parse_audit(p(&[])).unwrap().limit, 100);
        assert_eq!(
            parse_audit(p(&[("limit", "999999")])).unwrap().limit,
            audit::MAX_QUERY_LIMIT
        );
        assert!(parse_audit(p(&[("limit", "0")])).is_err());
        assert!(parse_audit(p(&[("since", "x")])).is_err());
        assert!(parse_audit(p(&[("refused", "maybe")])).is_err());
        assert!(!parse_audit(p(&[("refused", "")])).unwrap().refused);
    }

    #[test]
    fn field_comparisons_and_regex_params_parse() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let q = parse_search(p(&[
            ("f", "act:block"),
            ("f", "status>=500"),
            ("f", "src~^10\\."),
            ("re", "timeout|refused"),
        ]))
        .unwrap();
        assert_eq!(q.fields, [("act".to_string(), "block".to_string())]);
        assert_eq!(q.compare.len(), 2);
        assert!(q.message_re.unwrap().is_match("connection refused"));
        assert!(parse_search(p(&[("f", "status>=abc")])).is_err());
        assert!(parse_search(p(&[("f", "novalue")])).is_err());
        assert!(parse_search(p(&[("re", "(")])).is_err());
        assert!(parse_search(p(&[("re", "")])).unwrap().message_re.is_none());
        // The search page's own filters pass through the other endpoints' parsers too.
        assert_eq!(
            parse_top(p(&[("field", "host"), ("f", "d<2.5"), ("re", "x")]))
                .unwrap()
                .0
                .compare
                .len(),
            1
        );
    }

    #[test]
    fn tag_params_are_collected() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let q = parse_search(p(&[
            ("tag", "prod"),
            ("tag", "dmz"),
            ("tag", ""),
            ("host", "h"),
        ]))
        .unwrap();
        assert_eq!(q.tags, ["prod", "dmz"]);
        assert!(
            q.host_globs.is_empty(),
            "the handler resolves them against the configuration"
        );
        assert!(validate_view("v", "tag=prod&q=x").is_ok());
    }

    #[test]
    fn patterns_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let (q, l) = parse_patterns(p(&[("host", "fw")])).unwrap();
        assert_eq!((q.host.as_deref(), l), (Some("fw"), DEFAULT_PATTERNS));
        assert_eq!(parse_patterns(p(&[("limit", "5")])).unwrap().1, 5);
        assert_eq!(
            parse_patterns(p(&[("limit", "")])).unwrap().1,
            DEFAULT_PATTERNS
        );
        assert_eq!(
            parse_patterns(p(&[("limit", "9999")])).unwrap().1,
            MAX_PATTERNS
        );
        assert!(parse_patterns(p(&[("limit", "0")])).is_err());
        assert!(parse_patterns(p(&[("limit", "x")])).is_err());
        assert!(parse_patterns(p(&[("since", "x")])).is_err());
    }

    #[test]
    fn top_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let (q, g, l) = parse_top(p(&[("field", "src"), ("host", "fw")])).unwrap();
        assert_eq!(
            (q.host.as_deref(), g, l),
            (Some("fw"), GroupBy::Field("src".into()), DEFAULT_TOP_VALUES)
        );
        assert_eq!(parse_top(p(&[("field", "host")])).unwrap().1, GroupBy::Host);
        assert_eq!(
            parse_top(p(&[("field", "severity")])).unwrap().1,
            GroupBy::Severity
        );
        // A custom field with a built-in name needs the prefix.
        assert_eq!(
            parse_top(p(&[("field", "field:host")])).unwrap().1,
            GroupBy::Field("host".into())
        );
        assert_eq!(
            parse_top(p(&[("field", "a"), ("limit", "5000")]))
                .unwrap()
                .2,
            MAX_TOP_VALUES
        );
        assert_eq!(
            parse_top(p(&[("field", "a"), ("limit", "")])).unwrap().2,
            DEFAULT_TOP_VALUES
        );
        assert!(parse_top(p(&[])).is_err(), "field is required");
        assert!(parse_top(p(&[("field", "")])).is_err());
        assert!(parse_top(p(&[("field", "a b")])).is_err());
        assert!(parse_top(p(&[("field", "a"), ("limit", "0")])).is_err());
        assert!(parse_top(p(&[("field", "a"), ("since", "x")])).is_err());
    }

    #[test]
    fn context_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            parse_context(&p(&[])).unwrap(),
            (DEFAULT_CONTEXT_LINES, true)
        );
        assert_eq!(
            parse_context(&p(&[("lines", "20"), ("scope", "all")])).unwrap(),
            (20, false)
        );
        assert_eq!(
            parse_context(&p(&[("lines", "100000")])).unwrap().0,
            MAX_CONTEXT_LINES
        );
        assert_eq!(
            parse_context(&p(&[("lines", ""), ("scope", "")])).unwrap(),
            (5, true)
        );
        assert!(parse_context(&p(&[("lines", "-1")])).is_err());
        assert!(parse_context(&p(&[("lines", "many")])).is_err());
        assert!(parse_context(&p(&[("scope", "everything")])).is_err());
    }

    #[test]
    fn export_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let (q, f, l) = parse_export(p(&[("host", "pve")])).unwrap();
        assert_eq!(
            (q.host.as_deref(), f, l),
            (Some("pve"), Format::Ndjson, None)
        );
        // Unlike search, a limit above 1000 is accepted and not clamped.
        let (_, f, l) = parse_export(p(&[("format", "csv"), ("limit", "5000000")])).unwrap();
        assert_eq!((f, l), (Format::Csv, Some(5_000_000)));
        let (_, _, l) = parse_export(p(&[("limit", "")])).unwrap();
        assert_eq!(l, None);
        assert!(parse_export(p(&[("format", "xml")])).is_err());
        assert!(parse_export(p(&[("limit", "0")])).is_err());
        assert!(parse_export(p(&[("limit", "many")])).is_err());
        assert!(parse_export(p(&[("since", "x")])).is_err());
    }

    #[test]
    fn stats_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let r = parse_stats(p(&[
            ("bucket", "5m"),
            ("group_by", "severity"),
            ("host", "pve"),
        ]))
        .unwrap();
        assert_eq!((r.bucket_ms, r.group), (Some(300_000), GroupBy::Severity));
        assert_eq!(r.query.host.as_deref(), Some("pve"));
        let r = parse_stats(p(&[("group_by", "field:act")])).unwrap();
        assert_eq!(r.group, GroupBy::Field("act".into()));
        let r = parse_stats(p(&[("bucket", ""), ("group_by", "")])).unwrap();
        assert_eq!((r.bucket_ms, r.group), (None, GroupBy::None));
        assert!(parse_stats(p(&[("bucket", "soon")])).is_err());
        assert!(parse_stats(p(&[("group_by", "message")])).is_err());
        assert!(parse_stats(p(&[("group_by", "field:a b")])).is_err());
        assert!(parse_stats(p(&[("since", "x")])).is_err());
    }

    #[test]
    fn search_params_parse_and_validate() {
        let p = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        };
        let q = parse_search(p(&[
            ("q", "disk"),
            ("host", "pve"),
            ("level", "9"),
            ("limit", "99999"),
            ("f", "act:blocked"),
            ("f", "src:10.0.0.1:80"),
        ]))
        .unwrap();
        assert_eq!(
            (
                q.text.as_deref(),
                q.host.as_deref(),
                q.max_severity,
                q.limit
            ),
            (Some("disk"), Some("pve"), Some(7), MAX_LIMIT)
        );
        assert_eq!(
            q.fields,
            vec![
                ("act".to_string(), "blocked".to_string()),
                ("src".to_string(), "10.0.0.1:80".to_string())
            ]
        );
        assert!(parse_search(p(&[("since", "abc")])).is_err());
        let q = parse_search(p(&[("before", "1700000000123:42")])).unwrap();
        assert_eq!(q.before, Some((1_700_000_000_123, 42)));
        for bad in ["1700", "a:1", "1:b", ":", "1:2:3"] {
            assert!(parse_search(p(&[("before", bad)])).is_err(), "{bad:?}");
        }
        assert!(parse_search(p(&[("before", "")])).unwrap().before.is_none());
        assert!(parse_search(p(&[("f", "novalue")])).is_err());
        assert!(parse_search(p(&[("f", "a b:c")])).is_err());
        // Empty form values (as sent by the UI) are ignored.
        let q = parse_search(p(&[("host", ""), ("level", ""), ("since", "")])).unwrap();
        assert!(q.host.is_none() && q.max_severity.is_none() && q.since_ms.is_none());
    }
}
