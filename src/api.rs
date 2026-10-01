//! HTTP API: JSON ingestion, search, metrics and the embedded web UI.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Query as QueryParams, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;

use crate::ingest::{Sink, now_ms};
use crate::metrics::Metrics;
use crate::model::LogEntry;
use crate::store::{self, Query};

const MAX_LIMIT: usize = 1000;
const DEFAULT_LIMIT: usize = 100;
const INDEX_HTML: &str = include_str!("web/index.html");

#[derive(Clone)]
pub struct AppState {
    pub sink: Sink,
    pub db_path: PathBuf,
    pub token: Option<Arc<str>>,
}

pub fn router(state: AppState, max_body_bytes: usize) -> Router {
    let protected = Router::new()
        .route("/ingest", post(ingest))
        .route("/api/logs", get(search))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .layer(DefaultBodyLimit::max(max_body_bytes));

    Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .merge(protected)
        .with_state(state)
}

/// Constant-time comparison to avoid leaking token prefixes through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(expected) = &state.token {
        let ok = bearer(req.headers()).is_some_and(|t| ct_eq(t.as_bytes(), expected.as_bytes()));
        if !ok {
            return (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
        }
    }
    next.run(req).await
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.sink.metrics().render(),
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

    Some(LogEntry {
        ts,
        host: text(&["host", "_HOSTNAME"]).unwrap_or_else(|| "unknown".into()),
        app: text(&["app", "SYSLOG_IDENTIFIER", "_COMM"]).unwrap_or_default(),
        severity,
        message,
    })
}

#[derive(serde::Serialize)]
struct IngestResult {
    accepted: usize,
    rejected: usize,
}

/// Accepts NDJSON (one object per line) or a single JSON array of objects.
async fn ingest(State(state): State<AppState>, body: String) -> impl IntoResponse {
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

    let status = if accepted == 0 && rejected > 0 {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, Json(IngestResult { accepted, rejected }))
}

#[derive(Deserialize, Default)]
struct SearchParams {
    q: Option<String>,
    host: Option<String>,
    app: Option<String>,
    /// Maximum severity number (0 = emergency … 7 = debug).
    level: Option<u8>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<usize>,
}

async fn search(
    State(state): State<AppState>,
    QueryParams(p): QueryParams<SearchParams>,
) -> Response {
    let query = Query {
        text: p.q,
        host: p.host.filter(|s| !s.is_empty()),
        app: p.app.filter(|s| !s.is_empty()),
        max_severity: p.level.map(|l| l.min(7)),
        since_ms: p.since,
        until_ms: p.until,
        limit: p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
    };
    let path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = store::open(&path)?;
        store::search(&conn, &query).map_err(anyhow::Error::from)
    })
    .await;

    match result {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => {
            tracing::error!("search failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "search failed").into_response()
        }
        Err(e) => {
            tracing::error!("search task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "search failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn constant_time_compare() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreT"));
        assert!(!ct_eq(b"secret", b"secre"));
    }
}
