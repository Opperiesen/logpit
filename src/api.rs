//! HTTP API: JSON ingestion, search, metrics and the embedded web UI.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Query as QueryParams, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::auth::{Auth, Decision, Scope};
use crate::ingest::{Sink, now_ms};
use crate::metrics::Metrics;
use crate::model::LogEntry;
use crate::stats;
use crate::store::{self, GroupBy, Query};

const MAX_LIMIT: usize = 1000;
const DEFAULT_LIMIT: usize = 100;
const MAX_TAIL_SUBSCRIBERS: usize = 32;
const INDEX_HTML: &str = include_str!("web/index.html");

#[derive(Clone)]
pub struct AppState {
    pub sink: Sink,
    pub db_path: PathBuf,
    pub auth: Arc<Auth>,
}

pub fn router(state: AppState, max_body_bytes: usize) -> Router {
    let write = Router::new()
        .route("/ingest", post(ingest))
        .route_layer(middleware::from_fn_with_state(
            (state.clone(), Scope::Write),
            require_scope,
        ))
        .layer(DefaultBodyLimit::max(max_body_bytes));
    let read = Router::new()
        .route("/api/logs", get(search))
        .route("/api/tail", get(tail))
        .route("/api/stats", get(stats))
        .route("/api/hosts", get(hosts))
        .route_layer(middleware::from_fn_with_state(
            (state.clone(), Scope::Read),
            require_scope,
        ));
    let protected = write.merge(read);

    Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .merge(protected)
        .with_state(state)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn require_scope(
    State((state, scope)): State<(AppState, Scope)>,
    req: Request,
    next: Next,
) -> Response {
    match state.auth.check(bearer(req.headers()), scope) {
        Decision::Allowed => next.run(req).await,
        Decision::Unauthorized => {
            (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response()
        }
        Decision::Forbidden => {
            (StatusCode::FORBIDDEN, "this token lacks the required scope").into_response()
        }
    }
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.sink.metrics().render() + &state.sink.silence().render_metrics(),
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
                .filter_map(|(k, v)| {
                    let v = match v {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => return None,
                    };
                    Some((k.clone(), v))
                })
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
            "since" if !v.is_empty() => q.since_ms = Some(num("since", &v)?),
            "until" if !v.is_empty() => q.until_ms = Some(num("until", &v)?),
            "limit" if !v.is_empty() => {
                q.limit = num("limit", &v)?.clamp(1, MAX_LIMIT as i64) as usize
            }
            "f" if !v.is_empty() => {
                let (key, value) = v.split_once(':').ok_or("f must be key:value")?;
                if !crate::store::valid_field_key(key) {
                    return Err(format!("invalid field name {key:?}"));
                }
                q.fields.push((key.to_string(), value.to_string()));
            }
            _ => {}
        }
    }
    Ok(q)
}

async fn search(
    State(state): State<AppState>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let query = match parse_search(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
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
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let req = match parse_stats(params) {
        Ok(r) => r,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let path = state.db_path.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Result<stats::Stats, String>> {
            let conn = store::open(&path)?;
            let until = req.query.until_ms.unwrap_or_else(now_ms);
            let since = match req.query.since_ms {
                Some(s) => s,
                None => store::min_ts(&conn)?
                    .unwrap_or(until - 3_600_000)
                    .min(until),
            };
            if since > until {
                return Ok(Err("since must not be after until".into()));
            }
            let bucket_ms = req
                .bucket_ms
                .unwrap_or_else(|| stats::auto_bucket_ms(until - since));
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
            let mut rows = store::stats(&conn, &query, bucket_ms, &req.group)?;
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
        .await;

    match result {
        Ok(Ok(Ok(s))) => Json(s).into_response(),
        Ok(Ok(Err(msg))) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Ok(Err(e)) => {
            tracing::error!("stats failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "stats failed").into_response()
        }
        Err(e) => {
            tracing::error!("stats task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "stats failed").into_response()
        }
    }
}

/// Per-host totals (entries, errors, warnings, last activity, silence state) over the entries
/// matching the search filters. `limit` caps the number of hosts.
async fn hosts(
    State(state): State<AppState>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let query = match parse_search(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = store::open(&path)?;
        store::host_summary(&conn, &query).map_err(anyhow::Error::from)
    })
    .await;
    match result {
        Ok(Ok(mut rows)) => {
            for r in &mut rows {
                r.silent = state.sink.silence().is_silent(&r.host);
            }
            Json(rows).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("host summary failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "host summary failed").into_response()
        }
        Err(e) => {
            tracing::error!("host summary task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "host summary failed").into_response()
        }
    }
}

/// Server-sent events stream of newly ingested entries matching the search filters
/// (`q`, `host`, `app`, `level`, `f`). A `lagged` event reports entries skipped when
/// the client reads too slowly.
async fn tail(
    State(state): State<AppState>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let query = match parse_search(params) {
        Ok(q) => q,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
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
        assert!(parse_search(p(&[("f", "novalue")])).is_err());
        assert!(parse_search(p(&[("f", "a b:c")])).is_err());
        // Empty form values (as sent by the UI) are ignored.
        let q = parse_search(p(&[("host", ""), ("level", ""), ("since", "")])).unwrap();
        assert!(q.host.is_none() && q.max_severity.is_none() && q.since_ms.is_none());
    }
}
