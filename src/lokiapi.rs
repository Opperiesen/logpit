//! Loki's query API (`/loki/api/v1/query_range`, `query`, `labels`, `label/<name>/values` and
//! `series`), so that Grafana's Loki data source can browse and chart LogPit. Queries are the
//! LogQL subset of [`crate::logql`].
//!
//! Streams are identified by `host`, `app` (when set) and `level`; structured fields can be used
//! in selectors and `by (...)` clauses as extra labels.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axum::body::Bytes;
use axum::extract::{Extension, Query as QueryParams, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::api::AppState;
use crate::auth::Identity;
use crate::ingest::now_ms;
use crate::logql::{self, Expr, LabelKind, LogExpr, RangeFn, level_label};
use crate::store::{self, GroupBy, Query};

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 5000;
/// Points per series, as in Loki.
const MAX_POINTS: i64 = 11_000;
/// Series in one metric result.
const MAX_SERIES: usize = 1000;
const DEFAULT_RANGE_MS: i64 = 3_600_000;
const LABEL_WINDOW_MS: i64 = 6 * 3_600_000;
const MAX_LABEL_VALUES: usize = 1000;
const MAX_FIELD_LABELS: usize = 100;

// ---- parameters ---------------------------------------------------------------------------

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes an `application/x-www-form-urlencoded` body.
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

/// The query string's parameters plus those of a form-encoded POST body.
fn all_params(
    mut params: Vec<(String, String)>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Vec<(String, String)> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    if is_form && let Ok(text) = std::str::from_utf8(body) {
        params.extend(parse_form(text));
    }
    params
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, v)| k == name && !v.is_empty())
        .map(|(_, v)| v.as_str())
}

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-10-03T12:00:00Z`, with optional fraction and `±hh:mm` offset, as Unix ms.
fn parse_rfc3339(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once(['T', 't', ' '])?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    if d.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return None;
    }
    let (clock, offset_min) = if let Some(c) = rest.strip_suffix(['Z', 'z']) {
        (c, 0)
    } else {
        let at = rest.rfind(['+', '-'])?;
        let (c, off) = rest.split_at(at);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':')?;
        (
            c,
            sign * (oh.parse::<i64>().ok()? * 60 + om.parse::<i64>().ok()?),
        )
    };
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let mut t = hms.split(':');
    let (h, mi, s): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    if t.next().is_some() || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let millis = if frac.is_empty() {
        0
    } else if frac.bytes().all(|b| b.is_ascii_digit()) {
        format!("{:0<3}", &frac[..frac.len().min(3)])
            .parse::<i64>()
            .ok()?
    } else {
        return None;
    };
    let secs = days_from_civil(y, mo, da) * 86_400 + h * 3600 + mi * 60 + s - offset_min * 60;
    Some(secs * 1000 + millis)
}

/// A Loki time: Unix seconds (maybe fractional), milliseconds, microseconds or nanoseconds
/// (told apart by size), or RFC 3339. Returns Unix ms.
pub fn parse_time(text: &str) -> Result<i64, String> {
    let t = text.trim();
    if let Ok(n) = t.parse::<f64>()
        && n.is_finite()
        && n >= 0.0
    {
        let ms = if n >= 1e17 {
            n / 1e6
        } else if n >= 1e14 {
            n / 1e3
        } else if n >= 1e11 {
            n
        } else {
            n * 1e3
        };
        return Ok(ms.floor() as i64);
    }
    parse_rfc3339(t).ok_or_else(|| format!("invalid time {text:?}"))
}

/// A step: seconds (maybe fractional) or a duration such as `1m`. Returns ms.
fn parse_step(text: &str) -> Result<i64, String> {
    let ms = match text.trim().parse::<f64>() {
        Ok(secs) if secs.is_finite() => (secs * 1000.0).round() as i64,
        _ => logql::parse_duration_ms(text).ok_or_else(|| format!("invalid step {text:?}"))?,
    };
    if ms < 1 {
        return Err("step must be positive".into());
    }
    Ok(ms)
}

fn bad(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn server_failure(what: &str, e: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!("loki {what} failed: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{what} failed"))
}

fn success(data: Value) -> Response {
    axum::Json(json!({ "status": "success", "data": data })).into_response()
}

fn gcd(a: i64, b: i64) -> i64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

// ---- running queries ----------------------------------------------------------------------

fn base_query(log: &LogExpr, who: &Identity, since: i64, until: i64) -> Result<Query, String> {
    let mut q = Query {
        since_ms: Some(since),
        until_ms: Some(until),
        access: who.access.clone(),
        ..Default::default()
    };
    log.apply(&mut q)?;
    Ok(q)
}

fn stream_labels(host: &str, app: &str, severity: u8) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("host".to_string(), host.to_string());
    if !app.is_empty() {
        labels.insert("app".to_string(), app.to_string());
    }
    labels.insert("level".to_string(), level_label(severity).to_string());
    labels
}

/// Log lines as Loki streams.
fn log_streams(
    conn: &rusqlite::Connection,
    log: &LogExpr,
    who: &Identity,
    (start, end): (i64, i64),
    limit: usize,
    forward: bool,
) -> Result<Value, String> {
    let mut q = base_query(log, who, start, end)?;
    q.limit = limit;
    let rows = store::search_ordered(conn, &q, forward).map_err(|e| e.to_string())?;
    let mut streams: Vec<(BTreeMap<String, String>, Vec<Value>)> = Vec::new();
    let mut index: HashMap<BTreeMap<String, String>, usize> = HashMap::new();
    for r in rows {
        let labels = stream_labels(&r.host, &r.app, r.severity);
        let at = *index.entry(labels.clone()).or_insert_with(|| {
            streams.push((labels, Vec::new()));
            streams.len() - 1
        });
        let ns = (r.ts as i128 * 1_000_000).to_string();
        streams[at].1.push(json!([ns, r.message]));
    }
    Ok(json!({
        "resultType": "streams",
        "result": streams
            .into_iter()
            .map(|(labels, values)| json!({ "stream": labels, "values": values }))
            .collect::<Vec<_>>(),
        "stats": {},
    }))
}

/// How a series label is read from the database and what it is called in the result.
struct Grouping {
    name: String,
    kind: LabelKind,
}

fn groupings(sum_by: &Option<Vec<String>>) -> Result<Vec<Grouping>, String> {
    let names: Vec<String> = match sum_by {
        Some(labels) => labels.clone(),
        None => ["host", "app", "level"].map(String::from).to_vec(),
    };
    names
        .into_iter()
        .map(|name| {
            let kind = logql::label_kind(&name)?;
            Ok(Grouping { name, kind })
        })
        .collect()
}

fn group_by(g: &Grouping) -> GroupBy {
    match &g.kind {
        LabelKind::Host => GroupBy::Host,
        LabelKind::App => GroupBy::App,
        LabelKind::Level => GroupBy::Severity,
        LabelKind::Field(k) => GroupBy::Field(k.clone()),
    }
}

/// The text of one group value as a label value (severity numbers become level words).
fn label_value(g: &Grouping, raw: String) -> String {
    match (&g.kind, raw.parse::<u8>()) {
        (LabelKind::Level, Ok(sev)) => level_label(sev).to_string(),
        _ => raw,
    }
}

/// Counts per series and bucket, with severities merged into level words.
type Counts = HashMap<Vec<String>, BTreeMap<i64, u64>>;

fn count_series(
    conn: &rusqlite::Connection,
    q: &Query,
    origin: i64,
    bucket_ms: i64,
    groups: &[Grouping],
) -> Result<Counts, String> {
    let by: Vec<GroupBy> = groups.iter().map(group_by).collect();
    let rows = store::series(conn, q, origin, bucket_ms, &by).map_err(|e| e.to_string())?;
    let mut counts: Counts = HashMap::new();
    for (bucket, raw, n) in rows {
        let labels: Vec<String> = groups
            .iter()
            .zip(raw)
            .map(|(g, v)| label_value(g, v))
            .collect();
        *counts.entry(labels).or_default().entry(bucket).or_insert(0) += n;
        if counts.len() > MAX_SERIES {
            return Err(format!(
                "more than {MAX_SERIES} series: group by fewer labels or narrow the selector"
            ));
        }
    }
    Ok(counts)
}

fn metric_labels(groups: &[Grouping], values: &[String]) -> BTreeMap<String, String> {
    groups
        .iter()
        .zip(values)
        .filter(|(_, v)| !v.is_empty())
        .map(|(g, v)| (g.name.clone(), v.clone()))
        .collect()
}

fn number_text(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

struct Metric<'a> {
    func: RangeFn,
    log: &'a LogExpr,
    range_ms: i64,
    sum_by: &'a Option<Vec<String>>,
}

impl Metric<'_> {
    fn value(&self, count: u64) -> f64 {
        match self.func {
            RangeFn::CountOverTime => count as f64,
            RangeFn::Rate => count as f64 / (self.range_ms as f64 / 1000.0),
        }
    }
}

/// A matrix: for each step `t` the entries in `(t - range, t]`, omitting steps without entries.
fn metric_matrix(
    conn: &rusqlite::Connection,
    m: &Metric,
    who: &Identity,
    (start, end): (i64, i64),
    step_ms: i64,
) -> Result<Value, String> {
    if (end - start) / step_ms + 1 > MAX_POINTS {
        return Err(format!(
            "exceeded the maximum resolution of {MAX_POINTS} points per series: use a larger step"
        ));
    }
    let origin = start - m.range_ms;
    let bucket = gcd(step_ms, m.range_ms);
    let groups = groupings(m.sum_by)?;
    let q = base_query(m.log, who, origin + 1, end)?;
    let counts = count_series(conn, &q, origin, bucket, &groups)?;
    let (per_step, per_range) = (step_ms / bucket, m.range_ms / bucket);
    let mut result: Vec<(BTreeMap<String, String>, Vec<Value>)> = Vec::new();
    for (labels, buckets) in counts {
        // Running totals over the sparse buckets, to sum any window with two lookups.
        let mut at: Vec<i64> = Vec::with_capacity(buckets.len());
        let mut total: Vec<u64> = Vec::with_capacity(buckets.len());
        let mut run = 0;
        for (idx, n) in &buckets {
            run += n;
            at.push(*idx);
            total.push(run);
        }
        let upto = |idx: i64| -> u64 {
            match at.partition_point(|b| *b <= idx) {
                0 => 0,
                n => total[n - 1],
            }
        };
        let mut values = Vec::new();
        let mut t = start;
        let mut k = 0i64;
        while t <= end {
            // Window (t - range, t] is buckets k*per_step ..= k*per_step + per_range - 1.
            let hi = k * per_step + per_range - 1;
            let count = upto(hi) - upto(hi - per_range);
            if count > 0 {
                values.push(json!([t as f64 / 1000.0, number_text(m.value(count))]));
            }
            t += step_ms;
            k += 1;
        }
        if !values.is_empty() {
            result.push((metric_labels(&groups, &labels), values));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(json!({
        "resultType": "matrix",
        "result": result
            .into_iter()
            .map(|(metric, values)| json!({ "metric": metric, "values": values }))
            .collect::<Vec<_>>(),
        "stats": {},
    }))
}

/// A vector: the entries in `(t - range, t]` per series.
fn metric_vector(
    conn: &rusqlite::Connection,
    m: &Metric,
    who: &Identity,
    t: i64,
) -> Result<Value, String> {
    let origin = t - m.range_ms;
    let groups = groupings(m.sum_by)?;
    let q = base_query(m.log, who, origin + 1, t)?;
    let counts = count_series(conn, &q, origin, m.range_ms, &groups)?;
    let mut result: Vec<(BTreeMap<String, String>, u64)> = counts
        .into_iter()
        .map(|(labels, b)| (metric_labels(&groups, &labels), b.values().sum()))
        .filter(|(_, n)| *n > 0)
        .collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(json!({
        "resultType": "vector",
        "result": result
            .into_iter()
            .map(|(metric, n)| json!({
                "metric": metric,
                "value": [t as f64 / 1000.0, number_text(m.value(n))],
            }))
            .collect::<Vec<_>>(),
        "stats": {},
    }))
}

// ---- handlers -----------------------------------------------------------------------------

fn parse_limit(params: &[(String, String)]) -> Result<usize, String> {
    match param(params, "limit") {
        None => Ok(DEFAULT_LIMIT),
        Some(v) => v
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .map(|n| n.min(MAX_LIMIT))
            .ok_or_else(|| "invalid limit".to_string()),
    }
}

/// `start` and `end` (default: the hour before `end`, and now).
fn parse_window(params: &[(String, String)], default_span: i64) -> Result<(i64, i64), String> {
    let now = now_ms();
    let end = param(params, "end").map_or(Ok(now), parse_time)?;
    let start = match param(params, "start") {
        Some(s) => parse_time(s)?,
        None => end - default_span,
    };
    if start > end {
        return Err("start must not be after end".into());
    }
    Ok((start, end))
}

async fn run_blocking<T: Send + 'static>(
    state: &AppState,
    what: &'static str,
    job: impl FnOnce(&rusqlite::Connection) -> Result<T, String> + Send + 'static,
) -> Result<T, (StatusCode, String)> {
    let path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Result<T, String>, String> {
        let conn = store::open(&path).map_err(|e| format!("{e:#}"))?;
        Ok(job(&conn))
    })
    .await;
    match result {
        Ok(Ok(Ok(v))) => Ok(v),
        // What the job itself reports is about the query (a bad regex, too many series).
        Ok(Ok(Err(msg))) => Err((StatusCode::BAD_REQUEST, msg)),
        Ok(Err(msg)) => Err(server_failure(what, msg)),
        Err(e) => Err(server_failure(what, e)),
    }
}

/// `GET|POST /loki/api/v1/query_range`: log streams for a log query, a matrix for a metric one.
pub async fn query_range(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = all_params(params, &headers, &body);
    let Some(query) = param(&params, "query") else {
        return bad("query is required");
    };
    let expr = match logql::parse(query) {
        Ok(e) => e,
        Err(msg) => return bad(format!("parse error: {msg}")),
    };
    let window = match parse_window(&params, DEFAULT_RANGE_MS) {
        Ok(w) => w,
        Err(msg) => return bad(msg),
    };
    let limit = match parse_limit(&params) {
        Ok(l) => l,
        Err(msg) => return bad(msg),
    };
    let forward = param(&params, "direction").is_some_and(|d| d.eq_ignore_ascii_case("forward"));
    let step = match param(&params, "step") {
        Some(s) => match parse_step(s) {
            Ok(ms) => ms,
            Err(msg) => return bad(msg),
        },
        // Loki's default: about 250 points.
        None => ((window.1 - window.0) / 250).max(1000) / 1000 * 1000,
    };
    let data = run_blocking(&state, "query", move |conn| match expr {
        Expr::Log(log) => log_streams(conn, &log, &who, window, limit, forward),
        Expr::Metric {
            func,
            log,
            range_ms,
            sum_by,
        } => {
            let m = Metric {
                func,
                log: &log,
                range_ms,
                sum_by: &sum_by,
            };
            metric_matrix(conn, &m, &who, window, step)
        }
        Expr::Scalar(_) => Err("a range query needs a log or metric query".into()),
    })
    .await;
    match data {
        Ok(v) => success(v),
        Err(e) => e.into_response(),
    }
}

/// `GET|POST /loki/api/v1/query`: a vector for a metric query, the newest lines of the last hour
/// for a log query, and the answer to `vector(1)+vector(1)`, which Grafana uses as its health check.
pub async fn query_instant(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = all_params(params, &headers, &body);
    let Some(query) = param(&params, "query") else {
        return bad("query is required");
    };
    let expr = match logql::parse(query) {
        Ok(e) => e,
        Err(msg) => return bad(format!("parse error: {msg}")),
    };
    let t = match param(&params, "time").map_or(Ok(now_ms()), parse_time) {
        Ok(t) => t,
        Err(msg) => return bad(msg),
    };
    let limit = match parse_limit(&params) {
        Ok(l) => l,
        Err(msg) => return bad(msg),
    };
    let forward = param(&params, "direction").is_some_and(|d| d.eq_ignore_ascii_case("forward"));
    if let Expr::Scalar(v) = &expr {
        return success(json!({
            "resultType": "vector",
            "result": [{ "metric": {}, "value": [t as f64 / 1000.0, number_text(*v)] }],
        }));
    }
    let data = run_blocking(&state, "query", move |conn| match expr {
        Expr::Log(log) => log_streams(conn, &log, &who, (t - 3_600_000, t), limit, forward),
        Expr::Metric {
            func,
            log,
            range_ms,
            sum_by,
        } => {
            let m = Metric {
                func,
                log: &log,
                range_ms,
                sum_by: &sum_by,
            };
            metric_vector(conn, &m, &who, t)
        }
        Expr::Scalar(_) => unreachable!("answered above"),
    })
    .await;
    match data {
        Ok(v) => success(v),
        Err(e) => e.into_response(),
    }
}

/// The filters of an optional `query` selector (`{host="a"}`) for the label endpoints.
fn selector_query(
    params: &[(String, String)],
    who: &Identity,
    window: (i64, i64),
) -> Result<Query, String> {
    let log = match param(params, "query") {
        Some(text) => match logql::parse(text).map_err(|m| format!("parse error: {m}"))? {
            Expr::Log(l) => l,
            _ => return Err("query must be a log stream selector".into()),
        },
        None => LogExpr::default(),
    };
    base_query(&log, who, window.0, window.1)
}

/// `GET /loki/api/v1/labels`: `host`, `app`, `level` and the structured fields.
pub async fn labels(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let window = match parse_window(&params, LABEL_WINDOW_MS) {
        Ok(w) => w,
        Err(msg) => return bad(msg),
    };
    let q = match selector_query(&params, &who, window) {
        Ok(q) => q,
        Err(msg) => return bad(msg),
    };
    let data = run_blocking(&state, "labels", move |conn| {
        let fields = store::field_names(conn, &q, MAX_FIELD_LABELS).map_err(|e| e.to_string())?;
        let mut names: BTreeSet<String> = ["host", "app", "level"].map(String::from).into();
        names.extend(fields.into_iter().map(|(k, _)| k));
        Ok(names.into_iter().collect::<Vec<_>>())
    })
    .await;
    match data {
        Ok(names) => success(json!(names)),
        Err(e) => e.into_response(),
    }
}

/// `GET /loki/api/v1/label/<name>/values`.
pub async fn label_values(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    axum::extract::Path(name): axum::extract::Path<String>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
) -> Response {
    let window = match parse_window(&params, LABEL_WINDOW_MS) {
        Ok(w) => w,
        Err(msg) => return bad(msg),
    };
    let q = match selector_query(&params, &who, window) {
        Ok(q) => q,
        Err(msg) => return bad(msg),
    };
    let grouping = match logql::label_kind(&name) {
        Ok(kind) => Grouping { name, kind },
        Err(msg) => return bad(msg),
    };
    let data = run_blocking(&state, "label values", move |conn| {
        let top = store::top_values(conn, &q, &group_by(&grouping), MAX_LABEL_VALUES)
            .map_err(|e| e.to_string())?;
        // Several severities share a level word, so the words are collected as a set.
        let values: BTreeSet<String> = top
            .values
            .into_iter()
            .map(|v| label_value(&grouping, v.value))
            .collect();
        Ok(values.into_iter().collect::<Vec<_>>())
    })
    .await;
    match data {
        Ok(values) => success(json!(values)),
        Err(e) => e.into_response(),
    }
}

/// `GET|POST /loki/api/v1/series`: the label sets of the streams matching the `match[]` selectors.
pub async fn series_list(
    State(state): State<AppState>,
    Extension(who): Extension<Identity>,
    QueryParams(params): QueryParams<Vec<(String, String)>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = all_params(params, &headers, &body);
    let window = match parse_window(&params, LABEL_WINDOW_MS) {
        Ok(w) => w,
        Err(msg) => return bad(msg),
    };
    let mut matches: Vec<&str> = params
        .iter()
        .filter(|(k, _)| k == "match[]" || k == "match")
        .map(|(_, v)| v.as_str())
        .collect();
    if matches.is_empty() {
        matches.push("{}");
    }
    let mut queries = Vec::new();
    for text in matches {
        let log = match logql::parse(text) {
            Ok(Expr::Log(l)) => l,
            Ok(_) => return bad("match[] must be a log stream selector"),
            Err(msg) => return bad(format!("parse error: {msg}")),
        };
        match base_query(&log, &who, window.0, window.1) {
            Ok(q) => queries.push(q),
            Err(msg) => return bad(msg),
        }
    }
    let data = run_blocking(&state, "series", move |conn| {
        let groups = groupings(&None)?;
        let mut seen: BTreeSet<BTreeMap<String, String>> = BTreeSet::new();
        for q in &queries {
            let counts = count_series(conn, q, window.0 - 1, window.1 - window.0 + 1, &groups)?;
            seen.extend(counts.keys().map(|labels| metric_labels(&groups, labels)));
        }
        Ok(seen.into_iter().collect::<Vec<_>>())
    })
    .await;
    match data {
        Ok(sets) => success(json!(sets)),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LogEntry;

    #[test]
    fn times_accept_every_loki_form() {
        // 2026-10-03T12:00:00Z
        let ms = 1_791_028_800_000i64;
        for text in [
            "1791028800",
            "1791028800.0",
            "1791028800000",
            "1791028800000000",
            "1791028800000000000",
            "2026-10-03T12:00:00Z",
            "2026-10-03T14:00:00+02:00",
            "2026-10-03T07:30:00-04:30",
            "2026-10-03 12:00:00Z",
        ] {
            assert_eq!(parse_time(text), Ok(ms), "{text}");
        }
        assert_eq!(parse_time("2026-10-03T12:00:00.250Z"), Ok(ms + 250));
        assert_eq!(parse_time("1791028800.5"), Ok(ms + 500));
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(parse_time("2000-02-29T00:00:00Z"), Ok(951_782_400_000));
        for bad in [
            "",
            "yesterday",
            "2026-13-03T12:00:00Z",
            "2026-10-03T25:00:00Z",
            "-5",
            "NaN",
        ] {
            assert!(parse_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn steps_are_seconds_or_durations() {
        assert_eq!(parse_step("15"), Ok(15_000));
        assert_eq!(parse_step("0.5"), Ok(500));
        assert_eq!(parse_step("1m"), Ok(60_000));
        assert_eq!(parse_step("1h30m"), Ok(5_400_000));
        for bad in ["", "0", "-1", "x", "0s"] {
            assert!(parse_step(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn form_bodies_are_decoded() {
        assert_eq!(
            parse_form("query=%7Bhost%3D%22a%22%7D&limit=5&match%5B%5D=%7B%7D&x=a+b&y=%zz&z=%4"),
            [
                ("query".to_string(), "{host=\"a\"}".to_string()),
                ("limit".to_string(), "5".to_string()),
                ("match[]".to_string(), "{}".to_string()),
                ("x".to_string(), "a b".to_string()),
                ("y".to_string(), "%zz".to_string()),
                ("z".to_string(), "%4".to_string()),
            ]
        );
        assert!(parse_form("").is_empty());
    }

    fn db(
        name: &str,
        entries: &[(i64, &str, &str, u8, &str)],
    ) -> (std::path::PathBuf, rusqlite::Connection) {
        let path =
            std::env::temp_dir().join(format!("logpit-loki-{name}-{}.db", std::process::id()));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        let mut conn = store::open(&path).unwrap();
        let batch: Vec<LogEntry> = entries
            .iter()
            .map(|(ts, host, app, sev, msg)| LogEntry {
                ts: *ts,
                host: host.to_string(),
                app: app.to_string(),
                severity: *sev,
                message: msg.to_string(),
                ..Default::default()
            })
            .collect();
        store::insert_batch(&mut conn, &batch).unwrap();
        (path, conn)
    }

    fn who() -> Identity {
        Identity::anonymous()
    }

    type Series = (BTreeMap<String, String>, Vec<(f64, String)>);

    fn values(v: &Value) -> Vec<Series> {
        v["result"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let metric = s["metric"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect();
                let points = s["values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| (p[0].as_f64().unwrap(), p[1].as_str().unwrap().to_string()))
                    .collect();
                (metric, points)
            })
            .collect()
    }

    #[test]
    fn log_queries_return_streams_newest_first_or_oldest_first() {
        let (path, conn) = db(
            "streams",
            &[
                (1_000, "web1", "nginx", 3, "boom 1"),
                (2_000, "web1", "nginx", 3, "boom 2"),
                (3_000, "web1", "nginx", 6, "ok"),
                (4_000, "db1", "", 4, "slow"),
            ],
        );
        let run = |q: &str, forward: bool, limit: usize| {
            let Expr::Log(log) = logql::parse(q).unwrap() else {
                panic!()
            };
            log_streams(&conn, &log, &who(), (0, 10_000), limit, forward).unwrap()
        };
        let all = run("{}", false, 100);
        assert_eq!(all["resultType"], "streams");
        let result = all["result"].as_array().unwrap();
        assert_eq!(result.len(), 3, "one stream per host, app and level");
        // Newest first overall: the first stream is the db1 one.
        assert_eq!(
            result[0]["stream"],
            json!({"host": "db1", "level": "warning"})
        );
        assert_eq!(result[0]["values"], json!([["4000000000", "slow"]]));
        let errors = run(r#"{host="web1", level="error"}"#, false, 100);
        assert_eq!(
            errors["result"][0]["values"],
            json!([["2000000000", "boom 2"], ["1000000000", "boom 1"]])
        );
        assert_eq!(
            errors["result"][0]["stream"],
            json!({"host": "web1", "app": "nginx", "level": "error"})
        );
        let forward = run(r#"{app="nginx"} |= "boom""#, true, 100);
        assert_eq!(
            forward["result"][0]["values"],
            json!([["1000000000", "boom 1"], ["2000000000", "boom 2"]])
        );
        assert_eq!(
            run("{}", false, 2)["result"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["values"].as_array().unwrap().len())
                .sum::<usize>(),
            2
        );
        // Access limits apply.
        let Expr::Log(log) = logql::parse("{}").unwrap() else {
            panic!()
        };
        let limited = Identity {
            name: "t".into(),
            access: crate::auth::Access {
                hosts: vec!["db1".into()],
                apps: vec![],
            },
        };
        let v = log_streams(&conn, &log, &limited, (0, 10_000), 100, false).unwrap();
        assert_eq!(v["result"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn metric_queries_count_entries_in_trailing_windows() {
        // Entries at 1s, 2s, 12s (web1 error), 13s (web1 info), 25s (db1 error).
        let (path, conn) = db(
            "matrix",
            &[
                (1_000, "web1", "a", 3, "x"),
                (2_000, "web1", "a", 3, "x"),
                (12_000, "web1", "a", 3, "x"),
                (13_000, "web1", "a", 6, "y"),
                (25_000, "db1", "a", 3, "x"),
            ],
        );
        let run = |q: &str, start: i64, end: i64, step: i64| {
            let Expr::Metric {
                func,
                log,
                range_ms,
                sum_by,
            } = logql::parse(q).unwrap()
            else {
                panic!()
            };
            let m = Metric {
                func,
                log: &log,
                range_ms,
                sum_by: &sum_by,
            };
            values(&metric_matrix(&conn, &m, &who(), (start, end), step).unwrap())
        };
        // Window 10s, step 10s from t=10s: (0,10], (10,20], (20,30].
        let total = run("sum(count_over_time({}[10s]))", 10_000, 30_000, 10_000);
        assert_eq!(total.len(), 1);
        assert!(total[0].0.is_empty());
        assert_eq!(
            total[0].1,
            [
                (10.0, "2".to_string()),
                (20.0, "2".to_string()),
                (30.0, "1".to_string())
            ]
        );
        // Grouped by level, zero points are omitted.
        let by_level = run(
            "sum by (level) (count_over_time({}[10s]))",
            10_000,
            30_000,
            10_000,
        );
        assert_eq!(by_level.len(), 2);
        assert_eq!(by_level[0].0["level"], "error");
        assert_eq!(
            by_level[0].1,
            [
                (10.0, "2".to_string()),
                (20.0, "1".to_string()),
                (30.0, "1".to_string())
            ]
        );
        assert_eq!(by_level[1].0["level"], "info");
        assert_eq!(by_level[1].1, [(20.0, "1".to_string())]);
        // A window longer than the step overlaps: 20s window every 10s.
        let wide = run("sum(count_over_time({}[20s]))", 10_000, 30_000, 10_000);
        assert_eq!(
            wide[0].1,
            [
                (10.0, "2".to_string()),
                (20.0, "4".to_string()),
                (30.0, "3".to_string())
            ]
        );
        // A step that does not divide the window still works (gcd 5s buckets).
        let odd = run("sum(count_over_time({}[15s]))", 15_000, 25_000, 10_000);
        assert_eq!(odd[0].1, [(15.0, "4".to_string()), (25.0, "3".to_string())]);
        // `rate` divides by the window, and selectors narrow.
        let rate = run(r#"sum(rate({host="web1"}[10s]))"#, 10_000, 20_000, 10_000);
        assert_eq!(
            rate[0].1,
            [(10.0, "0.2".to_string()), (20.0, "0.2".to_string())]
        );
        // Without `sum`, one series per stream (host, app, level).
        let streams = run("count_over_time({}[30s])", 30_000, 30_000, 1_000);
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[0].0["host"], "db1");
        // Grouping by a label that does not exist gives one series with no labels.
        let none = run(
            "sum by (nothing) (count_over_time({}[30s]))",
            30_000,
            30_000,
            1_000,
        );
        assert_eq!(none.len(), 1);
        assert!(none[0].0.is_empty());
        // Too many points is refused.
        let Expr::Metric {
            func,
            log,
            range_ms,
            sum_by,
        } = logql::parse("sum(rate({}[5m]))").unwrap()
        else {
            panic!()
        };
        let m = Metric {
            func,
            log: &log,
            range_ms,
            sum_by: &sum_by,
        };
        assert!(metric_matrix(&conn, &m, &who(), (0, 100_000_000), 1000).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn instant_vector_counts_the_trailing_window() {
        let (path, conn) = db(
            "vector",
            &[
                (1_000, "web1", "a", 3, "x"),
                (9_000, "web1", "a", 3, "x"),
                (9_500, "db1", "a", 6, "y"),
            ],
        );
        let Expr::Metric {
            func,
            log,
            range_ms,
            sum_by,
        } = logql::parse(r#"sum by (host) (count_over_time({app="a"}[10s]))"#).unwrap()
        else {
            panic!()
        };
        let m = Metric {
            func,
            log: &log,
            range_ms,
            sum_by: &sum_by,
        };
        let v = metric_vector(&conn, &m, &who(), 10_000).unwrap();
        assert_eq!(v["resultType"], "vector");
        assert_eq!(
            v["result"],
            json!([
                {"metric": {"host": "db1"}, "value": [10.0, "1"]},
                {"metric": {"host": "web1"}, "value": [10.0, "2"]},
            ])
        );
        // The window is (t-10s, t]: an entry exactly at t-10s is out.
        let v = metric_vector(&conn, &m, &who(), 11_000).unwrap();
        assert_eq!(v["result"].as_array().unwrap().len(), 2);
        let v = metric_vector(&conn, &m, &who(), 11_000 + 100).unwrap();
        assert_eq!(v["result"][0]["value"][1], "1");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn series_and_labels_use_the_stream_labels() {
        let (path, conn) = db(
            "series",
            &[
                (1_000, "web1", "nginx", 3, "x"),
                (2_000, "web1", "nginx", 5, "x"),
                (3_000, "web1", "nginx", 6, "x"),
                (4_000, "db1", "", 6, "x"),
            ],
        );
        let groups = groupings(&None).unwrap();
        let mut q = Query {
            since_ms: Some(0),
            until_ms: Some(10_000),
            ..Default::default()
        };
        logql::parse("{}").ok();
        let counts = count_series(&conn, &q, -1, 10_001, &groups).unwrap();
        let sets: BTreeSet<_> = counts.keys().map(|l| metric_labels(&groups, l)).collect();
        // `notice` and `info` share the level word, so they are one stream.
        assert_eq!(sets.len(), 3);
        assert!(sets.contains(&BTreeMap::from([
            ("host".to_string(), "db1".to_string()),
            ("level".to_string(), "info".to_string()),
        ])));
        q.column_filters.clear();
        let g = Grouping {
            name: "level".into(),
            kind: LabelKind::Level,
        };
        let top = store::top_values(&conn, &q, &group_by(&g), 10).unwrap();
        let words: BTreeSet<String> = top
            .values
            .into_iter()
            .map(|v| label_value(&g, v.value))
            .collect();
        assert_eq!(
            words,
            BTreeSet::from(["error".to_string(), "info".to_string()])
        );
        let _ = std::fs::remove_file(path);
    }
}
