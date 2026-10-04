//! OpenTelemetry traces: the spans of `ExportTraceServiceRequest`, sent to `POST /v1/traces`
//! (protobuf or JSON) or to gRPC `TraceService/Export`. A span keeps its trace, its parent, its
//! timing, its status, its service and host (read from the resource like the logs'), its
//! attributes and its events, all bounded. A span without a usable trace or span id is skipped.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::model::truncate_utf8;
use crate::otlp::{
    APP_KEYS, Attrs, HOST_KEYS, hex, json_attrs, json_nanos, key_value, scope_name, text,
};
use crate::proto::{Reader, utf8};
use crate::structured::MAX_VALUE_BYTES;

const MAX_ATTRIBUTES: usize = 64;
const MAX_EVENTS: usize = 32;
const MAX_NAME_BYTES: usize = 255;
const MAX_STATUS_BYTES: usize = 1024;

/// What a span did, as OpenTelemetry's `SpanKind`.
pub const KINDS: [&str; 6] = [
    "unspecified",
    "internal",
    "server",
    "client",
    "producer",
    "consumer",
];

/// `Status.code`: unset, ok or error.
pub const STATUS_UNSET: u8 = 0;
pub const STATUS_OK: u8 = 1;
pub const STATUS_ERROR: u8 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SpanEvent {
    /// Microseconds since the epoch.
    pub ts_us: i64,
    pub name: String,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub attributes: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Span {
    /// 32 lower-case hex digits.
    pub trace_id: String,
    /// 16 lower-case hex digits.
    pub span_id: String,
    /// Empty for a root span.
    pub parent_id: String,
    pub name: String,
    /// Index into [`KINDS`].
    pub kind: u8,
    /// The resource's `service.name` (or what stands for it, as for logs).
    pub service: String,
    pub host: String,
    /// Microseconds since the epoch.
    pub start_us: i64,
    pub duration_us: i64,
    /// [`STATUS_UNSET`], [`STATUS_OK`] or [`STATUS_ERROR`].
    pub status: u8,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status_message: String,
    /// The resource's other attributes and the span's own, the span's winning on a clash.
    pub attributes: Map<String, Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<SpanEvent>,
}

/// A trace or span id that names something: the right length of hex, not all zeros.
fn usable_id(id: &str, len: usize) -> bool {
    id.len() == len && id.bytes().all(|b| b.is_ascii_hexdigit()) && id.bytes().any(|b| b != b'0')
}

fn clip(mut s: String, max: usize) -> String {
    truncate_utf8(&mut s, max);
    s
}

/// Attributes as a bounded map: at most [`MAX_ATTRIBUTES`] keys, long text values clipped.
fn bounded(attrs: impl IntoIterator<Item = (String, Value)>) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in attrs {
        if out.len() >= MAX_ATTRIBUTES && !out.contains_key(&k) {
            continue;
        }
        let v = match v {
            Value::String(s) => Value::String(clip(s, MAX_VALUE_BYTES)),
            Value::Array(_) | Value::Object(_) => {
                let mut s = v.to_string();
                if s.len() > MAX_VALUE_BYTES {
                    truncate_utf8(&mut s, MAX_VALUE_BYTES);
                    Value::String(s)
                } else {
                    v
                }
            }
            other => other,
        };
        out.insert(clip(k, MAX_NAME_BYTES), v);
    }
    out
}

/// The span as read off the wire, before the resource is applied.
#[derive(Default)]
struct Raw {
    trace_id: String,
    span_id: String,
    parent_id: String,
    name: String,
    kind: u64,
    start_ns: u64,
    end_ns: u64,
    attributes: Attrs,
    events: Vec<SpanEvent>,
    status: u64,
    status_message: String,
}

fn finish(resource: &[(String, Value)], scope: &str, raw: Raw) -> Option<Span> {
    let (trace_id, span_id) = (
        raw.trace_id.to_ascii_lowercase(),
        raw.span_id.to_ascii_lowercase(),
    );
    if !usable_id(&trace_id, 32) || !usable_id(&span_id, 16) {
        return None;
    }
    let parent = raw.parent_id.to_ascii_lowercase();
    let find = |keys: &[&str]| {
        keys.iter().find_map(|k| {
            resource
                .iter()
                .find(|(name, _)| name == k)
                .and_then(|(name, v)| Some((name.clone(), text(v)?)))
        })
    };
    let (host, service) = (find(&HOST_KEYS), find(&APP_KEYS));
    let used: Vec<String> = [&host, &service]
        .into_iter()
        .flatten()
        .map(|(k, _)| k.clone())
        .collect();
    let scope_attr =
        (!scope.is_empty()).then(|| ("otel.scope".to_string(), Value::String(scope.to_string())));
    let attributes = bounded(
        resource
            .iter()
            .filter(|(k, _)| !used.contains(k))
            .cloned()
            .chain(scope_attr)
            .chain(raw.attributes),
    );
    let start_us = i64::try_from(raw.start_ns / 1000).unwrap_or(0);
    let end_us = i64::try_from(raw.end_ns / 1000).unwrap_or(0);
    let mut events = raw.events;
    events.truncate(MAX_EVENTS);
    Some(Span {
        trace_id,
        span_id,
        parent_id: if usable_id(&parent, 16) {
            parent
        } else {
            String::new()
        },
        name: clip(raw.name, MAX_NAME_BYTES),
        kind: u8::try_from(raw.kind)
            .ok()
            .filter(|k| usize::from(*k) < KINDS.len())
            .unwrap_or(0),
        service: service
            .map(|(_, v)| clip(v, MAX_NAME_BYTES))
            .unwrap_or_default(),
        host: host.map_or_else(|| "unknown".to_string(), |(_, v)| clip(v, MAX_NAME_BYTES)),
        start_us,
        duration_us: (end_us - start_us).max(0),
        status: u8::try_from(raw.status)
            .ok()
            .filter(|s| *s <= STATUS_ERROR)
            .unwrap_or(STATUS_UNSET),
        status_message: clip(raw.status_message, MAX_STATUS_BYTES),
        attributes,
        events,
    })
}

/// The refusal that is LogPit's fault (the database), not the sender's.
pub const STORE_FAILED: &str = "storing the spans failed";

/// Decodes an export (protobuf, or JSON with `json`) and stores its spans, counting what was stored
/// and what was skipped; returns how many spans the export carried. Runs on a blocking thread.
// ponytail: spans are written by the request itself, beside the log writer thread (SQLite waits for
// its turn); give them the batched queue if trace volume ever makes those writes contend.
pub fn store_spans(
    db_path: &std::path::Path,
    metrics: &crate::metrics::Metrics,
    body: &[u8],
    json: bool,
) -> Result<usize, &'static str> {
    let (spans, skipped) = if json {
        decode_json(body)?
    } else {
        decode_protobuf(body)?
    };
    crate::metrics::Metrics::inc(&metrics.spans_rejected, skipped as u64);
    if spans.is_empty() {
        return Ok(0);
    }
    let stored = crate::store::open(db_path)
        .map_err(|e| {
            tracing::error!("opening the database for spans failed: {e:#}");
        })
        .and_then(|mut conn| {
            crate::store::insert_spans(&mut conn, &spans)
                .map_err(|e| tracing::error!("storing spans failed: {e:#}"))
        })
        .map_err(|()| STORE_FAILED)?;
    crate::metrics::Metrics::inc(&metrics.spans_stored, stored as u64);
    Ok(spans.len())
}

// ---- protobuf -----------------------------------------------------------------------------

/// `Span.Event { fixed64 time_unix_nano = 1; string name = 2; repeated KeyValue attributes = 3; }`.
fn event(buf: &[u8]) -> Option<SpanEvent> {
    let (mut ts_ns, mut name, mut attrs) = (0u64, String::new(), Attrs::new());
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 1) => ts_ns = r.fixed64()?,
            (2, 2) => name = utf8(r.bytes()?),
            (3, 2) if attrs.len() < MAX_ATTRIBUTES => attrs.push(key_value(r.bytes()?, 0)?),
            (_, wire) => r.skip(wire)?,
        }
    }
    Some(SpanEvent {
        ts_us: i64::try_from(ts_ns / 1000).unwrap_or(0),
        name: clip(name, MAX_NAME_BYTES),
        attributes: bounded(attrs),
    })
}

/// `Status { string message = 2; StatusCode code = 3; }`.
fn status(buf: &[u8]) -> Option<(u64, String)> {
    let (mut code, mut message) = (0, String::new());
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (2, 2) => message = utf8(r.bytes()?),
            (3, 0) => code = r.varint()?,
            (_, wire) => r.skip(wire)?,
        }
    }
    Some((code, message))
}

fn span(buf: &[u8]) -> Option<Raw> {
    let mut raw = Raw::default();
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 2) => raw.trace_id = hex(r.bytes()?),
            (2, 2) => raw.span_id = hex(r.bytes()?),
            (4, 2) => raw.parent_id = hex(r.bytes()?),
            (5, 2) => raw.name = utf8(r.bytes()?),
            (6, 0) => raw.kind = r.varint()?,
            (7, 1) => raw.start_ns = r.fixed64()?,
            (8, 1) => raw.end_ns = r.fixed64()?,
            (9, 2) if raw.attributes.len() < MAX_ATTRIBUTES => {
                raw.attributes.push(key_value(r.bytes()?, 0)?)
            }
            (11, 2) if raw.events.len() < MAX_EVENTS => raw.events.push(event(r.bytes()?)?),
            (15, 2) => (raw.status, raw.status_message) = status(r.bytes()?)?,
            (_, wire) => r.skip(wire)?,
        }
    }
    Some(raw)
}

/// Decodes an `ExportTraceServiceRequest`; also returns how many spans were skipped for want of a
/// usable trace or span id.
pub fn decode_protobuf(buf: &[u8]) -> Result<(Vec<Span>, usize), &'static str> {
    const BAD: &str = "malformed OTLP protobuf";
    let (mut out, mut skipped) = (Vec::new(), 0);
    let mut top = Reader::new(buf);
    while !top.done() {
        match top.key().ok_or(BAD)? {
            (1, 2) => {
                // ResourceSpans { Resource resource = 1; repeated ScopeSpans scope_spans = 2; }
                let (mut resource, mut scopes) = (Attrs::new(), Vec::new());
                let mut r = Reader::new(top.bytes().ok_or(BAD)?);
                while !r.done() {
                    match r.key().ok_or(BAD)? {
                        (1, 2) => {
                            let mut res = Reader::new(r.bytes().ok_or(BAD)?);
                            while !res.done() {
                                match res.key().ok_or(BAD)? {
                                    (1, 2) => resource
                                        .push(key_value(res.bytes().ok_or(BAD)?, 0).ok_or(BAD)?),
                                    (_, wire) => res.skip(wire).ok_or(BAD)?,
                                }
                            }
                        }
                        (2, 2) => scopes.push(r.bytes().ok_or(BAD)?),
                        (_, wire) => r.skip(wire).ok_or(BAD)?,
                    }
                }
                for scope_buf in scopes {
                    // ScopeSpans { InstrumentationScope scope = 1; repeated Span spans = 2; }
                    let (mut name, mut raws) = (String::new(), Vec::new());
                    let mut s = Reader::new(scope_buf);
                    while !s.done() {
                        match s.key().ok_or(BAD)? {
                            (1, 2) => name = scope_name(s.bytes().ok_or(BAD)?).ok_or(BAD)?,
                            (2, 2) => raws.push(span(s.bytes().ok_or(BAD)?).ok_or(BAD)?),
                            (_, wire) => s.skip(wire).ok_or(BAD)?,
                        }
                    }
                    for raw in raws {
                        match finish(&resource, &name, raw) {
                            Some(s) => out.push(s),
                            None => skipped += 1,
                        }
                    }
                }
            }
            (_, wire) => top.skip(wire).ok_or(BAD)?,
        }
    }
    Ok((out, skipped))
}

// ---- JSON ---------------------------------------------------------------------------------

/// An enum written as its number or its name (`SPAN_KIND_SERVER`, `STATUS_CODE_ERROR`).
fn json_enum(v: Option<&Value>, prefix: &str, names: &[&str]) -> u64 {
    match v {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => {
            let name = s.strip_prefix(prefix).unwrap_or(s).to_ascii_lowercase();
            names.iter().position(|n| *n == name).unwrap_or(0) as u64
        }
        _ => 0,
    }
}

/// Decodes the JSON form of an `ExportTraceServiceRequest`, with the count of skipped spans.
pub fn decode_json(body: &[u8]) -> Result<(Vec<Span>, usize), &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "invalid JSON")?;
    let resource_spans = v
        .get("resourceSpans")
        .and_then(Value::as_array)
        .ok_or("missing \"resourceSpans\"")?;
    let (mut out, mut skipped) = (Vec::new(), 0);
    let attrs = |v: Option<&Value>| {
        v.and_then(Value::as_array)
            .map(|a| json_attrs(a, 0))
            .unwrap_or_default()
    };
    let string = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or("").to_string();
    for rs in resource_spans {
        let resource = attrs(rs.pointer("/resource/attributes"));
        for ss in rs
            .get("scopeSpans")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let scope = string(ss.pointer("/scope/name"));
            for sp in ss
                .get("spans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let events = sp
                    .get("events")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .take(MAX_EVENTS)
                    .map(|e| SpanEvent {
                        ts_us: i64::try_from(json_nanos(e.get("timeUnixNano")) / 1000).unwrap_or(0),
                        name: clip(string(e.get("name")), MAX_NAME_BYTES),
                        attributes: bounded(attrs(e.get("attributes"))),
                    })
                    .collect();
                let raw = Raw {
                    trace_id: string(sp.get("traceId")),
                    span_id: string(sp.get("spanId")),
                    parent_id: string(sp.get("parentSpanId")),
                    name: string(sp.get("name")),
                    kind: json_enum(sp.get("kind"), "SPAN_KIND_", &KINDS),
                    start_ns: json_nanos(sp.get("startTimeUnixNano")),
                    end_ns: json_nanos(sp.get("endTimeUnixNano")),
                    attributes: attrs(sp.get("attributes")),
                    events,
                    status: json_enum(
                        sp.pointer("/status/code"),
                        "STATUS_CODE_",
                        &["unset", "ok", "error"],
                    ),
                    status_message: string(sp.pointer("/status/message")),
                };
                match finish(&resource, &scope, raw) {
                    Some(s) => out.push(s),
                    None => skipped += 1,
                }
            }
        }
    }
    Ok((out, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::encode::{fixed64_field, len_field, num_field};

    const TRACE: [u8; 16] = [0xab; 16];
    const SPAN: [u8; 8] = [0x11; 8];
    const PARENT: [u8; 8] = [0x22; 8];

    fn kv(key: &str, value: &str) -> Vec<u8> {
        let mut any = Vec::new();
        len_field(1, value.as_bytes(), &mut any);
        let mut out = Vec::new();
        len_field(1, key.as_bytes(), &mut out);
        len_field(2, &any, &mut out);
        out
    }

    fn request(spans: &[Vec<u8>]) -> Vec<u8> {
        let mut resource = Vec::new();
        len_field(1, &kv("service.name", "checkout"), &mut resource);
        len_field(1, &kv("host.name", "pve"), &mut resource);
        len_field(1, &kv("deployment.environment", "home"), &mut resource);
        let mut scope = Vec::new();
        len_field(1, b"my.tracer", &mut scope);
        let mut scope_spans = Vec::new();
        len_field(1, &scope, &mut scope_spans);
        for s in spans {
            len_field(2, s, &mut scope_spans);
        }
        let mut rs = Vec::new();
        len_field(1, &resource, &mut rs);
        len_field(2, &scope_spans, &mut rs);
        let mut out = Vec::new();
        len_field(1, &rs, &mut out);
        out
    }

    fn span_bytes(trace: &[u8], span: &[u8], parent: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        len_field(1, trace, &mut out);
        len_field(2, span, &mut out);
        if let Some(p) = parent {
            len_field(4, p, &mut out);
        }
        len_field(5, b"GET /cart", &mut out);
        num_field(6, 2, &mut out);
        fixed64_field(7, 1_700_000_000_000_000_000, &mut out);
        fixed64_field(8, 1_700_000_000_250_000_000, &mut out);
        len_field(9, &kv("http.route", "/cart"), &mut out);
        let mut ev = Vec::new();
        fixed64_field(1, 1_700_000_000_100_000_000, &mut ev);
        len_field(2, b"cache miss", &mut ev);
        len_field(11, &ev, &mut out);
        let mut st = Vec::new();
        len_field(2, b"timeout talking to db", &mut st);
        num_field(3, 2, &mut st);
        len_field(15, &st, &mut out);
        out
    }

    #[test]
    fn protobuf_spans_keep_their_tree_timing_status_and_resource() {
        let body = request(&[
            span_bytes(&TRACE, &SPAN, Some(&PARENT)),
            span_bytes(&[0; 16], &SPAN, None), // no usable trace id
            span_bytes(&TRACE, &[1, 2, 3], None), // span id of the wrong length
        ]);
        let (spans, skipped) = decode_protobuf(&body).unwrap();
        assert_eq!((spans.len(), skipped), (1, 2));
        let s = &spans[0];
        assert_eq!(s.trace_id, "ab".repeat(16));
        assert_eq!(
            (s.span_id.as_str(), s.parent_id.as_str()),
            ("1111111111111111", "2222222222222222")
        );
        assert_eq!(
            (s.name.as_str(), KINDS[usize::from(s.kind)]),
            ("GET /cart", "server")
        );
        assert_eq!((s.service.as_str(), s.host.as_str()), ("checkout", "pve"));
        assert_eq!(
            (s.start_us, s.duration_us),
            (1_700_000_000_000_000, 250_000)
        );
        assert_eq!(
            (s.status, s.status_message.as_str()),
            (STATUS_ERROR, "timeout talking to db")
        );
        assert_eq!(s.attributes["http.route"], "/cart");
        assert_eq!(s.attributes["deployment.environment"], "home");
        assert_eq!(s.attributes["otel.scope"], "my.tracer");
        assert!(
            !s.attributes.contains_key("service.name"),
            "the service is a column"
        );
        assert_eq!(
            (s.events.len(), s.events[0].name.as_str(), s.events[0].ts_us),
            (1, "cache miss", 1_700_000_000_100_000)
        );
    }

    #[test]
    fn json_spans_read_like_protobuf_ones() {
        let body = br#"{"resourceSpans":[{"resource":{"attributes":[
            {"key":"service.name","value":{"stringValue":"checkout"}}]},
          "scopeSpans":[{"scope":{"name":"t"},"spans":[
            {"traceId":"ABABABABABABABABABABABABABABABAB","spanId":"1111111111111111",
             "name":"SELECT cart","kind":"SPAN_KIND_CLIENT",
             "startTimeUnixNano":"1700000000000000000","endTimeUnixNano":"1700000000004000000",
             "attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}}],
             "status":{"code":"STATUS_CODE_OK"}},
            {"traceId":"","spanId":"1111111111111111"}]}]}]}"#;
        let (spans, skipped) = decode_json(body).unwrap();
        assert_eq!((spans.len(), skipped), (1, 1));
        let s = &spans[0];
        assert_eq!(s.trace_id, "ab".repeat(16), "ids are lower-cased");
        assert!(s.parent_id.is_empty(), "a root span");
        assert_eq!(KINDS[usize::from(s.kind)], "client");
        assert_eq!((s.status, s.duration_us), (STATUS_OK, 4000));
        assert_eq!(s.host, "unknown");
        assert_eq!(s.attributes["db.system"], "postgresql");
        assert!(decode_json(b"[]").is_err());
        assert!(decode_json(b"{").is_err());
    }

    #[test]
    fn limits_hold_and_malformed_input_is_refused() {
        let mut many = Vec::new();
        len_field(1, &TRACE, &mut many);
        len_field(2, &SPAN, &mut many);
        len_field(5, "x".repeat(5000).as_bytes(), &mut many);
        for i in 0..200 {
            len_field(9, &kv(&format!("k{i}"), &"v".repeat(5000)), &mut many);
        }
        let (spans, _) = decode_protobuf(&request(&[many])).unwrap();
        let s = &spans[0];
        assert_eq!(s.attributes.len(), MAX_ATTRIBUTES);
        assert!(s.name.len() <= MAX_NAME_BYTES);
        assert!(
            s.attributes
                .values()
                .all(|v| v.as_str().is_none_or(|t| t.len() <= MAX_VALUE_BYTES))
        );
        // An end before the start is a zero duration, never a negative one.
        let mut back = Vec::new();
        len_field(1, &TRACE, &mut back);
        len_field(2, &SPAN, &mut back);
        fixed64_field(7, 2_000_000, &mut back);
        fixed64_field(8, 1_000_000, &mut back);
        assert_eq!(
            decode_protobuf(&request(&[back])).unwrap().0[0].duration_us,
            0
        );
        for bad in [&b"\x0a\xff"[..], b"\x0a\x05\x12\x10", b"\xff\xff\xff"] {
            assert!(decode_protobuf(bad).is_err(), "{bad:?}");
        }
        assert_eq!(decode_protobuf(b"").unwrap().0.len(), 0);
    }
}
