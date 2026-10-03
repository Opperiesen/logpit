//! OpenTelemetry logs over HTTP (`POST /v1/logs`), so the OpenTelemetry Collector and SDK
//! exporters can send to LogPit. Both encodings are accepted: protobuf (`application/x-protobuf`)
//! and JSON. Resource and log attributes become LogPit fields.

use serde_json::{Map, Value};

use crate::model::{LogEntry, level_severity, truncate_utf8};
use crate::proto::{Reader, utf8};
use crate::structured::MAX_VALUE_BYTES;

const MAX_FIELDS: usize = 64;
const MAX_DEPTH: usize = 4;

/// Resource attributes checked, in order, for the host and the application.
const HOST_KEYS: [&str; 4] = [
    "host.name",
    "k8s.node.name",
    "k8s.pod.name",
    "service.instance.id",
];
const APP_KEYS: [&str; 3] = [
    "service.name",
    "k8s.container.name",
    "process.executable.name",
];

type Attrs = Vec<(String, Value)>;

#[derive(Default)]
struct Record {
    time_ns: u64,
    observed_ns: u64,
    severity_number: u32,
    severity_text: String,
    body: Value,
    attributes: Attrs,
    trace_id: String,
    span_id: String,
}

// ---- protobuf -----------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `AnyValue`: one of string, bool, int, double, array, key/value list or bytes.
fn any_value(buf: &[u8], depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return Some(Value::Null);
    }
    let mut r = Reader::new(buf);
    let mut out = Value::Null;
    while !r.done() {
        out = match r.key()? {
            (1, 2) => Value::String(utf8(r.bytes()?)),
            (2, 0) => Value::Bool(r.varint()? != 0),
            (3, 0) => Value::from(r.varint()? as i64),
            (4, 1) => serde_json::Number::from_f64(f64::from_bits(r.fixed64()?))
                .map_or(Value::Null, Value::Number),
            (5, 2) => {
                // ArrayValue { repeated AnyValue values = 1; }
                let mut items = Vec::new();
                let mut a = Reader::new(r.bytes()?);
                while !a.done() {
                    match a.key()? {
                        (1, 2) => items.push(any_value(a.bytes()?, depth + 1)?),
                        (_, wire) => a.skip(wire)?,
                    }
                }
                Value::Array(items)
            }
            (6, 2) => {
                // KeyValueList { repeated KeyValue values = 1; }
                let mut map = Map::new();
                let mut a = Reader::new(r.bytes()?);
                while !a.done() {
                    match a.key()? {
                        (1, 2) => {
                            let (k, v) = key_value(a.bytes()?, depth + 1)?;
                            map.insert(k, v);
                        }
                        (_, wire) => a.skip(wire)?,
                    }
                }
                Value::Object(map)
            }
            (7, 2) => Value::String(hex(r.bytes()?)),
            (_, wire) => {
                r.skip(wire)?;
                out
            }
        };
    }
    Some(out)
}

/// `KeyValue { string key = 1; AnyValue value = 2; }`.
fn key_value(buf: &[u8], depth: usize) -> Option<(String, Value)> {
    let (mut key, mut value) = (String::new(), Value::Null);
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 2) => key = utf8(r.bytes()?),
            (2, 2) => value = any_value(r.bytes()?, depth)?,
            (_, wire) => r.skip(wire)?,
        }
    }
    Some((key, value))
}

fn log_record(buf: &[u8]) -> Option<Record> {
    let mut rec = Record::default();
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 1) => rec.time_ns = r.fixed64()?,
            (2, 0) => rec.severity_number = u32::try_from(r.varint()?).unwrap_or(0),
            (3, 2) => rec.severity_text = utf8(r.bytes()?),
            (5, 2) => rec.body = any_value(r.bytes()?, 0)?,
            (6, 2) => rec.attributes.push(key_value(r.bytes()?, 0)?),
            (9, 2) => rec.trace_id = hex(r.bytes()?),
            (10, 2) => rec.span_id = hex(r.bytes()?),
            (11, 1) => rec.observed_ns = r.fixed64()?,
            (_, wire) => r.skip(wire)?,
        }
    }
    Some(rec)
}

/// `InstrumentationScope { string name = 1; string version = 2; … }`: the name.
fn scope_name(buf: &[u8]) -> Option<String> {
    let mut name = String::new();
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 2) => name = utf8(r.bytes()?),
            (_, wire) => r.skip(wire)?,
        }
    }
    Some(name)
}

/// Decodes an `ExportLogsServiceRequest` into entries. `now_ms` stamps records without a time.
pub fn decode_protobuf(buf: &[u8], now_ms: i64) -> Result<Vec<LogEntry>, &'static str> {
    const BAD: &str = "malformed OTLP protobuf";
    let mut out = Vec::new();
    let mut top = Reader::new(buf);
    while !top.done() {
        match top.key().ok_or(BAD)? {
            (1, 2) => {
                // ResourceLogs { Resource resource = 1; repeated ScopeLogs scope_logs = 2; }
                let (mut resource, mut scopes) = (Attrs::new(), Vec::new());
                let mut r = Reader::new(top.bytes().ok_or(BAD)?);
                while !r.done() {
                    match r.key().ok_or(BAD)? {
                        (1, 2) => {
                            // Resource { repeated KeyValue attributes = 1; }
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
                    // ScopeLogs { InstrumentationScope scope = 1; repeated LogRecord log_records = 2; }
                    let (mut name, mut records) = (String::new(), Vec::new());
                    let mut s = Reader::new(scope_buf);
                    while !s.done() {
                        match s.key().ok_or(BAD)? {
                            (1, 2) => name = scope_name(s.bytes().ok_or(BAD)?).ok_or(BAD)?,
                            (2, 2) => records.push(log_record(s.bytes().ok_or(BAD)?).ok_or(BAD)?),
                            (_, wire) => s.skip(wire).ok_or(BAD)?,
                        }
                    }
                    out.extend(
                        records
                            .into_iter()
                            .map(|rec| to_entry(&resource, &name, rec, now_ms)),
                    );
                }
            }
            (_, wire) => top.skip(wire).ok_or(BAD)?,
        }
    }
    Ok(out)
}

// ---- JSON ---------------------------------------------------------------------------------

/// JSON `AnyValue`: `{"stringValue": …}`, `{"intValue": "5"}`, `{"arrayValue": {"values": […]}}`…
fn json_any(v: &Value, depth: usize) -> Value {
    let Some(obj) = v.as_object().filter(|_| depth <= MAX_DEPTH) else {
        return Value::Null;
    };
    if let Some(s) = obj.get("stringValue") {
        return s.clone();
    }
    if let Some(b) = obj.get("boolValue") {
        return b.clone();
    }
    if let Some(i) = obj.get("intValue") {
        return match i {
            Value::String(s) => s
                .parse::<i64>()
                .map_or_else(|_| Value::String(s.clone()), Value::from),
            other => other.clone(),
        };
    }
    if let Some(d) = obj.get("doubleValue") {
        return d.clone();
    }
    if let Some(b) = obj.get("bytesValue") {
        return b.clone();
    }
    if let Some(items) = obj
        .get("arrayValue")
        .and_then(|a| a.get("values"))
        .and_then(Value::as_array)
    {
        return Value::Array(items.iter().map(|i| json_any(i, depth + 1)).collect());
    }
    if let Some(items) = obj
        .get("kvlistValue")
        .and_then(|a| a.get("values"))
        .and_then(Value::as_array)
    {
        return Value::Object(json_attrs(items, depth + 1).into_iter().collect());
    }
    Value::Null
}

fn json_attrs(items: &[Value], depth: usize) -> Attrs {
    items
        .iter()
        .filter_map(|kv| {
            Some((
                kv.get("key")?.as_str()?.to_string(),
                json_any(kv.get("value")?, depth),
            ))
        })
        .collect()
}

/// A nanosecond timestamp, which OTLP/JSON writes as a string (or, loosely, a number).
fn json_nanos(v: Option<&Value>) -> u64 {
    match v {
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        _ => 0,
    }
}

/// `severityNumber` as an integer or as the enum's name (`SEVERITY_NUMBER_WARN`).
fn json_severity_number(v: Option<&Value>) -> u32 {
    match v {
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
        Some(Value::String(s)) => {
            let name = s.strip_prefix("SEVERITY_NUMBER_").unwrap_or(s);
            let base = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]
                .iter()
                .position(|p| name.starts_with(p))
                .map_or(0, |i| [1, 5, 9, 13, 17, 21][i]);
            let offset = name
                .chars()
                .last()
                .and_then(|c| c.to_digit(10))
                .map_or(0, |d| d.saturating_sub(1));
            if base == 0 { 0 } else { base + offset }
        }
        _ => 0,
    }
}

/// Decodes the JSON form of an `ExportLogsServiceRequest`.
pub fn decode_json(body: &[u8], now_ms: i64) -> Result<Vec<LogEntry>, &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "invalid JSON")?;
    let resource_logs = v
        .get("resourceLogs")
        .and_then(Value::as_array)
        .ok_or("missing \"resourceLogs\"")?;
    let mut out = Vec::new();
    for rl in resource_logs {
        let resource = rl
            .pointer("/resource/attributes")
            .and_then(Value::as_array)
            .map(|a| json_attrs(a, 0))
            .unwrap_or_default();
        for sl in rl
            .get("scopeLogs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let scope = sl
                .pointer("/scope/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            for lr in sl
                .get("logRecords")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let id = |key: &str| {
                    let s = lr.get(key).and_then(Value::as_str).unwrap_or("");
                    s.to_string()
                };
                let rec = Record {
                    time_ns: json_nanos(lr.get("timeUnixNano")),
                    observed_ns: json_nanos(lr.get("observedTimeUnixNano")),
                    severity_number: json_severity_number(lr.get("severityNumber")),
                    severity_text: lr
                        .get("severityText")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    body: lr.get("body").map_or(Value::Null, |b| json_any(b, 0)),
                    attributes: lr
                        .get("attributes")
                        .and_then(Value::as_array)
                        .map(|a| json_attrs(a, 0))
                        .unwrap_or_default(),
                    trace_id: id("traceId"),
                    span_id: id("spanId"),
                };
                out.push(to_entry(&resource, scope, rec, now_ms));
            }
        }
    }
    Ok(out)
}

// ---- mapping to entries -------------------------------------------------------------------

/// Syslog severity for an OTLP `SeverityNumber` (1-24): trace and debug are 7, info 6, warn 4,
/// error 3, fatal 2.
fn severity_of(number: u32, text: &str) -> u8 {
    match number {
        1..=8 => 7,
        9..=12 => 6,
        13..=16 => 4,
        17..=20 => 3,
        21..=24 => 2,
        _ => level_severity(text).unwrap_or(6),
    }
}

/// A value as field text; null, empty strings and unusable values give nothing.
fn text(v: &Value) -> Option<String> {
    let mut s = match v {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(_) | Value::Object(_) => v.to_string(),
        _ => return None,
    };
    truncate_utf8(&mut s, MAX_VALUE_BYTES);
    Some(s)
}

fn to_entry(resource: &[(String, Value)], scope: &str, rec: Record, now_ms: i64) -> LogEntry {
    let find = |keys: &[&str]| {
        keys.iter().find_map(|k| {
            resource
                .iter()
                .find(|(name, _)| name == k)
                .and_then(|(name, v)| Some((name.as_str(), text(v)?)))
        })
    };
    let host = find(&HOST_KEYS);
    let app = find(&APP_KEYS);
    let used: Vec<&str> = [&host, &app]
        .into_iter()
        .flatten()
        .map(|(k, _)| *k)
        .collect();

    let ts_ns = if rec.time_ns > 0 {
        rec.time_ns
    } else {
        rec.observed_ns
    };
    let message = text(&rec.body).unwrap_or_else(|| "(no message)".to_string());
    let mut e = LogEntry {
        ts: if ts_ns > 0 {
            i64::try_from(ts_ns / 1_000_000).unwrap_or(now_ms)
        } else {
            now_ms
        },
        host: host.map_or_else(|| "unknown".to_string(), |(_, v)| v),
        app: app.map(|(_, v)| v).unwrap_or_default(),
        severity: severity_of(rec.severity_number, &rec.severity_text),
        message,
        ..Default::default()
    };

    // Values read out of a JSON or key=value message come first, so attributes win on a clash.
    let extracted = crate::structured::extract(&e.message);
    let scope_field =
        (!scope.is_empty()).then(|| ("scope".to_string(), Value::String(scope.to_string())));
    let ids = [("trace_id", &rec.trace_id), ("span_id", &rec.span_id)]
        .into_iter()
        .filter(|(_, v)| !v.is_empty() && v.chars().any(|c| c != '0'))
        .map(|(k, v)| (k.to_string(), Value::String(v.clone())));
    let attrs = resource
        .iter()
        .filter(|(k, _)| !used.contains(&k.as_str()))
        .cloned()
        .chain(scope_field)
        .chain(rec.attributes.iter().cloned())
        .chain(ids);
    for (k, v) in extracted
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .chain(attrs)
    {
        if e.fields.len() >= MAX_FIELDS && !e.fields.contains_key(&k) {
            continue;
        }
        if let (Some(key), Some(value)) = (crate::structured::sanitize_key(&k), text(&v)) {
            e.fields.insert(key, value);
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proto::encode::{fixed64_field, len_field, num_field};

    fn string_value(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        len_field(1, s.as_bytes(), &mut v);
        v
    }
    fn kv(key: &str, any: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        len_field(1, key.as_bytes(), &mut v);
        len_field(2, any, &mut v);
        v
    }
    fn str_kv(key: &str, val: &str) -> Vec<u8> {
        kv(key, &string_value(val))
    }

    struct Rec<'a> {
        time_ns: u64,
        sev: u64,
        sev_text: &'a str,
        body: Vec<u8>,
        attrs: Vec<Vec<u8>>,
        trace: Option<[u8; 16]>,
    }

    fn request(resource: Vec<Vec<u8>>, scope: &str, records: Vec<Rec>) -> Vec<u8> {
        let mut scope_logs = Vec::new();
        let mut sc = Vec::new();
        len_field(1, scope.as_bytes(), &mut sc);
        len_field(1, &sc, &mut scope_logs);
        for r in records {
            let mut lr = Vec::new();
            fixed64_field(1, r.time_ns, &mut lr);
            num_field(2, r.sev, &mut lr);
            len_field(3, r.sev_text.as_bytes(), &mut lr);
            len_field(5, &r.body, &mut lr);
            for a in &r.attrs {
                len_field(6, a, &mut lr);
            }
            if let Some(t) = r.trace {
                len_field(9, &t, &mut lr);
                len_field(10, &[1, 2, 3, 4, 5, 6, 7, 8], &mut lr);
            }
            len_field(2, &lr, &mut scope_logs);
        }
        let mut res = Vec::new();
        for a in &resource {
            len_field(1, a, &mut res);
        }
        let mut rl = Vec::new();
        len_field(1, &res, &mut rl);
        len_field(2, &scope_logs, &mut rl);
        let mut out = Vec::new();
        len_field(1, &rl, &mut out);
        out
    }

    fn int_value(i: i64) -> Vec<u8> {
        let mut v = Vec::new();
        num_field(3, i as u64, &mut v);
        v
    }

    #[test]
    fn protobuf_request_maps_resource_scope_and_record() {
        let body = request(
            vec![
                str_kv("service.name", "checkout"),
                str_kv("host.name", "node-7"),
                str_kv("deployment.environment", "prod"),
                kv("service.instance.number", &int_value(3)),
            ],
            "my.library",
            vec![
                Rec {
                    time_ns: 1_700_000_000_123_456_789,
                    sev: 17,
                    sev_text: "ERROR",
                    body: string_value("payment failed"),
                    attrs: vec![
                        str_kv("http.method", "POST"),
                        kv("http.status_code", &int_value(500)),
                    ],
                    trace: Some([0xab; 16]),
                },
                Rec {
                    time_ns: 0,
                    sev: 0,
                    sev_text: "warn",
                    body: string_value("no time, severity from the text"),
                    attrs: vec![],
                    trace: None,
                },
            ],
        );
        let entries = decode_protobuf(&body, 42).unwrap();
        assert_eq!(entries.len(), 2);
        let e = &entries[0];
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.severity, e.ts),
            ("node-7", "checkout", 3, 1_700_000_000_123)
        );
        assert_eq!(e.message, "payment failed");
        let f = |k: &str| e.fields.get(k).map(String::as_str);
        assert_eq!(f("deployment.environment"), Some("prod"));
        assert_eq!(f("service.instance.number"), Some("3"), "ints become text");
        assert_eq!(
            (f("http.method"), f("http.status_code"), f("scope")),
            (Some("POST"), Some("500"), Some("my.library"))
        );
        assert_eq!(f("trace_id"), Some("abababababababababababababababab"));
        assert_eq!(f("span_id"), Some("0102030405060708"));
        assert!(
            f("host.name").is_none() && f("service.name").is_none(),
            "mapped attributes are not repeated"
        );
        // No timestamp: the arrival time. Severity number 0: the level text decides.
        let second = &entries[1];
        assert_eq!((second.ts, second.severity), (42, 4));
        assert!(!second.fields.contains_key("trace_id"));
    }

    #[test]
    fn severity_numbers_cover_the_whole_range() {
        for (n, sev) in [
            (1, 7),
            (4, 7),
            (5, 7),
            (8, 7),
            (9, 6),
            (12, 6),
            (13, 4),
            (16, 4),
            (17, 3),
            (20, 3),
            (21, 2),
            (24, 2),
            (0, 6),
            (99, 6),
        ] {
            assert_eq!(severity_of(n, ""), sev, "number {n}");
        }
        assert_eq!(severity_of(0, "ERROR"), 3);
        assert_eq!(severity_of(0, "nonsense"), 6);
    }

    #[test]
    fn body_types_and_json_or_logfmt_inside_the_body() {
        let mut arr = Vec::new();
        let mut inner = Vec::new();
        len_field(1, &string_value("a"), &mut inner);
        len_field(1, &int_value(2), &mut inner);
        len_field(5, &inner, &mut arr);
        let req = |body: Vec<u8>| {
            decode_protobuf(
                &request(
                    vec![],
                    "",
                    vec![Rec {
                        time_ns: 1,
                        sev: 9,
                        sev_text: "",
                        body,
                        attrs: vec![],
                        trace: None,
                    }],
                ),
                0,
            )
            .unwrap()
            .remove(0)
        };
        assert_eq!(
            req(arr).message,
            r#"["a",2]"#,
            "a list body is shown as JSON"
        );
        assert_eq!(req(Vec::new()).message, "(no message)");
        let e = req(string_value("level=warn user=bob took=3ms"));
        assert_eq!(
            e.fields["user"], "bob",
            "logfmt in the body is extracted like any message"
        );
        // An attribute with the same key wins over what was read from the body.
        let e = decode_protobuf(
            &request(
                vec![],
                "",
                vec![Rec {
                    time_ns: 1,
                    sev: 9,
                    sev_text: "",
                    body: string_value("user=bob x=1"),
                    attrs: vec![str_kv("user", "attr-wins")],
                    trace: None,
                }],
            ),
            0,
        )
        .unwrap()
        .remove(0);
        assert_eq!(
            (e.fields["user"].as_str(), e.fields["x"].as_str()),
            ("attr-wins", "1")
        );
    }

    #[test]
    fn malformed_protobuf_is_an_error_not_a_panic() {
        let good = request(
            vec![str_kv("service.name", "s")],
            "sc",
            vec![Rec {
                time_ns: 5,
                sev: 9,
                sev_text: "INFO",
                body: string_value("m"),
                attrs: vec![str_kv("k", "v")],
                trace: Some([1; 16]),
            }],
        );
        assert!(decode_protobuf(&[], 0).unwrap().is_empty());
        for cut in 1..good.len() {
            let _ = decode_protobuf(&good[..cut], 0); // never a panic
        }
        assert!(decode_protobuf(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f], 0).is_err());
        assert!(decode_protobuf(&[0x0b], 0).is_err());
        let mut x: u64 = 0x0dd_ba11_cafe_f00d;
        for _ in 0..30_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let data: Vec<u8> = (0..(x % 64)).map(|i| (x >> (i % 56)) as u8).collect();
            let _ = decode_protobuf(&data, 0);
        }
    }

    #[test]
    fn json_request_maps_the_same_way() {
        let body = br#"{"resourceLogs":[{
            "resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}},{"key":"host.name","value":{"stringValue":"h1"}},{"key":"count","value":{"intValue":"7"}}]},
            "scopeLogs":[{"scope":{"name":"lib"},"logRecords":[
              {"timeUnixNano":"1700000000000000000","severityNumber":13,"severityText":"WARN","body":{"stringValue":"careful"},
               "attributes":[{"key":"user","value":{"stringValue":"bob"}},{"key":"ok","value":{"boolValue":true}},{"key":"ratio","value":{"doubleValue":0.5}},
                             {"key":"tags","value":{"arrayValue":{"values":[{"stringValue":"a"},{"intValue":"2"}]}}},
                             {"key":"nested","value":{"kvlistValue":{"values":[{"key":"k","value":{"stringValue":"v"}}]}}}],
               "traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174"},
              {"observedTimeUnixNano":"1700000001000000000","severityNumber":"SEVERITY_NUMBER_ERROR2","body":{"stringValue":"enum name"}}
            ]}]}]}"#;
        let e = decode_json(body, 0).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(
            (
                e[0].host.as_str(),
                e[0].app.as_str(),
                e[0].severity,
                e[0].ts
            ),
            ("h1", "api", 4, 1_700_000_000_000)
        );
        assert_eq!(e[0].message, "careful");
        let f = |k: &str| e[0].fields.get(k).map(String::as_str);
        assert_eq!(
            (f("count"), f("user"), f("ok"), f("ratio"), f("scope")),
            (
                Some("7"),
                Some("bob"),
                Some("true"),
                Some("0.5"),
                Some("lib")
            )
        );
        assert_eq!(f("tags"), Some(r#"["a",2]"#));
        assert_eq!(f("nested"), Some(r#"{"k":"v"}"#));
        assert_eq!(f("trace_id"), Some("5b8efff798038103d269b633813fc60c"));
        assert_eq!(
            (e[1].ts, e[1].severity),
            (1_700_000_001_000, 3),
            "observed time and an enum name (ERROR2 = 18)"
        );
        for bad in ["", "[]", "{}", r#"{"resourceLogs":{}}"#] {
            assert!(decode_json(bad.as_bytes(), 0).is_err(), "{bad:?}");
        }
        // Missing pieces are tolerated: no resource, no scope, no records.
        assert!(
            decode_json(br#"{"resourceLogs":[{}]}"#, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn json_severity_names_and_limits() {
        for (v, n) in [
            ("SEVERITY_NUMBER_TRACE", 1),
            ("SEVERITY_NUMBER_TRACE4", 4),
            ("SEVERITY_NUMBER_DEBUG", 5),
            ("SEVERITY_NUMBER_INFO", 9),
            ("SEVERITY_NUMBER_INFO3", 11),
            ("SEVERITY_NUMBER_WARN", 13),
            ("SEVERITY_NUMBER_ERROR", 17),
            ("SEVERITY_NUMBER_FATAL4", 24),
            ("SEVERITY_NUMBER_UNSPECIFIED", 0),
            ("nonsense", 0),
        ] {
            assert_eq!(
                json_severity_number(Some(&Value::String(v.into()))),
                n,
                "{v}"
            );
        }
        assert_eq!(json_severity_number(Some(&Value::from(21))), 21);
        let many: String = (0..200)
            .map(|i| format!(r#"{{"key":"k{i}","value":{{"stringValue":"v"}}}},"#))
            .collect();
        let body = format!(
            r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"body":{{"stringValue":"m"}},"attributes":[{many}{{"key":"last","value":{{"stringValue":"v"}}}}]}}]}}]}}]}}"#
        );
        assert_eq!(
            decode_json(body.as_bytes(), 0).unwrap()[0].fields.len(),
            MAX_FIELDS
        );
    }
}
