//! Loki's push API (`POST /loki/api/v1/push`), so Promtail, Grafana Alloy, Vector, Fluent Bit and
//! Docker's Loki driver can ship logs to LogPit.
//!
//! Two encodings are accepted: JSON (`{"streams":[{"stream":{labels},"values":[[ts_ns, line]]}]}`)
//! and Loki's native protobuf compressed with snappy, which is what Promtail and Alloy send. The
//! protobuf is read by a small hand-written decoder (the message is tiny) instead of a dependency.

use serde_json::Value;

use crate::model::{LogEntry, level_severity, truncate_utf8};
use crate::proto::{Reader, utf8};
use crate::structured::MAX_VALUE_BYTES;

const MAX_FIELDS: usize = 64;
/// Largest snappy-decompressed push accepted.
pub const MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;

/// One line of a stream.
#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    pub ts_ms: Option<i64>,
    pub line: String,
    /// Loki's structured metadata, attached to the line.
    pub metadata: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Stream {
    pub labels: Vec<(String, String)>,
    pub lines: Vec<Line>,
}

// ---- labels -------------------------------------------------------------------------------

/// Parses the label set of a protobuf stream, `{app="web", env="prod"}`. Anything that does not
/// look like a label is skipped rather than failing the whole push.
pub fn parse_labels(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = text
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .chars()
        .peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace() || *c == ',').is_some() {}
        let mut name = String::new();
        while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.') {
            name.push(c);
        }
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.next_if_eq(&'=').is_none() {
            // Not `name=`: skip to the next separator, or stop at the end.
            if chars.by_ref().find(|c| *c == ',').is_none() {
                break;
            }
            continue;
        }
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let mut value = String::new();
        if chars.next_if_eq(&'"').is_some() {
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => match chars.next() {
                        Some('n') => value.push('\n'),
                        Some('t') => value.push('\t'),
                        Some(other) => value.push(other),
                        None => break,
                    },
                    _ => value.push(c),
                }
            }
        } else {
            while let Some(c) = chars.next_if(|c| *c != ',') {
                value.push(c);
            }
            value = value.trim().to_string();
        }
        if !name.is_empty() {
            out.push((name, value));
        }
    }
    out
}

// ---- protobuf -----------------------------------------------------------------------------

/// `google.protobuf.Timestamp { int64 seconds = 1; int32 nanos = 2; }` as Unix milliseconds.
fn timestamp_ms(buf: &[u8]) -> Option<i64> {
    let (mut seconds, mut nanos) = (0i64, 0i64);
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 0) => seconds = r.varint()? as i64,
            (2, 0) => nanos = i64::from(r.varint()? as i32),
            (_, wire) => r.skip(wire)?,
        }
    }
    seconds.checked_mul(1000)?.checked_add(nanos / 1_000_000)
}

/// `LabelPairAdapter { string name = 1; string value = 2; }`.
fn label_pair(buf: &[u8]) -> Option<(String, String)> {
    let (mut name, mut value) = (String::new(), String::new());
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 2) => name = utf8(r.bytes()?),
            (2, 2) => value = utf8(r.bytes()?),
            (_, wire) => r.skip(wire)?,
        }
    }
    Some((name, value))
}

/// `EntryAdapter { Timestamp timestamp = 1; string line = 2; repeated LabelPairAdapter
/// structuredMetadata = 3; }`.
fn entry(buf: &[u8]) -> Option<Line> {
    let mut line = Line {
        ts_ms: None,
        line: String::new(),
        metadata: Vec::new(),
    };
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 2) => line.ts_ms = timestamp_ms(r.bytes()?),
            (2, 2) => line.line = utf8(r.bytes()?),
            (3, 2) => line.metadata.extend(label_pair(r.bytes()?)),
            (_, wire) => r.skip(wire)?,
        }
    }
    Some(line)
}

/// `StreamAdapter { string labels = 1; repeated EntryAdapter entries = 2; uint64 hash = 3; }`.
fn stream(buf: &[u8]) -> Option<Stream> {
    let mut s = Stream {
        labels: Vec::new(),
        lines: Vec::new(),
    };
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key()? {
            (1, 2) => s.labels = parse_labels(&utf8(r.bytes()?)),
            (2, 2) => s.lines.push(entry(r.bytes()?)?),
            (_, wire) => r.skip(wire)?,
        }
    }
    Some(s)
}

/// Decodes a (decompressed) `PushRequest { repeated StreamAdapter streams = 1; }`.
pub fn decode_protobuf(buf: &[u8]) -> Result<Vec<Stream>, &'static str> {
    let mut streams = Vec::new();
    let mut r = Reader::new(buf);
    while !r.done() {
        match r.key().ok_or("malformed protobuf")? {
            (1, 2) => streams
                .push(stream(r.bytes().ok_or("malformed protobuf")?).ok_or("malformed protobuf")?),
            (_, wire) => r.skip(wire).ok_or("malformed protobuf")?,
        }
    }
    Ok(streams)
}

// ---- JSON ---------------------------------------------------------------------------------

/// Decodes `{"streams":[{"stream":{...},"values":[["<ns>","line",{metadata}?],...]}]}`.
pub fn decode_json(body: &[u8]) -> Result<Vec<Stream>, &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "invalid JSON")?;
    let streams = v
        .get("streams")
        .and_then(Value::as_array)
        .ok_or("missing \"streams\"")?;
    let mut out = Vec::new();
    for s in streams {
        let labels = s
            .get("stream")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), crate::structured::json_scalar(v)?)))
                    .collect()
            })
            .unwrap_or_default();
        let mut lines = Vec::new();
        for value in s
            .get("values")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let pair = value
                .as_array()
                .ok_or("a value must be [timestamp, line]")?;
            let (Some(ts), Some(line)) = (pair.first(), pair.get(1)) else {
                return Err("a value must be [timestamp, line]");
            };
            let ts_ms = crate::structured::json_scalar(ts)
                .and_then(|t| t.parse::<i128>().ok())
                .and_then(|ns| i64::try_from(ns / 1_000_000).ok());
            let metadata = pair
                .get(2)
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| Some((k.clone(), crate::structured::json_scalar(v)?)))
                        .collect()
                })
                .unwrap_or_default();
            lines.push(Line {
                ts_ms,
                line: line
                    .as_str()
                    .ok_or("a log line must be a string")?
                    .to_string(),
                metadata,
            });
        }
        out.push(Stream { labels, lines });
    }
    Ok(out)
}

// ---- mapping to entries -------------------------------------------------------------------

/// Labels checked, in order, for the host and the application.
const HOST_LABELS: [&str; 5] = ["host", "hostname", "nodename", "node_name", "instance"];
const APP_LABELS: [&str; 7] = [
    "app",
    "service_name",
    "service",
    "job",
    "container",
    "unit",
    "syslog_identifier",
];
const LEVEL_LABELS: [&str; 4] = ["level", "severity", "detected_level", "log_level"];

/// Builds a LogPit entry from a stream's labels and one of its lines. Labels that name the host,
/// the application or the level fill those; the others (and structured metadata) become fields.
/// `extracted` holds what could be read out of the line itself (JSON or logfmt); labels win over
/// it when they use the same key.
pub fn to_entry(
    labels: &[(String, String)],
    line: &Line,
    extracted: Vec<(String, String)>,
    now_ms: i64,
) -> LogEntry {
    let find = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| labels.iter().find(|(k, v)| k == n && !v.is_empty()))
    };
    let host_label = find(&HOST_LABELS);
    let app_label = find(&APP_LABELS);
    let level_label = find(&LEVEL_LABELS);
    let used: Vec<&str> = [host_label, app_label, level_label]
        .into_iter()
        .flatten()
        .map(|(k, _)| k.as_str())
        .collect();

    let mut e = LogEntry {
        ts: line.ts_ms.unwrap_or(now_ms),
        host: host_label.map_or_else(|| "unknown".to_string(), |(_, v)| v.clone()),
        app: app_label.map(|(_, v)| v.clone()).unwrap_or_default(),
        severity: level_label
            .and_then(|(_, v)| level_severity(v))
            .unwrap_or(6),
        message: line.line.clone(),
        ..Default::default()
    };
    let others = labels
        .iter()
        .filter(|(k, _)| !used.contains(&k.as_str()))
        .chain(line.metadata.iter());
    for (k, v) in extracted.iter().chain(others) {
        if e.fields.len() >= MAX_FIELDS && !e.fields.contains_key(k) {
            continue;
        }
        if let (Some(key), false) = (crate::structured::sanitize_key(k), v.is_empty()) {
            let mut value = v.clone();
            truncate_utf8(&mut value, MAX_VALUE_BYTES);
            e.fields.insert(key, value);
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proto::encode::{len_field, num_field};

    fn entry_bytes(secs: i64, nanos: i32, line: &str, meta: &[(&str, &str)]) -> Vec<u8> {
        let mut ts = Vec::new();
        num_field(1, secs as u64, &mut ts);
        num_field(2, nanos as u64, &mut ts);
        let mut e = Vec::new();
        len_field(1, &ts, &mut e);
        len_field(2, line.as_bytes(), &mut e);
        for (k, v) in meta {
            let mut pair = Vec::new();
            len_field(1, k.as_bytes(), &mut pair);
            len_field(2, v.as_bytes(), &mut pair);
            len_field(3, &pair, &mut e);
        }
        e
    }
    fn push_bytes(streams: &[(&str, Vec<Vec<u8>>)]) -> Vec<u8> {
        let mut req = Vec::new();
        for (labels, entries) in streams {
            let mut s = Vec::new();
            len_field(1, labels.as_bytes(), &mut s);
            for e in entries {
                len_field(2, e, &mut s);
            }
            num_field(3, 7, &mut s); // the stream hash, which is ignored
            len_field(1, &s, &mut req);
        }
        req
    }

    #[test]
    fn labels_are_parsed_like_prometheus_label_sets() {
        let l = parse_labels(r#"{app="web", env="prod", msg="say \"hi\"\nnow", empty=""}"#);
        assert_eq!(
            l,
            [
                ("app", "web"),
                ("env", "prod"),
                ("msg", "say \"hi\"\nnow"),
                ("empty", "")
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        assert_eq!(parse_labels("{}"), []);
        assert_eq!(parse_labels(""), []);
        // Unquoted values, odd spacing, junk between labels: no panic, and what is valid is kept.
        assert_eq!(parse_labels("{a=1 ,  b = \"2\" , ???, c=\"3\"}").len(), 3);
        assert_eq!(
            parse_labels("{unterminated=\"abc"),
            [("unterminated".to_string(), "abc".to_string())]
        );
    }

    #[test]
    fn protobuf_push_is_decoded() {
        let body = push_bytes(&[
            (
                r#"{app="web",host="h1",level="error"}"#,
                vec![
                    entry_bytes(1_700_000_000, 123_000_000, "disk failed", &[]),
                    entry_bytes(1_700_000_001, 0, "second", &[("trace_id", "abc")]),
                ],
            ),
            (
                r#"{app="db"}"#,
                vec![entry_bytes(1_700_000_002, 999_999_999, "q", &[])],
            ),
        ]);
        let streams = decode_protobuf(&body).unwrap();
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0].labels.len(), 3);
        assert_eq!(
            streams[0].lines[0],
            Line {
                ts_ms: Some(1_700_000_000_123),
                line: "disk failed".into(),
                metadata: vec![]
            }
        );
        assert_eq!(
            streams[0].lines[1].metadata,
            [("trace_id".to_string(), "abc".to_string())]
        );
        assert_eq!(
            streams[1].lines[0].ts_ms,
            Some(1_700_000_002_999),
            "nanoseconds are truncated to ms"
        );
        assert!(decode_protobuf(&[]).unwrap().is_empty());
    }

    #[test]
    fn malformed_protobuf_is_an_error_not_a_panic() {
        let good = push_bytes(&[(r#"{a="b"}"#, vec![entry_bytes(1, 0, "x", &[])])]);
        for cut in 1..good.len() {
            let _ = decode_protobuf(&good[..cut]); // any truncation: Ok or Err, never a panic
        }
        assert!(
            decode_protobuf(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f]).is_err(),
            "length beyond the buffer"
        );
        assert!(decode_protobuf(&[0x0b]).is_err(), "deprecated wire type 3");
        let mut x: u64 = 0xdead_beef_cafe_f00d;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let data: Vec<u8> = (0..(x % 48)).map(|i| (x >> (i % 56)) as u8).collect();
            let _ = decode_protobuf(&data);
        }
    }

    #[test]
    fn snappy_wrapped_protobuf_round_trips() {
        let body = push_bytes(&[(r#"{app="web"}"#, vec![entry_bytes(5, 0, "hello", &[])])]);
        let compressed = crate::snappy::compress_literal(&body);
        let plain = crate::snappy::decompress(&compressed, MAX_DECOMPRESSED_BYTES).unwrap();
        assert_eq!(decode_protobuf(&plain).unwrap()[0].lines[0].line, "hello");
    }

    #[test]
    fn json_push_is_decoded() {
        let body = br#"{"streams":[
            {"stream":{"app":"web","n":5,"ok":true},"values":[["1700000000000000000","a line"],["1700000001500000000","b",{"trace":"t1"}]]},
            {"stream":{},"values":[]}
        ]}"#;
        let streams = decode_json(body).unwrap();
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0].lines[0].ts_ms, Some(1_700_000_000_000));
        assert_eq!(streams[0].lines[1].ts_ms, Some(1_700_000_001_500));
        assert_eq!(
            streams[0].lines[1].metadata,
            [("trace".to_string(), "t1".to_string())]
        );
        assert!(
            streams[0]
                .labels
                .contains(&("n".to_string(), "5".to_string())),
            "numbers and bools become strings"
        );
        for bad in [
            "",
            "[]",
            "{}",
            r#"{"streams":{}}"#,
            r#"{"streams":[{"values":[["1"]]}]}"#,
            r#"{"streams":[{"values":[["1",5]]}]}"#,
            r#"{"streams":[{"values":["x"]}]}"#,
        ] {
            assert!(decode_json(bad.as_bytes()).is_err(), "{bad:?}");
        }
        // A timestamp that is not a number is tolerated (the entry gets the arrival time).
        let odd = decode_json(br#"{"streams":[{"values":[["soon","x"]]}]}"#).unwrap();
        assert_eq!(odd[0].lines[0].ts_ms, None);
    }

    fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn labels_map_to_host_app_level_and_fields() {
        let line = Line {
            ts_ms: Some(1000),
            line: "disk failed".into(),
            metadata: vec![("trace_id".into(), "abc".into())],
        };
        let e = to_entry(
            &labels(&[
                ("hostname", "pve"),
                ("service_name", "kernel"),
                ("level", "ERROR"),
                ("env", "prod"),
            ]),
            &line,
            vec![],
            5,
        );
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.severity, e.ts),
            ("pve", "kernel", 3, 1000)
        );
        assert_eq!(e.message, "disk failed");
        assert_eq!(e.fields.get("env").map(String::as_str), Some("prod"));
        assert_eq!(e.fields.get("trace_id").map(String::as_str), Some("abc"));
        assert!(
            !e.fields.contains_key("hostname") && !e.fields.contains_key("level"),
            "mapped labels are not repeated"
        );
        // Without labels or a timestamp: defaults, with the arrival time.
        let bare = to_entry(
            &[],
            &Line {
                ts_ms: None,
                line: "x".into(),
                metadata: vec![],
            },
            vec![],
            777,
        );
        assert_eq!(
            (
                bare.host.as_str(),
                bare.app.as_str(),
                bare.severity,
                bare.ts
            ),
            ("unknown", "", 6, 777)
        );
    }

    #[test]
    fn level_words_and_label_precedence() {
        for (word, sev) in [
            ("debug", 7),
            ("TRACE", 7),
            ("info", 6),
            ("notice", 5),
            ("warn", 4),
            ("Warning", 4),
            ("error", 3),
            ("crit", 2),
            ("alert", 1),
            ("fatal", 0),
            ("panic", 0),
            ("3", 3),
        ] {
            assert_eq!(level_severity(word), Some(sev), "{word}");
        }
        assert_eq!(level_severity("unknown"), None);
        assert_eq!(level_severity("loud"), None);
        // First of the candidate labels wins; labels beat what was read from the line.
        let line = Line {
            ts_ms: None,
            line: "m".into(),
            metadata: vec![],
        };
        let e = to_entry(
            &labels(&[("instance", "i1"), ("host", "h1"), ("status", "label")]),
            &line,
            vec![
                ("status".into(), "line".into()),
                ("extra".into(), "x".into()),
            ],
            0,
        );
        assert_eq!(e.host, "h1", "host is preferred to instance");
        assert_eq!(e.fields["status"], "label");
        assert_eq!(e.fields["extra"], "x");
        // Invalid keys are made valid, empty values dropped, and the number of fields is bounded.
        let many: Vec<(String, String)> = (0..200).map(|i| (format!("k{i}"), "v".into())).collect();
        let e = to_entry(&many, &line, vec![], 0);
        assert_eq!(e.fields.len(), MAX_FIELDS);
        let e = to_entry(&labels(&[("a b/c", "1"), ("blank", "")]), &line, vec![], 0);
        assert_eq!(e.fields.keys().collect::<Vec<_>>(), ["a_b_c"]);
    }
}
