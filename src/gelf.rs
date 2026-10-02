//! GELF (Graylog Extended Log Format) input: one JSON object per message, over UDP, TCP
//! (messages separated by a NUL byte or a newline) or `POST /gelf`.
//!
//! Compressed (gzip, zlib) and chunked UDP messages are not supported; the sender needs to use
//! uncompressed GELF (Docker: `--log-opt gelf-compression-type=none`).

use std::io;

use bytes::BytesMut;
use serde_json::Value;
use tokio_util::codec::Decoder;

use crate::model::{LogEntry, truncate_utf8};

const MAX_FIELDS: usize = 64;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 1024;

/// Keys checked, in order, for the application name.
const APP_KEYS: [&str; 6] = [
    "_app",
    "_application",
    "_facility",
    "facility",
    "_container_name",
    "_tag",
];

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn field_key(key: &str) -> Option<String> {
    let mut k: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    truncate_utf8(&mut k, MAX_KEY_BYTES);
    (!k.trim_matches('_').is_empty()).then_some(k)
}

/// Parses one GELF message. `now_ms` is used when it carries no timestamp.
pub fn parse(data: &[u8], now_ms: i64) -> Result<LogEntry, &'static str> {
    let data = data.trim_ascii();
    match data {
        [0x1f, 0x8b, ..] | [0x78, ..] => {
            return Err("compressed GELF is not supported; set the sender's compression to none");
        }
        [0x1e, 0x0f, ..] => {
            return Err("chunked GELF is not supported; send each message in one datagram");
        }
        _ => {}
    }
    let Value::Object(obj) =
        serde_json::from_slice::<Value>(data).map_err(|_| "invalid GELF: not JSON")?
    else {
        return Err("invalid GELF: not a JSON object");
    };
    let short = obj
        .get("short_message")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("invalid GELF: short_message is required")?;
    let full = obj
        .get("full_message")
        .and_then(Value::as_str)
        .filter(|f| !f.is_empty() && *f != short);
    let message = match full {
        Some(full) => format!("{short}\n{full}"),
        None => short.to_string(),
    };

    // Seconds since the epoch, usually with a fractional part; a value too large for that is
    // already in milliseconds.
    let ts = match obj.get("timestamp").and_then(number) {
        Some(t) if t.is_finite() && t > 0.0 => {
            if t > 1e11 {
                t as i64
            } else {
                (t * 1000.0).round() as i64
            }
        }
        _ => now_ms,
    };
    let severity = obj
        .get("level")
        .and_then(number)
        .filter(|l| (0.0..=7.0).contains(l))
        .map_or(6, |l| l as u8);
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .filter(|h| !h.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let app_key = APP_KEYS
        .into_iter()
        .find(|k| obj.get(*k).and_then(scalar).is_some());
    let app = app_key
        .and_then(|k| obj.get(k).and_then(scalar))
        .unwrap_or_default();

    let mut e = LogEntry {
        ts,
        host,
        app,
        severity,
        message,
        ..Default::default()
    };
    // Additional fields are the keys that start with an underscore (`_id` is reserved).
    for (key, value) in &obj {
        let Some(name) = key.strip_prefix('_') else {
            continue;
        };
        if name == "id" || Some(key.as_str()) == app_key || e.fields.len() >= MAX_FIELDS {
            continue;
        }
        if let (Some(k), Some(mut v)) = (field_key(name), scalar(value)) {
            truncate_utf8(&mut v, MAX_VALUE_BYTES);
            e.fields.insert(k, v);
        }
    }
    Ok(e)
}

/// Splits a TCP stream into GELF messages: each ends at a NUL byte or a newline.
pub struct GelfFrames {
    max_len: usize,
}

impl GelfFrames {
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }

    fn too_long(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("GELF message longer than {} bytes", self.max_len),
        )
    }
}

impl Decoder for GelfFrames {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Vec<u8>>> {
        loop {
            match src.iter().position(|b| matches!(b, 0 | b'\n')) {
                Some(i) if i > self.max_len => return Err(self.too_long()),
                Some(i) => {
                    let frame = src.split_to(i + 1);
                    let body = frame[..i].trim_ascii();
                    if body.is_empty() {
                        continue; // separators between messages carry nothing
                    }
                    return Ok(Some(body.to_vec()));
                }
                None if src.len() > self.max_len => return Err(self.too_long()),
                None => return Ok(None),
            }
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<Vec<u8>>> {
        if let Some(frame) = self.decode(src)? {
            return Ok(Some(frame));
        }
        let rest = src.split();
        let body = rest.trim_ascii();
        Ok((!body.is_empty()).then(|| body.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> Result<LogEntry, &'static str> {
        parse(s.as_bytes(), 42)
    }

    #[test]
    fn a_full_message_maps_to_an_entry() {
        let e = parse_str(
            r#"{"version":"1.1","host":"web1","short_message":"disk failed","full_message":"stack\ntrace",
                "timestamp":1700000000.1234,"level":3,"_app":"billing","_user":"bob","_retries":3,
                "_ok":true,"_id":"ignored","_nested":{"a":1},"_empty":"","other":"no underscore"}"#,
        )
        .unwrap();
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.severity, e.ts),
            ("web1", "billing", 3, 1_700_000_000_123)
        );
        assert_eq!(e.message, "disk failed\nstack\ntrace");
        assert_eq!(e.fields["user"], "bob");
        assert_eq!(e.fields["retries"], "3");
        assert_eq!(e.fields["ok"], "true");
        for absent in ["id", "nested", "empty", "app", "other"] {
            assert!(
                !e.fields.contains_key(absent),
                "{absent} must not be a field"
            );
        }
    }

    #[test]
    fn defaults_and_tolerance() {
        let e = parse_str(r#"{"short_message":"hi"}"#).unwrap();
        assert_eq!(
            (
                e.host.as_str(),
                e.app.as_str(),
                e.severity,
                e.ts,
                e.message.as_str()
            ),
            ("unknown", "", 6, 42, "hi")
        );
        // The legacy facility names the app; a full_message equal to the short one is not repeated.
        let e = parse_str(r#"{"short_message":"x","full_message":"x","facility":"cron","level":"4","timestamp":"1700000000"}"#).unwrap();
        assert_eq!(
            (e.app.as_str(), e.severity, e.ts, e.message.as_str()),
            ("cron", 4, 1_700_000_000_000, "x")
        );
        // Millisecond timestamps (too large to be seconds) are accepted; junk falls back to now.
        assert_eq!(
            parse_str(r#"{"short_message":"x","timestamp":1700000000123}"#)
                .unwrap()
                .ts,
            1_700_000_000_123
        );
        assert_eq!(
            parse_str(r#"{"short_message":"x","timestamp":-5}"#)
                .unwrap()
                .ts,
            42
        );
        assert_eq!(
            parse_str(r#"{"short_message":"x","timestamp":"soon"}"#)
                .unwrap()
                .ts,
            42
        );
        // A level outside 0-7 means info.
        assert_eq!(
            parse_str(r#"{"short_message":"x","level":9}"#)
                .unwrap()
                .severity,
            6
        );
        // Whitespace around the message (as a TCP sender may add) is fine.
        assert!(parse(b"  {\"short_message\":\"x\"}\n", 0).is_ok());
    }

    #[test]
    fn invalid_and_unsupported_messages_are_refused_with_a_reason() {
        for (input, expect) in [
            (&b"{\"host\":\"h\"}"[..], "short_message"),
            (b"{\"short_message\":\"\"}", "short_message"),
            (b"{\"short_message\":5}", "short_message"),
            (b"not json", "not JSON"),
            (b"[1,2]", "not a JSON object"),
            (b"\x1f\x8b\x08\x00....", "compressed"),
            (b"x\x9c\x4b\xcb", "compressed"),
            (b"\x1e\x0fchunk", "chunked"),
            (b"", "not JSON"),
        ] {
            let err = parse(input, 0).unwrap_err();
            assert!(err.contains(expect), "{input:?}: {err}");
        }
    }

    #[test]
    fn limits_hold() {
        let many: String = (0..200).map(|i| format!("\"_k{i}\":\"v\",")).collect();
        let e = parse_str(&format!("{{{many}\"short_message\":\"x\"}}")).unwrap();
        assert_eq!(e.fields.len(), MAX_FIELDS);
        let long = "z".repeat(5000);
        let e = parse_str(&format!(
            r#"{{"short_message":"x","_big":"{long}","_bad key!":"1"}}"#
        ))
        .unwrap();
        assert_eq!(e.fields["big"].len(), MAX_VALUE_BYTES);
        assert!(e.fields.contains_key("bad_key_"));
    }

    fn frames(input: &[u8], max: usize) -> Vec<Vec<u8>> {
        let mut codec = GelfFrames::new(max);
        let mut buf = BytesMut::from(input);
        let mut out = Vec::new();
        while let Some(f) = codec.decode(&mut buf).unwrap() {
            out.push(f);
        }
        out
    }

    #[test]
    fn tcp_framing_accepts_nul_and_newline_separators() {
        assert_eq!(
            frames(b"{\"a\":1}\0{\"b\":2}\0", 100),
            [b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]
        );
        assert_eq!(
            frames(b"{\"a\":1}\n\n{\"b\":2}\r\n", 100).len(),
            2,
            "newlines and blank lines"
        );
        assert_eq!(frames(b"{\"a\":1}\0\0\0{\"b\":2}\0", 100).len(), 2);
        // A partial message waits for its terminator, and the last one is kept at end of input.
        let mut codec = GelfFrames::new(100);
        let mut buf = BytesMut::from(&b"{\"a\":1}"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(codec.decode_eof(&mut buf).unwrap().unwrap(), b"{\"a\":1}");
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
        // Too long, with or without a terminator.
        assert!(
            GelfFrames::new(5)
                .decode(&mut BytesMut::from(&b"0123456789\0"[..]))
                .is_err()
        );
        assert!(
            GelfFrames::new(5)
                .decode(&mut BytesMut::from(&b"0123456789"[..]))
                .is_err()
        );
    }
}
