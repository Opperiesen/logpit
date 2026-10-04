//! GELF (Graylog Extended Log Format) input: one JSON object per message, over UDP, TCP
//! (messages separated by a NUL byte or a newline) or `POST /gelf`.
//!
//! Messages may be gzip- or zlib-compressed (the usual default of GELF senders). Over UDP, a
//! message too large for one datagram arrives in chunks that [`Chunks`] puts back together, with
//! bounded memory: incomplete messages are given up after a few seconds.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use serde_json::Value;
use tokio_util::codec::Decoder;

use crate::model::{LogEntry, truncate_utf8};
use crate::structured::MAX_VALUE_BYTES;

const MAX_FIELDS: usize = 64;
/// A compressed message may not expand beyond this.
const MAX_MESSAGE_BYTES: usize = 1 << 20;

/// Keys checked, in order, for the application name.
const APP_KEYS: [&str; 6] = [
    "_app",
    "_application",
    "_facility",
    "facility",
    "_container_name",
    "_tag",
];

/// A non-empty string, a number or a boolean as text.
fn scalar(v: &Value) -> Option<String> {
    crate::structured::json_scalar(v).filter(|s| !s.is_empty())
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parses one GELF message. `now_ms` is used when it carries no timestamp.
pub fn parse(data: &[u8], now_ms: i64) -> Result<LogEntry, &'static str> {
    let data = data.trim_ascii();
    if data.starts_with(&[0x1e, 0x0f]) {
        return Err("chunked GELF is only accepted over UDP");
    }
    // gzip and zlib (what Docker's GELF driver and most libraries use by default) are undone first.
    let inflated;
    let data = if crate::inflate::looks_like_gzip(data) {
        inflated = crate::inflate::gunzip(data, MAX_MESSAGE_BYTES)
            .map_err(|_| "invalid compressed GELF message")?;
        inflated.as_slice()
    } else if crate::inflate::looks_like_zlib(data) {
        inflated = crate::inflate::zlib(data, MAX_MESSAGE_BYTES)
            .map_err(|_| "invalid compressed GELF message")?;
        inflated.as_slice()
    } else {
        data
    };
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
        if let (Some(k), Some(mut v)) = (crate::structured::sanitize_key(name), scalar(value)) {
            truncate_utf8(&mut v, MAX_VALUE_BYTES);
            e.fields.insert(k, v);
        }
    }
    Ok(e)
}

/// Starts a chunk: magic bytes, an 8-byte message id, the sequence number and the chunk count.
const CHUNK_MAGIC: [u8; 2] = [0x1e, 0x0f];
const CHUNK_HEADER: usize = 12;
/// The GELF specification's limits: at most 128 chunks, and a message is dropped when its chunks
/// have not all arrived within five seconds.
const MAX_CHUNKS: u8 = 128;
const CHUNK_TIMEOUT: Duration = Duration::from_secs(5);
/// Bytes held by all incomplete messages together; a chunk that would go past it is refused.
const MAX_PENDING_BYTES: usize = 8 << 20;

pub fn is_chunk(datagram: &[u8]) -> bool {
    datagram.starts_with(&CHUNK_MAGIC)
}

struct Pending {
    started: Instant,
    parts: Vec<Option<Vec<u8>>>,
    missing: usize,
    bytes: usize,
}

/// Reassembles chunked GELF datagrams. Messages are keyed by sender and id, so one sender
/// cannot complete or spoil another's.
#[derive(Default)]
pub struct Chunks {
    pending: HashMap<(IpAddr, [u8; 8]), Pending>,
    bytes: usize,
}

impl Chunks {
    /// Adds one chunk; returns the whole message once its last chunk arrives.
    pub fn add(
        &mut self,
        peer: IpAddr,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let (Some(header), Some(payload)) =
            (datagram.get(..CHUNK_HEADER), datagram.get(CHUNK_HEADER..))
        else {
            return Err("invalid GELF chunk: truncated header");
        };
        let mut id = [0u8; 8];
        id.copy_from_slice(&header[2..10]);
        let (seq, count) = (header[10], header[11]);
        if count == 0 || count > MAX_CHUNKS || seq >= count {
            return Err("invalid GELF chunk: bad sequence number or count");
        }
        if self.bytes + payload.len() > MAX_PENDING_BYTES {
            return Err("too many incomplete chunked GELF messages");
        }
        let key = (peer, id);
        let p = self.pending.entry(key).or_insert_with(|| Pending {
            started: now,
            parts: vec![None; usize::from(count)],
            missing: usize::from(count),
            bytes: 0,
        });
        if p.parts.len() != usize::from(count) {
            return Err("invalid GELF chunk: count differs between chunks");
        }
        if p.bytes + payload.len() > MAX_MESSAGE_BYTES {
            self.bytes -= p.bytes;
            self.pending.remove(&key);
            return Err("chunked GELF message too large");
        }
        let slot = &mut p.parts[usize::from(seq)];
        if slot.is_some() {
            return Ok(None); // a repeated chunk changes nothing
        }
        *slot = Some(payload.to_vec());
        p.missing -= 1;
        p.bytes += payload.len();
        self.bytes += payload.len();
        if p.missing > 0 {
            return Ok(None);
        }
        let p = self.pending.remove(&key).expect("just updated");
        self.bytes -= p.bytes;
        Ok(Some(p.parts.into_iter().flatten().flatten().collect()))
    }

    /// Drops the messages whose chunks did not all arrive in time; returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        let bytes = &mut self.bytes;
        self.pending.retain(|_, p| {
            let keep = now.duration_since(p.started) < CHUNK_TIMEOUT;
            if !keep {
                *bytes -= p.bytes;
            }
            keep
        });
        before - self.pending.len()
    }
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
            (b"\x1e\x0fchunk", "only accepted over UDP"),
            (b"", "not JSON"),
        ] {
            let err = parse(input, 0).unwrap_err();
            assert!(err.contains(expect), "{input:?}: {err}");
        }
    }

    // The same message compressed by Python's gzip and zlib modules.
    const GZIPPED: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0x8b, 0xc1, 0x0a, 0x80,
        0x20, 0x10, 0x44, 0x7f, 0x45, 0xf6, 0x1c, 0x41, 0xd0, 0xa9, 0x9f, 0x11, 0xb3, 0x21, 0x25,
        0x75, 0x63, 0x57, 0xea, 0x10, 0xfd, 0x7b, 0xda, 0x6d, 0xde, 0xbc, 0x99, 0x87, 0x2e, 0x88,
        0x46, 0x2e, 0xb4, 0x18, 0x9a, 0xc6, 0x89, 0x06, 0x43, 0x81, 0xb5, 0x76, 0xdc, 0xd8, 0x1f,
        0x90, 0x9f, 0x5a, 0xab, 0x81, 0xa5, 0xda, 0x0c, 0x55, 0xb7, 0xa3, 0x6b, 0xcf, 0xf9, 0x94,
        0x86, 0xd8, 0x4c, 0x40, 0x4a, 0xdc, 0x47, 0x09, 0x17, 0x52, 0x93, 0x73, 0xcb, 0xd6, 0x73,
        0xa9, 0x2e, 0x16, 0x88, 0x2d, 0x2e, 0xff, 0x97, 0x1b, 0x2b, 0xbd, 0x1f, 0x6f, 0x43, 0x30,
        0x50, 0x73, 0x00, 0x00, 0x00,
    ];
    const ZLIBBED: &[u8] = &[
        0x78, 0x9c, 0x1d, 0x8b, 0xc1, 0x0a, 0x80, 0x20, 0x10, 0x44, 0x7f, 0x45, 0xf6, 0x1c, 0x41,
        0xd0, 0xa9, 0x9f, 0x11, 0xb3, 0x21, 0x25, 0x75, 0x63, 0x57, 0xea, 0x10, 0xfd, 0x7b, 0xda,
        0x6d, 0xde, 0xbc, 0x99, 0x87, 0x2e, 0x88, 0x46, 0x2e, 0xb4, 0x18, 0x9a, 0xc6, 0x89, 0x06,
        0x43, 0x81, 0xb5, 0x76, 0xdc, 0xd8, 0x1f, 0x90, 0x9f, 0x5a, 0xab, 0x81, 0xa5, 0xda, 0x0c,
        0x55, 0xb7, 0xa3, 0x6b, 0xcf, 0xf9, 0x94, 0x86, 0xd8, 0x4c, 0x40, 0x4a, 0xdc, 0x47, 0x09,
        0x17, 0x52, 0x93, 0x73, 0xcb, 0xd6, 0x73, 0xa9, 0x2e, 0x16, 0x88, 0x2d, 0x2e, 0xff, 0x97,
        0x1b, 0x2b, 0xbd, 0x1f, 0x5c, 0x92, 0x25, 0x62,
    ];

    #[test]
    fn gzip_and_zlib_messages_are_decompressed() {
        for compressed in [GZIPPED, ZLIBBED] {
            let e = parse(compressed, 0).unwrap();
            assert_eq!(
                (
                    e.host.as_str(),
                    e.app.as_str(),
                    e.severity,
                    e.message.as_str()
                ),
                ("dockerhost", "web", 4, "compressed hello")
            );
        }
        // Damaged compressed data is refused with a reason, never a panic.
        assert!(parse(&GZIPPED[..GZIPPED.len() - 5], 0).is_err());
        assert!(parse(&ZLIBBED[..ZLIBBED.len() / 2], 0).is_err());
        let mut flipped = GZIPPED.to_vec();
        flipped[14] ^= 0xff;
        assert!(parse(&flipped, 0).is_err());
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

    fn chunk(id: u8, seq: u8, count: u8, payload: &[u8]) -> Vec<u8> {
        let mut c = vec![0x1e, 0x0f, id, 0, 0, 0, 0, 0, 0, 0, seq, count];
        c.extend_from_slice(payload);
        c
    }

    #[test]
    fn chunks_are_reassembled_in_any_order() {
        let peer: IpAddr = [10, 0, 0, 1].into();
        let other: IpAddr = [10, 0, 0, 2].into();
        let t = Instant::now();
        let mut chunks = Chunks::default();
        // Docker compresses then chunks: the gzipped message split in three, out of order.
        let (a, rest) = GZIPPED.split_at(40);
        let (b, c) = rest.split_at(40);
        assert!(is_chunk(&chunk(1, 2, 3, c)));
        assert_eq!(chunks.add(peer, &chunk(1, 2, 3, c), t), Ok(None));
        assert_eq!(chunks.add(peer, &chunk(1, 0, 3, a), t), Ok(None));
        assert_eq!(chunks.add(peer, &chunk(1, 0, 3, a), t), Ok(None), "repeat");
        // The same id from another sender is another message.
        assert_eq!(chunks.add(other, &chunk(1, 1, 3, b), t), Ok(None));
        let whole = chunks.add(peer, &chunk(1, 1, 3, b), t).unwrap().unwrap();
        assert_eq!(parse(&whole, 0).unwrap().message, "compressed hello");
        // One chunk is a whole message; the other sender's part expires and frees its bytes.
        let one = chunks.add(peer, &chunk(2, 0, 1, b"{\"short_message\":\"x\"}"), t);
        assert_eq!(parse(&one.unwrap().unwrap(), 0).unwrap().message, "x");
        assert_eq!(chunks.expire(t + Duration::from_secs(4)), 0);
        assert_eq!(chunks.expire(t + CHUNK_TIMEOUT), 1);
        assert_eq!((chunks.pending.len(), chunks.bytes), (0, 0));
    }

    #[test]
    fn bad_chunks_are_refused_and_memory_stays_bounded() {
        let peer: IpAddr = [10, 0, 0, 1].into();
        let t = Instant::now();
        let mut chunks = Chunks::default();
        for (bad, expect) in [
            (vec![0x1e, 0x0f, 1, 2], "truncated"),
            (chunk(1, 0, 0, b"x"), "count"),
            (chunk(1, 3, 3, b"x"), "count"),
            (chunk(1, 0, 129, b"x"), "count"),
        ] {
            assert!(chunks.add(peer, &bad, t).unwrap_err().contains(expect));
        }
        chunks.add(peer, &chunk(1, 0, 3, b"x"), t).unwrap();
        assert!(
            chunks
                .add(peer, &chunk(1, 1, 2, b"x"), t)
                .unwrap_err()
                .contains("differs")
        );
        // A message may not grow past the message limit, nor all of them past the pending one.
        let big = vec![b'z'; 60_000];
        let mut err = Ok(None);
        for seq in 0..20 {
            err = chunks.add(peer, &chunk(2, seq, 100, &big), t);
            if err.is_err() {
                break;
            }
        }
        assert_eq!(err, Err("chunked GELF message too large"));
        assert_eq!(chunks.bytes, 1, "the dropped message freed its bytes");
        let mut refused = false;
        for id in 3..=255 {
            for seq in 0..16 {
                if chunks.add(peer, &chunk(id, seq, 100, &big), t).is_err() {
                    refused = true;
                }
            }
        }
        assert!(refused && chunks.bytes <= MAX_PENDING_BYTES);
    }
}
