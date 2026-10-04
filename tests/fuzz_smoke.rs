//! Deterministic smoke fuzzing of every parser that sees untrusted input.
//!
//! The release build uses `panic = "abort"`, so a single panic in a parser would take the whole
//! server down. Each target gets random bytes and mutations of valid samples; the only assertion
//! is that nothing panics. `LOGPIT_FUZZ_ITERS` raises the number of cases per target (default
//! 3000) and `LOGPIT_FUZZ_SEED` changes the sequence.

use bytes::BytesMut;
use tokio_util::codec::Decoder;

/// xorshift64*: small, fast and reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }

    /// A random sample from `seeds`, then a few random edits: bit flips, interesting bytes,
    /// insertions, deletions, truncation and duplication of a slice.
    fn mutate(&mut self, seeds: &[&[u8]]) -> Vec<u8> {
        const INTERESTING: &[u8] = b"\0\n\r <>[]{}\"\\=:|*?-+.,0179\x7f\x80\xbf\xc0\xff";
        let mut v = seeds[self.below(seeds.len())].to_vec();
        for _ in 0..=self.below(4) {
            let at = self.below(v.len() + 1);
            match self.below(6) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] ^= 1 << self.below(8);
                }
                1 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = INTERESTING[self.below(INTERESTING.len())];
                }
                2 => v.insert(at, INTERESTING[self.below(INTERESTING.len())]),
                3 if at < v.len() => {
                    v.remove(at);
                }
                4 => v.truncate(at),
                _ => {
                    let end = (at + self.below(16)).min(v.len());
                    let slice = v[at..end].to_vec();
                    let to = self.below(v.len() + 1);
                    v.splice(to..to, slice);
                }
            }
        }
        v
    }

    fn input(&mut self, seeds: &[&[u8]]) -> Vec<u8> {
        if seeds.is_empty() || self.below(4) == 0 {
            self.bytes(256)
        } else {
            self.mutate(seeds)
        }
    }
}

fn iterations() -> usize {
    std::env::var("LOGPIT_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000)
}

/// Runs `target` on generated inputs; a panic names the target and the input that caused it.
fn fuzz(name: &str, seeds: &[&[u8]], target: impl Fn(&[u8])) {
    let seed: u64 = std::env::var("LOGPIT_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5eed_1065);
    let mut rng = Rng(seed
        ^ name
            .bytes()
            .fold(0u64, |h, b| h.wrapping_mul(31) ^ u64::from(b)));
    for _ in 0..iterations() {
        let input = rng.input(seeds);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| target(&input)));
        if result.is_err() {
            panic!("{name} panicked on input {input:?}");
        }
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A snappy block made of one literal, which is what a minimal valid sample needs.
fn snappy_literal(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 60);
    let mut out = vec![data.len() as u8];
    out.push(((data.len() - 1) as u8) << 2);
    out.extend_from_slice(data);
    out
}

#[test]
fn syslog_messages() {
    let seeds: &[&[u8]] = &[
        b"<34>1 2024-01-02T03:04:05.123Z host app 123 ID47 [ex@1 a=\"b\\\"]\"] \xef\xbb\xbfmsg",
        b"<13>Jan  2 03:04:05 host sshd[42]: Accepted publickey",
        b"<191>1 - - - - - - x",
        b"Oct 11 22:14:15 mymachine su: 'su root' failed",
    ];
    fuzz("syslog::parse", seeds, |b| {
        let _ = logpit::syslog::parse(&text(b), "10.0.0.1", 0);
    });
}

#[test]
fn syslog_and_gelf_framing() {
    let seeds: &[&[u8]] = &[
        b"12 <13>abcdefgh<13>plain\n\n7 <1>abc",
        b"99999999 <1>x\n",
        b"{\"short_message\":\"a\"}\0{\"short_message\":\"b\"}\n",
    ];
    fuzz("framing", seeds, |b| {
        // Fed in two pieces, as a socket would, then closed.
        let cut = b.len() / 3;
        let mut syslog = logpit::framing::SyslogFrames::new(64);
        let mut gelf = logpit::gelf::GelfFrames::new(64);
        for codec in 0..2 {
            let mut buf = BytesMut::from(&b[..cut]);
            let mut step = |buf: &mut BytesMut, eof: bool| -> bool {
                let r = match (codec, eof) {
                    (0, false) => syslog.decode(buf).map(|f| f.is_some()),
                    (0, true) => syslog.decode_eof(buf).map(|f| f.is_some()),
                    (_, false) => gelf.decode(buf).map(|f| f.is_some()),
                    (_, true) => gelf.decode_eof(buf).map(|f| f.is_some()),
                };
                matches!(r, Ok(true))
            };
            while step(&mut buf, false) {}
            buf.extend_from_slice(&b[cut..]);
            while step(&mut buf, false) {}
            while step(&mut buf, true) {}
        }
    });
}

#[test]
fn gelf_messages() {
    let seeds: &[&[u8]] = &[
        br#"{"version":"1.1","host":"h","short_message":"m","full_message":"f","timestamp":1700000000.5,"level":3,"_user":"u","_n":5}"#,
        br#"{"short_message":"x","timestamp":-1e308,"level":99}"#,
    ];
    fuzz("gelf::parse", seeds, |b| {
        let _ = logpit::gelf::parse(b, 0);
    });
}

#[test]
fn gelf_chunks() {
    let seeds: &[&[u8]] = &[
        b"\x1e\x0f\x01\x02\x03\x04\x05\x06\x07\x08\x00\x02{\"short_message\":",
        b"\x1e\x0f\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\"m\"}",
    ];
    let chunks = std::cell::RefCell::new(logpit::gelf::Chunks::default());
    let start = std::time::Instant::now();
    fuzz("gelf::Chunks", seeds, |b| {
        let mut chunks = chunks.borrow_mut();
        if let Ok(Some(message)) = chunks.add([127, 0, 0, 1].into(), b, start) {
            let _ = logpit::gelf::parse(&message, 0);
        }
        chunks.expire(start);
    });
}

#[test]
fn decompressors() {
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
    let snappy = snappy_literal(b"hello snappy hello snappy");
    // A literal followed by a 1-byte-offset copy of it.
    let copy: &[u8] = &[8, 0b0000_1100, b'a', b'b', b'c', b'd', 0b0000_0001, 4];
    fuzz("inflate", &[GZ_HELLO, ZL_HELLO], |b| {
        let _ = logpit::inflate::gunzip(b, 4096);
        let _ = logpit::inflate::zlib(b, 4096);
    });
    fuzz("snappy", &[&snappy, copy], |b| {
        let _ = logpit::snappy::decompress(b, 4096);
    });
}

#[test]
fn loki_push_bodies() {
    // PushRequest { streams: [{ labels: "{host=\"h\"}", entries: [{ ts: {1, 2}, line: "x" }] }] }
    let labels = br#"{host="h", app="a", level="warn"}"#;
    let entry: &[u8] = &[0x0a, 0x04, 0x08, 0x01, 0x10, 0x02, 0x12, 0x01, b'x'];
    let mut stream = vec![0x0a, labels.len() as u8];
    stream.extend_from_slice(labels);
    stream.extend_from_slice(&[0x12, entry.len() as u8]);
    stream.extend_from_slice(entry);
    let mut push = vec![0x0a, stream.len() as u8];
    push.extend_from_slice(&stream);
    let json = br#"{"streams":[{"stream":{"host":"h","n":1},"values":[["1700000000000000000","line",{"k":"v"}],["x","y"]]}]}"#;
    fuzz("loki::decode_protobuf", &[&push], |b| {
        let _ = logpit::loki::decode_protobuf(b);
    });
    fuzz("loki::decode_json", &[json], |b| {
        let _ = logpit::loki::decode_json(b);
    });
    fuzz(
        "loki::parse_labels",
        &[labels, br#"{a="\"\\", b=~"x"}"#],
        |b| {
            let _ = logpit::loki::parse_labels(&text(b));
        },
    );
}

#[test]
fn otlp_bodies() {
    let json = br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"h"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"1700000000000000000","severityNumber":17,"body":{"kvlistValue":{"values":[{"key":"a","value":{"intValue":"3"}}]}},"attributes":[{"key":"x","value":{"arrayValue":{"values":[{"boolValue":true}]}}}]}]}]}]}"#;
    // ExportLogsServiceRequest { resource_logs { scope_logs { log_records { body: "hi" } } } }
    let record: &[u8] = &[0x2a, 0x04, 0x0a, 0x02, b'h', b'i'];
    let mut scope = vec![0x12, record.len() as u8];
    scope.extend_from_slice(record);
    let mut resource = vec![0x12, scope.len() as u8];
    resource.extend_from_slice(&scope);
    let mut request = vec![0x0a, resource.len() as u8];
    request.extend_from_slice(&resource);
    fuzz("otlp::decode_protobuf", &[&request], |b| {
        let _ = logpit::otlp::decode_protobuf(b, 0);
    });
    fuzz("otlp::decode_json", &[json], |b| {
        let _ = logpit::otlp::decode_json(b, 0);
    });
}

#[test]
fn otlp_traces() {
    let json = br#"{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"s"}}]},"scopeSpans":[{"spans":[{"traceId":"0af7651916cd43dd8448eb211c80319c","spanId":"b7ad6b7169203331","parentSpanId":"00f067aa0ba902b7","name":"n","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1","endTimeUnixNano":"2","events":[{"timeUnixNano":"1","name":"e"}],"status":{"code":2,"message":"m"}}]}]}]}"#;
    // ExportTraceServiceRequest { resource_spans { scope_spans { spans { trace_id, span_id, name, status } } } }
    let mut span = vec![0x0a, 16];
    span.extend_from_slice(&[0x5a; 16]);
    span.extend_from_slice(&[0x12, 8]);
    span.extend_from_slice(&[0x5b; 8]);
    span.extend_from_slice(&[0x2a, 1, b'n', 0x7a, 2, 0x18, 2]);
    let mut scope = vec![0x12, span.len() as u8];
    scope.extend_from_slice(&span);
    let mut resource = vec![0x12, scope.len() as u8];
    resource.extend_from_slice(&scope);
    let mut request = vec![0x0a, resource.len() as u8];
    request.extend_from_slice(&resource);
    fuzz("spans::decode_protobuf", &[&request], |b| {
        let _ = logpit::spans::decode_protobuf(b);
    });
    fuzz("spans::decode_json", &[json], |b| {
        let _ = logpit::spans::decode_json(b);
    });
}

#[test]
fn message_level_parsers() {
    let seeds: &[&[u8]] = &[
        b"CEF:0|Ubiquiti|UniFi Network|9.0|400|Blocked|5|src=10.0.0.1 dst=1.1.1.1 msg=a\\=b c\\\\",
        b"level=warn user=\"bob smith\" n=5 ok",
        br#"{"level":"error","msg":"x","nested":{"a":[1,2]},"n":1.5}"#,
        b"GET /index.html 200 1234 0.003s 2001:db8::1 ab12cd34-0000-1111-2222-333344445555",
    ];
    fuzz("cef", seeds, |b| {
        let t = text(b);
        let _ = logpit::cef::parse(&t);
        let _ = logpit::cef::parse_extension(&t);
    });
    fuzz("structured::extract", seeds, |b| {
        let _ = logpit::structured::extract(&text(b));
    });
    fuzz("patterns::template", seeds, |b| {
        let t = logpit::patterns::template(&text(b));
        let _ = logpit::patterns::search_hint(&t);
    });
    fuzz("api::entry_from_json", seeds, |b| {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(b) {
            let _ = logpit::api::entry_from_json(&v, 0);
        }
    });
}

#[test]
fn query_languages() {
    let seeds: &[&[u8]] = &[
        br#"sum by (host) (count_over_time({host=~"web.*", app!="x"} |= "err" != "ok" |~ "a+" [5m]))"#,
        br#"rate({level="error"} | json | status >= 500 [1h30m])"#,
        br#"{app="nginx"} | logfmt | duration > 1.5s"#,
        br#"disk "exact phrase" -noise host:* foo*"#,
        b"status>=500",
        b"user=~^adm",
        b"1h30m500ms",
    ];
    fuzz("logql::parse", seeds, |b| {
        let _ = logpit::logql::parse(&text(b));
        let _ = logpit::logql::parse_duration_ms(&text(b));
    });
    fuzz("query::parse", seeds, |b| {
        let p = logpit::query::parse(&text(b));
        let _ = (p.fts_include(), p.fts_exclude(), p.matches("some text"));
    });
    fuzz("filters::parse_expr", seeds, |b| {
        let _ = logpit::filters::parse_expr(&text(b));
    });
    fuzz("api parameters", seeds, |b| {
        let t = text(b);
        let _ = logpit::lokiapi::parse_time(&t);
        let _ = logpit::stats::parse_bucket_ms(&t);
        let _ = logpit::tags::glob_match(&t, "web-01.example");
        let _ = logpit::tags::glob_match("w*b-?1*", &t);
    });
}

/// Hostile search text must never make SQLite fail, whatever FTS5 makes of it.
#[test]
fn search_text_never_breaks_the_query() {
    let dir = std::env::temp_dir().join(format!("logpit-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fuzz.db");
    let mut conn = logpit::store::open(&path).unwrap();
    logpit::store::insert_batch(
        &mut conn,
        &[logpit::model::LogEntry {
            ts: 1,
            host: "h".into(),
            message: "plain message with words".into(),
            ..Default::default()
        }],
    )
    .unwrap();
    let seeds: &[&[u8]] = &[
        br#"disk "exact phrase" -noise foo* NEAR(a b) col:val ^start"#,
        b"\"\" - * ( ) AND OR NOT",
    ];
    let iters = iterations() / 10;
    let mut rng = Rng(0xf75);
    for _ in 0..iters.max(100) {
        let t = text(&rng.input(seeds));
        let q = logpit::store::Query {
            text: Some(t.clone()),
            limit: 5,
            ..Default::default()
        };
        if let Err(e) = logpit::store::search(&conn, &q) {
            panic!("search for {t:?} failed: {e}");
        }
    }
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}
