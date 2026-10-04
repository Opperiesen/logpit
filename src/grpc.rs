//! OTLP over gRPC: `opentelemetry.proto.collector.logs.v1.LogsService/Export`, the unary call the
//! OpenTelemetry SDKs and Collector use by default. It is plain HTTP/2 (served on the HTTP port,
//! with or without TLS) carrying length-prefixed protobuf, the same `ExportLogsServiceRequest` the
//! OTLP/HTTP endpoint reads, answered with a `grpc-status` in the trailers.

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, Full};

use crate::ingest::{Sink, now_ms};
use crate::metrics::Metrics;

/// The path of the call.
pub const LOGS_EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";
/// The same call for traces (`ExportTraceServiceRequest`).
pub const TRACES_EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// Largest message accepted once decompressed.
const MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// gRPC status codes used here.
pub mod code {
    pub const OK: u8 = 0;
    pub const INVALID_ARGUMENT: u8 = 3;
    pub const RESOURCE_EXHAUSTED: u8 = 8;
    pub const UNIMPLEMENTED: u8 = 12;
    pub const INTERNAL: u8 = 13;
}

/// A failure to turn the request body into the one protobuf message it must carry.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal(pub u8, pub &'static str);

/// The message of a unary call: `[compressed flag][length: u32 big endian][message]`, once.
pub fn read_message(body: &[u8], encoding: Option<&str>) -> Result<Vec<u8>, Refusal> {
    if body.len() < 5 {
        return Err(Refusal(
            code::INVALID_ARGUMENT,
            "the message frame is incomplete",
        ));
    }
    let flag = body[0];
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if len > MAX_MESSAGE {
        return Err(Refusal(
            code::RESOURCE_EXHAUSTED,
            "the message is too large",
        ));
    }
    let Some(payload) = body[5..].get(..len) else {
        return Err(Refusal(
            code::INVALID_ARGUMENT,
            "the message is shorter than its length",
        ));
    };
    if body.len() != 5 + len {
        return Err(Refusal(
            code::INVALID_ARGUMENT,
            "a unary call carries exactly one message",
        ));
    }
    match flag {
        0 => Ok(payload.to_vec()),
        1 => match encoding.map(str::to_ascii_lowercase).as_deref() {
            Some("gzip") => crate::inflate::gunzip(payload, MAX_MESSAGE).map_err(|e| match e {
                crate::inflate::Error::TooLarge => Refusal(
                    code::RESOURCE_EXHAUSTED,
                    "the message is too large once decompressed",
                ),
                crate::inflate::Error::Invalid(_) => {
                    Refusal(code::INVALID_ARGUMENT, "the compressed message is damaged")
                }
            }),
            _ => Err(Refusal(
                code::UNIMPLEMENTED,
                "only gzip compression is supported",
            )),
        },
        _ => Err(Refusal(code::INVALID_ARGUMENT, "invalid compression flag")),
    }
}

/// One uncompressed message in its frame.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// A failed call as a "trailers-only" response: HTTP 200 whose headers carry the status.
fn failure(status: u8, message: &str) -> Response {
    let mut resp = Response::new(Body::empty());
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    h.insert("grpc-status", HeaderValue::from(i16::from(status)));
    if let Ok(v) = HeaderValue::from_str(message) {
        h.insert("grpc-message", v);
    }
    resp
}

/// A successful call: one (empty) response message, then `grpc-status: 0` in the trailers.
fn success() -> Response {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from(i16::from(code::OK)));
    // An empty ExportLogsServiceResponse: nothing was refused.
    let body = Full::new(Bytes::from(frame(&[])))
        .with_trailers(async move { Some(Ok::<_, std::convert::Infallible>(trailers)) });
    let mut resp = Response::new(Body::new(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    resp
}

/// Handles `LogsService/Export`.
pub async fn export_logs(
    sink: Sink,
    charge: crate::quota::Charge,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let pushed = sink.clone();
    export(
        &sink.metrics().rejected,
        charge,
        headers,
        body,
        move |message| {
            let entries = crate::otlp::decode_protobuf(&message, now_ms())?;
            let count = entries.len();
            for entry in entries {
                pushed.push(entry);
            }
            Ok(count)
        },
    )
    .await
}

/// Handles `TraceService/Export`: the spans are stored at once (see [`crate::spans`]).
pub async fn export_traces(
    db_path: std::path::PathBuf,
    metrics: std::sync::Arc<Metrics>,
    charge: crate::quota::Charge,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let counters = metrics.clone();
    export(
        &metrics.spans_rejected,
        charge,
        headers,
        body,
        move |message| crate::spans::store_spans(&db_path, &counters, &message, false),
    )
    .await
}

/// One unary export: checks the content type, reads the one message, and hands it to `handle`
/// (on a blocking thread), which returns how many items it took or why it refused the message.
async fn export(
    rejected: &std::sync::atomic::AtomicU64,
    charge: crate::quota::Charge,
    headers: HeaderMap,
    body: Bytes,
    handle: impl FnOnce(Vec<u8>) -> Result<usize, &'static str> + Send + 'static,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // `application/grpc` and `application/grpc+proto` only: the JSON flavour is not gRPC-compatible
    // with OTLP.
    let is_proto = content_type == "application/grpc"
        || content_type.starts_with("application/grpc+proto")
        || content_type.starts_with("application/grpc;");
    if !is_proto {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/grpc",
        )
            .into_response();
    }
    let encoding = headers.get("grpc-encoding").and_then(|v| v.to_str().ok());
    let message = match read_message(&body, encoding) {
        Ok(m) => m,
        Err(Refusal(status, why)) => {
            Metrics::inc(rejected, 1);
            return failure(status, why);
        }
    };
    let result = tokio::task::spawn_blocking(move || handle(message)).await;
    match result {
        Ok(Ok(count)) => {
            charge.add(count);
            success()
        }
        Ok(Err(why)) if why == crate::spans::STORE_FAILED => failure(code::INTERNAL, why),
        Ok(Err(why)) => {
            Metrics::inc(rejected, 1);
            failure(code::INVALID_ARGUMENT, why)
        }
        Err(e) => {
            tracing::error!("otlp grpc task failed: {e}");
            failure(code::INTERNAL, "export failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        assert_eq!(frame(b"abc"), [0, 0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(frame(&[]), [0, 0, 0, 0, 0]);
        assert_eq!(read_message(&frame(b"hello"), None).unwrap(), b"hello");
        assert_eq!(read_message(&frame(&[]), None).unwrap(), b"");
    }

    #[test]
    fn compressed_messages_need_gzip_and_a_sound_stream() {
        let plain = b"some protobuf bytes some protobuf bytes".repeat(20);
        let gz = crate::archive::gzip_member(&plain);
        let mut framed = vec![1];
        framed.extend_from_slice(&(gz.len() as u32).to_be_bytes());
        framed.extend_from_slice(&gz);
        assert_eq!(read_message(&framed, Some("gzip")).unwrap(), plain);
        assert_eq!(read_message(&framed, Some("GZIP")).unwrap(), plain);
        assert_eq!(
            read_message(&framed, None),
            Err(Refusal(
                code::UNIMPLEMENTED,
                "only gzip compression is supported"
            ))
        );
        assert_eq!(
            read_message(&framed, Some("snappy")),
            Err(Refusal(
                code::UNIMPLEMENTED,
                "only gzip compression is supported"
            ))
        );
        let mut damaged = framed.clone();
        let mid = damaged.len() / 2;
        damaged[mid] ^= 0xff;
        assert_eq!(
            read_message(&damaged, Some("gzip")),
            Err(Refusal(
                code::INVALID_ARGUMENT,
                "the compressed message is damaged"
            ))
        );
        let mut flag = framed.clone();
        flag[0] = 2;
        assert_eq!(
            read_message(&flag, Some("gzip")),
            Err(Refusal(code::INVALID_ARGUMENT, "invalid compression flag"))
        );
    }

    #[test]
    fn malformed_frames_are_refused() {
        let invalid = |why| Err(Refusal(code::INVALID_ARGUMENT, why));
        assert_eq!(
            read_message(&[], None),
            invalid("the message frame is incomplete")
        );
        assert_eq!(
            read_message(&[0, 0, 0], None),
            invalid("the message frame is incomplete")
        );
        assert_eq!(
            read_message(&[0, 0, 0, 0, 5, 1, 2], None),
            invalid("the message is shorter than its length")
        );
        let mut two = frame(b"a");
        two.extend_from_slice(&frame(b"b"));
        assert_eq!(
            read_message(&two, None),
            invalid("a unary call carries exactly one message")
        );
        assert_eq!(
            read_message(&[0, 0xff, 0xff, 0xff, 0xff], None),
            Err(Refusal(
                code::RESOURCE_EXHAUSTED,
                "the message is too large"
            ))
        );
    }
}
