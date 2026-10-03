//! A small HTTP/1.1 GET client for the command line tools: status, headers, and a body that is
//! read whole or as a stream (chunked server-sent events included), over plain TCP or TLS.

use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::webhook::{Conn, Webhook};

const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest body [`Response::read_all`] collects unless told otherwise.
pub const DEFAULT_MAX_BODY: usize = 256 * 1024 * 1024;

enum Body {
    Fixed(u64),
    Chunked(u64),
    ChunkedDone,
    UntilClose,
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    reader: BufReader<Conn>,
    body: Body,
    /// How long one read may take; `None` waits for as long as the server does (live streams).
    idle: Option<Duration>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    async fn line(&mut self) -> anyhow::Result<String> {
        let mut text = String::new();
        let idle = self.idle;
        let read = self.reader.read_line(&mut text);
        let n = match idle {
            Some(d) => timeout(d, read)
                .await
                .context("the server stopped answering")??,
            None => read.await?,
        };
        if n == 0 {
            bail!("the connection closed in the middle of the response");
        }
        Ok(text.trim_end_matches(['\r', '\n']).to_string())
    }

    /// The next piece of the body, or `None` at its end.
    pub async fn next_chunk(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match self.body {
                Body::Fixed(0) | Body::ChunkedDone => return Ok(None),
                Body::Fixed(left) => {
                    let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
                    let n = self.read_some(&mut buf[..want]).await?;
                    if n == 0 {
                        bail!("the connection closed before the whole body arrived");
                    }
                    self.body = Body::Fixed(left - n as u64);
                    buf.truncate(n);
                    return Ok(Some(buf));
                }
                Body::UntilClose => {
                    let n = self.read_some(&mut buf).await?;
                    if n == 0 {
                        self.body = Body::Fixed(0);
                        return Ok(None);
                    }
                    buf.truncate(n);
                    return Ok(Some(buf));
                }
                Body::Chunked(0) => {
                    let size_line = self.line().await?;
                    let hex = size_line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(hex, 16)
                        .with_context(|| format!("invalid chunk size {hex:?}"))?;
                    if size == 0 {
                        // Trailers, up to the empty line.
                        while !self.line().await?.is_empty() {}
                        self.body = Body::ChunkedDone;
                        return Ok(None);
                    }
                    self.body = Body::Chunked(size);
                }
                Body::Chunked(left) => {
                    let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
                    let n = self.read_some(&mut buf[..want]).await?;
                    if n == 0 {
                        bail!("the connection closed in the middle of a chunk");
                    }
                    let left = left - n as u64;
                    if left == 0 {
                        // The CRLF that ends the chunk.
                        self.line().await?;
                    }
                    self.body = Body::Chunked(left);
                    buf.truncate(n);
                    return Ok(Some(buf));
                }
            }
        }
    }

    async fn read_some(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let idle = self.idle;
        let read = self.reader.read(buf);
        Ok(match idle {
            Some(d) => timeout(d, read)
                .await
                .context("the server stopped answering")??,
            None => read.await?,
        })
    }

    /// The whole body, refusing more than `max` bytes.
    pub async fn read_all(&mut self, max: usize) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            if out.len() + chunk.len() > max {
                bail!("the response is larger than {max} bytes");
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// Sends `GET <base path><path_and_query>` to the server of `hook` and returns once the headers
/// are in. `idle` bounds each read (`None` for a live stream).
pub async fn get(
    hook: &Webhook,
    path_and_query: &str,
    accept: &str,
    idle: Option<Duration>,
) -> anyhow::Result<Response> {
    let base = hook.path().trim_end_matches('/');
    let mut conn = hook.connect().await?;
    let mut request = format!(
        "GET {base}{path_and_query} HTTP/1.1\r\nHost: {}\r\nAccept: {accept}\r\nUser-Agent: logpit\r\nConnection: close\r\n",
        hook.authority()
    );
    for (name, value) in hook.extra_headers() {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    timeout(hook.io_timeout(), conn.write_all(request.as_bytes()))
        .await
        .context("the server did not accept the request")??;
    let mut reader = BufReader::new(conn);
    let mut head = Vec::new();
    loop {
        let mut line = String::new();
        let n = timeout(
            hook.io_timeout().max(Duration::from_secs(30)),
            reader.read_line(&mut line),
        )
        .await
        .context("the server did not answer")??;
        if n == 0 {
            bail!("the server closed the connection without answering");
        }
        head.push(line.trim_end_matches(['\r', '\n']).to_string());
        if head.last().is_some_and(|l| l.is_empty()) {
            break;
        }
        if head.iter().map(String::len).sum::<usize>() > MAX_HEAD_BYTES {
            bail!("the response headers are too large");
        }
    }
    let status = head
        .first()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .with_context(|| {
            format!(
                "unexpected response {:?}",
                head.first().map_or("", String::as_str)
            )
        })?;
    let headers: Vec<(String, String)> = head[1..]
        .iter()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let find = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let body =
        if find("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            Body::Chunked(0)
        } else if let Some(len) = find("content-length").and_then(|v| v.parse::<u64>().ok()) {
            Body::Fixed(len)
        } else {
            Body::UntilClose
        };
    Ok(Response {
        status,
        headers,
        reader,
        body,
        idle,
    })
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// A server that answers one request with `reply` (written in `pieces`, with pauses).
    async fn server(reply: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/base", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
            for piece in reply {
                s.write_all(&piece).await.unwrap();
                s.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            String::from_utf8_lossy(&seen).to_string()
        });
        (url, handle)
    }

    fn hook(url: &str) -> Webhook {
        Webhook::new(
            url,
            crate::webhook::WebhookFormat::Json,
            &["Authorization: Bearer t".to_string()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_sized_body_and_the_request_that_was_sent() {
        let (url, req) = server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Next-Cursor: 5:9\r\n\r\nhello ".to_vec(),
            b"world".to_vec(),
        ])
        .await;
        let mut r = get(
            &hook(&url),
            "/api/logs?q=a%20b",
            "application/json",
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("x-next-cursor"), Some("5:9"));
        assert_eq!(r.read_all(100).await.unwrap(), b"hello world");
        let sent = req.await.unwrap();
        assert!(
            sent.starts_with("GET /base/api/logs?q=a%20b HTTP/1.1\r\n"),
            "{sent}"
        );
        assert!(
            sent.contains("Authorization: Bearer t\r\n")
                && sent.contains("Accept: application/json\r\n")
        );
        assert!(sent.contains("Host: 127.0.0.1:"));
    }

    #[tokio::test]
    async fn chunked_bodies_arrive_piece_by_piece_with_trailers() {
        let (url, _) = server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ndata:".to_vec(),
            b"\r\n2\r\n a\r\n".to_vec(),
            b"A;ext=1\r\n 123456789\r\n".to_vec(),
            b"0\r\nTrailer: x\r\n\r\n".to_vec(),
        ])
        .await;
        let mut r = get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
            .await
            .unwrap();
        let mut pieces = Vec::new();
        while let Some(c) = r.next_chunk().await.unwrap() {
            pieces.push(String::from_utf8(c).unwrap());
        }
        assert_eq!(pieces.concat(), "data: a 123456789");
        assert!(pieces.len() >= 2, "streamed: {pieces:?}");
        assert!(r.next_chunk().await.unwrap().is_none(), "stays at the end");
    }

    #[tokio::test]
    async fn bodies_without_a_length_run_to_the_end_and_limits_hold() {
        let (url, _) = server(vec![b"HTTP/1.1 404 Not Found\r\n\r\nnot here".to_vec()]).await;
        let mut r = get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.read_all(100).await.unwrap(), b"not here");
        let (url, _) = server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n".to_vec(),
            vec![b'x'; 50],
        ])
        .await;
        let mut r = get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(
            r.read_all(10)
                .await
                .unwrap_err()
                .to_string()
                .contains("larger than 10")
        );
    }

    #[tokio::test]
    async fn truncated_and_garbled_responses_are_errors() {
        let (url, _) = server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort".to_vec(),
        ])
        .await;
        let mut r = get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(r.read_all(100).await.is_err());
        let (url, _) = server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec(),
        ])
        .await;
        let mut r = get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(r.read_all(100).await.is_err());
        let (url, _) = server(vec![b"garbage\r\n\r\n".to_vec()]).await;
        assert!(
            get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
                .await
                .is_err()
        );
        let (url, _) = server(vec![]).await;
        assert!(
            get(&hook(&url), "/x", "*/*", Some(Duration::from_secs(5)))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_silent_server_times_out_unless_streaming() {
        let (url, _) = server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            b"1\r\nx\r\n".to_vec(),
        ])
        .await;
        let mut r = get(&hook(&url), "/x", "*/*", Some(Duration::from_millis(300)))
            .await
            .unwrap();
        assert_eq!(r.next_chunk().await.unwrap().unwrap(), b"x");
        // Nothing more is coming and the server keeps the connection open: the read gives up.
        // (The test server dropped its side, so this ends as a closed connection instead.)
        assert!(r.next_chunk().await.is_err());
    }
}
