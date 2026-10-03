//! The alert webhook: a small HTTP/1.1 client over plain TCP or TLS, with a few message formats
//! for the usual chat and push services.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use rustls::RootCertStore;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::silence::Event;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);
const WEBHOOK_ATTEMPTS: u32 = 3;
/// Alert texts are clipped to this many characters (chat services reject long messages, and a
/// host name comes from whoever sent the logs).
const MAX_TEXT_CHARS: usize = 500;

/// How the alert is written in the request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    /// LogPit's own JSON: `event`, `host`, `silent_for_secs`, `threshold_secs`, `message`.
    #[default]
    Json,
    /// The message as plain text.
    Text,
    /// `{"text": …}`, understood by Slack, Mattermost and Rocket.Chat.
    Slack,
    /// `{"content": …}` for Discord, with mentions disabled.
    Discord,
    /// Plain text with `Title`, `Priority` and `Tags` headers, for ntfy.
    Ntfy,
}

impl WebhookFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            "slack" => Some(Self::Slack),
            "discord" => Some(Self::Discord),
            "ntfy" => Some(Self::Ntfy),
            _ => None,
        }
    }
}

pub struct Rendered {
    pub content_type: &'static str,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

fn clip_chars(s: &str) -> String {
    s.chars().take(MAX_TEXT_CHARS).collect()
}

/// Header values must be printable ASCII; anything else is replaced.
fn ascii_header_value(s: &str) -> String {
    s.chars()
        .take(100)
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect()
}

pub fn render(format: WebhookFormat, event: &Event) -> Rendered {
    let payload = event.payload();
    let message = clip_chars(payload["message"].as_str().unwrap_or_default());
    let json = |value: serde_json::Value| Rendered {
        content_type: "application/json",
        body: value.to_string(),
        headers: Vec::new(),
    };
    match format {
        WebhookFormat::Json => json(payload),
        WebhookFormat::Text => Rendered {
            content_type: "text/plain; charset=utf-8",
            body: message,
            headers: Vec::new(),
        },
        // Slack treats `<…>`, `&` as markup (`<!channel>` pings everyone): escape them.
        WebhookFormat::Slack => json(json!({
            "text": message.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"),
        })),
        WebhookFormat::Discord => json(json!({
            "content": message,
            "allowed_mentions": { "parse": [] },
        })),
        WebhookFormat::Ntfy => {
            let (title, priority, tags) = match event {
                Event::Silent { host, .. } => {
                    (format!("LogPit: {host} is silent"), "high", "warning")
                }
                Event::Recovered { host } => (
                    format!("LogPit: {host} recovered"),
                    "default",
                    "white_check_mark",
                ),
                Event::Pattern { rule, .. } => {
                    (format!("LogPit: {rule}"), "high", "rotating_light")
                }
                Event::NewPattern { host, .. } => {
                    (format!("LogPit: new pattern on {host}"), "high", "new")
                }
                Event::Surge { .. } => (
                    "LogPit: pattern surge".to_string(),
                    "high",
                    "chart_with_upwards_trend",
                ),
            };
            Rendered {
                content_type: "text/plain; charset=utf-8",
                body: message,
                headers: vec![
                    ("Title".into(), ascii_header_value(&title)),
                    ("Priority".into(), priority.into()),
                    ("Tags".into(), tags.into()),
                ],
            }
        }
    }
}

/// Parses `Name: value`, refusing anything that could break the request.
pub fn parse_header(line: &str) -> anyhow::Result<(String, String)> {
    let (name, value) = line
        .split_once(':')
        .with_context(|| "a webhook header must look like \"Name: value\"")?;
    let (name, value) = (name.trim(), value.trim());
    let token = |c: char| c.is_ascii_alphanumeric() || c == '-';
    if name.is_empty() || !name.chars().all(token) {
        bail!("invalid webhook header name {name:?}");
    }
    const OWNED: [&str; 6] = [
        "host",
        "content-length",
        "content-type",
        "connection",
        "transfer-encoding",
        "expect",
    ];
    if OWNED.contains(&name.to_ascii_lowercase().as_str()) {
        bail!("the webhook header {name:?} is set by LogPit and cannot be overridden");
    }
    if value.is_empty() || !value.chars().all(|c| (' '..='~').contains(&c)) {
        bail!("the value of webhook header {name:?} must be printable ASCII and not empty");
    }
    Ok((name.to_string(), value.to_string()))
}

fn default_connector() -> TlsConnector {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    connector_with(roots)
}

fn connector_with(roots: RootCertStore) -> TlsConnector {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the default TLS versions are supported")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Where and how alerts are sent: an `http://` or `https://` URL, a body format and optional
/// extra headers (an `Authorization` token, for instance).
#[derive(Clone)]
pub struct Webhook {
    authority: String,
    connect_addr: String,
    /// Name checked against the server certificate; `None` for plain HTTP.
    tls_name: Option<String>,
    path: String,
    format: WebhookFormat,
    headers: Vec<(String, String)>,
    connector: TlsConnector,
    timeout: Duration,
}

impl Webhook {
    /// LogPit's JSON to `url`, without extra headers.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        Self::new(url, WebhookFormat::Json, &[])
    }

    pub fn new(url: &str, format: WebhookFormat, headers: &[String]) -> anyhow::Result<Self> {
        let (https, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
            (Some(rest), _) => (true, rest),
            (_, Some(rest)) => (false, rest),
            _ => bail!("silence.webhook_url must start with http:// or https://"),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty()
            || authority.contains('@')
            || authority.contains(char::is_whitespace)
            || path.contains(['\r', '\n', ' '])
        {
            bail!("invalid silence.webhook_url");
        }
        // `host`, `host:port`, `[::1]` or `[::1]:port`.
        let (host, has_port) = match authority.strip_prefix('[') {
            Some(inner) => {
                let end = inner.find(']').context("invalid silence.webhook_url")?;
                (&inner[..end], inner[end + 1..].starts_with(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((h, _)) => (h, true),
                None => (authority, false),
            },
        };
        let default_port = if https { 443 } else { 80 };
        let connect_addr = if has_port {
            authority.to_owned()
        } else {
            format!("{authority}:{default_port}")
        };
        Ok(Self {
            authority: authority.to_owned(),
            connect_addr,
            tls_name: https.then(|| host.to_owned()),
            path: path.to_owned(),
            format,
            headers: headers
                .iter()
                .map(|h| parse_header(h))
                .collect::<Result<_, _>>()?,
            timeout: WEBHOOK_TIMEOUT,
            connector: if https {
                default_connector()
            } else {
                connector_with(RootCertStore::empty())
            },
        })
    }

    /// Trusts these certificate authorities instead of the built-in list (for tests).
    pub fn with_roots(mut self, roots: RootCertStore) -> Self {
        self.connector = connector_with(roots);
        self
    }

    fn request(&self, rendered: &Rendered) -> String {
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             Connection: close\r\nUser-Agent: logpit\r\n",
            self.path,
            self.authority,
            rendered.content_type,
            rendered.body.len()
        );
        for (name, value) in rendered.headers.iter().chain(&self.headers) {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(&rendered.body);
        req
    }

    /// Writes the request and returns the status code of the response.
    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        request: &str,
    ) -> anyhow::Result<u16> {
        timeout(self.timeout, stream.write_all(request.as_bytes())).await??;
        timeout(self.timeout, stream.flush()).await??;
        let mut buf = [0u8; 256];
        let n = timeout(self.timeout, stream.read(&mut buf)).await??;
        let head = String::from_utf8_lossy(&buf[..n]);
        head.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .with_context(|| {
                format!(
                    "unexpected response {:?}",
                    head.lines().next().unwrap_or("")
                )
            })
    }

    /// Connects (and negotiates TLS for `https`), sends `request` and returns the status code.
    async fn send_request(&self, request: &str) -> anyhow::Result<u16> {
        let tcp = timeout(self.timeout, TcpStream::connect(&self.connect_addr)).await??;
        match &self.tls_name {
            None => self.exchange(&mut { tcp }, request).await,
            Some(name) => {
                let server_name = ServerName::try_from(name.clone())
                    .with_context(|| format!("{name:?} is not a valid server name"))?;
                let mut tls =
                    timeout(self.timeout, self.connector.connect(server_name, tcp)).await??;
                self.exchange(&mut tls, request).await
            }
        }
    }

    pub async fn post_once(&self, event: &Event) -> anyhow::Result<()> {
        let status = self
            .send_request(&self.request(&render(self.format, event)))
            .await?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            bail!("webhook answered HTTP {status}")
        }
    }

    /// Posts `body` to the URL and returns the HTTP status, whatever it is, for callers that
    /// decide for themselves what to retry. Errors are connection, TLS and timeout failures.
    pub async fn post_body(&self, content_type: &'static str, body: String) -> anyhow::Result<u16> {
        let rendered = Rendered {
            content_type,
            body,
            headers: Vec::new(),
        };
        self.send_request(&self.request(&rendered)).await
    }

    /// Time allowed for each step (connect, TLS handshake, write, response); the default suits
    /// small notifications, bulk senders want longer.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sends the alert, retrying a couple of times; failures are logged, never fatal. The URL and
    /// headers can hold secrets, so they are never written to the log.
    pub async fn send(&self, event: &Event) {
        for attempt in 1..=WEBHOOK_ATTEMPTS {
            match self.post_once(event).await {
                Ok(()) => return,
                Err(e) => tracing::warn!("alert webhook attempt {attempt} failed: {e:#}"),
            }
            if attempt < WEBHOOK_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        tracing::error!("alert webhook gave up after {WEBHOOK_ATTEMPTS} attempts");
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use tokio::net::TcpListener;

    use super::*;
    use crate::tls::{build_acceptor, testpki::pki};

    fn silent(host: &str) -> Event {
        Event::Silent {
            host: host.into(),
            silent_for_ms: 125_000,
            threshold_ms: 120_000,
        }
    }

    fn recovered(host: &str) -> Event {
        Event::Recovered { host: host.into() }
    }

    #[test]
    fn new_pattern_and_surge_events_render_in_every_format() {
        let new = Event::NewPattern {
            pattern: "disk <*> failed".into(),
            host: "web1".into(),
            severity: "err".into(),
            sample: "disk 7 failed".into(),
        };
        let surge = Event::Surge {
            pattern: "retry <*>".into(),
            count: 400,
            usual: 12,
            window_secs: 60,
            sample: "retry 3".into(),
        };
        let payload = new.payload();
        assert_eq!(payload["event"], "new_pattern");
        assert_eq!(payload["pattern"], "disk <*> failed");
        let msg = payload["message"].as_str().unwrap();
        assert!(
            msg.contains("web1")
                && msg.contains("disk <*> failed")
                && msg.contains("disk 7 failed")
        );
        let payload = surge.payload();
        assert_eq!(payload["event"], "pattern_surge");
        assert_eq!(
            (payload["count"].as_u64(), payload["usual"].as_u64()),
            (Some(400), Some(12))
        );
        assert!(
            payload["message"]
                .as_str()
                .unwrap()
                .contains("400 times within 60s")
        );
        // Slack escapes the `<*>` of a template instead of sending markup.
        let slack = render(WebhookFormat::Slack, &new);
        assert!(
            slack.body.contains("disk &lt;*&gt; failed"),
            "{}",
            slack.body
        );
        let ntfy = render(WebhookFormat::Ntfy, &new);
        assert!(
            ntfy.headers
                .iter()
                .any(|(k, v)| k == "Title" && v.contains("web1"))
        );
        for format in [
            WebhookFormat::Json,
            WebhookFormat::Text,
            WebhookFormat::Discord,
            WebhookFormat::Ntfy,
        ] {
            assert!(!render(format, &surge).body.is_empty());
        }
    }

    #[test]
    fn url_parsing() {
        let w = Webhook::parse("http://ntfy.lan:8081/alerts").unwrap();
        assert_eq!(
            (
                w.connect_addr.as_str(),
                w.path.as_str(),
                w.tls_name.as_deref()
            ),
            ("ntfy.lan:8081", "/alerts", None)
        );
        let w = Webhook::parse("http://relay").unwrap();
        assert_eq!(
            (w.connect_addr.as_str(), w.path.as_str()),
            ("relay:80", "/")
        );
        let w = Webhook::parse("https://discord.com/api/webhooks/1/abc?wait=true").unwrap();
        assert_eq!(
            (
                w.connect_addr.as_str(),
                w.path.as_str(),
                w.tls_name.as_deref()
            ),
            (
                "discord.com:443",
                "/api/webhooks/1/abc?wait=true",
                Some("discord.com")
            )
        );
        let w = Webhook::parse("https://hooks.example.com:8443/x").unwrap();
        assert_eq!(
            (w.connect_addr.as_str(), w.tls_name.as_deref()),
            ("hooks.example.com:8443", Some("hooks.example.com"))
        );
        // IPv6 literals, with and without a port.
        let w = Webhook::parse("https://[::1]:9443/x").unwrap();
        assert_eq!(
            (w.connect_addr.as_str(), w.tls_name.as_deref()),
            ("[::1]:9443", Some("::1"))
        );
        let w = Webhook::parse("https://[2001:db8::1]/x").unwrap();
        assert_eq!(
            (w.connect_addr.as_str(), w.tls_name.as_deref()),
            ("[2001:db8::1]:443", Some("2001:db8::1"))
        );
        for bad in [
            "ftp://x/",
            "hooks.example.com/x",
            "http:///x",
            "https://user:pw@host/",
            "https://host/a b",
            "https://[::1/x",
            "",
        ] {
            assert!(Webhook::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn header_validation() {
        assert_eq!(
            parse_header("Authorization: Bearer tk_123").unwrap(),
            ("Authorization".into(), "Bearer tk_123".into())
        );
        assert_eq!(
            parse_header("  X-Api-Key :  abc  ").unwrap(),
            ("X-Api-Key".into(), "abc".into())
        );
        for bad in [
            "no colon",
            ": value",
            "X-A:",
            "Bad Name: v",
            "X-A: line\r\nInjected: 1",
            "X-A: tab\there",
            "X-A: accentué",
            "Host: other",
            "content-length: 0",
            "Content-Type: text/html",
            "Connection: keep-alive",
            "Transfer-Encoding: chunked",
        ] {
            assert!(parse_header(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn formats_render_each_service_body() {
        let ev = silent("pve");
        let json = render(WebhookFormat::Json, &ev);
        assert_eq!(json.content_type, "application/json");
        let v: serde_json::Value = serde_json::from_str(&json.body).unwrap();
        assert_eq!(
            (
                v["event"].as_str(),
                v["host"].as_str(),
                v["silent_for_secs"].as_i64()
            ),
            (Some("host_silent"), Some("pve"), Some(125))
        );

        let text = render(WebhookFormat::Text, &ev);
        assert_eq!(text.body, "No logs from pve for 2m (threshold 2m)");
        assert!(text.content_type.starts_with("text/plain"));

        let slack: serde_json::Value =
            serde_json::from_str(&render(WebhookFormat::Slack, &ev).body).unwrap();
        assert_eq!(slack["text"], "No logs from pve for 2m (threshold 2m)");
        let discord: serde_json::Value =
            serde_json::from_str(&render(WebhookFormat::Discord, &ev).body).unwrap();
        assert_eq!(discord["content"], "No logs from pve for 2m (threshold 2m)");
        assert_eq!(discord["allowed_mentions"]["parse"], json!([]), "no pings");

        let ntfy = render(WebhookFormat::Ntfy, &ev);
        assert_eq!(ntfy.body, "No logs from pve for 2m (threshold 2m)");
        let h = |name: &str| {
            ntfy.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            (h("Title"), h("Priority"), h("Tags")),
            (Some("LogPit: pve is silent"), Some("high"), Some("warning"))
        );
        let ok = render(WebhookFormat::Ntfy, &recovered("pve"));
        assert!(
            ok.headers
                .iter()
                .any(|(k, v)| k == "Tags" && v == "white_check_mark")
        );
        assert_eq!(WebhookFormat::parse("slack"), Some(WebhookFormat::Slack));
        assert_eq!(WebhookFormat::parse("xml"), None);
    }

    #[test]
    fn host_names_from_senders_cannot_ping_or_break_headers() {
        // A host name is chosen by whoever sent the logs.
        let evil = "<!channel> & <@U123> @everyone\r\nX-Injected: 1";
        let slack: serde_json::Value =
            serde_json::from_str(&render(WebhookFormat::Slack, &silent(evil)).body).unwrap();
        let text = slack["text"].as_str().unwrap();
        assert!(!text.contains('<') && !text.contains('>'), "{text}");
        assert!(text.contains("&lt;!channel&gt;") && text.contains("&amp;"));

        let ntfy = render(WebhookFormat::Ntfy, &silent(evil));
        let title = &ntfy.headers[0].1;
        assert!(title.chars().all(|c| (' '..='~').contains(&c)), "{title:?}");
        assert!(!title.contains('\r') && !title.contains('\n'));

        // Long names are clipped.
        let long = "h".repeat(10_000);
        assert!(
            render(WebhookFormat::Text, &silent(&long))
                .body
                .chars()
                .count()
                <= MAX_TEXT_CHARS
        );
        assert!(
            render(WebhookFormat::Ntfy, &silent(&long)).headers[0]
                .1
                .len()
                <= 100
        );
    }

    #[test]
    fn request_carries_format_headers_and_custom_headers() {
        let w = Webhook::new(
            "https://ntfy.example.com/alerts",
            WebhookFormat::Ntfy,
            &["Authorization: Bearer tk_123".to_string()],
        )
        .unwrap();
        let req = w.request(&render(WebhookFormat::Ntfy, &silent("pve")));
        assert!(
            req.starts_with("POST /alerts HTTP/1.1\r\nHost: ntfy.example.com\r\n"),
            "{req}"
        );
        for expected in [
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Title: LogPit: pve is silent\r\n",
            "Priority: high\r\n",
            "Authorization: Bearer tk_123\r\n",
            "Connection: close\r\n",
        ] {
            assert!(req.contains(expected), "missing {expected:?} in {req}");
        }
        assert!(req.ends_with("\r\n\r\nNo logs from pve for 2m (threshold 2m)"));
        let len = "No logs from pve for 2m (threshold 2m)".len();
        assert!(req.contains(&format!("Content-Length: {len}\r\n")));
    }

    /// A one-shot HTTP server on a free port that answers each connection with the next status.
    async fn http_server(
        statuses: Vec<&'static str>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for status in statuses {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                requests.push(String::from_utf8_lossy(&buf[..n]).to_string());
                s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            requests
        });
        (addr, task)
    }

    #[tokio::test]
    async fn plain_http_posts_and_retries_on_failure() {
        // The first attempt gets a 500, the retry a 200.
        let (addr, server) = http_server(vec!["500 Internal Server Error", "200 OK"]).await;
        let hook = Webhook::new(&format!("http://{addr}/hook"), WebhookFormat::Slack, &[]).unwrap();
        hook.send(&recovered("pve")).await;
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /hook HTTP/1.1\r\n"));
        assert!(requests[1].contains("Content-Type: application/json"));
        assert!(requests[1].contains(r#""text":"pve is sending logs again""#));
    }

    #[tokio::test]
    async fn https_delivers_when_the_certificate_is_trusted_and_fails_otherwise() {
        let pki = pki("webhook");
        let acceptor = build_acceptor(&pki.server_cert, &pki.server_key, None).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            // Two connections: one from the client that trusts the CA, one that does not.
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = tls.read(&mut buf).await {
                    requests.push(String::from_utf8_lossy(&buf[..n]).to_string());
                    let _ = tls
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = tls.shutdown().await;
                }
            }
            requests
        });
        let url = format!("https://localhost:{port}/api/webhooks/1/secret-token");
        let headers = ["X-Api-Key: k123".to_string()];

        // Trusting the test CA: the alert arrives, with the right name checked.
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let trusted = Webhook::new(&url, WebhookFormat::Discord, &headers)
            .unwrap()
            .with_roots(roots);
        trusted.post_once(&silent("pve")).await.unwrap();

        // The built-in public roots do not know the test CA: delivery must fail, not be skipped.
        let untrusting = Webhook::new(&url, WebhookFormat::Discord, &headers).unwrap();
        assert!(untrusting.post_once(&silent("pve")).await.is_err());

        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 1, "only the trusted client got through");
        let req = &requests[0];
        assert!(req.starts_with("POST /api/webhooks/1/secret-token HTTP/1.1\r\n"));
        assert!(req.contains("X-Api-Key: k123\r\n"));
        assert!(req.contains(r#""content":"No logs from pve for 2m (threshold 2m)""#));
        std::fs::remove_dir_all(&pki.dir).ok();
    }

    #[tokio::test]
    async fn https_refuses_a_certificate_issued_for_another_name() {
        let pki = pki("webhook-name");
        let acceptor = build_acceptor(&pki.server_cert, &pki.server_key, None).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp).await;
        });
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        // The certificate is for `localhost` and 127.0.0.1; asking for another name must fail.
        let hook = Webhook::parse(&format!("https://127.0.0.2:{port}/x"))
            .unwrap()
            .with_roots(roots);
        let mut other = hook.clone();
        other.connect_addr = format!("127.0.0.1:{port}");
        other.tls_name = Some("not-localhost.example".into());
        assert!(other.post_once(&recovered("pve")).await.is_err());
        std::fs::remove_dir_all(&pki.dir).ok();
    }

    /// Handshake only (no request is sent): the built-in roots must validate a real public chain.
    /// Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "needs network access"]
    async fn built_in_roots_validate_a_public_server() {
        let connector = default_connector();
        let tcp = TcpStream::connect(("github.com", 443)).await.unwrap();
        let name = ServerName::try_from("github.com").unwrap();
        connector
            .connect(name, tcp)
            .await
            .expect("the public chain should validate");
        // The same chain must not validate for a different name.
        let tcp = TcpStream::connect(("github.com", 443)).await.unwrap();
        let wrong = ServerName::try_from("example.org").unwrap();
        assert!(connector.connect(wrong, tcp).await.is_err());
    }
}
