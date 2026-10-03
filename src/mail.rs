//! E-mail notifications: the alerts LogPit raises, sent over SMTP (STARTTLS, implicit TLS or
//! plain, with optional authentication) to a list of recipients, beside the webhook.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::silence::Event;
use crate::webhook::Conn;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPTS: u32 = 3;
#[cfg(not(test))]
const RETRY_DELAY: Duration = Duration::from_secs(5);
#[cfg(test)]
const RETRY_DELAY: Duration = Duration::from_millis(20);
const MAX_RECIPIENTS: usize = 20;
const MAX_SUBJECT_CHARS: usize = 120;
const DEFAULT_MAX_PER_HOUR: u32 = 30;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// Plain connection upgraded with STARTTLS (usually port 587).
    #[default]
    Starttls,
    /// TLS from the first byte (usually port 465).
    Tls,
    /// No encryption (port 25 relays on a trusted network).
    None,
}

impl Security {
    fn default_port(self) -> u16 {
        match self {
            Self::Starttls => 587,
            Self::Tls => 465,
            Self::None => 25,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EmailConfig {
    /// SMTP server; empty turns e-mail notifications off.
    pub host: String,
    /// Port; `0` means the usual one for `security` (587, 465 or 25).
    pub port: u16,
    pub security: Security,
    /// Sender address.
    pub from: String,
    /// Recipient addresses.
    pub to: Vec<String>,
    /// Login, with `password`; needs `starttls` or `tls` (or a server on this machine).
    pub username: Option<String>,
    pub password: Option<String>,
    /// Put in front of every subject.
    pub subject_prefix: String,
    /// Name given in EHLO.
    pub helo: String,
    /// Most messages sent per hour; the rest are dropped and counted (`0` = no limit).
    pub max_per_hour: u32,
    /// Only these kinds of notification (`host_silent`, `volume_surge`…); empty means all.
    pub kinds: Vec<String>,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            security: Security::Starttls,
            from: String::new(),
            to: Vec::new(),
            username: None,
            password: None,
            subject_prefix: "[LogPit]".into(),
            helo: "localhost".into(),
            max_per_hour: DEFAULT_MAX_PER_HOUR,
            kinds: Vec::new(),
        }
    }
}

/// A plain `local@domain` address, without anything that could break a header or a command.
pub fn valid_address(a: &str) -> bool {
    let Some((local, domain)) = a.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-=".contains(c));
    let domain_ok = !domain.is_empty()
        && domain.len() <= 255
        && !domain.starts_with(['.', '-'])
        && domain.contains('.') | (domain == "localhost")
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    local_ok && domain_ok
}

fn is_local(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.starts_with("127.")
}

impl EmailConfig {
    pub fn enabled(&self) -> bool {
        !self.host.is_empty()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        if self.host.contains(char::is_whitespace) || self.host.contains(['/', '@', '<', '>']) {
            bail!("email.host must be a host name or address");
        }
        if !valid_address(&self.from) {
            bail!("email.from must be an address like logpit@example.com");
        }
        if self.to.is_empty() || self.to.len() > MAX_RECIPIENTS {
            bail!("email.to takes between 1 and {MAX_RECIPIENTS} addresses");
        }
        if let Some(bad) = self.to.iter().find(|a| !valid_address(a)) {
            bail!("email.to: {bad:?} is not an address like ops@example.com");
        }
        if self.username.is_some() != self.password.is_some() {
            bail!("email.username and email.password go together");
        }
        if self
            .username
            .as_ref()
            .is_some_and(|u| u.is_empty() || u.contains(['\r', '\n', '\0']))
        {
            bail!("email.username is not valid");
        }
        if self.security == Security::None && self.username.is_some() && !is_local(&self.host) {
            bail!(
                "email.security = \"none\" would send the password in clear text: use starttls or tls"
            );
        }
        if self.subject_prefix.chars().any(char::is_control) {
            bail!("email.subject_prefix must not contain control characters");
        }
        if self.helo.is_empty()
            || !self
                .helo
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
        {
            bail!("email.helo must be a host name");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        if self.port == 0 {
            self.security.default_port()
        } else {
            self.port
        }
    }
}

// ---- message ------------------------------------------------------------------------------

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(T[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The subject as a header value: plain ASCII as is, otherwise RFC 2047 encoded words.
fn encode_subject(subject: &str) -> String {
    if subject.is_ascii() {
        return subject.to_string();
    }
    let mut words = Vec::new();
    let mut piece = String::new();
    for c in subject.chars() {
        // A word's encoded form must stay under 75 characters: 36 bytes of text is 48 of base64.
        if piece.len() + c.len_utf8() > 36 {
            words.push(std::mem::take(&mut piece));
        }
        piece.push(c);
    }
    words.push(piece);
    words
        .iter()
        .map(|w| format!("=?UTF-8?B?{}?=", base64(w.as_bytes())))
        .collect::<Vec<_>>()
        .join("\r\n ")
}

/// Printable text on one line, clipped: what goes into a header.
fn header_text(text: &str, max: usize) -> String {
    let one: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let one = one.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = one.chars().take(max).collect();
    if one.chars().count() > max {
        out.push('…');
    }
    out
}

pub struct Message {
    pub subject: String,
    pub body: String,
}

/// The subject and body of a notification.
pub fn compose(event: &Event, prefix: &str) -> Message {
    let payload = event.payload();
    let text = payload["message"].as_str().unwrap_or_default();
    let kind = payload["event"].as_str().unwrap_or("alert");
    let subject = header_text(&format!("{prefix} {text}"), MAX_SUBJECT_CHARS);
    let mut body = format!("{text}\n\nevent: {kind}\n");
    if let Some(host) = payload["host"].as_str() {
        body.push_str(&format!("host: {}\n", header_text(host, 255)));
    }
    body.push_str(&format!(
        "\n{}\n",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    ));
    Message {
        subject: subject.trim().to_string(),
        body,
    }
}

/// The complete message as sent after `DATA`: headers, a base64 body, no line starting with a dot.
pub fn render(cfg: &EmailConfig, m: &Message, now_ms: i64, id: u64) -> String {
    let date = chrono::DateTime::from_timestamp_millis(now_ms)
        .unwrap_or_default()
        .to_rfc2822();
    let domain = cfg.from.split_once('@').map_or("localhost", |(_, d)| d);
    let mut out = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {date}\r\nMessage-ID: <{now_ms}.{id}@{domain}>\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\nAuto-Submitted: auto-generated\r\n\r\n",
        cfg.from,
        cfg.to.join(", "),
        encode_subject(&m.subject),
    );
    let b64 = base64(m.body.as_bytes());
    for line in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

// ---- SMTP ---------------------------------------------------------------------------------

struct Session {
    reader: BufReader<Conn>,
}

impl Session {
    async fn reply(&mut self) -> anyhow::Result<(u16, Vec<String>)> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = timeout(COMMAND_TIMEOUT, self.reader.read_line(&mut line))
                .await
                .context("the SMTP server stopped answering")??;
            if n == 0 {
                bail!("the SMTP server closed the connection");
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let code: u16 = line
                .get(..3)
                .and_then(|c| c.parse().ok())
                .context("garbled SMTP reply")?;
            let last = line.as_bytes().get(3) != Some(&b'-');
            lines.push(line.get(4..).unwrap_or("").to_string());
            if last {
                return Ok((code, lines));
            }
            if lines.len() > 100 {
                bail!("the SMTP reply is too long");
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let w = self.reader.get_mut();
        timeout(COMMAND_TIMEOUT, w.write_all(data))
            .await
            .context("SMTP write timed out")??;
        timeout(COMMAND_TIMEOUT, w.flush())
            .await
            .context("SMTP write timed out")??;
        Ok(())
    }

    async fn expect(&mut self, command: &str, ok: &[u16]) -> anyhow::Result<Vec<String>> {
        self.send(format!("{command}\r\n").as_bytes()).await?;
        self.expect_reply(command, ok).await
    }

    async fn expect_reply(&mut self, what: &str, ok: &[u16]) -> anyhow::Result<Vec<String>> {
        let (code, text) = self.reply().await?;
        if ok.contains(&code) {
            Ok(text)
        } else {
            // Never echo a command that carried the password.
            let what = what.split_whitespace().next().unwrap_or("command");
            bail!(
                "SMTP {what}: {code} {}",
                text.first().map_or("", String::as_str)
            )
        }
    }
}

/// Sends e-mail notifications, at most `max_per_hour` an hour.
pub struct Mailer {
    cfg: EmailConfig,
    connector: TlsConnector,
    sent_at: Mutex<VecDeque<i64>>,
    pub sent: std::sync::atomic::AtomicU64,
    pub failed: std::sync::atomic::AtomicU64,
    pub suppressed: std::sync::atomic::AtomicU64,
}

impl Mailer {
    pub fn new(cfg: &EmailConfig) -> anyhow::Result<Option<Arc<Self>>> {
        cfg.validate()?;
        if !cfg.enabled() {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self {
            cfg: cfg.clone(),
            connector: crate::webhook::default_connector(),
            sent_at: Mutex::default(),
            sent: Default::default(),
            failed: Default::default(),
            suppressed: Default::default(),
        })))
    }

    /// Trusts these authorities instead of the built-in list (for tests).
    pub fn with_roots(mut self: Arc<Self>, roots: rustls::RootCertStore) -> Arc<Self> {
        if let Some(m) = Arc::get_mut(&mut self) {
            m.connector = crate::webhook::connector_with(roots);
        }
        self
    }

    /// Whether this kind of notification goes out by e-mail.
    pub fn wants(&self, kind: &str) -> bool {
        self.cfg.kinds.is_empty() || self.cfg.kinds.iter().any(|k| k == kind)
    }

    /// Takes one of the hourly slots, false when they are all used.
    fn allow(&self, now_ms: i64) -> bool {
        if self.cfg.max_per_hour == 0 {
            return true;
        }
        let mut sent = self.sent_at.lock().unwrap_or_else(|e| e.into_inner());
        while sent.front().is_some_and(|t| now_ms - t >= 3_600_000) {
            sent.pop_front();
        }
        if sent.len() >= self.cfg.max_per_hour as usize {
            return false;
        }
        sent.push_back(now_ms);
        true
    }

    async fn connect(&self) -> anyhow::Result<Session> {
        let addr = (self.cfg.host.as_str(), self.cfg.port());
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("connecting to the SMTP server timed out")??;
        let server_name = ServerName::try_from(self.cfg.host.clone())
            .with_context(|| format!("{:?} is not a valid server name", self.cfg.host))?;
        let conn = if self.cfg.security == Security::Tls {
            let tls = timeout(
                CONNECT_TIMEOUT,
                self.connector.connect(server_name.clone(), tcp),
            )
            .await
            .context("the TLS handshake with the SMTP server timed out")??;
            Conn::Tls(Box::new(tls))
        } else {
            Conn::Plain(tcp)
        };
        let mut s = Session {
            reader: BufReader::new(conn),
        };
        s.expect_reply("greeting", &[220]).await?;
        let caps = s.expect(&format!("EHLO {}", self.cfg.helo), &[250]).await?;
        let has = |cap: &str| caps.iter().any(|l| l.to_ascii_uppercase().starts_with(cap));
        if self.cfg.security == Security::Starttls {
            if !has("STARTTLS") {
                bail!("the SMTP server does not offer STARTTLS");
            }
            s.expect("STARTTLS", &[220]).await?;
            let Conn::Plain(tcp) = s.reader.into_inner() else {
                bail!("STARTTLS on a connection that is already encrypted");
            };
            let tls = timeout(
                CONNECT_TIMEOUT,
                self.connector.connect(server_name.clone(), tcp),
            )
            .await
            .context("the TLS handshake with the SMTP server timed out")??;
            s = Session {
                reader: BufReader::new(Conn::Tls(Box::new(tls))),
            };
            // Capabilities may change once the channel is encrypted.
            let caps = s.expect(&format!("EHLO {}", self.cfg.helo), &[250]).await?;
            self.login(&mut s, &caps).await?;
        } else {
            self.login(&mut s, &caps).await?;
        }
        Ok(s)
    }

    async fn login(&self, s: &mut Session, caps: &[String]) -> anyhow::Result<()> {
        let (Some(user), Some(pass)) = (&self.cfg.username, &self.cfg.password) else {
            return Ok(());
        };
        let auth = caps
            .iter()
            .find(|l| l.to_ascii_uppercase().starts_with("AUTH"))
            .map(|l| l.to_ascii_uppercase())
            .context("the SMTP server does not offer authentication")?;
        if auth.split_whitespace().any(|m| m == "PLAIN") {
            let token = base64(format!("\0{user}\0{pass}").as_bytes());
            s.expect(&format!("AUTH PLAIN {token}"), &[235]).await?;
        } else if auth.split_whitespace().any(|m| m == "LOGIN") {
            s.expect("AUTH LOGIN", &[334]).await?;
            s.expect(&base64(user.as_bytes()), &[334]).await?;
            s.expect(&base64(pass.as_bytes()), &[235]).await?;
        } else {
            bail!("the SMTP server offers neither AUTH PLAIN nor AUTH LOGIN");
        }
        Ok(())
    }

    async fn deliver(&self, raw: &str) -> anyhow::Result<()> {
        let mut s = self.connect().await?;
        s.expect(&format!("MAIL FROM:<{}>", self.cfg.from), &[250])
            .await?;
        for rcpt in &self.cfg.to {
            s.expect(&format!("RCPT TO:<{rcpt}>"), &[250, 251]).await?;
        }
        s.expect("DATA", &[354]).await?;
        s.send(raw.as_bytes()).await?;
        s.expect(".", &[250]).await?;
        let _ = s.expect("QUIT", &[221]).await;
        Ok(())
    }

    /// Sends the notification, retrying a couple of times; `None` when it was not sent at all
    /// (a kind that is filtered out, or the hourly limit), otherwise whether it got through.
    pub async fn notify(&self, event: &Event, now_ms: i64) -> Option<bool> {
        let payload = event.payload();
        if !self.wants(payload["event"].as_str().unwrap_or("")) {
            return None;
        }
        if !self.allow(now_ms) {
            self.suppressed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                "e-mail notification dropped: {} an hour already sent",
                self.cfg.max_per_hour
            );
            return None;
        }
        let m = compose(event, &self.cfg.subject_prefix);
        let id = self.sent.load(std::sync::atomic::Ordering::Relaxed)
            + self.failed.load(std::sync::atomic::Ordering::Relaxed);
        let raw = render(&self.cfg, &m, now_ms, id);
        for attempt in 1..=ATTEMPTS {
            match self.deliver(&raw).await {
                Ok(()) => {
                    self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(true);
                }
                Err(e) => tracing::warn!("e-mail attempt {attempt} failed: {e:#}"),
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
        self.failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::error!("e-mail notification gave up after {ATTEMPTS} attempts");
        Some(false)
    }

    pub fn render_metrics(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        format!(
            "# HELP logpit_email_sent_total E-mail notifications delivered to the SMTP server\n\
             # TYPE logpit_email_sent_total counter\nlogpit_email_sent_total {}\n\
             # HELP logpit_email_failed_total E-mail notifications that failed after their attempts\n\
             # TYPE logpit_email_failed_total counter\nlogpit_email_failed_total {}\n\
             # HELP logpit_email_suppressed_total E-mail notifications dropped by max_per_hour\n\
             # TYPE logpit_email_suppressed_total counter\nlogpit_email_suppressed_total {}\n",
            self.sent.load(Relaxed),
            self.failed.load(Relaxed),
            self.suppressed.load(Relaxed)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering::Relaxed;

    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::tls::{build_acceptor, testpki::pki};

    fn silent() -> Event {
        Event::Silent {
            host: "pve".into(),
            silent_for_ms: 125_000,
            threshold_ms: 120_000,
        }
    }

    fn base_cfg(port: u16, security: Security) -> EmailConfig {
        EmailConfig {
            host: "localhost".into(),
            port,
            security,
            from: "logpit@example.com".into(),
            to: vec!["ops@example.com".into(), "oncall@example.org".into()],
            ..Default::default()
        }
    }

    #[test]
    fn addresses_are_checked() {
        for ok in [
            "a@b.co",
            "first.last+tag@sub.example.com",
            "x_y%z@localhost",
            "a@127.0.0.1",
        ] {
            assert!(valid_address(ok), "{ok}");
        }
        for bad in [
            "",
            "a",
            "@b.co",
            "a@",
            "a@b",
            "a b@c.de",
            "a@b c.de",
            "a@.b.co",
            "a@-b.co",
            "a<@b.co",
            "a@b.co\r\nBcc: x@y.z",
            "a\"@b.co",
            "a@b.co>",
            &format!("{}@b.co", "x".repeat(65)),
        ] {
            assert!(!valid_address(bad), "{bad:?}");
        }
    }

    #[test]
    fn base64_matches_the_standard_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), enc);
        }
        assert_eq!(base64(&[0, 255, 254, 253]), "AP/+/Q==");
    }

    #[test]
    fn subjects_and_headers_cannot_be_broken_out_of() {
        let e = Event::Silent {
            host: "evil\r\nBcc: attacker@example.com".into(),
            silent_for_ms: 1000,
            threshold_ms: 1000,
        };
        let m = compose(&e, "[LogPit]");
        assert!(!m.subject.contains(['\r', '\n']), "{:?}", m.subject);
        assert!(
            m.subject
                .starts_with("[LogPit] No logs from evil Bcc: attacker@example.com")
        );
        let raw = render(&base_cfg(25, Security::None), &m, 1_791_028_800_000, 7);
        let (head, _) = raw.split_once("\r\n\r\n").unwrap();
        assert!(!head.lines().any(|l| l.starts_with("Bcc")), "{head}");
        assert!(head.contains("To: ops@example.com, oncall@example.org\r\n"));
        assert!(head.contains("Date: Sat, 3 Oct 2026 12:00:00 +0000\r\n"));
        assert!(head.contains("Message-ID: <1791028800000.7@example.com>\r\n"));
        assert!(head.contains("Content-Transfer-Encoding: base64"));
        // A long subject is clipped, a non-ASCII one is encoded in words that stay short.
        let long = compose(
            &Event::NewPattern {
                pattern: "p".into(),
                host: "h".into(),
                severity: "err".into(),
                sample: "é".repeat(500),
            },
            "[LogPit]",
        );
        assert!(long.subject.chars().count() <= MAX_SUBJECT_CHARS + 1);
        let enc = encode_subject("Ça va très bien, merci beaucoup pour tout ce temps");
        assert!(
            enc.starts_with("=?UTF-8?B?") && enc.lines().all(|l| l.trim_start().len() <= 75),
            "{enc}"
        );
        assert_eq!(encode_subject("plain ascii"), "plain ascii");
    }

    #[test]
    fn the_body_is_base64_in_short_lines_with_the_details() {
        let m = compose(&silent(), "[LogPit]");
        let raw = render(&base_cfg(25, Security::None), &m, 0, 0);
        let (_, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(body.lines().all(|l| l.len() <= 76 && !l.starts_with('.')));
        assert!(body.ends_with("\r\n"));
        // Decode it back with an independent decoder.
        let text = body.replace("\r\n", "");
        let bytes = crate::api::base64_decode(&text).unwrap();
        let decoded = String::from_utf8(bytes).unwrap();
        assert!(decoded.starts_with("No logs from pve for 2m"), "{decoded}");
        assert!(decoded.contains("event: host_silent") && decoded.contains("host: pve"));
        assert!(decoded.contains("\"threshold_secs\": 120"));
    }

    #[test]
    fn configuration_is_validated() {
        let ok = base_cfg(0, Security::Starttls);
        assert!(ok.validate().is_ok());
        assert!(EmailConfig::default().validate().is_ok(), "off by default");
        assert_eq!(ok.port(), 587);
        assert_eq!(base_cfg(0, Security::Tls).port(), 465);
        assert_eq!(base_cfg(0, Security::None).port(), 25);
        assert_eq!(base_cfg(2525, Security::None).port(), 2525);
        for bad in [
            EmailConfig {
                from: "nope".into(),
                ..ok.clone()
            },
            EmailConfig {
                to: vec![],
                ..ok.clone()
            },
            EmailConfig {
                to: vec!["bad address".into()],
                ..ok.clone()
            },
            EmailConfig {
                to: vec!["a@b.co".into(); 21],
                ..ok.clone()
            },
            EmailConfig {
                username: Some("u".into()),
                ..ok.clone()
            },
            EmailConfig {
                password: Some("p".into()),
                ..ok.clone()
            },
            EmailConfig {
                host: "smtp.example.com/x".into(),
                ..ok.clone()
            },
            EmailConfig {
                host: "a b".into(),
                ..ok.clone()
            },
            EmailConfig {
                subject_prefix: "x\ny".into(),
                ..ok.clone()
            },
            EmailConfig {
                helo: "bad name".into(),
                ..ok.clone()
            },
            // A password must not cross the network unencrypted.
            EmailConfig {
                security: Security::None,
                host: "smtp.example.com".into(),
                username: Some("u".into()),
                password: Some("p".into()),
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        // On this machine a plain connection with a login is acceptable.
        let local = EmailConfig {
            security: Security::None,
            username: Some("u".into()),
            password: Some("p".into()),
            ..ok
        };
        assert!(local.validate().is_ok());
        assert!(toml::from_str::<EmailConfig>("bogus = 1").is_err());
    }

    // ---- a scripted SMTP server ----

    #[derive(Clone, Default)]
    struct Script {
        starttls: Option<TlsAcceptor>,
        implicit: Option<TlsAcceptor>,
        auth: &'static str,
        reject_rcpt: bool,
        reject_auth: bool,
        no_starttls_cap: bool,
    }

    #[derive(Clone, Default)]
    struct Seen {
        commands: Arc<Mutex<Vec<String>>>,
        messages: Arc<Mutex<Vec<String>>>,
        sessions: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn line<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Option<String> {
        let mut l = String::new();
        (r.read_line(&mut l).await.ok()? > 0).then(|| l.trim_end().to_string())
    }

    /// Runs one SMTP conversation; returns the stream when the client asked for STARTTLS.
    async fn converse<S: AsyncRead + AsyncWrite + Unpin>(
        s: S,
        script: &Script,
        seen: &Seen,
        first: bool,
    ) -> Option<S> {
        let mut r = BufReader::new(s);
        if first {
            r.get_mut().write_all(b"220 mock ESMTP\r\n").await.ok()?;
        }
        let mut data = false;
        let mut message = String::new();
        let mut stage = 0; // LOGIN steps
        while let Some(l) = line(&mut r).await {
            if data {
                if l == "." {
                    data = false;
                    seen.messages
                        .lock()
                        .unwrap()
                        .push(std::mem::take(&mut message));
                    r.get_mut().write_all(b"250 queued\r\n").await.ok()?;
                } else {
                    message.push_str(l.strip_prefix("..").map_or(&l, |x| x));
                    message.push_str("\r\n");
                }
                continue;
            }
            seen.commands.lock().unwrap().push(l.clone());
            let up = l.to_ascii_uppercase();
            let reply: String = if up.starts_with("EHLO") {
                let mut caps = String::from("250-mock\r\n");
                if script.starttls.is_some() && !script.no_starttls_cap && first {
                    caps.push_str("250-STARTTLS\r\n");
                }
                if !script.auth.is_empty() {
                    caps.push_str(&format!("250-AUTH {}\r\n", script.auth));
                }
                caps.push_str("250 8BITMIME\r\n");
                caps
            } else if up == "STARTTLS" {
                r.get_mut().write_all(b"220 go ahead\r\n").await.ok()?;
                return Some(r.into_inner());
            } else if up.starts_with("AUTH PLAIN ") {
                if script.reject_auth {
                    "535 no\r\n".into()
                } else {
                    "235 ok\r\n".into()
                }
            } else if up == "AUTH LOGIN" {
                stage = 1;
                "334 VXNlcm5hbWU6\r\n".into()
            } else if stage == 1 {
                stage = 2;
                "334 UGFzc3dvcmQ6\r\n".into()
            } else if stage == 2 {
                stage = 0;
                if script.reject_auth {
                    "535 no\r\n".into()
                } else {
                    "235 ok\r\n".into()
                }
            } else if up.starts_with("MAIL FROM:") {
                "250 ok\r\n".into()
            } else if up.starts_with("RCPT TO:") {
                if script.reject_rcpt {
                    "550 no such user\r\n".into()
                } else {
                    "250 ok\r\n".into()
                }
            } else if up == "DATA" {
                data = true;
                "354 go\r\n".into()
            } else if up == "QUIT" {
                let _ = r.get_mut().write_all(b"221 bye\r\n").await;
                return None;
            } else {
                "500 what\r\n".into()
            };
            r.get_mut().write_all(reply.as_bytes()).await.ok()?;
        }
        None
    }

    async fn smtp(script: Script) -> (u16, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Seen::default();
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (script, seen) = (script.clone(), seen2.clone());
                seen.sessions.fetch_add(1, Relaxed);
                tokio::spawn(async move {
                    if let Some(acc) = &script.implicit {
                        if let Ok(tls) = acc.accept(tcp).await {
                            converse(tls, &script, &seen, true).await;
                        }
                    } else if let Some(tcp) = converse(tcp, &script, &seen, true).await
                        && let Some(acc) = &script.starttls
                        && let Ok(tls) = acc.accept(tcp).await
                    {
                        converse(tls, &script, &seen, false).await;
                    }
                });
            }
        });
        (port, seen)
    }

    fn mailer(cfg: &EmailConfig, ca_pem: Option<&str>) -> Arc<Mailer> {
        let m = Mailer::new(cfg).unwrap().unwrap();
        match ca_pem {
            Some(pem) => {
                let mut roots = RootCertStore::empty();
                for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                    roots.add(c.unwrap()).unwrap();
                }
                m.with_roots(roots)
            }
            None => m,
        }
    }

    fn decoded(raw: &str) -> String {
        let (_, body) = raw.split_once("\r\n\r\n").unwrap();
        String::from_utf8(crate::api::base64_decode(&body.replace("\r\n", "")).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_plain_server_gets_the_envelope_and_the_message() {
        let (port, seen) = smtp(Script::default()).await;
        let m = mailer(&base_cfg(port, Security::None), None);
        assert_eq!(m.notify(&silent(), 1_791_028_800_000).await, Some(true));
        let cmds = seen.commands.lock().unwrap().clone();
        assert_eq!(cmds[0], "EHLO localhost");
        assert_eq!(cmds[1], "MAIL FROM:<logpit@example.com>");
        assert_eq!(
            &cmds[2..4],
            ["RCPT TO:<ops@example.com>", "RCPT TO:<oncall@example.org>"]
        );
        assert_eq!(cmds[4], "DATA");
        assert_eq!(cmds.last().unwrap(), "QUIT");
        let msgs = seen.messages.lock().unwrap().clone();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].starts_with("From: logpit@example.com\r\nTo: ops@example.com, oncall@example.org\r\nSubject: [LogPit] No logs from pve"));
        assert!(decoded(&msgs[0]).contains("host: pve"));
        assert_eq!((m.sent.load(Relaxed), m.failed.load(Relaxed)), (1, 0));
        assert!(m.render_metrics().contains("logpit_email_sent_total 1"));
    }

    #[tokio::test]
    async fn authentication_uses_plain_or_login_and_failures_are_reported() {
        let cfg = |port| EmailConfig {
            username: Some("bob".into()),
            password: Some("s3cret".into()),
            ..base_cfg(port, Security::None)
        };
        // The password is only valid on a server on this machine, which `localhost` is.
        let (port, seen) = smtp(Script {
            auth: "PLAIN LOGIN",
            ..Default::default()
        })
        .await;
        assert_eq!(
            mailer(&cfg(port), None).notify(&silent(), 0).await,
            Some(true)
        );
        let cmds = seen.commands.lock().unwrap().clone();
        assert!(
            cmds[1].starts_with("AUTH PLAIN ") && cmds[1].ends_with(&base64(b"\0bob\0s3cret")),
            "{cmds:?}"
        );
        let (port, seen) = smtp(Script {
            auth: "LOGIN",
            ..Default::default()
        })
        .await;
        assert_eq!(
            mailer(&cfg(port), None).notify(&silent(), 0).await,
            Some(true)
        );
        let cmds = seen.commands.lock().unwrap().clone();
        assert_eq!(
            &cmds[1..4],
            ["AUTH LOGIN", &base64(b"bob"), &base64(b"s3cret")]
        );
        // Refused credentials, and a server that offers no way to log in.
        let (port, _) = smtp(Script {
            auth: "PLAIN",
            reject_auth: true,
            ..Default::default()
        })
        .await;
        let m = mailer(&cfg(port), None);
        assert_eq!(m.notify(&silent(), 0).await, Some(false));
        assert_eq!(m.failed.load(Relaxed), 1);
        let (port, _) = smtp(Script::default()).await;
        assert_eq!(
            mailer(&cfg(port), None).notify(&silent(), 0).await,
            Some(false)
        );
    }

    #[tokio::test]
    async fn starttls_and_implicit_tls_encrypt_the_conversation() {
        let p = pki("mail");
        let acceptor = build_acceptor(&p.server_cert, &p.server_key, None).unwrap();
        let login = |c: EmailConfig| EmailConfig {
            username: Some("bob".into()),
            password: Some("pw".into()),
            ..c
        };
        // STARTTLS: the second EHLO and the login happen inside the tunnel.
        let (port, seen) = smtp(Script {
            starttls: Some(acceptor.clone()),
            auth: "PLAIN",
            ..Default::default()
        })
        .await;
        let m = mailer(&login(base_cfg(port, Security::Starttls)), Some(&p.ca_pem));
        assert_eq!(m.notify(&silent(), 0).await, Some(true));
        let cmds = seen.commands.lock().unwrap().clone();
        assert_eq!(&cmds[..2], ["EHLO localhost", "STARTTLS"]);
        assert_eq!(cmds[2], "EHLO localhost");
        assert!(cmds[3].starts_with("AUTH PLAIN "));
        // Implicit TLS from the first byte.
        let (port, seen) = smtp(Script {
            implicit: Some(acceptor.clone()),
            auth: "PLAIN",
            ..Default::default()
        })
        .await;
        let m = mailer(&login(base_cfg(port, Security::Tls)), Some(&p.ca_pem));
        assert_eq!(m.notify(&silent(), 0).await, Some(true));
        assert_eq!(seen.messages.lock().unwrap().len(), 1);
        // A server that does not offer STARTTLS is refused rather than used in clear text.
        let (port, seen) = smtp(Script {
            starttls: Some(acceptor.clone()),
            no_starttls_cap: true,
            ..Default::default()
        })
        .await;
        let m = mailer(&base_cfg(port, Security::Starttls), Some(&p.ca_pem));
        assert_eq!(m.notify(&silent(), 0).await, Some(false));
        assert!(seen.messages.lock().unwrap().is_empty());
        // And an untrusted certificate is not accepted.
        let (port, seen) = smtp(Script {
            starttls: Some(acceptor),
            ..Default::default()
        })
        .await;
        let m = mailer(
            &base_cfg(port, Security::Starttls),
            Some(&pki("mail-other").ca_pem),
        );
        assert_eq!(m.notify(&silent(), 0).await, Some(false));
        assert!(seen.messages.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn a_rejected_recipient_is_retried_then_reported() {
        let (port, seen) = smtp(Script {
            reject_rcpt: true,
            ..Default::default()
        })
        .await;
        let m = mailer(&base_cfg(port, Security::None), None);
        assert_eq!(m.notify(&silent(), 0).await, Some(false));
        assert_eq!(
            seen.sessions.load(Relaxed),
            ATTEMPTS as usize,
            "one connection per attempt"
        );
        assert!(seen.messages.lock().unwrap().is_empty());
        assert_eq!((m.sent.load(Relaxed), m.failed.load(Relaxed)), (0, 1));
        // A server that is not there at all.
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            mailer(&base_cfg(closed, Security::None), None)
                .notify(&silent(), 0)
                .await,
            Some(false)
        );
    }

    #[tokio::test]
    async fn kinds_and_the_hourly_limit_decide_what_is_sent() {
        let (port, seen) = smtp(Script::default()).await;
        let cfg = EmailConfig {
            kinds: vec!["host_silent".into()],
            max_per_hour: 2,
            ..base_cfg(port, Security::None)
        };
        let m = mailer(&cfg, None);
        let surge = Event::VolumeSurge {
            host: "h".into(),
            count: 9,
            baseline: 1,
            window_secs: 60,
        };
        assert_eq!(
            m.notify(&surge, 0).await,
            None,
            "not a kind that goes by e-mail"
        );
        assert_eq!(m.notify(&silent(), 0).await, Some(true));
        assert_eq!(m.notify(&silent(), 1000).await, Some(true));
        assert_eq!(
            m.notify(&silent(), 2000).await,
            None,
            "the third inside the hour is dropped"
        );
        assert_eq!(m.suppressed.load(Relaxed), 1);
        assert_eq!(seen.messages.lock().unwrap().len(), 2);
        // An hour later there is room again.
        assert_eq!(m.notify(&silent(), 3_600_001).await, Some(true));
        // 0 means no limit.
        let unlimited = mailer(
            &EmailConfig {
                max_per_hour: 0,
                ..cfg
            },
            None,
        );
        for i in 0..5 {
            assert_eq!(unlimited.notify(&silent(), i).await, Some(true));
        }
    }
}
