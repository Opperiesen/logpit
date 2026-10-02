//! Network ingestion: syslog over UDP/TCP feeding the bounded write queue.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, broadcast};
use tokio::time::timeout;
use tokio_util::codec::FramedRead;

use crate::framing::SyslogFrames;

use crate::metrics::Metrics;
use crate::model::{LogEntry, truncate_utf8};
use crate::silence::Tracker;
use crate::syslog;

const MAX_TCP_CONNECTIONS: usize = 256;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Entries a live-tail subscriber may fall behind before it starts losing some.
const LIVE_CAPACITY: usize = 1024;

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Entry point to the write queue. Never blocks: a full queue drops the entry.
#[derive(Clone)]
pub struct Sink {
    tx: SyncSender<LogEntry>,
    metrics: Arc<Metrics>,
    max_message_bytes: usize,
    live: broadcast::Sender<Arc<LogEntry>>,
    silence: Arc<Tracker>,
    parse_structured: bool,
    rules: Arc<crate::rules::Rules>,
    alerts: Arc<crate::alerts::AlertRules>,
    alert_tx: Option<tokio::sync::mpsc::Sender<crate::silence::Event>>,
}

impl Sink {
    pub fn new(
        tx: SyncSender<LogEntry>,
        metrics: Arc<Metrics>,
        max_message_bytes: usize,
        silence: Arc<Tracker>,
    ) -> Self {
        Self {
            tx,
            metrics,
            max_message_bytes,
            live: broadcast::channel(LIVE_CAPACITY).0,
            silence,
            parse_structured: false,
            rules: Arc::default(),
            alerts: Arc::default(),
            alert_tx: None,
        }
    }

    /// Extracts JSON and `key=value` data from messages into fields (off unless enabled).
    /// Drop and mask rules applied to every entry before it is queued.
    pub fn with_rules(mut self, rules: Arc<crate::rules::Rules>) -> Self {
        self.rules = rules;
        self
    }

    /// Pattern alerts; due notifications are sent on `tx` (never blocking ingestion: when the
    /// channel is full a notification is skipped).
    pub fn with_alerts(
        mut self,
        alerts: Arc<crate::alerts::AlertRules>,
        tx: tokio::sync::mpsc::Sender<crate::silence::Event>,
    ) -> Self {
        self.alerts = alerts;
        self.alert_tx = Some(tx);
        self
    }

    pub fn alerts(&self) -> &crate::alerts::AlertRules {
        &self.alerts
    }

    pub fn rules(&self) -> &crate::rules::Rules {
        &self.rules
    }

    pub fn with_structured_parsing(mut self, on: bool) -> Self {
        self.parse_structured = on;
        self
    }

    /// Subscribes to entries as they are accepted (before they reach the database).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LogEntry>> {
        self.live.subscribe()
    }

    pub fn live_subscribers(&self) -> usize {
        self.live.receiver_count()
    }

    pub fn silence(&self) -> &Tracker {
        &self.silence
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn push(&self, mut entry: LogEntry) {
        self.silence.touch(&entry.host, now_ms());
        crate::cef::enrich(&mut entry);
        if self.parse_structured {
            crate::structured::enrich(&mut entry);
        }
        if !self.rules.apply(&mut entry) {
            return;
        }
        if let Some(tx) = &self.alert_tx {
            for event in self.alerts.observe(&entry, now_ms()) {
                let _ = tx.try_send(event);
            }
        }
        truncate_utf8(&mut entry.message, self.max_message_bytes);
        let live = (self.live.receiver_count() > 0).then(|| Arc::new(entry.clone()));
        match self.tx.try_send(entry) {
            Ok(()) => {
                Metrics::inc(&self.metrics.received, 1);
                if let Some(entry) = live {
                    let _ = self.live.send(entry);
                }
            }
            Err(TrySendError::Full(_)) => Metrics::inc(&self.metrics.dropped, 1),
            Err(TrySendError::Disconnected(_)) => {
                tracing::error!("write queue closed; dropping entry");
                Metrics::inc(&self.metrics.dropped, 1);
            }
        }
    }

    /// Parses a raw syslog message and enqueues it.
    pub fn push_syslog(&self, raw: &str, peer: &str) {
        match syslog::parse(raw, peer, now_ms()) {
            Some(entry) => self.push(entry),
            None => Metrics::inc(&self.metrics.rejected, 1),
        }
    }
}

pub async fn run_udp(addr: SocketAddr, sink: Sink) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("syslog UDP listening on {addr}");
    let mut buf = vec![0u8; 65_536];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                let raw = String::from_utf8_lossy(&buf[..n]);
                sink.push_syslog(&raw, &peer.ip().to_string());
            }
            Err(e) => {
                tracing::warn!("UDP receive error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

pub async fn run_tcp(addr: SocketAddr, sink: Sink) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("syslog TCP listening on {addr}");
    serve_tcp(listener, sink).await
}

/// Reads syslog messages (newline-delimited or octet-counted) until the peer closes, goes
/// idle, or sends something invalid.
async fn handle_connection<S: AsyncRead + Unpin>(stream: S, peer: String, sink: Sink, what: &str) {
    let mut frames = FramedRead::new(stream, SyslogFrames::new(MAX_LINE_BYTES));
    loop {
        match timeout(TCP_IDLE_TIMEOUT, frames.next()).await {
            Ok(Some(Ok(line))) => sink.push_syslog(&line, &peer),
            Ok(Some(Err(e))) => {
                tracing::warn!("closing {what} connection from {peer}: {e}");
                Metrics::inc(&sink.metrics().rejected, 1);
                return;
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// Accepts connections up to the connection limit; `wrap` turns each accepted stream into
/// the handler's future (plain TCP reads it directly, TLS performs the handshake first).
async fn accept_loop<F, Fut>(
    listener: TcpListener,
    what: &'static str,
    wrap: F,
) -> anyhow::Result<()>
where
    F: Fn(tokio::net::TcpStream, String) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("{what} accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!("too many {what} connections; refusing {peer}");
            continue;
        };
        let work = wrap(stream, peer.ip().to_string());
        tokio::spawn(async move {
            let _permit = permit;
            work.await;
        });
    }
}

pub async fn serve_tcp(listener: TcpListener, sink: Sink) -> anyhow::Result<()> {
    accept_loop(listener, "TCP", move |stream, peer| {
        handle_connection(stream, peer, sink.clone(), "TCP")
    })
    .await
}

pub async fn run_tls(
    addr: SocketAddr,
    sink: Sink,
    acceptor: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("syslog TLS listening on {addr}");
    serve_tls(listener, sink, acceptor).await
}

pub async fn serve_tls(
    listener: TcpListener,
    sink: Sink,
    acceptor: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<()> {
    accept_loop(listener, "TLS", move |stream, peer| {
        let (sink, acceptor) = (sink.clone(), acceptor.clone());
        async move {
            match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => handle_connection(tls, peer, sink, "TLS").await,
                Ok(Err(e)) => {
                    // Port scanners and clients with the wrong CA end up here; not worth a warning.
                    tracing::debug!("TLS handshake with {peer} failed: {e}");
                    Metrics::inc(&sink.metrics().tls_failures, 1);
                }
                Err(_) => {
                    tracing::debug!("TLS handshake with {peer} timed out");
                    Metrics::inc(&sink.metrics().tls_failures, 1);
                }
            }
        }
    })
    .await
}
