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
/// Longest host or app name kept (a DNS name is at most 253 bytes); longer ones are cut, so a
/// hostile sender cannot make every per-host table and pattern match work on huge keys.
pub const MAX_NAME_BYTES: usize = 255;
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
    settings: Arc<crate::live::LiveSettings>,
    alert_tx: Option<tokio::sync::mpsc::Sender<crate::silence::Event>>,
    forwarders: Option<Arc<crate::forward::Forwarders>>,
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
            settings: Arc::default(),
            alert_tx: None,
            forwarders: None,
        }
    }

    /// Entries that are stored are also offered to these `[[forward]]` targets.
    pub fn with_forwarders(mut self, forwarders: Arc<crate::forward::Forwarders>) -> Self {
        self.forwarders = Some(forwarders);
        self
    }

    pub fn forwarders(&self) -> Option<&Arc<crate::forward::Forwarders>> {
        self.forwarders.as_ref()
    }

    /// The settings read on every entry (rules, alerts, rate limits, structured parsing), which
    /// a reload can replace while LogPit runs.
    pub fn with_settings(mut self, settings: Arc<crate::live::LiveSettings>) -> Self {
        self.settings = settings;
        self
    }

    /// Pattern alerts notify through this channel; ingestion never waits on it (when it is full a
    /// notification is skipped).
    pub fn with_alert_channel(
        mut self,
        tx: tokio::sync::mpsc::Sender<crate::silence::Event>,
    ) -> Self {
        self.alert_tx = Some(tx);
        self
    }

    pub fn settings(&self) -> &Arc<crate::live::LiveSettings> {
        &self.settings
    }

    /// Subscribes to entries as they are accepted (before they reach the database).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LogEntry>> {
        self.live.subscribe()
    }

    pub fn live_subscribers(&self) -> usize {
        self.live.receiver_count()
    }

    pub fn rules(&self) -> Arc<crate::rules::Rules> {
        self.settings.rules.get()
    }

    pub fn alerts(&self) -> Arc<crate::alerts::AlertRules> {
        self.settings.alerts.get()
    }

    pub fn limiter(&self) -> Arc<crate::ratelimit::RateLimiter> {
        self.settings.limiter.get()
    }

    pub fn silence(&self) -> &Tracker {
        &self.silence
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The counters, to share with work done off the request (spans are stored there).
    pub fn metrics_arc(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    pub fn push(&self, mut entry: LogEntry) {
        let now = now_ms();
        truncate_utf8(&mut entry.host, MAX_NAME_BYTES);
        truncate_utf8(&mut entry.app, MAX_NAME_BYTES);
        // A host that is being limited is still alive, so it counts for silence alerts.
        self.silence.touch(&entry.host, now);
        self.settings.volume.count(&entry.host);
        if !self.settings.limiter.get().allow(&entry.host, now) {
            return;
        }
        crate::cef::enrich(&mut entry);
        // A matching regex parser sets the fields, and by default stands in for the generic
        // JSON and key=value extraction.
        let parsed = self.settings.parsers.get().apply(&mut entry);
        if parsed != crate::parsers::Applied::Replaced
            && self
                .settings
                .structured
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Generic extraction leaves an entry that already has fields alone, so with
            // `keep_generic` it adds nothing the parser did not set; it exists for the
            // entries no parser matched.
            if parsed == crate::parsers::Applied::KeepGeneric {
                crate::structured::enrich_missing(&mut entry);
            } else {
                crate::structured::enrich(&mut entry);
            }
        }
        crate::trace::normalize(&mut entry);
        if !self.settings.rules.get().apply(&mut entry) {
            return;
        }
        self.settings.metrics.get().observe(&entry);
        if let Some(tx) = &self.alert_tx {
            for event in self.settings.alerts.get().observe(&entry, now) {
                let _ = tx.try_send(event);
            }
            for event in self.settings.ui_alerts.get().observe(&entry, now) {
                let _ = tx.try_send(event);
            }
            for event in self.settings.watch.observe(&entry, now) {
                let _ = tx.try_send(event);
            }
        }
        // Identical repeats are counted, not stored; a run that just ended is summarized.
        let (store, summary) = self.settings.dedup.observe(&entry, now);
        if let Some(summary) = summary {
            self.push_summary(summary);
        }
        if !store {
            return;
        }
        truncate_utf8(&mut entry.message, self.max_message_bytes);
        // A parser or a rule may have set them from the message.
        truncate_utf8(&mut entry.host, MAX_NAME_BYTES);
        truncate_utf8(&mut entry.app, MAX_NAME_BYTES);
        if let Some(forwarders) = &self.forwarders {
            forwarders.offer(&entry);
        }
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

    /// Enqueues a summary of collapsed repeats. It skips the pipeline, whose stages already saw
    /// every one of the entries it stands for.
    pub fn push_summary(&self, mut entry: LogEntry) {
        truncate_utf8(&mut entry.message, self.max_message_bytes);
        if let Some(forwarders) = &self.forwarders {
            forwarders.offer(&entry);
        }
        let live = (self.live.receiver_count() > 0).then(|| Arc::new(entry.clone()));
        match self.tx.try_send(entry) {
            Ok(()) => {
                Metrics::inc(&self.metrics.received, 1);
                if let Some(entry) = live {
                    let _ = self.live.send(entry);
                }
            }
            Err(_) => Metrics::inc(&self.metrics.dropped, 1),
        }
    }

    /// Parses a GELF message and enqueues it; the error says why it was refused.
    pub fn push_gelf(&self, data: &[u8]) -> Result<(), &'static str> {
        match crate::gelf::parse(data, now_ms()) {
            Ok(entry) => {
                self.push(entry);
                Ok(())
            }
            Err(e) => {
                Metrics::inc(&self.metrics.rejected, 1);
                Err(e)
            }
        }
    }

    /// Parses a raw syslog message and enqueues it.
    pub fn push_syslog(&self, raw: &str, peer: &str) {
        match syslog::parse_in(raw, peer, now_ms(), *self.settings.syslog_zone.get()) {
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

/// GELF over UDP: one message per datagram, or a message in chunks.
pub async fn run_gelf_udp(addr: SocketAddr, sink: Sink) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("GELF UDP listening on {addr}");
    let mut buf = vec![0u8; 65_536];
    let mut chunks = crate::gelf::Chunks::default();
    let mut warned = false;
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                let now = std::time::Instant::now();
                let expired = chunks.expire(now);
                Metrics::inc(&sink.metrics.rejected, expired as u64);
                let datagram = &buf[..n];
                let result = if crate::gelf::is_chunk(datagram) {
                    match chunks.add(peer.ip(), datagram, now) {
                        Ok(Some(message)) => sink.push_gelf(&message),
                        Ok(None) => Ok(()),
                        Err(e) => {
                            Metrics::inc(&sink.metrics.rejected, 1);
                            Err(e)
                        }
                    }
                } else {
                    sink.push_gelf(datagram)
                };
                if let Err(e) = result {
                    // A sender using compression would otherwise fail silently: say so once.
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            "GELF datagram from {} refused: {e} (further refusals are only counted)",
                            peer.ip()
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("GELF UDP receive error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// GELF over TCP: messages separated by a NUL byte or a newline.
pub async fn run_gelf_tcp(addr: SocketAddr, sink: Sink) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("GELF TCP listening on {addr}");
    accept_loop(listener, "GELF TCP", move |stream, peer| {
        let sink = sink.clone();
        async move {
            let mut frames = FramedRead::new(stream, crate::gelf::GelfFrames::new(MAX_LINE_BYTES));
            loop {
                match timeout(TCP_IDLE_TIMEOUT, frames.next()).await {
                    Ok(Some(Ok(message))) => {
                        let _ = sink.push_gelf(&message);
                    }
                    Ok(Some(Err(e))) => {
                        tracing::warn!("closing GELF connection from {peer}: {e}");
                        Metrics::inc(&sink.metrics().rejected, 1);
                        return;
                    }
                    Ok(None) | Err(_) => return,
                }
            }
        }
    })
    .await
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
    acceptor: Arc<crate::live::Reloadable<tokio_rustls::TlsAcceptor>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("syslog TLS listening on {addr}");
    serve_tls(listener, sink, acceptor).await
}

/// Serves TLS syslog; every new connection uses the acceptor current at that moment, so a reload
/// that renews the certificate applies to new connections while open ones continue unchanged.
pub async fn serve_tls(
    listener: TcpListener,
    sink: Sink,
    acceptor: Arc<crate::live::Reloadable<tokio_rustls::TlsAcceptor>>,
) -> anyhow::Result<()> {
    accept_loop(listener, "TLS", move |stream, peer| {
        let (sink, acceptor) = (sink.clone(), acceptor.get());
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
