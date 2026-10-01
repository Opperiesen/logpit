//! Network ingestion: syslog over UDP/TCP feeding the bounded write queue.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::metrics::Metrics;
use crate::model::{LogEntry, truncate_utf8};
use crate::syslog;

const MAX_TCP_CONNECTIONS: usize = 256;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_LINE_BYTES: usize = 64 * 1024;

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Entry point to the write queue. Never blocks: a full queue drops the entry.
#[derive(Clone)]
pub struct Sink {
    tx: SyncSender<LogEntry>,
    metrics: Arc<Metrics>,
    max_message_bytes: usize,
}

impl Sink {
    pub fn new(tx: SyncSender<LogEntry>, metrics: Arc<Metrics>, max_message_bytes: usize) -> Self {
        Self {
            tx,
            metrics,
            max_message_bytes,
        }
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn push(&self, mut entry: LogEntry) {
        truncate_utf8(&mut entry.message, self.max_message_bytes);
        match self.tx.try_send(entry) {
            Ok(()) => Metrics::inc(&self.metrics.received, 1),
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
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("TCP accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!("too many TCP connections; refusing {peer}");
            continue;
        };
        let sink = sink.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let peer = peer.ip().to_string();
            let mut lines =
                FramedRead::new(stream, LinesCodec::new_with_max_length(MAX_LINE_BYTES));
            loop {
                match timeout(TCP_IDLE_TIMEOUT, lines.next()).await {
                    Ok(Some(Ok(line))) => sink.push_syslog(&line, &peer),
                    Ok(Some(Err(e))) => {
                        tracing::warn!("closing TCP connection from {peer}: {e}");
                        Metrics::inc(&sink.metrics().rejected, 1);
                        return;
                    }
                    Ok(None) | Err(_) => return,
                }
            }
        });
    }
}
