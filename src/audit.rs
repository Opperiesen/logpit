//! Audit trail of API access: refused requests and the requests that read or change data,
//! kept in a bounded in-memory ring (`GET /api/audit`) and written to the log.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};

use serde::Serialize;

/// Events kept; older ones are dropped.
pub const CAPACITY: usize = 1000;
/// Most events one `/api/audit` call returns from the database.
pub const MAX_QUERY_LIMIT: usize = 10_000;
/// Longest query string kept in an event.
const MAX_QUERY_CHARS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Event {
    /// Unix ms.
    pub ts: i64,
    /// Name of the token used; absent when none or an unknown one was presented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub method: String,
    pub path: String,
    /// The query string (filters and search text), shortened.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub query: String,
    pub status: u16,
    /// Address of the connection (the proxy's, behind one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

/// Whether a request is worth an event: every refusal, and what reads entries or changes
/// shared state. Ingestion and the web page's background refreshes (stats, hosts, top values…)
/// are not, as they would drown the rest.
pub fn wanted(method: &str, path: &str, status: u16) -> bool {
    if status == 401 || status == 403 {
        return true;
    }
    if method != "GET" {
        return !(path == "/ingest"
            || path == "/gelf"
            || path == "/v1/logs"
            || path.starts_with("/loki/"));
    }
    path == "/api/logs"
        || path == "/api/export"
        || path == "/api/tail"
        || path == "/api/audit"
        || path == "/api/tokens"
        || path.starts_with("/api/logs/")
}

pub fn shorten_query(query: &str) -> String {
    match query.char_indices().nth(MAX_QUERY_CHARS) {
        Some((i, _)) => format!("{}…", &query[..i]),
        None => query.to_string(),
    }
}

/// Which events `/api/audit` returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    /// Name of the token.
    pub token: Option<String>,
    /// Only refused requests (401 and 403).
    pub refused: bool,
    pub limit: usize,
}

impl AuditQuery {
    fn matches(&self, e: &Event) -> bool {
        self.since_ms.is_none_or(|t| e.ts >= t)
            && self.until_ms.is_none_or(|t| e.ts <= t)
            && self
                .token
                .as_deref()
                .is_none_or(|t| e.token.as_deref() == Some(t))
            && (!self.refused || e.status == 401 || e.status == 403)
    }
}

/// Events waiting for the database writer; more are dropped (and counted in the log).
const QUEUE: usize = 4096;
/// Events written in one transaction at most.
const WRITE_BATCH: usize = 256;
const PURGE_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Default)]
pub struct AuditLog {
    /// The newest events, newest last. Without a database it is the whole trail.
    events: Mutex<VecDeque<Event>>,
    writer: Option<SyncSender<Event>>,
    db: Option<PathBuf>,
}

impl AuditLog {
    /// A trail kept in the database at `path` for `retention_days` (older events are purged at
    /// startup and every hour), written by a background thread so requests never wait for it.
    pub fn persistent(path: &Path, retention_days: u32) -> anyhow::Result<Self> {
        let mut conn = crate::store::open(path)?;
        let (tx, rx) = sync_channel::<Event>(QUEUE);
        let cutoff = move || crate::ingest::now_ms() - i64::from(retention_days) * 86_400_000;
        crate::store::purge_audit(&conn, cutoff())?;
        std::thread::Builder::new()
            .name("logpit-audit".into())
            .spawn(move || {
                let mut last_purge = std::time::Instant::now();
                loop {
                    let first = match rx.recv_timeout(PURGE_EVERY) {
                        Ok(e) => Some(e),
                        Err(RecvTimeoutError::Timeout) => None,
                        Err(RecvTimeoutError::Disconnected) => return,
                    };
                    let mut batch: Vec<Event> = first.into_iter().collect();
                    while batch.len() < WRITE_BATCH {
                        match rx.try_recv() {
                            Ok(e) => batch.push(e),
                            Err(_) => break,
                        }
                    }
                    if !batch.is_empty()
                        && let Err(e) = crate::store::insert_audit(&mut conn, &batch)
                    {
                        tracing::error!("audit write failed, {} events lost: {e}", batch.len());
                    }
                    if last_purge.elapsed() >= PURGE_EVERY {
                        last_purge = std::time::Instant::now();
                        if let Err(e) = crate::store::purge_audit(&conn, cutoff()) {
                            tracing::error!("audit purge failed: {e}");
                        }
                    }
                }
            })?;
        Ok(Self {
            events: Mutex::default(),
            writer: Some(tx),
            db: Some(path.to_path_buf()),
        })
    }

    pub fn record(&self, event: Event) {
        if let Some(writer) = &self.writer
            && writer.try_send(event.clone()).is_err()
        {
            tracing::warn!("audit queue full or closed: an event was not stored");
        }
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() >= CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Whether the trail is kept in the database (and so survives a restart).
    pub fn persistent_path(&self) -> Option<&Path> {
        self.db.as_deref()
    }

    /// The newest `limit` events kept in memory, newest first.
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        self.search(&AuditQuery {
            limit,
            ..Default::default()
        })
    }

    /// The events in memory matching `q`, newest first.
    pub fn search(&self, q: &AuditQuery) -> Vec<Event> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events
            .iter()
            .rev()
            .filter(|e| q.matches(e))
            .take(q.limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: i64) -> Event {
        Event {
            ts: n,
            token: Some("ops".into()),
            method: "GET".into(),
            path: "/api/logs".into(),
            query: String::new(),
            status: 200,
            peer: None,
        }
    }

    #[test]
    fn ring_keeps_the_newest_events_newest_first() {
        let log = AuditLog::default();
        for n in 0..(CAPACITY as i64 + 5) {
            log.record(event(n));
        }
        let all = log.recent(usize::MAX);
        assert_eq!(all.len(), CAPACITY);
        assert_eq!(all[0].ts, CAPACITY as i64 + 4);
        assert_eq!(all[CAPACITY - 1].ts, 5);
        assert_eq!(log.recent(2).len(), 2);
        assert!(AuditLog::default().recent(10).is_empty());
    }

    #[test]
    fn refusals_reads_and_changes_are_wanted_but_background_traffic_is_not() {
        assert!(wanted("GET", "/api/stats", 401));
        assert!(wanted("POST", "/ingest", 403));
        assert!(wanted("GET", "/api/logs", 200));
        assert!(wanted("GET", "/api/logs/12/context", 200));
        assert!(wanted("GET", "/api/export", 200));
        assert!(wanted("GET", "/api/tail", 200));
        assert!(wanted("POST", "/api/views", 200));
        assert!(wanted("DELETE", "/api/views/3", 200));
        assert!(wanted("GET", "/api/audit", 200));
        assert!(!wanted("POST", "/ingest", 200));
        assert!(!wanted("POST", "/loki/api/v1/push", 204));
        assert!(!wanted("GET", "/api/stats", 200));
        assert!(!wanted("GET", "/api/hosts", 200));
        assert!(!wanted("GET", "/api/views", 200));
    }

    #[test]
    fn long_queries_are_shortened_on_a_character_boundary() {
        assert_eq!(shorten_query("q=abc"), "q=abc");
        let long = "é".repeat(MAX_QUERY_CHARS + 10);
        let short = shorten_query(&long);
        assert_eq!(short.chars().count(), MAX_QUERY_CHARS + 1);
        assert!(short.ends_with('…'));
    }

    #[test]
    fn memory_search_filters_by_time_token_and_refusal() {
        let log = AuditLog::default();
        let mut denied = event(5);
        denied.token = None;
        denied.status = 401;
        let mut other = event(7);
        other.token = Some("web".into());
        for e in [event(1), event(3), denied, other] {
            log.record(e);
        }
        let q = |f: &dyn Fn(&mut AuditQuery)| {
            let mut q = AuditQuery {
                limit: 10,
                ..Default::default()
            };
            f(&mut q);
            log.search(&q).iter().map(|e| e.ts).collect::<Vec<_>>()
        };
        assert_eq!(q(&|_| {}), [7, 5, 3, 1]);
        assert_eq!(q(&|q| q.since_ms = Some(3)), [7, 5, 3]);
        assert_eq!(q(&|q| q.until_ms = Some(3)), [3, 1]);
        assert_eq!(q(&|q| q.token = Some("web".into())), [7]);
        assert_eq!(q(&|q| q.refused = true), [5]);
        assert_eq!(q(&|q| q.limit = 2), [7, 5]);
    }

    #[test]
    fn persistent_trail_is_stored_purged_and_filtered() {
        let dir = std::env::temp_dir().join(format!("logpit-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.db");
        let _ = std::fs::remove_file(&path);
        drop(crate::store::open(&path).unwrap());
        // An old event is purged when the trail starts; a recent one survives.
        {
            let mut conn = crate::store::open(&path).unwrap();
            let now = crate::ingest::now_ms();
            let mut old = event(now - 40 * 86_400_000);
            old.path = "/api/old".into();
            let mut recent = event(now - 1000);
            recent.path = "/api/recent".into();
            crate::store::insert_audit(&mut conn, &[old, recent]).unwrap();
        }
        let log = AuditLog::persistent(&path, 30).unwrap();
        assert_eq!(log.persistent_path(), Some(path.as_path()));
        let now = crate::ingest::now_ms();
        let mut denied = event(now);
        denied.status = 403;
        denied.token = Some("web".into());
        log.record(event(now - 10));
        log.record(denied);
        let conn = crate::store::open(&path).unwrap();
        let query = |f: &dyn Fn(&mut AuditQuery)| {
            let mut q = AuditQuery {
                limit: 50,
                ..Default::default()
            };
            f(&mut q);
            crate::store::audit_events(&conn, &q).unwrap()
        };
        // The writer is asynchronous: wait for both events to land.
        for _ in 0..200 {
            if query(&|_| {}).len() >= 3 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let all = query(&|_| {});
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|e| e.path != "/api/old"));
        assert_eq!(all[0].status, 403);
        assert_eq!(query(&|q| q.refused = true).len(), 1);
        assert_eq!(query(&|q| q.token = Some("web".into())).len(), 1);
        assert_eq!(query(&|q| q.since_ms = Some(now - 500)).len(), 2);
        assert_eq!(query(&|q| q.limit = 1).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
