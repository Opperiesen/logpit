//! Audit trail of API access: refused requests and the requests that read or change data,
//! kept in a bounded in-memory ring (`GET /api/audit`) and written to the log.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::Serialize;

/// Events kept; older ones are dropped.
pub const CAPACITY: usize = 1000;
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

#[derive(Default)]
pub struct AuditLog {
    events: Mutex<VecDeque<Event>>,
}

impl AuditLog {
    pub fn record(&self, event: Event) {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() >= CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// The newest `limit` events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events.iter().rev().take(limit).cloned().collect()
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
}
