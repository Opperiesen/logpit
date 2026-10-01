//! SQLite storage: batched writer thread, FTS5 search, retention.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::types::ToSql;
use rusqlite::{Connection, params, params_from_iter};
use serde::Serialize;

use crate::metrics::Metrics;
use crate::model::LogEntry;

const SCHEMA_VERSION: i64 = 1;

const MIGRATION_1: &str = "
CREATE TABLE logs (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    host     TEXT NOT NULL,
    app      TEXT NOT NULL,
    severity INTEGER NOT NULL,
    message  TEXT NOT NULL
);
CREATE INDEX idx_logs_ts ON logs(ts);
CREATE INDEX idx_logs_host_ts ON logs(host, ts);
CREATE VIRTUAL TABLE logs_fts USING fts5(message, content='logs', content_rowid='id');
CREATE TRIGGER logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
END;
CREATE TRIGGER logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message) VALUES ('delete', old.id, old.message);
END;
";

/// Opens (creating and migrating if needed) the database at `path`.
pub fn open(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("cannot open database {}", path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> anyhow::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        anyhow::bail!("database schema v{version} is newer than this build (v{SCHEMA_VERSION})");
    }
    if version < 1 {
        conn.execute_batch(&format!(
            "BEGIN; {MIGRATION_1} PRAGMA user_version = 1; COMMIT;"
        ))
        .context("schema migration failed")?;
    }
    Ok(())
}

/// Inserts `entries` in a single transaction.
pub fn insert_batch(conn: &mut Connection, entries: &[LogEntry]) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (ts, host, app, severity, message) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for e in entries {
            stmt.execute(params![e.ts, e.host, e.app, e.severity, e.message])?;
        }
    }
    tx.commit()
}

/// Drains the queue into the database until every sender is dropped, then flushes.
pub fn run_writer(
    mut conn: Connection,
    rx: Receiver<LogEntry>,
    batch_size: usize,
    flush_interval: Duration,
    metrics: Arc<Metrics>,
) {
    let mut batch: Vec<LogEntry> = Vec::with_capacity(batch_size);
    let mut deadline = Instant::now() + flush_interval;
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let disconnected = match rx.recv_timeout(timeout) {
            Ok(entry) => {
                batch.push(entry);
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        if disconnected || batch.len() >= batch_size || Instant::now() >= deadline {
            flush(&mut conn, &mut batch, &metrics);
            deadline = Instant::now() + flush_interval;
        }
        if disconnected {
            return;
        }
    }
}

fn flush(conn: &mut Connection, batch: &mut Vec<LogEntry>, metrics: &Metrics) {
    if batch.is_empty() {
        return;
    }
    match insert_batch(conn, batch) {
        Ok(()) => Metrics::inc(&metrics.stored, batch.len() as u64),
        Err(e) => {
            tracing::error!("failed to write batch of {}: {e}", batch.len());
            metrics.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    batch.clear();
}

/// Deletes entries older than `cutoff_ms`; returns the number removed.
pub fn purge_older_than(conn: &Connection, cutoff_ms: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM logs WHERE ts < ?1", params![cutoff_ms])
}

#[derive(Debug, Default, Clone)]
pub struct Query {
    pub text: Option<String>,
    pub host: Option<String>,
    pub app: Option<String>,
    /// Keep entries whose severity number is <= this value (lower = more severe).
    pub max_severity: Option<u8>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub id: i64,
    pub ts: i64,
    pub host: String,
    pub app: String,
    pub severity: u8,
    pub message: String,
}

/// Turns free text into an FTS5 query where every word is a quoted literal, so
/// user input can never be interpreted as FTS syntax.
pub fn fts_query(text: &str) -> Option<String> {
    let terms: Vec<String> = text
        .split_whitespace()
        .map(|w| format!("\"{}\"", w.replace('"', "\"\"")))
        .collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

pub fn search(conn: &Connection, q: &Query) -> rusqlite::Result<Vec<Row>> {
    let mut sql =
        String::from("SELECT l.id, l.ts, l.host, l.app, l.severity, l.message FROM logs l");
    let mut args: Vec<Box<dyn ToSql>> = Vec::new();
    let mut conds: Vec<&str> = Vec::new();

    if let Some(fts) = q.text.as_deref().and_then(fts_query) {
        sql.push_str(" JOIN logs_fts f ON f.rowid = l.id");
        conds.push("logs_fts MATCH ?");
        args.push(Box::new(fts));
    }
    if let Some(h) = &q.host {
        conds.push("l.host = ?");
        args.push(Box::new(h.clone()));
    }
    if let Some(a) = &q.app {
        conds.push("l.app = ?");
        args.push(Box::new(a.clone()));
    }
    if let Some(s) = q.max_severity {
        conds.push("l.severity <= ?");
        args.push(Box::new(s));
    }
    if let Some(t) = q.since_ms {
        conds.push("l.ts >= ?");
        args.push(Box::new(t));
    }
    if let Some(t) = q.until_ms {
        conds.push("l.ts <= ?");
        args.push(Box::new(t));
    }
    if !conds.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conds.join(" AND "));
    }
    sql.push_str(" ORDER BY l.ts DESC, l.id DESC LIMIT ?");
    args.push(Box::new(q.limit as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
        Ok(Row {
            id: r.get(0)?,
            ts: r.get(1)?,
            host: r.get(2)?,
            app: r.get(3)?,
            severity: r.get(4)?,
            message: r.get(5)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: i64, host: &str, sev: u8, msg: &str) -> LogEntry {
        LogEntry {
            ts,
            host: host.into(),
            app: "app".into(),
            severity: sev,
            message: msg.into(),
        }
    }

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn
    }

    fn q(limit: usize) -> Query {
        Query {
            limit,
            ..Default::default()
        }
    }

    #[test]
    fn insert_search_and_filters() {
        let mut conn = mem();
        insert_batch(
            &mut conn,
            &[
                entry(1000, "pve", 6, "VM 100 started"),
                entry(2000, "pve", 3, "disk error on sda"),
                entry(3000, "udr", 6, "wifi client connected"),
            ],
        )
        .unwrap();

        assert_eq!(search(&conn, &q(10)).unwrap().len(), 3);
        // Newest first.
        assert_eq!(search(&conn, &q(10)).unwrap()[0].ts, 3000);

        let by_text = Query {
            text: Some("disk error".into()),
            ..q(10)
        };
        let rows = search(&conn, &by_text).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "pve");

        let by_host = Query {
            host: Some("udr".into()),
            ..q(10)
        };
        assert_eq!(search(&conn, &by_host).unwrap().len(), 1);

        let errors = Query {
            max_severity: Some(3),
            ..q(10)
        };
        assert_eq!(search(&conn, &errors).unwrap().len(), 1);

        let window = Query {
            since_ms: Some(1500),
            until_ms: Some(2500),
            ..q(10)
        };
        assert_eq!(search(&conn, &window).unwrap().len(), 1);

        assert_eq!(search(&conn, &q(2)).unwrap().len(), 2);
    }

    #[test]
    fn hostile_search_text_is_treated_as_literal() {
        let mut conn = mem();
        insert_batch(&mut conn, &[entry(1, "h", 6, "plain message")]).unwrap();
        for text in [
            "\"",
            "AND OR NOT",
            "*",
            "col:val",
            "( )",
            "a\" OR \"b",
            "NEAR(",
            "-x",
        ] {
            let query = Query {
                text: Some(text.into()),
                ..q(10)
            };
            search(&conn, &query).unwrap_or_else(|e| panic!("{text:?} failed: {e}"));
        }
    }

    #[test]
    fn purge_removes_rows_and_fts_entries() {
        let mut conn = mem();
        insert_batch(
            &mut conn,
            &[
                entry(100, "h", 6, "old line"),
                entry(900, "h", 6, "new line"),
            ],
        )
        .unwrap();
        assert_eq!(purge_older_than(&conn, 500).unwrap(), 1);
        let rows = search(
            &conn,
            &Query {
                text: Some("line".into()),
                ..q(10)
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "new line");
    }

    #[test]
    fn migration_is_idempotent_and_rejects_newer_schema() {
        let conn = mem();
        migrate(&conn).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        assert!(migrate(&conn).is_err());
    }

    #[test]
    fn writer_flushes_on_disconnect() {
        let dir = std::env::temp_dir().join(format!("logpit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let conn = open(&path).unwrap();
        let metrics = Arc::new(Metrics::default());
        let (tx, rx) = std::sync::mpsc::sync_channel(16);
        let m = metrics.clone();
        let handle = std::thread::spawn(move || {
            run_writer(conn, rx, 100, Duration::from_secs(60), m);
        });
        tx.send(entry(1, "h", 6, "hello")).unwrap();
        tx.send(entry(2, "h", 6, "world")).unwrap();
        drop(tx);
        handle.join().unwrap();
        assert_eq!(metrics.stored.load(Ordering::Relaxed), 2);
        let read = open(&path).unwrap();
        assert_eq!(search(&read, &q(10)).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
