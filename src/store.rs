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

const SCHEMA_VERSION: i64 = 2;

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

/// v2: structured `fields` (JSON object) stored per entry and indexed for full-text search.
const MIGRATION_2: &str = "
ALTER TABLE logs ADD COLUMN fields TEXT;
DROP TRIGGER logs_ai;
DROP TRIGGER logs_ad;
DROP TABLE logs_fts;
CREATE VIRTUAL TABLE logs_fts USING fts5(message, fields, content='logs', content_rowid='id');
CREATE TRIGGER logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, message, fields) VALUES (new.id, new.message, new.fields);
END;
CREATE TRIGGER logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message, fields) VALUES ('delete', old.id, old.message, old.fields);
END;
INSERT INTO logs_fts(logs_fts) VALUES ('rebuild');
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
    for (target, sql) in [(1, MIGRATION_1), (2, MIGRATION_2)] {
        if version < target {
            conn.execute_batch(&format!(
                "BEGIN; {sql} PRAGMA user_version = {target}; COMMIT;"
            ))
            .with_context(|| format!("schema migration to v{target} failed"))?;
        }
    }
    Ok(())
}

/// Inserts `entries` in a single transaction.
pub fn insert_batch(conn: &mut Connection, entries: &[LogEntry]) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (ts, host, app, severity, message, fields) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for e in entries {
            let fields = (!e.fields.is_empty())
                .then(|| serde_json::to_string(&e.fields))
                .transpose()
                .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
            stmt.execute(params![e.ts, e.host, e.app, e.severity, e.message, fields])?;
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

/// Distinct hosts present in the database, at most `limit`.
pub fn known_hosts(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT DISTINCT host FROM logs LIMIT ?")?;
    stmt.query_map([limit as i64], |r| r.get(0))?.collect()
}

/// Deletes entries older than the cutoff of their severity (`cutoffs[severity]`, in Unix ms;
/// `None` keeps that severity forever). Returns the number removed.
pub fn purge(conn: &Connection, cutoffs: &[Option<i64>; 8]) -> rusqlite::Result<usize> {
    let mut removed = 0;
    let mut done = [false; 8];
    for first in 0..8 {
        let Some(cutoff) = cutoffs[first] else {
            continue;
        };
        if done[first] {
            continue;
        }
        // One statement per distinct cutoff, covering every severity that shares it.
        let group: Vec<String> = (first..8)
            .filter(|&s| cutoffs[s] == Some(cutoff))
            .inspect(|&s| done[s] = true)
            .map(|s| s.to_string())
            .collect();
        removed += conn.execute(
            &format!(
                "DELETE FROM logs WHERE ts < ?1 AND severity IN ({})",
                group.join(",")
            ),
            params![cutoff],
        )?;
    }
    Ok(removed)
}

/// What to split each bucket's count by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupBy {
    None,
    Host,
    App,
    Severity,
    /// A structured field (validated with [`valid_field_key`]).
    Field(String),
}

/// Counts of entries matching `q` per time bucket (`ts` floored to a multiple of
/// `bucket_ms`) and, optionally, per group. Returns `(bucket_start, group, count)`, with an
/// empty group when not grouping; empty buckets are not returned.
pub fn stats(
    conn: &Connection,
    q: &Query,
    bucket_ms: i64,
    group: &GroupBy,
) -> rusqlite::Result<Vec<(i64, String, u64)>> {
    let group_expr = match group {
        GroupBy::None => "''".to_string(),
        GroupBy::Host => "l.host".to_string(),
        GroupBy::App => "l.app".to_string(),
        GroupBy::Severity => "CAST(l.severity AS TEXT)".to_string(),
        GroupBy::Field(key) => {
            if !valid_field_key(key) {
                return Err(rusqlite::Error::InvalidParameterName(key.clone()));
            }
            // The key is restricted to a safe charset, so it can be inlined as a literal.
            format!("COALESCE(json_extract(l.fields, '$.\"{key}\"'), '')")
        }
    };
    let filter = Filter::new(q)?;
    // bucket_ms is an i64 formatted by us, never user text.
    let sql = format!(
        "SELECT (l.ts / {bucket_ms}) * {bucket_ms} AS b, {group_expr} AS g, COUNT(*) \
         FROM logs l{} GROUP BY b, g ORDER BY b",
        filter.sql()
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params_from_iter(filter.args.iter().map(|a| a.as_ref())),
        |r| {
            Ok((
                r.get(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as u64,
            ))
        },
    )?;
    rows.collect()
}

/// Smallest timestamp in the database, if any.
pub fn min_ts(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT MIN(ts) FROM logs", [], |r| r.get(0))
}

/// Bytes of the database file that hold data (pages not on the freelist). Deleting rows frees
/// pages for reuse but never shrinks the file, so this is the figure a size limit bounds.
pub fn used_bytes(conn: &Connection) -> rusqlite::Result<u64> {
    let pragma = |name: &str| conn.pragma_query_value(None, name, |r| r.get::<_, i64>(0));
    let pages = pragma("page_count")? - pragma("freelist_count")?;
    Ok(u64::try_from(pages).unwrap_or(0) * u64::try_from(pragma("page_size")?).unwrap_or(0))
}

/// Entries deleted per transaction when enforcing a size limit.
const EVICT_CHUNK: i64 = 500;
/// Upper bound on chunks per call; any remainder is handled by the next run.
const EVICT_MAX_CHUNKS: usize = 4000;
/// Give up after this many consecutive chunks that did not shrink the data in use, rather
/// than emptying the database on a measurement that is not moving.
const EVICT_MAX_STALLS: u32 = 5;

/// If the data in use exceeds `max_bytes`, deletes the oldest entries until it is down to
/// 90% of that (so the limit is not hit again on the next entry). Returns the number of
/// entries removed. Part of the full-text index is only reclaimed when SQLite merges its
/// segments, so slightly more than the strict minimum may be removed.
pub fn enforce_size_limit(conn: &Connection, max_bytes: u64) -> rusqlite::Result<usize> {
    if used_bytes(conn)? <= max_bytes {
        return Ok(0);
    }
    let target = max_bytes / 10 * 9;
    let (mut removed, mut stalls) = (0, 0);
    let mut used = used_bytes(conn)?;
    for _ in 0..EVICT_MAX_CHUNKS {
        let n = conn.execute(
            "DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY ts, id LIMIT ?1)",
            params![EVICT_CHUNK],
        )?;
        removed += n;
        let now = used_bytes(conn)?;
        stalls = if now < used { 0 } else { stalls + 1 };
        used = now;
        if n == 0 || used <= target || stalls >= EVICT_MAX_STALLS {
            break;
        }
    }
    Ok(removed)
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
    /// Exact-match filters on structured fields, as `(key, value)`; all must match.
    pub fields: Vec<(String, String)>,
    pub limit: usize,
}

/// Field keys are restricted to a safe charset so they can be used in a JSON path.
pub fn valid_field_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl Query {
    /// Whether a freshly ingested entry satisfies this query's filters, for live tailing.
    /// Time bounds and `limit` are ignored. Free text matches case-insensitively as
    /// substrings of the message or field values (no FTS index is involved).
    pub fn matches(&self, e: &LogEntry) -> bool {
        if self.host.as_ref().is_some_and(|h| *h != e.host)
            || self.app.as_ref().is_some_and(|a| *a != e.app)
            || self.max_severity.is_some_and(|s| e.severity > s)
        {
            return false;
        }
        if !self
            .fields
            .iter()
            .all(|(k, v)| e.fields.get(k).is_some_and(|x| x == v))
        {
            return false;
        }
        match self.text.as_deref() {
            Some(text) if text.split_whitespace().next().is_some() => {
                let hay = std::iter::once(e.message.as_str())
                    .chain(e.fields.values().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join("\n")
                    .to_lowercase();
                text.split_whitespace()
                    .all(|w| hay.contains(&w.to_lowercase()))
            }
            _ => true,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub id: i64,
    pub ts: i64,
    pub host: String,
    pub app: String,
    pub severity: u8,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
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

/// The FROM-join and WHERE conditions shared by search and stats for one query.
struct Filter {
    join_fts: bool,
    conds: Vec<&'static str>,
    args: Vec<Box<dyn ToSql>>,
}

impl Filter {
    fn new(q: &Query) -> rusqlite::Result<Self> {
        let mut f = Filter {
            join_fts: false,
            conds: Vec::new(),
            args: Vec::new(),
        };
        if let Some(fts) = q.text.as_deref().and_then(fts_query) {
            f.join_fts = true;
            f.conds.push("logs_fts MATCH ?");
            f.args.push(Box::new(fts));
        }
        if let Some(h) = &q.host {
            f.conds.push("l.host = ?");
            f.args.push(Box::new(h.clone()));
        }
        if let Some(a) = &q.app {
            f.conds.push("l.app = ?");
            f.args.push(Box::new(a.clone()));
        }
        if let Some(s) = q.max_severity {
            f.conds.push("l.severity <= ?");
            f.args.push(Box::new(s));
        }
        if let Some(t) = q.since_ms {
            f.conds.push("l.ts >= ?");
            f.args.push(Box::new(t));
        }
        if let Some(t) = q.until_ms {
            f.conds.push("l.ts <= ?");
            f.args.push(Box::new(t));
        }
        for (key, value) in &q.fields {
            if !valid_field_key(key) {
                return Err(rusqlite::Error::InvalidParameterName(key.clone()));
            }
            f.conds.push("json_extract(l.fields, ?) = ?");
            f.args.push(Box::new(format!("$.\"{key}\"")));
            f.args.push(Box::new(value.clone()));
        }
        Ok(f)
    }

    /// ` JOIN …` plus ` WHERE …`, to append after `FROM logs l`.
    fn sql(&self) -> String {
        let mut sql = String::new();
        if self.join_fts {
            sql.push_str(" JOIN logs_fts f ON f.rowid = l.id");
        }
        if !self.conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&self.conds.join(" AND "));
        }
        sql
    }
}

pub fn search(conn: &Connection, q: &Query) -> rusqlite::Result<Vec<Row>> {
    let mut filter = Filter::new(q)?;
    let mut sql = String::from(
        "SELECT l.id, l.ts, l.host, l.app, l.severity, l.message, l.fields FROM logs l",
    );
    sql.push_str(&filter.sql());
    sql.push_str(" ORDER BY l.ts DESC, l.id DESC LIMIT ?");
    filter.args.push(Box::new(q.limit as i64));
    let args = filter.args;

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
        Ok(Row {
            id: r.get(0)?,
            ts: r.get(1)?,
            host: r.get(2)?,
            app: r.get(3)?,
            severity: r.get(4)?,
            message: r.get(5)?,
            fields: r
                .get::<_, Option<String>>(6)?
                .and_then(|text| serde_json::from_str(&text).ok()),
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
            ..Default::default()
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
    fn live_query_matching() {
        let mut e = entry(1, "pve", 3, "Disk Error on sda");
        e.fields.insert("act".into(), "blocked".into());
        let mut q = q(10);
        assert!(q.matches(&e));
        q.text = Some("disk ERROR".into());
        q.host = Some("pve".into());
        q.max_severity = Some(3);
        q.fields.push(("act".into(), "blocked".into()));
        assert!(q.matches(&e));
        q.text = Some("blocked".into());
        assert!(q.matches(&e), "text also matches field values");
        q.text = Some("missing".into());
        assert!(!q.matches(&e));
        q.text = None;
        q.max_severity = Some(2);
        assert!(!q.matches(&e));
        q.max_severity = None;
        q.fields = vec![("act".into(), "allowed".into())];
        assert!(!q.matches(&e));
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
        assert_eq!(purge(&conn, &[Some(500); 8]).unwrap(), 1);
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
    fn stats_count_per_bucket_with_filters_and_groups() {
        let mut conn = mem();
        let mut a = entry(1_500, "pve", 3, "disk error");
        a.fields.insert("act".into(), "blocked".into());
        let batch = vec![
            entry(100, "pve", 6, "boot"),
            entry(900, "nas", 6, "sync"),
            a,
            entry(1_999, "nas", 3, "disk error"),
            entry(2_000, "pve", 6, "next bucket"),
        ];
        insert_batch(&mut conn, &batch).unwrap();
        let all = Query { ..q(0) };

        let plain = stats(&conn, &all, 1000, &GroupBy::None).unwrap();
        assert_eq!(
            plain,
            vec![
                (0, "".into(), 2),
                (1000, "".into(), 2),
                (2000, "".into(), 1)
            ]
        );

        let by_host = stats(&conn, &all, 1000, &GroupBy::Host).unwrap();
        assert_eq!(
            by_host,
            vec![
                (0, "nas".into(), 1),
                (0, "pve".into(), 1),
                (1000, "nas".into(), 1),
                (1000, "pve".into(), 1),
                (2000, "pve".into(), 1)
            ]
        );

        // Filters (full-text, severity, time range) apply exactly as in search.
        let errors = Query {
            text: Some("disk".into()),
            max_severity: Some(3),
            since_ms: Some(1000),
            ..q(0)
        };
        let by_sev = stats(&conn, &errors, 1000, &GroupBy::Severity).unwrap();
        assert_eq!(by_sev, vec![(1000, "3".into(), 2)]);

        // Grouping by a structured field; entries without it fall in the empty group.
        let by_act = stats(&conn, &all, 2000, &GroupBy::Field("act".into())).unwrap();
        assert_eq!(
            by_act,
            vec![
                (0, "".into(), 3),
                (0, "blocked".into(), 1),
                (2000, "".into(), 1)
            ]
        );
        assert!(stats(&conn, &all, 1000, &GroupBy::Field("a b".into())).is_err());

        assert_eq!(min_ts(&conn).unwrap(), Some(100));
        assert_eq!(min_ts(&mem()).unwrap(), None);
    }

    #[test]
    fn size_limit_evicts_oldest_entries_first() {
        let mut conn = mem();
        let filler = "x".repeat(1000);
        let batch: Vec<LogEntry> = (0..4000)
            .map(|i| entry(i, "h", 6, &format!("line {i} {filler}")))
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let before = used_bytes(&conn).unwrap();
        assert!(before > 4_000_000);

        // Under the limit: nothing happens.
        assert_eq!(enforce_size_limit(&conn, before + 1).unwrap(), 0);

        let limit = before / 2;
        let removed = enforce_size_limit(&conn, limit).unwrap();
        assert!(removed > 0 && removed < 4000, "removed {removed}");
        assert!(used_bytes(&conn).unwrap() <= limit / 10 * 9);

        let rows = search(&conn, &q(5000)).unwrap();
        assert_eq!(rows.len(), 4000 - removed);
        // The newest entry survives, and what remains is a contiguous newest range.
        assert_eq!(rows[0].ts, 3999);
        assert_eq!(rows.last().unwrap().ts, removed as i64);
        // The search index only returns what is still stored.
        let hits = |text: &str| {
            search(
                &conn,
                &Query {
                    text: Some(text.into()),
                    ..q(10)
                },
            )
            .unwrap()
            .len()
        };
        assert_eq!((hits("line 0"), hits("line 3999")), (0, 1));
    }

    #[test]
    fn purge_applies_each_severitys_own_cutoff() {
        let mut conn = mem();
        let batch: Vec<LogEntry> = (0..8)
            .flat_map(|sev| [entry(100, "h", sev, "old"), entry(900, "h", sev, "recent")])
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        // debug (7) and info (6) keep only entries newer than 500; error (3) newer than 50;
        // everything else is kept forever.
        let mut cutoffs = [None; 8];
        cutoffs[7] = Some(500);
        cutoffs[6] = Some(500);
        cutoffs[3] = Some(50);
        assert_eq!(
            purge(&conn, &cutoffs).unwrap(),
            2,
            "only old debug and info go"
        );
        let left = |sev: u8| {
            search(
                &conn,
                &Query {
                    max_severity: Some(sev),
                    ..q(100)
                },
            )
            .unwrap()
            .into_iter()
            .filter(|r| r.severity == sev)
            .count()
        };
        assert_eq!((left(7), left(6), left(3), left(0)), (1, 1, 2, 2));
        // The full-text index followed the deletions.
        let old = search(
            &conn,
            &Query {
                text: Some("old".into()),
                ..q(100)
            },
        )
        .unwrap();
        assert_eq!(old.len(), 6);
        // Cutoffs sharing a value are applied together; with none set nothing happens.
        assert_eq!(purge(&conn, &[None; 8]).unwrap(), 0);
        assert_eq!(purge(&conn, &[Some(950); 8]).unwrap(), 14);
    }

    #[test]
    fn fields_are_stored_searchable_and_filterable() {
        let mut conn = mem();
        let mut e = entry(1, "router", 6, "Blocked by Firewall");
        e.fields.insert("src".into(), "192.168.1.241".into());
        e.fields.insert("act".into(), "blocked".into());
        let mut other = entry(2, "router", 6, "Network Accessed");
        other.fields.insert("act".into(), "allowed".into());
        insert_batch(&mut conn, &[e, other, entry(3, "pve", 6, "plain")]).unwrap();

        let rows = search(
            &conn,
            &Query {
                fields: vec![("act".into(), "blocked".into())],
                ..q(10)
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fields.as_ref().unwrap()["src"], "192.168.1.241");

        // Field values are part of the full-text index.
        let by_text = Query {
            text: Some("192.168.1.241".into()),
            ..q(10)
        };
        assert_eq!(search(&conn, &by_text).unwrap().len(), 1);

        // Entries without fields serialize without a `fields` key and don't match filters.
        let all = search(&conn, &q(10)).unwrap();
        assert!(
            all.iter()
                .find(|r| r.host == "pve")
                .unwrap()
                .fields
                .is_none()
        );

        // Hostile keys are refused instead of reaching the JSON path.
        let bad = Query {
            fields: vec![("a\"] OR 1=1 --".into(), "x".into())],
            ..q(10)
        };
        assert!(search(&conn, &bad).is_err());
        assert!(
            valid_field_key("UNIFIcategory")
                && valid_field_key("cef_name")
                && !valid_field_key("a b")
        );
    }

    #[test]
    fn migrating_a_v1_database_keeps_and_reindexes_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(
            "BEGIN; {MIGRATION_1} PRAGMA user_version = 1; COMMIT;"
        ))
        .unwrap();
        conn.execute(
            "INSERT INTO logs (ts, host, app, severity, message) VALUES (1, 'h', 'a', 6, 'legacy entry')",
            [],
        )
        .unwrap();
        migrate(&conn).unwrap();
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let rows = search(
            &conn,
            &Query {
                text: Some("legacy".into()),
                ..q(10)
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].fields.is_none());
        assert_eq!(purge(&conn, &[Some(100); 8]).unwrap(), 1);
        assert!(
            search(
                &conn,
                &Query {
                    text: Some("legacy".into()),
                    ..q(10)
                }
            )
            .unwrap()
            .is_empty()
        );
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
