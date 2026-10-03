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
    register_functions(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// SQL functions used by search filters: `regexp(pattern, text)` (the `REGEXP` operator, the
/// pattern compiled once per statement) and `logpit_num(value)`, a value as a number or NULL.
fn register_functions(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    use rusqlite::types::ValueRef;
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("regexp", 2, flags, |ctx| {
        let re: std::sync::Arc<regex::Regex> = ctx.get_or_create_aux(0, |pattern| {
            let pattern = pattern.as_str().map_err(|e| e.to_string())?;
            crate::filters::compile_regex(pattern)
        })?;
        Ok(match ctx.get_raw(1) {
            ValueRef::Text(t) => Some(re.is_match(&String::from_utf8_lossy(t))),
            _ => None,
        })
    })?;
    conn.create_scalar_function("logpit_num", 1, flags, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Integer(i) => Some(i as f64),
            ValueRef::Real(r) => Some(r),
            ValueRef::Text(t) => std::str::from_utf8(t)
                .ok()
                .and_then(crate::filters::parse_number),
            _ => None,
        })
    })
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
    // Saved views live in an extra table that does not change the schema version, so an older
    // LogPit can still open the database (it simply ignores the table).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS views (
            id         INTEGER PRIMARY KEY,
            name       TEXT NOT NULL UNIQUE,
            query      TEXT NOT NULL,
            created_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id     INTEGER PRIMARY KEY,
            ts     INTEGER NOT NULL,
            token  TEXT,
            method TEXT NOT NULL,
            path   TEXT NOT NULL,
            query  TEXT NOT NULL,
            status INTEGER NOT NULL,
            peer   TEXT
        );
        CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY,
            ts        INTEGER NOT NULL,
            kind      TEXT NOT NULL,
            host      TEXT,
            message   TEXT NOT NULL,
            delivered INTEGER,
            details   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);",
    )?;
    // The e-mail outcome came later than the table: add its column to history written before.
    let has_email = conn
        .prepare("SELECT 1 FROM pragma_table_info('alerts') WHERE name = 'email'")?
        .exists([])?;
    if !has_email {
        conn.execute("ALTER TABLE alerts ADD COLUMN email INTEGER", [])?;
    }
    Ok(())
}

/// Appends audit events in one transaction.
pub fn insert_audit(conn: &mut Connection, events: &[crate::audit::Event]) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO audit (ts, token, method, path, query, status, peer) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for e in events {
            stmt.execute(params![
                e.ts, e.token, e.method, e.path, e.query, e.status, e.peer
            ])?;
        }
    }
    tx.commit()
}

/// The newest audit events matching `q`, newest first.
pub fn audit_events(
    conn: &Connection,
    q: &crate::audit::AuditQuery,
) -> rusqlite::Result<Vec<crate::audit::Event>> {
    let mut stmt = conn.prepare(
        "SELECT ts, token, method, path, query, status, peer FROM audit \
         WHERE (?1 IS NULL OR ts >= ?1) AND (?2 IS NULL OR ts <= ?2) \
           AND (?3 IS NULL OR token = ?3) AND (?4 = 0 OR status IN (401, 403)) \
         ORDER BY ts DESC, id DESC LIMIT ?5",
    )?;
    let rows = stmt.query_map(
        params![
            q.since_ms,
            q.until_ms,
            q.token,
            q.refused,
            i64::try_from(q.limit).unwrap_or(i64::MAX)
        ],
        |r| {
            Ok(crate::audit::Event {
                ts: r.get(0)?,
                token: r.get(1)?,
                method: r.get(2)?,
                path: r.get(3)?,
                query: r.get(4)?,
                status: r.get(5)?,
                peer: r.get(6)?,
            })
        },
    )?;
    rows.collect()
}

/// Records a raised notification.
pub fn insert_alert(conn: &Connection, e: &crate::alertlog::AlertEntry) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO alerts (ts, kind, host, message, delivered, email, details) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            e.ts,
            e.kind,
            e.host,
            e.message,
            e.delivered,
            e.email,
            e.details.to_string()
        ],
    )?;
    Ok(())
}

/// The newest notifications matching `q`, newest first.
pub fn alert_events(
    conn: &Connection,
    q: &crate::alertlog::AlertQuery,
) -> rusqlite::Result<Vec<crate::alertlog::AlertEntry>> {
    let mut stmt = conn.prepare(
        "SELECT ts, kind, host, message, delivered, details, email FROM alerts \
         WHERE (?1 IS NULL OR ts >= ?1) AND (?2 IS NULL OR ts <= ?2) \
           AND (?3 IS NULL OR kind = ?3) AND (?4 IS NULL OR host = ?4) \
         ORDER BY ts DESC, id DESC LIMIT ?5",
    )?;
    let rows = stmt.query_map(
        params![
            q.since_ms,
            q.until_ms,
            q.kind,
            q.host,
            i64::try_from(q.limit).unwrap_or(i64::MAX)
        ],
        |r| {
            Ok(crate::alertlog::AlertEntry {
                ts: r.get(0)?,
                kind: r.get(1)?,
                host: r.get(2)?,
                message: r.get(3)?,
                delivered: r.get(4)?,
                details: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                email: r.get(6)?,
            })
        },
    )?;
    rows.collect()
}

/// Deletes notifications older than `cutoff_ms`; returns how many.
pub fn purge_alerts(conn: &Connection, cutoff_ms: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM alerts WHERE ts < ?", [cutoff_ms])
}

/// Deletes audit events older than `cutoff_ms`; returns how many.
pub fn purge_audit(conn: &Connection, cutoff_ms: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM audit WHERE ts < ?", [cutoff_ms])
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

/// How often the writer checks for a stop request while it waits for entries.
const STOP_POLL: Duration = Duration::from_millis(100);
/// Entries the writer keeps for a retry while the database is locked; beyond this a failing
/// batch is dropped (and counted), so a database that stays locked cannot exhaust memory.
const MAX_RETAINED_FACTOR: usize = 10;

/// Drains the queue into the database until every sender is dropped or `stop` is set, then
/// flushes. On `stop` the entries already queued are written first; senders that are still
/// alive (an open TCP or HTTP connection) do not keep it running.
pub fn run_writer(
    mut conn: Connection,
    rx: Receiver<LogEntry>,
    batch_size: usize,
    flush_interval: Duration,
    metrics: Arc<Metrics>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut batch: Vec<LogEntry> = Vec::with_capacity(batch_size);
    let mut deadline = Instant::now() + flush_interval;
    let max_retained = batch_size.saturating_mul(MAX_RETAINED_FACTOR);
    loop {
        if stop.load(Ordering::Acquire) {
            batch.extend(rx.try_iter());
            flush(&mut conn, &mut batch, &metrics, 0);
            return;
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(STOP_POLL);
        let disconnected = match rx.recv_timeout(timeout) {
            Ok(entry) => {
                batch.push(entry);
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        if disconnected || batch.len() >= batch_size || Instant::now() >= deadline {
            flush(
                &mut conn,
                &mut batch,
                &metrics,
                if disconnected { 0 } else { max_retained },
            );
            deadline = Instant::now() + flush_interval;
        }
        if disconnected {
            return;
        }
    }
}

/// Writes `batch`. When the database is busy or locked (a purge, a backup, another process)
/// the batch is kept for the next attempt as long as it holds fewer than `retain` entries;
/// any other failure drops it.
fn flush(conn: &mut Connection, batch: &mut Vec<LogEntry>, metrics: &Metrics, retain: usize) {
    if batch.is_empty() {
        return;
    }
    match insert_batch(conn, batch) {
        Ok(()) => Metrics::inc(&metrics.stored, batch.len() as u64),
        Err(e) => {
            metrics.write_errors.fetch_add(1, Ordering::Relaxed);
            let busy = matches!(
                e.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            );
            if busy && batch.len() < retain {
                tracing::warn!(
                    "database busy, keeping {} entries for the next write: {e}",
                    batch.len()
                );
                return;
            }
            tracing::error!("failed to write batch of {}: {e}", batch.len());
        }
    }
    batch.clear();
}

/// Distinct hosts present in the database, at most `limit`.
pub fn known_hosts(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT DISTINCT host FROM logs LIMIT ?")?;
    stmt.query_map([limit as i64], |r| r.get(0))?.collect()
}

/// Called with each chunk of entries about to be deleted; an error stops the deletion.
pub type ArchiveHook<'a> = &'a dyn Fn(&[Row]) -> anyhow::Result<()>;

/// Entries deleted (and archived) per transaction by [`purge`].
const PURGE_CHUNK: i64 = 5000;

/// A retention rule for [`purge_rules`]: entries matching all of its conditions are kept until
/// `cutoff` (Unix ms), or forever when it is `None`. An empty list matches anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeRule {
    /// Host names or patterns (`*`, `?`).
    pub hosts: Vec<String>,
    /// App names or patterns.
    pub apps: Vec<String>,
    pub severities: Vec<u8>,
    pub cutoff: Option<i64>,
}

/// The condition for entries matching `rule`, with its arguments appended to `args`.
fn rule_match_sql(rule: &PurgeRule, args: &mut Vec<Box<dyn ToSql>>) -> String {
    let mut parts = Vec::new();
    parts.extend(pattern_condition("l.host", &rule.hosts, None, args));
    parts.extend(pattern_condition("l.app", &rule.apps, None, args));
    if !rule.severities.is_empty() {
        let list: Vec<String> = rule.severities.iter().map(u8::to_string).collect();
        parts.push(format!("l.severity IN ({})", list.join(",")));
    }
    if parts.is_empty() {
        "1".to_string()
    } else {
        format!("({})", parts.join(" AND "))
    }
}

/// Deletes the entries `predicate` selects (anonymous `?` placeholders filled from `args`, the
/// table aliased `l`), a chunk at a time, archiving each chunk first when asked.
fn purge_predicate(
    conn: &Connection,
    predicate: &str,
    args: Vec<Box<dyn ToSql>>,
    archive: Option<ArchiveHook<'_>>,
) -> anyhow::Result<usize> {
    fn refs<'a>(args: &'a [Box<dyn ToSql>], extra: Option<&'a i64>) -> Vec<&'a dyn ToSql> {
        let mut v: Vec<&dyn ToSql> = args.iter().map(|a| a.as_ref()).collect();
        v.extend(extra.map(|e| e as &dyn ToSql));
        v
    }
    let mut removed = 0;
    loop {
        let n = match archive {
            None => conn.execute(
                &format!(
                    "DELETE FROM logs WHERE id IN \
                     (SELECT l.id FROM logs l WHERE {predicate} LIMIT {PURGE_CHUNK})"
                ),
                params_from_iter(refs(&args, None)),
            )?,
            Some(archive) => {
                let rows = {
                    let mut stmt = conn.prepare(&format!(
                        "SELECT l.id, l.ts, l.host, l.app, l.severity, l.message, l.fields \
                         FROM logs l WHERE {predicate} ORDER BY l.id LIMIT {PURGE_CHUNK}"
                    ))?;
                    stmt.query_map(params_from_iter(refs(&args, None)), map_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                let Some(last) = rows.last().map(|r| r.id) else {
                    break;
                };
                archive(&rows)?;
                // The chunk is the first rows by id that match, so this is exactly that chunk.
                conn.execute(
                    &format!(
                        "DELETE FROM logs WHERE id IN \
                         (SELECT l.id FROM logs l WHERE {predicate} AND l.id <= ?)"
                    ),
                    params_from_iter(refs(&args, Some(&last))),
                )?
            }
        };
        removed += n;
        if (n as i64) < PURGE_CHUNK {
            break;
        }
    }
    Ok(removed)
}

/// Deletes entries older than the cutoff of their severity (`cutoffs[severity]`, in Unix ms;
/// `None` keeps that severity forever) and returns how many. With `archive`, each chunk is handed
/// to it first and deleted only once it accepted it; a failing `archive` stops the purge.
/// Work goes a chunk at a time, each a short transaction, so the writer never waits on a long
/// purge (an hour of backlog, or a lowered retention, can be millions of entries).
pub fn purge(
    conn: &Connection,
    cutoffs: &[Option<i64>; 8],
    archive: Option<ArchiveHook<'_>>,
) -> anyhow::Result<usize> {
    purge_rules(conn, &[], cutoffs, archive)
}

/// Like [`purge`], with `rules` in front: an entry is judged by the first rule it matches (kept
/// until its cutoff, or forever), and only entries that match no rule fall back to the cutoff of
/// their severity.
pub fn purge_rules(
    conn: &Connection,
    rules: &[PurgeRule],
    cutoffs: &[Option<i64>; 8],
    archive: Option<ArchiveHook<'_>>,
) -> anyhow::Result<usize> {
    let mut removed = 0;
    // The rules that come before: what an entry must not match to be judged by a later one.
    let not_earlier = |upto: usize, args: &mut Vec<Box<dyn ToSql>>| -> String {
        if upto == 0 {
            return String::new();
        }
        let parts: Vec<String> = rules[..upto]
            .iter()
            .map(|r| rule_match_sql(r, args))
            .collect();
        format!(" AND NOT ({})", parts.join(" OR "))
    };
    for (i, rule) in rules.iter().enumerate() {
        let Some(cutoff) = rule.cutoff else {
            continue;
        };
        let mut args: Vec<Box<dyn ToSql>> = vec![Box::new(cutoff)];
        let own = rule_match_sql(rule, &mut args);
        let earlier = not_earlier(i, &mut args);
        removed += purge_predicate(conn, &format!("l.ts < ? AND {own}{earlier}"), args, archive)?;
    }
    let mut done = [false; 8];
    for first in 0..8 {
        let Some(cutoff) = cutoffs[first] else {
            continue;
        };
        if done[first] {
            continue;
        }
        // One pass per distinct cutoff, covering every severity that shares it.
        let severities: Vec<String> = (first..8)
            .filter(|&s| cutoffs[s] == Some(cutoff))
            .inspect(|&s| done[s] = true)
            .map(|s| s.to_string())
            .collect();
        let mut args: Vec<Box<dyn ToSql>> = vec![Box::new(cutoff)];
        let earlier = not_earlier(rules.len(), &mut args);
        removed += purge_predicate(
            conn,
            &format!(
                "l.ts < ? AND l.severity IN ({}){earlier}",
                severities.join(",")
            ),
            args,
            archive,
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

/// SQL for the value an entry is grouped under; empty text when it has none.
fn group_sql(group: &GroupBy) -> rusqlite::Result<String> {
    Ok(match group {
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
    })
}

/// Entries per host in each of the `windows` complete windows of `window_ms` before `now_ms`,
/// oldest window first (windows aligned to the Unix epoch), for seeding volume baselines.
pub fn host_window_counts(
    conn: &Connection,
    now_ms: i64,
    window_ms: i64,
    windows: usize,
) -> rusqlite::Result<Vec<(String, Vec<u64>)>> {
    let last = now_ms.div_euclid(window_ms); // the window in progress
    let first = last - windows as i64;
    let mut stmt = conn.prepare(
        "SELECT host, ts / ?1 AS b, COUNT(*) FROM logs WHERE ts >= ?2 AND ts < ?3 GROUP BY host, b",
    )?;
    let rows = stmt.query_map(
        params![window_ms, first * window_ms, last * window_ms],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)? as u64,
            ))
        },
    )?;
    let mut hosts: std::collections::BTreeMap<String, Vec<u64>> = std::collections::BTreeMap::new();
    for row in rows {
        let (host, bucket, n) = row?;
        let idx = usize::try_from(bucket - first)
            .unwrap_or(0)
            .min(windows - 1);
        hosts.entry(host).or_insert_with(|| vec![0; windows])[idx] += n;
    }
    Ok(hosts.into_iter().collect())
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
    let group_expr = group_sql(group)?;
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

/// Counts of the entries matching `q` per bucket and per tuple of group values, for metric
/// queries: bucket `i` covers `(origin_ms + i * bucket_ms, origin_ms + (i + 1) * bucket_ms]`, and
/// `q` must keep only entries after `origin_ms`. Empty buckets are not returned.
pub fn series(
    conn: &Connection,
    q: &Query,
    origin_ms: i64,
    bucket_ms: i64,
    groups: &[GroupBy],
) -> rusqlite::Result<Vec<(i64, Vec<String>, u64)>> {
    let exprs = groups
        .iter()
        .map(group_sql)
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let select: String = exprs
        .iter()
        .enumerate()
        .map(|(i, e)| format!(", {e} AS g{i}"))
        .collect();
    let by: String = (0..exprs.len()).map(|i| format!(", g{i}")).collect();
    let filter = Filter::new(q)?;
    // Both numbers are i64 formatted by us, never user text.
    let sql = format!(
        "SELECT (l.ts - {origin_ms} - 1) / {bucket_ms} AS b{select}, COUNT(*) \
         FROM logs l{} GROUP BY b{by} ORDER BY b",
        filter.sql()
    );
    let mut stmt = conn.prepare(&sql)?;
    let n = exprs.len();
    let rows = stmt.query_map(
        params_from_iter(filter.args.iter().map(|a| a.as_ref())),
        |r| {
            let labels = (0..n)
                .map(|i| r.get::<_, String>(i + 1))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((r.get(0)?, labels, r.get::<_, i64>(n + 1)? as u64))
        },
    )?;
    rows.collect()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct HostSummary {
    pub host: String,
    pub count: u64,
    /// Entries of severity 0-3 (emergency to error).
    pub errors: u64,
    /// Entries of severity 4 (warning).
    pub warnings: u64,
    /// Timestamp of the host's most recent matching entry, Unix ms.
    pub last_ts: i64,
    /// Whether the silence alert is firing for this host; absent when alerts are off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,
    /// The `[[tags]]` the host belongs to; filled in by the API, not the database.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Column of the per-host summary to order by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSortKey {
    Host,
    Count,
    Errors,
    Warnings,
    LastTs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSort {
    pub key: HostSortKey,
    pub desc: bool,
}

impl Default for HostSort {
    /// Busiest hosts first.
    fn default() -> Self {
        Self {
            key: HostSortKey::Count,
            desc: true,
        }
    }
}

impl HostSort {
    /// Text sorts ascending first, numbers and dates descending first.
    pub fn natural(key: HostSortKey) -> Self {
        Self {
            key,
            desc: key != HostSortKey::Host,
        }
    }
}

/// Per-host totals over the entries matching `q`, ordered by `sort` (ties by host name), at
/// most `q.limit` hosts. The limit applies after sorting, so `LastTs` ascending lists the
/// quietest hosts even when there are more hosts than the limit.
pub fn host_summary(
    conn: &Connection,
    q: &Query,
    sort: HostSort,
) -> rusqlite::Result<Vec<HostSummary>> {
    let mut filter = Filter::new(q)?;
    let column = match sort.key {
        HostSortKey::Host => "l.host",
        HostSortKey::Count => "n",
        HostSortKey::Errors => "errors",
        HostSortKey::Warnings => "warnings",
        HostSortKey::LastTs => "last_ts",
    };
    let dir = if sort.desc { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT l.host, COUNT(*) AS n, COALESCE(SUM(l.severity <= 3), 0) AS errors, \
         COALESCE(SUM(l.severity = 4), 0) AS warnings, MAX(l.ts) AS last_ts FROM logs l{} \
         GROUP BY l.host ORDER BY {column} {dir}, l.host LIMIT ?",
        filter.sql()
    );
    filter.args.push(Box::new(q.limit as i64));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params_from_iter(filter.args.iter().map(|a| a.as_ref())),
        |r| {
            Ok(HostSummary {
                host: r.get(0)?,
                count: r.get::<_, i64>(1)? as u64,
                errors: r.get::<_, i64>(2)? as u64,
                warnings: r.get::<_, i64>(3)? as u64,
                last_ts: r.get(4)?,
                silent: None,
                tags: Vec::new(),
            })
        },
    )?;
    rows.collect()
}

#[derive(Debug, Serialize)]
pub struct EntryContext {
    pub entry: Row,
    /// The entries just before it, oldest first.
    pub before: Vec<Row>,
    /// The entries just after it, oldest first.
    pub after: Vec<Row>,
}

/// An entry with up to `lines` neighbours on each side, in the order logs are searched
/// (timestamp, then id). With `same_host` only the entry's own host is considered, which is
/// what reading one machine's log needs. `None` when no entry has that id.
pub fn context(
    conn: &Connection,
    id: i64,
    lines: usize,
    same_host: bool,
    access: &crate::auth::Access,
) -> rusqlite::Result<Option<EntryContext>> {
    const COLUMNS: &str = "l.id, l.ts, l.host, l.app, l.severity, l.message, l.fields";
    let entry = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM logs l WHERE l.id = ?1"),
            [id],
            map_row,
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    // An entry the caller may not read is reported as absent, like one that does not exist.
    let Some(entry) = entry.filter(|e| access.allows(&e.host, &e.app)) else {
        return Ok(None);
    };
    let host = if same_host { " AND l.host = ?4" } else { "" };
    let (limits, limit_args) = access_conditions(access, Some(if same_host { 5 } else { 4 }));
    let limits: String = limits.iter().map(|c| format!(" AND {c}")).collect();
    let side = |cmp: &str, order: &str| -> rusqlite::Result<Vec<Row>> {
        // Placeholders ?1..?3 (and ?4 for the host) come first, the access ones follow them.
        let sql = format!(
            "SELECT {COLUMNS} FROM logs l WHERE (l.ts, l.id) {cmp} (?1, ?2){host}{limits} \
             ORDER BY l.ts {order}, l.id {order} LIMIT ?3"
        );
        let limit = i64::try_from(lines).unwrap_or(i64::MAX);
        let mut args: Vec<&dyn ToSql> = vec![&entry.ts, &entry.id, &limit];
        if same_host {
            args.push(&entry.host);
        }
        args.extend(limit_args.iter().map(|a| a.as_ref()));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), map_row)?;
        rows.collect()
    };
    let mut before = side("<", "DESC")?;
    before.reverse();
    let after = side(">", "ASC")?;
    Ok(Some(EntryContext {
        entry,
        before,
        after,
    }))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TopValues {
    /// Entries matching the filters.
    pub matching: u64,
    /// Of those, the ones that have a value for the field.
    pub with_field: u64,
    /// Distinct values of the field among them.
    pub distinct: u64,
    /// The most frequent values, most frequent first (ties by value).
    pub values: Vec<TopValue>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TopValue {
    pub value: String,
    pub count: u64,
}

/// The `limit` most frequent values of `group` among the entries matching `q`.
pub fn top_values(
    conn: &Connection,
    q: &Query,
    group: &GroupBy,
    limit: usize,
) -> rusqlite::Result<TopValues> {
    let expr = group_sql(group)?;
    let top = {
        let mut filter = Filter::new(q)?;
        let sql = format!(
            "SELECT {expr} AS v, COUNT(*) AS n FROM logs l{} GROUP BY v HAVING v != '' \
             ORDER BY n DESC, v LIMIT ?",
            filter.sql()
        );
        filter
            .args
            .push(Box::new(i64::try_from(limit).unwrap_or(i64::MAX)));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params_from_iter(filter.args.iter().map(|a| a.as_ref())),
            |r| {
                Ok(TopValue {
                    value: r.get(0)?,
                    count: r.get::<_, i64>(1)? as u64,
                })
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let filter = Filter::new(q)?;
    let sql = format!(
        "SELECT COUNT(*), COALESCE(SUM(v != ''), 0), COUNT(DISTINCT NULLIF(v, '')) \
         FROM (SELECT {expr} AS v FROM logs l{})",
        filter.sql()
    );
    let (matching, with_field, distinct) = conn.query_row(
        &sql,
        params_from_iter(filter.args.iter().map(|a| a.as_ref())),
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        },
    )?;
    Ok(TopValues {
        matching: matching as u64,
        with_field: with_field as u64,
        distinct: distinct as u64,
        values: top,
    })
}

/// The newest `limit` entries matching `q` (newest first) with their message cut to
/// `max_chars`, for pattern analysis: no fields are read. The flag tells whether more matched.
pub fn recent_samples(
    conn: &Connection,
    q: &Query,
    limit: usize,
    max_chars: usize,
) -> rusqlite::Result<(Vec<crate::patterns::Sample>, bool)> {
    let mut filter = Filter::new(q)?;
    let sql = format!(
        "SELECT l.id, l.ts, l.host, l.severity, substr(l.message, 1, ?) FROM logs l{} \
         ORDER BY l.ts DESC, l.id DESC LIMIT ?",
        filter.sql()
    );
    // The message length is the first placeholder of the statement, ahead of the filter's.
    filter
        .args
        .insert(0, Box::new(i64::try_from(max_chars).unwrap_or(i64::MAX)));
    filter
        .args
        .push(Box::new(i64::try_from(limit + 1).unwrap_or(i64::MAX)));
    let mut stmt = conn.prepare(&sql)?;
    let mut samples = stmt
        .query_map(
            params_from_iter(filter.args.iter().map(|a| a.as_ref())),
            |r| {
                Ok(crate::patterns::Sample {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    host: r.get(2)?,
                    severity: r.get(3)?,
                    message: r.get(4)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let truncated = samples.len() > limit;
    samples.truncate(limit);
    Ok((samples, truncated))
}

/// The structured field names present in the entries matching `q`, with how many entries carry
/// each, most common first.
pub fn field_names(
    conn: &Connection,
    q: &Query,
    limit: usize,
) -> rusqlite::Result<Vec<(String, u64)>> {
    let mut filter = Filter::new(q)?;
    let sql = format!(
        "SELECT j.key, COUNT(*) AS n FROM logs l, json_each(l.fields) AS j{} \
         GROUP BY j.key ORDER BY n DESC, j.key LIMIT ?",
        filter.sql()
    );
    filter
        .args
        .push(Box::new(i64::try_from(limit).unwrap_or(i64::MAX)));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params_from_iter(filter.args.iter().map(|a| a.as_ref())),
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)),
    )?;
    rows.collect()
}

/// A saved search: the query string of the web UI (filters, time range, chart grouping).
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct View {
    pub id: i64,
    pub name: String,
    pub query: String,
    pub created_ts: i64,
}

/// At most this many views are kept.
pub const MAX_VIEWS: usize = 100;

pub fn list_views(conn: &Connection) -> rusqlite::Result<Vec<View>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, query, created_ts FROM views ORDER BY name COLLATE NOCASE, id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(View {
            id: r.get(0)?,
            name: r.get(1)?,
            query: r.get(2)?,
            created_ts: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// Saves a view under `name`, replacing the query of an existing view with that name. `Ok(None)`
/// when it would be a new view beyond [`MAX_VIEWS`].
pub fn save_view(
    conn: &Connection,
    name: &str,
    query: &str,
    now: i64,
) -> rusqlite::Result<Option<View>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM views WHERE name = ?1)",
        [name],
        |r| r.get(0),
    )?;
    if !exists {
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM views", [], |r| r.get(0))?;
        if n as usize >= MAX_VIEWS {
            return Ok(None);
        }
    }
    conn.execute(
        "INSERT INTO views (name, query, created_ts) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO UPDATE SET query = excluded.query",
        params![name, query, now],
    )?;
    conn.query_row(
        "SELECT id, name, query, created_ts FROM views WHERE name = ?1",
        [name],
        |r| {
            Ok(View {
                id: r.get(0)?,
                name: r.get(1)?,
                query: r.get(2)?,
                created_ts: r.get(3)?,
            })
        },
    )
    .map(Some)
}

/// Deletes a view; false when there was none with that id.
pub fn delete_view(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM views WHERE id = ?1", [id])? > 0)
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
pub fn enforce_size_limit(
    conn: &Connection,
    max_bytes: u64,
    archive: Option<ArchiveHook<'_>>,
) -> anyhow::Result<usize> {
    if used_bytes(conn)? <= max_bytes {
        return Ok(0);
    }
    let target = max_bytes / 10 * 9;
    let (mut removed, mut stalls) = (0, 0);
    let mut used = used_bytes(conn)?;
    for _ in 0..EVICT_MAX_CHUNKS {
        let n = match archive {
            None => conn.execute(
                "DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY ts, id LIMIT ?1)",
                params![EVICT_CHUNK],
            )?,
            // Archive the oldest chunk, then delete exactly those entries.
            Some(hook) => {
                let rows = {
                    let mut stmt = conn.prepare(
                        "SELECT id, ts, host, app, severity, message, fields FROM logs \
                         ORDER BY ts, id LIMIT ?1",
                    )?;
                    stmt.query_map(params![EVICT_CHUNK], map_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                if rows.is_empty() {
                    0
                } else {
                    hook(&rows)?;
                    let ids =
                        serde_json::to_string(&rows.iter().map(|r| r.id).collect::<Vec<_>>())?;
                    conn.execute(
                        "DELETE FROM logs WHERE id IN (SELECT value FROM json_each(?1))",
                        params![ids],
                    )?
                }
            }
        };
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
    /// Comparisons and regular expressions on structured fields; all must match as well.
    pub compare: Vec<crate::filters::FieldFilter>,
    /// The message must match this regular expression.
    pub message_re: Option<regex::Regex>,
    /// Conditions on the message text (LogQL line filters) and on the host and app columns beyond
    /// exact equality; all must hold.
    pub line_filters: Vec<crate::filters::LineFilter>,
    pub column_filters: Vec<crate::filters::ColumnFilter>,
    /// Keep only entries whose severity is in this set (`None`: any).
    pub severities: Option<Vec<u8>>,
    /// Cursor for paging: keep only entries older than `(ts, id)`, as in search order.
    pub before: Option<(i64, i64)>,
    /// What the caller may read, on top of the filters above (unrestricted by default).
    pub access: crate::auth::Access,
    /// Tag names asked for (`tag=` in the API); the API turns them into `host_globs`.
    pub tags: Vec<String>,
    /// The host must match one of these names or patterns (the hosts of the tags asked for).
    pub host_globs: Vec<String>,
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
        if !self.access.allows(&e.host, &e.app) {
            return false;
        }
        if !self.host_globs.is_empty()
            && !self
                .host_globs
                .iter()
                .any(|p| crate::tags::glob_match(p, &e.host))
        {
            return false;
        }
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
        if !self.line_filters.iter().all(|f| f.matches(&e.message))
            || !self
                .column_filters
                .iter()
                .all(|f| f.matches(&e.host, &e.app))
            || self
                .severities
                .as_ref()
                .is_some_and(|set| !set.contains(&e.severity))
        {
            return false;
        }
        if !self.compare.iter().all(|f| f.matches(&e.fields))
            || self
                .message_re
                .as_ref()
                .is_some_and(|re| !re.is_match(&e.message))
        {
            return false;
        }
        match self.text.as_deref().map(crate::query::parse) {
            Some(parsed) if !parsed.is_empty() => {
                let hay = std::iter::once(e.message.as_str())
                    .chain(e.fields.values().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join("\n")
                    .to_lowercase();
                parsed.matches(&hay)
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

/// The FROM-join and WHERE conditions shared by search and stats for one query.
struct Filter {
    join_fts: bool,
    conds: Vec<&'static str>,
    /// Conditions built at run time (the caller's access); their arguments come last in `args`.
    dynamic: Vec<String>,
    args: Vec<Box<dyn ToSql>>,
}

/// Conditions limiting `l.host` and `l.app` to what `access` allows, and their arguments in
/// placeholder order. With `first`, placeholders are numbered from it (`?5`, `?6`…), which a
/// statement that already uses numbered ones needs; otherwise they are anonymous.
fn access_conditions(
    access: &crate::auth::Access,
    first: Option<usize>,
) -> (Vec<String>, Vec<Box<dyn ToSql>>) {
    let (mut conds, mut args) = (Vec::new(), Vec::<Box<dyn ToSql>>::new());
    if let Some(cond) = pattern_condition("l.host", &access.hosts, first, &mut args) {
        conds.push(cond);
    }
    if let Some(cond) = pattern_condition("l.app", &access.apps, first, &mut args) {
        conds.push(cond);
    }
    (conds, args)
}

/// An SQLite `GLOB` pattern equivalent to the host pattern: `*` and `?` stay wildcards, and a `[`
/// that GLOB would read as a character class is made literal.
fn glob_for_sql(pattern: &str) -> String {
    pattern.replace('[', "[[]")
}

/// `(column IN (…) OR column GLOB ? OR …)` for names and patterns, pushing the arguments
/// (placeholders are numbered from `first` when given); `None` for an empty list.
fn pattern_condition(
    column: &str,
    patterns: &[String],
    first: Option<usize>,
    args: &mut Vec<Box<dyn ToSql>>,
) -> Option<String> {
    if patterns.is_empty() {
        return None;
    }
    let mark = |args: &Vec<Box<dyn ToSql>>| match first {
        Some(n) => format!("?{}", n + args.len()),
        None => "?".to_string(),
    };
    let (exact, wild): (Vec<&String>, Vec<&String>) =
        patterns.iter().partition(|p| !crate::tags::is_wildcard(p));
    let mut parts = Vec::new();
    if !exact.is_empty() {
        let mut marks = Vec::new();
        for p in exact {
            marks.push(mark(args));
            args.push(Box::new(p.clone()));
        }
        parts.push(format!("{column} IN ({})", marks.join(",")));
    }
    for p in wild {
        parts.push(format!("{column} GLOB {}", mark(args)));
        args.push(Box::new(glob_for_sql(p)));
    }
    Some(format!("({})", parts.join(" OR ")))
}

impl Filter {
    fn new(q: &Query) -> rusqlite::Result<Self> {
        let mut f = Filter {
            join_fts: false,
            conds: Vec::new(),
            dynamic: Vec::new(),
            args: Vec::new(),
        };
        let text = q
            .text
            .as_deref()
            .map(crate::query::parse)
            .unwrap_or_default();
        if let Some(fts) = text.fts_include() {
            f.join_fts = true;
            f.conds.push("logs_fts MATCH ?");
            f.args.push(Box::new(fts));
        }
        if let Some(fts) = text.fts_exclude() {
            f.conds
                .push("l.id NOT IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)");
            f.args.push(Box::new(fts));
        }
        if let Some((ts, id)) = q.before {
            f.conds.push("(l.ts, l.id) < (?, ?)");
            f.args.push(Box::new(ts));
            f.args.push(Box::new(id));
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
        for cf in &q.compare {
            use crate::filters::Op;
            if !valid_field_key(&cf.key) {
                return Err(rusqlite::Error::InvalidParameterName(cf.key.clone()));
            }
            let path = format!("$.\"{}\"", cf.key);
            // A field the entry does not have never satisfies a comparison (NULL is not true).
            match cf.op {
                Op::Ne => {
                    f.conds.push(
                        "(json_extract(l.fields, ?) IS NOT NULL AND json_extract(l.fields, ?) != ?)",
                    );
                    f.args.push(Box::new(path.clone()));
                    f.args.push(Box::new(path));
                    f.args.push(Box::new(cf.value.clone()));
                }
                Op::Re => {
                    f.conds.push("json_extract(l.fields, ?) REGEXP ?");
                    f.args.push(Box::new(path));
                    f.args.push(Box::new(cf.value.clone()));
                }
                op => {
                    f.conds.push(match op {
                        Op::Gt => "logpit_num(json_extract(l.fields, ?)) > ?",
                        Op::Ge => "logpit_num(json_extract(l.fields, ?)) >= ?",
                        Op::Lt => "logpit_num(json_extract(l.fields, ?)) < ?",
                        _ => "logpit_num(json_extract(l.fields, ?)) <= ?",
                    });
                    f.args.push(Box::new(path));
                    f.args.push(Box::new(cf.number.unwrap_or(0.0)));
                }
            }
        }
        if let Some(re) = &q.message_re {
            f.conds.push("l.message REGEXP ?");
            f.args.push(Box::new(re.as_str().to_string()));
        }
        let (dynamic, args) = access_conditions(&q.access, None);
        f.dynamic = dynamic;
        f.args.extend(args);
        if let Some(cond) = pattern_condition("l.host", &q.host_globs, None, &mut f.args) {
            f.dynamic.push(cond);
        }
        for lf in &q.line_filters {
            use crate::filters::LineOp;
            f.dynamic.push(
                match lf.op {
                    LineOp::Contains => "instr(l.message, ?) > 0",
                    LineOp::NotContains => "instr(l.message, ?) = 0",
                    LineOp::Re => "l.message REGEXP ?",
                    LineOp::NotRe => "NOT (l.message REGEXP ?)",
                }
                .to_string(),
            );
            f.args.push(Box::new(lf.value.clone()));
        }
        for cf in &q.column_filters {
            use crate::filters::{Column, ColumnMatch};
            let col = match cf.column {
                Column::Host => "l.host",
                Column::App => "l.app",
            };
            let (cond, arg) = match &cf.matcher {
                ColumnMatch::Eq(v) => (format!("{col} = ?"), v.clone()),
                ColumnMatch::Ne(v) => (format!("{col} != ?"), v.clone()),
                ColumnMatch::Re(re) => (format!("{col} REGEXP ?"), re.as_str().to_string()),
                ColumnMatch::NotRe(re) => {
                    (format!("NOT ({col} REGEXP ?)"), re.as_str().to_string())
                }
            };
            f.dynamic.push(cond);
            f.args.push(Box::new(arg));
        }
        if let Some(set) = &q.severities {
            // Severities are small integers, so they are written into the statement.
            f.dynamic.push(if set.is_empty() {
                "0".to_string()
            } else {
                let list: Vec<String> = set.iter().map(u8::to_string).collect();
                format!("l.severity IN ({})", list.join(","))
            });
        }
        Ok(f)
    }

    /// ` JOIN …` plus ` WHERE …`, to append after `FROM logs l`.
    fn sql(&self) -> String {
        let mut sql = String::new();
        if self.join_fts {
            sql.push_str(" JOIN logs_fts f ON f.rowid = l.id");
        }
        let conds: Vec<&str> = self
            .conds
            .iter()
            .copied()
            .chain(self.dynamic.iter().map(String::as_str))
            .collect();
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        sql
    }
}

pub fn search(conn: &Connection, q: &Query) -> rusqlite::Result<Vec<Row>> {
    search_ordered(conn, q, false)
}

/// Like [`search`], oldest first when `ascending`.
pub fn search_ordered(conn: &Connection, q: &Query, ascending: bool) -> rusqlite::Result<Vec<Row>> {
    let mut filter = Filter::new(q)?;
    let mut sql = String::from(
        "SELECT l.id, l.ts, l.host, l.app, l.severity, l.message, l.fields FROM logs l",
    );
    sql.push_str(&filter.sql());
    sql.push_str(if ascending {
        " ORDER BY l.ts ASC, l.id ASC LIMIT ?"
    } else {
        " ORDER BY l.ts DESC, l.id DESC LIMIT ?"
    });
    filter.args.push(Box::new(q.limit as i64));
    let args = filter.args;

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter().map(|a| a.as_ref())), map_row)?;
    rows.collect()
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
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
}

/// Visits the entries matching `q` oldest first, without loading them all in memory, stopping
/// early when `each` returns false or after `limit` entries. Returns how many were visited.
pub fn export_rows(
    conn: &Connection,
    q: &Query,
    limit: Option<u64>,
    each: &mut dyn FnMut(Row) -> bool,
) -> rusqlite::Result<u64> {
    let mut filter = Filter::new(q)?;
    let mut sql = String::from(
        "SELECT l.id, l.ts, l.host, l.app, l.severity, l.message, l.fields FROM logs l",
    );
    sql.push_str(&filter.sql());
    sql.push_str(" ORDER BY l.ts, l.id");
    if let Some(n) = limit {
        sql.push_str(" LIMIT ?");
        filter
            .args
            .push(Box::new(i64::try_from(n).unwrap_or(i64::MAX)));
    }
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(filter.args.iter().map(|a| a.as_ref())))?;
    let mut n = 0;
    while let Some(r) = rows.next()? {
        n += 1;
        if !each(map_row(r)?) {
            break;
        }
    }
    Ok(n)
}

/// Writes a consistent copy of the database at `db` to the new file `dest` (`VACUUM INTO`),
/// which is safe while LogPit is running, then checks the copy. Returns its size in bytes.
/// The schema is not migrated and an existing `dest` is never overwritten.
pub fn backup(db: &Path, dest: &Path) -> anyhow::Result<u64> {
    use rusqlite::OpenFlags;
    if !db.exists() {
        anyhow::bail!("database {} does not exist", db.display());
    }
    if dest.exists() {
        anyhow::bail!("{} already exists; choose a new file name", dest.display());
    }
    let dest_str = dest
        .to_str()
        .with_context(|| format!("backup path {} is not valid UTF-8", dest.display()))?;
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("cannot open database {}", db.display()))?;
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.execute("VACUUM INTO ?1", [dest_str])
        .with_context(|| format!("cannot write backup to {}", dest.display()))?;
    let copy = Connection::open_with_flags(dest, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let verdict: String = copy.pragma_query_value(None, "quick_check", |r| r.get(0))?;
    if verdict != "ok" {
        anyhow::bail!(
            "backup written to {} failed its integrity check: {verdict}",
            dest.display()
        );
    }
    Ok(std::fs::metadata(dest)?.len())
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
        register_functions(&conn).unwrap();
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
            "\"\"",
            "\"...\"",
            "...",
            "-\"\"",
            "foo*bar*",
            "OR",
            "NOT",
            "-\"a b\"*",
            "a\0b",
            "\"x\0y\"",
            "-\0",
        ] {
            let query = Query {
                text: Some(text.into()),
                ..q(10)
            };
            search(&conn, &query).unwrap_or_else(|e| panic!("{text:?} failed: {e}"));
        }
    }

    #[test]
    fn rich_text_search() {
        let mut conn = mem();
        insert_batch(
            &mut conn,
            &[
                entry(1, "h", 6, "disk error on sda"),
                entry(2, "h", 6, "disk timeout on sdb"),
                entry(3, "h", 6, "network error eth0"),
                entry(4, "h", 7, "debug disk scan"),
                entry(5, "h", 6, "failed login for root"),
                entry(6, "h", 6, "failure to mount"),
            ],
        )
        .unwrap();
        let find = |text: &str| -> Vec<i64> {
            let mut ts: Vec<i64> = search(
                &conn,
                &Query {
                    text: Some(text.into()),
                    ..q(100)
                },
            )
            .unwrap()
            .into_iter()
            .map(|r| r.ts)
            .collect();
            ts.sort();
            ts
        };
        assert_eq!(find("disk error"), [1], "words are ANDed");
        assert_eq!(find("error OR timeout"), [1, 2, 3]);
        assert_eq!(
            find("disk error OR network"),
            [1, 3],
            "AND binds tighter than OR"
        );
        assert_eq!(find("\"disk error\""), [1], "a phrase needs adjacent words");
        assert!(find("\"error disk\"").is_empty());
        assert_eq!(find("fail*"), [5, 6], "prefix");
        assert_eq!(find("disk -debug"), [1, 2], "exclusion");
        assert_eq!(find("disk NOT sda"), [2, 4]);
        assert_eq!(find("disk -sda -timeout"), [4]);
        assert_eq!(find("-disk -error"), [5, 6], "exclusion alone");
        assert_eq!(find("\"on sda\" OR \"eth0\""), [1, 3]);
        // Case does not matter, and operators only count in upper case.
        assert_eq!(find("DISK ERROR"), [1]);
        assert!(
            find("disk or error").is_empty(),
            "lower-case 'or' is a plain word"
        );
        // Exclusions also apply to stats-style filtering (same filter builder).
        let counted = stats(
            &conn,
            &Query {
                text: Some("disk -debug".into()),
                ..q(0)
            },
            1000,
            &GroupBy::None,
        )
        .unwrap();
        assert_eq!(counted.iter().map(|r| r.2).sum::<u64>(), 2);
    }

    #[test]
    fn cursor_pages_through_all_entries_without_gaps_or_repeats() {
        let mut conn = mem();
        // Many entries share timestamps, so the id has to break ties.
        let batch: Vec<LogEntry> = (0..47)
            .map(|i| entry(i / 5, "h", 6, &format!("m{i}")))
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let mut seen = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let page = search(
                &conn,
                &Query {
                    before: cursor,
                    ..q(10)
                },
            )
            .unwrap();
            pages += 1;
            seen.extend(page.iter().map(|r| r.message.clone()));
            match page.last().filter(|_| page.len() == 10) {
                Some(last) => cursor = Some((last.ts, last.id)),
                None => break,
            }
        }
        assert_eq!(pages, 5);
        assert_eq!(seen.len(), 47);
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 47, "no repeats");
        // Newest first throughout.
        assert_eq!(seen[0], "m46");
        assert_eq!(seen[46], "m0");
        // The cursor composes with the other filters.
        let q2 = Query {
            text: Some("m4".into()),
            before: Some((9, i64::MAX)),
            ..q(100)
        };
        assert!(
            search(&conn, &q2)
                .unwrap()
                .iter()
                .all(|r| r.message.starts_with("m4"))
        );
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
        assert_eq!(purge(&conn, &[Some(500); 8], None).unwrap(), 1);
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
    fn host_summary_counts_per_host() {
        let mut conn = mem();
        let batch = vec![
            entry(100, "pve", 6, "boot"),
            entry(200, "pve", 3, "disk error"),
            entry(300, "pve", 4, "slow"),
            entry(150, "nas", 2, "raid degraded"),
            entry(400, "pve", 7, "debug line"),
            entry(50, "ups", 6, "ok"),
        ];
        insert_batch(&mut conn, &batch).unwrap();

        let all = host_summary(&conn, &q(10), HostSort::default()).unwrap();
        let row = |h: &str| all.iter().find(|r| r.host == h).unwrap();
        assert_eq!(
            all.iter().map(|r| r.host.as_str()).collect::<Vec<_>>(),
            ["pve", "nas", "ups"]
        );
        assert_eq!(
            (
                row("pve").count,
                row("pve").errors,
                row("pve").warnings,
                row("pve").last_ts
            ),
            (4, 1, 1, 400)
        );
        assert_eq!(
            (row("nas").count, row("nas").errors, row("nas").warnings),
            (1, 1, 0)
        );
        assert_eq!(
            (row("ups").errors, row("ups").warnings, row("ups").last_ts),
            (0, 0, 50)
        );

        // Filters apply as in search (time window and full-text), and limit caps the hosts.
        let recent = Query {
            since_ms: Some(180),
            ..q(10)
        };
        let r = host_summary(&conn, &recent, HostSort::default()).unwrap();
        assert_eq!(
            r.iter()
                .map(|r| (r.host.as_str(), r.count))
                .collect::<Vec<_>>(),
            [("pve", 3)]
        );
        let text = Query {
            text: Some("error".into()),
            ..q(10)
        };
        assert_eq!(
            host_summary(&conn, &text, HostSort::default())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            host_summary(&conn, &q(2), HostSort::default())
                .unwrap()
                .len(),
            2
        );
        assert!(
            host_summary(&mem(), &q(10), HostSort::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn host_summary_sorting_and_limit_after_sort() {
        let mut conn = mem();
        let batch = vec![
            entry(100, "alpha", 6, "a"),
            entry(900, "alpha", 3, "a"),
            entry(300, "bravo", 6, "b"),
            entry(310, "bravo", 4, "b"),
            entry(320, "bravo", 6, "b"),
            entry(500, "charlie", 3, "c"),
            entry(510, "charlie", 3, "c"),
            entry(520, "charlie", 6, "c"),
            entry(530, "charlie", 4, "c"),
            entry(540, "charlie", 4, "c"),
        ];
        insert_batch(&mut conn, &batch).unwrap();
        let order = |key, desc, limit| {
            host_summary(&conn, &q(limit), HostSort { key, desc })
                .unwrap()
                .into_iter()
                .map(|r| r.host)
                .collect::<Vec<_>>()
        };
        use HostSortKey::*;
        // count: charlie 5, bravo 3, alpha 2; errors: charlie 2, alpha 1, bravo 0;
        // warnings: charlie 2, bravo 1, alpha 0; last seen: alpha 900, charlie 540, bravo 320.
        assert_eq!(order(Count, true, 10), ["charlie", "bravo", "alpha"]);
        assert_eq!(order(Count, false, 10), ["alpha", "bravo", "charlie"]);
        assert_eq!(order(Errors, true, 10), ["charlie", "alpha", "bravo"]);
        assert_eq!(order(Warnings, true, 10), ["charlie", "bravo", "alpha"]);
        assert_eq!(order(LastTs, true, 10), ["alpha", "charlie", "bravo"]);
        assert_eq!(order(LastTs, false, 10), ["bravo", "charlie", "alpha"]);
        assert_eq!(order(Host, false, 10), ["alpha", "bravo", "charlie"]);
        assert_eq!(order(Host, true, 10), ["charlie", "bravo", "alpha"]);
        // The limit applies after sorting: the quietest host, not the busiest.
        assert_eq!(order(LastTs, false, 1), ["bravo"]);
        assert_eq!(order(Count, true, 1), ["charlie"]);
        assert_eq!(
            HostSort::natural(Host),
            HostSort {
                key: Host,
                desc: false
            }
        );
        assert_eq!(
            HostSort::natural(LastTs),
            HostSort {
                key: LastTs,
                desc: true
            }
        );
    }

    #[test]
    fn export_visits_matching_rows_oldest_first() {
        let mut conn = mem();
        let batch = vec![
            entry(300, "pve", 6, "third"),
            entry(100, "nas", 6, "first"),
            entry(200, "pve", 3, "second disk error"),
            entry(400, "pve", 6, "fourth"),
        ];
        insert_batch(&mut conn, &batch).unwrap();
        let collect = |q: &Query, limit| {
            let mut got = Vec::new();
            let n = export_rows(&conn, q, limit, &mut |r| {
                got.push(r.message);
                true
            })
            .unwrap();
            (n, got)
        };
        assert_eq!(
            collect(&q(0), None).1,
            ["first", "second disk error", "third", "fourth"]
        );
        assert_eq!(collect(&q(0), Some(2)).1, ["first", "second disk error"]);
        let pve = Query {
            host: Some("pve".into()),
            ..q(0)
        };
        assert_eq!(collect(&pve, None).0, 3);
        let text = Query {
            text: Some("disk".into()),
            ..q(0)
        };
        assert_eq!(collect(&text, None).1, ["second disk error"]);
        // The visitor can stop the scan.
        let mut seen = 0;
        export_rows(&conn, &q(0), None, &mut |_| {
            seen += 1;
            false
        })
        .unwrap();
        assert_eq!(seen, 1);
    }

    #[test]
    fn backup_copies_a_live_database_and_refuses_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("logpit-backup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (src, dest) = (dir.join("src.db"), dir.join("copy.db"));
        let mut conn = open(&src).unwrap();
        insert_batch(
            &mut conn,
            &[
                entry(1, "pve", 6, "keep me"),
                entry(2, "nas", 3, "disk error"),
            ],
        )
        .unwrap();

        // The source stays open (as it would under a running server) while it is copied.
        let size = backup(&src, &dest).unwrap();
        assert!(size > 0);
        let copy = open(&dest).unwrap();
        let rows = search(
            &copy,
            &Query {
                text: Some("keep".into()),
                ..q(10)
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        let version: i64 = copy
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        assert!(
            backup(&src, &dest).is_err(),
            "an existing file is never overwritten"
        );
        assert!(backup(&dir.join("missing.db"), &dir.join("x.db")).is_err());
        drop((conn, copy));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn context_returns_neighbours_in_order() {
        let mut conn = mem();
        let mut batch = Vec::new();
        for i in 0..10 {
            batch.push(entry(i * 10, "pve", 6, &format!("pve {i}")));
            batch.push(entry(i * 10 + 5, "nas", 6, &format!("nas {i}")));
        }
        // Two entries with the same timestamp: the id orders them.
        batch.push(entry(50, "pve", 3, "pve tie"));
        insert_batch(&mut conn, &batch).unwrap();
        let id_of = |msg: &str| {
            search(
                &conn,
                &Query {
                    text: Some(msg.into()),
                    ..q(5)
                },
            )
            .unwrap()[0]
                .id
        };
        let msgs = |rows: &[Row]| rows.iter().map(|r| r.message.clone()).collect::<Vec<_>>();

        let c = context(&conn, id_of("\"pve 5\""), 2, true, &Default::default())
            .unwrap()
            .unwrap();
        assert_eq!(c.entry.message, "pve 5");
        assert_eq!(
            msgs(&c.before),
            ["pve 3", "pve 4"],
            "oldest first, own host only"
        );
        assert_eq!(
            msgs(&c.after),
            ["pve tie", "pve 6"],
            "same-timestamp entry follows by id"
        );

        let all = context(&conn, id_of("\"pve 5\""), 2, false, &Default::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            msgs(&all.before),
            ["pve 4", "nas 4"],
            "other hosts included"
        );
        assert_eq!(msgs(&all.after), ["pve tie", "nas 5"]);

        // Near the edges there are simply fewer neighbours; zero lines gives just the entry.
        let first = context(&conn, id_of("\"pve 0\""), 3, true, &Default::default())
            .unwrap()
            .unwrap();
        assert!(first.before.is_empty());
        assert_eq!(first.after.len(), 3);
        let bare = context(&conn, id_of("\"pve 5\""), 0, true, &Default::default())
            .unwrap()
            .unwrap();
        assert!(bare.before.is_empty() && bare.after.is_empty());

        assert!(
            context(&conn, 999_999, 5, true, &Default::default())
                .unwrap()
                .is_none()
        );
    }

    fn access(hosts: &[&str], apps: &[&str]) -> crate::auth::Access {
        crate::auth::Access {
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            apps: apps.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn access_limits_every_read_path() {
        let mut conn = mem();
        let mut batch = Vec::new();
        for (i, (host, app)) in [
            ("web1", "nginx"),
            ("web2", "nginx"),
            ("db1", "pg"),
            ("web1", "cron"),
            ("db1", "nginx"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut e = entry(i as i64 + 1, host, 3, "secret thing happened");
            e.app = app.into();
            batch.push(e);
        }
        insert_batch(&mut conn, &batch).unwrap();
        let limited = |hosts: &[&str], apps: &[&str]| Query {
            access: access(hosts, apps),
            ..q(100)
        };
        let hosts_of = |query: &Query| -> Vec<String> {
            search(&conn, query)
                .unwrap()
                .into_iter()
                .map(|r| r.host)
                .collect()
        };

        // Hosts, apps, both, and a text search all stay inside the allowed set.
        assert_eq!(
            hosts_of(&limited(&["web1", "web2"], &[])),
            ["web1", "web2", "web1"]
        );
        assert_eq!(hosts_of(&limited(&[], &["nginx"])), ["db1", "web2", "web1"]);
        assert_eq!(hosts_of(&limited(&["web1"], &["nginx"])), ["web1"]);
        assert!(hosts_of(&limited(&["nobody"], &[])).is_empty());
        let mut text = limited(&["db1"], &[]);
        text.text = Some("secret".into());
        assert_eq!(hosts_of(&text), ["db1", "db1"]);
        // The caller's own host filter cannot widen it.
        let mut asks_db = limited(&["web1"], &[]);
        asks_db.host = Some("db1".into());
        assert!(hosts_of(&asks_db).is_empty());

        let only_web1 = limited(&["web1"], &[]);
        let summary =
            host_summary(&conn, &only_web1, HostSort::natural(HostSortKey::Host)).unwrap();
        assert_eq!(
            summary.iter().map(|h| h.host.as_str()).collect::<Vec<_>>(),
            ["web1"]
        );
        let top = top_values(&conn, &only_web1, &GroupBy::Host, 10).unwrap();
        assert_eq!((top.matching, top.distinct), (2, 1));
        let (samples, _) = recent_samples(&conn, &only_web1, 10, 50).unwrap();
        assert_eq!(samples.len(), 2);
        let mut seen = 0;
        export_rows(&conn, &only_web1, None, &mut |_| {
            seen += 1;
            true
        })
        .unwrap();
        assert_eq!(seen, 2);
        let rows = stats(&conn, &only_web1, 1000, &GroupBy::Host).unwrap();
        assert_eq!(rows.iter().map(|(_, _, n)| n).sum::<u64>(), 2);

        // Live entries are filtered the same way.
        let live = entry(9, "db1", 3, "x");
        assert!(!only_web1.matches(&live));
        assert!(limited(&["db1"], &[]).matches(&live));
        assert!(q(0).matches(&live));
    }

    #[test]
    fn context_hides_entries_and_neighbours_outside_the_access() {
        let mut conn = mem();
        let batch: Vec<LogEntry> = (1..=6)
            .map(|i| {
                entry(
                    i,
                    if i % 2 == 0 { "a" } else { "b" },
                    6,
                    &format!("line {i}"),
                )
            })
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let id = |ts: i64| {
            conn.query_row("SELECT id FROM logs WHERE ts = ?", [ts], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
        };
        let only_a = access(&["a"], &[]);
        // Across hosts (`same_host` false) the neighbours of an `a` entry are still only `a`'s.
        let c = context(&conn, id(4), 5, false, &only_a).unwrap().unwrap();
        assert_eq!(c.before.iter().map(|r| r.ts).collect::<Vec<_>>(), [2]);
        assert_eq!(c.after.iter().map(|r| r.ts).collect::<Vec<_>>(), [6]);
        let c = context(&conn, id(4), 5, true, &only_a).unwrap().unwrap();
        assert_eq!(c.before.len() + c.after.len(), 2);
        // An entry of another host is as good as absent.
        assert!(context(&conn, id(3), 5, false, &only_a).unwrap().is_none());
        // Unrestricted still sees everything.
        let c = context(&conn, id(3), 5, false, &Default::default())
            .unwrap()
            .unwrap();
        assert_eq!(c.before.len() + c.after.len(), 5);
        // Several names and an app limit number their placeholders after the fixed ones.
        let wide = access(&["a", "b"], &["app"]);
        let c = context(&conn, id(3), 5, true, &wide).unwrap().unwrap();
        assert_eq!(c.before.len() + c.after.len(), 2);
        let c = context(&conn, id(3), 5, false, &wide).unwrap().unwrap();
        assert_eq!(c.before.len() + c.after.len(), 5);
    }

    #[test]
    fn comparisons_and_regular_expressions_filter_in_sql_and_live() {
        use crate::filters::{Expr, parse_expr};
        let mut conn = mem();
        let rows = [
            ("a", "GET /x 200", Some("200"), Some("0.5s"), Some("web")),
            ("a", "GET /y 503", Some("503"), Some("2.5"), Some("web")),
            ("b", "GET /z 404", Some("404"), Some("10"), Some("db")),
            ("b", "no fields here", None, None, None),
            ("c", "GET /w 500", Some("500"), Some("1e1"), Some("cache")),
        ];
        let batch: Vec<LogEntry> = rows
            .iter()
            .enumerate()
            .map(|(i, (host, msg, status, d, role))| {
                let mut e = entry(i as i64 + 1, host, 6, msg);
                for (k, v) in [("status", status), ("d", d), ("role", role)] {
                    if let Some(v) = v {
                        e.fields.insert(k.into(), v.to_string());
                    }
                }
                e
            })
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let with = |exprs: &[&str], re: Option<&str>| {
            let mut query = q(100);
            for x in exprs {
                match parse_expr(x).unwrap() {
                    Expr::Equals(k, v) => query.fields.push((k, v)),
                    Expr::Compare(f) => query.compare.push(f),
                }
            }
            query.message_re = re.map(|r| crate::filters::compile_regex(r).unwrap());
            query
        };
        // The SQL result and the in-memory one (live tail) must agree.
        let check = |query: Query, expect: &[i64]| {
            let mut ts: Vec<i64> = search(&conn, &query)
                .unwrap()
                .iter()
                .map(|r| r.ts)
                .collect();
            ts.sort();
            assert_eq!(ts, expect);
            let live: Vec<i64> = batch
                .iter()
                .filter(|e| query.matches(e))
                .map(|e| e.ts)
                .collect();
            assert_eq!(live, expect, "live tail disagrees");
        };
        check(with(&["status>=500"], None), &[2, 5]);
        check(with(&["status>500"], None), &[2]);
        check(with(&["status<=404"], None), &[1, 3]);
        check(with(&["status<300"], None), &[1]);
        // A value that is not a number matches no ordering ("0.5s"), and "1e1" is ten.
        check(with(&["d>=1"], None), &[2, 3, 5]);
        check(with(&["d<1"], None), &[]);
        // Entries without the field never match, `!=` included.
        check(with(&["role!=web"], None), &[3, 5]);
        check(with(&["role~^(db|cache)$"], None), &[3, 5]);
        check(with(&["status>=400", "role:web"], None), &[2]);
        check(with(&["status>=400", "status<=503"], None), &[2, 3, 5]);
        check(with(&[], Some(r"GET /[xy] ")), &[1, 2]);
        check(with(&[], Some("(?i)NO FIELDS")), &[4]);
        check(with(&["status>=500"], Some("/w")), &[5]);
        // Combined with free text, host and access limits.
        let mut text = with(&["status>=400"], None);
        text.text = Some("GET".into());
        text.access = access(&["a", "c"], &[]);
        check(text, &[2, 5]);
        // Counting and grouping follow the same filters.
        let top = top_values(&conn, &with(&["status>=500"], None), &GroupBy::Host, 10).unwrap();
        assert_eq!((top.matching, top.distinct), (2, 2));
    }

    #[test]
    fn line_filters_column_filters_and_severity_sets() {
        use crate::filters::{
            Column, ColumnFilter, ColumnMatch, LineFilter, LineOp, compile_regex,
        };
        let mut conn = mem();
        let rows = [
            ("web1", "nginx", 3, "upstream timed out (110)"),
            ("web2", "nginx", 6, "GET /index 200"),
            ("db1", "pg", 4, "slow query: 3.1s"),
            ("db1", "pg", 6, "checkpoint complete"),
            ("", "", 7, "Debug (lib) tick"),
        ];
        let batch: Vec<LogEntry> = rows
            .iter()
            .enumerate()
            .map(|(i, (h, a, sev, m))| {
                let mut e = entry(i as i64 + 1, h, *sev, m);
                e.app = a.to_string();
                e
            })
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let check = |query: Query, expect: &[i64]| {
            let mut ts: Vec<i64> = search(&conn, &query)
                .unwrap()
                .iter()
                .map(|r| r.ts)
                .collect();
            ts.sort();
            assert_eq!(ts, expect);
            let live: Vec<i64> = batch
                .iter()
                .filter(|e| query.matches(e))
                .map(|e| e.ts)
                .collect();
            assert_eq!(live, expect, "live tail disagrees");
        };
        let lines = |filters: &[(LineOp, &str)]| Query {
            line_filters: filters
                .iter()
                .map(|(o, v)| LineFilter::new(*o, v).unwrap())
                .collect(),
            ..q(100)
        };
        check(lines(&[(LineOp::Contains, "timed out")]), &[1]);
        check(lines(&[(LineOp::Contains, "(lib)")]), &[5]);
        check(lines(&[(LineOp::Contains, "debug")]), &[]);
        check(lines(&[(LineOp::NotContains, "GET")]), &[1, 3, 4, 5]);
        check(lines(&[(LineOp::Re, r"\d+\.\ds$")]), &[3]);
        check(lines(&[(LineOp::NotRe, "^(GET|slow)")]), &[1, 4, 5]);
        check(
            lines(&[(LineOp::Contains, "e"), (LineOp::NotContains, "query")]),
            &[1, 2, 4, 5],
        );

        let cols = |filters: Vec<ColumnFilter>| Query {
            column_filters: filters,
            ..q(100)
        };
        let re = |s: &str| compile_regex(s).unwrap();
        let f = |column, matcher| ColumnFilter { column, matcher };
        check(
            cols(vec![f(Column::Host, ColumnMatch::Eq("db1".into()))]),
            &[3, 4],
        );
        check(
            cols(vec![f(Column::Host, ColumnMatch::Ne("db1".into()))]),
            &[1, 2, 5],
        );
        check(
            cols(vec![f(Column::App, ColumnMatch::Re(re("^(nginx|pg)$")))]),
            &[1, 2, 3, 4],
        );
        check(
            cols(vec![f(Column::Host, ColumnMatch::NotRe(re("^web")))]),
            &[3, 4, 5],
        );
        check(
            cols(vec![
                f(Column::App, ColumnMatch::Eq("pg".into())),
                f(Column::Host, ColumnMatch::NotRe(re("^web"))),
            ]),
            &[3, 4],
        );
        let sev = |set: Option<Vec<u8>>| Query {
            severities: set,
            ..q(100)
        };
        check(sev(Some(vec![3, 4])), &[1, 3]);
        check(sev(Some(vec![6])), &[2, 4]);
        check(sev(Some(vec![])), &[]);
        check(sev(None), &[1, 2, 3, 4, 5]);
        // Combined with the access limits and the structured filters.
        let mut limited = lines(&[(LineOp::NotContains, "GET")]);
        limited.access = access(&["web1", "db1"], &[]);
        limited.severities = Some(vec![3, 6]);
        check(limited, &[1, 4]);
    }

    #[test]
    fn host_window_counts_cover_the_complete_windows_before_now() {
        let mut conn = mem();
        // Windows of 1000 ms; now = 10_500 is inside window 10, so windows 6..=9 are asked for.
        let mut batch = Vec::new();
        for (ts, host) in [
            (5_999, "a"), // window 5: before the range
            (6_000, "a"),
            (6_999, "a"),
            (7_500, "b"),
            (9_000, "a"),
            (9_999, "a"),
            (10_000, "a"), // window 10: still running, not counted
        ] {
            batch.push(entry(ts, host, 6, "m"));
        }
        insert_batch(&mut conn, &batch).unwrap();
        let got = host_window_counts(&conn, 10_500, 1000, 4).unwrap();
        assert_eq!(
            got,
            [
                ("a".to_string(), vec![2, 0, 0, 2]),
                ("b".to_string(), vec![0, 1, 0, 0])
            ]
        );
        assert!(
            host_window_counts(&conn, 100_000, 1000, 4)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn host_patterns_work_in_access_and_tag_filters_sql_and_live() {
        let mut conn = mem();
        let hosts = ["web1", "web2", "web10", "db1", "proxy1", "[odd]", "a*b"];
        let batch: Vec<LogEntry> = hosts
            .iter()
            .enumerate()
            .map(|(i, h)| entry(i as i64 + 1, h, 6, "m"))
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let check = |query: Query, expect: &[&str]| {
            let mut got: Vec<String> = search(&conn, &query)
                .unwrap()
                .into_iter()
                .map(|r| r.host)
                .collect();
            got.sort();
            let mut want: Vec<String> = expect.iter().map(|s| s.to_string()).collect();
            want.sort();
            assert_eq!(got, want, "SQL");
            let mut live: Vec<String> = batch
                .iter()
                .filter(|e| query.matches(e))
                .map(|e| e.host.clone())
                .collect();
            live.sort();
            assert_eq!(live, want, "live tail disagrees");
        };
        let globs = |p: &[&str]| Query {
            host_globs: p.iter().map(|s| s.to_string()).collect(),
            ..q(100)
        };
        check(globs(&["web*"]), &["web1", "web2", "web10"]);
        check(globs(&["web?"]), &["web1", "web2"]);
        check(globs(&["web*", "db1"]), &["web1", "web2", "web10", "db1"]);
        check(globs(&["proxy1"]), &["proxy1"]);
        check(
            globs(&["*1"]),
            &["web1", "web10", "db1", "proxy1"]
                .iter()
                .filter(|h| h.ends_with('1'))
                .copied()
                .collect::<Vec<_>>(),
        );
        // A bracket in a host name is literal, not a character class, in both worlds.
        check(globs(&["[odd]"]), &["[odd]"]);
        check(globs(&["[odd]*"]), &["[odd]"]);
        check(globs(&["a*b"]), &["a*b"]);
        check(globs(&["nothing*"]), &[]);
        // Token restrictions accept the same patterns, and combine with the tag filter.
        let mut limited = globs(&["web*", "db1"]);
        limited.access = access(&["web1*", "proxy1"], &[]);
        check(limited, &["web1", "web10"]);
        let mut only = q(100);
        only.access = access(&["db*", "proxy?"], &[]);
        check(only, &["db1", "proxy1"]);
        // Placeholders stay in step in the statements that number them (context).
        let id = |ts: i64| {
            conn.query_row("SELECT id FROM logs WHERE ts = ?", [ts], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
        };
        let acc = access(&["web*", "db1"], &["app"]);
        let c = context(&conn, id(1), 10, false, &acc).unwrap().unwrap();
        assert_eq!(c.after.len(), 3, "web2, web10 and db1 follow web1");
        assert!(
            context(&conn, id(5), 10, false, &acc).unwrap().is_none(),
            "proxy1 is outside"
        );
    }

    #[test]
    fn recent_samples_are_newest_first_filtered_and_cut() {
        let mut conn = mem();
        let batch: Vec<LogEntry> = (0..5)
            .map(|i| {
                entry(
                    i,
                    if i % 2 == 0 { "a" } else { "b" },
                    6,
                    &format!("job {i} finished with a long tail of words"),
                )
            })
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let (s, more) = recent_samples(&conn, &q(0), 3, 8).unwrap();
        assert!(more);
        assert_eq!(s.iter().map(|x| x.ts).collect::<Vec<_>>(), [4, 3, 2]);
        assert_eq!(s[0].message, "job 4 fi");
        assert_eq!(s[0].host, "a");
        let only_b = Query {
            host: Some("b".into()),
            ..q(0)
        };
        let (s, more) = recent_samples(&conn, &only_b, 3, 100).unwrap();
        assert!(!more);
        assert_eq!(s.iter().map(|x| x.ts).collect::<Vec<_>>(), [3, 1]);
        let text = Query {
            text: Some("finished".into()),
            since_ms: Some(2),
            ..q(0)
        };
        let (s, _) = recent_samples(&conn, &text, 10, 100).unwrap();
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn top_values_and_field_names() {
        let mut conn = mem();
        let mut batch = Vec::new();
        for (i, (host, sev, src)) in [
            ("fw", 4, Some("10.0.0.1")),
            ("fw", 4, Some("10.0.0.1")),
            ("fw", 4, Some("10.0.0.1")),
            ("fw", 4, Some("10.0.0.2")),
            ("fw", 4, Some("10.0.0.2")),
            ("fw", 4, Some("10.0.0.3")),
            ("nas", 3, None),
            ("nas", 6, Some("10.0.0.9")),
        ]
        .into_iter()
        .enumerate()
        {
            let mut e = entry(i as i64, host, sev, "blocked packet");
            if let Some(src) = src {
                e.fields.insert("src".into(), src.into());
                e.fields.insert("act".into(), "block".into());
            }
            batch.push(e);
        }
        insert_batch(&mut conn, &batch).unwrap();

        let src = top_values(&conn, &q(0), &GroupBy::Field("src".into()), 2).unwrap();
        assert_eq!((src.matching, src.with_field, src.distinct), (8, 7, 4));
        let vals: Vec<(&str, u64)> = src
            .values
            .iter()
            .map(|v| (v.value.as_str(), v.count))
            .collect();
        assert_eq!(
            vals,
            [("10.0.0.1", 3), ("10.0.0.2", 2)],
            "limit applies, most frequent first"
        );

        // Ties are ordered by value; entries without the field are not a value.
        let all = top_values(&conn, &q(0), &GroupBy::Field("src".into()), 10).unwrap();
        assert_eq!(
            all.values
                .iter()
                .map(|v| v.value.as_str())
                .collect::<Vec<_>>(),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"]
        );

        // Built-in dimensions, and filters narrowing the population.
        let hosts = top_values(&conn, &q(0), &GroupBy::Host, 5).unwrap();
        assert_eq!(
            hosts.values[0],
            TopValue {
                value: "fw".into(),
                count: 6
            }
        );
        let sev = top_values(&conn, &q(0), &GroupBy::Severity, 5).unwrap();
        assert_eq!(
            sev.values[0],
            TopValue {
                value: "4".into(),
                count: 6
            }
        );
        let only_fw = Query {
            host: Some("fw".into()),
            ..q(0)
        };
        let r = top_values(&conn, &only_fw, &GroupBy::Field("src".into()), 5).unwrap();
        assert_eq!((r.matching, r.with_field, r.distinct), (6, 6, 3));
        let none = top_values(&conn, &q(0), &GroupBy::Field("missing".into()), 5).unwrap();
        assert_eq!(
            (none.with_field, none.distinct, none.values.len()),
            (0, 0, 0)
        );
        assert!(top_values(&conn, &q(0), &GroupBy::Field("a b".into()), 5).is_err());

        let names = field_names(&conn, &q(0), 10).unwrap();
        assert_eq!(names, [("act".to_string(), 7), ("src".to_string(), 7)]);
        let narrowed = field_names(
            &conn,
            &Query {
                host: Some("nas".into()),
                ..q(0)
            },
            10,
        )
        .unwrap();
        assert_eq!(narrowed, [("act".to_string(), 1), ("src".to_string(), 1)]);
        let text = field_names(
            &conn,
            &Query {
                text: Some("blocked".into()),
                ..q(0)
            },
            1,
        )
        .unwrap();
        assert_eq!(text.len(), 1, "limit applies to the names too");
    }

    #[test]
    fn purge_archives_each_chunk_before_deleting_it() {
        use std::cell::RefCell;
        let mut conn = mem();
        // 12 000 old entries (three chunks), a few of another severity, and fresh ones.
        let mut batch: Vec<LogEntry> = (0..12_000)
            .map(|i| entry(i, "h", 6, &format!("old {i}")))
            .collect();
        batch.extend((0..5).map(|i| entry(i, "h", 3, &format!("old error {i}"))));
        batch.extend((0..7).map(|i| entry(1_000_000 + i, "h", 6, &format!("fresh {i}"))));
        insert_batch(&mut conn, &batch).unwrap();
        let archived = RefCell::new(Vec::<String>::new());
        let hook = |rows: &[Row]| -> anyhow::Result<()> {
            archived
                .borrow_mut()
                .extend(rows.iter().map(|r| r.message.clone()));
            Ok(())
        };
        // Info is kept 500 ms back from now=1_000_500; errors forever.
        let mut cutoffs = [None; 8];
        cutoffs[6] = Some(500_000);
        let removed = purge(&conn, &cutoffs, Some(&hook)).unwrap();
        assert_eq!(removed, 12_000);
        let archived = archived.into_inner();
        assert_eq!(archived.len(), 12_000);
        let unique: std::collections::HashSet<&String> = archived.iter().collect();
        assert_eq!(unique.len(), 12_000, "every entry archived exactly once");
        assert!(
            archived
                .iter()
                .all(|m| m.starts_with("old ") && !m.contains("error"))
        );
        // What was not expired is untouched: the errors and the fresh entries.
        let left = search(&conn, &q(100)).unwrap();
        assert_eq!(left.len(), 12);

        // Several severities sharing a cutoff go together; no hook behaves like `purge`.
        let seen = RefCell::new(0);
        let count = |rows: &[Row]| -> anyhow::Result<()> {
            *seen.borrow_mut() += rows.len();
            Ok(())
        };
        assert_eq!(purge(&conn, &[Some(500_000); 8], Some(&count)).unwrap(), 5);
        assert_eq!(*seen.borrow(), 5);
        assert_eq!(purge(&conn, &[Some(2_000_000); 8], None).unwrap(), 7);
        assert!(search(&conn, &q(100)).unwrap().is_empty());
    }

    #[test]
    fn retention_rules_judge_by_the_first_match_and_fall_back_to_the_severity_table() {
        let mut conn = mem();
        // (ts, host, app, severity): all old, so the cutoffs decide.
        let rows = [
            (1, "fw1", "dnsmasq", 6),
            (2, "fw2", "kernel", 6),
            (3, "web1", "nginx", 6),
            (4, "web1", "nginx", 3),
            (5, "db1", "pg", 7),
            (6, "web2", "cron", 6),
            (7, "web2", "cron", 3),
        ];
        let batch: Vec<LogEntry> = rows
            .iter()
            .map(|(ts, h, a, s)| {
                let mut e = entry(*ts, h, *s, "m");
                e.app = a.to_string();
                e
            })
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let rule = |hosts: &[&str], apps: &[&str], sev: &[u8], cutoff: Option<i64>| PurgeRule {
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            apps: apps.iter().map(|s| s.to_string()).collect(),
            severities: sev.to_vec(),
            cutoff,
        };
        // fw*: purge everything older than 100; web1 errors: keep forever (and shield them from the
        // later rules); cron: purge at 100. Anything else follows the severity table: info at 100.
        let rules = [
            rule(&["fw*"], &[], &[], Some(100)),
            rule(&["web1"], &[], &[3], None),
            rule(&[], &["cron"], &[], Some(100)),
            rule(&["web*"], &[], &[], Some(100)),
        ];
        let mut cutoffs = [None; 8];
        cutoffs[6] = Some(100);
        let left = |conn: &Connection| -> Vec<i64> {
            let mut ts: Vec<i64> = search(conn, &q(100))
                .unwrap()
                .iter()
                .map(|r| r.ts)
                .collect();
            ts.sort();
            ts
        };
        let removed = purge_rules(&conn, &rules, &cutoffs, None).unwrap();
        // Gone: fw1, fw2 (rule 1), web1 info (rule 4), web2 info and error (rule 3 for cron).
        // Kept: web1 error (rule 2 keeps it, so rule 4 does not touch it) and db1 debug (severity
        // table: only info has a cutoff).
        assert_eq!(removed, 5);
        assert_eq!(left(&conn), [4, 5]);
    }

    #[test]
    fn retention_rules_archive_what_they_remove_and_stay_inside_their_cutoff() {
        use std::cell::RefCell;
        let mut conn = mem();
        let mut batch = Vec::new();
        for (ts, host) in [(10, "fw1"), (900, "fw1"), (10, "web1")] {
            batch.push(entry(ts, host, 6, &format!("{host} {ts}")));
        }
        insert_batch(&mut conn, &batch).unwrap();
        let archived = RefCell::new(Vec::<String>::new());
        let hook = |rows: &[Row]| -> anyhow::Result<()> {
            archived
                .borrow_mut()
                .extend(rows.iter().map(|r| r.message.clone()));
            Ok(())
        };
        let rules = [PurgeRule {
            hosts: vec!["fw*".into()],
            cutoff: Some(500),
            ..Default::default()
        }];
        assert_eq!(
            purge_rules(&conn, &rules, &[None; 8], Some(&hook)).unwrap(),
            1
        );
        assert_eq!(archived.into_inner(), ["fw1 10"]);
        assert_eq!(
            search(&conn, &q(10)).unwrap().len(),
            2,
            "fresh fw1 and web1 stay"
        );
        // An empty rule list is the plain severity purge.
        assert_eq!(purge_rules(&conn, &[], &[Some(1000); 8], None).unwrap(), 2);
    }

    #[test]
    fn a_failing_archive_keeps_the_entries() {
        let mut conn = mem();
        let batch: Vec<LogEntry> = (0..10).map(|i| entry(i, "h", 6, "x")).collect();
        insert_batch(&mut conn, &batch).unwrap();
        let fail = |_: &[Row]| -> anyhow::Result<()> { anyhow::bail!("disk full") };
        let err = purge(&conn, &[Some(100); 8], Some(&fail)).unwrap_err();
        assert!(err.to_string().contains("disk full"));
        assert_eq!(search(&conn, &q(100)).unwrap().len(), 10);
    }

    #[test]
    fn size_cap_eviction_archives_what_it_removes() {
        use std::cell::RefCell;
        let mut conn = mem();
        let filler = "x".repeat(1000);
        let batch: Vec<LogEntry> = (0..4000)
            .map(|i| entry(i, "h", 6, &format!("line {i} {filler}")))
            .collect();
        insert_batch(&mut conn, &batch).unwrap();
        let before = used_bytes(&conn).unwrap();
        let archived = RefCell::new(Vec::<i64>::new());
        let hook = |rows: &[Row]| -> anyhow::Result<()> {
            archived.borrow_mut().extend(rows.iter().map(|r| r.ts));
            Ok(())
        };
        let removed = enforce_size_limit(&conn, before / 2, Some(&hook)).unwrap();
        let archived = archived.into_inner();
        assert!(removed > 0 && removed < 4000);
        assert_eq!(archived.len(), removed);
        // Oldest first, and exactly the entries that are gone.
        assert_eq!(archived, (0..removed as i64).collect::<Vec<_>>());
        assert_eq!(search(&conn, &q(5000)).unwrap().len(), 4000 - removed);
        // A failing archive stops the eviction.
        let fail = |_: &[Row]| -> anyhow::Result<()> { anyhow::bail!("nope") };
        let left = search(&conn, &q(5000)).unwrap().len();
        assert!(enforce_size_limit(&conn, 1, Some(&fail)).is_err());
        assert_eq!(search(&conn, &q(5000)).unwrap().len(), left);
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
        assert_eq!(enforce_size_limit(&conn, before + 1, None).unwrap(), 0);

        let limit = before / 2;
        let removed = enforce_size_limit(&conn, limit, None).unwrap();
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
            purge(&conn, &cutoffs, None).unwrap(),
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
        assert_eq!(purge(&conn, &[None; 8], None).unwrap(), 0);
        assert_eq!(purge(&conn, &[Some(950); 8], None).unwrap(), 14);
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
        assert_eq!(purge(&conn, &[Some(100); 8], None).unwrap(), 1);
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
    fn views_are_saved_replaced_listed_and_deleted() {
        let conn = mem();
        assert!(list_views(&conn).unwrap().is_empty());
        let a = save_view(&conn, "Errors on pve", "host=pve&level=3", 100)
            .unwrap()
            .unwrap();
        let b = save_view(&conn, "disk", "q=disk&range=86400000", 200)
            .unwrap()
            .unwrap();
        assert_ne!(a.id, b.id);
        // Listed by name, ignoring case.
        let c = save_view(&conn, "Alpha", "group=host", 300)
            .unwrap()
            .unwrap();
        let names: Vec<String> = list_views(&conn)
            .unwrap()
            .into_iter()
            .map(|v| v.name)
            .collect();
        assert_eq!(names, ["Alpha", "disk", "Errors on pve"]);
        // Saving under an existing name replaces its query and keeps the id.
        let again = save_view(&conn, "disk", "q=disk+error", 999)
            .unwrap()
            .unwrap();
        assert_eq!(
            (again.id, again.query.as_str(), again.created_ts),
            (b.id, "q=disk+error", 200)
        );
        assert_eq!(list_views(&conn).unwrap().len(), 3);
        assert!(delete_view(&conn, c.id).unwrap());
        assert!(!delete_view(&conn, c.id).unwrap(), "already gone");
        assert!(!delete_view(&conn, 12345).unwrap());
        assert_eq!(list_views(&conn).unwrap().len(), 2);
    }

    #[test]
    fn views_are_capped_but_existing_ones_can_still_be_updated() {
        let conn = mem();
        for i in 0..MAX_VIEWS {
            assert!(
                save_view(&conn, &format!("v{i}"), "q=x", 0)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            save_view(&conn, "one too many", "q=x", 0)
                .unwrap()
                .is_none()
        );
        assert!(
            save_view(&conn, "v7", "q=changed", 0).unwrap().is_some(),
            "replacing is not adding"
        );
        assert_eq!(list_views(&conn).unwrap().len(), MAX_VIEWS);
    }

    #[test]
    fn the_views_table_does_not_change_the_schema_version() {
        let conn = mem();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(
            version, SCHEMA_VERSION,
            "an older LogPit can still open the database"
        );
        // An existing database without the table gets it on open, and keeps its views afterwards.
        conn.execute("DROP TABLE views", []).unwrap();
        migrate(&conn).unwrap();
        save_view(&conn, "kept", "q=x", 1).unwrap();
        migrate(&conn).unwrap();
        assert_eq!(
            list_views(&conn).unwrap().len(),
            1,
            "migrating again leaves the data alone"
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
            run_writer(conn, rx, 100, Duration::from_secs(60), m, Arc::default());
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

    fn temp_db(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("logpit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        (dir, path)
    }

    #[test]
    fn writer_stops_on_request_while_senders_are_alive() {
        let (dir, path) = temp_db("writer-stop");
        let conn = open(&path).unwrap();
        let metrics = Arc::new(Metrics::default());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::sync_channel(16);
        let (m, s) = (metrics.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            run_writer(conn, rx, 100, Duration::from_secs(60), m, s);
        });
        tx.send(entry(1, "h", 6, "queued before the stop")).unwrap();
        stop.store(true, Ordering::Release);
        // `tx` is still alive, like the sink of an open connection: the writer exits anyway,
        // after writing what was queued.
        let started = Instant::now();
        handle.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(metrics.stored.load(Ordering::Relaxed), 1);
        drop(tx);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writer_keeps_its_batch_while_the_database_is_locked() {
        let (dir, path) = temp_db("writer-busy");
        let conn = open(&path).unwrap();
        conn.busy_timeout(Duration::from_millis(20)).unwrap();
        let metrics = Arc::new(Metrics::default());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Another connection holds the write lock, as a long purge or a backup would.
        let blocker = open(&path).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(16);
        let (m, s) = (metrics.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            run_writer(conn, rx, 100, Duration::from_millis(30), m, s);
        });
        tx.send(entry(1, "h", 6, "one")).unwrap();
        tx.send(entry(2, "h", 6, "two")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while metrics.write_errors.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < deadline, "the writer never hit the lock");
            std::thread::sleep(Duration::from_millis(10));
        }
        blocker.execute_batch("COMMIT").unwrap();
        drop(tx);
        handle.join().unwrap();
        assert_eq!(
            metrics.stored.load(Ordering::Relaxed),
            2,
            "no entry was lost"
        );
        assert_eq!(search(&blocker, &q(10)).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn purge_removes_more_than_one_chunk() {
        let mut conn = mem();
        let n = PURGE_CHUNK as usize * 2 + 7;
        let entries: Vec<LogEntry> = (0..n)
            .map(|i| entry(i as i64, "h", 6, "old"))
            .chain([entry(1_000_000, "h", 6, "recent")])
            .collect();
        insert_batch(&mut conn, &entries).unwrap();
        assert_eq!(purge(&conn, &[Some(1_000_000); 8], None).unwrap(), n);
        let left = search(&conn, &q(10)).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].message, "recent");
    }
}
