//! Scheduled backups: a consistent copy of the database (`VACUUM INTO`, as `logpit --backup`) every
//! so many hours into a directory, keeping the newest few and removing the rest.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::ingest::now_ms;
use crate::metrics::Metrics;

const MAX_EVERY_HOURS: u64 = 24 * 365;
const MAX_KEEP: usize = 1000;
/// First backup after startup waits this long, so the server is up and serving first.
const START_DELAY: Duration = Duration::from_secs(60);
/// A failed backup is tried again after this long at most.
const RETRY_AFTER: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfig {
    /// Directory the copies go to; setting it turns scheduled backups on.
    pub dir: Option<PathBuf>,
    /// Hours between two backups.
    pub every_hours: u64,
    /// Copies kept; older ones LogPit made are removed after each successful backup.
    pub keep: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            dir: None,
            every_hours: 24,
            keep: 7,
        }
    }
}

impl BackupConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.every_hours == 0 || self.every_hours > MAX_EVERY_HOURS {
            bail!("backup.every_hours must be between 1 and {MAX_EVERY_HOURS}");
        }
        if self.keep == 0 || self.keep > MAX_KEEP {
            bail!("backup.keep must be between 1 and {MAX_KEEP}");
        }
        if self.dir.as_ref().is_some_and(|d| d.as_os_str().is_empty()) {
            bail!("backup.dir must not be empty");
        }
        Ok(())
    }
}

/// `logpit-20261003T120000Z.db`: sorts by time, and is the only name LogPit ever removes.
pub fn file_name(now_ms: i64) -> String {
    let t = chrono::DateTime::from_timestamp_millis(now_ms).unwrap_or_default();
    t.format("logpit-%Y%m%dT%H%M%SZ.db").to_string()
}

fn is_ours(name: &str) -> bool {
    let b = name.as_bytes();
    name.len() == "logpit-20261003T120000Z.db".len()
        && name.starts_with("logpit-")
        && name.ends_with("Z.db")
        && b[7..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'T'
        && b[16..22].iter().all(u8::is_ascii_digit)
}

/// The backups in `dir` that LogPit made, oldest first.
pub fn list(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some_and(is_ours))
        .map(|e| e.path())
        .collect();
    files.sort();
    Ok(files)
}

/// Removes all but the newest `keep` backups; returns how many went.
pub fn rotate(dir: &Path, keep: usize) -> anyhow::Result<usize> {
    let files = list(dir).with_context(|| format!("cannot list {}", dir.display()))?;
    let excess = files.len().saturating_sub(keep);
    for f in &files[..excess] {
        std::fs::remove_file(f).with_context(|| format!("cannot remove {}", f.display()))?;
    }
    Ok(excess)
}

/// The Unix ms time of the newest backup, from its name.
fn newest_ms(dir: &Path) -> Option<i64> {
    let last = list(dir).ok()?.pop()?;
    let name = last.file_name()?.to_str()?;
    let naive = chrono::NaiveDateTime::parse_from_str(&name[7..22], "%Y%m%dT%H%M%S").ok()?;
    Some(naive.and_utc().timestamp_millis())
}

/// How long to wait before the next backup: the rest of the interval since the newest one,
/// `START_DELAY` when there is none or it is overdue.
pub fn first_delay(dir: &Path, every: Duration, now_ms: i64) -> Duration {
    match newest_ms(dir) {
        Some(last) => {
            let due = last + i64::try_from(every.as_millis()).unwrap_or(i64::MAX);
            let wait = u64::try_from(due - now_ms).unwrap_or(0);
            Duration::from_millis(wait).max(START_DELAY)
        }
        None => START_DELAY,
    }
}

/// What one backup did.
#[derive(Debug)]
pub struct Done {
    pub path: PathBuf,
    pub bytes: u64,
    pub removed: usize,
}

/// Writes a backup of `db` into `dir` and rotates. A partial file from a failure is removed.
pub fn run_once(db: &Path, dir: &Path, keep: usize, now_ms: i64) -> anyhow::Result<Done> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create the backup directory {}", dir.display()))?;
    let path = dir.join(file_name(now_ms));
    let bytes = match crate::store::backup(db, &path) {
        Ok(n) => n,
        Err(e) => {
            // The file may exist from before this attempt (same second): leave that one alone.
            if !path.exists()
                || std::fs::metadata(&path)
                    .map(|m| m.len() == 0)
                    .unwrap_or(false)
            {
                let _ = std::fs::remove_file(&path);
            }
            return Err(e);
        }
    };
    let removed = rotate(dir, keep)?;
    Ok(Done {
        path,
        bytes,
        removed,
    })
}

/// Creates the directory and checks that it is writable, so a bad setting stops startup.
pub fn prepare(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create the backup directory {}", dir.display()))?;
    let probe = dir.join(format!(".write-test-{}", std::process::id()));
    std::fs::write(&probe, b"ok")
        .with_context(|| format!("the backup directory {} is not writable", dir.display()))?;
    let _ = std::fs::remove_file(probe);
    Ok(())
}

/// Runs backups on schedule for as long as the process lives.
pub async fn run(db: PathBuf, cfg: BackupConfig, metrics: Arc<Metrics>) {
    let Some(dir) = cfg.dir.clone() else {
        return;
    };
    let every = Duration::from_secs(cfg.every_hours * 3600);
    let mut wait = first_delay(&dir, every, now_ms());
    tracing::info!(
        "scheduled backups: every {}h into {} (keeping {}); next in {}s",
        cfg.every_hours,
        dir.display(),
        cfg.keep,
        wait.as_secs()
    );
    loop {
        tokio::time::sleep(wait).await;
        let (db, dir, keep) = (db.clone(), dir.clone(), cfg.keep);
        let result = tokio::task::spawn_blocking(move || run_once(&db, &dir, keep, now_ms())).await;
        match result {
            Ok(Ok(done)) => {
                Metrics::inc(&metrics.backups, 1);
                metrics.backup_last_ts.store(
                    u64::try_from(now_ms() / 1000).unwrap_or(0),
                    Ordering::Relaxed,
                );
                metrics
                    .backup_last_bytes
                    .store(done.bytes, Ordering::Relaxed);
                tracing::info!(
                    "backup written: {} ({} MB), {} old removed",
                    done.path.display(),
                    done.bytes / 1_000_000,
                    done.removed
                );
                wait = every;
            }
            Ok(Err(e)) => {
                Metrics::inc(&metrics.backup_errors, 1);
                tracing::error!("scheduled backup failed: {e:#}");
                wait = every.min(RETRY_AFTER);
            }
            Err(e) => {
                Metrics::inc(&metrics.backup_errors, 1);
                tracing::error!("scheduled backup task failed: {e}");
                wait = every.min(RETRY_AFTER);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LogEntry;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("logpit-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn database(dir: &Path, rows: usize) -> PathBuf {
        let path = dir.join("live.db");
        let mut conn = crate::store::open(&path).unwrap();
        let batch: Vec<LogEntry> = (0..rows)
            .map(|i| LogEntry {
                ts: i as i64,
                host: "h".into(),
                message: format!("row {i}"),
                ..Default::default()
            })
            .collect();
        crate::store::insert_batch(&mut conn, &batch).unwrap();
        path
    }

    #[test]
    fn names_sort_by_time_and_only_ours_are_recognised() {
        assert_eq!(file_name(1_791_028_800_000), "logpit-20261003T120000Z.db");
        assert!(file_name(1_000_000_000_000) < file_name(1_791_028_800_000));
        for ok in ["logpit-20261003T120000Z.db", "logpit-19700101T000000Z.db"] {
            assert!(is_ours(ok), "{ok}");
        }
        for other in [
            "logpit.db",
            "logpit-20261003T120000Z.db-wal",
            "logpit-20261003T120000Z.db.gz",
            "logpit-2026100312000Z.db",
            "logpit-2026100TT120000Z.db",
            "my-logpit-20261003T120000Z.db",
            "logpit-20261003T12000aZ.db",
            "logpit-20261003T120000Z.dbx",
        ] {
            assert!(!is_ours(other), "{other}");
        }
    }

    #[test]
    fn a_backup_is_a_consistent_copy_and_old_ones_are_rotated() {
        let dir = temp_dir("run");
        let db = database(&dir, 50);
        let out = dir.join("backups");
        // Foreign files in the directory are never touched.
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("notes.txt"), "keep me").unwrap();
        std::fs::write(out.join("logpit.db"), "not ours").unwrap();
        let mut last = None;
        for i in 0..5 {
            let done = run_once(&db, &out, 3, 1_791_028_800_000 + i * 1000).unwrap();
            assert!(done.bytes > 0);
            assert_eq!(done.removed, if i >= 3 { 1 } else { 0 }, "run {i}");
            last = Some(done.path);
        }
        let kept = list(&out).unwrap();
        assert_eq!(kept.len(), 3);
        assert!(kept[2].ends_with("logpit-20261003T120004Z.db"), "{kept:?}");
        assert!(kept[0].ends_with("logpit-20261003T120002Z.db"));
        assert!(out.join("notes.txt").exists() && out.join("logpit.db").exists());
        // The copy opens and has the data.
        let copy = crate::store::open(&last.unwrap()).unwrap();
        let n: i64 = copy
            .query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 50);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_backup_leaves_no_partial_file_and_keeps_the_old_ones() {
        let dir = temp_dir("fail");
        let out = dir.join("b");
        let db = database(&dir, 5);
        run_once(&db, &out, 5, 1_791_028_800_000).unwrap();
        // The database is gone: the backup fails and removes nothing it should keep.
        let missing = dir.join("missing.db");
        assert!(run_once(&missing, &out, 5, 1_791_028_801_000).is_err());
        assert_eq!(list(&out).unwrap().len(), 1);
        assert!(!out.join(file_name(1_791_028_801_000)).exists());
        // A second backup in the same second does not overwrite the first.
        assert!(run_once(&db, &out, 5, 1_791_028_800_000).is_err());
        assert_eq!(list(&out).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_first_backup_waits_out_the_interval_since_the_newest() {
        let dir = temp_dir("delay");
        let every = Duration::from_secs(24 * 3600);
        let t0 = 1_791_028_800_000; // the time of the newest backup below
        // None yet: shortly after start.
        assert_eq!(first_delay(&dir, every, t0), START_DELAY);
        std::fs::write(dir.join(file_name(t0)), b"x").unwrap();
        // Ten hours later: fourteen hours to go.
        assert_eq!(
            first_delay(&dir, every, t0 + 10 * 3_600_000),
            Duration::from_secs(14 * 3600)
        );
        // Overdue (or nearly due): no sooner than the start delay.
        assert_eq!(first_delay(&dir, every, t0 + 30 * 3_600_000), START_DELAY);
        assert_eq!(
            first_delay(&dir, every, t0 + 24 * 3_600_000 - 5_000),
            START_DELAY
        );
        // The newest counts, not the oldest.
        std::fs::write(dir.join(file_name(t0 - 86_400_000)), b"x").unwrap();
        assert_eq!(
            first_delay(&dir, every, t0 + 10 * 3_600_000),
            Duration::from_secs(14 * 3600)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_are_validated_and_the_directory_is_checked() {
        let ok = BackupConfig::default();
        assert!(ok.validate().is_ok());
        for bad in [
            BackupConfig {
                every_hours: 0,
                ..ok.clone()
            },
            BackupConfig {
                every_hours: 999_999,
                ..ok.clone()
            },
            BackupConfig {
                keep: 0,
                ..ok.clone()
            },
            BackupConfig {
                keep: 5000,
                ..ok.clone()
            },
            BackupConfig {
                dir: Some(PathBuf::new()),
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err());
        }
        assert!(toml::from_str::<BackupConfig>("bogus = 1").is_err());
        let dir = temp_dir("prep");
        prepare(&dir.join("new/nested")).unwrap();
        let file = dir.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(prepare(&file.join("sub")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
