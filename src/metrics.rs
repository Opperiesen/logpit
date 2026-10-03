use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide counters exposed on `/metrics` in Prometheus text format.
#[derive(Default)]
pub struct Metrics {
    /// Entries accepted into the write queue.
    pub received: AtomicU64,
    /// Entries dropped because the write queue was full.
    pub dropped: AtomicU64,
    /// Inputs that could not be parsed or exceeded limits.
    pub rejected: AtomicU64,
    /// Entries durably written to SQLite.
    pub stored: AtomicU64,
    /// Failed batch writes.
    pub write_errors: AtomicU64,
    /// Entries evicted to stay under `storage.max_db_size_mb`.
    pub size_evicted: AtomicU64,
    /// TLS connections that failed or timed out during the handshake.
    pub tls_failures: AtomicU64,
    /// Configuration reloads (SIGHUP) that were applied.
    pub reloads: AtomicU64,
    /// Configuration reloads that failed and left the running configuration untouched.
    pub reload_failures: AtomicU64,
    /// Bytes of the database holding data, as last measured by the retention task.
    pub db_used_bytes: AtomicU64,
    /// Entries written to the cold archive before being removed.
    pub archived: AtomicU64,
    /// Archive writes that failed (the entries were kept in the database).
    pub archive_errors: AtomicU64,
    /// Scheduled backups written, and that failed.
    pub backups: AtomicU64,
    pub backup_errors: AtomicU64,
    /// Unix seconds of the last successful scheduled backup (0: none yet) and its size.
    pub backup_last_ts: AtomicU64,
    pub backup_last_bytes: AtomicU64,
    /// Whether scheduled backups are configured, which decides if their metrics are shown.
    pub backup_enabled: std::sync::atomic::AtomicBool,
}

impl Metrics {
    pub fn inc(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let rows = [
            (
                "logpit_received_total",
                "Entries accepted into the write queue",
                &self.received,
            ),
            (
                "logpit_dropped_total",
                "Entries dropped because the queue was full",
                &self.dropped,
            ),
            (
                "logpit_rejected_total",
                "Inputs rejected as invalid or oversized",
                &self.rejected,
            ),
            (
                "logpit_stored_total",
                "Entries written to storage",
                &self.stored,
            ),
            (
                "logpit_write_errors_total",
                "Failed storage batch writes",
                &self.write_errors,
            ),
            (
                "logpit_config_reloads_total",
                "Configuration reloads applied",
                &self.reloads,
            ),
            (
                "logpit_config_reload_failures_total",
                "Configuration reloads that failed (the running configuration was kept)",
                &self.reload_failures,
            ),
            (
                "logpit_tls_handshake_failures_total",
                "TLS connections (syslog and HTTPS) that failed the handshake",
                &self.tls_failures,
            ),
            (
                "logpit_size_evicted_total",
                "Entries evicted to stay under the database size limit",
                &self.size_evicted,
            ),
            (
                "logpit_archived_total",
                "Entries written to the cold archive before removal",
                &self.archived,
            ),
            (
                "logpit_archive_errors_total",
                "Cold archive writes that failed, which keep the entries in the database",
                &self.archive_errors,
            ),
        ];
        for (name, help, counter) in rows {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {}", counter.load(Ordering::Relaxed));
        }
        let _ = writeln!(
            out,
            "# HELP logpit_db_used_bytes Database bytes holding data\n# TYPE logpit_db_used_bytes gauge\nlogpit_db_used_bytes {}",
            self.db_used_bytes.load(Ordering::Relaxed)
        );
        if self.backup_enabled.load(Ordering::Relaxed) {
            let _ = writeln!(
                out,
                "# HELP logpit_backups_total Scheduled backups written\n# TYPE logpit_backups_total counter\nlogpit_backups_total {}\n\
                 # HELP logpit_backup_errors_total Scheduled backups that failed\n# TYPE logpit_backup_errors_total counter\nlogpit_backup_errors_total {}\n\
                 # HELP logpit_backup_last_success_timestamp_seconds Unix time of the last scheduled backup (0 if none yet)\n# TYPE logpit_backup_last_success_timestamp_seconds gauge\nlogpit_backup_last_success_timestamp_seconds {}\n\
                 # HELP logpit_backup_last_size_bytes Size of the last scheduled backup\n# TYPE logpit_backup_last_size_bytes gauge\nlogpit_backup_last_size_bytes {}",
                self.backups.load(Ordering::Relaxed),
                self.backup_errors.load(Ordering::Relaxed),
                self.backup_last_ts.load(Ordering::Relaxed),
                self.backup_last_bytes.load(Ordering::Relaxed)
            );
        }
        out
    }
}
