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
    /// Bytes of the database holding data, as last measured by the retention task.
    pub db_used_bytes: AtomicU64,
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
                "logpit_tls_handshake_failures_total",
                "Syslog TLS connections that failed the handshake",
                &self.tls_failures,
            ),
            (
                "logpit_size_evicted_total",
                "Entries evicted to stay under the database size limit",
                &self.size_evicted,
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
        out
    }
}
