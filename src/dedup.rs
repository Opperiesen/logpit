//! Collapsing repeated messages at ingestion: the first of a run of identical entries (same host,
//! app, severity and message) is stored as usual, the identical ones that follow within the
//! window are only counted, and when the window ends one summary entry
//! (`<message> [repeated N more times over Ds]`, with a `repeats` field) takes their place.
//!
//! Alerts, metrics and rate limits still see every entry: only what is stored and shown in the
//! live tail is reduced.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use anyhow::bail;
use serde::Deserialize;

use crate::model::LogEntry;

/// Messages longer than this are never collapsed, so a group's memory stays small.
const MAX_MESSAGE_BYTES: usize = 2048;
const MAX_WINDOW_SECS: u64 = 3600;
const MAX_KEYS_LIMIT: usize = 1_000_000;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DedupConfig {
    /// Turns it on. Off by default: every repeated message is stored.
    pub enabled: bool,
    /// How long identical entries are counted after the first one before a summary replaces them.
    pub window_secs: u64,
    /// Distinct messages tracked at once; when full, new ones are stored without collapsing.
    pub max_keys: usize,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: 30,
            max_keys: 10_000,
        }
    }
}

impl DedupConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.window_secs == 0 || self.window_secs > MAX_WINDOW_SECS {
            bail!("ingest.dedup.window_secs must be between 1 and {MAX_WINDOW_SECS}");
        }
        if self.max_keys == 0 || self.max_keys > MAX_KEYS_LIMIT {
            bail!("ingest.dedup.max_keys must be between 1 and {MAX_KEYS_LIMIT}");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Settings {
    enabled: bool,
    window_ms: i64,
    max_keys: usize,
}

#[derive(Hash, PartialEq, Eq)]
struct Key {
    host: String,
    app: String,
    severity: u8,
    message: String,
}

struct Group {
    /// Arrival of the first entry, when the window started.
    start: i64,
    /// Timestamp of the latest identical entry.
    last_ts: i64,
    suppressed: u64,
}

pub struct Dedup {
    settings: RwLock<Settings>,
    groups: Mutex<HashMap<Key, Group>>,
    suppressed_total: AtomicU64,
    summaries_total: AtomicU64,
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new(&DedupConfig::default())
    }
}

fn settings_of(cfg: &DedupConfig) -> Settings {
    Settings {
        enabled: cfg.enabled,
        window_ms: i64::try_from(cfg.window_secs).unwrap_or(30) * 1000,
        max_keys: cfg.max_keys,
    }
}

impl Dedup {
    pub fn new(cfg: &DedupConfig) -> Self {
        Self {
            settings: RwLock::new(settings_of(cfg)),
            groups: Mutex::new(HashMap::new()),
            suppressed_total: AtomicU64::new(0),
            summaries_total: AtomicU64::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .enabled
    }

    /// Applies new settings; groups in flight finish with the window they started with.
    pub fn reconfigure(&self, cfg: &DedupConfig) {
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = settings_of(cfg);
    }

    /// Looks at an entry that arrived at `now` (Unix ms). Returns whether to store it, and the
    /// summary of the run it ends, if any.
    pub fn observe(&self, e: &LogEntry, now: i64) -> (bool, Option<LogEntry>) {
        let s = *self.settings.read().unwrap_or_else(|p| p.into_inner());
        if !s.enabled || e.message.len() > MAX_MESSAGE_BYTES {
            return (true, None);
        }
        let key = Key {
            host: e.host.clone(),
            app: e.app.clone(),
            severity: e.severity,
            message: e.message.clone(),
        };
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        match groups.get_mut(&key) {
            Some(g) if now >= g.start && now - g.start < s.window_ms => {
                g.suppressed += 1;
                g.last_ts = g.last_ts.max(e.ts);
                self.suppressed_total.fetch_add(1, Ordering::Relaxed);
                (false, None)
            }
            Some(g) => {
                // The window is over (or the clock went back): summarize it and start another.
                let summary = self.summary(&key, g);
                *g = Group {
                    start: now,
                    last_ts: e.ts,
                    suppressed: 0,
                };
                (true, summary)
            }
            None => {
                if groups.len() < s.max_keys {
                    groups.insert(
                        key,
                        Group {
                            start: now,
                            last_ts: e.ts,
                            suppressed: 0,
                        },
                    );
                }
                (true, None)
            }
        }
    }

    fn summary(&self, key: &Key, g: &Group) -> Option<LogEntry> {
        if g.suppressed == 0 {
            return None;
        }
        self.summaries_total.fetch_add(1, Ordering::Relaxed);
        let secs = (g.last_ts - g.start).max(0) / 1000;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("repeats".to_string(), g.suppressed.to_string());
        Some(LogEntry {
            ts: g.last_ts,
            host: key.host.clone(),
            app: key.app.clone(),
            severity: key.severity,
            message: format!(
                "{} [repeated {} more times over {secs}s]",
                key.message, g.suppressed
            ),
            fields,
        })
    }

    /// Closes the groups whose window ended by `now` and returns their summaries.
    pub fn flush(&self, now: i64) -> Vec<LogEntry> {
        let window = self
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .window_ms;
        self.drain(|g| now < g.start || now - g.start >= window)
    }

    /// Closes every group, for shutdown.
    pub fn flush_all(&self) -> Vec<LogEntry> {
        self.drain(|_| true)
    }

    fn drain(&self, due: impl Fn(&Group) -> bool) -> Vec<LogEntry> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::new();
        groups.retain(|key, g| {
            if !due(g) {
                return true;
            }
            out.extend(self.summary(key, g));
            false
        });
        out.sort_by_key(|e| e.ts);
        out
    }

    /// Prometheus text; empty while it is off.
    pub fn render_metrics(&self) -> String {
        if !self.enabled() {
            return String::new();
        }
        let groups = self.groups.lock().unwrap_or_else(|p| p.into_inner()).len();
        format!(
            "# HELP logpit_dedup_suppressed_total Repeated entries counted instead of stored\n\
             # TYPE logpit_dedup_suppressed_total counter\n\
             logpit_dedup_suppressed_total {}\n\
             # HELP logpit_dedup_summaries_total Summary entries stored for runs of repeats\n\
             # TYPE logpit_dedup_summaries_total counter\n\
             logpit_dedup_summaries_total {}\n\
             # HELP logpit_dedup_groups Distinct messages currently being collapsed\n\
             # TYPE logpit_dedup_groups gauge\n\
             logpit_dedup_groups {groups}\n",
            self.suppressed_total.load(Ordering::Relaxed),
            self.summaries_total.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dedup(window_secs: u64, max_keys: usize) -> Dedup {
        Dedup::new(&DedupConfig {
            enabled: true,
            window_secs,
            max_keys,
        })
    }

    fn entry(ts: i64, host: &str, severity: u8, message: &str) -> LogEntry {
        LogEntry {
            ts,
            host: host.into(),
            app: "app".into(),
            severity,
            message: message.into(),
            ..Default::default()
        }
    }

    #[test]
    fn repeats_inside_the_window_are_counted_and_summarized_when_it_ends() {
        let d = dedup(10, 100);
        let e = |ts| entry(ts, "h", 4, "link down");
        assert_eq!(d.observe(&e(0), 0), (true, None), "the first one is stored");
        for t in [1000, 2000, 5000] {
            assert_eq!(d.observe(&e(t), t), (false, None));
        }
        // Nothing is due before the window ends.
        assert!(d.flush(9_999).is_empty());
        let summaries = d.flush(10_000);
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.message, "link down [repeated 3 more times over 5s]");
        assert_eq!((s.ts, s.host.as_str(), s.severity), (5000, "h", 4));
        assert_eq!(s.fields["repeats"], "3");
        // The group is gone, so the next one starts a new run and is stored.
        assert_eq!(d.observe(&e(11_000), 11_000), (true, None));
        assert!(d.flush(11_000).is_empty());
    }

    #[test]
    fn an_entry_after_the_window_ends_the_run_itself() {
        let d = dedup(10, 100);
        let e = |ts| entry(ts, "h", 6, "tick");
        d.observe(&e(0), 0);
        d.observe(&e(1000), 1000);
        let (stored, summary) = d.observe(&e(12_000), 12_000);
        assert!(stored, "it starts the next run");
        assert_eq!(
            summary.unwrap().message,
            "tick [repeated 1 more times over 1s]"
        );
        // A run without repeats ends silently.
        assert_eq!(d.observe(&e(30_000), 30_000), (true, None));
    }

    #[test]
    fn only_identical_host_app_severity_and_message_collapse() {
        let d = dedup(10, 100);
        assert!(d.observe(&entry(0, "a", 6, "x"), 0).0);
        assert!(!d.observe(&entry(1, "a", 6, "x"), 1).0);
        assert!(d.observe(&entry(2, "b", 6, "x"), 2).0, "another host");
        assert!(d.observe(&entry(3, "a", 3, "x"), 3).0, "another severity");
        assert!(d.observe(&entry(4, "a", 6, "y"), 4).0, "another message");
        let mut other_app = entry(5, "a", 6, "x");
        other_app.app = "other".into();
        assert!(d.observe(&other_app, 5).0);
    }

    #[test]
    fn disabled_long_and_overflowing_entries_pass_through() {
        let off = Dedup::default();
        assert!(!off.enabled());
        assert_eq!(off.observe(&entry(0, "h", 6, "x"), 0), (true, None));
        assert_eq!(off.observe(&entry(1, "h", 6, "x"), 1), (true, None));
        assert_eq!(off.render_metrics(), "");
        let d = dedup(10, 2);
        let long = "z".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(d.observe(&entry(0, "h", 6, &long), 0).0);
        assert!(
            d.observe(&entry(1, "h", 6, &long), 1).0,
            "too long to track"
        );
        // With the table full, new messages are stored but not tracked.
        assert!(d.observe(&entry(0, "h", 6, "a"), 0).0);
        assert!(d.observe(&entry(0, "h", 6, "b"), 0).0);
        assert!(d.observe(&entry(0, "h", 6, "c"), 0).0);
        assert!(
            d.observe(&entry(1, "h", 6, "c"), 1).0,
            "c was never tracked"
        );
        assert!(!d.observe(&entry(1, "h", 6, "a"), 1).0, "a was");
    }

    #[test]
    fn flush_all_closes_everything_oldest_first() {
        let d = dedup(60, 100);
        for (t, m) in [(0, "a"), (1, "b")] {
            d.observe(&entry(t, "h", 6, m), t);
        }
        d.observe(&entry(500, "h", 6, "b"), 500);
        d.observe(&entry(900, "h", 6, "a"), 900);
        d.observe(&entry(950, "h", 6, "a"), 950);
        let all = d.flush_all();
        assert_eq!(
            all.iter()
                .map(|e| (e.ts, e.message.as_str()))
                .collect::<Vec<_>>(),
            [
                (500, "b [repeated 1 more times over 0s]"),
                (950, "a [repeated 2 more times over 0s]")
            ]
        );
        assert!(d.flush_all().is_empty());
        let text = d.render_metrics();
        assert!(text.contains("logpit_dedup_suppressed_total 3"));
        assert!(text.contains("logpit_dedup_summaries_total 2"));
        assert!(text.contains("logpit_dedup_groups 0"));
    }

    #[test]
    fn a_clock_that_goes_back_does_not_hold_a_run_open() {
        let d = dedup(10, 100);
        d.observe(&entry(100_000, "h", 6, "x"), 100_000);
        assert!(!d.observe(&entry(100_500, "h", 6, "x"), 100_500).0);
        // Now earlier than the start: the run is closed rather than counted forever.
        let (stored, summary) = d.observe(&entry(1_000, "h", 6, "x"), 1_000);
        assert!(stored);
        assert!(summary.is_some());
        assert_eq!(d.flush(1_000_000).len(), 0);
    }

    #[test]
    fn settings_are_validated() {
        let ok = DedupConfig::default();
        assert!(ok.validate().is_ok());
        for bad in [
            DedupConfig {
                window_secs: 0,
                ..ok.clone()
            },
            DedupConfig {
                window_secs: 99_999,
                ..ok.clone()
            },
            DedupConfig {
                max_keys: 0,
                ..ok.clone()
            },
            DedupConfig {
                max_keys: usize::MAX,
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err());
        }
        assert!(toml::from_str::<DedupConfig>("bogus = 1").is_err());
    }
}
