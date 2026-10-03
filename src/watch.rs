//! Watching message patterns: a notification when a message template that was never seen before
//! appears (a new kind of error after a deployment), and optionally when a known template
//! suddenly shows up far more often than usual.
//!
//! Templates come from [`crate::patterns::template`]. The set of known templates lives in memory,
//! is seeded from the newest stored entries at startup and, to avoid a flood of "new" patterns
//! after a restart or on an empty database, nothing is announced during a learning period.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use anyhow::{Context, bail};
use regex::Regex;
use serde::Deserialize;

use crate::model::{LogEntry, severity_name};
use crate::rules::{SeveritySpec, severity_set};
use crate::silence::Event;

/// Entries read from the database to seed the known templates.
pub const SEED_ENTRIES: usize = 50_000;
const MAX_KNOWN_LIMIT: usize = 500_000;
/// Surge detection needs this many closed windows of history for a template.
const BASELINE_WINDOWS: u64 = 10;
/// Weight of the newest window in the moving average of a template's window counts.
const EWMA_WEIGHT: f64 = 0.1;
const MAX_WINDOW_SECS: u64 = 3600;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WatchConfig {
    /// Turns the watch on. It is off by default: it examines every entry that is ingested.
    pub enabled: bool,
    /// After startup (or when the watch is turned on) nothing is announced for this long, and
    /// the templates seen meanwhile are learned.
    pub learn_secs: u64,
    /// Only entries with these severities are watched (names or numbers); default: warning and
    /// above (`emerg` … `warning`).
    pub severity: Vec<SeveritySpec>,
    /// Messages matching one of these regular expressions are ignored.
    pub ignore: Vec<String>,
    /// Templates remembered; beyond that new ones are no longer learned or announced.
    pub max_known: usize,
    /// Most notifications per minute (new patterns and surges together); the rest are counted
    /// in `logpit_pattern_alerts_suppressed_total`.
    pub max_per_minute: u32,
    /// Notify when a known template appears at least this many times as often as its usual
    /// count per window (and `surge_min` times). `0` turns surge detection off.
    pub surge_factor: f64,
    /// A surge needs at least this many entries within one window.
    pub surge_min: u64,
    /// Length of the window surges are measured over.
    pub surge_window_secs: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            learn_secs: 600,
            severity: Vec::new(),
            ignore: Vec::new(),
            max_known: 20_000,
            max_per_minute: 10,
            surge_factor: 0.0,
            surge_min: 100,
            surge_window_secs: 60,
        }
    }
}

impl WatchConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        Settings::from_config(self).map(|_| ())
    }
}

struct Settings {
    enabled: bool,
    learn_ms: i64,
    severities: [bool; 8],
    ignore: Vec<Regex>,
    max_known: usize,
    max_per_minute: u32,
    surge_factor: f64,
    surge_min: u64,
    window_ms: i64,
}

impl Settings {
    fn from_config(c: &WatchConfig) -> anyhow::Result<Self> {
        if c.max_known == 0 || c.max_known > MAX_KNOWN_LIMIT {
            bail!("new_patterns.max_known must be between 1 and {MAX_KNOWN_LIMIT}");
        }
        if c.surge_window_secs == 0 || c.surge_window_secs > MAX_WINDOW_SECS {
            bail!("new_patterns.surge_window_secs must be between 1 and {MAX_WINDOW_SECS}");
        }
        if !c.surge_factor.is_finite() || c.surge_factor < 0.0 {
            bail!("new_patterns.surge_factor must be 0 (off) or a positive number");
        }
        if c.surge_factor > 0.0 && c.surge_factor < 1.0 {
            bail!("new_patterns.surge_factor must be at least 1");
        }
        if c.learn_secs > 30 * 86_400 {
            bail!("new_patterns.learn_secs must be at most 30 days");
        }
        let ignore = c
            .ignore
            .iter()
            .map(|p| {
                crate::filters::compile_regex(p)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("new_patterns.ignore {p:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        // Warning and above unless told otherwise.
        let severities = severity_set(&c.severity)?
            .unwrap_or([true, true, true, true, true, false, false, false]);
        Ok(Self {
            enabled: c.enabled,
            learn_ms: i64::try_from(c.learn_secs).unwrap_or(0) * 1000,
            severities,
            ignore,
            max_known: c.max_known,
            max_per_minute: c.max_per_minute,
            surge_factor: c.surge_factor,
            surge_min: c.surge_min,
            window_ms: i64::try_from(c.surge_window_secs).unwrap_or(60) * 1000,
        })
    }
}

/// What is remembered about a template.
struct Known {
    /// Entries in the current window.
    count: u64,
    window_start: i64,
    /// Moving average of the counts of closed windows.
    usual: f64,
    /// Closed windows seen so far (history for the average).
    windows: u64,
    last_surge: i64,
}

struct State {
    known: HashMap<String, Known>,
    /// Nothing is announced before this time (Unix ms).
    learning_until: i64,
    minute_start: i64,
    sent_this_minute: u32,
    full_warned: bool,
}

pub struct PatternWatch {
    settings: RwLock<Settings>,
    state: Mutex<State>,
    new_patterns: AtomicU64,
    surges: AtomicU64,
    suppressed: AtomicU64,
}

impl Default for PatternWatch {
    fn default() -> Self {
        Self::new(&WatchConfig::default(), 0).expect("the default watch settings are valid")
    }
}

impl PatternWatch {
    pub fn new(cfg: &WatchConfig, now: i64) -> anyhow::Result<Self> {
        let settings = Settings::from_config(cfg)?;
        Ok(Self {
            state: Mutex::new(State {
                known: HashMap::new(),
                learning_until: now + settings.learn_ms,
                minute_start: now,
                sent_this_minute: 0,
                full_warned: false,
            }),
            settings: RwLock::new(settings),
            new_patterns: AtomicU64::new(0),
            surges: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        })
    }

    pub fn enabled(&self) -> bool {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .enabled
    }

    /// Applies new settings, keeping the templates learned so far. Turning the watch on starts a
    /// new learning period.
    pub fn reconfigure(&self, cfg: &WatchConfig, now: i64) -> anyhow::Result<()> {
        let new = Settings::from_config(cfg)?;
        let was_enabled = self.enabled();
        let learn_ms = new.learn_ms;
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = new;
        if cfg.enabled && !was_enabled {
            self.lock().learning_until = now + learn_ms;
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Learns the templates of already stored entries, so that they are not announced as new.
    pub fn seed<'a>(&self, messages: impl IntoIterator<Item = (u8, &'a str)>, now: i64) {
        let settings = self.settings.read().unwrap_or_else(|e| e.into_inner());
        let mut state = self.lock();
        for (severity, message) in messages {
            if state.known.len() >= settings.max_known {
                break;
            }
            if !settings.severities[usize::from(severity.min(7))] {
                continue;
            }
            let template = crate::patterns::template(message);
            if !template.is_empty() {
                state
                    .known
                    .entry(template)
                    .or_insert_with(|| Known::new(now));
            }
        }
    }

    /// Examines an entry that arrived at `now` (Unix ms) and returns the notifications due.
    pub fn observe(&self, entry: &LogEntry, now: i64) -> Vec<Event> {
        let settings = self.settings.read().unwrap_or_else(|e| e.into_inner());
        if !settings.enabled || !settings.severities[usize::from(entry.severity.min(7))] {
            return Vec::new();
        }
        if settings.ignore.iter().any(|re| re.is_match(&entry.message)) {
            return Vec::new();
        }
        let template = crate::patterns::template(&entry.message);
        if template.is_empty() {
            return Vec::new();
        }
        let mut state = self.lock();
        let mut due = None;
        if let Some(known) = state.known.get_mut(&template) {
            if known.observe(now, &settings) {
                due = Some(Notice::Surge {
                    count: known.count,
                    usual: known.usual,
                });
            }
        } else if state.known.len() >= settings.max_known {
            if !state.full_warned {
                state.full_warned = true;
                tracing::warn!(
                    "new_patterns: {} templates are known, new ones are no longer announced \
                     (raise new_patterns.max_known)",
                    settings.max_known
                );
            }
        } else {
            let mut known = Known::new(now);
            known.count = 1;
            state.known.insert(template.clone(), known);
            if now >= state.learning_until {
                due = Some(Notice::New);
            }
        }
        let Some(notice) = due else {
            return Vec::new();
        };
        // At most `max_per_minute` notifications per minute.
        if now - state.minute_start >= 60_000 || now < state.minute_start {
            state.minute_start = now;
            state.sent_this_minute = 0;
        }
        if state.sent_this_minute >= settings.max_per_minute {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        state.sent_this_minute += 1;
        drop(state);
        let sample = entry.message.clone();
        match notice {
            Notice::New => {
                self.new_patterns.fetch_add(1, Ordering::Relaxed);
                vec![Event::NewPattern {
                    pattern: template,
                    host: entry.host.clone(),
                    severity: severity_name(entry.severity).to_string(),
                    sample,
                }]
            }
            Notice::Surge { count, usual } => {
                self.surges.fetch_add(1, Ordering::Relaxed);
                vec![Event::Surge {
                    pattern: template,
                    count,
                    usual: usual.round() as u64,
                    window_secs: u64::try_from(settings.window_ms / 1000).unwrap_or(0),
                    sample,
                }]
            }
        }
    }

    /// Prometheus text for the watch; empty while it is off.
    pub fn render_metrics(&self) -> String {
        if !self.enabled() {
            return String::new();
        }
        let mut out = String::new();
        let known = self.lock().known.len();
        for (name, kind, help, value) in [
            (
                "logpit_new_patterns_total",
                "counter",
                "New message patterns announced",
                self.new_patterns.load(Ordering::Relaxed),
            ),
            (
                "logpit_pattern_surges_total",
                "counter",
                "Message pattern surges announced",
                self.surges.load(Ordering::Relaxed),
            ),
            (
                "logpit_pattern_alerts_suppressed_total",
                "counter",
                "Pattern notifications dropped by max_per_minute",
                self.suppressed.load(Ordering::Relaxed),
            ),
            (
                "logpit_known_patterns",
                "gauge",
                "Message templates currently remembered",
                known as u64,
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}"
            );
        }
        out
    }
}

enum Notice {
    New,
    Surge { count: u64, usual: f64 },
}

impl Known {
    fn new(now: i64) -> Self {
        Self {
            count: 0,
            window_start: now,
            usual: 0.0,
            windows: 0,
            last_surge: i64::MIN,
        }
    }

    /// Counts an entry of a known template; true when it makes a surge.
    fn observe(&mut self, now: i64, s: &Settings) -> bool {
        if s.surge_factor <= 0.0 {
            return false;
        }
        if now < self.window_start {
            // The clock went back: start over rather than miscount.
            self.window_start = now;
            self.count = 0;
        }
        let elapsed = (now - self.window_start) / s.window_ms;
        if elapsed > 0 {
            // The window that just ended counts, then the empty ones after it, each decaying
            // the average; cap the loop, since a long silence has decayed it long before.
            let mut next = self.count as f64;
            for _ in 0..elapsed.min(64) {
                self.usual = if self.windows == 0 {
                    next
                } else {
                    (1.0 - EWMA_WEIGHT) * self.usual + EWMA_WEIGHT * next
                };
                self.windows += 1;
                next = 0.0;
            }
            self.window_start += elapsed * s.window_ms;
            self.count = 0;
        }
        self.count += 1;
        let quiet_since_surge = now.saturating_sub(self.last_surge) >= 5 * s.window_ms;
        if self.windows >= BASELINE_WINDOWS
            && self.count >= s.surge_min
            && self.count as f64 >= s.surge_factor * self.usual.max(1.0)
            && quiet_since_surge
        {
            self.last_surge = now;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml_text: &str) -> WatchConfig {
        let mut c: WatchConfig = toml::from_str(toml_text).unwrap();
        c.enabled = true;
        c
    }

    fn entry(severity: u8, message: &str) -> LogEntry {
        LogEntry {
            host: "web1".into(),
            app: "app".into(),
            severity,
            message: message.into(),
            ..Default::default()
        }
    }

    fn watch(toml_text: &str) -> PatternWatch {
        PatternWatch::new(&cfg(toml_text), 0).unwrap()
    }

    const T: i64 = 1_000_000;

    #[test]
    fn announces_a_template_once_after_the_learning_period() {
        let w = watch("learn_secs = 100");
        let e = |n: u32| entry(3, &format!("disk {n} failed"));
        // During learning, templates are learned silently.
        assert!(w.observe(&e(1), 50_000).is_empty());
        // A known template is not new, whatever its numbers.
        assert!(w.observe(&e(2), T).is_empty());
        // A different one is.
        let ev = w.observe(&entry(3, "kernel panic at 0xdead"), T);
        assert_eq!(ev.len(), 1);
        match &ev[0] {
            Event::NewPattern {
                pattern,
                host,
                severity,
                sample,
            } => {
                assert_eq!(pattern, "kernel panic at <*>");
                assert_eq!((host.as_str(), severity.as_str()), ("web1", "err"));
                assert_eq!(sample, "kernel panic at 0xdead");
            }
            other => panic!("{other:?}"),
        }
        // Only once.
        assert!(
            w.observe(&entry(3, "kernel panic at 0xbeef"), T + 1)
                .is_empty()
        );
    }

    #[test]
    fn severity_and_ignore_decide_what_is_watched() {
        let w = watch("learn_secs = 0\nignore = [\"healthcheck\"]");
        // Info is not watched by default, and does not make the pattern known at err level.
        assert!(w.observe(&entry(6, "worker 4 started"), T).is_empty());
        assert_eq!(w.observe(&entry(3, "worker 4 started"), T).len(), 1);
        assert!(
            w.observe(&entry(3, "healthcheck failed for db"), T)
                .is_empty()
        );
        let only_crit = watch("learn_secs = 0\nseverity = [\"crit\"]");
        assert!(only_crit.observe(&entry(3, "boom"), T).is_empty());
        assert_eq!(only_crit.observe(&entry(2, "boom"), T).len(), 1);
        // An empty message has no template.
        assert!(w.observe(&entry(3, "   "), T).is_empty());
    }

    #[test]
    fn disabled_watch_does_nothing() {
        let w = PatternWatch::default();
        assert!(!w.enabled());
        assert!(w.observe(&entry(0, "anything"), T).is_empty());
        assert_eq!(w.render_metrics(), "");
    }

    #[test]
    fn seeding_marks_stored_templates_as_known() {
        let w = watch("learn_secs = 0");
        w.seed(
            [
                (3u8, "disk 1 failed"),
                (6, "chatty 5"),
                (4, "cert expires in 9 days"),
            ],
            0,
        );
        assert!(w.observe(&entry(3, "disk 77 failed"), T).is_empty());
        assert!(w.observe(&entry(4, "cert expires in 2 days"), T).is_empty());
        // Info was outside the watched severities, so it was not learned.
        assert_eq!(w.observe(&entry(4, "chatty 6"), T).len(), 1);
    }

    #[test]
    fn notifications_are_throttled_per_minute() {
        let w = watch("learn_secs = 0\nmax_per_minute = 2");
        let sent: usize = (0..5)
            .map(|i| {
                w.observe(&entry(3, &format!("kind{} broke", "x".repeat(i + 1))), T)
                    .len()
            })
            .sum();
        assert_eq!(sent, 2);
        assert!(
            w.render_metrics()
                .contains("logpit_pattern_alerts_suppressed_total 3")
        );
        // The next minute has room again.
        assert_eq!(
            w.observe(&entry(3, "yet another thing"), T + 61_000).len(),
            1
        );
    }

    #[test]
    fn known_templates_stop_at_the_cap_without_announcing() {
        let w = watch("learn_secs = 0\nmax_known = 2");
        assert_eq!(w.observe(&entry(3, "aaa"), T).len(), 1);
        assert_eq!(w.observe(&entry(3, "bbb"), T).len(), 1);
        assert!(w.observe(&entry(3, "ccc"), T).is_empty());
        assert!(w.render_metrics().contains("logpit_known_patterns 2"));
    }

    #[test]
    fn a_surge_needs_history_volume_and_a_jump() {
        // Windows of 10 s; a surge is 5x the usual count and at least 20 entries.
        let w = watch("learn_secs = 0\nsurge_factor = 5\nsurge_min = 20\nsurge_window_secs = 10");
        let e = entry(3, "retry 3 failed");
        let burst = |from: i64, n: i64| -> usize {
            (0..n)
                .map(|i| {
                    w.observe(&e, from + i * 10)
                        .iter()
                        .filter(|e| matches!(e, Event::Surge { .. }))
                        .count()
                })
                .sum()
        };
        // 12 quiet windows with 2 entries each build the baseline (~2 per window).
        for win in 0..12 {
            assert_eq!(burst(T + win * 10_000, 2), 0);
        }
        // 15 entries in a window is a jump but below the minimum.
        assert_eq!(burst(T + 12 * 10_000, 15), 0);
        // 40 entries is both.
        assert_eq!(burst(T + 13 * 10_000, 40), 1, "one notification per surge");
        // The surge is not repeated in the following windows while it lasts.
        assert_eq!(burst(T + 14 * 10_000, 40), 0);
        assert!(w.render_metrics().contains("logpit_pattern_surges_total 1"));
    }

    #[test]
    fn no_surge_without_a_baseline_or_when_off() {
        let off = watch("learn_secs = 0");
        let e = entry(3, "hot 1");
        let mut n = 0;
        for i in 0..500 {
            n += off.observe(&e, T + i).len();
        }
        assert_eq!(n, 1, "only the new-pattern notice");
        let young = watch("learn_secs = 0\nsurge_factor = 2\nsurge_min = 5");
        let mut surges = 0;
        for i in 0..500 {
            surges += young
                .observe(&e, T + i)
                .iter()
                .filter(|e| matches!(e, Event::Surge { .. }))
                .count();
        }
        assert_eq!(surges, 0, "the template has no history yet");
    }

    #[test]
    fn reconfigure_keeps_known_templates_and_relearns_when_turned_on() {
        let w = PatternWatch::new(&WatchConfig::default(), 0).unwrap();
        assert!(!w.enabled());
        w.reconfigure(&cfg("learn_secs = 100"), T).unwrap();
        assert!(w.enabled());
        // Learning for 100 s from the moment it was turned on.
        assert!(w.observe(&entry(3, "first thing"), T + 50_000).is_empty());
        assert_eq!(w.observe(&entry(3, "second thing"), T + 150_000).len(), 1);
        assert!(w.observe(&entry(3, "first thing"), T + 151_000).is_empty());
        // Changing other settings does not start a new learning period or forget templates.
        w.reconfigure(&cfg("learn_secs = 100\nmax_per_minute = 1"), T + 152_000)
            .unwrap();
        assert!(w.observe(&entry(3, "second thing"), T + 153_000).is_empty());
        // The one allowed notification of that minute went to "second thing".
        assert!(w.observe(&entry(3, "third thing"), T + 154_000).is_empty());
        assert_eq!(w.observe(&entry(3, "fourth thing"), T + 215_000).len(), 1);
        assert!(w.reconfigure(&cfg("max_known = 0"), 0).is_err());
    }

    #[test]
    fn invalid_settings_are_refused() {
        for bad in [
            "max_known = 0",
            "surge_window_secs = 0",
            "surge_factor = 0.5",
            "surge_factor = -1",
            "ignore = [\"(\"]",
            "severity = [\"loud\"]",
            "learn_secs = 99999999",
        ] {
            assert!(cfg(bad).validate().is_err(), "{bad}");
        }
        assert!(cfg("surge_factor = 3").validate().is_ok());
        assert!(toml::from_str::<WatchConfig>("bogus = 1").is_err());
    }
}
