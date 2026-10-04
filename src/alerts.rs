//! Pattern alerts: notify when entries matching a condition pile up, such as five disk errors
//! in ten minutes, or any host logging more than a thousand lines a minute.
//!
//! Each rule keeps the arrival times of its last `count` matches (so memory is bounded by `count`,
//! not by traffic) and fires when `count` matches fall within `window_secs`. After firing it
//! clears them and stays quiet for `cooldown_secs`; matches during the cooldown still count, so a
//! problem that goes on is reported again once the cooldown ends.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::model::LogEntry;
use crate::rules::{SeveritySpec, severity_set};
use crate::silence::Event;

const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Largest `count` accepted; the ring of timestamps holds this many numbers per tracked key.
const MAX_COUNT: usize = 10_000;
/// With `per_host`, at most this many hosts are tracked per rule.
const MAX_KEYS: usize = 1024;
const MAX_WINDOW_SECS: u64 = 7 * 86_400;

#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AlertConfig {
    /// Label in notifications and metrics; defaults to `alert-<position>`.
    pub name: Option<String>,
    /// Only entries whose message matches this regular expression.
    pub pattern: Option<String>,
    /// Only entries from this host (exact match).
    pub host: Option<String>,
    /// Only entries from this app (exact match).
    pub app: Option<String>,
    /// Only entries with one of these severities (names or numbers).
    #[serde(default)]
    pub severity: Vec<SeveritySpec>,
    /// Fire when this many matching entries arrive within `window_secs`.
    pub count: usize,
    pub window_secs: u64,
    /// Minimum time between two notifications of this rule (per host); defaults to `window_secs`.
    pub cooldown_secs: Option<u64>,
    /// Count and notify per host instead of across all hosts.
    #[serde(default)]
    pub per_host: bool,
}

struct Ring {
    times: VecDeque<i64>,
    last_fired: Option<i64>,
}

struct Alert {
    name: String,
    host: Option<String>,
    app: Option<String>,
    severities: Option<[bool; 8]>,
    pattern: Option<Regex>,
    count: usize,
    window_ms: i64,
    cooldown_ms: i64,
    per_host: bool,
    state: Mutex<HashMap<String, Ring>>,
    fired: AtomicU64,
}

#[derive(Default)]
pub struct AlertRules {
    alerts: Vec<Alert>,
}

impl AlertRules {
    pub fn from_config(configs: &[AlertConfig]) -> anyhow::Result<Self> {
        let mut alerts = Vec::with_capacity(configs.len());
        let mut names = std::collections::HashSet::new();
        for (i, c) in configs.iter().enumerate() {
            let name = c.name.clone().unwrap_or_else(|| format!("alert-{}", i + 1));
            let ctx = || format!("alert {name:?}");
            if name.is_empty() {
                bail!("alert {} has an empty name", i + 1);
            }
            if !names.insert(name.clone()) {
                bail!("{}: the name is used by another alert", ctx());
            }
            if c.count == 0 || c.count > MAX_COUNT {
                bail!("{}: count must be between 1 and {MAX_COUNT}", ctx());
            }
            if c.window_secs == 0 || c.window_secs > MAX_WINDOW_SECS {
                bail!(
                    "{}: window_secs must be between 1 and {MAX_WINDOW_SECS}",
                    ctx()
                );
            }
            if c.cooldown_secs.is_some_and(|s| s > MAX_WINDOW_SECS) {
                bail!("{}: cooldown_secs must be at most {MAX_WINDOW_SECS}", ctx());
            }
            let pattern = match &c.pattern {
                Some(p) => Some(
                    RegexBuilder::new(p)
                        .size_limit(REGEX_SIZE_LIMIT)
                        .build()
                        .with_context(|| format!("{}: invalid pattern {p:?}", ctx()))?,
                ),
                None => None,
            };
            let window_ms = i64::try_from(c.window_secs).unwrap_or(i64::MAX / 1000) * 1000;
            let cooldown_ms = c.cooldown_secs.map_or(window_ms, |s| {
                i64::try_from(s).unwrap_or(i64::MAX / 1000) * 1000
            });
            alerts.push(Alert {
                name: name.clone(),
                host: c.host.clone(),
                app: c.app.clone(),
                severities: severity_set(&c.severity).with_context(ctx)?,
                pattern,
                count: c.count,
                window_ms,
                cooldown_ms,
                per_host: c.per_host,
                state: Mutex::new(HashMap::new()),
                fired: AtomicU64::new(0),
            });
        }
        Ok(Self { alerts })
    }

    /// The stored rules that still build (a rule that a newer or older LogPit wrote and this one
    /// refuses is left out, with a warning), as one set.
    pub fn from_stored(rules: &[crate::store::StoredAlertRule]) -> Self {
        let mut ok = Vec::new();
        for r in rules {
            match Self::from_config(std::slice::from_ref(&r.rule)) {
                Ok(_) => ok.push(r.rule.clone()),
                Err(e) => tracing::warn!("stored alert rule {} left out: {e:#}", r.id),
            }
        }
        Self::from_config(&ok).unwrap_or_default()
    }

    /// Whether a rule has this name.
    pub fn has(&self, name: &str) -> bool {
        self.alerts.iter().any(|a| a.name == name)
    }

    pub fn is_empty(&self) -> bool {
        self.alerts.is_empty()
    }

    /// Records `entry` (which arrived at `now`, Unix ms) against every alert it matches and
    /// returns the notifications that became due.
    pub fn observe(&self, entry: &LogEntry, now: i64) -> Vec<Event> {
        let mut events = Vec::new();
        for alert in &self.alerts {
            if alert.matches(entry) && alert.record(&entry.host, now) {
                alert.fired.fetch_add(1, Ordering::Relaxed);
                events.push(Event::Pattern {
                    rule: alert.name.clone(),
                    host: alert.per_host.then(|| entry.host.clone()),
                    count: alert.count,
                    window_secs: u64::try_from(alert.window_ms / 1000).unwrap_or(0),
                    sample: entry.message.clone(),
                });
            }
        }
        events
    }

    /// Prometheus text: how many times each alert fired.
    pub fn render_metrics(&self) -> String {
        Self::render_all(&[self])
    }

    /// The counters of several sets (the configuration's and the web UI's) under one metric header.
    pub fn render_all(sets: &[&Self]) -> String {
        if sets.iter().all(|s| s.alerts.is_empty()) {
            return String::new();
        }
        let mut out = String::from(
            "# HELP logpit_alerts_fired_total Notifications sent by each pattern alert\n\
             # TYPE logpit_alerts_fired_total counter\n",
        );
        for a in sets.iter().flat_map(|s| &s.alerts) {
            let name = a
                .name
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = writeln!(
                out,
                "logpit_alerts_fired_total{{rule=\"{name}\"}} {}",
                a.fired.load(Ordering::Relaxed)
            );
        }
        out
    }
}

impl Alert {
    fn matches(&self, e: &LogEntry) -> bool {
        self.host.as_ref().is_none_or(|h| *h == e.host)
            && self.app.as_ref().is_none_or(|a| *a == e.app)
            && self
                .severities
                .is_none_or(|s| s[usize::from(e.severity.min(7))])
            && self.pattern.as_ref().is_none_or(|p| p.is_match(&e.message))
    }

    /// Adds a match; true when the alert fires.
    fn record(&self, host: &str, now: i64) -> bool {
        let key = if self.per_host { host } else { "" };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.contains_key(key) && state.len() >= MAX_KEYS {
            // Make room by forgetting hosts that have been quiet for longer than the window.
            let window = self.window_ms;
            state.retain(|_, r| r.times.back().is_some_and(|t| now - t <= window));
            if state.len() >= MAX_KEYS {
                return false;
            }
        }
        let ring = state.entry(key.to_string()).or_insert_with(|| Ring {
            times: VecDeque::with_capacity(self.count.min(64)),
            last_fired: None,
        });
        ring.times.push_back(now);
        if ring.times.len() > self.count {
            ring.times.pop_front();
        }
        let full = ring.times.len() == self.count;
        let within_window = ring
            .times
            .front()
            .is_some_and(|t| now - t <= self.window_ms);
        let cooled_down = ring.last_fired.is_none_or(|t| now - t >= self.cooldown_ms);
        if full && within_window && cooled_down {
            ring.times.clear();
            ring.last_fired = Some(now);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alerts(toml_text: &str) -> anyhow::Result<AlertRules> {
        #[derive(Deserialize)]
        struct Wrapper {
            alerts: Vec<AlertConfig>,
        }
        AlertRules::from_config(&toml::from_str::<Wrapper>(toml_text).unwrap().alerts)
    }

    fn entry(host: &str, app: &str, severity: u8, message: &str) -> LogEntry {
        LogEntry {
            host: host.into(),
            app: app.into(),
            severity,
            message: message.into(),
            ..Default::default()
        }
    }

    fn fired(a: &AlertRules, e: &LogEntry, now_secs: i64) -> usize {
        a.observe(e, now_secs * 1000).len()
    }

    #[test]
    fn fires_when_count_matches_arrive_within_the_window() {
        let a =
            alerts("[[alerts]]\nname = \"disk\"\npattern = \"disk\"\ncount = 3\nwindow_secs = 60")
                .unwrap();
        let e = entry("pve", "kernel", 3, "disk error on sda");
        assert_eq!(
            (fired(&a, &e, 0), fired(&a, &e, 10), fired(&a, &e, 20)),
            (0, 0, 1)
        );
        // Non-matching entries do not count.
        assert_eq!(fired(&a, &entry("pve", "x", 3, "network down"), 21), 0);
        // After firing the alert clears its matches and stays quiet for the cooldown (= window
        // here). Matches that arrive meanwhile still count, so a problem that is still going on
        // is reported again as soon as the cooldown ends and a new match arrives.
        assert_eq!(
            (fired(&a, &e, 30), fired(&a, &e, 40), fired(&a, &e, 50)),
            (0, 0, 0),
            "cooldown"
        );
        assert_eq!(
            fired(&a, &e, 81),
            1,
            "ongoing: 40, 50 and 81 are within the window"
        );
        // That firing cleared the matches, so it takes a fresh burst, and stale ones do not count.
        assert_eq!((fired(&a, &e, 82), fired(&a, &e, 83)), (0, 0));
        assert_eq!(
            fired(&a, &e, 1000),
            0,
            "matches from long ago do not add up"
        );
    }

    #[test]
    fn matches_spread_over_more_than_the_window_do_not_fire() {
        let a = alerts("[[alerts]]\ncount = 3\nwindow_secs = 10").unwrap();
        let e = entry("h", "a", 6, "x");
        for t in [0, 6, 12, 18, 24, 30] {
            assert_eq!(
                fired(&a, &e, t),
                0,
                "t={t}: 3 within 10s never happens at one every 6s"
            );
        }
        // A burst does.
        assert_eq!(
            (fired(&a, &e, 40), fired(&a, &e, 41), fired(&a, &e, 42)),
            (0, 0, 1)
        );
    }

    #[test]
    fn conditions_narrow_what_is_counted() {
        let a = alerts(
            "[[alerts]]\nname = \"a\"\nhost = \"pve\"\napp = \"kernel\"\nseverity = [\"err\", \"crit\"]\n\
             pattern = \"(?i)error\"\ncount = 1\nwindow_secs = 60",
        )
        .unwrap();
        assert_eq!(fired(&a, &entry("pve", "kernel", 3, "Disk ERROR"), 0), 1);
        for (h, ap, s, m) in [
            ("nas", "kernel", 3, "error"),
            ("pve", "sshd", 3, "error"),
            ("pve", "kernel", 6, "error"),
            ("pve", "kernel", 3, "fine"),
        ] {
            assert_eq!(fired(&a, &entry(h, ap, s, m), 1000), 0, "{h} {ap} {s} {m}");
        }
    }

    #[test]
    fn per_host_counts_and_cools_down_separately() {
        let a =
            alerts("[[alerts]]\ncount = 2\nwindow_secs = 60\ncooldown_secs = 300\nper_host = true")
                .unwrap();
        let (pve, nas) = (entry("pve", "a", 6, "x"), entry("nas", "a", 6, "x"));
        assert_eq!(
            (fired(&a, &pve, 0), fired(&a, &nas, 1)),
            (0, 0),
            "one each: neither fires"
        );
        let ev = a.observe(&pve, 2000);
        assert_eq!(ev.len(), 1);
        assert!(matches!(&ev[0], Event::Pattern { host: Some(h), .. } if h == "pve"));
        assert_eq!(fired(&a, &nas, 3), 1, "nas reaches its own count");
        assert_eq!(
            (fired(&a, &pve, 4), fired(&a, &pve, 5)),
            (0, 0),
            "pve is cooling down"
        );
        assert_eq!(
            (fired(&a, &pve, 400), fired(&a, &pve, 401)),
            (0, 1),
            "after the cooldown"
        );
        // Without per_host the event carries no host.
        let global = alerts("[[alerts]]\ncount = 1\nwindow_secs = 5").unwrap();
        assert!(matches!(
            &global.observe(&pve, 0)[0],
            Event::Pattern { host: None, .. }
        ));
    }

    #[test]
    fn every_alert_is_evaluated_and_counted() {
        let a = alerts(
            "[[alerts]]\nname = \"any\"\ncount = 1\nwindow_secs = 5\n\
             [[alerts]]\nname = \"errors\"\nseverity = [3]\ncount = 1\nwindow_secs = 5",
        )
        .unwrap();
        assert_eq!(fired(&a, &entry("h", "a", 3, "x"), 0), 2);
        let m = a.render_metrics();
        assert!(
            m.contains("logpit_alerts_fired_total{rule=\"any\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("logpit_alerts_fired_total{rule=\"errors\"} 1"),
            "{m}"
        );
        assert_eq!(AlertRules::default().render_metrics(), "");
    }

    #[test]
    fn memory_is_bounded() {
        // Many hosts: only MAX_KEYS are tracked at once.
        let a = alerts("[[alerts]]\ncount = 2\nwindow_secs = 3600\nper_host = true").unwrap();
        for i in 0..(MAX_KEYS + 200) {
            a.observe(&entry(&format!("h{i}"), "a", 6, "x"), 0);
        }
        assert_eq!(a.alerts[0].state.lock().unwrap().len(), MAX_KEYS);
        // Quiet hosts are forgotten to make room for new ones once the window has passed.
        a.observe(&entry("newcomer", "a", 6, "x"), 4_000 * 1000);
        assert!(a.alerts[0].state.lock().unwrap().contains_key("newcomer"));
        // A huge count only ever stores `count` timestamps, never the traffic.
        let big = alerts("[[alerts]]\ncount = 5\nwindow_secs = 3600").unwrap();
        for t in 0..1000 {
            big.observe(&entry("h", "a", 6, "x"), t);
        }
        assert!(big.alerts[0].state.lock().unwrap()[""].times.len() <= 5);
    }

    #[test]
    fn invalid_alerts_are_rejected() {
        for (text, why) in [
            ("[[alerts]]\ncount = 0\nwindow_secs = 60", "zero count"),
            (
                "[[alerts]]\ncount = 100000\nwindow_secs = 60",
                "count too large",
            ),
            ("[[alerts]]\ncount = 1\nwindow_secs = 0", "zero window"),
            (
                "[[alerts]]\ncount = 1\nwindow_secs = 99999999",
                "window too long",
            ),
            (
                "[[alerts]]\ncount = 1\nwindow_secs = 5\ncooldown_secs = 99999999",
                "cooldown too long",
            ),
            (
                "[[alerts]]\ncount = 1\nwindow_secs = 5\npattern = \"(\"",
                "bad regex",
            ),
            (
                "[[alerts]]\ncount = 1\nwindow_secs = 5\nseverity = [\"loud\"]",
                "bad severity",
            ),
            (
                "[[alerts]]\nname = \"\"\ncount = 1\nwindow_secs = 5",
                "empty name",
            ),
            (
                "[[alerts]]\nname = \"a\"\ncount = 1\nwindow_secs = 5\n[[alerts]]\nname = \"a\"\ncount = 1\nwindow_secs = 5",
                "duplicate name",
            ),
        ] {
            assert!(alerts(text).is_err(), "{why}");
        }
    }
}
