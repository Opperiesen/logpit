//! Per-host silence alerts: tracks when each host last sent a log and reports hosts that
//! have gone quiet (and later recovered), via a webhook and a Prometheus gauge.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::Mutex;

use serde_json::json;

use crate::config::SilenceConfig;
use crate::ingest::now_ms;

/// Upper bound on tracked hosts, so spoofed hostnames cannot grow memory without limit.
pub const MAX_TRACKED_HOSTS: usize = 1024;
/// A silent host that is not named in the config is forgotten after this long.
const FORGET_AFTER_MS: i64 = 7 * 86_400_000;

/// Silence thresholds: a default for every host plus per-host overrides (0 = never alert).
#[derive(Debug, Clone, Default)]
pub struct Rules {
    default_after_ms: Option<i64>,
    hosts: BTreeMap<String, Option<i64>>,
}

impl Rules {
    pub fn from_config(cfg: &SilenceConfig) -> Self {
        let ms =
            |secs: u64| (secs > 0).then(|| i64::try_from(secs).unwrap_or(i64::MAX / 1000) * 1000);
        Self {
            default_after_ms: ms(cfg.default_after_secs),
            hosts: cfg.hosts.iter().map(|(h, s)| (h.clone(), ms(*s))).collect(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.default_after_ms.is_some() || self.hosts.values().any(Option::is_some)
    }

    /// Hosts that are tracked even before they have sent anything.
    pub fn configured_hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts
            .iter()
            .filter(|(_, t)| t.is_some())
            .map(|(h, _)| h.as_str())
    }

    fn threshold_ms(&self, host: &str) -> Option<i64> {
        match self.hosts.get(host) {
            Some(own) => *own,
            None => self.default_after_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Silent {
        host: String,
        silent_for_ms: i64,
        threshold_ms: i64,
    },
    Recovered {
        host: String,
    },
    /// A pattern alert reached its threshold (see the `alerts` module).
    Pattern {
        rule: String,
        host: Option<String>,
        count: usize,
        window_secs: u64,
        /// The entry's message that tipped the alert over, for context.
        sample: String,
    },
    /// A message template that was never seen before (see the `watch` module).
    NewPattern {
        pattern: String,
        host: String,
        severity: String,
        sample: String,
    },
    /// A known template showing up far more often than usual.
    Surge {
        pattern: String,
        /// Entries in the current window.
        count: u64,
        /// Usual entries per window.
        usual: u64,
        window_secs: u64,
        sample: String,
    },
}

/// A sample taken from a log line: one line, clipped.
fn one_line(sample: &str) -> String {
    let sample: String = sample.split_whitespace().collect::<Vec<_>>().join(" ");
    sample.chars().take(200).collect()
}

impl Event {
    pub fn payload(&self) -> serde_json::Value {
        match self {
            Event::Silent {
                host,
                silent_for_ms,
                threshold_ms,
            } => json!({
                "event": "host_silent",
                "host": host,
                "silent_for_secs": silent_for_ms / 1000,
                "threshold_secs": threshold_ms / 1000,
                "message": format!(
                    "No logs from {host} for {} (threshold {})",
                    fmt_secs(silent_for_ms / 1000),
                    fmt_secs(threshold_ms / 1000)
                ),
            }),
            Event::Recovered { host } => json!({
                "event": "host_recovered",
                "host": host,
                "message": format!("{host} is sending logs again"),
            }),
            Event::Pattern {
                rule,
                host,
                count,
                window_secs,
                sample,
            } => {
                let sample = one_line(sample);
                let on = host
                    .as_ref()
                    .map(|h| format!(" on {h}"))
                    .unwrap_or_default();
                json!({
                    "event": "log_alert",
                    "rule": rule,
                    "host": host,
                    "count": count,
                    "window_secs": window_secs,
                    "sample": sample,
                    "message": format!(
                        "Alert {rule}: {count} matching entries within {}{on}. Last: {sample}",
                        fmt_secs(i64::try_from(*window_secs).unwrap_or(i64::MAX))
                    ),
                })
            }
            Event::NewPattern {
                pattern,
                host,
                severity,
                sample,
            } => {
                let sample = one_line(sample);
                json!({
                    "event": "new_pattern",
                    "pattern": pattern,
                    "host": host,
                    "severity": severity,
                    "sample": sample,
                    "message": format!(
                        "New log pattern ({severity}) on {host}: {pattern}. Example: {sample}"
                    ),
                })
            }
            Event::Surge {
                pattern,
                count,
                usual,
                window_secs,
                sample,
            } => {
                let sample = one_line(sample);
                let window = fmt_secs(i64::try_from(*window_secs).unwrap_or(i64::MAX));
                json!({
                    "event": "pattern_surge",
                    "pattern": pattern,
                    "count": count,
                    "usual": usual,
                    "window_secs": window_secs,
                    "sample": sample,
                    "message": format!(
                        "Pattern surge: {pattern} seen {count} times within {window} \
                         (usually about {usual}). Last: {sample}"
                    ),
                })
            }
        }
    }
}

fn fmt_secs(s: i64) -> String {
    match s {
        0..=119 => format!("{s}s"),
        120..=7199 => format!("{}m", s / 60),
        _ => format!("{}h{}m", s / 3600, s % 3600 / 60),
    }
}

struct HostState {
    last_seen_ms: i64,
    alerted: bool,
}

/// Last-seen times per host. Cheap to update from the ingestion path; a no-op when
/// silence alerts are disabled.
pub struct Tracker {
    enabled: std::sync::atomic::AtomicBool,
    hosts: Mutex<HashMap<String, HostState>>,
}

impl Tracker {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: std::sync::atomic::AtomicBool::new(enabled),
            hosts: Mutex::new(HashMap::new()),
        }
    }

    fn enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Turns tracking on or off (a reload can change the thresholds). Switching it on starts
    /// from the hosts seen from now on.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HostState>> {
        self.hosts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records that `host` just sent a log.
    pub fn touch(&self, host: &str, now: i64) {
        if !self.enabled() {
            return;
        }
        let mut hosts = self.lock();
        if let Some(s) = hosts.get_mut(host) {
            s.last_seen_ms = now;
        } else if hosts.len() < MAX_TRACKED_HOSTS {
            hosts.insert(
                host.to_owned(),
                HostState {
                    last_seen_ms: now,
                    alerted: false,
                },
            );
        }
    }

    /// Starts tracking known hosts as if they had just been seen, giving each a full
    /// threshold of grace after a restart.
    pub fn seed<'a>(&self, hosts: impl IntoIterator<Item = &'a str>, now: i64) {
        for h in hosts {
            if self.enabled() {
                let mut map = self.lock();
                if map.len() < MAX_TRACKED_HOSTS {
                    map.entry(h.to_owned()).or_insert(HostState {
                        last_seen_ms: now,
                        alerted: false,
                    });
                }
            }
        }
    }

    /// Compares every tracked host against its threshold and returns the transitions
    /// since the previous call (each host alerts once until it recovers).
    pub fn evaluate(&self, rules: &Rules, now: i64) -> Vec<Event> {
        let mut events = Vec::new();
        let mut hosts = self.lock();
        hosts.retain(|host, s| {
            let Some(threshold_ms) = rules.threshold_ms(host) else {
                return false;
            };
            let silent_for_ms = now - s.last_seen_ms;
            if silent_for_ms > threshold_ms {
                if !s.alerted {
                    s.alerted = true;
                    events.push(Event::Silent {
                        host: host.clone(),
                        silent_for_ms,
                        threshold_ms,
                    });
                }
                silent_for_ms <= FORGET_AFTER_MS || rules.hosts.contains_key(host)
            } else {
                if s.alerted {
                    s.alerted = false;
                    events.push(Event::Recovered { host: host.clone() });
                }
                true
            }
        });
        events
    }

    /// Whether the alert is firing for `host`; `None` when alerts are off or the host is untracked.
    pub fn is_silent(&self, host: &str) -> Option<bool> {
        if !self.enabled() {
            return None;
        }
        self.lock().get(host).map(|s| s.alerted)
    }

    /// Prometheus text for the currently silent hosts.
    pub fn render_metrics(&self) -> String {
        if !self.enabled() {
            return String::new();
        }
        let hosts = self.lock();
        let mut silent: Vec<&str> = hosts
            .iter()
            .filter(|(_, s)| s.alerted)
            .map(|(h, _)| h.as_str())
            .collect();
        silent.sort_unstable();
        let mut out = String::new();
        out.push_str(
            "# HELP logpit_host_silent 1 for each host that exceeded its silence threshold\n",
        );
        out.push_str("# TYPE logpit_host_silent gauge\n");
        for h in silent {
            let label = h
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = writeln!(out, "logpit_host_silent{{host=\"{label}\"}} 1");
        }
        let _ = writeln!(
            out,
            "# HELP logpit_tracked_hosts Hosts tracked for silence alerts"
        );
        let _ = writeln!(out, "# TYPE logpit_tracked_hosts gauge");
        let _ = writeln!(out, "logpit_tracked_hosts {}", hosts.len());
        out
    }
}

/// Periodically evaluates silence rules, logging and notifying on each transition. The thresholds,
/// the check period and the webhook are read again on every round, so a reload applies at once.
pub async fn run(
    tracker: std::sync::Arc<Tracker>,
    live: std::sync::Arc<crate::live::LiveSettings>,
) {
    loop {
        let settings = live.silence.get();
        tokio::time::sleep(settings.interval).await;
        // The settings may have been replaced while sleeping; use the current ones.
        let settings = live.silence.get();
        for event in tracker.evaluate(&settings.rules, now_ms()) {
            let message = event.payload()["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            match event {
                Event::Silent { .. } => tracing::warn!("silence alert: {message}"),
                Event::Recovered { .. } => tracing::info!("silence recovered: {message}"),
                Event::Pattern { .. } | Event::NewPattern { .. } | Event::Surge { .. } => {
                    tracing::warn!("{message}")
                }
            }
            if let Some(hook) = settings.webhook.clone() {
                tokio::spawn(async move { hook.send(&event).await });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(default_secs: u64, hosts: &[(&str, u64)]) -> Rules {
        Rules::from_config(&SilenceConfig {
            default_after_secs: default_secs,
            hosts: hosts.iter().map(|(h, s)| (h.to_string(), *s)).collect(),
            ..Default::default()
        })
    }

    #[test]
    fn alerts_once_then_recovers() {
        let r = rules(60, &[]);
        let t = Tracker::new(r.enabled());
        t.touch("pve", 0);
        assert!(
            t.evaluate(&r, 60_000).is_empty(),
            "exactly at threshold is fine"
        );
        let ev = t.evaluate(&r, 61_000);
        assert_eq!(
            ev,
            vec![Event::Silent {
                host: "pve".into(),
                silent_for_ms: 61_000,
                threshold_ms: 60_000
            }]
        );
        assert!(
            t.evaluate(&r, 90_000).is_empty(),
            "no repeat while still silent"
        );
        assert!(
            t.render_metrics()
                .contains("logpit_host_silent{host=\"pve\"} 1")
        );
        t.touch("pve", 100_000);
        assert_eq!(
            t.evaluate(&r, 101_000),
            vec![Event::Recovered { host: "pve".into() }]
        );
        assert!(!t.render_metrics().contains("host=\"pve\""));
    }

    #[test]
    fn is_silent_reports_alert_state() {
        let r = rules(60, &[]);
        let t = Tracker::new(true);
        t.touch("pve", 0);
        assert_eq!(t.is_silent("pve"), Some(false));
        assert_eq!(t.is_silent("unknown"), None);
        t.evaluate(&r, 61_000);
        assert_eq!(t.is_silent("pve"), Some(true));
        assert_eq!(Tracker::new(false).is_silent("pve"), None);
    }

    #[test]
    fn per_host_override_and_disable() {
        let r = rules(60, &[("nas", 3600), ("printer", 0)]);
        let t = Tracker::new(true);
        for h in ["pve", "nas", "printer"] {
            t.touch(h, 0);
        }
        let ev = t.evaluate(&r, 120_000);
        assert_eq!(ev.len(), 1, "only pve exceeded its threshold: {ev:?}");
        assert!(matches!(&ev[0], Event::Silent { host, .. } if host == "pve"));
        // The disabled host is dropped from tracking.
        assert!(
            !t.render_metrics().contains("printer")
                && t.render_metrics().contains("tracked_hosts 2")
        );
    }

    #[test]
    fn configured_host_that_never_reports_alerts() {
        let r = rules(0, &[("ghost", 30)]);
        assert!(r.enabled());
        let t = Tracker::new(true);
        t.seed(r.configured_hosts(), 1_000);
        assert!(t.evaluate(&r, 31_000).is_empty());
        assert_eq!(t.evaluate(&r, 31_001).len(), 1);
    }

    #[test]
    fn disabled_tracker_ignores_everything_and_memory_is_bounded() {
        let off = Tracker::new(false);
        off.touch("a", 0);
        assert_eq!(off.render_metrics(), "");

        let on = Tracker::new(true);
        for i in 0..MAX_TRACKED_HOSTS + 50 {
            on.touch(&format!("h{i}"), 0);
        }
        assert_eq!(on.lock().len(), MAX_TRACKED_HOSTS);
    }

    #[test]
    fn long_silent_unconfigured_hosts_are_forgotten() {
        let r = rules(60, &[]);
        let t = Tracker::new(true);
        t.touch("old", 0);
        assert_eq!(t.evaluate(&r, 61_000).len(), 1);
        t.evaluate(&r, FORGET_AFTER_MS + 1);
        assert!(t.lock().is_empty());
    }

    #[test]
    fn metric_labels_are_escaped() {
        let r = rules(1, &[]);
        let t = Tracker::new(true);
        t.touch("a\"b\\c\nd", 0);
        t.evaluate(&r, 5_000);
        assert!(t.render_metrics().contains(r#"host="a\"b\\c\nd""#));
    }
}
