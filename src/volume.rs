//! Volume alerts: notify when a host sends far more, or far fewer, logs than it usually does.
//!
//! Entries are counted per host in fixed windows. Each closed window is compared with a moving
//! average of the earlier ones (the host's baseline); a window above `high_factor` times the
//! baseline is a surge, one below `low_factor` times it a drop. This complements silence alerts,
//! which only notice a host that stopped completely.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use anyhow::bail;
use serde::Deserialize;

use crate::silence::Event;

const MAX_HOSTS_LIMIT: usize = 100_000;
const MIN_WINDOW_SECS: u64 = 10;
const MAX_WINDOW_SECS: u64 = 86_400;
const MAX_BASELINE_WINDOWS: usize = 1000;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct VolumeConfig {
    /// Turns the watch on (off by default).
    pub enabled: bool,
    /// Length of a counting window.
    pub window_secs: u64,
    /// Closed windows the baseline is averaged over; nothing is reported for a host before it has
    /// seen that many.
    pub baseline_windows: usize,
    /// A window with at least this many times the baseline is a surge; `0` turns surges off.
    pub high_factor: f64,
    /// A window with at most this fraction of the baseline is a drop (zero included); `0` turns
    /// drops off.
    pub low_factor: f64,
    /// Hosts whose baseline is below this many entries per window are ignored: for them a
    /// handful of lines is not a signal.
    pub min_baseline: u64,
    /// Minimum time between two notifications for one host.
    pub cooldown_secs: u64,
    /// Hosts tracked; further ones are not watched.
    pub max_hosts: usize,
}

impl Default for VolumeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: 300,
            baseline_windows: 12,
            high_factor: 5.0,
            low_factor: 0.2,
            min_baseline: 20,
            cooldown_secs: 3600,
            max_hosts: 1024,
        }
    }
}

impl VolumeConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(MIN_WINDOW_SECS..=MAX_WINDOW_SECS).contains(&self.window_secs) {
            bail!("volume.window_secs must be between {MIN_WINDOW_SECS} and {MAX_WINDOW_SECS}");
        }
        if !(3..=MAX_BASELINE_WINDOWS).contains(&self.baseline_windows) {
            bail!("volume.baseline_windows must be between 3 and {MAX_BASELINE_WINDOWS}");
        }
        if !self.high_factor.is_finite()
            || self.high_factor < 0.0
            || (self.high_factor > 0.0 && self.high_factor < 1.5)
        {
            bail!("volume.high_factor must be 0 (off) or at least 1.5");
        }
        if !self.low_factor.is_finite() || !(0.0..1.0).contains(&self.low_factor) {
            bail!("volume.low_factor must be 0 (off) or between 0 and 1");
        }
        if self.max_hosts == 0 || self.max_hosts > MAX_HOSTS_LIMIT {
            bail!("volume.max_hosts must be between 1 and {MAX_HOSTS_LIMIT}");
        }
        if self.cooldown_secs > 30 * 86_400 {
            bail!("volume.cooldown_secs must be at most 30 days");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Settings {
    enabled: bool,
    window_ms: i64,
    windows: usize,
    high: f64,
    low: f64,
    min_baseline: f64,
    cooldown_ms: i64,
    max_hosts: usize,
}

fn settings_of(c: &VolumeConfig) -> Settings {
    Settings {
        enabled: c.enabled,
        window_ms: i64::try_from(c.window_secs).unwrap_or(300) * 1000,
        windows: c.baseline_windows,
        high: c.high_factor,
        low: c.low_factor,
        min_baseline: c.min_baseline as f64,
        cooldown_ms: i64::try_from(c.cooldown_secs).unwrap_or(0) * 1000,
        max_hosts: c.max_hosts,
    }
}

#[derive(Default)]
struct Host {
    /// Entries in the current window.
    count: u64,
    /// Moving average of the closed windows.
    baseline: f64,
    /// Closed windows seen.
    seen: usize,
    /// Consecutive windows that were anomalous, which keep the baseline from following them.
    anomalous: usize,
    last_alert: Option<i64>,
}

pub struct VolumeWatch {
    settings: RwLock<Settings>,
    hosts: Mutex<HashMap<String, Host>>,
    surges: AtomicU64,
    drops: AtomicU64,
}

impl Default for VolumeWatch {
    fn default() -> Self {
        Self::new(&VolumeConfig::default())
    }
}

impl VolumeWatch {
    pub fn new(cfg: &VolumeConfig) -> Self {
        Self {
            settings: RwLock::new(settings_of(cfg)),
            hosts: Mutex::new(HashMap::new()),
            surges: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        }
    }

    fn settings(&self) -> Settings {
        *self.settings.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn enabled(&self) -> bool {
        self.settings().enabled
    }

    /// The window length in seconds, for the task that closes windows.
    pub fn window_secs(&self) -> u64 {
        u64::try_from(self.settings().window_ms / 1000).unwrap_or(300)
    }

    /// Applies new settings. A different window length makes the baselines meaningless, so they
    /// start over.
    pub fn reconfigure(&self, cfg: &VolumeConfig) {
        let new = settings_of(cfg);
        let changed = self.settings().window_ms != new.window_ms;
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = new;
        if changed {
            self.hosts.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }

    /// Counts one entry from `host` in the current window.
    pub fn count(&self, host: &str) {
        let s = self.settings();
        if !s.enabled {
            return;
        }
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = hosts.get_mut(host) {
            h.count += 1;
        } else if hosts.len() < s.max_hosts {
            hosts.insert(
                host.to_string(),
                Host {
                    count: 1,
                    ..Default::default()
                },
            );
        }
    }

    /// Starts hosts off with the per-window counts of recent history (oldest window first), so a
    /// restart does not mean waiting for the baseline to build up again.
    pub fn seed(&self, history: impl IntoIterator<Item = (String, Vec<u64>)>) {
        let s = self.settings();
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        for (name, counts) in history {
            if hosts.len() >= s.max_hosts && !hosts.contains_key(&name) {
                continue;
            }
            let h = hosts.entry(name).or_default();
            for c in counts {
                h.fold(c as f64, s.windows);
            }
        }
    }

    /// Closes the current window of every host at `now` and returns the notifications due.
    pub fn close_window(&self, now: i64) -> Vec<Event> {
        let s = self.settings();
        if !s.enabled {
            return Vec::new();
        }
        let window_secs = u64::try_from(s.window_ms / 1000).unwrap_or(0);
        let mut events = Vec::new();
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        for (name, h) in hosts.iter_mut() {
            let count = std::mem::take(&mut h.count);
            let c = count as f64;
            let mut anomalous = false;
            if h.seen >= s.windows && h.baseline >= s.min_baseline {
                let cooled = h.last_alert.is_none_or(|t| now - t >= s.cooldown_ms);
                let surge = s.high > 0.0 && c >= s.high * h.baseline;
                let drop = s.low > 0.0 && c <= s.low * h.baseline;
                anomalous = surge || drop;
                if anomalous && cooled {
                    h.last_alert = Some(now);
                    let baseline = h.baseline.round() as u64;
                    if surge {
                        self.surges.fetch_add(1, Ordering::Relaxed);
                        events.push(Event::VolumeSurge {
                            host: name.clone(),
                            count,
                            baseline,
                            window_secs,
                        });
                    } else {
                        self.drops.fetch_add(1, Ordering::Relaxed);
                        events.push(Event::VolumeDrop {
                            host: name.clone(),
                            count,
                            baseline,
                            window_secs,
                        });
                    }
                }
            }
            // The baseline stays put during an anomaly, until it has lasted a whole baseline
            // length: then it is the new normal.
            h.anomalous = if anomalous { h.anomalous + 1 } else { 0 };
            if !anomalous || h.anomalous >= s.windows {
                h.fold(c, s.windows);
            }
        }
        // Forget hosts that have been silent for a long time and carry no baseline worth keeping.
        hosts.retain(|_, h| h.baseline >= 0.5 || h.count > 0);
        events.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        events
    }

    /// Prometheus text; empty while the watch is off.
    pub fn render_metrics(&self) -> String {
        if !self.enabled() {
            return String::new();
        }
        let tracked = self.hosts.lock().unwrap_or_else(|e| e.into_inner()).len();
        let mut out = String::from(
            "# HELP logpit_volume_alerts_total Volume notifications sent, by kind\n\
             # TYPE logpit_volume_alerts_total counter\n",
        );
        let _ = writeln!(
            out,
            "logpit_volume_alerts_total{{kind=\"surge\"}} {}\nlogpit_volume_alerts_total{{kind=\"drop\"}} {}",
            self.surges.load(Ordering::Relaxed),
            self.drops.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP logpit_volume_hosts Hosts whose volume is being watched\n\
             # TYPE logpit_volume_hosts gauge\nlogpit_volume_hosts {tracked}"
        );
        out
    }
}

impl Host {
    /// Adds a closed window to the baseline: the plain average while it builds up, then a
    /// moving average over about `windows` windows.
    fn fold(&mut self, count: f64, windows: usize) {
        self.baseline = if self.seen == 0 {
            count
        } else if self.seen < windows {
            (self.baseline * self.seen as f64 + count) / (self.seen as f64 + 1.0)
        } else {
            let alpha = 2.0 / (windows as f64 + 1.0);
            (1.0 - alpha) * self.baseline + alpha * count
        };
        self.seen += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml_text: &str) -> VolumeConfig {
        let mut c: VolumeConfig = toml::from_str(toml_text).unwrap();
        c.enabled = true;
        c
    }

    fn feed(w: &VolumeWatch, host: &str, n: u64) {
        for _ in 0..n {
            w.count(host);
        }
    }

    const MIN: i64 = 300_000;

    fn small() -> VolumeWatch {
        VolumeWatch::new(&cfg(
            "baseline_windows = 4\nmin_baseline = 10\ncooldown_secs = 600",
        ))
    }

    #[test]
    fn nothing_is_reported_while_the_baseline_builds() {
        let w = small();
        for i in 0..4 {
            feed(&w, "web1", if i == 3 { 1000 } else { 100 });
            assert!(w.close_window(i * MIN).is_empty(), "window {i}");
        }
    }

    #[test]
    fn a_surge_and_a_drop_are_reported_once_per_cooldown() {
        let w = small();
        for i in 0..4 {
            feed(&w, "web1", 100);
            w.close_window(i * MIN);
        }
        feed(&w, "web1", 700);
        let ev = w.close_window(4 * MIN);
        assert_eq!(
            ev,
            [Event::VolumeSurge {
                host: "web1".into(),
                count: 700,
                baseline: 100,
                window_secs: 300
            }]
        );
        // Another surge inside the cooldown (10 minutes) stays quiet.
        feed(&w, "web1", 700);
        assert!(w.close_window(5 * MIN).is_empty());
        // After the cooldown a drop is reported (the baseline did not follow the surge).
        feed(&w, "web1", 5);
        let ev = w.close_window(9 * MIN);
        assert_eq!(
            ev,
            [Event::VolumeDrop {
                host: "web1".into(),
                count: 5,
                baseline: 100,
                window_secs: 300
            }]
        );
        let m = w.render_metrics();
        assert!(m.contains("logpit_volume_alerts_total{kind=\"surge\"} 1"));
        assert!(m.contains("logpit_volume_alerts_total{kind=\"drop\"} 1"));
        assert!(m.contains("logpit_volume_hosts 1"));
    }

    #[test]
    fn a_host_that_sends_nothing_is_a_drop() {
        let w = small();
        for i in 0..4 {
            feed(&w, "db1", 50);
            w.close_window(i * MIN);
        }
        let ev = w.close_window(4 * MIN);
        assert_eq!(ev.len(), 1);
        assert!(matches!(&ev[0], Event::VolumeDrop { host, count: 0, .. } if host == "db1"));
    }

    #[test]
    fn small_baselines_and_modest_changes_are_ignored() {
        let w = small();
        for i in 0..4 {
            feed(&w, "quiet", 4);
            feed(&w, "steady", 100);
            w.close_window(i * MIN);
        }
        // A quiet host (baseline 4 < 10) jumping tenfold is not a signal; a steady one doubling
        // or halving is within the factors (5x and 0.2x).
        feed(&w, "quiet", 40);
        feed(&w, "steady", 200);
        assert!(w.close_window(4 * MIN).is_empty());
        feed(&w, "quiet", 4);
        feed(&w, "steady", 50);
        assert!(w.close_window(5 * MIN).is_empty());
    }

    #[test]
    fn a_lasting_change_becomes_the_new_normal() {
        let w = VolumeWatch::new(&cfg(
            "baseline_windows = 4\nmin_baseline = 10\ncooldown_secs = 0",
        ));
        for i in 0..4 {
            feed(&w, "h", 100);
            w.close_window(i * MIN);
        }
        let mut alerts = 0;
        // 800 per window forever: alerts at first, then silence once the baseline caught up.
        for i in 4..30 {
            feed(&w, "h", 800);
            alerts += w.close_window(i * MIN).len();
        }
        assert!((1..=5).contains(&alerts), "{alerts}");
        feed(&w, "h", 800);
        assert!(w.close_window(30 * MIN).is_empty());
    }

    #[test]
    fn seeding_skips_the_wait_and_factors_can_be_turned_off() {
        let w = small();
        w.seed([("web1".to_string(), vec![100, 100, 100, 100])]);
        feed(&w, "web1", 900);
        assert_eq!(w.close_window(0).len(), 1, "the baseline came from history");
        let no_surge = VolumeWatch::new(&cfg(
            "baseline_windows = 4\nmin_baseline = 10\nhigh_factor = 0",
        ));
        no_surge.seed([("h".to_string(), vec![100; 4])]);
        feed(&no_surge, "h", 9000);
        assert!(no_surge.close_window(0).is_empty());
        let no_drop = VolumeWatch::new(&cfg(
            "baseline_windows = 4\nmin_baseline = 10\nlow_factor = 0",
        ));
        no_drop.seed([("h".to_string(), vec![100; 4])]);
        assert!(no_drop.close_window(0).is_empty());
    }

    #[test]
    fn disabled_cap_and_reconfiguration() {
        let off = VolumeWatch::default();
        assert!(!off.enabled());
        off.count("h");
        assert!(off.close_window(0).is_empty());
        assert_eq!(off.render_metrics(), "");
        let capped = VolumeWatch::new(&cfg("max_hosts = 2"));
        for h in ["a", "b", "c"] {
            capped.count(h);
        }
        assert!(capped.render_metrics().contains("logpit_volume_hosts 2"));
        // A new window length starts the baselines over; other changes keep them.
        let w = small();
        w.seed([("h".to_string(), vec![100; 4])]);
        w.reconfigure(&cfg(
            "baseline_windows = 4\nmin_baseline = 10\nhigh_factor = 3",
        ));
        feed(&w, "h", 400);
        assert_eq!(w.close_window(0).len(), 1);
        w.reconfigure(&cfg(
            "window_secs = 60\nbaseline_windows = 4\nmin_baseline = 10",
        ));
        assert_eq!(w.window_secs(), 60);
        feed(&w, "h", 4000);
        assert!(w.close_window(0).is_empty(), "no baseline yet");
    }

    #[test]
    fn settings_are_validated() {
        let ok = VolumeConfig::default();
        assert!(ok.validate().is_ok());
        for bad in [
            VolumeConfig {
                window_secs: 5,
                ..ok.clone()
            },
            VolumeConfig {
                window_secs: 999_999,
                ..ok.clone()
            },
            VolumeConfig {
                baseline_windows: 2,
                ..ok.clone()
            },
            VolumeConfig {
                high_factor: 1.0,
                ..ok.clone()
            },
            VolumeConfig {
                high_factor: -1.0,
                ..ok.clone()
            },
            VolumeConfig {
                low_factor: 1.0,
                ..ok.clone()
            },
            VolumeConfig {
                low_factor: -0.1,
                ..ok.clone()
            },
            VolumeConfig {
                max_hosts: 0,
                ..ok.clone()
            },
            VolumeConfig {
                cooldown_secs: 99_999_999,
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err());
        }
        assert!(
            VolumeConfig {
                high_factor: 0.0,
                low_factor: 0.0,
                ..ok
            }
            .validate()
            .is_ok()
        );
        assert!(toml::from_str::<VolumeConfig>("bogus = 1").is_err());
    }
}
