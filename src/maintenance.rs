//! Maintenance windows: while one covers a host, the notifications about that host (silence,
//! pattern alerts, new patterns, volume) are not sent to the webhook or by e-mail. They still reach
//! the log and the alert history, marked `muted`. Windows come from `[[maintenance]]` (a one-off
//! period, or a daily or weekly time of day in UTC) and from `POST /api/maintenance` (one-off,
//! kept in memory until it ends or the process restarts).

use std::sync::Mutex;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::live::Reloadable;

const DAY_MS: i64 = 86_400_000;
const MINUTE_MS: i64 = 60_000;
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
/// Longest ad-hoc window (a week) and most of them held at once.
pub const MAX_MINUTES: u32 = 7 * 24 * 60;
const MAX_ADHOC: usize = 100;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceConfig {
    /// Hosts the window covers: names or patterns with `*` and `?`.
    pub hosts: Vec<String>,
    /// Or the hosts of these `[[tags]]`, together with `hosts`.
    pub tags: Vec<String>,
    /// Shown in the alert history in place of the muted notifications.
    pub reason: String,
    /// A one-off period, as RFC 3339 times (`2026-10-05T02:00:00Z`): set both `from` and `until`.
    pub from: Option<String>,
    pub until: Option<String>,
    /// A time of day in UTC, `HH:MM-HH:MM` (an end before the start runs into the next day),
    /// on every day or only on `days` (`mon` … `sun`).
    pub between: Option<String>,
    pub days: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    Once {
        from: i64,
        until: i64,
    },
    /// Days as a bit mask (bit 0 = Monday) and minutes since midnight UTC.
    Daily {
        days: u8,
        start: u32,
        end: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub hosts: Vec<String>,
    pub reason: String,
    pub schedule: Schedule,
}

fn parse_time(what: &str, text: &str) -> anyhow::Result<i64> {
    Ok(chrono::DateTime::parse_from_rfc3339(text)
        .with_context(|| format!("maintenance {what} {text:?} is not an RFC 3339 time"))?
        .timestamp_millis())
}

fn parse_clock(text: &str) -> Option<u32> {
    let (h, m) = text.trim().split_once(':')?;
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

impl Window {
    pub fn from_config(cfg: &MaintenanceConfig, tags: &crate::tags::Tags) -> anyhow::Result<Self> {
        let mut hosts = cfg.hosts.clone();
        crate::tags::validate_patterns("maintenance hosts", &hosts)?;
        for h in tags
            .patterns(&cfg.tags)
            .map_err(|e| anyhow::anyhow!("maintenance: {e}"))?
        {
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
        if hosts.is_empty() {
            bail!("a maintenance window needs hosts or tags (use \"*\" for every host)");
        }
        let schedule = match (&cfg.from, &cfg.until, &cfg.between) {
            (Some(from), Some(until), None) if cfg.days.is_empty() => {
                let (from, until) = (parse_time("from", from)?, parse_time("until", until)?);
                if until <= from {
                    bail!("maintenance until must be after from");
                }
                Schedule::Once { from, until }
            }
            (None, None, Some(between)) => {
                let bad = || anyhow::anyhow!("maintenance between {between:?} must be HH:MM-HH:MM");
                let (a, b) = between.split_once('-').ok_or_else(bad)?;
                let (start, end) = (
                    parse_clock(a).ok_or_else(bad)?,
                    parse_clock(b).ok_or_else(bad)?,
                );
                if start == end {
                    bail!("maintenance between {between:?} is empty");
                }
                let mut days = 0u8;
                for d in &cfg.days {
                    let i = DAYS
                        .iter()
                        .position(|n| n.eq_ignore_ascii_case(d))
                        .with_context(|| format!("maintenance day {d:?} is not mon … sun"))?;
                    days |= 1 << i;
                }
                if cfg.days.is_empty() {
                    days = 0x7f;
                }
                Schedule::Daily { days, start, end }
            }
            _ => bail!(
                "a maintenance window sets from and until, or between (with optional days), not both"
            ),
        };
        Ok(Self {
            hosts,
            reason: cfg.reason.clone(),
            schedule,
        })
    }

    pub fn covers(&self, host: &str) -> bool {
        self.hosts.iter().any(|p| crate::tags::glob_match(p, host))
    }

    pub fn active(&self, now_ms: i64) -> bool {
        match self.schedule {
            Schedule::Once { from, until } => (from..until).contains(&now_ms),
            Schedule::Daily { days, start, end } => {
                // 1970-01-01 was a Thursday.
                let dow = (now_ms.div_euclid(DAY_MS) + 3).rem_euclid(7) as u32;
                let minute = (now_ms.rem_euclid(DAY_MS) / MINUTE_MS) as u32;
                let on = |d: u32| days & (1 << d) != 0;
                if start < end {
                    on(dow) && (start..end).contains(&minute)
                } else {
                    (on(dow) && minute >= start) || (on((dow + 6) % 7) && minute < end)
                }
            }
        }
    }
}

/// A window as `GET /api/maintenance` shows it.
#[derive(Debug, Serialize)]
pub struct WindowInfo {
    /// Only windows created through the API have one, to delete them with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// `config` or `api`.
    pub source: &'static str,
    pub hosts: Vec<String>,
    pub reason: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub between: Option<String>,
}

impl WindowInfo {
    fn new(id: Option<u64>, w: &Window, now: i64) -> Self {
        let (mut from, mut until, mut days, mut between) = (None, None, Vec::new(), None);
        match w.schedule {
            Schedule::Once { from: f, until: u } => (from, until) = (Some(f), Some(u)),
            Schedule::Daily {
                days: mask,
                start,
                end,
            } => {
                days = (0..7)
                    .filter(|i| mask & (1 << i) != 0)
                    .map(|i| DAYS[i])
                    .collect();
                between = Some(format!(
                    "{:02}:{:02}-{:02}:{:02}",
                    start / 60,
                    start % 60,
                    end / 60,
                    end % 60
                ));
            }
        }
        Self {
            id,
            source: if id.is_some() { "api" } else { "config" },
            hosts: w.hosts.clone(),
            reason: w.reason.clone(),
            active: w.active(now),
            from,
            until,
            days,
            between,
        }
    }
}

#[derive(Default)]
pub struct Maintenance {
    configured: Reloadable<Vec<Window>>,
    adhoc: Mutex<(u64, Vec<(u64, Window)>)>,
}

impl Maintenance {
    pub fn windows(
        configs: &[MaintenanceConfig],
        tags: &crate::tags::Tags,
    ) -> anyhow::Result<Vec<Window>> {
        configs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                Window::from_config(c, tags).with_context(|| format!("maintenance #{}", i + 1))
            })
            .collect()
    }

    pub fn new(windows: Vec<Window>) -> Self {
        Self {
            configured: Reloadable::new(windows),
            adhoc: Mutex::default(),
        }
    }

    pub fn reconfigure(&self, windows: Vec<Window>) {
        self.configured.set(std::sync::Arc::new(windows));
    }

    /// The reason to show when `host` is under maintenance at `now_ms`.
    pub fn muting(&self, host: &str, now_ms: i64) -> Option<String> {
        let reason = |w: &Window| {
            if w.reason.is_empty() {
                "maintenance".to_string()
            } else {
                w.reason.clone()
            }
        };
        if let Some(w) = self
            .configured
            .get()
            .iter()
            .find(|w| w.covers(host) && w.active(now_ms))
        {
            return Some(reason(w));
        }
        let adhoc = self.adhoc.lock().unwrap_or_else(|e| e.into_inner());
        adhoc
            .1
            .iter()
            .find(|(_, w)| w.covers(host) && w.active(now_ms))
            .map(|(_, w)| reason(w))
    }

    /// Starts a window of `minutes` from now on `hosts`; returns its id.
    pub fn add(
        &self,
        hosts: Vec<String>,
        minutes: u32,
        reason: String,
        now_ms: i64,
    ) -> Result<(u64, WindowInfo), String> {
        if hosts.is_empty() {
            return Err("hosts is required (use [\"*\"] for every host)".into());
        }
        crate::tags::validate_patterns("hosts", &hosts).map_err(|e| e.to_string())?;
        if !(1..=MAX_MINUTES).contains(&minutes) {
            return Err(format!("minutes must be between 1 and {MAX_MINUTES}"));
        }
        if reason.len() > 200 || reason.chars().any(char::is_control) {
            return Err("reason must be at most 200 characters, without control characters".into());
        }
        let window = Window {
            hosts,
            reason,
            schedule: Schedule::Once {
                from: now_ms,
                until: now_ms + i64::from(minutes) * MINUTE_MS,
            },
        };
        let mut adhoc = self.adhoc.lock().unwrap_or_else(|e| e.into_inner());
        adhoc.1.retain(|(_, w)| match w.schedule {
            Schedule::Once { until, .. } => until > now_ms,
            _ => true,
        });
        if adhoc.1.len() >= MAX_ADHOC {
            return Err(format!("at most {MAX_ADHOC} windows at once"));
        }
        adhoc.0 += 1;
        let id = adhoc.0;
        let info = WindowInfo::new(Some(id), &window, now_ms);
        adhoc.1.push((id, window));
        Ok((id, info))
    }

    pub fn remove(&self, id: u64) -> bool {
        let mut adhoc = self.adhoc.lock().unwrap_or_else(|e| e.into_inner());
        let before = adhoc.1.len();
        adhoc.1.retain(|(i, _)| *i != id);
        adhoc.1.len() != before
    }

    /// Every window (configured, then created through the API that have not ended).
    pub fn list(&self, now_ms: i64) -> Vec<WindowInfo> {
        let mut out: Vec<WindowInfo> = self
            .configured
            .get()
            .iter()
            .map(|w| WindowInfo::new(None, w, now_ms))
            .collect();
        let adhoc = self.adhoc.lock().unwrap_or_else(|e| e.into_inner());
        out.extend(adhoc.1.iter().filter_map(|(id, w)| match w.schedule {
            Schedule::Once { until, .. } if until <= now_ms => None,
            _ => Some(WindowInfo::new(Some(*id), w, now_ms)),
        }));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags() -> crate::tags::Tags {
        crate::tags::Tags::from_config(&[crate::tags::TagConfig {
            name: "web".into(),
            hosts: vec!["web*".into()],
        }])
        .unwrap()
    }

    fn cfg(toml_text: &str) -> MaintenanceConfig {
        toml::from_str(toml_text).unwrap()
    }

    fn window(toml_text: &str) -> anyhow::Result<Window> {
        Window::from_config(&cfg(toml_text), &tags())
    }

    /// 2026-10-05 is a Monday.
    fn at(day: u32, h: i64, m: i64) -> i64 {
        let base = chrono::DateTime::parse_from_rfc3339(&format!("2026-10-{day:02}T00:00:00Z"))
            .unwrap()
            .timestamp_millis();
        base + h * 3_600_000 + m * MINUTE_MS
    }

    #[test]
    fn one_off_windows_cover_their_period_and_hosts() {
        let w = window(
            "hosts = [\"db1\"]\ntags = [\"web\"]\nreason = \"upgrade\"\n\
             from = \"2026-10-05T02:00:00Z\"\nuntil = \"2026-10-05T04:00:00+00:00\"",
        )
        .unwrap();
        assert!(w.covers("db1") && w.covers("web7") && !w.covers("mail"));
        assert!(!w.active(at(5, 1, 59)));
        assert!(w.active(at(5, 2, 0)) && w.active(at(5, 3, 59)));
        assert!(!w.active(at(5, 4, 0)));
    }

    #[test]
    fn daily_windows_follow_days_and_run_past_midnight() {
        let nightly = window("hosts = [\"*\"]\nbetween = \"02:00-04:30\"").unwrap();
        assert!(nightly.active(at(6, 3, 0)) && !nightly.active(at(6, 4, 30)));
        assert!(!nightly.active(at(6, 1, 59)));
        let sundays =
            window("hosts = [\"*\"]\nbetween = \"02:00-04:00\"\ndays = [\"Sun\"]").unwrap();
        assert!(sundays.active(at(11, 3, 0)), "2026-10-11 is a Sunday");
        assert!(!sundays.active(at(10, 3, 0)), "Saturday");
        // 23:00 to 01:00 on Saturdays: Sunday's first hour belongs to Saturday's window.
        let late = window("hosts = [\"*\"]\nbetween = \"23:00-01:00\"\ndays = [\"sat\"]").unwrap();
        assert!(late.active(at(10, 23, 30)) && late.active(at(11, 0, 30)));
        assert!(!late.active(at(11, 23, 30)) && !late.active(at(10, 0, 30)));
        assert!(!late.active(at(11, 1, 0)));
    }

    #[test]
    fn bad_windows_are_refused() {
        for bad in [
            "",
            "hosts = [\"a\"]",
            "tags = [\"nope\"]\nbetween = \"01:00-02:00\"",
            "hosts = [\"a\"]\nfrom = \"2026-10-05T02:00:00Z\"",
            "hosts = [\"a\"]\nfrom = \"2026-10-05T04:00:00Z\"\nuntil = \"2026-10-05T02:00:00Z\"",
            "hosts = [\"a\"]\nfrom = \"yesterday\"\nuntil = \"tomorrow\"",
            "hosts = [\"a\"]\nbetween = \"01:00-01:00\"",
            "hosts = [\"a\"]\nbetween = \"25:00-26:00\"",
            "hosts = [\"a\"]\nbetween = \"01:00-02:00\"\ndays = [\"funday\"]",
            "hosts = [\"a\"]\nbetween = \"01:00-02:00\"\nfrom = \"2026-10-05T02:00:00Z\"\nuntil = \"2026-10-05T03:00:00Z\"",
        ] {
            assert!(window(bad).is_err(), "{bad}");
        }
        assert!(toml::from_str::<MaintenanceConfig>("host = \"a\"").is_err());
    }

    #[test]
    fn api_windows_mute_until_they_end_or_are_removed() {
        let m = Maintenance::new(Vec::new());
        let now = at(5, 12, 0);
        assert_eq!(m.muting("web1", now), None);
        let (id, info) = m
            .add(vec!["web*".into()], 30, "deploy".into(), now)
            .unwrap();
        assert_eq!((info.source, info.active), ("api", true));
        assert_eq!(
            m.muting("web1", now + 29 * MINUTE_MS).as_deref(),
            Some("deploy")
        );
        assert_eq!(m.muting("db1", now), None);
        assert_eq!(m.muting("web1", now + 30 * MINUTE_MS), None);
        assert_eq!(m.list(now).len(), 1);
        assert!(
            m.list(now + 31 * MINUTE_MS).is_empty(),
            "ended windows are not listed"
        );
        let (second, _) = m.add(vec!["*".into()], 5, String::new(), now).unwrap();
        assert_eq!(m.muting("x", now).as_deref(), Some("maintenance"));
        assert!(m.remove(second) && !m.remove(second));
        assert!(m.remove(id));
        assert_eq!(m.muting("web1", now), None);
        for (hosts, minutes) in [
            (vec![], 5),
            (vec!["a".into()], 0),
            (vec!["a".into()], MAX_MINUTES + 1),
        ] {
            assert!(m.add(hosts, minutes, String::new(), now).is_err());
        }
    }

    #[test]
    fn configured_windows_can_be_replaced() {
        let m = Maintenance::new(vec![
            window("hosts = [\"a\"]\nbetween = \"00:00-23:59\"").unwrap(),
        ]);
        let now = at(5, 12, 0);
        assert!(m.muting("a", now).is_some());
        m.reconfigure(Vec::new());
        assert!(m.muting("a", now).is_none());
    }
}
