//! Per-token ingestion quotas: a rate (events per second, with a burst of ten seconds) and a daily
//! total (events per UTC day) for the tokens that write. A request is refused with 429 once its
//! token has no budget left; the events it carried are charged after it ran, so a request can
//! overshoot a limit by at most its own size and the next ones are refused until the budget is
//! back. The counters live in memory: they start from zero after a restart.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const DAY_MS: i64 = 86_400_000;
/// The rate bucket holds this many seconds of the allowed rate.
const BURST_SECS: f64 = 10.0;

/// What a token may ingest; `None` means no limit on that dimension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    pub per_sec: Option<u32>,
    pub per_day: Option<u64>,
}

impl Limits {
    pub fn any(&self) -> bool {
        self.per_sec.is_some() || self.per_day.is_some()
    }
}

/// Events a request pushed, counted by its handler and charged to the token once it is done.
#[derive(Debug, Clone, Default)]
pub struct Charge(std::sync::Arc<AtomicU64>);

impl Charge {
    pub fn add(&self, events: usize) {
        self.0.fetch_add(events as u64, Ordering::Relaxed);
    }

    pub fn total(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

struct State {
    /// Events the rate bucket still allows; negative after an overshoot.
    bucket: f64,
    refilled: Instant,
    /// UTC day number of `used`.
    day: i64,
    used: u64,
    rejected: u64,
}

#[derive(Default)]
pub struct Quotas {
    state: Mutex<HashMap<String, State>>,
}

impl Quotas {
    fn with<T>(
        &self,
        name: &str,
        limits: &Limits,
        now_ms: i64,
        at: Instant,
        f: impl FnOnce(&mut State) -> T,
    ) -> T {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let s = map.entry(name.to_string()).or_insert_with(|| State {
            bucket: f64::from(limits.per_sec.unwrap_or(0)) * BURST_SECS,
            refilled: at,
            day: now_ms.div_euclid(DAY_MS),
            used: 0,
            rejected: 0,
        });
        if let Some(rate) = limits.per_sec {
            let rate = f64::from(rate);
            let elapsed = at.saturating_duration_since(s.refilled).as_secs_f64();
            s.bucket = (s.bucket + elapsed * rate).min(rate * BURST_SECS);
        }
        s.refilled = at;
        let day = now_ms.div_euclid(DAY_MS);
        if s.day != day {
            (s.day, s.used) = (day, 0);
        }
        f(s)
    }

    /// `Err(seconds)` when the token has used up its budget: how long until it may write again.
    pub fn check(&self, name: &str, limits: &Limits, now_ms: i64, at: Instant) -> Result<(), u64> {
        if !limits.any() {
            return Ok(());
        }
        self.with(name, limits, now_ms, at, |s| {
            let mut wait = 0;
            if let Some(rate) = limits.per_sec
                && s.bucket <= 0.0
            {
                wait = wait.max((-s.bucket / f64::from(rate)).ceil().max(1.0) as u64);
            }
            if let Some(day) = limits.per_day
                && s.used >= day
            {
                let left = (s.day + 1) * DAY_MS - now_ms;
                wait = wait.max(((left + 999) / 1000).max(1) as u64);
            }
            if wait > 0 {
                s.rejected += 1;
                Err(wait)
            } else {
                Ok(())
            }
        })
    }

    /// Charges `events` to the token.
    pub fn charge(&self, name: &str, limits: &Limits, events: u64, now_ms: i64, at: Instant) {
        if !limits.any() || events == 0 {
            return;
        }
        self.with(name, limits, now_ms, at, |s| {
            s.bucket -= events as f64;
            s.used = s.used.saturating_add(events);
        });
    }

    pub fn render_metrics(&self) -> String {
        let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<_> = map.iter().filter(|(_, s)| s.rejected > 0).collect();
        if names.is_empty() {
            return String::new();
        }
        names.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = String::from(
            "# HELP logpit_quota_rejected_total Requests refused with 429 because a token used up its quota\n\
             # TYPE logpit_quota_rejected_total counter\n",
        );
        for (name, s) in names {
            out.push_str(&format!(
                "logpit_quota_rejected_total{{token=\"{name}\"}} {}\n",
                s.rejected
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn no_limits_never_refuse() {
        let q = Quotas::default();
        let now = Instant::now();
        q.charge("a", &Limits::default(), 1_000_000, 0, now);
        assert!(q.check("a", &Limits::default(), 0, now).is_ok());
        assert_eq!(q.render_metrics(), "");
    }

    #[test]
    fn the_rate_allows_a_burst_then_refills() {
        let q = Quotas::default();
        let l = Limits {
            per_sec: Some(10),
            per_day: None,
        };
        let t0 = Instant::now();
        assert!(q.check("a", &l, 0, t0).is_ok());
        // The burst is 100 events; a request of 130 overshoots by 30 and is still accepted.
        q.charge("a", &l, 130, 0, t0);
        // 30 events in debt at 10/s: three seconds to get back to zero.
        assert_eq!(q.check("a", &l, 0, t0), Err(3));
        assert_eq!(q.check("a", &l, 0, t0 + Duration::from_secs(2)), Err(1));
        assert!(
            q.check("a", &l, 0, t0 + Duration::from_millis(3100))
                .is_ok()
        );
        // Other tokens are independent.
        assert!(q.check("b", &l, 0, t0).is_ok());
        // The refill never goes past the burst.
        assert!(q.check("a", &l, 0, t0 + Duration::from_secs(3600)).is_ok());
        q.charge("a", &l, 100, 0, t0 + Duration::from_secs(3600));
        assert_eq!(q.check("a", &l, 0, t0 + Duration::from_secs(3600)), Err(1));
    }

    #[test]
    fn the_daily_total_resets_at_midnight_utc() {
        let q = Quotas::default();
        let l = Limits {
            per_sec: None,
            per_day: Some(1000),
        };
        let t = Instant::now();
        let evening = 5 * DAY_MS + 23 * 3_600_000 + 30 * 60_000;
        q.charge("a", &l, 999, evening, t);
        assert!(q.check("a", &l, evening, t).is_ok());
        q.charge("a", &l, 1, evening, t);
        // Half an hour to midnight.
        assert_eq!(q.check("a", &l, evening, t), Err(1800));
        assert!(q.check("a", &l, 6 * DAY_MS, t).is_ok());
        let metrics = q.render_metrics();
        assert!(metrics.contains("logpit_quota_rejected_total{token=\"a\"} 1"));
    }

    #[test]
    fn charges_count_what_handlers_add() {
        let c = Charge::default();
        let other = c.clone();
        c.add(3);
        other.add(4);
        assert_eq!(c.total(), 7);
    }
}
