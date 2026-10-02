//! Rate limiting at ingestion, so a sender that goes haywire cannot drown the others or fill
//! the disk. A token bucket per host (entries per second, with a burst allowance) and an optional
//! one across all hosts.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

/// Hosts tracked with a bucket of their own; the rest share one bucket (so inventing host names
/// does not escape the limit).
const MAX_HOSTS: usize = 4096;
/// Distinct hosts remembered for the per-host drop counters.
const MAX_OFFENDERS: usize = 256;
/// Hosts listed in the metrics, worst first.
const METRIC_OFFENDERS: usize = 10;
/// A host that is being limited is mentioned in the log at most this often.
const WARN_EVERY_MS: i64 = 60_000;
const MAX_RATE: u64 = 10_000_000;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Sustained entries per second allowed from one host; 0 = no per-host limit.
    pub per_host_per_sec: u64,
    /// Entries a host may send at once before the sustained rate applies; 0 = four times the rate.
    pub burst: u64,
    /// Sustained entries per second across all hosts; 0 = no global limit.
    pub global_per_sec: u64,
}

impl RateLimitConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, v) in [
            ("per_host_per_sec", self.per_host_per_sec),
            ("burst", self.burst),
            ("global_per_sec", self.global_per_sec),
        ] {
            if v > MAX_RATE {
                anyhow::bail!("ingest.rate_limit.{name} must be at most {MAX_RATE}");
            }
        }
        if self.burst > 0 && self.per_host_per_sec == 0 {
            anyhow::bail!("ingest.rate_limit.burst needs per_host_per_sec");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Rate {
    per_sec: f64,
    burst: f64,
}

struct Bucket {
    tokens: f64,
    last_ms: i64,
    last_warn_ms: Option<i64>,
    dropped_since_warn: u64,
}

impl Bucket {
    fn full(rate: Rate, now: i64) -> Self {
        Self {
            tokens: rate.burst,
            last_ms: now,
            last_warn_ms: None,
            dropped_since_warn: 0,
        }
    }

    fn refill(&mut self, rate: Rate, now: i64) {
        let elapsed = (now - self.last_ms).max(0) as f64 / 1000.0;
        self.tokens = (self.tokens + elapsed * rate.per_sec).min(rate.burst);
        self.last_ms = now.max(self.last_ms);
    }
}

#[derive(Default)]
struct State {
    hosts: HashMap<String, Bucket>,
    /// Shared by hosts beyond [`MAX_HOSTS`].
    overflow: Option<Bucket>,
    global: Option<Bucket>,
    offenders: HashMap<String, u64>,
}

pub struct RateLimiter {
    per_host: Option<Rate>,
    global: Option<Rate>,
    state: Mutex<State>,
    limited: AtomicU64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(&RateLimitConfig::default())
    }
}

impl RateLimiter {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let per_host = (cfg.per_host_per_sec > 0).then(|| Rate {
            per_sec: cfg.per_host_per_sec as f64,
            burst: if cfg.burst > 0 {
                cfg.burst
            } else {
                cfg.per_host_per_sec.saturating_mul(4)
            } as f64,
        });
        let global = (cfg.global_per_sec > 0).then(|| Rate {
            per_sec: cfg.global_per_sec as f64,
            burst: cfg.global_per_sec.saturating_mul(4) as f64,
        });
        Self {
            per_host,
            global,
            state: Mutex::new(State::default()),
            limited: AtomicU64::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        self.per_host.is_some() || self.global.is_some()
    }

    /// Whether an entry from `host` arriving at `now` (Unix ms) may be accepted. An entry takes a
    /// token from the host's bucket and from the global one, and is refused when either is empty
    /// (and then takes nothing).
    pub fn allow(&self, host: &str, now: i64) -> bool {
        if !self.enabled() {
            return true;
        }
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        let mut denied_by_host = false;

        if let Some(rate) = self.per_host {
            let tracked = state.hosts.contains_key(host);
            if !tracked && state.hosts.len() >= MAX_HOSTS {
                // Make room by forgetting hosts whose bucket is full again, else share one bucket.
                state.hosts.retain(|_, b| {
                    b.refill(rate, now);
                    b.tokens < rate.burst
                });
            }
            let use_overflow = !state.hosts.contains_key(host) && state.hosts.len() >= MAX_HOSTS;
            let bucket = if use_overflow {
                state
                    .overflow
                    .get_or_insert_with(|| Bucket::full(rate, now))
            } else {
                state
                    .hosts
                    .entry(host.to_string())
                    .or_insert_with(|| Bucket::full(rate, now))
            };
            bucket.refill(rate, now);
            if bucket.tokens < 1.0 {
                bucket.dropped_since_warn += 1;
                if bucket.last_warn_ms.is_none_or(|t| now - t >= WARN_EVERY_MS) {
                    tracing::warn!(
                        "rate limit exceeded by {host} (limit {}/s, burst {}): dropping its excess entries, {} since the last notice",
                        rate.per_sec,
                        rate.burst,
                        bucket.dropped_since_warn
                    );
                    bucket.last_warn_ms = Some(now);
                    bucket.dropped_since_warn = 0;
                }
                denied_by_host = true;
            }
        }

        let mut denied_by_global = false;
        if let (false, Some(rate)) = (denied_by_host, self.global) {
            let bucket = state.global.get_or_insert_with(|| Bucket::full(rate, now));
            bucket.refill(rate, now);
            if bucket.tokens < 1.0 {
                denied_by_global = true;
            } else {
                bucket.tokens -= 1.0;
            }
        }

        if denied_by_host || denied_by_global {
            self.limited.fetch_add(1, Ordering::Relaxed);
            if state.offenders.contains_key(host) || state.offenders.len() < MAX_OFFENDERS {
                *state.offenders.entry(host.to_string()).or_default() += 1;
            }
            return false;
        }
        // Both limits passed: now charge the host bucket (the global one is already charged).
        if self.per_host.is_some() {
            let tracked = state.hosts.contains_key(host);
            let bucket = if tracked {
                state.hosts.get_mut(host)
            } else {
                state.overflow.as_mut()
            };
            if let Some(b) = bucket {
                b.tokens -= 1.0;
            }
        }
        true
    }

    pub fn limited_total(&self) -> u64 {
        self.limited.load(Ordering::Relaxed)
    }

    /// Prometheus text: the total, and the hosts that have been refused most.
    pub fn render_metrics(&self) -> String {
        if !self.enabled() {
            return String::new();
        }
        let mut out = format!(
            "# HELP logpit_rate_limited_total Entries refused by the rate limit\n\
             # TYPE logpit_rate_limited_total counter\nlogpit_rate_limited_total {}\n",
            self.limited_total()
        );
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut worst: Vec<(&String, &u64)> = state.offenders.iter().collect();
        worst.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        if !worst.is_empty() {
            out.push_str(
                "# HELP logpit_rate_limited_host_total Entries refused, for the hosts refused most\n\
                 # TYPE logpit_rate_limited_host_total counter\n",
            );
        }
        for (host, n) in worst.into_iter().take(METRIC_OFFENDERS) {
            let label = host
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = writeln!(
                out,
                "logpit_rate_limited_host_total{{host=\"{label}\"}} {n}"
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(per_host: u64, burst: u64, global: u64) -> RateLimiter {
        RateLimiter::new(&RateLimitConfig {
            per_host_per_sec: per_host,
            burst,
            global_per_sec: global,
        })
    }

    fn allowed(l: &RateLimiter, host: &str, n: usize, at: i64) -> usize {
        (0..n).filter(|_| l.allow(host, at)).count()
    }

    #[test]
    fn disabled_limiter_allows_everything() {
        let l = RateLimiter::default();
        assert!(!l.enabled());
        assert_eq!(allowed(&l, "h", 100_000, 0), 100_000);
        assert_eq!(l.render_metrics(), "");
    }

    #[test]
    fn burst_then_sustained_rate() {
        let l = limiter(10, 20, 0);
        assert_eq!(allowed(&l, "pve", 50, 0), 20, "the burst, then refused");
        assert_eq!(l.limited_total(), 30);
        // Half a second later 5 tokens have come back; a full second gives 10.
        assert_eq!(allowed(&l, "pve", 50, 500), 5);
        assert_eq!(allowed(&l, "pve", 50, 1500), 10);
        // Idle for long: the bucket refills only up to the burst.
        assert_eq!(allowed(&l, "pve", 100, 60_000), 20);
        // The default burst is four times the rate.
        assert_eq!(allowed(&limiter(5, 0, 0), "h", 100, 0), 20);
    }

    #[test]
    fn hosts_are_limited_independently() {
        let l = limiter(10, 10, 0);
        assert_eq!(allowed(&l, "noisy", 1000, 0), 10);
        assert_eq!(
            allowed(&l, "quiet", 5, 0),
            5,
            "a noisy host does not use up the others' allowance"
        );
        assert_eq!(allowed(&l, "other", 10, 0), 10);
    }

    #[test]
    fn global_limit_applies_across_hosts_and_refused_entries_cost_nothing() {
        let l = limiter(0, 0, 10); // burst 40
        let total: usize = (0..10).map(|i| allowed(&l, &format!("h{i}"), 10, 0)).sum();
        assert_eq!(total, 40, "the global burst is shared by every host");
        // With both limits, an entry refused by the host limit must not consume global tokens.
        let both = limiter(2, 2, 100); // global burst 400
        assert_eq!(allowed(&both, "a", 1000, 0), 2);
        assert_eq!(allowed(&both, "b", 1000, 0), 2);
        // 400 - 4 tokens remain; refused entries took none, so a later fresh host gets its share.
        assert_eq!(allowed(&both, "c", 5, 0), 2);
    }

    #[test]
    fn inventing_host_names_does_not_escape_the_limit() {
        let l = limiter(1, 1, 0);
        // MAX_HOSTS distinct hosts each take their one token...
        let first_wave = (0..MAX_HOSTS)
            .filter(|i| l.allow(&format!("h{i}"), 0))
            .count();
        assert_eq!(first_wave, MAX_HOSTS);
        // ...then newcomers share a single bucket: only one more gets through, not one each.
        let second_wave = (0..1000).filter(|i| l.allow(&format!("new{i}"), 0)).count();
        assert_eq!(second_wave, 1);
        assert_eq!(
            l.state.lock().unwrap().hosts.len(),
            MAX_HOSTS,
            "memory stays bounded"
        );
        // Once the old buckets have refilled, they are forgotten and newcomers get their own again.
        assert!(l.allow("brand-new", 10_000));
        assert!(l.state.lock().unwrap().hosts.contains_key("brand-new"));
    }

    #[test]
    fn metrics_list_the_worst_offenders() {
        let l = limiter(1, 1, 0);
        allowed(&l, "chatty", 11, 0); // 10 refused
        allowed(&l, "loud\"host", 4, 0); // 3 refused
        allowed(&l, "fine", 1, 0);
        let m = l.render_metrics();
        assert!(m.contains("logpit_rate_limited_total 13\n"), "{m}");
        let chatty = m.find("host=\"chatty\"} 10").expect("chatty listed");
        let loud = m
            .find("host=\"loud\\\"host\"} 3")
            .expect("loud listed, label escaped");
        assert!(chatty < loud, "worst first: {m}");
        assert!(!m.contains("host=\"fine\""));
        // At most METRIC_OFFENDERS hosts are listed.
        let many = limiter(1, 1, 0);
        for i in 0..50 {
            allowed(&many, &format!("h{i:02}"), 3, 0);
        }
        assert_eq!(
            many.render_metrics()
                .matches("logpit_rate_limited_host_total{")
                .count(),
            METRIC_OFFENDERS
        );
    }

    #[test]
    fn config_validation() {
        assert!(RateLimitConfig::default().validate().is_ok());
        assert!(
            RateLimitConfig {
                per_host_per_sec: 100,
                burst: 500,
                global_per_sec: 1000
            }
            .validate()
            .is_ok()
        );
        assert!(
            RateLimitConfig {
                burst: 10,
                ..Default::default()
            }
            .validate()
            .is_err(),
            "burst alone is meaningless"
        );
        assert!(
            RateLimitConfig {
                per_host_per_sec: MAX_RATE + 1,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
