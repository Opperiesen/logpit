//! Settings that can change while LogPit runs, and the reload that swaps them (on `SIGHUP`).
//!
//! A reload rebuilds every affected piece from the new configuration first, and only when all of
//! them built does it swap them in, so a typo in the file never leaves LogPit half-configured: the
//! running configuration simply stays.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio_rustls::TlsAcceptor;

use crate::alerts::AlertRules;
use crate::auth::Auth;
use crate::config::Config;
use crate::dedup::Dedup;
use crate::logmetrics::LogMetrics;
use crate::parsers::Parsers;
use crate::ratelimit::RateLimiter;
use crate::rules::Rules;
use crate::silence;
use crate::watch::PatternWatch;
use crate::webhook::Webhook;

/// A value that can be replaced while readers use it: `get` hands out the current one, and a reader
/// that already holds a value keeps it until it is done.
pub struct Reloadable<T>(RwLock<Arc<T>>);

impl<T> Reloadable<T> {
    pub fn new(value: T) -> Self {
        Self(RwLock::new(Arc::new(value)))
    }

    pub fn get(&self) -> Arc<T> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, value: Arc<T>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = value;
    }
}

impl<T: Default> Default for Reloadable<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// What the silence checker and the notifier need: thresholds, the webhook and the check period.
pub struct SilenceSettings {
    pub rules: silence::Rules,
    pub webhook: Option<Webhook>,
    pub interval: Duration,
}

impl Default for SilenceSettings {
    fn default() -> Self {
        Self {
            rules: silence::Rules::default(),
            webhook: None,
            interval: Duration::from_secs(30),
        }
    }
}

impl SilenceSettings {
    fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let s = &cfg.silence;
        let webhook = match s.webhook_url.as_str() {
            "" => None,
            url => Some(Webhook::new(url, s.webhook_format, &s.webhook_headers)?),
        };
        Ok(Self {
            rules: silence::Rules::from_config(s),
            webhook,
            interval: Duration::from_secs(s.check_interval_secs),
        })
    }
}

#[derive(Default)]
pub struct LiveSettings {
    pub rules: Reloadable<Rules>,
    pub alerts: Reloadable<AlertRules>,
    /// Counters derived from the logs.
    pub metrics: Reloadable<LogMetrics>,
    /// Regex parsers.
    pub parsers: Reloadable<Parsers>,
    /// Host tags.
    pub tags: Reloadable<crate::tags::Tags>,
    pub limiter: Reloadable<RateLimiter>,
    pub structured: AtomicBool,
    pub auth: Reloadable<Auth>,
    pub silence: Reloadable<SilenceSettings>,
    /// New-pattern and surge notifications; its settings are swapped in place so that the
    /// templates it has learned survive a reload.
    pub watch: PatternWatch,
    /// Collapsing of repeated messages; settings are swapped in place so open runs survive.
    pub dedup: Dedup,
    /// Per-host volume watch; settings are swapped in place so baselines survive a reload.
    pub volume: crate::volume::VolumeWatch,
    /// The acceptor of the syslog TLS listener, when it is enabled.
    pub tls: Option<Arc<Reloadable<TlsAcceptor>>>,
}

/// What a reload did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadReport {
    /// Settings that were rebuilt and swapped in.
    pub applied: Vec<&'static str>,
    /// Settings that differ in the new file but only take effect after a restart.
    pub restart_required: Vec<&'static str>,
}

fn tls_acceptor(cfg: &Config) -> anyhow::Result<Option<TlsAcceptor>> {
    let s = &cfg.syslog;
    match (s.tls_listen.is_empty(), &s.tls_cert, &s.tls_key) {
        (false, Some(cert), Some(key)) => {
            crate::tls::build_acceptor(cert, key, s.tls_client_ca.as_deref()).map(Some)
        }
        _ => Ok(None),
    }
}

impl LiveSettings {
    /// Builds everything from the configuration at startup.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            rules: Reloadable::new(Rules::from_config(&cfg.ingest.rules)?),
            alerts: Reloadable::new(AlertRules::from_config(&cfg.alerts)?),
            metrics: Reloadable::new(LogMetrics::from_config(
                &cfg.metrics,
                &crate::tags::Tags::from_config(&cfg.tags)?,
            )?),
            parsers: Reloadable::new(Parsers::from_config(&cfg.parsers)?),
            tags: Reloadable::new(crate::tags::Tags::from_config(&cfg.tags)?),
            limiter: Reloadable::new(RateLimiter::new(&cfg.ingest.rate_limit)),
            structured: AtomicBool::new(cfg.ingest.parse_structured),
            auth: Reloadable::new(cfg.auth()),
            silence: Reloadable::new(SilenceSettings::from_config(cfg)?),
            watch: PatternWatch::new(&cfg.new_patterns, crate::ingest::now_ms())?,
            dedup: Dedup::new(&cfg.ingest.dedup),
            volume: crate::volume::VolumeWatch::new(&cfg.volume),
            tls: tls_acceptor(cfg)?.map(|a| Arc::new(Reloadable::new(a))),
        })
    }

    /// Settings of `new` that `old` was started with and that cannot change while running.
    pub fn restart_required(&self, old: &Config, new: &Config) -> Vec<&'static str> {
        let mut out = Vec::new();
        if old.storage != new.storage {
            out.push("storage");
        }
        if old.syslog.udp_listen != new.syslog.udp_listen {
            out.push("syslog.udp_listen");
        }
        if old.syslog.tcp_listen != new.syslog.tcp_listen {
            out.push("syslog.tcp_listen");
        }
        if old.gelf.udp_listen != new.gelf.udp_listen {
            out.push("gelf.udp_listen");
        }
        if old.gelf.tcp_listen != new.gelf.tcp_listen {
            out.push("gelf.tcp_listen");
        }
        // The TLS listener cannot be started or stopped by a reload, only its certificates change.
        let tls_wanted = tls_configured(new);
        if old.syslog.tls_listen != new.syslog.tls_listen || (tls_wanted != self.tls.is_some()) {
            out.push("syslog.tls_listen");
        }
        if old.http.listen != new.http.listen {
            out.push("http.listen");
        }
        if old.http.max_body_bytes != new.http.max_body_bytes {
            out.push("http.max_body_bytes");
        }
        if old.forward != new.forward {
            out.push("forward");
        }
        if old.http.audit_retention_days != new.http.audit_retention_days {
            out.push("http.audit_retention_days");
        }
        out
    }

    /// Rebuilds what changed from `new` and swaps it in, or fails without changing anything.
    /// Components whose configuration is unchanged are kept, with their counters and state
    /// (alert windows, rate-limit buckets). The TLS certificate files and the tokens are always
    /// read again, since renewing a certificate or rotating a token changes files, not the
    /// configuration.
    pub fn reload(&self, old: &Config, new: &Config) -> anyhow::Result<ReloadReport> {
        let mut report = ReloadReport {
            restart_required: self.restart_required(old, new),
            ..Default::default()
        };

        // 1. Build every replacement. Nothing is applied until all of them exist.
        let rules = (old.ingest.rules != new.ingest.rules)
            .then(|| Rules::from_config(&new.ingest.rules).map(Arc::new))
            .transpose()?;
        let alerts = (old.alerts != new.alerts)
            .then(|| AlertRules::from_config(&new.alerts).map(Arc::new))
            .transpose()?;
        // The `tag` label reads the tags, so a change to them rebuilds the counters too.
        let metrics = (old.metrics != new.metrics || old.tags != new.tags)
            .then(|| {
                let tags = crate::tags::Tags::from_config(&new.tags)?;
                LogMetrics::from_config(&new.metrics, &tags).map(Arc::new)
            })
            .transpose()?;
        let parsers = (old.parsers != new.parsers)
            .then(|| Parsers::from_config(&new.parsers).map(Arc::new))
            .transpose()?;
        let limiter = (old.ingest.rate_limit != new.ingest.rate_limit)
            .then(|| Arc::new(RateLimiter::new(&new.ingest.rate_limit)));
        let silence = (old.silence != new.silence)
            .then(|| SilenceSettings::from_config(new).map(Arc::new))
            .transpose()?;
        let tls = match (&self.tls, tls_acceptor(new)?) {
            (Some(_), Some(acceptor)) => Some(Arc::new(acceptor)),
            _ => None,
        };
        let auth = Arc::new(new.auth());
        let tags = (old.tags != new.tags)
            .then(|| crate::tags::Tags::from_config(&new.tags).map(Arc::new))
            .transpose()?;
        // Checked here so a bad value fails the reload before anything is applied.
        new.new_patterns.validate()?;
        new.ingest.dedup.validate()?;
        new.volume.validate()?;

        // 2. Swap.
        if let Some(rules) = rules {
            self.rules.set(rules);
            report.applied.push("ingest rules");
        }
        if let Some(alerts) = alerts {
            self.alerts.set(alerts);
            report.applied.push("alerts");
        }
        if let Some(metrics) = metrics {
            self.metrics.set(metrics);
            report.applied.push("log metrics");
        }
        if let Some(tags) = tags {
            self.tags.set(tags);
            report.applied.push("host tags");
        }
        if let Some(parsers) = parsers {
            self.parsers.set(parsers);
            report.applied.push("regex parsers");
        }
        if let Some(limiter) = limiter {
            self.limiter.set(limiter);
            report.applied.push("rate limits");
        }
        if old.ingest.parse_structured != new.ingest.parse_structured {
            self.structured
                .store(new.ingest.parse_structured, Ordering::Relaxed);
            report.applied.push("structured parsing");
        }
        if let Some(silence) = silence {
            self.silence.set(silence);
            report.applied.push("silence alerts and webhook");
        }
        if old.volume != new.volume {
            self.volume.reconfigure(&new.volume);
            report.applied.push("volume alerts");
        }
        if old.ingest.dedup != new.ingest.dedup {
            self.dedup.reconfigure(&new.ingest.dedup);
            report.applied.push("dedup");
        }
        if old.new_patterns != new.new_patterns {
            self.watch
                .reconfigure(&new.new_patterns, crate::ingest::now_ms())?;
            report.applied.push("new-pattern alerts");
        }
        if old.http.token != new.http.token || old.http.tokens != new.http.tokens {
            report.applied.push("API tokens");
        }
        self.auth.set(auth);
        if let (Some(slot), Some(acceptor)) = (&self.tls, tls) {
            // `Arc<TlsAcceptor>` into the slot: connections accepted from now on use it.
            slot.set(acceptor);
            report.applied.push("TLS certificates");
        }
        Ok(report)
    }
}

fn tls_configured(cfg: &Config) -> bool {
    !cfg.syslog.tls_listen.is_empty()
        && cfg.syslog.tls_cert.is_some()
        && cfg.syslog.tls_key.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Scope;

    fn cfg(toml_text: &str) -> Config {
        Config::parse(toml_text).unwrap()
    }

    #[test]
    fn reloadable_readers_keep_the_value_they_hold() {
        let r = Reloadable::new(1);
        let held = r.get();
        r.set(Arc::new(2));
        assert_eq!((*held, *r.get()), (1, 2));
    }

    #[test]
    fn unchanged_parts_are_kept_and_changed_parts_swapped() {
        let old = cfg(
            "[[ingest.rules]]\nname = \"a\"\naction = \"drop\"\nhost = \"x\"\n\
                       [[alerts]]\nname = \"al\"\ncount = 1\nwindow_secs = 5",
        );
        let live = LiveSettings::from_config(&old).unwrap();
        let rules_before = live.rules.get();
        let alerts_before = live.alerts.get();

        // Only the rules change.
        let new = cfg(
            "[[ingest.rules]]\nname = \"a\"\naction = \"drop\"\nhost = \"y\"\n\
                       [[alerts]]\nname = \"al\"\ncount = 1\nwindow_secs = 5",
        );
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(report.applied, ["ingest rules"]);
        assert!(
            !Arc::ptr_eq(&rules_before, &live.rules.get()),
            "rules were rebuilt"
        );
        assert!(
            Arc::ptr_eq(&alerts_before, &live.alerts.get()),
            "alerts kept, with their state"
        );

        // A new rule takes effect: the old behavior is gone.
        let mut e = crate::model::LogEntry {
            host: "y".into(),
            message: "m".into(),
            ..Default::default()
        };
        assert!(!live.rules.get().apply(&mut e));
        let mut e = crate::model::LogEntry {
            host: "x".into(),
            message: "m".into(),
            ..Default::default()
        };
        assert!(live.rules.get().apply(&mut e));
    }

    #[test]
    fn a_bad_configuration_changes_nothing() {
        let old = cfg("[[ingest.rules]]\naction = \"drop\"\nhost = \"x\"");
        let live = LiveSettings::from_config(&old).unwrap();
        let rules_before = live.rules.get();
        // Valid rules, but an unusable webhook elsewhere in the file: nothing may be applied.
        let mut new = cfg("[[ingest.rules]]\naction = \"drop\"\nhost = \"changed\"");
        new.silence.webhook_url = "ftp://nope".into();
        assert!(live.reload(&old, &new).is_err());
        assert!(
            Arc::ptr_eq(&rules_before, &live.rules.get()),
            "the rules were not swapped either"
        );
        assert!(live.silence.get().webhook.is_none());
    }

    #[test]
    fn new_pattern_settings_reload_keep_what_was_learned() {
        let old = cfg("[new_patterns]\nenabled = true\nlearn_secs = 0");
        let live = LiveSettings::from_config(&old).unwrap();
        let first = crate::model::LogEntry {
            severity: 3,
            message: "disk 1 failed".into(),
            ..Default::default()
        };
        let now = crate::ingest::now_ms() + 1000;
        assert_eq!(live.watch.observe(&first, now).len(), 1);
        let new = cfg("[new_patterns]\nenabled = true\nlearn_secs = 0\nmax_per_minute = 5");
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(report.applied, ["new-pattern alerts"]);
        assert!(
            live.watch.observe(&first, now + 1).is_empty(),
            "still known"
        );
        // An invalid new section fails the whole reload and changes nothing.
        let mut bad = new.clone();
        bad.new_patterns.ignore = vec!["(".into()];
        assert!(live.reload(&new, &bad).is_err());
        // Turning it off stops notifications.
        let off = cfg("");
        live.reload(&new, &off).unwrap();
        let other = crate::model::LogEntry {
            severity: 3,
            message: "something else".into(),
            ..Default::default()
        };
        assert!(live.watch.observe(&other, now + 2).is_empty());
    }

    #[test]
    fn log_metrics_reload_when_changed_and_are_kept_otherwise() {
        let old = cfg("[[metrics]]\nname = \"errors\"\nseverity = [\"err\"]");
        let live = LiveSettings::from_config(&old).unwrap();
        let e = crate::model::LogEntry {
            severity: 3,
            message: "boom".into(),
            ..Default::default()
        };
        live.metrics.get().observe(&e);
        assert!(
            live.metrics
                .get()
                .render()
                .contains("logpit_log_errors_total 1")
        );
        // An unrelated change keeps the counters.
        let same = cfg(
            "[[metrics]]\nname = \"errors\"\nseverity = [\"err\"]\n[ingest.rate_limit]\nper_host_per_sec = 10",
        );
        let report = live.reload(&old, &same).unwrap();
        assert!(!report.applied.contains(&"log metrics"));
        assert!(
            live.metrics
                .get()
                .render()
                .contains("logpit_log_errors_total 1")
        );
        // A changed rule list starts from zero.
        let changed = cfg("[[metrics]]\nname = \"errors\"\nseverity = [\"err\", \"crit\"]");
        let report = live.reload(&same, &changed).unwrap();
        assert!(report.applied.contains(&"log metrics"));
        assert!(
            live.metrics
                .get()
                .render()
                .contains("logpit_log_errors_total 0")
        );
        // A bad rule fails the reload and changes nothing.
        let mut bad = changed.clone();
        bad.metrics[0].name = "Bad".into();
        assert!(live.reload(&changed, &bad).is_err());
    }

    #[test]
    fn dedup_settings_follow_a_reload_and_keep_open_runs() {
        let old = cfg("[ingest.dedup]\nenabled = true\nwindow_secs = 60");
        let live = LiveSettings::from_config(&old).unwrap();
        let e = crate::model::LogEntry {
            ts: 1000,
            host: "h".into(),
            message: "same".into(),
            ..Default::default()
        };
        assert!(live.dedup.observe(&e, 1000).0);
        assert!(!live.dedup.observe(&e, 2000).0);
        let new = cfg("[ingest.dedup]\nenabled = true\nwindow_secs = 30");
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(report.applied, ["dedup"]);
        assert!(
            !live.dedup.observe(&e, 3000).0,
            "the open run kept counting"
        );
        let off = cfg("");
        live.reload(&new, &off).unwrap();
        assert!(
            live.dedup.observe(&e, 4000).0,
            "turned off: everything is stored"
        );
        let mut bad = new.clone();
        bad.ingest.dedup.window_secs = 0;
        assert!(live.reload(&off, &bad).is_err());
    }

    #[test]
    fn forward_targets_need_a_restart() {
        let old = cfg("");
        let live = LiveSettings::from_config(&old).unwrap();
        let new = cfg("[[forward]]\nsyslog = \"udp://10.0.0.5:514\"");
        let report = live.reload(&old, &new).unwrap();
        assert!(report.applied.is_empty());
        assert_eq!(report.restart_required, ["forward"]);
    }

    #[test]
    fn parsers_follow_a_reload() {
        let old = cfg("[[parsers]]\nname = \"p\"\nregex = '^(?P<kind>\\w+)'");
        let live = LiveSettings::from_config(&old).unwrap();
        let mut e = crate::model::LogEntry {
            message: "disk full".into(),
            ..Default::default()
        };
        live.parsers.get().apply(&mut e);
        assert_eq!(e.fields["kind"], "disk");
        let new = cfg("[[parsers]]\nname = \"p\"\nregex = '^\\w+ (?P<what>\\w+)'");
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(report.applied, ["regex parsers"]);
        let mut e = crate::model::LogEntry {
            message: "disk full".into(),
            ..Default::default()
        };
        live.parsers.get().apply(&mut e);
        assert_eq!(e.fields.get("what").map(String::as_str), Some("full"));
        assert!(!e.fields.contains_key("kind"));
        let mut bad = new.clone();
        bad.parsers[0].regex = "(".into();
        assert!(live.reload(&new, &bad).is_err());
    }

    #[test]
    fn tags_reload_and_rebuild_the_counters_that_use_them() {
        let text = |hosts: &str| {
            format!(
                "[[tags]]\nname = \"prod\"\nhosts = [{hosts}]\n\
                 [[metrics]]\nname = \"all\"\nlabels = [\"tag\"]\n\
                 [[http.tokens]]\ntoken = \"t\"\nscopes = [\"read\"]\ntags = [\"prod\"]"
            )
        };
        let old = cfg(&text("\"web*\""));
        let live = LiveSettings::from_config(&old).unwrap();
        let e = crate::model::LogEntry {
            host: "db1".into(),
            message: "x".into(),
            ..Default::default()
        };
        live.metrics.get().observe(&e);
        assert!(
            live.metrics
                .get()
                .render()
                .contains("logpit_log_all_total{tag=\"\"} 1")
        );
        assert_eq!(live.tags.get().of_host("web3"), ["prod"]);
        assert!(
            !live
                .auth
                .get()
                .identify(Some("t"), Scope::Read)
                .unwrap()
                .access
                .allows("db1", "")
        );
        let new = cfg(&text("\"web*\", \"db*\""));
        let report = live.reload(&old, &new).unwrap();
        assert!(report.applied.contains(&"host tags") && report.applied.contains(&"log metrics"));
        assert_eq!(live.tags.get().of_host("db1"), ["prod"]);
        assert!(
            live.auth
                .get()
                .identify(Some("t"), Scope::Read)
                .unwrap()
                .access
                .allows("db1", "")
        );
        live.metrics.get().observe(&e);
        assert!(
            live.metrics
                .get()
                .render()
                .contains("logpit_log_all_total{tag=\"prod\"} 1")
        );
    }

    #[test]
    fn volume_settings_follow_a_reload() {
        let old = cfg("");
        let live = LiveSettings::from_config(&old).unwrap();
        assert!(!live.volume.enabled());
        let new = cfg(
            "[volume]\nenabled = true\nwindow_secs = 60\nbaseline_windows = 3\nmin_baseline = 1",
        );
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(report.applied, ["volume alerts"]);
        assert!(live.volume.enabled());
        assert_eq!(live.volume.window_secs(), 60);
        for _ in 0..4 {
            for _ in 0..10 {
                live.volume.count("h");
            }
            live.volume.close_window(0);
        }
        for _ in 0..200 {
            live.volume.count("h");
        }
        assert_eq!(live.volume.close_window(0).len(), 1);
        let mut bad = new.clone();
        bad.volume.window_secs = 1;
        assert!(live.reload(&new, &bad).is_err());
    }

    #[test]
    fn tokens_are_always_reread() {
        let old = cfg("[http]\ntoken = \"old-secret\"");
        let live = LiveSettings::from_config(&old).unwrap();
        assert_eq!(
            live.auth.get().check(Some("old-secret"), Scope::Read),
            crate::auth::Decision::Allowed
        );
        let new = cfg("[http]\ntoken = \"new-secret\"");
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(report.applied, ["API tokens"]);
        use crate::auth::Decision::*;
        assert_eq!(
            live.auth.get().check(Some("old-secret"), Scope::Read),
            Unauthorized
        );
        assert_eq!(
            live.auth.get().check(Some("new-secret"), Scope::Write),
            Allowed
        );
    }

    #[test]
    fn settings_that_need_a_restart_are_reported_not_applied() {
        let old = cfg("[http]\nlisten = \"127.0.0.1:8080\"");
        let live = LiveSettings::from_config(&old).unwrap();
        let new = cfg("[http]\nlisten = \"0.0.0.0:9000\"\nmax_body_bytes = 1000\n\
             [storage]\npath = \"other.db\"\n[syslog]\nudp_listen = \"0.0.0.0:514\"");
        let report = live.reload(&old, &new).unwrap();
        assert!(report.applied.is_empty());
        assert_eq!(
            report.restart_required,
            [
                "storage",
                "syslog.udp_listen",
                "http.listen",
                "http.max_body_bytes"
            ]
        );
        // Identical configurations need nothing.
        assert!(live.restart_required(&old, &old).is_empty());
    }

    #[test]
    fn silence_and_structured_parsing_follow_the_new_file() {
        let old = cfg("");
        let live = LiveSettings::from_config(&old).unwrap();
        assert!(live.structured.load(Ordering::Relaxed) && !live.silence.get().rules.enabled());
        let new = cfg(
            "[ingest]\nparse_structured = false\n[silence]\ndefault_after_secs = 60\ncheck_interval_secs = 5",
        );
        let report = live.reload(&old, &new).unwrap();
        assert_eq!(
            report.applied,
            ["structured parsing", "silence alerts and webhook"]
        );
        assert!(!live.structured.load(Ordering::Relaxed));
        let s = live.silence.get();
        assert!(s.rules.enabled());
        assert_eq!(s.interval, Duration::from_secs(5));
    }
}
