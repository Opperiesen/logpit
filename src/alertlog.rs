//! History of the notifications LogPit raised (silence, pattern alerts, new patterns and surges,
//! volume): kept in the database (or only in memory) and served by `GET /api/alerts`, so they stay
//! visible when the webhook is down, absent or ignored.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::Value;

use crate::ingest::now_ms;
use crate::live::LiveSettings;
use crate::silence::Event;

/// Entries kept in memory (all of them when there is no database).
pub const MEMORY: usize = 200;
/// Most entries one query returns.
pub const MAX_QUERY_LIMIT: usize = 1000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AlertEntry {
    /// Unix ms when the event was raised.
    pub ts: i64,
    /// `host_silent`, `host_recovered`, `log_alert`, `new_pattern`, `pattern_surge`, `volume_surge`
    /// or `volume_drop`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub message: String,
    /// Whether the webhook accepted it; absent when no webhook was configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered: Option<bool>,
    /// Whether the SMTP server accepted the e-mail; absent when e-mail is off, the kind is not
    /// sent by e-mail or the hourly limit dropped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<bool>,
    /// The event as the webhook gets it in `json` format.
    pub details: Value,
}

impl AlertEntry {
    pub fn from_event(event: &Event, ts: i64, delivered: Option<bool>) -> Self {
        let details = event.payload();
        Self {
            ts,
            kind: details["event"].as_str().unwrap_or("alert").to_string(),
            host: details["host"].as_str().map(str::to_string),
            message: details["message"].as_str().unwrap_or_default().to_string(),
            delivered,
            email: None,
            details,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AlertQuery {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub kind: Option<String>,
    pub host: Option<String>,
    pub limit: usize,
}

impl AlertQuery {
    fn matches(&self, e: &AlertEntry) -> bool {
        self.since_ms.is_none_or(|t| e.ts >= t)
            && self.until_ms.is_none_or(|t| e.ts <= t)
            && self.kind.as_ref().is_none_or(|k| *k == e.kind)
            && self
                .host
                .as_ref()
                .is_none_or(|h| e.host.as_ref() == Some(h))
    }
}

#[derive(Default)]
pub struct AlertLog {
    memory: Mutex<VecDeque<AlertEntry>>,
    db: Option<PathBuf>,
    retention_days: u32,
}

impl AlertLog {
    /// A history in the database at `db` for `retention_days`; without a path, or with 0 days, only
    /// the last [`MEMORY`] entries are kept, in memory.
    pub fn new(db: Option<PathBuf>, retention_days: u32) -> Self {
        Self {
            memory: Mutex::default(),
            db: db.filter(|_| retention_days > 0),
            retention_days,
        }
    }

    pub fn persistent_path(&self) -> Option<&std::path::Path> {
        self.db.as_deref()
    }

    /// Adds an entry to memory and, when persistent, to the database (which never fails the
    /// caller: a write error is logged).
    pub async fn record(&self, entry: AlertEntry) {
        {
            let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
            if memory.len() >= MEMORY {
                memory.pop_front();
            }
            memory.push_back(entry.clone());
        }
        let Some(path) = self.db.clone() else {
            return;
        };
        let cutoff = now_ms() - i64::from(self.retention_days) * 86_400_000;
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let conn = crate::store::open(&path)?;
            crate::store::insert_alert(&conn, &entry)?;
            crate::store::purge_alerts(&conn, cutoff)?;
            Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("alert history write failed: {e:#}"),
            Err(e) => tracing::error!("alert history task failed: {e}"),
        }
    }

    /// The newest matching entries held in memory, newest first.
    pub fn search_memory(&self, q: &AlertQuery) -> Vec<AlertEntry> {
        let memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
        memory
            .iter()
            .rev()
            .filter(|e| q.matches(e))
            .take(q.limit)
            .cloned()
            .collect()
    }
}

/// Raises a notification: writes it to the log, sends it to the webhook of the moment (in the
/// background, with its retries) and records it with the outcome.
pub fn dispatch(event: Event, live: &Arc<LiveSettings>, log: &Arc<AlertLog>) {
    let ts = now_ms();
    let message = event.payload()["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    match event {
        Event::Recovered { .. } => tracing::info!("silence recovered: {message}"),
        Event::Silent { .. } => tracing::warn!("silence alert: {message}"),
        _ => tracing::warn!("{message}"),
    }
    // A host under maintenance, or a pattern alert put on mute, still gets its alert logged and
    // recorded, but nobody is told.
    let rule_muted = match &event {
        Event::Pattern { rule, .. } => live.mutes.muting(rule, ts).map(|until| {
            let end = chrono::DateTime::from_timestamp_millis(until).unwrap_or_default();
            format!("rule muted until {}", end.format("%Y-%m-%d %H:%M UTC"))
        }),
        _ => None,
    };
    let muted = rule_muted.or_else(|| {
        event.payload()["host"]
            .as_str()
            .and_then(|host| live.maintenance.muting(host, ts))
    });
    if let Some(reason) = muted {
        tracing::info!("muted ({reason}): {message}");
        let mut entry = AlertEntry::from_event(&event, ts, None);
        entry.details["muted"] = Value::String(reason);
        let log = log.clone();
        tokio::spawn(async move { log.record(entry).await });
        return;
    }
    let settings = live.silence.get();
    let (hook, mailer) = (settings.webhook.clone(), settings.email.clone());
    let log = log.clone();
    tokio::spawn(async move {
        // The webhook and the e-mail go out at the same time: each has its own retries.
        let webhook = async {
            match &hook {
                Some(hook) => Some(hook.send(&event).await),
                None => None,
            }
        };
        let email = async {
            match &mailer {
                Some(m) => m.notify(&event, ts).await,
                None => None,
            }
        };
        let (delivered, emailed) = tokio::join!(webhook, email);
        let mut entry = AlertEntry::from_event(&event, ts, delivered);
        entry.email = emailed;
        log.record(entry).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: i64, kind: &str, host: Option<&str>) -> AlertEntry {
        AlertEntry {
            ts,
            kind: kind.into(),
            host: host.map(String::from),
            message: format!("{kind} at {ts}"),
            delivered: None,
            email: None,
            details: Value::Null,
        }
    }

    #[test]
    fn entries_are_built_from_events() {
        let e = AlertEntry::from_event(
            &Event::Silent {
                host: "pve".into(),
                silent_for_ms: 125_000,
                threshold_ms: 120_000,
            },
            42,
            Some(true),
        );
        assert_eq!(
            (e.ts, e.kind.as_str(), e.host.as_deref()),
            (42, "host_silent", Some("pve"))
        );
        assert!(e.message.contains("pve") && e.delivered == Some(true));
        assert_eq!(e.details["event"], "host_silent");
        // A pattern alert without a host has none.
        let p = AlertEntry::from_event(
            &Event::Pattern {
                rule: "disk".into(),
                host: None,
                count: 5,
                window_secs: 60,
                sample: "x".into(),
            },
            1,
            None,
        );
        assert_eq!(
            (p.kind.as_str(), p.host.clone(), p.delivered),
            ("log_alert", None, None)
        );
        let n = AlertEntry::from_event(
            &Event::NewPattern {
                pattern: "p".into(),
                host: "web1".into(),
                severity: "err".into(),
                sample: "s".into(),
            },
            1,
            Some(false),
        );
        assert_eq!(
            (n.kind.as_str(), n.host.as_deref(), n.delivered),
            ("new_pattern", Some("web1"), Some(false))
        );
        let json = serde_json::to_value(&n).unwrap();
        assert_eq!(json["delivered"], false);
        assert!(serde_json::to_value(&p).unwrap().get("delivered").is_none());
    }

    #[tokio::test]
    async fn memory_keeps_the_newest_entries_and_filters() {
        let log = AlertLog::new(None, 30);
        assert!(log.persistent_path().is_none(), "no path, no database");
        for i in 0..(MEMORY as i64 + 20) {
            let kind = if i % 2 == 0 {
                "volume_surge"
            } else {
                "host_silent"
            };
            log.record(entry(i, kind, Some(if i % 3 == 0 { "a" } else { "b" })))
                .await;
        }
        let q = |f: &dyn Fn(&mut AlertQuery)| {
            let mut q = AlertQuery {
                limit: 1000,
                ..Default::default()
            };
            f(&mut q);
            log.search_memory(&q)
        };
        let all = q(&|_| {});
        assert_eq!(all.len(), MEMORY);
        assert_eq!((all[0].ts, all[MEMORY - 1].ts), (MEMORY as i64 + 19, 20));
        assert!(
            q(&|q| q.kind = Some("host_silent".into()))
                .iter()
                .all(|e| e.kind == "host_silent")
        );
        assert!(
            q(&|q| q.host = Some("a".into()))
                .iter()
                .all(|e| e.host.as_deref() == Some("a"))
        );
        assert_eq!(q(&|q| q.since_ms = Some(210)).len(), 10);
        assert_eq!(q(&|q| q.until_ms = Some(30)).len(), 11);
        assert_eq!(q(&|q| q.limit = 3).len(), 3);
    }

    #[tokio::test]
    async fn alerts_of_a_muted_rule_are_recorded_but_muted() {
        let live = Arc::new(LiveSettings::default());
        live.mutes.set("disk", now_ms() + 60_000, now_ms());
        let log = Arc::new(AlertLog::new(None, 30));
        let pattern = |rule: &str| Event::Pattern {
            rule: rule.into(),
            host: Some("nas".into()),
            count: 3,
            window_secs: 600,
            sample: "unreadable sectors".into(),
        };
        dispatch(pattern("disk"), &live, &log);
        dispatch(pattern("auth"), &live, &log);
        let q = AlertQuery {
            limit: 10,
            ..Default::default()
        };
        for _ in 0..100 {
            if log.search_memory(&q).len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let entries = log.search_memory(&q);
        assert_eq!(entries.len(), 2);
        let rule = |e: &&AlertEntry| e.details["rule"].as_str().map(String::from);
        let muted = entries
            .iter()
            .find(|e| rule(e).as_deref() == Some("disk"))
            .unwrap();
        assert!(
            muted.details["muted"]
                .as_str()
                .unwrap()
                .starts_with("rule muted until ")
        );
        let other = entries
            .iter()
            .find(|e| rule(e).as_deref() == Some("auth"))
            .unwrap();
        assert!(other.details.get("muted").is_none());
    }

    #[tokio::test]
    async fn alerts_for_hosts_under_maintenance_are_recorded_but_muted() {
        let live = Arc::new(
            LiveSettings::from_config(
                &crate::config::Config::parse(
                    "[[maintenance]]\nhosts = [\"web*\"]\nreason = \"upgrade\"\n\
                     from = \"2020-01-01T00:00:00Z\"\nuntil = \"2100-01-01T00:00:00Z\"",
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let log = Arc::new(AlertLog::new(None, 30));
        let silent = |host: &str| Event::Silent {
            host: host.into(),
            silent_for_ms: 125_000,
            threshold_ms: 120_000,
        };
        dispatch(silent("web1"), &live, &log);
        dispatch(silent("db1"), &live, &log);
        let q = AlertQuery {
            limit: 10,
            ..Default::default()
        };
        for _ in 0..100 {
            if log.search_memory(&q).len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let entries = log.search_memory(&q);
        assert_eq!(entries.len(), 2);
        let muted = entries
            .iter()
            .find(|e| e.host.as_deref() == Some("web1"))
            .unwrap();
        assert_eq!(muted.details["muted"], "upgrade");
        assert_eq!(muted.delivered, None);
        let other = entries
            .iter()
            .find(|e| e.host.as_deref() == Some("db1"))
            .unwrap();
        assert!(other.details.get("muted").is_none());
    }

    #[tokio::test]
    async fn the_database_keeps_entries_until_they_expire() {
        let dir = std::env::temp_dir().join(format!("logpit-alertlog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.db");
        let _ = std::fs::remove_file(&path);
        drop(crate::store::open(&path).unwrap());
        let log = AlertLog::new(Some(path.clone()), 7);
        assert_eq!(log.persistent_path(), Some(path.as_path()));
        let now = now_ms();
        log.record(entry(now - 10 * 86_400_000, "host_silent", Some("old")))
            .await;
        let mut recent = entry(now - 1000, "volume_drop", Some("db1"));
        recent.delivered = Some(false);
        recent.details = serde_json::json!({"count": 0});
        log.record(recent.clone()).await;
        log.record(entry(now, "new_pattern", None)).await;
        let conn = crate::store::open(&path).unwrap();
        let all = crate::store::alert_events(
            &conn,
            &AlertQuery {
                limit: 100,
                ..Default::default()
            },
        )
        .unwrap();
        // The ten-day-old entry was purged by the recording that followed it.
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].kind, "new_pattern");
        assert_eq!(all[1], recent);
        let drops = crate::store::alert_events(
            &conn,
            &AlertQuery {
                kind: Some("volume_drop".into()),
                host: Some("db1".into()),
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(drops, [recent]);
        assert_eq!(
            crate::store::alert_events(
                &conn,
                &AlertQuery {
                    since_ms: Some(now - 10),
                    limit: 10,
                    ..Default::default()
                }
            )
            .unwrap()
            .len(),
            1
        );
        // With 0 days there is no database, only memory.
        assert!(AlertLog::new(Some(path), 0).persistent_path().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
