//! Ingestion rules: drop entries that are only noise, and mask secrets before they are stored.
//!
//! Rules run in order on each entry, after structured fields have been extracted and before the
//! entry is queued, broadcast to live tails or written to disk.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::model::{LogEntry, parse_severity};

/// Compiled regexes may not grow beyond this (a guard against pathological patterns).
const REGEX_SIZE_LIMIT: usize = 1 << 20;
const DEFAULT_MASK: &str = "***";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Discard the entry.
    Drop,
    /// Replace what the pattern matches, in the message and in field values.
    Mask,
}

/// A severity given as a name (`debug`, `err`, …) or a number (0-7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum SeveritySpec {
    Number(i64),
    Name(String),
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Label in logs and metrics; defaults to `rule-<position>`.
    pub name: Option<String>,
    pub action: Action,
    /// Only entries from this host (exact match).
    pub host: Option<String>,
    /// Only entries from this app (exact match).
    pub app: Option<String>,
    /// Only entries with one of these severities.
    #[serde(default)]
    pub severity: Vec<SeveritySpec>,
    /// Regular expression searched in the message. Required for `mask`; for `drop` it narrows
    /// the rule to messages that match.
    pub pattern: Option<String>,
    /// Replacement for `mask` (default `***`); `$1` refers to a capture group, `$$` is a `$`.
    pub replace: Option<String>,
}

struct Rule {
    name: String,
    action: Action,
    host: Option<String>,
    app: Option<String>,
    severities: Option<[bool; 8]>,
    pattern: Option<Regex>,
    replace: String,
    hits: AtomicU64,
}

#[derive(Default)]
pub struct Rules {
    rules: Vec<Rule>,
}

pub(crate) fn severity_set(specs: &[SeveritySpec]) -> anyhow::Result<Option<[bool; 8]>> {
    if specs.is_empty() {
        return Ok(None);
    }
    let mut set = [false; 8];
    for spec in specs {
        let sev = match spec {
            SeveritySpec::Number(n) => u8::try_from(*n).ok().filter(|n| *n <= 7),
            SeveritySpec::Name(name) => parse_severity(name),
        };
        let sev =
            sev.with_context(|| format!("unknown severity {spec:?} (use emerg … debug or 0-7)"))?;
        set[usize::from(sev)] = true;
    }
    Ok(Some(set))
}

impl Rules {
    pub fn from_config(configs: &[RuleConfig]) -> anyhow::Result<Self> {
        let mut rules = Vec::with_capacity(configs.len());
        for (i, c) in configs.iter().enumerate() {
            let name = c.name.clone().unwrap_or_else(|| format!("rule-{}", i + 1));
            let ctx = || format!("ingest rule {name:?}");
            if name.is_empty() {
                bail!("ingest rule {} has an empty name", i + 1);
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
            let severities = severity_set(&c.severity).with_context(ctx)?;
            match c.action {
                Action::Mask if pattern.is_none() => {
                    bail!("{}: a mask rule needs a pattern", ctx())
                }
                Action::Drop if c.replace.is_some() => {
                    bail!("{}: replace only applies to mask rules", ctx())
                }
                Action::Drop
                    if pattern.is_none()
                        && c.host.is_none()
                        && c.app.is_none()
                        && severities.is_none() =>
                {
                    bail!(
                        "{}: a drop rule with no condition would discard everything",
                        ctx()
                    )
                }
                _ => {}
            }
            rules.push(Rule {
                name,
                action: c.action,
                host: c.host.clone(),
                app: c.app.clone(),
                severities,
                pattern,
                replace: c
                    .replace
                    .clone()
                    .unwrap_or_else(|| DEFAULT_MASK.to_string()),
                hits: AtomicU64::new(0),
            });
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Applies the rules in order. Returns false when the entry was dropped.
    pub fn apply(&self, entry: &mut LogEntry) -> bool {
        for rule in &self.rules {
            if !rule.in_scope(entry) {
                continue;
            }
            match rule.action {
                Action::Drop => {
                    if rule
                        .pattern
                        .as_ref()
                        .is_none_or(|p| p.is_match(&entry.message))
                    {
                        rule.hits.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
                Action::Mask => {
                    if rule.mask(entry) {
                        rule.hits.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        true
    }

    /// Prometheus text: how many entries each rule dropped or changed.
    pub fn render_metrics(&self) -> String {
        if self.rules.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "# HELP logpit_rule_hits_total Entries dropped or masked by an ingestion rule\n\
             # TYPE logpit_rule_hits_total counter\n",
        );
        for r in &self.rules {
            let name = r
                .name
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let action = match r.action {
                Action::Drop => "drop",
                Action::Mask => "mask",
            };
            let _ = writeln!(
                out,
                "logpit_rule_hits_total{{rule=\"{name}\",action=\"{action}\"}} {}",
                r.hits.load(Ordering::Relaxed)
            );
        }
        out
    }
}

impl Rule {
    fn in_scope(&self, e: &LogEntry) -> bool {
        self.host.as_ref().is_none_or(|h| *h == e.host)
            && self.app.as_ref().is_none_or(|a| *a == e.app)
            && self
                .severities
                .is_none_or(|s| s[usize::from(e.severity.min(7))])
    }

    /// Masks the message and the field values; true when anything changed.
    fn mask(&self, e: &mut LogEntry) -> bool {
        let Some(pattern) = &self.pattern else {
            return false;
        };
        let mut changed = false;
        let mut replace = |text: &mut String| {
            if let std::borrow::Cow::Owned(masked) =
                pattern.replace_all(text, self.replace.as_str())
            {
                *text = masked;
                changed = true;
            }
        };
        replace(&mut e.message);
        for value in e.fields.values_mut() {
            replace(value);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(toml_text: &str) -> anyhow::Result<Rules> {
        #[derive(Deserialize)]
        struct Wrapper {
            rules: Vec<RuleConfig>,
        }
        Rules::from_config(&toml::from_str::<Wrapper>(toml_text).unwrap().rules)
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

    #[test]
    fn drop_rules_match_on_scope_and_pattern() {
        let r = rules(
            r#"
            [[rules]]
            action = "drop"
            app = "cron"
            severity = ["info", "debug"]

            [[rules]]
            action = "drop"
            pattern = "GET /healthz"

            [[rules]]
            action = "drop"
            host = "printer"
            severity = [7]
            pattern = "(?i)heartbeat"
            "#,
        )
        .unwrap();
        let keep = |mut e: LogEntry| r.apply(&mut e);
        assert!(!keep(entry("h", "cron", 6, "job done")), "app + severity");
        assert!(
            keep(entry("h", "cron", 3, "job failed")),
            "an error from cron stays"
        );
        assert!(keep(entry("h", "sshd", 6, "job done")));
        assert!(
            !keep(entry("h", "nginx", 6, "GET /healthz 200")),
            "pattern alone"
        );
        assert!(keep(entry("h", "nginx", 6, "GET /index 200")));
        assert!(
            !keep(entry("printer", "x", 7, "HeartBeat ok")),
            "all conditions together"
        );
        assert!(
            keep(entry("printer", "x", 6, "heartbeat ok")),
            "severity differs"
        );
        assert!(keep(entry("other", "x", 7, "heartbeat ok")), "host differs");
    }

    #[test]
    fn mask_rules_rewrite_message_and_fields() {
        let r = rules(
            r#"
            [[rules]]
            action = "mask"
            pattern = "(token|password)=\\S+"
            replace = "$1=[hidden]"

            [[rules]]
            action = "mask"
            pattern = '\b\d{1,3}(\.\d{1,3}){3}\b'
            host = "router"
            "#,
        )
        .unwrap();
        let mut e = entry(
            "router",
            "a",
            6,
            "login password=hunter2 from 10.1.2.3 and 10.9.9.9",
        );
        e.fields.insert("note".into(), "token=abc123 seen".into());
        e.fields.insert("src".into(), "192.168.0.7".into());
        assert!(r.apply(&mut e));
        assert_eq!(e.message, "login password=[hidden] from *** and ***");
        assert_eq!(e.fields["note"], "token=[hidden] seen");
        assert_eq!(e.fields["src"], "***", "field values are masked too");
        // The second rule is limited to the router.
        let mut other = entry("web", "a", 6, "from 10.1.2.3 password=x");
        r.apply(&mut other);
        assert_eq!(other.message, "from 10.1.2.3 password=[hidden]");
    }

    #[test]
    fn rules_apply_in_order_and_a_drop_stops_the_chain() {
        let r = rules(
            r#"
            [[rules]]
            action = "mask"
            pattern = "secret"
            [[rules]]
            action = "drop"
            pattern = "\\*\\*\\*"
            "#,
        )
        .unwrap();
        // The mask runs first, so the drop rule sees the masked text.
        assert!(!r.apply(&mut entry("h", "a", 6, "a secret here")));
        assert!(r.apply(&mut entry("h", "a", 6, "nothing to see")));
    }

    #[test]
    fn invalid_rules_are_rejected() {
        for (text, why) in [
            ("[[rules]]\naction = \"drop\"", "drop with no condition"),
            ("[[rules]]\naction = \"mask\"", "mask without a pattern"),
            (
                "[[rules]]\naction = \"mask\"\npattern = \"(unclosed\"",
                "bad regex",
            ),
            (
                "[[rules]]\naction = \"drop\"\nhost = \"h\"\nreplace = \"x\"",
                "replace on drop",
            ),
            (
                "[[rules]]\naction = \"drop\"\nseverity = [\"loud\"]",
                "unknown severity",
            ),
            (
                "[[rules]]\naction = \"drop\"\nseverity = [9]",
                "severity out of range",
            ),
            (
                "[[rules]]\naction = \"drop\"\nname = \"\"\nhost = \"h\"",
                "empty name",
            ),
        ] {
            assert!(rules(text).is_err(), "{why}");
        }
        // A pattern bigger than the regex size limit is refused rather than compiled.
        let huge = format!(
            "[[rules]]\naction = \"mask\"\npattern = '{}'",
            "(a{100}){100}".repeat(50)
        );
        assert!(rules(&huge).is_err());
    }

    #[test]
    fn hits_are_counted_per_rule() {
        let r = rules(
            "[[rules]]\nname = \"noise\"\naction = \"drop\"\napp = \"cron\"\n\
             [[rules]]\naction = \"mask\"\npattern = \"x\"",
        )
        .unwrap();
        r.apply(&mut entry("h", "cron", 6, "a"));
        r.apply(&mut entry("h", "cron", 6, "b"));
        r.apply(&mut entry("h", "web", 6, "xx"));
        r.apply(&mut entry("h", "web", 6, "none"));
        let m = r.render_metrics();
        assert!(
            m.contains("logpit_rule_hits_total{rule=\"noise\",action=\"drop\"} 2"),
            "{m}"
        );
        assert!(
            m.contains("logpit_rule_hits_total{rule=\"rule-2\",action=\"mask\"} 1"),
            "{m}"
        );
        assert_eq!(Rules::default().render_metrics(), "");
    }
}
