//! Regex parsers: `[[parsers]]` rules whose named capture groups become structured fields (and,
//! when asked, the host, app, severity, timestamp or message of the entry), for log formats that
//! have no JSON or `key=value` in them: web server access logs, sshd, firewalls…
//!
//! Parsers are tried in order on each entry and the first one that matches wins. The regex engine
//! runs in linear time whatever the pattern.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use regex::Regex;
use serde::Deserialize;

use crate::model::{LogEntry, level_severity};
use crate::rules::{SeveritySpec, severity_set};

const MAX_FIELDS: usize = 64;
/// Longest parser regex, a bit more than the 500 bytes of filters since formats can be long.
const MAX_REGEX_BYTES: usize = 4096;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ParserConfig {
    /// Label in metrics; defaults to `parser-<position>`.
    pub name: Option<String>,
    /// The regular expression; each named group `(?P<name>…)` becomes a field.
    pub regex: String,
    /// Only entries from this host (exact match).
    pub host: Option<String>,
    /// Only entries from this app (exact match).
    pub app: Option<String>,
    /// Only entries with one of these severities (names or numbers).
    #[serde(default)]
    pub severity: Vec<SeveritySpec>,
    /// The group holding the severity: a level word (`error`, `warn`…) or a number 0-7.
    pub level_from: Option<String>,
    /// The group that replaces the entry's host.
    pub host_from: Option<String>,
    /// The group that replaces the entry's app.
    pub app_from: Option<String>,
    /// The group that replaces the stored message (to cut a prefix already captured elsewhere).
    pub message_from: Option<String>,
    /// The group holding the entry's own timestamp, read with `timestamp_format`.
    pub timestamp_from: Option<String>,
    /// `rfc3339`, `unix` (seconds), `unix_ms`, or a strftime pattern such as
    /// `%d/%b/%Y:%H:%M:%S %z` (a pattern without a zone is read as UTC).
    pub timestamp_format: Option<String>,
    /// Also keep the fields of generic `key=value`/JSON extraction (default: a matching parser
    /// replaces it, since its fields are the precise ones).
    #[serde(default)]
    pub keep_generic: bool,
}

struct Parser {
    name: String,
    regex: Regex,
    host: Option<String>,
    app: Option<String>,
    severities: Option<[bool; 8]>,
    level_from: Option<String>,
    host_from: Option<String>,
    app_from: Option<String>,
    message_from: Option<String>,
    timestamp_from: Option<String>,
    timestamp_format: Option<String>,
    keep_generic: bool,
    matched: AtomicU64,
}

#[derive(Default)]
pub struct Parsers {
    parsers: Vec<Parser>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// No parser matched.
    No,
    /// One matched and the generic extraction should still run.
    KeepGeneric,
    /// One matched and its fields stand in for the generic extraction.
    Replaced,
}

/// A timestamp text as Unix ms.
fn parse_timestamp(text: &str, format: &str) -> Option<i64> {
    let text = text.trim();
    match format {
        "rfc3339" => chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|t| t.timestamp_millis()),
        "unix" => text
            .parse::<f64>()
            .ok()
            .filter(|s| s.is_finite() && *s >= 0.0)
            .map(|s| (s * 1000.0).round() as i64),
        "unix_ms" => text.parse::<i64>().ok().filter(|ms| *ms >= 0),
        pattern => chrono::DateTime::parse_from_str(text, pattern)
            .map(|t| t.timestamp_millis())
            .ok()
            .or_else(|| {
                chrono::NaiveDateTime::parse_from_str(text, pattern)
                    .ok()
                    .map(|t| t.and_utc().timestamp_millis())
            }),
    }
}

/// Whether a strftime pattern is accepted by chrono (its parser does not validate it ahead of use).
fn valid_strftime(pattern: &str) -> bool {
    let mut out = String::new();
    chrono::format::StrftimeItems::new(pattern)
        .all(|item| !matches!(item, chrono::format::Item::Error))
        && write!(out, "{}", chrono::DateTime::UNIX_EPOCH.format(pattern)).is_ok()
}

impl Parsers {
    pub fn from_config(configs: &[ParserConfig]) -> anyhow::Result<Self> {
        let mut parsers = Vec::with_capacity(configs.len());
        let mut names = std::collections::HashSet::new();
        for (i, c) in configs.iter().enumerate() {
            let name = c
                .name
                .clone()
                .unwrap_or_else(|| format!("parser-{}", i + 1));
            let ctx = || format!("parser {name:?}");
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                bail!("parser name {name:?} must be 1 to 64 letters, digits, '_', '-' or '.'");
            }
            if !names.insert(name.clone()) {
                bail!("{}: the name is used by another parser", ctx());
            }
            let regex = crate::filters::compile_regex_up_to(&c.regex, MAX_REGEX_BYTES)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("{}: regex", ctx()))?;
            let groups: Vec<&str> = regex.capture_names().flatten().collect();
            for (what, group) in [
                ("level_from", &c.level_from),
                ("host_from", &c.host_from),
                ("app_from", &c.app_from),
                ("message_from", &c.message_from),
                ("timestamp_from", &c.timestamp_from),
            ] {
                if let Some(g) = group
                    && !groups.contains(&g.as_str())
                {
                    bail!(
                        "{}: {what} names the group {g:?}, which the regex does not define",
                        ctx()
                    );
                }
            }
            match (&c.timestamp_from, &c.timestamp_format) {
                (Some(_), None) => bail!("{}: timestamp_from needs timestamp_format", ctx()),
                (None, Some(_)) => bail!("{}: timestamp_format needs timestamp_from", ctx()),
                (Some(_), Some(f))
                    if !matches!(f.as_str(), "rfc3339" | "unix" | "unix_ms")
                        && !valid_strftime(f) =>
                {
                    bail!(
                        "{}: timestamp_format {f:?} is not a valid strftime pattern",
                        ctx()
                    )
                }
                _ => {}
            }
            if groups.is_empty()
                && c.level_from.is_none()
                && c.message_from.is_none()
                && c.host_from.is_none()
                && c.app_from.is_none()
            {
                bail!(
                    "{}: the regex has no named group, so it would extract nothing",
                    ctx()
                );
            }
            parsers.push(Parser {
                name: name.clone(),
                regex,
                host: c.host.clone(),
                app: c.app.clone(),
                severities: severity_set(&c.severity).with_context(ctx)?,
                level_from: c.level_from.clone(),
                host_from: c.host_from.clone(),
                app_from: c.app_from.clone(),
                message_from: c.message_from.clone(),
                timestamp_from: c.timestamp_from.clone(),
                timestamp_format: c.timestamp_format.clone(),
                keep_generic: c.keep_generic,
                matched: AtomicU64::new(0),
            });
        }
        Ok(Self { parsers })
    }

    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    /// Runs the first parser that applies to `entry` and matches its message.
    pub fn apply(&self, entry: &mut LogEntry) -> Applied {
        for p in &self.parsers {
            if p.host.as_ref().is_some_and(|h| *h != entry.host)
                || p.app.as_ref().is_some_and(|a| *a != entry.app)
                || p.severities
                    .is_some_and(|s| !s[usize::from(entry.severity.min(7))])
            {
                continue;
            }
            // Capture on a copy of the message so replacing it below is safe.
            let message = entry.message.clone();
            let Some(caps) = p.regex.captures(&message) else {
                continue;
            };
            p.matched.fetch_add(1, Ordering::Relaxed);
            let group = |name: &Option<String>| {
                name.as_deref()
                    .and_then(|n| caps.name(n))
                    .map(|m| m.as_str())
                    .filter(|v| !v.is_empty())
            };
            for name in p.regex.capture_names().flatten() {
                if entry.fields.len() >= MAX_FIELDS {
                    break;
                }
                if let (Some(m), Some(key)) =
                    (caps.name(name), crate::structured::sanitize_key(name))
                    && !m.as_str().is_empty()
                {
                    entry
                        .fields
                        .insert(key, crate::structured::clip(m.as_str()));
                }
            }
            if let Some(sev) = group(&p.level_from).and_then(level_severity) {
                entry.severity = sev;
            }
            if let Some(h) = group(&p.host_from) {
                entry.host = h.to_string();
            }
            if let Some(a) = group(&p.app_from) {
                entry.app = a.to_string();
            }
            if let (Some(text), Some(format)) = (group(&p.timestamp_from), &p.timestamp_format)
                && let Some(ts) = parse_timestamp(text, format)
            {
                entry.ts = ts;
            }
            if let Some(m) = group(&p.message_from) {
                entry.message = m.to_string();
            }
            return if p.keep_generic {
                Applied::KeepGeneric
            } else {
                Applied::Replaced
            };
        }
        Applied::No
    }

    /// Prometheus text: how many entries each parser matched.
    pub fn render_metrics(&self) -> String {
        if self.parsers.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "# HELP logpit_parser_matched_total Entries each regex parser matched\n\
             # TYPE logpit_parser_matched_total counter\n",
        );
        for p in &self.parsers {
            let _ = writeln!(
                out,
                "logpit_parser_matched_total{{parser=\"{}\"}} {}",
                p.name,
                p.matched.load(Ordering::Relaxed)
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsers(toml_text: &str) -> anyhow::Result<Parsers> {
        #[derive(Deserialize)]
        struct W {
            parsers: Vec<ParserConfig>,
        }
        Parsers::from_config(&toml::from_str::<W>(toml_text).unwrap().parsers)
    }

    fn entry(host: &str, app: &str, severity: u8, message: &str) -> LogEntry {
        LogEntry {
            ts: 1,
            host: host.into(),
            app: app.into(),
            severity,
            message: message.into(),
            ..Default::default()
        }
    }

    const NGINX: &str = r#"[[parsers]]
name = "nginx"
app = "nginx"
regex = '^(?P<remote>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\d+|-)'
timestamp_from = "time"
timestamp_format = "%d/%b/%Y:%H:%M:%S %z"
"#;

    #[test]
    fn named_groups_become_fields_and_the_timestamp_is_read() {
        let p = parsers(NGINX).unwrap();
        let mut e = entry(
            "web1",
            "nginx",
            6,
            r#"10.0.0.7 - - [03/Oct/2026:12:00:00 +0200] "GET /api/x?y=1 HTTP/1.1" 502 -"#,
        );
        assert_eq!(p.apply(&mut e), Applied::Replaced);
        assert_eq!(e.fields["remote"], "10.0.0.7");
        assert_eq!(e.fields["method"], "GET");
        assert_eq!(e.fields["path"], "/api/x?y=1");
        assert_eq!(e.fields["status"], "502");
        assert_eq!(e.fields["bytes"], "-");
        // 12:00 at +02:00 is 10:00 UTC.
        assert_eq!(e.ts, 1_791_021_600_000);
        assert!(
            p.render_metrics()
                .contains("logpit_parser_matched_total{parser=\"nginx\"} 1")
        );
        // Other apps and lines that do not match are left alone.
        let mut other = entry(
            "web1",
            "apache",
            6,
            r#"10.0.0.7 - - [03/Oct/2026:12:00:00 +0200] "GET / HTTP/1.1" 200 5"#,
        );
        assert_eq!(p.apply(&mut other), Applied::No);
        assert!(other.fields.is_empty());
        let mut junk = entry("web1", "nginx", 6, "worker process exited");
        assert_eq!(p.apply(&mut junk), Applied::No);
        assert_eq!(junk.ts, 1);
    }

    #[test]
    fn level_host_app_and_message_can_come_from_groups() {
        let p = parsers(
            r#"[[parsers]]
regex = '^(?P<h>\S+) (?P<a>\w+)\[\d+\]: (?P<lvl>[A-Za-z]+): (?P<msg>.*)$'
host_from = "h"
app_from = "a"
level_from = "lvl"
message_from = "msg"
"#,
        )
        .unwrap();
        let mut e = entry(
            "relay",
            "",
            6,
            "db7 postgres[412]: ERROR: deadlock detected",
        );
        assert_eq!(p.apply(&mut e), Applied::Replaced);
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.severity),
            ("db7", "postgres", 3)
        );
        assert_eq!(e.message, "deadlock detected");
        assert_eq!(e.fields["lvl"], "ERROR");
        // An unknown level word leaves the severity as it was.
        let mut e = entry("relay", "", 5, "db7 postgres[412]: LOUD: x");
        p.apply(&mut e);
        assert_eq!(e.severity, 5);
    }

    #[test]
    fn the_first_matching_parser_wins_and_filters_apply() {
        let p = parsers(
            r#"[[parsers]]
name = "ssh-fail"
app = "sshd"
severity = ["warning", "err"]
regex = 'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+)'
keep_generic = true
[[parsers]]
name = "any-sshd"
regex = '^(?P<kind>\w+)'
"#,
        )
        .unwrap();
        let mut e = entry(
            "h",
            "sshd",
            4,
            "Failed password for invalid user bob from 1.2.3.4 port 22",
        );
        assert_eq!(p.apply(&mut e), Applied::KeepGeneric);
        assert_eq!(
            (e.fields["user"].as_str(), e.fields["src"].as_str()),
            ("bob", "1.2.3.4")
        );
        assert!(!e.fields.contains_key("kind"), "the first parser took it");
        // Wrong severity: the first parser is skipped and the second one takes it.
        let mut info = entry("h", "sshd", 6, "Failed password for bob from 1.2.3.4");
        assert_eq!(p.apply(&mut info), Applied::Replaced);
        assert_eq!(info.fields["kind"], "Failed");
        let metrics = p.render_metrics();
        assert!(
            metrics.contains("parser=\"ssh-fail\"} 1")
                && metrics.contains("parser=\"any-sshd\"} 1")
        );
    }

    #[test]
    fn empty_groups_and_limits() {
        let p = parsers(
            r#"[[parsers]]
regex = '^(?P<a>\w*) (?P<b>\w*) (?P<very odd>x)?'
"#,
        );
        // Group names with spaces are not valid in the regex crate: refused at load time.
        assert!(p.is_err());
        let p = parsers("[[parsers]]\nregex = '^(?P<a>\\w*)-(?P<b>\\w*)-(?P<c>[0-9]*)'").unwrap();
        let mut e = entry("h", "a", 6, "x--");
        p.apply(&mut e);
        assert_eq!(
            e.fields.len(),
            1,
            "empty captures add no field: {:?}",
            e.fields
        );
        let mut long = entry("h", "a", 6, &format!("v-{}-5", "y".repeat(5000)));
        p.apply(&mut long);
        assert!(long.fields["b"].len() <= 1024);
        // The field cap holds.
        let groups: String = (0..80).map(|i| format!("(?P<g{i}>x)")).collect();
        let many = parsers(&format!("[[parsers]]\nregex = '{groups}'")).unwrap();
        let mut e = entry("h", "a", 6, &"x".repeat(80));
        many.apply(&mut e);
        assert_eq!(e.fields.len(), MAX_FIELDS);
    }

    #[test]
    fn timestamp_formats() {
        let ms = 1_791_028_800_123i64;
        assert_eq!(
            parse_timestamp("2026-10-03T12:00:00.123Z", "rfc3339"),
            Some(ms)
        );
        assert_eq!(parse_timestamp("1791028800.123", "unix"), Some(ms));
        assert_eq!(parse_timestamp("1791028800123", "unix_ms"), Some(ms));
        assert_eq!(
            parse_timestamp("2026-10-03 12:00:00", "%Y-%m-%d %H:%M:%S"),
            Some(ms - 123)
        );
        assert_eq!(
            parse_timestamp("03/Oct/2026:14:00:00 +0200", "%d/%b/%Y:%H:%M:%S %z"),
            Some(ms - 123)
        );
        for (text, fmt) in [
            ("nope", "rfc3339"),
            ("-5", "unix"),
            ("x", "unix_ms"),
            ("2026", "%Y-%m-%d"),
        ] {
            assert_eq!(parse_timestamp(text, fmt), None, "{text}");
        }
        // A bad timestamp leaves the entry's own.
        let p = parsers("[[parsers]]\nregex = '^(?P<t>\\S+) (?P<rest>.*)'\ntimestamp_from = \"t\"\ntimestamp_format = \"rfc3339\"").unwrap();
        let mut e = entry("h", "a", 6, "garbage here");
        p.apply(&mut e);
        assert_eq!(e.ts, 1);
        assert_eq!(e.fields["rest"], "here");
    }

    #[test]
    fn invalid_parsers_are_refused() {
        for bad in [
            "regex = '('",
            "regex = '^x'",
            "regex = '(?P<a>x)'\nlevel_from = \"nope\"",
            "regex = '(?P<a>x)'\nhost_from = \"b\"",
            "regex = '(?P<a>x)'\ntimestamp_from = \"a\"",
            "regex = '(?P<a>x)'\ntimestamp_format = \"rfc3339\"",
            "regex = '(?P<a>x)'\ntimestamp_from = \"a\"\ntimestamp_format = \"%Q\"",
            "regex = '(?P<a>x)'\nseverity = [\"loud\"]",
            "regex = '(?P<a>x)'\nname = \"bad name\"",
            "regex = '(?P<a>x)'\nname = \"\"",
        ] {
            assert!(parsers(&format!("[[parsers]]\n{bad}")).is_err(), "{bad}");
        }
        assert!(parsers("[[parsers]]\nname = \"a\"\nregex = '(?P<a>x)'\n[[parsers]]\nname = \"a\"\nregex = '(?P<b>x)'").is_err());
        assert!(toml::from_str::<ParserConfig>("regex = 'x'\nbogus = 1").is_err());
        assert!(Parsers::default().is_empty());
    }
}
