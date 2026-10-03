//! Prometheus metrics derived from the logs: each `[[metrics]]` rule counts the entries that
//! match it (and optionally sums a numeric field), per combination of the labels it asks for,
//! and `/metrics` exposes the counters.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;

use anyhow::{Context, bail};
use regex::Regex;
use serde::Deserialize;

use crate::logql::level_label;
use crate::model::LogEntry;
use crate::rules::{SeveritySpec, severity_set};

const DEFAULT_MAX_SERIES: usize = 200;
const MAX_SERIES_LIMIT: usize = 10_000;
const MAX_LABELS: usize = 5;
/// Value of every label of the series that stands for all the combinations beyond `max_series`.
const OVERFLOW: &str = "_other";
const MAX_LABEL_VALUE_CHARS: usize = 120;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricConfig {
    /// Becomes the counter `logpit_log_<name>_total`: lower-case letters, digits and `_`.
    pub name: String,
    /// One line of help text for the metric.
    pub help: Option<String>,
    /// Only entries whose message matches this regular expression.
    pub pattern: Option<String>,
    /// Only entries from this host (exact match).
    pub host: Option<String>,
    /// Only entries from this app (exact match).
    pub app: Option<String>,
    /// Only entries with one of these severities (names or numbers).
    #[serde(default)]
    pub severity: Vec<SeveritySpec>,
    /// Label dimensions: `host`, `app`, `level`, or the name of a structured field. Each
    /// distinct combination is a time series, so prefer few, low-cardinality labels.
    #[serde(default)]
    pub labels: Vec<String>,
    /// A structured field holding a number to add up as `logpit_log_<name>_value_sum`.
    pub value_field: Option<String>,
    /// Most series kept; combinations beyond it are counted under `_other`.
    pub max_series: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Label {
    Host,
    App,
    Level,
    /// The first `[[tags]]` tag the host belongs to (empty when none).
    Tag,
    Field(String),
}

#[derive(Default)]
struct Series {
    count: u64,
    sum: f64,
}

struct Rule {
    name: String,
    help: String,
    host: Option<String>,
    app: Option<String>,
    severities: Option<[bool; 8]>,
    pattern: Option<Regex>,
    labels: Vec<(String, Label)>,
    value_field: Option<String>,
    max_series: usize,
    series: Mutex<HashMap<Vec<String>, Series>>,
}

#[derive(Default)]
pub struct LogMetrics {
    rules: Vec<Rule>,
    tags: crate::tags::Tags,
}

fn valid_metric_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 48
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl LogMetrics {
    pub fn from_config(configs: &[MetricConfig], tags: &crate::tags::Tags) -> anyhow::Result<Self> {
        let mut rules = Vec::with_capacity(configs.len());
        let mut names = std::collections::HashSet::new();
        for c in configs {
            let ctx = || format!("metric {:?}", c.name);
            if !valid_metric_name(&c.name) {
                bail!(
                    "metric name {:?} must start with a lower-case letter and use only \
                     lower-case letters, digits and '_' (at most 48 characters)",
                    c.name
                );
            }
            if !names.insert(c.name.clone()) {
                bail!("{}: the name is used by another metric", ctx());
            }
            if c.labels.len() > MAX_LABELS {
                bail!("{}: at most {MAX_LABELS} labels", ctx());
            }
            let mut labels = Vec::new();
            for l in &c.labels {
                let kind = match l.as_str() {
                    "host" => Label::Host,
                    "app" => Label::App,
                    "level" => Label::Level,
                    "tag" => Label::Tag,
                    other if crate::store::valid_field_key(other) => Label::Field(other.into()),
                    other => bail!("{}: invalid label {other:?}", ctx()),
                };
                if labels.iter().any(|(name, _)| name == l) {
                    bail!("{}: label {l:?} is listed twice", ctx());
                }
                // Prometheus label names cannot contain `.` or `-`.
                labels.push((l.replace(['.', '-'], "_"), kind));
            }
            for (i, (a, _)) in labels.iter().enumerate() {
                if a == "le" || a == "quantile" || labels[..i].iter().any(|(b, _)| b == a) {
                    bail!(
                        "{}: label name {a:?} is reserved or collides after cleaning",
                        ctx()
                    );
                }
            }
            if let Some(f) = &c.value_field
                && !crate::store::valid_field_key(f)
            {
                bail!("{}: invalid value_field {f:?}", ctx());
            }
            let max_series = c.max_series.unwrap_or(DEFAULT_MAX_SERIES);
            if max_series == 0 || max_series > MAX_SERIES_LIMIT {
                bail!(
                    "{}: max_series must be between 1 and {MAX_SERIES_LIMIT}",
                    ctx()
                );
            }
            let pattern = match &c.pattern {
                Some(p) => Some(
                    crate::filters::compile_regex(p)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("{}: pattern {p:?}", ctx()))?,
                ),
                None => None,
            };
            rules.push(Rule {
                name: c.name.clone(),
                help: help_text(c.help.as_deref(), &c.name),
                host: c.host.clone(),
                app: c.app.clone(),
                severities: severity_set(&c.severity).with_context(ctx)?,
                pattern,
                labels,
                value_field: c.value_field.clone(),
                max_series,
                series: Mutex::new(HashMap::new()),
            });
        }
        Ok(Self {
            rules,
            tags: tags.clone(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Counts `entry` in every rule it matches.
    pub fn observe(&self, entry: &LogEntry) {
        for rule in &self.rules {
            rule.observe(entry, &self.tags);
        }
    }

    /// Prometheus text for every rule, series sorted for stable output.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for rule in &self.rules {
            rule.render(&mut out);
        }
        out
    }
}

/// Help text on one line, safe to put in the exposition format.
fn help_text(help: Option<&str>, name: &str) -> String {
    let text = help.map_or_else(
        || format!("Entries matching the {name} rule"),
        str::to_string,
    );
    text.replace('\\', "\\\\").replace('\n', " ")
}

fn escape_label(v: &str) -> String {
    let clipped: String = v.chars().take(MAX_LABEL_VALUE_CHARS).collect();
    clipped
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl Rule {
    fn matches(&self, e: &LogEntry) -> bool {
        self.host.as_ref().is_none_or(|h| *h == e.host)
            && self.app.as_ref().is_none_or(|a| *a == e.app)
            && self
                .severities
                .is_none_or(|s| s[usize::from(e.severity.min(7))])
            && self.pattern.as_ref().is_none_or(|p| p.is_match(&e.message))
    }

    fn observe(&self, e: &LogEntry, tags: &crate::tags::Tags) {
        if !self.matches(e) {
            return;
        }
        let key: Vec<String> = self
            .labels
            .iter()
            .map(|(_, kind)| match kind {
                Label::Host => e.host.clone(),
                Label::App => e.app.clone(),
                Label::Level => level_label(e.severity).to_string(),
                Label::Tag => tags
                    .of_host(&e.host)
                    .first()
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
                Label::Field(k) => e.fields.get(k).cloned().unwrap_or_default(),
            })
            .collect();
        let value = self
            .value_field
            .as_ref()
            .and_then(|f| e.fields.get(f))
            .and_then(|v| crate::filters::parse_number(v));
        let mut series = self.series.lock().unwrap_or_else(|p| p.into_inner());
        let key = if !series.contains_key(&key) && series.len() >= self.max_series {
            vec![OVERFLOW.to_string(); self.labels.len()]
        } else {
            key
        };
        let s = series.entry(key).or_default();
        s.count += 1;
        if let Some(v) = value {
            s.sum += v;
        }
    }

    fn render(&self, out: &mut String) {
        let series = self.series.lock().unwrap_or_else(|p| p.into_inner());
        let mut rows: Vec<(&Vec<String>, &Series)> = series.iter().collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        let selector = |values: &[String]| -> String {
            if self.labels.is_empty() {
                return String::new();
            }
            let pairs: Vec<String> = self
                .labels
                .iter()
                .zip(values)
                .map(|((name, _), v)| format!("{name}=\"{}\"", escape_label(v)))
                .collect();
            format!("{{{}}}", pairs.join(","))
        };
        let metric = format!("logpit_log_{}_total", self.name);
        let _ = writeln!(
            out,
            "# HELP {metric} {}\n# TYPE {metric} counter",
            self.help
        );
        if rows.is_empty() && self.labels.is_empty() {
            let _ = writeln!(out, "{metric} 0");
        }
        for (values, s) in &rows {
            let _ = writeln!(out, "{metric}{} {}", selector(values), s.count);
        }
        if self.value_field.is_some() {
            let sum = format!("logpit_log_{}_value_sum", self.name);
            let _ = writeln!(
                out,
                "# HELP {sum} Sum of the numeric field of the entries counted by {}\n# TYPE {sum} counter",
                self.name
            );
            if rows.is_empty() && self.labels.is_empty() {
                let _ = writeln!(out, "{sum} 0");
            }
            for (values, s) in &rows {
                let _ = writeln!(out, "{sum}{} {}", selector(values), s.sum);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(toml_text: &str) -> anyhow::Result<LogMetrics> {
        #[derive(Deserialize)]
        struct Wrapper {
            metrics: Vec<MetricConfig>,
        }
        LogMetrics::from_config(
            &toml::from_str::<Wrapper>(toml_text).unwrap().metrics,
            &crate::tags::Tags::default(),
        )
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
    fn counts_matching_entries_per_label_combination() {
        let m = rules(
            "[[metrics]]\nname = \"ssh_failures\"\npattern = \"Failed password\"\n\
             labels = [\"host\", \"level\"]\nhelp = \"SSH login failures\"",
        )
        .unwrap();
        for (h, s, msg) in [
            ("web1", 4, "Failed password for root"),
            ("web1", 4, "Failed password for bob"),
            ("web2", 3, "Failed password for root"),
            ("web1", 4, "Accepted password"),
        ] {
            m.observe(&entry(h, "sshd", s, msg));
        }
        let text = m.render();
        assert!(text.contains("# HELP logpit_log_ssh_failures_total SSH login failures"));
        assert!(text.contains("# TYPE logpit_log_ssh_failures_total counter"));
        assert!(text.contains("logpit_log_ssh_failures_total{host=\"web1\",level=\"warning\"} 2"));
        assert!(text.contains("logpit_log_ssh_failures_total{host=\"web2\",level=\"error\"} 1"));
        assert!(!text.contains("Accepted"));
    }

    #[test]
    fn the_tag_label_is_the_first_tag_of_the_host() {
        let tags = crate::tags::Tags::from_config(&[
            crate::tags::TagConfig {
                name: "prod".into(),
                hosts: vec!["web*".into()],
            },
            crate::tags::TagConfig {
                name: "web".into(),
                hosts: vec!["web*".into(), "proxy1".into()],
            },
        ])
        .unwrap();
        let configs: Vec<MetricConfig> = vec![MetricConfig {
            name: "by_tag".into(),
            labels: vec!["tag".into(), "host".into()],
            ..serde_json::from_str(r#"{"name":"x"}"#).unwrap()
        }];
        let m = LogMetrics::from_config(&configs, &tags).unwrap();
        for h in ["web1", "proxy1", "nas"] {
            m.observe(&entry(h, "a", 6, "x"));
        }
        let text = m.render();
        assert!(
            text.contains("logpit_log_by_tag_total{tag=\"prod\",host=\"web1\"} 1"),
            "{text}"
        );
        assert!(text.contains("logpit_log_by_tag_total{tag=\"web\",host=\"proxy1\"} 1"));
        assert!(text.contains("logpit_log_by_tag_total{tag=\"\",host=\"nas\"} 1"));
    }

    #[test]
    fn conditions_and_unlabelled_counters() {
        let m = rules(
            "[[metrics]]\nname = \"web_errors\"\napp = \"nginx\"\nseverity = [\"err\", \"crit\"]\n",
        )
        .unwrap();
        assert!(m.render().contains("logpit_log_web_errors_total 0\n"));
        m.observe(&entry("a", "nginx", 3, "x"));
        m.observe(&entry("b", "nginx", 2, "x"));
        m.observe(&entry("a", "nginx", 6, "x"));
        m.observe(&entry("a", "apache", 3, "x"));
        assert!(m.render().contains("logpit_log_web_errors_total 2\n"));
    }

    #[test]
    fn field_labels_and_sums() {
        let m = rules(
            "[[metrics]]\nname = \"requests\"\nlabels = [\"http.status\", \"app\"]\nvalue_field = \"bytes\"",
        )
        .unwrap();
        let mut e = entry("h", "api", 6, "GET /");
        e.fields.insert("http.status".into(), "200".into());
        e.fields.insert("bytes".into(), "1500".into());
        m.observe(&e);
        e.fields.insert("bytes".into(), "500.5".into());
        m.observe(&e);
        // A non-numeric value counts the entry but adds nothing; a missing field is an empty label.
        e.fields.insert("bytes".into(), "n/a".into());
        e.fields.remove("http.status");
        m.observe(&e);
        let text = m.render();
        assert!(
            text.contains("logpit_log_requests_total{http_status=\"200\",app=\"api\"} 2"),
            "{text}"
        );
        assert!(text.contains("logpit_log_requests_total{http_status=\"\",app=\"api\"} 1"));
        assert!(
            text.contains("logpit_log_requests_value_sum{http_status=\"200\",app=\"api\"} 2000.5")
        );
        assert!(text.contains("# TYPE logpit_log_requests_value_sum counter"));
    }

    #[test]
    fn series_beyond_the_cap_fold_into_other() {
        let m =
            rules("[[metrics]]\nname = \"by_host\"\nlabels = [\"host\"]\nmax_series = 2").unwrap();
        for h in ["a", "b", "c", "d", "a"] {
            m.observe(&entry(h, "x", 6, "m"));
        }
        let text = m.render();
        assert!(text.contains("logpit_log_by_host_total{host=\"a\"} 2"));
        assert!(text.contains("logpit_log_by_host_total{host=\"b\"} 1"));
        assert!(text.contains("logpit_log_by_host_total{host=\"_other\"} 2"));
        assert!(!text.contains("host=\"c\"") && !text.contains("host=\"d\""));
    }

    #[test]
    fn label_values_are_escaped_and_clipped() {
        let m = rules("[[metrics]]\nname = \"m\"\nlabels = [\"app\"]").unwrap();
        m.observe(&entry("h", "we\"ird\\app\nx", 6, "x"));
        m.observe(&entry("h", &"z".repeat(500), 6, "x"));
        let text = m.render();
        assert!(text.contains(r#"app="we\"ird\\app\nx""#), "{text}");
        assert!(text.contains(&format!("app=\"{}\"", "z".repeat(MAX_LABEL_VALUE_CHARS))));
    }

    #[test]
    fn invalid_rules_are_rejected() {
        for bad in [
            "name = \"Bad-Name\"",
            "name = \"\"",
            "name = \"1abc\"",
            "name = \"ok\"\nlabels = [\"a b\"]",
            "name = \"ok\"\nlabels = [\"host\", \"host\"]",
            "name = \"ok\"\nlabels = [\"a.b\", \"a-b\"]",
            "name = \"ok\"\nlabels = [\"le\"]",
            "name = \"ok\"\nlabels = [\"a\",\"b\",\"c\",\"d\",\"e\",\"f\"]",
            "name = \"ok\"\nvalue_field = \"a b\"",
            "name = \"ok\"\nmax_series = 0",
            "name = \"ok\"\nmax_series = 100000",
            "name = \"ok\"\npattern = \"(\"",
            "name = \"ok\"\nseverity = [\"loud\"]",
        ] {
            assert!(rules(&format!("[[metrics]]\n{bad}")).is_err(), "{bad}");
        }
        assert!(rules("[[metrics]]\nname = \"a\"\n[[metrics]]\nname = \"a\"").is_err());
        assert!(LogMetrics::default().is_empty());
    }
}
