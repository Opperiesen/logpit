//! A subset of LogQL, enough for Grafana's Loki data source to query LogPit.
//!
//! Supported: stream selectors (`{host="web1", level=~"error|warn"}`), line filters (`|=`, `!=`,
//! `|~`, `!~`), the `| json` and `| logfmt` stages (LogPit already extracts those fields), label
//! filters (`| status >= 500`, `| env="prod"`), `count_over_time` and `rate` over a range, and
//! `sum` / `sum by (labels)` of those. Anything else is refused with a message saying what.
//!
//! Labels map onto LogPit: `host` and `app` are the columns (with the usual Loki names as
//! aliases), `level` the severity, and every other label a structured field.

use std::collections::BTreeSet;

use regex::Regex;

use crate::filters::{
    Column, ColumnFilter, ColumnMatch, Expr as FieldExpr, LineFilter, LineOp, compile_regex,
    parse_expr,
};
use crate::model::{level_severity, severity_name};
use crate::store::Query;

/// Label names of the host column, and of the app column.
const HOST_LABELS: [&str; 2] = ["host", "hostname"];
const APP_LABELS: [&str; 4] = ["app", "service_name", "service", "job"];
const LEVEL_LABELS: [&str; 4] = ["level", "severity", "detected_level", "log_level"];

/// The `level` label of a severity, in the words Grafana colours.
pub fn level_label(severity: u8) -> &'static str {
    match severity {
        0..=2 => "critical",
        3 => "error",
        4 => "warning",
        5 | 6 => "info",
        _ => "debug",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOp {
    Eq,
    Ne,
    Re,
    NotRe,
    Gt,
    Ge,
    Lt,
    Le,
}

/// `name op value` in a selector or as a label filter after a pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelMatcher {
    pub name: String,
    pub op: MatchOp,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogExpr {
    pub matchers: Vec<LabelMatcher>,
    pub line_filters: Vec<(LineOp, String)>,
    pub label_filters: Vec<LabelMatcher>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeFn {
    CountOverTime,
    Rate,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Log(LogExpr),
    Metric {
        func: RangeFn,
        log: LogExpr,
        range_ms: i64,
        /// `Some(labels)` for `sum by (labels)` (empty for a plain `sum`); `None` keeps one series
        /// per stream.
        sum_by: Option<Vec<String>>,
    },
    /// `vector(1)` expressions, which Grafana sends to test the connection.
    Scalar(f64),
}

// ---- tokens -------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(String),
    /// `[5m]`, kept as the text between the brackets.
    Range(String),
    Op(&'static str),
    Punct(char),
}

fn lex(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            c if c.is_whitespace() => i += 1,
            '{' | '}' | '(' | ')' | ',' | '+' | '-' | '*' | '/' => {
                toks.push(Tok::Punct(c));
                i += 1;
            }
            '[' => {
                let end = chars[i..]
                    .iter()
                    .position(|c| *c == ']')
                    .ok_or("unterminated [")?;
                toks.push(Tok::Range(chars[i + 1..i + end].iter().collect()));
                i += end + 1;
            }
            '"' | '`' => {
                let quote = c;
                let mut s = String::new();
                i += 1;
                loop {
                    let ch = *chars.get(i).ok_or("unterminated string")?;
                    i += 1;
                    if ch == quote {
                        break;
                    }
                    if ch == '\\' && quote == '"' {
                        let esc = *chars.get(i).ok_or("unterminated string")?;
                        i += 1;
                        s.push(match esc {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                    } else {
                        s.push(ch);
                    }
                }
                toks.push(Tok::Str(s));
            }
            '|' if next == Some('=') => {
                toks.push(Tok::Op("|="));
                i += 2;
            }
            '|' if next == Some('~') => {
                toks.push(Tok::Op("|~"));
                i += 2;
            }
            '|' => {
                toks.push(Tok::Op("|"));
                i += 1;
            }
            '!' if next == Some('=') => {
                toks.push(Tok::Op("!="));
                i += 2;
            }
            '!' if next == Some('~') => {
                toks.push(Tok::Op("!~"));
                i += 2;
            }
            '=' if next == Some('~') => {
                toks.push(Tok::Op("=~"));
                i += 2;
            }
            '=' if next == Some('=') => {
                toks.push(Tok::Op("="));
                i += 2;
            }
            '=' => {
                toks.push(Tok::Op("="));
                i += 1;
            }
            '>' | '<' => {
                let (op, len) = match (c, next) {
                    ('>', Some('=')) => (">=", 2),
                    ('<', Some('=')) => ("<=", 2),
                    ('>', _) => (">", 1),
                    _ => ("<", 1),
                };
                toks.push(Tok::Op(op));
                i += len;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == '_')
                {
                    i += 1;
                }
                toks.push(Tok::Num(chars[start..i].iter().collect()));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.')
                {
                    i += 1;
                }
                toks.push(Tok::Ident(chars[start..i].iter().collect()));
            }
            other => return Err(format!("unexpected character {other:?}")),
        }
    }
    Ok(toks)
}

// ---- durations ----------------------------------------------------------------------------

/// `30s`, `5m`, `1h30m`, `500ms`, `2d`, `1w`: a sequence of numbers with units.
pub fn parse_duration_ms(text: &str) -> Option<i64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let mut total = 0f64;
    let mut rest = t;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let (num, tail) = rest.split_at(end);
        let value: f64 = num.parse().ok()?;
        let (unit_ms, len) = if tail.starts_with("ms") {
            (1.0, 2)
        } else if tail.starts_with('s') {
            (1000.0, 1)
        } else if tail.starts_with('m') {
            (60_000.0, 1)
        } else if tail.starts_with('h') {
            (3_600_000.0, 1)
        } else if tail.starts_with('d') {
            (86_400_000.0, 1)
        } else if tail.starts_with('w') {
            (7.0 * 86_400_000.0, 1)
        } else {
            return None;
        };
        total += value * unit_ms;
        rest = &tail[len..];
    }
    (total.is_finite() && total > 0.0 && total < 1e13).then_some(total.round() as i64)
}

// ---- parser -------------------------------------------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

type Res<T> = Result<T, String>;

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn eat_punct(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, c: char) -> Res<()> {
        if self.eat_punct(c) {
            Ok(())
        } else {
            Err(format!("expected {c:?}"))
        }
    }

    fn ident(&mut self) -> Res<String> {
        match self.next() {
            Some(Tok::Ident(s)) => Ok(s),
            _ => Err("expected a name".into()),
        }
    }

    fn selector(&mut self) -> Res<Vec<LabelMatcher>> {
        self.expect_punct('{')?;
        let mut matchers = Vec::new();
        while !self.eat_punct('}') {
            let name = self.ident()?;
            let op = match self.next() {
                Some(Tok::Op("=")) => MatchOp::Eq,
                Some(Tok::Op("!=")) => MatchOp::Ne,
                Some(Tok::Op("=~")) => MatchOp::Re,
                Some(Tok::Op("!~")) => MatchOp::NotRe,
                _ => return Err(format!("expected =, !=, =~ or !~ after label {name}")),
            };
            let Some(Tok::Str(value)) = self.next() else {
                return Err(format!("the value of label {name} must be a quoted string"));
            };
            matchers.push(LabelMatcher { name, op, value });
            if !self.eat_punct(',') && self.peek() != Some(&Tok::Punct('}')) {
                return Err("expected , or } in the selector".into());
            }
        }
        Ok(matchers)
    }

    /// A selector followed by line filters and pipeline stages.
    fn log_expr(&mut self) -> Res<LogExpr> {
        let mut log = LogExpr {
            matchers: self.selector()?,
            ..Default::default()
        };
        loop {
            match self.peek() {
                Some(Tok::Op(op @ ("|=" | "!=" | "|~" | "!~"))) => {
                    let line_op = match *op {
                        "|=" => LineOp::Contains,
                        "!=" => LineOp::NotContains,
                        "|~" => LineOp::Re,
                        _ => LineOp::NotRe,
                    };
                    self.pos += 1;
                    let Some(Tok::Str(text)) = self.next() else {
                        return Err("a line filter takes a quoted string".into());
                    };
                    log.line_filters.push((line_op, text));
                }
                Some(Tok::Op("|")) => {
                    self.pos += 1;
                    self.stage(&mut log)?;
                }
                _ => return Ok(log),
            }
        }
    }

    fn stage(&mut self, log: &mut LogExpr) -> Res<()> {
        let name = self.ident()?;
        match name.as_str() {
            // LogPit has already extracted JSON and logfmt fields at ingestion.
            "json" | "logfmt" if !matches!(self.peek(), Some(Tok::Op("=" | "!="))) => Ok(()),
            _ => {
                let op = match self.next() {
                    Some(Tok::Op("=")) => MatchOp::Eq,
                    Some(Tok::Op("!=")) => MatchOp::Ne,
                    Some(Tok::Op("=~")) => MatchOp::Re,
                    Some(Tok::Op("!~")) => MatchOp::NotRe,
                    Some(Tok::Op(">")) => MatchOp::Gt,
                    Some(Tok::Op(">=")) => MatchOp::Ge,
                    Some(Tok::Op("<")) => MatchOp::Lt,
                    Some(Tok::Op("<=")) => MatchOp::Le,
                    _ => {
                        return Err(format!(
                            "pipeline stage `| {name}` is not supported (json, logfmt and label \
                             filters are)"
                        ));
                    }
                };
                let value = match self.next() {
                    Some(Tok::Str(s)) | Some(Tok::Num(s)) => s,
                    _ => return Err(format!("the value of label filter {name} is missing")),
                };
                log.label_filters.push(LabelMatcher { name, op, value });
                Ok(())
            }
        }
    }

    fn by_clause(&mut self) -> Res<Option<Vec<String>>> {
        match self.peek() {
            Some(Tok::Ident(w)) if w == "by" => {
                self.pos += 1;
                self.expect_punct('(')?;
                let mut labels = Vec::new();
                while !self.eat_punct(')') {
                    labels.push(self.ident()?);
                    if !self.eat_punct(',') && self.peek() != Some(&Tok::Punct(')')) {
                        return Err("expected , or ) in the by clause".into());
                    }
                }
                Ok(Some(labels))
            }
            Some(Tok::Ident(w)) if w == "without" => {
                Err("`without` is not supported, use `by (labels)`".into())
            }
            _ => Ok(None),
        }
    }

    fn range_agg(&mut self) -> Res<(RangeFn, LogExpr, i64)> {
        let name = self.ident()?;
        let func = match name.as_str() {
            "count_over_time" => RangeFn::CountOverTime,
            "rate" => RangeFn::Rate,
            other => {
                return Err(format!(
                    "`{other}` is not supported (count_over_time, rate and sum are)"
                ));
            }
        };
        self.expect_punct('(')?;
        let log = self.log_expr()?;
        let Some(Tok::Range(text)) = self.next() else {
            return Err(format!("{name} needs a range such as [5m]"));
        };
        let range_ms = parse_duration_ms(&text).ok_or_else(|| format!("invalid range [{text}]"))?;
        self.expect_punct(')')?;
        Ok((func, log, range_ms))
    }

    fn scalar(&mut self) -> Res<f64> {
        match self.next() {
            Some(Tok::Ident(w)) if w == "vector" => {
                self.expect_punct('(')?;
                let Some(Tok::Num(n)) = self.next() else {
                    return Err("vector() takes a number".into());
                };
                self.expect_punct(')')?;
                n.parse().map_err(|_| format!("invalid number {n}"))
            }
            _ => Err("unsupported expression".into()),
        }
    }

    fn expr(&mut self) -> Res<Expr> {
        match self.peek() {
            Some(Tok::Punct('{')) => Ok(Expr::Log(self.log_expr()?)),
            Some(Tok::Ident(w)) if w == "vector" => {
                let mut value = self.scalar()?;
                while let Some(Tok::Punct(op @ ('+' | '-' | '*' | '/'))) = self.peek().cloned() {
                    self.pos += 1;
                    let rhs = self.scalar()?;
                    value = match op {
                        '+' => value + rhs,
                        '-' => value - rhs,
                        '*' => value * rhs,
                        _ => value / rhs,
                    };
                }
                Ok(Expr::Scalar(value))
            }
            Some(Tok::Ident(w)) if w == "sum" => {
                self.pos += 1;
                let mut by = self.by_clause()?;
                self.expect_punct('(')?;
                let (func, log, range_ms) = self.range_agg()?;
                self.expect_punct(')')?;
                if by.is_none() {
                    by = self.by_clause()?;
                }
                Ok(Expr::Metric {
                    func,
                    log,
                    range_ms,
                    sum_by: Some(by.unwrap_or_default()),
                })
            }
            Some(Tok::Ident(_)) => {
                let (func, log, range_ms) = self.range_agg()?;
                Ok(Expr::Metric {
                    func,
                    log,
                    range_ms,
                    sum_by: None,
                })
            }
            _ => Err("expected a stream selector like {host=\"web1\"}".into()),
        }
    }
}

/// Parses a LogQL query of the supported subset.
pub fn parse(query: &str) -> Result<Expr, String> {
    let mut p = Parser {
        toks: lex(query)?,
        pos: 0,
    };
    let expr = p.expr()?;
    if p.pos < p.toks.len() {
        return Err("unexpected text after the end of the query".into());
    }
    Ok(expr)
}

// ---- translation to a store query ---------------------------------------------------------

/// What a label name stands for in LogPit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelKind {
    Host,
    App,
    Level,
    Field(String),
}

pub fn label_kind(name: &str) -> Result<LabelKind, String> {
    if HOST_LABELS.contains(&name) {
        Ok(LabelKind::Host)
    } else if APP_LABELS.contains(&name) {
        Ok(LabelKind::App)
    } else if LEVEL_LABELS.contains(&name) {
        Ok(LabelKind::Level)
    } else if crate::store::valid_field_key(name) {
        Ok(LabelKind::Field(name.to_string()))
    } else {
        Err(format!("invalid label name {name:?}"))
    }
}

/// Loki label matchers (`=~`, `!~`) match the whole value.
fn anchored(pattern: &str) -> Result<Regex, String> {
    compile_regex(&format!("^(?:{pattern})$"))
}

/// The severities a `level` matcher keeps.
fn level_set(op: MatchOp, value: &str) -> Result<BTreeSet<u8>, String> {
    let names = |s: u8| [level_label(s), severity_name(s)];
    let wanted: BTreeSet<u8> = match op {
        MatchOp::Eq | MatchOp::Ne => {
            let v = value.trim().to_ascii_lowercase();
            (0..=7u8)
                .filter(|s| names(*s).contains(&v.as_str()) || level_severity(&v) == Some(*s))
                .collect()
        }
        MatchOp::Re | MatchOp::NotRe => {
            let re = anchored(value)?;
            (0..=7u8)
                .filter(|s| names(*s).iter().any(|n| re.is_match(n)))
                .collect()
        }
        _ => return Err("the level label cannot be compared with < or >".into()),
    };
    Ok(if matches!(op, MatchOp::Ne | MatchOp::NotRe) {
        (0..=7u8).filter(|s| !wanted.contains(s)).collect()
    } else {
        wanted
    })
}

fn apply_matcher(m: &LabelMatcher, q: &mut Query) -> Result<(), String> {
    match label_kind(&m.name)? {
        kind @ (LabelKind::Host | LabelKind::App) => {
            let column = if kind == LabelKind::Host {
                Column::Host
            } else {
                Column::App
            };
            let matcher = match m.op {
                MatchOp::Eq => ColumnMatch::Eq(m.value.clone()),
                MatchOp::Ne => ColumnMatch::Ne(m.value.clone()),
                MatchOp::Re => ColumnMatch::Re(anchored(&m.value)?),
                MatchOp::NotRe => ColumnMatch::NotRe(anchored(&m.value)?),
                _ => return Err(format!("label {} cannot be compared with < or >", m.name)),
            };
            q.column_filters.push(ColumnFilter { column, matcher });
        }
        LabelKind::Level => {
            let set = level_set(m.op, &m.value)?;
            q.severities = Some(match q.severities.take() {
                Some(prev) => prev.into_iter().filter(|s| set.contains(s)).collect(),
                None => set.into_iter().collect(),
            });
        }
        LabelKind::Field(key) => {
            let text = match m.op {
                MatchOp::Eq => {
                    q.fields.push((key, m.value.clone()));
                    return Ok(());
                }
                MatchOp::Ne => format!("{key}!={}", m.value),
                MatchOp::Re => format!("{key}~^(?:{})$", m.value),
                MatchOp::Gt => format!("{key}>{}", m.value),
                MatchOp::Ge => format!("{key}>={}", m.value),
                MatchOp::Lt => format!("{key}<{}", m.value),
                MatchOp::Le => format!("{key}<={}", m.value),
                // A field that is absent counts as not matching the pattern.
                MatchOp::NotRe => return Err("`!~` on a field label is not supported".into()),
            };
            match parse_expr(&text)? {
                FieldExpr::Compare(f) => q.compare.push(f),
                FieldExpr::Equals(k, v) => q.fields.push((k, v)),
            }
        }
    }
    Ok(())
}

impl LogExpr {
    /// Adds this expression's conditions to `q`.
    pub fn apply(&self, q: &mut Query) -> Result<(), String> {
        for m in self.matchers.iter().chain(&self.label_filters) {
            apply_matcher(m, q)?;
        }
        for (op, text) in &self.line_filters {
            q.line_filters.push(LineFilter::new(*op, text)?);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(q: &str) -> LogExpr {
        match parse(q).unwrap() {
            Expr::Log(l) => l,
            other => panic!("{q}: {other:?}"),
        }
    }

    fn m(name: &str, op: MatchOp, value: &str) -> LabelMatcher {
        LabelMatcher {
            name: name.into(),
            op,
            value: value.into(),
        }
    }

    #[test]
    fn selectors_filters_and_stages() {
        let l = log(
            r#"{host="web1", app=~"ngi.*", level!="debug"} |= "error" != "healthz" |~ "t(im|o)e" !~ `\d+ ms` | json | status >= 500 | env="prod""#,
        );
        assert_eq!(
            l.matchers,
            [
                m("host", MatchOp::Eq, "web1"),
                m("app", MatchOp::Re, "ngi.*"),
                m("level", MatchOp::Ne, "debug"),
            ]
        );
        assert_eq!(
            l.line_filters,
            [
                (LineOp::Contains, "error".to_string()),
                (LineOp::NotContains, "healthz".to_string()),
                (LineOp::Re, "t(im|o)e".to_string()),
                (LineOp::NotRe, r"\d+ ms".to_string()),
            ]
        );
        assert_eq!(
            l.label_filters,
            [
                m("status", MatchOp::Ge, "500"),
                m("env", MatchOp::Eq, "prod")
            ]
        );
        // Trailing comma, escapes, a bare selector and `logfmt`.
        assert_eq!(log(r#"{a="x",}"#).matchers.len(), 1);
        assert_eq!(
            log(r#"{a="say \"hi\"\n"}"#).matchers[0].value,
            "say \"hi\"\n"
        );
        assert!(log("{}").matchers.is_empty());
        assert!(log(r#"{a="x"} | logfmt"#).label_filters.is_empty());
    }

    #[test]
    fn metric_queries() {
        let e = parse(r#"sum by (level) (count_over_time({host="a"} |= "x" [5m]))"#).unwrap();
        match e {
            Expr::Metric {
                func,
                log,
                range_ms,
                sum_by,
            } => {
                assert_eq!(func, RangeFn::CountOverTime);
                assert_eq!(range_ms, 300_000);
                assert_eq!(sum_by, Some(vec!["level".to_string()]));
                assert_eq!(log.line_filters.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        // `by` after the parentheses, a plain sum, and no sum at all.
        assert!(matches!(
            parse(r#"sum(rate({a="b"}[1m])) by (host, app)"#).unwrap(),
            Expr::Metric { func: RangeFn::Rate, sum_by: Some(l), .. } if l == ["host", "app"]
        ));
        assert!(matches!(
            parse(r#"sum(count_over_time({a="b"}[1h30m]))"#).unwrap(),
            Expr::Metric { sum_by: Some(l), range_ms: 5_400_000, .. } if l.is_empty()
        ));
        assert!(matches!(
            parse(r#"rate({a="b"}[10s])"#).unwrap(),
            Expr::Metric { sum_by: None, .. }
        ));
    }

    #[test]
    fn the_connection_test_expression_is_a_scalar() {
        assert_eq!(parse("vector(1)+vector(1)").unwrap(), Expr::Scalar(2.0));
        assert_eq!(
            parse("vector(3) * vector(2) - vector(1)").unwrap(),
            Expr::Scalar(5.0)
        );
    }

    #[test]
    fn unsupported_or_malformed_queries_say_why() {
        for (q, hint) in [
            ("", "stream selector"),
            ("topk(3, rate({a=\"b\"}[1m]))", "not supported"),
            ("avg_over_time({a=\"b\"}[1m])", "not supported"),
            ("{a=\"b\"} | line_format \"x\"", "line_format"),
            ("{a=\"b\"} | unwrap n", "unwrap"),
            ("{a=\"b\"", "selector"),
            ("{a=b}", "quoted string"),
            ("{a=\"b\"} |= x", "quoted string"),
            ("sum without (a) (rate({a=\"b\"}[1m]))", "without"),
            ("rate({a=\"b\"})", "range"),
            ("rate({a=\"b\"}[0s])", "invalid range"),
            ("{a=\"b\"} extra", "after the end"),
            ("{a=\"b\"} |= \"x", "unterminated"),
            ("{a=\"b\"} @", "unexpected character"),
        ] {
            let err = parse(q).expect_err(q);
            assert!(err.contains(hint), "{q:?}: {err}");
        }
    }

    #[test]
    fn durations() {
        for (text, ms) in [
            ("500ms", 500),
            ("30s", 30_000),
            ("5m", 300_000),
            ("1h30m", 5_400_000),
            ("2d", 172_800_000),
            ("1w", 604_800_000),
            ("1.5s", 1500),
        ] {
            assert_eq!(parse_duration_ms(text), Some(ms), "{text}");
        }
        for bad in ["", "5", "m", "5x", "0s", "-1s", "1h xx"] {
            assert_eq!(parse_duration_ms(bad), None, "{bad}");
        }
    }

    #[test]
    fn level_labels_cover_loki_and_syslog_words() {
        assert_eq!(level_label(3), "error");
        assert_eq!(level_label(4), "warning");
        assert_eq!(level_label(6), "info");
        let set = |op, v: &str| level_set(op, v).unwrap().into_iter().collect::<Vec<_>>();
        assert_eq!(set(MatchOp::Eq, "error"), [3]);
        assert_eq!(set(MatchOp::Eq, "err"), [3]);
        assert_eq!(set(MatchOp::Eq, "warn"), [4]);
        assert_eq!(set(MatchOp::Eq, "warning"), [4]);
        assert_eq!(set(MatchOp::Eq, "info"), [5, 6]);
        assert_eq!(set(MatchOp::Eq, "critical"), [0, 1, 2]);
        assert_eq!(set(MatchOp::Eq, "fatal"), [0]);
        assert_eq!(set(MatchOp::Re, "error|warning"), [3, 4]);
        assert_eq!(set(MatchOp::Ne, "debug"), [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(set(MatchOp::NotRe, "info|debug"), [0, 1, 2, 3, 4]);
        assert!(set(MatchOp::Eq, "bogus").is_empty());
        assert!(level_set(MatchOp::Gt, "3").is_err());
    }

    #[test]
    fn translation_to_a_store_query() {
        let mut q = Query::default();
        log(r#"{hostname="web1", service_name=~"ngi.*", detected_level="error", env="prod", region!="eu"} |= "boom" | status>=500"#)
            .apply(&mut q)
            .unwrap();
        assert_eq!(q.column_filters.len(), 2);
        assert_eq!(q.severities, Some(vec![3]));
        assert_eq!(q.fields, [("env".to_string(), "prod".to_string())]);
        assert_eq!(q.compare.len(), 2);
        assert_eq!(q.line_filters.len(), 1);
        // Regex matchers are anchored: `ngi` alone does not match `nginx`.
        let re = match &q.column_filters[1].matcher {
            ColumnMatch::Re(re) => re.clone(),
            other => panic!("{other:?}"),
        };
        assert!(re.is_match("nginx") && !re.is_match("my-nginx"));
        // Two level matchers intersect.
        let mut q = Query::default();
        log(r#"{level=~"error|warning", level!="warning"}"#)
            .apply(&mut q)
            .unwrap();
        assert_eq!(q.severities, Some(vec![3]));
        // Things that cannot be expressed are refused.
        for bad in [
            r#"{level>"3"}"#,
            r#"{a="b"} | level > 3"#,
            r#"{host="a"} | host >= 1"#,
            r#"{x!~"y"}"#,
            r#"{a="b"} | status >= abc"#,
            r#"{"bad key"="b"}"#,
            r#"{host=~"("}"#,
        ] {
            let attempt = parse(bad).and_then(|e| match e {
                Expr::Log(l) => l.apply(&mut Query::default()),
                _ => Ok(()),
            });
            assert!(attempt.is_err(), "{bad}");
        }
    }
}
