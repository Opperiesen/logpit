//! Filters on structured fields and on the message beyond exact matches: `f=` expressions with
//! comparisons (`status>=500`, `act!=block`, `host~^web`) and regular expressions (`re=`).

use std::collections::BTreeMap;

use regex::{Regex, RegexBuilder};

/// Longest regular expression accepted.
pub const MAX_REGEX_BYTES: usize = 500;
/// Compiled size cap of a regular expression (bytes), which bounds memory and compile time.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Compiles a user-supplied regular expression. The engine runs in linear time, so a hostile
/// pattern cannot stall a search, but its size is still bounded.
pub fn compile_regex(pattern: &str) -> Result<Regex, String> {
    compile_regex_up_to(pattern, MAX_REGEX_BYTES)
}

/// Like [`compile_regex`] with another length limit, for the places that take bigger patterns.
pub fn compile_regex_up_to(pattern: &str, max_bytes: usize) -> Result<Regex, String> {
    if pattern.len() > max_bytes {
        return Err(format!("regular expression longer than {max_bytes} bytes"));
    }
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("invalid regular expression: {}", first_line(&e.to_string())))
}

fn first_line(s: &str) -> &str {
    let line = s.lines().last().unwrap_or(s).trim();
    line.strip_prefix("error: ").unwrap_or(line)
}

/// A number as typed in a log field or a filter: plain decimal or exponent notation, finite.
pub fn parse_number(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok().filter(|n| n.is_finite())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    /// The value matches a regular expression.
    Re,
}

/// One comparison on a structured field. Exact matches (`key:value`) are not here: they are
/// handled by the plain `fields` filter of a query. An entry without the field never matches.
#[derive(Debug, Clone)]
pub struct FieldFilter {
    pub key: String,
    pub op: Op,
    /// The right-hand side as typed.
    pub value: String,
    /// `value` as a number, for the ordering operators.
    pub number: Option<f64>,
    pub regex: Option<Regex>,
}

/// What an `f=` expression asks for.
#[derive(Debug, Clone)]
pub enum Expr {
    /// `key:value` (or `key=value`): exact match.
    Equals(String, String),
    Compare(FieldFilter),
}

const FORMS: &str = "f must be key:value, key!=value, key>=number (also >, <, <=) or key~regex";

/// Parses an `f=` expression. The key uses the charset of field names, which excludes every
/// operator character, so the first character outside it starts the operator.
pub fn parse_expr(text: &str) -> Result<Expr, String> {
    let split = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
        .ok_or(FORMS)?;
    let (key, rest) = text.split_at(split);
    if !crate::store::valid_field_key(key) {
        return Err(format!("invalid field name {key:?}"));
    }
    let (op, value) = if let Some(v) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) {
        return Ok(Expr::Equals(key.to_string(), v.to_string()));
    } else if let Some(v) = rest.strip_prefix("!=") {
        (Op::Ne, v)
    } else if let Some(v) = rest.strip_prefix(">=") {
        (Op::Ge, v)
    } else if let Some(v) = rest.strip_prefix("<=") {
        (Op::Le, v)
    } else if let Some(v) = rest.strip_prefix('>') {
        (Op::Gt, v)
    } else if let Some(v) = rest.strip_prefix('<') {
        (Op::Lt, v)
    } else if let Some(v) = rest.strip_prefix('~') {
        (Op::Re, v)
    } else {
        return Err(FORMS.into());
    };
    let (number, regex) = match op {
        Op::Gt | Op::Ge | Op::Lt | Op::Le => (
            Some(parse_number(value).ok_or_else(|| format!("{value:?} is not a number"))?),
            None,
        ),
        Op::Re => (None, Some(compile_regex(value)?)),
        Op::Ne => (None, None),
    };
    Ok(Expr::Compare(FieldFilter {
        key: key.to_string(),
        op,
        value: value.to_string(),
        number,
        regex,
    }))
}

impl FieldFilter {
    /// Whether an entry's fields satisfy the comparison.
    pub fn matches(&self, fields: &BTreeMap<String, String>) -> bool {
        let Some(actual) = fields.get(&self.key) else {
            return false;
        };
        match self.op {
            Op::Ne => *actual != self.value,
            Op::Re => self.regex.as_ref().is_some_and(|r| r.is_match(actual)),
            op => match (parse_number(actual), self.number) {
                (Some(a), Some(b)) => match op {
                    Op::Gt => a > b,
                    Op::Ge => a >= b,
                    Op::Lt => a < b,
                    _ => a <= b,
                },
                _ => false,
            },
        }
    }
}

/// How a message line filter compares: LogQL's `|=`, `!=`, `|~` and `!~`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineOp {
    Contains,
    NotContains,
    Re,
    NotRe,
}

/// A condition on the message text: a substring (case-sensitive) or an unanchored regex.
#[derive(Debug, Clone)]
pub struct LineFilter {
    pub op: LineOp,
    /// The text, or the regular expression source.
    pub value: String,
    pub regex: Option<Regex>,
}

impl LineFilter {
    pub fn new(op: LineOp, value: &str) -> Result<Self, String> {
        let regex = match op {
            LineOp::Re | LineOp::NotRe => Some(compile_regex(value)?),
            _ => None,
        };
        Ok(Self {
            op,
            value: value.to_string(),
            regex,
        })
    }

    pub fn matches(&self, message: &str) -> bool {
        match (self.op, &self.regex) {
            (LineOp::Contains, _) => message.contains(&self.value),
            (LineOp::NotContains, _) => !message.contains(&self.value),
            (LineOp::Re, Some(re)) => re.is_match(message),
            (LineOp::NotRe, Some(re)) => !re.is_match(message),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    Host,
    App,
}

/// A condition on the host or app column that the plain `host=`/`app=` filters cannot express.
#[derive(Debug, Clone)]
pub enum ColumnMatch {
    Eq(String),
    Ne(String),
    /// Matches the whole value (the regex is anchored by whoever built it).
    Re(Regex),
    NotRe(Regex),
}

#[derive(Debug, Clone)]
pub struct ColumnFilter {
    pub column: Column,
    pub matcher: ColumnMatch,
}

impl ColumnFilter {
    pub fn matches(&self, host: &str, app: &str) -> bool {
        let v = match self.column {
            Column::Host => host,
            Column::App => app,
        };
        match &self.matcher {
            ColumnMatch::Eq(x) => v == x,
            ColumnMatch::Ne(x) => v != x,
            ColumnMatch::Re(re) => re.is_match(v),
            ColumnMatch::NotRe(re) => !re.is_match(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(text: &str) -> FieldFilter {
        match parse_expr(text).unwrap() {
            Expr::Compare(f) => f,
            Expr::Equals(..) => panic!("{text} is an equality"),
        }
    }

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn equality_forms_keep_everything_after_the_operator() {
        for (text, key, value) in [
            ("act:block", "act", "block"),
            ("act=block", "act", "block"),
            ("url:http://x/?a=b", "url", "http://x/?a=b"),
            ("empty:", "empty", ""),
            ("a.b-c_d:1", "a.b-c_d", "1"),
        ] {
            match parse_expr(text).unwrap() {
                Expr::Equals(k, v) => assert_eq!((k.as_str(), v.as_str()), (key, value), "{text}"),
                Expr::Compare(_) => panic!("{text}"),
            }
        }
    }

    #[test]
    fn comparison_forms_parse() {
        assert_eq!(cmp("status>=500").op, Op::Ge);
        assert_eq!(cmp("status>=500").number, Some(500.0));
        assert_eq!(cmp("d<2.5").op, Op::Lt);
        assert_eq!(cmp("d<=-1e3").number, Some(-1000.0));
        assert_eq!(cmp("d>0").op, Op::Gt);
        assert_eq!(cmp("act!=block").op, Op::Ne);
        assert_eq!(cmp("act!=block").value, "block");
        let re = cmp("src~^10\\.0\\.");
        assert_eq!(re.op, Op::Re);
        assert!(re.regex.unwrap().is_match("10.0.0.7"));
    }

    #[test]
    fn bad_expressions_are_refused() {
        for text in [
            "",
            "novalue",
            "status>=abc",
            "status>=",
            "d<nan",
            "d>inf",
            "~x",
            ":x",
            "a b:c",
            "a!b",
            "k~(",
        ] {
            assert!(parse_expr(text).is_err(), "{text:?} should be refused");
        }
        let long = format!("k~{}", "a".repeat(MAX_REGEX_BYTES + 1));
        assert!(parse_expr(&long).is_err());
        assert!(
            parse_expr("k~(")
                .unwrap_err()
                .starts_with("invalid regular expression: unclosed")
        );
        // A pattern that compiles to an automaton beyond the cap is refused, not run.
        assert!(compile_regex("(a{1000}){1000}").is_err());
    }

    #[test]
    fn comparisons_need_the_field_and_a_number_where_ordering() {
        let f = fields(&[("status", "503"), ("name", "web"), ("d", "2.5s")]);
        assert!(cmp("status>=500").matches(&f));
        assert!(cmp("status>500").matches(&f));
        assert!(!cmp("status<500").matches(&f));
        assert!(cmp("status<=503").matches(&f));
        assert!(!cmp("status>503").matches(&f));
        // A value that is not a number matches no ordering, whichever way.
        assert!(!cmp("d>1").matches(&f));
        assert!(!cmp("d<=1").matches(&f));
        assert!(!cmp("name>=0").matches(&f));
        // A missing field matches nothing, `!=` included.
        assert!(!cmp("absent!=x").matches(&f));
        assert!(!cmp("absent>0").matches(&f));
        assert!(cmp("name!=db").matches(&f));
        assert!(!cmp("name!=web").matches(&f));
        assert!(cmp("name~^we").matches(&f));
        assert!(!cmp("name~^db").matches(&f));
    }

    #[test]
    fn line_and_column_filters() {
        let f = |op, v: &str| LineFilter::new(op, v).unwrap();
        assert!(f(LineOp::Contains, "Error").matches("an Error here"));
        assert!(
            !f(LineOp::Contains, "error").matches("an Error here"),
            "case-sensitive"
        );
        assert!(f(LineOp::NotContains, "debug").matches("fine"));
        assert!(f(LineOp::Re, "t(im|o)e").matches("a timeout"));
        assert!(!f(LineOp::NotRe, "t(im|o)e").matches("a timeout"));
        assert!(f(LineOp::NotRe, "xyz").matches("a timeout"));
        assert!(LineFilter::new(LineOp::Re, "(").is_err());
        assert!(
            LineFilter::new(LineOp::Contains, "(").is_ok(),
            "text, not a pattern"
        );
        let col = |column, matcher| ColumnFilter { column, matcher };
        let re = |s: &str| compile_regex(s).unwrap();
        assert!(col(Column::Host, ColumnMatch::Eq("a".into())).matches("a", "x"));
        assert!(col(Column::App, ColumnMatch::Ne("x".into())).matches("a", "y"));
        assert!(col(Column::App, ColumnMatch::Re(re("^(web|db)$"))).matches("h", "db"));
        assert!(!col(Column::App, ColumnMatch::Re(re("^(web|db)$"))).matches("h", "dbx"));
        assert!(col(Column::Host, ColumnMatch::NotRe(re("^a$"))).matches("b", ""));
    }
}
