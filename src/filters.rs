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
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(format!(
            "regular expression longer than {MAX_REGEX_BYTES} bytes"
        ));
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
}
