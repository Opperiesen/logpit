//! The search-text language of `q`: words, `"phrases"`, `prefix*`, `OR`, and `-exclusions`.
//!
//! The text is parsed here and compiled to an FTS5 expression made only of quoted strings,
//! so user input can never be interpreted as FTS5 syntax (column filters, `NEAR`, grouping…).

/// A word, or a phrase when it contains spaces. `prefix` matches words starting with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    pub text: String,
    pub prefix: bool,
}

/// `any_of` is an OR of AND-groups (`a b OR c` is `(a AND b) OR c`); `none_of` terms exclude
/// an entry if any of them matches, whatever the OR group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    pub any_of: Vec<Vec<Term>>,
    pub none_of: Vec<Term>,
}

/// Parses `input`. Operators are upper case (`OR`, `NOT`, `AND`): lower case words are plain
/// words. `-x` and `NOT x` exclude, `AND` is accepted and does nothing (it is the default),
/// and an unterminated quote runs to the end of the input.
pub fn parse(input: &str) -> Parsed {
    let mut out = Parsed::default();
    let mut group: Vec<Term> = Vec::new();
    let mut negate = false;
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut excluded = std::mem::take(&mut negate);
        if c == '-' {
            chars.next();
            // A lone `-` (followed by space or nothing) is not an operator.
            if chars.peek().is_none_or(|n| n.is_whitespace()) {
                continue;
            }
            excluded = true;
        }

        let (text, quoted) = if chars.peek() == Some(&'"') {
            chars.next();
            let mut s = String::new();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                s.push(ch);
            }
            (s, true)
        } else {
            let mut s = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    break;
                }
                s.push(ch);
                chars.next();
            }
            (s, false)
        };

        // Operators are bare upper-case words, never quoted or negated ones.
        if !quoted && !excluded {
            match text.as_str() {
                "OR" => {
                    if !group.is_empty() {
                        out.any_of.push(std::mem::take(&mut group));
                    }
                    continue;
                }
                "NOT" => {
                    negate = true;
                    continue;
                }
                "AND" => continue,
                _ => {}
            }
        }

        // A trailing `*` (right after a word or a closing quote) makes it a prefix.
        let mut prefix = false;
        let mut text = text;
        if !quoted {
            while text.ends_with('*') {
                text.pop();
                prefix = true;
            }
        } else if chars.peek() == Some(&'*') {
            while chars.peek() == Some(&'*') {
                chars.next();
            }
            prefix = true;
        }
        let text = text.trim().to_string();
        if text.is_empty() {
            continue;
        }
        let term = Term { text, prefix };
        if excluded {
            out.none_of.push(term);
        } else {
            group.push(term);
        }
    }
    if !group.is_empty() {
        out.any_of.push(group);
    }
    out
}

fn fts_term(t: &Term) -> String {
    let star = if t.prefix { "*" } else { "" };
    format!("\"{}\"{star}", t.text.replace('"', "\"\""))
}

impl Parsed {
    pub fn is_empty(&self) -> bool {
        self.any_of.is_empty() && self.none_of.is_empty()
    }

    /// FTS5 expression for the entries that must match, if there are positive terms.
    pub fn fts_include(&self) -> Option<String> {
        let groups: Vec<String> = self
            .any_of
            .iter()
            .map(|g| g.iter().map(fts_term).collect::<Vec<_>>().join(" "))
            .collect();
        (!groups.is_empty()).then(|| groups.join(" OR "))
    }

    /// FTS5 expression for the entries that must not match, if there are exclusions.
    pub fn fts_exclude(&self) -> Option<String> {
        (!self.none_of.is_empty()).then(|| {
            self.none_of
                .iter()
                .map(fts_term)
                .collect::<Vec<_>>()
                .join(" OR ")
        })
    }

    /// In-memory check against already lower-cased text, for the live tail, which has no
    /// full-text index: terms match as substrings (so slightly more loosely than FTS5).
    pub fn matches(&self, haystack_lower: &str) -> bool {
        let has = |t: &Term| haystack_lower.contains(&t.text.to_lowercase());
        let included = self.any_of.is_empty() || self.any_of.iter().any(|g| g.iter().all(has));
        included && !self.none_of.iter().any(has)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(text: &str, prefix: bool) -> Term {
        Term {
            text: text.into(),
            prefix,
        }
    }

    #[test]
    fn plain_words_are_anded() {
        let p = parse("  disk   error ");
        assert_eq!(p.any_of, vec![vec![t("disk", false), t("error", false)]]);
        assert_eq!(p.fts_include().unwrap(), "\"disk\" \"error\"");
        assert!(p.fts_exclude().is_none());
        assert!(parse("").is_empty() && parse("   ").is_empty());
    }

    #[test]
    fn or_splits_groups_and_extra_operators_are_ignored() {
        let p = parse("disk error OR timeout");
        assert_eq!(
            p.fts_include().unwrap(),
            "\"disk\" \"error\" OR \"timeout\""
        );
        // Leading, trailing and doubled ORs, and AND, do nothing.
        assert_eq!(
            parse("OR a OR OR b OR").fts_include().unwrap(),
            "\"a\" OR \"b\""
        );
        assert_eq!(parse("a AND b").fts_include().unwrap(), "\"a\" \"b\"");
        // Lower-case operators are ordinary words.
        assert_eq!(parse("a or b").fts_include().unwrap(), "\"a\" \"or\" \"b\"");
    }

    #[test]
    fn phrases_and_prefixes() {
        assert_eq!(
            parse("\"disk error\"").fts_include().unwrap(),
            "\"disk error\""
        );
        assert_eq!(parse("fail*").fts_include().unwrap(), "\"fail\"*");
        assert_eq!(
            parse("\"disk err\"*").fts_include().unwrap(),
            "\"disk err\"*"
        );
        assert_eq!(
            parse("a** b").any_of,
            vec![vec![t("a", true), t("b", false)]]
        );
        // An unterminated quote runs to the end; embedded quotes cannot escape the string.
        assert_eq!(
            parse("\"disk error").fts_include().unwrap(),
            "\"disk error\""
        );
        assert_eq!(parse("a\"b").fts_include().unwrap(), "\"a\"\"b\"");
    }

    #[test]
    fn exclusions() {
        let p = parse("disk -debug NOT \"cron job\" -tmp*");
        assert_eq!(p.fts_include().unwrap(), "\"disk\"");
        assert_eq!(
            p.fts_exclude().unwrap(),
            "\"debug\" OR \"cron job\" OR \"tmp\"*"
        );
        // Exclusion alone, a lone dash and a dangling NOT.
        let only = parse("-debug");
        assert!(only.fts_include().is_none() && only.fts_exclude().is_some());
        assert!(parse("- a").any_of == vec![vec![t("a", false)]]);
        assert!(parse("a NOT").none_of.is_empty());
        // Hyphens inside a word are part of it.
        assert_eq!(parse("foo-bar").fts_include().unwrap(), "\"foo-bar\"");
    }

    #[test]
    fn syntax_characters_never_reach_fts() {
        for hostile in [
            "col:val",
            "NEAR(a b)",
            "( )",
            "a\" OR \"b",
            "*",
            "\"\"",
            "-\"\"",
            "^x",
        ] {
            let p = parse(hostile);
            for expr in [p.fts_include(), p.fts_exclude()].into_iter().flatten() {
                // Every term is a quoted string; nothing is left outside quotes except OR/*.
                let mut inside = false;
                let mut outside = String::new();
                let mut chars = expr.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        if inside && chars.peek() == Some(&'"') {
                            chars.next(); // doubled quote inside a string
                        } else {
                            inside = !inside;
                        }
                    } else if !inside {
                        outside.push(c);
                    }
                }
                assert!(!inside, "{hostile:?} -> {expr}");
                assert!(
                    outside.split_whitespace().all(|w| w == "OR" || w == "*"),
                    "{hostile:?} -> {expr} leaves {outside:?}"
                );
            }
        }
    }

    #[test]
    fn in_memory_matching_for_the_live_tail() {
        let hay = "disk error on sda, cron job done";
        assert!(parse("disk error").matches(hay));
        assert!(parse("tape OR error").matches(hay));
        assert!(!parse("tape OR ribbon").matches(hay));
        assert!(parse("\"cron job\"").matches(hay));
        assert!(!parse("\"job cron\"").matches(hay));
        assert!(parse("disk -debug").matches(hay));
        assert!(!parse("disk -cron").matches(hay));
        assert!(parse("-debug").matches(hay));
        assert!(parse("").matches(hay));
        assert!(parse("DISK").matches(hay), "case-insensitive");
    }
}
