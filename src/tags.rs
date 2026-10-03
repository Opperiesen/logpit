//! Host tags: `[[tags]]` give names (`prod`, `dmz`, `web`) to sets of hosts, written as exact
//! names or patterns with `*` and `?`. A tag is resolved when a query runs, against the current
//! configuration, so changing it applies to the entries already stored.

use anyhow::bail;
use serde::{Deserialize, Serialize};

const MAX_TAGS: usize = 100;
const MAX_PATTERNS: usize = 200;
const MAX_PATTERN_BYTES: usize = 255;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TagConfig {
    /// Letters, digits, `_`, `-` and `.`.
    pub name: String,
    /// Host names, exact or with `*` (any run of characters) and `?` (one character).
    pub hosts: Vec<String>,
}

/// Whether `text` matches `pattern`, where `*` stands for any run of characters (possibly empty)
/// and `?` for exactly one. Everything else is literal and case matters.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    // The position after the last `*` and the text position it is currently stretched to.
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) && p[pi] != '*' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi + 1);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            mark += 1;
            ti = mark;
            pi = s;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whether the pattern has wildcards, as opposed to being a plain host name.
pub fn is_wildcard(pattern: &str) -> bool {
    pattern.contains(['*', '?'])
}

/// Checks a list of host patterns (shared by tags and token restrictions).
pub fn validate_patterns(what: &str, patterns: &[String]) -> anyhow::Result<()> {
    if patterns.len() > MAX_PATTERNS {
        bail!("{what}: at most {MAX_PATTERNS} hosts or patterns");
    }
    for p in patterns {
        if p.is_empty() || p.len() > MAX_PATTERN_BYTES || p.chars().any(char::is_control) {
            bail!("{what}: {p:?} is not a valid host or pattern");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tags {
    tags: Vec<TagConfig>,
}

impl Tags {
    pub fn from_config(configs: &[TagConfig]) -> anyhow::Result<Self> {
        if configs.len() > MAX_TAGS {
            bail!("at most {MAX_TAGS} tags");
        }
        let mut seen = std::collections::HashSet::new();
        for c in configs {
            if c.name.is_empty()
                || c.name.len() > 64
                || !c
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                bail!(
                    "tag name {:?} must be 1 to 64 letters, digits, '_', '-' or '.'",
                    c.name
                );
            }
            if !seen.insert(c.name.as_str()) {
                bail!("tag {:?} is defined twice", c.name);
            }
            if c.hosts.is_empty() {
                bail!("tag {:?} needs at least one host or pattern", c.name);
            }
            validate_patterns(&format!("tag {:?}", c.name), &c.hosts)?;
        }
        Ok(Self {
            tags: configs.to_vec(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    pub fn all(&self) -> &[TagConfig] {
        &self.tags
    }

    pub fn contains(&self, name: &str) -> bool {
        self.tags.iter().any(|t| t.name == name)
    }

    /// The host patterns of the named tags together; an unknown name is an error that lists the
    /// known ones.
    pub fn patterns(&self, names: &[String]) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        for name in names {
            let Some(tag) = self.tags.iter().find(|t| t.name == *name) else {
                let known: Vec<&str> = self.tags.iter().map(|t| t.name.as_str()).collect();
                return Err(if known.is_empty() {
                    format!("unknown tag {name:?}: no tags are configured")
                } else {
                    format!("unknown tag {name:?} (known: {})", known.join(", "))
                });
            };
            for h in &tag.hosts {
                if !out.contains(h) {
                    out.push(h.clone());
                }
            }
        }
        Ok(out)
    }

    /// The tags a host belongs to, in configuration order.
    pub fn of_host(&self, host: &str) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|t| t.hosts.iter().any(|p| glob_match(p, host)))
            .map(|t| t.name.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(toml_text: &str) -> anyhow::Result<Tags> {
        #[derive(Deserialize)]
        struct W {
            tags: Vec<TagConfig>,
        }
        Tags::from_config(&toml::from_str::<W>(toml_text).unwrap().tags)
    }

    #[test]
    fn globs_match_like_shell_wildcards() {
        for (p, t, ok) in [
            ("web1", "web1", true),
            ("web1", "web10", false),
            ("web*", "web", true),
            ("web*", "web12", true),
            ("web*", "xweb", false),
            ("*web", "xxweb", true),
            ("*", "", true),
            ("*", "anything", true),
            ("w?b", "web", true),
            ("w?b", "wb", false),
            ("w?b", "weeb", false),
            ("*.home.arpa", "pve.home.arpa", true),
            ("*.home.arpa", "pve.home.arpa.evil", false),
            ("a*b*c", "aXXbYYc", true),
            ("a*b*c", "aXXbYY", false),
            ("a*b*c", "abc", true),
            ("**", "x", true),
            ("a**b", "ab", true),
            ("", "", true),
            ("", "x", false),
            ("é*", "éa", true),
            ("?", "é", true),
            ("[a]", "[a]", true),
            ("[a]", "a", false),
            ("WEB*", "web1", false),
            ("*a", "baba", true),
            ("*ab", "aab", true),
            ("a*a*a", "aaa", true),
        ] {
            assert_eq!(glob_match(p, t), ok, "{p:?} vs {t:?}");
        }
        // Many stars over a long text stay fast (no exponential backtracking).
        let text = "a".repeat(5000);
        assert!(!glob_match("*a*a*a*a*a*a*a*a*a*a*b", &text));
        assert!(is_wildcard("web*") && is_wildcard("w?b") && !is_wildcard("web1"));
    }

    #[test]
    fn tags_resolve_to_patterns_and_hosts_know_their_tags() {
        let t = tags(
            "[[tags]]\nname = \"prod\"\nhosts = [\"web*\", \"db1\"]\n\
             [[tags]]\nname = \"web\"\nhosts = [\"web*\", \"proxy1\"]\n\
             [[tags]]\nname = \"dmz\"\nhosts = [\"proxy?\"]",
        )
        .unwrap();
        assert_eq!(t.of_host("web7"), ["prod", "web"]);
        assert_eq!(t.of_host("db1"), ["prod"]);
        assert_eq!(t.of_host("proxy1"), ["web", "dmz"]);
        assert!(t.of_host("nas").is_empty());
        assert_eq!(
            t.patterns(&["prod".into(), "web".into()]).unwrap(),
            ["web*", "db1", "proxy1"],
            "duplicates are dropped, order kept"
        );
        assert!(t.patterns(&[]).unwrap().is_empty());
        let err = t.patterns(&["nope".into()]).unwrap_err();
        assert!(err.contains("known: prod, web, dmz"), "{err}");
        assert!(
            Tags::default()
                .patterns(&["x".into()])
                .unwrap_err()
                .contains("no tags")
        );
        assert!(t.contains("dmz") && !t.contains("x"));
    }

    #[test]
    fn invalid_tags_are_refused() {
        for bad in [
            "name = \"\"\nhosts = [\"a\"]",
            "name = \"has space\"\nhosts = [\"a\"]",
            "name = \"ok\"\nhosts = []",
            "name = \"ok\"\nhosts = [\"\"]",
            "name = \"ok\"\nhosts = [\"a\\nb\"]",
        ] {
            assert!(tags(&format!("[[tags]]\n{bad}")).is_err(), "{bad}");
        }
        assert!(
            tags(
                "[[tags]]\nname = \"a\"\nhosts = [\"x\"]\n[[tags]]\nname = \"a\"\nhosts = [\"y\"]"
            )
            .is_err()
        );
        let long = format!("[[tags]]\nname = \"a\"\nhosts = [\"{}\"]", "x".repeat(300));
        assert!(tags(&long).is_err());
        let many: String = (0..201).map(|i| format!("\"h{i}\",")).collect();
        assert!(tags(&format!("[[tags]]\nname = \"a\"\nhosts = [{many}]")).is_err());
        assert!(toml::from_str::<TagConfig>("name = \"a\"\nhosts = [\"b\"]\nbogus = 1").is_err());
        assert!(Tags::default().is_empty());
    }
}
