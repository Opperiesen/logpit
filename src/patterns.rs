//! Message patterns for `/api/patterns`: messages that differ only by numbers, ids or addresses
//! are folded into one template (`user <*> logged in from <*>`) and counted, with how the count
//! moved between the first and second half of the window.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

/// Placeholder that replaces a variable token.
pub const WILDCARD: &str = "<*>";
/// Tokens kept from a message; the rest of a very long line does not distinguish patterns.
const MAX_TOKENS: usize = 48;
/// Distinct templates tracked in one response; entries of any further template are only counted.
pub const MAX_PATTERNS: usize = 5000;
/// Distinct hosts remembered per template (the reported host count stops there).
const MAX_HOSTS: usize = 100;
/// Literal words offered as a search for a template.
const SEARCH_WORDS: usize = 6;

/// An entry as read for pattern analysis; the message may be shortened.
pub struct Sample {
    pub id: i64,
    pub ts: i64,
    pub host: String,
    pub severity: u8,
    pub message: String,
}

const OPENING: &[char] = &['(', '[', '{', '"', '\'', '<'];
const CLOSING: &[char] = &[',', ';', ':', '.', ')', ']', '}', '"', '\'', '>', '!', '?'];

/// A token with a digit is a variable (counter, id, address, port, duration…).
fn mask_value(core: &str) -> &str {
    if core.bytes().any(|b| b.is_ascii_digit()) {
        WILDCARD
    } else {
        core
    }
}

fn mask_token(token: &str, out: &mut String) {
    let core_start = token.len() - token.trim_start_matches(OPENING).len();
    let core_end = token.trim_end_matches(CLOSING).len().max(core_start);
    let (lead, core, tail) = (
        &token[..core_start],
        &token[core_start..core_end],
        &token[core_end..],
    );
    out.push_str(lead);
    match core.split_once('=') {
        Some((key, value)) if !key.is_empty() => {
            out.push_str(key);
            out.push('=');
            mask_token(value, out);
        }
        _ => out.push_str(mask_value(core)),
    }
    out.push_str(tail);
}

/// The template of a message: its first line with every token containing a digit (and the value
/// of `key=value` tokens that has one) replaced by [`WILDCARD`]. Words such as user names are
/// kept, so messages that differ in those stay separate patterns.
pub fn template(message: &str) -> String {
    let line = message.lines().next().unwrap_or("");
    let mut out = String::with_capacity(line.len());
    for (i, token) in line.split_whitespace().take(MAX_TOKENS).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        mask_token(token, &mut out);
    }
    out
}

/// Plain words of a template, usable as a free-text search for the entries it covers.
pub fn search_hint(template: &str) -> String {
    template
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| w.len() >= 3 && w.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .take(SEARCH_WORDS)
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Example {
    pub id: i64,
    pub ts: i64,
    pub host: String,
    pub message: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Pattern {
    pub pattern: String,
    /// Words of the pattern to search for (empty when it has none).
    pub search: String,
    pub count: u64,
    /// Entries in the first half of the window.
    pub previous: u64,
    /// Entries in the second half of the window.
    pub recent: u64,
    /// Distinct hosts, counted up to 100.
    pub hosts: usize,
    /// The most severe level seen.
    pub severity: String,
    pub first_ts: i64,
    pub last_ts: i64,
    /// The newest entry of the pattern.
    pub example: Example,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Patterns {
    /// Entries analysed (the newest matches, up to the scan limit).
    pub scanned: u64,
    /// More entries matched than were analysed.
    pub truncated: bool,
    /// Window used for `previous` and `recent`: its first half and its second half.
    pub since: i64,
    pub until: i64,
    /// Distinct patterns found.
    pub distinct: u64,
    /// Entries of patterns not in the list (beyond `limit`, or past the tracking cap).
    pub other: u64,
    pub patterns: Vec<Pattern>,
}

struct Acc {
    count: u64,
    previous: u64,
    hosts: BTreeSet<String>,
    severity: u8,
    first_ts: i64,
    last_ts: i64,
    example: Example,
}

/// Groups `samples` (newest first, as the store returns them) into patterns. The window runs
/// from `since` (default the oldest sample, or when the scan was cut short, the oldest one kept) to
/// `until`; its midpoint separates `previous` from `recent`.
pub fn analyse(
    samples: &[Sample],
    truncated: bool,
    since: Option<i64>,
    until: i64,
    limit: usize,
) -> Patterns {
    let oldest = samples.iter().map(|s| s.ts).min();
    let start = match (since, oldest) {
        (Some(s), Some(o)) if truncated => s.max(o),
        (Some(s), _) => s,
        (None, Some(o)) => o,
        (None, None) => until,
    }
    .min(until);
    let mid = start + (until - start) / 2;

    let mut map: HashMap<String, Acc> = HashMap::new();
    let mut untracked = 0u64;
    for s in samples {
        let key = template(&s.message);
        if !map.contains_key(&key) && map.len() >= MAX_PATTERNS {
            untracked += 1;
            continue;
        }
        let acc = map.entry(key).or_insert_with(|| Acc {
            count: 0,
            previous: 0,
            hosts: BTreeSet::new(),
            severity: s.severity,
            first_ts: s.ts,
            last_ts: s.ts,
            example: Example {
                id: s.id,
                ts: s.ts,
                host: s.host.clone(),
                message: s.message.clone(),
            },
        });
        acc.count += 1;
        if s.ts < mid {
            acc.previous += 1;
        }
        acc.severity = acc.severity.min(s.severity);
        acc.first_ts = acc.first_ts.min(s.ts);
        acc.last_ts = acc.last_ts.max(s.ts);
        if acc.hosts.len() < MAX_HOSTS {
            acc.hosts.insert(s.host.clone());
        }
    }

    let distinct = map.len() as u64 + u64::from(untracked > 0);
    let mut all: Vec<(String, Acc)> = map.into_iter().collect();
    all.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
    let listed: u64 = all.iter().take(limit).map(|(_, a)| a.count).sum();
    let total: u64 = all.iter().map(|(_, a)| a.count).sum::<u64>() + untracked;
    let patterns = all
        .into_iter()
        .take(limit)
        .map(|(pattern, a)| Pattern {
            search: search_hint(&pattern),
            pattern,
            count: a.count,
            previous: a.previous,
            recent: a.count - a.previous,
            hosts: a.hosts.len(),
            severity: crate::model::severity_name(a.severity).to_string(),
            first_ts: a.first_ts,
            last_ts: a.last_ts,
            example: a.example,
        })
        .collect();
    Patterns {
        scanned: samples.len() as u64,
        truncated,
        since: start,
        until,
        distinct,
        other: total - listed,
        patterns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: i64, ts: i64, host: &str, severity: u8, message: &str) -> Sample {
        Sample {
            id,
            ts,
            host: host.into(),
            severity,
            message: message.into(),
        }
    }

    #[test]
    fn numbers_ids_and_addresses_are_masked() {
        assert_eq!(
            template("user 4312 logged in from 10.0.0.7:5514"),
            "user <*> logged in from <*>"
        );
        assert_eq!(
            template("GET /api/v1/items/42 took 12ms (status=200)"),
            "GET <*> took <*> (status=<*>)"
        );
        assert_eq!(template("session 3f2a-91 closed."), "session <*> closed.");
        assert_eq!(template("retry [3/5], giving up"), "retry [<*>], giving up");
    }

    #[test]
    fn words_and_key_names_survive() {
        assert_eq!(template("auth failed for alice"), "auth failed for alice");
        assert_eq!(template("user=alice id=42"), "user=alice id=<*>");
        assert_eq!(template("code=\"E42\" ok"), "code=\"<*>\" ok");
        assert_eq!(template("=7 =x"), "<*> =x");
    }

    #[test]
    fn only_the_first_line_counts_and_spacing_is_normalised() {
        assert_eq!(
            template("panic at 12\n  frame 1\n  frame 2"),
            "panic at <*>"
        );
        assert_eq!(template("  a \t b  "), "a b");
        assert_eq!(template(""), "");
        assert_eq!(template("\n12"), "");
    }

    #[test]
    fn long_lines_are_cut_to_the_token_limit() {
        let msg = vec!["word"; 200].join(" ");
        assert_eq!(template(&msg).split(' ').count(), MAX_TOKENS);
    }

    #[test]
    fn search_hint_keeps_plain_words() {
        assert_eq!(
            search_hint("user <*> logged in from <*>"),
            "user logged from"
        );
        assert_eq!(search_hint("<*> <*>"), "");
        assert_eq!(
            search_hint("a: b, connection_reset by peer"),
            "connection_reset peer"
        );
        let long = search_hint("one1 two three four five six seven eight");
        assert_eq!(long.split(' ').count(), SEARCH_WORDS);
    }

    #[test]
    fn counts_trend_hosts_and_severity() {
        // Newest first; the window is 0..100, so the halves are 0..50 and 50..100.
        let samples = vec![
            sample(6, 90, "b", 3, "disk 7 full"),
            sample(5, 80, "a", 6, "disk 3 full"),
            sample(4, 70, "a", 6, "disk 9 full"),
            sample(3, 60, "a", 6, "hello"),
            sample(2, 20, "a", 6, "disk 1 full"),
            sample(1, 0, "a", 6, "hello"),
        ];
        let p = analyse(&samples, false, Some(0), 100, 10);
        assert_eq!(p.scanned, 6);
        assert_eq!(p.distinct, 2);
        assert_eq!(p.other, 0);
        let disk = &p.patterns[0];
        assert_eq!(disk.pattern, "disk <*> full");
        assert_eq!(disk.search, "disk full");
        assert_eq!((disk.count, disk.previous, disk.recent), (4, 1, 3));
        assert_eq!(disk.hosts, 2);
        assert_eq!(disk.severity, "err");
        assert_eq!((disk.first_ts, disk.last_ts), (20, 90));
        // The example is the newest entry.
        assert_eq!(disk.example.id, 6);
        let hello = &p.patterns[1];
        assert_eq!((hello.count, hello.previous, hello.recent), (2, 1, 1));
        assert_eq!(hello.severity, "info");
    }

    #[test]
    fn limit_folds_the_rest_into_other() {
        let samples: Vec<Sample> = (0..10)
            .map(|i| {
                sample(
                    i,
                    100 - i,
                    "a",
                    6,
                    &format!("word{} x", "a".repeat(i as usize)),
                )
            })
            .collect();
        // Words without digits stay distinct, so ten patterns of one entry each.
        let p = analyse(&samples, false, None, 100, 3);
        assert_eq!(p.distinct, 10);
        assert_eq!(p.patterns.len(), 3);
        assert_eq!(p.other, 7);
    }

    #[test]
    fn window_follows_the_oldest_sample_when_unbounded_or_truncated() {
        let samples = vec![sample(2, 1000, "a", 6, "x"), sample(1, 500, "a", 6, "x")];
        let p = analyse(&samples, false, None, 1000, 5);
        assert_eq!((p.since, p.until), (500, 1000));
        assert_eq!(p.patterns[0].previous, 1);
        // A scan cut short starts at its oldest entry even if `since` reaches further back.
        let p = analyse(&samples, true, Some(0), 1000, 5);
        assert_eq!(p.since, 500);
        assert!(p.truncated);
        // A bounded, complete scan keeps the requested start.
        let p = analyse(&samples, false, Some(0), 1000, 5);
        assert_eq!(p.since, 0);
    }

    #[test]
    fn empty_input_is_empty_output() {
        let p = analyse(&[], false, None, 5, 5);
        assert_eq!((p.scanned, p.distinct, p.other), (0, 0, 0));
        assert!(p.patterns.is_empty());
    }
}
