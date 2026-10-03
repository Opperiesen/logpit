//! Structured data found inside the message text: a JSON object, or `key=value` pairs
//! (logfmt). The values become `fields`, so they are filterable (`f=key:value`), can be grouped
//! in statistics and are part of the full-text index. The message itself is left untouched.

use serde_json::Value;

use crate::model::LogEntry;

const MAX_FIELDS: usize = 64;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_DEPTH: usize = 3;
/// Messages longer than this are not scanned.
const MAX_SCAN_BYTES: usize = 64 * 1024;

pub(crate) fn clip(s: &str) -> String {
    let mut v = s.to_string();
    crate::model::truncate_utf8(&mut v, MAX_VALUE_BYTES);
    v
}

/// Turns a JSON/logfmt key into a valid field name (letters, digits, `_`, `.`, `-`).
pub(crate) fn sanitize_key(key: &str) -> Option<String> {
    let mut k: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    crate::model::truncate_utf8(&mut k, MAX_KEY_BYTES);
    (!k.trim_matches('_').is_empty()).then_some(k)
}

fn flatten(prefix: &str, value: &Value, depth: usize, out: &mut Vec<(String, String)>) {
    if out.len() >= MAX_FIELDS {
        return;
    }
    match value {
        Value::String(s) if !s.is_empty() => out.push((prefix.to_string(), clip(s))),
        Value::Number(n) => out.push((prefix.to_string(), n.to_string())),
        Value::Bool(b) => out.push((prefix.to_string(), b.to_string())),
        Value::Object(map) if depth < MAX_DEPTH => {
            for (k, v) in map {
                let Some(k) = sanitize_key(k) else { continue };
                let key = if prefix.is_empty() {
                    k
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, v, depth + 1, out);
            }
        }
        // Null, empty strings, arrays and objects nested too deep carry nothing useful here.
        _ => {}
    }
}

fn from_json(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) {
        flatten("", &Value::Object(map), 0, &mut out);
    }
    out
}

/// A logfmt key: starts with a letter or underscore, then letters, digits, `_`, `.`, `-`.
fn is_logfmt_key(k: &str) -> bool {
    let mut chars = k.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// `key=value key2="quoted value" …`. It only counts as logfmt when at least two pairs are
/// present and they are at least as many as the bare words, so a sentence that happens to
/// contain `a=b` is left alone.
fn from_logfmt(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut bare = 0usize;
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(rest.len());
        let (token, after) = rest.split_at(end);
        if after.starts_with('=') && is_logfmt_key(token) {
            let value_part = &after[1..];
            let (value, remaining) = if let Some(quoted) = value_part.strip_prefix('"') {
                let mut value = String::new();
                let mut chars = quoted.char_indices();
                let mut consumed = quoted.len();
                while let Some((i, c)) = chars.next() {
                    match c {
                        '\\' => match chars.next() {
                            Some((_, n @ ('"' | '\\'))) => value.push(n),
                            Some((_, 'n')) => value.push('\n'),
                            Some((_, n)) => {
                                value.push('\\');
                                value.push(n);
                            }
                            None => value.push('\\'),
                        },
                        '"' => {
                            consumed = i + 1;
                            break;
                        }
                        _ => value.push(c),
                    }
                }
                (value, &quoted[consumed.min(quoted.len())..])
            } else {
                let stop = value_part
                    .find(char::is_whitespace)
                    .unwrap_or(value_part.len());
                (value_part[..stop].to_string(), &value_part[stop..])
            };
            pairs.push((token.to_string(), value));
            rest = remaining.trim_start();
        } else {
            // A bare word (or a token whose `=` is part of something else, like a URL).
            bare += 1;
            let stop = rest.find(char::is_whitespace).unwrap_or(rest.len());
            rest = rest[stop..].trim_start();
        }
    }
    if pairs.len() >= 2 && pairs.len() >= bare {
        pairs.into_iter().filter(|(_, v)| !v.is_empty()).collect()
    } else {
        Vec::new()
    }
}

/// The `(key, value)` pairs found in `message`, or nothing when it is plain text.
pub fn extract(message: &str) -> Vec<(String, String)> {
    let text = message.trim();
    if text.is_empty() || text.len() > MAX_SCAN_BYTES {
        return Vec::new();
    }
    if text.starts_with('{') && text.ends_with('}') {
        let found = from_json(text);
        if !found.is_empty() {
            return found;
        }
    }
    from_logfmt(text)
}

/// Adds the structured values of the message to the entry's fields. Entries that already carry
/// fields (parsed CEF, or sent with `fields` over HTTP) are left as they are.
pub fn enrich(entry: &mut LogEntry) {
    if !entry.fields.is_empty() {
        return;
    }
    for (key, value) in extract(&entry.message) {
        if entry.fields.len() >= MAX_FIELDS {
            break;
        }
        if let Some(key) = sanitize_key(&key) {
            entry.fields.entry(key).or_insert_with(|| clip(&value));
        }
    }
}

/// Like [`enrich`], but also for an entry that has fields already: the generic values are added
/// under keys that are not taken yet (what `keep_generic` parsers ask for).
pub fn enrich_missing(entry: &mut LogEntry) {
    for (key, value) in extract(&entry.message) {
        if entry.fields.len() >= MAX_FIELDS {
            break;
        }
        if let Some(key) = sanitize_key(&key) {
            entry.fields.entry(key).or_insert_with(|| clip(&value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn logfmt_pairs_and_quotes() {
        assert_eq!(
            extract(r#"level=info msg="user logged in" user=bob took=12ms"#),
            kv(&[
                ("level", "info"),
                ("msg", "user logged in"),
                ("user", "bob"),
                ("took", "12ms")
            ])
        );
        assert_eq!(
            extract(r#"a="say \"hi\"" b=2"#),
            kv(&[("a", r#"say "hi""#), ("b", "2")])
        );
        // An unterminated quote takes the rest; empty values are dropped.
        assert_eq!(extract(r#"a=1 b="open"#), kv(&[("a", "1"), ("b", "open")]));
        assert_eq!(extract("a=1 b= c=3"), kv(&[("a", "1"), ("c", "3")]));
    }

    #[test]
    fn plain_text_is_not_logfmt() {
        for text in [
            "disk error on sda",
            "user=bob logged in from the office today",
            "see https://example.com/?a=1&b=2 for details",
            "x = y",
            "1=2 3=4",
            "",
            "   ",
        ] {
            assert!(extract(text).is_empty(), "{text:?}");
        }
        // Mostly pairs with a stray word still counts.
        assert_eq!(extract("sshd a=1 b=2").len(), 2);
    }

    #[test]
    fn json_objects_are_flattened() {
        let got = extract(
            r#"{"level":"warn","msg":"slow","http":{"method":"GET","status":200,"deep":{"x":{"y":1}}},"ok":true,"nothing":null,"list":[1,2],"empty":""}"#,
        );
        // Nested objects are joined with dots down to MAX_DEPTH levels; null, empty strings and
        // arrays are skipped.
        assert_eq!(
            got,
            kv(&[
                ("http.method", "GET"),
                ("http.status", "200"),
                ("level", "warn"),
                ("msg", "slow"),
                ("ok", "true"),
            ])
        );
        // Not an object, or not valid JSON: not structured (and not logfmt either).
        assert!(extract("[1,2,3]").is_empty());
        assert!(extract("{broken json").is_empty());
        assert!(extract("{\"a\":}").is_empty());
    }

    #[test]
    fn keys_are_made_valid_and_limits_hold() {
        let got = extract(r#"{"user name":"a","é":"b","a/b":"c"}"#);
        assert!(got.iter().any(|(k, v)| k == "user_name" && v == "a"));
        assert!(
            got.iter().all(|(k, _)| crate::store::valid_field_key(k)),
            "{got:?}"
        );

        let many: String = (0..200).map(|i| format!("k{i}=v ")).collect();
        let mut e = LogEntry {
            message: many,
            ..Default::default()
        };
        enrich(&mut e);
        assert_eq!(e.fields.len(), MAX_FIELDS);

        let long = format!("a={} b=2", "x".repeat(5000));
        let mut e = LogEntry {
            message: long,
            ..Default::default()
        };
        enrich(&mut e);
        assert_eq!(e.fields["a"].len(), MAX_VALUE_BYTES);
        assert!(extract(&format!("a=1 b=2 {}", "z".repeat(MAX_SCAN_BYTES))).is_empty());
    }

    #[test]
    fn enrich_keeps_the_message_and_existing_fields() {
        let mut e = LogEntry {
            message: "level=info user=bob".into(),
            ..Default::default()
        };
        enrich(&mut e);
        assert_eq!(e.message, "level=info user=bob");
        assert_eq!(e.fields["user"], "bob");

        let mut cef = LogEntry {
            message: "a=1 b=2".into(),
            ..Default::default()
        };
        cef.fields.insert("cef_name".into(), "x".into());
        enrich(&mut cef);
        assert_eq!(
            cef.fields.len(),
            1,
            "entries that already have fields are left alone"
        );
    }
}
