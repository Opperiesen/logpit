//! Trace correlation: whatever names a log line's trace and span (OpenTelemetry attributes, JSON
//! logs, Loki labels, a W3C `traceparent` header) ends up in the `trace_id` and `span_id` fields, in
//! lower case, so one search (`trace=<id>`) finds every entry of a request across hosts.

use crate::model::LogEntry;

pub const TRACE_ID: &str = "trace_id";
pub const SPAN_ID: &str = "span_id";

/// Other names for the trace id and the span id, compared in lower case.
const TRACE_ALIASES: &[&str] = &[
    "traceid",
    "trace-id",
    "trace.id",
    "otel.trace_id",
    "dd.trace_id",
    "x-b3-traceid",
    "x-trace-id",
];
const SPAN_ALIASES: &[&str] = &[
    "spanid",
    "span-id",
    "span.id",
    "otel.span_id",
    "dd.span_id",
    "x-b3-spanid",
];
/// Longest id kept (a trace id is 32 hex characters; some systems use longer opaque strings).
const MAX_ID_BYTES: usize = 128;

/// An id as it is stored and searched: trimmed, without quotes, and in lower case when it is
/// hexadecimal (OpenTelemetry writes ids in lower case, other tools in upper case).
pub fn normalize_id(raw: &str) -> Option<String> {
    let id = raw.trim().trim_matches('"').trim();
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
        return None;
    }
    Some(if id.bytes().all(|b| b.is_ascii_hexdigit()) {
        id.to_ascii_lowercase()
    } else {
        id.to_string()
    })
}

/// `00-<32 hex>-<16 hex>-<2 hex>` (W3C Trace Context) as (trace id, span id).
fn parse_traceparent(value: &str) -> Option<(String, String)> {
    let mut parts = value.trim().split('-');
    let (version, trace, span, flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    // An all-zero id means "no trace".
    let zero = |s: &str| s.bytes().all(|b| b == b'0');
    (hex(version, 2)
        && hex(trace, 32)
        && hex(span, 16)
        && hex(flags, 2)
        && !zero(trace)
        && !zero(span))
    .then(|| (trace.to_ascii_lowercase(), span.to_ascii_lowercase()))
}

/// Sets `trace_id` and `span_id` from the first alias found when the entry does not have them
/// already. The original fields stay.
pub fn normalize(entry: &mut LogEntry) {
    if entry.fields.is_empty() {
        return;
    }
    for (canonical, aliases) in [(TRACE_ID, TRACE_ALIASES), (SPAN_ID, SPAN_ALIASES)] {
        let found = match entry.fields.get(canonical) {
            Some(v) => normalize_id(v),
            None => entry
                .fields
                .iter()
                .find(|(k, _)| aliases.contains(&k.to_ascii_lowercase().as_str()))
                .and_then(|(_, v)| normalize_id(v)),
        };
        if let Some(id) = found {
            entry.fields.insert(canonical.to_string(), id);
        }
    }
    if let Some((trace, span)) = entry
        .fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("traceparent"))
        .and_then(|(_, v)| parse_traceparent(v))
    {
        entry.fields.entry(TRACE_ID.to_string()).or_insert(trace);
        entry.fields.entry(SPAN_ID.to_string()).or_insert(span);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fields: &[(&str, &str)]) -> LogEntry {
        LogEntry {
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    fn get<'a>(e: &'a LogEntry, k: &str) -> Option<&'a str> {
        e.fields.get(k).map(String::as_str)
    }

    #[test]
    fn aliases_become_the_canonical_fields_in_lower_case() {
        let mut e = entry(&[
            ("traceId", "4BF92F3577B34DA6A3CE929D0E0E4736"),
            ("span.id", "00F067AA0BA902B7"),
        ]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(get(&e, SPAN_ID), Some("00f067aa0ba902b7"));
        assert!(e.fields.contains_key("traceId"), "the original stays");
        let mut e = entry(&[("dd.trace_id", "\"123456789\""), ("x", "y")]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), Some("123456789"));
        assert_eq!(get(&e, SPAN_ID), None);
    }

    #[test]
    fn the_canonical_field_wins_and_is_lowercased() {
        let mut e = entry(&[("trace_id", "ABCDEF"), ("traceId", "other")]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), Some("abcdef"));
        // Opaque ids keep their case.
        let mut e = entry(&[("trace_id", "Req-7")]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), Some("Req-7"));
    }

    #[test]
    fn a_traceparent_header_gives_both_ids_unless_set() {
        let tp = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        let mut e = entry(&[("traceparent", tp)]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(get(&e, SPAN_ID), Some("00f067aa0ba902b7"));
        let mut e = entry(&[("traceparent", tp), ("trace_id", "mine")]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), Some("mine"));
        for bad in [
            "garbage",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4bf92f35-00f067aa0ba902b7-01",
        ] {
            let mut e = entry(&[("traceparent", bad)]);
            normalize(&mut e);
            assert_eq!(get(&e, TRACE_ID), None, "{bad}");
        }
    }

    #[test]
    fn unusable_ids_are_ignored() {
        assert_eq!(normalize_id("  "), None);
        assert_eq!(normalize_id(&"a".repeat(MAX_ID_BYTES + 1)), None);
        assert_eq!(normalize_id("a\nb"), None);
        assert_eq!(normalize_id(" AbC "), Some("abc".into()));
        let mut e = entry(&[("traceId", "")]);
        normalize(&mut e);
        assert_eq!(get(&e, TRACE_ID), None);
        // No fields, nothing to do.
        let mut e = LogEntry::default();
        normalize(&mut e);
        assert!(e.fields.is_empty());
    }
}
