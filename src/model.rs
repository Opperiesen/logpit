use std::collections::BTreeMap;

use serde::Serialize;

/// A single normalized log record.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LogEntry {
    /// Unix timestamp in milliseconds.
    pub ts: i64,
    pub host: String,
    pub app: String,
    /// Syslog severity, 0 (emergency) to 7 (debug).
    pub severity: u8,
    pub message: String,
    /// Structured key/value data (e.g. parsed CEF extensions). Empty when none.
    pub fields: BTreeMap<String, String>,
}

/// Truncates `s` to at most `max` bytes without splitting a UTF-8 character.
pub fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries() {
        let mut s = "aé".repeat(10);
        truncate_utf8(&mut s, 4);
        assert_eq!(s, "aéa");
        let mut short = String::from("ok");
        truncate_utf8(&mut short, 10);
        assert_eq!(short, "ok");
    }
}
