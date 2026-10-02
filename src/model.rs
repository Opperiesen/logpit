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

/// Short name of a syslog severity (`err`, `warn`, …).
pub fn severity_name(sev: u8) -> &'static str {
    const NAMES: [&str; 8] = [
        "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug",
    ];
    NAMES.get(usize::from(sev)).copied().unwrap_or("unknown")
}

/// Parses a syslog severity given as a name (`err`, `warning`, …) or number (0-7).
pub fn parse_severity(s: &str) -> Option<u8> {
    let s = s.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<u8>() {
        return (n <= 7).then_some(n);
    }
    Some(match s.as_str() {
        "emerg" | "emergency" => 0,
        "alert" => 1,
        "crit" | "critical" => 2,
        "err" | "error" => 3,
        "warn" | "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => return None,
    })
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
    fn severity_names_and_numbers() {
        assert_eq!(parse_severity("Debug"), Some(7));
        assert_eq!(parse_severity("warning"), Some(4));
        assert_eq!(parse_severity(" 3 "), Some(3));
        assert_eq!(parse_severity("8"), None);
        assert_eq!(parse_severity("loud"), None);
    }

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
