//! Lenient syslog parser covering RFC 5424 and RFC 3164 (BSD) messages.
//!
//! Parsing never fails on malformed input: anything that is not recognised is
//! kept verbatim as the message, attributed to the sending peer.

use chrono::DateTime;

use crate::model::LogEntry;

const DEFAULT_SEVERITY: u8 = 6;
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Parses one syslog datagram or line. Returns `None` when there is no message.
///
/// `peer` is used as host when the message does not carry one; `now_ms` is used
/// when the message has no usable timestamp (RFC 3164 timestamps carry no year
/// or zone, so the reception time is used instead).
pub fn parse(raw: &str, peer: &str, now_ms: i64) -> Option<LogEntry> {
    let s = raw.trim_end_matches(['\n', '\r', '\0']);
    let (severity, rest) = parse_pri(s);

    let entry = match rest.strip_prefix("1 ") {
        Some(body) => parse_5424(body, severity, peer, now_ms),
        None => None,
    }
    .or_else(|| parse_3164(rest, severity, peer, now_ms))?;

    (!entry.message.is_empty()).then_some(entry)
}

fn parse_pri(s: &str) -> (u8, &str) {
    let Some(inner) = s.strip_prefix('<') else {
        return (DEFAULT_SEVERITY, s);
    };
    let Some(end) = inner.find('>').filter(|&i| (1..=3).contains(&i)) else {
        return (DEFAULT_SEVERITY, s);
    };
    match inner[..end].parse::<u16>() {
        Ok(pri) if pri <= 191 => ((pri & 7) as u8, &inner[end + 1..]),
        _ => (DEFAULT_SEVERITY, s),
    }
}

fn nil_or(field: &str, fallback: &str) -> String {
    if field == "-" {
        fallback.to_string()
    } else {
        field.to_string()
    }
}

fn parse_5424(body: &str, severity: u8, peer: &str, now_ms: i64) -> Option<LogEntry> {
    let (ts, rest) = body.split_once(' ')?;
    let (host, rest) = rest.split_once(' ')?;
    let (app, rest) = rest.split_once(' ')?;
    let (_procid, rest) = rest.split_once(' ')?;
    let (_msgid, rest) = rest.split_once(' ').unwrap_or((rest, ""));

    let ts = if ts == "-" {
        now_ms
    } else {
        DateTime::parse_from_rfc3339(ts).map_or(now_ms, |d| d.timestamp_millis())
    };
    let message = skip_structured_data(rest).trim_start_matches('\u{feff}');

    Some(LogEntry {
        ts,
        host: nil_or(host, peer),
        app: nil_or(app, ""),
        severity,
        message: message.to_string(),
    })
}

/// Returns the message that follows the (optional) structured-data section.
fn skip_structured_data(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('-') {
        return rest.strip_prefix(' ').unwrap_or(rest);
    }
    let bytes = s.as_bytes();
    let mut pos = 0;
    while bytes.get(pos) == Some(&b'[') {
        let mut i = pos + 1;
        let mut in_quote = false;
        let mut closed = false;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 1,
                b'"' => in_quote = !in_quote,
                b']' if !in_quote => {
                    closed = true;
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        if !closed {
            // Unterminated element: keep everything as the message.
            return s;
        }
        pos = i + 1;
    }
    let rest = &s[pos..];
    rest.strip_prefix(' ').unwrap_or(rest)
}

fn has_3164_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() > 16
        && MONTHS.iter().any(|m| &b[..3] == *m)
        && b[3] == b' '
        && (b[4] == b' ' || b[4].is_ascii_digit())
        && b[5].is_ascii_digit()
        && b[6] == b' '
        && b[9] == b':'
        && b[12] == b':'
        && b[15] == b' '
}

fn parse_3164(s: &str, severity: u8, peer: &str, now_ms: i64) -> Option<LogEntry> {
    let (host, body) = if has_3164_timestamp(s) {
        let after = &s[16..];
        match after.split_once(' ') {
            Some((host, body)) => (host.to_string(), body),
            None => (peer.to_string(), after),
        }
    } else {
        (peer.to_string(), s)
    };

    let (app, message) = match body.find(':') {
        Some(i) if i <= 48 && !body[..i].contains(' ') && i > 0 => {
            let tag = &body[..i];
            let app = tag.split('[').next().unwrap_or(tag);
            (app.to_string(), body[i + 1..].trim_start())
        }
        _ => (String::new(), body),
    };

    Some(LogEntry {
        ts: now_ms,
        host,
        app,
        severity,
        message: message.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    #[test]
    fn rfc5424_full() {
        let raw =
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su 123 ID47 - 'su root' failed";
        let e = parse(raw, "10.0.0.1", NOW).unwrap();
        assert_eq!(e.severity, 2);
        assert_eq!(e.host, "mymachine.example.com");
        assert_eq!(e.app, "su");
        assert_eq!(e.message, "'su root' failed");
        assert_eq!(e.ts, 1_065_910_455_003);
    }

    #[test]
    fn rfc5424_structured_data_with_escapes() {
        let raw = r#"<165>1 2003-08-24T05:14:15.000003-07:00 host app - ID47 [ex@1 a="x\]y" b="z"][o@2 k="v"] An event"#;
        let e = parse(raw, "p", NOW).unwrap();
        assert_eq!(e.message, "An event");
        assert_eq!(e.severity, 5);
    }

    #[test]
    fn rfc5424_nil_fields_fall_back() {
        let e = parse("<14>1 - - - - - - hello", "10.1.1.1", NOW).unwrap();
        assert_eq!(
            (e.ts, e.host.as_str(), e.app.as_str()),
            (NOW, "10.1.1.1", "")
        );
        assert_eq!(e.message, "hello");
    }

    #[test]
    fn rfc3164_with_tag_and_pid() {
        let raw = "<13>Oct 11 22:14:15 pve sshd[4242]: Accepted publickey for root";
        let e = parse(raw, "10.0.0.1", NOW).unwrap();
        assert_eq!((e.host.as_str(), e.app.as_str()), ("pve", "sshd"));
        assert_eq!(e.message, "Accepted publickey for root");
        assert_eq!(e.severity, 5);
        assert_eq!(e.ts, NOW);
    }

    #[test]
    fn rfc3164_single_digit_day() {
        let e = parse("<13>Oct  1 02:03:04 pve cron: tick", "p", NOW).unwrap();
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.message.as_str()),
            ("pve", "cron", "tick")
        );
    }

    #[test]
    fn plain_text_uses_peer_and_default_severity() {
        let e = parse("just some text\r\n", "192.168.1.1", NOW).unwrap();
        assert_eq!(e.host, "192.168.1.1");
        assert_eq!(e.severity, DEFAULT_SEVERITY);
        assert_eq!(e.message, "just some text");
    }

    #[test]
    fn malformed_input_never_panics() {
        for raw in [
            "",
            "<",
            "<>",
            "<999>x",
            "<13",
            "<13>1 ",
            "<13>1 a b c d e [",
            "<13>1 a b c d e [x",
            "Oct 11 22:14:15",
            "Oct 11 22:14:15 ",
            "é",
            "<13>é",
            "<13>Oct 1é 22:14:15 h t: m",
            "\0\0",
        ] {
            let _ = parse(raw, "peer", NOW);
        }
    }

    #[test]
    fn empty_message_is_dropped() {
        assert!(parse("", "p", NOW).is_none());
        assert!(parse("<13>\n", "p", NOW).is_none());
    }
}
