//! Lenient syslog parser covering RFC 5424 and RFC 3164 (BSD) messages.
//!
//! Parsing never fails on malformed input: anything that is not recognised is
//! kept verbatim as the message, attributed to the sending peer.

use chrono::{DateTime, Datelike, NaiveDate, TimeZone};

use crate::model::LogEntry;

/// How the timestamp of an RFC 3164 message, which has no year and no zone, is read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Rfc3164Zone {
    /// Ignore it and use the reception time (the default: always plausible, never skewed).
    #[default]
    Reception,
    /// The clock of the sender is in UTC.
    Utc,
    /// The clock of the sender is in this machine's local zone, DST included (`TZ`, or the
    /// system zone; a container without zone data is UTC).
    Local,
    /// The sender's clock is a fixed offset from UTC, in seconds east.
    Fixed(i32),
    /// The sender's clock follows a zone's rule, DST included (`Europe/Paris`, or a POSIX rule).
    Rule(crate::tz::Rule),
}

impl Rfc3164Zone {
    /// `reception`, `utc`, `local`, an offset such as `+02:00`, `-0500` or `+1`, a zone name
    /// such as `Europe/Paris`, or a POSIX rule such as `CET-1CEST,M3.5.0,M10.5.0/3`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim().to_ascii_lowercase();
        match t.as_str() {
            "" | "reception" => return Ok(Self::Reception),
            "utc" | "z" => return Ok(Self::Utc),
            "local" => return Ok(Self::Local),
            _ => {}
        }
        let bad = || {
            format!(
                "{text:?} is not reception, utc, local, an offset like +02:00, a zone name like \
                 Europe/Paris or a POSIX rule"
            )
        };
        let sign = match t.chars().next() {
            Some('+') => 1,
            Some('-') => -1,
            _ if text.contains(['/', ',']) => {
                return crate::tz::Rule::parse(text.trim()).map(Self::Rule);
            }
            _ => {
                return crate::tz::Rule::parse(text.trim())
                    .map(Self::Rule)
                    .map_err(|_| bad());
            }
        };
        let digits: String = t[1..].chars().filter(|c| *c != ':').collect();
        let (h, m) = match digits.len() {
            1 | 2 => (digits.as_str(), "0"),
            3 => (&digits[..1], &digits[1..]),
            4 => (&digits[..2], &digits[2..]),
            _ => return Err(bad()),
        };
        let (h, m): (i32, i32) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
        if h > 14 || m > 59 {
            return Err(bad());
        }
        Ok(Self::Fixed(sign * (h * 3600 + m * 60)))
    }

    /// The Unix ms of a wall-clock time in this zone, `None` when it does not exist there (a DST
    /// gap) or the zone is `Reception`.
    fn to_ms(self, naive: chrono::NaiveDateTime) -> Option<i64> {
        match self {
            Self::Reception => None,
            Self::Utc => Some(naive.and_utc().timestamp_millis()),
            Self::Fixed(secs) => Some(naive.and_utc().timestamp_millis() - i64::from(secs) * 1000),
            Self::Rule(rule) => rule.to_ms(naive),
            Self::Local => chrono::Local
                .from_local_datetime(&naive)
                .earliest()
                .map(|t| t.timestamp_millis()),
        }
    }
}

/// Reads `Mmm dd hh:mm:ss` (as `has_3164_timestamp` recognised it) in `zone`. The year is the
/// current one, or the previous one when that would put the message more than a day in the future
/// (a message from late December read in early January).
fn timestamp_3164(s: &str, zone: Rfc3164Zone, now_ms: i64) -> Option<i64> {
    let b = s.as_bytes();
    let month = MONTHS.iter().position(|m| &b[..3] == *m)? as u32 + 1;
    let num = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&b[range]).ok()?.trim().parse().ok()
    };
    let (day, hour, min, sec) = (num(4..6)?, num(7..9)?, num(10..12)?, num(13..15)?);
    let now_year = chrono::DateTime::from_timestamp_millis(now_ms)?.year();
    let at = |year: i32| {
        let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
        zone.to_ms(naive)
    };
    match at(now_year) {
        Some(ts) if ts > now_ms + 86_400_000 => at(now_year - 1).or(Some(ts)),
        other => other,
    }
}

const DEFAULT_SEVERITY: u8 = 6;
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Parses one syslog datagram or line. Returns `None` when there is no message.
///
/// `peer` is used as host when the message does not carry one; `now_ms` is used
/// when the message has no usable timestamp (RFC 3164 timestamps carry no year
/// or zone, so the reception time is used instead unless a zone is given to [`parse_in`]).
pub fn parse(raw: &str, peer: &str, now_ms: i64) -> Option<LogEntry> {
    parse_in(raw, peer, now_ms, Rfc3164Zone::Reception)
}

/// Like [`parse`], reading the timestamps of RFC 3164 messages in `zone`.
pub fn parse_in(raw: &str, peer: &str, now_ms: i64, zone: Rfc3164Zone) -> Option<LogEntry> {
    let s = raw.trim_end_matches(['\n', '\r', '\0']);
    let (severity, rest) = parse_pri(s);

    let entry = match rest.strip_prefix("1 ") {
        Some(body) => parse_5424(body, severity, peer, now_ms),
        None => None,
    }
    .or_else(|| parse_3164(rest, severity, peer, now_ms, zone))?;

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
        ..Default::default()
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

fn parse_3164(
    s: &str,
    severity: u8,
    peer: &str,
    now_ms: i64,
    zone: Rfc3164Zone,
) -> Option<LogEntry> {
    let ts = if has_3164_timestamp(s) {
        timestamp_3164(s, zone, now_ms).unwrap_or(now_ms)
    } else {
        now_ms
    };
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
        ts,
        host,
        app,
        severity,
        message: message.to_string(),
        ..Default::default()
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

    // 2026-10-03T12:00:00Z
    const OCT3: i64 = 1_791_028_800_000;

    fn ts(raw: &str, now: i64, zone: Rfc3164Zone) -> i64 {
        parse_in(raw, "p", now, zone).unwrap().ts
    }

    #[test]
    fn rfc3164_timestamps_are_read_in_the_configured_zone() {
        let raw = "<13>Oct  3 14:00:00 pve sshd[1]: hi";
        // The default ignores the stamp.
        assert_eq!(ts(raw, OCT3, Rfc3164Zone::Reception), OCT3);
        assert_eq!(parse(raw, "p", OCT3).unwrap().ts, OCT3);
        assert_eq!(ts(raw, OCT3, Rfc3164Zone::Utc), OCT3 + 2 * 3_600_000);
        assert_eq!(ts(raw, OCT3, Rfc3164Zone::Fixed(2 * 3600)), OCT3);
        assert_eq!(
            ts(raw, OCT3, Rfc3164Zone::Fixed(-5 * 3600 - 1800)),
            OCT3 + 7 * 3_600_000 + 1_800_000
        );
        // `local` is whatever the machine's zone says; compare with chrono's own conversion.
        let naive = NaiveDate::from_ymd_opt(2026, 10, 3)
            .unwrap()
            .and_hms_opt(14, 0, 0)
            .unwrap();
        let expected = chrono::Local
            .from_local_datetime(&naive)
            .earliest()
            .unwrap()
            .timestamp_millis();
        assert_eq!(ts(raw, OCT3, Rfc3164Zone::Local), expected);
        // Host, app and message are unaffected.
        let e = parse_in(raw, "p", OCT3, Rfc3164Zone::Utc).unwrap();
        assert_eq!(
            (e.host.as_str(), e.app.as_str(), e.message.as_str()),
            ("pve", "sshd", "hi")
        );
        // RFC 5424 keeps its own zone-aware time, and so do messages without a stamp.
        assert_eq!(
            ts(
                "<14>1 2003-10-11T22:14:15.003Z h a - - - m",
                OCT3,
                Rfc3164Zone::Fixed(3600)
            ),
            1_065_910_455_003
        );
        assert_eq!(ts("<13>no stamp here", OCT3, Rfc3164Zone::Utc), OCT3);
    }

    #[test]
    fn the_year_is_the_current_one_unless_that_is_in_the_future() {
        let utc = Rfc3164Zone::Utc;
        // Early January, a message from the last day of December: last year.
        let jan2 = 1_767_312_000_000; // 2026-01-02T00:00:00Z
        assert_eq!(
            ts("<13>Dec 31 23:59:00 h a: m", jan2, utc),
            1_767_225_540_000
        ); // 2025-12-31T23:59:00Z
        // A little clock skew ahead (under a day) stays in the current year.
        assert_eq!(
            ts("<13>Oct  4 11:00:00 h a: m", OCT3, utc),
            OCT3 + 23 * 3_600_000
        );
        // More than a day ahead is last year's.
        assert_eq!(
            ts("<13>Oct  5 12:00:00 h a: m", OCT3, utc),
            1_759_665_600_000
        ); // 2025-10-05T12:00:00Z
        // Earlier in the year is simply this year.
        assert_eq!(
            ts("<13>Jan  1 00:00:00 h a: m", OCT3, utc),
            1_767_225_600_000
        );
    }

    #[test]
    fn impossible_dates_fall_back_to_the_reception_time() {
        let utc = Rfc3164Zone::Utc;
        for raw in [
            "<13>Feb 30 12:00:00 h a: m",
            "<13>Feb 29 12:00:00 h a: m", // 2026 is not a leap year
            "<13>Oct 32 12:00:00 h a: m",
            "<13>Oct  3 25:00:00 h a: m",
            "<13>Oct  3 12:61:00 h a: m",
        ] {
            assert_eq!(ts(raw, OCT3, utc), OCT3, "{raw}");
        }
        // 2028 is: a leap day parses.
        let in_2028 = 1_835_000_000_000; // 2028-02-29T09:... well inside 2028
        assert_ne!(ts("<13>Feb 29 12:00:00 h a: m", in_2028, utc), in_2028);
    }

    #[test]
    fn zone_settings_parse() {
        for (text, zone) in [
            ("reception", Rfc3164Zone::Reception),
            ("", Rfc3164Zone::Reception),
            ("UTC", Rfc3164Zone::Utc),
            ("z", Rfc3164Zone::Utc),
            ("Local", Rfc3164Zone::Local),
            ("+02:00", Rfc3164Zone::Fixed(7200)),
            ("+0200", Rfc3164Zone::Fixed(7200)),
            ("+2", Rfc3164Zone::Fixed(7200)),
            ("-05:30", Rfc3164Zone::Fixed(-19_800)),
            ("-530", Rfc3164Zone::Fixed(-19_800)),
            ("+14", Rfc3164Zone::Fixed(14 * 3600)),
        ] {
            assert_eq!(Rfc3164Zone::parse(text), Ok(zone), "{text:?}");
        }
        if std::path::Path::new("/usr/share/zoneinfo/Europe/Paris").exists() {
            assert!(matches!(
                Rfc3164Zone::parse(" Europe/Paris "),
                Ok(Rfc3164Zone::Rule(_))
            ));
        }
        let paris = Rfc3164Zone::parse("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        // Summer in Paris is UTC+2: 14:00 there is noon UTC.
        assert_eq!(ts("<13>Oct  3 14:00:00 h a: m", OCT3, paris), OCT3);
        assert!(
            Rfc3164Zone::parse("Nowhere/Atlantis")
                .unwrap_err()
                .contains("not found")
        );
        for bad in [
            "Nowhere/Atlantis",
            "CET-1CEST,M3.5.0",
            "02:00",
            "+15:00",
            "+02:60",
            "+",
            "+12345",
            "gmt+1",
            "+a",
        ] {
            assert!(Rfc3164Zone::parse(bad).is_err(), "{bad}");
        }
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
