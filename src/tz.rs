//! Time zones by rule: a POSIX `TZ` string (`CET-1CEST,M3.5.0,M10.5.0/3`) or a zone name
//! (`Europe/Paris`) looked up in the system zone database, of which only the rule for current
//! times (the footer of a TZif v2+ file) is used. LogPit embeds no zone data.

use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime};

/// Where zone names are looked up.
const ZONEINFO: &str = "/usr/share/zoneinfo";
/// A zone file is a few kilobytes; anything larger is not one.
const MAX_ZONE_FILE: u64 = 1 << 20;

/// The day a DST transition falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Day {
    /// `Mm.w.d`: weekday `d` (0 = Sunday) of week `w` (1-5, 5 = the last) of month `m`.
    Month { month: u32, week: u32, weekday: u32 },
    /// `Jn`: day 1-365, February 29 never counted.
    Julian(u32),
    /// `n`: day 0-365, February 29 counted.
    Ordinal(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Transition {
    day: Day,
    /// Local time of day, in seconds (may be negative or past 24h).
    secs: i32,
}

/// Offsets are in seconds east of UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    std: i32,
    dst: Option<(i32, Transition, Transition)>,
}

impl Rule {
    /// A zone name looked up in the zone database, or a POSIX `TZ` string with DST rules. One
    /// without (`GMT+1`) is refused: POSIX counts hours west, so it reads as the opposite of what
    /// it seems, and a fixed offset says the same thing plainly.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.contains(',') {
            Self::posix(text)
        } else {
            Self::named(text)
        }
    }

    fn named(name: &str) -> Result<Self, String> {
        let safe = !name.is_empty()
            && !name.starts_with('/')
            && name
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/_-+".contains(c));
        if !safe {
            return Err(format!("{name:?} is not a zone name"));
        }
        let path = format!("{ZONEINFO}/{name}");
        let data = std::fs::metadata(&path)
            .ok()
            .filter(|m| m.is_file() && m.len() <= MAX_ZONE_FILE)
            .and_then(|_| std::fs::read(&path).ok())
            .ok_or_else(|| {
                format!("zone {name:?} not found in {ZONEINFO} (mount it, or give a POSIX rule)")
            })?;
        let footer =
            footer(&data).ok_or_else(|| format!("{path} has no rule for current times"))?;
        // ponytail: only the current rule is used, so a rule change in the past year reads
        // older stamps with the new rule; parse the transition table if that ever matters.
        Self::posix(footer).map_err(|e| format!("{path}: {e}"))
    }

    fn posix(text: &str) -> Result<Self, String> {
        let bad = |what: &str| format!("{text:?} is not a POSIX TZ rule ({what})");
        let mut p = Cursor(text.as_bytes());
        p.name().ok_or_else(|| bad("standard zone name"))?;
        let std = -p.offset().ok_or_else(|| bad("standard offset"))?;
        if p.done() {
            return Ok(Self { std, dst: None });
        }
        p.name().ok_or_else(|| bad("DST zone name"))?;
        let dst = match p.peek() {
            Some(b',') => std + 3600,
            _ => -p.offset().ok_or_else(|| bad("DST offset"))?,
        };
        let mut transition = || -> Option<Transition> {
            p.eat(b',')?;
            let day = p.day()?;
            let secs = if p.eat(b'/').is_some() {
                p.time(167)?
            } else {
                7200
            };
            Some(Transition { day, secs })
        };
        let start = transition().ok_or_else(|| bad("DST start"))?;
        let end = transition().ok_or_else(|| bad("DST end"))?;
        if !p.done() {
            return Err(bad("trailing text"));
        }
        Ok(Self {
            std,
            dst: Some((dst, start, end)),
        })
    }

    /// The Unix ms of a wall-clock time under this rule; the earlier one when it occurs twice
    /// (the hour repeated when DST ends), `None` when it does not occur (the hour skipped).
    pub fn to_ms(self, naive: NaiveDateTime) -> Option<i64> {
        let wall = naive.and_utc().timestamp();
        let Some((dst, start, end)) = self.dst else {
            return Some((wall - i64::from(self.std)) * 1000);
        };
        let year = naive.year();
        let (start, end) = (
            start.at(year)? - i64::from(self.std),
            end.at(year)? - i64::from(dst),
        );
        let in_dst = |utc: i64| {
            if start < end {
                (start..end).contains(&utc)
            } else {
                utc >= start || utc < end // southern hemisphere: DST spans the new year
            }
        };
        let as_dst = wall - i64::from(dst);
        let as_std = wall - i64::from(self.std);
        let dst_ok = in_dst(as_dst).then_some(as_dst);
        let std_ok = (!in_dst(as_std)).then_some(as_std);
        dst_ok.into_iter().chain(std_ok).min().map(|t| t * 1000)
    }
}

impl Transition {
    /// The wall-clock Unix seconds (as if UTC) of this transition in `year`.
    fn at(self, year: i32) -> Option<i64> {
        let date = match self.day {
            Day::Month {
                month,
                week,
                weekday,
            } => {
                let first = NaiveDate::from_ymd_opt(year, month, 1)?;
                let offset = (weekday + 7 - first.weekday().num_days_from_sunday()) % 7;
                let mut date = first + Duration::days(i64::from(offset + (week - 1) * 7));
                while date.month() != month {
                    date -= Duration::days(7); // week 5 means the last such weekday
                }
                date
            }
            Day::Julian(n) => {
                let leap = NaiveDate::from_ymd_opt(year, 2, 29).is_some();
                NaiveDate::from_yo_opt(year, n + u32::from(leap && n >= 60))?
            }
            Day::Ordinal(n) => NaiveDate::from_yo_opt(year, n + 1)?,
        };
        Some(date.and_hms_opt(0, 0, 0)?.and_utc().timestamp() + i64::from(self.secs))
    }
}

/// The POSIX rule at the end of a TZif v2+ file, between its last two newlines.
fn footer(data: &[u8]) -> Option<&str> {
    if !data.starts_with(b"TZif") || data.get(4).is_none_or(|v| *v < b'2') {
        return None;
    }
    let body = data.strip_suffix(b"\n")?;
    let start = body.iter().rposition(|b| *b == b'\n')? + 1;
    std::str::from_utf8(&body[start..])
        .ok()
        .filter(|s| !s.is_empty())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }

    fn eat(&mut self, b: u8) -> Option<()> {
        (self.peek() == Some(b)).then(|| self.0 = &self.0[1..])
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &'a [u8] {
        let n = self.0.iter().take_while(|b| f(**b)).count();
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }

    /// `CET`, or a quoted name such as `<+03>`.
    fn name(&mut self) -> Option<()> {
        if self.eat(b'<').is_some() {
            let n = self.take_while(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-');
            return if n.len() >= 3 { self.eat(b'>') } else { None };
        }
        (self.take_while(|b| b.is_ascii_alphabetic()).len() >= 3).then_some(())
    }

    fn number(&mut self, max: u32) -> Option<u32> {
        let digits = self.take_while(|b| b.is_ascii_digit());
        if digits.is_empty() || digits.len() > 3 {
            return None;
        }
        std::str::from_utf8(digits)
            .ok()?
            .parse()
            .ok()
            .filter(|n| *n <= max)
    }

    /// `[+-]hh[:mm[:ss]]` in seconds, hours up to `max_h`.
    fn time(&mut self, max_h: u32) -> Option<i32> {
        let sign = if self.eat(b'-').is_some() {
            -1
        } else {
            self.eat(b'+');
            1
        };
        let mut secs = self.number(max_h)? * 3600;
        for unit in [60, 1] {
            if self.eat(b':').is_none() {
                break;
            }
            secs += self.number(59)? * unit;
        }
        Some(sign * i32::try_from(secs).ok()?)
    }

    /// An offset as POSIX writes it: hours **west** of UTC.
    fn offset(&mut self) -> Option<i32> {
        self.time(24)
    }

    fn day(&mut self) -> Option<Day> {
        if self.eat(b'M').is_some() {
            let month = self.number(12).filter(|m| *m >= 1)?;
            self.eat(b'.')?;
            let week = self.number(5).filter(|w| *w >= 1)?;
            self.eat(b'.')?;
            let weekday = self.number(6)?;
            return Some(Day::Month {
                month,
                week,
                weekday,
            });
        }
        if self.eat(b'J').is_some() {
            return self.number(365).filter(|n| *n >= 1).map(Day::Julian);
        }
        self.number(365).map(Day::Ordinal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rule: &str, y: i32, mo: u32, d: u32, h: u32, mi: u32) -> Option<i64> {
        let naive = NaiveDate::from_ymd_opt(y, mo, d)?.and_hms_opt(h, mi, 0)?;
        Rule::posix(rule).unwrap().to_ms(naive)
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> Option<i64> {
        at("UTC0", y, mo, d, h, mi)
    }

    const PARIS: &str = "CET-1CEST,M3.5.0,M10.5.0/3";

    #[test]
    fn european_summer_time() {
        // Winter is UTC+1, summer UTC+2.
        assert_eq!(at(PARIS, 2026, 1, 15, 12, 0), utc(2026, 1, 15, 11, 0));
        assert_eq!(at(PARIS, 2026, 7, 15, 12, 0), utc(2026, 7, 15, 10, 0));
        // 2026-03-29 (last Sunday of March): 02:00-03:00 does not exist.
        assert_eq!(at(PARIS, 2026, 3, 29, 1, 59), utc(2026, 3, 29, 0, 59));
        assert_eq!(at(PARIS, 2026, 3, 29, 2, 30), None);
        assert_eq!(at(PARIS, 2026, 3, 29, 3, 0), utc(2026, 3, 29, 1, 0));
        // 2026-10-25: 02:00-03:00 happens twice; the first (summer) one is taken.
        assert_eq!(at(PARIS, 2026, 10, 25, 2, 30), utc(2026, 10, 25, 0, 30));
        assert_eq!(at(PARIS, 2026, 10, 25, 3, 0), utc(2026, 10, 25, 2, 0));
        assert_eq!(at(PARIS, 2026, 10, 25, 1, 59), utc(2026, 10, 24, 23, 59));
    }

    #[test]
    fn other_rule_shapes() {
        // US: second Sunday of March to first Sunday of November, at 02:00 by default.
        let ny = "EST5EDT,M3.2.0,M11.1.0";
        assert_eq!(at(ny, 2026, 1, 1, 0, 0), utc(2026, 1, 1, 5, 0));
        assert_eq!(at(ny, 2026, 3, 8, 2, 30), None);
        assert_eq!(at(ny, 2026, 7, 4, 12, 0), utc(2026, 7, 4, 16, 0));
        // Southern hemisphere: DST spans the new year (Sydney, UTC+10/+11).
        let syd = "AEST-10AEDT,M10.1.0,M4.1.0/3";
        assert_eq!(at(syd, 2026, 1, 15, 12, 0), utc(2026, 1, 15, 1, 0));
        assert_eq!(at(syd, 2026, 7, 15, 12, 0), utc(2026, 7, 15, 2, 0));
        // Quoted names, no DST, half hours.
        assert_eq!(at("<-03>3", 2026, 7, 1, 9, 0), utc(2026, 7, 1, 12, 0));
        assert_eq!(at("IST-5:30", 2026, 7, 1, 12, 0), utc(2026, 7, 1, 6, 30));
        // Julian and zero-based days, and an explicit DST offset (Lord Howe: +10:30/+11).
        let j = "AAA-1BBB,J60,J300";
        assert_eq!(at(j, 2028, 3, 1, 12, 0), utc(2028, 3, 1, 10, 0)); // J60 is March 1, also in a leap year
        assert_eq!(at(j, 2028, 2, 29, 12, 0), utc(2028, 2, 29, 11, 0));
        assert_eq!(
            at("AAA-1BBB,59,300", 2028, 2, 29, 12, 0),
            utc(2028, 2, 29, 10, 0)
        );
        let lhi = "<+1030>-10:30<+11>-11,M10.1.0,M4.1.0";
        assert_eq!(at(lhi, 2026, 7, 1, 12, 0), utc(2026, 7, 1, 1, 30));
        assert_eq!(at(lhi, 2026, 1, 1, 12, 0), utc(2026, 1, 1, 1, 0));
    }

    #[test]
    fn malformed_rules_are_refused() {
        for bad in [
            "",
            "C-1",
            "CET",
            "CET-1CEST",
            "CET-1CEST,M3.5.0",
            "CET-1CEST,M13.5.0,M10.5.0",
            "CET-1CEST,M3.6.0,M10.5.0",
            "CET-1CEST,M3.5.7,M10.5.0",
            "CET-1CEST,J0,J5",
            "CET-25",
            "CET-1 junk",
            "<+03-3",
            "CET-1CEST,M3.5.0,M10.5.0/200",
        ] {
            assert!(Rule::posix(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_are_looked_up_safely() {
        for bad in [
            "GMT+1",
            "Europe/../../etc/passwd",
            "/etc/passwd",
            "Nowhere/Atlantis",
            "",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Rule::parse(PARIS), Rule::posix(PARIS));
    }

    #[test]
    fn zone_files_give_their_footer_rule() {
        let mut file = b"TZif2\0\0\0binary\n\x0a\xffdata\n".to_vec();
        file.extend_from_slice(b"CET-1CEST,M3.5.0,M10.5.0/3\n");
        assert_eq!(footer(&file), Some(PARIS));
        assert_eq!(
            footer(b"TZif\0data\nCET-1\n"),
            None,
            "version 1 has no footer"
        );
        assert_eq!(footer(b"TZif2data\n\n"), None);
        assert_eq!(footer(b"nope\nCET-1\n"), None);
        // The system's own database, where there is one (CI and most desktops).
        if std::path::Path::new(ZONEINFO).join("Europe/Paris").exists() {
            assert_eq!(
                Rule::parse("Europe/Paris"),
                Rule::parse(PARIS),
                "the current French rule"
            );
        }
    }
}
