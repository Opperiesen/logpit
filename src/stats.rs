//! Time-bucketed counts for `/api/stats`: bucket sizing, gap filling and group folding.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

/// Upper bound on buckets in one response.
pub const MAX_BUCKETS: i64 = 2000;
/// Groups kept per response; the rest are folded into [`OTHER`].
pub const MAX_GROUPS: usize = 10;
pub const OTHER: &str = "other";

/// Bucket sizes tried by [`auto_bucket_ms`], smallest first.
const AUTO_SIZES_MS: [i64; 12] = [
    10_000,
    30_000,
    60_000,
    300_000,
    900_000,
    1_800_000,
    3_600_000,
    10_800_000,
    21_600_000,
    43_200_000,
    86_400_000,
    604_800_000,
];

/// The smallest standard bucket that keeps the range within about 120 buckets.
pub fn auto_bucket_ms(span_ms: i64) -> i64 {
    AUTO_SIZES_MS
        .into_iter()
        .find(|b| span_ms / b <= 120)
        .unwrap_or(AUTO_SIZES_MS[AUTO_SIZES_MS.len() - 1])
}

/// A bucket size in milliseconds, at least one second: a bare number of seconds (`90`) or a
/// duration as LogQL writes them (`30s`, `5m`, `1h30m`, `1d`).
pub fn parse_bucket_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let ms = if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse::<i64>().ok()?.checked_mul(1000)?
    } else {
        crate::logql::parse_duration_ms(s)?
    };
    (ms >= 1000).then_some(ms)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Bucket {
    /// Start of the bucket, Unix ms.
    pub ts: i64,
    pub total: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Stats {
    pub bucket_ms: i64,
    pub since: i64,
    pub until: i64,
    /// Group names, largest first (`other` last), when grouping.
    pub keys: Vec<String>,
    pub buckets: Vec<Bucket>,
}

/// Builds the response from sparse `(bucket_start, group, count)` rows: every bucket in
/// `since..=until` is present (zero-filled), and only the [`MAX_GROUPS`] largest groups are
/// kept, the rest being summed into `other`.
pub fn assemble(
    rows: Vec<(i64, String, u64)>,
    since: i64,
    until: i64,
    bucket_ms: i64,
    grouped: bool,
) -> Stats {
    let mut keys = Vec::new();
    let mut fold = HashMap::new();
    if grouped {
        let mut totals: HashMap<&str, u64> = HashMap::new();
        for (_, g, n) in &rows {
            *totals.entry(g).or_default() += n;
        }
        let mut ranked: Vec<(&str, u64)> = totals.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        keys = ranked
            .iter()
            .take(MAX_GROUPS)
            .map(|(g, _)| g.to_string())
            .collect();
        fold = ranked
            .iter()
            .skip(MAX_GROUPS)
            .map(|(g, _)| (g.to_string(), ()))
            .collect::<HashMap<_, _>>();
        if !fold.is_empty() {
            keys.push(OTHER.to_string());
        }
    }

    let first = since.div_euclid(bucket_ms) * bucket_ms;
    let last = until.div_euclid(bucket_ms) * bucket_ms;
    let mut buckets: BTreeMap<i64, Bucket> = (0..=(last - first) / bucket_ms)
        .map(|i| {
            let ts = first + i * bucket_ms;
            (
                ts,
                Bucket {
                    ts,
                    total: 0,
                    groups: BTreeMap::new(),
                },
            )
        })
        .collect();
    for (ts, group, n) in rows {
        let Some(b) = buckets.get_mut(&ts) else {
            continue;
        };
        b.total += n;
        if grouped {
            let key = if fold.contains_key(&group) {
                OTHER.to_string()
            } else {
                group
            };
            *b.groups.entry(key).or_default() += n;
        }
    }
    Stats {
        bucket_ms,
        since,
        until,
        keys,
        buckets: buckets.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_parsing() {
        assert_eq!(parse_bucket_ms("90"), Some(90_000));
        assert_eq!(parse_bucket_ms("30s"), Some(30_000));
        assert_eq!(parse_bucket_ms("5m"), Some(300_000));
        assert_eq!(parse_bucket_ms("2h"), Some(7_200_000));
        assert_eq!(parse_bucket_ms("1d"), Some(86_400_000));
        assert_eq!(parse_bucket_ms("1h30m"), Some(5_400_000));
        for bad in [
            "",
            "0",
            "0s",
            "m",
            "5x",
            "-5m",
            "500ms",
            "99999999999999999999",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_bucket_ms(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn auto_bucket_keeps_about_120_buckets() {
        assert_eq!(auto_bucket_ms(3_600_000), 30_000); // 1 h
        assert_eq!(auto_bucket_ms(900_000), 10_000); // 15 min
        assert_eq!(auto_bucket_ms(86_400_000), 900_000); // 24 h
        assert_eq!(auto_bucket_ms(7 * 86_400_000), 3_600_000 * 3); // 7 d
        assert_eq!(auto_bucket_ms(i64::MAX / 2), 604_800_000);
    }

    #[test]
    fn gaps_are_zero_filled() {
        let s = assemble(
            vec![(60_000, String::new(), 3), (180_000, String::new(), 1)],
            70_000,
            200_000,
            60_000,
            false,
        );
        let seen: Vec<(i64, u64)> = s.buckets.iter().map(|b| (b.ts, b.total)).collect();
        assert_eq!(seen, vec![(60_000, 3), (120_000, 0), (180_000, 1)]);
        assert!(s.keys.is_empty() && s.buckets[0].groups.is_empty());
    }

    #[test]
    fn small_groups_fold_into_other() {
        let rows: Vec<_> = (0..13)
            .map(|i| (0, format!("h{i:02}"), 100 - i as u64))
            .collect();
        let s = assemble(rows, 0, 0, 1000, true);
        assert_eq!(s.keys.len(), MAX_GROUPS + 1);
        assert_eq!(s.keys[0], "h00");
        assert_eq!(s.keys.last().unwrap(), OTHER);
        let b = &s.buckets[0];
        assert_eq!(b.groups[OTHER], 100 - 10 + 100 - 11 + 100 - 12);
        assert_eq!(b.groups.len(), MAX_GROUPS + 1);
        assert_eq!(b.total, b.groups.values().sum::<u64>());
    }

    #[test]
    fn few_groups_have_no_other() {
        let s = assemble(
            vec![(0, "a".into(), 2), (0, "b".into(), 5)],
            0,
            0,
            1000,
            true,
        );
        assert_eq!(s.keys, vec!["b", "a"]);
    }
}
