//! Pattern alerts put on mute for a while, from the web UI or `POST /api/mutes`: while a rule is
//! muted its notifications are still logged and recorded in the alert history (marked `muted`), but
//! the webhook and e-mail are not told. Mutes live in memory until they end or LogPit restarts, like
//! the maintenance windows started through the API, and there are at most [`MAX_MUTES`] of them.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

pub const MAX_MUTES: usize = 200;
/// Longest mute, in minutes: a week, as for maintenance windows.
pub const MAX_MINUTES: u32 = crate::maintenance::MAX_MINUTES;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Mute {
    pub rule: String,
    /// Unix ms when it ends.
    pub until: i64,
}

#[derive(Default)]
pub struct Mutes(Mutex<HashMap<String, i64>>);

impl Mutes {
    /// Mutes `rule` until `until` (replacing an earlier mute of it). False when there are already
    /// [`MAX_MUTES`] other live mutes.
    pub fn set(&self, rule: &str, until: i64, now: i64) -> bool {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, end| *end > now);
        if map.len() >= MAX_MUTES && !map.contains_key(rule) {
            return false;
        }
        map.insert(rule.to_string(), until);
        true
    }

    /// Ends the mute of `rule`; false when it was not muted.
    pub fn clear(&self, rule: &str, now: i64) -> bool {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(rule).is_some_and(|end| end > now)
    }

    /// When the mute of `rule` ends, if it is muted at `now`.
    pub fn muting(&self, rule: &str, now: i64) -> Option<i64> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.get(rule).copied().filter(|end| *end > now)
    }

    /// The live mutes, soonest end first.
    pub fn list(&self, now: i64) -> Vec<Mute> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<Mute> = map
            .iter()
            .filter(|(_, end)| **end > now)
            .map(|(rule, until)| Mute {
                rule: rule.clone(),
                until: *until,
            })
            .collect();
        out.sort_by(|a, b| a.until.cmp(&b.until).then_with(|| a.rule.cmp(&b.rule)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutes_end_by_themselves_and_stay_bounded() {
        let m = Mutes::default();
        assert!(m.set("disk", 1000, 0));
        assert_eq!(m.muting("disk", 999), Some(1000));
        assert_eq!(m.muting("disk", 1000), None, "it ends at its end");
        assert_eq!(m.muting("other", 0), None);
        assert!(
            m.set("disk", 5000, 0),
            "a new mute replaces the earlier one"
        );
        assert_eq!(
            m.list(0),
            [Mute {
                rule: "disk".into(),
                until: 5000
            }]
        );
        assert!(m.clear("disk", 0));
        assert!(!m.clear("disk", 0));
        for i in 0..MAX_MUTES {
            assert!(m.set(&format!("r{i}"), 100, 0));
        }
        assert!(!m.set("one more", 100, 0));
        assert!(
            m.set("r0", 200, 0),
            "an existing mute can still be extended"
        );
        // Ended mutes make room again.
        assert!(m.set("one more", 300, 150));
        assert_eq!(m.list(150).len(), 2);
    }
}
