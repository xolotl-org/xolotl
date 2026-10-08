//! Persisted account lockout and backoff policy.

use xolotl_types::Value;

/// Account lockout state persisted at `state://vault/console/lockouts/<u>`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct LockoutState {
    pub consecutive_failures: u32,
    pub locked_until_ms: i64,
}

/// Exponential backoff: after `threshold` consecutive failures the account is
/// locked for `base_ms * 2^(failures - threshold)`, capped at `max_ms`.
pub(crate) fn lockout_until_ms(
    consecutive_failures: u32,
    threshold: u32,
    base_ms: i64,
    max_ms: i64,
    now_ms: i64,
) -> i64 {
    if consecutive_failures < threshold {
        return 0;
    }
    let exponent = (consecutive_failures - threshold).min(10);
    let backoff = base_ms.saturating_mul(1i64 << exponent);
    now_ms + backoff.min(max_ms)
}

impl LockoutState {
    pub(crate) fn is_locked(&self, now_ms: i64) -> bool {
        self.locked_until_ms > now_ms
    }

    pub(crate) fn remaining_ms(&self, now_ms: i64) -> i64 {
        (self.locked_until_ms - now_ms).max(0)
    }
}

/// Serialize the account-lockout policy and an example backoff schedule to a
/// [`Value`] map for descriptor output.
pub(crate) fn lockout_policy_to_value(threshold: u32, base_ms: i64, max_ms: i64) -> Value {
    let now = 0;
    let mut schedule = Vec::new();
    for failures in [threshold, threshold + 1, threshold + 3, threshold + 6] {
        let locked_until = lockout_until_ms(failures, threshold, base_ms, max_ms, now);
        let state = LockoutState {
            consecutive_failures: failures,
            locked_until_ms: locked_until,
        };
        let mut row = std::collections::BTreeMap::new();
        row.insert(
            "consecutive_failures".into(),
            Value::integer(failures as i64),
        );
        row.insert(
            "locked_for_ms".into(),
            Value::integer(state.remaining_ms(now)),
        );
        schedule.push(Value::map(row));
    }
    let mut map = std::collections::BTreeMap::new();
    map.insert("threshold".into(), Value::integer(threshold as i64));
    map.insert("base_ms".into(), Value::integer(base_ms));
    map.insert("max_ms".into(), Value::integer(max_ms));
    map.insert("schedule".into(), Value::list(schedule));
    Value::map(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_backoff_is_exponential_and_capped() {
        let now = 1_000_000;
        assert_eq!(lockout_until_ms(2, 5, 1000, 60_000, now), 0);
        assert_eq!(lockout_until_ms(5, 5, 1000, 60_000, now), now + 1000);
        assert_eq!(lockout_until_ms(6, 5, 1000, 60_000, now), now + 2000);
        assert_eq!(lockout_until_ms(8, 5, 1000, 60_000, now), now + 8000);
        assert_eq!(lockout_until_ms(20, 5, 1000, 60_000, now), now + 60_000);
    }

    #[test]
    fn lockout_state_predicate() {
        let state = LockoutState {
            consecutive_failures: 5,
            locked_until_ms: 2000,
        };
        assert!(state.is_locked(1000));
        assert!(!state.is_locked(2000));
        assert_eq!(state.remaining_ms(1500), 500);
        assert_eq!(state.remaining_ms(3000), 0);
    }
}
