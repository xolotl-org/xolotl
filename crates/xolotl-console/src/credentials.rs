//! Backend-enforced password policy and account lockout helpers. The policy is
//! checked server-side on every password set/change so a client cannot submit a
//! weak password. Account lockout is a persisted, exponential backoff gate so
//! repeated failures throttle the account regardless of source address.

use xolotl_types::Value;

/// Server-enforced password strength policy. Fields have security lower bounds
/// enforced by [`PasswordPolicy::bounded`]; a policy below the floor is
/// rejected so misconfiguration cannot weaken the floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub min_entropy_bits: u8,
    pub max_common_password_matches: u32,
}

/// Absolute security floor. `bounded` never returns a policy weaker than this.
pub const PASSWORD_MIN_LENGTH_FLOOR: usize = 12;
pub const PASSWORD_MIN_ENTROPY_FLOOR: u8 = 30;
pub const PASSWORD_MAX_LENGTH: usize = 1024;

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 14,
            min_entropy_bits: 42,
            max_common_password_matches: 0,
        }
    }
}

impl PasswordPolicy {
    /// Clamp the policy to at least the security floor.
    pub fn bounded(self) -> Self {
        Self {
            min_length: self.min_length.max(PASSWORD_MIN_LENGTH_FLOOR),
            min_entropy_bits: self.min_entropy_bits.max(PASSWORD_MIN_ENTROPY_FLOOR),
            max_common_password_matches: self.max_common_password_matches,
        }
    }
}

/// Reason a password was rejected by the policy.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasswordPolicyError {
    #[error("password is shorter than the minimum length of {min}")]
    TooShort { min: usize },
    #[error("password is longer than the maximum length of {max}")]
    TooLong { max: usize },
    #[error("password entropy estimate ({got} bits) is below the minimum of {min} bits")]
    LowEntropy { got: u8, min: u8 },
    #[error("password contains the account identifier fragment {fragment:?}")]
    ContainsIdentifier { fragment: String },
    #[error("password matches a known weak/common password")]
    CommonPassword,
}

/// Enforce the policy against a candidate password for a given account
/// identifier (username). The identifier and its fragments are rejected as
/// substrings (case-insensitive) to block the most common guessable pattern.
pub fn enforce_password_strength(
    policy: &PasswordPolicy,
    identifier: &str,
    password: &str,
) -> Result<(), PasswordPolicyError> {
    let length = password.chars().count();
    if length < policy.min_length {
        return Err(PasswordPolicyError::TooShort {
            min: policy.min_length,
        });
    }
    if length > PASSWORD_MAX_LENGTH {
        return Err(PasswordPolicyError::TooLong {
            max: PASSWORD_MAX_LENGTH,
        });
    }
    if estimate_entropy_bits(password) < policy.min_entropy_bits {
        return Err(PasswordPolicyError::LowEntropy {
            got: estimate_entropy_bits(password),
            min: policy.min_entropy_bits,
        });
    }
    check_identifier_fragments(identifier, password)?;
    if is_common_password(password) {
        return Err(PasswordPolicyError::CommonPassword);
    }
    Ok(())
}

/// Rough entropy estimate: bounded by both length and distinct-symbol
/// diversity so low-diversity passwords (long runs, few unique chars) score
/// low regardless of length. This is a fast heuristic gate, not a precise
/// entropy calculation — the goal is to reject low-diversity passwords.
pub fn estimate_entropy_bits(password: &str) -> u8 {
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return 0;
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for ch in &chars {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if !ch.is_whitespace() {
            has_symbol = true;
        }
    }
    let mut pool: u32 = 0;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 32;
    }
    if pool == 0 {
        return 0;
    }
    let per_char = (pool as f64).log2();
    let length_entropy = per_char * (chars.len() as f64);
    let mut distinct = std::collections::HashSet::new();
    for ch in &chars {
        distinct.insert(ch.to_ascii_lowercase());
    }
    let diversity_entropy = per_char * (distinct.len() as f64);
    let estimate = length_entropy.min(diversity_entropy) - repeated_char_penalty(&chars);
    estimate.clamp(0.0, 128.0) as u8
}

fn repeated_char_penalty(chars: &[char]) -> f64 {
    let mut run_penalty = 0.0_f64;
    let mut run = 1usize;
    for window in chars.windows(2) {
        if window[0].eq_ignore_ascii_case(&window[1]) {
            run += 1;
        } else {
            if run >= 3 {
                run_penalty += (run as f64) * 1.5;
            }
            run = 1;
        }
    }
    if run >= 3 {
        run_penalty += (run as f64) * 1.5;
    }
    run_penalty
}

fn check_identifier_fragments(identifier: &str, password: &str) -> Result<(), PasswordPolicyError> {
    let lower_pw = password.to_lowercase();
    for fragment in identifier_fragments(identifier) {
        if fragment.len() >= 4 && lower_pw.contains(&fragment.to_lowercase()) {
            return Err(PasswordPolicyError::ContainsIdentifier { fragment });
        }
    }
    Ok(())
}

fn identifier_fragments(identifier: &str) -> Vec<String> {
    identifier
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// A small built-in denylist of the most common passwords. Matches both exact
/// equality and containment of a long common token (>= 7 chars), so derived
/// forms like `password12345678!` are rejected. This is not a substitute for a
/// breach-corpus check, but blocks the trivially weak cases without an external
/// dependency.
fn is_common_password(password: &str) -> bool {
    const COMMON: &[&str] = &[
        "password",
        "password123",
        "password1234",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "abc123",
        "abcdef",
        "letmein",
        "welcome",
        "welcome1",
        "admin",
        "admin123",
        "root",
        "root123",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "baseball",
        "sunshine",
        "princess",
        "changeme",
        "changeme123",
        "passw0rd",
        "p@ssw0rd",
        "p@ssword",
    ];
    let lower = password.to_lowercase();
    COMMON
        .iter()
        .any(|common| lower == *common || (common.len() >= 7 && lower.contains(common)))
}

/// Serialize a password policy to a [`Value`] map for descriptor/config output.
pub fn password_policy_to_value(policy: &PasswordPolicy) -> Value {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "min_length".into(),
        Value::integer(policy.min_length as i64),
    );
    map.insert(
        "min_entropy_bits".into(),
        Value::integer(i64::from(policy.min_entropy_bits)),
    );
    map.insert(
        "max_common_password_matches".into(),
        Value::integer(policy.max_common_password_matches as i64),
    );
    map.insert(
        "min_length_floor".into(),
        Value::integer(PASSWORD_MIN_LENGTH_FLOOR as i64),
    );
    map.insert(
        "min_entropy_floor".into(),
        Value::integer(i64::from(PASSWORD_MIN_ENTROPY_FLOOR)),
    );
    map.insert(
        "max_length".into(),
        Value::integer(PASSWORD_MAX_LENGTH as i64),
    );
    Value::map(map)
}

/// Account lockout state persisted at `state://kernel/console/users/<u>/lockout`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockoutState {
    pub consecutive_failures: u32,
    pub locked_until_ms: i64,
}

/// Exponential backoff: after `threshold` consecutive failures the account is
/// locked for `base_ms * 2^(failures - threshold)`, capped at `max_ms`.
pub fn lockout_until_ms(
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
    pub fn is_locked(&self, now_ms: i64) -> bool {
        self.locked_until_ms > now_ms
    }

    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        (self.locked_until_ms - now_ms).max(0)
    }
}

/// Serialize the account-lockout policy and an example backoff schedule to a
/// [`Value`] map for descriptor output.
pub fn lockout_policy_to_value(threshold: u32, base_ms: i64, max_ms: i64) -> Value {
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
    use anyhow::ensure;

    #[test]
    fn bounded_policy_enforces_floor() {
        let weak = PasswordPolicy {
            min_length: 4,
            min_entropy_bits: 4,
            max_common_password_matches: 0,
        }
        .bounded();
        assert_eq!(weak.min_length, PASSWORD_MIN_LENGTH_FLOOR);
        assert_eq!(weak.min_entropy_bits, PASSWORD_MIN_ENTROPY_FLOOR);
    }

    #[test]
    fn rejects_short_password() -> anyhow::Result<()> {
        let policy = PasswordPolicy::default().bounded();
        let err = match enforce_password_strength(&policy, "alice", "short1!") {
            Err(err) => err,
            Ok(()) => anyhow::bail!("short password was accepted"),
        };
        ensure!(
            matches!(err, PasswordPolicyError::TooShort { .. }),
            "expected TooShort, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_username_fragment() -> anyhow::Result<()> {
        let policy = PasswordPolicy::default().bounded();
        let pw = "alice-secret-phrase-X9q";
        let err = match enforce_password_strength(&policy, "alice", pw) {
            Err(err) => err,
            Ok(()) => anyhow::bail!("username-fragment password was accepted"),
        };
        ensure!(
            matches!(err, PasswordPolicyError::ContainsIdentifier { .. }),
            "expected ContainsIdentifier, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_common_password() -> anyhow::Result<()> {
        let policy = PasswordPolicy::default().bounded();
        let err = match enforce_password_strength(&policy, "bob", "password12345678!") {
            Err(err) => err,
            Ok(()) => anyhow::bail!("common password was accepted"),
        };
        ensure!(
            matches!(err, PasswordPolicyError::CommonPassword),
            "expected CommonPassword, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_low_entropy_runs() -> anyhow::Result<()> {
        let policy = PasswordPolicy::default().bounded();
        let pw = "aaaaaaaaaaaaaaX1!";
        let err = match enforce_password_strength(&policy, "carol", pw) {
            Err(err) => err,
            Ok(()) => anyhow::bail!("low-entropy password was accepted"),
        };
        ensure!(
            matches!(err, PasswordPolicyError::LowEntropy { .. }),
            "expected LowEntropy, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accepts_strong_password() -> anyhow::Result<()> {
        let policy = PasswordPolicy::default().bounded();
        enforce_password_strength(&policy, "dave", "correct-horse-battery-9qL!")
            .map_err(|e| anyhow::anyhow!("strong password was rejected: {e}"))?;
        Ok(())
    }

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
