//! A persistent sliding window over an explicit, stable host-defined scope.

use super::{CheckCtx, CompiledCheck, PolicyDecision};
use xolotl_types::{Failure, IdentityRef, Path, Value};

/// Admit at most `max_per_window` checks within a sliding time window.
///
/// The host selects a stable logical scope, such as a concrete resource path or
/// tenant API name. All checks with the same scope, backend and acting identity
/// share one account, independently of local ResourceId assignment. Use separate
/// scopes for independent policies. Revisions of the window require explicit state
/// migration or a new scope; a changed window never silently forgets retained hits.
/// This counts policy evaluations, including later denials by another residual.
pub struct RateLimitCheck {
    scope: String,
    max_per_window: u32,
    window_millis: i64,
    state: xolotl_state::Backend,
}

impl RateLimitCheck {
    /// Select the account scope and state backend. Scope must contain 1–512 UTF-8
    /// bytes and not be blank; the window must be positive. Zero admissions is a
    /// valid limit. This constructor performs no backend I/O.
    pub fn new(
        scope: impl Into<String>,
        max_per_window: u32,
        window_millis: i64,
        state: xolotl_state::Backend,
    ) -> Result<Self, Failure> {
        let scope = scope.into();
        if scope.trim().is_empty() || scope.len() > 512 || window_millis <= 0 {
            return Err(Failure::InvalidInput { reason: "rate-limit scope must be nonblank and at most 512 bytes; window must be positive".into() });
        }
        Ok(Self {
            scope,
            max_per_window,
            window_millis,
            state,
        })
    }
}

#[async_trait::async_trait]
impl CompiledCheck for RateLimitCheck {
    async fn evaluate(&self, ctx: &CheckCtx) -> PolicyDecision {
        let path = match rate_limit_path(&self.scope, ctx.acting) {
            Ok(path) => path,
            Err(e) => {
                return PolicyDecision::Deny {
                    reason: format!("rate limit path invalid: {e}"),
                };
            }
        };

        for _ in 0..RATE_LIMIT_CAS_ATTEMPTS {
            let current = match self.state.read(&path).await {
                Ok(value) => value,
                Err(e) => {
                    return PolicyDecision::Deny {
                        reason: format!("rate limit state read failed: {e}"),
                    };
                }
            };
            let mut hits = match decode_rate_hits(current.as_ref(), self.window_millis) {
                Ok(hits) => hits,
                Err(reason) => {
                    return PolicyDecision::Deny {
                        reason: format!("rate limit state malformed: {reason}"),
                    };
                }
            };

            // Evict timestamps that have slid out of the window, then normalize
            // storage order so the durable value remains deterministic.
            if let Some(cutoff) = ctx.now_millis.checked_sub(self.window_millis) {
                hits.retain(|&timestamp| timestamp > cutoff);
            }
            hits.sort_unstable();

            if hits.len() >= self.max_per_window as usize {
                let new = encode_rate_hits(&hits, self.window_millis);
                if current.as_ref() == Some(&new) {
                    return PolicyDecision::Deny {
                        reason: "rate limit exceeded".into(),
                    };
                }
                match self.state.write_cas(&path, current, new).await {
                    Ok(_commit) => {
                        return PolicyDecision::Deny {
                            reason: "rate limit exceeded".into(),
                        };
                    }
                    Err(xolotl_state::StateFailure {
                        error: xolotl_state::StateError::CasFailed { .. },
                        ..
                    }) => continue,
                    Err(e) => {
                        return PolicyDecision::Deny {
                            reason: format!("rate limit state write failed: {e}"),
                        };
                    }
                }
            }

            hits.push(ctx.now_millis);
            hits.sort_unstable();
            let new = encode_rate_hits(&hits, self.window_millis);
            match self.state.write_cas(&path, current, new).await {
                Ok(_commit) => return PolicyDecision::Allow,
                Err(xolotl_state::StateFailure {
                    error: xolotl_state::StateError::CasFailed { .. },
                    ..
                }) => continue,
                Err(e) => {
                    return PolicyDecision::Deny {
                        reason: format!("rate limit state write failed: {e}"),
                    };
                }
            }
        }

        PolicyDecision::Deny {
            reason: "rate limit state contention".into(),
        }
    }
    fn name(&self) -> &'static str {
        "rate_limit"
    }
}

const RATE_LIMIT_CAS_ATTEMPTS: usize = 16;

pub(super) fn rate_limit_path(
    scope: &str,
    acting: IdentityRef,
) -> Result<Path, xolotl_types::PathError> {
    let key = blake3::derive_key("xolotl.policy.rate-limit.scope.v1", scope.as_bytes());
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("ratelimit")?
        .try_push_literal(blake3::Hash::from(key).to_hex().as_str())?
        .try_push_literal(format!("identity:{}", acting.get()))
}

fn decode_rate_hits(value: Option<&Value>, window: i64) -> Result<Vec<i64>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let fields = value.as_map().ok_or("expected a rate-limit record")?;
    if fields.len() != 3 || fields.get("version").and_then(Value::as_int) != Some(1) {
        return Err("invalid rate-limit record format".into());
    }
    if fields.get("window_millis").and_then(Value::as_int) != Some(window) {
        return Err(
            "rate-limit window changed; select a new scope or explicitly migrate its state".into(),
        );
    }
    let hits = fields
        .get("hits")
        .and_then(Value::as_list)
        .ok_or("missing rate-limit timestamp list")?;
    hits.iter()
        .map(|value| {
            value
                .as_int()
                .ok_or_else(|| "expected integer timestamp".into())
        })
        .collect()
}

fn encode_rate_hits(hits: &[i64], window: i64) -> Value {
    Value::map(std::collections::BTreeMap::from([
        ("version".into(), Value::integer(1)),
        ("window_millis".into(), Value::integer(window)),
        (
            "hits".into(),
            Value::list(hits.iter().copied().map(Value::integer).collect()),
        ),
    ]))
}

#[cfg(test)]
mod tests;
