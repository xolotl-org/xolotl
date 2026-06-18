//! `Policy` → `PolicySnapshot`: source policy compiles, partially
//! evaluates, and leaves only *residual* [`CompiledCheck`]s for the hot path.
//!
//! Anything decidable at `open()` (does this identity may-read this path?) is
//! evaluated and **eliminated** there. Only input-dependent checks (budget,
//! redaction, input predicates, command match, rate limit) remain. If the
//! residual is empty, the Handle is marked `Unconditional` and the data
//! plane skips policy entirely.
//!
//! A [`PolicySource`] is the slow-path object an operator registers; it
//! compiles against an [`OpenContext`] into a residual snapshot. The kernel's
//! [`Registry`](crate::registry::Registry) holds the registered sources, and
//! `open()` runs every source whose selector matches the resource, merging
//! their residuals.

use nexus_types::{Capability, ConstraintSet, IdentityRef, Path, ResourceId, Rights, Value};
use std::sync::Arc;

/// The verdict of a policy / one check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    /// Residual checks allowed the operation to proceed.
    Allow,
    /// Requires human confirmation. Carries the approval key.
    Ask {
        /// Stable key used by the approval broker to correlate a decision.
        approval_key: String,
        /// Operator-facing reason for the approval request.
        reason: String,
    },
    /// Policy rejected the operation.
    Deny {
        /// Human-readable denial reason.
        reason: String,
    },
}

impl PolicyDecision {
    /// Whether this decision is [`PolicyDecision::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// What `open()` knows when compiling a policy: everything fixed at open
/// time, so decidable checks can be evaluated and eliminated now.
pub struct OpenContext<'a> {
    /// Resource being opened.
    pub resource: ResourceId,
    /// The resource's address (for path-based policy matching).
    pub resource_path: &'a Path,
    /// The verb the open is for (`read`/`perform`/`write`/…).
    pub verb: &'a str,
    /// The rights being granted on this handle.
    pub rights: Rights,
    /// The identity the holder will act as.
    pub acting: IdentityRef,
    /// Wall clock at open (for static time-window evaluation).
    pub now_millis: i64,
}

/// Errors returned while compiling a source policy at open time.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCompileError {
    /// The policy denied the open before a handle could be created.
    #[error("policy denied at open: {0}")]
    DeniedAtOpen(String),
}

/// A registered source policy. It is arbitrarily complex but **never on
/// the hot path**: it compiles once at `open()` into a residual snapshot,
/// partially evaluating away everything the [`OpenContext`] already decides.
pub trait PolicySource: Send + Sync + 'static {
    /// Whether this policy applies to the resource being opened. Cheap; called
    /// for every registered policy at open.
    fn applies_to(&self, ctx: &OpenContext) -> bool;
    /// Compile to a residual snapshot, partially evaluating. Returning an empty
    /// snapshot means "fully satisfied at open" (contributes nothing to the hot
    /// path); returning `Err(DeniedAtOpen)` rejects the open outright.
    fn compile(&self, ctx: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError>;
}

/// The request context a residual check evaluates against (the runtime view of
/// an operation — input + acting + wall clock + target resource).
pub struct CheckCtx<'a> {
    /// Operation input being evaluated.
    pub input: &'a Value,
    /// Identity the operation acts as.
    pub acting: nexus_types::IdentityRef,
    /// Wall clock timestamp used for time-dependent residual checks.
    pub now_millis: i64,
    /// The resource the operation targets.
    pub target: ResourceId,
}

/// One residual check. Every policy type — capability predicates,
/// budget settlement, redaction, rate limit, approval, command match —
/// is an instance of this. Sequentially evaluated only for `Conditional`
/// handles; `Unconditional` handles carry none.
#[async_trait::async_trait]
pub trait CompiledCheck: Send + Sync + 'static {
    /// Evaluate this residual check against one operation.
    async fn evaluate(&self, ctx: &CheckCtx) -> PolicyDecision;
    /// Short name for trace/why-not projections.
    fn name(&self) -> &'static str;
}

/// A compiled, frozen policy attached to a `Conditional` handle. It is the
/// payload of `FastPath::Conditional`; an `Unconditional` handle has no
/// `PolicySnapshot` at all, so "zero policy cost" is a structural fact.
#[derive(Clone)]
pub struct PolicySnapshot {
    checks: Arc<Vec<Arc<dyn CompiledCheck>>>,
}

impl PolicySnapshot {
    /// Create a policy snapshot from residual checks.
    pub fn new(checks: Vec<Arc<dyn CompiledCheck>>) -> Self {
        Self {
            checks: Arc::new(checks),
        }
    }

    /// Create an empty residual snapshot.
    pub fn empty() -> Self {
        Self {
            checks: Arc::new(Vec::new()),
        }
    }

    /// Whether the residual is empty, allowing the handle to be marked
    /// `Unconditional`.
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Number of residual checks in this snapshot.
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Concatenate two residual snapshots, as `open()` does when merging the
    /// residuals of every matching source policy.
    pub fn merge(self, other: PolicySnapshot) -> PolicySnapshot {
        let mut checks: Vec<Arc<dyn CompiledCheck>> = (*self.checks).clone();
        checks.extend(other.checks.iter().cloned());
        PolicySnapshot::new(checks)
    }

    /// Run residual checks in order; the first non-Allow short-circuits.
    pub async fn check(&self, ctx: &CheckCtx<'_>) -> PolicyDecision {
        for c in self.checks.iter() {
            let d = c.evaluate(ctx).await;
            if !d.is_allow() {
                return d;
            }
        }
        PolicyDecision::Allow
    }
}

// Built-in residual checks.

/// A residual constraint-set check: the grant's input predicates that could
/// not be eliminated at open (e.g. `@account=alice`, `@budget<=0.10`). Carries
/// the [`ConstraintSet`] and evaluates it fail-closed against the op input.
pub struct ConstraintCheck {
    /// Constraint predicates to evaluate against operation input.
    pub constraints: ConstraintSet,
}

#[async_trait::async_trait]
impl CompiledCheck for ConstraintCheck {
    async fn evaluate(&self, ctx: &CheckCtx) -> PolicyDecision {
        if self.constraints.eval(ctx.input, ctx.now_millis) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny {
                reason: "input constraint not satisfied".into(),
            }
        }
    }
    fn name(&self) -> &'static str {
        "constraint"
    }
}

/// A residual approval gate: the operation is held until a human
/// approves the `approval_key` out-of-band. It consults a shared
/// [`ApprovalRegistry`] so that once the broker records a decision, re-running
/// the operation resolves: `approved` ⇒ Allow, `denied` ⇒ Deny, otherwise Ask
/// (still pending). Without a registry it is always `Ask` (the simplest gate).
pub struct ApprovalCheck {
    /// Approval correlation key.
    pub approval_key: String,
    /// Reason shown to the approver.
    pub reason: String,
    /// Optional hydrated decision source.
    pub registry: Option<ApprovalRegistry>,
}

impl ApprovalCheck {
    /// A gate that always asks (no resolution source).
    pub fn always(approval_key: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            approval_key: approval_key.into(),
            reason: reason.into(),
            registry: None,
        }
    }

    /// A gate backed by a resolution registry.
    pub fn with_registry(
        approval_key: impl Into<String>,
        reason: impl Into<String>,
        registry: ApprovalRegistry,
    ) -> Self {
        Self {
            approval_key: approval_key.into(),
            reason: reason.into(),
            registry: Some(registry),
        }
    }
}

#[async_trait::async_trait]
impl CompiledCheck for ApprovalCheck {
    async fn evaluate(&self, _ctx: &CheckCtx) -> PolicyDecision {
        match self
            .registry
            .as_ref()
            .and_then(|r| r.decision(&self.approval_key))
        {
            Some(ApprovalDecision::Approved) => PolicyDecision::Allow,
            Some(ApprovalDecision::Denied) => PolicyDecision::Deny {
                reason: format!("approval denied: {}", self.reason),
            },
            // Pending or no record yet → still asking.
            _ => PolicyDecision::Ask {
                approval_key: self.approval_key.clone(),
                reason: self.reason.clone(),
            },
        }
    }
    fn name(&self) -> &'static str {
        "approval"
    }
}

/// A human-approval decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    /// No human decision has been recorded.
    Pending,
    /// Human approved the operation.
    Approved,
    /// Human denied the operation.
    Denied,
}

/// Shared resolution source for [`ApprovalCheck`]. The Approval Broker
/// writes decisions here when a human approves/denies; the residual check reads
/// them on the next execution so a suspended operation can resume. The Approval
/// Broker persists records at `state://kernel/approvals/*`; this registry is the
/// residual check's already-hydrated decision source.
#[derive(Clone, Default)]
pub struct ApprovalRegistry {
    inner: Arc<parking_lot::RwLock<std::collections::HashMap<String, ApprovalDecision>>>,
}

impl ApprovalRegistry {
    /// Create an empty approval decision registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the current decision for an approval key.
    pub fn decision(&self, key: &str) -> Option<ApprovalDecision> {
        self.inner.read().get(key).copied()
    }

    /// Store or replace the decision for an approval key.
    pub fn set(&self, key: impl Into<String>, decision: ApprovalDecision) {
        self.inner.write().insert(key.into(), decision);
    }
}

/// A residual rate-limit check: allow at most `max_per_window`
/// operations per `window_millis`, as a true **sliding window** keyed by
/// `(target, acting)`. The window holds the timestamps of recent admissions;
/// on each call, entries older than `window_millis` are evicted, then the
/// request is admitted iff fewer than `max_per_window` remain.
///
/// Keying by `acting` means a delegated identity gets its own budget; Bob
/// acting as Alice is limited per `(target, Alice)`. The window is stored in
/// `state://kernel/ratelimit/resource:<target>/identity:<acting>`, so a
/// crash/restart preserves the active sliding window.
pub struct RateLimitCheck {
    /// Maximum allowed admissions inside one sliding window.
    pub max_per_window: u32,
    /// Sliding window length in milliseconds.
    pub window_millis: i64,
    state: nexus_state::Backend,
}

impl RateLimitCheck {
    /// Create a rate-limit residual check backed by the state plane.
    pub fn new(max_per_window: u32, window_millis: i64, state: nexus_state::Backend) -> Self {
        Self {
            max_per_window,
            window_millis: window_millis.max(1),
            state,
        }
    }
}

#[async_trait::async_trait]
impl CompiledCheck for RateLimitCheck {
    async fn evaluate(&self, ctx: &CheckCtx) -> PolicyDecision {
        let path = match rate_limit_path(ctx.target, ctx.acting) {
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
            let mut hits = match decode_rate_hits(current.clone()) {
                Ok(hits) => hits,
                Err(reason) => {
                    return PolicyDecision::Deny {
                        reason: format!("rate limit state malformed: {reason}"),
                    };
                }
            };

            // Evict timestamps that have slid out of the window, then normalize
            // storage order so the durable value remains deterministic.
            let cutoff = ctx.now_millis - self.window_millis;
            hits.retain(|&t| t > cutoff);
            hits.sort_unstable();

            if hits.len() as u32 >= self.max_per_window {
                let new = encode_rate_hits(&hits);
                if current.as_ref() == Some(&new) {
                    return PolicyDecision::Deny {
                        reason: "rate limit exceeded".into(),
                    };
                }
                match self.state.write_cas(&path, current, new).await {
                    Ok(()) => {
                        return PolicyDecision::Deny {
                            reason: "rate limit exceeded".into(),
                        };
                    }
                    Err(nexus_state::StateError::CasFailed { .. }) => continue,
                    Err(e) => {
                        return PolicyDecision::Deny {
                            reason: format!("rate limit state write failed: {e}"),
                        };
                    }
                }
            }

            hits.push(ctx.now_millis);
            hits.sort_unstable();
            let new = encode_rate_hits(&hits);
            match self.state.write_cas(&path, current, new).await {
                Ok(()) => return PolicyDecision::Allow,
                Err(nexus_state::StateError::CasFailed { .. }) => continue,
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

fn rate_limit_path(
    target: ResourceId,
    acting: IdentityRef,
) -> Result<Path, nexus_types::PathError> {
    Path::parse(&format!(
        "state://kernel/ratelimit/resource:{}/identity:{}",
        target.get(),
        acting.get()
    ))
}

fn decode_rate_hits(value: Option<Value>) -> Result<Vec<i64>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::List(items)) => {
            let mut hits = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Int(t) => hits.push(t),
                    other => return Err(format!("expected integer timestamp, found {other:?}")),
                }
            }
            Ok(hits)
        }
        Some(other) => Err(format!("expected timestamp list, found {other:?}")),
    }
}

fn encode_rate_hits(hits: &[i64]) -> Value {
    Value::List(hits.iter().copied().map(Value::Int).collect())
}

/// A policy source that attaches a residual [`ConstraintCheck`] for a capability
/// pattern when the open's path matches. The static parts (verb /
/// scheme / segments) are decided at open and eliminated; only the predicate
/// (if any) survives as a residual input check.
pub struct CapabilityPolicy {
    /// Capability pattern this policy source applies to.
    pub pattern: Capability,
    /// Predicate constraints that survive as residual checks.
    pub constraints: ConstraintSet,
}

impl PolicySource for CapabilityPolicy {
    fn applies_to(&self, ctx: &OpenContext) -> bool {
        self.pattern
            .verb_scheme_segments_match(ctx.verb, ctx.resource_path)
    }

    fn compile(&self, _ctx: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        // Static match already decided at `applies_to`; only the input-dependent
        // predicate constraints survive as residual.
        if self.constraints.is_empty() {
            Ok(PolicySnapshot::empty())
        } else {
            Ok(PolicySnapshot::new(vec![Arc::new(ConstraintCheck {
                constraints: self.constraints.clone(),
            })]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use nexus_state::{Backend, InMemoryBackend};
    use nexus_types::cap::Predicate;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn state() -> Backend {
        Arc::new(InMemoryBackend::new())
    }

    fn ctx<'a>(input: &'a Value) -> CheckCtx<'a> {
        CheckCtx {
            input,
            acting: nexus_types::IdentityRef::ROOT,
            now_millis: 0,
            target: ResourceId::new(1),
        }
    }

    #[tokio::test]
    async fn empty_snapshot_allows_and_is_unconditional() -> anyhow::Result<()> {
        let snap = PolicySnapshot::empty();
        ensure!(snap.is_empty(), "empty snapshot should report empty");
        let decision = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            decision == PolicyDecision::Allow,
            "empty snapshot should allow, got {decision:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn constraint_check_is_fail_closed() -> anyhow::Result<()> {
        let cs = ConstraintSet {
            predicates: vec![Predicate::parse("account=alice").context("predicate did not parse")?],
        };
        let snap = PolicySnapshot::new(vec![Arc::new(ConstraintCheck { constraints: cs })]);
        let mut m = BTreeMap::new();
        m.insert("account".into(), Value::Str("alice".into()));
        let allowed = snap.check(&ctx(&Value::Map(m))).await;
        ensure!(
            allowed == PolicyDecision::Allow,
            "matching constraint should allow, got {allowed:?}"
        );
        // Missing field → denied.
        let denied = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            matches!(denied, PolicyDecision::Deny { .. }),
            "missing constraint input should deny, got {denied:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_non_allow_short_circuits() -> anyhow::Result<()> {
        let snap = PolicySnapshot::new(vec![Arc::new(ApprovalCheck::always("k", "needs ok"))]);
        let decision = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            matches!(decision, PolicyDecision::Ask { .. }),
            "approval check should ask, got {decision:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn approval_resolves_to_allow_once_approved() -> anyhow::Result<()> {
        // A gate backed by a registry asks until the broker records a decision:
        // approved means Allow, denied means Deny.
        let reg = ApprovalRegistry::new();
        let snap = PolicySnapshot::new(vec![Arc::new(ApprovalCheck::with_registry(
            "pay-1",
            "confirm payment",
            reg.clone(),
        ))]);
        // Pending → Ask.
        let pending = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            matches!(pending, PolicyDecision::Ask { .. }),
            "pending approval should ask, got {pending:?}"
        );
        // Approved → Allow (the suspended op would now pass on retry).
        reg.set("pay-1", ApprovalDecision::Approved);
        let approved = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            approved.is_allow(),
            "approved request should allow, got {approved:?}"
        );
        // Denied → Deny.
        reg.set("pay-1", ApprovalDecision::Denied);
        let denied = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            matches!(denied, PolicyDecision::Deny { .. }),
            "denied approval should deny, got {denied:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_denies_past_the_window_budget() -> anyhow::Result<()> {
        let snap = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(2, 1000, state()))]);
        // Two allowed in the window…
        let first = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            first.is_allow(),
            "first rate-limit hit should allow, got {first:?}"
        );
        let second = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            second.is_allow(),
            "second rate-limit hit should allow, got {second:?}"
        );
        // …third denied.
        let third = snap.check(&ctx(&Value::Null)).await;
        ensure!(
            matches!(third, PolicyDecision::Deny { .. }),
            "third rate-limit hit should deny, got {third:?}"
        );
        // After the window slides past all prior hits, allowed again.
        let later = CheckCtx {
            input: &Value::Null,
            acting: nexus_types::IdentityRef::ROOT,
            now_millis: 2000,
            target: ResourceId::new(1),
        };
        let later = snap.check(&later).await;
        ensure!(
            later.is_allow(),
            "post-window hit should allow, got {later:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_is_keyed_by_target_and_acting() -> anyhow::Result<()> {
        // Different targets and acting identities each get their own window.
        let snap = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(1, 1000, state()))]);
        let alice = CheckCtx {
            input: &Value::Null,
            acting: nexus_types::IdentityRef::new(10),
            now_millis: 0,
            target: ResourceId::new(1),
        };
        let bob = CheckCtx {
            input: &Value::Null,
            acting: nexus_types::IdentityRef::new(20),
            now_millis: 0,
            target: ResourceId::new(1),
        };
        let other_target = CheckCtx {
            input: &Value::Null,
            acting: nexus_types::IdentityRef::new(10),
            now_millis: 0,
            target: ResourceId::new(2),
        };
        let alice_first = snap.check(&alice).await;
        ensure!(alice_first.is_allow(), "alice first hit should allow");
        // Alice's second is denied…
        let alice_second = snap.check(&alice).await;
        ensure!(
            matches!(alice_second, PolicyDecision::Deny { .. }),
            "alice second hit should deny, got {alice_second:?}"
        );
        // …but the same acting identity on a different target has its own budget.
        let other = snap.check(&other_target).await;
        ensure!(other.is_allow(), "other target should allow, got {other:?}");
        // Bob (different acting) still has his own budget too.
        let bob = snap.check(&bob).await;
        ensure!(
            bob.is_allow(),
            "different acting identity should allow, got {bob:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_sliding_window_evicts_old_hits() -> anyhow::Result<()> {
        // A true sliding window: a hit at t=0 and one at t=600 with max=2,
        // window=1000. At t=1100 the t=0 hit has slid out, so one more fits.
        let rl = RateLimitCheck::new(2, 1000, state());
        let input = Value::Null;
        let mk = |t: i64| CheckCtx {
            input: &input,
            acting: nexus_types::IdentityRef::ROOT,
            now_millis: t,
            target: ResourceId::new(1),
        };
        let first = rl.evaluate(&mk(0)).await;
        ensure!(first.is_allow(), "first hit should allow, got {first:?}");
        let second = rl.evaluate(&mk(600)).await;
        ensure!(second.is_allow(), "second hit should allow, got {second:?}");
        // t=700: both still in window → denied.
        let denied = rl.evaluate(&mk(700)).await;
        ensure!(
            matches!(denied, PolicyDecision::Deny { .. }),
            "in-window excess hit should deny, got {denied:?}"
        );
        // t=1100: t=0 evicted (1100-1000=100 cutoff), only t=600 remains → allowed.
        let later = rl.evaluate(&mk(1100)).await;
        ensure!(
            later.is_allow(),
            "post-eviction hit should allow, got {later:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_persists_window_across_check_instances() -> anyhow::Result<()> {
        let state = state();
        let a = RateLimitCheck::new(1, 1000, state.clone());
        let b = RateLimitCheck::new(1, 1000, state);
        let input = Value::Null;
        let mk = |t: i64| CheckCtx {
            input: &input,
            acting: nexus_types::IdentityRef::ROOT,
            now_millis: t,
            target: ResourceId::new(1),
        };

        let first = a.evaluate(&mk(0)).await;
        ensure!(first.is_allow(), "first persisted hit should allow");
        let second = b.evaluate(&mk(1)).await;
        ensure!(
            matches!(second, PolicyDecision::Deny { .. }),
            "second persisted hit should deny, got {second:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_persists_evicted_window() -> anyhow::Result<()> {
        let state = state();
        let rl = RateLimitCheck::new(2, 1000, state.clone());
        let input = Value::Null;
        let mk = |t: i64| CheckCtx {
            input: &input,
            acting: nexus_types::IdentityRef::ROOT,
            now_millis: t,
            target: ResourceId::new(1),
        };

        let first = rl.evaluate(&mk(0)).await;
        ensure!(first.is_allow(), "first hit should allow");
        let second = rl.evaluate(&mk(600)).await;
        ensure!(second.is_allow(), "second hit should allow");
        let denied = rl.evaluate(&mk(700)).await;
        ensure!(
            matches!(denied, PolicyDecision::Deny { .. }),
            "in-window excess hit should deny, got {denied:?}"
        );
        let later = rl.evaluate(&mk(1100)).await;
        ensure!(later.is_allow(), "post-eviction hit should allow");

        let path = rate_limit_path(ResourceId::new(1), nexus_types::IdentityRef::ROOT)
            .context("rate limit path failed")?;
        let stored = state
            .read(&path)
            .await
            .context("rate limit state read failed")?;
        ensure!(
            stored == Some(Value::List(vec![Value::Int(600), Value::Int(1100)])),
            "stored rate-limit window mismatch: {stored:?}"
        );
        Ok(())
    }

    #[test]
    fn rate_limit_uses_documented_state_path() -> anyhow::Result<()> {
        let path = rate_limit_path(ResourceId::new(7), nexus_types::IdentityRef::new(9))
            .context("rate limit path failed")?;
        ensure!(
            path.to_string() == "state://kernel/ratelimit/resource:7/identity:9",
            "rate-limit state path mismatch: {path}"
        );
        Ok(())
    }

    #[test]
    fn snapshots_merge_residuals() -> anyhow::Result<()> {
        let a = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(5, 1000, state()))]);
        let b = PolicySnapshot::new(vec![Arc::new(ApprovalCheck::always("k", "r"))]);
        let merged = a.merge(b);
        ensure!(merged.len() == 2, "merged snapshot length mismatch");
        Ok(())
    }
}
