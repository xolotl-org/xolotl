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

use std::sync::Arc;
use xolotl_types::{
    Capability, ConstraintSet, Expiry, IdentityRef, Path, ResourceId, Rights, Value,
};

mod rate_limit;
pub use rate_limit::RateLimitCheck;

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
    /// Hosted opens run this without holding the registry or handle-table locks.
    /// A control-plane change during this call invalidates the prepared open;
    /// installation never reruns the callback or evaluates its residual checks.
    fn compile(&self, ctx: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError>;
}

/// The request context a residual check evaluates against (the runtime view of
/// an operation — input + acting + wall clock + target resource).
pub struct CheckCtx<'a> {
    /// Operation input being evaluated.
    pub input: &'a Value,
    /// Identity the operation acts as.
    pub acting: xolotl_types::IdentityRef,
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
    /// Whether this pure grant guard must be checked again before an awaited
    /// child admission becomes a delegated handle. Stateful host policies run
    /// only at invocation and must not be charged twice for one operation.
    fn guards_derivation(&self) -> bool {
        false
    }
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
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
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

    /// Recheck only immutable grant conditions after asynchronous host custody
    /// and before creating a child. This uses the same operation input and a
    /// fresh clock, without rerunning stateful source policies.
    pub async fn check_derivation(&self, ctx: &CheckCtx<'_>) -> PolicyDecision {
        for check in self.checks.iter().filter(|check| check.guards_derivation()) {
            let decision = check.evaluate(ctx).await;
            if !decision.is_allow() {
                return decision;
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

/// One grant's conjunction. Distinct matching grants are alternatives, never
/// a conjunction: the operation may use any one grant that still covers it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub(crate) struct GrantCondition {
    pub constraints: ConstraintSet,
    pub expires: Expiry,
}

/// Residual authority for overlapping grants. Open cannot choose between
/// input-dependent grants, so this check makes the choice per operation.
pub(crate) struct GrantAlternativesCheck {
    pub alternatives: Vec<GrantCondition>,
}

#[async_trait::async_trait]
impl CompiledCheck for GrantAlternativesCheck {
    async fn evaluate(&self, ctx: &CheckCtx) -> PolicyDecision {
        if self.alternatives.iter().any(|grant| {
            !grant.expires.is_expired(ctx.now_millis)
                && grant.constraints.eval(ctx.input, ctx.now_millis)
        }) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny {
                reason: "no matching grant constraint is satisfied".into(),
            }
        }
    }

    fn name(&self) -> &'static str {
        "grant_alternatives"
    }

    fn guards_derivation(&self) -> bool {
        true
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
        self.pattern.matches_structure(ctx.verb, ctx.resource_path)
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
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use xolotl_state::{Backend, InMemoryBackend};
    use xolotl_types::cap::Predicate;

    fn state() -> Backend {
        InMemoryBackend::new().into_backend()
    }

    fn ctx<'a>(input: &'a Value) -> CheckCtx<'a> {
        CheckCtx {
            input,
            acting: xolotl_types::IdentityRef::ROOT,
            now_millis: 0,
            target: ResourceId::new(1),
        }
    }

    #[tokio::test]
    async fn empty_snapshot_allows_and_is_unconditional() -> anyhow::Result<()> {
        let snap = PolicySnapshot::empty();
        ensure!(snap.is_empty(), "empty snapshot should report empty");
        let decision = snap.check(&ctx(&Value::null())).await;
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
        m.insert("account".into(), Value::string("alice".into()));
        let allowed = snap.check(&ctx(&Value::map(m))).await;
        ensure!(
            allowed == PolicyDecision::Allow,
            "matching constraint should allow, got {allowed:?}"
        );
        // Missing field → denied.
        let denied = snap.check(&ctx(&Value::null())).await;
        ensure!(
            matches!(denied, PolicyDecision::Deny { .. }),
            "missing constraint input should deny, got {denied:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_non_allow_short_circuits() -> anyhow::Result<()> {
        let snap = PolicySnapshot::new(vec![Arc::new(ApprovalCheck::always("k", "needs ok"))]);
        let decision = snap.check(&ctx(&Value::null())).await;
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
        let pending = snap.check(&ctx(&Value::null())).await;
        ensure!(
            matches!(pending, PolicyDecision::Ask { .. }),
            "pending approval should ask, got {pending:?}"
        );
        // Approved → Allow (the suspended op would now pass on retry).
        reg.set("pay-1", ApprovalDecision::Approved);
        let approved = snap.check(&ctx(&Value::null())).await;
        ensure!(
            approved.is_allow(),
            "approved request should allow, got {approved:?}"
        );
        // Denied → Deny.
        reg.set("pay-1", ApprovalDecision::Denied);
        let denied = snap.check(&ctx(&Value::null())).await;
        ensure!(
            matches!(denied, PolicyDecision::Deny { .. }),
            "denied approval should deny, got {denied:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_denies_past_the_window_budget() -> anyhow::Result<()> {
        let snap = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(
            "tests",
            2,
            1000,
            state(),
        )?)]);
        // Two allowed in the window…
        let first = snap.check(&ctx(&Value::null())).await;
        ensure!(
            first.is_allow(),
            "first rate-limit hit should allow, got {first:?}"
        );
        let second = snap.check(&ctx(&Value::null())).await;
        ensure!(
            second.is_allow(),
            "second rate-limit hit should allow, got {second:?}"
        );
        // …third denied.
        let third = snap.check(&ctx(&Value::null())).await;
        ensure!(
            matches!(third, PolicyDecision::Deny { .. }),
            "third rate-limit hit should deny, got {third:?}"
        );
        // After the window slides past all prior hits, allowed again.
        let later = CheckCtx {
            input: &Value::null(),
            acting: xolotl_types::IdentityRef::ROOT,
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
    async fn rate_limit_is_keyed_by_scope_and_acting() -> anyhow::Result<()> {
        let backend = state();
        // Stable scopes and acting identities each get their own window.
        let snap = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(
            "tests",
            1,
            1000,
            backend.clone(),
        )?)]);
        let alice = CheckCtx {
            input: &Value::null(),
            acting: xolotl_types::IdentityRef::new(10),
            now_millis: 0,
            target: ResourceId::new(1),
        };
        let bob = CheckCtx {
            input: &Value::null(),
            acting: xolotl_types::IdentityRef::new(20),
            now_millis: 0,
            target: ResourceId::new(1),
        };
        let other_target = CheckCtx {
            input: &Value::null(),
            acting: xolotl_types::IdentityRef::new(10),
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
        // A different scope has its own account in the same backend.
        let other = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(
            "other", 1, 1000, backend,
        )?)])
        .check(&other_target)
        .await;
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
        let rl = RateLimitCheck::new("tests", 2, 1000, state())?;
        let input = Value::null();
        let mk = |t: i64| CheckCtx {
            input: &input,
            acting: xolotl_types::IdentityRef::ROOT,
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
        let a = RateLimitCheck::new("tests", 1, 1000, state.clone())?;
        let b = RateLimitCheck::new("tests", 1, 1000, state)?;
        let input = Value::null();
        let mk = |t: i64| CheckCtx {
            input: &input,
            acting: xolotl_types::IdentityRef::ROOT,
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
        let rl = RateLimitCheck::new("tests", 2, 1000, state.clone())?;
        let input = Value::null();
        let mk = |t: i64| CheckCtx {
            input: &input,
            acting: xolotl_types::IdentityRef::ROOT,
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

        let path = super::rate_limit::rate_limit_path("tests", xolotl_types::IdentityRef::ROOT)
            .context("rate limit path failed")?;
        let stored = state
            .read(&path)
            .await
            .context("rate limit state read failed")?;
        ensure!(
            stored
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|fields| fields.get("hits"))
                == Some(&Value::list(vec![
                    Value::integer(600),
                    Value::integer(1100)
                ])),
            "stored rate-limit window mismatch: {stored:?}"
        );
        Ok(())
    }

    #[test]
    fn snapshots_merge_residuals() -> anyhow::Result<()> {
        let a = PolicySnapshot::new(vec![Arc::new(RateLimitCheck::new(
            "tests",
            5,
            1000,
            state(),
        )?)]);
        let b = PolicySnapshot::new(vec![Arc::new(ApprovalCheck::always("k", "r"))]);
        let merged = a.merge(b);
        ensure!(merged.len() == 2, "merged snapshot length mismatch");
        Ok(())
    }
}
