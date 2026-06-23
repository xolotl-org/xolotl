//! `Process` — the only active entity, plus the process lifecycle types
//! and `Outcome`.
//!
//! Only a Process can issue an [`Operation`](crate::operation::Operation);
//! Resources are always passive. A Process is bound to one frozen compiled
//! program (referenced here by hash; the live `ExecutionGraph` lives in
//! `andrias-graph`) and recovers against that same product.

use crate::grant::Expiry;
use crate::ids::{GrantId, IdentityRef, ProcessId};
use crate::path::Path;
use crate::value::{Failure, Value};
use serde::{Deserialize, Serialize};

/// Reference to a Program source. The kernel does
/// not prescribe the source format (`Do<A>`, model plan, runbook, native).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramRef {
    /// Opaque source identifier (path or content id of the program source).
    pub source_id: String,
}

/// Reference to the frozen compiled program a Process is bound to. The
/// live `ExecutionGraph` lives in `andrias-graph`; here we carry its hash so the
/// type stays wasm-safe and serializable. Recovery re-binds the same hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledProgramRef {
    /// Hash of the compiled execution graph bound to the process.
    pub graph_hash: [u8; 32],
}

/// Whether a Program satisfies the recoverability contract.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recoverability {
    /// Satisfies the contract; crash-recovers automatically.
    #[default]
    Recoverable,
    /// Explicitly marked non-recoverable; not auto-resumed after a crash.
    NonRecoverable,
}

/// Lifecycle status of a Process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    /// Process record exists but execution has not started.
    #[default]
    Created,
    /// Process is actively executing its graph.
    Running,
    /// Process is blocked on a wait, approval, stream, or async result.
    Waiting,
    /// Process is paused by policy or operator action.
    Suspended,
    /// Process is running cleanup before terminal completion.
    Finalizing,
    /// Process completed successfully.
    Completed,
    /// Process terminated with failure.
    Failed,
    /// Process was cancelled before normal completion.
    Cancelled,
}

impl ProcessStatus {
    /// Returns true for statuses that cannot transition back to execution.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ProcessStatus::Completed | ProcessStatus::Failed | ProcessStatus::Cancelled
        )
    }
}

/// When a Process expires. On expiry it enters `Finalizing`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpireRule {
    /// Continue until explicitly cancelled.
    UntilCancelled,
    /// Expire after the program reaches success or failure.
    #[default]
    UntilDoneOrFail,
    /// Wall-clock millis-since-epoch deadline.
    Deadline(i64),
    /// Expire when a signal is written to this path.
    OnSignal(Path),
    /// Expire when any configured budget dimension is exhausted.
    BudgetExhausted,
}

/// Budget account state for a Process. Spending dimensions are tracked
/// here; the budget *spec* (limits) lives in [`StartRecord`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetState {
    /// Micro-USD already reserved or spent in the current accounting window.
    pub spent_micro_usd: u64,
    /// Number of operations currently reserved but not settled.
    pub inflight_ops: u32,
    /// Inference tokens reserved or spent in the current accounting window.
    pub inference_tokens: u64,
}

impl BudgetState {
    /// Try to reserve one operation's estimated cost against `spec`:
    /// pre-debit `inflight_ops`, estimated USD, and estimated tokens, denying
    /// (without mutating) if any dimension would exceed its limit. The estimate
    /// is deliberately conservative (high) so a side effect is never issued and
    /// only then discovered to be over budget. Returns `Err(dim)` naming the
    /// exhausted dimension, or `Ok(())` after reserving.
    pub fn try_reserve(
        &mut self,
        spec: &BudgetSpec,
        est_micro_usd: u64,
        est_tokens: u64,
    ) -> Result<(), String> {
        if let Some(max) = spec.max_inflight_ops
            && self.inflight_ops + 1 > max
        {
            return Err("inflight_ops".into());
        }
        // Daily and monthly USD share the single `spent_micro_usd` counter; the
        // tighter limit binds.
        let projected_usd = self.spent_micro_usd.saturating_add(est_micro_usd);
        if let Some(max) = spec.daily_micro_usd
            && projected_usd > max
        {
            return Err("daily_micro_usd".into());
        }
        if let Some(max) = spec.monthly_micro_usd
            && projected_usd > max
        {
            return Err("monthly_micro_usd".into());
        }
        if let Some(max) = spec.max_inference_tokens
            && self.inference_tokens.saturating_add(est_tokens) > max
        {
            return Err("inference_tokens".into());
        }
        self.inflight_ops += 1;
        self.spent_micro_usd = projected_usd;
        self.inference_tokens = self.inference_tokens.saturating_add(est_tokens);
        Ok(())
    }

    /// Settle a previously-reserved operation against its actual cost:
    /// release the inflight slot and adjust the reserved USD/tokens to the
    /// measured values (the estimate was conservative, so this usually refunds).
    pub fn settle(
        &mut self,
        reserved_micro_usd: u64,
        actual_micro_usd: u64,
        reserved_tokens: u64,
        actual_tokens: u64,
    ) {
        self.inflight_ops = self.inflight_ops.saturating_sub(1);
        // spent = spent - reserved + actual, saturating to avoid underflow.
        self.spent_micro_usd = self
            .spent_micro_usd
            .saturating_sub(reserved_micro_usd)
            .saturating_add(actual_micro_usd);
        self.inference_tokens = self
            .inference_tokens
            .saturating_sub(reserved_tokens)
            .saturating_add(actual_tokens);
    }
}

/// Per-dimension budget limits. `None` = unbounded on that dimension.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetSpec {
    /// Maximum micro-USD allowed per day.
    pub daily_micro_usd: Option<u64>,
    /// Maximum micro-USD allowed per month.
    pub monthly_micro_usd: Option<u64>,
    /// Maximum number of concurrent in-flight operations.
    pub max_inflight_ops: Option<u32>,
    /// Maximum inference tokens allowed in the accounting window.
    pub max_inference_tokens: Option<u64>,
}

/// Startup parameters for a Process: identity prefix, initial grants,
/// budget, persona parameters.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StartRecord {
    /// The identity prefix this Process acts as by default.
    pub identity: IdentityRef,
    /// Budget limits for the process.
    pub budget: BudgetSpec,
    /// Expiry behavior for the process.
    pub expires: ExpireRule,
    /// Free-form persona / configuration parameters.
    #[serde(default)]
    pub params: Value,
}

/// The only active entity. Holds compiled capabilities (handles, by id in
/// the kernel's HandleTable) and grant sources; runs one frozen compiled
/// program.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Process {
    /// Stable process id.
    pub id: ProcessId,
    /// Parent process, if this was spawned by another process.
    pub parent: Option<ProcessId>,
    /// Program source reference used at creation time.
    pub source: ProgramRef,
    /// Frozen compiled graph reference used for execution and recovery.
    pub program: CompiledProgramRef,
    /// Startup identity, budget, expiry, and parameters.
    pub start: StartRecord,
    /// Grant sources held by this Process (handles are tracked in the kernel
    /// HandleTable, keyed by owner).
    pub grants: Vec<GrantId>,
    /// Current budget account state.
    pub budget: BudgetState,
    /// Lifecycle state.
    pub status: ProcessStatus,
}

/// One attenuation a parent applies to a grant when spawning a child: a
/// child's grant can only narrow, never strengthen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrantAttenuation {
    /// Parent grant being attenuated.
    pub grant: GrantId,
    /// Narrowed selector literal (must be ⊆ the parent grant's selector).
    pub selector: String,
    /// Tighter expiry (must be ≤ the parent's).
    #[serde(default)]
    pub expires: Expiry,
}

/// Request to create a child Process. Grants may only be attenuated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpawnRequest {
    /// Parent process issuing the spawn.
    pub parent: ProcessId,
    /// Child program source reference.
    pub program: ProgramRef,
    /// Child startup parameters.
    pub start: StartRecord,
    /// Attenuated grants delegated to the child.
    pub grants: Vec<GrantAttenuation>,
}

/// The result of one operation / node evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Completed with a value.
    Done(Value),
    /// Failed; may be handled by an `OrElse` branch.
    Fail(Failure),
    /// Short-circuited — a residual policy / cache synthesized the value
    /// without invoking the driver.
    Short(Value),
}

impl Outcome {
    /// Returns true for successful outcomes, including short-circuited success.
    pub fn is_success(&self) -> bool {
        matches!(self, Outcome::Done(_) | Outcome::Short(_))
    }

    /// Returns true when the outcome is a failure.
    pub fn is_fail(&self) -> bool {
        matches!(self, Outcome::Fail(_))
    }

    /// Convert success outcomes into their value, or return the failure.
    pub fn into_value(self) -> Result<Value, Failure> {
        match self {
            Outcome::Done(v) | Outcome::Short(v) => Ok(v),
            Outcome::Fail(f) => Err(f),
        }
    }

    /// Borrow the success value if this outcome completed.
    pub fn value(&self) -> Option<&Value> {
        match self {
            Outcome::Done(v) | Outcome::Short(v) => Some(v),
            Outcome::Fail(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn budget_reserve_denies_over_usd_limit() {
        let spec = BudgetSpec {
            daily_micro_usd: Some(1000),
            ..Default::default()
        };
        let mut b = BudgetState::default();
        // First reservation of 600 fits.
        assert!(b.try_reserve(&spec, 600, 0).is_ok());
        assert_eq!(b.spent_micro_usd, 600);
        // Second of 600 would hit 1200 > 1000 → denied, state unchanged.
        assert_eq!(b.try_reserve(&spec, 600, 0), Err("daily_micro_usd".into()));
        assert_eq!(b.spent_micro_usd, 600);
        assert_eq!(b.inflight_ops, 1);
    }

    #[test]
    fn budget_reserve_denies_over_inflight() {
        let spec = BudgetSpec {
            max_inflight_ops: Some(1),
            ..Default::default()
        };
        let mut b = BudgetState::default();
        assert!(b.try_reserve(&spec, 0, 0).is_ok());
        assert_eq!(b.try_reserve(&spec, 0, 0), Err("inflight_ops".into()));
    }

    #[test]
    fn budget_settle_refunds_overestimate_and_releases_inflight() -> anyhow::Result<()> {
        let spec = BudgetSpec {
            daily_micro_usd: Some(1000),
            ..Default::default()
        };
        let mut b = BudgetState::default();
        b.try_reserve(&spec, 500, 50)
            .map_err(|error| anyhow::anyhow!("reserve failed: {error}"))?;
        b.settle(500, 100, 50, 10);
        ensure!(
            b.spent_micro_usd == 100,
            "overestimate was not refunded: {}",
            b.spent_micro_usd
        );
        ensure!(
            b.inference_tokens == 10,
            "unexpected token count: {}",
            b.inference_tokens
        );
        ensure!(b.inflight_ops == 0, "inflight slot was not released");
        Ok(())
    }

    #[test]
    fn budget_unbounded_spec_never_denies() {
        let spec = BudgetSpec::default();
        let mut b = BudgetState::default();
        assert!(b.try_reserve(&spec, u64::MAX, u64::MAX).is_ok());
    }

    #[test]
    fn outcome_into_value() -> anyhow::Result<()> {
        let value = Outcome::Done(Value::Int(1))
            .into_value()
            .map_err(|error| anyhow::anyhow!("done outcome returned failure: {error:?}"))?;
        ensure!(
            value == Value::Int(1),
            "unexpected outcome value: {value:?}"
        );
        ensure!(
            matches!(
                Outcome::Fail(Failure::Cancelled).into_value(),
                Err(Failure::Cancelled)
            ),
            "failure outcome did not return failure"
        );
        Ok(())
    }

    #[test]
    fn process_status_terminal() {
        assert!(ProcessStatus::Completed.is_terminal());
        assert!(!ProcessStatus::Running.is_terminal());
    }

    #[test]
    fn outcome_serde() -> anyhow::Result<()> {
        let o = Outcome::Done(Value::Str("ok".into()));
        let s = serde_json::to_string(&o)?;
        let back: Outcome = serde_json::from_str(&s)?;
        ensure!(o == back, "outcome serde roundtrip changed value");
        Ok(())
    }
}
