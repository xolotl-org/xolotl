//! Explicit host ownership for an Operation adapted into an asynchronous process.

use super::{ClockDomainError, HostDeadline};
use std::{sync::Arc, time::Duration};
use xolotl_types::{
    ExecutionOutput, Failure, IdentityRef, MethodContract, MethodId, OperationId, Path, ProcessId,
    ProcessStatus, ResourceId, TaintSet, TaintedFailure, Value,
};

/// Immutable child admission metadata, supplied after method and propagation checks.
/// No invocation handle or input payload is exposed as a public process reference.
#[derive(Clone, Debug)]
pub struct AsyncProcessRequest {
    /// Parent invocation creating this child; stable within that invocation.
    pub source: OperationId,
    /// Prospective child identifier. It is not admitted when the host returns an
    /// existing acceptance, and is never reused after a rejected reservation.
    pub process: ProcessId,
    /// Acting identity of the attenuated invocation, not an account ownership claim.
    pub acting: IdentityRef,
    /// Resource selected by the parent's frozen dispatch plan.
    pub resource: ResourceId,
    /// Concrete target when the opened handle retains a path binding.
    pub target: Option<Path>,
    /// Method selected by the parent invocation.
    pub method: MethodId,
    /// Frozen method semantics inherited by the child.
    pub contract: MethodContract,
    /// Input provenance, retained even if admission or cancellation prevents dispatch.
    pub input_taint: TaintSet,
    /// Original host deadline. Child admission cannot extend or remove it.
    pub deadline: Option<HostDeadline>,
}

/// Reserve host ownership before any child task or Driver starts.
///
/// Hosts supply account attribution, capacity and retained-result policy through
/// their own implementation. Admission may await host storage or capacity; the
/// parent deadline and cancellation bound it. It must not run child Operations.
/// Dropping its future must release unaccepted reservations or transfer their
/// cleanup to a host-owned supervisor. Keep an [`AsyncProcessAdmission`] guard
/// across waits once host capacity is reserved. Remote requests that can outlive
/// their future also need host-owned reconciliation of uncertain reservations.
/// A failure leaves no admitted child or derived handle.
/// The kernel supplies no implicit State result directory or background owner.
/// Method idempotency caches body results only; every process acceptance reaches
/// this host. Reconcile repeated source invocations with
/// [`AsyncProcessAdmission::already_accepted`] when the host retains their receipts.
#[async_trait::async_trait]
pub trait AsyncProcessHost: Send + Sync + 'static {
    /// Reserve an execution slot and return its reference and lifecycle owner.
    async fn admit(&self, request: &AsyncProcessRequest) -> Result<AsyncProcessAdmission, Failure>;
}

/// Reference and ownership accepted by a host. The kernel keeps the owner through
/// task exit and retryable terminal publication. This is volatile admission;
/// writing a reference to persistent storage does not make the child recoverable.
/// Dropping this guard before kernel process admission calls the owner's
/// [`AsyncProcessOwner::rejected`] hook exactly once. A reconciled receipt has
/// no new reservation to release.
#[must_use = "an admission owns a reservation until the kernel accepts it"]
pub struct AsyncProcessAdmission {
    pub(crate) reference: Value,
    pub(crate) owner: Option<Arc<dyn AsyncProcessOwner>>,
    pub(crate) deadline: Option<HostDeadline>,
    pub(crate) finalization_timeout: Option<Duration>,
}

impl Drop for AsyncProcessAdmission {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take()
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.rejected())).is_err()
        {
            tracing::error!("async process reservation release panicked");
        }
    }
}

impl AsyncProcessAdmission {
    /// Accept a host-defined reference without exposing kernel handles or State paths.
    pub fn new(reference: Value, owner: Arc<dyn AsyncProcessOwner>) -> Self {
        Self {
            reference,
            owner: Some(owner),
            deadline: None,
            finalization_timeout: None,
        }
    }

    /// Return the receipt for this source invocation's earlier acceptance.
    /// The host must bind it to the same source and authority, and keep unfinished
    /// work and cleanup under the original owner. The kernel creates no new process or task and
    /// does not call that owner's hooks again. Admission checks still apply.
    /// This is acceptance reconciliation, not a new successful body outcome.
    pub fn already_accepted(reference: Value) -> Self {
        Self {
            reference,
            owner: None,
            deadline: None,
            finalization_timeout: None,
        }
    }

    /// Narrow the parent's deadline. A later deadline never renews parent authority.
    pub fn with_deadline(mut self, deadline: HostDeadline) -> Result<Self, ClockDomainError> {
        self.deadline = Some(match self.deadline {
            Some(saved) => saved.earliest(deadline)?,
            None => deadline,
        });
        Ok(self)
    }

    /// Bound the first lifecycle/publication attempt after the body stops. A timed
    /// out attempt retains its outcome and owner for host-driven cleanup retries.
    /// Hosts separately bound calls to `Bootstrap::drain_cleanup` or finalization.
    pub fn with_finalization_timeout(mut self, timeout: Duration) -> Self {
        self.finalization_timeout = Some(timeout);
        self
    }
}

/// Host supervision and result custody for one accepted child.
///
/// Implementations must retain their ownership independently of a connection or
/// bearer token. The kernel revokes child handles and drops the body before
/// publishing. A publisher receives the exact known outcome, or `None` if the
/// body was abandoned; missing output must not be presented as a known result.
#[async_trait::async_trait]
pub trait AsyncProcessOwner: Send + Sync + 'static {
    /// Release a reservation rejected before process admission. No child task or
    /// Driver ran. This synchronous callback must be bounded and must not panic.
    /// If release requires asynchronous work, retain that cleanup under a host
    /// supervisor before returning; the kernel cannot await a dropped admission.
    /// It is not called after a process has been admitted; that lifecycle publishes
    /// a terminal record even if managed task attachment subsequently fails.
    fn rejected(&self) {}

    /// The managed attempt has dropped all body/finalizer captures. This follows
    /// successful publication as well as failed cleanup or forced abort before
    /// the first poll. Hosts can use this acknowledgement to finish shutdown.
    /// Unless `publish` succeeded, cleanup is still pending; a later `publish`
    /// can acknowledge it. `None` means the body's effects are unknown.
    /// This synchronous notification must be bounded and must not panic.
    fn released(&self, _status: ProcessStatus, _output: Option<&ExecutionOutput>) {}

    /// Revalidate live authority and prepare host state before the first Driver
    /// call. Cancellation and the inherited deadline also bound this future.
    async fn prepare(&self) -> Result<(), TaintedFailure> {
        Ok(())
    }

    /// Remain pending while the child may run; resolve to request cancellation.
    /// Hosts can combine revocation polling, explicit cancellation and shutdown.
    /// This future is polled concurrently with preparation and execution; dropping
    /// it must release observations. Kernel process cancellation remains independent.
    async fn cancelled(&self) -> Failure {
        std::future::pending().await
    }

    /// Publish the business result after local handle disposal and status selection.
    /// Calls may repeat after failure or interruption; preserve the first accepted
    /// result and retention deadline. Success permits process cleanup to complete.
    /// This callback never causes the Driver to be executed again.
    async fn publish(
        &self,
        status: ProcessStatus,
        output: Option<&ExecutionOutput>,
    ) -> Result<(), Failure>;
}
