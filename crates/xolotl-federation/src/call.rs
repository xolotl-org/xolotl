//! Stable, transport-independent identities for a federated resource call.
//! A CallRef is only a locator; every operation still needs an authenticated
//! presenter, verified subject and the target's current access decision.

use std::sync::Arc;

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use sha2::{Digest as _, Sha384};

use crate::{Digest, ExportName, FederationError, FederationNodeId, FederationSubject, RequestId};

const MAX_PATH_BYTES: usize = 1024;
const MAX_METHOD_BYTES: usize = 128;
const MAX_FAILURE_CODE_BYTES: usize = 128;
/// Maximum accepted input payload for one federated call.
pub const MAX_CALL_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum unresolved remote effect identities retained by one call result.
pub const MAX_CALL_UNRESOLVED_EFFECT_IDS: usize = 128;

/// A target-allocated identity which must never be reused, including after
/// restart and normal receipt expiry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CallRef {
    /// Node that allocated and owns this call identity.
    pub target: FederationNodeId,
    /// Opaque, nonzero, never-reused target-local identity.
    pub id: [u8; 32],
}

impl CallRef {
    /// Validate a target-allocated call identity.
    pub fn new(target: FederationNodeId, id: [u8; 32]) -> Result<Self, FederationError> {
        if id == [0; 32] {
            return Err(FederationError::Invalid("call identity is zero"));
        }
        Ok(Self { target, id })
    }

    /// Generate a fresh call identity using the operating system RNG.
    pub fn random(target: FederationNodeId) -> Result<Self, FederationError> {
        let mut id = [0; 32];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_error| FederationError::Storage("call identity RNG unavailable".into()))?;
        Self::new(target, id)
    }
}

/// Canonical export-relative concrete path. No dot segments, empty segments,
/// URI escaping, fragment or query interpretation is performed by this layer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CallPath(String);

impl CallPath {
    /// Validate a concrete path relative to an exported resource.
    pub fn new(value: impl Into<String>) -> Result<Self, FederationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PATH_BYTES
            || !value.starts_with('/')
            || value.contains('%')
            || value.contains('?')
            || value.contains('#')
            || value.chars().any(char::is_control)
            || (value != "/"
                && value
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == ".."))
        {
            return Err(FederationError::Invalid(
                "invalid export-relative call path",
            ));
        }
        Ok(Self(value))
    }

    /// Return the canonical export-relative path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable method name under an exported contract. Numeric local MethodId
/// values are never placed on the federation wire.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CallMethod(String);

impl CallMethod {
    /// Validate a stable method name for the exported contract.
    pub fn new(value: impl Into<String>) -> Result<Self, FederationError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_METHOD_BYTES || value.chars().any(char::is_control)
        {
            return Err(FederationError::Invalid("invalid federated method"));
        }
        Ok(Self(value))
    }

    /// Return the stable method name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Exact exported resource and method selected by a call.
pub struct CallTarget {
    /// Name of the target-owned export.
    pub export: ExportName,
    /// Concrete path beneath that export.
    pub path: CallPath,
    /// Stable method name in the export contract.
    pub method: CallMethod,
    /// Digest of the stable method semantics, not a local numeric method ID.
    pub contract_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Origin-authenticated request to reserve one target-owned call identity.
pub struct PrepareCallRequest {
    /// Origin node authenticated by the transport.
    pub authenticated_origin: FederationNodeId,
    /// Principal proven separately for this request.
    pub subject: FederationSubject,
    /// Stable origin-generated request identity for prepare retries.
    pub origin_request_id: RequestId,
    /// Exact target and method to reserve.
    pub target: CallTarget,
    /// SHA-384 digest of the input that will later be invoked.
    pub input_digest: Digest,
    /// Expected input length in bytes.
    pub input_bytes: u64,
    /// Latest time at which a new reservation may be made.
    pub prepare_deadline_ms: u64,
    /// Deadline for execution of the reserved call.
    pub execution_deadline_ms: u64,
    /// Requested duration for retaining a terminal result.
    pub result_retention_ms: u64,
}

impl PrepareCallRequest {
    /// Check identities, deadlines, target contract and empty-input digest.
    pub fn validate(
        &self,
        local_node: FederationNodeId,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        if self.authenticated_origin == local_node
            || self.prepare_deadline_ms <= now_ms
            || self.execution_deadline_ms <= now_ms
            || self.prepare_deadline_ms > self.execution_deadline_ms
            || self.result_retention_ms == 0
            || self.target.contract_digest == [0; 32]
            || (self.input_bytes == 0
                && self.input_digest != Digest::from_bytes(Sha384::digest([]).into()))
        {
            return Err(FederationError::Invalid("invalid call preparation"));
        }
        if let FederationSubject::Node(node) = &self.subject
            && *node != self.authenticated_origin
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Observable lifecycle state of a target-owned call.
pub enum CallStatus {
    /// Identity reserved; invocation has not claimed the work.
    Reserved,
    /// Invocation claimed; local Kernel acceptance is unresolved.
    Preparing,
    /// The original Kernel work was durably accepted.
    Accepted,
    /// A durable terminal result is available.
    Finished,
    /// The call is closed without further execution.
    Closed,
    /// No retained evidence. This never proves that execution did not occur.
    Unproven,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Receipt for a durable target-side call reservation.
pub struct CallPrepared {
    /// Origin request to which this reservation is bound.
    pub origin_request_id: RequestId,
    /// Target-allocated identity for all later controls and inspections.
    pub call: CallRef,
    /// Current lifecycle state at preparation.
    pub status: CallStatus,
    /// Reservation expiry, in Unix milliseconds.
    pub reserved_until_ms: u64,
    /// Latest execution time, in Unix milliseconds.
    pub execution_deadline_ms: u64,
    /// Agreed terminal-result retention duration in milliseconds.
    pub result_retention_ms: u64,
    /// Revision of the exact method authority used at preparation.
    pub authority_revision: u64,
    /// Revision of this call’s control state.
    pub control_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Request to claim and supply input for an existing reservation.
pub struct InvokeCallRequest {
    /// Origin node authenticated by the transport.
    pub authenticated_origin: FederationNodeId,
    /// Principal proven for the original call.
    pub subject: FederationSubject,
    /// Origin request bound to the reservation.
    pub origin_request_id: RequestId,
    /// Target-owned call identity to invoke.
    pub call: CallRef,
    /// Input bytes whose length and digest match the preparation.
    pub input: Arc<[u8]>,
}

impl InvokeCallRequest {
    /// Compute the SHA-384 digest of the supplied input.
    pub fn input_digest(&self) -> Digest {
        Digest::from_bytes(Sha384::digest(&self.input).into())
    }
}

/// The one locally reserved Kernel identity for this target-owned call.
/// A bridge durably reserves these IDs before binding them to CallRef.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallKernelBinding {
    /// Durably reserved local Kernel process identity.
    pub process: u64,
    /// Durably reserved local Kernel lifecycle identity.
    pub lifecycle: u64,
}

impl CallKernelBinding {
    /// Reject zero Kernel identities before binding them to a call.
    pub fn validate(self) -> Result<(), FederationError> {
        if self.process == 0 || self.lifecycle == 0 {
            return Err(FederationError::Invalid("zero Kernel call identity"));
        }
        Ok(())
    }
}

/// Private bridge view. A remote Inspect never exposes the retained input,
/// local Kernel IDs or original authorization claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallKernelView {
    /// Target-owned call identity.
    pub call: CallRef,
    /// Original authenticated preparation and method target.
    pub request: PrepareCallRequest,
    /// Current lifecycle state.
    pub status: CallStatus,
    /// Retained input for local recovery, if invocation supplied it.
    pub input: Option<Arc<[u8]>>,
    /// Local Kernel identity bound to the call, if allocated.
    pub binding: Option<CallKernelBinding>,
    /// Digest of the Kernel acceptance receipt, if accepted.
    pub accepted_digest: Option<Digest>,
    /// Whether stopping the original work has been requested.
    pub cancellation_requested: bool,
    /// Whether the Kernel committed a cancellation receipt.
    pub kernel_cancel_accepted: bool,
    /// Whether the original execution was observed stopped.
    pub execution_stopped: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Receipt after invocation or Kernel acceptance changes call state.
pub struct CallInvoked {
    /// Target-owned call identity.
    pub call: CallRef,
    /// Resulting lifecycle state.
    pub status: CallStatus,
    /// New control revision for subsequent conditional operations.
    pub control_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Origin-authenticated request for a retained call inspection.
pub struct InspectCallRequest {
    /// Origin node authenticated by the transport.
    pub authenticated_origin: FederationNodeId,
    /// Principal proven for this inspection.
    pub subject: FederationSubject,
    /// Target-owned call identity to inspect.
    pub call: CallRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Stable, restricted failure identifier returned with a failed call.
pub struct CallFailureCode(String);

impl CallFailureCode {
    /// Validate an ASCII failure identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, FederationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_FAILURE_CODE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(FederationError::Invalid("invalid call failure code"));
        }
        Ok(Self(value))
    }

    /// Return the failure identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Durable terminal result and its integrity evidence.
pub struct PersistedCallResult {
    /// Whether execution completed successfully.
    pub succeeded: bool,
    /// Result bytes retained by the target.
    pub output: Arc<[u8]>,
    /// SHA-384 digest of the retained result bytes.
    pub output_digest: Digest,
    /// Stable failure identifier, required exactly when execution failed.
    pub failure_code: Option<CallFailureCode>,
}

impl PersistedCallResult {
    /// Build a result with a digest computed from the retained bytes.
    pub fn new(
        succeeded: bool,
        output: Arc<[u8]>,
        failure_code: Option<CallFailureCode>,
    ) -> Result<Self, FederationError> {
        if succeeded == failure_code.is_some() {
            return Err(FederationError::Invalid(
                "call result and failure code disagree",
            ));
        }
        let output_digest = Digest::from_bytes(Sha384::digest(&output).into());
        Ok(Self {
            succeeded,
            output,
            output_digest,
            failure_code,
        })
    }

    /// Verify the retained bytes and success/failure consistency.
    pub fn verify(&self) -> Result<(), FederationError> {
        if self.output_digest != Digest::from_bytes(Sha384::digest(&self.output).into())
            || self.succeeded == self.failure_code.is_some()
        {
            return Err(FederationError::Corrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Public target-side evidence for the current call state.
pub struct CallInspection {
    /// Target-owned identity being inspected.
    pub call: CallRef,
    /// Current lifecycle state.
    pub status: CallStatus,
    /// Current revision of cancellation and lifecycle controls.
    pub control_revision: u64,
    /// Current revision of the method authority.
    pub authority_revision: u64,
    /// Original reservation expiry, in Unix milliseconds.
    pub reserved_until_ms: u64,
    /// Original execution deadline, in Unix milliseconds.
    pub execution_deadline_ms: u64,
    /// Time until which the terminal result is retained.
    pub result_retained_until_ms: u64,
    /// Retained terminal result, if one exists.
    pub result: Option<PersistedCallResult>,
    /// Kernel effects that remain unresolved after execution.
    pub unresolved_effect_ids: Vec<[u8; 32]>,
    /// Whether a stop was requested.
    pub cancellation_requested: bool,
    /// Whether the Kernel accepted cancellation.
    pub kernel_cancel_accepted: bool,
    /// Whether original execution was observed stopped.
    pub execution_stopped: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Origin-authenticated request to stop the original call.
pub struct CancelCallRequest {
    /// Origin node authenticated by the transport.
    pub authenticated_origin: FederationNodeId,
    /// Principal proven for this control request.
    pub subject: FederationSubject,
    /// Stable request identity for idempotent cancellation retries.
    pub control_request_id: RequestId,
    /// Target-owned call identity to control.
    pub call: CallRef,
    /// Optional compare-and-swap revision for the call control state.
    pub expected_control_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Target receipt for an idempotent cancellation request.
pub struct CallCancelled {
    /// Control request to which this receipt belongs.
    pub control_request_id: RequestId,
    /// Target-owned call identity.
    pub call: CallRef,
    /// Lifecycle state after the control request.
    pub status: CallStatus,
    /// Resulting control revision.
    pub control_revision: u64,
    /// Whether the stop request is durably recorded.
    pub cancellation_requested: bool,
    /// Whether the Kernel accepted cancellation.
    pub kernel_cancel_accepted: bool,
    /// Whether original execution was observed stopped.
    pub execution_stopped: bool,
}

/// One exact host-owned method grant. The presenter is the authenticated
/// transport node; a Hosted subject also requires its separate holder proof.
/// Revisions are local CAS values and must be rechecked at every commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallAuthorityRule {
    /// Principal allowed to invoke the method.
    pub subject: FederationSubject,
    /// Authenticated transport node allowed to present that principal.
    pub presenter: FederationNodeId,
    /// Exact exported method covered by this authority.
    pub target: CallTarget,
    /// Whether this authority currently admits new work.
    pub enabled: bool,
    /// Expiry of this authority in Unix milliseconds.
    pub expires_ms: u64,
    /// Maximum input size this authority permits.
    pub max_input_bytes: u64,
    /// Maximum time between preparation and its deadline.
    pub max_prepare_window_ms: u64,
    /// Maximum duration for retaining a terminal result.
    pub max_result_retention_ms: u64,
}

impl CallAuthorityRule {
    /// Validate nonzero bounds and a consistent node principal.
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.expires_ms == 0
            || self.max_prepare_window_ms == 0
            || self.max_result_retention_ms == 0
            || self.target.contract_digest == [0; 32]
        {
            return Err(FederationError::Invalid("invalid call authority"));
        }
        if let FederationSubject::Node(node) = &self.subject
            && *node != self.presenter
        {
            return Err(FederationError::Invalid(
                "node call subject differs from presenter",
            ));
        }
        Ok(())
    }
}

/// Exact identity of a host-owned call grant. The encoding defines the stable
/// keyset order used by durable and in-memory authority scans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallAuthorityKey {
    /// Principal identified by this grant key.
    pub subject: FederationSubject,
    /// Authenticated presenter identified by this grant key.
    pub presenter: FederationNodeId,
    /// Exact method target identified by this grant key.
    pub target: CallTarget,
}

impl CallAuthorityKey {
    /// Extract the immutable grant key from a rule.
    pub fn from_rule(rule: &CallAuthorityRule) -> Self {
        Self {
            subject: rule.subject.clone(),
            presenter: rule.presenter,
            target: rule.target.clone(),
        }
    }

    /// Encode the key in its durable lexicographic scan order.
    pub fn encoded(&self) -> Result<Vec<u8>, FederationError> {
        fn append_name(key: &mut Vec<u8>, name: &str) -> Result<(), FederationError> {
            let len = u16::try_from(name.len()).map_err(|_error| FederationError::Capacity)?;
            key.extend_from_slice(&len.to_be_bytes());
            key.extend_from_slice(name.as_bytes());
            Ok(())
        }

        let mut key = Vec::with_capacity(256);
        key.extend_from_slice(self.presenter.as_bytes());
        match &self.subject {
            FederationSubject::Node(node) => {
                key.push(1);
                key.extend_from_slice(node.as_bytes());
            }
            FederationSubject::Hosted(hosted) => {
                key.push(2);
                key.extend_from_slice(&hosted.issuer.as_bytes());
                append_name(&mut key, &hosted.namespace)?;
                append_name(&mut key, &hosted.subject)?;
            }
        }
        append_name(&mut key, self.target.export.as_str())?;
        append_name(&mut key, self.target.path.as_str())?;
        append_name(&mut key, self.target.method.as_str())?;
        key.extend_from_slice(&self.target.contract_digest);
        Ok(key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Current revision and policy of one exact method grant.
pub struct CallAuthorityEntry {
    /// Compare-and-swap revision of the rule.
    pub revision: u64,
    /// Current rule for this exact grant key.
    pub rule: CallAuthorityRule,
}

/// Atomic call directory and method-grant port. A durable implementation must
/// recheck its own peer, subject and method policy in the same transaction as
/// each state transition. It must never infer that absent evidence means the
/// method did not run. A Kernel bridge uses the CallRef as the stable local
/// acceptance identity and reconciles Preparing before submitting work again.
pub trait FederationCallStore: Send + Sync {
    /// Bind the host's trusted clock to local call decisions, sampling only
    /// after acquiring the backend writer or mutation lock. The bound view
    /// ignores stale caller timestamps, preserves the shared clock floor and
    /// rejects genuine rollback. The clock supplies no remote authorization:
    /// remote decisions still need their separate verified proof, and local
    /// accepted-work receipts must remain recordable after remote revocation.
    /// Delivery validation keeps its separate read-only clock/floor contract.
    /// The callback must be fast and must not reenter the store. Unsupported
    /// custom stores fail closed; a live bridge requires this port at creation.
    fn bind_local_call_clock(
        &self,
        _clock: std::sync::Arc<dyn crate::FederationObjectClock>,
    ) -> Result<std::sync::Arc<dyn FederationCallStore>, FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Revalidate payload disclosure for the original actor against current
    /// method, peer and export authority. This is not Inspect: cancellation
    /// receipts can remain visible after revocation, but retained output cannot.
    /// Read only: do not persist time, execute, clone output, extend retention
    /// or change call state. Blocking backends require bounded host workers.
    /// `retained_output_until_ms` is the locally admitted output's exclusive
    /// retention deadline, or None for unresolved-effect identities only.
    /// Recheck that exact deadline; queueing does not extend result visibility.
    fn authorize_call_delivery(
        &self,
        _request: &InspectCallRequest,
        _retained_output_until_ms: Option<u64>,
        _now_ms: u64,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_call_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationCallStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Return the node whose calls and grants this store owns.
    fn local_node(&self) -> FederationNodeId;

    /// Create or change an exact method grant using its expected revision.
    fn set_call_authority(
        &self,
        expected_revision: Option<u64>,
        rule: CallAuthorityRule,
    ) -> Result<u64, FederationError>;

    /// Read the current exact grant for CAS reconciliation. A disabled grant
    /// remains visible so it cannot accidentally be recreated at revision 1.
    fn call_authority(
        &self,
        key: &CallAuthorityKey,
    ) -> Result<Option<CallAuthorityEntry>, FederationError>;

    /// Return at most 256 entries after an exclusive semantic key. Callers
    /// advance with `CallAuthorityKey::from_rule` on the last returned entry.
    fn scan_call_authorities(
        &self,
        after: Option<&CallAuthorityKey>,
        max: usize,
    ) -> Result<Vec<CallAuthorityEntry>, FederationError>;

    /// Read only an already committed reservation for this exact origin and
    /// request. A caller may use this after a deadline or method removal to
    /// recover the original CallRef for cancellation. It never admits new work.
    fn prepared_call_for_request(
        &self,
        request: &PrepareCallRequest,
    ) -> Result<Option<CallPrepared>, FederationError>;

    /// Reserve or replay one origin request after checking current authority.
    fn prepare_call(
        &self,
        request: PrepareCallRequest,
        now_ms: u64,
    ) -> Result<CallPrepared, FederationError>;

    /// Claims the original work identity once. This is not Kernel acceptance.
    fn invoke_call(
        &self,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Result<CallInvoked, FederationError>;

    /// Only the trusted local bridge binds the original local execution identity.
    /// It must do so before transferring work to the live task owner. A different
    /// binding for the same CallRef is always a conflict.
    fn bind_kernel_identity(
        &self,
        call: CallRef,
        binding: CallKernelBinding,
        now_ms: u64,
    ) -> Result<CallKernelBinding, FederationError>;

    /// Local admission data, including the input committed with Preparing.
    fn kernel_call(&self, call: CallRef, now_ms: u64) -> Result<CallKernelView, FederationError>;

    /// Reauthorize running the original body against its retained grant and
    /// current peer/export/method revisions. Cleanup can use kernel_call even
    /// when this check denies further execution.
    fn authorize_kernel_execution(&self, call: CallRef, now_ms: u64)
    -> Result<(), FederationError>;

    /// Trusted bridge closes Preparing only while it owns the original
    /// admission and can prove that no execution worker was accepted.
    fn close_unaccepted_call(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError>;

    /// Bounded keyset page for admission, cancellation and terminal observations.
    /// A retained row does not authorize restarting its program.
    fn scan_pending_kernel_calls(
        &self,
        after: Option<[u8; 32]>,
        max: usize,
    ) -> Result<Vec<CallRef>, FederationError>;

    /// Trusted host requests stopping original work once its fixed execution
    /// deadline has passed. This is distinct from a remote Cancel receipt.
    fn request_call_deadline_stop(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError>;

    /// Only the local execution bridge reports a checked Kernel acceptance.
    fn record_kernel_acceptance(
        &self,
        call: CallRef,
        acceptance_digest: Digest,
    ) -> Result<CallInvoked, FederationError>;

    /// Called only after the live owner accepts cancellation of original work.
    fn record_kernel_cancel_accepted(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError>;

    /// Called after the original execution is observed stopped or retired.
    fn record_execution_stopped(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError>;

    /// Only the local execution bridge reports a durable result and unresolved
    /// effect identities after observing the original Kernel work.
    fn record_call_result(
        &self,
        call: CallRef,
        result: PersistedCallResult,
        unresolved_effect_ids: Vec<[u8; 32]>,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError>;

    /// Inspect retained evidence without exposing local Kernel identifiers.
    fn inspect_call(
        &self,
        request: InspectCallRequest,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError>;

    /// Apply or replay an origin-authenticated cancellation request.
    fn cancel_call(
        &self,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Result<CallCancelled, FederationError>;
}
