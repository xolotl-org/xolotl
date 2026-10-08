#![forbid(unsafe_code)]

//! `xolotl-gateway` - the shared Gateway runtime.
//!
//! A Gateway verifies transport credentials, maps them to Xolotl identities, and
//! submits typed requests through the kernel executor.
//!
//! Protocol adapters stay thin. They parse transport frames and credentials,
//! then call this crate so authentication, profile mapping, exposed surfaces,
//! limits, taint, audit, and Handle ownership remain one shared boundary.
//! Request authority is rechecked before each resource dispatch and before
//! protected delivery. Revocation rejects undispatched work without rolling
//! back accepted effects or erasing their reconciliation evidence.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use xolotl_graph::{DoNode, OperationTemplate, WaitSpec};
use xolotl_kernel::host::AbortTask;
use xolotl_kernel::{
    Bootstrap, CompiledRequestGrantTemplate, Executor, GatewayAudit, RequestProcess,
};
use xolotl_state::StateCursor;
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{
    BlobRef, Capability, CompletionOrigin, CostModel, ExecutionOutput, Failure, GrantMethods,
    GrantRights, OutputMode, Path, ProcessId, ReplayClass, ResourceName, ResourceSelector,
    StreamMarker, UnresolvedOperations, Value, ValueMap, ValueView,
};
#[cfg(test)]
use xolotl_types::{Outcome, ProcessStatus, TaintSet};

mod auth;
mod idempotency_store;
#[cfg(feature = "test-support")]
pub use idempotency_store::tests::gateway_idempotency_acceptance;
pub use idempotency_store::{
    GatewayEvidenceNamespace, GatewayIdempotencyLimits, GatewayIdempotencyRecord,
    GatewayIdempotencyStore, GatewayIdempotencyUsage, MemoryGatewayIdempotencyStore,
};
mod maintenance_health;
mod object;
mod paths;
mod profile;
mod request_registry;
mod request_scope;
mod schema;
mod submission;
mod transport;
pub mod value_inspection;

pub mod external;

use maintenance_health::MaintenanceHealth;
pub use maintenance_health::{
    GatewayMaintenanceProgress, GatewayMaintenanceState, GatewayMaintenanceStatus,
};
#[cfg(test)]
use submission::idempotency::submission_hash;
use submission::idempotency::{
    finish_request_without_idempotency_and_fail, required_idempotency_material,
};
pub use submission::{
    GatewayOutputChunk, GatewayOutputEvent, GatewayOutputStream, GatewayPreparation,
};
pub use xolotl_kernel::host::HostDeadline;
pub use xolotl_kernel::stream::StreamWindow;

/// Positive Gateway profile revision bound to sessions and submissions.
///
/// The complete inclusive range `1..=u64::MAX` is valid; zero is invalid.
/// Sessions, acceptance and retained request evidence preserve this range
/// without narrowing it to a signed integer. The retained acceptance encoding
/// and validation contract is defined by [`GatewayAccepted::profile_rev`].
pub type GatewayProfileRev = u64;
/// Monotonic generation for credential and principal state.
pub type GatewayGeneration = u64;

pub use auth::{
    BearerToken, BearerTokenHash, ClientCertificateCredential, ClientCertificateDerSha384,
    GatewayAuthMethod, GatewayCredential, GatewayIdentityMapping, GatewaySession,
    PresentedCredential, VerifiedPrincipal,
};
use auth::{GatewayCredentialKind, hash_bearer_token};
pub use object::{
    BeginObjectUploadRequest, CommitObjectUploadResponse, GatewayObjectDownload, GatewayObjectKind,
    GatewayObjectReadGrant, GatewayObjectUpload, GatewayObjectUploadTicket,
    GatewayPayloadProvenance, IssueObjectReadGrantRequest, IssueObjectUploadTicketRequest,
    ObjectStoreProof, OpenObjectReadRequest,
};
#[cfg(feature = "structured-output")]
pub use object::{
    GatewayExternalizedOutput, GatewayOutputDisclosurePolicy, GatewayOutputDisclosureRequest,
    GatewayOutputExternalizationError, GatewayOutputExternalizer, GatewayOutputKind,
    GatewayOutputObjectOptions,
};
use profile::{CompiledGatewayProfile, CompiledSurfaceDescriptor};
pub use profile::{
    GATEWAY_PROFILES_PREFIX, GatewayBudgetProfile, GatewayLimitProfile,
    GatewayPrincipalSurfaceBinding, GatewayProfile, GatewayProfileDocument, GatewayPublication,
    GatewaySurface, gateway_profile_id, gateway_profile_path,
};
#[cfg(test)]
use request_registry::{COMPLETED_REQUEST_RETENTION, prune_request_history};
use request_registry::{
    GatewayBudgetCharge, GatewayRequestEntry, GatewayRequestGuard, GatewayRequestLease,
    GatewayRequestRegistry, GatewayRequestState, spawn_deadline_sweeper, sweep_expired_requests,
};
use schema::{validate_surface_input, validate_surface_stream_item};
pub use transport::{
    GatewayAllowedHost, GatewayAllowedOrigin, GatewayTransportSecurityConfig,
    GatewayTransportSecurityMode, GatewayTrustedProxyConfig, GatewayUnsafeTransportRelaxation,
    browser_origin_allowed, gateway_host_allowed, local_trusted_browser_origin,
};

const MAX_LOWERED_SUBMISSION_NODES: usize = 4096;
const MAX_LOWERED_SUBMISSION_DEPTH: usize = 128;
const DEFAULT_MAX_LITERAL_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_COLLECT_LIMIT: usize = 1024;
const DEFAULT_MAX_DEADLINE_MS_FROM_NOW: i64 = 5 * 60 * 1000;
const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1024;
const DEFAULT_MAX_PRINCIPAL_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_SURFACE_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_RISK_CLASS_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_RECENT_CANCELLATIONS: usize = 4096;
const DEFAULT_MAX_STREAM_ITEMS: usize = 4096;
const DEFAULT_MAX_STREAM_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_STREAM_INLINE_ITEM_BYTES: usize = 1024 * 1024;
const DEFAULT_BUDGET_MAX_INFLIGHT_OPS: u64 = 8192;
const DEFAULT_BUDGET_MAX_BYTES_IN: u64 = 64 * 1024 * 1024;
const DEFAULT_BUDGET_MAX_INLINE_VALUE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_BUDGET_MAX_STREAM_ITEMS: u64 = 64 * 1024;
const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 1024;
const GATEWAY_REQUEST_ID_RANDOM_BYTES: usize = 16;
const GATEWAY_EFFECT_METHOD: &str = "invoke";
const GATEWAY_EFFECT_HANDLE_VERB: &str = "perform";

/// Errors surfaced by gateway authentication, authorization, profile
/// compilation, request admission, and kernel setup.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Credentials were absent or failed validation.
    #[error("authentication failed")]
    Unauthenticated,
    /// Authenticated principal is not allowed to use this gateway.
    #[error("principal {0} is not authorized for this gateway")]
    Unauthorized(String),
    /// Gateway profile is malformed or references unavailable runtime state.
    #[error("gateway profile invalid: {0}")]
    InvalidProfile(String),
    /// The request was rejected by gateway admission or kernel setup.
    #[error("request rejected: {0}")]
    Rejected(String),
    /// The request could not start because a bounded gateway resource is full.
    #[error("gateway limit exceeded: {0}")]
    LimitExceeded(String),
    /// A mutation or execution may have taken effect, but the gateway cannot
    /// prove the final verdict. Reconcile the original identity before retrying.
    #[error("gateway operation outcome unknown: {0}")]
    Indeterminate(String),
    /// Execution was observed, but its complete result could not be settled or
    /// delivered. The original acceptance and known effect identities survive.
    #[error("gateway submission outcome unknown: {}", .0.detail)]
    SubmissionIndeterminate(Box<GatewaySubmissionIndeterminate>),
}

/// Evidence retained when an accepted submission cannot deliver a complete result.
#[derive(Debug)]
pub struct GatewaySubmissionIndeterminate {
    /// Original server acceptance; it never authorizes a fresh execution.
    pub accepted: GatewayAccepted,
    /// Bounded host-observed effect identities for external reconciliation.
    pub unresolved_operations: UnresolvedOperations,
    /// Stable, redacted explanation for protocol clients.
    pub reason_code: &'static str,
    detail: String,
}

impl GatewayError {
    pub(crate) fn is_indeterminate(&self) -> bool {
        matches!(
            self,
            Self::Indeterminate(_) | Self::SubmissionIndeterminate(_)
        )
    }

    pub(crate) fn with_request_cleanup_failure(self, reason: String) -> Self {
        match self {
            Self::Indeterminate(detail) => {
                Self::Indeterminate(format!("{detail}; request cleanup failed: {reason}"))
            }
            Self::SubmissionIndeterminate(mut evidence) => {
                evidence.detail = format!("{}; request cleanup failed: {reason}", evidence.detail);
                evidence.unresolved_operations.identities_incomplete = true;
                Self::SubmissionIndeterminate(evidence)
            }
            other => Self::Indeterminate(format!("{other}; request cleanup failed: {reason}")),
        }
    }

    /// Preserve host-observed acceptance and effect evidence after settlement
    /// or delivery fails. This record never authorizes a new execution.
    pub fn submission_indeterminate(
        accepted: GatewayAccepted,
        unresolved_operations: UnresolvedOperations,
        reason_code: &'static str,
        detail: String,
    ) -> Self {
        Self::SubmissionIndeterminate(Box::new(GatewaySubmissionIndeterminate {
            accepted,
            unresolved_operations,
            reason_code,
            detail,
        }))
    }

    /// Redacted message suitable for returning to an external client.
    pub fn public_message(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "authentication failed",
            GatewayError::Unauthorized(_) => "authorization failed",
            GatewayError::InvalidProfile(_)
            | GatewayError::Rejected(_)
            | GatewayError::LimitExceeded(_) => "request rejected",
            GatewayError::Indeterminate(_) | GatewayError::SubmissionIndeterminate(_) => {
                "outcome unknown; reconcile before retrying"
            }
        }
    }

    /// Stable audit outcome tag for this error.
    pub fn audit_outcome(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "auth_failed",
            GatewayError::Unauthorized(_) => "permission_denied",
            GatewayError::InvalidProfile(_) => "profile_invalid",
            GatewayError::Rejected(_) => "request_rejected",
            GatewayError::LimitExceeded(_) => "limit_exceeded",
            GatewayError::Indeterminate(_) | GatewayError::SubmissionIndeterminate(_) => {
                "outcome_unknown"
            }
        }
    }

    /// Stable lower-snake wire error code.
    pub fn code(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "unauthenticated",
            GatewayError::Unauthorized(_) => "permission_denied",
            GatewayError::InvalidProfile(_) => "profile_invalid",
            GatewayError::Rejected(_) => "request_rejected",
            GatewayError::LimitExceeded(_) => "limit_exceeded",
            GatewayError::Indeterminate(_) | GatewayError::SubmissionIndeterminate(_) => {
                "outcome_unknown"
            }
        }
    }
}

/// Authenticated, redacted profile descriptor returned by gateway discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDescriptor {
    /// Active profile name.
    pub profile_name: String,
    /// Active profile revision.
    pub profile_rev: GatewayProfileRev,
    /// Profile surfaces visible to the authenticated session.
    pub surfaces: Vec<GatewaySurfaceDescriptor>,
    /// Protocol publications visible to the authenticated session.
    pub publications: Vec<GatewayPublicationDescriptor>,
    /// Effective gateway admission limits for this profile.
    pub limits: GatewayLimitProfile,
}

/// Profile authentication readiness, independent of maintenance task health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayReadiness {
    /// The active profile can authenticate clients.
    Ready,
    /// The active profile is serving as the last known good snapshot.
    DegradedLastKnownGood,
    /// The active profile is closed and authenticates nobody.
    NotReadyClosed,
}

impl GatewayReadiness {
    /// Return the stable status label for this readiness state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::DegradedLastKnownGood => "degraded_lkg",
            Self::NotReadyClosed => "not_ready_closed",
        }
    }
}

/// Redacted metadata for the most recent failed profile reload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProfileReloadFailure {
    /// Profile revision supplied by the failed reload attempt.
    pub attempted_profile_rev: GatewayProfileRev,
    /// Stable low-cardinality failure code.
    pub code: String,
    /// Public failure summary.
    pub public_message: String,
}

/// Redacted runtime status for health and diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRuntimeStatus {
    /// Active profile name.
    pub profile_name: String,
    /// Active profile revision.
    pub profile_rev: GatewayProfileRev,
    /// True when the runtime can authenticate at least one client.
    pub ready: bool,
    /// Current readiness class.
    pub readiness: GatewayReadiness,
    /// True when a failed reload left the previous snapshot active.
    pub lkg_active: bool,
    /// Consecutive failed reload attempts since the last successful swap.
    pub consecutive_failed_reloads: u64,
    /// Most recent redacted reload failure, if any.
    pub last_reload_failure: Option<GatewayProfileReloadFailure>,
    /// Request and object maintenance progress or the host's manual responsibility.
    /// Profile readiness is independent of this status.
    pub maintenance: GatewayMaintenanceStatus,
}

/// One profile surface visible through authenticated discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySurfaceDescriptor {
    /// Stable surface id within the profile.
    pub surface_id: String,
    /// Original ledger, Profile, subject and surface binding for guarded retries.
    /// Retain this before submitting; never replace it for an uncertain request.
    /// This fingerprint is not authority or an execution-liveness guarantee.
    pub request_scope: String,
    /// Resource target exposed through this surface.
    pub target: ResourceName,
    /// Capability literal required before this surface may be published.
    publish_capability: Option<String>,
    /// Input schema descriptor advertised for this surface.
    pub input_schema: Option<Value>,
    /// Output schema descriptor advertised for this surface.
    pub output_schema: Option<Value>,
    /// Schema for each incremental output value, independent of the final value.
    pub output_stream_schema: Option<Value>,
}

impl GatewaySurfaceDescriptor {
    /// Return whether a publishing capability is allowed for this surface.
    pub fn allows_publish_capability(&self, capability: &str) -> bool {
        let Some(surface_publish) = &self.publish_capability else {
            return false;
        };
        let Ok(surface_publish) = Capability::parse(surface_publish) else {
            return false;
        };
        let Ok(candidate) = Capability::parse(capability) else {
            return false;
        };
        surface_publish.covers_cap(&candidate)
    }
}

/// One protocol publication visible through authenticated discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPublicationDescriptor {
    /// Protocol adapter that owns this publication.
    pub protocol: String,
    /// Protocol object kind inside the adapter.
    pub kind: String,
    /// Protocol-visible stable name.
    pub name: String,
    /// Protocol-visible address when it is distinct from `name`.
    pub address: Option<String>,
    /// Published Gateway surface id.
    pub surface_id: String,
    /// Optional protocol display title.
    pub title: Option<String>,
    /// Optional human-readable protocol description.
    pub description: Option<String>,
    /// Optional protocol-specific properties.
    pub properties: BTreeMap<String, Value>,
    /// Optional protocol annotations.
    pub annotations: Option<Value>,
    /// Optional protocol metadata.
    pub metadata: Option<Value>,
}

/// Client options attached to one Gateway submission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubmitOptions {
    /// Original scope advertised for this authenticated surface. Required when
    /// supplying an idempotency key or submission token. Preparation rejects a
    /// mismatch before reservation or effects; retry never refreshes this value.
    pub expected_request_scope: Option<String>,
    /// Client supplied idempotency key for non-idempotent retry boundaries.
    /// Literal material; no prefix syntax or account/surface authority.
    pub idempotency_key: Option<String>,
    /// Server-issued token for retry-safe non-idempotent submission.
    /// Literal material; carrying a token does not grant authority.
    pub submission_token: Option<String>,
    /// Store-wide retry range, default zero. Changing the epoch starts a new
    /// request and never inherits a prior result; clients must not advance an
    /// uncertain request automatically. Closed identities may query retained
    /// evidence but cannot execute anew. Discover the range via Gateway.
    pub retry_epoch: u64,
    /// Client requested deadline in milliseconds since Unix epoch. A request
    /// whose effective deadline exceeds the profile ceiling is rejected.
    pub deadline_ms: Option<u64>,
}

/// A typed submission accepted by the gateway runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySubmission {
    surface_id: String,
    body: GatewaySubmissionBody,
    requested_output: OutputMode,
    options: SubmitOptions,
    server_deadline: Option<HostDeadline>,
}

/// Payload-independent submission fields frozen before preparation work.
#[derive(Clone, Debug)]
pub struct GatewaySubmissionHead {
    /// Profile surface selected for submission, not a resource authority grant.
    pub surface_id: String,
    /// Output port to reserve before materializing or inspecting the payload.
    pub requested_output: OutputMode,
    /// Client timeout and optional request-idempotency identity.
    pub options: SubmitOptions,
    /// Additional host or transport deadline in this runtime's clock domain.
    pub server_deadline: Option<HostDeadline>,
}

impl GatewaySubmissionHead {
    /// Select a surface for ordinary unary input preparation.
    pub fn direct_input(surface_id: impl Into<String>) -> Self {
        Self {
            surface_id: surface_id.into(),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
            server_deadline: None,
        }
    }
}

impl GatewaySubmission {
    /// Submit one `Value` through a declared Gateway surface.
    pub fn direct_input(surface_id: impl Into<String>, payload: Value) -> Self {
        Self {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload,
                provenance: None,
            }),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
            server_deadline: None,
        }
    }

    /// Open one admitted input stream for a declared Gateway surface.
    pub fn input_stream(surface_id: impl Into<String>, open: GatewayStreamOpenRequest) -> Self {
        Self {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::InputStream(open),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
            server_deadline: None,
        }
    }

    /// Attach provenance to a direct input submission.
    pub fn with_provenance(mut self, provenance: GatewayPayloadProvenance) -> Self {
        match &mut self.body {
            GatewaySubmissionBody::DirectInput(input) => input.provenance = Some(provenance),
            GatewaySubmissionBody::InputStream(_) => {}
        }
        self
    }

    /// Set the requested output mode.
    pub fn with_requested_output(mut self, output: OutputMode) -> Self {
        self.requested_output = output;
        self
    }

    /// Replace submission options.
    pub fn with_options(mut self, options: SubmitOptions) -> Self {
        self.options = options;
        self
    }

    /// Bound this submission by a transport-owned monotonic deadline from
    /// [`Gateway::deadline_after`]. Client options cannot extend this bound.
    pub fn with_server_deadline(mut self, deadline: HostDeadline) -> Self {
        self.server_deadline = Some(deadline);
        self
    }

    /// Surface boundary selected by the caller.
    pub fn surface_id(&self) -> &str {
        &self.surface_id
    }

    /// Requested output mode.
    pub fn requested_output(&self) -> OutputMode {
        self.requested_output
    }

    /// Retry/deadline/encoding options.
    pub fn options(&self) -> &SubmitOptions {
        &self.options
    }
}

/// Server-generated acceptance metadata for one Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAccepted {
    /// Collision-resistant server authority for cancellation and replay.
    pub submission_id: String,
    /// Trace identity generated independently from `submission_id`.
    pub trace_root: String,
    /// Positive full-width u64 profile revision that admitted the request.
    ///
    /// Retained records encode `accepted_profile_rev` as a positive integer
    /// through `i64::MAX`; larger values through `u64::MAX` use a canonical
    /// unsigned decimal string without a sign or leading zeros. Small values
    /// must use the integer representation, not a string.
    ///
    /// Encoding rejects zero or a revision inconsistent with the original
    /// request fingerprint before serializing acceptance for settlement.
    /// Decoding rejects negative integers, zero, floats, signs, leading zeros,
    /// nondecimal characters, string overflow and noncanonical representations.
    /// It validates the complete original request fingerprint and requires this
    /// revision to match that binding without truncation or loss of precision.
    pub profile_rev: GatewayProfileRev,
    /// Surface boundary used for admission, if one was selected.
    pub surface_id: String,
}

/// Result of a completed Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySubmitResult {
    /// Server acceptance metadata for the request.
    pub accepted: GatewayAccepted,
    /// Final execution outcome and its data and control provenance.
    pub output: ExecutionOutput,
    /// Whether this Gateway request executed or reused a retained request result.
    /// Cache hits within the executed program remain `CurrentAttempt` here.
    pub origin: CompletionOrigin,
}

/// Runtime-owned admission context for one accepted client input stream.
pub struct GatewayAcceptedInputStream {
    accepted: GatewayAccepted,
    open: GatewayStreamOpenRequest,
    limits: GatewayLimitProfile,
    profile: Arc<CompiledGatewayProfile>,
    session: GatewaySession,
    surface_id: String,
    requested_output: OutputMode,
    options: SubmitOptions,
    deadline: Option<HostDeadline>,
    request_guard: GatewayRequestGuard,
    request_process: ProcessId,
    executor: Executor,
}

impl GatewayAcceptedInputStream {
    /// Return the server acceptance metadata bound to this stream.
    /// Reauthorize with [`Self::validate_delivery`] at actual disclosure.
    pub fn accepted(&self) -> &GatewayAccepted {
        &self.accepted
    }

    /// Check the original session and surface against the current runtime
    /// profile before disclosing cached acceptance metadata.
    pub fn validate_delivery(&self) -> Result<(), GatewayError> {
        self.request_guard.lease.delivery.validate()
    }

    /// Return the admitted stream declaration.
    pub fn open_request(&self) -> &GatewayStreamOpenRequest {
        &self.open
    }

    /// Return the profile limits that bound the stream chunks.
    pub fn limits(&self) -> &GatewayLimitProfile {
        &self.limits
    }

    /// Validate one decoded input stream item against the admitted surface.
    pub fn validate_chunk_item(&self, item: &Value) -> Result<(), GatewayError> {
        let surface = self
            .profile
            .surface_by_id(&self.surface_id)
            .ok_or_else(|| {
                GatewayError::Rejected("stream surface is no longer available".into())
            })?;
        validate_surface_stream_item(surface, self.open.modality, item)
    }
}

/// Cancellation request scoped to the authenticated principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayCancelRequest {
    /// Server-generated submission id returned by `submit`.
    pub submission_id: String,
    /// Trace root returned with the same submission.
    pub trace_root: String,
    /// Optional caller-visible reason for audit or transport delivery.
    pub reason: Option<String>,
}

/// The body of a Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GatewaySubmissionBody {
    /// Direct kernel `Value` input lowered by the selected surface.
    DirectInput(GatewayDirectInput),
    /// Stream-open request admitted before transport chunks are folded into a
    /// direct input payload.
    InputStream(GatewayStreamOpenRequest),
}

/// Direct input payload. The payload is exactly the kernel `Value`; large refs
/// are expressed as `Value::{Blob,Tensor,Frame}` and require provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GatewayDirectInput {
    /// Kernel value supplied by the client.
    pub(crate) payload: Value,
    /// Provenance for inbound large refs.
    pub(crate) provenance: Option<GatewayPayloadProvenance>,
}

/// Stream-open request carried on streaming transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamOpenRequest {
    /// Client stream id, scoped to a single submission.
    pub stream_id: String,
    /// Declared direction.
    pub direction: GatewayStreamDirection,
    /// Declared modality.
    pub modality: GatewayModality,
    /// Profile-selected stream item schema id; client requests leave it empty.
    pub item_schema_id: String,
    /// Maximum inline item bytes requested by the client.
    pub max_inline_item_bytes: u64,
    /// Optional item cap.
    pub max_items: Option<u64>,
    /// Optional byte cap.
    pub max_bytes: Option<u64>,
}

/// Gateway stream direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayStreamDirection {
    /// Client sends items to kernel.
    ClientToKernel,
    /// Kernel sends items to client.
    KernelToClient,
    /// State subscription delivery to client.
    StateSubscriptionToClient,
}

/// Transport modality aligned to kernel `Value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayModality {
    /// General structured values accepted by the surface schema.
    Value,
    /// Text values carried inline.
    Text,
    /// Opaque byte values carried inline or by an admitted object reference.
    Bytes,
    /// Typed tensor references with a dtype and shape.
    Tensor,
    /// Timestamped audio frame references.
    AudioFrame,
    /// Timestamped video frame references.
    VideoFrame,
    /// Timestamped pose or trajectory frame references.
    PoseFrame,
    /// Timestamped sensor frame references.
    SensorFrame,
    /// Structured event items interpreted by the surface schema.
    Event,
    /// Control messages interpreted by the surface schema.
    Control,
}

/// One stream item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamChunk {
    /// Stream identifier within the active submission.
    pub stream_id: String,
    /// Sequence number used to validate ordered delivery within the stream.
    pub seq: u64,
    /// Payload validated against the stream's admitted modality and limits.
    pub item: Value,
    /// Upload ticket or store proof required when the payload contains objects.
    pub provenance: Option<GatewayPayloadProvenance>,
}

/// Terminal stream marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamEnd {
    /// Stream identifier within the active submission.
    pub stream_id: String,
    /// Terminal sequence number following the admitted stream items.
    pub seq: u64,
    /// Graceful completion or an explicit stream failure.
    pub marker: StreamMarker,
}

/// Static inspection result for a lowered submission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LoweredSubmissionInspection {
    node_count: usize,
    max_depth: usize,
    literal_bytes: usize,
    operation_count: usize,
    estimated_cost_micro_usd: u64,
    step_ref_count: usize,
    wait_signal_count: usize,
    wait_deadline_count: usize,
}

/// Literal retry material, normalized and validated exactly as for submission.
/// Neither variant grants authority or identifies a request across profiles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayRequestIdentity {
    /// Caller-provided idempotency key.
    IdempotencyKey(String),
    /// Caller-provided submission token.
    SubmissionToken(String),
}

/// Point lookup bound to the original scope and retry epoch, without a payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequestLookup {
    /// Original surface identifier.
    pub surface_id: String,
    /// Original descriptor's request scope; a changed scope rejects disclosure.
    pub expected_request_scope: String,
    /// Original retry epoch, including a closed epoch with retained evidence.
    pub retry_epoch: u64,
    /// Original retry identity, not authorization.
    pub identity: GatewayRequestIdentity,
}

/// Retained request evidence, not an execution-liveness assertion.
#[derive(Clone, Debug)]
pub enum GatewayRequestEvidence {
    /// No retained record was observed; this does not prove non-execution.
    Unproven,
    /// A reservation exists; this proves neither running nor acceptance.
    Reserved,
    /// Bounded original acceptance, result class and unresolved-effect evidence.
    /// No result payload or failure details are disclosed and no export is created.
    /// Backend read/decode is bounded by the store's existing `max_record_bytes`,
    /// not independent of the retained payload's size.
    Settled(Box<GatewayRequestSummary>),
    /// Result retired; the original request must not execute again.
    Retired,
}

/// Payload-independent projection of the original settled record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequestSummary {
    /// Original acceptance, not a newly accepted attempt.
    pub accepted: GatewayAccepted,
    /// Original terminal class without value or error details.
    pub result_class: GatewayRequestResultClass,
    /// Bounded unresolved operation identities; omissions remain explicit.
    pub unresolved_operations: xolotl_types::UnresolvedOperations,
}

/// Terminal classification that does not disclose result contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayRequestResultClass {
    /// Normal completion.
    Done,
    /// Short-circuit completion.
    Short,
    /// Known program failure.
    Fail,
}

/// Read-only retained-result availability, without authorizing execution.
#[derive(Clone, Debug)]
pub enum GatewayRetainedRequestResult {
    /// Original cached result, ready for adapter-controlled delivery.
    Available(Box<GatewaySubmitResult>),
    /// No retained result was observed; execution is not disproven.
    Unproven,
    /// Only a reservation was observed; execution liveness is not proven.
    Reserved,
    /// The result was retired and the original identity cannot execute again.
    Retired,
}

/// The shared gateway contract. Implementors verify credentials, map them to a
/// session, and run typed submissions through a profile-bound runtime.
#[async_trait]
pub trait Gateway: Send + Sync {
    /// Project a transport timeout into this Gateway's host clock domain.
    fn deadline_after(&self, duration: Duration) -> Result<HostDeadline, GatewayError>;

    /// Return redacted runtime status for transport handshakes and health.
    fn status(&self) -> GatewayRuntimeStatus;

    /// Inspect Host/SNI authorities currently registered for this listener.
    /// Request authorization must use [`Self::validate_session_authority`] so
    /// hosts and session generation come from the same profile snapshot.
    fn registered_gateway_hosts(&self) -> Vec<GatewayAllowedHost>;

    /// Return browser origins currently registered for browser transports.
    fn registered_browser_origins(&self) -> Vec<GatewayAllowedOrigin>;

    /// Verify a credential and create a Gateway session.
    async fn authenticate(
        &self,
        credential: PresentedCredential,
    ) -> Result<GatewaySession, GatewayError>;

    /// Validate the current session and its request authority against one
    /// profile snapshot. A transport resolves verified proxy headers before
    /// calling this; a separately read host list is not an authorization check.
    fn validate_session_authority(
        &self,
        session: &GatewaySession,
        authority: &str,
    ) -> Result<(), GatewayError>;

    /// Describe the active profile for an authenticated session.
    ///
    /// This is intentionally authenticated: unauthenticated discovery must not
    /// expose resource paths, effect names, capability literals, or limits.
    fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError>;

    /// Discover the current request retry range under existing session authority.
    /// Closure is a trusted storage-owner action, not application authority.
    async fn retry_epoch(&self, session: &GatewaySession) -> Result<u64, GatewayError>;

    /// Read one original request's evidence under current session, principal,
    /// surface and scope authority, rechecked after the store await. This uses
    /// no Process, execution slot, reservation, settlement, audit write or scan,
    /// and neither requires an open epoch nor advances it. Corrupt records are
    /// errors, never absence. No historical profile is searched or inferred.
    /// Transports must still check access at actual emission after later awaits.
    /// Backend observation still reads/decodes the original record, bounded by
    /// the store's existing `max_record_bytes`; this is not payload-independent
    /// allocation or I/O. No result payload is disclosed or exported.
    /// Settled projection validates record metadata and required payload shape,
    /// not the complete payload codec. In particular, failure JSON is not parsed;
    /// delivery/replay rejects corrupt payloads without changing settled evidence.
    async fn lookup_request(
        &self,
        session: &GatewaySession,
        lookup: GatewayRequestLookup,
    ) -> Result<GatewayRequestEvidence, GatewayError>;

    /// Read only the original retained result under the same scope, epoch and
    /// identity checks as lookup, including closed epochs. Never executes,
    /// reserves, settles or creates an export. Unproven, reserved and retired
    /// records are explicitly unavailable states. A successful result has
    /// cached origin; adapters own bounded inline delivery or configured export
    /// and must recheck current delivery authority after all awaits.
    async fn read_retained_request_result(
        &self,
        session: &GatewaySession,
        lookup: GatewayRequestLookup,
    ) -> Result<GatewayRetainedRequestResult, GatewayError>;

    /// Authorize delivery of acceptance, output, and reconciliation evidence
    /// for the original session and surface under the current profile snapshot.
    /// Adapters must check after their last await, at actual emission (including
    /// cached acceptance and structured fallbacks). Denial withholds disclosure;
    /// it must not erase committed effects or re-execute the submission.
    fn validate_submission_access(
        &self,
        session: &GatewaySession,
        surface_id: &str,
    ) -> Result<(), GatewayError>;

    /// Reserve shared capacity before materializing or inspecting the payload.
    fn prepare_submission(
        &self,
        session: &GatewaySession,
        head: GatewaySubmissionHead,
        output_window: Option<StreamWindow>,
    ) -> Result<GatewayPreparation, GatewayError>;

    /// Consume preparation ownership without acquiring another admission slot.
    async fn submit_prepared(
        &self,
        preparation: GatewayPreparation,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError>;

    /// Transfer preparation ownership into incremental output execution.
    async fn submit_output_stream_prepared(
        &self,
        preparation: GatewayPreparation,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewayOutputStream, GatewayError>;

    /// Admit and run one Gateway submission as the session identity.
    async fn submit(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewaySubmitResult, GatewayError>;

    /// Admit an incremental output request. The returned owner drives execution
    /// while polled and cancels the request when dropped.
    async fn submit_output_stream(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
        window: StreamWindow,
    ) -> Result<GatewayOutputStream, GatewayError>;

    /// Admit a stream-open submission before accepting stream chunks.
    async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<Box<GatewayAcceptedInputStream>, GatewayError>;

    /// Complete an admitted input stream with the folded payload.
    async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError>;

    /// Mark an admitted input stream failed before dispatch.
    async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        reason: &str,
    ) -> Result<(), GatewayError>;

    /// Cancel an admitted request owned by the authenticated principal.
    fn cancel(
        &self,
        session: &GatewaySession,
        request: GatewayCancelRequest,
    ) -> Result<bool, GatewayError>;

    /// Issue a ticket for a subsequent object upload/commit.
    async fn issue_object_upload_ticket(
        &self,
        session: &GatewaySession,
        request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError>;

    /// Begin an owned incremental upload without collecting its input.
    /// The returned upload accepts borrowed chunks and publishes its receipt at commit.
    async fn begin_object_upload(
        &self,
        session: &GatewaySession,
        request: BeginObjectUploadRequest,
    ) -> Result<GatewayObjectUpload, GatewayError>;

    /// Open an authenticated byte range using an explicitly issued read grant.
    /// A reference or upload receipt alone cannot authorize a download.
    async fn open_object_read(
        &self,
        session: &GatewaySession,
        request: OpenObjectReadRequest,
    ) -> Result<GatewayObjectDownload, GatewayError>;

    /// Record required gateway-local audit metadata for an inbound request.
    /// Missing observation storage is an error.
    fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String>;

    /// Record an observation when the host installed observation storage.
    /// Selected storage failures remain errors. Implementations without an
    /// explicit storage-availability contract conservatively require recording.
    fn record_optional_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String> {
        self.record_gateway_audit(audit)
    }
}

/// Profile-driven in-process Gateway runtime over a [`Bootstrap`].
///
/// Every submission is statically admitted, stamped with inbound taint, then
/// executed as a fresh attenuated child Process. Handles are opened per request
/// Process from profile surfaces.
pub struct GatewayRuntime {
    boot: Arc<Bootstrap>,
    idempotency: Arc<dyn GatewayIdempotencyStore>,
    objects: ObjectStore,
    state: Arc<RwLock<GatewayRuntimeState>>,
    requests: Arc<GatewayRequestRegistry>,
    request_maintenance: Option<Arc<dyn AbortTask>>,
    object_maintenance: Option<Arc<dyn AbortTask>>,
    maintenance_health: MaintenanceHealth,
}

impl Drop for GatewayRuntime {
    fn drop(&mut self) {
        if let Some(task) = &self.request_maintenance {
            task.abort();
        }
        if let Some(task) = &self.object_maintenance {
            task.abort();
        }
    }
}

/// Position of the bounded Gateway maintenance pass. Keep one cursor per
/// manually driven runtime and reuse it across calls to [`GatewayRuntime::maintain_once`].
#[derive(Debug, Default)]
pub struct GatewayMaintenanceCursor {
    ticket_cursor: Option<StateCursor>,
    grant_cursor: Option<StateCursor>,
}

/// Work completed by one bounded Gateway maintenance pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayMaintenanceReport {
    /// Running requests whose monotonic deadline elapsed.
    pub expired_requests: usize,
    /// Expired request processes whose cancellation could not be confirmed.
    pub failed_request_cancellations: usize,
    /// Whether the State host exposed both query and bounded-write ports for
    /// Gateway object record scans. Otherwise the host owns record cleanup.
    pub object_scans_available: bool,
    /// Upload-ticket records examined in this pass.
    pub upload_tickets_examined: usize,
    /// Expired upload tickets removed in this pass.
    pub upload_tickets_removed: usize,
    /// Upload-ticket records too large for a bounded maintenance page.
    pub upload_tickets_skipped_oversized: usize,
    /// Object read-grant records examined in this pass.
    pub read_grants_examined: usize,
    /// Expired object read grants removed in this pass.
    pub read_grants_removed: usize,
    /// Read-grant records too large for a bounded maintenance page.
    pub read_grants_skipped_oversized: usize,
}

#[derive(Clone, Copy)]
enum GatewayMaintenanceMode {
    Automatic,
    Manual,
}

struct GatewayRuntimeState {
    profile: Arc<CompiledGatewayProfile>,
    lkg_active: bool,
    consecutive_failed_reloads: u64,
    last_reload_failure: Option<GatewayProfileReloadFailure>,
}

struct GatewaySubmissionAuthority {
    state: Arc<RwLock<GatewayRuntimeState>>,
    session: GatewaySession,
    surface_id: String,
}

impl std::fmt::Debug for GatewaySubmissionAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewaySubmissionAuthority")
            .finish_non_exhaustive()
    }
}

impl GatewaySubmissionAuthority {
    fn new(runtime: &GatewayRuntime, session: &GatewaySession, surface_id: &str) -> Arc<Self> {
        Arc::new(Self {
            state: runtime.state.clone(),
            session: session.clone(),
            surface_id: surface_id.into(),
        })
    }

    fn validate(&self) -> Result<(), GatewayError> {
        let profile = self.state.read().profile.clone();
        GatewayRuntime::validate_submission_profile_access(
            &profile,
            &self.session,
            &self.surface_id,
        )
        .map_err(|_access_error| {
            GatewayError::Indeterminate("submission delivery access unavailable".into())
        })
    }
}

#[async_trait]
impl xolotl_kernel::RequestAuthorizer for GatewaySubmissionAuthority {
    async fn authorize(&self) -> Result<(), Failure> {
        self.validate().map_err(|_access_error| Failure::Custom {
            kind: "gateway.request.authorization".into(),
            message: "gateway request authority unavailable".into(),
        })
    }
}

impl GatewayRuntime {
    /// Create a runtime backed by `boot` and an explicit profile.
    pub fn new(
        boot: Arc<Bootstrap>,
        profile: GatewayProfile,
        idempotency: Arc<dyn GatewayIdempotencyStore>,
    ) -> Result<Self, GatewayError> {
        Self::new_with_maintenance(
            boot,
            profile,
            idempotency,
            GatewayMaintenanceMode::Automatic,
        )
    }

    /// Create a Gateway for hosts that drive maintenance themselves.
    /// The host must call [`Self::maintain_once`] repeatedly while this Gateway
    /// is live, including while requests are idle, so deadlines and expired
    /// object authority are reclaimed. The host controls its own cadence.
    /// It must also call [`Bootstrap::drain_cleanup`] when abandoned request
    /// scopes need finalization. That call may wait for detached cleanup owners,
    /// so schedule it separately from a short maintenance tick.
    pub fn new_manual(
        boot: Arc<Bootstrap>,
        profile: GatewayProfile,
        idempotency: Arc<dyn GatewayIdempotencyStore>,
    ) -> Result<Self, GatewayError> {
        Self::new_with_maintenance(boot, profile, idempotency, GatewayMaintenanceMode::Manual)
    }

    fn new_with_maintenance(
        boot: Arc<Bootstrap>,
        profile: GatewayProfile,
        idempotency: Arc<dyn GatewayIdempotencyStore>,
        maintenance: GatewayMaintenanceMode,
    ) -> Result<Self, GatewayError> {
        idempotency.limits().validate()?;
        let profile = Arc::new(Self::compile_profile(&boot, profile)?);
        let requests = Arc::new(GatewayRequestRegistry::new(
            profile.limits.max_recent_cancellations,
            boot.kernel().host_runtime().clone(),
        ));
        let maintenance_started = boot.kernel().host_runtime().now();
        let object_scans_available =
            boot.kernel().state().has_query() && boot.kernel().state().has_bounded_write();
        let (request_maintenance, object_maintenance, maintenance_health) =
            if matches!(maintenance, GatewayMaintenanceMode::Automatic) {
                let (request, request_life) = spawn_deadline_sweeper(&boot, &requests)?;
                let object = match object::spawn_object_maintenance(&boot, &requests) {
                    Ok(object) => object,
                    Err(error) => {
                        request.abort();
                        return Err(error);
                    }
                };
                let (object_maintenance, object_records) = match object {
                    Some((task, life)) => (Some(task), Some(life)),
                    None => (None, None),
                };
                (
                    Some(request),
                    object_maintenance,
                    MaintenanceHealth::automatic(maintenance_started, request_life, object_records),
                )
            } else {
                (
                    None,
                    None,
                    MaintenanceHealth::manual(maintenance_started, object_scans_available),
                )
            };
        Ok(Self {
            boot,
            idempotency,
            objects: ObjectStore::new(),
            state: Arc::new(RwLock::new(GatewayRuntimeState {
                profile,
                lkg_active: false,
                consecutive_failed_reloads: 0,
                last_reload_failure: None,
            })),
            requests,
            request_maintenance,
            object_maintenance,
            maintenance_health,
        })
    }

    /// Replace the active profile snapshot.
    ///
    /// Compilation and resource resolution happen before the swap. If the new
    /// profile is malformed, the current snapshot remains active and the error
    /// is returned.
    pub fn replace_profile(
        &self,
        profile: GatewayProfile,
    ) -> Result<GatewayProfileRev, GatewayError> {
        let attempted_rev = profile.revision;
        let active_rev = self.profile_rev();
        if attempted_rev <= active_rev {
            self.record_reload_failure(attempted_rev, "stale_revision");
            return Err(GatewayError::InvalidProfile(format!(
                "profile revision must increase above active revision {active_rev}"
            )));
        }
        let profile = match Self::compile_profile(&self.boot, profile) {
            Ok(profile) => Arc::new(profile),
            Err(error) => {
                self.record_reload_failure(attempted_rev, reload_failure_code(&error));
                return Err(error);
            }
        };
        let revision = profile.revision;
        let max_recent_cancellations = profile.limits.max_recent_cancellations;
        let mut state = self.state.write();
        if revision <= state.profile.revision {
            state.record_reload_failure(attempted_rev, "stale_revision");
            return Err(GatewayError::InvalidProfile(format!(
                "profile revision must increase above active revision {}",
                state.profile.revision
            )));
        }
        *state = GatewayRuntimeState {
            profile,
            lkg_active: false,
            consecutive_failed_reloads: 0,
            last_reload_failure: None,
        };
        // Serialize the history limit with profile revisions.
        self.requests.set_history_limit(max_recent_cancellations);
        Ok(revision)
    }

    /// Return the profile name served by this runtime.
    pub fn profile_name(&self) -> String {
        self.profile_snapshot().profile_name.clone()
    }

    /// Return the profile revision served by this runtime.
    pub fn profile_rev(&self) -> GatewayProfileRev {
        self.profile_snapshot().revision
    }

    /// Whether the active profile can authenticate at least one credential.
    ///
    /// Closed profiles compile successfully so listeners can start fail-closed,
    /// but do not report production readiness.
    pub fn is_ready(&self) -> bool {
        self.profile_snapshot().has_authenticating_credentials()
    }

    /// Return redacted runtime status.
    pub fn status(&self) -> GatewayRuntimeStatus {
        let maintenance = self
            .maintenance_health
            .status(self.boot.kernel().host_runtime().now());
        self.state.read().status(maintenance)
    }

    /// Reclaim running request registry entries whose server deadline expired.
    pub fn sweep_deadline_expired_requests(&self) -> usize {
        sweep_expired_requests(&self.boot, &self.requests).expired_requests
    }

    /// Advance all Gateway maintenance once. Each object scan is bounded to
    /// one page; callers of [`Self::new_manual`] must schedule this repeatedly.
    /// If the State host lacks query or bounded-write ports, object scans are
    /// skipped; that host owns record cleanup, while expired grants and tickets
    /// remain unusable at authorization time.
    /// Ticket and grant scans run independently. If either fails, the other is
    /// still attempted; earlier cleanup may already be committed. Retain the
    /// cursor and retry after an error.
    /// This does not drain Kernel request cleanup. Manual hosts should call
    /// [`Bootstrap::drain_cleanup`] separately when abandoned scopes need
    /// finalization; it may wait for detached cleanup owners.
    pub async fn maintain_once(
        &self,
        cursor: &mut GatewayMaintenanceCursor,
    ) -> Result<GatewayMaintenanceReport, GatewayError> {
        let host = self.boot.kernel().host_runtime();
        let request_pass = self
            .maintenance_health
            .manual_request()
            .map(|tracker| tracker.begin(host.now()));
        let sweep = sweep_expired_requests(&self.boot, &self.requests);
        if let Some(pass) = request_pass {
            pass.complete(host.now(), sweep.failed_cancellations == 0);
        }
        let mut report = GatewayMaintenanceReport {
            expired_requests: sweep.expired_requests,
            failed_request_cancellations: sweep.failed_cancellations,
            ..GatewayMaintenanceReport::default()
        };
        if self.boot.kernel().state().has_query() && self.boot.kernel().state().has_bounded_write()
        {
            report.object_scans_available = true;
            let object_pass = self
                .maintenance_health
                .manual_object()
                .map(|tracker| tracker.begin(host.now()));
            let tickets =
                object::maintain_upload_tickets_once(&self.boot, &mut cursor.ticket_cursor).await;
            let grants =
                object::maintain_read_grants_once(&self.boot, &mut cursor.grant_cursor).await;
            if let Some(pass) = object_pass {
                pass.complete(host.now(), tickets.is_ok() && grants.is_ok());
            }
            let (tickets, grants) = match (tickets, grants) {
                (Ok(tickets), Ok(grants)) => (tickets, grants),
                (Err(ticket), Err(grant)) => {
                    return Err(GatewayError::Rejected(format!(
                        "gateway object maintenance failed: {ticket}; {grant}"
                    )));
                }
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
            report.upload_tickets_examined = tickets.examined;
            report.upload_tickets_removed = tickets.removed;
            report.upload_tickets_skipped_oversized = tickets.skipped_oversized;
            report.read_grants_examined = grants.examined;
            report.read_grants_removed = grants.removed;
            report.read_grants_skipped_oversized = grants.skipped_oversized;
        }
        Ok(report)
    }

    /// Describe the active profile for an authenticated session.
    ///
    /// This is intentionally authenticated: unauthenticated discovery must not
    /// expose resource paths, effect names, capability literals, or limits.
    pub fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError> {
        let profile = self.profile_snapshot();
        if session.profile_name != profile.profile_name || session.profile_rev != profile.revision {
            return Err(GatewayError::Rejected(
                "gateway session was issued by a different profile snapshot".into(),
            ));
        }
        profile.session_identity_path(session)?;
        let evidence_namespace = self.idempotency.evidence_namespace()?;
        let visible = profile.visible_surfaces_for_principal(&session.principal.principal_id);
        let visible_publications = profile
            .publication_descriptors
            .iter()
            .filter(|publication| {
                visible.is_some_and(|surfaces| surfaces.contains(&publication.surface_id))
            })
            .cloned()
            .collect();
        Ok(GatewayDescriptor {
            profile_name: profile.profile_name.clone(),
            profile_rev: profile.revision,
            surfaces: profile
                .surface_descriptors
                .iter()
                .filter(|surface| {
                    visible.is_some_and(|surfaces| surfaces.contains(&surface.surface_id))
                })
                .map(|surface| {
                    Ok(GatewaySurfaceDescriptor {
                        surface_id: surface.surface_id.clone(),
                        request_scope: request_scope::fingerprint(
                            &profile,
                            session,
                            surface,
                            evidence_namespace,
                        ),
                        target: surface.target.clone(),
                        publish_capability: surface.publish_capability.clone(),
                        input_schema: surface.input_schema.clone(),
                        output_schema: surface.output_schema.clone(),
                        output_stream_schema: surface.output_stream_schema.clone(),
                    })
                })
                .collect::<Result<_, GatewayError>>()?,
            publications: visible_publications,
            limits: profile.limits.clone(),
        })
    }

    /// Check the original session and submit binding before disclosing an
    /// accepted request's identity, output, or unresolved effects.
    pub fn validate_submission_access(
        &self,
        session: &GatewaySession,
        surface_id: &str,
    ) -> Result<(), GatewayError> {
        let profile = self.profile_snapshot();
        Self::validate_submission_profile_access(&profile, session, surface_id)
    }

    fn validate_submission_profile_access(
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_id: &str,
    ) -> Result<(), GatewayError> {
        validate_current_session(profile, session)?;
        if !profile.principal_can_submit(&session.principal.principal_id, surface_id) {
            return Err(GatewayError::Unauthorized(
                "submission evidence access revoked".into(),
            ));
        }
        Ok(())
    }

    /// Admit a `SubmitStream` stream-open request before any input chunk is
    /// consumed.
    pub async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<Box<GatewayAcceptedInputStream>, GatewayError> {
        submission::validate_output_port(submission.requested_output, false)?;
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        let host = self.boot.kernel().host_runtime();
        let now = host.now();
        let now_ms = host.now_millis();
        // Stream-open has no payload fingerprint. Reservation or replay waits
        // until completion has folded the entire input.
        let deadline =
            request_deadline(&submission.options, submission.server_deadline, now, now_ms)?;
        validate_request_deadline(deadline, now, &profile.limits)?;
        validate_submit_options(&submission.options)?;
        let has_idempotency_material = required_idempotency_material(&submission)?.is_some();

        let GatewaySubmission {
            surface_id,
            body,
            requested_output,
            options,
            server_deadline: _,
        } = submission;
        let GatewaySubmissionBody::InputStream(open) = body else {
            return Err(GatewayError::Rejected(
                "stream admission requires a stream_open body".into(),
            ));
        };
        let surface = validate_input_stream_open_request(&profile, session, &surface_id, &open)?;
        request_scope::validate(
            &profile,
            session,
            surface,
            self.idempotency.as_ref(),
            &options,
        )?;
        let mut surface_ids = BTreeSet::new();
        surface_ids.insert(surface.surface_id.clone());
        let program = stream_open_admission_program(surface, requested_output);
        let admission = inspect_lowered_submission(
            &program,
            &profile,
            &session.principal.principal_id,
            surface,
            &self.boot,
            false,
        )?;
        if admission.requires_idempotency && !has_idempotency_material {
            return Err(GatewayError::Rejected(
                "idempotency_key or submission_token is required for non-idempotent effects".into(),
            ));
        }
        let risk_class = request_risk_class(&admission);
        let fair_surface_ids = vec![surface.surface_id.clone()];
        let budget_charge = gateway_budget_charge_for_stream_open(
            &admission,
            surface,
            &self.boot,
            &open,
            &profile.limits,
            deadline,
            now,
        )?;
        let budget_guard = self
            .requests
            .try_reserve_budget(&profile.limits.budget, budget_charge)?;
        let admission_guard = self.requests.try_admit(
            &profile.limits,
            session.principal.principal_id.clone(),
            fair_surface_ids.clone(),
            risk_class.clone(),
        )?;
        let accepted = self
            .requests
            .new_acceptance(profile.revision, surface.surface_id.clone())?;
        let authority = GatewaySubmissionAuthority::new(self, session, &surface_id);
        let (request_owner, executor) = self
            .executor_for(&profile, session, &surface_ids, authority.clone())
            .await?;
        let request_process = request_owner.id();
        let entry = GatewayRequestEntry {
            accepted: accepted.clone(),
            request_process,
            gateway_id: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            state: GatewayRequestState::Running,
            deadline,
            cancelled_until: None,
        };
        let request_guard = self.requests.insert_running(
            entry,
            admission_guard,
            budget_guard,
            request_owner,
            authority,
        )?;
        Ok(Box::new(GatewayAcceptedInputStream {
            accepted,
            open,
            limits: profile.limits.clone(),
            profile,
            session: session.clone(),
            surface_id,
            requested_output,
            options,
            deadline,
            request_guard,
            request_process,
            executor,
        }))
    }

    /// Complete an accepted input stream and run it through the same request
    /// registry entry that admitted the stream-open frame.
    /// The stream must belong to this runtime; cloned `Arc` handles share its
    /// registry, while a separately constructed runtime is rejected.
    pub async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        submission::complete_input_stream(self, stream, payload, provenance).await
    }

    /// Mark an accepted input stream failed before dispatch.
    /// The stream must belong to this runtime; cloned `Arc` handles share its
    /// registry, while a separately constructed runtime is rejected.
    pub async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        _reason: &str,
    ) -> Result<(), GatewayError> {
        self.validate_input_stream_owner(&stream)?;
        self.boot
            .finish_process_as(stream.request_process, xolotl_types::ProcessStatus::Failed)
            .await
            .map_err(|error| GatewayError::Rejected(error.to_string()))
    }

    fn validate_input_stream_owner(
        &self,
        stream: &GatewayAcceptedInputStream,
    ) -> Result<(), GatewayError> {
        if !Arc::ptr_eq(&self.requests, &stream.request_guard.lease.registry) {
            return Err(GatewayError::Rejected(
                "input stream belongs to a different gateway runtime".into(),
            ));
        }
        Ok(())
    }

    fn compile_profile(
        boot: &Bootstrap,
        profile: GatewayProfile,
    ) -> Result<CompiledGatewayProfile, GatewayError> {
        let mut profile = CompiledGatewayProfile::compile(profile)?;
        for surface in &profile.surface_descriptors {
            validate_surface_method(boot, &surface.target, GATEWAY_EFFECT_METHOD).map_err(|e| {
                GatewayError::InvalidProfile(format!(
                    "surface {} references missing method {} on {}: {e}",
                    surface.surface_id,
                    GATEWAY_EFFECT_METHOD,
                    surface.target.path()
                ))
            })?;
        }
        let surface_descriptors = &profile.surface_descriptors;
        let surfaces_by_id = &profile.surfaces_by_id;
        for (principal_id, binding) in &mut profile.surface_bindings_by_principal {
            binding.request_grants_by_surface.clear();
            for surface_id in &binding.submit {
                let Some(&surface_index) = surfaces_by_id.get(surface_id) else {
                    return Err(GatewayError::InvalidProfile(format!(
                        "submit surface {surface_id} for principal {principal_id} is unavailable"
                    )));
                };
                let surface = &surface_descriptors[surface_index];
                if !binding
                    .capability_ceiling
                    .iter()
                    .any(|ceiling| ceiling.covers_cap(&surface.grant_capability))
                {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {principal_id} does not cover surface {} grant template {}",
                        surface.surface_id, surface.grant_template
                    )));
                }
                binding.request_grants_by_surface.insert(
                    surface.surface_id.clone(),
                    CompiledRequestGrantTemplate {
                        selector: surface.grant_selector.clone(),
                        rights: GrantRights::new(
                            GrantMethods::name(GATEWAY_EFFECT_METHOD),
                            xolotl_types::RightFlags::empty(),
                        ),
                    },
                );
            }
        }
        if let Some(anchor) = profile.authority_anchor {
            if boot.kernel().processes().identity(anchor).is_none() {
                return Err(GatewayError::InvalidProfile(format!(
                    "authority anchor process {anchor} does not exist"
                )));
            }
            let now_millis = boot.kernel().host_runtime().now_millis();
            let mut anchor_grants = boot.kernel().registry().grants_of(anchor);
            anchor_grants.extend(boot.kernel().processes().attached_grants(anchor));
            for surface in &profile.surface_descriptors {
                if !anchor_grants.iter().any(|grant| {
                    !grant.expires.is_expired(now_millis)
                        && grant.rights.methods.allows(GATEWAY_EFFECT_METHOD)
                        && grant.selector.pattern.covers_cap(&surface.grant_capability)
                }) {
                    return Err(GatewayError::InvalidProfile(format!(
                        "authority anchor does not cover surface {} grant template {}",
                        surface.surface_id, surface.grant_template
                    )));
                }
            }
        }
        profile.bind_identities(boot.kernel().identities())?;
        Ok(profile)
    }

    fn profile_snapshot(&self) -> Arc<CompiledGatewayProfile> {
        self.state.read().profile.clone()
    }

    /// Record a failed dynamic profile reload while keeping the active snapshot.
    pub fn record_reload_failure(&self, attempted_rev: GatewayProfileRev, code: &'static str) {
        self.state
            .write()
            .record_reload_failure(attempted_rev, code);
    }

    fn spawn_gateway_request_process(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_ids: &BTreeSet<String>,
    ) -> Result<RequestProcess<'static>, GatewayError> {
        let id_ref = profile.session_identity_ref(session)?;
        let surfaces = profile.surface_descriptors_for_ids(surface_ids)?;
        let binding = if surface_ids.is_empty() {
            None
        } else {
            Some(
                profile
                    .surface_bindings_by_principal
                    .get(&session.principal.principal_id)
                    .ok_or_else(|| {
                        GatewayError::Rejected("principal has no callable surfaces".into())
                    })?,
            )
        };
        let mut grant_templates = BTreeMap::<String, ResourceSelector>::new();
        for surface in surfaces {
            let Some(binding) = binding else {
                continue;
            };
            if !binding.submit.contains(&surface.surface_id) {
                return Err(GatewayError::Rejected(format!(
                    "surface {} is not callable by principal",
                    surface.surface_id
                )));
            }
            let Some(request_grant) = binding.request_grants_by_surface.get(&surface.surface_id)
            else {
                return Err(GatewayError::Rejected(format!(
                    "surface {} has no compiled request grant",
                    surface.surface_id
                )));
            };
            grant_templates
                .entry(surface.grant_template.clone())
                .or_insert_with(|| request_grant.selector.clone());
        }
        let declared: Vec<CompiledRequestGrantTemplate> = grant_templates
            .values()
            .map(|selector| CompiledRequestGrantTemplate {
                selector: selector.clone(),
                rights: GrantRights::new(
                    GrantMethods::name(GATEWAY_EFFECT_METHOD),
                    xolotl_types::RightFlags::empty(),
                ),
            })
            .collect();
        let anchor = profile.authority_anchor.unwrap_or(self.boot.root());
        self.boot
            .request_under_owned(anchor, id_ref, &declared)
            .map_err(|e| GatewayError::Rejected(e.to_string()))
    }

    async fn executor_for(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_ids: &BTreeSet<String>,
        authority: Arc<GatewaySubmissionAuthority>,
    ) -> Result<(RequestProcess<'static>, Executor), GatewayError> {
        let surfaces = profile.surface_descriptors_for_ids(surface_ids)?;
        let request = self.spawn_gateway_request_process(profile, session, surface_ids)?;
        let proc = request.id();
        let ex = request.executor().with_request_authorizer(authority);
        let mut opened = BTreeSet::new();
        for surface in surfaces {
            let key = format!("{}\0{}", surface.target.path(), GATEWAY_EFFECT_HANDLE_VERB);
            if !opened.insert(key) {
                continue;
            }
            let opened = self
                .boot
                .open_for_method(
                    proc,
                    &surface.target,
                    GATEWAY_EFFECT_HANDLE_VERB,
                    GATEWAY_EFFECT_METHOD,
                )
                .map_err(|e| GatewayError::Rejected(e.to_string()));
            let opened = match opened {
                Ok(opened) => opened,
                Err(error) => {
                    return finish_request_without_idempotency_and_fail(&self.boot, proc, error)
                        .await;
                }
            };
            if let Err(error) = ex.bind_handle(surface.target.clone(), opened) {
                return finish_request_without_idempotency_and_fail(
                    &self.boot,
                    proc,
                    GatewayError::Rejected(error.to_string()),
                )
                .await;
            }
        }
        Ok((request, ex))
    }

    fn source_label(profile: &CompiledGatewayProfile) -> String {
        format!("gateway/{}", profile.profile_name)
    }
}

impl GatewayRuntimeState {
    fn record_reload_failure(&mut self, attempted_rev: GatewayProfileRev, code: &'static str) {
        self.lkg_active = true;
        self.consecutive_failed_reloads = self.consecutive_failed_reloads.saturating_add(1);
        self.last_reload_failure = Some(GatewayProfileReloadFailure {
            attempted_profile_rev: attempted_rev,
            code: code.into(),
            public_message: "profile reload rejected".into(),
        });
    }

    fn status(&self, maintenance: GatewayMaintenanceStatus) -> GatewayRuntimeStatus {
        let ready = self.profile.has_authenticating_credentials();
        let readiness = if self.lkg_active && ready {
            GatewayReadiness::DegradedLastKnownGood
        } else if ready {
            GatewayReadiness::Ready
        } else {
            GatewayReadiness::NotReadyClosed
        };
        GatewayRuntimeStatus {
            profile_name: self.profile.profile_name.clone(),
            profile_rev: self.profile.revision,
            ready,
            readiness,
            lkg_active: self.lkg_active,
            consecutive_failed_reloads: self.consecutive_failed_reloads,
            last_reload_failure: self.last_reload_failure.clone(),
            maintenance,
        }
    }
}

fn reload_failure_code(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::InvalidProfile(_) => "invalid_profile",
        GatewayError::Unauthenticated => "auth_failed",
        GatewayError::Unauthorized(_) => "permission_denied",
        GatewayError::Rejected(_) => "request_rejected",
        GatewayError::LimitExceeded(_) => "limit_exceeded",
        GatewayError::Indeterminate(_) | GatewayError::SubmissionIndeterminate(_) => {
            "outcome_unknown"
        }
    }
}

#[async_trait]
impl Gateway for GatewayRuntime {
    fn deadline_after(&self, duration: Duration) -> Result<HostDeadline, GatewayError> {
        self.boot
            .kernel()
            .host_runtime()
            .deadline_after(duration)
            .ok_or_else(|| GatewayError::Rejected("transport deadline is out of range".into()))
    }

    fn status(&self) -> GatewayRuntimeStatus {
        GatewayRuntime::status(self)
    }

    fn registered_gateway_hosts(&self) -> Vec<GatewayAllowedHost> {
        self.profile_snapshot().registered_hosts.clone()
    }

    fn registered_browser_origins(&self) -> Vec<GatewayAllowedOrigin> {
        self.profile_snapshot().registered_origins.clone()
    }

    fn validate_session_authority(
        &self,
        session: &GatewaySession,
        authority: &str,
    ) -> Result<(), GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        if !gateway_host_allowed(authority, &profile.registered_hosts) {
            return Err(GatewayError::Unauthorized(
                session.principal.principal_id.clone(),
            ));
        }
        Ok(())
    }

    async fn authenticate(
        &self,
        credential: PresentedCredential,
    ) -> Result<GatewaySession, GatewayError> {
        let profile = self.profile_snapshot();
        let principal = match credential {
            PresentedCredential::Bearer(token) => profile.verify_bearer(&token)?,
            PresentedCredential::ClientCertificate(credential) => {
                profile.verify_client_certificate(&credential)?
            }
        };
        profile.session_for_principal(principal)
    }

    fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError> {
        GatewayRuntime::describe(self, session)
    }

    async fn retry_epoch(&self, session: &GatewaySession) -> Result<u64, GatewayError> {
        validate_current_session(&self.profile_snapshot(), session)?;
        let epoch = self.idempotency.retry_epoch().await?;
        validate_current_session(&self.profile_snapshot(), session)?;
        Ok(epoch)
    }

    async fn lookup_request(
        &self,
        session: &GatewaySession,
        lookup: GatewayRequestLookup,
    ) -> Result<GatewayRequestEvidence, GatewayError> {
        submission::idempotency::lookup_request(self, session, lookup).await
    }

    async fn read_retained_request_result(
        &self,
        session: &GatewaySession,
        lookup: GatewayRequestLookup,
    ) -> Result<GatewayRetainedRequestResult, GatewayError> {
        submission::idempotency::read_retained_request_result(self, session, lookup).await
    }

    fn validate_submission_access(
        &self,
        session: &GatewaySession,
        surface_id: &str,
    ) -> Result<(), GatewayError> {
        GatewayRuntime::validate_submission_access(self, session, surface_id)
    }

    fn prepare_submission(
        &self,
        session: &GatewaySession,
        head: GatewaySubmissionHead,
        output_window: Option<StreamWindow>,
    ) -> Result<GatewayPreparation, GatewayError> {
        submission::prepare_submission(self, session, head, output_window)
    }

    async fn submit_prepared(
        &self,
        preparation: GatewayPreparation,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        submission::submit_prepared(self, preparation, payload, provenance).await
    }

    async fn submit_output_stream_prepared(
        &self,
        preparation: GatewayPreparation,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewayOutputStream, GatewayError> {
        submission::submit_output_stream_prepared(self, preparation, payload, provenance).await
    }

    async fn submit(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        submission::submit(self, session, submission).await
    }

    async fn submit_output_stream(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
        window: StreamWindow,
    ) -> Result<GatewayOutputStream, GatewayError> {
        submission::submit_output_stream(self, session, submission, window).await
    }

    async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<Box<GatewayAcceptedInputStream>, GatewayError> {
        GatewayRuntime::accept_input_stream_submission(self, session, submission).await
    }

    async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        GatewayRuntime::complete_input_stream_submission(self, stream, payload, provenance).await
    }

    async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        reason: &str,
    ) -> Result<(), GatewayError> {
        GatewayRuntime::fail_input_stream_submission(self, stream, reason).await
    }

    fn cancel(
        &self,
        session: &GatewaySession,
        request: GatewayCancelRequest,
    ) -> Result<bool, GatewayError> {
        self.requests.cancel(session, &request, &self.boot)
    }

    async fn issue_object_upload_ticket(
        &self,
        session: &GatewaySession,
        request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError> {
        self.issue_upload_ticket(session, request).await
    }

    async fn begin_object_upload(
        &self,
        session: &GatewaySession,
        request: BeginObjectUploadRequest,
    ) -> Result<GatewayObjectUpload, GatewayError> {
        self.begin_upload(session, request).await
    }

    async fn open_object_read(
        &self,
        session: &GatewaySession,
        request: OpenObjectReadRequest,
    ) -> Result<GatewayObjectDownload, GatewayError> {
        self.open_read(session, request).await
    }

    fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String> {
        self.boot
            .record_gateway_audit(audit)
            .map_err(|e| e.to_string())
    }

    fn record_optional_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String> {
        self.boot
            .record_optional_gateway_audit(audit)
            .map_err(|error| error.to_string())
    }
}

fn parse_identity_path(identity: &str) -> Result<Path, GatewayError> {
    let path = Path::parse(identity)
        .map_err(|e| GatewayError::InvalidProfile(format!("invalid identity path: {e}")))?;
    xolotl_kernel::identity::validate_path(&path)
        .map_err(|error| GatewayError::InvalidProfile(error.to_string()))?;
    Ok(path)
}

fn validate_surface_method(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<(), GatewayError> {
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(target)
        .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
    let (_, descriptor) = boot
        .kernel()
        .registry()
        .resource_method(resource_id, method)
        .ok_or_else(|| GatewayError::InvalidProfile("method missing".into()))?;
    if descriptor.authority.verb() != GATEWAY_EFFECT_HANDLE_VERB {
        return Err(GatewayError::InvalidProfile(format!(
            "method {method} on {} requires {} authority, expected {}",
            target.path(),
            descriptor.authority.verb(),
            GATEWAY_EFFECT_HANDLE_VERB
        )));
    }
    Ok(())
}

fn operation_replay_class(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<ReplayClass, GatewayError> {
    Ok(operation_method_metadata(boot, target, method)?.replay)
}

#[derive(Clone, Copy, Debug)]
struct GatewayMethodMetadata {
    replay: ReplayClass,
    cost: CostModel,
    batchable: bool,
}

fn operation_method_metadata(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<GatewayMethodMetadata, GatewayError> {
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(target)
        .map_err(|e| GatewayError::Rejected(e.to_string()))?;
    let (_, descriptor) = boot
        .kernel()
        .registry()
        .resource_method(resource_id, method)
        .ok_or_else(|| {
            GatewayError::Rejected(format!(
                "operation method {method} is unavailable on {}",
                target.path()
            ))
        })?;
    Ok(GatewayMethodMetadata {
        replay: descriptor.replay,
        cost: descriptor.cost,
        batchable: descriptor.batchable,
    })
}

fn estimate_gateway_operation_cost(
    cost: &CostModel,
    batchable: bool,
    input: Option<&Value>,
) -> u64 {
    let Some(input) = input else {
        return cost.estimate_micro_usd(1, 1);
    };
    let in_tokens = input.approx_tokens();
    let out_tokens = in_tokens;
    match (batchable, input.view()) {
        (true, ValueView::List(items)) => {
            let flat = cost.flat_micro_usd.saturating_mul(items.len() as u64);
            let variable = CostModel {
                flat_micro_usd: 0,
                ..*cost
            }
            .estimate_micro_usd(in_tokens, out_tokens);
            flat.saturating_add(variable)
        }
        _ => cost.estimate_micro_usd(in_tokens, out_tokens),
    }
}

async fn lower_submission<'profile>(
    submission: GatewaySubmission,
    profile: &'profile CompiledGatewayProfile,
    runtime: &GatewayRuntime,
    session: &GatewaySession,
) -> Result<LoweredSubmission<'profile>, GatewayError> {
    match submission.body {
        GatewaySubmissionBody::DirectInput(input) => {
            if submission.surface_id.trim().is_empty() {
                return Err(GatewayError::Rejected(
                    "direct input requires a surface_id".into(),
                ));
            }
            let surface = profile
                .surface_by_id(&submission.surface_id)
                .ok_or_else(|| {
                    GatewayError::Rejected(format!(
                        "unknown gateway surface {}",
                        submission.surface_id
                    ))
                })?;
            if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
                return Err(GatewayError::Rejected(format!(
                    "surface {} is not callable by principal",
                    surface.surface_id
                )));
            }
            if value_any(&input.payload, |value| {
                matches!(value.view(), ValueView::StreamEnd(_))
            }) {
                return Err(GatewayError::Rejected(
                    "direct input cannot be StreamEnd".into(),
                ));
            }
            validate_surface_input(surface, &input.payload)?;
            validate_inline_value_bytes(&input.payload, &profile.limits, "direct input")?;
            let objects = runtime
                .admit_input_objects(
                    &input.payload,
                    input.provenance.as_ref(),
                    session,
                    surface,
                    submission.options.submission_token.as_deref(),
                )
                .await?;
            Ok(LoweredSubmission {
                program: DoNode::op(OperationTemplate {
                    target: surface.target.clone(),
                    method: GATEWAY_EFFECT_METHOD.into(),
                    method_id: None,
                    output: submission.requested_output,
                    literal_input: Some(input.payload),
                }),
                surface,
                objects,
            })
        }
        GatewaySubmissionBody::InputStream(open) => {
            if open.stream_id.trim().is_empty() {
                return Err(GatewayError::Rejected(
                    "stream_open requires a stream_id".into(),
                ));
            }
            Err(GatewayError::Rejected(
                "stream input must be completed by a streaming transport before dispatch".into(),
            ))
        }
    }
}

fn validate_input_stream_open_request<'a>(
    profile: &'a CompiledGatewayProfile,
    session: &GatewaySession,
    surface_id: &str,
    open: &GatewayStreamOpenRequest,
) -> Result<&'a CompiledSurfaceDescriptor, GatewayError> {
    if surface_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream input requires a surface_id".into(),
        ));
    }
    if open.stream_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream_open requires a stream_id".into(),
        ));
    }
    if open.direction != GatewayStreamDirection::ClientToKernel {
        return Err(GatewayError::Rejected(
            "stream input requires CLIENT_TO_KERNEL direction".into(),
        ));
    }
    if open.modality == GatewayModality::Control {
        return Err(GatewayError::Rejected(
            "CONTROL modality cannot be submitted as operation input".into(),
        ));
    }
    if !open.item_schema_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream item schema is selected by the gateway profile".into(),
        ));
    }
    if open.max_inline_item_bytes == 0 {
        return Err(GatewayError::Rejected(
            "stream_open max_inline_item_bytes must be non-zero".into(),
        ));
    }
    let profile_max_inline_item_bytes =
        u64::try_from(profile.limits.max_stream_inline_item_bytes).unwrap_or(u64::MAX);
    if open.max_inline_item_bytes > profile_max_inline_item_bytes {
        return Err(GatewayError::Rejected(format!(
            "stream_open max_inline_item_bytes exceeds max_stream_inline_item_bytes ({})",
            profile.limits.max_stream_inline_item_bytes
        )));
    }
    let profile_max_items = u64::try_from(profile.limits.max_stream_items).unwrap_or(u64::MAX);
    if let Some(max_items) = open.max_items {
        if max_items == 0 {
            return Err(GatewayError::Rejected(
                "stream_open max_items must be non-zero".into(),
            ));
        }
        if max_items > profile_max_items {
            return Err(GatewayError::Rejected(format!(
                "stream_open max_items exceeds max_stream_items ({})",
                profile.limits.max_stream_items
            )));
        }
    }
    let profile_max_bytes = u64::try_from(profile.limits.max_stream_bytes).unwrap_or(u64::MAX);
    if let Some(max_bytes) = open.max_bytes {
        if max_bytes == 0 {
            return Err(GatewayError::Rejected(
                "stream_open max_bytes must be non-zero".into(),
            ));
        }
        if max_bytes > profile_max_bytes {
            return Err(GatewayError::Rejected(format!(
                "stream_open max_bytes exceeds max_stream_bytes ({})",
                profile.limits.max_stream_bytes
            )));
        }
    }
    let surface = profile
        .surface_by_id(surface_id)
        .ok_or_else(|| GatewayError::Rejected(format!("unknown gateway surface {surface_id}")))?;
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(format!(
            "surface {} is not callable by principal",
            surface.surface_id
        )));
    }
    Ok(surface)
}

fn stream_open_admission_program(
    surface: &CompiledSurfaceDescriptor,
    requested_output: OutputMode,
) -> DoNode {
    DoNode::op(OperationTemplate {
        target: surface.target.clone(),
        method: GATEWAY_EFFECT_METHOD.into(),
        method_id: None,
        output: requested_output,
        literal_input: Some(Value::null()),
    })
}

struct LoweredSubmission<'profile> {
    program: DoNode,
    surface: &'profile CompiledSurfaceDescriptor,
    objects: object::ObjectAdmission,
}

fn request_deadline(
    options: &SubmitOptions,
    server_deadline: Option<HostDeadline>,
    now: HostDeadline,
    now_ms: i64,
) -> Result<Option<HostDeadline>, GatewayError> {
    // Even with no client deadline, reject a foreign transport clock before
    // any request owner is admitted.
    if let Some(server_deadline) = server_deadline {
        server_deadline
            .elapsed_at(now)
            .map_err(|error| GatewayError::Rejected(error.to_string()))?;
    }
    let client_deadline = options
        .deadline_ms
        .map(|deadline| {
            let deadline = i64::try_from(deadline)
                .map_err(|_error| GatewayError::Rejected("deadline_ms is out of range".into()))?;
            let remaining_ms = deadline.saturating_sub(now_ms).max(0) as u64;
            now.checked_add(std::time::Duration::from_millis(remaining_ms))
                .ok_or_else(|| GatewayError::Rejected("deadline_ms is out of range".into()))
        })
        .transpose()?;
    match (client_deadline, server_deadline) {
        (Some(client), Some(server)) => client
            .earliest(server)
            .map(Some)
            .map_err(|error| GatewayError::Rejected(error.to_string())),
        (client, server) => Ok(client.or(server)),
    }
}

fn request_risk_class(admission: &LoweredSubmissionAdmission) -> String {
    if admission.requires_idempotency {
        "non_idempotent_effect".into()
    } else if admission.inspection.operation_count > 0 {
        "effect".into()
    } else if admission.inspection.wait_deadline_count > 0
        || admission.inspection.wait_signal_count > 0
    {
        "wait".into()
    } else {
        "inert".into()
    }
}

fn gateway_budget_charge_for_submit(
    admission: &LoweredSubmissionAdmission,
    deadline: Option<HostDeadline>,
    now: HostDeadline,
) -> Result<GatewayBudgetCharge, GatewayError> {
    let literal_bytes = admission.inspection.literal_bytes as u64;
    Ok(GatewayBudgetCharge {
        inflight_ops: admission.inspection.operation_count as u64,
        wall_ms: request_wall_ms(deadline, now)?,
        bytes_in: literal_bytes,
        bytes_out: 0,
        inline_value_bytes: literal_bytes,
        stream_items: 0,
        estimated_cost_micro_usd: admission.inspection.estimated_cost_micro_usd,
    })
}

fn gateway_budget_charge_for_stream_open(
    admission: &LoweredSubmissionAdmission,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    open: &GatewayStreamOpenRequest,
    limits: &GatewayLimitProfile,
    deadline: Option<HostDeadline>,
    now: HostDeadline,
) -> Result<GatewayBudgetCharge, GatewayError> {
    let stream_items = open.max_items.unwrap_or(limits.max_stream_items as u64);
    let bytes_in = open.max_bytes.unwrap_or(limits.max_stream_bytes as u64);
    let declared_inline = stream_items.saturating_mul(open.max_inline_item_bytes);
    let estimated_cost_micro_usd =
        estimate_gateway_stream_cost(boot, surface, bytes_in, stream_items)?;
    Ok(GatewayBudgetCharge {
        inflight_ops: admission.inspection.operation_count as u64,
        wall_ms: request_wall_ms(deadline, now)?,
        bytes_in,
        bytes_out: 0,
        inline_value_bytes: declared_inline.min(bytes_in),
        stream_items,
        estimated_cost_micro_usd,
    })
}

fn estimate_gateway_stream_cost(
    boot: &Bootstrap,
    surface: &CompiledSurfaceDescriptor,
    bytes_in: u64,
    stream_items: u64,
) -> Result<u64, GatewayError> {
    let metadata = operation_method_metadata(boot, &surface.target, GATEWAY_EFFECT_METHOD)?;
    let in_tokens = (bytes_in / 4).max(1);
    let out_tokens = in_tokens;
    if metadata.batchable {
        let flat = metadata
            .cost
            .flat_micro_usd
            .saturating_mul(stream_items.max(1));
        let variable = CostModel {
            flat_micro_usd: 0,
            ..metadata.cost
        }
        .estimate_micro_usd(in_tokens, out_tokens);
        return Ok(flat.saturating_add(variable));
    }
    Ok(metadata.cost.estimate_micro_usd(in_tokens, out_tokens))
}

fn request_wall_ms(deadline: Option<HostDeadline>, now: HostDeadline) -> Result<u64, GatewayError> {
    let Some(deadline) = deadline else {
        return Ok(0);
    };
    let remaining = deadline
        .saturating_duration_since(now)
        .map_err(|error| GatewayError::Rejected(error.to_string()))?;
    let milliseconds = remaining
        .as_millis()
        .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
    Ok(u64::try_from(milliseconds).unwrap_or(u64::MAX))
}

fn validate_request_deadline(
    deadline: Option<HostDeadline>,
    now: HostDeadline,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    let remaining = deadline
        .saturating_duration_since(now)
        .map_err(|error| GatewayError::Rejected(error.to_string()))?;
    if remaining.is_zero() {
        return Err(GatewayError::Rejected(
            "request deadline has already expired".into(),
        ));
    }
    let max_ms = u64::try_from(limits.max_deadline_ms_from_now).unwrap_or(0);
    if remaining > Duration::from_millis(max_ms) {
        return Err(GatewayError::Rejected(format!(
            "request deadline exceeds max_deadline_ms_from_now ({})",
            limits.max_deadline_ms_from_now
        )));
    }
    Ok(())
}

fn validate_submit_options(options: &SubmitOptions) -> Result<(), GatewayError> {
    if let Some(key) = normalize_optional_string(options.idempotency_key.clone()) {
        validate_idempotency_key(&key)?;
    }
    if let Some(token) = normalize_optional_string(options.submission_token.clone()) {
        validate_submission_token(&token)?;
    }
    Ok(())
}

fn validate_current_session(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
) -> Result<(), GatewayError> {
    if session.profile_name != profile.profile_name || session.profile_rev != profile.revision {
        return Err(GatewayError::Rejected(
            "gateway session was issued by a different profile snapshot".into(),
        ));
    }
    profile.session_identity_path(session)?;
    Ok(())
}

fn validate_submission_token(token: &str) -> Result<(), GatewayError> {
    let ok = !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid submission token".into()))
    }
}

fn validate_idempotency_key(key: &str) -> Result<(), GatewayError> {
    let ok = !key.is_empty()
        && key.len() <= 256
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid idempotency key".into()))
    }
}

fn validate_content_hash(hash: &str) -> Result<(), GatewayError> {
    let ok = BlobRef::is_valid_hash(hash);
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "large object reference hash must be lowercase hex SHA-384".into(),
        ))
    }
}

fn validate_internal_hash(hash: &str) -> Result<(), GatewayError> {
    let ok = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "internal hash must be 64 lowercase hexadecimal characters".into(),
        ))
    }
}

fn random_gateway_id(prefix: &str, profile_rev: GatewayProfileRev) -> Result<String, GatewayError> {
    let mut bytes = [0u8; GATEWAY_REQUEST_ID_RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| GatewayError::Rejected(format!("gateway request entropy failed: {e}")))?;
    let mut id = String::with_capacity(prefix.len() + 1 + 20 + 1 + bytes.len() * 2);
    id.push_str(prefix);
    id.push('-');
    id.push_str(&profile_rev.to_string());
    id.push('-');
    for byte in bytes {
        push_hex_byte(&mut id, byte);
    }
    Ok(id)
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn required_str<'a>(map: &'a ValueMap, key: &'static str) -> Result<&'a str, GatewayError> {
    optional_str(map, key)
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

fn optional_str<'a>(map: &'a ValueMap, key: &'static str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn required_i64(map: &ValueMap, key: &'static str) -> Result<i64, GatewayError> {
    map.get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

impl GatewayModality {
    fn as_str(self) -> &'static str {
        match self {
            GatewayModality::Value => "value",
            GatewayModality::Text => "text",
            GatewayModality::Bytes => "bytes",
            GatewayModality::Tensor => "tensor",
            GatewayModality::AudioFrame => "audio_frame",
            GatewayModality::VideoFrame => "video_frame",
            GatewayModality::PoseFrame => "pose_frame",
            GatewayModality::SensorFrame => "sensor_frame",
            GatewayModality::Event => "event",
            GatewayModality::Control => "control",
        }
    }
}

impl GatewayStreamDirection {
    fn as_str(self) -> &'static str {
        match self {
            GatewayStreamDirection::ClientToKernel => "client_to_kernel",
            GatewayStreamDirection::KernelToClient => "kernel_to_client",
            GatewayStreamDirection::StateSubscriptionToClient => "state_subscription_to_client",
        }
    }
}

fn value_any(value: &Value, pred: impl Fn(&Value) -> bool) -> bool {
    use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
    if !matches!(value.view(), ValueView::List(_) | ValueView::Map(_)) {
        return pred(value);
    }
    let mut visited = BTreeSet::new();
    let mut walk = ValuePostorder::new(value);
    while let Some(node) = walk.next(|key| visited.contains(&key)) {
        if pred(node) {
            return true;
        }
        visited.insert(ValueNodeKey::of(node));
    }
    false
}

fn inspect_lowered_submission(
    program: &DoNode,
    profile: &CompiledGatewayProfile,
    principal_id: &str,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    validate_input_schema: bool,
) -> Result<LoweredSubmissionAdmission, GatewayError> {
    if !profile.principal_can_submit(principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(format!(
            "surface {} is not callable by principal",
            surface.surface_id
        )));
    }
    let limits = &profile.limits;
    let mut admission = LoweredSubmissionAdmission::default();
    let mut stack = vec![(program, 1usize)];
    while let Some((node, depth)) = stack.pop() {
        admission.inspection.node_count = admission.inspection.node_count.saturating_add(1);
        if admission.inspection.node_count > MAX_LOWERED_SUBMISSION_NODES {
            return Err(GatewayError::Rejected(format!(
                "lowered submission exceeds node limit ({})",
                MAX_LOWERED_SUBMISSION_NODES
            )));
        }
        admission.inspection.max_depth = admission.inspection.max_depth.max(depth);
        if depth > MAX_LOWERED_SUBMISSION_DEPTH {
            return Err(GatewayError::Rejected(format!(
                "lowered submission exceeds depth limit ({})",
                MAX_LOWERED_SUBMISSION_DEPTH
            )));
        }

        match node {
            DoNode::Pure(value) => add_value_bytes(&mut admission.inspection, value, limits)?,
            DoNode::AndThen { d, .. } => {
                inspect_step_ref(&mut admission.inspection)?;
                stack.push((d, depth.saturating_add(1)));
            }
            DoNode::OrElse { d, .. } => {
                inspect_step_ref(&mut admission.inspection)?;
                stack.push((d, depth.saturating_add(1)));
            }
            DoNode::Finally { body, cleanup } => {
                stack.push((cleanup, depth.saturating_add(1)));
                stack.push((body, depth.saturating_add(1)));
            }
            DoNode::Both(a, b) | DoNode::Race(a, b) => {
                stack.push((a, depth.saturating_add(1)));
                stack.push((b, depth.saturating_add(1)));
            }
            DoNode::Let { name, value, body } => {
                add_literal_bytes(&mut admission.inspection, name.len(), limits)?;
                stack.push((value, depth.saturating_add(1)));
                stack.push((body, depth.saturating_add(1)));
            }
            DoNode::Use(name) => {
                add_literal_bytes(&mut admission.inspection, name.len(), limits)?;
            }
            DoNode::Acting { .. } => {
                return Err(GatewayError::Rejected(
                    "lowered submissions cannot contain Acting".into(),
                ));
            }
            DoNode::Fail(failure) => {
                add_literal_bytes(
                    &mut admission.inspection,
                    failure_literal_bytes(failure),
                    limits,
                )?;
            }
            DoNode::Wait(spec) => inspect_wait(&mut admission.inspection, spec)?,
            DoNode::Op(tmpl) => inspect_operation(
                &mut admission,
                tmpl,
                surface,
                boot,
                limits,
                validate_input_schema,
            )?,
        }
    }
    Ok(admission)
}

#[derive(Default)]
struct LoweredSubmissionAdmission {
    inspection: LoweredSubmissionInspection,
    requires_idempotency: bool,
}

fn inspect_step_ref(inspection: &mut LoweredSubmissionInspection) -> Result<(), GatewayError> {
    inspection.step_ref_count = inspection.step_ref_count.saturating_add(1);
    Err(GatewayError::Rejected(
        "lowered submissions cannot contain StepRef".into(),
    ))
}

fn inspect_wait(
    inspection: &mut LoweredSubmissionInspection,
    spec: &WaitSpec,
) -> Result<(), GatewayError> {
    match spec {
        WaitSpec::Signal(_) => {
            inspection.wait_signal_count = inspection.wait_signal_count.saturating_add(1);
            Err(GatewayError::Rejected(
                "lowered submissions cannot contain Wait(Signal)".into(),
            ))
        }
        WaitSpec::Deadline(_) => {
            inspection.wait_deadline_count = inspection.wait_deadline_count.saturating_add(1);
            Err(GatewayError::Rejected(
                "lowered submissions cannot contain Wait(Deadline)".into(),
            ))
        }
    }
}

fn inspect_operation(
    admission: &mut LoweredSubmissionAdmission,
    tmpl: &OperationTemplate,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    limits: &GatewayLimitProfile,
    validate_input_schema: bool,
) -> Result<(), GatewayError> {
    admission.inspection.operation_count = admission.inspection.operation_count.saturating_add(1);
    if tmpl.target != surface.target || tmpl.method != GATEWAY_EFFECT_METHOD {
        return Err(GatewayError::Rejected(format!(
            "operation {}.{} does not match selected surface {}",
            tmpl.target.path(),
            tmpl.method,
            surface.surface_id,
        )));
    }
    let metadata = operation_method_metadata(boot, &surface.target, GATEWAY_EFFECT_METHOD)?;
    if matches!(metadata.replay, ReplayClass::NonIdempotentEffect) {
        admission.requires_idempotency = true;
    }
    admission.inspection.estimated_cost_micro_usd = admission
        .inspection
        .estimated_cost_micro_usd
        .saturating_add(estimate_gateway_operation_cost(
            &metadata.cost,
            metadata.batchable,
            tmpl.literal_input.as_ref(),
        ));
    if validate_input_schema && let Some(input) = &tmpl.literal_input {
        validate_surface_input(surface, input)?;
    }
    if let OutputMode::Collect { limit } = tmpl.output
        && limit > limits.max_collect_limit
    {
        return Err(GatewayError::Rejected(format!(
            "collect limit exceeds max_collect_limit ({})",
            limits.max_collect_limit
        )));
    }
    if let Some(input) = &tmpl.literal_input {
        add_value_bytes(&mut admission.inspection, input, limits)?;
    }
    Ok(())
}

fn add_value_bytes(
    inspection: &mut LoweredSubmissionInspection,
    value: &Value,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    add_value_bytes_with_label(inspection, value, limits, "submission")
}

fn validate_inline_value_bytes(
    value: &Value,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    let mut inspection = LoweredSubmissionInspection::default();
    add_value_bytes_with_label(&mut inspection, value, limits, label)
}

fn add_value_bytes_with_label(
    inspection: &mut LoweredSubmissionInspection,
    value: &Value,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    let remaining = limits
        .max_literal_bytes
        .saturating_sub(inspection.literal_bytes);
    let bytes = value_inspection::inline_bytes(value, remaining).ok_or_else(|| {
        GatewayError::Rejected(format!(
            "{label} exceeds max_literal_bytes ({})",
            limits.max_literal_bytes
        ))
    })?;
    add_literal_bytes_with_label(inspection, bytes, limits, label)
}

fn add_literal_bytes(
    inspection: &mut LoweredSubmissionInspection,
    bytes: usize,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    add_literal_bytes_with_label(inspection, bytes, limits, "submission")
}

fn add_literal_bytes_with_label(
    inspection: &mut LoweredSubmissionInspection,
    bytes: usize,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    inspection.literal_bytes = inspection.literal_bytes.saturating_add(bytes);
    if inspection.literal_bytes > limits.max_literal_bytes {
        return Err(GatewayError::Rejected(format!(
            "{label} exceeds max_literal_bytes ({})",
            limits.max_literal_bytes
        )));
    }
    Ok(())
}

fn failure_literal_bytes(failure: &Failure) -> usize {
    failure.to_string().len()
}

#[cfg(test)]
fn now_millis() -> i64 {
    xolotl_kernel::host::system_now_millis()
}

#[cfg(test)]
mod tests;
