//! External Provider and Source session admission helpers.
//!
//! [`EndpointSession`] tracks handshake state for transport adapters.
//! Provider invocation and Source ingest helpers validate session context,
//! generation counters, schemas, limits, and state reservations before a frame
//! reaches the daemon.

use super::secure_envelope::{EnvelopeAad, SecureEnvelope};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use xolotl_kernel::{CheckCtx, PolicyDecision, PolicySnapshot};
use xolotl_source::{
    SourceClaim, SourceClaimId, SourceCommit, SourceCommitOutcome, SourceCommitRejection,
    SourceIngress, SourceStoreError, SourceStreamOpen, SourceStreamOpenOutcome,
    SourceStreamPosition, SourceStreamRetire, SourceStreamRetireOutcome, SourceStreamScope,
};
use xolotl_types::ErrorInfo;
use xolotl_types::external::{
    AckStatus, CommandResult, ControlFrame, EventAck, ExternalProjectionDef, InboundEvent, Invoke,
    InvokeResult, JsonSchema, ObservedGenerations, OutboundCommand, Role, RoleReady,
    RoleSessionClientHello, SessionContext, SourceStreamOperation, SourceStreamOutcome,
    SourceStreamRejectCode, SourceStreamRejected, SourceStreamRequest, SourceStreamResult,
    SourceStreamSnapshot as ExternalSourceStreamSnapshot,
    SourceStreamState as ExternalSourceStreamState,
};
use xolotl_types::{
    IdentityRef, Path, ResourceId, TaintSet, TaintSource, Value, ValueMap, ValueView,
};

const EXTERNAL_TRANSCRIPT_DOMAIN: &[u8] = b"xolotl/external/session-transcript/v1\0";

/// Hash the canonical v1 Hello and daemon-selected Context for AEAD binding.
///
/// Both sides convert their validated frames to the typed v1 model before
/// encoding; protobuf field order and unknown wire fields do not affect the
/// transcript. This is evaluated once per connection, outside the data path.
pub fn external_session_transcript_hash(
    hello: &RoleSessionClientHello,
    context: &SessionContext,
) -> [u8; 32] {
    let hello = xolotl_proto::role_session_client_hello_to_pb(hello).encode_to_vec();
    let context = xolotl_proto::session_context_to_pb(context).encode_to_vec();
    let mut hash = Sha256::new();
    hash.update(EXTERNAL_TRANSCRIPT_DOMAIN);
    for frame in [&hello, &context] {
        hash.update((frame.len() as u64).to_be_bytes());
        hash.update(frame);
    }
    hash.finalize().into()
}

/// Daemon-to-external sender for one ready Provider or Source session.
#[async_trait::async_trait]
pub trait ExternalSessionOutbound: Send + Sync + 'static {
    /// Error returned by the transport sender.
    type Error: Send + Sync + 'static;

    /// Send one Provider invocation to the connected endpoint.
    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Self::Error>;

    /// Send one Source outbound command to the connected endpoint.
    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Self::Error>;

    /// Send one control frame to the connected endpoint.
    async fn send_control(&self, frame: ControlFrame) -> Result<(), Self::Error>;

    /// Enqueue best-effort cancellation synchronously without spawning a task.
    /// Admission does not confirm delivery; full or closed queues reject it.
    fn enqueue_cancel(&self, frame: ControlFrame) -> Result<(), Self::Error>;
}

/// Runtime hooks for one external Provider or Source session.
#[async_trait::async_trait]
pub trait ExternalSessionHandler: Send + Sync + 'static {
    /// Error returned by the handler.
    type Error: Send + Sync + 'static;
    /// Error returned by the transport sender.
    type OutboundError: Send + Sync + 'static;

    /// Select the authoritative session context for a client hello.
    async fn adjudicate_session(
        &self,
        hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, Self::Error>;

    /// Register a ready session after the endpoint confirms the context.
    async fn on_ready(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: Arc<dyn ExternalSessionOutbound<Error = Self::OutboundError>>,
    ) -> Result<(), Self::Error>;

    /// Release local session registrations synchronously, without network work.
    /// Called once for any selected context, including partial handshakes and
    /// cancellation or dropped transport futures. Must not block or spawn.
    fn on_closed(
        &self,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), Self::Error>;

    /// Admit and handle one Source event.
    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<EventAck, Self::Error>;

    /// Handle one Source ordered-stream lifecycle request and return a
    /// correlated result without tying logical stream life to the connection.
    async fn on_source_stream_request(
        &self,
        request: SourceStreamRequest,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<SourceStreamResult, Self::Error>;

    /// Handle a Source command result.
    async fn on_command_result(
        &self,
        result: CommandResult,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), Self::Error>;

    /// Handle a Provider invocation result.
    async fn on_invoke_result(
        &self,
        result: InvokeResult,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), Self::Error>;

    /// Handle a control frame.
    async fn on_control(
        &self,
        frame: ControlFrame,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), Self::Error>;

    /// Open one encrypted external envelope.
    async fn open_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Authenticate and encrypt one daemon-to-endpoint frame for a ready session.
    async fn seal_secure_envelope(
        &self,
        plaintext: Vec<u8>,
        aad: EnvelopeAad,
        context: &SessionContext,
    ) -> Result<SecureEnvelope, Self::OutboundError>;
}

fn saturating_i64_from_u64(value: u64, label: &'static str) -> i64 {
    match i64::try_from(value) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(?error, value, label, "u64 milliseconds overflowed i64");
            i64::MAX
        }
    }
}

/// Where a session is in the handshake. Business frames are only
/// admitted in [`SessionPhase::Ready`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    /// Connected; awaiting `RoleSessionClientHello` (stage 1).
    AwaitingHello,
    /// Hello received, `SessionContext` sent; awaiting `RoleReady` (stage 3).
    AwaitingReady,
    /// Handshake complete; business frames flow.
    Ready,
    /// Terminally closed (mismatch / revoked / shutdown). Fail-closed.
    Closed,
}

/// Why a frame was rejected by the session gate.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionReject {
    /// A business frame arrived before the handshake completed.
    #[error("session is not ready")]
    NotReady,
    /// A handshake frame arrived in the wrong phase.
    #[error("session frame is out of order")]
    OutOfOrder,
    /// The external endpoint's confirmed context did not match the daemon's.
    #[error("session context mismatch")]
    ContextMismatch,
    /// A Source frame's observed generations are stale vs the session.
    #[error("session observed generation is stale")]
    StaleGeneration,
    /// The frame's credential generation has been revoked.
    #[error("session credential generation is revoked")]
    RevokedCredential,
    /// The session is closed.
    #[error("session is closed")]
    Closed,
}

/// Why a Source event ingest was rejected at the daemon boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceIngestError {
    /// Session gate rejected the frame before ingest.
    #[error("session rejected frame: {0:?}")]
    Session(SessionReject),
    /// Frame targeted a projection different from the ready session.
    #[error("source projection {0} is not the ready session projection")]
    ProjectionMismatch(String),
    /// Frame's observed registry hash differs from the current registry.
    #[error("source session registry hash mismatch")]
    RegistryHashMismatch,
    /// Frame credential generation differs from the current credential.
    #[error("source session credential generation mismatch")]
    CredentialGenerationMismatch,
    /// Frame binding generation differs from the current binding generation.
    #[error("source session binding generation mismatch")]
    BindingGenerationMismatch,
    /// Frame installation config version differs from current install state.
    #[error("source session installation config version mismatch")]
    InstallationConfigVersionMismatch,
    /// Frame projection version differs from current projection state.
    #[error("source session projection version mismatch")]
    ProjectionVersionMismatch,
    /// Ready projection is not declared as a Source role.
    #[error("projection is not a Source")]
    NotSource,
    /// Source projection has no declared event sink.
    #[error("Source projection has no emits declaration")]
    MissingEmits,
    /// Event id could not be represented as a durable path segment.
    #[error("source event id is not a valid path segment")]
    InvalidEventId,
    /// The event id was previously committed with a different request identity.
    #[error("source event id conflicts with a different request")]
    EventIdConflict,
    /// Stream id could not be represented as a durable path segment.
    #[error("source stream id is not a valid path segment")]
    InvalidStreamId,
    /// Event supplied only one of `stream_id` or `seq`.
    #[error("source event stream_id and seq must be supplied together")]
    InvalidSequence,
    /// Event sequence was not greater than the last admitted sequence.
    #[error("source event sequence replay: last={last}, seq={seq}")]
    SequenceReplay {
        /// Last admitted sequence.
        last: u64,
        /// Sequence supplied by the event.
        seq: u64,
    },
    /// Event sequence skipped over the next required value.
    #[error("source event sequence gap: expected={expected}, seq={seq}")]
    SequenceGap {
        /// Next expected sequence.
        expected: u64,
        /// Sequence supplied by the event.
        seq: u64,
    },
    /// Event payload failed declared schema validation.
    #[error("payload schema mismatch: {0}")]
    Schema(String),
    /// Event payload exceeded the projection inline byte limit.
    #[error("source event payload exceeded inline byte limit")]
    PayloadTooLarge,
    /// Event payload carried a forbidden authority or secret field.
    #[error("source event payload contains forbidden field: {field}")]
    ForbiddenPayloadField {
        /// Field name that triggered the rejection.
        field: String,
    },
    /// Residual source policy rejected the event payload.
    #[error("policy rejected source event: {0}")]
    Policy(String),
    /// Source projection ingress rate limit has been reached.
    #[error("source event rate limit exceeded")]
    RateLimited,
    /// Source stream is above its backpressure threshold.
    #[error("source event stream is backpressured")]
    Backpressured,
    /// The Source commit result is unknown; a trusted host can inspect its
    /// private claim receipt, and the same event id remains safe to retry.
    #[error("source event commit outcome is unknown")]
    CommitOutcomeUnknown,
    /// Source stream capacity has been reached.
    #[error("source event stream capacity exceeded")]
    CapacityExceeded,
    /// The storage owner cannot retain another decision/receipt or rate record.
    #[error("source event retention capacity exceeded")]
    RetentionCapacityExceeded,
    /// Ordered event targeted a stream that has not been opened or was retired.
    #[error("source ordered stream is not active")]
    StreamInactive,
    /// Ordered event targeted a prior incarnation of the stream name.
    #[error("source ordered stream epoch mismatch: active={active_epoch}")]
    StreamEpochMismatch {
        /// Current active stream incarnation.
        active_epoch: u64,
    },
    /// Source scope was retired or replaced after this session became ready.
    #[error("source scope is no longer active")]
    ScopeInactive,
    /// Commit parameters no longer match the active Source declaration.
    #[error("source event does not match the active declaration")]
    DeclarationMismatch,
    /// The declared sink currently holds a value other than a sequence.
    #[error("source event sink is not a sequence")]
    SinkTypeMismatch,
    /// State write or dedup bookkeeping failed.
    #[error("state write failed: {0}")]
    State(String),
}

/// Why a Provider invocation frame was rejected.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderInvocationError {
    /// Session gate rejected the frame.
    #[error("session rejected frame: {0:?}")]
    Session(SessionReject),
    /// Ready session is not a Provider projection.
    #[error("projection is not a Provider")]
    NotProvider,
    /// Session registry hash differs from the current registry.
    #[error("provider session registry hash mismatch")]
    RegistryHashMismatch,
    /// Session credential generation differs from the current credential.
    #[error("provider session credential generation mismatch")]
    CredentialGenerationMismatch,
    /// Session binding generation differs from the current binding generation.
    #[error("provider session binding generation mismatch")]
    BindingGenerationMismatch,
    /// Session projection version differs from the current projection state.
    #[error("provider session projection version mismatch")]
    ProjectionVersionMismatch,
    /// Invocation id was empty.
    #[error("provider invocation id must not be empty")]
    EmptyInvocationId,
    /// Invocation id is already registered in-flight.
    #[error("provider invocation id is already in flight")]
    DuplicateInvocationId,
    /// Result did not match any registered in-flight invocation.
    #[error("provider invocation is not in flight")]
    InvocationNotFound,
    /// Result came from a different Provider session.
    #[error("provider invocation session mismatch")]
    SessionMismatch,
    /// Invocation deadline has expired.
    #[error("provider invocation deadline exceeded")]
    DeadlineExceeded,
    /// Result value exceeded the registered inline byte limit.
    #[error("provider result exceeded inline byte limit")]
    ResultTooLarge,
    /// Result payload failed declared schema validation.
    #[error("provider result schema mismatch: {0}")]
    Schema(String),
    /// In-flight invocation limit has been reached.
    #[error("provider invocation in-flight limit exceeded")]
    InFlightLimitExceeded,
    /// This registry can no longer assign a distinct registration identity.
    #[error("provider invocation registration identities exhausted")]
    RegistrationIdsExhausted,
}

/// In-flight Provider invocation registry.
///
/// The daemon registers an `Invoke` before sending it to a Provider. A returned
/// `InvokeResult` is accepted only if it matches one registered invocation and
/// the session generations still match the ready Provider context.
#[derive(Debug, Default)]
pub struct ProviderInvocationRegistry {
    entries: BTreeMap<String, ProviderInvocationEntry>,
    next_registration_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderInvocationEntry {
    registration_id: u64,
    installation_id: String,
    projection_id: String,
    session_id: String,
    acting: IdentityRef,
    effect_path: Path,
    registry_hash: String,
    credential_generation: u64,
    binding_generation: u64,
    projection_version: u64,
    deadline_ms: Option<i64>,
    max_inline_result_bytes: Option<usize>,
    output_schema: Option<JsonSchema>,
}

impl ProviderInvocationRegistry {
    /// Create an empty invocation registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered in-flight invocations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no invocation is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove one in-flight invocation without admitting a result.
    pub fn remove(&mut self, invocation_id: &str) -> bool {
        self.entries.remove(invocation_id).is_some()
    }

    /// Remove only the registration owned by one invocation future. A result
    /// may already have freed the id for another invocation before that future
    /// is dropped, so cancellation must not remove the newer entry.
    pub fn remove_if(&mut self, invocation_id: &str, registration_id: u64) -> bool {
        if self
            .entries
            .get(invocation_id)
            .is_none_or(|entry| entry.registration_id != registration_id)
        {
            return false;
        }
        self.entries.remove(invocation_id);
        true
    }

    /// Remove all in-flight invocations registered to one Provider session.
    pub fn drain_for_session(&mut self, context: &SessionContext) -> Vec<String> {
        self.entries
            .extract_if(.., |_, entry| {
                entry.installation_id == context.installation_id
                    && entry.projection_id == context.projection_id
                    && entry.session_id == context.session_id
            })
            .map(|(id, _)| id)
            .collect()
    }

    /// Register one daemon-to-Provider invoke before it is sent.
    pub fn register(
        &mut self,
        req: ProviderInvocationRegister<'_>,
    ) -> Result<u64, ProviderInvocationError> {
        let ctx = provider_context(
            req.session,
            req.current_registry_hash,
            req.credential_generation,
            req.current_binding_generation,
            req.current_projection_version,
        )?;
        if req.invoke.invocation_id.trim().is_empty() {
            return Err(ProviderInvocationError::EmptyInvocationId);
        }
        if self.entries.contains_key(&req.invoke.invocation_id) {
            return Err(ProviderInvocationError::DuplicateInvocationId);
        }
        if req.max_in_flight.is_some()
            || req.max_effect_in_flight.is_some()
            || req.max_identity_in_flight.is_some()
        {
            let mut in_flight = 0usize;
            let mut effect_in_flight = 0usize;
            let mut identity_in_flight = 0usize;
            for entry in self.entries.values() {
                if !provider_entry_matches_context(entry, ctx) {
                    continue;
                }
                in_flight = in_flight.saturating_add(1);
                if entry.effect_path == req.invoke.effect_path {
                    effect_in_flight = effect_in_flight.saturating_add(1);
                }
                if entry.acting == req.acting {
                    identity_in_flight = identity_in_flight.saturating_add(1);
                }
            }
            if req.max_in_flight.is_some_and(|max| in_flight >= max)
                || req
                    .max_effect_in_flight
                    .is_some_and(|max| effect_in_flight >= max)
                || req
                    .max_identity_in_flight
                    .is_some_and(|max| identity_in_flight >= max)
            {
                return Err(ProviderInvocationError::InFlightLimitExceeded);
            }
        }
        if let Some(deadline) = req.invoke.deadline_ms
            && deadline <= req.now_millis
        {
            return Err(ProviderInvocationError::DeadlineExceeded);
        }
        let registration_id = self
            .next_registration_id
            .checked_add(1)
            .ok_or(ProviderInvocationError::RegistrationIdsExhausted)?;
        self.next_registration_id = registration_id;
        self.entries.insert(
            req.invoke.invocation_id.clone(),
            ProviderInvocationEntry {
                registration_id,
                installation_id: ctx.installation_id.clone(),
                projection_id: ctx.projection_id.clone(),
                session_id: ctx.session_id.clone(),
                acting: req.acting,
                effect_path: req.invoke.effect_path.clone(),
                registry_hash: ctx.registry_hash.clone(),
                credential_generation: ctx.credential_generation,
                binding_generation: ctx.binding_generation,
                projection_version: ctx.projection_version,
                deadline_ms: req.invoke.deadline_ms,
                max_inline_result_bytes: req.max_inline_result_bytes,
                output_schema: req.output_schema.cloned(),
            },
        );
        Ok(registration_id)
    }

    /// Admit a Provider result and remove its in-flight entry.
    pub fn resolve(
        &mut self,
        req: ProviderInvocationResolve<'_>,
    ) -> Result<InvokeResult, ProviderInvocationError> {
        let ctx = provider_context(
            req.session,
            req.current_registry_hash,
            req.credential_generation,
            req.current_binding_generation,
            req.current_projection_version,
        )?;
        let terminal_error = {
            let entry = self
                .entries
                .get(&req.result.invocation_id)
                .ok_or(ProviderInvocationError::InvocationNotFound)?;
            if !provider_entry_matches_context(entry, ctx) {
                return Err(ProviderInvocationError::SessionMismatch);
            }
            if let Some(deadline) = entry.deadline_ms
                && deadline <= req.now_millis
            {
                Some(ProviderInvocationError::DeadlineExceeded)
            } else if let Some(limit) = entry.max_inline_result_bytes
                && result_exceeds_inline_bytes(&req.result.outcome, limit)
            {
                Some(ProviderInvocationError::ResultTooLarge)
            } else if let (Ok(value), Some(schema)) =
                (&req.result.outcome, entry.output_schema.as_ref())
                && let Err(error) = validate_json_schema(Some(schema), value)
            {
                Some(ProviderInvocationError::Schema(error))
            } else {
                None
            }
        };
        if let Some(error) = terminal_error {
            self.entries.remove(&req.result.invocation_id);
            return Err(error);
        }
        self.entries.remove(&req.result.invocation_id);
        Ok(req.result)
    }
}

fn provider_entry_matches_context(entry: &ProviderInvocationEntry, ctx: &SessionContext) -> bool {
    entry.installation_id == ctx.installation_id
        && entry.projection_id == ctx.projection_id
        && entry.session_id == ctx.session_id
        && entry.registry_hash == ctx.registry_hash
        && entry.credential_generation == ctx.credential_generation
        && entry.binding_generation == ctx.binding_generation
        && entry.projection_version == ctx.projection_version
}

/// Context for registering one Provider invoke.
pub struct ProviderInvocationRegister<'a> {
    /// Ready Provider session.
    pub session: &'a EndpointSession,
    /// Invoke being sent to the Provider.
    pub invoke: &'a Invoke,
    /// Current registry hash expected by this daemon.
    pub current_registry_hash: &'a str,
    /// Current credential generation for the installation.
    pub credential_generation: u64,
    /// Current binding generation for the Provider projection.
    pub current_binding_generation: u64,
    /// Current Provider projection version.
    pub current_projection_version: u64,
    /// Wall-clock timestamp used for deadline admission.
    pub now_millis: i64,
    /// Acting identity that caused this Provider invocation.
    pub acting: IdentityRef,
    /// Maximum in-flight invocations accepted for this ready Provider session.
    pub max_in_flight: Option<usize>,
    /// Maximum in-flight invocations accepted for this acting identity on this ready Provider session.
    pub max_identity_in_flight: Option<usize>,
    /// Maximum in-flight invocations accepted for this effect on this ready Provider session.
    pub max_effect_in_flight: Option<usize>,
    /// Maximum inline result bytes accepted from this invocation.
    pub max_inline_result_bytes: Option<usize>,
    /// Output schema declared for the invoked effect.
    pub output_schema: Option<&'a JsonSchema>,
}

/// Context for resolving one Provider invoke result.
pub struct ProviderInvocationResolve<'a> {
    /// Ready Provider session.
    pub session: &'a EndpointSession,
    /// Result frame received from the Provider.
    pub result: InvokeResult,
    /// Current registry hash expected by this daemon.
    pub current_registry_hash: &'a str,
    /// Current credential generation for the installation.
    pub credential_generation: u64,
    /// Current binding generation for the Provider projection.
    pub current_binding_generation: u64,
    /// Current Provider projection version.
    pub current_projection_version: u64,
    /// Wall-clock timestamp used for deadline admission.
    pub now_millis: i64,
}

fn provider_context<'a>(
    session: &'a EndpointSession,
    current_registry_hash: &str,
    credential_generation: u64,
    current_binding_generation: u64,
    current_projection_version: u64,
) -> Result<&'a SessionContext, ProviderInvocationError> {
    session
        .admit_business()
        .map_err(ProviderInvocationError::Session)?;
    session
        .admit_credential(credential_generation)
        .map_err(ProviderInvocationError::Session)?;
    let ctx = session
        .context()
        .ok_or(ProviderInvocationError::Session(SessionReject::NotReady))?;
    if ctx.role != Role::Provider {
        return Err(ProviderInvocationError::NotProvider);
    }
    if ctx.registry_hash != current_registry_hash {
        return Err(ProviderInvocationError::RegistryHashMismatch);
    }
    if ctx.credential_generation != credential_generation {
        return Err(ProviderInvocationError::CredentialGenerationMismatch);
    }
    if ctx.binding_generation != current_binding_generation {
        return Err(ProviderInvocationError::BindingGenerationMismatch);
    }
    if ctx.projection_version != current_projection_version {
        return Err(ProviderInvocationError::ProjectionVersionMismatch);
    }
    Ok(ctx)
}

fn result_exceeds_inline_bytes(outcome: &Result<Value, ErrorInfo>, limit: usize) -> bool {
    match outcome {
        Ok(value) => crate::value_inspection::inline_bytes(value, limit).is_none(),
        Err(error) => error
            .kind
            .len()
            .checked_add(error.message.len())
            .is_none_or(|bytes| bytes > limit),
    }
}

/// Why a Source outbound command frame was rejected.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceCommandError {
    /// Session gate rejected the frame.
    #[error("session rejected frame: {0:?}")]
    Session(SessionReject),
    /// Ready session is not a Source projection.
    #[error("projection is not a Source")]
    NotSource,
    /// Session registry hash differs from the current registry.
    #[error("source session registry hash mismatch")]
    RegistryHashMismatch,
    /// Session credential generation differs from the current credential.
    #[error("source session credential generation mismatch")]
    CredentialGenerationMismatch,
    /// Session binding generation differs from the current binding generation.
    #[error("source session binding generation mismatch")]
    BindingGenerationMismatch,
    /// Session installation config version differs from current install state.
    #[error("source session installation config version mismatch")]
    InstallationConfigVersionMismatch,
    /// Session projection version differs from current projection state.
    #[error("source session projection version mismatch")]
    ProjectionVersionMismatch,
    /// Command id was empty.
    #[error("source command id must not be empty")]
    EmptyCommandId,
    /// Command id is already registered or retained for replay suppression.
    #[error("source command id is already in flight or retained")]
    DuplicateCommandId,
    /// Result did not match any registered in-flight command.
    #[error("source command is not in flight")]
    CommandNotFound,
    /// Result came from a different Source session.
    #[error("source command session mismatch")]
    SessionMismatch,
    /// Command deadline has expired.
    #[error("source command deadline exceeded")]
    DeadlineExceeded,
    /// Result value exceeded the registered inline byte limit.
    #[error("source command result exceeded inline byte limit")]
    ResultTooLarge,
    /// Command or result value did not match the declared schema.
    #[error("source command schema rejected value: {0}")]
    Schema(String),
    /// In-flight command limit has been reached.
    #[error("source command in-flight limit exceeded")]
    InFlightLimitExceeded,
    /// Command dispatch rate limit has been reached.
    #[error("source command rate limit exceeded")]
    RateLimited,
    /// Shared pending and retained metadata capacity has been exhausted.
    #[error("source command retention capacity exceeded")]
    RetentionCapacityExceeded,
    /// This registry can no longer assign a distinct registration identity.
    #[error("source command registration identities exhausted")]
    RegistrationIdsExhausted,
}

/// In-flight Source outbound command registry.
///
/// The daemon registers an [`OutboundCommand`] before sending it to a Source.
/// A returned [`CommandResult`] is accepted only if it matches a registered
/// command and the session generations still match the ready Source context.
#[derive(Debug)]
pub struct SourceCommandRegistry {
    entries: BTreeMap<String, SourceCommandEntry>,
    retained_ids: BTreeMap<String, i64>,
    rate_windows: BTreeMap<SourceCommandRateKey, SourceCommandRateWindow>,
    maintenance: SourceCommandMaintenance,
    capacity: NonZeroUsize,
    next_registration_id: u64,
}

/// Default shared capacity for pending commands, terminal ids, and rate rows.
pub const DEFAULT_SOURCE_COMMAND_LIMIT: NonZeroUsize = NonZeroUsize::MIN.saturating_add(65_535);

const SOURCE_COMMAND_MAINTENANCE_BATCH: usize = 64;

impl Default for SourceCommandRegistry {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_SOURCE_COMMAND_LIMIT)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceCommandEntry {
    registration_id: u64,
    installation_id: String,
    projection_id: String,
    session_id: String,
    registry_hash: String,
    credential_generation: u64,
    binding_generation: u64,
    installation_config_version: u64,
    projection_version: u64,
    deadline_ms: Option<i64>,
    max_inline_result_bytes: Option<usize>,
    command_result_schema: Option<JsonSchema>,
    idempotency_window_ms: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceCommandRateKey {
    installation_id: String,
    projection_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceCommandRateWindow {
    window_start_ms: i64,
    retained_until_ms: i64,
    count: usize,
}

#[derive(Debug, Default)]
struct SourceCommandMaintenance {
    phase: SourceCommandSweepPhase,
    next_expiration: Option<i64>,
    scanned_expiration: Option<i64>,
}

#[derive(Debug, Default)]
enum SourceCommandSweepPhase {
    #[default]
    Idle,
    Ids(Option<String>),
    Rates(Option<SourceCommandRateKey>),
}

/// Progress of one bounded pass over retained command metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceCommandMaintenanceReport {
    /// Retained ID and rate rows examined, including rows not yet expired.
    pub examined: usize,
    /// Capacity units released by this pass.
    pub removed: usize,
    /// This sweep completed, or no sweep is currently due.
    pub reached_end: bool,
}

impl SourceCommandMaintenance {
    fn observe(&mut self, until: i64) {
        self.next_expiration = Some(
            self.next_expiration
                .map_or(until, |current| current.min(until)),
        );
        if !matches!(self.phase, SourceCommandSweepPhase::Idle) {
            self.scanned_expiration = Some(
                self.scanned_expiration
                    .map_or(until, |current| current.min(until)),
            );
        }
    }

    fn expire(
        &mut self,
        retained_ids: &mut BTreeMap<String, i64>,
        rate_windows: &mut BTreeMap<SourceCommandRateKey, SourceCommandRateWindow>,
        now_millis: i64,
    ) -> SourceCommandMaintenanceReport {
        let mut report = SourceCommandMaintenanceReport::default();
        if matches!(self.phase, SourceCommandSweepPhase::Idle) {
            if self.next_expiration.is_none_or(|until| until > now_millis) {
                report.reached_end = true;
                return report;
            }
            self.phase = SourceCommandSweepPhase::Ids(None);
            self.scanned_expiration = None;
        }
        while report.examined < SOURCE_COMMAND_MAINTENANCE_BATCH {
            let limit = SOURCE_COMMAND_MAINTENANCE_BATCH - report.examined;
            let batch = match &mut self.phase {
                SourceCommandSweepPhase::Ids(cursor) => sweep_source_command_rows(
                    retained_ids,
                    cursor,
                    &mut self.scanned_expiration,
                    now_millis,
                    limit,
                    |until| *until,
                ),
                SourceCommandSweepPhase::Rates(cursor) => sweep_source_command_rows(
                    rate_windows,
                    cursor,
                    &mut self.scanned_expiration,
                    now_millis,
                    limit,
                    |window| window.retained_until_ms,
                ),
                SourceCommandSweepPhase::Idle => break,
            };
            report.examined += batch.examined;
            report.removed += batch.removed;
            if batch.reached_end {
                match self.phase {
                    SourceCommandSweepPhase::Ids(_) => {
                        self.phase = SourceCommandSweepPhase::Rates(None)
                    }
                    SourceCommandSweepPhase::Rates(_) => {
                        self.phase = SourceCommandSweepPhase::Idle;
                        self.next_expiration = self.scanned_expiration.take();
                        report.reached_end = true;
                        break;
                    }
                    SourceCommandSweepPhase::Idle => break,
                }
            }
        }
        report
    }
}

fn sweep_source_command_rows<Key: Ord + Clone, Row>(
    rows: &mut BTreeMap<Key, Row>,
    cursor: &mut Option<Key>,
    earliest: &mut Option<i64>,
    now_millis: i64,
    limit: usize,
    deadline: impl Fn(&Row) -> i64,
) -> SourceCommandMaintenanceReport {
    use std::ops::Bound;
    let start = cursor.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut expired = Vec::new();
    let mut last = None;
    let mut examined = 0;
    for (key, row) in rows.range((start, Bound::Unbounded)).take(limit) {
        let until = deadline(row);
        if until <= now_millis {
            expired.push(key.clone());
        } else {
            *earliest = Some(earliest.map_or(until, |current| current.min(until)));
        }
        last = Some(key);
        examined += 1;
    }
    *cursor = last.cloned();
    let removed = expired.len();
    for key in expired {
        rows.remove(&key);
    }
    SourceCommandMaintenanceReport {
        examined,
        removed,
        reached_end: examined < limit,
    }
}

impl SourceCommandRegistry {
    /// Create an empty command registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bound all pending commands, terminal ids, and projection rate rows.
    pub fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self {
            entries: BTreeMap::new(),
            retained_ids: BTreeMap::new(),
            rate_windows: BTreeMap::new(),
            maintenance: SourceCommandMaintenance::default(),
            capacity,
            next_registration_id: 0,
        }
    }

    /// Capacity units held across active commands and retained metadata.
    pub fn occupied(&self) -> usize {
        self.entries.len() + self.retained_ids.len() + self.rate_windows.len()
    }

    /// Examine at most 64 retained ids or rate rows and report sweep progress.
    pub fn expire_retained(&mut self, now_millis: i64) -> SourceCommandMaintenanceReport {
        self.maintenance
            .expire(&mut self.retained_ids, &mut self.rate_windows, now_millis)
    }

    /// Number of registered in-flight commands.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no command is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove only the pending registration owned by one dispatch attempt.
    /// Use this before publication is possible; removal does not retain the id.
    pub fn remove_if(&mut self, id: &str, registration_id: u64) -> bool {
        if self
            .entries
            .get(id)
            .is_none_or(|entry| entry.registration_id != registration_id)
        {
            return false;
        }
        self.entries.remove(id);
        true
    }

    /// Retire the exact registration when delivery or execution may have
    /// occurred. The retained id fences late results and ambiguous retries.
    pub fn retire_if(&mut self, id: &str, registration_id: u64, now_millis: i64) -> bool {
        if self
            .entries
            .get(id)
            .is_none_or(|entry| entry.registration_id != registration_id)
        {
            return false;
        }
        self.terminal_remove(id, now_millis)
    }

    /// Remove all in-flight commands registered to one Source session.
    pub fn drain_for_session(&mut self, context: &SessionContext, now_millis: i64) -> Vec<String> {
        self.extract_terminal(now_millis, |entry| {
            entry.installation_id == context.installation_id
                && entry.projection_id == context.projection_id
                && entry.session_id == context.session_id
        })
    }

    /// Remove all in-flight commands whose deadline has passed.
    pub fn expire(&mut self, now_millis: i64) -> Vec<String> {
        self.extract_terminal(now_millis, |entry| {
            entry
                .deadline_ms
                .is_some_and(|deadline| deadline <= now_millis)
        })
    }

    fn extract_terminal<F>(&mut self, now_millis: i64, mut pred: F) -> Vec<String>
    where
        F: FnMut(&SourceCommandEntry) -> bool,
    {
        let retained_ids = &mut self.retained_ids;
        let maintenance = &mut self.maintenance;
        self.entries
            .extract_if(.., |_, entry| pred(entry))
            .map(|(id, entry)| {
                retain_source_command_id(
                    retained_ids,
                    maintenance,
                    &id,
                    now_millis,
                    entry.idempotency_window_ms,
                );
                id
            })
            .collect()
    }

    /// Register one daemon-to-Source command before it is sent.
    pub fn register(&mut self, req: SourceCommandRegister<'_>) -> Result<u64, SourceCommandError> {
        self.expire_retained(req.now_millis);
        let ctx = source_command_context(
            req.session,
            req.current_registry_hash,
            req.credential_generation,
            req.current_binding_generation,
            req.current_installation_config_version,
            req.current_projection_version,
        )?;
        if req.command.id.trim().is_empty() {
            return Err(SourceCommandError::EmptyCommandId);
        }
        if self.entries.contains_key(&req.command.id) {
            return Err(SourceCommandError::DuplicateCommandId);
        }
        if let Some(until) = self.retained_ids.get(req.command.id.as_str()).copied() {
            if until > req.now_millis {
                return Err(SourceCommandError::DuplicateCommandId);
            }
            self.retained_ids.remove(req.command.id.as_str());
        }
        if let Some(max) = req.max_in_flight
            && self
                .entries
                .values()
                .filter(|entry| source_command_entry_matches_context(entry, ctx))
                .count()
                >= max
        {
            return Err(SourceCommandError::InFlightLimitExceeded);
        }
        if let Some(deadline) = req.deadline_ms
            && deadline <= req.now_millis
        {
            return Err(SourceCommandError::DeadlineExceeded);
        }
        if let Err(error) = validate_json_schema(req.command_schema, &req.command.action) {
            return Err(SourceCommandError::Schema(error));
        }
        let registration_id = self
            .next_registration_id
            .checked_add(1)
            .ok_or(SourceCommandError::RegistrationIdsExhausted)?;
        let rate_key = SourceCommandRateKey {
            installation_id: ctx.installation_id.clone(),
            projection_id: ctx.projection_id.clone(),
        };
        self.expire_rate(&rate_key, req.now_millis);
        let needed = 1 + usize::from(!self.rate_windows.contains_key(&rate_key));
        if needed > self.capacity.get().saturating_sub(self.occupied()) {
            return Err(SourceCommandError::RetentionCapacityExceeded);
        }
        self.admit_rate(
            rate_key,
            req.now_millis,
            req.rate_limit_window_ms,
            req.rate_limit_max_commands,
        )?;
        self.next_registration_id = registration_id;
        self.entries.insert(
            req.command.id.clone(),
            SourceCommandEntry {
                registration_id,
                installation_id: ctx.installation_id.clone(),
                projection_id: ctx.projection_id.clone(),
                session_id: ctx.session_id.clone(),
                registry_hash: ctx.registry_hash.clone(),
                credential_generation: ctx.credential_generation,
                binding_generation: ctx.binding_generation,
                installation_config_version: ctx.installation_config_version,
                projection_version: ctx.projection_version,
                deadline_ms: req.deadline_ms,
                max_inline_result_bytes: req.max_inline_result_bytes,
                command_result_schema: req.command_result_schema.cloned(),
                idempotency_window_ms: req.idempotency_window_ms,
            },
        );
        Ok(registration_id)
    }

    /// Admit a Source command result and remove its in-flight entry.
    pub fn resolve(
        &mut self,
        req: SourceCommandResolve<'_>,
    ) -> Result<CommandResult, SourceCommandError> {
        let ctx = source_command_context(
            req.session,
            req.current_registry_hash,
            req.credential_generation,
            req.current_binding_generation,
            req.current_installation_config_version,
            req.current_projection_version,
        )?;
        let terminal_error = {
            let entry = self
                .entries
                .get(&req.result.id)
                .ok_or(SourceCommandError::CommandNotFound)?;
            if !source_command_entry_matches_context(entry, ctx) {
                return Err(SourceCommandError::SessionMismatch);
            }
            if let Some(deadline) = entry.deadline_ms
                && deadline <= req.now_millis
            {
                Some(SourceCommandError::DeadlineExceeded)
            } else if let Some(limit) = entry.max_inline_result_bytes
                && result_exceeds_inline_bytes(&req.result.outcome, limit)
            {
                Some(SourceCommandError::ResultTooLarge)
            } else if let (Ok(value), Some(schema)) =
                (&req.result.outcome, entry.command_result_schema.as_ref())
                && let Err(error) = validate_json_schema(Some(schema), value)
            {
                Some(SourceCommandError::Schema(error))
            } else {
                None
            }
        };
        if let Some(error) = terminal_error {
            self.terminal_remove(&req.result.id, req.now_millis);
            return Err(error);
        }
        self.terminal_remove(&req.result.id, req.now_millis);
        Ok(req.result)
    }

    fn terminal_remove(&mut self, id: &str, now_millis: i64) -> bool {
        let Some(entry) = self.entries.remove(id) else {
            return false;
        };
        self.retain_id(id, now_millis, entry.idempotency_window_ms);
        true
    }

    fn retain_id(&mut self, id: &str, now_millis: i64, window_ms: u64) {
        retain_source_command_id(
            &mut self.retained_ids,
            &mut self.maintenance,
            id,
            now_millis,
            window_ms,
        );
    }

    fn expire_rate(&mut self, key: &SourceCommandRateKey, now_millis: i64) {
        if self
            .rate_windows
            .get(key)
            .is_some_and(|window| window.retained_until_ms <= now_millis)
        {
            self.rate_windows.remove(key);
        }
    }

    fn admit_rate(
        &mut self,
        key: SourceCommandRateKey,
        now_millis: i64,
        window_ms: u64,
        max_commands: usize,
    ) -> Result<(), SourceCommandError> {
        if window_ms == 0 || max_commands == 0 {
            return Err(SourceCommandError::RateLimited);
        }
        let window_ms = saturating_i64_from_u64(window_ms, "source command rate window");
        let retained_until_ms = now_millis.saturating_add(window_ms);
        let window = self
            .rate_windows
            .entry(key)
            .or_insert(SourceCommandRateWindow {
                window_start_ms: now_millis,
                retained_until_ms,
                count: 0,
            });
        if now_millis < window.window_start_ms || now_millis >= window.retained_until_ms {
            *window = SourceCommandRateWindow {
                window_start_ms: now_millis,
                retained_until_ms,
                count: 0,
            };
        }
        if window.count >= max_commands {
            return Err(SourceCommandError::RateLimited);
        }
        window.count = window.count.saturating_add(1);
        self.maintenance.observe(window.retained_until_ms);
        Ok(())
    }
}

fn source_command_entry_matches_context(entry: &SourceCommandEntry, ctx: &SessionContext) -> bool {
    entry.installation_id == ctx.installation_id
        && entry.projection_id == ctx.projection_id
        && entry.session_id == ctx.session_id
        && entry.registry_hash == ctx.registry_hash
        && entry.credential_generation == ctx.credential_generation
        && entry.binding_generation == ctx.binding_generation
        && entry.installation_config_version == ctx.installation_config_version
        && entry.projection_version == ctx.projection_version
}

fn retain_source_command_id(
    retained_ids: &mut BTreeMap<String, i64>,
    maintenance: &mut SourceCommandMaintenance,
    id: &str,
    now_millis: i64,
    window_ms: u64,
) {
    if window_ms == 0 {
        return;
    }
    let until = now_millis.saturating_add(saturating_i64_from_u64(
        window_ms,
        "source command idempotency window",
    ));
    retained_ids.insert(id.to_owned(), until);
    maintenance.observe(until);
}

/// Context for registering one Source outbound command.
pub struct SourceCommandRegister<'a> {
    /// Ready Source session.
    pub session: &'a EndpointSession,
    /// Command being sent to the Source.
    pub command: &'a OutboundCommand,
    /// Current registry hash expected by this daemon.
    pub current_registry_hash: &'a str,
    /// Current credential generation for the installation.
    pub credential_generation: u64,
    /// Current binding generation for the Source projection.
    pub current_binding_generation: u64,
    /// Current shared installation config version.
    pub current_installation_config_version: u64,
    /// Current Source projection version.
    pub current_projection_version: u64,
    /// Wall-clock timestamp used for deadline admission.
    pub now_millis: i64,
    /// Optional command deadline in milliseconds since epoch.
    pub deadline_ms: Option<i64>,
    /// Maximum in-flight commands accepted for this ready Source session.
    pub max_in_flight: Option<usize>,
    /// Maximum inline result bytes accepted from this command.
    pub max_inline_result_bytes: Option<usize>,
    /// Bounded replay-suppression window for terminal command ids.
    pub idempotency_window_ms: u64,
    /// Rate-limit window for daemon-to-Source commands on one projection.
    pub rate_limit_window_ms: u64,
    /// Maximum daemon-to-Source commands admitted per projection window.
    pub rate_limit_max_commands: usize,
    /// Schema declared for daemon-to-source command action values.
    pub command_schema: Option<&'a JsonSchema>,
    /// Schema declared for successful source command result values.
    pub command_result_schema: Option<&'a JsonSchema>,
}

/// Context for resolving one Source command result.
pub struct SourceCommandResolve<'a> {
    /// Ready Source session.
    pub session: &'a EndpointSession,
    /// Result frame received from the Source.
    pub result: CommandResult,
    /// Current registry hash expected by this daemon.
    pub current_registry_hash: &'a str,
    /// Current credential generation for the installation.
    pub credential_generation: u64,
    /// Current binding generation for the Source projection.
    pub current_binding_generation: u64,
    /// Current shared installation config version.
    pub current_installation_config_version: u64,
    /// Current Source projection version.
    pub current_projection_version: u64,
    /// Wall-clock timestamp used for deadline admission.
    pub now_millis: i64,
}

fn source_command_context<'a>(
    session: &'a EndpointSession,
    current_registry_hash: &str,
    credential_generation: u64,
    current_binding_generation: u64,
    current_installation_config_version: u64,
    current_projection_version: u64,
) -> Result<&'a SessionContext, SourceCommandError> {
    session
        .admit_business()
        .map_err(SourceCommandError::Session)?;
    session
        .admit_credential(credential_generation)
        .map_err(SourceCommandError::Session)?;
    let ctx = session
        .context()
        .ok_or(SourceCommandError::Session(SessionReject::NotReady))?;
    if ctx.role != Role::Source {
        return Err(SourceCommandError::NotSource);
    }
    if ctx.registry_hash != current_registry_hash {
        return Err(SourceCommandError::RegistryHashMismatch);
    }
    if ctx.credential_generation != credential_generation {
        return Err(SourceCommandError::CredentialGenerationMismatch);
    }
    if ctx.binding_generation != current_binding_generation {
        return Err(SourceCommandError::BindingGenerationMismatch);
    }
    if ctx.installation_config_version != current_installation_config_version {
        return Err(SourceCommandError::InstallationConfigVersionMismatch);
    }
    if ctx.projection_version != current_projection_version {
        return Err(SourceCommandError::ProjectionVersionMismatch);
    }
    Ok(ctx)
}

/// Runtime authority required to admit one inbound Source event.
pub struct SourceIngest<'a> {
    /// Source-private atomic commit port, paired with the declared sink's
    /// State backend by the host assembly.
    pub store: &'a dyn SourceIngress,
    /// Ready endpoint session that gates this frame.
    pub session: &'a EndpointSession,
    /// Installation id the frame claims to belong to.
    pub installation_id: &'a str,
    /// Source projection definition admitted for the installation.
    pub projection: &'a ExternalProjectionDef,
    /// Current registry hash expected by this daemon.
    pub current_registry_hash: &'a str,
    /// Current credential generation for the installation.
    pub credential_generation: u64,
    /// Current binding generation for the source projection.
    pub current_binding_generation: u64,
    /// Current shared installation config version.
    pub current_installation_config_version: u64,
    /// Residual source policy snapshot evaluated before append.
    pub policy: &'a PolicySnapshot,
    /// Identity the source event is admitted under.
    pub acting: IdentityRef,
    /// Resource id for the declared event sink. Source policy uses this as the
    /// runtime target key; callers that have not registered a concrete Resource
    /// can pass `ResourceId::new(0)` and still get input-dependent checks.
    pub target: ResourceId,
    /// Wall-clock timestamp used by residual policy checks.
    pub now_millis: i64,
    /// Clock sampled by the Source owner after acquiring its commit boundary.
    pub decision_clock: Arc<dyn xolotl_source::SourceClock>,
    /// Event id dedupe retention window in milliseconds.
    pub dedupe_window_ms: u64,
}

/// Execute a stream lifecycle operation through the Source storage owner.
/// The host must first gate the ready session against current installation,
/// projection and credential authority; the store rechecks the scope epoch in
/// its own serializable domain before changing any stream state.
pub async fn operate_source_stream(
    store: &dyn SourceIngress,
    context: &SessionContext,
    request: SourceStreamRequest,
) -> SourceStreamResult {
    let SourceStreamRequest {
        request_id,
        stream_id,
        operation,
    } = request;
    let rejected = |code| {
        SourceStreamOutcome::Rejected(SourceStreamRejected {
            code,
            current_revision: None,
            active_epoch: None,
            current: None,
        })
    };
    let outcome = if context.role != Role::Source || context.scope_epoch == 0 {
        rejected(SourceStreamRejectCode::ScopeInactive)
    } else if validate_source_segment(&request_id, SourcePathError::StreamId).is_err() {
        rejected(SourceStreamRejectCode::InvalidRequestId)
    } else if validate_source_segment(&stream_id, SourcePathError::StreamId).is_err() {
        rejected(SourceStreamRejectCode::InvalidStreamId)
    } else {
        let stream = SourceStreamScope {
            installation_id: &context.installation_id,
            projection_id: &context.projection_id,
            scope_epoch: context.scope_epoch,
            stream_id: &stream_id,
        };
        match operation {
            SourceStreamOperation::Inspect => match store.inspect_stream(stream).await {
                Ok(Some(snapshot)) => {
                    SourceStreamOutcome::Inspected(external_source_stream_snapshot(snapshot))
                }
                Ok(None) => rejected(SourceStreamRejectCode::ScopeInactive),
                Err(error) => source_stream_store_error(error),
            },
            SourceStreamOperation::Open { expected_revision } => {
                match store
                    .open_stream(SourceStreamOpen {
                        stream,
                        open_id: &request_id,
                        expected_revision,
                    })
                    .await
                {
                    Ok(SourceStreamOpenOutcome::Opened(snapshot)) => {
                        SourceStreamOutcome::Opened(external_source_stream_snapshot(snapshot))
                    }
                    Ok(SourceStreamOpenOutcome::AlreadyOpen(snapshot)) => {
                        SourceStreamOutcome::Rejected(SourceStreamRejected {
                            code: SourceStreamRejectCode::AlreadyOpen,
                            current_revision: None,
                            active_epoch: None,
                            current: Some(external_source_stream_snapshot(snapshot)),
                        })
                    }
                    Ok(SourceStreamOpenOutcome::RevisionConflict { current_revision }) => {
                        SourceStreamOutcome::Rejected(SourceStreamRejected {
                            code: SourceStreamRejectCode::RevisionConflict,
                            current_revision: Some(current_revision),
                            active_epoch: None,
                            current: None,
                        })
                    }
                    Ok(SourceStreamOpenOutcome::QuotaExceeded) => {
                        rejected(SourceStreamRejectCode::QuotaExceeded)
                    }
                    Ok(SourceStreamOpenOutcome::ScopeInactive) => {
                        rejected(SourceStreamRejectCode::ScopeInactive)
                    }
                    Err(error) => source_stream_store_error(error),
                }
            }
            SourceStreamOperation::Retire { stream_epoch: 0 } => {
                rejected(SourceStreamRejectCode::InvalidEpoch)
            }
            SourceStreamOperation::Retire { stream_epoch } => {
                match store
                    .retire_stream(SourceStreamRetire {
                        stream,
                        stream_epoch,
                    })
                    .await
                {
                    Ok(SourceStreamRetireOutcome::Retired { revision }) => {
                        SourceStreamOutcome::Retired { revision }
                    }
                    Ok(SourceStreamRetireOutcome::Inactive { revision }) => {
                        SourceStreamOutcome::Rejected(SourceStreamRejected {
                            code: SourceStreamRejectCode::Inactive,
                            current_revision: Some(revision),
                            active_epoch: None,
                            current: None,
                        })
                    }
                    Ok(SourceStreamRetireOutcome::Stale { active_epoch }) => {
                        SourceStreamOutcome::Rejected(SourceStreamRejected {
                            code: SourceStreamRejectCode::StaleEpoch,
                            current_revision: None,
                            active_epoch: Some(active_epoch),
                            current: None,
                        })
                    }
                    Ok(SourceStreamRetireOutcome::ScopeInactive) => {
                        rejected(SourceStreamRejectCode::ScopeInactive)
                    }
                    Err(error) => source_stream_store_error(error),
                }
            }
        }
    };
    SourceStreamResult {
        request_id,
        stream_id,
        outcome,
    }
}

fn external_source_stream_snapshot(
    snapshot: xolotl_source::SourceStreamSnapshot,
) -> ExternalSourceStreamSnapshot {
    ExternalSourceStreamSnapshot {
        revision: snapshot.revision,
        active: snapshot.active.map(|active| ExternalSourceStreamState {
            stream_epoch: active.stream_epoch,
            last_seq: active.last_seq,
            open_id: active.open_id,
            opened_at_revision: active.opened_at_revision,
        }),
    }
}

fn source_stream_store_error(error: SourceStoreError) -> SourceStreamOutcome {
    let code = match error {
        SourceStoreError::Aborted(message) => {
            tracing::warn!(%message, "Source stream lifecycle storage operation aborted");
            SourceStreamRejectCode::StorageUnavailable
        }
        SourceStoreError::Indeterminate(message) => {
            tracing::error!(%message, "Source stream lifecycle outcome requires inspection");
            SourceStreamRejectCode::OutcomeUnknown
        }
    };
    SourceStreamOutcome::Rejected(SourceStreamRejected {
        code,
        current_revision: None,
        active_epoch: None,
        current: None,
    })
}

/// Authoritative daemon ingest for one [`InboundEvent`]. This is the
/// only place an external Source frame becomes state: it gates the ready
/// session, validates declaration/schema/policy, dedupes event ids durably, and
/// forcibly stamps daemon-owned inbound taint before appending to the declared sink.
pub async fn ingest_source_event(
    req: SourceIngest<'_>,
    event: InboundEvent,
) -> Result<EventAck, SourceIngestError> {
    let emits = admit_source_ingest(&req, &event).await?;
    validate_source_segment(&event.id, SourcePathError::EventId)?;
    let stream = source_stream_position(&event)?;
    let stream_epoch = stream.map(|position| position.stream_epoch);
    let scope_epoch = req
        .session
        .context()
        .ok_or(SourceIngestError::Session(SessionReject::NotReady))?
        .scope_epoch;
    check_source_policy(&req, &event).await?;
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy)
        .map_err(|_error| SourceIngestError::State("source claim entropy unavailable".into()))?;
    let claim_id = SourceClaimId::from_bytes(entropy);
    let source_key = source_projection_key(req.installation_id, &req.projection.id);
    let taint = TaintSet::of(TaintSource::Inbound {
        source: format!("source/{source_key}").into(),
        channel: emits.sink.to_string().into(),
    });
    let result = req
        .store
        .commit(SourceCommit {
            claim: SourceClaim {
                installation_id: req.installation_id,
                projection_id: &req.projection.id,
                event_id: &event.id,
                claim_id,
                scope_epoch,
                stream_epoch,
            },
            received_at_ms: req.now_millis,
            decision_clock: req.decision_clock.clone(),
            dedupe_window_ms: req.dedupe_window_ms,
            sink: &emits.sink,
            capacity: &emits.capacity,
            max_inline_payload_bytes: emits.max_inline_payload_bytes,
            payload: &event.payload,
            taint: &taint,
            stream,
            rate_limit: emits.rate_limit.as_ref(),
        })
        .await
        .map_err(|error| {
            if matches!(error, SourceStoreError::Indeterminate(_)) {
                tracing::error!(
                    installation_id = req.installation_id,
                    projection_id = %req.projection.id,
                    scope_epoch,
                    ?stream_epoch,
                    event_id = %event.id,
                    %claim_id,
                    "Source atomic commit result requires host evidence inspection"
                );
            }
            match error {
                SourceStoreError::Aborted(message) => SourceIngestError::State(message),
                SourceStoreError::Indeterminate(_) => SourceIngestError::CommitOutcomeUnknown,
            }
        })?;
    let status = match result {
        SourceCommitOutcome::Accepted => AckStatus::Accepted,
        SourceCommitOutcome::Duplicate => AckStatus::Duplicate,
        SourceCommitOutcome::Rejected(SourceCommitRejection::Backpressured) => {
            return Err(SourceIngestError::Backpressured);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::CapacityExceeded) => {
            return Err(SourceIngestError::CapacityExceeded);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::RetentionCapacityExceeded) => {
            return Err(SourceIngestError::RetentionCapacityExceeded);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict) => {
            return Err(SourceIngestError::EventIdConflict);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::PayloadTooLarge) => {
            return Err(SourceIngestError::PayloadTooLarge);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::StreamInactive) => {
            return Err(SourceIngestError::StreamInactive);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::StreamEpochMismatch {
            active_epoch,
        }) => {
            return Err(SourceIngestError::StreamEpochMismatch { active_epoch });
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive) => {
            return Err(SourceIngestError::ScopeInactive);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::DeclarationMismatch) => {
            return Err(SourceIngestError::DeclarationMismatch);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::SinkTypeMismatch) => {
            return Err(SourceIngestError::SinkTypeMismatch);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited) => {
            return Err(SourceIngestError::RateLimited);
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::SequenceReplay { last, seq }) => {
            return Err(SourceIngestError::SequenceReplay { last, seq });
        }
        SourceCommitOutcome::Rejected(SourceCommitRejection::SequenceGap { expected, seq }) => {
            return Err(SourceIngestError::SequenceGap { expected, seq });
        }
    };
    Ok(EventAck {
        id: event.id,
        status,
        reject_reason: None,
        stream_epoch,
    })
}

fn source_stream_position(
    event: &InboundEvent,
) -> Result<Option<SourceStreamPosition<'_>>, SourceIngestError> {
    match (event.stream_id.as_deref(), event.seq, event.stream_epoch) {
        (None, None, None) => Ok(None),
        (Some(stream_id), Some(seq), Some(stream_epoch))
            if (1..=i64::MAX as u64).contains(&seq) && stream_epoch != 0 =>
        {
            validate_source_segment(stream_id, SourcePathError::StreamId)?;
            Ok(Some(SourceStreamPosition {
                stream_id,
                stream_epoch,
                seq,
            }))
        }
        _ => Err(SourceIngestError::InvalidSequence),
    }
}

fn validate_source_segment(segment: &str, error: SourcePathError) -> Result<(), SourceIngestError> {
    if segment.is_empty() || segment.len() > 256 {
        return Err(error.into_error());
    }
    Path::try_new("state")
        .and_then(|path| path.try_push_literal(segment))
        .map(|_path| ())
        .map_err(|_error| error.into_error())
}

async fn admit_source_ingest<'a>(
    req: &'a SourceIngest<'_>,
    event: &InboundEvent,
) -> Result<&'a xolotl_types::EventSource, SourceIngestError> {
    req.session
        .admit_source_event(&event.observed)
        .map_err(SourceIngestError::Session)?;
    req.session
        .admit_credential(req.credential_generation)
        .map_err(SourceIngestError::Session)?;
    let ctx = req
        .session
        .context()
        .ok_or(SourceIngestError::Session(SessionReject::NotReady))?;
    if ctx.installation_id != req.installation_id || ctx.projection_id != req.projection.id {
        return Err(SourceIngestError::ProjectionMismatch(
            source_projection_key(req.installation_id, &req.projection.id),
        ));
    }
    if ctx.role != Role::Source || req.projection.role != Role::Source {
        return Err(SourceIngestError::NotSource);
    }
    if ctx.registry_hash != req.current_registry_hash {
        return Err(SourceIngestError::RegistryHashMismatch);
    }
    if ctx.credential_generation != req.credential_generation {
        return Err(SourceIngestError::CredentialGenerationMismatch);
    }
    if ctx.binding_generation != req.current_binding_generation {
        return Err(SourceIngestError::BindingGenerationMismatch);
    }
    if ctx.installation_config_version != req.current_installation_config_version {
        return Err(SourceIngestError::InstallationConfigVersionMismatch);
    }
    if ctx.projection_version != req.projection.version {
        return Err(SourceIngestError::ProjectionVersionMismatch);
    }
    let emits = req
        .projection
        .emits
        .as_ref()
        .ok_or(SourceIngestError::MissingEmits)?;
    if emits.max_inline_payload_bytes == 0 {
        return Err(SourceIngestError::PayloadTooLarge);
    }
    reject_source_forbidden_payload_fields(&event.payload)?;
    validate_json_schema(emits.event_schema.as_ref(), &event.payload)
        .map_err(SourceIngestError::Schema)?;
    Ok(emits)
}

fn reject_source_forbidden_payload_fields(value: &Value) -> Result<(), SourceIngestError> {
    use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
    if !matches!(value.view(), ValueView::Map(_) | ValueView::List(_)) {
        return Ok(());
    }
    let mut visited = BTreeSet::new();
    let mut walk = ValuePostorder::new(value);
    while let Some(node) = walk.next(|key| visited.contains(&key)) {
        if let Some(map) = node.as_map() {
            for key in map.keys() {
                if is_forbidden_source_payload_field(key) {
                    return Err(SourceIngestError::ForbiddenPayloadField {
                        field: key.to_owned(),
                    });
                }
            }
        }
        visited.insert(ValueNodeKey::of(node));
    }
    Ok(())
}

fn is_forbidden_source_payload_field(key: &str) -> bool {
    let normalized = key
        .chars()
        .map(|c| match c {
            '-' | '.' | ':' => '_',
            c => c.to_ascii_lowercase(),
        })
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "authorization"
            | "token"
            | "auth_token"
            | "access_token"
            | "refresh_token"
            | "session_token"
            | "bearer_token"
            | "authority"
            | "authorities"
            | "api_key"
            | "apikey"
            | "x_api_key"
            | "password"
            | "secret"
            | "raw_secret"
            | "pairing_secret"
            | "private_key"
            | "taint"
            | "_taint"
            | "provenance"
            | "_provenance"
            | "identity"
            | "identity_ref"
            | "acting"
            | "acting_identity"
            | "principal"
            | "principal_id"
            | "sink"
            | "event_sink"
            | "source_sink"
            | "capability"
            | "capabilities"
            | "raw_capability"
            | "grant"
            | "credential"
            | "credentials"
            | "credential_id"
            | "credential_ref"
            | "handle"
            | "binding"
            | "binding_generation"
            | "credential_generation"
            | "installation_config_version"
            | "projection_version"
            | "presentation_config_generation"
            | "alias_catalog_generation"
            | "registry_hash"
            | "policy"
            | "policy_result"
            | "policy_decision"
    )
}

async fn check_source_policy(
    req: &SourceIngest<'_>,
    event: &InboundEvent,
) -> Result<(), SourceIngestError> {
    match req
        .policy
        .check(&CheckCtx {
            input: &event.payload,
            acting: req.acting,
            now_millis: req.now_millis,
            target: req.target,
        })
        .await
    {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Ask { reason, .. } | PolicyDecision::Deny { reason } => {
            Err(SourceIngestError::Policy(reason))
        }
    }
}

fn source_projection_key(installation_id: &str, projection_id: &str) -> String {
    format!("{installation_id}/{projection_id}")
}

#[derive(Clone, Copy)]
enum SourcePathError {
    EventId,
    StreamId,
}

impl SourcePathError {
    fn into_error(self) -> SourceIngestError {
        match self {
            Self::EventId => SourceIngestError::InvalidEventId,
            Self::StreamId => SourceIngestError::InvalidStreamId,
        }
    }
}

/// Validate a Xolotl value against the external schema subset.
pub fn validate_json_schema(schema: Option<&JsonSchema>, value: &Value) -> Result<(), String> {
    match schema.map(Value::view) {
        None => Ok(()),
        Some(ValueView::Map(schema)) => validate_schema_map(schema, value),
        Some(_) => Err("schema must be an object".into()),
    }
}

fn validate_schema_map(schema: &ValueMap, value: &Value) -> Result<(), String> {
    let supported: BTreeSet<&str> = ["type", "required", "properties", "items"]
        .into_iter()
        .collect();
    for key in schema.keys() {
        if !supported.contains(key) {
            return Err(format!("unsupported schema keyword `{key}`"));
        }
    }

    if let Some(t) = schema.get("type") {
        let expected = t
            .as_str()
            .ok_or_else(|| "`type` must be a string".to_string())?;
        if !schema_type_matches(expected, value) {
            return Err(format!("expected `{expected}`"));
        }
    }

    if let Some(required) = schema.get("required") {
        let keys = match required.view() {
            ValueView::List(xs) => xs,
            _ => return Err("`required` must be a list".into()),
        };
        let m = match value.view() {
            ValueView::Map(m) => m,
            _ => return Err("`required` applies only to objects".into()),
        };
        for key in keys {
            let key = key
                .as_str()
                .ok_or_else(|| "`required` entries must be strings".to_string())?;
            if !m.contains_key(key) {
                return Err(format!("missing required property `{key}`"));
            }
        }
    }

    if let Some(properties) = schema.get("properties") {
        let props = match properties.view() {
            ValueView::Map(m) => m,
            _ => return Err("`properties` must be an object".into()),
        };
        let value_map = match value.view() {
            ValueView::Map(m) => m,
            _ => return Err("`properties` applies only to objects".into()),
        };
        for (key, prop_schema) in props {
            if let Some(prop_value) = value_map.get(key) {
                validate_json_schema(Some(prop_schema), prop_value)
                    .map_err(|e| format!("property `{key}`: {e}"))?;
            }
        }
    }

    if let Some(item_schema) = schema.get("items") {
        let items = match value.view() {
            ValueView::List(items) => items,
            _ => return Err("`items` applies only to arrays".into()),
        };
        for (index, item) in items.iter().enumerate() {
            validate_json_schema(Some(item_schema), item)
                .map_err(|e| format!("item `{index}`: {e}"))?;
        }
    }

    Ok(())
}

fn schema_type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "any" => true,
        "null" => matches!(value.view(), ValueView::Null),
        "boolean" | "bool" => matches!(value.view(), ValueView::Bool(_)),
        "integer" | "int" => matches!(value.view(), ValueView::Int(_)),
        "number" => matches!(value.view(), ValueView::Int(_) | ValueView::Float(_)),
        "string" | "str" => matches!(value.view(), ValueView::Str(_)),
        "array" | "list" => matches!(value.view(), ValueView::List(_)),
        "object" | "map" => matches!(value.view(), ValueView::Map(_)),
        "bytes" => matches!(value.view(), ValueView::Bytes(_)),
        "blob" => matches!(value.view(), ValueView::Blob(_)),
        "tensor" => matches!(value.view(), ValueView::Tensor(_)),
        "frame" => matches!(value.view(), ValueView::Frame(_)),
        "stream_end" => matches!(value.view(), ValueView::StreamEnd(_)),
        _ => false,
    }
}

/// Authoritative state for one external Provider/Source session.
///
/// The daemon owns this state; the external program only echoes what it
/// observes.
#[derive(Clone)]
pub struct EndpointSession {
    phase: SessionPhase,
    /// The daemon-adjudicated context sent after hello.
    context: Option<SessionContext>,
    /// Canonical Hello/Context hash expected in authenticated frame AAD.
    transcript_hash: Option<[u8; 32]>,
    /// The credential generation currently valid; frames on an older generation
    /// are rejected after a revoke.
    valid_credential_generation: u64,
}

impl EndpointSession {
    /// A fresh session awaiting the role client's hello.
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::AwaitingHello,
            context: None,
            transcript_hash: None,
            valid_credential_generation: 0,
        }
    }

    /// Current handshake phase.
    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// Whether the session has completed the handshake and may carry business
    /// frames.
    pub fn is_ready(&self) -> bool {
        self.phase == SessionPhase::Ready
    }

    /// Authoritative session context sent by the daemon after hello.
    pub fn context(&self) -> Option<&SessionContext> {
        self.context.as_ref()
    }

    /// Canonical Hello/Context hash for this negotiated session.
    pub fn transcript_hash(&self) -> Option<&[u8; 32]> {
        self.transcript_hash.as_ref()
    }

    /// Receive the role client's hello and return the daemon-adjudicated
    /// `SessionContext`.
    ///
    /// The hello must match the daemon-selected identity, registry hash, and
    /// lightweight generation axes.
    pub fn on_hello(
        &mut self,
        hello: &RoleSessionClientHello,
        adjudicate: impl FnOnce(&RoleSessionClientHello) -> SessionContext,
    ) -> Result<SessionContext, SessionReject> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionReject::Closed);
        }
        if self.phase != SessionPhase::AwaitingHello {
            return Err(SessionReject::OutOfOrder);
        }
        let context = adjudicate(hello);
        if hello.installation_id != context.installation_id
            || hello.projection_id != context.projection_id
            || hello.role != context.role
            || hello.registry_hash != context.registry_hash
            || hello.observed.presentation_config_generation
                != context.presentation_config_generation
            || hello.observed.alias_catalog_generation != context.alias_catalog_generation
            || context.installation_epoch == 0
            || (context.role == Role::Source && context.scope_epoch == 0)
            || (context.role == Role::Provider && context.scope_epoch != 0)
        {
            self.phase = SessionPhase::Closed;
            return Err(SessionReject::ContextMismatch);
        }
        self.valid_credential_generation = context.credential_generation;
        self.transcript_hash = Some(external_session_transcript_hash(hello, &context));
        self.context = Some(context.clone());
        self.phase = SessionPhase::AwaitingReady;
        Ok(context)
    }

    /// Confirm an authenticated role client's acceptance of the daemon-selected context.
    ///
    /// The transport must first open an AEAD envelope bound to this session,
    /// validate its `role_ready` frame type, and only then call this method.
    /// Any divergence is fail-closed: the session moves to Closed and business
    /// frames never flow.
    pub fn on_authenticated_ready(&mut self, ready: &RoleReady) -> Result<(), SessionReject> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionReject::Closed);
        }
        if self.phase != SessionPhase::AwaitingReady {
            return Err(SessionReject::OutOfOrder);
        }
        match &self.context {
            Some(ctx) if &ready.accepted_context == ctx => {
                self.phase = SessionPhase::Ready;
                Ok(())
            }
            _ => {
                self.phase = SessionPhase::Closed;
                Err(SessionReject::ContextMismatch)
            }
        }
    }

    /// Gate a business frame: only
    /// admitted once `Ready`. Returns `Ok` to dispatch, or the reject reason.
    pub fn admit_business(&self) -> Result<(), SessionReject> {
        match self.phase {
            SessionPhase::Ready => Ok(()),
            SessionPhase::Closed => Err(SessionReject::Closed),
            _ => Err(SessionReject::NotReady),
        }
    }

    /// Gate an inbound Source event's observed generations: a Source
    /// frame must not claim generations newer than the session's authoritative
    /// ones (a stale or forged frame is rejected). Equal/older presentation
    /// generations are fine (the external endpoint may lag a config push).
    pub fn admit_source_event(&self, observed: &ObservedGenerations) -> Result<(), SessionReject> {
        self.admit_business()?;
        let ctx = self.context.as_ref().ok_or(SessionReject::NotReady)?;
        if observed.presentation_config_generation > ctx.presentation_config_generation
            || observed.alias_catalog_generation > ctx.alias_catalog_generation
        {
            return Err(SessionReject::StaleGeneration);
        }
        Ok(())
    }

    /// Gate a credential generation: after a revoke bumps
    /// `valid_credential_generation`, any frame on an older generation is
    /// rejected. Equal-or-newer is accepted.
    pub fn admit_credential(&self, generation: u64) -> Result<(), SessionReject> {
        if generation < self.valid_credential_generation {
            return Err(SessionReject::RevokedCredential);
        }
        Ok(())
    }

    /// Revoke all credentials older than `new_generation`: bumps the
    /// floor so stale-generation frames are refused thereafter.
    pub fn revoke_below(&mut self, new_generation: u64) {
        self.valid_credential_generation = self.valid_credential_generation.max(new_generation);
    }

    /// Close the session (shutdown / error). Fail-closed: no further frames.
    pub fn close(&mut self) {
        self.phase = SessionPhase::Closed;
    }
}

impl Default for EndpointSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, anyhow, bail, ensure};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use xolotl_kernel::{CompiledCheck, PolicyDecision};
    use xolotl_source::{
        ExternalInstallationAuthority, ExternalInstallationMutation, ExternalInstallationRecord,
        SourceClaimEvidence, SourceClaimInspection, SourceEventCommit, SourceEvidenceInspection,
        SourceFuture, SourceStreamLifecycle,
    };
    use xolotl_state::InMemoryBackend;
    use xolotl_types::external::{
        EventSource, ExternalInstallationDef, OverflowPolicy, Role, SourceRateLimit,
        StreamCapacity, Transport, TrustLevel,
    };
    use xolotl_types::{FloatBits, MethodId, Purity, TaintSource};

    fn hello() -> RoleSessionClientHello {
        RoleSessionClientHello {
            role: Role::Source,
            installation_id: "inst-1".into(),
            projection_id: "source".into(),
            registry_hash: "h".into(),
            observed: ObservedGenerations {
                presentation_config_generation: 2,
                alias_catalog_generation: 1,
            },
            config_schema: None,
        }
    }

    fn ctx() -> SessionContext {
        SessionContext {
            installation_id: "inst-1".into(),
            projection_id: "source".into(),
            role: Role::Source,
            registry_hash: "h".into(),
            credential_generation: 3,
            binding_generation: 1,
            installation_config_version: 1,
            projection_version: 1,
            presentation_config_generation: 2,
            alias_catalog_generation: 1,
            session_id: "session-1".into(),
            scope_epoch: 1,
            installation_epoch: 1,
            key_epoch: 1,
        }
    }

    fn ctx_with_session_id(session_id: &str) -> SessionContext {
        SessionContext {
            session_id: session_id.into(),
            ..ctx()
        }
    }

    fn provider_ctx() -> SessionContext {
        SessionContext {
            projection_id: "provider".into(),
            role: Role::Provider,
            scope_epoch: 0,
            ..ctx()
        }
    }

    fn provider_ctx_with_session_id(session_id: &str) -> SessionContext {
        SessionContext {
            projection_id: "provider".into(),
            role: Role::Provider,
            scope_epoch: 0,
            session_id: session_id.into(),
            ..ctx()
        }
    }

    fn complete_handshake() -> anyhow::Result<EndpointSession> {
        complete_handshake_with_session_id("session-1")
    }

    fn complete_handshake_with_session_id(session_id: &str) -> anyhow::Result<EndpointSession> {
        let mut s = EndpointSession::new();
        let sent = s.on_hello(&hello(), |_| ctx_with_session_id(session_id))?;
        s.on_authenticated_ready(&RoleReady {
            accepted_context: sent,
        })?;
        Ok(s)
    }

    fn complete_handshake_with_record(
        record: &ExternalInstallationRecord,
    ) -> anyhow::Result<EndpointSession> {
        let scope_epoch = record.scope_epoch("source").context("Source scope epoch")?;
        let projection = record
            .definition
            .projection("source")
            .context("Source projection")?;
        let mut session = EndpointSession::new();
        let context = session.on_hello(&hello(), |_| SessionContext {
            installation_epoch: record.installation_epoch,
            installation_config_version: record.definition.version,
            projection_version: projection.version,
            scope_epoch,
            ..ctx()
        })?;
        session.on_authenticated_ready(&RoleReady {
            accepted_context: context,
        })?;
        Ok(session)
    }

    fn complete_provider_handshake() -> anyhow::Result<EndpointSession> {
        complete_provider_handshake_with_session_id("session-1")
    }

    fn complete_provider_handshake_with_session_id(
        session_id: &str,
    ) -> anyhow::Result<EndpointSession> {
        let mut hello = hello();
        hello.role = Role::Provider;
        hello.projection_id = "provider".into();
        let mut s = EndpointSession::new();
        let sent = s.on_hello(&hello, |_| provider_ctx_with_session_id(session_id))?;
        s.on_authenticated_ready(&RoleReady {
            accepted_context: sent,
        })?;
        Ok(s)
    }

    fn invoke(invocation_id: &str) -> anyhow::Result<Invoke> {
        invoke_with_path(invocation_id, "effect://external-provider/inst-1/search")
    }

    fn invoke_with_path(invocation_id: &str, effect_path: &str) -> anyhow::Result<Invoke> {
        Ok(Invoke {
            invocation_id: invocation_id.into(),
            effect_path: Path::parse(effect_path)
                .map_err(|error| anyhow!("path parse failed for {effect_path}: {error}"))?,
            method_id: MethodId::new(0),
            input: message_payload("query"),
            deadline_ms: Some(1_000),
            output_stream_to: None,
        })
    }

    fn invoke_result(invocation_id: &str, value: Value) -> InvokeResult {
        InvokeResult {
            invocation_id: invocation_id.into(),
            outcome: Ok(value),
        }
    }

    fn invoke_error_result(invocation_id: &str, kind: &str, message: &str) -> InvokeResult {
        InvokeResult {
            invocation_id: invocation_id.into(),
            outcome: Err(ErrorInfo {
                kind: kind.into(),
                message: message.into(),
            }),
        }
    }

    fn outbound_command(id: &str, action: Value) -> OutboundCommand {
        OutboundCommand {
            id: id.into(),
            action,
            observed: ObservedGenerations {
                presentation_config_generation: 2,
                alias_catalog_generation: 1,
            },
        }
    }

    fn command_result(id: &str, value: Value) -> CommandResult {
        CommandResult {
            id: id.into(),
            outcome: Ok(value),
        }
    }

    fn command_error_result(id: &str, kind: &str, message: &str) -> CommandResult {
        CommandResult {
            id: id.into(),
            outcome: Err(ErrorInfo {
                kind: kind.into(),
                message: message.into(),
            }),
        }
    }

    fn provider_register<'a>(
        session: &'a EndpointSession,
        invoke: &'a Invoke,
    ) -> ProviderInvocationRegister<'a> {
        ProviderInvocationRegister {
            session,
            invoke,
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_projection_version: 1,
            now_millis: 123,
            acting: IdentityRef::ROOT,
            max_in_flight: Some(1024),
            max_identity_in_flight: Some(1024),
            max_effect_in_flight: Some(1024),
            max_inline_result_bytes: Some(1024),
            output_schema: None,
        }
    }

    fn provider_resolve<'a>(
        session: &'a EndpointSession,
        result: &'a InvokeResult,
    ) -> ProviderInvocationResolve<'a> {
        ProviderInvocationResolve {
            session,
            result: result.clone(),
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_projection_version: 1,
            now_millis: 123,
        }
    }

    fn source_command_register<'a>(
        session: &'a EndpointSession,
        command: &'a OutboundCommand,
    ) -> SourceCommandRegister<'a> {
        SourceCommandRegister {
            session,
            command,
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_installation_config_version: 1,
            current_projection_version: 1,
            now_millis: 123,
            deadline_ms: Some(1_000),
            max_in_flight: Some(1024),
            max_inline_result_bytes: Some(1024),
            idempotency_window_ms: 60_000,
            rate_limit_window_ms: 60_000,
            rate_limit_max_commands: 1024,
            command_schema: None,
            command_result_schema: None,
        }
    }

    fn source_command_resolve<'a>(
        session: &'a EndpointSession,
        result: &'a CommandResult,
    ) -> SourceCommandResolve<'a> {
        SourceCommandResolve {
            session,
            result: result.clone(),
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_installation_config_version: 1,
            current_projection_version: 1,
            now_millis: 123,
        }
    }

    fn source_projection(schema: Option<Value>) -> anyhow::Result<ExternalProjectionDef> {
        Ok(ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: source_event_sink()?,
                purity: Purity::Effectful,
                event_schema: schema,
                max_inline_payload_bytes: 65_536,
                capacity: source_capacity(1024, OverflowPolicy::DropOldest),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            version: 1,
        })
    }

    fn source_event_sink() -> anyhow::Result<Path> {
        xolotl_types::sandboxed_source_event_sink_path("inst-1", "source")
            .map_err(|error| anyhow!("source event sink path failed: {error}"))
    }

    fn source_capacity(max_events: u32, on_overflow: OverflowPolicy) -> StreamCapacity {
        StreamCapacity {
            max_events,
            on_overflow,
        }
    }

    fn event(id: &str, payload: Value) -> InboundEvent {
        InboundEvent {
            id: id.into(),
            payload,
            observed: ObservedGenerations {
                presentation_config_generation: 2,
                alias_catalog_generation: 1,
            },
            timestamp_ms: 123,
            stream_id: None,
            seq: None,
            stream_epoch: None,
        }
    }

    fn sequenced_event(
        stream_id: &str,
        stream_epoch: u64,
        seq: u64,
        id: &str,
        payload: Value,
    ) -> InboundEvent {
        InboundEvent {
            stream_id: Some(stream_id.into()),
            seq: Some(seq),
            stream_epoch: Some(stream_epoch),
            ..event(id, payload)
        }
    }

    async fn open_test_stream(
        store: &dyn SourceIngress,
        session: &EndpointSession,
        stream_id: &str,
    ) -> anyhow::Result<u64> {
        let context = session.context().context("ready Source context")?;
        let inspect = operate_source_stream(
            store,
            context,
            SourceStreamRequest {
                request_id: "inspect".into(),
                stream_id: stream_id.into(),
                operation: SourceStreamOperation::Inspect,
            },
        )
        .await;
        let SourceStreamOutcome::Inspected(snapshot) = inspect.outcome else {
            bail!("stream inspection failed: {:?}", inspect.outcome);
        };
        let opened = operate_source_stream(
            store,
            context,
            SourceStreamRequest {
                request_id: format!("open-{}-{}", context.scope_epoch, snapshot.revision),
                stream_id: stream_id.into(),
                operation: SourceStreamOperation::Open {
                    expected_revision: snapshot.revision,
                },
            },
        )
        .await;
        let SourceStreamOutcome::Opened(snapshot) = opened.outcome else {
            bail!("stream open failed: {:?}", opened.outcome);
        };
        Ok(snapshot
            .active
            .context("opened stream lacks state")?
            .stream_epoch)
    }

    fn source_req<'a>(
        store: &'a dyn SourceIngress,
        session: &'a EndpointSession,
        projection: &'a ExternalProjectionDef,
        policy: &'a PolicySnapshot,
    ) -> SourceIngest<'a> {
        SourceIngest {
            store,
            session,
            installation_id: "inst-1",
            projection,
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_installation_config_version: session
                .context()
                .map_or(1, |context| context.installation_config_version),
            policy,
            acting: IdentityRef::ROOT,
            target: ResourceId::new(1),
            now_millis: 123,
            decision_clock: Arc::new(|| 123),
            dedupe_window_ms: 60_000,
        }
    }

    fn source_installation(projection: ExternalProjectionDef) -> ExternalInstallationDef {
        ExternalInstallationDef {
            id: "inst-1".into(),
            platform: "test".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Full,
            config_schema: Value::map(Default::default()),
            config: Value::null(),
            projections: vec![projection],
            version: 0,
        }
    }

    async fn memory_source_with(
        projection: ExternalProjectionDef,
    ) -> anyhow::Result<(
        xolotl_state::Backend,
        Arc<InMemoryBackend>,
        ExternalInstallationRecord,
    )> {
        memory_source_with_options(projection, xolotl_state::InMemoryOptions::default()).await
    }

    async fn memory_source_with_options(
        projection: ExternalProjectionDef,
        options: xolotl_state::InMemoryOptions,
    ) -> anyhow::Result<(
        xolotl_state::Backend,
        Arc<InMemoryBackend>,
        ExternalInstallationRecord,
    )> {
        let (state, store) = InMemoryBackend::with_options(options)?.into_source_parts();
        let ExternalInstallationMutation::Applied(Some(record)) = store
            .compare_install(source_installation(projection), None)
            .await?
        else {
            bail!("initial Source installation did not apply");
        };
        Ok((state, store, record))
    }

    async fn memory_source() -> anyhow::Result<(
        xolotl_state::Backend,
        Arc<InMemoryBackend>,
        ExternalInstallationRecord,
    )> {
        memory_source_with(source_projection(None)?).await
    }

    async fn replace_source_projection(
        store: &InMemoryBackend,
        projection: ExternalProjectionDef,
    ) -> anyhow::Result<ExternalInstallationRecord> {
        let current = store
            .load_installation("inst-1")
            .await?
            .context("current Source installation")?;
        let expected = current.revision();
        let mut definition = current.definition;
        definition.projections = vec![projection];
        let ExternalInstallationMutation::Applied(Some(record)) =
            store.compare_install(definition, Some(expected)).await?
        else {
            bail!("Source declaration replacement did not apply");
        };
        Ok(record)
    }

    async fn expect_source_ingest_error(
        req: SourceIngest<'_>,
        event: InboundEvent,
    ) -> anyhow::Result<SourceIngestError> {
        match ingest_source_event(req, event).await {
            Ok(ack) => bail!("expected source ingest error, got {ack:?}"),
            Err(err) => Ok(err),
        }
    }

    fn message_payload(text: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::string(text.into()));
        Value::map(m)
    }

    fn message_schema() -> Value {
        let mut text_schema = BTreeMap::new();
        text_schema.insert("type".into(), Value::string("string".into()));

        let mut props = BTreeMap::new();
        props.insert("text".into(), Value::map(text_schema));

        let mut schema = BTreeMap::new();
        schema.insert("type".into(), Value::string("object".into()));
        schema.insert(
            "required".into(),
            Value::list(vec![Value::string("text".into())]),
        );
        schema.insert("properties".into(), Value::map(props));
        Value::map(schema)
    }

    struct DenyAll;

    #[async_trait::async_trait]
    impl CompiledCheck for DenyAll {
        async fn evaluate(&self, _ctx: &CheckCtx) -> PolicyDecision {
            PolicyDecision::Deny {
                reason: "blocked".into(),
            }
        }

        fn name(&self) -> &'static str {
            "deny_all"
        }
    }

    #[test]
    fn business_frame_before_ready_is_rejected() -> anyhow::Result<()> {
        let mut s = EndpointSession::new();
        ensure!(
            s.admit_business() == Err(SessionReject::NotReady),
            "business should be rejected before hello"
        );
        s.on_hello(&hello(), |_| ctx())?;
        ensure!(
            s.admit_business() == Err(SessionReject::NotReady),
            "business should be rejected before ready"
        );
        Ok(())
    }

    #[test]
    fn full_handshake_reaches_ready_and_admits_business() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        ensure!(s.is_ready(), "session should be ready");
        ensure!(s.admit_business() == Ok(()), "business should be admitted");
        Ok(())
    }

    #[test]
    fn handshake_rejects_missing_or_wrong_role_epochs() {
        let mut provider_hello = hello();
        provider_hello.role = Role::Provider;
        provider_hello.projection_id = "provider".into();
        for (hello, context) in [
            (
                hello(),
                SessionContext {
                    installation_epoch: 0,
                    ..ctx()
                },
            ),
            (
                hello(),
                SessionContext {
                    scope_epoch: 0,
                    ..ctx()
                },
            ),
            (
                provider_hello,
                SessionContext {
                    scope_epoch: 1,
                    ..provider_ctx()
                },
            ),
        ] {
            let mut session = EndpointSession::new();
            assert_eq!(
                session.on_hello(&hello, |_| context),
                Err(SessionReject::ContextMismatch)
            );
            assert_eq!(session.phase(), SessionPhase::Closed);
        }
    }

    #[test]
    fn context_mismatch_is_fail_closed() -> anyhow::Result<()> {
        let mut s = EndpointSession::new();
        let _sent = s.on_hello(&hello(), |_| ctx())?;
        let mut wrong = ctx();
        wrong.credential_generation = 999;
        let r = s.on_authenticated_ready(&RoleReady {
            accepted_context: wrong,
        });
        ensure!(
            r == Err(SessionReject::ContextMismatch),
            "unexpected ready result: {r:?}"
        );
        ensure!(
            s.phase() == SessionPhase::Closed,
            "session should be closed"
        );
        ensure!(
            s.admit_business() == Err(SessionReject::Closed),
            "closed session should reject business"
        );
        Ok(())
    }

    #[test]
    fn hello_context_mismatch_is_fail_closed() -> anyhow::Result<()> {
        let mut s = EndpointSession::new();
        let mut hello = hello();
        hello.registry_hash = "old".into();

        let r = s.on_hello(&hello, |_| ctx());

        ensure!(
            r == Err(SessionReject::ContextMismatch),
            "unexpected hello result: {r:?}"
        );
        ensure!(
            s.phase() == SessionPhase::Closed,
            "session should be closed"
        );
        ensure!(
            s.admit_business() == Err(SessionReject::Closed),
            "closed session should reject business"
        );
        Ok(())
    }

    #[test]
    fn out_of_order_ready_is_rejected() -> anyhow::Result<()> {
        let mut s = EndpointSession::new();
        ensure!(
            s.on_authenticated_ready(&RoleReady {
                accepted_context: ctx()
            }) == Err(SessionReject::OutOfOrder),
            "ready before hello should be rejected"
        );
        Ok(())
    }

    #[test]
    fn stale_source_generation_is_rejected() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let stale = ObservedGenerations {
            presentation_config_generation: 99,
            alias_catalog_generation: 1,
        };
        ensure!(
            s.admit_source_event(&stale) == Err(SessionReject::StaleGeneration),
            "stale source generation should be rejected"
        );
        let ok = ObservedGenerations {
            presentation_config_generation: 2,
            alias_catalog_generation: 0,
        };
        ensure!(
            s.admit_source_event(&ok) == Ok(()),
            "matching generation should be accepted"
        );
        Ok(())
    }

    #[test]
    fn revoked_credential_generation_is_rejected() -> anyhow::Result<()> {
        let mut s = complete_handshake()?;
        ensure!(
            s.admit_credential(3) == Ok(()),
            "generation 3 should be accepted"
        );
        s.revoke_below(5);
        ensure!(
            s.admit_credential(4) == Err(SessionReject::RevokedCredential),
            "generation 4 should be revoked"
        );
        ensure!(
            s.admit_credential(5) == Ok(()),
            "generation 5 should be accepted"
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_result_must_hit_registered_entry() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("inv-1")?;
        registry.register(provider_register(&s, &inv))?;
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let unknown = invoke_result("missing", Value::null());
        ensure!(
            registry.resolve(provider_resolve(&s, &unknown))
                == Err(ProviderInvocationError::InvocationNotFound),
            "unknown invocation should be rejected"
        );

        let result = invoke_result("inv-1", Value::string("ok".into()));
        let resolved = registry.resolve(provider_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(provider_resolve(&s, &result))
                == Err(ProviderInvocationError::InvocationNotFound),
            "resolved invocation should not be present"
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_rejects_duplicate_in_flight_id() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("inv-1")?;
        registry.register(provider_register(&s, &inv))?;

        let mut duplicate = provider_register(&s, &inv);
        duplicate.max_inline_result_bytes = Some(1);
        ensure!(
            registry.register(duplicate) == Err(ProviderInvocationError::DuplicateInvocationId),
            "duplicate invocation id should be rejected"
        );
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let result = invoke_result("inv-1", Value::string("ok".into()));
        let resolved = registry.resolve(provider_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        ensure!(registry.is_empty(), "registry should be empty");
        Ok(())
    }

    #[test]
    fn provider_cancellation_only_removes_its_own_registration() -> anyhow::Result<()> {
        let session = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let invocation = invoke("reused-id")?;
        let old = registry.register(provider_register(&session, &invocation))?;
        ensure!(registry.remove_if("reused-id", old));
        ensure!(registry.is_empty());

        let current = registry.register(provider_register(&session, &invocation))?;
        ensure!(current != old);
        ensure!(!registry.remove_if("reused-id", old));
        ensure!(registry.len() == 1);
        ensure!(registry.remove_if("reused-id", current));
        ensure!(registry.is_empty());
        Ok(())
    }

    #[test]
    fn provider_invocation_rejects_when_in_flight_limit_is_reached() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let other = complete_provider_handshake_with_session_id("session-2")?;
        let mut registry = ProviderInvocationRegistry::new();
        let first = invoke("inv-1")?;
        let second = invoke("inv-2")?;
        let other_invocation = invoke("inv-other")?;

        let mut first_register = provider_register(&s, &first);
        first_register.max_in_flight = Some(1);
        registry.register(first_register)?;

        let mut second_register = provider_register(&s, &second);
        second_register.max_in_flight = Some(1);
        ensure!(
            registry.register(second_register)
                == Err(ProviderInvocationError::InFlightLimitExceeded),
            "in-flight limit should be enforced"
        );
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let mut other_register = provider_register(&other, &other_invocation);
        other_register.max_in_flight = Some(1);
        registry.register(other_register)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );

        let result = invoke_result("inv-1", Value::string("ok".into()));
        let resolved = registry.resolve(provider_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        let mut retry = provider_register(&s, &second);
        retry.max_in_flight = Some(1);
        registry.register(retry)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_rejects_when_effect_in_flight_limit_is_reached() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let first = invoke_with_path("inv-1", "effect://external-provider/inst-1/search")?;
        let same_effect = invoke_with_path("inv-2", "effect://external-provider/inst-1/search")?;
        let other_effect = invoke_with_path("inv-3", "effect://external-provider/inst-1/index")?;

        let mut first_register = provider_register(&s, &first);
        first_register.max_in_flight = Some(8);
        first_register.max_effect_in_flight = Some(1);
        registry.register(first_register)?;

        let mut same_effect_register = provider_register(&s, &same_effect);
        same_effect_register.max_in_flight = Some(8);
        same_effect_register.max_effect_in_flight = Some(1);
        ensure!(
            registry.register(same_effect_register)
                == Err(ProviderInvocationError::InFlightLimitExceeded),
            "same-effect limit should be enforced"
        );

        let mut other_effect_register = provider_register(&s, &other_effect);
        other_effect_register.max_in_flight = Some(8);
        other_effect_register.max_effect_in_flight = Some(1);
        registry.register(other_effect_register)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_rejects_when_identity_in_flight_limit_is_reached() -> anyhow::Result<()>
    {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let first = invoke_with_path("inv-1", "effect://external-provider/inst-1/search")?;
        let same_identity = invoke_with_path("inv-2", "effect://external-provider/inst-1/index")?;
        let other_identity = invoke_with_path("inv-3", "effect://external-provider/inst-1/index")?;

        let mut first_register = provider_register(&s, &first);
        first_register.acting = IdentityRef::new(7);
        first_register.max_in_flight = Some(8);
        first_register.max_identity_in_flight = Some(1);
        registry.register(first_register)?;

        let mut same_identity_register = provider_register(&s, &same_identity);
        same_identity_register.acting = IdentityRef::new(7);
        same_identity_register.max_in_flight = Some(8);
        same_identity_register.max_identity_in_flight = Some(1);
        ensure!(
            registry.register(same_identity_register)
                == Err(ProviderInvocationError::InFlightLimitExceeded),
            "same-identity limit should be enforced"
        );

        let mut other_identity_register = provider_register(&s, &other_identity);
        other_identity_register.acting = IdentityRef::new(8);
        other_identity_register.max_in_flight = Some(8);
        other_identity_register.max_identity_in_flight = Some(1);
        registry.register(other_identity_register)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_rejects_before_ready_or_wrong_role() -> anyhow::Result<()> {
        let inv = invoke("inv-1")?;
        let mut registry = ProviderInvocationRegistry::new();
        let mut awaiting = EndpointSession::new();
        awaiting.on_hello(&hello(), |_| ctx())?;
        ensure!(
            registry.register(provider_register(&awaiting, &inv))
                == Err(ProviderInvocationError::Session(SessionReject::NotReady)),
            "not-ready provider session should be rejected"
        );

        let source = complete_handshake()?;
        ensure!(
            registry.register(provider_register(&source, &inv))
                == Err(ProviderInvocationError::NotProvider),
            "source session should not register provider invocation"
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_result_checks_generation_and_session() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("inv-1")?;
        registry.register(provider_register(&s, &inv))?;
        let result = invoke_result("inv-1", Value::string("ok".into()));

        let mut wrong_generation = provider_resolve(&s, &result);
        wrong_generation.current_binding_generation = 2;
        ensure!(
            registry.resolve(wrong_generation)
                == Err(ProviderInvocationError::BindingGenerationMismatch),
            "binding generation mismatch should be rejected"
        );

        let mut other = provider_ctx();
        other.projection_id = "other-provider".into();
        let mut other_session = EndpointSession::new();
        let mut hello = hello();
        hello.role = Role::Provider;
        hello.projection_id = "other-provider".into();
        let sent = other_session.on_hello(&hello, |_| other)?;
        other_session.on_authenticated_ready(&RoleReady {
            accepted_context: sent,
        })?;
        ensure!(
            registry.resolve(provider_resolve(&other_session, &result))
                == Err(ProviderInvocationError::SessionMismatch),
            "session mismatch should be rejected"
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_checks_deadline_and_result_size() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let mut expired = invoke("expired")?;
        expired.deadline_ms = Some(100);
        ensure!(
            registry.register(provider_register(&s, &expired))
                == Err(ProviderInvocationError::DeadlineExceeded),
            "expired invocation should be rejected"
        );

        let inv = invoke("large")?;
        let mut small_limit = provider_register(&s, &inv);
        small_limit.max_inline_result_bytes = Some(4);
        registry.register(small_limit)?;
        let result = invoke_result("large", Value::string("too large".into()));
        ensure!(
            registry.resolve(provider_resolve(&s, &result))
                == Err(ProviderInvocationError::ResultTooLarge),
            "large result should be rejected"
        );
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(provider_resolve(&s, &result))
                == Err(ProviderInvocationError::InvocationNotFound),
            "oversized result should close invocation"
        );

        let inv = invoke("large-error")?;
        let mut small_limit = provider_register(&s, &inv);
        small_limit.max_inline_result_bytes = Some(4);
        registry.register(small_limit)?;
        let result = invoke_error_result("large-error", "remote", "too large");
        ensure!(
            registry.resolve(provider_resolve(&s, &result))
                == Err(ProviderInvocationError::ResultTooLarge),
            "large error result should be rejected"
        );
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(provider_resolve(&s, &result))
                == Err(ProviderInvocationError::InvocationNotFound),
            "oversized error result should close invocation"
        );

        let inv = invoke("timeout")?;
        registry.register(provider_register(&s, &inv))?;
        let result = invoke_result("timeout", Value::null());
        let mut late = provider_resolve(&s, &result);
        late.now_millis = 2_000;
        ensure!(
            registry.resolve(late) == Err(ProviderInvocationError::DeadlineExceeded),
            "late result should be rejected"
        );
        Ok(())
    }

    #[test]
    fn provider_invocation_checks_output_schema() -> anyhow::Result<()> {
        let s = complete_provider_handshake()?;
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("schema")?;
        let schema = Value::map(BTreeMap::from([("type".into(), Value::from("string"))]));
        let mut register = provider_register(&s, &inv);
        register.output_schema = Some(&schema);
        registry.register(register)?;

        let result = invoke_result("schema", Value::integer(7));
        ensure!(
            matches!(
                registry.resolve(provider_resolve(&s, &result)),
                Err(ProviderInvocationError::Schema(_))
            ),
            "schema mismatch should be rejected"
        );
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(provider_resolve(&s, &result))
                == Err(ProviderInvocationError::InvocationNotFound),
            "schema failure should close invocation"
        );
        Ok(())
    }

    #[test]
    fn source_command_result_must_hit_registered_entry() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        registry.register(source_command_register(&s, &command))?;
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let unknown = command_result("missing", Value::null());
        ensure!(
            registry.resolve(source_command_resolve(&s, &unknown))
                == Err(SourceCommandError::CommandNotFound),
            "unknown command should be rejected"
        );

        let result = command_result("cmd-1", Value::string("ok".into()));
        let resolved = registry.resolve(source_command_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(source_command_resolve(&s, &result))
                == Err(SourceCommandError::CommandNotFound),
            "resolved command should not be present"
        );
        Ok(())
    }

    #[test]
    fn source_command_rejects_duplicate_in_flight_id() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        registry.register(source_command_register(&s, &command))?;

        let mut duplicate = source_command_register(&s, &command);
        duplicate.max_inline_result_bytes = Some(1);
        ensure!(
            registry.register(duplicate) == Err(SourceCommandError::DuplicateCommandId),
            "duplicate command id should be rejected"
        );
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let result = command_result("cmd-1", Value::string("ok".into()));
        let resolved = registry.resolve(source_command_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        ensure!(registry.is_empty(), "registry should be empty");
        Ok(())
    }

    #[test]
    fn source_command_old_cleanup_cannot_remove_reused_id() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("reused-id", message_payload("send"));
        let mut first = source_command_register(&session, &command);
        first.idempotency_window_ms = 0;
        let old_registration = registry.register(first)?;
        ensure!(registry.remove_if("reused-id", old_registration));

        let mut second = source_command_register(&session, &command);
        second.idempotency_window_ms = 0;
        let current_registration = registry.register(second)?;
        ensure!(current_registration > old_registration);
        ensure!(!registry.remove_if("reused-id", old_registration));
        ensure!(!registry.retire_if("reused-id", old_registration, 124));
        ensure!(registry.len() == 1);
        ensure!(registry.retire_if("reused-id", current_registration, 124));
        ensure!(registry.is_empty());
        Ok(())
    }

    #[test]
    fn source_command_ambiguous_delivery_retains_id_until_window_end() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("ambiguous-id", message_payload("send"));
        let mut first = source_command_register(&session, &command);
        first.idempotency_window_ms = 500;
        let registration_id = registry.register(first)?;

        ensure!(registry.retire_if("ambiguous-id", registration_id, 200));
        ensure!(!registry.retire_if("ambiguous-id", registration_id, 201));
        let mut retry = source_command_register(&session, &command);
        retry.now_millis = 699;
        retry.deadline_ms = Some(1_000);
        ensure!(
            registry.register(retry) == Err(SourceCommandError::DuplicateCommandId),
            "an uncertain dispatch must fence an immediate retry"
        );
        let mut after_window = source_command_register(&session, &command);
        after_window.now_millis = 700;
        after_window.deadline_ms = Some(1_000);
        ensure!(registry.register(after_window)? > registration_id);
        Ok(())
    }

    #[test]
    fn source_command_exhausted_registration_ids_do_not_consume_rate() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        registry.next_registration_id = u64::MAX;
        let command = outbound_command("cmd", message_payload("send"));
        ensure!(
            registry.register(source_command_register(&session, &command))
                == Err(SourceCommandError::RegistrationIdsExhausted)
        );
        ensure!(registry.is_empty());
        ensure!(registry.rate_windows.is_empty());
        Ok(())
    }

    #[test]
    fn source_command_terminal_ids_charge_admission_capacity() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        registry.retained_ids = (0..65_536)
            .map(|index| (format!("retained-{index}"), 60_000))
            .collect();
        registry.maintenance.observe(60_000);
        let command = outbound_command("new-command", message_payload("send"));
        ensure!(
            registry.register(source_command_register(&session, &command))
                == Err(SourceCommandError::RetentionCapacityExceeded)
        );
        ensure!(registry.is_empty());
        ensure!(registry.rate_windows.is_empty());
        Ok(())
    }

    #[test]
    fn source_command_capacity_is_reserved_through_terminal_and_cancel() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(2));
        let first = outbound_command("first", message_payload("send"));
        registry.register(source_command_register(&session, &first))?;
        ensure!(registry.occupied() == 2);
        registry.resolve(source_command_resolve(
            &session,
            &command_result("first", Value::null()),
        ))?;
        ensure!(registry.occupied() == 2);
        let second = outbound_command("second", message_payload("send"));
        let registration = registry.register(source_command_register(&session, &second))?;
        ensure!(registry.occupied() == 3);
        let rejected = outbound_command("rejected", message_payload("send"));
        let rate_before = registry
            .rate_windows
            .values()
            .next()
            .context("missing command rate row")?
            .count;
        ensure!(
            registry.register(source_command_register(&session, &rejected))
                == Err(SourceCommandError::RetentionCapacityExceeded)
        );
        ensure!(
            registry
                .rate_windows
                .values()
                .next()
                .context("missing command rate row after rejection")?
                .count
                == rate_before
        );
        ensure!(registry.retire_if("second", registration, 123));
        ensure!(registry.occupied() == 3 && registry.is_empty());
        ensure!(
            registry.register(source_command_register(&session, &first))
                == Err(SourceCommandError::DuplicateCommandId)
        );
        ensure!(registry.expire_retained(60_123).removed == 3);
        ensure!(registry.occupied() == 0);
        Ok(())
    }

    #[test]
    fn source_command_presend_release_and_zero_window_keep_rate_charge() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(1));
        let command = outbound_command("command", message_payload("send"));
        let mut request = source_command_register(&session, &command);
        request.idempotency_window_ms = 0;
        let registration = registry.register(request)?;
        ensure!(registry.occupied() == 2);
        ensure!(!registry.remove_if("command", registration + 1));
        ensure!(registry.remove_if("command", registration));
        ensure!(registry.occupied() == 1);
        let mut request = source_command_register(&session, &command);
        request.idempotency_window_ms = 0;
        registry.register(request)?;
        registry.resolve(source_command_resolve(
            &session,
            &command_result("command", Value::null()),
        ))?;
        ensure!(registry.occupied() == 1);
        ensure!(registry.retained_ids.is_empty());
        ensure!(
            registry
                .rate_windows
                .values()
                .next()
                .context("missing command rate row after terminal transition")?
                .count
                == 2
        );
        ensure!(registry.expire_retained(60_122).removed == 0);
        ensure!(registry.expire_retained(60_123).removed == 1);
        ensure!(registry.occupied() == 0);
        Ok(())
    }

    #[test]
    fn source_command_expiry_bounds_examined_rows_and_revisits_live_rows() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(199));
        for index in 0..130 {
            let id = format!("command-{index}");
            let command = outbound_command(&id, message_payload("send"));
            let registration = registry.register(source_command_register(&session, &command))?;
            ensure!(registry.retire_if(&id, registration, 123 + index));
        }
        ensure!(registry.occupied() == 131);
        ensure!(registry.expire_retained(60_123).removed == 1);
        ensure!(!registry.retained_ids.contains_key("command-0"));
        ensure!(registry.retained_ids.contains_key("command-1"));
        let live_batch = registry.expire_retained(60_123);
        ensure!(live_batch.examined == 64);
        ensure!(live_batch.removed == 0 && !live_batch.reached_end);
        let mut removed = 0;
        for _ in 0..5 {
            let report = registry.expire_retained(100_000);
            ensure!(report.examined <= 64);
            removed += report.removed;
        }
        ensure!(removed == 130);
        ensure!(registry.expire_retained(100_000).reached_end);
        ensure!(registry.occupied() == 0);
        Ok(())
    }

    #[test]
    fn source_command_expired_retry_preserves_new_fence_despite_cleanup_backlog()
    -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(199));
        for index in 0..130 {
            let command = outbound_command(&format!("command-{index:03}"), message_payload("send"));
            let registration = registry.register(source_command_register(&session, &command))?;
            ensure!(registry.retire_if(&command.id, registration, 123 + index));
        }
        let command = outbound_command("command-129", message_payload("send"));
        let mut request = source_command_register(&session, &command);
        request.now_millis = 61_000;
        request.deadline_ms = Some(62_000);
        let registration = registry.register(request)?;
        ensure!(registry.retire_if(&command.id, registration, 61_000));
        for _ in 0..3 {
            registry.expire_retained(61_000);
        }
        ensure!(registry.occupied() == 2);
        let mut request = source_command_register(&session, &command);
        request.now_millis = 61_001;
        request.deadline_ms = Some(62_000);
        ensure!(registry.register(request) == Err(SourceCommandError::DuplicateCommandId));
        ensure!(registry.expire_retained(121_000).removed == 2);
        ensure!(registry.occupied() == 0);
        Ok(())
    }

    #[test]
    fn source_command_sweep_keeps_earlier_insertions_before_its_cursor() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(199));
        for index in 0..130 {
            let command = outbound_command(&format!("command-{index:03}"), message_payload("send"));
            let mut request = source_command_register(&session, &command);
            if index == 0 {
                request.idempotency_window_ms = 1;
            }
            let registration = registry.register(request)?;
            ensure!(registry.retire_if(&command.id, registration, 123));
        }
        ensure!(registry.expire_retained(124).removed == 1);
        let command = outbound_command("aaa", message_payload("send"));
        let mut request = source_command_register(&session, &command);
        request.now_millis = 124;
        request.idempotency_window_ms = 1;
        let registration = registry.register(request)?;
        ensure!(registry.retire_if(&command.id, registration, 124));
        for _ in 0..3 {
            registry.expire_retained(124);
        }
        ensure!(registry.expire_retained(125).removed == 1);
        ensure!(!registry.retained_ids.contains_key("aaa"));
        ensure!(registry.occupied() == 130);
        Ok(())
    }

    #[test]
    fn source_command_rate_refresh_updates_expiry_hint() -> anyhow::Result<()> {
        let session = complete_handshake()?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(1));
        let command = outbound_command("command", message_payload("send"));
        let registration = registry.register(source_command_register(&session, &command))?;
        ensure!(registry.remove_if("command", registration));
        let mut request = source_command_register(&session, &command);
        request.now_millis = 100;
        let registration = registry.register(request)?;
        ensure!(registry.remove_if("command", registration));
        ensure!(registry.expire_retained(60_099).removed == 0);
        ensure!(registry.expire_retained(60_100).removed == 1);
        ensure!(registry.occupied() == 0);
        Ok(())
    }

    #[test]
    fn source_command_capacity_is_global_across_projections() -> anyhow::Result<()> {
        let first = complete_handshake()?;
        let mut hello = hello();
        hello.projection_id = "another".into();
        let mut second = EndpointSession::new();
        let context = second.on_hello(&hello, |_| SessionContext {
            projection_id: "another".into(),
            ..ctx()
        })?;
        second.on_authenticated_ready(&RoleReady {
            accepted_context: context,
        })?;
        let mut registry =
            SourceCommandRegistry::with_capacity(NonZeroUsize::MIN.saturating_add(2));
        let first_command = outbound_command("first", message_payload("send"));
        registry.register(source_command_register(&first, &first_command))?;
        let second_command = outbound_command("second", message_payload("send"));
        ensure!(
            registry.register(source_command_register(&second, &second_command))
                == Err(SourceCommandError::RetentionCapacityExceeded)
        );
        ensure!(registry.occupied() == 2 && registry.rate_windows.len() == 1);
        Ok(())
    }

    #[test]
    fn source_command_retains_terminal_ids_for_idempotency_window() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        let mut register = source_command_register(&s, &command);
        register.idempotency_window_ms = 500;
        registry.register(register)?;

        let result = command_result("cmd-1", Value::string("ok".into()));
        let resolved = registry.resolve(source_command_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        ensure!(registry.is_empty(), "registry should be empty");

        let mut duplicate = source_command_register(&s, &command);
        duplicate.now_millis = 600;
        duplicate.deadline_ms = Some(1_000);
        duplicate.idempotency_window_ms = 500;
        ensure!(
            registry.register(duplicate) == Err(SourceCommandError::DuplicateCommandId),
            "terminal duplicate should be rejected inside idempotency window"
        );

        let mut after_window = source_command_register(&s, &command);
        after_window.now_millis = 624;
        after_window.deadline_ms = Some(1_000);
        after_window.idempotency_window_ms = 500;
        registry.register(after_window)?;
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );
        Ok(())
    }

    #[test]
    fn source_command_rejects_when_in_flight_limit_is_reached() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let other = complete_handshake_with_session_id("session-2")?;
        let mut registry = SourceCommandRegistry::new();
        let first = outbound_command("cmd-1", message_payload("send"));
        let second = outbound_command("cmd-2", message_payload("send"));
        let other_command = outbound_command("cmd-other", message_payload("send"));

        let mut first_register = source_command_register(&s, &first);
        first_register.max_in_flight = Some(1);
        registry.register(first_register)?;

        let mut second_register = source_command_register(&s, &second);
        second_register.max_in_flight = Some(1);
        ensure!(
            registry.register(second_register) == Err(SourceCommandError::InFlightLimitExceeded),
            "in-flight limit should be enforced"
        );
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let mut other_register = source_command_register(&other, &other_command);
        other_register.max_in_flight = Some(1);
        registry.register(other_register)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );

        let result = command_result("cmd-1", Value::string("ok".into()));
        let resolved = registry.resolve(source_command_resolve(&s, &result))?;
        ensure!(resolved == result, "unexpected result: {resolved:?}");
        let mut retry = source_command_register(&s, &second);
        retry.max_in_flight = Some(1);
        registry.register(retry)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );
        Ok(())
    }

    #[test]
    fn source_command_rate_limit_is_separate_from_in_flight_limit() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let first = outbound_command("cmd-1", message_payload("send"));
        let second = outbound_command("cmd-2", message_payload("send"));

        let mut first_register = source_command_register(&s, &first);
        first_register.max_in_flight = Some(1024);
        first_register.rate_limit_window_ms = 1_000;
        first_register.rate_limit_max_commands = 1;
        registry.register(first_register)?;

        let mut second_register = source_command_register(&s, &second);
        second_register.max_in_flight = Some(1024);
        second_register.rate_limit_window_ms = 1_000;
        second_register.rate_limit_max_commands = 1;
        ensure!(
            registry.register(second_register) == Err(SourceCommandError::RateLimited),
            "rate limit should be enforced"
        );

        let mut after_window = source_command_register(&s, &second);
        after_window.now_millis = 1_200;
        after_window.deadline_ms = Some(2_000);
        after_window.max_in_flight = Some(1024);
        after_window.rate_limit_window_ms = 1_000;
        after_window.rate_limit_max_commands = 1;
        registry.register(after_window)?;
        ensure!(
            registry.len() == 2,
            "unexpected registry length: {}",
            registry.len()
        );
        Ok(())
    }

    #[test]
    fn source_command_deadline_and_drain_retain_ids() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let elapsed = outbound_command("elapsed", message_payload("send"));
        let drained = outbound_command("drained", message_payload("send"));

        let mut elapsed_register = source_command_register(&s, &elapsed);
        elapsed_register.deadline_ms = Some(500);
        elapsed_register.idempotency_window_ms = 1_000;
        registry.register(elapsed_register)?;
        ensure!(
            registry.expire(600) == vec!["elapsed".to_string()],
            "elapsed command should expire"
        );
        let mut elapsed_retry = source_command_register(&s, &elapsed);
        elapsed_retry.now_millis = 700;
        elapsed_retry.deadline_ms = Some(2_000);
        elapsed_retry.idempotency_window_ms = 1_000;
        ensure!(
            registry.register(elapsed_retry) == Err(SourceCommandError::DuplicateCommandId),
            "elapsed command should remain retained"
        );

        let mut drained_register = source_command_register(&s, &drained);
        drained_register.now_millis = 1_700;
        drained_register.deadline_ms = Some(3_000);
        drained_register.idempotency_window_ms = 1_000;
        registry.register(drained_register)?;
        let context = s.context().context("missing ready context")?;
        ensure!(
            registry.drain_for_session(context, 1_800) == vec!["drained".to_string()],
            "drained command should be retained"
        );
        let mut drained_retry = source_command_register(&s, &drained);
        drained_retry.now_millis = 1_900;
        drained_retry.deadline_ms = Some(3_000);
        drained_retry.idempotency_window_ms = 1_000;
        ensure!(
            registry.register(drained_retry) == Err(SourceCommandError::DuplicateCommandId),
            "drained command should remain retained"
        );
        Ok(())
    }

    #[test]
    fn source_command_expire_removes_only_elapsed_deadlines() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let elapsed = outbound_command("elapsed", message_payload("send"));
        let future = outbound_command("future", message_payload("send"));

        let mut elapsed_register = source_command_register(&s, &elapsed);
        elapsed_register.deadline_ms = Some(500);
        registry.register(elapsed_register)?;
        let mut future_register = source_command_register(&s, &future);
        future_register.deadline_ms = Some(2_000);
        registry.register(future_register)?;

        ensure!(
            registry.expire(499).is_empty(),
            "nothing should expire before deadline"
        );
        ensure!(
            registry.expire(500) == vec!["elapsed".to_string()],
            "elapsed command should expire"
        );
        ensure!(
            registry.len() == 1,
            "unexpected registry length: {}",
            registry.len()
        );

        let elapsed_result = command_result("elapsed", Value::null());
        ensure!(
            registry.resolve(source_command_resolve(&s, &elapsed_result))
                == Err(SourceCommandError::CommandNotFound),
            "expired command should not resolve"
        );
        let future_result = command_result("future", Value::string("ok".into()));
        let resolved = registry.resolve(source_command_resolve(&s, &future_result))?;
        ensure!(resolved == future_result, "unexpected result: {resolved:?}");
        ensure!(registry.is_empty(), "registry should be empty");
        Ok(())
    }

    #[test]
    fn source_command_rejects_before_ready_or_wrong_role() -> anyhow::Result<()> {
        let command = outbound_command("cmd-1", message_payload("send"));
        let mut registry = SourceCommandRegistry::new();
        let mut awaiting = EndpointSession::new();
        awaiting.on_hello(&hello(), |_| ctx())?;
        ensure!(
            registry.register(source_command_register(&awaiting, &command))
                == Err(SourceCommandError::Session(SessionReject::NotReady)),
            "not-ready source session should be rejected"
        );

        let provider = complete_provider_handshake()?;
        ensure!(
            registry.register(source_command_register(&provider, &command))
                == Err(SourceCommandError::NotSource),
            "provider session should not register source command"
        );
        Ok(())
    }

    #[test]
    fn source_command_result_checks_generation_and_session() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        registry.register(source_command_register(&s, &command))?;
        let result = command_result("cmd-1", Value::string("ok".into()));

        let mut wrong_generation = source_command_resolve(&s, &result);
        wrong_generation.current_installation_config_version = 2;
        ensure!(
            registry.resolve(wrong_generation)
                == Err(SourceCommandError::InstallationConfigVersionMismatch),
            "installation config generation mismatch should be rejected"
        );

        let mut other = ctx();
        other.projection_id = "other-source".into();
        let mut other_session = EndpointSession::new();
        let mut hello = hello();
        hello.projection_id = "other-source".into();
        let sent = other_session.on_hello(&hello, |_| other)?;
        other_session.on_authenticated_ready(&RoleReady {
            accepted_context: sent,
        })?;
        ensure!(
            registry.resolve(source_command_resolve(&other_session, &result))
                == Err(SourceCommandError::SessionMismatch),
            "session mismatch should be rejected"
        );
        Ok(())
    }

    #[test]
    fn source_command_checks_deadline_and_result_size() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let expired = outbound_command("expired", message_payload("send"));
        let mut expired_register = source_command_register(&s, &expired);
        expired_register.deadline_ms = Some(100);
        ensure!(
            registry.register(expired_register) == Err(SourceCommandError::DeadlineExceeded),
            "expired command should be rejected"
        );

        let command = outbound_command("large", message_payload("send"));
        let mut small_limit = source_command_register(&s, &command);
        small_limit.max_inline_result_bytes = Some(4);
        registry.register(small_limit)?;
        let result = command_result("large", Value::string("too large".into()));
        ensure!(
            registry.resolve(source_command_resolve(&s, &result))
                == Err(SourceCommandError::ResultTooLarge),
            "large result should be rejected"
        );
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(source_command_resolve(&s, &result))
                == Err(SourceCommandError::CommandNotFound),
            "oversized result should close command"
        );

        let command = outbound_command("large-error", message_payload("send"));
        let mut small_limit = source_command_register(&s, &command);
        small_limit.max_inline_result_bytes = Some(4);
        registry.register(small_limit)?;
        let result = command_error_result("large-error", "remote", "too large");
        ensure!(
            registry.resolve(source_command_resolve(&s, &result))
                == Err(SourceCommandError::ResultTooLarge),
            "large error result should be rejected"
        );
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(source_command_resolve(&s, &result))
                == Err(SourceCommandError::CommandNotFound),
            "oversized error result should close command"
        );
        ensure!(
            registry.register(source_command_register(&s, &command))
                == Err(SourceCommandError::DuplicateCommandId),
            "oversized error result should retain command id"
        );

        let command = outbound_command("timeout", message_payload("send"));
        registry.register(source_command_register(&s, &command))?;
        let result = command_result("timeout", Value::null());
        let mut late = source_command_resolve(&s, &result);
        late.now_millis = 2_000;
        ensure!(
            registry.resolve(late) == Err(SourceCommandError::DeadlineExceeded),
            "late result should be rejected"
        );
        Ok(())
    }

    #[test]
    fn source_command_checks_command_and_result_schema() -> anyhow::Result<()> {
        let s = complete_handshake()?;
        let mut registry = SourceCommandRegistry::new();
        let schema = message_schema();

        let bad_command = outbound_command("bad-command", Value::string("raw".into()));
        let mut register = source_command_register(&s, &bad_command);
        register.command_schema = Some(&schema);
        ensure!(
            matches!(
                registry.register(register),
                Err(SourceCommandError::Schema(_))
            ),
            "bad command should fail schema validation"
        );
        ensure!(registry.is_empty(), "registry should be empty");

        let command = outbound_command("bad-result", message_payload("send"));
        let mut register = source_command_register(&s, &command);
        register.command_schema = Some(&schema);
        register.command_result_schema = Some(&schema);
        registry.register(register)?;

        let result = command_result("bad-result", Value::string("raw".into()));
        ensure!(
            matches!(
                registry.resolve(source_command_resolve(&s, &result)),
                Err(SourceCommandError::Schema(_))
            ),
            "bad command result should fail schema validation"
        );
        ensure!(registry.is_empty(), "registry should be empty");
        ensure!(
            registry.resolve(source_command_resolve(&s, &result))
                == Err(SourceCommandError::CommandNotFound),
            "schema failure should close command"
        );
        Ok(())
    }

    #[tokio::test]
    async fn source_atomic_accept_dedup_and_taint() -> anyhow::Result<()> {
        let projection = source_projection(Some(message_schema()))?;
        let (state, store, record) = memory_source_with(projection.clone()).await?;
        let session = complete_handshake_with_record(&record)?;
        let policy = PolicySnapshot::empty();
        let frame = event("evt-1", message_payload("one"));
        let accepted = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            frame.clone(),
        )
        .await?;
        ensure!(accepted.status == AckStatus::Accepted);
        let repeated = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            frame.clone(),
        )
        .await?;
        ensure!(repeated.status == AckStatus::Duplicate);
        let conflict = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            event("evt-1", message_payload("changed")),
        )
        .await?;
        ensure!(conflict == SourceIngestError::EventIdConflict);
        let sink = state.read_tainted(&source_event_sink()?).await?;
        let sink_value = sink.value.clone().context("sink missing")?;
        ensure!(sink_value.as_list().is_some_and(|items| items.len() == 1));
        ensure!(sink.taint.sources().iter().any(|source| matches!(source,
            TaintSource::Inbound { source, .. } if source.as_str() == "source/inst-1/source"
        )));
        let installed = store
            .load_installation("inst-1")
            .await?
            .context("installed Source")?;
        ensure!(matches!(
            store.compare_retire("inst-1", installed.revision()).await?,
            ExternalInstallationMutation::Applied(None)
        ));
        let stale = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            frame,
        )
        .await?;
        ensure!(stale == SourceIngestError::ScopeInactive);
        Ok(())
    }

    #[tokio::test]
    async fn source_retention_capacity_is_a_typed_rejection_and_preserves_duplicates()
    -> anyhow::Result<()> {
        let projection = source_projection(None)?;
        let (state, store, record) = memory_source_with_options(
            projection.clone(),
            xolotl_state::InMemoryOptions {
                source_retention_limit: std::num::NonZeroUsize::MIN,
                ..xolotl_state::InMemoryOptions::default()
            },
        )
        .await?;
        let session = complete_handshake_with_record(&record)?;
        let policy = PolicySnapshot::empty();
        let first = event("retained", message_payload("one"));
        let accepted = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            first.clone(),
        )
        .await?;
        ensure!(accepted.status == AckStatus::Accepted);
        let before = state.read_tainted(&source_event_sink()?).await?;
        let rejected = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            event("new", message_payload("two")),
        )
        .await?;
        ensure!(rejected == SourceIngestError::RetentionCapacityExceeded);
        let repeated = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            first,
        )
        .await?;
        ensure!(repeated.status == AckStatus::Duplicate);
        ensure!(state.read_tainted(&source_event_sink()?).await? == before);
        Ok(())
    }

    #[tokio::test]
    async fn source_non_sequence_sink_is_typed_rejection_and_retryable() -> anyhow::Result<()> {
        let (state, store, record) = memory_source().await?;
        let session = complete_handshake_with_record(&record)?;
        let projection = source_projection(None)?;
        let policy = PolicySnapshot::empty();
        let sink = source_event_sink()?;
        let stream_epoch = open_test_stream(store.as_ref(), &session, "stream").await?;
        state.write_set(&sink, Value::integer(7)).await?;
        let frame = sequenced_event(
            "stream",
            stream_epoch,
            1,
            "non-sequence",
            message_payload("one"),
        );
        let error = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            frame.clone(),
        )
        .await?;
        ensure!(error == SourceIngestError::SinkTypeMismatch);
        ensure!(state.read(&sink).await? == Some(Value::integer(7)));

        state.write_set(&sink, Value::list(Vec::new())).await?;
        let accepted = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            frame,
        )
        .await?;
        ensure!(accepted.status == AckStatus::Accepted);
        ensure!(
            state
                .read(&sink)
                .await?
                .and_then(|value| value.as_list().map(|items| items.len()))
                == Some(1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn source_stream_control_fences_retired_epochs_and_recovers_open_retry()
    -> anyhow::Result<()> {
        let (state, store, record) = memory_source().await?;
        let session = complete_handshake_with_record(&record)?;
        let context = session.context().context("ready Source context")?;
        let projection = source_projection(None)?;
        let policy = PolicySnapshot::empty();
        let inspect = SourceStreamRequest {
            request_id: "inspect-1".into(),
            stream_id: "records".into(),
            operation: SourceStreamOperation::Inspect,
        };
        let SourceStreamOutcome::Inspected(initial) =
            operate_source_stream(store.as_ref(), context, inspect.clone())
                .await
                .outcome
        else {
            bail!("initial stream inspection failed");
        };
        ensure!(initial.revision == 0 && initial.active.is_none());

        let open = SourceStreamRequest {
            request_id: "open-1".into(),
            stream_id: "records".into(),
            operation: SourceStreamOperation::Open {
                expected_revision: initial.revision,
            },
        };
        let first = operate_source_stream(store.as_ref(), context, open.clone()).await;
        let SourceStreamOutcome::Opened(opened) = first.outcome else {
            bail!("stream open failed: {:?}", first.outcome);
        };
        let first_epoch = opened
            .active
            .as_ref()
            .context("opened stream is inactive")?
            .stream_epoch;
        ensure!(first_epoch != 0 && opened.revision > initial.revision);
        let retry = operate_source_stream(store.as_ref(), context, open.clone()).await;
        ensure!(retry.outcome == SourceStreamOutcome::Opened(opened.clone()));

        let accepted = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("records", first_epoch, 1, "same-id", message_payload("old")),
        )
        .await?;
        ensure!(accepted.status == AckStatus::Accepted);
        ensure!(accepted.stream_epoch == Some(first_epoch));
        let SourceStreamOutcome::Inspected(position) =
            operate_source_stream(store.as_ref(), context, inspect.clone())
                .await
                .outcome
        else {
            bail!("stream position inspection failed");
        };
        ensure!(
            position
                .active
                .as_ref()
                .is_some_and(|state| state.last_seq == 1)
        );

        let retired = operate_source_stream(
            store.as_ref(),
            context,
            SourceStreamRequest {
                request_id: "retire-1".into(),
                stream_id: "records".into(),
                operation: SourceStreamOperation::Retire {
                    stream_epoch: first_epoch,
                },
            },
        )
        .await;
        let SourceStreamOutcome::Retired { revision } = retired.outcome else {
            bail!("stream retirement failed: {:?}", retired.outcome);
        };
        let old_open_retry = operate_source_stream(store.as_ref(), context, open).await;
        ensure!(matches!(
            old_open_retry.outcome,
            SourceStreamOutcome::Rejected(SourceStreamRejected {
                code: SourceStreamRejectCode::RevisionConflict,
                current_revision: Some(current),
                ..
            }) if current == revision
        ));
        let rejected = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event(
                "records",
                first_epoch,
                2,
                "old-after-retire",
                message_payload("old"),
            ),
        )
        .await?;
        ensure!(rejected == SourceIngestError::StreamInactive);

        let reopened = operate_source_stream(
            store.as_ref(),
            context,
            SourceStreamRequest {
                request_id: "open-2".into(),
                stream_id: "records".into(),
                operation: SourceStreamOperation::Open {
                    expected_revision: revision,
                },
            },
        )
        .await;
        let SourceStreamOutcome::Opened(reopened) = reopened.outcome else {
            bail!("same-name reopen failed: {:?}", reopened.outcome);
        };
        let new_epoch = reopened
            .active
            .context("reopened stream is inactive")?
            .stream_epoch;
        ensure!(new_epoch > first_epoch);
        let stale = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("records", first_epoch, 1, "stale", message_payload("old")),
        )
        .await?;
        ensure!(
            matches!(stale, SourceIngestError::StreamEpochMismatch { active_epoch } if active_epoch == new_epoch)
        );
        let new_ack = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("records", new_epoch, 1, "same-id", message_payload("new")),
        )
        .await?;
        ensure!(new_ack.status == AckStatus::Accepted);
        ensure!(new_ack.stream_epoch == Some(new_epoch));
        ensure!(
            state
                .read(&source_event_sink()?)
                .await?
                .and_then(|value| value.as_list().map(|items| items.len()))
                == Some(2)
        );
        Ok(())
    }

    #[tokio::test]
    async fn source_payload_limit_matches_backend_encoding_before_commit() -> anyhow::Result<()> {
        let (state, store, record) = memory_source().await?;
        let mut session = complete_handshake_with_record(&record)?;
        let mut projection = source_projection(None)?;
        let policy = PolicySnapshot::empty();
        let sink = source_event_sink()?;

        for (index, payload) in [Value::null(), Value::string("quoted \"text\"\n".into())]
            .into_iter()
            .enumerate()
        {
            let id = format!("measured-{index}");
            let encoded_bytes = xolotl_state::host::encoded_size(
                &xolotl_types::tagged_value::serializable(&payload),
            )?;
            ensure!(encoded_bytes > 1);
            ensure!(
                crate::value_inspection::inline_bytes(&payload, encoded_bytes - 1).is_some(),
                "this payload must have passed the old logical-footprint check"
            );
            let before = state
                .read(&sink)
                .await?
                .map_or(0, |value| value.as_list().map_or(0, |items| items.len()));
            projection
                .emits
                .as_mut()
                .context("source emits missing")?
                .max_inline_payload_bytes = encoded_bytes - 1;
            let error = expect_source_ingest_error(
                source_req(store.as_ref(), &session, &projection, &policy),
                event(&id, payload.clone()),
            )
            .await?;
            ensure!(error == SourceIngestError::PayloadTooLarge);
            let after_rejection = state
                .read(&sink)
                .await?
                .map_or(0, |value| value.as_list().map_or(0, |items| items.len()));
            ensure!(
                after_rejection == before,
                "rejection must precede the commit"
            );

            projection
                .emits
                .as_mut()
                .context("source emits missing")?
                .max_inline_payload_bytes = encoded_bytes;
            let record = replace_source_projection(store.as_ref(), projection.clone()).await?;
            session = complete_handshake_with_record(&record)?;
            let accepted = ingest_source_event(
                source_req(store.as_ref(), &session, &projection, &policy),
                event(&id, payload),
            )
            .await?;
            ensure!(accepted.status == AckStatus::Accepted);
        }
        Ok(())
    }

    #[tokio::test]
    async fn source_atomic_sequence_capacity_rate_and_drop_oldest() -> anyhow::Result<()> {
        let mut projection = source_projection(None)?;
        let emits = projection.emits.as_mut().context("emits missing")?;
        emits.capacity = source_capacity(1, OverflowPolicy::DisconnectBridge);
        emits.rate_limit = Some(SourceRateLimit {
            window_ms: 1000,
            max_events: 2,
        });
        let (state, store, record) = memory_source_with(projection.clone()).await?;
        let mut session = complete_handshake_with_record(&record)?;
        let policy = PolicySnapshot::empty();
        let mut stream_epoch = open_test_stream(store.as_ref(), &session, "stream").await?;
        let gap = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("stream", stream_epoch, 2, "gap", message_payload("gap")),
        )
        .await?;
        ensure!(matches!(
            gap,
            SourceIngestError::SequenceGap {
                expected: 1,
                seq: 2
            }
        ));
        let first = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("stream", stream_epoch, 1, "one", message_payload("one")),
        )
        .await?;
        ensure!(first.status == AckStatus::Accepted);
        let full = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("stream", stream_epoch, 2, "two", message_payload("two")),
        )
        .await?;
        ensure!(full == SourceIngestError::CapacityExceeded);
        projection.emits.as_mut().context("emits missing")?.capacity =
            source_capacity(1, OverflowPolicy::DropOldest);
        projection
            .emits
            .as_mut()
            .context("emits missing")?
            .rate_limit
            .as_mut()
            .context("source rate limit")?
            .max_events = 1;
        let record = replace_source_projection(store.as_ref(), projection.clone()).await?;
        session = complete_handshake_with_record(&record)?;
        stream_epoch = open_test_stream(store.as_ref(), &session, "stream").await?;
        let second = ingest_source_event(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("stream", stream_epoch, 1, "two", message_payload("two")),
        )
        .await?;
        ensure!(second.status == AckStatus::Accepted);
        let limited = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            sequenced_event("stream", stream_epoch, 2, "three", message_payload("three")),
        )
        .await?;
        ensure!(limited == SourceIngestError::RateLimited);
        let sink = state
            .read(&source_event_sink()?)
            .await?
            .context("sink missing")?;
        let items = sink.as_list().context("sink not a list")?;
        ensure!(items.len() == 1 && items.first() == Some(&message_payload("two")));
        Ok(())
    }

    struct InjectUnknown {
        inner: Arc<InMemoryBackend>,
        after_commit: bool,
        claim: std::sync::Mutex<Option<SourceClaimId>>,
    }

    impl SourceEventCommit for InjectUnknown {
        fn commit<'a>(
            &'a self,
            request: SourceCommit<'a>,
        ) -> SourceFuture<'a, SourceCommitOutcome> {
            Box::pin(async move {
                *self.claim.lock().map_err(|_error| {
                    SourceStoreError::Aborted("test claim lock poisoned".into())
                })? = Some(request.claim.claim_id);
                if self.after_commit {
                    let outcome = self.inner.commit(request).await?;
                    if outcome != SourceCommitOutcome::Accepted {
                        return Ok(outcome);
                    }
                }
                Err(SourceStoreError::Indeterminate(
                    "injected lost response".into(),
                ))
            })
        }
    }

    impl SourceStreamLifecycle for InjectUnknown {
        fn inspect_stream<'a>(
            &'a self,
            stream: SourceStreamScope<'a>,
        ) -> SourceFuture<'a, Option<xolotl_source::SourceStreamSnapshot>> {
            self.inner.inspect_stream(stream)
        }

        fn open_stream<'a>(
            &'a self,
            request: SourceStreamOpen<'a>,
        ) -> SourceFuture<'a, SourceStreamOpenOutcome> {
            self.inner.open_stream(request)
        }

        fn retire_stream<'a>(
            &'a self,
            request: SourceStreamRetire<'a>,
        ) -> SourceFuture<'a, SourceStreamRetireOutcome> {
            self.inner.retire_stream(request)
        }
    }

    #[tokio::test]
    async fn source_unknown_commit_uses_private_evidence_without_replay() -> anyhow::Result<()> {
        for after_commit in [false, true] {
            let (state, store, record) = memory_source().await?;
            let session = complete_handshake_with_record(&record)?;
            let scope_epoch = record.scope_epoch("source").context("Source scope epoch")?;
            let injected = InjectUnknown {
                inner: store.clone(),
                after_commit,
                claim: std::sync::Mutex::new(None),
            };
            let projection = source_projection(None)?;
            let policy = PolicySnapshot::empty();
            let frame = event("uncertain", message_payload("one"));
            let error = expect_source_ingest_error(
                source_req(&injected, &session, &projection, &policy),
                frame.clone(),
            )
            .await?;
            ensure!(error == SourceIngestError::CommitOutcomeUnknown);
            let claim_id = injected
                .claim
                .lock()
                .map_err(|_error| anyhow!("claim lock poisoned"))?
                .context("claim not recorded")?;
            let evidence = store
                .inspect(SourceEvidenceInspection {
                    claim: SourceClaim {
                        installation_id: "inst-1",
                        projection_id: "source",
                        event_id: "uncertain",
                        claim_id,
                        scope_epoch,
                        stream_epoch: None,
                    },
                })
                .await?;
            ensure!(matches!(evidence, SourceClaimEvidence::Committed(_)) == after_commit);
            let retry = ingest_source_event(
                source_req(store.as_ref(), &session, &projection, &policy),
                frame,
            )
            .await?;
            ensure!(
                retry.status
                    == if after_commit {
                        AckStatus::Duplicate
                    } else {
                        AckStatus::Accepted
                    }
            );
            let sink = state
                .read(&source_event_sink()?)
                .await?
                .context("sink missing")?;
            ensure!(sink.as_list().is_some_and(|items| items.len() == 1));
        }
        Ok(())
    }

    #[tokio::test]
    async fn source_invalid_frame_and_policy_never_call_store() -> anyhow::Result<()> {
        let (state, store, record) = memory_source().await?;
        let mut session = EndpointSession::new();
        let scope_epoch = record.scope_epoch("source").context("Source scope epoch")?;
        session.on_hello(&hello(), |_| SessionContext {
            installation_epoch: record.installation_epoch,
            scope_epoch,
            ..ctx()
        })?;
        let projection = source_projection(Some(message_schema()))?;
        let policy = PolicySnapshot::empty();
        let unready = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            event("unready", message_payload("one")),
        )
        .await?;
        ensure!(matches!(
            unready,
            SourceIngestError::Session(SessionReject::NotReady)
        ));
        let session = complete_handshake_with_record(&record)?;
        let schema = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            event("bad-schema", Value::float(FloatBits(1.0))),
        )
        .await?;
        ensure!(matches!(schema, SourceIngestError::Schema(_)));
        let forbidden = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            event(
                "forbidden",
                Value::map(BTreeMap::from([(
                    "token".into(),
                    Value::string("secret".into()),
                )])),
            ),
        )
        .await?;
        ensure!(matches!(
            forbidden,
            SourceIngestError::ForbiddenPayloadField { .. }
        ));
        let bad_id = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &policy),
            event("bad/id", message_payload("one")),
        )
        .await?;
        ensure!(bad_id == SourceIngestError::InvalidEventId);
        let deny = PolicySnapshot::new(vec![Arc::new(DenyAll)]);
        let denied = expect_source_ingest_error(
            source_req(store.as_ref(), &session, &projection, &deny),
            event("denied", message_payload("one")),
        )
        .await?;
        ensure!(denied == SourceIngestError::Policy("blocked".into()));
        ensure!(state.read(&source_event_sink()?).await?.is_none());
        Ok(())
    }
}
