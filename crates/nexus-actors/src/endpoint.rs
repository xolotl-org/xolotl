//! Endpoint session supervisor for external Provider/Source sessions.
//!
//! The state machine gates the 3-stage handshake and enforces the fail-closed
//! frame discipline plus the secure-envelope credential layer.
//!
//! An external Source or Provider connects and runs:
//! ```text
//!   stage 1: role client -> RoleSessionClientHello   (identity + cached generations)
//!   stage 2: daemon      -> SessionContext           (authoritative generations)
//!   stage 3: role client -> RoleReady(accepted)      (confirms alignment)
//! ```
//! The daemon dispatches **no business frame** (`Invoke`, inbound event) before
//! `RoleReady`. After it, every Source frame's `ObservedGenerations`
//! must not exceed the session's, and frames bearing a revoked credential generation
//! are rejected. This module is the in-process
//! state machine + envelope crypto; the live gRPC transport binds to it.

use nexus_kernel::{CheckCtx, PolicyDecision, PolicySnapshot};
use nexus_state::{Backend, StateError};
use nexus_types::external::{
    AckStatus, CommandResult, EventAck, ExternalProjectionDef, InboundEvent, Invoke, InvokeResult,
    JsonSchema, ObservedGenerations, OutboundCommand, OverflowPolicy, Role, RoleReady,
    RoleSessionClientHello, SessionContext, SourceRateLimit,
};
use nexus_types::{IdentityRef, Path, ResourceId, TaintSet, TaintSource, Value};
use std::collections::{BTreeMap, BTreeSet};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionReject {
    /// A business frame arrived before the handshake completed.
    NotReady,
    /// A handshake frame arrived in the wrong phase.
    OutOfOrder,
    /// The external endpoint's confirmed context did not match the daemon's.
    ContextMismatch,
    /// A Source frame's observed generations are stale vs the session.
    StaleGeneration,
    /// The frame's credential generation has been revoked.
    RevokedCredential,
    /// The session is closed.
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
    #[error("source event id is empty after path normalization")]
    InvalidEventId,
    /// Stream id could not be represented as a durable path segment.
    #[error("source stream id is empty after path normalization")]
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
    /// Source stream capacity has been reached.
    #[error("source event stream capacity exceeded")]
    CapacityExceeded,
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
}

/// In-flight Provider invocation registry.
///
/// The daemon registers an `Invoke` before sending it to a Provider. A returned
/// `InvokeResult` is accepted only if it matches one registered invocation and
/// the session generations still match the ready Provider context.
#[derive(Debug, Default)]
pub struct ProviderInvocationRegistry {
    entries: BTreeMap<String, ProviderInvocationEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderInvocationEntry {
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
    ) -> Result<(), ProviderInvocationError> {
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
        self.entries.insert(
            req.invoke.invocation_id.clone(),
            ProviderInvocationEntry {
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
        Ok(())
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
            } else if let (Ok(value), Some(limit)) =
                (&req.result.outcome, entry.max_inline_result_bytes)
                && value_inline_bytes(value) > limit
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

fn value_inline_bytes(value: &Value) -> usize {
    let mut total = 0usize;
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Null | Value::Bool(_) => total = total.saturating_add(1),
            Value::Int(_) | Value::Float(_) => total = total.saturating_add(8),
            Value::Str(s) => total = total.saturating_add(s.len()),
            Value::Bytes(bytes) => total = total.saturating_add(bytes.len()),
            Value::List(items) => {
                total = total.saturating_add(items.len());
                for item in items {
                    stack.push(item);
                }
            }
            Value::Map(map) => {
                total = total.saturating_add(map.len());
                for (key, value) in map {
                    total = total.saturating_add(key.len());
                    stack.push(value);
                }
            }
            Value::Blob(blob) => {
                total = total.saturating_add(blob.hash.len()).saturating_add(16);
                if let Some(mime) = &blob.mime {
                    total = total.saturating_add(mime.len());
                }
            }
            Value::Tensor(tensor) => {
                total = total
                    .saturating_add(tensor.blob.hash.len())
                    .saturating_add(tensor.shape.len().saturating_mul(8))
                    .saturating_add(24);
                if let Some(mime) = &tensor.blob.mime {
                    total = total.saturating_add(mime.len());
                }
            }
            Value::Frame(frame) => {
                total = total
                    .saturating_add(frame.blob.hash.len())
                    .saturating_add(32);
                if let Some(mime) = &frame.blob.mime {
                    total = total.saturating_add(mime.len());
                }
            }
            Value::StreamEnd(marker) => match marker {
                nexus_types::StreamMarker::Done => total = total.saturating_add(1),
                nexus_types::StreamMarker::Error { message } => {
                    total = total.saturating_add(message.len())
                }
            },
        }
    }
    total
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
}

/// In-flight Source outbound command registry.
///
/// The daemon registers an [`OutboundCommand`] before sending it to a Source.
/// A returned [`CommandResult`] is accepted only if it matches a registered
/// command and the session generations still match the ready Source context.
#[derive(Debug, Default)]
pub struct SourceCommandRegistry {
    entries: BTreeMap<String, SourceCommandEntry>,
    retained_ids: BTreeMap<String, i64>,
    rate_windows: BTreeMap<SourceCommandRateKey, SourceCommandRateWindow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceCommandEntry {
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

impl SourceCommandRegistry {
    /// Create an empty command registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered in-flight commands.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no command is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove one in-flight command without admitting a result.
    pub fn remove(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
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
        self.entries
            .extract_if(.., |_, entry| pred(entry))
            .map(|(id, entry)| {
                retain_source_command_id(
                    retained_ids,
                    &id,
                    now_millis,
                    entry.idempotency_window_ms,
                );
                id
            })
            .collect()
    }

    /// Register one daemon-to-Source command before it is sent.
    pub fn register(&mut self, req: SourceCommandRegister<'_>) -> Result<(), SourceCommandError> {
        self.prune_retained(req.now_millis);
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
        if self.retained_ids.contains_key(&req.command.id) {
            return Err(SourceCommandError::DuplicateCommandId);
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
        self.admit_rate(
            &SourceCommandRateKey {
                installation_id: ctx.installation_id.clone(),
                projection_id: ctx.projection_id.clone(),
            },
            req.now_millis,
            req.rate_limit_window_ms,
            req.rate_limit_max_commands,
        )?;
        self.entries.insert(
            req.command.id.clone(),
            SourceCommandEntry {
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
        Ok(())
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
            } else if let (Ok(value), Some(limit)) =
                (&req.result.outcome, entry.max_inline_result_bytes)
                && value_inline_bytes(value) > limit
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
        retain_source_command_id(
            &mut self.retained_ids,
            id,
            now_millis,
            entry.idempotency_window_ms,
        );
        true
    }

    fn prune_retained(&mut self, now_millis: i64) {
        self.retained_ids
            .retain(|_, retained_until| *retained_until > now_millis);
        self.rate_windows
            .retain(|_, window| window.retained_until_ms > now_millis);
    }

    fn admit_rate(
        &mut self,
        key: &SourceCommandRateKey,
        now_millis: i64,
        window_ms: u64,
        max_commands: usize,
    ) -> Result<(), SourceCommandError> {
        if window_ms == 0 || max_commands == 0 {
            return Err(SourceCommandError::RateLimited);
        }
        let window_ms = i64::try_from(window_ms).unwrap_or(i64::MAX);
        let retained_until_ms = now_millis.saturating_add(window_ms);
        let window = self
            .rate_windows
            .entry(key.clone())
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
    id: &str,
    now_millis: i64,
    window_ms: u64,
) {
    if window_ms == 0 {
        return;
    }
    let window_ms = i64::try_from(window_ms).unwrap_or(i64::MAX);
    retained_ids.insert(id.to_string(), now_millis.saturating_add(window_ms));
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
    /// State backend used for dedup and event append.
    pub state: Backend,
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
    /// Event id dedupe retention window in milliseconds.
    pub dedupe_window_ms: u64,
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
    prune_source_dedup_window(
        &req.state,
        req.installation_id,
        &req.projection.id,
        req.now_millis,
        req.dedupe_window_ms,
    )
    .await?;
    let source_key = source_projection_key(req.installation_id, &req.projection.id);
    let dedup = source_event_dedup_path(req.installation_id, &req.projection.id, &event.id)?;

    let dedup = match reserve_source_dedup(&req.state, dedup, req.now_millis).await? {
        SourceDedupReservation::Reserved(reservation) => reservation,
        SourceDedupReservation::Duplicate => {
            return Ok(EventAck {
                id: event.id,
                status: AckStatus::Duplicate,
                reject_reason: None,
            });
        }
    };

    let sequence = match reserve_source_sequence(&req, &event).await {
        Ok(sequence) => sequence,
        Err(e) => {
            rollback_source_dedup(&req.state, dedup).await;
            return Err(e);
        }
    };

    if let Err(e) = check_source_policy(&req, &event).await {
        rollback_source_dedup(&req.state, dedup).await;
        rollback_source_sequence(&req.state, sequence).await;
        return Err(e);
    }

    let rate = match reserve_source_event_rate(&req, emits.rate_limit.as_ref()).await {
        Ok(rate) => rate,
        Err(e) => {
            rollback_source_dedup(&req.state, dedup).await;
            rollback_source_sequence(&req.state, sequence).await;
            return Err(e);
        }
    };

    let taint = TaintSet::of(TaintSource::Inbound {
        source: format!("source/{source_key}").into(),
        channel: emits.sink.to_string().into(),
    });
    if let Err(e) = append_source_event(&req, emits, &event, taint).await {
        rollback_source_dedup(&req.state, dedup).await;
        rollback_source_sequence(&req.state, sequence).await;
        rollback_source_rate_limit(&req.state, rate).await;
        return Err(e);
    }
    commit_source_dedup(&req.state, dedup, req.now_millis).await?;

    Ok(EventAck {
        id: event.id,
        status: AckStatus::Accepted,
        reject_reason: None,
    })
}

#[derive(Clone)]
struct SourceDedupEntry {
    path: Path,
    pending: Value,
}

enum SourceDedupReservation {
    Reserved(SourceDedupEntry),
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceDedupStatus {
    Pending,
    Accepted,
}

async fn reserve_source_dedup(
    state: &Backend,
    path: Path,
    now_millis: i64,
) -> Result<SourceDedupReservation, SourceIngestError> {
    let pending = source_dedup_record(SourceDedupStatus::Pending, now_millis);
    match state.write_cas(&path, None, pending.clone()).await {
        Ok(()) => Ok(SourceDedupReservation::Reserved(SourceDedupEntry {
            path,
            pending,
        })),
        Err(StateError::CasFailed { actual, .. }) => {
            match source_dedup_status(actual.as_deref())? {
                Some(SourceDedupStatus::Accepted) => Ok(SourceDedupReservation::Duplicate),
                Some(SourceDedupStatus::Pending) => Err(SourceIngestError::Backpressured),
                None => Err(SourceIngestError::State(
                    "source dedup reservation changed unexpectedly".into(),
                )),
            }
        }
        Err(e) => Err(SourceIngestError::State(e.to_string())),
    }
}

async fn commit_source_dedup(
    state: &Backend,
    entry: SourceDedupEntry,
    now_millis: i64,
) -> Result<(), SourceIngestError> {
    state
        .write_cas(
            &entry.path,
            Some(entry.pending),
            source_dedup_record(SourceDedupStatus::Accepted, now_millis),
        )
        .await
        .map_err(|e| SourceIngestError::State(e.to_string()))
}

async fn rollback_source_dedup(state: &Backend, entry: SourceDedupEntry) {
    let current = state.read(&entry.path).await.ok().flatten();
    if current == Some(entry.pending) {
        let _ = state.write_delete(&entry.path).await;
    }
}

fn source_dedup_record(status: SourceDedupStatus, received_at_ms: i64) -> Value {
    let mut record = BTreeMap::new();
    let status = match status {
        SourceDedupStatus::Pending => "pending",
        SourceDedupStatus::Accepted => "accepted",
    };
    record.insert("status".into(), Value::Str(status.into()));
    record.insert("received_at_ms".into(), Value::Int(received_at_ms));
    Value::Map(record)
}

fn source_dedup_status(
    value: Option<&Value>,
) -> Result<Option<SourceDedupStatus>, SourceIngestError> {
    let Some(Value::Map(record)) = value else {
        return match value {
            None => Ok(None),
            Some(other) => Err(SourceIngestError::State(format!(
                "source dedup record expected map, found {other:?}"
            ))),
        };
    };
    match record.get("status").and_then(Value::as_str) {
        Some("pending") => Ok(Some(SourceDedupStatus::Pending)),
        Some("accepted") => Ok(Some(SourceDedupStatus::Accepted)),
        Some(other) => Err(SourceIngestError::State(format!(
            "source dedup record has invalid status {other:?}"
        ))),
        None => Err(SourceIngestError::State(
            "source dedup record missing status".into(),
        )),
    }
}

fn source_dedup_received_at(value: &Value) -> Result<i64, SourceIngestError> {
    let Value::Map(record) = value else {
        return Err(SourceIngestError::State(format!(
            "source dedup record expected map, found {value:?}"
        )));
    };
    match record.get("received_at_ms") {
        Some(Value::Int(ts)) => Ok(*ts),
        Some(other) => Err(SourceIngestError::State(format!(
            "source dedup record timestamp expected integer, found {other:?}"
        ))),
        None => Err(SourceIngestError::State(
            "source dedup record missing timestamp".into(),
        )),
    }
}

struct SourceSequenceReservation {
    path: Path,
    previous: Option<u64>,
    seq: u64,
}

async fn reserve_source_sequence(
    req: &SourceIngest<'_>,
    event: &InboundEvent,
) -> Result<Option<SourceSequenceReservation>, SourceIngestError> {
    let (Some(stream_id), Some(seq)) = (event.stream_id.as_deref(), event.seq) else {
        if event.stream_id.is_some() || event.seq.is_some() {
            return Err(SourceIngestError::InvalidSequence);
        }
        return Ok(None);
    };
    if seq > i64::MAX as u64 {
        return Err(SourceIngestError::InvalidSequence);
    }
    let path = source_stream_last_seq_path(req.installation_id, &req.projection.id, stream_id)?;
    for _ in 0..8 {
        let current = req
            .state
            .read(&path)
            .await
            .map_err(|e| SourceIngestError::State(e.to_string()))?;
        let previous = match current {
            None => None,
            Some(Value::Int(n)) if n >= 0 => Some(n as u64),
            Some(_) => {
                return Err(SourceIngestError::State(
                    "source stream sequence state is not an integer".into(),
                ));
            }
        };
        let expected = previous.map_or(1, |last| last.saturating_add(1));
        if seq < expected {
            return Err(SourceIngestError::SequenceReplay {
                last: previous.unwrap_or(0),
                seq,
            });
        }
        if seq > expected {
            return Err(SourceIngestError::SequenceGap { expected, seq });
        }
        let expected_value = previous.map(|last| Value::Int(last as i64));
        match req
            .state
            .write_cas(&path, expected_value, Value::Int(seq as i64))
            .await
        {
            Ok(()) => {
                return Ok(Some(SourceSequenceReservation {
                    path,
                    previous,
                    seq,
                }));
            }
            Err(StateError::CasFailed { .. }) => continue,
            Err(e) => return Err(SourceIngestError::State(e.to_string())),
        }
    }
    Err(SourceIngestError::State(
        "source stream sequence reservation changed too often".into(),
    ))
}

async fn rollback_source_sequence(state: &Backend, reservation: Option<SourceSequenceReservation>) {
    let Some(reservation) = reservation else {
        return;
    };
    let current = state.read(&reservation.path).await.ok().flatten();
    if current != Some(Value::Int(reservation.seq as i64)) {
        return;
    }
    match reservation.previous {
        Some(previous) => {
            let _ = state
                .write_cas(
                    &reservation.path,
                    Some(Value::Int(reservation.seq as i64)),
                    Value::Int(previous as i64),
                )
                .await;
        }
        None => {
            let _ = state.write_delete(&reservation.path).await;
        }
    }
}

struct SourceRateReservation {
    path: Path,
    previous: Option<Value>,
    value: Value,
}

const SOURCE_RATE_CAS_ATTEMPTS: usize = 16;

async fn reserve_source_event_rate(
    req: &SourceIngest<'_>,
    rate_limit: Option<&SourceRateLimit>,
) -> Result<Option<SourceRateReservation>, SourceIngestError> {
    let Some(rate_limit) = rate_limit else {
        return Ok(None);
    };
    if rate_limit.window_ms == 0 || rate_limit.max_events == 0 {
        return Err(SourceIngestError::RateLimited);
    }
    let window_ms = i64::try_from(rate_limit.window_ms).unwrap_or(i64::MAX);
    let path = source_event_rate_path(req.installation_id, &req.projection.id)?;
    for _ in 0..SOURCE_RATE_CAS_ATTEMPTS {
        let current = req
            .state
            .read(&path)
            .await
            .map_err(|e| SourceIngestError::State(e.to_string()))?;
        let mut hits = decode_source_rate_hits(current.as_ref())?;
        let cutoff = req.now_millis.saturating_sub(window_ms);
        hits.retain(|&t| t > cutoff);
        hits.sort_unstable();

        if hits.len() >= rate_limit.max_events as usize {
            let new = encode_source_rate_hits(&hits);
            if current.as_ref() == Some(&new) {
                return Err(SourceIngestError::RateLimited);
            }
            match req.state.write_cas(&path, current, new).await {
                Ok(()) => return Err(SourceIngestError::RateLimited),
                Err(StateError::CasFailed { .. }) => continue,
                Err(e) => return Err(SourceIngestError::State(e.to_string())),
            }
        }

        hits.push(req.now_millis);
        hits.sort_unstable();
        let new = encode_source_rate_hits(&hits);
        match req
            .state
            .write_cas(&path, current.clone(), new.clone())
            .await
        {
            Ok(()) => {
                return Ok(Some(SourceRateReservation {
                    path,
                    previous: current,
                    value: new,
                }));
            }
            Err(StateError::CasFailed { .. }) => continue,
            Err(e) => return Err(SourceIngestError::State(e.to_string())),
        }
    }
    Err(SourceIngestError::State(
        "source event rate state changed too often".into(),
    ))
}

async fn rollback_source_rate_limit(state: &Backend, reservation: Option<SourceRateReservation>) {
    let Some(reservation) = reservation else {
        return;
    };
    let current = state.read(&reservation.path).await.ok().flatten();
    if current.as_ref() != Some(&reservation.value) {
        return;
    }
    match reservation.previous {
        Some(previous) => {
            let _ = state
                .write_cas(&reservation.path, Some(reservation.value), previous)
                .await;
        }
        None => {
            let _ = state.write_delete(&reservation.path).await;
        }
    }
}

fn decode_source_rate_hits(value: Option<&Value>) -> Result<Vec<i64>, SourceIngestError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::List(items)) => {
            let mut hits = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Int(t) => hits.push(*t),
                    other => {
                        return Err(SourceIngestError::State(format!(
                            "source event rate state expected integer timestamp, found {other:?}"
                        )));
                    }
                }
            }
            Ok(hits)
        }
        Some(other) => Err(SourceIngestError::State(format!(
            "source event rate state expected timestamp list, found {other:?}"
        ))),
    }
}

fn encode_source_rate_hits(hits: &[i64]) -> Value {
    Value::List(hits.iter().copied().map(Value::Int).collect())
}

async fn append_source_event(
    req: &SourceIngest<'_>,
    emits: &nexus_types::external::EventSource,
    event: &InboundEvent,
    taint: TaintSet,
) -> Result<(), SourceIngestError> {
    let max_events = emits.capacity.max_events as usize;
    if max_events == 0 {
        return Err(SourceIngestError::CapacityExceeded);
    }
    match &emits.capacity.on_overflow {
        OverflowPolicy::DropOldest => {
            append_source_event_drop_oldest(req, emits, event, taint, max_events).await
        }
        OverflowPolicy::Backpressure {
            pause_threshold, ..
        } => {
            let current_len = source_sink_len(&req.state, &emits.sink).await?;
            if current_len >= *pause_threshold as usize {
                return Err(SourceIngestError::Backpressured);
            }
            append_source_event_item(&req.state, &emits.sink, event.payload.clone(), taint).await
        }
        OverflowPolicy::DisconnectBridge => {
            let current_len = source_sink_len(&req.state, &emits.sink).await?;
            if current_len >= max_events {
                return Err(SourceIngestError::CapacityExceeded);
            }
            append_source_event_item(&req.state, &emits.sink, event.payload.clone(), taint).await
        }
    }
}

async fn append_source_event_drop_oldest(
    req: &SourceIngest<'_>,
    emits: &nexus_types::external::EventSource,
    event: &InboundEvent,
    taint: TaintSet,
    max_events: usize,
) -> Result<(), SourceIngestError> {
    let current = req
        .state
        .read_tainted(&emits.sink)
        .await
        .map_err(|e| SourceIngestError::State(e.to_string()))?;
    let Some(current) = current else {
        return append_source_event_item(&req.state, &emits.sink, event.payload.clone(), taint)
            .await;
    };
    match current.value {
        Value::List(items) if items.len() < max_events => {
            append_source_event_item(&req.state, &emits.sink, event.payload.clone(), taint).await
        }
        Value::List(items) => {
            let keep = max_events.saturating_sub(1);
            let start = items.len().saturating_sub(keep);
            let mut next = items.into_iter().skip(start).collect::<Vec<_>>();
            next.push(event.payload.clone());
            let next_taint = current.taint.merged(&taint);
            req.state
                .write_set_tainted(&emits.sink, Value::List(next), next_taint)
                .await
                .map_err(|e| SourceIngestError::State(e.to_string()))
        }
        other => Err(SourceIngestError::State(format!(
            "source event sink expected list, found {other:?}"
        ))),
    }
}

async fn append_source_event_item(
    state: &Backend,
    sink: &Path,
    payload: Value,
    taint: TaintSet,
) -> Result<(), SourceIngestError> {
    state
        .write_append_tainted(sink, payload, taint)
        .await
        .map_err(|e| SourceIngestError::State(e.to_string()))
}

async fn source_sink_len(state: &Backend, sink: &Path) -> Result<usize, SourceIngestError> {
    match state
        .read(sink)
        .await
        .map_err(|e| SourceIngestError::State(e.to_string()))?
    {
        None => Ok(0),
        Some(Value::List(items)) => Ok(items.len()),
        Some(other) => Err(SourceIngestError::State(format!(
            "source event sink expected list, found {other:?}"
        ))),
    }
}

async fn prune_source_dedup_window(
    state: &Backend,
    installation_id: &str,
    projection_id: &str,
    now_millis: i64,
    window_ms: u64,
) -> Result<(), SourceIngestError> {
    let cutoff = now_millis.saturating_sub(i64::try_from(window_ms).unwrap_or(i64::MAX));
    let prefix = source_event_dedup_prefix(installation_id, projection_id)?;
    let rows = state
        .read_prefix(&prefix)
        .await
        .map_err(|e| SourceIngestError::State(e.to_string()))?;
    for (path, value) in rows {
        if source_dedup_received_at(&value)? < cutoff {
            state
                .write_delete(&path)
                .await
                .map_err(|e| SourceIngestError::State(e.to_string()))?;
        }
    }
    Ok(())
}

async fn admit_source_ingest<'a>(
    req: &'a SourceIngest<'_>,
    event: &InboundEvent,
) -> Result<&'a nexus_types::EventSource, SourceIngestError> {
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
    if emits.max_inline_payload_bytes == 0
        || value_inline_bytes(&event.payload) > emits.max_inline_payload_bytes
    {
        return Err(SourceIngestError::PayloadTooLarge);
    }
    reject_source_forbidden_payload_fields(&event.payload)?;
    validate_json_schema(emits.event_schema.as_ref(), &event.payload)
        .map_err(SourceIngestError::Schema)?;
    Ok(emits)
}

fn reject_source_forbidden_payload_fields(value: &Value) -> Result<(), SourceIngestError> {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Map(map) => {
                for (key, value) in map {
                    if is_forbidden_source_payload_field(key) {
                        return Err(SourceIngestError::ForbiddenPayloadField {
                            field: key.clone(),
                        });
                    }
                    stack.push(value);
                }
            }
            Value::List(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            _ => {}
        }
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

fn source_event_dedup_path(
    installation_id: &str,
    projection_id: &str,
    event_id: &str,
) -> Result<Path, SourceIngestError> {
    let installation_id = path_segment(installation_id);
    let projection_id = path_segment(projection_id);
    let event_id = path_segment(event_id);
    if installation_id.is_empty() || projection_id.is_empty() || event_id.is_empty() {
        return Err(SourceIngestError::InvalidEventId);
    }
    Path::parse(&format!(
        "state://kernel/source-events/{}/{}/{}",
        installation_id, projection_id, event_id
    ))
    .map_err(|e| SourceIngestError::State(format!("invalid dedup path: {e}")))
}

fn source_event_dedup_prefix(
    installation_id: &str,
    projection_id: &str,
) -> Result<Path, SourceIngestError> {
    let installation_id = path_segment(installation_id);
    let projection_id = path_segment(projection_id);
    if installation_id.is_empty() || projection_id.is_empty() {
        return Err(SourceIngestError::InvalidEventId);
    }
    Path::parse(&format!(
        "state://kernel/source-events/{}/{}",
        installation_id, projection_id
    ))
    .map_err(|e| SourceIngestError::State(format!("invalid dedup prefix: {e}")))
}

fn source_stream_last_seq_path(
    installation_id: &str,
    projection_id: &str,
    stream_id: &str,
) -> Result<Path, SourceIngestError> {
    let installation_id = path_segment(installation_id);
    let projection_id = path_segment(projection_id);
    let stream_id = path_segment(stream_id);
    if installation_id.is_empty() || projection_id.is_empty() || stream_id.is_empty() {
        return Err(SourceIngestError::InvalidStreamId);
    }
    Path::parse(&format!(
        "state://kernel/source-streams/{}/{}/{}",
        installation_id, projection_id, stream_id
    ))
    .map_err(|e| SourceIngestError::State(format!("invalid source stream path: {e}")))
}

fn source_event_rate_path(
    installation_id: &str,
    projection_id: &str,
) -> Result<Path, SourceIngestError> {
    let installation_id = path_segment(installation_id);
    let projection_id = path_segment(projection_id);
    if installation_id.is_empty() || projection_id.is_empty() {
        return Err(SourceIngestError::State(
            "source event rate path has empty segment".into(),
        ));
    }
    Path::parse(&format!(
        "state://kernel/source-rates/{}/{}",
        installation_id, projection_id
    ))
    .map_err(|e| SourceIngestError::State(format!("invalid source event rate path: {e}")))
}

fn source_projection_key(installation_id: &str, projection_id: &str) -> String {
    format!("{installation_id}/{projection_id}")
}

fn path_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Validate a Nexus value against the external schema subset.
pub fn validate_json_schema(schema: Option<&JsonSchema>, value: &Value) -> Result<(), String> {
    match schema {
        None => Ok(()),
        Some(Value::Map(schema)) => validate_schema_map(schema, value),
        Some(_) => Err("schema must be an object".into()),
    }
}

fn validate_schema_map(
    schema: &std::collections::BTreeMap<String, Value>,
    value: &Value,
) -> Result<(), String> {
    let supported: BTreeSet<&str> = ["type", "required", "properties", "items"]
        .into_iter()
        .collect();
    for key in schema.keys() {
        if !supported.contains(key.as_str()) {
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
        let keys = match required {
            Value::List(xs) => xs,
            _ => return Err("`required` must be a list".into()),
        };
        let m = match value {
            Value::Map(m) => m,
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
        let props = match properties {
            Value::Map(m) => m,
            _ => return Err("`properties` must be an object".into()),
        };
        let value_map = match value {
            Value::Map(m) => m,
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
        let items = match value {
            Value::List(items) => items,
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
        "null" => matches!(value, Value::Null),
        "boolean" | "bool" => matches!(value, Value::Bool(_)),
        "integer" | "int" => matches!(value, Value::Int(_)),
        "number" => matches!(value, Value::Int(_) | Value::Float(_)),
        "string" | "str" => matches!(value, Value::Str(_)),
        "array" | "list" => matches!(value, Value::List(_)),
        "object" | "map" => matches!(value, Value::Map(_)),
        "bytes" => matches!(value, Value::Bytes(_)),
        "blob" => matches!(value, Value::Blob(_)),
        "tensor" => matches!(value, Value::Tensor(_)),
        "frame" => matches!(value, Value::Frame(_)),
        "stream_end" => matches!(value, Value::StreamEnd(_)),
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
    /// The daemon-adjudicated context sent in stage 2.
    context: Option<SessionContext>,
    /// The credential generation currently valid; frames on an older generation
    /// are rejected after a revoke.
    valid_credential_generation: u64,
}

impl EndpointSession {
    /// A fresh session awaiting the role client's hello (stage 1).
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::AwaitingHello,
            context: None,
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

    /// Stage 1 to 2: the role client's hello is received and the daemon
    /// adjudicates the authoritative `SessionContext` to send back. The hello
    /// must match the daemon-selected identity, registry hash, and lightweight
    /// generation axes. Returns the context to transmit, or rejects
    /// out-of-order/closed/mismatch.
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
        {
            self.phase = SessionPhase::Closed;
            return Err(SessionReject::ContextMismatch);
        }
        self.valid_credential_generation = context.credential_generation;
        self.context = Some(context.clone());
        self.phase = SessionPhase::AwaitingReady;
        Ok(context)
    }

    /// Stage 3: the role client confirms alignment. The accepted context
    /// must match what the daemon sent verbatim — any divergence is fail-closed
    /// (the session moves to Closed, no business frames ever flow).
    pub fn on_ready(&mut self, ready: &RoleReady) -> Result<(), SessionReject> {
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
    use nexus_kernel::{CompiledCheck, PolicyDecision};
    use nexus_state::InMemoryBackend;
    use nexus_types::external::{
        EventSource, OverflowPolicy, Role, SourceRateLimit, StreamCapacity,
    };
    use nexus_types::{FloatBits, MethodId, Purity, TaintSource};
    use std::collections::BTreeMap;
    use std::sync::Arc;

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
            ..ctx()
        }
    }

    fn provider_ctx_with_session_id(session_id: &str) -> SessionContext {
        SessionContext {
            projection_id: "provider".into(),
            role: Role::Provider,
            session_id: session_id.into(),
            ..ctx()
        }
    }

    fn complete_handshake() -> EndpointSession {
        complete_handshake_with_session_id("session-1")
    }

    fn complete_handshake_with_session_id(session_id: &str) -> EndpointSession {
        let mut s = EndpointSession::new();
        let sent = s
            .on_hello(&hello(), |_| ctx_with_session_id(session_id))
            .unwrap();
        s.on_ready(&RoleReady {
            accepted_context: sent,
        })
        .unwrap();
        s
    }

    fn complete_provider_handshake() -> EndpointSession {
        complete_provider_handshake_with_session_id("session-1")
    }

    fn complete_provider_handshake_with_session_id(session_id: &str) -> EndpointSession {
        let mut hello = hello();
        hello.role = Role::Provider;
        hello.projection_id = "provider".into();
        let mut s = EndpointSession::new();
        let sent = s
            .on_hello(&hello, |_| provider_ctx_with_session_id(session_id))
            .unwrap();
        s.on_ready(&RoleReady {
            accepted_context: sent,
        })
        .unwrap();
        s
    }

    fn invoke(invocation_id: &str) -> Invoke {
        invoke_with_path(invocation_id, "effect://external-provider/inst-1/search")
    }

    fn invoke_with_path(invocation_id: &str, effect_path: &str) -> Invoke {
        Invoke {
            invocation_id: invocation_id.into(),
            effect_path: Path::parse(effect_path).unwrap(),
            method_id: MethodId::new(0),
            input: message_payload("query"),
            deadline_ms: Some(1_000),
            output_stream_to: None,
        }
    }

    fn invoke_result(invocation_id: &str, value: Value) -> InvokeResult {
        InvokeResult {
            invocation_id: invocation_id.into(),
            outcome: Ok(value),
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

    fn source_projection(schema: Option<Value>) -> ExternalProjectionDef {
        ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: source_event_sink(),
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
        }
    }

    fn source_event_sink() -> Path {
        nexus_types::sandboxed_source_event_sink_path("inst-1", "source").unwrap()
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
        }
    }

    fn sequenced_event(stream_id: &str, seq: u64, id: &str, payload: Value) -> InboundEvent {
        InboundEvent {
            stream_id: Some(stream_id.into()),
            seq: Some(seq),
            ..event(id, payload)
        }
    }

    fn source_req<'a>(
        state: Backend,
        session: &'a EndpointSession,
        projection: &'a ExternalProjectionDef,
        policy: &'a PolicySnapshot,
    ) -> SourceIngest<'a> {
        SourceIngest {
            state,
            session,
            installation_id: "inst-1",
            projection,
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_installation_config_version: 1,
            policy,
            acting: IdentityRef::ROOT,
            target: ResourceId::new(1),
            now_millis: 123,
            dedupe_window_ms: 60_000,
        }
    }

    fn message_payload(text: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::Str(text.into()));
        Value::Map(m)
    }

    fn message_schema() -> Value {
        let mut text_schema = BTreeMap::new();
        text_schema.insert("type".into(), Value::Str("string".into()));

        let mut props = BTreeMap::new();
        props.insert("text".into(), Value::Map(text_schema));

        let mut schema = BTreeMap::new();
        schema.insert("type".into(), Value::Str("object".into()));
        schema.insert(
            "required".into(),
            Value::List(vec![Value::Str("text".into())]),
        );
        schema.insert("properties".into(), Value::Map(props));
        Value::Map(schema)
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
    fn business_frame_before_ready_is_rejected() {
        let mut s = EndpointSession::new();
        assert_eq!(s.admit_business(), Err(SessionReject::NotReady));
        s.on_hello(&hello(), |_| ctx()).unwrap();
        // Still not Ready (awaiting RoleReady) → business frame refused.
        assert_eq!(s.admit_business(), Err(SessionReject::NotReady));
    }

    #[test]
    fn full_handshake_reaches_ready_and_admits_business() {
        let s = complete_handshake();
        assert!(s.is_ready());
        assert_eq!(s.admit_business(), Ok(()));
    }

    #[test]
    fn context_mismatch_is_fail_closed() {
        let mut s = EndpointSession::new();
        let _sent = s.on_hello(&hello(), |_| ctx()).unwrap();
        // The external endpoint confirms a DIFFERENT context → fail-closed Close.
        let mut wrong = ctx();
        wrong.credential_generation = 999;
        let r = s.on_ready(&RoleReady {
            accepted_context: wrong,
        });
        assert_eq!(r, Err(SessionReject::ContextMismatch));
        assert_eq!(s.phase(), SessionPhase::Closed);
        assert_eq!(s.admit_business(), Err(SessionReject::Closed));
    }

    #[test]
    fn hello_context_mismatch_is_fail_closed() {
        let mut s = EndpointSession::new();
        let mut hello = hello();
        hello.registry_hash = "old".into();

        let r = s.on_hello(&hello, |_| ctx());

        assert_eq!(r, Err(SessionReject::ContextMismatch));
        assert_eq!(s.phase(), SessionPhase::Closed);
        assert_eq!(s.admit_business(), Err(SessionReject::Closed));
    }

    #[test]
    fn out_of_order_ready_is_rejected() {
        let mut s = EndpointSession::new();
        // RoleReady before hello → out of order.
        assert_eq!(
            s.on_ready(&RoleReady {
                accepted_context: ctx()
            }),
            Err(SessionReject::OutOfOrder)
        );
    }

    #[test]
    fn stale_source_generation_is_rejected() {
        let s = complete_handshake();
        // Claiming a newer presentation generation than the session's → stale.
        let stale = ObservedGenerations {
            presentation_config_generation: 99,
            alias_catalog_generation: 1,
        };
        assert_eq!(
            s.admit_source_event(&stale),
            Err(SessionReject::StaleGeneration)
        );
        // Matching/older is fine.
        let ok = ObservedGenerations {
            presentation_config_generation: 2,
            alias_catalog_generation: 0,
        };
        assert_eq!(s.admit_source_event(&ok), Ok(()));
    }

    #[test]
    fn revoked_credential_generation_is_rejected() {
        let mut s = complete_handshake();
        // Current valid gen = 3. A frame on gen 3 is fine.
        assert_eq!(s.admit_credential(3), Ok(()));
        // Revoke below 5 → gen 3/4 now refused, 5+ accepted.
        s.revoke_below(5);
        assert_eq!(s.admit_credential(4), Err(SessionReject::RevokedCredential));
        assert_eq!(s.admit_credential(5), Ok(()));
    }

    #[test]
    fn provider_invocation_result_must_hit_registered_entry() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("inv-1");
        registry.register(provider_register(&s, &inv)).unwrap();
        assert_eq!(registry.len(), 1);

        let unknown = invoke_result("missing", Value::Null);
        assert_eq!(
            registry.resolve(provider_resolve(&s, &unknown)),
            Err(ProviderInvocationError::InvocationNotFound)
        );

        let result = invoke_result("inv-1", Value::Str("ok".into()));
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)).unwrap(),
            result
        );
        assert!(registry.is_empty());
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)),
            Err(ProviderInvocationError::InvocationNotFound)
        );
    }

    #[test]
    fn provider_invocation_rejects_duplicate_in_flight_id() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("inv-1");
        registry.register(provider_register(&s, &inv)).unwrap();

        let mut duplicate = provider_register(&s, &inv);
        duplicate.max_inline_result_bytes = Some(1);
        assert_eq!(
            registry.register(duplicate),
            Err(ProviderInvocationError::DuplicateInvocationId)
        );
        assert_eq!(registry.len(), 1);

        let result = invoke_result("inv-1", Value::Str("ok".into()));
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)).unwrap(),
            result
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn provider_invocation_rejects_when_in_flight_limit_is_reached() {
        let s = complete_provider_handshake();
        let other = complete_provider_handshake_with_session_id("session-2");
        let mut registry = ProviderInvocationRegistry::new();
        let first = invoke("inv-1");
        let second = invoke("inv-2");
        let other_invocation = invoke("inv-other");

        let mut first_register = provider_register(&s, &first);
        first_register.max_in_flight = Some(1);
        registry.register(first_register).unwrap();

        let mut second_register = provider_register(&s, &second);
        second_register.max_in_flight = Some(1);
        assert_eq!(
            registry.register(second_register),
            Err(ProviderInvocationError::InFlightLimitExceeded)
        );
        assert_eq!(registry.len(), 1);

        let mut other_register = provider_register(&other, &other_invocation);
        other_register.max_in_flight = Some(1);
        registry.register(other_register).unwrap();
        assert_eq!(registry.len(), 2);

        let result = invoke_result("inv-1", Value::Str("ok".into()));
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)).unwrap(),
            result
        );
        let mut retry = provider_register(&s, &second);
        retry.max_in_flight = Some(1);
        registry.register(retry).unwrap();
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn provider_invocation_rejects_when_effect_in_flight_limit_is_reached() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let first = invoke_with_path("inv-1", "effect://external-provider/inst-1/search");
        let same_effect = invoke_with_path("inv-2", "effect://external-provider/inst-1/search");
        let other_effect = invoke_with_path("inv-3", "effect://external-provider/inst-1/index");

        let mut first_register = provider_register(&s, &first);
        first_register.max_in_flight = Some(8);
        first_register.max_effect_in_flight = Some(1);
        registry.register(first_register).unwrap();

        let mut same_effect_register = provider_register(&s, &same_effect);
        same_effect_register.max_in_flight = Some(8);
        same_effect_register.max_effect_in_flight = Some(1);
        assert_eq!(
            registry.register(same_effect_register),
            Err(ProviderInvocationError::InFlightLimitExceeded)
        );

        let mut other_effect_register = provider_register(&s, &other_effect);
        other_effect_register.max_in_flight = Some(8);
        other_effect_register.max_effect_in_flight = Some(1);
        registry.register(other_effect_register).unwrap();
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn provider_invocation_rejects_when_identity_in_flight_limit_is_reached() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let first = invoke_with_path("inv-1", "effect://external-provider/inst-1/search");
        let same_identity = invoke_with_path("inv-2", "effect://external-provider/inst-1/index");
        let other_identity = invoke_with_path("inv-3", "effect://external-provider/inst-1/index");

        let mut first_register = provider_register(&s, &first);
        first_register.acting = IdentityRef::new(7);
        first_register.max_in_flight = Some(8);
        first_register.max_identity_in_flight = Some(1);
        registry.register(first_register).unwrap();

        let mut same_identity_register = provider_register(&s, &same_identity);
        same_identity_register.acting = IdentityRef::new(7);
        same_identity_register.max_in_flight = Some(8);
        same_identity_register.max_identity_in_flight = Some(1);
        assert_eq!(
            registry.register(same_identity_register),
            Err(ProviderInvocationError::InFlightLimitExceeded)
        );

        let mut other_identity_register = provider_register(&s, &other_identity);
        other_identity_register.acting = IdentityRef::new(8);
        other_identity_register.max_in_flight = Some(8);
        other_identity_register.max_identity_in_flight = Some(1);
        registry.register(other_identity_register).unwrap();
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn provider_invocation_rejects_before_ready_or_wrong_role() {
        let inv = invoke("inv-1");
        let mut registry = ProviderInvocationRegistry::new();
        let mut awaiting = EndpointSession::new();
        awaiting.on_hello(&hello(), |_| ctx()).unwrap();
        assert_eq!(
            registry.register(provider_register(&awaiting, &inv)),
            Err(ProviderInvocationError::Session(SessionReject::NotReady))
        );

        let source = complete_handshake();
        assert_eq!(
            registry.register(provider_register(&source, &inv)),
            Err(ProviderInvocationError::NotProvider)
        );
    }

    #[test]
    fn provider_invocation_result_checks_generation_and_session() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("inv-1");
        registry.register(provider_register(&s, &inv)).unwrap();
        let result = invoke_result("inv-1", Value::Str("ok".into()));

        let mut wrong_generation = provider_resolve(&s, &result);
        wrong_generation.current_binding_generation = 2;
        assert_eq!(
            registry.resolve(wrong_generation),
            Err(ProviderInvocationError::BindingGenerationMismatch)
        );

        let mut other = provider_ctx();
        other.projection_id = "other-provider".into();
        let mut other_session = EndpointSession::new();
        let mut hello = hello();
        hello.role = Role::Provider;
        hello.projection_id = "other-provider".into();
        let sent = other_session.on_hello(&hello, |_| other).unwrap();
        other_session
            .on_ready(&RoleReady {
                accepted_context: sent,
            })
            .unwrap();
        assert_eq!(
            registry.resolve(provider_resolve(&other_session, &result)),
            Err(ProviderInvocationError::SessionMismatch)
        );
    }

    #[test]
    fn provider_invocation_checks_deadline_and_result_size() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let mut expired = invoke("expired");
        expired.deadline_ms = Some(100);
        assert_eq!(
            registry.register(provider_register(&s, &expired)),
            Err(ProviderInvocationError::DeadlineExceeded)
        );

        let inv = invoke("large");
        let mut small_limit = provider_register(&s, &inv);
        small_limit.max_inline_result_bytes = Some(4);
        registry.register(small_limit).unwrap();
        let result = invoke_result("large", Value::Str("too large".into()));
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)),
            Err(ProviderInvocationError::ResultTooLarge)
        );
        assert!(registry.is_empty());
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)),
            Err(ProviderInvocationError::InvocationNotFound)
        );

        let inv = invoke("timeout");
        registry.register(provider_register(&s, &inv)).unwrap();
        let result = invoke_result("timeout", Value::Null);
        let mut late = provider_resolve(&s, &result);
        late.now_millis = 2_000;
        assert_eq!(
            registry.resolve(late),
            Err(ProviderInvocationError::DeadlineExceeded)
        );
    }

    #[test]
    fn provider_invocation_checks_output_schema() {
        let s = complete_provider_handshake();
        let mut registry = ProviderInvocationRegistry::new();
        let inv = invoke("schema");
        let schema = Value::Map(BTreeMap::from([("type".into(), Value::from("string"))]));
        let mut register = provider_register(&s, &inv);
        register.output_schema = Some(&schema);
        registry.register(register).unwrap();

        let result = invoke_result("schema", Value::Int(7));
        assert!(matches!(
            registry.resolve(provider_resolve(&s, &result)),
            Err(ProviderInvocationError::Schema(_))
        ));
        assert!(registry.is_empty());
        assert_eq!(
            registry.resolve(provider_resolve(&s, &result)),
            Err(ProviderInvocationError::InvocationNotFound)
        );
    }

    #[test]
    fn source_command_result_must_hit_registered_entry() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        registry
            .register(source_command_register(&s, &command))
            .unwrap();
        assert_eq!(registry.len(), 1);

        let unknown = command_result("missing", Value::Null);
        assert_eq!(
            registry.resolve(source_command_resolve(&s, &unknown)),
            Err(SourceCommandError::CommandNotFound)
        );

        let result = command_result("cmd-1", Value::Str("ok".into()));
        assert_eq!(
            registry
                .resolve(source_command_resolve(&s, &result))
                .unwrap(),
            result
        );
        assert!(registry.is_empty());
        assert_eq!(
            registry.resolve(source_command_resolve(&s, &result)),
            Err(SourceCommandError::CommandNotFound)
        );
    }

    #[test]
    fn source_command_rejects_duplicate_in_flight_id() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        registry
            .register(source_command_register(&s, &command))
            .unwrap();

        let mut duplicate = source_command_register(&s, &command);
        duplicate.max_inline_result_bytes = Some(1);
        assert_eq!(
            registry.register(duplicate),
            Err(SourceCommandError::DuplicateCommandId)
        );
        assert_eq!(registry.len(), 1);

        let result = command_result("cmd-1", Value::Str("ok".into()));
        assert_eq!(
            registry
                .resolve(source_command_resolve(&s, &result))
                .unwrap(),
            result
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn source_command_retains_terminal_ids_for_idempotency_window() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        let mut register = source_command_register(&s, &command);
        register.idempotency_window_ms = 500;
        registry.register(register).unwrap();

        let result = command_result("cmd-1", Value::Str("ok".into()));
        assert_eq!(
            registry
                .resolve(source_command_resolve(&s, &result))
                .unwrap(),
            result
        );
        assert!(registry.is_empty());

        let mut duplicate = source_command_register(&s, &command);
        duplicate.now_millis = 600;
        duplicate.deadline_ms = Some(1_000);
        duplicate.idempotency_window_ms = 500;
        assert_eq!(
            registry.register(duplicate),
            Err(SourceCommandError::DuplicateCommandId)
        );

        let mut after_window = source_command_register(&s, &command);
        after_window.now_millis = 624;
        after_window.deadline_ms = Some(1_000);
        after_window.idempotency_window_ms = 500;
        registry.register(after_window).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn source_command_rejects_when_in_flight_limit_is_reached() {
        let s = complete_handshake();
        let other = complete_handshake_with_session_id("session-2");
        let mut registry = SourceCommandRegistry::new();
        let first = outbound_command("cmd-1", message_payload("send"));
        let second = outbound_command("cmd-2", message_payload("send"));
        let other_command = outbound_command("cmd-other", message_payload("send"));

        let mut first_register = source_command_register(&s, &first);
        first_register.max_in_flight = Some(1);
        registry.register(first_register).unwrap();

        let mut second_register = source_command_register(&s, &second);
        second_register.max_in_flight = Some(1);
        assert_eq!(
            registry.register(second_register),
            Err(SourceCommandError::InFlightLimitExceeded)
        );
        assert_eq!(registry.len(), 1);

        let mut other_register = source_command_register(&other, &other_command);
        other_register.max_in_flight = Some(1);
        registry.register(other_register).unwrap();
        assert_eq!(registry.len(), 2);

        let result = command_result("cmd-1", Value::Str("ok".into()));
        assert_eq!(
            registry
                .resolve(source_command_resolve(&s, &result))
                .unwrap(),
            result
        );
        let mut retry = source_command_register(&s, &second);
        retry.max_in_flight = Some(1);
        registry.register(retry).unwrap();
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn source_command_rate_limit_is_separate_from_in_flight_limit() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let first = outbound_command("cmd-1", message_payload("send"));
        let second = outbound_command("cmd-2", message_payload("send"));

        let mut first_register = source_command_register(&s, &first);
        first_register.max_in_flight = Some(1024);
        first_register.rate_limit_window_ms = 1_000;
        first_register.rate_limit_max_commands = 1;
        registry.register(first_register).unwrap();

        let mut second_register = source_command_register(&s, &second);
        second_register.max_in_flight = Some(1024);
        second_register.rate_limit_window_ms = 1_000;
        second_register.rate_limit_max_commands = 1;
        assert_eq!(
            registry.register(second_register),
            Err(SourceCommandError::RateLimited)
        );

        let mut after_window = source_command_register(&s, &second);
        after_window.now_millis = 1_200;
        after_window.deadline_ms = Some(2_000);
        after_window.max_in_flight = Some(1024);
        after_window.rate_limit_window_ms = 1_000;
        after_window.rate_limit_max_commands = 1;
        registry.register(after_window).unwrap();
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn source_command_deadline_and_drain_retain_ids() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let elapsed = outbound_command("elapsed", message_payload("send"));
        let drained = outbound_command("drained", message_payload("send"));

        let mut elapsed_register = source_command_register(&s, &elapsed);
        elapsed_register.deadline_ms = Some(500);
        elapsed_register.idempotency_window_ms = 1_000;
        registry.register(elapsed_register).unwrap();
        assert_eq!(registry.expire(600), vec!["elapsed".to_string()]);
        let mut elapsed_retry = source_command_register(&s, &elapsed);
        elapsed_retry.now_millis = 700;
        elapsed_retry.deadline_ms = Some(2_000);
        elapsed_retry.idempotency_window_ms = 1_000;
        assert_eq!(
            registry.register(elapsed_retry),
            Err(SourceCommandError::DuplicateCommandId)
        );

        let mut drained_register = source_command_register(&s, &drained);
        drained_register.now_millis = 1_700;
        drained_register.deadline_ms = Some(3_000);
        drained_register.idempotency_window_ms = 1_000;
        registry.register(drained_register).unwrap();
        assert_eq!(
            registry.drain_for_session(s.context().unwrap(), 1_800),
            vec!["drained".to_string()]
        );
        let mut drained_retry = source_command_register(&s, &drained);
        drained_retry.now_millis = 1_900;
        drained_retry.deadline_ms = Some(3_000);
        drained_retry.idempotency_window_ms = 1_000;
        assert_eq!(
            registry.register(drained_retry),
            Err(SourceCommandError::DuplicateCommandId)
        );
    }

    #[test]
    fn source_command_expire_removes_only_elapsed_deadlines() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let elapsed = outbound_command("elapsed", message_payload("send"));
        let future = outbound_command("future", message_payload("send"));

        let mut elapsed_register = source_command_register(&s, &elapsed);
        elapsed_register.deadline_ms = Some(500);
        registry.register(elapsed_register).unwrap();
        let mut future_register = source_command_register(&s, &future);
        future_register.deadline_ms = Some(2_000);
        registry.register(future_register).unwrap();

        assert_eq!(registry.expire(499), Vec::<String>::new());
        assert_eq!(registry.expire(500), vec!["elapsed".to_string()]);
        assert_eq!(registry.len(), 1);

        let elapsed_result = command_result("elapsed", Value::Null);
        assert_eq!(
            registry.resolve(source_command_resolve(&s, &elapsed_result)),
            Err(SourceCommandError::CommandNotFound)
        );
        let future_result = command_result("future", Value::Str("ok".into()));
        assert_eq!(
            registry
                .resolve(source_command_resolve(&s, &future_result))
                .unwrap(),
            future_result
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn source_command_rejects_before_ready_or_wrong_role() {
        let command = outbound_command("cmd-1", message_payload("send"));
        let mut registry = SourceCommandRegistry::new();
        let mut awaiting = EndpointSession::new();
        awaiting.on_hello(&hello(), |_| ctx()).unwrap();
        assert_eq!(
            registry.register(source_command_register(&awaiting, &command)),
            Err(SourceCommandError::Session(SessionReject::NotReady))
        );

        let provider = complete_provider_handshake();
        assert_eq!(
            registry.register(source_command_register(&provider, &command)),
            Err(SourceCommandError::NotSource)
        );
    }

    #[test]
    fn source_command_result_checks_generation_and_session() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let command = outbound_command("cmd-1", message_payload("send"));
        registry
            .register(source_command_register(&s, &command))
            .unwrap();
        let result = command_result("cmd-1", Value::Str("ok".into()));

        let mut wrong_generation = source_command_resolve(&s, &result);
        wrong_generation.current_installation_config_version = 2;
        assert_eq!(
            registry.resolve(wrong_generation),
            Err(SourceCommandError::InstallationConfigVersionMismatch)
        );

        let mut other = ctx();
        other.projection_id = "other-source".into();
        let mut other_session = EndpointSession::new();
        let mut hello = hello();
        hello.projection_id = "other-source".into();
        let sent = other_session.on_hello(&hello, |_| other).unwrap();
        other_session
            .on_ready(&RoleReady {
                accepted_context: sent,
            })
            .unwrap();
        assert_eq!(
            registry.resolve(source_command_resolve(&other_session, &result)),
            Err(SourceCommandError::SessionMismatch)
        );
    }

    #[test]
    fn source_command_checks_deadline_and_result_size() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let expired = outbound_command("expired", message_payload("send"));
        let mut expired_register = source_command_register(&s, &expired);
        expired_register.deadline_ms = Some(100);
        assert_eq!(
            registry.register(expired_register),
            Err(SourceCommandError::DeadlineExceeded)
        );

        let command = outbound_command("large", message_payload("send"));
        let mut small_limit = source_command_register(&s, &command);
        small_limit.max_inline_result_bytes = Some(4);
        registry.register(small_limit).unwrap();
        let result = command_result("large", Value::Str("too large".into()));
        assert_eq!(
            registry.resolve(source_command_resolve(&s, &result)),
            Err(SourceCommandError::ResultTooLarge)
        );
        assert!(registry.is_empty());
        assert_eq!(
            registry.resolve(source_command_resolve(&s, &result)),
            Err(SourceCommandError::CommandNotFound)
        );

        let command = outbound_command("timeout", message_payload("send"));
        registry
            .register(source_command_register(&s, &command))
            .unwrap();
        let result = command_result("timeout", Value::Null);
        let mut late = source_command_resolve(&s, &result);
        late.now_millis = 2_000;
        assert_eq!(
            registry.resolve(late),
            Err(SourceCommandError::DeadlineExceeded)
        );
    }

    #[test]
    fn source_command_checks_command_and_result_schema() {
        let s = complete_handshake();
        let mut registry = SourceCommandRegistry::new();
        let schema = message_schema();

        let bad_command = outbound_command("bad-command", Value::Str("raw".into()));
        let mut register = source_command_register(&s, &bad_command);
        register.command_schema = Some(&schema);
        assert!(matches!(
            registry.register(register),
            Err(SourceCommandError::Schema(_))
        ));
        assert!(registry.is_empty());

        let command = outbound_command("bad-result", message_payload("send"));
        let mut register = source_command_register(&s, &command);
        register.command_schema = Some(&schema);
        register.command_result_schema = Some(&schema);
        registry.register(register).unwrap();

        let result = command_result("bad-result", Value::Str("raw".into()));
        assert!(matches!(
            registry.resolve(source_command_resolve(&s, &result)),
            Err(SourceCommandError::Schema(_))
        ));
        assert!(registry.is_empty());
        assert_eq!(
            registry.resolve(source_command_resolve(&s, &result)),
            Err(SourceCommandError::CommandNotFound)
        );
    }

    #[tokio::test]
    async fn source_ingest_rejects_before_ready_and_writes_nothing() {
        let mut s = EndpointSession::new();
        s.on_hello(&hello(), |_| ctx()).unwrap();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("e1", message_payload("hello")),
        )
        .await
        .unwrap_err();

        assert_eq!(err, SourceIngestError::Session(SessionReject::NotReady));
        assert_eq!(state.read(&source_event_sink()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn source_ingest_accepts_taints_and_dedupes_event_id() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let first = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-1", message_payload("hello")),
        )
        .await
        .unwrap();
        let second = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-1", message_payload("ignored")),
        )
        .await
        .unwrap();

        assert_eq!(first.status, AckStatus::Accepted);
        assert_eq!(second.status, AckStatus::Duplicate);
        let sink = source_event_sink();
        let tv = state.read_tainted(&sink).await.unwrap().unwrap();
        assert_eq!(tv.value, Value::List(vec![message_payload("hello")]));
        assert!(tv.taint.sources().iter().any(|taint_source| {
            matches!(
                taint_source,
                TaintSource::Inbound {
                    source,
                    channel
                } if source.as_str() == "source/inst-1/source"
                    && channel.as_str() == "state://events/external/inst-1/source"
            )
        }));
    }

    #[tokio::test]
    async fn source_ingest_enforces_stream_sequence_order() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();

        let gap = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            sequenced_event("chat", 2, "evt-2", message_payload("gap")),
        )
        .await
        .unwrap_err();
        assert_eq!(
            gap,
            SourceIngestError::SequenceGap {
                expected: 1,
                seq: 2
            }
        );

        let first = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            sequenced_event("chat", 1, "evt-1", message_payload("one")),
        )
        .await
        .unwrap();
        assert_eq!(first.status, AckStatus::Accepted);

        let replay = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            sequenced_event("chat", 1, "evt-replay", message_payload("again")),
        )
        .await
        .unwrap_err();
        assert_eq!(
            replay,
            SourceIngestError::SequenceReplay { last: 1, seq: 1 }
        );

        let second = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            sequenced_event("chat", 2, "evt-2-ok", message_payload("two")),
        )
        .await
        .unwrap();
        assert_eq!(second.status, AckStatus::Accepted);
    }

    #[tokio::test]
    async fn source_ingest_duplicate_event_id_wins_before_sequence_replay() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let first = sequenced_event("chat", 1, "evt-1", message_payload("one"));
        let duplicate = first.clone();

        assert_eq!(
            ingest_source_event(source_req(state.clone(), &s, &def, &policy), first)
                .await
                .unwrap()
                .status,
            AckStatus::Accepted
        );
        assert_eq!(
            ingest_source_event(source_req(state.clone(), &s, &def, &policy), duplicate)
                .await
                .unwrap()
                .status,
            AckStatus::Duplicate
        );
    }

    #[tokio::test]
    async fn source_ingest_drop_oldest_keeps_stream_within_capacity() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut def = source_projection(None);
        def.emits.as_mut().unwrap().capacity = source_capacity(2, OverflowPolicy::DropOldest);
        let policy = PolicySnapshot::empty();

        for (id, payload) in [
            ("evt-1", message_payload("one")),
            ("evt-2", message_payload("two")),
            ("evt-3", message_payload("three")),
        ] {
            assert_eq!(
                ingest_source_event(
                    source_req(state.clone(), &s, &def, &policy),
                    event(id, payload)
                )
                .await
                .unwrap()
                .status,
                AckStatus::Accepted
            );
        }

        assert_eq!(
            state.read(&source_event_sink()).await.unwrap(),
            Some(Value::List(vec![
                message_payload("two"),
                message_payload("three")
            ]))
        );
    }

    #[tokio::test]
    async fn source_ingest_backpressure_rolls_back_sequence_dedup_and_rate() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut def = source_projection(None);
        let emits = def.emits.as_mut().unwrap();
        emits.capacity = source_capacity(
            2,
            OverflowPolicy::Backpressure {
                pause_threshold: 1,
                resume_threshold: 0,
            },
        );
        emits.rate_limit = Some(SourceRateLimit {
            window_ms: 1_000,
            max_events: 2,
        });
        let policy = PolicySnapshot::empty();

        assert_eq!(
            ingest_source_event(
                source_req(state.clone(), &s, &def, &policy),
                sequenced_event("chat", 1, "evt-1", message_payload("one")),
            )
            .await
            .unwrap()
            .status,
            AckStatus::Accepted
        );
        assert_eq!(
            ingest_source_event(
                source_req(state.clone(), &s, &def, &policy),
                sequenced_event("chat", 2, "evt-2", message_payload("two")),
            )
            .await
            .unwrap_err(),
            SourceIngestError::Backpressured
        );

        def.emits.as_mut().unwrap().capacity = source_capacity(2, OverflowPolicy::DropOldest);
        assert_eq!(
            ingest_source_event(
                source_req(state.clone(), &s, &def, &policy),
                sequenced_event("chat", 2, "evt-2", message_payload("two")),
            )
            .await
            .unwrap()
            .status,
            AckStatus::Accepted
        );
        assert_eq!(
            state.read(&source_event_sink()).await.unwrap(),
            Some(Value::List(vec![
                message_payload("one"),
                message_payload("two")
            ]))
        );
    }

    #[tokio::test]
    async fn source_ingest_disconnect_policy_rejects_at_capacity() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut def = source_projection(None);
        def.emits.as_mut().unwrap().capacity = source_capacity(1, OverflowPolicy::DisconnectBridge);
        let policy = PolicySnapshot::empty();

        assert_eq!(
            ingest_source_event(
                source_req(state.clone(), &s, &def, &policy),
                event("evt-1", message_payload("one")),
            )
            .await
            .unwrap()
            .status,
            AckStatus::Accepted
        );
        assert_eq!(
            ingest_source_event(
                source_req(state.clone(), &s, &def, &policy),
                event("evt-2", message_payload("two")),
            )
            .await
            .unwrap_err(),
            SourceIngestError::CapacityExceeded
        );
    }

    #[tokio::test]
    async fn source_ingest_rate_limit_is_durable_and_windowed() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut def = source_projection(None);
        def.emits.as_mut().unwrap().rate_limit = Some(SourceRateLimit {
            window_ms: 100,
            max_events: 1,
        });
        let policy = PolicySnapshot::empty();
        let mut first = source_req(state.clone(), &s, &def, &policy);
        first.now_millis = 1_000;
        assert_eq!(
            ingest_source_event(first, event("evt-1", message_payload("one")))
                .await
                .unwrap()
                .status,
            AckStatus::Accepted
        );

        let mut limited = source_req(state.clone(), &s, &def, &policy);
        limited.now_millis = 1_050;
        assert_eq!(
            ingest_source_event(limited, event("evt-2", message_payload("two")))
                .await
                .unwrap_err(),
            SourceIngestError::RateLimited
        );

        let mut after_window = source_req(state.clone(), &s, &def, &policy);
        after_window.now_millis = 1_101;
        assert_eq!(
            ingest_source_event(after_window, event("evt-2", message_payload("two")))
                .await
                .unwrap()
                .status,
            AckStatus::Accepted
        );

        let path = source_event_rate_path("inst-1", "source").unwrap();
        assert_eq!(
            state.read(&path).await.unwrap(),
            Some(Value::List(vec![Value::Int(1_101)]))
        );
    }

    #[tokio::test]
    async fn source_ingest_payload_limit_rejects_before_dedup_or_append() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut def = source_projection(None);
        def.emits.as_mut().unwrap().max_inline_payload_bytes = 4;
        let policy = PolicySnapshot::empty();

        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-big", message_payload("too-large")),
        )
        .await
        .unwrap_err();

        assert_eq!(err, SourceIngestError::PayloadTooLarge);
        assert_eq!(state.read(&source_event_sink()).await.unwrap(), None);
        assert_eq!(
            state
                .read(&source_event_dedup_path("inst-1", "source", "evt-big").unwrap())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn source_ingest_rejects_secret_and_taint_override_fields() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let mut nested = BTreeMap::new();
        nested.insert("access-token".into(), Value::Str("raw-token".into()));
        let mut payload = BTreeMap::new();
        payload.insert("metadata".into(), Value::Map(nested));

        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-secret", Value::Map(payload)),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            SourceIngestError::ForbiddenPayloadField {
                field: "access-token".into()
            }
        );

        let mut payload = BTreeMap::new();
        payload.insert("taint".into(), Value::Str("trusted".into()));
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-taint", Value::Map(payload)),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            SourceIngestError::ForbiddenPayloadField {
                field: "taint".into()
            }
        );
        assert_eq!(state.read(&source_event_sink()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn source_ingest_prunes_old_dedup_records_within_window() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let old_path = source_event_dedup_path("inst-1", "source", "old").unwrap();
        state
            .write_set(
                &old_path,
                source_dedup_record(SourceDedupStatus::Accepted, 1),
            )
            .await
            .expect("seed old dedup");
        let mut req = source_req(state.clone(), &s, &def, &policy);
        req.now_millis = 10_000;
        req.dedupe_window_ms = 100;

        let ack = ingest_source_event(req, event("new", message_payload("hello")))
            .await
            .unwrap();

        assert_eq!(ack.status, AckStatus::Accepted);
        assert_eq!(state.read(&old_path).await.unwrap(), None);
    }

    #[tokio::test]
    async fn source_ingest_zero_dedup_window_still_prunes_old_records() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let old_path = source_event_dedup_path("inst-1", "source", "old").unwrap();
        state
            .write_set(
                &old_path,
                source_dedup_record(SourceDedupStatus::Accepted, 1),
            )
            .await
            .expect("seed old dedup");
        let mut req = source_req(state.clone(), &s, &def, &policy);
        req.now_millis = 10_000;
        req.dedupe_window_ms = 0;

        let ack = ingest_source_event(req, event("new", message_payload("hello")))
            .await
            .unwrap();

        assert_eq!(ack.status, AckStatus::Accepted);
        assert_eq!(state.read(&old_path).await.unwrap(), None);
    }

    #[tokio::test]
    async fn source_ingest_dedup_uses_receipt_time_not_event_timestamp() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let mut req = source_req(state.clone(), &s, &def, &policy);
        req.now_millis = 10_000;
        req.dedupe_window_ms = 100;

        let mut first = event("evt-old-clock", message_payload("hello"));
        first.timestamp_ms = 1;
        let ack = ingest_source_event(req, first).await.unwrap();
        assert_eq!(ack.status, AckStatus::Accepted);

        let dedup_path = source_event_dedup_path("inst-1", "source", "evt-old-clock").unwrap();
        assert_eq!(
            state.read(&dedup_path).await.unwrap(),
            Some(source_dedup_record(SourceDedupStatus::Accepted, 10_000))
        );

        let mut req = source_req(state.clone(), &s, &def, &policy);
        req.now_millis = 10_050;
        req.dedupe_window_ms = 100;
        let mut duplicate = event("evt-old-clock", message_payload("ignored"));
        duplicate.timestamp_ms = 1;
        let ack = ingest_source_event(req, duplicate).await.unwrap();
        assert_eq!(ack.status, AckStatus::Duplicate);

        let tv = state
            .read_tainted(&source_event_sink())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tv.value, Value::List(vec![message_payload("hello")]));
    }

    #[tokio::test]
    async fn source_ingest_pending_dedup_does_not_ack_duplicate() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let dedup_path = source_event_dedup_path("inst-1", "source", "evt-pending").unwrap();
        state
            .write_set(
                &dedup_path,
                source_dedup_record(SourceDedupStatus::Pending, 10_000),
            )
            .await
            .expect("seed pending dedup");

        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-pending", message_payload("retry")),
        )
        .await
        .unwrap_err();

        assert_eq!(err, SourceIngestError::Backpressured);
        assert_eq!(state.read(&source_event_sink()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn source_ingest_rejects_schema_mismatch_and_policy_deny() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(Some(message_schema()));
        let policy = PolicySnapshot::empty();
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-schema", Value::Float(FloatBits(1.0))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SourceIngestError::Schema(_)));

        let deny = PolicySnapshot::new(vec![Arc::new(DenyAll)]);
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &deny),
            event("evt-deny", message_payload("hello")),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SourceIngestError::Policy("blocked".into()));
        assert_eq!(state.read(&source_event_sink()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn source_ingest_rejects_generation_mismatches() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let mut req = source_req(state, &s, &def, &policy);
        req.current_registry_hash = "other";
        let err = ingest_source_event(req, event("evt-hash", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::RegistryHashMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut req = source_req(state, &s, &def, &policy);
        req.credential_generation = 4;
        let err = ingest_source_event(req, event("evt-cred", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::CredentialGenerationMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut req = source_req(state, &s, &def, &policy);
        req.current_binding_generation = 2;
        let err = ingest_source_event(req, event("evt-binding", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::BindingGenerationMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut req = source_req(state, &s, &def, &policy);
        req.current_installation_config_version = 2;
        let err = ingest_source_event(req, event("evt-config", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::InstallationConfigVersionMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut projection = source_projection(None);
        projection.version = 2;
        let req = source_req(state, &s, &projection, &policy);
        let err = ingest_source_event(req, event("evt-projection", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::ProjectionVersionMismatch);
    }
}
