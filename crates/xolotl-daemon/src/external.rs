//! External Provider and Source session operations for this daemon host.

use super::*;
use std::collections::{BTreeMap, HashMap, btree_map::Entry};
use std::time::Duration;
use tokio::sync::oneshot;
use xolotl_gateway::external::{
    EndpointSession, EnvelopeAad, ExternalCredential, ExternalSessionHandler,
    ExternalSessionOutbound, ProviderInvocationError, ProviderInvocationRegister,
    ProviderInvocationRegistry, ProviderInvocationResolve, SecureEnvelope, SecureEnvelopeEpochGate,
    SecureEnvelopeReplayWindow, SourceCommandError, SourceIngest, SourceIngestError,
    ingest_source_event, operate_source_stream, validate_json_schema,
};
use xolotl_kernel::PolicySnapshot;
use xolotl_kernel::Registry;
use xolotl_kernel::driver::{DriverError, RemoteInvokeDispatch};
use xolotl_types::Value;
use xolotl_types::external::{
    AckStatus, EventAck, ExternalInstallationDef, ExternalProjectionDef, InboundEvent, Role,
    RoleSessionClientHello, SessionContext, SourceStreamRequest, SourceStreamResult,
};
use xolotl_types::external::{
    CommandResult, ConfigAxis, ControlFrame, EffectCapability, Invoke, InvokeResult,
};
use xolotl_types::external::{ObservedGenerations, OutboundCommand};
use xolotl_types::{IdentityRef, Path, ResourceId};
use xolotl_types::{MethodId, ResourceName, ResourceSelector, Transport};

mod authority;
mod bindings;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
mod listeners;
mod provider;
mod source;
mod source_endpoint;

use authority::{
    ExternalAuthority, context_matches_authority, load_external_authority, new_external_session_id,
};
#[cfg(all(test, feature = "external-grpc"))]
use bindings::{
    ProviderBindingDeclaration, register_provider_binding, register_provider_bindings_at_generation,
};
use bindings::{
    SourceBindingPublisher, register_provider_bindings, validate_provider_projection_bindings,
};
#[cfg(feature = "external-grpc")]
pub(super) use listeners::start_external_grpc;
#[cfg(feature = "external-websocket")]
pub(super) use listeners::start_external_websocket;
use provider::ProviderRoleEndpoint;
#[cfg(all(test, feature = "external-grpc"))]
use provider::await_provider_result;
use source::SourceCommandHub;

#[derive(Clone, Copy)]
struct ExternalCallDeadline {
    wall_millis: i64,
    monotonic: tokio::time::Instant,
}

impl ExternalCallDeadline {
    fn new(wall_millis: i64, at_millis: i64) -> Result<Self, tonic::Status> {
        let remaining = wall_millis.saturating_sub(at_millis).max(0) as u64;
        let monotonic = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| {
                tonic::Status::invalid_argument("external call deadline out of range")
            })?;
        Ok(Self {
            wall_millis,
            monotonic,
        })
    }

    fn expired(self) -> bool {
        self.wall_millis <= now_millis() || self.monotonic <= tokio::time::Instant::now()
    }
}

struct DaemonExternalSessionHandler {
    state: Backend,
    source_store: Arc<dyn SourceStore>,
    decision_clock: Arc<dyn xolotl_source::SourceClock>,
    registry: Registry,
    session_limits: config::ExternalGatewaySessionLimits,
    provider_sessions: Arc<std::sync::Mutex<BTreeMap<ProviderSessionKey, ProviderSessionRecord>>>,
    source_hub: SourceCommandHub,
    source_bindings: SourceBindingPublisher,
    // Provider registration and waiter mutations take both locks in this order.
    // Neither half may become visible separately to another Provider path.
    provider_invocations: Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    provider_waiters: Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    pairing_credentials: PairingDisplayEdge,
    #[cfg(test)]
    external_credentials: Arc<std::sync::Mutex<BTreeMap<(String, u64), ExternalCredential>>>,
    secure_replay_windows:
        Arc<std::sync::Mutex<BTreeMap<SecureReplayKey, SecureEnvelopeReplayWindow>>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProviderSessionKey {
    installation_id: String,
    projection_id: String,
    session_id: String,
}

#[derive(Clone)]
struct ProviderSessionRecord {
    endpoint_id: xolotl_types::EndpointId,
    context: SessionContext,
    ready_endpoints: HashMap<ProviderEndpointKey, Path>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProviderEndpointKey {
    resource_id: ResourceId,
    method_id: MethodId,
    binding_generation: u64,
}

impl ProviderEndpointKey {
    fn from_dispatch(dispatch: RemoteInvokeDispatch) -> Self {
        Self {
            resource_id: dispatch.resource_id,
            method_id: dispatch.method_id,
            binding_generation: dispatch.binding_generation,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SecureReplayKey {
    installation_id: String,
    projection_id: String,
    role: &'static str,
    session_id: String,
}

type ExternalSessionOutboundHandle = Arc<dyn ExternalSessionOutbound<Error = tonic::Status>>;

/// Source command routing and projection publication are daemon-wide. Each
/// transport still owns a handler with its own admission limits.
#[derive(Clone)]
pub(super) struct SharedSourceCommands {
    hub: SourceCommandHub,
    publisher: SourceBindingPublisher,
}

impl SharedSourceCommands {
    pub(super) fn new(
        state: Backend,
        source_store: Arc<dyn SourceStore>,
        registry: Registry,
        capacity: std::num::NonZeroUsize,
    ) -> Self {
        let hub = SourceCommandHub::new(state, source_store, capacity);
        let publisher = SourceBindingPublisher::new(registry, hub.clone());
        Self { hub, publisher }
    }

    pub(super) fn expire_retained(
        &self,
        now_millis: i64,
    ) -> Result<xolotl_gateway::external::SourceCommandMaintenanceReport, tonic::Status> {
        self.hub.expire_retained(now_millis)
    }
}

impl DaemonExternalSessionHandler {
    #[cfg(all(test, feature = "external-grpc"))]
    fn new(
        state: Backend,
        source_store: Arc<dyn SourceStore>,
        registry: Registry,
        source_dedupe_window_ms: u64,
    ) -> Self {
        Self::with_limits(
            state,
            source_store,
            registry,
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms,
                ..Default::default()
            },
        )
    }

    #[cfg(all(test, feature = "external-grpc"))]
    fn with_limits(
        state: Backend,
        source_store: Arc<dyn SourceStore>,
        registry: Registry,
        session_limits: config::ExternalGatewaySessionLimits,
    ) -> Self {
        Self::with_limits_and_credentials(
            state,
            source_store,
            registry,
            session_limits,
            PairingDisplayEdge::default(),
        )
    }

    #[cfg(all(test, feature = "external-grpc"))]
    fn with_limits_and_credentials(
        state: Backend,
        source_store: Arc<dyn SourceStore>,
        registry: Registry,
        session_limits: config::ExternalGatewaySessionLimits,
        pairing_credentials: PairingDisplayEdge,
    ) -> Self {
        let shared = SharedSourceCommands::new(
            state.clone(),
            source_store.clone(),
            registry.clone(),
            xolotl_gateway::external::DEFAULT_SOURCE_COMMAND_LIMIT,
        );
        Self::with_shared_source_commands(
            state,
            source_store,
            registry,
            session_limits,
            pairing_credentials,
            shared,
            Arc::new(now_millis),
        )
    }

    fn with_shared_source_commands(
        state: Backend,
        source_store: Arc<dyn SourceStore>,
        registry: Registry,
        session_limits: config::ExternalGatewaySessionLimits,
        pairing_credentials: PairingDisplayEdge,
        shared_source_commands: SharedSourceCommands,
        decision_clock: Arc<dyn xolotl_source::SourceClock>,
    ) -> Self {
        let session_limits = session_limits.bounded();
        Self {
            state,
            source_store,
            decision_clock,
            registry,
            session_limits,
            provider_sessions: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            source_hub: shared_source_commands.hub,
            source_bindings: shared_source_commands.publisher,
            provider_invocations: Arc::new(
                std::sync::Mutex::new(ProviderInvocationRegistry::new()),
            ),
            provider_waiters: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            pairing_credentials,
            #[cfg(test)]
            external_credentials: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            secure_replay_windows: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    #[cfg(all(test, feature = "external-grpc"))]
    async fn register_provider_invoke(
        &self,
        invoke: &Invoke,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<oneshot::Receiver<InvokeResult>, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Provider,
            )
            .await?;
        let (tx, rx) = oneshot::channel();
        let capability = authority
            .provider_capabilities
            .get(&invoke.effect_path)
            .ok_or_else(|| tonic::Status::permission_denied("provider invocation rejected"))?;
        validate_json_schema(capability.input_schema.as_ref(), &invoke.input).map_err(|error| {
            tonic::Status::invalid_argument(format!("provider invocation rejected: {error}"))
        })?;
        let output_schema = capability.output_schema.as_ref();
        {
            let mut invocations = self.provider_invocations.lock().map_err(|_error| {
                tonic::Status::internal("provider invocation registry unavailable")
            })?;
            let mut waiters = self.provider_waiters.lock().map_err(|_error| {
                tonic::Status::internal("provider invocation waiter unavailable")
            })?;
            let registration_id = invocations
                .register(ProviderInvocationRegister {
                    session,
                    invoke,
                    current_registry_hash: &authority.context.registry_hash,
                    credential_generation: authority.context.credential_generation,
                    current_binding_generation: authority.context.binding_generation,
                    current_projection_version: authority.context.projection_version,
                    now_millis: now_millis(),
                    acting: IdentityRef::ROOT,
                    max_in_flight: Some(self.session_limits.provider_max_in_flight_invocations),
                    max_identity_in_flight: Some(
                        self.session_limits.provider_max_in_flight_per_identity,
                    ),
                    max_effect_in_flight: Some(
                        self.session_limits.provider_max_in_flight_per_effect,
                    ),
                    max_inline_result_bytes: Some(
                        self.session_limits.provider_max_inline_result_bytes,
                    ),
                    output_schema,
                })
                .map_err(provider_invocation_status)?;
            match waiters.entry(invoke.invocation_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(tx);
                }
                Entry::Occupied(_) => {
                    invocations.remove_if(&invoke.invocation_id, registration_id);
                    return Err(tonic::Status::failed_precondition(
                        "provider invocation waiter duplicate",
                    ));
                }
            }
        }
        Ok(rx)
    }

    #[cfg(all(test, feature = "external-grpc"))]
    async fn send_source_command(
        &self,
        command: OutboundCommand,
        session: &EndpointSession,
        context: &SessionContext,
        deadline_ms: Option<i64>,
    ) -> Result<source::PendingSourceCommand, tonic::Status> {
        let mut pending = self
            .source_hub
            .begin_for_session(command, session, context, deadline_ms)
            .await?;
        pending
            .send()
            .await
            .map_err(|error| tonic::Status::unavailable(error.to_string()))?;
        Ok(pending)
    }
}

impl DaemonExternalSessionHandler {
    async fn adjudicate_external_session(
        &self,
        hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, tonic::Status> {
        let mut authority = self
            .load_authority(&hello.installation_id, &hello.projection_id, hello.role)
            .await?
            .context;
        authority.session_id = new_external_session_id()?;
        Ok(authority)
    }

    fn close_external_session(
        &self,
        _session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        match context.role {
            Role::Provider => {
                let key = provider_session_key(&context);
                let mut sessions = self.provider_sessions.lock().map_err(|_error| {
                    tonic::Status::internal("provider session registry unavailable")
                })?;
                if sessions
                    .get(&key)
                    .is_some_and(|record| record.context == context)
                {
                    let record = sessions.remove(&key);
                    drop(sessions);
                    if let Some(record) = record {
                        self.registry.unregister_endpoint(record.endpoint_id);
                    }
                } else {
                    drop(sessions);
                }
                let mut invocations = self.provider_invocations.lock().map_err(|_error| {
                    tonic::Status::internal("provider invocation registry unavailable")
                })?;
                let mut waiters = self.provider_waiters.lock().map_err(|_error| {
                    tonic::Status::internal("provider invocation waiter unavailable")
                })?;
                let pending = invocations.drain_for_session(&context);
                if !pending.is_empty() {
                    for invocation_id in pending {
                        waiters.remove(&invocation_id);
                    }
                }
            }
            Role::Source => {
                self.source_hub.close(&context)?;
            }
        }
        remove_secure_replay_windows_for_context(&self.secure_replay_windows, &context)?;
        Ok(())
    }

    async fn handle_inbound_event(
        &self,
        event: InboundEvent,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<EventAck, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Source,
            )
            .await?;
        let policy = PolicySnapshot::empty();
        let event_id = event.id.clone();
        let stream_epoch = event.stream_epoch;
        match ingest_source_event(
            SourceIngest {
                store: self.source_store.as_ref(),
                session,
                installation_id: &context.installation_id,
                projection: &authority.projection,
                current_registry_hash: &authority.context.registry_hash,
                credential_generation: authority.context.credential_generation,
                current_binding_generation: authority.context.binding_generation,
                current_installation_config_version: authority.context.installation_config_version,
                policy: &policy,
                acting: IdentityRef::ROOT,
                target: ResourceId::new(0),
                now_millis: now_millis(),
                decision_clock: self.decision_clock.clone(),
                dedupe_window_ms: self.session_limits.source_dedupe_window_ms,
            },
            event,
        )
        .await
        {
            Ok(ack) => Ok(ack),
            Err(error) => match source_ingest_error_ack(event_id, stream_epoch, &error) {
                Some(ack) => Ok(ack),
                None => Err(source_ingest_status(error)),
            },
        }
    }

    async fn handle_source_stream_request(
        &self,
        request: SourceStreamRequest,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<SourceStreamResult, tonic::Status> {
        session.admit_business().map_err(|_error| {
            tonic::Status::permission_denied("source stream session is not ready")
        })?;
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Source,
            )
            .await?;
        if !context_matches_authority(&authority.context, context) {
            return Err(tonic::Status::permission_denied(
                "source stream session authority changed",
            ));
        }
        session
            .admit_credential(authority.context.credential_generation)
            .map_err(|_error| {
                tonic::Status::permission_denied("source stream credential was revoked")
            })?;
        Ok(operate_source_stream(self.source_store.as_ref(), context, request).await)
    }

    async fn handle_command_result(
        &self,
        result: CommandResult,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Source,
            )
            .await?;
        self.source_hub
            .resolve(result, session, context, &authority)
    }

    async fn handle_invoke_result(
        &self,
        result: InvokeResult,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), tonic::Status> {
        let invocation_id = result.invocation_id.clone();
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Provider,
            )
            .await?;
        let (accepted, waiter) = {
            let mut invocations = self.provider_invocations.lock().map_err(|_error| {
                tonic::Status::internal("provider invocation registry unavailable")
            })?;
            let mut waiters = self.provider_waiters.lock().map_err(|_error| {
                tonic::Status::internal("provider invocation waiter unavailable")
            })?;
            match invocations.resolve(ProviderInvocationResolve {
                session,
                result,
                current_registry_hash: &authority.context.registry_hash,
                credential_generation: authority.context.credential_generation,
                current_binding_generation: authority.context.binding_generation,
                current_projection_version: authority.context.projection_version,
                now_millis: now_millis(),
            }) {
                Ok(accepted) => {
                    let waiter = waiters.remove(&accepted.invocation_id).ok_or_else(|| {
                        tonic::Status::failed_precondition("provider invocation waiter missing")
                    })?;
                    (accepted, waiter)
                }
                Err(error) => {
                    if provider_invocation_error_removes_entry(&error) {
                        waiters.remove(&invocation_id);
                    }
                    return Err(provider_invocation_status(error));
                }
            }
        };
        waiter
            .send(accepted)
            .map_err(|_error| tonic::Status::unavailable("provider invocation receiver closed"))
    }

    async fn handle_control(
        &self,
        frame: ControlFrame,
        _session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, context) {
            return Err(tonic::Status::permission_denied(
                "external control frame rejected",
            ));
        }
        validate_external_control_frame(&frame, context)
    }

    async fn open_external_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        _session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<Vec<u8>, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, context) {
            return Err(tonic::Status::permission_denied("secure envelope rejected"));
        }
        if _session.transcript_hash().map(|hash| hash.as_slice())
            != Some(envelope.aad().transcript_hash.as_slice())
        {
            return Err(tonic::Status::permission_denied(
                "secure envelope transcript rejected",
            ));
        }
        let credential = self
            .pairing_credentials
            .credential(
                &context.installation_id,
                context.installation_epoch,
                context.credential_generation,
            )
            .map(|psk| {
                ExternalCredential::new(
                    context.installation_id.clone(),
                    context.credential_generation,
                    psk,
                )
            });
        #[cfg(test)]
        let credential = if credential.is_some() {
            credential
        } else {
            self.external_credentials
                .lock()
                .map_err(|_error| tonic::Status::internal("external credential store unavailable"))?
                .get(&(
                    context.installation_id.clone(),
                    context.credential_generation,
                ))
                .cloned()
        };
        let credential = credential
            .ok_or_else(|| tonic::Status::unauthenticated("external credential unavailable"))?;
        let replay_key = SecureReplayKey {
            installation_id: context.installation_id.clone(),
            projection_id: context.projection_id.clone(),
            role: context.role.as_str(),
            session_id: context.session_id.clone(),
        };
        let mut replay_windows = self.secure_replay_windows.lock().map_err(|_error| {
            tonic::Status::internal("secure envelope replay state unavailable")
        })?;
        // Sequence numbers span key epochs on one connection. A single bounded
        // replay window also prevents cross-epoch retransmission and avoids
        // retaining one allocation for every rekey.
        let replay_window = replay_windows.entry(replay_key).or_default();
        let epoch_gate = SecureEnvelopeEpochGate::new(authority.key_epoch);
        credential
            .open_with_replay_window_and_epoch_gate(
                envelope,
                authority.context.credential_generation,
                replay_window,
                &epoch_gate,
            )
            .map_err(|_error| tonic::Status::permission_denied("secure envelope rejected"))
    }
}

#[async_trait::async_trait]
impl ExternalSessionHandler for DaemonExternalSessionHandler {
    type Error = tonic::Status;
    type OutboundError = tonic::Status;

    async fn adjudicate_session(
        &self,
        hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, tonic::Status> {
        self.adjudicate_external_session(hello).await
    }

    async fn on_ready(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: ExternalSessionOutboundHandle,
    ) -> Result<(), tonic::Status> {
        self.register_ready_session(session, context, outbound)
            .await
    }

    fn on_closed(
        &self,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.close_external_session(session, context)
    }

    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<EventAck, tonic::Status> {
        self.handle_inbound_event(event, session, context).await
    }

    async fn on_source_stream_request(
        &self,
        request: SourceStreamRequest,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<SourceStreamResult, tonic::Status> {
        self.handle_source_stream_request(request, session, context)
            .await
    }

    async fn on_command_result(
        &self,
        result: CommandResult,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_command_result(result, session, context).await
    }

    async fn on_invoke_result(
        &self,
        result: InvokeResult,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_invoke_result(result, session, context).await
    }

    async fn on_control(
        &self,
        frame: ControlFrame,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_control(frame, session, context).await
    }

    async fn open_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<Vec<u8>, tonic::Status> {
        self.open_external_secure_envelope(envelope, session, context)
            .await
    }

    async fn seal_secure_envelope(
        &self,
        plaintext: Vec<u8>,
        mut aad: EnvelopeAad,
        context: &SessionContext,
    ) -> Result<SecureEnvelope, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, context)
            || aad.version != 1
            || aad.projection_id != context.projection_id
            || aad.role != context.role.as_str()
            || aad.session_id != context.session_id
            || aad.binding_generation != context.binding_generation
            || aad.credential_generation != context.credential_generation
            || aad.transcript_hash.len() != 32
            || aad.direction != "daemon_to_client"
        {
            return Err(tonic::Status::permission_denied(
                "external outbound context rejected",
            ));
        }
        aad.key_epoch = authority.key_epoch;
        let psk = self.pairing_credentials.credential(
            &context.installation_id,
            context.installation_epoch,
            context.credential_generation,
        );
        #[cfg(test)]
        let credential = if let Some(psk) = psk {
            ExternalCredential::new(
                context.installation_id.clone(),
                context.credential_generation,
                psk,
            )
        } else {
            self.external_credentials
                .lock()
                .map_err(|_error| tonic::Status::internal("external credential store unavailable"))?
                .get(&(
                    context.installation_id.clone(),
                    context.credential_generation,
                ))
                .cloned()
                .ok_or_else(|| tonic::Status::unauthenticated("external credential unavailable"))?
        };
        #[cfg(not(test))]
        let credential = ExternalCredential::new(
            context.installation_id.clone(),
            context.credential_generation,
            psk.ok_or_else(|| tonic::Status::unauthenticated("external credential unavailable"))?,
        );
        credential.seal_with_aad(&plaintext, aad).map_err(|_error| {
            tonic::Status::permission_denied("external outbound envelope rejected")
        })
    }
}

impl DaemonExternalSessionHandler {
    async fn register_ready_session(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: ExternalSessionOutboundHandle,
    ) -> Result<(), tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, &context) {
            return Err(tonic::Status::permission_denied(
                "external session context rejected",
            ));
        }
        match context.role {
            Role::Provider => {
                let binding_declarations =
                    validate_provider_projection_bindings(&authority.projection)?;
                let mut provider_sessions = self.provider_sessions.lock().map_err(|_error| {
                    tonic::Status::internal("provider session registry unavailable")
                })?;
                let endpoint_id = self.registry.next_endpoint_id();
                let endpoint = ProviderRoleEndpoint {
                    state: self.state.clone(),
                    source_store: self.source_store.clone(),
                    context: context.clone(),
                    session: session.clone(),
                    outbound,
                    provider_invocations: self.provider_invocations.clone(),
                    provider_waiters: self.provider_waiters.clone(),
                    provider_sessions: self.provider_sessions.clone(),
                    session_limits: self.session_limits,
                };
                self.registry
                    .register_endpoint(endpoint_id, Arc::new(endpoint));
                let ready_endpoints = match register_provider_bindings(
                    &self.registry,
                    &binding_declarations,
                    endpoint_id,
                    &context,
                ) {
                    Ok(ready_endpoints) => ready_endpoints,
                    Err(error) => {
                        self.registry.unregister_endpoint(endpoint_id);
                        return Err(error);
                    }
                };
                if let Some(old) = provider_sessions.insert(
                    provider_session_key(&context),
                    ProviderSessionRecord {
                        endpoint_id,
                        context,
                        ready_endpoints,
                    },
                ) {
                    self.registry.unregister_endpoint(old.endpoint_id);
                }
            }
            Role::Source => {
                self.source_bindings
                    .publish(&context, &authority.projection)?;
                self.source_hub
                    .register_ready(session, context, outbound, self.session_limits)?;
            }
        }
        Ok(())
    }

    async fn load_authority(
        &self,
        installation_id: &str,
        projection_id: &str,
        role: Role,
    ) -> Result<ExternalAuthority, tonic::Status> {
        load_external_authority(
            &self.state,
            installation_id,
            projection_id,
            role,
            self.source_store.as_ref(),
        )
        .await
    }
}

fn provider_session_key(context: &SessionContext) -> ProviderSessionKey {
    ProviderSessionKey {
        installation_id: context.installation_id.clone(),
        projection_id: context.projection_id.clone(),
        session_id: context.session_id.clone(),
    }
}

fn remove_secure_replay_windows_for_context(
    replay_windows: &std::sync::Mutex<BTreeMap<SecureReplayKey, SecureEnvelopeReplayWindow>>,
    context: &SessionContext,
) -> Result<(), tonic::Status> {
    let role = context.role.as_str();
    replay_windows
        .lock()
        .map_err(|_error| tonic::Status::internal("secure envelope replay state unavailable"))?
        .retain(|key, _| {
            key.installation_id != context.installation_id
                || key.projection_id != context.projection_id
                || key.role != role
                || key.session_id != context.session_id
        });
    Ok(())
}

fn status_to_driver_error(status: tonic::Status) -> DriverError {
    DriverError::Transport(status.message().to_string())
}

fn validate_external_control_frame(
    frame: &ControlFrame,
    context: &SessionContext,
) -> Result<(), tonic::Status> {
    match frame {
        ControlFrame::Heartbeat { timestamp_ms } if *timestamp_ms >= 0 => Ok(()),
        ControlFrame::Heartbeat { .. } => Err(tonic::Status::invalid_argument(
            "external control frame rejected",
        )),
        ControlFrame::FlowControl(_) => Err(tonic::Status::permission_denied(
            "external control frame rejected",
        )),
        ControlFrame::PresentationProfileUpdate {
            profile_generation: _,
            profile_hash,
            profile: _,
        } if !profile_hash.trim().is_empty() => Ok(()),
        ControlFrame::PresentationProfileUpdate { .. } => Err(tonic::Status::invalid_argument(
            "external control frame rejected",
        )),
        ControlFrame::ConfigAck {
            axis: ConfigAxis::InstallationConfig,
            version,
            status: _,
        } if *version == context.installation_config_version => Ok(()),
        ControlFrame::ConfigAck {
            axis: ConfigAxis::PresentationConfig,
            version,
            status: _,
        } if *version == context.presentation_config_generation => Ok(()),
        ControlFrame::ConfigAck { .. } => Err(tonic::Status::permission_denied(
            "external control frame rejected",
        )),
        ControlFrame::Shutdown { .. }
        | ControlFrame::ProviderCancel { .. }
        | ControlFrame::InstallationConfigUpdate { .. }
        | ControlFrame::PresentationConfigUpdate { .. } => Err(tonic::Status::permission_denied(
            "external control frame rejected",
        )),
    }
}

fn source_ingest_status(error: SourceIngestError) -> tonic::Status {
    let message = format!("source event rejected: {error}");
    match error {
        SourceIngestError::Session(_)
        | SourceIngestError::ScopeInactive
        | SourceIngestError::ProjectionMismatch(_)
        | SourceIngestError::RegistryHashMismatch
        | SourceIngestError::CredentialGenerationMismatch
        | SourceIngestError::BindingGenerationMismatch
        | SourceIngestError::InstallationConfigVersionMismatch
        | SourceIngestError::ProjectionVersionMismatch
        | SourceIngestError::NotSource
        | SourceIngestError::MissingEmits => tonic::Status::permission_denied(message),
        SourceIngestError::InvalidEventId
        | SourceIngestError::EventIdConflict
        | SourceIngestError::InvalidStreamId
        | SourceIngestError::InvalidSequence
        | SourceIngestError::SequenceReplay { .. }
        | SourceIngestError::SequenceGap { .. }
        | SourceIngestError::StreamInactive
        | SourceIngestError::StreamEpochMismatch { .. }
        | SourceIngestError::Schema(_)
        | SourceIngestError::PayloadTooLarge
        | SourceIngestError::ForbiddenPayloadField { .. }
        | SourceIngestError::Policy(_) => tonic::Status::invalid_argument(message),
        SourceIngestError::RateLimited
        | SourceIngestError::Backpressured
        | SourceIngestError::CapacityExceeded
        | SourceIngestError::RetentionCapacityExceeded => {
            tonic::Status::resource_exhausted(message)
        }
        SourceIngestError::SinkTypeMismatch | SourceIngestError::DeclarationMismatch => {
            tonic::Status::failed_precondition(message)
        }
        SourceIngestError::CommitOutcomeUnknown => tonic::Status::unknown(message),
        SourceIngestError::State(_) => tonic::Status::unavailable(message),
    }
}

fn source_ingest_error_ack(
    event_id: String,
    stream_epoch: Option<u64>,
    error: &SourceIngestError,
) -> Option<EventAck> {
    if matches!(error, SourceIngestError::CommitOutcomeUnknown) {
        return Some(EventAck {
            id: event_id,
            status: AckStatus::OutcomeUnknown,
            reject_reason: None,
            stream_epoch,
        });
    }
    let reason = match error {
        SourceIngestError::InvalidEventId => "invalid_event_id",
        SourceIngestError::EventIdConflict => "event_id_conflict",
        SourceIngestError::InvalidStreamId => "invalid_stream_id",
        SourceIngestError::InvalidSequence
        | SourceIngestError::SequenceReplay { .. }
        | SourceIngestError::SequenceGap { .. } => "ordering_rejected",
        SourceIngestError::StreamInactive => "stream_inactive",
        SourceIngestError::StreamEpochMismatch { .. } => "stream_epoch_mismatch",
        SourceIngestError::Schema(_) => "schema_rejected",
        SourceIngestError::PayloadTooLarge => "payload_too_large",
        SourceIngestError::ForbiddenPayloadField { .. } => "forbidden_payload_field",
        SourceIngestError::Policy(_) => "policy_rejected",
        SourceIngestError::RateLimited => "rate_limited",
        SourceIngestError::Backpressured => "backpressured",
        SourceIngestError::CapacityExceeded => "capacity_exceeded",
        SourceIngestError::RetentionCapacityExceeded => "retention_capacity_exceeded",
        SourceIngestError::SinkTypeMismatch => "sink_type_mismatch",
        SourceIngestError::Session(_)
        | SourceIngestError::ScopeInactive
        | SourceIngestError::DeclarationMismatch
        | SourceIngestError::ProjectionMismatch(_)
        | SourceIngestError::RegistryHashMismatch
        | SourceIngestError::CredentialGenerationMismatch
        | SourceIngestError::BindingGenerationMismatch
        | SourceIngestError::InstallationConfigVersionMismatch
        | SourceIngestError::ProjectionVersionMismatch
        | SourceIngestError::NotSource
        | SourceIngestError::MissingEmits
        | SourceIngestError::CommitOutcomeUnknown
        | SourceIngestError::State(_) => return None,
    };
    Some(EventAck {
        id: event_id,
        status: AckStatus::Rejected,
        reject_reason: Some(reason.into()),
        stream_epoch,
    })
}

fn provider_invocation_status(error: ProviderInvocationError) -> tonic::Status {
    let message = format!("provider invocation result rejected: {error}");
    match error {
        ProviderInvocationError::InvocationNotFound
        | ProviderInvocationError::SessionMismatch
        | ProviderInvocationError::NotProvider
        | ProviderInvocationError::RegistryHashMismatch
        | ProviderInvocationError::CredentialGenerationMismatch
        | ProviderInvocationError::BindingGenerationMismatch
        | ProviderInvocationError::ProjectionVersionMismatch => {
            tonic::Status::permission_denied(message)
        }
        ProviderInvocationError::Session(_) => tonic::Status::failed_precondition(message),
        ProviderInvocationError::EmptyInvocationId
        | ProviderInvocationError::DuplicateInvocationId
        | ProviderInvocationError::Schema(_) => tonic::Status::invalid_argument(message),
        ProviderInvocationError::DeadlineExceeded => tonic::Status::deadline_exceeded(message),
        ProviderInvocationError::ResultTooLarge
        | ProviderInvocationError::InFlightLimitExceeded
        | ProviderInvocationError::RegistrationIdsExhausted => {
            tonic::Status::resource_exhausted(message)
        }
    }
}

fn provider_invocation_error_removes_entry(error: &ProviderInvocationError) -> bool {
    matches!(
        error,
        ProviderInvocationError::DeadlineExceeded
            | ProviderInvocationError::ResultTooLarge
            | ProviderInvocationError::Schema(_)
    )
}

fn source_command_status(error: SourceCommandError) -> tonic::Status {
    source_command_error_status(error, "source command result rejected")
}

fn source_command_dispatch_status(error: SourceCommandError) -> tonic::Status {
    source_command_error_status(error, "source command rejected")
}

fn source_command_error_status(error: SourceCommandError, message: &'static str) -> tonic::Status {
    let message = format!("{message}: {error}");
    match error {
        SourceCommandError::CommandNotFound
        | SourceCommandError::SessionMismatch
        | SourceCommandError::NotSource
        | SourceCommandError::RegistryHashMismatch
        | SourceCommandError::CredentialGenerationMismatch
        | SourceCommandError::BindingGenerationMismatch
        | SourceCommandError::InstallationConfigVersionMismatch
        | SourceCommandError::ProjectionVersionMismatch => {
            tonic::Status::permission_denied(message)
        }
        SourceCommandError::Session(_) => tonic::Status::failed_precondition(message),
        SourceCommandError::EmptyCommandId
        | SourceCommandError::DuplicateCommandId
        | SourceCommandError::Schema(_) => tonic::Status::invalid_argument(message),
        SourceCommandError::DeadlineExceeded => tonic::Status::deadline_exceeded(message),
        SourceCommandError::ResultTooLarge
        | SourceCommandError::InFlightLimitExceeded
        | SourceCommandError::RateLimited
        | SourceCommandError::RetentionCapacityExceeded
        | SourceCommandError::RegistrationIdsExhausted => {
            tonic::Status::resource_exhausted(message)
        }
    }
}

fn source_command_error_removes_entry(error: &SourceCommandError) -> bool {
    matches!(
        error,
        SourceCommandError::DeadlineExceeded
            | SourceCommandError::ResultTooLarge
            | SourceCommandError::Schema(_)
    )
}

#[cfg(all(test, feature = "external-grpc"))]
mod tests;
