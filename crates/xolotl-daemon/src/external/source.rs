//! One Source command lifecycle shared by all external transports.

use super::*;
use xolotl_gateway::external::{
    SourceCommandMaintenanceReport, SourceCommandRegister, SourceCommandRegistry,
    SourceCommandResolve,
};

type SourceProjectionKey = (String, String);
const MAX_SOURCE_COMMAND_WAIT_MS: i64 = 60_000;

#[derive(Clone)]
pub(super) struct SourceCommandHub {
    state: Backend,
    source_store: Arc<dyn SourceStore>,
    inner: Arc<std::sync::Mutex<SourceHubState>>,
}

#[derive(Default)]
struct SourceHubState {
    sessions: BTreeMap<SourceProjectionKey, BTreeMap<String, Arc<ReadySourceSession>>>,
    commands: SourceCommandRegistry,
    waiters: BTreeMap<String, oneshot::Sender<CommandResult>>,
}

struct ReadySourceSession {
    session: EndpointSession,
    context: SessionContext,
    outbound: ExternalSessionOutboundHandle,
    limits: config::ExternalGatewaySessionLimits,
}

#[derive(Debug)]
pub(super) enum SourceDispatchError {
    /// Authority, routing, or command admission rejected the operation before send.
    Rejected(tonic::Status),
    /// Send may have started. No v1 Source cancel or durable receipt can settle the outcome.
    OutcomeUnknown {
        command_id: String,
        cause: tonic::Status,
    },
}

impl std::fmt::Display for SourceDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(status) => write!(formatter, "source command rejected: {status}"),
            Self::OutcomeUnknown { command_id, cause } => {
                write!(
                    formatter,
                    "source command {command_id} outcome unknown: {cause}"
                )
            }
        }
    }
}

impl std::error::Error for SourceDispatchError {}

pub(super) struct PendingSourceCommand {
    command_id: String,
    registration_id: u64,
    inner: Arc<std::sync::Mutex<SourceHubState>>,
    outbound: ExternalSessionOutboundHandle,
    receiver: oneshot::Receiver<CommandResult>,
    command: Option<OutboundCommand>,
    deadline: Option<ExternalCallDeadline>,
    send_started: bool,
    completed: bool,
}

impl PendingSourceCommand {
    pub(super) async fn send(&mut self) -> Result<(), SourceDispatchError> {
        if !self.send_started && self.deadline.is_some_and(ExternalCallDeadline::expired) {
            return Err(SourceDispatchError::Rejected(
                tonic::Status::deadline_exceeded("source command deadline exceeded before send"),
            ));
        }
        let Some(command) = self.command.take() else {
            return Err(self.unknown(tonic::Status::failed_precondition(
                "Source command send already started",
            )));
        };
        self.send_started = true;
        self.outbound
            .send_outbound_command(command)
            .await
            .map_err(|cause| self.unknown(cause))
    }

    #[cfg(all(test, feature = "external-grpc"))]
    pub(super) async fn wait(&mut self) -> Result<CommandResult, SourceDispatchError> {
        let Some(deadline) = self.deadline else {
            return self.wait_result().await;
        };
        let result = tokio::select! {
            biased;
            result = self.wait_result() => Some(result),
            () = tokio::time::sleep_until(deadline.monotonic) => None,
        };
        result.unwrap_or_else(|| {
            Err(self.unknown(tonic::Status::deadline_exceeded(
                "source command deadline exceeded; remote outcome unknown",
            )))
        })
    }

    async fn wait_result(&mut self) -> Result<CommandResult, SourceDispatchError> {
        let result = (&mut self.receiver).await;
        let result = result.map_err(|_error| {
            self.unknown(tonic::Status::unavailable(
                "source command session closed; remote outcome unknown",
            ))
        })?;
        self.completed = true;
        Ok(result)
    }

    fn unknown(&self, cause: tonic::Status) -> SourceDispatchError {
        SourceDispatchError::OutcomeUnknown {
            command_id: self.command_id.clone(),
            cause,
        }
    }
}

impl Drop for PendingSourceCommand {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = match self.inner.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                tracing::warn!(command_id = %self.command_id, "Source command hub was poisoned during cleanup");
                poisoned.into_inner()
            }
        };
        let removed = if self.send_started {
            state
                .commands
                .retire_if(&self.command_id, self.registration_id, now_millis())
        } else {
            state
                .commands
                .remove_if(&self.command_id, self.registration_id)
        };
        if removed {
            state.waiters.remove(&self.command_id);
        }
    }
}

impl SourceCommandHub {
    pub(super) fn new(
        state: Backend,
        source_store: Arc<dyn SourceStore>,
        capacity: std::num::NonZeroUsize,
    ) -> Self {
        Self {
            state,
            source_store,
            inner: Arc::new(std::sync::Mutex::new(SourceHubState {
                commands: SourceCommandRegistry::with_capacity(capacity),
                ..SourceHubState::default()
            })),
        }
    }

    pub(super) fn expire_retained(
        &self,
        now_millis: i64,
    ) -> Result<SourceCommandMaintenanceReport, tonic::Status> {
        Ok(self.lock()?.commands.expire_retained(now_millis))
    }

    pub(super) fn register_ready(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: ExternalSessionOutboundHandle,
        limits: config::ExternalGatewaySessionLimits,
    ) -> Result<(), tonic::Status> {
        if !session.is_ready()
            || session.context() != Some(&context)
            || context.role != Role::Source
        {
            return Err(tonic::Status::failed_precondition(
                "source session not ready",
            ));
        }
        let key = (
            context.installation_id.clone(),
            context.projection_id.clone(),
        );
        let mut state = self.lock()?;
        if state
            .sessions
            .get(&key)
            .and_then(|sessions| sessions.get(&context.session_id))
            .is_some()
        {
            // Session ids are daemon-generated once per connection. Refusing
            // a second Ready for the same id keeps an old connection's Close
            // from removing a replacement that happens to reuse its context.
            return Err(tonic::Status::already_exists(
                "source session id already ready",
            ));
        }
        state.sessions.entry(key).or_default().insert(
            context.session_id.clone(),
            Arc::new(ReadySourceSession {
                session: session.clone(),
                context,
                outbound,
                limits,
            }),
        );
        Ok(())
    }

    pub(super) fn close(&self, context: &SessionContext) -> Result<(), tonic::Status> {
        let key = (
            context.installation_id.clone(),
            context.projection_id.clone(),
        );
        let mut state = self.lock()?;
        let mut removed = false;
        if let Some(sessions) = state.sessions.get_mut(&key) {
            if sessions
                .get(&context.session_id)
                .is_some_and(|record| record.context == *context)
            {
                sessions.remove(&context.session_id);
                removed = true;
            }
            if sessions.is_empty() {
                state.sessions.remove(&key);
            }
        }
        if removed {
            for id in state.commands.drain_for_session(context, now_millis()) {
                state.waiters.remove(&id);
            }
        }
        Ok(())
    }

    pub(super) fn resolve(
        &self,
        result: CommandResult,
        session: &EndpointSession,
        context: &SessionContext,
        authority: &ExternalAuthority,
    ) -> Result<(), tonic::Status> {
        let result_id = result.id.clone();
        let mut state = self.lock()?;
        let key = (
            context.installation_id.clone(),
            context.projection_id.clone(),
        );
        if !state.sessions.get(&key).is_some_and(|sessions| {
            sessions
                .get(&context.session_id)
                .is_some_and(|record| record.context == *context)
        }) {
            return Err(tonic::Status::permission_denied(
                "source session is not ready",
            ));
        }
        let accepted = match state.commands.resolve(SourceCommandResolve {
            session,
            result,
            current_registry_hash: &authority.context.registry_hash,
            credential_generation: authority.context.credential_generation,
            current_binding_generation: authority.context.binding_generation,
            current_installation_config_version: authority.context.installation_config_version,
            current_projection_version: authority.context.projection_version,
            now_millis: now_millis(),
        }) {
            Ok(accepted) => accepted,
            Err(error) => {
                if source_command_error_removes_entry(&error) {
                    state.waiters.remove(&result_id);
                }
                return Err(source_command_status(error));
            }
        };
        let waiter = state
            .waiters
            .remove(&accepted.id)
            .ok_or_else(|| tonic::Status::failed_precondition("source command waiter missing"))?;
        // Dropping the lock before waking the caller keeps response processing
        // independent of command registration and close.
        drop(state);
        waiter
            .send(accepted)
            .map_err(|_error| tonic::Status::unavailable("source command receiver closed"))
    }

    /// Dispatch only when one ready Source session names this projection.
    /// The caller is a trusted Kernel endpoint, not an external HTTP adapter.
    pub(super) async fn dispatch_for_projection(
        &self,
        installation_id: &str,
        projection_id: &str,
        command: OutboundCommand,
        deadline_ms: Option<i64>,
    ) -> Result<CommandResult, SourceDispatchError> {
        let authority = load_external_authority(
            &self.state,
            installation_id,
            projection_id,
            Role::Source,
            self.source_store.as_ref(),
        )
        .await
        .map_err(SourceDispatchError::Rejected)?;
        // A caller may omit its own deadline, but a connected Source must not
        // hold daemon capacity forever. A shorter caller deadline still wins.
        let host_deadline = now_millis().saturating_add(MAX_SOURCE_COMMAND_WAIT_MS);
        let deadline_ms =
            Some(deadline_ms.map_or(host_deadline, |deadline| deadline.min(host_deadline)));
        let mut pending = self.begin_for_projection(command, deadline_ms, &authority)?;
        self.run(&mut pending).await
    }

    async fn run(
        &self,
        pending: &mut PendingSourceCommand,
    ) -> Result<CommandResult, SourceDispatchError> {
        if let Some(deadline) = pending.deadline {
            let operation = async {
                pending.send().await?;
                pending.wait_result().await
            };
            let result = tokio::select! {
                biased;
                result = operation => Some(result),
                () = tokio::time::sleep_until(deadline.monotonic) => None,
            };
            match result {
                Some(result) => result,
                None if pending.send_started => {
                    Err(pending.unknown(tonic::Status::deadline_exceeded(
                        "source command deadline exceeded; remote outcome unknown",
                    )))
                }
                None => Err(SourceDispatchError::Rejected(
                    tonic::Status::deadline_exceeded(
                        "source command deadline exceeded before send",
                    ),
                )),
            }
        } else {
            pending.send().await?;
            pending.wait_result().await
        }
    }

    fn begin_for_projection(
        &self,
        command: OutboundCommand,
        deadline_ms: Option<i64>,
        authority: &ExternalAuthority,
    ) -> Result<PendingSourceCommand, SourceDispatchError> {
        let key = (
            authority.context.installation_id.clone(),
            authority.context.projection_id.clone(),
        );
        let mut state = self.lock().map_err(SourceDispatchError::Rejected)?;
        let sessions = state.sessions.get(&key).ok_or_else(|| {
            SourceDispatchError::Rejected(tonic::Status::failed_precondition(
                "source projection has no ready session",
            ))
        })?;
        let mut eligible = sessions
            .values()
            .filter(|record| context_matches_authority(&authority.context, &record.context));
        let record = eligible.next().ok_or_else(|| {
            SourceDispatchError::Rejected(tonic::Status::failed_precondition(
                "source projection has no current ready session",
            ))
        })?;
        if eligible.next().is_some() {
            return Err(SourceDispatchError::Rejected(
                tonic::Status::failed_precondition(
                    "source projection has ambiguous ready sessions",
                ),
            ));
        }
        let selected = record.clone();
        self.register_pending(&mut state, command, deadline_ms, authority, selected)
            .map_err(SourceDispatchError::Rejected)
    }

    fn register_pending(
        &self,
        state: &mut SourceHubState,
        mut command: OutboundCommand,
        deadline_ms: Option<i64>,
        authority: &ExternalAuthority,
        selected: Arc<ReadySourceSession>,
    ) -> Result<PendingSourceCommand, tonic::Status> {
        if !context_matches_authority(&authority.context, &selected.context) {
            return Err(tonic::Status::permission_denied(
                "source command authority changed",
            ));
        }
        let emits = authority
            .projection
            .emits
            .as_ref()
            .filter(|emits| emits.commands)
            .ok_or_else(|| tonic::Status::permission_denied("source commands are disabled"))?;
        command.observed = ObservedGenerations {
            presentation_config_generation: selected.context.presentation_config_generation,
            alias_catalog_generation: selected.context.alias_catalog_generation,
        };
        let (tx, rx) = oneshot::channel();
        let admitted_at = now_millis();
        let deadline = deadline_ms
            .map(|deadline| ExternalCallDeadline::new(deadline, admitted_at))
            .transpose()?;
        let registration_id = state
            .commands
            .register(SourceCommandRegister {
                session: &selected.session,
                command: &command,
                current_registry_hash: &authority.context.registry_hash,
                credential_generation: authority.context.credential_generation,
                current_binding_generation: authority.context.binding_generation,
                current_installation_config_version: authority.context.installation_config_version,
                current_projection_version: authority.context.projection_version,
                now_millis: admitted_at,
                deadline_ms,
                max_in_flight: Some(selected.limits.source_max_in_flight_commands),
                max_inline_result_bytes: Some(
                    selected.limits.source_command_max_inline_result_bytes,
                ),
                idempotency_window_ms: selected.limits.source_dedupe_window_ms,
                rate_limit_window_ms: selected.limits.source_command_rate_limit_window_ms,
                rate_limit_max_commands: selected.limits.source_command_rate_limit_max,
                command_schema: emits.command_schema.as_ref(),
                command_result_schema: emits.command_result_schema.as_ref(),
            })
            .map_err(source_command_dispatch_status)?;
        match state.waiters.entry(command.id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(tx);
            }
            Entry::Occupied(_) => {
                state.commands.remove_if(&command.id, registration_id);
                return Err(tonic::Status::internal("source command waiter duplicate"));
            }
        }
        Ok(PendingSourceCommand {
            command_id: command.id.clone(),
            registration_id,
            inner: Arc::clone(&self.inner),
            outbound: Arc::clone(&selected.outbound),
            receiver: rx,
            command: Some(command),
            deadline,
            send_started: false,
            completed: false,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SourceHubState>, tonic::Status> {
        self.inner
            .lock()
            .map_err(|_error| tonic::Status::internal("source command hub unavailable"))
    }

    #[cfg(all(test, feature = "external-grpc"))]
    pub(super) async fn begin_for_session(
        &self,
        command: OutboundCommand,
        session: &EndpointSession,
        context: &SessionContext,
        deadline_ms: Option<i64>,
    ) -> Result<PendingSourceCommand, tonic::Status> {
        let authority = load_external_authority(
            &self.state,
            &context.installation_id,
            &context.projection_id,
            Role::Source,
            self.source_store.as_ref(),
        )
        .await?;
        let mut state = self.lock()?;
        let key = (
            context.installation_id.clone(),
            context.projection_id.clone(),
        );
        let record = state
            .sessions
            .get(&key)
            .and_then(|sessions| sessions.get(&context.session_id))
            .ok_or_else(|| tonic::Status::failed_precondition("source session not ready"))?;
        if record.context != *context || session.context() != Some(context) {
            return Err(tonic::Status::permission_denied(
                "source session context rejected",
            ));
        }
        let selected = record.clone();
        self.register_pending(&mut state, command, deadline_ms, &authority, selected)
    }

    #[cfg(all(test, feature = "external-grpc"))]
    pub(super) fn occupied(&self) -> Result<usize, tonic::Status> {
        Ok(self.lock()?.commands.occupied())
    }

    #[cfg(all(test, feature = "external-grpc"))]
    pub(super) fn counts(&self) -> Result<(usize, usize, usize), tonic::Status> {
        let state = self.lock()?;
        Ok((
            state.sessions.values().map(BTreeMap::len).sum(),
            state.commands.len(),
            state.waiters.len(),
        ))
    }
}
