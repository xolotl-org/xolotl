//! Provider remote endpoint dispatch and invocation lifecycle.

use super::*;
use xolotl_kernel::driver::RemoteEndpoint;

pub(super) struct ProviderRoleEndpoint {
    pub(super) state: Backend,
    pub(super) source_store: Arc<dyn SourceStore>,
    pub(super) context: SessionContext,
    pub(super) session: EndpointSession,
    pub(super) outbound: ExternalSessionOutboundHandle,
    pub(super) provider_invocations: Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    pub(super) provider_waiters:
        Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    pub(super) provider_sessions:
        Arc<std::sync::Mutex<BTreeMap<ProviderSessionKey, ProviderSessionRecord>>>,
    pub(super) session_limits: config::ExternalGatewaySessionLimits,
}

/// Own one in-flight registration across every suspension point in `invoke`.
/// A cancelled caller drops this guard before its provider can reply. The
/// registration identity prevents an old future from removing a newer use of
/// the same invocation id.
struct PendingProviderInvocation<'a> {
    invocation_id: String,
    registration_id: u64,
    invocations: &'a Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    waiters: &'a Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    outbound: &'a ExternalSessionOutboundHandle,
    send_started: bool,
    completed: bool,
    cancel_reason: &'static str,
}

impl PendingProviderInvocation<'_> {
    fn remove_owned(&self) -> bool {
        let mut invocations = match self.invocations.lock() {
            Ok(invocations) => invocations,
            Err(poisoned) => {
                tracing::warn!(invocation_id = %self.invocation_id, "provider invocation registry was poisoned during cleanup");
                poisoned.into_inner()
            }
        };
        if !invocations.remove_if(&self.invocation_id, self.registration_id) {
            return false;
        }
        // Every Provider path takes these locks in this order and changes the
        // registration and waiter before releasing either lock.
        match self.waiters.lock() {
            Ok(mut waiters) => {
                waiters.remove(&self.invocation_id);
            }
            Err(poisoned) => {
                tracing::warn!(invocation_id = %self.invocation_id, "provider invocation waiter registry was poisoned during cleanup");
                poisoned.into_inner().remove(&self.invocation_id);
            }
        }
        true
    }
}

impl Drop for PendingProviderInvocation<'_> {
    fn drop(&mut self) {
        let owned = self.remove_owned();
        if self.completed || !self.send_started || !owned {
            return;
        }
        let frame = ControlFrame::ProviderCancel {
            invocation_id: self.invocation_id.clone(),
            reason: self.cancel_reason.into(),
        };
        if self.outbound.enqueue_cancel(frame).is_err() {
            tracing::warn!(invocation_id = %self.invocation_id, "provider cancellation queue rejected frame");
        }
    }
}

#[async_trait::async_trait]
impl RemoteEndpoint for ProviderRoleEndpoint {
    async fn invoke(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: Invoke,
    ) -> Result<InvokeResult, DriverError> {
        let deadline = invoke
            .deadline_ms
            .map(|deadline| ExternalCallDeadline::new(deadline, now_millis()))
            .transpose()
            .map_err(status_to_driver_error)?;
        let authority = load_external_authority(
            &self.state,
            &self.context.installation_id,
            &self.context.projection_id,
            Role::Provider,
            self.source_store.as_ref(),
        )
        .await
        .map_err(status_to_driver_error)?;
        if !context_matches_authority(&authority.context, &self.context) {
            return Err(DriverError::Transport("provider authority changed".into()));
        }
        let capability = self.admit_invoke(dispatch, &invoke, &authority)?;
        validate_json_schema(capability.input_schema.as_ref(), &invoke.input).map_err(|error| {
            DriverError::Transport(format!("provider invoke input rejected: {error}"))
        })?;
        let output_schema = capability.output_schema.as_ref();
        let invocation_id = invoke.invocation_id.clone();

        let (tx, rx) = oneshot::channel();
        let registration_id = {
            let mut invocations = self.provider_invocations.lock().map_err(|_error| {
                DriverError::Transport("provider invocation registry unavailable".into())
            })?;
            let mut waiters = self.provider_waiters.lock().map_err(|_error| {
                DriverError::Transport("provider invocation waiter unavailable".into())
            })?;
            let registration_id = invocations
                .register(ProviderInvocationRegister {
                    session: &self.session,
                    invoke: &invoke,
                    current_registry_hash: &authority.context.registry_hash,
                    credential_generation: authority.context.credential_generation,
                    current_binding_generation: authority.context.binding_generation,
                    current_projection_version: authority.context.projection_version,
                    now_millis: now_millis(),
                    acting: dispatch.acting,
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
                .map_err(|error| DriverError::Transport(error.to_string()))?;
            match waiters.entry(invocation_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(tx);
                    registration_id
                }
                Entry::Occupied(_) => {
                    invocations.remove_if(&invocation_id, registration_id);
                    return Err(DriverError::Transport(
                        "provider invocation waiter duplicate".into(),
                    ));
                }
            }
        };

        let mut pending = PendingProviderInvocation {
            invocation_id: invocation_id.clone(),
            registration_id,
            invocations: &self.provider_invocations,
            waiters: &self.provider_waiters,
            outbound: &self.outbound,
            send_started: false,
            completed: false,
            cancel_reason: "cancelled",
        };

        if deadline.is_some_and(ExternalCallDeadline::expired) {
            return Err(DriverError::Transport(
                "provider invoke deadline exceeded before send".into(),
            ));
        }
        pending.send_started = true;
        let operation = async {
            self.outbound
                .send_invoke(invoke)
                .await
                .map_err(|_error| ProviderAwaitError::ProviderUnavailable)?;
            await_provider_result(rx).await
        };
        let outcome = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline.monotonic, operation)
                .await
                .unwrap_or(Err(ProviderAwaitError::DeadlineExceeded)),
            None => operation.await,
        };
        match outcome {
            Ok(result) => {
                pending.completed = true;
                Ok(result)
            }
            Err(error) => {
                pending.cancel_reason = error.reason();
                Err(error.into_driver_error(invocation_id))
            }
        }
    }
}

impl ProviderRoleEndpoint {
    fn admit_invoke<'a>(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: &Invoke,
        authority: &'a ExternalAuthority,
    ) -> Result<&'a EffectCapability, DriverError> {
        if invoke.method_id != dispatch.method_id {
            return Err(DriverError::Transport(
                "provider invoke method rejected".into(),
            ));
        }
        let sessions = self.provider_sessions.lock().map_err(|_error| {
            DriverError::Transport("provider session registry unavailable".into())
        })?;
        let session = sessions
            .get(&provider_session_key(&self.context))
            .ok_or_else(|| DriverError::Transport("provider session not ready".into()))?;
        if session.context != self.context {
            return Err(DriverError::Transport(
                "provider session context rejected".into(),
            ));
        }
        if dispatch.endpoint_id != session.endpoint_id {
            return Err(DriverError::Transport(
                "provider invoke effect rejected".into(),
            ));
        }
        let Some(ready_path) = session
            .ready_endpoints
            .get(&ProviderEndpointKey::from_dispatch(dispatch))
        else {
            if session.ready_endpoints.keys().any(|key| {
                key.resource_id == dispatch.resource_id
                    && key.binding_generation == dispatch.binding_generation
            }) {
                return Err(DriverError::Transport(
                    "provider invoke method rejected".into(),
                ));
            }
            return Err(DriverError::Transport(
                "provider invoke effect rejected".into(),
            ));
        };
        if ready_path != &invoke.effect_path {
            return Err(DriverError::Transport(
                "provider invoke effect rejected".into(),
            ));
        }
        authority
            .provider_capabilities
            .get(ready_path)
            .ok_or_else(|| DriverError::Transport("provider invoke effect rejected".into()))
    }
}

pub(super) async fn await_provider_result(
    rx: oneshot::Receiver<InvokeResult>,
) -> Result<InvokeResult, ProviderAwaitError> {
    rx.await
        .map_err(|_error| ProviderAwaitError::ProviderUnavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProviderAwaitError {
    DeadlineExceeded,
    ProviderUnavailable,
}

impl ProviderAwaitError {
    fn reason(self) -> &'static str {
        match self {
            ProviderAwaitError::DeadlineExceeded => "deadline_exceeded",
            ProviderAwaitError::ProviderUnavailable => "delivery_or_session_lost",
        }
    }

    pub(super) fn into_driver_error(self, operation_id: String) -> DriverError {
        DriverError::OutcomeUnknown {
            operation_id,
            reason: self.reason().into(),
        }
    }
}
