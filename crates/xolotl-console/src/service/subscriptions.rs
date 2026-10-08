//! Subscription ownership and authorization independent of the transport.

pub(crate) mod source;

use super::*;
use crate::protocol::{ConsoleEvent, ExecutionReference, STREAM_AUDIT_FACTS, STREAM_STATE_WATCH};
use crate::streams::StreamLease;
use futures_util::{StreamExt, stream::BoxStream};
use source::{NotificationSource, SourceError};
use xolotl_kernel::host::{ClockDomainError, HostDeadline};

/// An authenticated live subscription. Dropping it closes its source and cancels
/// any attached execution. Values retained after `recv` belong to the caller.
/// A subscription does not replay history or extend its visibility deadline.
pub struct ConsoleSubscription {
    state: Arc<ConsoleState>,
    sid: String,
    principal: ConsolePrincipal,
    access: Access,
    deadline: HostDeadline,
    events: Option<BoxStream<'static, Result<ConsoleEvent, ConsoleFailure>>>,
    pending: Option<ConsoleEvent>,
    lease: Option<StreamLease>,
    worker: Option<crate::host_task::HostTask<()>>,
    execution: Option<ExecutionReference>,
}

#[derive(Clone)]
pub(super) enum Access {
    State(Path),
    Facts(Option<u64>),
    Candidates(Vec<xolotl_types::Capability>),
    Runtime {
        operations: Vec<(String, Path, Option<String>)>,
        expires_at: Option<i64>,
    },
}

impl Access {
    pub(super) async fn authorize(
        &self,
        state: &ConsoleState,
        principal: &ConsolePrincipal,
    ) -> Result<(), ConsoleError> {
        require_step_up(principal)?;
        match self {
            Self::State(pattern) => {
                auth::authorize_path(&state.state, principal, "subscribe", pattern, None)
                    .await
                    .map_err(Into::into)
            }
            Self::Facts(process) => authorize_fact_read(principal, *process),
            Self::Candidates(candidates) => {
                if runtime::executions::current_candidates_allowed(
                    state,
                    &principal.grants,
                    candidates,
                ) {
                    Ok(())
                } else {
                    Err(auth::AuthError::PermissionDenied.into())
                }
            }
            Self::Runtime {
                operations,
                expires_at,
            } => {
                // A stream may deliver output after the operation that made it.
                // An earlier time-bound alternative must not keep authorizing
                // queued output merely because another selector still matches.
                if expires_at
                    .is_some_and(|until| state.boot.kernel().host_runtime().now_millis() >= until)
                {
                    return Err(auth::AuthError::PermissionDenied.into());
                }
                if operations.iter().all(|(verb, path, method)| match method {
                    Some(method) => {
                        runtime::method_allowed(state, &principal.grants, verb, path, method)
                    }
                    None => runtime::allowed(state, &principal.grants, verb, path),
                }) {
                    Ok(())
                } else {
                    Err(auth::AuthError::PermissionDenied.into())
                }
            }
        }
    }
}

impl ConsoleSubscription {
    /// Retain this subscription's authority through adapter queue/readiness waits.
    pub fn delivery_authority(&self) -> super::ConsoleDelivery {
        super::ConsoleDelivery::new(
            Arc::clone(&self.state),
            self.sid.clone(),
            self.principal.clone(),
            Some(self.access.clone()),
            Some(self.deadline),
        )
    }
    /// Allocated runtime execution, available before the first event and after
    /// closure. A reference alone does not authorize process or Fact reads.
    pub fn execution(&self) -> Option<&ExecutionReference> {
        self.execution.as_ref()
    }

    /// Original visibility deadline, also enforced while waiting for an event.
    pub fn deadline(&self) -> HostDeadline {
        self.deadline
    }

    /// Time left for an adapter's own delivery timer. Service authorization
    /// always checks the original host-clock deadline again before disclosure.
    pub fn remaining_visibility(&self) -> Result<std::time::Duration, ClockDomainError> {
        self.deadline
            .saturating_duration_since(self.state.boot.kernel().host_runtime().now())
    }

    /// Receive one event after revalidating the session and current authority.
    /// Returns `None` after normal completion or closure. A terminal error is
    /// returned once; transient authentication-capacity rejection keeps the
    /// pending event for a retry. Cancelling this future does the same.
    pub async fn recv(&mut self) -> Result<Option<ConsoleEvent>, ConsoleFailure> {
        if self.events.is_none() {
            return Ok(None);
        }
        let runtime = self.state.boot.kernel().host_runtime().clone();
        if crate::host_time::elapsed(&runtime, self.deadline).map_err(|failure| {
            self.failure_context(ConsoleFailure::from(ConsoleError::Runtime(failure)))
        })? {
            self.stop();
            return Err(self.failure_context(expired()));
        }
        let result = crate::host_time::timeout_at(&runtime, self.deadline, self.receive()).await;
        let result = match result {
            Ok(result)
                if !crate::host_time::elapsed(&runtime, self.deadline).map_err(|failure| {
                    self.failure_context(ConsoleFailure::from(ConsoleError::Runtime(failure)))
                })? =>
            {
                result
            }
            Ok(_) | Err(_) => Err(expired()),
        };
        let authentication_busy = matches!(
            &result,
            Err(failure) if failure.code == protocol::ConsoleErrorCode::RateLimited
        );
        if !matches!(result, Ok(Some(_))) && !authentication_busy {
            self.stop();
        }
        result.map_err(|failure| self.failure_context(failure))
    }

    fn failure_context(&self, mut failure: ConsoleFailure) -> ConsoleFailure {
        if failure.execution.is_none() {
            failure.execution = self.execution.clone().map(Box::new);
        }
        failure
    }

    async fn receive(&mut self) -> Result<Option<ConsoleEvent>, ConsoleFailure> {
        if self.pending.is_none() {
            let Some(events) = self.events.as_mut() else {
                return Ok(None);
            };
            self.pending = events.next().await.transpose()?;
        }
        if self.pending.is_none() {
            return Ok(None);
        }
        let _capacity =
            super::authentication_capacity(&self.state).map_err(ConsoleFailure::from)?;
        let principal = self
            .state
            .auth
            .validate_sid(&self.state.boot, &self.sid)
            .await?;
        if principal != self.principal {
            return Err(ConsoleFailure::new(
                protocol::ConsoleErrorCode::Forbidden,
                "subscription authority changed; open a new subscription".into(),
            ));
        }
        self.access
            .authorize(&self.state, &principal)
            .await
            .map_err(ConsoleFailure::from)?;
        if let Some(event) = &self.pending {
            validate_event(event, self.state.streams.max_event_bytes())?;
        }
        Ok(self.pending.take())
    }

    /// Close and join attached execution, releasing capacity and queued values.
    /// Dropping the subscription also requests cancellation without waiting.
    pub async fn close(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _completed = worker.await;
        }
    }

    fn stop(&mut self) {
        self.events = None;
        self.pending = None;
        self.lease = None;
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

fn expired() -> ConsoleFailure {
    ConsoleFailure::new(
        protocol::ConsoleErrorCode::Forbidden,
        "subscription visibility expired".into(),
    )
}

pub(super) fn validate_event(event: &ConsoleEvent, limit: usize) -> Result<(), ConsoleFailure> {
    crate::wire::validate_event(event, limit).map_err(|_error| {
        ConsoleFailure::new(
            protocol::ConsoleErrorCode::Internal,
            "subscription event exceeds host delivery limits; effects may have occurred".into(),
        )
    })
}

impl Drop for ConsoleSubscription {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ConsoleService {
    /// Open a subscription using the same admission as WebSocket. `source` is
    /// host-verified audit provenance. Reconnect by creating a new subscription;
    /// a runtime subscription is an execution and must not be retried blindly.
    pub async fn subscribe(
        &self,
        bearer: &str,
        source: Option<&str>,
        stream: StreamCall,
    ) -> Result<ConsoleSubscription, ConsoleFailure> {
        self.subscribe_invocation(bearer, source, stream, None)
            .await
    }

    /// Open a Rust runtime subscription without serializing an owned program.
    /// It retains the same visibility lease, account revalidation and bounded
    /// delivery behavior as the protocol stream.
    pub async fn subscribe_runtime(
        &self,
        bearer: &str,
        source: Option<&str>,
        request: crate::runtime::RuntimeRequest,
    ) -> Result<ConsoleSubscription, ConsoleFailure> {
        let (stream, typed) = runtime::request::stream(request);
        self.subscribe_invocation(bearer, source, stream, Some(typed))
            .await
    }

    async fn subscribe_invocation(
        &self,
        bearer: &str,
        source: Option<&str>,
        stream: StreamCall,
        typed: Option<runtime::TypedRuntimeInput>,
    ) -> Result<ConsoleSubscription, ConsoleFailure> {
        let authenticated = self
            .authenticate_session(bearer)
            .await
            .map_err(ConsoleFailure::from)?;
        open(
            &self.state,
            &authenticated.principal,
            &authenticated.sid,
            source,
            stream,
            typed,
        )
        .await
        .map_err(|error| {
            record_console_error_audit(&self.state, Some(&authenticated.principal), source, &error);
            error.into()
        })
    }
}

pub(crate) async fn open(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    sid: &str,
    source: Option<&str>,
    stream: StreamCall,
    typed: Option<runtime::TypedRuntimeInput>,
) -> Result<ConsoleSubscription, ConsoleError> {
    if stream
        .registry_rev
        .is_some_and(|revision| revision != state.registry.current_rev())
    {
        return Err(ConsoleError::RegistryChanged {
            current_registry_rev: state.registry.current_rev(),
        });
    }
    if typed.is_some() {
        admission::validate_stream_header(&state.registry, &stream)?;
    } else {
        admission::validate_stream(&state.registry, &stream)?;
    }
    require_stream_visibility_access(principal, &stream)?;
    let deadline = state
        .boot
        .kernel()
        .host_runtime()
        .deadline_after(std::time::Duration::from_millis(
            stream.ttl_ms.unwrap_or_default(),
        ))
        .ok_or_else(|| {
            ConsoleError::BadRequest("subscription visibility deadline is not representable".into())
        })?;
    let lease = state.streams.acquire(principal.account_key())?;
    let mut worker = None;
    let mut execution = None;
    let (access, events) = match stream.stream.as_str() {
        STREAM_STATE_WATCH => {
            let mut input = input_map(input_value(&stream.input)?)?;
            let pattern = Path::parse(&string_arg(&mut input, "pattern")?)?;
            ensure_observable_state_path(&pattern)?;
            let access = Access::State(pattern.clone());
            let authentication = super::authentication_capacity(state)?;
            access.authorize(state, principal).await?;
            let receiver = state.state.subscribe(&pattern).await?;
            drop(authentication);
            record_visibility_audit(
                state,
                principal,
                source,
                "state_watch",
                VisibilityAuditDetails::stream(&stream, Some(&pattern.to_string())),
            )?;
            (
                access,
                projected(receiver, |event| Ok(Some(ConsoleEvent::from(event)))),
            )
        }
        STREAM_AUDIT_FACTS => {
            let mut input = input_map(input_value(&stream.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?;
            let access = Access::Facts(process);
            access.authorize(state, principal).await?;
            let max_bytes =
                facts::byte_limit(&state.queries, optional_usize_arg(&mut input, "max_bytes")?)?;
            let target = process
                .map(|pid| fact_path(pid).map(|path| path.to_string()))
                .transpose()?
                .unwrap_or_else(|| "state://fact".into());
            record_visibility_audit(
                state,
                principal,
                source,
                "audit_facts_stream",
                VisibilityAuditDetails::stream(&stream, Some(&target)),
            )?;
            let sink = state.boot.kernel().facts().clone();
            let receiver = sink.store().subscribe_facts();
            (
                access,
                projected(receiver, facts::live_projection(sink, process, max_bytes)),
            )
        }
        protocol::STREAM_RUNTIME_OPERATION | protocol::STREAM_RUNTIME_PROGRAM => {
            let runtime =
                runtime::stream(state, principal, sid, source, &stream, deadline, typed).await?;
            worker = Some(runtime.worker);
            execution = Some(runtime.execution);
            (runtime.authority, runtime.events)
        }
        _ => return Err(ConsoleError::BadRequest("unknown console stream".into())),
    };
    Ok(ConsoleSubscription {
        state: state.clone(),
        sid: sid.into(),
        principal: principal.clone(),
        access,
        deadline,
        events: Some(events),
        pending: None,
        lease: Some(lease),
        worker,
        execution,
    })
}

fn projected<S, P>(
    source: S,
    mut project: P,
) -> BoxStream<'static, Result<ConsoleEvent, ConsoleFailure>>
where
    S: NotificationSource,
    P: FnMut(S::Event) -> Result<Option<ConsoleEvent>, &'static str> + Send + 'static,
{
    source
        .into_events()
        .filter_map(move |event| {
            let event = match event {
                Ok(event) => project(event).map_err(str::to_owned),
                Err(SourceError::Closed) => Err("notification source closed".into()),
                Err(SourceError::Lagged(count)) => Err(format!(
                    "stream lagged by {count} notifications; resynchronize and subscribe again"
                )),
                Err(SourceError::Invalidated) => {
                    Err("notification source invalidated; reread and subscribe again".into())
                }
                Err(SourceError::Failed) => Err("notification source failed".into()),
                #[cfg(feature = "http")]
                Err(SourceError::Rejected(failure)) => {
                    return std::future::ready(Some(Err(failure)));
                }
            };
            std::future::ready(event.transpose().map(|result| {
                result.map_err(|reason| {
                    ConsoleFailure::new(protocol::ConsoleErrorCode::Internal, reason)
                })
            }))
        })
        .boxed()
}

#[cfg(test)]
mod tests;
