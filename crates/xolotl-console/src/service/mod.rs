//! Management application service shared by transport adapters and Rust hosts.

pub(crate) mod actions;
pub(crate) mod admission;
mod audit;
mod authentication;
pub use authentication::ConsoleAuthenticationAdmission;
mod authority;
mod delivery;
mod error;
pub(crate) mod facts;
mod input;
mod installations;
mod paths;
mod runtime;
mod session;
mod source;
pub(crate) mod subscriptions;
#[cfg(feature = "http")]
pub(crate) use delivery::withheld;
pub use delivery::{ConsoleDelivery, PreparedConsoleResult};
pub use subscriptions::ConsoleSubscription;

pub(crate) use audit::*;
pub(crate) use authority::*;
pub(crate) use error::ConsoleError;
pub(crate) use input::*;
pub(crate) use paths::*;
pub(crate) use runtime::retained_runtime_completion;

use crate::auth::{self, ConsolePrincipal};
use crate::mgmt;
use crate::protocol::{self, ActionCall, ActionResult, ConsoleFailure, StreamCall};
use crate::runtime::RuntimeRequest;
use crate::state::ConsoleState;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::OwnedSemaphorePermit;
use xolotl_types::{Path, Value};

const MAX_VISIBILITY_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_VISIBILITY_TEXT_BYTES: usize = 1024;

/// Authenticated management entry point for embedded hosts and transport adapters.
/// Calls revalidate the bearer token and use the same admission as WebSocket calls.
/// Adapters validate their transport, origin and peer provenance before invoking
/// this service. Authentication methods share the host's configured credential policy.
#[derive(Clone)]
pub struct ConsoleService {
    state: Arc<ConsoleState>,
}

/// One non-clonable call reservation bound to its originating service.
///
/// A custom transport can acquire this before collecting or decoding a request.
/// Dropping it on malformed input, timeout or cancellation releases capacity.
/// Its dispatch methods consume the reservation and hold it through bearer
/// validation and action dispatch. The transport
/// still owns its frame, body timeout, connection and source-provenance checks.
#[must_use = "hold the reservation until dispatch or explicitly drop it"]
pub struct ConsoleCallAdmission<'service> {
    service: &'service ConsoleService,
    capacity: CallAdmission,
}

impl ConsoleCallAdmission<'_> {
    /// Execute a decoded action under the service that issued this reservation.
    /// `source` is host-verified audit provenance, not authority.
    pub async fn call(
        self,
        bearer: &str,
        source: Option<&str>,
        call: ActionCall,
    ) -> Result<ActionResult, ConsoleFailure> {
        self.prepare_call(bearer, source, call)
            .await?
            .deliver()
            .await
    }

    /// Prepare an action while retaining authority for a later transport handoff.
    pub async fn prepare_call(
        self,
        bearer: &str,
        source: Option<&str>,
        call: ActionCall,
    ) -> Result<PreparedConsoleResult, ConsoleFailure> {
        self.service
            .call_invocation_admitted(bearer, source, Invocation::Protocol(call), self.capacity)
            .await
    }

    /// Execute an owned Rust operation or portable program after transport admission.
    pub async fn run_runtime(
        self,
        bearer: &str,
        source: Option<&str>,
        request: RuntimeRequest,
    ) -> Result<ActionResult, ConsoleFailure> {
        let (call, typed) = runtime::request::action(request, false);
        self.service
            .call_invocation_admitted(
                bearer,
                source,
                Invocation::Runtime {
                    call,
                    typed: Box::new(typed),
                },
                self.capacity,
            )
            .await?
            .deliver()
            .await
    }

    /// Submit an owned Rust runtime execution after transport admission.
    pub async fn submit_runtime(
        self,
        bearer: &str,
        source: Option<&str>,
        request: RuntimeRequest,
    ) -> Result<ActionResult, ConsoleFailure> {
        let (call, typed) = runtime::request::action(request, true);
        self.service
            .call_invocation_admitted(
                bearer,
                source,
                Invocation::Runtime {
                    call,
                    typed: Box::new(typed),
                },
                self.capacity,
            )
            .await?
            .deliver()
            .await
    }
}

/// Cleanup obligations retained after independent execution attempts have stopped.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConsoleExecutionShutdown {
    /// Volatile executions still awaiting kernel cleanup confirmation after the
    /// bounded pass. Their records and capacity remain held for a later retry.
    pub volatile_cleanup_pending: usize,
}

impl ConsoleService {
    /// Share an existing Console host, its authentication store and registry.
    pub fn new(state: Arc<ConsoleState>) -> Self {
        Self { state }
    }

    /// Synchronously close independent submission admission without cancelling jobs.
    pub fn close_execution_admission(&self) {
        self.state.executions.close();
    }

    /// Read the original live registry instance and currently open retry epoch.
    /// This trusted local observation does not authenticate a client, reserve
    /// work, renew retention or rotate the epoch. Remote clients discover the
    /// same tuple through authenticated `runtime.describe` and retain their
    /// original identity across retries, including after host-driven closure.
    pub fn submission_retry_scope(&self) -> (String, u64) {
        self.state.executions.submission_retry_scope()
    }

    /// Close the expected volatile root-submission retry epoch and open its
    /// successor. This trusted host operation is not a client RPC. Existing
    /// records keep their acceptance evidence and cleanup custody; unknown old
    /// identities can no longer start effects. Retrying uses the original
    /// identity, never the successor epoch. Overflow changes nothing.
    pub fn close_submission_retry_epoch(&self, expected: u64) -> Result<u64, ConsoleFailure> {
        self.state
            .executions
            .close_submission_retry_epoch(expected)
            .map_err(Into::into)
    }

    /// Close submission admission, cancel jobs and await bounded finalization.
    /// Terminal records remain readable until forgotten, expired or dropped with
    /// the host. Failed cleanup retains custody for a later shutdown attempt.
    pub async fn shutdown_executions(&self) -> ConsoleExecutionShutdown {
        self.close_execution_admission();
        self.state.executions.shutdown().await;
        runtime::executions::cleanup::shutdown(&self.state).await;
        ConsoleExecutionShutdown {
            volatile_cleanup_pending: self.state.executions.pending_volatile_cleanup_count(),
        }
    }

    /// Execute one action. `source` is host-verified audit provenance, not authority.
    pub async fn call(
        &self,
        bearer: &str,
        source: Option<&str>,
        call: ActionCall,
    ) -> Result<ActionResult, ConsoleFailure> {
        self.admit_call()?.call(bearer, source, call).await
    }

    /// Prepare a result for an adapter that retains authority until disclosure.
    pub async fn prepare_call(
        &self,
        bearer: &str,
        source: Option<&str>,
        call: ActionCall,
    ) -> Result<PreparedConsoleResult, ConsoleFailure> {
        self.admit_call()?.prepare_call(bearer, source, call).await
    }

    /// Reserve shared call capacity before a custom adapter reads or decodes
    /// its request. A failed parse may simply drop the returned reservation;
    /// successful parsing consumes it with one of `ConsoleCallAdmission`'s
    /// dispatch methods.
    /// The reservation borrows this service and cannot dispatch on another one.
    pub fn admit_call(&self) -> Result<ConsoleCallAdmission<'_>, ConsoleFailure> {
        let capacity = self.reserve_call().map_err(ConsoleFailure::from)?;
        Ok(ConsoleCallAdmission {
            service: self,
            capacity,
        })
    }

    /// Execute an owned Rust operation or portable program through the same
    /// call admission, account revalidation and audit as `runtime.*` actions.
    pub async fn run_runtime(
        &self,
        bearer: &str,
        source: Option<&str>,
        request: RuntimeRequest,
    ) -> Result<ActionResult, ConsoleFailure> {
        self.admit_call()?
            .run_runtime(bearer, source, request)
            .await
    }

    /// Accept an independent Rust runtime execution under the same directory
    /// ownership, recovery and result-visibility rules as protocol submissions.
    pub async fn submit_runtime(
        &self,
        bearer: &str,
        source: Option<&str>,
        request: RuntimeRequest,
    ) -> Result<ActionResult, ConsoleFailure> {
        self.admit_call()?
            .submit_runtime(bearer, source, request)
            .await
    }

    async fn call_invocation_admitted(
        &self,
        bearer: &str,
        source: Option<&str>,
        invocation: Invocation,
        capacity: CallAdmission,
    ) -> Result<PreparedConsoleResult, ConsoleFailure> {
        let authenticated = self
            .authenticate_session(bearer)
            .await
            .map_err(ConsoleFailure::from)?;
        let principal = authenticated.principal;
        let collector = delivery::DeliveryCollector::default();
        let context = actions::ActionContext {
            state: &self.state,
            source_addr: source,
            session_id: &authenticated.sid,
            delivery: Some(&collector),
        };
        let deadline = invocation
            .call()
            .ttl_ms
            .map(|ttl| {
                crate::host_time::after(
                    self.state.boot.kernel().host_runtime(),
                    std::time::Duration::from_millis(ttl),
                )
                .map_err(ConsoleError::Runtime)
                .map_err(ConsoleFailure::from)
            })
            .transpose()?;
        match execute_invocation_admitted(&context, &principal, invocation, capacity).await {
            Ok(execution) => Ok(PreparedConsoleResult {
                result: Ok(execution.result),
                delivery: execution.delivery,
            }),
            Err(error) => {
                record_console_error_audit(&self.state, Some(&principal), source, &error);
                let invalidated = error.session_invalidated();
                Ok(PreparedConsoleResult {
                    result: Err(error.into()),
                    delivery: (!invalidated).then(|| {
                        ConsoleDelivery::new(
                            Arc::clone(&self.state),
                            authenticated.sid,
                            principal,
                            collector.take(),
                            deadline,
                        )
                    }),
                })
            }
        }
    }
}

enum Invocation {
    Protocol(ActionCall),
    Runtime {
        call: ActionCall,
        typed: Box<runtime::TypedRuntimeInput>,
    },
}

impl Invocation {
    fn call(&self) -> &ActionCall {
        match self {
            Self::Protocol(call) | Self::Runtime { call, .. } => call,
        }
    }
}

/// Reserve authentication work before any credential or session State I/O.
/// This is shared by embedded, HTTP and WebSocket entry points; CPU-bound
/// password verification and external verifiers keep their narrower budgets.
pub(crate) fn authentication_capacity(
    state: &ConsoleState,
) -> Result<OwnedSemaphorePermit, ConsoleError> {
    state
        .authentications
        .clone()
        .try_acquire_owned()
        .map_err(|_error| ConsoleError::RateLimited)
}

/// The action permit follows the request from credential verification through
/// dispatch. Its private field prevents adapters from claiming admission with
/// a placeholder value.
pub(crate) struct CallAdmission {
    _capacity: OwnedSemaphorePermit,
}

pub(crate) fn call_capacity(state: &ConsoleState) -> Result<CallAdmission, ConsoleError> {
    Ok(CallAdmission {
        _capacity: state
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_error| ConsoleError::RateLimited)?,
    })
}

pub(crate) struct Execution {
    pub result: ActionResult,
    pub delivery: Option<ConsoleDelivery>,
    /// The accepted action revoked the caller's current session.
    pub session_invalidated: bool,
}

#[cfg(test)]
pub(crate) async fn execute(
    context: &actions::ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> Result<Execution, ConsoleError> {
    let capacity = call_capacity(context.state)?;
    execute_admitted(context, principal, call, capacity).await
}

/// Execute with an action capacity reservation held by the caller. Rust and
/// WebSocket adapters acquire it before their credential State lookup.
#[cfg(any(feature = "http", test))]
pub(crate) async fn execute_admitted(
    context: &actions::ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: ActionCall,
    _capacity: CallAdmission,
) -> Result<Execution, ConsoleError> {
    execute_invocation_admitted(context, principal, Invocation::Protocol(call), _capacity).await
}

async fn execute_invocation_admitted(
    context: &actions::ActionContext<'_>,
    principal: &ConsolePrincipal,
    invocation: Invocation,
    _capacity: CallAdmission,
) -> Result<Execution, ConsoleError> {
    let collector = delivery::DeliveryCollector::default();
    let context = actions::ActionContext {
        state: context.state,
        source_addr: context.source_addr,
        session_id: context.session_id,
        delivery: Some(context.delivery.unwrap_or(&collector)),
    };
    let call = invocation.call();
    let visibility_deadline = call
        .ttl_ms
        .map(|ttl| {
            crate::host_time::after(
                context.state.boot.kernel().host_runtime(),
                std::time::Duration::from_millis(ttl),
            )
            .map_err(ConsoleError::Runtime)
        })
        .transpose()?;
    match &invocation {
        Invocation::Protocol(call) => admission::validate_call(&context.state.registry, call)?,
        Invocation::Runtime { call, .. } => {
            admission::validate_call_header(&context.state.registry, call)?;
        }
    }
    let descriptor = context
        .state
        .registry
        .action_by_id(&call.action)
        .ok_or_else(|| ConsoleError::BadRequest("unknown console action".into()))?;
    if descriptor.requires_step_up {
        require_step_up(principal)?;
    }
    Box::pin(dispatch(&context, principal, invocation))
        .await
        .and_then(|mut execution| {
            execution.result.server_rev = match server_rev(context.state) {
                Ok(revision) => revision,
                Err(error) => {
                    // A mutation or independent execution may already have been
                    // accepted. Keep its recovery identity when revision metadata
                    // cannot be reported after the actual dispatch.
                    let error = if execution.result.execution.is_some() {
                        match execution.result.output.as_ref() {
                            Some(output) => error.with_runtime_completion(
                                runtime::retained_delivery_completion(context.state, output),
                            ),
                            None => error,
                        }
                    } else {
                        error
                    };
                    let error =
                        if let Some(unresolved) = execution.result.unresolved_operations.take() {
                            error.with_unresolved_operations(*unresolved)
                        } else {
                            error
                        };
                    let error = if let Some(reference) = execution.result.execution.take() {
                        error.with_execution(*reference)
                    } else {
                        error
                    };
                    return Err(if execution.session_invalidated {
                        error.with_session_invalidation()
                    } else {
                        error
                    });
                }
            };
            if !execution.session_invalidated {
                execution.delivery = Some(ConsoleDelivery::new(
                    Arc::clone(context.state),
                    context.session_id.to_owned(),
                    principal.clone(),
                    context.delivery.and_then(|delivery| delivery.take()),
                    visibility_deadline,
                ));
            }
            Ok(execution)
        })
}

async fn dispatch(
    context: &actions::ActionContext<'_>,
    principal: &ConsolePrincipal,
    invocation: Invocation,
) -> Result<Execution, ConsoleError> {
    match invocation {
        Invocation::Protocol(call) => {
            if let Some(execution) = session::dispatch_action(context, principal, &call).await? {
                return Ok(execution);
            }
            actions::dispatch_call(context, principal, call)
                .await
                .map(|result| Execution {
                    result,
                    delivery: None,
                    session_invalidated: false,
                })
        }
        Invocation::Runtime { call, typed } => {
            let result = if matches!(
                call.action.as_str(),
                protocol::ACTION_RUNTIME_OPERATION_SUBMIT | protocol::ACTION_RUNTIME_PROGRAM_SUBMIT
            ) {
                runtime::executions::submit(context, principal, &call, Some(*typed)).await
            } else {
                runtime::run(context, principal, &call, Some(*typed)).await
            }?;
            Ok(Execution {
                result,
                delivery: None,
                session_invalidated: false,
            })
        }
    }
}

pub(crate) fn server_rev(state: &ConsoleState) -> Result<u64, ConsoleError> {
    if !state.boot.kernel().facts().is_enabled() {
        return Ok(0);
    }
    Ok(state.boot.kernel().facts().observed_cursor()?)
}

/// Intermediate response value; `execute_admitted` replaces it after the
/// action dispatch. Never deliver this hint to a client directly.
fn server_rev_hint(state: &ConsoleState) -> u64 {
    state.boot.kernel().facts().cursor()
}

pub(crate) fn registry_rev(state: &ConsoleState) -> u64 {
    state.registry.current_rev()
}

pub(crate) fn protocol_greeting(
    state: &ConsoleState,
) -> Result<protocol::ProtocolGreeting, ConsoleError> {
    Ok(protocol::protocol_greeting(
        server_rev(state)?,
        registry_rev(state),
        u64::try_from(state.boot.kernel().host_runtime().now_millis()).unwrap_or(0),
    ))
}

pub(crate) fn registry_snapshot(
    state: &ConsoleState,
) -> Result<protocol::RegistrySnapshot, ConsoleError> {
    let mut snapshot = protocol::registry_snapshot(
        server_rev(state)?,
        registry_rev(state),
        u64::try_from(state.boot.kernel().host_runtime().now_millis()).unwrap_or(0),
    );
    snapshot
        .actions
        .retain(|action| state.registry.action_enabled(&action.id));
    snapshot
        .streams
        .retain(|stream| state.registry.stream_by_id(&stream.id).is_some());
    Ok(snapshot)
}

#[cfg(test)]
pub(crate) mod tests;
