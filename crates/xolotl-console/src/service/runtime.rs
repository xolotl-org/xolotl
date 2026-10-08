//! Runtime action entry points and shared capability policy.

use super::{actions::ActionContext, *};
use crate::auth::{AuthError, ConsolePrincipal};
use crate::protocol::{
    ACTION_RUNTIME_OPERATION_INVOKE, ActionCall, ConsoleErrorCode, ExecutionReference,
};
use std::{collections::HashSet, time::Duration};
#[cfg(test)]
use xolotl_graph::portable::{Expression, Program};
use xolotl_graph::{OperationTemplate, WaitSpec, portable::Import};
use xolotl_kernel::host::HostDeadline;
use xolotl_kernel::{CompiledRequestGrantTemplate, PreparedProgram};
use xolotl_types::{
    CapSet, ExecutionOutput, Failure, Interface, Outcome, OutputMode, ResourceName, TaintSet,
    TaintedValue, UnresolvedOperations,
};

mod discovery;
mod modes;
use modes::ExecutionMode;
mod plan;
use plan::{AdmittedOperation, Plan, admit_operation, output_supported, plan, signal_operation};
pub(super) mod request;
pub(super) use request::TypedRuntimeInput;

pub(super) fn describe(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
) -> Result<Value, ConsoleError> {
    let (registry_instance, retry_epoch) = state.executions.submission_retry_scope();
    Ok(map_value([
        (
            "submission_retry_scope",
            map_value([
                ("registry_instance", Value::string(registry_instance)),
                ("retry_epoch", Value::string(retry_epoch.to_string())),
            ]),
        ),
        (
            "config",
            serde_value(crate::runtime::PublicRuntimeConfig::from(
                &state.runtime.config,
            ))?,
        ),
        ("subscription_limits", serde_value(state.streams.config())?),
        (
            "source_version",
            Value::integer(i64::from(xolotl_graph::portable::SOURCE_VERSION)),
        ),
        ("execution_modes", modes::describe(state)),
        (
            "supported_imports",
            Value::list(
                [
                    "operation",
                    "module",
                    "transform",
                    "acting",
                    "wait_deadline",
                    "wait_signal",
                ]
                .map(|s| Value::string(s.into()))
                .into(),
            ),
        ),
        ("atomic", Value::boolean(false)),
        (
            "modules",
            serde_value(discovery::visible_manifests(state, principal))?,
        ),
    ]))
}

/// Discovery describes installed contracts, filtered by exposure and capability.
/// It deliberately does not claim that input-dependent policy will admit a call.
pub(super) fn resource(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    input: Value,
) -> Result<Value, ConsoleError> {
    enabled(state)?;
    let mut input = input_map(input)?;
    let path = Path::parse(&string_arg(&mut input, "target")?)?;
    public_target(&path)?;
    // Avoid revealing whether an unauthorized resource even exists.
    if !target_allowed(state, &principal.grants, &path) {
        return Err(AuthError::PermissionDenied.into());
    }
    let registry = state.boot.kernel().registry();
    let id = registry
        .resolve_resource(&ResourceName::new(path.clone()))
        .map_err(|_error| ConsoleError::BadRequest("resource is not installed".into()))?;
    let resource = registry
        .resource(id)
        .ok_or_else(|| ConsoleError::BadRequest("resource is not installed".into()))?;
    let interfaces: Vec<Interface> = resource
        .interfaces
        .interfaces
        .iter()
        .filter_map(|id| registry.interface(*id))
        .filter_map(|mut interface| {
            let method_count = interface.methods.len();
            interface.methods.retain(|method| {
                method_allowed(
                    state,
                    &principal.grants,
                    method.authority.verb(),
                    &path,
                    &method.name,
                )
            });
            let all_methods_visible = interface.methods.len() == method_count;
            // Retain algebraic metadata only for methods visible to this caller.
            let visible = |name: &str| interface.methods.iter().any(|method| method.name == name);
            interface.laws.retain(|law| match law {
                xolotl_types::InterfaceLaw::Idempotent { method } => visible(method),
                xolotl_types::InterfaceLaw::ReadYourWrites { write, read } => {
                    visible(write) && visible(read)
                }
                xolotl_types::InterfaceLaw::Commutes { a, b } => visible(a) && visible(b),
                // Custom names carry no structured method references. A partial
                // projection cannot establish whether the law describes a
                // method the caller is not allowed to discover.
                xolotl_types::InterfaceLaw::Custom { .. } => all_methods_visible,
            });
            (!interface.methods.is_empty()).then_some(interface)
        })
        .collect();
    if interfaces.is_empty() {
        return Err(AuthError::PermissionDenied.into());
    }
    Ok(map_value([
        ("target", Value::string(path.to_string())),
        ("resource_id", Value::string(id.get().to_string())),
        ("kind", serde_value(resource.descriptor.kind)?),
        ("addressing", serde_value(resource.descriptor.addressing)?),
        ("interfaces", serde_value(interfaces)?),
        ("advisory", Value::boolean(true)),
    ]))
}

fn enabled(state: &ConsoleState) -> Result<(), ConsoleError> {
    if state.runtime.config.enabled {
        Ok(())
    } else {
        Err(ConsoleError::BadRequest(
            "runtime execution is disabled by this host".into(),
        ))
    }
}

/// The Kernel owns the execution deadline. Console may still need bounded time
/// to observe its already-running evaluation and close the request process.
/// This window never changes the executor's deadline or admits another effect.
fn settlement_deadline(deadline: HostDeadline, cleanup_timeout_ms: u64) -> HostDeadline {
    // The execution deadline was already validated. If the additional host
    // wait is not representable, keep that deadline instead of overflowing.
    deadline
        .checked_add(Duration::from_millis(cleanup_timeout_ms))
        .unwrap_or(deadline)
}

/// No Kernel decision arrived for a started evaluation. Console cannot infer
/// which logical operations were dispatched, so the identity list stays empty.
fn settlement_timeout() -> Failure {
    Failure::OutcomeUnknown {
        operation_ids: Vec::new(),
        reason: "settlement_timeout".into(),
    }
}

pub(super) fn allowed(state: &ConsoleState, grants: &CapSet, verb: &str, path: &Path) -> bool {
    state.runtime.capabilities.contains(verb, path)
        && grants.matches_preflight(verb, path, state.boot.kernel().host_runtime().now_millis())
}

pub(super) fn method_allowed(
    state: &ConsoleState,
    grants: &CapSet,
    verb: &str,
    path: &Path,
    method: &str,
) -> bool {
    state
        .runtime
        .capabilities
        .contains_method(verb, path, method)
        && grants.matches_method_preflight(
            verb,
            path,
            method,
            state.boot.kernel().host_runtime().now_millis(),
        )
}

/// Propagating a method handle is authorized independently of invoking it.
/// Input-dependent candidates remain residual until the actual operation.
pub(super) fn propagation_method_allowed(
    state: &ConsoleState,
    grants: &CapSet,
    path: &Path,
    method: &str,
) -> bool {
    method_allowed(state, grants, "spawn-with", path, method)
}

/// Establish a shared possible method before resolving the resource. Discovery
/// filters installed methods; execution checks input-dependent predicates.
fn target_allowed(state: &ConsoleState, grants: &CapSet, path: &Path) -> bool {
    let now = state.boot.kernel().host_runtime().now_millis();
    xolotl_types::MethodAuthority::ALL.iter().any(|authority| {
        let verb = authority.verb();
        let mut host_methods = HashSet::new();
        let mut host_all_methods = false;
        for host in state.runtime.capabilities.iter() {
            match host.method.as_deref() {
                Some(method) if host.matches_method_preflight(verb, path, method, now) => {
                    host_methods.insert(method);
                }
                None if host.matches_preflight(verb, path, now) => {
                    host_all_methods = true;
                    break;
                }
                _ => {}
            }
        }
        if !host_all_methods && host_methods.is_empty() {
            return false;
        }
        grants
            .iter()
            .any(|account| match account.method.as_deref() {
                Some(method) => {
                    (host_all_methods || host_methods.contains(method))
                        && account.matches_method_preflight(verb, path, method, now)
                }
                None => account.matches_preflight(verb, path, now),
            })
    })
}

fn public_target(path: &Path) -> Result<(), ConsoleError> {
    if !path.is_concrete() || path.segments().is_empty() {
        return Err(ConsoleError::BadRequest(
            "runtime targets must be concrete resource paths".into(),
        ));
    }
    // Typed Console management handlers own these invariants and custody gates.
    // A catch-all host exposure must never turn into a raw management bypass.
    if xolotl_types::is_kernel_reserved(path)
        || xolotl_types::is_vault_reserved(path)
        || xolotl_types::is_fact_reserved(path)
    {
        return Err(ConsoleError::BadRequest(
            "reserved resources require their dedicated Console actions".into(),
        ));
    }
    Ok(())
}

fn begin(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    plan: &Plan,
) -> Result<xolotl_kernel::RequestProcess<'static>, ConsoleError> {
    begin_with_request(context, principal, call, plan, |state, identity, grants| {
        state
            .boot
            .request_under_owned(state.runtime_anchor(), identity, grants)
    })
}

fn begin_with_request(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    plan: &Plan,
    request: impl FnOnce(
        &ConsoleState,
        xolotl_types::IdentityRef,
        &[CompiledRequestGrantTemplate],
    ) -> Result<
        xolotl_kernel::RequestProcess<'static>,
        xolotl_kernel::BootstrapError,
    >,
) -> Result<xolotl_kernel::RequestProcess<'static>, ConsoleError> {
    let state = context.state;
    let identity = prepare_begin(context, principal, call)?;
    let request = request(state, identity, &plan.grants).map_err(request_error)?;
    finish_begin(state, request, plan)
}

fn prepare_begin(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<xolotl_types::IdentityRef, ConsoleError> {
    let state = context.state;
    record_visibility_audit(
        state,
        principal,
        context.source_addr,
        "runtime_execute",
        VisibilityAuditDetails::action(call, None),
    )?;
    state
        .boot
        .kernel()
        .identities()
        .resolve_or_register(&principal_identity_path(principal)?)
        .map_err(|error| ConsoleError::Operation(error.to_string()))
}

fn request_error(error: xolotl_kernel::BootstrapError) -> ConsoleError {
    match error {
        xolotl_kernel::BootstrapError::CapabilityCeiling { .. } => {
            AuthError::PermissionDenied.into()
        }
        error @ xolotl_kernel::BootstrapError::RequestGrantLimit { .. } => {
            ConsoleError::BadRequest(error.to_string())
        }
        other => ConsoleError::Operation(other.to_string()),
    }
}

fn finish_begin(
    state: &ConsoleState,
    request: xolotl_kernel::RequestProcess<'static>,
    plan: &Plan,
) -> Result<xolotl_kernel::RequestProcess<'static>, ConsoleError> {
    state
        .boot
        .kernel()
        .processes()
        .restrict_budget(request.id(), &plan.budget)
        .map_err(ConsoleError::Runtime)?;
    Ok(request)
}

pub(super) async fn run(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    typed: Option<TypedRuntimeInput>,
) -> Result<ActionResult, ConsoleError> {
    let state = context.state;
    let plan = plan(state, principal, call, false, typed)?;
    if let Some(delivery) = context.delivery {
        delivery.record(plan.delivery_access());
    }
    let request = begin(context, principal, call, &plan)?;
    let reference = ExecutionReference {
        execution_id: None,
        process_id: request.id().get().to_string(),
        program_id: plan.program_id.clone(),
    };
    // Keep the attached evaluator's Future state off the service dispatch stack.
    match Box::pin(run_allocated(context, principal, plan, request)).await {
        Ok((output, unresolved)) => {
            let mut result =
                ActionResult::value(output, server_rev_hint(state), registry_rev(state));
            result.execution = Some(Box::new(reference));
            if !unresolved.is_empty() {
                result.unresolved_operations = Some(Box::new(unresolved));
            }
            Ok(result)
        }
        Err(error) => Err(error.with_execution(reference)),
    }
}

async fn run_allocated(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    plan: Plan,
    request: xolotl_kernel::RequestProcess<'static>,
) -> Result<(Value, UnresolvedOperations), ConsoleError> {
    let state = context.state;
    let Plan {
        prepared,
        steps,
        input,
        operations,
        deadline,
        program_id,
        budget,
        ..
    } = plan;
    let process_id = request.id();
    let executor = request
        .executor()
        .with_steps(steps)
        .with_execution_config(
            state
                .runtime
                .execution_config(state.boot.kernel().execution_config()),
        )
        .with_deadline(deadline)?;
    // Preparation opens all methods and checks static policy before *any* driver
    // is invoked. Residual policy is still evaluated against each actual input.
    for operation in operations {
        if let Err(failure) = executor.prepare_operation(&operation.template) {
            let cleanup_deadline = crate::host_time::after(
                state.boot.kernel().host_runtime(),
                Duration::from_millis(state.runtime.config.executions.cleanup_timeout_ms),
            )
            .map_err(ConsoleError::Runtime)?;
            let _completed = crate::host_time::timeout_at(
                state.boot.kernel().host_runtime(),
                cleanup_deadline,
                request.finish(&ExecutionOutput::new(
                    Outcome::Fail(failure.clone()),
                    TaintSet::author(),
                )),
            )
            .await;
            return Err(ConsoleError::Runtime(failure));
        }
    }
    if state.boot.kernel().facts().is_enabled() {
        state
            .boot
            .record_gateway_audit(xolotl_kernel::GatewayAudit {
                event: "console_runtime",
                username: Some(&principal.username),
                source_addr: context.source_addr,
                outcome: "started",
                details: Some(map_value([
                    ("process_id", Value::string(process_id.get().to_string())),
                    ("program_id", Value::string(program_id.clone())),
                    (
                        "authentication",
                        crate::auth::audit::authentication_summary(&principal.authentication),
                    ),
                ])),
            })?;
    }
    if crate::host_time::elapsed(state.boot.kernel().host_runtime(), deadline)
        .map_err(ConsoleError::Runtime)?
    {
        return Err(ConsoleError::Runtime(Failure::Timeout));
    }
    let output = crate::host_time::timeout_at(
        state.boot.kernel().host_runtime(),
        settlement_deadline(deadline, state.runtime.config.executions.cleanup_timeout_ms),
        executor.eval_prepared(&prepared, TaintedValue::new(input, TaintSet::author())),
    )
    .await
    .map_err(|_error| ConsoleError::Runtime(settlement_timeout()))?;
    // Lifecycle finalization is separate from evaluation. A failed or slow
    // finalizer cannot erase a Kernel-authored uncertain-operation identity.
    let cleanup_deadline = crate::host_time::after(
        state.boot.kernel().host_runtime(),
        Duration::from_millis(state.runtime.config.executions.cleanup_timeout_ms),
    )
    .map_err(ConsoleError::Runtime)?;
    let cleanup_ticket = request.cleanup_ticket();
    let finalized = crate::host_time::timeout_at(
        state.boot.kernel().host_runtime(),
        cleanup_deadline,
        request.finish(&output),
    )
    .await;
    let (finalization, mut unresolved_operations) =
        finalization_projection(state, &cleanup_ticket)?;
    unresolved_operations.merge(&output.unresolved_operations);
    let cleanup_failure = finalized
        .map_err(|_error| {
            ConsoleError::Finalization(xolotl_kernel::RequestFinishError {
                source: xolotl_kernel::BootstrapError::CleanupWaitExpired {
                    process: cleanup_ticket.process(),
                },
                cleanup: cleanup_ticket.clone(),
            })
        })
        .and_then(|result| result.map_err(ConsoleError::Finalization))
        .err();
    if let Some(error) = cleanup_failure {
        let completion = retained_runtime_completion(state, &output, finalization, Some(&error))?;
        let error = match &output.outcome {
            Outcome::Fail(failure) => {
                ConsoleError::Runtime(failure.clone()).with_cleanup_error(error)
            }
            _ => error,
        };
        return Err(error
            .with_runtime_completion(completion)
            .with_unresolved_operations(unresolved_operations));
    }
    if let Outcome::Fail(failure) = &output.outcome {
        let completion = retained_runtime_completion(state, &output, finalization, None)?;
        return Err(ConsoleError::Runtime(failure.clone())
            .with_runtime_completion(completion)
            .with_unresolved_operations(unresolved_operations));
    }
    let ExecutionOutput { outcome, taint, .. } = output;
    let (outcome, value) = match outcome {
        Outcome::Done(value) => ("done", value),
        Outcome::Short(value) => ("short", value),
        Outcome::Fail(failure) => {
            return Err(
                ConsoleError::Runtime(failure).with_unresolved_operations(unresolved_operations)
            );
        }
    };
    let budget = match crate::runtime::budget::value(&budget) {
        Ok(value) => value,
        Err(error) => return Err(error.with_unresolved_operations(unresolved_operations)),
    };
    let taint = match serde_value(taint) {
        Ok(value) => value,
        Err(error) => return Err(error.with_unresolved_operations(unresolved_operations)),
    };
    Ok((
        map_value([
            ("process_id", Value::string(process_id.get().to_string())),
            ("program_id", Value::string(program_id)),
            ("budget", budget),
            ("outcome", Value::string(outcome.into())),
            ("value", value),
            ("taint", taint),
            ("finalization", finalization),
        ]),
        unresolved_operations,
    ))
}

fn finalization_projection(
    state: &ConsoleState,
    ticket: &xolotl_kernel::CleanupTicket,
) -> Result<(Value, xolotl_types::UnresolvedOperations), ConsoleError> {
    use crate::runtime::executions::finalization::FinalizationProjection;
    let projection =
        ticket
            .finalization_report()
            .map_or(FinalizationProjection::Pending, |report| {
                FinalizationProjection::encode(
                    &report,
                    state.runtime.config.executions.max_finalization_bytes,
                )
            });
    Ok((
        projection.value()?,
        ticket.unresolved_operations().unwrap_or_default(),
    ))
}

pub(crate) fn retained_runtime_completion(
    state: &ConsoleState,
    output: &ExecutionOutput,
    finalization: Value,
    cleanup_failure: Option<&ConsoleError>,
) -> Result<Value, ConsoleError> {
    use crate::runtime::executions::RetainedResult;
    let retained = executions::result_value(output)
        .map(|value| {
            RetainedResult::encode(&value, state.runtime.config.executions.max_result_bytes)
        })
        .unwrap_or_else(|_| RetainedResult::Omitted("body result could not be represented".into()));
    let (body, failure) = match &retained {
        RetainedResult::Available(_) => (retained.value()?, Value::null()),
        RetainedResult::Omitted(_) => (Value::null(), retained.value()?),
    };
    let cleanup_failure = cleanup_failure
        .map(|_| {
            serde_value(ConsoleFailure::new(
                ConsoleErrorCode::Internal,
                "runtime lifecycle cleanup remains pending".into(),
            ))
        })
        .transpose()?
        .unwrap_or(Value::null());
    Ok(map_value([
        ("body", body),
        ("body_retention_failure", failure),
        ("finalization", finalization),
        ("cleanup_failure", cleanup_failure),
    ]))
}

pub(super) fn retained_delivery_completion(state: &ConsoleState, output: &Value) -> Value {
    use crate::runtime::executions::RetainedResult;
    let retained = RetainedResult::encode(output, state.runtime.config.executions.max_result_bytes);
    let finalization = output
        .as_map()
        .and_then(|fields| fields.get("finalization"))
        .cloned()
        .unwrap_or_else(Value::null);
    match retained {
        RetainedResult::Available(_) => map_value([
            ("body", retained.value().unwrap_or_else(|_| Value::null())),
            ("body_retention_failure", Value::null()),
            ("finalization", finalization),
        ]),
        RetainedResult::Omitted(_) => map_value([
            ("body", Value::null()),
            (
                "body_retention_failure",
                retained.value().unwrap_or_else(|_| Value::null()),
            ),
            ("finalization", finalization),
        ]),
    }
}

pub(super) mod executions;
mod modules;
pub(super) use executions::{access_execution, lookup_submission, submit};
mod streaming;
pub(super) use streaming::stream;

#[cfg(test)]
mod tests;
