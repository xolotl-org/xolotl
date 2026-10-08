//! Explicit submission transfers request ownership to the Console execution service.

use super::*;
use crate::auth::ExecutionOwner;
use crate::runtime::executions::{
    Admission, Completion, OutputPageRequest, Registration, RetainedResult, RootSubmissionEvidence,
    RootSubmissionProbe, StopReason,
};
use tokio::sync::watch;
use xolotl_types::{Capability, ProcessStatus, RightFlags};

mod children;
pub(in crate::service) mod cleanup;

pub(in crate::service) async fn submit(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    typed: Option<TypedRuntimeInput>,
) -> Result<ActionResult, ConsoleError> {
    let state = context.state;
    if !state.runtime.config.executions.enabled {
        return Err(ConsoleError::BadRequest(
            "independent execution is disabled by this host".into(),
        ));
    }

    enabled(state)?;
    require_visibility_access(principal, call)?;
    let typed = plan::prepare_input(state, call, false, typed)?;
    let authentication = super::super::authentication_capacity(state)?;
    let runtime = state.boot.kernel().host_runtime();
    let authentication_deadline = crate::host_time::after(
        runtime,
        Duration::from_millis(call.ttl_ms.unwrap_or_default()),
    )
    .map_err(ConsoleError::Runtime)?;
    let owner = crate::host_time::timeout_at(
        runtime,
        authentication_deadline,
        state
            .auth
            .execution_owner(&state.boot, context.session_id, principal),
    )
    .await
    .map_err(|_error| ConsoleError::Runtime(Failure::Timeout))??;
    drop(authentication);
    let reservation = if let Some(identity) = &typed.submission_identity {
        match state.executions.prepare_root_submission(
            &owner,
            identity,
            typed.submission_fingerprint()?,
        )? {
            RootSubmissionProbe::Preparing => return Err(ConsoleError::RateLimited),
            RootSubmissionProbe::Existing { reference, retired } => {
                let evidence = if retired { "retired" } else { "accepted" };
                let mut result = ActionResult::value(
                    map_value([
                        ("execution", serde_value(&reference)?),
                        ("submission_evidence", Value::string(evidence.into())),
                    ]),
                    server_rev_hint(state),
                    registry_rev(state),
                );
                result.execution = Some(Box::new(reference));
                return Ok(result);
            }
            RootSubmissionProbe::Reserved(reservation) => Some(reservation),
        }
    } else {
        None
    };
    let mut plan = plan(state, principal, call, false, Some(typed))?;
    plan.admission_deadline = plan
        .admission_deadline
        .earliest(authentication_deadline)
        .map_err(|error| ConsoleError::Runtime(error.into()))?;
    if let Some(delivery) = context.delivery {
        delivery.record(plan.delivery_access());
    }
    let stream_output = plan
        .operations
        .iter()
        .any(|operation| operation.template.output == OutputMode::Stream);
    let authority: Vec<_> = plan
        .operations
        .iter()
        .flat_map(|op| {
            let method = (
                op.authority.verb().to_owned(),
                op.template.target.path().clone(),
            );
            let propagation = (op.template.output == OutputMode::AsyncProcess)
                .then(|| ("spawn-with".into(), op.template.target.path().clone()));
            std::iter::once(method).chain(propagation)
        })
        .chain(
            plan.identities
                .iter()
                .map(|identity| ("act-as".into(), identity.clone())),
        )
        .collect();
    let authority_candidates = admitted_authority_candidates(&plan, &principal.grants, &authority)?;
    if crate::host_time::elapsed(runtime, plan.admission_deadline).map_err(ConsoleError::Runtime)? {
        return Err(ConsoleError::Runtime(Failure::Timeout));
    }

    let request = begin(context, principal, call, &plan)?;
    // The process exists before reservation but no Operation has executed. A
    // rejected reservation drops the owned request and cannot leak an orphan.
    let reference = ExecutionReference {
        execution_id: None,
        process_id: request.id().get().to_string(),
        program_id: plan.program_id.clone(),
    };
    let remaining = i64::try_from(
        plan.deadline
            .saturating_duration_since(runtime.now())
            .map_err(|error| ConsoleError::Runtime(error.into()))?
            .as_millis(),
    )
    .map_err(|_error| {
        ConsoleError::BadRequest("execution deadline is not representable".into())
            .with_execution(reference.clone())
    })?;
    let deadline = runtime.now_millis().checked_add(remaining).ok_or_else(|| {
        ConsoleError::BadRequest("execution deadline is not representable".into())
            .with_execution(reference.clone())
    })?;
    let cleanup_ticket = state
        .boot
        .cleanup_ticket(request.id())
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    if crate::host_time::elapsed(runtime, plan.admission_deadline).map_err(ConsoleError::Runtime)? {
        return Err(ConsoleError::Runtime(Failure::Timeout).with_execution(reference));
    }
    let admission = Admission {
        owner: owner.clone(),
        authority: authority.clone(),
        authority_candidates: authority_candidates.clone().into(),
        reference: reference.clone(),
        budget: plan.budget.clone(),
        deadline,
        origin: None,
        stream_output,
    };
    let guarded = reservation.is_some();
    let registered = if let Some(reservation) = reservation {
        reservation.register(admission, cleanup_ticket.clone())
    } else {
        state.executions.register_authorized(admission)
    };
    let (registration, stop, reference) =
        registered.map_err(|error| error.with_execution(reference))?;
    if !guarded {
        registration.bind_cleanup(cleanup_ticket.clone())?;
    }
    cleanup::start(state).map_err(|error| error.with_execution(reference.clone()))?;
    let mut metadata = state.executions.get(
        &owner,
        reference.execution_id.as_deref().unwrap_or_default(),
    )?;
    if guarded {
        let mut fields = input_map(metadata)?;
        fields
            .insert(
                "submission_evidence".into(),
                Value::string("accepted".into()),
            )
            .map_err(|error| ConsoleError::Operation(error.to_string()))?;
        metadata = Value::from(fields);
    }
    let worker = Worker {
        state: state.clone(),
        owner,
        authority,
        authority_candidates,
        request,
        cleanup_ticket,
        registration,
        stop,
        reference: reference.clone(),
    };
    // No await between reservation and spawning: dropping the transport's future
    // cannot leave an accepted record without its worker. The worker retains no SID.
    let _detached = runtime.spawn(Box::pin(worker.run(plan))).map_err(|error| {
        ConsoleError::Operation(format!("execution worker could not start: {error}"))
            .with_execution(reference.clone())
    })?;
    let mut result = ActionResult::value(metadata, server_rev_hint(state), registry_rev(state));
    result.execution = Some(Box::new(reference));
    Ok(result)
}

pub(in crate::service) async fn lookup_submission(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Value, ConsoleError> {
    enabled(context.state)?;
    let mut input = input_map(call.input.clone())?;
    let identity = super::request::submission_identity(input.remove("submission_identity"))?
        .ok_or_else(|| ConsoleError::BadRequest("submission_identity is required".into()))?;
    let _authentication = super::super::authentication_capacity(context.state)?;
    let owner = context
        .state
        .auth
        .execution_owner(&context.state.boot, context.session_id, principal)
        .await?;
    let (evidence, reference) = match context
        .state
        .executions
        .lookup_root_submission(&owner, &identity)?
    {
        RootSubmissionEvidence::Unproven => ("unproven", None),
        RootSubmissionEvidence::Preparing => ("preparing", None),
        RootSubmissionEvidence::Accepted(reference) => ("accepted", Some(reference)),
        RootSubmissionEvidence::Retired(reference) => ("retired", Some(reference)),
    };
    Ok(map_value([
        ("evidence", Value::string(evidence.into())),
        (
            "execution",
            match reference {
                Some(reference) => serde_value(reference)?,
                None => Value::null(),
            },
        ),
    ]))
}

pub(in crate::service) async fn access_execution(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Value, ConsoleError> {
    let state = context.state;
    let authentication = super::super::authentication_capacity(state)?;
    let owner = state
        .auth
        .execution_owner(&state.boot, context.session_id, principal)
        .await?;
    drop(authentication);
    let mut input = input_map(call.input.clone())?;
    if call.action == protocol::ACTION_RUNTIME_EXECUTION_LIST {
        let limit = optional_usize_arg(&mut input, "limit")?
            .unwrap_or(64)
            .min(state.queries.max_process_limit);
        let max_bytes = optional_usize_arg(&mut input, "max_bytes")?
            .unwrap_or(state.queries.max_page_bytes)
            .min(state.queries.max_page_bytes);
        if limit == 0 || max_bytes == 0 {
            return Err(ConsoleError::BadRequest(
                "page limits must be positive".into(),
            ));
        }
        let cursor = optional_string_arg(&mut input, "cursor")?;
        return state
            .executions
            .list(&owner, cursor.as_deref(), limit, max_bytes);
    }
    let id = string_arg(&mut input, "execution_id")?;
    match call.action.as_str() {
        protocol::ACTION_RUNTIME_EXECUTION_GET => state.executions.get(&owner, &id),
        protocol::ACTION_RUNTIME_EXECUTION_CANCEL => state.executions.cancel(&owner, &id).await,
        protocol::ACTION_RUNTIME_EXECUTION_FORGET => state.executions.forget(&owner, &id).await,
        protocol::ACTION_RUNTIME_EXECUTION_RESULT => {
            require_visibility_access(principal, call)?;
            let _authentication = super::super::authentication_capacity(state)?;
            let current = delivery_principal(context, principal, call, &owner).await?;
            let result = state.executions.result(&owner, &id, |candidates| {
                capture_delivery_candidates(context, &current.grants, candidates)
            })?;
            record_visibility_audit(
                state,
                principal,
                context.source_addr,
                "runtime_result",
                VisibilityAuditDetails::action(call, Some(&id)),
            )?;
            Ok(result)
        }
        protocol::ACTION_RUNTIME_EXECUTION_OUTPUT_READ => {
            read_output(context, principal, call, &owner, &id, input).await
        }
        _ => Err(ConsoleError::BadRequest("unknown execution action".into())),
    }
}

async fn delivery_principal(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    owner: &ExecutionOwner,
) -> Result<ConsolePrincipal, ConsoleError> {
    let current = context
        .state
        .auth
        .execution_delivery(&context.state.boot, context.session_id, principal, owner)
        .await?;
    require_visibility_access(&current, call)?;
    Ok(current)
}

async fn read_output(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    owner: &ExecutionOwner,
    id: &str,
    mut input: xolotl_types::ValueMap,
) -> Result<Value, ConsoleError> {
    require_visibility_access(principal, call)?;
    let state = context.state;
    let after = optional_u64_arg(&mut input, "cursor")?.unwrap_or(0);
    let limit = optional_usize_arg(&mut input, "limit")?
        .unwrap_or(64)
        .min(state.runtime.config.executions.max_output_events);
    let max_bytes = optional_usize_arg(&mut input, "max_bytes")?
        .unwrap_or(state.runtime.config.executions.max_output_page_bytes)
        .min(state.runtime.config.executions.max_output_page_bytes);
    let wait_ms = optional_u64_arg(&mut input, "wait_ms")?.unwrap_or(0);
    if limit == 0 || max_bytes < 512 || wait_ms > 30_000 {
        return Err(ConsoleError::BadRequest(
            "invalid output page or wait limit".into(),
        ));
    }
    let runtime = state.boot.kernel().host_runtime();
    let start = runtime.now();
    let visibility_deadline = start
        .checked_add(Duration::from_millis(call.ttl_ms.unwrap_or_default()))
        .ok_or_else(|| {
            ConsoleError::BadRequest("output visibility deadline is not representable".into())
        })?;
    let wait_deadline = start
        .checked_add(Duration::from_millis(wait_ms))
        .ok_or_else(|| {
            ConsoleError::BadRequest("output wait deadline is not representable".into())
        })?;
    let event_limit = state.runtime.config.executions.delivery_event_limit();
    loop {
        let notified = state.executions.output_notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let _authentication = super::super::authentication_capacity(state)?;
        let current = delivery_principal(context, principal, call, owner).await?;
        if crate::host_time::elapsed(runtime, visibility_deadline).map_err(ConsoleError::Runtime)? {
            return Err(ConsoleError::BadRequest("output visibility expired".into()));
        }
        drop(_authentication);
        let page = state
            .executions
            .output_page_for_delivery(
                owner,
                id,
                |candidates| current_candidates_allowed(state, &current.grants, candidates),
                OutputPageRequest {
                    after,
                    limit,
                    max_bytes,
                    event_limit,
                },
            )
            .await?;
        if page.has_entries()
            || page.complete()
            || wait_ms == 0
            || crate::host_time::elapsed(runtime, wait_deadline).map_err(ConsoleError::Runtime)?
        {
            let (value, read) = page.into_value(max_bytes)?;
            let authentication = super::super::authentication_capacity(state)?;
            let current = delivery_principal(context, principal, call, owner).await?;
            if crate::host_time::elapsed(runtime, visibility_deadline)
                .map_err(ConsoleError::Runtime)?
            {
                return Err(ConsoleError::BadRequest("output visibility expired".into()));
            }
            drop(authentication);
            state
                .executions
                .validate_output_delivery(owner, &read, |candidates| {
                    capture_delivery_candidates(context, &current.grants, candidates)
                })?;
            record_visibility_audit(
                state,
                principal,
                context.source_addr,
                "runtime_output",
                VisibilityAuditDetails::action(call, Some(id)),
            )?;
            return Ok(value);
        }
        let wake_at = wait_deadline
            .earliest(visibility_deadline)
            .map_err(|error| ConsoleError::Runtime(error.into()))?;
        tokio::select! {
            _ = &mut notified => {},
            _ = runtime.sleep_until(wake_at) => {},
        }
    }
}

struct Worker {
    state: Arc<ConsoleState>,
    owner: ExecutionOwner,
    authority: Vec<(String, Path)>,
    authority_candidates: Vec<Capability>,
    request: xolotl_kernel::RequestProcess<'static>,
    cleanup_ticket: xolotl_kernel::CleanupTicket,
    registration: Registration,
    stop: watch::Receiver<Option<StopReason>>,
    reference: ExecutionReference,
}

fn record_body(
    state: &ConsoleState,
    registration: &Registration,
    output: &ExecutionOutput,
    stop_cause: Option<&'static str>,
) {
    let result = result_value(output)
        .map(|value| {
            RetainedResult::encode(&value, state.runtime.config.executions.max_result_bytes)
        })
        .unwrap_or(RetainedResult::Omitted(
            "result could not be represented".into(),
        ));
    registration.record_body(Completion {
        outcome: terminal_outcome(Some(output)).into(),
        stop_cause,
        result,
        unresolved_operations: output.unresolved_operations.clone(),
        cleanup_complete: false,
        finalization: Default::default(),
    });
}

fn record_acquired_body(
    state: &ConsoleState,
    request: &xolotl_kernel::RequestProcess<'_>,
    registration: &Registration,
    output: &ExecutionOutput,
) {
    if let Err(error) = request.complete_body(output) {
        tracing::warn!(process = %request.id(), %error, "execution body handoff failed");
    }
    record_body(state, registration, output, None);
}

impl Worker {
    async fn run(mut self, plan: Plan) {
        let (output, stop_outcome) = self.evaluate(plan).await;
        self.finish(output, stop_outcome).await;
    }

    /// Release the plan, executor and evaluation captures before lifecycle
    /// completion may publish the attempt's exit and release its capacity.
    async fn evaluate(&mut self, plan: Plan) -> (ExecutionOutput, Option<&'static str>) {
        let deadline = plan.deadline;
        let runtime = self.state.boot.kernel().host_runtime();
        let stream_output = plan
            .operations
            .iter()
            .any(|operation| operation.template.output == OutputMode::Stream);
        let output_ports = stream_output.then(|| streaming::ports(&self.state.runtime.config));
        let executor = self
            .request
            .executor()
            .with_steps(plan.steps)
            .with_execution_config(
                self.state
                    .runtime
                    .execution_config(self.state.boot.kernel().execution_config()),
            )
            .with_deadline(deadline);
        let executor = match executor {
            Ok(executor) => executor,
            Err(error) => {
                return (
                    ExecutionOutput::new(Outcome::Fail(error.into()), TaintSet::author()),
                    Some("clock_domain"),
                );
            }
        }
        .with_async_process_host(Arc::new(children::Host::new(
            &self.state,
            self.owner.clone(),
            self.authority.clone(),
            self.authority_candidates.clone(),
            self.reference.clone(),
            deadline,
        )));
        let executor = if let Some((router, _)) = &output_ports {
            executor.with_stream_router(router.clone())
        } else {
            executor
        };
        let cleanup_timeout_ms = self.state.runtime.config.executions.cleanup_timeout_ms;
        let admission_deadline = runtime
            .deadline_after(Duration::from_millis(
                self.state.runtime.config.executions.authority_timeout_ms,
            ))
            .and_then(|limit| deadline.earliest(limit).ok())
            .unwrap_or(deadline);
        let admission = if self.stop.borrow().is_some() {
            Ok(Err(ConsoleError::Runtime(Failure::Cancelled)))
        } else {
            tokio::select! {
                biased;
                _changed = self.stop.changed() => Ok(Err(ConsoleError::Runtime(Failure::Cancelled))),
                admitted = crate::host_time::timeout_at(runtime, admission_deadline, check_authority(&self.state, &self.owner, &self.authority, &self.authority_candidates)) => admitted,
            }
        };
        let admitted = match admission {
            Ok(Ok(())) if self.stop.borrow().is_some() => {
                Err(ConsoleError::Runtime(Failure::Cancelled))
            }
            Ok(Ok(())) => plan.operations.iter().try_for_each(|operation| {
                executor
                    .prepare_operation(&operation.template)
                    .map_err(ConsoleError::Runtime)
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(ConsoleError::Runtime(Failure::Timeout)),
        };
        if let Err(error) = admitted {
            (
                ExecutionOutput::new(
                    Outcome::Fail(match error {
                        ConsoleError::Runtime(failure) => failure,
                        _ => Failure::Cancelled,
                    }),
                    TaintSet::author(),
                ),
                Some(match *self.stop.borrow() {
                    Some(StopReason::Cancelled) => "cancelled",
                    Some(StopReason::Shutdown) => "shutdown",
                    None => "rejected",
                }),
            )
        } else {
            let mut body_output = None;
            let request = &self.request;
            let state = &self.state;
            let registration = &self.registration;
            let (stop_outcome, unsettled) = {
                let execution = async {
                    let evaluation = async move {
                        let output = executor
                            .eval_prepared(
                                &plan.prepared,
                                TaintedValue::new(plan.input, TaintSet::author()),
                            )
                            .await;
                        record_acquired_body(state, request, registration, &output);
                        output
                    };
                    if let Some((router, ports)) = output_ports {
                        drop(router);
                        let boot = Arc::clone(&self.state.boot);
                        let process = self.request.id();
                        let failure = streaming::pump_log(
                            evaluation,
                            ports,
                            &self.registration,
                            self.state.runtime.config.executions.max_output_event_bytes,
                            move || {
                                drop(boot.cancel_process(process));
                            },
                            &mut body_output,
                        )
                        .await;
                        failure.map(|_| "output_limit")
                    } else {
                        body_output = Some(evaluation.await);
                        None
                    }
                };
                tokio::pin!(execution);
                let monitor = monitor(
                    &self.state,
                    &self.owner,
                    &self.authority,
                    &self.authority_candidates,
                    &mut self.stop,
                );
                tokio::pin!(monitor);
                let stopped = tokio::select! {
                    biased;
                    output = &mut execution => Ok(output),
                    reason = &mut monitor => Err(reason),
                    _ = runtime.sleep_until(deadline) => Err("timed_out"),
                };
                match stopped {
                    Ok(stop_reason) => (stop_reason, false),
                    Err(reason) => {
                        self.registration.record_stop_cause(reason);
                        // At the deadline the Kernel must make its own terminal
                        // decision, including the IDs of effects still in flight.
                        // Cancelling here would preempt that decision. Explicit
                        // cancellation and authority revocation still propagate at once.
                        if reason != "timed_out" {
                            let _cancelled = self.state.boot.cancel_process(self.request.id());
                        }
                        let settlement_deadline = if reason == "timed_out" {
                            super::settlement_deadline(deadline, cleanup_timeout_ms)
                        } else {
                            deadline
                                .earliest(super::settlement_deadline(
                                    runtime.now(),
                                    cleanup_timeout_ms,
                                ))
                                .unwrap_or(deadline)
                        };
                        let settled = crate::host_time::timeout_at(
                            runtime,
                            settlement_deadline,
                            &mut execution,
                        )
                        .await
                        .ok();
                        (settled.flatten().or(Some(reason)), settled.is_none())
                    }
                }
            };
            if unsettled && body_output.is_none() {
                let _cancelled = self.state.boot.cancel_process(self.request.id());
            }
            let output = body_output.unwrap_or_else(|| {
                ExecutionOutput::new(
                    Outcome::Fail(super::settlement_timeout()),
                    TaintSet::author(),
                )
            });
            (output, stop_outcome)
        }
    }

    async fn finish(self, output: ExecutionOutput, stop_outcome: Option<&'static str>) {
        // Publish the known body result before awaiting cleanup. Drop/panic during
        // finalization must not turn a successful body into an unknown execution.
        if self.registration.body_recorded() {
            if let Some(stop_cause) = stop_outcome {
                self.registration.record_stop_cause(stop_cause);
            }
        } else {
            record_body(&self.state, &self.registration, &output, stop_outcome);
        }
        let runtime = self.state.boot.kernel().host_runtime();
        let cleanup_deadline = crate::host_time::after(
            runtime,
            Duration::from_millis(self.state.runtime.config.executions.cleanup_timeout_ms),
        );
        let _attempt = crate::host_time::timeout_at(
            runtime,
            cleanup_deadline.unwrap_or_else(|_| runtime.now()),
            self.request.finish(&output),
        )
        .await;
        let cleanup_complete = self.cleanup_ticket.is_complete();
        self.registration.finish(cleanup_complete);
    }
}

fn terminal_outcome(output: Option<&ExecutionOutput>) -> &'static str {
    let Some(output) = output else {
        return "interrupted";
    };
    match &output.outcome {
        Outcome::Done(_) => "done",
        Outcome::Short(_) => "short",
        Outcome::Fail(Failure::Timeout) => "timed_out",
        Outcome::Fail(Failure::Cancelled) => "cancelled",
        Outcome::Fail(_) => "failed",
    }
}

pub(super) fn result_value(output: &ExecutionOutput) -> Result<Value, ConsoleError> {
    let (value, failure) = match &output.outcome {
        Outcome::Done(value) | Outcome::Short(value) => (value.clone(), Value::null()),
        Outcome::Fail(failure) => (
            Value::null(),
            serde_value(ConsoleFailure::from(ConsoleError::Runtime(failure.clone())))?,
        ),
    };
    Ok(map_value([
        ("value", value),
        ("failure", failure),
        ("taint", serde_value(&output.taint)?),
    ]))
}

fn admitted_authority_candidates(
    plan: &Plan,
    principal_grants: &CapSet,
    authority: &[(String, Path)],
) -> Result<Vec<Capability>, ConsoleError> {
    let mut seen = std::collections::HashSet::new();
    let mut candidates = Vec::new();
    let mut retain = |candidate: Capability| {
        if authority
            .iter()
            .any(|(verb, path)| candidate.matches_path_structure(verb, path))
            && seen.insert(candidate.clone())
        {
            candidates.push(candidate);
        }
    };
    for grant in &plan.grants {
        let candidate = &grant.selector.pattern;
        for operation in &plan.operations {
            let verb = operation.authority.verb();
            let path = operation.template.target.path();
            let method = &operation.template.method;
            if grant.selector.matches(verb, path) && grant.rights.methods.allows(method) {
                let mut selected = candidate.clone();
                selected.method = Some(method.clone());
                retain(selected);
            }
            if operation.template.output == OutputMode::AsyncProcess
                && grant.rights.flags.contains(RightFlags::SPAWN_WITH)
                && grant.selector.matches(verb, path)
                && principal_grants.iter().any(|source| {
                    source.predicate == candidate.predicate
                        && source.matches_method("spawn-with", path, method)
                })
            {
                let mut selected = candidate.clone();
                selected.verb = "spawn-with".into();
                selected.method = Some(method.clone());
                retain(selected);
            }
        }
        if candidate.verb == "act-as" && grant.rights.flags.contains(RightFlags::DELEGATE) {
            retain(candidate.clone());
        }
    }
    if !authority_covered_by_candidates(authority, &candidates)
        || plan.operations.iter().any(|operation| {
            let path = operation.template.target.path();
            let method = operation.template.method.as_str();
            let covers = |verb| {
                candidates.iter().any(|candidate| {
                    candidate.method.as_deref() == Some(method)
                        && candidate.matches_method(verb, path, method)
                })
            };
            !covers(operation.authority.verb())
                || (operation.template.output == OutputMode::AsyncProcess && !covers("spawn-with"))
        })
    {
        return Err(ConsoleError::Operation(
            "admitted execution authority has no account candidate".into(),
        ));
    }
    Ok(candidates)
}

fn authority_covered_by_candidates(
    authority: &[(String, Path)],
    candidates: &[Capability],
) -> bool {
    authority.iter().all(|(verb, path)| {
        candidates
            .iter()
            .any(|candidate| candidate.matches_path_structure(verb, path))
    })
}

async fn check_authority(
    state: &ConsoleState,
    owner: &ExecutionOwner,
    authority: &[(String, Path)],
    candidates: &[Capability],
) -> Result<(), ConsoleError> {
    enabled(state)?;
    if !authority_covered_by_candidates(authority, candidates) {
        return Err(AuthError::PermissionDenied.into());
    }
    let grants = state.auth.execution_grants(&state.boot, owner).await?;
    if !current_candidates_allowed(state, &grants, candidates) {
        return Err(AuthError::PermissionDenied.into());
    }
    Ok(())
}

/// Preserve the admitted method and predicate when observing retained output.
/// A path-only check would allow a grant for a different method on that path.
pub(in crate::service) fn current_candidates_allowed(
    state: &ConsoleState,
    grants: &CapSet,
    candidates: &[Capability],
) -> bool {
    let now = state.boot.kernel().host_runtime().now_millis();
    if candidates.iter().any(|candidate| {
        !state.runtime.capabilities.iter().any(|exposure| {
            exposure.covers_cap_path_pattern(candidate)
                && exposure.predicate.is_none()
                && (exposure.method.is_none() || exposure.method == candidate.method)
        })
    }) {
        return false;
    }
    // A current grant can cover an admitted candidate only if it is
    // unconditional or carries the same predicate. Index that choice once for
    // this account snapshot so periodic checks do not rescan every grant for
    // every imported operation.
    let mut grants_by_kind: std::collections::HashMap<
        (Option<&xolotl_types::Predicate>, &str, &str),
        Vec<&Capability>,
    > = std::collections::HashMap::new();
    for current in grants.iter() {
        if current.predicate.as_ref().is_some_and(|predicate| {
            predicate.key == "until" && !predicate.eval(&Value::null(), now)
        }) {
            continue;
        }
        grants_by_kind
            .entry((
                current.predicate.as_ref(),
                current.verb.as_str(),
                current.scheme.as_str(),
            ))
            .or_default()
            .push(current);
    }
    let current_covers = |candidate: &Capability| {
        [None, candidate.predicate.as_ref()]
            .into_iter()
            .enumerate()
            .filter(|(index, predicate)| *index == 0 || predicate.is_some())
            .any(|(_, predicate)| {
                [candidate.verb.as_str(), "*"].into_iter().any(|verb| {
                    [candidate.scheme.as_str(), "*", "**"]
                        .into_iter()
                        .any(|scheme| {
                            grants_by_kind
                                .get(&(predicate, verb, scheme))
                                .is_some_and(|matching| {
                                    matching.iter().any(|current| current.covers_cap(candidate))
                                })
                        })
                })
            })
    };
    candidates.iter().all(current_covers)
}

fn capture_delivery_candidates(
    context: &ActionContext<'_>,
    grants: &CapSet,
    candidates: &[Capability],
) -> bool {
    let allowed = current_candidates_allowed(context.state, grants, candidates);
    if allowed && let Some(delivery) = context.delivery {
        delivery.record(super::super::subscriptions::Access::Candidates(
            candidates.to_vec(),
        ));
    }
    allowed
}

async fn monitor(
    state: &ConsoleState,
    owner: &ExecutionOwner,
    authority: &[(String, Path)],
    candidates: &[Capability],
    stop: &mut watch::Receiver<Option<StopReason>>,
) -> &'static str {
    let poll = Duration::from_millis(state.runtime.config.executions.authority_poll_ms);
    let runtime = state.boot.kernel().host_runtime();
    loop {
        if let Some(reason) = *stop.borrow_and_update() {
            return match reason {
                StopReason::Cancelled => "cancelled",
                StopReason::Shutdown => "shutdown",
            };
        }
        let Ok(check_deadline) = crate::host_time::after(runtime, poll) else {
            return "authority_revoked";
        };
        tokio::select! {
            _changed = stop.changed() => {},
            _tick = runtime.sleep_until(check_deadline) => {
                let Ok(authority_deadline) = crate::host_time::after(
                    runtime,
                    Duration::from_millis(state.runtime.config.executions.authority_timeout_ms),
                ) else {
                    return "authority_revoked";
                };
                let check = crate::host_time::timeout_at(runtime, authority_deadline, check_authority(state, owner, authority, candidates));
                tokio::pin!(check);
                tokio::select! {
                    _changed = stop.changed() => {},
                    current = &mut check => if !matches!(current, Ok(Ok(()))) { return "authority_revoked"; },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
