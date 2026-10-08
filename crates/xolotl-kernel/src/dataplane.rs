//! The data plane: compiled invocation admission and effect execution.
//!
//! `execute` is the data-plane hot path: generational handle lookup → owner check
//! → active check → rights bitmap → (Conditional only) residual policy → driver
//! budget reservation → dispatch → Fact completion. Delegation and budget
//! checks follow retained ancestor chains. `Unconditional` handles skip the policy step
//! entirely as a structural fast path. The data plane receives compiled handles
//! and driver plans.

use crate::driver::{DriverContext, DriverError, DriverOutput, StreamSendError};
use crate::fact::FactSink;
use crate::handle::{FastPath, HandleTable};
use crate::host::stream::DynStreamSink;
use crate::host::{ClockDomainError, HostDeadline, HostRuntime};
use crate::invocation::{
    CompletionError, GrantedMethod, Invocation, InvocationOptions, InvocationResult,
};
use crate::policy::{CheckCtx, PolicyDecision};
use crate::runtime_domain::{RuntimeAssemblyError, check_runtime_domains};
use futures_util::FutureExt;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_types::{
    CompletionOrigin, DecisionTag, Failure, Operation, Outcome, OutputMode, OutputModeSet, Path,
    TaintSet, TaintedFailure, Value,
};

mod accounting;
mod admission;
mod async_process;
mod fact_io;
mod stream;
pub use fact_io::FactIoMode;
use fact_io::FactWriteError;
pub(crate) use fact_io::FactWriteStage;
#[cfg(test)]
use stream::stream_path;
use stream::{CollectedOutput, collect_driver_stream};

#[derive(Default)]
struct DispatchAttachments<'a> {
    output_sink: Option<DynStreamSink>,
    witness: Option<&'a AtomicBool>,
    observations: Option<&'a parking_lot::Mutex<TaintSet>>,
}

struct IdempotentObservation {
    outcome: Option<Outcome>,
    taint: TaintSet,
}

fn may_have_external_effect(replay: xolotl_types::ReplayClass) -> bool {
    matches!(
        replay,
        xolotl_types::ReplayClass::IdempotentEffect
            | xolotl_types::ReplayClass::NonIdempotentEffect
    )
}

/// Revalidate host-owned request authority before each resource invocation.
/// Child calls inherit the same boundary; resource grants remain independently checked.
#[async_trait::async_trait]
pub trait RequestAuthorizer: Send + Sync {
    /// Reject revoked or no-longer-valid request ownership before dispatch.
    async fn authorize(&self) -> Result<(), Failure>;
}

/// The data plane: a handle table and a fact sink. Shared behind a lock;
/// the lock is held only for the table lookup, released before the (async)
/// driver call.
#[derive(Clone)]
pub struct DataPlane {
    /// Shared handle table used for generational handle lookup.
    pub(crate) handles: HandleTable,
    /// Fact sink used to record operation attempts and completions.
    pub facts: FactSink,
    /// Idempotency dedup store: effective-key → cached outcome for
    /// `IdempotentEffect` ops. Records are stored under the kernel-reserved
    /// `state://kernel/idemp/<hash>` subtree,
    /// where the hash is over the authenticated-context-bound key
    /// (`idempotency::derive_key`), so an injected Plan cannot forge or collide
    /// another identity's records.
    state: xolotl_state::Backend,
    /// Optional process table for the `AsyncProcess` adapter.
    processes: Option<crate::process::ProcessTable>,
    async_process_host: Option<Arc<dyn crate::host::async_process::AsyncProcessHost>>,
    deadline: Option<HostDeadline>,
    host_runtime: HostRuntime,
    fact_io_mode: FactIoMode,
    request_authorizer: Option<Arc<dyn RequestAuthorizer>>,
}

impl DataPlane {
    /// Create a data plane over a handle table, fact sink, and state backend.
    pub fn new(handles: HandleTable, facts: FactSink, state: xolotl_state::Backend) -> Self {
        Self::new_with_host_runtime(handles, facts, state, HostRuntime::default())
    }

    /// Create a data plane using the host clock and scheduler selected for its owner.
    pub fn new_with_host_runtime(
        handles: HandleTable,
        facts: FactSink,
        state: xolotl_state::Backend,
        host_runtime: HostRuntime,
    ) -> Self {
        Self {
            handles,
            facts,
            state,
            processes: None,
            async_process_host: None,
            deadline: None,
            host_runtime,
            fact_io_mode: FactIoMode::Inline,
            request_authorizer: None,
        }
    }

    /// Shared handle table selected when this data plane was assembled.
    pub fn handles(&self) -> &HandleTable {
        &self.handles
    }

    /// Install the same scheduler and clock used by the owning Kernel.
    pub fn with_host_runtime(mut self, runtime: HostRuntime) -> Result<Self, ClockDomainError> {
        if let Some(deadline) = self.deadline {
            runtime.validate_deadline(deadline)?;
        }
        if self
            .processes
            .as_ref()
            .is_some_and(|processes| !runtime.shares_clock_with(processes.host_runtime()))
        {
            return Err(ClockDomainError);
        }
        self.host_runtime = runtime;
        Ok(self)
    }

    /// The host clock and scheduler selected for this data plane.
    pub fn host_runtime(&self) -> &HostRuntime {
        &self.host_runtime
    }

    /// Select whether hosted Fact writes and accepted-replay reads run inline
    /// or on the host's bounded blocking executor. Memory sinks normally use
    /// the inline path.
    pub fn with_fact_io_mode(mut self, mode: FactIoMode) -> Self {
        self.fact_io_mode = mode;
        self
    }

    /// Attach the process table used by async process outputs. Kernel-owned
    /// handles and processes must come from the same runtime assembly.
    pub fn with_processes(
        mut self,
        processes: crate::process::ProcessTable,
    ) -> Result<Self, RuntimeAssemblyError> {
        if self
            .processes
            .as_ref()
            .is_some_and(|attached| !attached.same_table(&processes))
        {
            return Err(RuntimeAssemblyError::DifferentProcessTable);
        }
        check_runtime_domains(&[self.handles.runtime_domain(), processes.runtime_domain()])?;
        if !self
            .host_runtime
            .shares_clock_with(processes.host_runtime())
        {
            return Err(RuntimeAssemblyError::DifferentClockDomain);
        }
        self.processes = Some(processes);
        Ok(self)
    }

    /// Attach the ProcessTable owned by the Kernel that supplied these handles.
    /// KernelBuilder establishes their common runtime domain before exposure.
    pub(crate) fn with_kernel_processes(mut self, processes: crate::process::ProcessTable) -> Self {
        self.processes = Some(processes);
        self
    }

    /// A standalone Executor's explicit identity is authoritative even if its
    /// caller reused a data-plane view previously attached to a process table.
    pub(crate) fn without_processes(mut self) -> Self {
        self.processes = None;
        self
    }

    /// Supply explicit admission, supervision and result custody for AsyncProcess.
    /// Without a host, asynchronous process output is rejected before child creation.
    pub fn with_async_process_host(
        mut self,
        host: Arc<dyn crate::host::async_process::AsyncProcessHost>,
    ) -> Self {
        self.async_process_host = Some(host);
        self
    }

    /// Whether a child ownership service is installed; individual requests still
    /// require propagation rights, process capacity and the service's admission.
    pub fn has_async_process_host(&self) -> bool {
        self.async_process_host.is_some()
    }

    pub(crate) fn with_request_authorizer(
        mut self,
        authorizer: Arc<dyn RequestAuthorizer>,
    ) -> Self {
        self.request_authorizer = Some(authorizer);
        self
    }

    pub(crate) fn has_request_authorizer(&self) -> bool {
        self.request_authorizer.is_some()
    }

    async fn authorize_request(&self, process: xolotl_types::ProcessId) -> Result<(), Failure> {
        let Some(authorizer) = &self.request_authorizer else {
            return Ok(());
        };
        let cancellation = async {
            match &self.processes {
                Some(processes) => {
                    let cleanup = crate::process::current_finalizer(processes) == Some(process)
                        || crate::process::current_cleanup(processes) == Some(process);
                    processes.wait_for_cancellation(process, cleanup).await;
                }
                None => std::future::pending().await,
            }
        };
        let deadline = async {
            match self.deadline {
                Some(deadline) => self
                    .host_runtime
                    .sleep_until(deadline)
                    .await
                    .map_err(Into::into),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            () = cancellation => Err(Failure::Cancelled),
            result = deadline => Err(result.err().unwrap_or(Failure::Timeout)),
            result = AssertUnwindSafe(authorizer.authorize()).catch_unwind() => {
                result.unwrap_or_else(|payload| Err(Failure::HandlerError {
                    kind: "panic".into(),
                    message: crate::bootstrap::panic_payload_message("request authorization", payload),
                }))
            }
        }
    }

    /// Bound children created by this data plane. Repeated calls can only shorten
    /// the deadline; ordinary invocation cancellation remains the caller's task.
    pub fn with_deadline(mut self, deadline: HostDeadline) -> Result<Self, ClockDomainError> {
        self.host_runtime.validate_deadline(deadline)?;
        self.deadline = Some(match self.deadline {
            Some(saved) => saved.earliest(deadline)?,
            None => deadline,
        });
        Ok(self)
    }

    /// Invoke one opened method through shared admission, accounting and Fact rules.
    /// Method rights, replay, costs and output support come from the frozen plan.
    /// Completion errors retain the real output and must be checked before
    /// acknowledging the request or advancing an interpreter.
    pub async fn execute(&self, op: &Operation, options: InvocationOptions) -> InvocationResult {
        self.execute_with_dispatch_witness(op, options, None).await
    }

    pub(crate) async fn execute_with_dispatch_witness(
        &self,
        op: &Operation,
        options: InvocationOptions,
        witness: Option<&AtomicBool>,
    ) -> InvocationResult {
        self.execute_inner(
            op,
            options,
            false,
            DispatchAttachments {
                output_sink: None,
                witness,
                observations: None,
            },
        )
        .await
    }

    /// Invoke with a dedicated output stream. Each invocation owns one terminal lifecycle.
    pub async fn execute_with_stream(
        &self,
        op: &Operation,
        options: InvocationOptions,
        sink: DynStreamSink,
    ) -> InvocationResult {
        self.execute_stream_with_dispatch_witness(op, options, sink, None)
            .await
    }

    pub(crate) async fn execute_stream_with_dispatch_witness(
        &self,
        op: &Operation,
        options: InvocationOptions,
        sink: DynStreamSink,
        witness: Option<&AtomicBool>,
    ) -> InvocationResult {
        let dispatched = AtomicBool::new(false);
        let dispatched = witness.unwrap_or(&dispatched);
        let observations = parking_lot::Mutex::new(TaintSet::pristine());
        stream::run_streamed_invocation(
            self.execute_inner(
                op,
                options,
                false,
                DispatchAttachments {
                    output_sink: Some(sink.clone()),
                    witness: Some(dispatched),
                    observations: Some(&observations),
                },
            ),
            sink,
            op.id,
            &op.taint,
            Some(&observations),
            dispatched,
        )
        .await
    }

    async fn execute_inner(
        &self,
        op: &Operation,
        options: InvocationOptions,
        async_child: bool,
        attachments: DispatchAttachments<'_>,
    ) -> InvocationResult {
        // A Kernel-owned handle table must never be detached from its process
        // ancestry, even through a manually assembled DataPlane or Executor.
        if self.processes.is_none() && self.handles.runtime_domain().is_some() {
            return InvocationResult::new(
                DriverOutput::new(Outcome::Fail(Failure::policy(
                    "process",
                    "kernel-owned handles require their process table",
                )))
                .with_taint(op.taint.clone()),
            );
        }
        if let Some(deadline) = self.deadline
            && let Err(error) = self.host_runtime.validate_deadline(deadline)
        {
            return InvocationResult::new(
                DriverOutput::new(Outcome::Fail(error.into())).with_taint(op.taint.clone()),
            );
        }
        let DispatchAttachments {
            output_sink,
            witness: dispatch_witness,
            observations,
        } = attachments;
        // Capture the caller before any admission branch or host callback. An installed
        // process table is authoritative even when the caller no longer exists.
        let options = InvocationOptions {
            caller_identity: match &self.processes {
                Some(processes) => processes.identity(op.process),
                None => options.caller_identity,
            },
            ..options
        };
        let InvocationOptions { now_millis, .. } = options;
        // Pure admission uses one table view. Even rejection callbacks run only
        // after the resolver has released its guard and returned an owned result.
        let (mut resolved, mut invocation) = match self.resolve_invocation(op, options, async_child)
        {
            Ok(admitted) => admitted,
            Err(denied) => {
                return self
                    .deny(
                        op,
                        denied.resource,
                        denied.replay,
                        options,
                        DecisionTag::Denied,
                        denied.failure,
                    )
                    .await;
            }
        };
        let contract = invocation.contract();
        let xolotl_types::MethodContract {
            replay, supports, ..
        } = contract;

        let observe_lifecycle = || {
            self.processes.as_ref().and_then(|processes| {
                let finalizer = crate::process::current_finalizer(processes) == Some(op.process);
                let cleanup = crate::process::current_cleanup(processes) == Some(op.process);
                let status = processes.status(op.process);
                let cleanup_only =
                    finalizer || (cleanup && status != Some(xolotl_types::ProcessStatus::Running));
                if cleanup_only && !contract.permits_cleanup(op.process) {
                    return Some(Failure::policy(
                        "finalizer",
                        "method is not admitted for cleanup",
                    ));
                }
                match status {
                    Some(xolotl_types::ProcessStatus::Running) => None,
                    Some(xolotl_types::ProcessStatus::Finalizing) if finalizer || cleanup => None,
                    Some(xolotl_types::ProcessStatus::Cancelled) if cleanup => None,
                    _ => Some(Failure::Cancelled),
                }
            })
        };
        let lifecycle_failure = observe_lifecycle();
        if let Some(failure) = lifecycle_failure {
            return self
                .deny(
                    op,
                    Some(resolved.resource),
                    replay,
                    options,
                    DecisionTag::Denied,
                    failure,
                )
                .await;
        }

        if let Some(admit) = resolved.input_admission {
            match std::panic::catch_unwind(AssertUnwindSafe(|| admit(&op.input))) {
                Ok(Ok(())) => {}
                Ok(Err(rejection)) => {
                    let mut redacted = op.clone();
                    redacted.input = rejection.recorded_input;
                    return self
                        .deny(
                            &redacted,
                            Some(resolved.resource),
                            replay,
                            options,
                            DecisionTag::RejectedByPolicy,
                            rejection.failure,
                        )
                        .await;
                }
                Err(payload) => {
                    return self
                        .deny(
                            op,
                            Some(resolved.resource),
                            replay,
                            options,
                            DecisionTag::Denied,
                            Failure::policy(
                                "input",
                                crate::bootstrap::panic_payload_message("input admission", payload),
                            ),
                        )
                        .await;
                }
            }
        }

        // The driver receives the full input value. Large modality values
        // (Blob/Tensor/Frame) use out-of-line references. Other inputs remain
        // inline and their retained Fact snapshots own the corresponding payload.
        let input = op.input.clone();

        // Conditional handles run residual policy; Unconditional skip it.
        if let FastPath::Conditional(snapshot) = &resolved.fast_path {
            let ctx = CheckCtx {
                input: &input,
                acting: op.acting,
                now_millis,
                target: resolved.resource,
            };
            match snapshot.check(&ctx).await {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny { reason } => {
                    return self
                        .deny(
                            op,
                            Some(resolved.resource),
                            replay,
                            options,
                            DecisionTag::RejectedByPolicy,
                            Failure::policy("residual", reason),
                        )
                        .await;
                }
                PolicyDecision::Ask {
                    approval_key,
                    reason,
                } => {
                    // This is not a hard denial. The operation is suspended
                    // pending human approval. It records as RejectedByPolicy
                    // because the effect did not happen, but returns the
                    // retryable `ApprovalPending` failure so re-execution can
                    // pass once the broker approves the key.
                    return self
                        .deny(
                            op,
                            Some(resolved.resource),
                            replay,
                            options,
                            DecisionTag::RejectedByPolicy,
                            Failure::ApprovalPending {
                                approval_key,
                                reason,
                            },
                        )
                        .await;
                }
            }
        }

        let adapts_process = matches!(op.output, OutputMode::AsyncProcess) && !async_child;
        // Process acceptance belongs to the host, independently of method replay.
        // A method's business key may reuse a body result across executions, but
        // must never reuse a process reference or bypass another owner's admission.
        // Idempotency dedup: an `IdempotentEffect` body is keyed by its
        // authenticated-context-bound idempotency key. A second op with the same
        // effective key short-circuits to the cached outcome instead of
        // re-issuing the effect. Non-idempotent ops are never deduped here;
        // interruptions retain the original operation identity as unknown.
        let idem_key = if !adapts_process
            && matches!(replay, xolotl_types::ReplayClass::IdempotentEffect)
        {
            let key = xolotl_types::idempotency::derive_key(
                op.id,
                op.acting,
                &input,
                xolotl_types::idempotency::KeyScope {
                    resource: resolved.resource,
                    target: resolved.bound_path.as_ref(),
                    method: op.method,
                    output: op.output,
                },
            );
            let cached = match self.read_idempotent_outcome(&key).await {
                Ok(cached) => cached,
                Err(error) => {
                    invocation.observe(&error.taint);
                    if let Some(observations) = observations {
                        *observations.lock() = error.taint.clone();
                    }
                    tracing::error!(?error, op = ?op.id, "idempotency state read failed; denying op");
                    return self
                        .deny_invocation(
                            &invocation,
                            DecisionTag::RejectedByPolicy,
                            Failure::policy("idempotency", format!("state read failed: {error}")),
                        )
                        .await;
                }
            };
            if let Some(observations) = observations {
                *observations.lock() = cached.taint.clone();
            }
            match cached.outcome {
                Some(outcome) => {
                    if let Err(failure) = self.authorize_request(op.process).await {
                        invocation.observe(&cached.taint);
                        return self
                            .deny_invocation(&invocation, DecisionTag::Denied, failure)
                            .await;
                    }
                    // Cache delivery changes origin, not the retained business outcome.
                    let output = crate::invocation::complete_output(
                        DriverOutput::new(outcome)
                            .with_taint(cached.taint)
                            .with_origin(CompletionOrigin::CachedOutcome),
                        invocation.taint(),
                    );
                    let completion_error = if invocation.records_fact() {
                        self.write_fact(
                            FactWriteStage::Complete,
                            invocation.completed_fact(DecisionTag::Ok, &output),
                        )
                        .await
                        .err()
                        .map(|error| fact_completion_error(error, op.id))
                    } else {
                        None
                    };
                    return InvocationResult {
                        output,
                        completion_error,
                        effect_may_have_started: false,
                    };
                }
                None => invocation.observe(&cached.taint),
            }
            Some(key)
        } else {
            None
        };

        if let Err(failure) = invocation.check_input_taint() {
            return self
                .deny_invocation(&invocation, DecisionTag::Denied, failure)
                .await;
        }

        let do_record = invocation.records_fact();
        let mut reservation = match &self.processes {
            Some(processes) if !adapts_process => {
                match accounting::Reservation::reserve(
                    processes,
                    op,
                    contract,
                    resolved.bound_path.as_ref(),
                ) {
                    Ok(reservation) => Some(reservation),
                    Err(error @ Failure::BudgetExhausted { .. }) => {
                        return self
                            .deny_invocation(&invocation, DecisionTag::RejectedByPolicy, error)
                            .await;
                    }
                    Err(error) => {
                        return InvocationResult {
                            output: DriverOutput::new(Outcome::Fail(error.clone()))
                                .with_taint(invocation.taint().clone()),
                            completion_error: Some(CompletionError::Dispatch(error)),
                            effect_may_have_started: false,
                        };
                    }
                }
            }
            _ => None,
        };
        if do_record {
            let pending = invocation.pending_fact();
            if let Err(e) = self.write_fact(FactWriteStage::Begin, pending).await {
                tracing::error!(?e, op = ?op.id, "selected fact append failed; denying op");
                let output = DriverOutput {
                    outcome: Outcome::Fail(e.failure(op.id, FactWriteStage::Begin)),
                    taint: invocation.taint().clone(),
                    usage: None,
                    origin: CompletionOrigin::CurrentAttempt,
                };
                return InvocationResult::new(output);
            }
        }

        // Dispatch through the frozen plan. The
        // operation's own `method` id is authoritative. The op's input taint and
        // the handle's bound path are handed to the driver so persistence
        // drivers derive provenance and state drivers reach the concrete
        // path without a path ever entering the Operation/Fact.
        let mut ctx = DriverContext::new(op.acting, op.process)
            .with_operation_id(op.id)
            .with_taint(invocation.taint().clone());
        if let Some(deadline) = self.deadline {
            // Sample wall time first, then the monotonic remainder, so the
            // projection cannot extend the host deadline between reads.
            let wall_now = self.host_runtime.now_millis();
            let remaining = match deadline.saturating_duration_since(self.host_runtime.now()) {
                Ok(remaining) => remaining,
                Err(error) => {
                    let failure = Failure::from(error);
                    return InvocationResult {
                        output: DriverOutput::new(Outcome::Fail(failure.clone()))
                            .with_taint(invocation.taint().clone()),
                        completion_error: Some(CompletionError::Dispatch(failure)),
                        effect_may_have_started: false,
                    };
                }
            };
            let milliseconds = i64::try_from(remaining.as_millis()).unwrap_or(i64::MAX);
            ctx = ctx.with_deadline_ms(wall_now.saturating_add(milliseconds));
        }
        // Ordinary dispatch transfers its owned target into the driver context.
        // AsyncProcess uses the target for child admission and does not call this
        // context's driver, so it retains the path in `resolved` instead.
        if !adapts_process {
            ctx.target_path = resolved.bound_path.take();
        }
        let mut dispatch_output = op.output;
        let mut collect_sink = None;
        match op.output {
            OutputMode::Stream => match self.attach_stream_sink(op, &mut ctx, output_sink) {
                Ok(_) => {}
                Err(error) => {
                    return self
                        .deny_invocation(&invocation, DecisionTag::DriverError, error)
                        .await;
                }
            },
            OutputMode::Collect { limit } => {
                if supports.contains(OutputModeSet::STREAM) {
                    dispatch_output = OutputMode::Stream;
                    let Some(sink) = self.attach_collect_sink(&mut ctx) else {
                        return self
                            .deny_invocation(
                                &invocation,
                                DecisionTag::DriverError,
                                Failure::InvalidInput {
                                    reason: "failed to construct collect stream sink".into(),
                                },
                            )
                            .await;
                    };
                    collect_sink = Some((sink, limit));
                } else {
                    dispatch_output = OutputMode::Unary;
                }
            }
            _ => {}
        };
        if !adapts_process && let Err(failure) = self.authorize_request(op.process).await {
            return self
                .deny_invocation(&invocation, DecisionTag::Denied, failure)
                .await;
        }
        let async_result = if adapts_process {
            Some(
                self.start_async_process(op, contract, &resolved, options.record, dispatch_witness)
                    .await,
            )
        } else {
            None
        };
        let is_async = async_result.is_some();
        let async_accepted = async_result.as_ref().is_some_and(Outcome::is_success);
        if let Some(reservation) = &mut reservation
            && let Err(dispatch) = reservation.dispatched()
        {
            let output = DriverOutput::new(Outcome::Fail(dispatch.failure.clone()))
                .with_taint(invocation.taint().clone());
            let completion_error = if do_record && !dispatch.may_have_started && !async_accepted {
                self.write_fact(
                    FactWriteStage::Complete,
                    invocation.completed_fact(DecisionTag::Denied, &output),
                )
                .await
                .err()
                .map(|error| fact_completion_error(error, op.id))
                .unwrap_or_else(|| CompletionError::Dispatch(dispatch.failure.clone()))
            } else {
                CompletionError::Dispatch(dispatch.failure.clone())
            };
            return InvocationResult {
                output,
                completion_error: Some(completion_error),
                effect_may_have_started: dispatch.may_have_started || async_accepted,
            };
        }
        let plan = &resolved.plan;
        let call = async move {
            let result = if is_async {
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            } else {
                // AsyncProcess and streamed calls can lose this future after an
                // effectful driver starts. Mark the boundary before polling it.
                if may_have_external_effect(replay)
                    && let Some(witness) = dispatch_witness
                {
                    witness.store(true, Ordering::Relaxed);
                }
                match AssertUnwindSafe(plan.call(op.method, input, dispatch_output, &ctx))
                    .catch_unwind()
                    .await
                {
                    Ok(result) => result,
                    Err(payload) => Err(DriverError::Other(
                        crate::bootstrap::panic_payload_message("driver", payload),
                    )),
                }
            };
            drop(ctx);
            result
        };
        let (result, completed) = match collect_sink {
            Some((rx, limit)) => {
                match collect_driver_stream(call, rx, limit, invocation.taint().clone()).await {
                    CollectedOutput::Complete(output) => (Ok(output), true),
                    CollectedOutput::Interrupted(output) => (Ok(output), false),
                }
            }
            _ => (call.await, true),
        };
        // Output projection and cache failures do not change work already done.
        let charge = reservation
            .as_ref()
            .filter(|_| completed)
            .map(|reservation| match &result {
                Ok(output) => reservation.actual(output),
                Err(_) => reservation.actual(&DriverOutput::new(Outcome::Fail(Failure::Cancelled))),
            });
        let (result, driver_output_taint, usage, origin) = match result {
            Ok(output) => (
                Ok(output.outcome),
                output.taint,
                output.usage,
                output.origin,
            ),
            Err(DriverError::Stream(error))
                if matches!(op.output, OutputMode::Stream) && may_have_external_effect(replay) =>
            {
                (
                    Err(Failure::OutcomeUnknown {
                        operation_ids: vec![op.id.to_string()],
                        reason: "stream_output_rejected_after_dispatch".into(),
                    }),
                    error.into_inner().taint,
                    None,
                    CompletionOrigin::CurrentAttempt,
                )
            }
            Err(error) => {
                let error = driver_err_to_failure(error);
                (
                    Err(error.failure),
                    error.taint,
                    None,
                    CompletionOrigin::CurrentAttempt,
                )
            }
        };

        let (decision, outcome) = match async_result {
            Some(out) => (
                if out.is_success() {
                    DecisionTag::Ok
                } else {
                    DecisionTag::Denied
                },
                out,
            ),
            None => match result {
                Ok(out) => {
                    let out = match op.output {
                        OutputMode::Collect { .. } if !supports.contains(OutputModeSet::STREAM) => {
                            collect_outcome(out, Vec::new(), op.output)
                        }
                        OutputMode::SinkOnly => crate::invocation::sink_outcome(out),
                        _ => out,
                    };
                    (
                        if out.is_success() {
                            DecisionTag::Ok
                        } else {
                            DecisionTag::DriverError
                        },
                        out,
                    )
                }
                Err(e) => (DecisionTag::DriverError, Outcome::Fail(e)),
            },
        };

        let output = crate::invocation::complete_output(
            DriverOutput {
                outcome,
                taint: driver_output_taint,
                usage,
                origin,
            },
            invocation.taint(),
        );

        let (output, settlement) = match (charge, reservation.take()) {
            (Some(charge), Some(reservation)) => reservation.settle(charge, output),
            _ => (output, Ok(())),
        };
        if let Err(error) = settlement {
            return InvocationResult {
                output,
                completion_error: Some(CompletionError::Settlement(error)),
                effect_may_have_started: true,
            };
        }
        // The effect cannot be undone by a failed completion write. Preserve
        // its real output and surface the commit error to the request owner.
        let completion_error = if do_record && completed {
            self.write_fact(
                FactWriteStage::Complete,
                invocation.completed_fact(decision, &output),
            )
            .await
            .err()
            .map(|error| fact_completion_error(error, op.id))
        } else {
            None
        };

        if completed
            && let Some(key) = idem_key.as_ref()
            && output.outcome.is_success()
            && let Err(e) = self
                .write_idempotent_outcome(key, &output.outcome, output.taint.clone())
                .await
        {
            tracing::error!(?e, op = ?op.id, "idempotency cache write failed after completed effect");
        }

        InvocationResult {
            output,
            completion_error,
            effect_may_have_started: true,
        }
    }

    async fn read_idempotent_outcome(
        &self,
        key: &str,
    ) -> xolotl_state::StateResult<IdempotentObservation> {
        let path = idempotency_path(key).map_err(|e| {
            xolotl_state::StateError::Backend(format!("invalid idempotency path: {e}"))
        })?;
        let observation = self.state.read_tainted(&path).await?;
        let outcome = match observation.value {
            Some(value) => {
                let outcome = outcome_from_value(value).map_err(|error| {
                    xolotl_state::StateFailure::new(
                        xolotl_state::StateError::Backend(error),
                        observation.taint.clone(),
                    )
                })?;
                Some(outcome)
            }
            None => None,
        };
        Ok(IdempotentObservation {
            outcome,
            taint: observation.taint,
        })
    }

    async fn write_idempotent_outcome(
        &self,
        key: &str,
        outcome: &Outcome,
        taint: TaintSet,
    ) -> xolotl_state::StateResult<xolotl_state::StateCommit> {
        let path = idempotency_path(key).map_err(|e| {
            xolotl_state::StateError::Backend(format!("invalid idempotency path: {e}"))
        })?;
        self.state
            .write_set_tainted(&path, outcome_to_value(outcome), taint)
            .await
    }

    async fn deny(
        &self,
        op: &Operation,
        resource: Option<xolotl_types::ResourceId>,
        replay: xolotl_types::ReplayClass,
        options: InvocationOptions,
        tag: DecisionTag,
        failure: Failure,
    ) -> InvocationResult {
        if !options.record {
            return InvocationResult::new(
                DriverOutput::new(Outcome::Fail(failure)).with_taint(op.taint.clone()),
            );
        }
        let fact = crate::invocation::denied_fact(op, resource, replay, options, tag);
        self.record_denial(fact, failure, true).await
    }

    async fn deny_invocation(
        &self,
        invocation: &Invocation<'_>,
        tag: DecisionTag,
        failure: Failure,
    ) -> InvocationResult {
        if !invocation.records_fact() {
            return InvocationResult::new(
                DriverOutput::new(Outcome::Fail(failure)).with_taint(invocation.taint().clone()),
            );
        }
        self.record_denial(
            invocation.denied_fact(tag),
            failure,
            invocation.records_fact(),
        )
        .await
    }

    async fn record_denial(
        &self,
        fact: xolotl_types::Fact,
        failure: Failure,
        record: bool,
    ) -> InvocationResult {
        let taint = fact.taint.clone();
        if !record {
            return InvocationResult::new(
                DriverOutput::new(Outcome::Fail(failure)).with_taint(taint),
            );
        }
        let id = fact.id;
        let completion_error = self
            .write_fact(FactWriteStage::Complete, fact)
            .await
            .err()
            .map(|error| fact_completion_error(error, id));
        InvocationResult {
            output: DriverOutput::new(Outcome::Fail(failure)).with_taint(taint),
            completion_error,
            effect_may_have_started: false,
        }
    }
}

fn fact_completion_error(error: FactWriteError, id: xolotl_types::OperationId) -> CompletionError {
    CompletionError::Fact(error.failure(id, FactWriteStage::Complete))
}

fn idempotency_path(key: &str) -> Result<Path, xolotl_types::PathError> {
    let hash = blake3::hash(key.as_bytes());
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("idemp")?
        .try_push_literal(hash.to_hex())
}

fn outcome_to_value(outcome: &Outcome) -> Value {
    let mut m = BTreeMap::new();
    match outcome {
        Outcome::Done(v) => {
            m.insert("status".into(), Value::string("done".into()));
            m.insert("value".into(), v.clone());
        }
        Outcome::Short(v) => {
            m.insert("status".into(), Value::string("short".into()));
            m.insert("value".into(), v.clone());
        }
        Outcome::Fail(f) => {
            m.insert("status".into(), Value::string("fail".into()));
            m.insert("failure".into(), Value::string(f.to_string()));
        }
    }
    Value::map(m)
}

fn outcome_from_value(value: Value) -> Result<Outcome, String> {
    let m = value
        .as_map()
        .ok_or_else(|| format!("expected outcome map, found {value:?}"))?;
    let status = m
        .get("status")
        .ok_or_else(|| String::from("missing outcome status"))?;
    let status = status
        .as_str()
        .ok_or_else(|| format!("outcome status must be a string, found {status:?}"))?;
    match status {
        "done" => m
            .get("value")
            .cloned()
            .map(Outcome::Done)
            .ok_or_else(|| "missing done value".into()),
        "short" => m
            .get("value")
            .cloned()
            .map(Outcome::Short)
            .ok_or_else(|| "missing short value".into()),
        "fail" => Err("failed outcomes are not idempotency cache entries".into()),
        other => Err(format!("unknown outcome status `{other}`")),
    }
}

fn collect_outcome(outcome: Outcome, chunks: Vec<Value>, requested: OutputMode) -> Outcome {
    let OutputMode::Collect { limit } = requested else {
        return outcome;
    };
    match outcome {
        Outcome::Done(v) | Outcome::Short(v) => {
            if chunks.is_empty() && limit > 0 {
                Outcome::Done(Value::list(vec![v]))
            } else {
                Outcome::Done(Value::list(chunks))
            }
        }
        Outcome::Fail(f) => Outcome::Fail(f),
    }
}

struct Resolved {
    resource: xolotl_types::ResourceId,
    plan: crate::driver::DriverPlan,
    fast_path: FastPath,
    bound_path: Option<xolotl_types::Path>,
    input_admission: Option<crate::driver::InputAdmission>,
}

fn driver_err_to_failure(e: DriverError) -> TaintedFailure {
    let failure = match e {
        DriverError::NoSuchMethod(_) => Failure::policy("driver", "no such method"),
        DriverError::UnsupportedOutput(_) => Failure::InvalidInput {
            reason: "unsupported output mode".into(),
        },
        DriverError::InvalidInput(reason) => Failure::InvalidInput { reason },
        DriverError::Transport(m) => Failure::HandlerError {
            kind: "transport".into(),
            message: m,
        },
        DriverError::OutcomeUnknown {
            operation_id,
            reason,
        } => Failure::OutcomeUnknown {
            operation_ids: vec![operation_id],
            reason,
        },
        DriverError::Stream(error) => {
            let (message, value) = match error {
                StreamSendError::Full(value) => ("output sink is full".into(), value),
                StreamSendError::Closed(value) => ("output sink is closed".into(), value),
                StreamSendError::Rejected { value, reason } => {
                    (format!("output sink rejected chunk: {reason:?}"), value)
                }
            };
            return TaintedFailure::new(
                Failure::HandlerError {
                    kind: "stream".into(),
                    message,
                },
                value.taint,
            );
        }
        DriverError::Other(m) => Failure::HandlerError {
            kind: "driver".into(),
            message: m,
        },
    };
    TaintedFailure::pristine(failure)
}

// Small helpers used above to keep the hot path readable.

#[cfg(test)]
mod tests;
