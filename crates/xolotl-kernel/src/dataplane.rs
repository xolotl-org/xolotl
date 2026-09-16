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
use crate::invocation::{GrantedMethod, Invocation, InvocationOptions};
use crate::policy::{CheckCtx, PolicyDecision};
use futures_util::FutureExt;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use xolotl_types::{
    CompletionOrigin, DecisionTag, Failure, Operation, Outcome, OutputMode, OutputModeSet, Path,
    TaintSet, TaintedFailure, Value,
};

mod accounting;
mod async_process;
mod stream;
#[cfg(test)]
use stream::stream_path;
use stream::{CollectedOutput, collect_driver_stream};

/// The data plane: a handle table and a fact sink. Shared behind a lock;
/// the lock is held only for the table lookup, released before the (async)
/// driver call.
#[derive(Clone)]
pub struct DataPlane {
    /// Shared handle table used for generational handle lookup.
    pub handles: Arc<RwLock<HandleTable>>,
    /// Fact sink used to record operation attempts and completions.
    pub facts: FactSink,
    /// Idempotency dedup store: effective-key → cached outcome for
    /// `IdempotentEffect` ops. Records are stored under `state://idemp/<hash>`,
    /// where the hash is over the authenticated-context-bound key
    /// (`idempotency::derive_key`), so an injected Plan cannot forge or collide
    /// another identity's records.
    state: xolotl_state::Backend,
    /// Optional process table for the `AsyncProcess` adapter.
    processes: Option<crate::process::ProcessTable>,
}

impl DataPlane {
    /// Create a data plane over a handle table, fact sink, and state backend.
    pub fn new(
        handles: Arc<RwLock<HandleTable>>,
        facts: FactSink,
        state: xolotl_state::Backend,
    ) -> Self {
        Self {
            handles,
            facts,
            state,
            processes: None,
        }
    }

    /// Attach the process table used by async process outputs.
    pub fn with_processes(mut self, processes: crate::process::ProcessTable) -> Self {
        self.processes = Some(processes);
        self
    }

    /// Invoke one opened method through shared admission, accounting and Fact rules.
    /// Method rights, replay, costs and output support come from the frozen plan.
    pub async fn execute(&self, op: &Operation, options: InvocationOptions) -> DriverOutput {
        self.execute_inner(op, options, false, None).await
    }

    /// Invoke with a dedicated output stream. Each invocation owns one terminal lifecycle.
    pub async fn execute_with_stream(
        &self,
        op: &Operation,
        options: InvocationOptions,
        sink: DynStreamSink,
    ) -> DriverOutput {
        stream::run_streamed_invocation(
            self.execute_inner(op, options, false, Some(sink.clone())),
            sink,
            &op.taint,
        )
        .await
    }

    async fn execute_inner(
        &self,
        op: &Operation,
        options: InvocationOptions,
        async_child: bool,
        output_sink: Option<DynStreamSink>,
    ) -> DriverOutput {
        let InvocationOptions { now_millis, .. } = options;
        let replay = xolotl_types::ReplayClass::Observation;
        // Resolve the handle, clone the dispatch plan + fast-path, and capture
        // the resource id — all under a short read lock. The driver call
        // happens after the lock is dropped so concurrent ops on other handles
        // overlap.
        let (resolved, invocation) = {
            let table = self.handles.read();
            let Some(h) = table.get(op.handle) else {
                return self.deny(
                    op,
                    None,
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::policy("handle", "stale or unknown handle"),
                );
            };
            if !h.is_active() {
                return self.deny(
                    op,
                    Some(h.resource),
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::policy("state", "handle not active"),
                );
            }
            let Some(entry) = h.driver_plan.entry(op.method) else {
                return self.deny(
                    op,
                    Some(h.resource),
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::policy("method", "method absent from opened dispatch plan"),
                );
            };
            let contract = entry.contract;
            let invocation = match Invocation::admit(
                op,
                GrantedMethod {
                    owner: h.process,
                    acting: h.acting,
                    rights: h.rights,
                    resource: h.resource,
                    contract,
                },
                options,
            ) {
                Ok(invocation) => invocation,
                Err(failure) => {
                    return self.deny(
                        op,
                        Some(h.resource),
                        contract.replay,
                        now_millis,
                        DecisionTag::Denied,
                        failure,
                    );
                }
            };
            (
                Resolved {
                    resource: h.resource,
                    plan: h.driver_plan.clone(),
                    fast_path: h.fast_path.clone(),
                    bound_path: h.bound_path.clone(),
                    input_admission: entry.input_admission,
                },
                invocation,
            )
        };
        let contract = invocation.contract();
        let xolotl_types::MethodContract {
            replay, supports, ..
        } = contract;

        if let Some(admit) = resolved.input_admission {
            match std::panic::catch_unwind(AssertUnwindSafe(|| admit(&op.input))) {
                Ok(Ok(())) => {}
                Ok(Err(rejection)) => {
                    let mut redacted = op.clone();
                    redacted.input = rejection.recorded_input;
                    return self.deny(
                        &redacted,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::RejectedByPolicy,
                        rejection.failure,
                    );
                }
                Err(payload) => {
                    return self.deny(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::Denied,
                        Failure::policy(
                            "input",
                            crate::bootstrap::panic_payload_message("input admission", payload),
                        ),
                    );
                }
            }
        }

        if let Some(processes) = &self.processes {
            let finalizer = crate::process::current_finalizer(processes) == Some(op.process);
            let cleanup = crate::process::current_cleanup(processes) == Some(op.process);
            let status = processes.status(op.process);
            let cleanup_only =
                finalizer || (cleanup && status != Some(xolotl_types::ProcessStatus::Running));
            if cleanup_only && !contract.permits_cleanup(op.process) {
                return self.deny(
                    op,
                    Some(resolved.resource),
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::policy("finalizer", "method is not admitted for cleanup"),
                );
            }
            let admitted = match status {
                Some(xolotl_types::ProcessStatus::Running) => true,
                Some(xolotl_types::ProcessStatus::Finalizing) if finalizer || cleanup => true,
                Some(xolotl_types::ProcessStatus::Cancelled) if cleanup => true,
                _ => false,
            };
            if !admitted {
                return self.deny(
                    op,
                    Some(resolved.resource),
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::Cancelled,
                );
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
                    return self.deny(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::RejectedByPolicy,
                        Failure::policy("residual", reason),
                    );
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
                    return self.deny(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::RejectedByPolicy,
                        Failure::ApprovalPending {
                            approval_key,
                            reason,
                        },
                    );
                }
            }
        }

        // Idempotency dedup: an `IdempotentEffect` op is keyed by its
        // authenticated-context-bound idempotency key. A second op with the same
        // effective key short-circuits to the cached outcome instead of
        // re-issuing the effect — this is what makes crash-replay and explicit
        // outbox retries safe. Non-idempotent ops are never deduped here (their
        // safety comes from the write-ahead barrier + quarantine instead).
        let idem_key = if matches!(replay, xolotl_types::ReplayClass::IdempotentEffect) {
            let key = xolotl_types::idempotency::derive_key(
                op.id,
                op.acting,
                &input,
                xolotl_types::idempotency::KeyScope {
                    resource: resolved.resource,
                    method: op.method,
                    output: op.output,
                    creates_process: matches!(op.output, OutputMode::AsyncProcess) && !async_child,
                },
            );
            match self.read_idempotent_outcome(&key).await {
                Ok(Some(cached)) => {
                    // Cache delivery changes origin, not the retained business outcome.
                    let output = crate::invocation::complete_output(
                        DriverOutput::new(cached.outcome)
                            .with_taint(cached.taint)
                            .with_origin(CompletionOrigin::CachedOutcome),
                        &op.taint,
                    );
                    if invocation.records_fact()
                        && let Err(e) = self
                            .facts
                            .complete(invocation.completed_fact(DecisionTag::Ok, &output))
                    {
                        tracing::error!(?e, op = ?op.id, "idempotent-dedup fact record failed; denying op");
                        return DriverOutput {
                            outcome: Outcome::Fail(Failure::policy(
                                "durability",
                                format!("dedup fact record failed: {e}"),
                            )),
                            taint: output.taint,
                            usage: None,
                            origin: CompletionOrigin::CurrentAttempt,
                        };
                    }
                    return output;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(?e, op = ?op.id, "idempotency state read failed; denying op");
                    let mut fact = crate::invocation::denied_fact(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::RejectedByPolicy,
                    );
                    fact.taint.union(&e.taint);
                    return self.record_denial(
                        fact,
                        Failure::policy("idempotency", format!("state read failed: {e}")),
                    );
                }
            }
            Some(key)
        } else {
            None
        };

        // Begin the Fact *before* the effect as the write-ahead barrier for
        // NonIdempotentEffect. Only Deterministic/Observation reads may
        // skip when their output is not consumed. IdempotentEffect and
        // NonIdempotentEffect are external side effects and must record even
        // when their result is ignored.
        let do_record = invocation.records_fact();
        let adapts_process = matches!(op.output, OutputMode::AsyncProcess) && !async_child;
        let mut reservation = match &self.processes {
            Some(processes) if !adapts_process => {
                match accounting::Reservation::reserve(processes, op, contract) {
                    Ok(reservation) => Some(reservation),
                    Err(dim) => {
                        return self.deny(
                            op,
                            Some(resolved.resource),
                            replay,
                            now_millis,
                            DecisionTag::RejectedByPolicy,
                            Failure::BudgetExhausted { dim },
                        );
                    }
                }
            }
            _ => None,
        };
        if do_record {
            let pending = invocation.pending_fact();
            // Fail-closed: if we cannot durably record the intent, we must NOT
            // issue the effect ( — the write-ahead barrier exists precisely
            // to prevent an "already happened, never recorded" effect).
            if let Err(e) = self.facts.begin(pending) {
                tracing::error!(?e, op = ?op.id, "write-ahead fact append failed; denying op");
                return DriverOutput {
                    outcome: Outcome::Fail(Failure::policy(
                        "durability",
                        format!("write-ahead barrier failed: {e}"),
                    )),
                    taint: op.taint.clone(),
                    usage: None,
                    origin: CompletionOrigin::CurrentAttempt,
                };
            }
        }

        // Dispatch through the frozen plan. The
        // operation's own `method` id is authoritative. The op's input taint and
        // the handle's bound path are handed to the driver so persistence
        // drivers derive provenance and state drivers reach the concrete
        // path without a path ever entering the Operation/Fact.
        let mut ctx = DriverContext::new(op.acting, op.process)
            .with_operation_id(op.id)
            .with_taint(op.taint.clone());
        if let Some(p) = &resolved.bound_path {
            ctx = ctx.with_target_path(p.clone());
        }
        let mut dispatch_output = op.output;
        let mut collect_sink = None;
        match op.output {
            OutputMode::Stream => match self.attach_stream_sink(op, &mut ctx, output_sink) {
                Ok(_) => {}
                Err(error) => {
                    return self.deny(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::DriverError,
                        error,
                    );
                }
            },
            OutputMode::Collect { limit } => {
                if supports.contains(OutputModeSet::STREAM) {
                    dispatch_output = OutputMode::Stream;
                    let Some(sink) = self.attach_collect_sink(&mut ctx) else {
                        return self.deny(
                            op,
                            Some(resolved.resource),
                            replay,
                            now_millis,
                            DecisionTag::DriverError,
                            Failure::InvalidInput {
                                reason: "failed to construct collect stream sink".into(),
                            },
                        );
                    };
                    collect_sink = Some((sink, limit));
                } else {
                    dispatch_output = OutputMode::Unary;
                }
            }
            _ => {}
        };
        let async_result = if adapts_process {
            Some(self.start_async_process(op, contract, &resolved))
        } else {
            None
        };
        let is_async = async_result.is_some();
        if let Some(reservation) = &mut reservation {
            reservation.dispatched();
        }
        let plan = &resolved.plan;
        let call = async move {
            let result = if is_async {
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            } else {
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
                match collect_driver_stream(call, rx, limit, op.taint.clone()).await {
                    CollectedOutput::Complete(output) => (Ok(output), true),
                    CollectedOutput::Interrupted(output) => (Ok(output), false),
                }
            }
            _ => (call.await, true),
        };
        // Output projection and cache failures do not change work already done.
        if completed && let Some(reservation) = reservation.take() {
            let charge = match &result {
                Ok(output) => reservation.actual(output),
                Err(_) => reservation.actual(&DriverOutput::new(Outcome::Fail(Failure::Cancelled))),
            };
            reservation.settle(charge);
        }
        let (result, driver_output_taint, usage, origin) = match result {
            Ok(output) => (
                Ok(output.outcome),
                output.taint,
                output.usage,
                output.origin,
            ),
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
                        OutputMode::SinkOnly => sink_outcome(out),
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
            &op.taint,
        );

        // Complete the Fact with the outcome (only if we began one). The effect
        // has already been issued, so a completion-write failure cannot un-issue
        // it: log it and let crash recovery reconcile from the begun (fsync'd)
        // pending record. The caller still gets the real outcome.
        if do_record
            && completed
            && let Err(e) = self
                .facts
                .complete(invocation.completed_fact(decision, &output))
        {
            tracing::error!(?e, op = ?op.id, "post-effect fact completion failed; recovery will reconcile");
        }

        if completed
            && let Some(key) = idem_key.as_ref()
            && output.outcome.is_success()
            && let Err(e) = self
                .write_idempotent_outcome(key, &output.outcome, output.taint.clone())
                .await
        {
            tracing::error!(?e, op = ?op.id, "idempotency cache write failed after completed effect");
        }

        output
    }

    async fn read_idempotent_outcome(
        &self,
        key: &str,
    ) -> xolotl_state::StateResult<Option<DriverOutput>> {
        let path = idempotency_path(key).map_err(|e| {
            xolotl_state::StateError::Backend(format!("invalid idempotency path: {e}"))
        })?;
        match self.state.read_tainted(&path).await? {
            Some(value) => {
                let outcome = outcome_from_value(value.value).map_err(|error| {
                    xolotl_state::StateFailure::new(
                        xolotl_state::StateError::Backend(error),
                        value.taint.clone(),
                    )
                })?;
                Ok(Some(DriverOutput::new(outcome).with_taint(value.taint)))
            }
            None => Ok(None),
        }
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

    fn deny(
        &self,
        op: &Operation,
        resource: Option<xolotl_types::ResourceId>,
        replay: xolotl_types::ReplayClass,
        now_millis: i64,
        tag: DecisionTag,
        failure: Failure,
    ) -> DriverOutput {
        let fact = crate::invocation::denied_fact(op, resource, replay, now_millis, tag);
        self.record_denial(fact, failure)
    }

    fn record_denial(&self, fact: xolotl_types::Fact, failure: Failure) -> DriverOutput {
        // A denied or rejected effect attempt is still recorded because
        // failures must record a Fact for why-not and retry decisions. A record
        // failure on the deny path is logged; the effect was never issued, so
        // there is nothing unsafe to reconcile.
        let taint = fact.taint.clone();
        let operation = fact.id;
        if let Err(e) = self.facts.complete(fact) {
            tracing::error!(?e, op = ?operation, "deny-path fact record failed");
        }
        DriverOutput::new(Outcome::Fail(failure)).with_taint(taint)
    }
}

fn idempotency_path(key: &str) -> Result<Path, xolotl_types::PathError> {
    let hash = blake3::hash(key.as_bytes());
    Path::try_new("state")?
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

fn sink_outcome(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Done(_) | Outcome::Short(_) => Outcome::Done(Value::null()),
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
