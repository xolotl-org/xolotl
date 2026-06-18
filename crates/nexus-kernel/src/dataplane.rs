//! The data plane: fixed-cost operation execution.
//!
//! `execute` is the data-plane hot path: generational handle lookup → owner check
//! → active check → rights bitmap → (Conditional only) residual policy → driver
//! dispatch → Fact append. `Unconditional` handles skip the policy step
//! entirely as a structural fast path. The data plane receives compiled handles
//! and driver plans.

use crate::driver::{DriverContext, DriverError};
use crate::fact::FactSink;
use crate::handle::{FastPath, HandleTable};
use crate::open::derive_handle;
use crate::policy::{CheckCtx, PolicyDecision};
use crate::process::ProcessEntry;
use nexus_types::{
    DecisionTag, Fact, Failure, Operation, Outcome, OutcomeRef, OutputMode, OutputModeSet, Path,
    TaintSet, Timestamp, Value, ValueRef,
};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Result of executing one operation: the outcome plus the recorded decision
/// tag (so the executor can drive control flow and the Fact is consistent).
pub struct ExecOutput {
    /// Driver or policy outcome produced by the operation.
    pub outcome: Outcome,
    /// Taint carried by the operation result.
    pub output_taint: TaintSet,
}

/// Execution knobs derived by the executor after handle/open planning.
#[derive(Clone, Copy, Debug)]
pub struct ExecuteParams {
    /// Method bit position used for rights and spawn-derived handles.
    pub method_index: u32,
    /// Replay class recorded on the resulting fact.
    pub replay: nexus_types::ReplayClass,
    /// Output modes declared by the selected method.
    pub supports: OutputModeSet,
    /// Whether list-shaped batches are part of the method contract.
    pub batchable: bool,
    /// Wall-clock timestamp assigned to emitted facts.
    pub now_millis: i64,
    /// Whether a deterministic operation records a fact.
    pub record: bool,
}

struct CompletedFact<'a> {
    op: &'a Operation,
    resource: nexus_types::ResourceId,
    replay: nexus_types::ReplayClass,
    now_millis: i64,
    decision: DecisionTag,
    outcome: &'a Outcome,
    taint: &'a TaintSet,
    batchable: bool,
}

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
    state: nexus_state::Backend,
    /// Optional process table for the `AsyncProcess` adapter.
    processes: Option<crate::process::ProcessTable>,
}

impl DataPlane {
    /// Create a data plane over a handle table, fact sink, and state backend.
    pub fn new(
        handles: Arc<RwLock<HandleTable>>,
        facts: FactSink,
        state: nexus_state::Backend,
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

    /// Execute one operation. `method_index` is the bit position of the
    /// method within the resource's interface (for the rights bitmap);
    /// `replay` is the operation's derived [`nexus_types::ReplayClass`] used for the Fact
    /// barrier. `now_millis` stamps the Fact and feeds residual checks.
    /// `record` gates Fact creation: side effects, observations that feed
    /// control flow, and denials always record; a pure-deterministic read whose
    /// output nothing consumes may skip (recovery recomputes it).
    pub async fn execute(
        &self,
        op: &Operation,
        method_index: u32,
        replay: nexus_types::ReplayClass,
        supports: OutputModeSet,
        now_millis: i64,
        record: bool,
    ) -> ExecOutput {
        self.execute_batchable(
            op,
            ExecuteParams {
                method_index,
                replay,
                supports,
                batchable: false,
                now_millis,
                record,
            },
        )
        .await
    }

    /// Execute one operation while passing the method's `batchable` declaration
    /// into the driver context.
    pub async fn execute_batchable(&self, op: &Operation, params: ExecuteParams) -> ExecOutput {
        self.execute_inner(op, params, false).await
    }

    /// Record a pre-dispatch denial for an Operation that has already resolved
    /// to a handle but must fail before issuing the driver call. This covers
    /// executor-level checks such as budget reservation: the
    /// effect is never sent, but the rejected attempt still appears in the Fact
    /// stream for recovery, why-not, audit, and accounting projections.
    pub fn record_pre_dispatch_denial(
        &self,
        op: &Operation,
        replay: nexus_types::ReplayClass,
        now_millis: i64,
        tag: DecisionTag,
        failure: Failure,
    ) -> ExecOutput {
        let resource = self.handles.read().get(op.handle).map(|h| h.resource);
        self.deny(op, resource, replay, now_millis, tag, failure)
    }

    async fn execute_inner(
        &self,
        op: &Operation,
        params: ExecuteParams,
        async_child: bool,
    ) -> ExecOutput {
        let ExecuteParams {
            method_index,
            replay,
            supports,
            batchable,
            now_millis,
            record,
        } = params;
        // Resolve the handle, clone the dispatch plan + fast-path, and capture
        // the resource id — all under a short read lock. The driver call
        // happens after the lock is dropped so concurrent ops on other handles
        // overlap.
        let resolved = {
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
            // owner check (pointer-cheap), active check, rights bitmap.
            if !h.check_owner(op.process) {
                return self.deny(
                    op,
                    Some(h.resource),
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::policy("owner", "handle not owned by caller"),
                );
            }
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
            if !h.allows_method(method_index) {
                return self.deny(
                    op,
                    Some(h.resource),
                    replay,
                    now_millis,
                    DecisionTag::Denied,
                    Failure::PermissionDenied {
                        required: vec![],
                        actual: vec![],
                    },
                );
            }
            Resolved {
                resource: h.resource,
                plan: h.driver_plan.clone(),
                fast_path: h.fast_path.clone(),
                bound_path: h.bound_path.clone(),
            }
        };

        // The driver receives the full input value. Large modality values
        // (Blob/Tensor/Frame) are already out-of-line refs, so this is cheap;
        // the Fact records the fixed-size `ValueRef` projection.
        let input = op.input.clone();

        // Pairing display secrets are generated inside PairingDriver and handed
        // to the Console/transport edge through a non-Operation channel. If an
        // malformed caller sends `pairing_secret` as input, reject before
        // policy/driver dispatch and record only a redacted Fact.
        if pairing_secret_in_operation_input(resolved.bound_path.as_ref(), &input) {
            let mut redacted = op.clone();
            redacted.input = redact_pairing_secret_input(&input);
            return self.deny(
                &redacted,
                Some(resolved.resource),
                replay,
                now_millis,
                DecisionTag::RejectedByPolicy,
                Failure::InvalidInput {
                    reason: "pairing_secret is not an Operation input".into(),
                },
            );
        }

        if !op.output.is_supported_by(supports) {
            return self.deny(
                op,
                Some(resolved.resource),
                replay,
                now_millis,
                DecisionTag::Denied,
                Failure::InvalidInput {
                    reason: format!(
                        "method {:?} does not support output mode {:?}",
                        op.method, op.output
                    ),
                },
            );
        }

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
        let idem_key = if matches!(replay, nexus_types::ReplayClass::IdempotentEffect) {
            let key = nexus_types::idempotency::derive_key(op.id, op.acting, &input);
            match self.read_idempotent_outcome(&key).await {
                Ok(Some(cached)) => {
                    // A duplicate: replay the prior result as a Short-circuit
                    // (the driver is not called again). Still recorded so the
                    // Fact log reflects the (deduped) attempt.
                    let short = match cached {
                        Outcome::Done(v) | Outcome::Short(v) => Outcome::Short(v),
                        Outcome::Fail(f) => Outcome::Fail(f),
                    };
                    if (record
                        || matches!(
                            replay,
                            nexus_types::ReplayClass::IdempotentEffect
                                | nexus_types::ReplayClass::NonIdempotentEffect
                        ))
                        && let Err(e) = self.facts.complete(self.completed_fact(CompletedFact {
                            op,
                            resource: resolved.resource,
                            replay,
                            now_millis,
                            decision: DecisionTag::Ok,
                            outcome: &short,
                            taint: &op.taint,
                            batchable,
                        }))
                    {
                        tracing::error!(?e, op = ?op.id, "idempotent-dedup fact record failed");
                    }
                    return ExecOutput {
                        outcome: short,
                        output_taint: TaintSet::pristine(),
                    };
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(?e, op = ?op.id, "idempotency state read failed; denying op");
                    return self.deny(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::RejectedByPolicy,
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
        let do_record = record
            || matches!(
                replay,
                nexus_types::ReplayClass::IdempotentEffect
                    | nexus_types::ReplayClass::NonIdempotentEffect
            )
            || matches!(op.output, OutputMode::AsyncProcess);
        if do_record {
            let pending = self.pending_fact(op, resolved.resource, replay, now_millis);
            // Fail-closed: if we cannot durably record the intent, we must NOT
            // issue the effect ( — the write-ahead barrier exists precisely
            // to prevent an "already happened, never recorded" effect).
            if let Err(e) = self.facts.begin(pending) {
                tracing::error!(?e, op = ?op.id, "write-ahead fact append failed; denying op");
                return ExecOutput {
                    outcome: Outcome::Fail(Failure::policy(
                        "durability",
                        format!("write-ahead barrier failed: {e}"),
                    )),
                    output_taint: TaintSet::pristine(),
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
        let mut stream_task = None;
        let mut collect_task = None;
        match op.output {
            OutputMode::Stream => match self.attach_stream_sink(op, &mut ctx) {
                Ok(task) => stream_task = Some(task),
                Err(error) => {
                    return self.deny(
                        op,
                        Some(resolved.resource),
                        replay,
                        now_millis,
                        DecisionTag::DriverError,
                        driver_err_to_failure(error),
                    );
                }
            },
            OutputMode::Collect { limit } => {
                if supports.contains(OutputModeSet::STREAM) {
                    dispatch_output = OutputMode::Stream;
                    let Some(task) = self.attach_collect_sink(&mut ctx, limit) else {
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
                    collect_task = Some(task);
                } else {
                    dispatch_output = OutputMode::Unary;
                }
            }
            _ => {}
        };
        let async_result = if matches!(op.output, OutputMode::AsyncProcess) && !async_child {
            Some(self.start_async_process(op, params, &resolved))
        } else {
            None
        };
        let mut result = match &async_result {
            Some(_) => Ok(Outcome::Done(Value::Null)),
            None => {
                resolved
                    .plan
                    .call(op.method, input, dispatch_output, &ctx)
                    .await
            }
        };
        if matches!(op.output, OutputMode::Stream) {
            match &result {
                Ok(_) => {
                    if !ctx.emit(Value::StreamEnd(nexus_types::StreamMarker::Done)) {
                        tracing::debug!(op = ?op.id, "stream end marker receiver closed");
                    }
                }
                Err(e) => {
                    if !ctx.emit(Value::StreamEnd(nexus_types::StreamMarker::Error {
                        message: e.to_string(),
                    })) {
                        tracing::debug!(op = ?op.id, "stream error marker receiver closed");
                    }
                }
            }
        }
        let driver_output_taint = ctx.output_taint();
        drop(ctx);
        if let Some(task) = stream_task {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    result = Err(DriverError::Other(format!("stream sink failed: {e}")));
                }
                Err(e) => {
                    result = Err(DriverError::Other(format!("stream sink task failed: {e}")));
                }
            }
        }
        let collected = match collect_task {
            Some(task) => match task.await {
                Ok(chunks) => Some(chunks),
                Err(e) => {
                    result = Err(DriverError::Other(format!("collect sink task failed: {e}")));
                    None
                }
            },
            None => None,
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
                        OutputMode::Collect { .. } => {
                            collect_outcome(out, collected.unwrap_or_default(), op.output)
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
                Err(e) => (
                    DecisionTag::DriverError,
                    Outcome::Fail(driver_err_to_failure(e)),
                ),
            },
        };

        let output_taint = if outcome.is_success() {
            driver_output_taint
        } else {
            TaintSet::pristine()
        };
        let mut fact_taint = op.taint.clone();
        fact_taint.union(&output_taint);

        // Complete the Fact with the outcome (only if we began one). The effect
        // has already been issued, so a completion-write failure cannot un-issue
        // it: log it and let crash recovery reconcile from the begun (fsync'd)
        // pending record. The caller still gets the real outcome.
        if do_record
            && let Err(e) = self.facts.complete(self.completed_fact(CompletedFact {
                op,
                resource: resolved.resource,
                replay,
                now_millis,
                decision,
                outcome: &outcome,
                taint: &fact_taint,
                batchable,
            }))
        {
            tracing::error!(?e, op = ?op.id, "post-effect fact completion failed; recovery will reconcile");
        }

        // Cache a successful IdempotentEffect outcome under its key so a later
        // op with the same key dedupes to it. Failures are not cached —
        // Failed idempotent operations are re-attempted.
        if let Some(key) = idem_key
            && outcome.is_success()
            && let Err(e) = self.write_idempotent_outcome(&key, &outcome).await
        {
            tracing::error!(?e, op = ?op.id, "idempotency state write failed");
        }
        ExecOutput {
            outcome,
            output_taint,
        }
    }

    async fn read_idempotent_outcome(
        &self,
        key: &str,
    ) -> nexus_state::StateResult<Option<Outcome>> {
        let path = idempotency_path(key).map_err(|e| {
            nexus_state::StateError::Backend(format!("invalid idempotency path: {e}"))
        })?;
        match self.state.read(&path).await? {
            Some(value) => outcome_from_value(value)
                .map(Some)
                .map_err(nexus_state::StateError::Backend),
            None => Ok(None),
        }
    }

    async fn write_idempotent_outcome(
        &self,
        key: &str,
        outcome: &Outcome,
    ) -> nexus_state::StateResult<()> {
        let path = idempotency_path(key).map_err(|e| {
            nexus_state::StateError::Backend(format!("invalid idempotency path: {e}"))
        })?;
        self.state.write_set(&path, outcome_to_value(outcome)).await
    }

    fn deny(
        &self,
        op: &Operation,
        resource: Option<nexus_types::ResourceId>,
        replay: nexus_types::ReplayClass,
        now_millis: i64,
        tag: DecisionTag,
        failure: Failure,
    ) -> ExecOutput {
        // A denied or rejected effect attempt is still recorded because
        // failures must record a Fact for why-not and retry decisions. A record
        // failure on the deny path is logged; the effect was never issued, so
        // there is nothing unsafe to reconcile.
        let fact = self.completed_fact(CompletedFact {
            op,
            resource: resource.unwrap_or_else(|| nexus_types::ResourceId::new(0)),
            replay,
            now_millis,
            decision: tag,
            outcome: &Outcome::Fail(failure.clone()),
            taint: &op.taint,
            batchable: false,
        });
        if let Err(e) = self.facts.complete(fact) {
            tracing::error!(?e, op = ?op.id, "deny-path fact record failed");
        }
        ExecOutput {
            outcome: Outcome::Fail(failure),
            output_taint: TaintSet::pristine(),
        }
    }

    fn pending_fact(
        &self,
        op: &Operation,
        resource: nexus_types::ResourceId,
        replay: nexus_types::ReplayClass,
        now_millis: i64,
    ) -> Fact {
        Fact {
            id: op.id,
            schema_version: Fact::SCHEMA_VERSION,
            caller: op.process,
            acting: op.acting,
            handle: op.handle,
            resource,
            method: op.method,
            input_ref: ValueRef::of_ref(&op.input),
            taint: op.taint.clone(),
            decision: DecisionTag::Ok, // provisional; set on complete
            outcome_ref: OutcomeRef::None,
            batch: None,
            replay,
            timestamp: Timestamp::millis(now_millis),
        }
    }

    fn completed_fact(&self, input: CompletedFact<'_>) -> Fact {
        let CompletedFact {
            op,
            resource,
            replay,
            now_millis,
            decision,
            outcome,
            taint,
            batchable,
        } = input;
        let outcome_ref = match outcome {
            Outcome::Done(v) | Outcome::Short(v) => OutcomeRef::of_ref(v),
            Outcome::Fail(_) => OutcomeRef::None,
        };
        let batch = if batchable {
            nexus_types::BatchSummary::new(&op.input, Some(&outcome_ref))
        } else {
            None
        };
        Fact {
            id: op.id,
            schema_version: Fact::SCHEMA_VERSION,
            caller: op.process,
            acting: op.acting,
            handle: op.handle,
            resource,
            method: op.method,
            input_ref: ValueRef::of_ref(&op.input),
            taint: taint.clone(),
            decision,
            outcome_ref,
            batch,
            replay,
            timestamp: Timestamp::millis(now_millis),
        }
    }

    fn attach_stream_sink(
        &self,
        op: &Operation,
        ctx: &mut DriverContext,
    ) -> Result<tokio::task::JoinHandle<Result<(), String>>, DriverError> {
        let state = self.state.clone();
        let path = stream_path(op).map_err(|error| {
            DriverError::InvalidInput(format!("stream path construction failed: {error}"))
        })?;
        let taint = op.taint.clone();
        let append_path = path.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let previous = std::mem::replace(
            ctx,
            DriverContext::new(op.acting, op.process).with_operation_id(op.id),
        );
        *ctx = previous.with_stream(path, tx);
        Ok(tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                if let Err(e) = state
                    .write_append_tainted(&append_path, chunk, taint.clone())
                    .await
                {
                    tracing::error!(?e, path = %append_path, "stream append failed");
                    return Err(format!("append to {append_path} failed: {e}"));
                }
            }
            Ok(())
        }))
    }

    fn attach_collect_sink(
        &self,
        ctx: &mut DriverContext,
        limit: usize,
    ) -> Option<tokio::task::JoinHandle<Vec<Value>>> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let acting = ctx.acting;
        let caller = ctx.caller;
        let previous = std::mem::replace(ctx, DriverContext::new(acting, caller));
        let collect_path = match collect_stream_path() {
            Ok(path) => path,
            Err(e) => {
                tracing::error!(?e, "collect stream path construction failed");
                return None;
            }
        };
        *ctx = previous.with_stream(collect_path, tx);
        Some(tokio::spawn(async move {
            let mut chunks = Vec::new();
            while chunks.len() < limit {
                match rx.recv().await {
                    Some(chunk) => chunks.push(chunk),
                    None => break,
                }
            }
            chunks
        }))
    }

    fn start_async_process(
        &self,
        op: &Operation,
        params: ExecuteParams,
        resolved: &Resolved,
    ) -> Outcome {
        let ExecuteParams {
            method_index,
            replay,
            supports,
            batchable,
            ..
        } = params;
        let Some(processes) = self.processes.clone() else {
            return Outcome::Fail(Failure::policy(
                "async-process",
                "AsyncProcess requires a process table",
            ));
        };
        let state = self.state.clone();

        let child = processes.fresh_id();
        let child_handle = {
            let mut handles = self.handles.write();
            match derive_handle(
                &mut handles,
                op.handle,
                nexus_types::Rights::new(
                    nexus_types::MethodBitmap::method(method_index),
                    nexus_types::RightFlags::empty(),
                ),
                nexus_types::DeriveKind::SpawnWith,
                child,
            ) {
                Ok(id) => id,
                Err(_) => {
                    return Outcome::Fail(Failure::PermissionDenied {
                        required: vec!["SPAWN_WITH".into()],
                        actual: vec![],
                    });
                }
            }
        };

        let mut entry = ProcessEntry::new(child, Some(op.process), op.acting);
        entry.status = nexus_types::ProcessStatus::Running;
        processes.insert(entry);

        let (proc_path, status_path, outcome_path) = match (
            async_proc_path(child),
            async_status_path(child),
            async_outcome_path(child),
        ) {
            (Ok(proc_path), Ok(status_path), Ok(outcome_path)) => {
                (proc_path, status_path, outcome_path)
            }
            (proc_path, status_path, outcome_path) => {
                let mut errors = Vec::new();
                if let Err(e) = proc_path {
                    errors.push(format!("proc path: {e}"));
                }
                if let Err(e) = status_path {
                    errors.push(format!("status path: {e}"));
                }
                if let Err(e) = outcome_path {
                    errors.push(format!("outcome path: {e}"));
                }
                return Outcome::Fail(Failure::InvalidInput {
                    reason: format!(
                        "failed to construct async process resource paths: {}",
                        errors.join(", ")
                    ),
                });
            }
        };
        let child_op = Operation {
            id: nexus_types::OperationId::new(child, nexus_types::NodeId::ROOT, 0),
            process: child,
            acting: op.acting,
            handle: child_handle,
            method: op.method,
            input: op.input.clone(),
            taint: op.taint.clone(),
            // The child is the actual Executor Resource. It calls the driver in
            // the same mode, but `async_child=true` below prevents another
            // wrapper spawn.
            output: OutputMode::AsyncProcess,
        };
        let child_dp = self.clone();
        let child_state = state.clone();
        let child_processes = processes.clone();
        let parent = op.process;
        let child_taint = op.taint.clone();
        let child_status_path = status_path.clone();
        let child_outcome_path = outcome_path.clone();
        let child_proc_path = proc_path.clone();
        tokio::spawn(async move {
            let started = async_status_value(
                "running",
                parent,
                child,
                &child_proc_path,
                &child_outcome_path,
                None,
            );
            if let Err(e) = child_state
                .write_set_tainted(&child_status_path, started, child_taint.clone())
                .await
            {
                tracing::error!(?e, child = ?child, "async process status write failed");
            }
            let outcome = Box::pin(child_dp.execute_inner(
                &child_op,
                ExecuteParams {
                    method_index,
                    replay,
                    supports,
                    batchable,
                    now_millis: crate::executor::now_millis(),
                    record: true,
                },
                true,
            ))
            .await
            .outcome;
            let terminal = if outcome.is_success() {
                nexus_types::ProcessStatus::Completed
            } else {
                nexus_types::ProcessStatus::Failed
            };
            child_processes.set_status(child, terminal);
            if let Err(e) = child_state
                .write_set_tainted(
                    &child_outcome_path,
                    outcome_to_value(&outcome),
                    child_taint.clone(),
                )
                .await
            {
                tracing::error!(?e, child = ?child, "async process outcome write failed");
            }
            let phase = if outcome.is_success() {
                "completed"
            } else {
                "failed"
            };
            let status = async_status_value(
                phase,
                parent,
                child,
                &child_proc_path,
                &child_outcome_path,
                Some(&outcome),
            );
            if let Err(e) = child_state
                .write_set_tainted(&child_status_path, status, child_taint)
                .await
            {
                tracing::error!(?e, child = ?child, "async process terminal status write failed");
            }
        });

        Outcome::Done(async_ref_value(
            AsyncRefMeta {
                parent: op.process,
                child,
                resource: resolved.resource,
                method: op.method,
                handle: child_handle,
            },
            AsyncRefPaths {
                proc_path: &proc_path,
                status_path: &status_path,
                outcome_path: &outcome_path,
            },
        ))
    }
}

fn stream_path(op: &Operation) -> Result<Path, nexus_types::PathError> {
    Path::try_new("state")?
        .try_push("stream")?
        .try_push(op.process.get().to_string())?
        .try_push(op.id.position.get().to_string())
}

fn collect_stream_path() -> Result<Path, nexus_types::PathError> {
    Path::try_new("state")?
        .try_push("stream")?
        .try_push("collect")
}

fn idempotency_path(key: &str) -> Result<Path, nexus_types::PathError> {
    let hash = blake3::hash(key.as_bytes());
    Path::try_new("state")?
        .try_push("idemp")?
        .try_push(hash.to_hex())
}

fn async_proc_path(process: nexus_types::ProcessId) -> Result<Path, nexus_types::PathError> {
    Path::try_new("proc")?
        .try_push("async")?
        .try_push(process.get().to_string())
}

fn async_status_path(process: nexus_types::ProcessId) -> Result<Path, nexus_types::PathError> {
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("async")?
        .try_push(process.get().to_string())?
        .try_push("status")
}

fn async_outcome_path(process: nexus_types::ProcessId) -> Result<Path, nexus_types::PathError> {
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("async")?
        .try_push(process.get().to_string())?
        .try_push("outcome")
}

struct AsyncRefMeta {
    parent: nexus_types::ProcessId,
    child: nexus_types::ProcessId,
    resource: nexus_types::ResourceId,
    method: nexus_types::MethodId,
    handle: nexus_types::HandleId,
}

struct AsyncRefPaths<'a> {
    proc_path: &'a Path,
    status_path: &'a Path,
    outcome_path: &'a Path,
}

fn async_ref_value(meta: AsyncRefMeta, paths: AsyncRefPaths<'_>) -> Value {
    let mut m = BTreeMap::new();
    m.insert("kind".into(), Value::Str("executor_resource".into()));
    m.insert("path".into(), Value::Str(paths.proc_path.to_string()));
    m.insert(
        "parent_process".into(),
        Value::Int(meta.parent.get() as i64),
    );
    m.insert("process".into(), Value::Int(meta.child.get() as i64));
    m.insert("resource".into(), Value::Int(meta.resource.get() as i64));
    m.insert("method".into(), Value::Int(meta.method.get() as i64));
    m.insert(
        "handle".into(),
        Value::Str(format!("{}.{}", meta.handle.index, meta.handle.generation)),
    );
    m.insert(
        "status_path".into(),
        Value::Str(paths.status_path.to_string()),
    );
    m.insert(
        "outcome_path".into(),
        Value::Str(paths.outcome_path.to_string()),
    );
    Value::Map(m)
}

fn async_status_value(
    phase: &str,
    parent: nexus_types::ProcessId,
    child: nexus_types::ProcessId,
    proc_path: &Path,
    outcome_path: &Path,
    outcome: Option<&Outcome>,
) -> Value {
    let mut m = BTreeMap::new();
    m.insert("phase".into(), Value::Str(phase.into()));
    m.insert("path".into(), Value::Str(proc_path.to_string()));
    m.insert("parent_process".into(), Value::Int(parent.get() as i64));
    m.insert("process".into(), Value::Int(child.get() as i64));
    m.insert("outcome_path".into(), Value::Str(outcome_path.to_string()));
    if let Some(outcome) = outcome {
        m.insert("outcome".into(), outcome_to_value(outcome));
    }
    Value::Map(m)
}

fn outcome_to_value(outcome: &Outcome) -> Value {
    let mut m = BTreeMap::new();
    match outcome {
        Outcome::Done(v) => {
            m.insert("status".into(), Value::Str("done".into()));
            m.insert("value".into(), v.clone());
        }
        Outcome::Short(v) => {
            m.insert("status".into(), Value::Str("short".into()));
            m.insert("value".into(), v.clone());
        }
        Outcome::Fail(f) => {
            m.insert("status".into(), Value::Str("fail".into()));
            m.insert("failure".into(), Value::Str(f.to_string()));
        }
    }
    Value::Map(m)
}

fn outcome_from_value(value: Value) -> Result<Outcome, String> {
    let mut m = match value {
        Value::Map(m) => m,
        other => return Err(format!("expected outcome map, found {other:?}")),
    };
    let status = match m.remove("status") {
        Some(Value::Str(status)) => status,
        Some(other) => return Err(format!("outcome status must be a string, found {other:?}")),
        None => return Err("missing outcome status".into()),
    };
    match status.as_str() {
        "done" => m
            .remove("value")
            .map(Outcome::Done)
            .ok_or_else(|| "missing done value".into()),
        "short" => m
            .remove("value")
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
                Outcome::Done(Value::List(vec![v]))
            } else {
                Outcome::Done(Value::List(chunks))
            }
        }
        Outcome::Fail(f) => Outcome::Fail(f),
    }
}

fn sink_outcome(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Done(_) | Outcome::Short(_) => Outcome::Done(Value::Null),
        Outcome::Fail(f) => Outcome::Fail(f),
    }
}

fn pairing_secret_in_operation_input(path: Option<&Path>, input: &Value) -> bool {
    is_pairing_secret_generation_path(path)
        && matches!(input, Value::Map(m) if m.contains_key("pairing_secret"))
}

fn is_pairing_secret_generation_path(path: Option<&Path>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let segments = path.segments();
    path.scheme() == "effect"
        && segments.len() == 3
        && segments[0].as_str() == "external"
        && segments[1].as_str() == "pairing"
        && matches!(segments[2].as_str(), "create" | "replace")
}

fn redact_pairing_secret_input(input: &Value) -> Value {
    let Value::Map(fields) = input else {
        return input.clone();
    };
    let mut redacted = fields.clone();
    if redacted.contains_key("pairing_secret") {
        redacted.insert("pairing_secret".into(), Value::Str("<redacted>".into()));
    }
    Value::Map(redacted)
}

struct Resolved {
    resource: nexus_types::ResourceId,
    plan: crate::driver::DriverPlan,
    fast_path: FastPath,
    bound_path: Option<nexus_types::Path>,
}

fn driver_err_to_failure(e: DriverError) -> Failure {
    match e {
        DriverError::NoSuchMethod(_) => Failure::policy("driver", "no such method"),
        DriverError::UnsupportedOutput(_) => Failure::InvalidInput {
            reason: "unsupported output mode".into(),
        },
        DriverError::InvalidInput(reason) => Failure::InvalidInput { reason },
        DriverError::Transport(m) => Failure::HandlerError {
            kind: "transport".into(),
            message: m,
        },
        DriverError::Other(m) => Failure::HandlerError {
            kind: "driver".into(),
            message: m,
        },
    }
}

// Small helpers used above to keep the hot path readable.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{Driver, DriverContext, DriverPlan, EchoDriver, FnDriver};
    use crate::fact::FactStore;
    use crate::handle::{Handle, HandleState};
    use anyhow::{Context, bail, ensure};
    use nexus_state::{Backend, InMemoryBackend, StateError, StateResult, StateStream};
    use nexus_types::{
        DriverId, HandleId, IdentityRef, MethodBitmap, MethodId, NodeId, OperationId, OutputMode,
        OutputModeSet, ProcessId, ReplayClass, ResourceId, RightFlags, Rights, Value,
    };

    const SUPPORTS_UNARY: OutputModeSet = OutputModeSet::UNARY;
    const SUPPORTS_STREAM: OutputModeSet = OutputModeSet::STREAM;
    const SUPPORTS_ASYNC: OutputModeSet = OutputModeSet::ASYNC_PROCESS;

    fn test_state() -> Backend {
        Arc::new(InMemoryBackend::new())
    }

    fn dataplane_with_handle(rights: Rights, fast_path: FastPath) -> (DataPlane, HandleId) {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(EchoDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights,
            driver_plan: plan,
            fast_path,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, _) = FactSink::in_memory();
        (
            DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state()),
            id,
        )
    }

    struct TaintReportingStateDriver {
        state: Backend,
    }

    #[async_trait::async_trait]
    impl Driver for TaintReportingStateDriver {
        async fn call(
            &self,
            method: MethodId,
            _input: Value,
            _output: OutputMode,
            ctx: &DriverContext,
        ) -> Result<Outcome, DriverError> {
            let path = ctx
                .target_path
                .clone()
                .ok_or_else(|| DriverError::Other("state test driver has no bound path".into()))?;
            match method.get() {
                0 => {
                    let tv = self
                        .state
                        .read_tainted(&path)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                    match tv {
                        Some(tv) => {
                            ctx.set_output_taint(tv.taint);
                            Ok(Outcome::Done(tv.value))
                        }
                        None => Ok(Outcome::Done(Value::Null)),
                    }
                }
                4 => {
                    let rows = self
                        .state
                        .read_prefix_tainted(&path)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                    let mut taint = nexus_types::TaintSet::pristine();
                    let values = rows
                        .into_iter()
                        .map(|(p, tv)| {
                            taint.union(&tv.taint);
                            let mut m = BTreeMap::new();
                            m.insert("path".into(), Value::Str(p.to_string()));
                            m.insert("value".into(), tv.value);
                            Value::Map(m)
                        })
                        .collect();
                    ctx.set_output_taint(taint);
                    Ok(Outcome::Done(Value::List(values)))
                }
                _ => Err(DriverError::NoSuchMethod(method)),
            }
        }
    }

    fn dataplane_with_state_handle(
        state: Backend,
        method: MethodId,
        bound_path: Path,
    ) -> (DataPlane, HandleId, Arc<crate::fact::InMemoryFactStore>) {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            method,
            Arc::new(TaintReportingStateDriver {
                state: state.clone(),
            }),
        );
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: Some(bound_path),
        });
        let (facts, store) = FactSink::in_memory();
        (
            DataPlane::new(Arc::new(RwLock::new(table)), facts, state),
            id,
            store,
        )
    }

    fn op(handle: HandleId, method: u64, input: Value) -> Operation {
        Operation {
            id: OperationId::new(ProcessId::new(1), NodeId::new(0), 0),
            process: ProcessId::new(1),
            acting: IdentityRef::ROOT,
            handle,
            method: MethodId::new(method),
            input,
            taint: nexus_types::TaintSet::pristine(),
            output: OutputMode::Unary,
        }
    }

    #[tokio::test]
    async fn unconditional_executes_and_records_ok() -> anyhow::Result<()> {
        let (dp, id) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
        );
        let out = dp
            .execute(
                &op(id, 7, Value::Int(9)),
                0,
                ReplayClass::Deterministic,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::Int(9)),
            "unexpected outcome: {:?}",
            out.outcome
        );
        Ok(())
    }

    #[tokio::test]
    async fn state_read_output_taint_uses_persisted_taint() -> anyhow::Result<()> {
        let state = test_state();
        let path = Path::parse("state://chat/private")?;
        let protected =
            nexus_types::TaintSet::of(nexus_types::TaintSource::Protected { path: path.clone() });
        state
            .write_set_tainted(&path, Value::Str("secret".into()), protected)
            .await
            .context("writing protected state failed")?;
        let (dp, id, store) = dataplane_with_state_handle(state, MethodId::new(0), path);

        let out = dp
            .execute(
                &op(id, 0, Value::Null),
                0,
                ReplayClass::Observation,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;

        ensure!(
            out.output_taint.has_protected(),
            "output taint should be protected"
        );
        let facts = store.all_facts().context("reading facts failed")?;
        let fact = facts.first().context("missing recorded fact")?;
        ensure!(fact.taint.has_protected(), "fact taint should be protected");
        Ok(())
    }

    #[tokio::test]
    async fn state_list_output_taint_unions_persisted_taint() -> anyhow::Result<()> {
        let state = test_state();
        let prefix = Path::parse("state://chat")?;
        let public = Path::parse("state://chat/public")?;
        let private = Path::parse("state://chat/private")?;
        state
            .write_set(&public, Value::Str("ok".into()))
            .await
            .context("writing public state failed")?;
        let protected = nexus_types::TaintSet::of(nexus_types::TaintSource::Protected {
            path: private.clone(),
        });
        state
            .write_set_tainted(&private, Value::Str("secret".into()), protected)
            .await
            .context("writing protected state failed")?;
        let (dp, id, store) = dataplane_with_state_handle(state, MethodId::new(4), prefix);

        let out = dp
            .execute(
                &op(id, 4, Value::Null),
                4,
                ReplayClass::Observation,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;

        ensure!(
            out.output_taint.has_protected(),
            "listed output taint should be protected"
        );
        let facts = store.all_facts().context("reading facts failed")?;
        let fact = facts.first().context("missing recorded fact")?;
        ensure!(fact.taint.has_protected(), "fact taint should be protected");
        Ok(())
    }

    #[tokio::test]
    async fn large_modality_input_reaches_driver_intact() -> anyhow::Result<()> {
        // Blob/Tensor/Frame input reaches the driver as the full value. The
        // Fact record stores a fixed-size ValueRef::External.
        use nexus_types::BlobRef;
        let (dp, id) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
        );
        let blob = Value::Blob(BlobRef {
            hash: "deadbeef".into(),
            size: 4096,
            mime: None,
        });
        let out = dp
            .execute(
                &op(id, 7, blob.clone()),
                0,
                ReplayClass::Deterministic,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;
        // EchoDriver returns its input — the driver saw the real Blob, not Null.
        ensure!(
            out.outcome == Outcome::Done(blob),
            "large modality outcome mismatch: {:?}",
            out.outcome
        );
        Ok(())
    }

    #[tokio::test]
    async fn batchable_list_records_single_fact_with_batch_summary() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(EchoDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        let input = Value::List(vec![Value::Str("a".into()), Value::Str("b".into())]);
        let out = dp
            .execute_batchable(
                &op(id, 7, input),
                ExecuteParams {
                    method_index: 0,
                    replay: ReplayClass::Deterministic,
                    supports: SUPPORTS_UNARY,
                    batchable: true,
                    now_millis: 0,
                    record: true,
                },
            )
            .await;
        ensure!(
            matches!(out.outcome, Outcome::Done(Value::List(_))),
            "batchable call should return a list, got {:?}",
            out.outcome
        );
        let facts = store
            .facts_of(ProcessId::new(1))
            .context("reading facts failed")?;
        ensure!(facts.len() == 1, "batchable call should record one Fact");
        let fact = facts.first().context("missing batchable fact")?;
        let batch = fact.batch.as_ref().context("missing batch summary")?;
        ensure!(batch.elements == 2, "batch element count mismatch");
        ensure!(
            matches!(fact.outcome_ref, OutcomeRef::Inline(Value::List(_))),
            "batch fact outcome should be inline list"
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_right_is_denied() -> anyhow::Result<()> {
        let (dp, id) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
        );
        // method_index 3 is not in the bitmap.
        let out = dp
            .execute(
                &op(id, 7, Value::Null),
                3,
                ReplayClass::Deterministic,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(Failure::PermissionDenied { .. })),
            "missing right should deny, got {:?}",
            out.outcome
        );
        Ok(())
    }

    #[tokio::test]
    async fn wrong_owner_is_denied() -> anyhow::Result<()> {
        let (dp, id) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
        );
        let mut o = op(id, 7, Value::Null);
        o.process = ProcessId::new(999);
        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_UNARY, 0, true)
            .await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(_)),
            "wrong owner should fail"
        );
        Ok(())
    }

    #[tokio::test]
    async fn driver_failure_records_driver_error() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(7),
            Arc::new(FnDriver(|_, _| Err(DriverError::Other("boom".into())))),
        );
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        // record=false, but a NonIdempotentEffect is always recorded so
        // the write-ahead barrier still fires.
        let out = dp
            .execute(
                &op(id, 7, Value::Null),
                0,
                ReplayClass::NonIdempotentEffect,
                SUPPORTS_UNARY,
                0,
                false,
            )
            .await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(Failure::HandlerError { .. })),
            "driver failure should surface handler error, got {:?}",
            out.outcome
        );
        // NonIdempotentEffect ⇒ write-ahead barrier fired at begin.
        ensure!(store.sync_count() >= 1, "write-ahead barrier should sync");
        Ok(())
    }

    #[tokio::test]
    async fn unconsumed_deterministic_read_skips_fact() -> anyhow::Result<()> {
        // With record=false and a Deterministic class, no Fact is written
        // because recovery can recompute the read. The store stays empty.
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(EchoDriver));
        let id2 = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let dp2 = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        let out = dp2
            .execute(
                &op(id2, 7, Value::Int(1)),
                0,
                ReplayClass::Deterministic,
                SUPPORTS_UNARY,
                0,
                false,
            )
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::Int(1)),
            "deterministic read outcome mismatch: {:?}",
            out.outcome
        );
        ensure!(
            store.is_empty(),
            "unconsumed deterministic read should write no Fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unconsumed_idempotent_effect_still_records_fact() -> anyhow::Result<()> {
        // Effectful / IdempotentEffect operations are external side effects, so
        // recovery must know they happened even if later graph nodes do not
        // consume the result.
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(EchoDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        let out = dp
            .execute(
                &op(id, 7, Value::Int(1)),
                0,
                ReplayClass::IdempotentEffect,
                SUPPORTS_UNARY,
                0,
                false,
            )
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::Int(1)),
            "idempotent effect outcome mismatch: {:?}",
            out.outcome
        );
        ensure!(store.len() == 1, "idempotent effect should write one Fact");
        Ok(())
    }

    #[tokio::test]
    async fn idempotent_effect_dedupes_by_business_key() -> anyhow::Result<()> {
        // Two IdempotentEffect ops carrying the same `_idem_key` run the driver
        // only once; the second short-circuits to the cached outcome.
        use std::sync::atomic::{AtomicU32, Ordering};
        static CALLS: AtomicU32 = AtomicU32::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(7),
            Arc::new(FnDriver(|_m: MethodId, _in: Value| {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Value::Int(100))
            })),
        );
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let state = test_state();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone());

        let mut m = std::collections::BTreeMap::new();
        m.insert("_idem_key".to_string(), Value::Str("order-1".into()));
        let input = Value::Map(m);
        let o = op(id, 7, input);
        let mut retry = o.clone();
        retry.id = retry.id.retry();

        let first = dp
            .execute(
                &o,
                0,
                ReplayClass::IdempotentEffect,
                SUPPORTS_UNARY,
                0,
                false,
            )
            .await;
        let second = dp
            .execute(
                &retry,
                0,
                ReplayClass::IdempotentEffect,
                SUPPORTS_UNARY,
                0,
                false,
            )
            .await;

        ensure!(
            first.outcome == Outcome::Done(Value::Int(100)),
            "first idempotent outcome mismatch: {:?}",
            first.outcome
        );
        // Second deduped → Short with the same value, driver NOT called again.
        ensure!(
            second.outcome == Outcome::Short(Value::Int(100)),
            "second idempotent outcome mismatch: {:?}",
            second.outcome
        );
        ensure!(CALLS.load(Ordering::SeqCst) == 1, "driver should run once");
        let facts = store
            .facts_of(ProcessId::new(1))
            .context("reading facts failed")?;
        ensure!(facts.len() == 2, "retry attempts should remain auditable");
        let first_fact = facts.first().context("missing first retry fact")?;
        let second_fact = facts.get(1).context("missing second retry fact")?;
        ensure!(first_fact.id.attempt == 0, "first attempt mismatch");
        ensure!(second_fact.id.attempt == 1, "second attempt mismatch");
        ensure!(
            facts.iter().all(|f| f.decision == DecisionTag::Ok),
            "all retry facts should be ok decisions"
        );
        Ok(())
    }

    #[tokio::test]
    async fn idempotent_effect_dedupes_across_data_plane_instances() -> anyhow::Result<()> {
        // Idempotency records live in state://idemp/*, so a restarted DataPlane
        // sharing the backend still dedupes the same effective key.
        use std::sync::atomic::{AtomicU32, Ordering};
        static CALLS: AtomicU32 = AtomicU32::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let mk_table = || {
            let mut table = HandleTable::new();
            let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
            plan.insert(
                MethodId::new(7),
                Arc::new(FnDriver(|_m: MethodId, _in: Value| {
                    CALLS.fetch_add(1, Ordering::SeqCst);
                    Ok(Value::Int(100))
                })),
            );
            let id = table.insert(Handle {
                id: HandleId::new(0, 0),
                process: ProcessId::new(1),
                resource: ResourceId::new(5),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                driver_plan: plan,
                fast_path: FastPath::Unconditional,
                state: HandleState::Active,
                bound_path: None,
            });
            (table, id)
        };

        let state = test_state();
        let (table1, id1) = mk_table();
        let (facts1, _) = FactSink::in_memory();
        let dp1 = DataPlane::new(Arc::new(RwLock::new(table1)), facts1, state.clone());
        let (table2, id2) = mk_table();
        let (facts2, _) = FactSink::in_memory();
        let dp2 = DataPlane::new(Arc::new(RwLock::new(table2)), facts2, state.clone());

        let mut m = std::collections::BTreeMap::new();
        m.insert("_idem_key".to_string(), Value::Str("order-1".into()));
        let first = dp1
            .execute(
                &op(id1, 7, Value::Map(m.clone())),
                0,
                ReplayClass::IdempotentEffect,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;
        let second = dp2
            .execute(
                &op(id2, 7, Value::Map(m)),
                0,
                ReplayClass::IdempotentEffect,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;

        ensure!(
            first.outcome == Outcome::Done(Value::Int(100)),
            "first dataplane outcome mismatch: {:?}",
            first.outcome
        );
        ensure!(
            second.outcome == Outcome::Short(Value::Int(100)),
            "second dataplane outcome mismatch: {:?}",
            second.outcome
        );
        ensure!(CALLS.load(Ordering::SeqCst) == 1, "driver should run once");
        let prefix = Path::parse("state://idemp")?;
        let entries = state
            .read_prefix(&prefix)
            .await
            .context("reading idempotency prefix failed")?;
        ensure!(!entries.is_empty(), "idempotency state should be populated");
        Ok(())
    }

    /// A FactStore whose writes always fail, exercising the fail-closed
    /// write-ahead path without needing a real disk fault.
    struct FailingFactStore;
    impl crate::fact::FactStore for FailingFactStore {
        fn append(&self, _fact: Fact) -> Result<u64, crate::fact::FactError> {
            Err(crate::fact::FactError("simulated disk failure".into()))
        }
        fn complete(&self, _fact: Fact) -> Result<(), crate::fact::FactError> {
            Err(crate::fact::FactError("simulated disk failure".into()))
        }
        fn sync(&self) -> Result<(), crate::fact::FactError> {
            Err(crate::fact::FactError("simulated disk failure".into()))
        }
        fn facts_of(&self, _process: ProcessId) -> Result<Vec<Fact>, crate::fact::FactError> {
            Ok(Vec::new())
        }
        fn all_facts(&self) -> Result<Vec<Fact>, crate::fact::FactError> {
            Ok(Vec::new())
        }
        fn cursor(&self) -> u64 {
            0
        }
    }

    #[tokio::test]
    async fn write_ahead_failure_denies_effect_fail_closed() -> anyhow::Result<()> {
        // A NonIdempotentEffect must write ahead before the effect is issued.
        // If that durable append fails, the op is denied and the driver is
        // never called; no effect can happen without a record.
        use std::sync::atomic::{AtomicBool, Ordering};
        static CALLED: AtomicBool = AtomicBool::new(false);
        CALLED.store(false, Ordering::SeqCst);

        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(7),
            Arc::new(FnDriver(|_m: MethodId, _in: Value| {
                CALLED.store(true, Ordering::SeqCst);
                Ok(Value::Int(1))
            })),
        );
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let facts = FactSink::new(Arc::new(FailingFactStore));
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());

        let out = dp
            .execute(
                &op(id, 7, Value::Int(9)),
                0,
                ReplayClass::NonIdempotentEffect,
                SUPPORTS_UNARY,
                0,
                true,
            )
            .await;

        ensure!(matches!(out.outcome, Outcome::Fail(_)), "op must be denied");
        ensure!(
            !CALLED.load(Ordering::SeqCst),
            "driver must not run when the write-ahead barrier fails"
        );
        Ok(())
    }

    struct StreamingDriver;

    #[async_trait::async_trait]
    impl Driver for StreamingDriver {
        async fn call(
            &self,
            _method: MethodId,
            _input: Value,
            output: OutputMode,
            ctx: &DriverContext,
        ) -> Result<Outcome, DriverError> {
            if output != OutputMode::Stream {
                return Err(DriverError::Other("expected stream output".into()));
            }
            if !ctx.emit(Value::Str("chunk-1".into())) {
                return Err(DriverError::Other("first chunk was not accepted".into()));
            }
            if !ctx.emit(Value::Str("chunk-2".into())) {
                return Err(DriverError::Other("second chunk was not accepted".into()));
            }
            Ok(Outcome::Done(Value::Int(2)))
        }
    }

    struct OneChunkStreamingDriver;

    #[async_trait::async_trait]
    impl Driver for OneChunkStreamingDriver {
        async fn call(
            &self,
            _method: MethodId,
            _input: Value,
            output: OutputMode,
            ctx: &DriverContext,
        ) -> Result<Outcome, DriverError> {
            if output != OutputMode::Stream {
                return Err(DriverError::Other("expected stream output".into()));
            }
            if !ctx.emit(Value::Str("chunk".into())) {
                return Err(DriverError::Other("chunk was not accepted".into()));
            }
            Ok(Outcome::Done(Value::Int(1)))
        }
    }

    struct FailingAppendState;

    #[async_trait::async_trait]
    impl nexus_state::StateBackend for FailingAppendState {
        async fn read_tainted(
            &self,
            _path: &Path,
        ) -> StateResult<Option<nexus_state::TaintedValue>> {
            Ok(None)
        }

        async fn write_set_tainted(
            &self,
            _path: &Path,
            _value: Value,
            _taint: nexus_types::TaintSet,
        ) -> StateResult<()> {
            Ok(())
        }

        async fn write_append_tainted(
            &self,
            _path: &Path,
            _item: Value,
            _taint: nexus_types::TaintSet,
        ) -> StateResult<()> {
            Err(StateError::Backend("simulated append failure".into()))
        }

        async fn write_cas_tainted(
            &self,
            _path: &Path,
            _expected: Option<Value>,
            _new: Value,
            _taint: nexus_types::TaintSet,
        ) -> StateResult<()> {
            Ok(())
        }

        async fn write_delete(&self, _path: &Path) -> StateResult<()> {
            Ok(())
        }

        async fn read_prefix_tainted(
            &self,
            _prefix: &Path,
        ) -> StateResult<Vec<(Path, nexus_state::TaintedValue)>> {
            Ok(Vec::new())
        }

        async fn subscribe(&self, _pattern: &Path) -> StateResult<StateStream> {
            let (_tx, rx) = tokio::sync::broadcast::channel(1);
            Ok(rx)
        }
    }

    #[tokio::test]
    async fn stream_chunks_append_to_state_with_one_fact() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(StreamingDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let state: nexus_state::Backend = Arc::new(nexus_state::InMemoryBackend::new());
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone());

        let mut o = op(id, 7, Value::Null);
        o.output = OutputMode::Stream;
        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_STREAM, 0, true)
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::Int(2)),
            "streaming outcome mismatch: {:?}",
            out.outcome
        );

        let stream = state
            .read(&Path::parse("state://stream/1/0")?)
            .await
            .context("reading stream state failed")?;
        ensure!(
            stream
                == Some(Value::List(vec![
                    Value::Str("chunk-1".into()),
                    Value::Str("chunk-2".into()),
                    Value::StreamEnd(nexus_types::StreamMarker::Done),
                ])),
            "stream state mismatch: {stream:?}"
        );
        ensure!(
            store.len() == 1,
            "streaming chunks should append to state, not one Fact per chunk"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stream_append_failure_returns_driver_error() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(OneChunkStreamingDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, _) = FactSink::in_memory();
        let state: nexus_state::Backend = Arc::new(FailingAppendState);
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state);

        let mut o = op(id, 7, Value::Null);
        o.output = OutputMode::Stream;
        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_STREAM, 0, true)
            .await;

        match out.outcome {
            Outcome::Fail(nexus_types::Failure::HandlerError { message, .. }) => {
                ensure!(
                    message.contains("stream sink failed"),
                    "unexpected handler error message: {message}"
                );
            }
            other => bail!("expected stream sink failure, got {other:?}"),
        }
        Ok(())
    }

    struct CollectDriver;

    #[async_trait::async_trait]
    impl Driver for CollectDriver {
        async fn call(
            &self,
            _method: MethodId,
            _input: Value,
            output: OutputMode,
            ctx: &DriverContext,
        ) -> Result<Outcome, DriverError> {
            if output != OutputMode::Stream {
                return Err(DriverError::Other("expected stream output".into()));
            }
            if !ctx.emit(Value::Str("a".into())) {
                return Err(DriverError::Other(
                    "first collect chunk was not accepted".into(),
                ));
            }
            if !ctx.emit(Value::Str("b".into())) {
                return Err(DriverError::Other(
                    "second collect chunk was not accepted".into(),
                ));
            }
            Ok(Outcome::Done(Value::Int(2)))
        }
    }

    #[tokio::test]
    async fn collect_aggregates_stream_chunks_up_to_limit() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(CollectDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        let mut o = op(id, 7, Value::Null);
        o.output = OutputMode::Collect { limit: 1 };

        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_STREAM, 0, true)
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::List(vec![Value::Str("a".into())])),
            "collect outcome mismatch: {:?}",
            out.outcome
        );
        ensure!(store.len() == 1, "collect should record one Fact");
        Ok(())
    }

    #[tokio::test]
    async fn collect_wraps_unary_result_when_no_chunks_are_emitted() -> anyhow::Result<()> {
        struct UnaryOnlyCollectDriver;

        #[async_trait::async_trait]
        impl Driver for UnaryOnlyCollectDriver {
            async fn call(
                &self,
                _method: MethodId,
                input: Value,
                output: OutputMode,
                ctx: &DriverContext,
            ) -> Result<Outcome, DriverError> {
                if output != OutputMode::Unary {
                    return Err(DriverError::Other("expected unary output".into()));
                }
                if ctx.stream_to.is_some() {
                    return Err(DriverError::Other("unexpected stream sink".into()));
                }
                Ok(Outcome::Done(input))
            }
        }

        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(UnaryOnlyCollectDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        let mut o = op(id, 7, Value::Int(9));
        o.output = OutputMode::Collect { limit: 8 };
        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_UNARY, 0, true)
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::List(vec![Value::Int(9)])),
            "collect unary wrap outcome mismatch: {:?}",
            out.outcome
        );
        Ok(())
    }

    #[tokio::test]
    async fn sink_only_suppresses_response_body() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(EchoDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
        let mut o = op(id, 7, Value::Str("response-body".into()));
        o.output = OutputMode::SinkOnly;
        let out = dp
            .execute(
                &o,
                0,
                ReplayClass::NonIdempotentEffect,
                OutputModeSet::SINK_ONLY,
                0,
                true,
            )
            .await;
        ensure!(
            out.outcome == Outcome::Done(Value::Null),
            "sink-only outcome mismatch: {:?}",
            out.outcome
        );
        let facts = store
            .facts_of(ProcessId::new(1))
            .context("reading facts failed")?;
        ensure!(facts.len() == 1, "sink-only should record one Fact");
        let fact = facts.first().context("missing sink-only fact")?;
        ensure!(
            matches!(
                fact.outcome_ref,
                nexus_types::OutcomeRef::Inline(Value::Null)
            ),
            "sink-only fact should record Null"
        );
        Ok(())
    }

    struct AsyncDriver;

    #[async_trait::async_trait]
    impl Driver for AsyncDriver {
        async fn call(
            &self,
            _method: MethodId,
            input: Value,
            output: OutputMode,
            _ctx: &DriverContext,
        ) -> Result<Outcome, DriverError> {
            if output != OutputMode::AsyncProcess {
                return Err(DriverError::Other("expected async process output".into()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok(Outcome::Done(input))
        }
    }

    type AsyncFixture = (
        DataPlane,
        HandleId,
        nexus_state::Backend,
        Arc<crate::fact::InMemoryFactStore>,
        crate::process::ProcessTable,
    );

    fn async_dataplane(rights: Rights) -> anyhow::Result<AsyncFixture> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(7), Arc::new(AsyncDriver));
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            resource: ResourceId::new(5),
            rights,
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        });
        let (facts, store) = FactSink::in_memory();
        let state: nexus_state::Backend = Arc::new(nexus_state::InMemoryBackend::new());
        let processes = crate::process::ProcessTable::new();
        let parent = processes.fresh_id();
        ensure!(
            parent == ProcessId::new(1),
            "unexpected parent process id: {parent:?}"
        );
        let mut entry = ProcessEntry::new(parent, None, IdentityRef::ROOT);
        entry.status = nexus_types::ProcessStatus::Running;
        processes.insert(entry);
        let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone())
            .with_processes(processes.clone());
        Ok((dp, id, state, store, processes))
    }

    #[tokio::test]
    async fn async_process_requires_spawn_with_right() -> anyhow::Result<()> {
        let (dp, id, _state, _store, _processes) =
            async_dataplane(Rights::new(MethodBitmap::method(0), RightFlags::empty()))?;
        let mut o = op(id, 7, Value::Str("work".into()));
        o.output = OutputMode::AsyncProcess;

        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_ASYNC, 0, true)
            .await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(Failure::PermissionDenied { .. })),
            "async process without spawn right should deny, got {:?}",
            out.outcome
        );
        Ok(())
    }

    #[tokio::test]
    async fn async_process_returns_pollable_resource_and_records_child_fact() -> anyhow::Result<()>
    {
        let (dp, id, state, store, processes) =
            async_dataplane(Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH))?;
        let mut o = op(id, 7, Value::Str("work".into()));
        o.output = OutputMode::AsyncProcess;

        let out = dp
            .execute(&o, 0, ReplayClass::Deterministic, SUPPORTS_ASYNC, 0, false)
            .await;
        let (child, status_path, outcome_path) = match out.outcome {
            Outcome::Done(Value::Map(m)) => {
                ensure!(
                    m.get("kind") == Some(&Value::Str("executor_resource".into())),
                    "async resource kind mismatch: {m:?}"
                );
                ensure!(
                    m.get("path") == Some(&Value::Str("proc://async/2".into())),
                    "async resource path mismatch: {m:?}"
                );
                let child = match m.get("process") {
                    Some(Value::Int(n)) => ProcessId::new(*n as u64),
                    other => bail!("expected child process id, got {other:?}"),
                };
                let status_path = match m.get("status_path") {
                    Some(Value::Str(s)) => Path::parse(s)?,
                    other => bail!("expected status path, got {other:?}"),
                };
                let outcome_path = match m.get("outcome_path") {
                    Some(Value::Str(s)) => Path::parse(s)?,
                    other => bail!("expected outcome path, got {other:?}"),
                };
                (child, status_path, outcome_path)
            }
            other => bail!("expected async resource map, got {other:?}"),
        };
        ensure!(child == ProcessId::new(2), "child process id mismatch");
        ensure!(processes.exists(child), "child process should exist");

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(v) = state.read(&outcome_path).await? {
                    break Ok::<Value, anyhow::Error>(v);
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .context("async child did not write outcome before timeout")??;
        let mut expected = BTreeMap::new();
        expected.insert("status".into(), Value::Str("done".into()));
        expected.insert("value".into(), Value::Str("work".into()));
        ensure!(
            outcome == Value::Map(expected),
            "async child outcome mismatch: {outcome:?}"
        );
        ensure!(
            processes.status(child) == Some(nexus_types::ProcessStatus::Completed),
            "async child should be completed"
        );
        let status = state
            .read(&status_path)
            .await
            .context("reading child status failed")?
            .context("missing child status")?;
        match status {
            Value::Map(m) => ensure!(
                m.get("phase") == Some(&Value::Str("completed".into())),
                "child status phase mismatch: {m:?}"
            ),
            other => bail!("expected status map, got {other:?}"),
        }
        ensure!(
            store.len() == 2,
            "parent spawn and child execution should each record one Fact"
        );
        Ok(())
    }
}
