//! Shared admission, execution ownership, and output delivery for submissions.

use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::time::Instant;
use xolotl_kernel::{Bootstrap, Executor};
use xolotl_types::{CompletionOrigin, Outcome, OutputMode, ProcessId, TaintSet, TaintSource};

use crate::schema::enforce_surface_output_schema;
use crate::{
    CompiledGatewayProfile, GatewayAccepted, GatewayError, GatewayRequestEntry,
    GatewayRequestGuard, GatewayRequestState, GatewayRuntime, GatewaySession, GatewaySubmission,
    GatewaySubmitResult, LoweredSubmission, StreamWindow, gateway_budget_charge_for_submit,
    inspect_lowered_submission, lower_submission, lowered_large_value_ref_summaries, now_millis,
    request_deadline, request_risk_class, validate_current_session, validate_submit_options,
};
use idempotency::{
    GatewayIdempotencyReservation, SubmissionIdempotency,
    commit_submission_idempotency_and_finish_request, finish_request_without_idempotency_and_fail,
    initial_idempotency_material, release_submission_idempotency_reservation_and_fail,
    required_idempotency_material, reserve_submission_idempotency_if_present,
};
use output::OutputPort;

pub(crate) mod idempotency;
mod input;
mod output;

pub(crate) use input::complete_input_stream;
pub use output::{GatewayOutputChunk, GatewayOutputEvent, GatewayOutputStream};

enum SubmissionStart {
    Accepted(Box<PreparedSubmission>),
    Replay(Box<GatewaySubmitResult>),
}

struct PreparedSubmission {
    boot: Arc<Bootstrap>,
    profile: Arc<CompiledGatewayProfile>,
    accepted: GatewayAccepted,
    requested_output: OutputMode,
    deadline: Option<Instant>,
    idempotency: Option<Box<GatewayIdempotencyReservation>>,
    request_guard: GatewayRequestGuard,
    request_process: ProcessId,
    executor: Executor,
    program: xolotl_graph::DoNode,
    entry_taint: TaintSet,
}

pub(crate) fn validate_output_port(mode: OutputMode, streaming: bool) -> Result<(), GatewayError> {
    match (mode, streaming) {
        (OutputMode::Stream, true) => Ok(()),
        (OutputMode::Stream, false) => Err(GatewayError::Rejected(
            "stream output requires submit_output_stream".into(),
        )),
        (_, true) => Err(GatewayError::Rejected(
            "submit_output_stream requires Stream output mode".into(),
        )),
        (_, false) => Ok(()),
    }
}

pub(crate) async fn submit(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    submission: GatewaySubmission,
) -> Result<GatewaySubmitResult, GatewayError> {
    match prepare(runtime, session, submission, None).await? {
        SubmissionStart::Replay(result) => Ok(*result),
        SubmissionStart::Accepted(prepared) => prepared.execute(None).complete().await,
    }
}

pub(crate) async fn submit_output_stream(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    submission: GatewaySubmission,
    window: StreamWindow,
) -> Result<GatewayOutputStream, GatewayError> {
    match prepare(runtime, session, submission, Some(window)).await? {
        SubmissionStart::Replay(result) => Ok(GatewayOutputStream::replay(*result)),
        SubmissionStart::Accepted(prepared) => Ok(GatewayOutputStream::start(*prepared, window)),
    }
}

async fn prepare(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    submission: GatewaySubmission,
    output_window: Option<StreamWindow>,
) -> Result<SubmissionStart, GatewayError> {
    validate_output_port(submission.requested_output, output_window.is_some())?;
    if output_window
        .is_some_and(|window| window.max_chunks.get() > tokio::sync::Semaphore::MAX_PERMITS)
    {
        return Err(GatewayError::Rejected(
            "stream chunk window exceeds host channel capacity".into(),
        ));
    }
    let profile = runtime.profile_snapshot();
    validate_current_session(&profile, session)?;
    let now_ms = now_millis();
    let mut idempotency = match reserve_submission_idempotency_if_present(
        &runtime.boot.kernel.state,
        &profile,
        session,
        &submission,
        initial_idempotency_material(&runtime.boot, &profile, session, &submission)?,
        now_ms,
    )
    .await?
    {
        Some(SubmissionIdempotency::Replay(result)) => return Ok(SubmissionStart::Replay(result)),
        Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
        None => None,
    };

    // Ordinary pre-dispatch failures release only this reservation. Dropping an
    // in-progress admission leaves its uncertain CAS result reserved.
    let admitted = async {
        validate_submit_options(&submission.options, &profile.limits, now_ms)?;
        let deadline = request_deadline(&submission.options)?;
        let LoweredSubmission {
            program,
            surface,
            objects,
        } = lower_submission(submission.clone(), &profile, runtime, session).await?;
        let admission = inspect_lowered_submission(
            &program,
            &profile,
            &session.principal.principal_id,
            surface,
            &runtime.boot,
            true,
        )?;
        if admission.requires_idempotency && idempotency.is_none() {
            idempotency = match reserve_submission_idempotency_if_present(
                &runtime.boot.kernel.state,
                &profile,
                session,
                &submission,
                required_idempotency_material(&submission)?,
                now_ms,
            )
            .await?
            {
                Some(SubmissionIdempotency::Replay(result)) => {
                    return Ok(SubmissionStart::Replay(result));
                }
                Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
                None => {
                    return Err(GatewayError::Rejected(
                        "idempotency_key or submission_token is required for non-idempotent effects"
                            .into(),
                    ));
                }
            };
        }
        let risk_class = request_risk_class(&admission);
        let surface_ids = BTreeSet::from([surface.surface_id.clone()]);
        let fair_surface_ids = vec![surface.surface_id.clone()];
        let mut budget_charge =
            gateway_budget_charge_for_submit(&admission, &submission.options, now_ms)?;
        if let Some(window) = output_window {
            let bytes = u64::try_from(window.max_inline_bytes.get()).map_err(|_error| {
                GatewayError::Rejected("stream byte window is out of range".into())
            })?;
            budget_charge.bytes_out = bytes;
            budget_charge.inline_value_bytes = budget_charge
                .inline_value_bytes
                .checked_add(bytes)
                .ok_or_else(|| GatewayError::Rejected("stream byte reservation overflow".into()))?;
            budget_charge.stream_items =
                u64::try_from(window.max_chunks.get()).map_err(|_error| {
                    GatewayError::Rejected("stream chunk window is out of range".into())
                })?;
        }
        let budget_guard = runtime
            .requests
            .try_reserve_budget(&profile.limits.budget, budget_charge)?;
        let admission_guard = runtime.requests.try_admit(
            &profile.limits,
            session.principal.principal_id.clone(),
            fair_surface_ids.clone(),
            risk_class.clone(),
        )?;
        let accepted = runtime
            .requests
            .new_acceptance(profile.revision, surface.surface_id.clone())?;
        let (request_owner, executor) = runtime
            .executor_for(&profile, session, &surface_ids)
            .await?;
        let request_process = request_owner.id();
        let entry = GatewayRequestEntry {
            accepted: accepted.clone(),
            request_process,
            gateway_id: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            state: GatewayRequestState::Running,
            deadline,
            retained_until_ms: i64::MAX,
            risk_class,
            surface_ids: fair_surface_ids,
            large_value_refs: lowered_large_value_ref_summaries(&program),
            admission_released: false,
        };
        let request_guard =
            runtime
                .requests
                .insert_running(entry, admission_guard, budget_guard, request_owner)?;
        let object_taint = match request_guard
            .commit_objects(runtime, session, objects, deadline)
            .await
        {
            Ok(taint) => taint,
            Err(error) => {
                return finish_request_without_idempotency_and_fail(
                    &runtime.boot,
                    request_process,
                    error,
                )
                .await;
            }
        };
        let entry_taint = entry_taint(&profile, &object_taint);
        Ok(SubmissionStart::Accepted(Box::new(PreparedSubmission {
            boot: runtime.boot.clone(),
            profile,
            accepted,
            requested_output: submission.requested_output,
            deadline,
            idempotency: idempotency.take(),
            request_guard,
            request_process,
            executor,
            program,
            entry_taint,
        })))
    }
    .await;
    match admitted {
        Ok(start) => Ok(start),
        Err(error) => {
            release_submission_idempotency_reservation_and_fail(
                &runtime.boot.kernel.state,
                idempotency.as_deref(),
                error,
            )
            .await
        }
    }
}

fn entry_taint(profile: &CompiledGatewayProfile, objects: &TaintSet) -> TaintSet {
    let mut taint = TaintSet::of(TaintSource::Inbound {
        source: GatewayRuntime::source_label(profile).into(),
        channel: "submit".into(),
    });
    taint.union(objects);
    taint
}

type ExecutionFuture =
    Pin<Box<dyn Future<Output = Result<GatewaySubmitResult, GatewayError>> + Send + 'static>>;

struct SubmissionExecution {
    future: Option<ExecutionFuture>,
    request_guard: GatewayRequestGuard,
}

impl PreparedSubmission {
    fn execute(self, output: Option<OutputPort>) -> SubmissionExecution {
        let Self {
            boot,
            profile,
            accepted,
            requested_output,
            deadline,
            idempotency,
            request_guard,
            request_process,
            mut executor,
            program,
            entry_taint,
        } = self;
        if let Some(output) = &output {
            executor = executor.with_stream_router(output.router.clone());
        }
        if let Some(deadline) = deadline {
            executor = executor.with_deadline(deadline);
        }
        let lease = request_guard.lease.clone();
        let future = Box::pin(async move {
            let surface = profile.surface_by_id(&accepted.surface_id).ok_or_else(|| {
                GatewayError::Rejected("accepted surface is not available in its profile".into())
            })?;
            let mut execution_output = executor.eval_tainted(&program, entry_taint).await;
            enforce_surface_output_schema(surface, requested_output, &mut execution_output);
            if let Some(failure) = output.as_ref().and_then(OutputPort::failure) {
                execution_output.outcome = Outcome::Fail(failure.failure);
                execution_output.taint.union(&failure.taint);
            }
            lease.finish_execution(&mut execution_output, &boot);
            commit_submission_idempotency_and_finish_request(
                &boot,
                request_process,
                idempotency.as_deref(),
                &accepted,
                &execution_output,
            )
            .await?;
            Ok(GatewaySubmitResult {
                accepted,
                output: execution_output,
                origin: CompletionOrigin::CurrentAttempt,
            })
        });
        SubmissionExecution {
            future: Some(future),
            request_guard,
        }
    }
}

impl SubmissionExecution {
    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<GatewaySubmitResult, GatewayError>> {
        let Some(future) = self.future.as_mut() else {
            return Poll::Pending;
        };
        let Poll::Ready(result) = future.as_mut().poll(cx) else {
            return Poll::Pending;
        };
        self.future = None;
        match &result {
            Ok(_) => self.request_guard.finish(),
            Err(_) => self.request_guard.fail(),
        }
        Poll::Ready(result)
    }

    async fn complete(mut self) -> Result<GatewaySubmitResult, GatewayError> {
        poll_fn(|cx| self.poll_complete(cx)).await
    }
}
