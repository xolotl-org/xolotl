//! Shared admission, execution ownership, and output delivery for submissions.

use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use xolotl_kernel::{Bootstrap, Executor, host::HostDeadline};
use xolotl_types::{
    CompletionOrigin, Outcome, OutputMode, ProcessId, ProcessStatus, TaintSet, TaintSource,
};

use crate::request_registry::GatewayAdmissionGuard;
use crate::schema::enforce_surface_output_schema;
use crate::{
    CompiledGatewayProfile, GATEWAY_EFFECT_METHOD, GatewayAccepted, GatewayDirectInput,
    GatewayError, GatewayPayloadProvenance, GatewayRequestEntry, GatewayRequestGuard,
    GatewayRequestState, GatewayRuntime, GatewaySession, GatewaySubmission, GatewaySubmissionBody,
    GatewaySubmissionHead, GatewaySubmitResult, LoweredSubmission, ReplayClass, StreamWindow,
    Value, gateway_budget_charge_for_submit, inspect_lowered_submission, lower_submission,
    operation_replay_class, request_deadline, request_risk_class, validate_current_session,
    validate_request_deadline, validate_submit_options,
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

/// Affine capacity owner for one authenticated, payload-independent preparation.
#[must_use]
pub struct GatewayPreparation {
    profile: Arc<CompiledGatewayProfile>,
    session: GatewaySession,
    head: GatewaySubmissionHead,
    deadline: Option<HostDeadline>,
    output_window: Option<StreamWindow>,
    admission_guard: GatewayAdmissionGuard,
    risk_class: String,
}

pub(crate) fn prepare_submission(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    head: GatewaySubmissionHead,
    output_window: Option<StreamWindow>,
) -> Result<GatewayPreparation, GatewayError> {
    validate_output_port(head.requested_output, output_window.is_some())?;
    if output_window
        .is_some_and(|window| window.max_chunks.get() > tokio::sync::Semaphore::MAX_PERMITS)
    {
        return Err(GatewayError::Rejected(
            "stream chunk window exceeds host channel capacity".into(),
        ));
    }
    let profile = runtime.profile_snapshot();
    validate_current_session(&profile, session)?;
    let surface = profile.surface_by_id(&head.surface_id).ok_or_else(|| {
        GatewayError::Rejected(format!("unknown gateway surface {}", head.surface_id))
    })?;
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(format!(
            "surface {} is not callable by principal",
            surface.surface_id
        )));
    }
    let host = runtime.boot.kernel().host_runtime();
    let deadline = request_deadline(
        &head.options,
        head.server_deadline,
        host.now(),
        host.now_millis(),
    )?;
    validate_request_deadline(deadline, host.now(), &profile.limits)?;
    validate_submit_options(&head.options)?;
    crate::request_scope::validate(
        &profile,
        session,
        surface,
        runtime.idempotency.as_ref(),
        &head.options,
    )?;
    let risk_class = if matches!(
        operation_replay_class(&runtime.boot, &surface.target, GATEWAY_EFFECT_METHOD)?,
        ReplayClass::NonIdempotentEffect
    ) {
        "non_idempotent_effect"
    } else {
        "effect"
    }
    .to_string();
    let admission_guard = runtime.requests.try_admit(
        &profile.limits,
        session.principal.principal_id.clone(),
        vec![surface.surface_id.clone()],
        risk_class.clone(),
    )?;
    Ok(GatewayPreparation {
        profile,
        session: session.clone(),
        head,
        deadline,
        output_window,
        admission_guard,
        risk_class,
    })
}

fn prepare_direct(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    submission: GatewaySubmission,
    output_window: Option<StreamWindow>,
) -> Result<(GatewayPreparation, GatewayDirectInput), GatewayError> {
    let GatewaySubmission {
        surface_id,
        body,
        requested_output,
        options,
        server_deadline,
    } = submission;
    let GatewaySubmissionBody::DirectInput(input) = body else {
        return Err(GatewayError::Rejected(
            "stream input must be completed by its admitted owner".into(),
        ));
    };
    let preparation = prepare_submission(
        runtime,
        session,
        GatewaySubmissionHead {
            surface_id,
            requested_output,
            options,
            server_deadline,
        },
        output_window,
    )?;
    Ok((preparation, input))
}

impl GatewayRequestGuard {
    fn ensure_live(
        &self,
        runtime: &GatewayRuntime,
        deadline: Option<HostDeadline>,
    ) -> Result<(), GatewayError> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| GatewayError::Rejected("gateway request is already finished".into()))?;
        if deadline
            .map(|deadline| deadline.elapsed_at(runtime.boot.kernel().host_runtime().now()))
            .transpose()
            .map_err(|error| GatewayError::Rejected(error.to_string()))?
            .unwrap_or(false)
        {
            return Err(GatewayError::Rejected(
                "gateway request deadline expired".into(),
            ));
        }
        if self.lease.state() != Some(GatewayRequestState::Running) {
            return Err(GatewayError::Rejected(
                "gateway request is no longer running".into(),
            ));
        }
        if runtime.boot.kernel().processes().status(process.id()) != Some(ProcessStatus::Running) {
            return Err(GatewayError::Rejected(
                "gateway request is no longer running".into(),
            ));
        }
        Ok(())
    }

    async fn commit_objects(
        &self,
        runtime: &GatewayRuntime,
        session: &GatewaySession,
        objects: crate::object::ObjectAdmission,
        deadline: Option<HostDeadline>,
        identity: Option<&str>,
    ) -> Result<TaintSet, GatewayError> {
        self.ensure_live(runtime, deadline)?;
        objects.commit(runtime, session, identity).await
    }
}

enum SubmissionStart {
    Accepted(Box<PreparedSubmission>),
    Replay(Box<GatewaySubmitResult>),
}

struct PreparedSubmission {
    boot: Arc<Bootstrap>,
    profile: Arc<CompiledGatewayProfile>,
    accepted: GatewayAccepted,
    requested_output: OutputMode,
    deadline: Option<HostDeadline>,
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
    let (preparation, input) = prepare_direct(runtime, session, submission, None)?;
    submit_prepared(runtime, preparation, input.payload, input.provenance).await
}

pub(crate) async fn submit_prepared(
    runtime: &GatewayRuntime,
    preparation: GatewayPreparation,
    payload: Value,
    provenance: Option<GatewayPayloadProvenance>,
) -> Result<GatewaySubmitResult, GatewayError> {
    if preparation.output_window.is_some() {
        return Err(GatewayError::Rejected(
            "stream preparation requires submit_output_stream_prepared".into(),
        ));
    }
    let delivery = crate::GatewaySubmissionAuthority::new(
        runtime,
        &preparation.session,
        &preparation.head.surface_id,
    );
    let start = match prepare(runtime, preparation, payload, provenance, delivery.clone()).await {
        Ok(start) => start,
        Err(error) => {
            if matches!(error, GatewayError::SubmissionIndeterminate(_)) {
                delivery.validate()?;
            }
            return Err(error);
        }
    };
    let result = match start {
        SubmissionStart::Replay(result) => Ok(*result),
        SubmissionStart::Accepted(prepared) => prepared.execute(None)?.complete().await,
    };
    delivery.validate()?;
    result
}

pub(crate) async fn submit_output_stream(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    submission: GatewaySubmission,
    window: StreamWindow,
) -> Result<GatewayOutputStream, GatewayError> {
    let (preparation, input) = prepare_direct(runtime, session, submission, Some(window))?;
    submit_output_stream_prepared(runtime, preparation, input.payload, input.provenance).await
}

pub(crate) async fn submit_output_stream_prepared(
    runtime: &GatewayRuntime,
    preparation: GatewayPreparation,
    payload: Value,
    provenance: Option<GatewayPayloadProvenance>,
) -> Result<GatewayOutputStream, GatewayError> {
    let window = preparation.output_window.ok_or_else(|| {
        GatewayError::Rejected("unary preparation requires submit_prepared".into())
    })?;
    let delivery = crate::GatewaySubmissionAuthority::new(
        runtime,
        &preparation.session,
        &preparation.head.surface_id,
    );
    let start = match prepare(runtime, preparation, payload, provenance, delivery.clone()).await {
        Ok(start) => start,
        Err(error) => {
            if matches!(error, GatewayError::SubmissionIndeterminate(_)) {
                delivery.validate()?;
            }
            return Err(error);
        }
    };
    match start {
        SubmissionStart::Replay(result) => Ok(GatewayOutputStream::replay(*result, delivery)),
        SubmissionStart::Accepted(prepared) => GatewayOutputStream::start(*prepared, window),
    }
}

async fn prepare(
    runtime: &GatewayRuntime,
    preparation: GatewayPreparation,
    payload: Value,
    provenance: Option<GatewayPayloadProvenance>,
    delivery: Arc<crate::GatewaySubmissionAuthority>,
) -> Result<SubmissionStart, GatewayError> {
    if !preparation.admission_guard.belongs_to(&runtime.requests) {
        return Err(GatewayError::Rejected(
            "preparation belongs to another gateway runtime".into(),
        ));
    }
    let GatewayPreparation {
        profile,
        session,
        head,
        deadline,
        output_window,
        admission_guard,
        risk_class: prepared_risk_class,
    } = preparation;
    let session = &session;
    validate_current_session(&runtime.profile_snapshot(), session)?;
    let submission = GatewaySubmission {
        surface_id: head.surface_id,
        body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
            payload,
            provenance,
        }),
        requested_output: head.requested_output,
        options: head.options,
        server_deadline: head.server_deadline,
    };
    let host = runtime.boot.kernel().host_runtime();
    let now = host.now();
    let now_ms = host.now_millis();
    validate_request_deadline(deadline, now, &profile.limits)?;
    let mut admission_guard = Some(admission_guard);
    let mut idempotency = match reserve_submission_idempotency_if_present(
        &runtime.idempotency,
        &profile,
        session,
        &submission,
        initial_idempotency_material(&runtime.boot, &profile, session, &submission)?,
        now_ms,
    )
    .await?
    {
        Some(SubmissionIdempotency::Replay(result)) => {
            runtime.validate_submission_access(session, &submission.surface_id)?;
            validate_request_deadline(deadline, host.now(), &profile.limits)?;
            return Ok(SubmissionStart::Replay(result));
        }
        Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
        None => None,
    };

    // Ordinary pre-dispatch failures release only this reservation. Dropping an
    // in-progress admission leaves its uncertain CAS result reserved.
    let admitted = async {
        runtime.validate_submission_access(session, &submission.surface_id)?;
        validate_request_deadline(deadline, host.now(), &profile.limits)?;
        let LoweredSubmission {
            program,
            surface,
            objects,
        } = lower_submission(submission.clone(), &profile, runtime, session).await?;
        runtime.validate_submission_access(session, &submission.surface_id)?;
        validate_request_deadline(deadline, host.now(), &profile.limits)?;
        let admission = inspect_lowered_submission(
            &program,
            &profile,
            &session.principal.principal_id,
            surface,
            &runtime.boot,
            true,
        )?;
        if (admission.requires_idempotency || objects.requires_idempotency()) && idempotency.is_none() {
            idempotency = match reserve_submission_idempotency_if_present(
                &runtime.idempotency,
                &profile,
                session,
                &submission,
                required_idempotency_material(&submission)?,
                now_ms,
            )
            .await?
            {
                Some(SubmissionIdempotency::Replay(result)) => {
                    runtime.validate_submission_access(session, &submission.surface_id)?;
                    validate_request_deadline(deadline, host.now(), &profile.limits)?;
                    return Ok(SubmissionStart::Replay(result));
                }
                Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
                None => {
                    return Err(GatewayError::Rejected(
                        "idempotency_key or submission_token is required for non-idempotent effects and single-use objects"
                            .into(),
                    ));
                }
            };
        }
        let risk_class = request_risk_class(&admission);
        if risk_class != prepared_risk_class {
            return Err(GatewayError::Rejected("prepared operation risk class changed".into()));
        }
        runtime.validate_submission_access(session, &submission.surface_id)?;
        validate_request_deadline(deadline, host.now(), &profile.limits)?;
        let surface_ids = BTreeSet::from([surface.surface_id.clone()]);
        let mut budget_charge = gateway_budget_charge_for_submit(&admission, deadline, now)?;
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
        let accepted = runtime
            .requests
            .new_acceptance(profile.revision, surface.surface_id.clone())?;
        let (request_owner, executor) = runtime
            .executor_for(&profile, session, &surface_ids, delivery.clone())
            .await?;
        runtime.validate_submission_access(session, &submission.surface_id)?;
        validate_request_deadline(deadline, host.now(), &profile.limits)?;
        let request_process = request_owner.id();
        let entry = GatewayRequestEntry {
            accepted: accepted.clone(),
            request_process,
            gateway_id: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            state: GatewayRequestState::Running,
            deadline,
            cancelled_until: None,
        };
        let request_guard =
            runtime
                .requests
                .insert_running(entry, admission_guard.take().ok_or_else(|| GatewayError::Rejected(
                    "preparation admission was already transferred".into(),
                ))?, budget_guard, request_owner,
                    delivery.clone())?;
        let object_identity = idempotency.as_deref().map(GatewayIdempotencyReservation::effect_identity);
        let object_taint = match request_guard
            .commit_objects(runtime, session, objects, deadline, object_identity.as_deref())
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
            release_submission_idempotency_reservation_and_fail(idempotency.as_deref(), error).await
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
    fn execute(self, output: Option<OutputPort>) -> Result<SubmissionExecution, GatewayError> {
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
            executor = executor
                .with_deadline(deadline)
                .map_err(|error| GatewayError::Rejected(error.to_string()))?;
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
                &mut execution_output,
            )
            .await
            .map_err(|error| {
                GatewayError::submission_indeterminate(
                    accepted.clone(),
                    execution_output.unresolved_operations.clone(),
                    "settlement_failed",
                    error.to_string(),
                )
            })?;
            Ok(GatewaySubmitResult {
                accepted,
                output: execution_output,
                origin: CompletionOrigin::CurrentAttempt,
            })
        });
        Ok(SubmissionExecution {
            future: Some(future),
            request_guard,
        })
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
        let result = result.and_then(|result| {
            self.request_guard.finish().map_err(|error| {
                GatewayError::submission_indeterminate(
                    result.accepted.clone(),
                    result.output.unresolved_operations.clone(),
                    "settlement_failed",
                    error.to_string(),
                )
            })?;
            Ok(result)
        });
        if result.is_err() {
            self.request_guard.fail();
        }
        Poll::Ready(result)
    }

    async fn complete(mut self) -> Result<GatewaySubmitResult, GatewayError> {
        poll_fn(|cx| self.poll_complete(cx)).await
    }
}
