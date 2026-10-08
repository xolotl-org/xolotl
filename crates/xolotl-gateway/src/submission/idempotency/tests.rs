use super::*;
use crate::{
    Gateway, GatewayAuthMethod, GatewayIdempotencyLimits, GatewayIdempotencyStore,
    GatewayIdempotencyUsage, GatewayModality, GatewayPrincipalSurfaceBinding, GatewayProfile,
    GatewayRuntime, GatewayStreamDirection, GatewayStreamOpenRequest, GatewaySurface,
    MemoryGatewayIdempotencyStore, PresentedCredential, VerifiedPrincipal,
};
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::future::{Future, pending, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};
use xolotl_kernel::host::{
    AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
};
use xolotl_types::{
    BlobRef, CompletionOrigin, DType, Failure, FloatBits, FrameKind, FrameRef, IdentityRef,
    Outcome, Path, TaintSet, TaintSource, TaintedValue, TensorRef,
};

#[tokio::test]
async fn request_cleanup_preserves_indeterminate_evidence_and_reservations() -> Result<()> {
    for structured in [false, true] {
        for cleanup_failure in [false, true] {
            for boundary in ["finish", "finish_release", "release"] {
                let boot = Bootstrap::in_memory();
                let store = memory_store();
                let reservation = reserved(Submission::new()?.reserve(&store).await?)?;
                let process = if cleanup_failure {
                    xolotl_types::ProcessId::new(u64::MAX)
                } else {
                    boot.request_under(boot.root(), IdentityRef::ROOT, &[])?
                        .detach()
                };
                let _cleanup_pin = if cleanup_failure {
                    None
                } else {
                    Some(boot.cleanup_ticket(process)?)
                };
                let mut unresolved = xolotl_types::UnresolvedOperations::default();
                ensure!(unresolved.record("observed-effect"));
                unresolved.identities_incomplete = true;
                let error = if structured {
                    GatewayError::submission_indeterminate(
                        accepted(),
                        unresolved.clone(),
                        "settlement_failed",
                        "private settlement details".into(),
                    )
                } else {
                    GatewayError::Indeterminate("receipt consumption verdict unavailable".into())
                };
                let result: Result<(), GatewayError> = match boundary {
                    "release" => {
                        release_submission_idempotency_reservation_and_fail(
                            Some(&reservation),
                            error,
                        )
                        .await
                    }
                    "finish_release" => {
                        finish_request_release_idempotency_and_fail(
                            &boot,
                            process,
                            Some(&reservation),
                            error,
                        )
                        .await
                    }
                    _ => finish_request_without_idempotency_and_fail(&boot, process, error).await,
                };
                let Err(error) = result else {
                    bail!("unknown result became success");
                };
                ensure!(error.code() == "outcome_unknown");
                ensure!(error.public_message() == "outcome unknown; reconcile before retrying");
                if structured {
                    let GatewayError::SubmissionIndeterminate(evidence) = error else {
                        bail!("structured acceptance was lost at {boundary}");
                    };
                    ensure!(evidence.accepted == accepted());
                    ensure!(evidence.unresolved_operations == unresolved);
                    ensure!(evidence.reason_code == "settlement_failed");
                    ensure!(evidence.detail.contains("private settlement details"));
                    ensure!(
                        evidence.detail.contains("request cleanup failed")
                            == (cleanup_failure && boundary != "release")
                    );
                } else {
                    ensure!(matches!(error, GatewayError::Indeterminate(_)));
                }
                ensure!(
                    store
                        .observe(&reservation.key)
                        .await?
                        .map(|record| record.value)
                        == Some(reservation.pending_record.clone())
                );
                ensure!(matches!(
                    Submission::new()?.reserve(&store).await,
                    Err(GatewayError::LimitExceeded(_))
                ));
                if !cleanup_failure {
                    ensure!(
                        boot.kernel().processes().status(process)
                            == Some(if boundary == "release" {
                                ProcessStatus::Running
                            } else {
                                ProcessStatus::Failed
                            })
                    );
                }
            }
        }
    }
    Ok(())
}

fn memory_store() -> Arc<dyn GatewayIdempotencyStore> {
    Arc::new(MemoryGatewayIdempotencyStore::default())
}

#[derive(Default)]
struct FaultStore {
    inner: MemoryGatewayIdempotencyStore,
    ticket: parking_lot::Mutex<Option<CleanupTicket>>,
    require_finalization: bool,
    observed_complete: AtomicBool,
    pause_next: AtomicBool,
    fail_observe: AtomicBool,
    pause_observe: AtomicBool,
    observe_entered: tokio::sync::Notify,
    observe_release: tokio::sync::Notify,
    raw: parking_lot::Mutex<BTreeMap<String, TaintedValue>>,
}

#[async_trait::async_trait]
impl GatewayIdempotencyStore for FaultStore {
    fn evidence_namespace(&self) -> Result<crate::GatewayEvidenceNamespace, GatewayError> {
        self.inner.evidence_namespace()
    }

    async fn retry_epoch(&self) -> Result<u64, GatewayError> {
        self.inner.retry_epoch().await
    }

    async fn close_retry_epoch(&self, expected: u64) -> Result<u64, GatewayError> {
        self.inner.close_retry_epoch(expected).await
    }

    fn limits(&self) -> GatewayIdempotencyLimits {
        self.inner.limits()
    }

    async fn reserve(
        &self,
        key: &str,
        pending_record: TaintedValue,
    ) -> Result<Option<TaintedValue>, GatewayError> {
        let raw = self.raw.lock().get(key).cloned();
        if raw.is_some() {
            return Ok(raw);
        }
        let observed = self.inner.reserve(key, pending_record).await?;
        if observed.is_none() && self.pause_next.swap(false, Ordering::AcqRel) {
            pending().await
        } else {
            Ok(observed)
        }
    }

    async fn complete(
        &self,
        key: &str,
        expected: Value,
        result: TaintedValue,
    ) -> Result<(), GatewayError> {
        if self.raw.lock().contains_key(key) {
            return Err(GatewayError::Indeterminate(
                "fault-injected record changed during settlement".into(),
            ));
        }
        if self.require_finalization {
            let complete = self.ticket.lock().as_ref().is_some_and(|ticket| {
                ticket.is_complete() && ticket.finalization_report().is_some()
            });
            self.observed_complete.store(complete, Ordering::SeqCst);
            if !complete {
                return Err(GatewayError::Rejected(
                    "cache commit preceded confirmed finalization".into(),
                ));
            }
        }
        self.inner.complete(key, expected, result).await
    }

    async fn release(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        let raw = self.raw.lock().get(key).cloned();
        if let Some(raw) = raw {
            if raw.value != expected {
                return Err(GatewayError::Indeterminate(
                    "fault-injected record changed before release".into(),
                ));
            }
            if raw
                .value
                .as_map()
                .and_then(|map| map.get("state"))
                .and_then(Value::as_str)
                != Some("pending")
            {
                return Err(GatewayError::Rejected(
                    "fault-injected record is not pending".into(),
                ));
            }
            let original = self.inner.observe(key).await?.ok_or_else(|| {
                GatewayError::Indeterminate("fault-injected reservation absent".into())
            })?;
            self.inner.release(key, original.value).await?;
            self.raw.lock().remove(key);
            return Ok(());
        }
        self.inner.release(key, expected).await
    }

    async fn observe(&self, key: &str) -> Result<Option<TaintedValue>, GatewayError> {
        if self.pause_observe.swap(false, Ordering::AcqRel) {
            self.observe_entered.notify_one();
            self.observe_release.notified().await;
        }
        if self.fail_observe.load(Ordering::Acquire) {
            return Err(GatewayError::Rejected(
                "separate observation unavailable".into(),
            ));
        }
        let raw = self.raw.lock().get(key).cloned();
        if raw.is_some() {
            return Ok(raw);
        }
        self.inner.observe(key).await
    }

    async fn retire(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        if self.raw.lock().contains_key(key) {
            return Err(GatewayError::Rejected(
                "fault-injected record cannot retire".into(),
            ));
        }
        self.inner.retire(key, expected).await
    }

    async fn usage(&self) -> Result<GatewayIdempotencyUsage, GatewayError> {
        self.inner.usage().await
    }
}

#[tokio::test]
async fn retired_submission_is_rejected_without_releasing_its_identity() -> Result<()> {
    let store = memory_store();
    let submission = Submission::new()?;
    let reservation = reserved(submission.reserve(&store).await?)?;
    let output = ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author());
    commit_submission_idempotency_output(&reservation, &accepted(), &output, 42).await?;
    let committed = store
        .observe(&reservation.key)
        .await?
        .context("missing committed request")?;
    store.retire(&reservation.key, committed.value).await?;
    let retired = store.observe(&reservation.key).await?;
    let usage = store.usage().await?;
    ensure!(usage.records == 1);
    ensure!(matches!(
        submission.reserve(&store).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(store.observe(&reservation.key).await? == retired);
    ensure!(store.usage().await? == usage);
    Ok(())
}

#[tokio::test]
async fn retained_result_commit_follows_confirmed_finalization() -> Result<()> {
    let port = Arc::new(FaultStore {
        require_finalization: true,
        ..Default::default()
    });
    let store: Arc<dyn GatewayIdempotencyStore> = port.clone();
    let boot = Bootstrap::in_memory();
    let submission = Submission::new()?;
    let reservation = reserved(submission.reserve(&store).await?)?;
    let owner = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
    let process = owner.id();
    *port.ticket.lock() = Some(owner.cleanup_ticket());
    let mut output = ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author());
    let before = store.usage().await?;
    ensure!(matches!(
        commit_submission_idempotency_output(&reservation, &accepted(), &output, 42).await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(!port.observed_complete.load(Ordering::SeqCst));
    ensure!(store.usage().await? == before);
    ensure!(
        store
            .observe(&reservation.key)
            .await?
            .map(|record| record.value)
            == Some(reservation.pending_record.clone())
    );
    commit_submission_idempotency_and_finish_request(
        &boot,
        process,
        Some(&reservation),
        &accepted(),
        &mut output,
    )
    .await?;
    ensure!(port.observed_complete.load(Ordering::SeqCst));
    ensure!(output.outcome == Outcome::Done(Value::integer(42)));
    let SubmissionIdempotency::Replay(replay) = submission.reserve(&store).await? else {
        bail!("finalized output was not retained");
    };
    ensure!(replay.output == output);
    owner.detach();
    Ok(())
}

#[tokio::test]
async fn closed_epoch_pending_and_unknown_remain_queryable_without_reservation() -> Result<()> {
    let store = memory_store();
    let submission = Submission::new()?;
    let reservation = reserved(submission.reserve(&store).await?)?;
    ensure!(store.close_retry_epoch(0).await? == 1);
    let pending = store
        .observe(&reservation.key)
        .await?
        .context("closed pending missing")?;
    ensure!(matches!(
        submission.reserve(&store).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(store.observe(&reservation.key).await? == Some(pending));
    let output = ExecutionOutput::new(
        Outcome::Fail(Failure::OutcomeUnknown {
            operation_ids: vec!["retained-operation".into()],
            reason: "uncertain effect".into(),
        }),
        TaintSet::author(),
    );
    commit_submission_idempotency_output(&reservation, &accepted(), &output, 43).await?;
    ensure!(store.close_retry_epoch(1).await? == 2);
    let SubmissionIdempotency::Replay(replayed) = submission.reserve(&store).await? else {
        bail!("closed unknown was redispatched");
    };
    ensure!(replayed.accepted == accepted());
    ensure!(replayed.output == output);
    ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
    let mut fixture = Submission::new()?;
    ensure!(matches!(
        reserve_submission_idempotency_if_present(
            &store,
            &fixture.profile,
            &fixture.session,
            &fixture.submission,
            Some(("idempotency_key", "new-old-key".into())),
            44
        )
        .await,
        Err(GatewayError::Rejected(_))
    ));
    fixture.submission.options.retry_epoch = 2;
    let scoped = reserve_submission_idempotency_if_present(
        &store,
        &fixture.profile,
        &fixture.session,
        &fixture.submission,
        Some(("idempotency_key", "new-old-key".into())),
        44,
    )
    .await?
    .context("scoped reservation missing")?;
    ensure!(matches!(scoped, SubmissionIdempotency::Reserved(_)));
    Ok(())
}

#[tokio::test]
async fn identity_material_remains_literal_independently_of_epoch() -> Result<()> {
    let store = memory_store();
    let fixture = Submission::new()?;
    for material in [
        "plain-key",
        "gw-retry:1:key",
        "gw-retry:01:key",
        "gw-retry:1:",
    ] {
        let reservation = reserve_submission_idempotency_if_present(
            &store,
            &fixture.profile,
            &fixture.session,
            &fixture.submission,
            Some(("idempotency_key", material.into())),
            42,
        )
        .await?
        .context("literal reservation")?;
        ensure!(reserved(reservation)?.fingerprint.retry_epoch == 0);
    }
    Ok(())
}

#[tokio::test]
async fn missing_finalization_retains_pending_without_flattening_body() -> Result<()> {
    let boot = Bootstrap::in_memory();
    let store = memory_store();
    let reservation = reserved(Submission::new()?.reserve(&store).await?)?;
    let mut output = ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author());
    ensure!(matches!(
        commit_submission_idempotency_and_finish_request(
            &boot,
            ProcessId::new(u64::MAX),
            Some(&reservation),
            &accepted(),
            &mut output,
        )
        .await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(output.outcome == Outcome::Done(Value::integer(42)));
    ensure!(output.unresolved_operations.identities_incomplete);
    ensure!(
        store
            .observe(&reservation.key)
            .await?
            .map(|record| record.value)
            == Some(reservation.pending_record)
    );
    let owner = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
    ensure!(confirmed_finalization_report(&owner.cleanup_ticket()).is_err());
    Ok(())
}

#[test]
fn finalizer_report_merges_evidence_without_replacing_body_outcome() -> Result<()> {
    let finalizer_taint = TaintSet::of(TaintSource::Inbound {
        source: "finalizer".into(),
        channel: "cleanup".into(),
    });
    let mut finalizer_unresolved = xolotl_types::UnresolvedOperations::default();
    ensure!(finalizer_unresolved.record("finalizer-effect"));
    finalizer_unresolved.identities_incomplete = true;
    let report = ProcessFinalizationReport {
        status: ProcessStatus::Failed,
        taint: finalizer_taint.clone(),
        unresolved_operations: finalizer_unresolved,
        finalizer_failures: vec![(
            0,
            xolotl_types::TaintedFailure::new(Failure::Cancelled, finalizer_taint.clone()),
        )],
        released_handles: 1,
        revoked_handles: 1,
    };
    let mut output = ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author());
    ensure!(output.unresolved_operations.record("body-effect"));
    merge_finalization_report(&mut output, &report);
    ensure!(output.outcome == Outcome::Done(Value::integer(42)));
    let mut expected_taint = TaintSet::author();
    expected_taint.union(&finalizer_taint);
    ensure!(output.taint == expected_taint);
    ensure!(output.unresolved_operations.operation_ids == ["body-effect", "finalizer-effect"]);
    ensure!(output.unresolved_operations.identities_incomplete);
    ensure!(report.finalizer_failures.len() == 1);
    Ok(())
}

struct ManualWallClock(AtomicI64);

impl HostClock for ManualWallClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn unix_millis(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(pending())
    }
}

struct ManualMonotonicClock {
    base: Instant,
    elapsed_ms: AtomicU64,
}

impl HostClock for ManualMonotonicClock {
    fn monotonic_now(&self) -> Instant {
        self.base + Duration::from_millis(self.elapsed_ms.load(Ordering::SeqCst))
    }

    fn unix_millis(&self) -> i64 {
        1_000 + i64::try_from(self.elapsed_ms.load(Ordering::SeqCst)).unwrap_or(i64::MAX)
    }

    fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(pending())
    }
}

struct NoTasks;

impl TaskSpawner for NoTasks {
    fn spawn(
        &self,
        _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        Err(TaskSpawnError::Unavailable)
    }
}

#[tokio::test]
async fn idempotency_metadata_follows_the_kernel_host_clock() -> Result<()> {
    let clock = Arc::new(ManualWallClock(AtomicI64::new(1_000)));
    let boot = Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(TokioBlockingSpawner::default()),
            ))
            .build(),
    );
    let store = memory_store();
    let submission = Submission::new()?;
    let reservation = reserved(
        submission
            .reserve_at(&store, boot.kernel().host_runtime().now_millis())
            .await?,
    )?;
    let pending = store
        .observe(&reservation.key)
        .await?
        .context("missing pending idempotency record")?
        .value;
    ensure!(
        pending
            .as_map()
            .and_then(|map| map.get("created_at_ms"))
            .and_then(Value::as_int)
            == Some(1_000)
    );

    clock.0.store(2_000, Ordering::SeqCst);
    let process = boot
        .request_under(boot.root(), IdentityRef::ROOT, &[])?
        .detach();
    let mut output = ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author());
    commit_submission_idempotency_and_finish_request(
        &boot,
        process,
        Some(&reservation),
        &accepted(),
        &mut output,
    )
    .await?;
    let committed = store
        .observe(&reservation.key)
        .await?
        .context("missing committed idempotency record")?
        .value;
    ensure!(
        committed
            .as_map()
            .and_then(|map| map.get("committed_at_ms"))
            .and_then(Value::as_int)
            == Some(2_000)
    );
    Ok(())
}

async fn stream_fixture() -> Result<(Arc<Bootstrap>, GatewayRuntime, GatewaySession)> {
    let boot = Arc::new(Bootstrap::in_memory());
    let profile = stream_profile(&boot)?;
    let gateway = GatewayRuntime::new(boot.clone(), profile, memory_store())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(
            "stream-idempotency-test-token-32-bytes",
        ))
        .await?;
    Ok((boot, gateway, session))
}

fn stream_profile(boot: &Bootstrap) -> Result<GatewayProfile> {
    let effect = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    Ok(GatewayProfile::new("stream-idempotency-cleanup")
        .with_bearer_identity(
            "client-key",
            "client",
            "stream-idempotency-test-token-32-bytes",
            "identity://client",
        )?
        .with_surface(GatewaySurface::effect_invoke("echo", effect))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "client",
            ["echo"],
            ["perform://effect/echo/say"],
        )))
}

fn stream_submission(key: &str, request_scope: &str) -> GatewaySubmission {
    GatewaySubmission::input_stream(
        "echo",
        GatewayStreamOpenRequest {
            stream_id: "input".into(),
            direction: GatewayStreamDirection::ClientToKernel,
            modality: GatewayModality::Text,
            item_schema_id: String::new(),
            max_inline_item_bytes: 16,
            max_items: Some(4),
            max_bytes: Some(64),
        },
    )
    .with_options(SubmitOptions {
        expected_request_scope: Some(request_scope.into()),
        idempotency_key: Some(key.into()),
        ..SubmitOptions::default()
    })
}

#[tokio::test]
async fn malformed_folded_input_finishes_its_owned_process() -> Result<()> {
    let (boot, gateway, session) = stream_fixture().await?;
    let request_scope = crate::tests::test_request_scope(&gateway, &session, "echo")?;
    let mut stream = gateway
        .accept_input_stream_submission(&session, stream_submission("valid-key", &request_scope))
        .await?;
    let process = stream.request_process;
    // A transport normally validates this before stream-open acceptance. Fault
    // injection tests the completion boundary with a malformed owned stream.
    stream.options.idempotency_key = Some("invalid/key".into());
    let result = gateway
        .complete_input_stream_submission(*stream, Value::string("text".into()), None)
        .await;
    ensure!(matches!(result, Err(GatewayError::Rejected(_))));
    ensure!(
        boot.kernel().processes().status(process) == Some(ProcessStatus::Failed),
        "malformed folded input left its owned request unfinished"
    );
    Ok(())
}

#[tokio::test]
async fn replay_cleanup_failure_is_indeterminate() -> Result<()> {
    let (_boot, gateway, session) = stream_fixture().await?;
    let request_scope = crate::tests::test_request_scope(&gateway, &session, "echo")?;
    let first = gateway
        .accept_input_stream_submission(&session, stream_submission("replay-key", &request_scope))
        .await?;
    gateway
        .complete_input_stream_submission(*first, Value::string("text".into()), None)
        .await?;
    let mut replay = gateway
        .accept_input_stream_submission(&session, stream_submission("replay-key", &request_scope))
        .await?;
    // Force request finalization to fail after the committed result is found.
    replay.request_process = ProcessId::new(u64::MAX);
    let result = gateway
        .complete_input_stream_submission(*replay, Value::string("text".into()), None)
        .await;
    ensure!(matches!(result, Err(GatewayError::Indeterminate(_))));
    Ok(())
}

#[tokio::test]
async fn expired_input_stream_cannot_replay_a_committed_result() -> Result<()> {
    let clock = Arc::new(ManualMonotonicClock {
        base: Instant::now(),
        elapsed_ms: AtomicU64::new(0),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(TokioBlockingSpawner::default()),
            ))
            .build(),
    ));
    let gateway = GatewayRuntime::new_manual(boot.clone(), stream_profile(&boot)?, memory_store())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(
            "stream-idempotency-test-token-32-bytes",
        ))
        .await?;
    let request_scope = crate::tests::test_request_scope(&gateway, &session, "echo")?;
    let first = gateway
        .accept_input_stream_submission(
            &session,
            stream_submission("expired-replay-key", &request_scope),
        )
        .await?;
    gateway
        .complete_input_stream_submission(*first, Value::string("text".into()), None)
        .await?;

    let deadline = boot
        .kernel()
        .host_runtime()
        .deadline_after(Duration::from_millis(10))
        .context("deadline overflow")?;
    let replay = gateway
        .accept_input_stream_submission(
            &session,
            stream_submission("expired-replay-key", &request_scope).with_server_deadline(deadline),
        )
        .await?;
    clock.elapsed_ms.store(11, Ordering::SeqCst);
    let result = gateway
        .complete_input_stream_submission(*replay, Value::string("text".into()), None)
        .await;
    ensure!(matches!(result, Err(GatewayError::Rejected(_))));
    Ok(())
}

#[tokio::test]
async fn executed_result_with_stale_reservation_is_indeterminate() -> Result<()> {
    let store = memory_store();
    let submission = Submission::new()?;
    let previous = reserved(submission.reserve(&store).await?)?;
    let rejected: Result<(), GatewayError> = release_submission_idempotency_reservation_and_fail(
        Some(&previous),
        GatewayError::Rejected("known pre-dispatch rejection".into()),
    )
    .await;
    ensure!(matches!(rejected, Err(GatewayError::Rejected(_))));
    let current = reserved(submission.reserve(&store).await?)?;
    let output = ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author());
    let Err(error) =
        commit_submission_idempotency_output(&previous, &accepted(), &output, 43).await
    else {
        anyhow::bail!("stale owner must not replace a new reservation");
    };
    ensure!(matches!(error, GatewayError::Indeterminate(_)));
    ensure!(
        store
            .observe(&current.key)
            .await?
            .map(|record| record.value)
            == Some(current.pending_record)
    );
    Ok(())
}

struct Submission {
    profile: CompiledGatewayProfile,
    session: GatewaySession,
    submission: GatewaySubmission,
}

impl Submission {
    fn new() -> Result<Self> {
        Ok(Self {
            profile: CompiledGatewayProfile::compile(
                GatewayProfile::new("idempotency").with_revision(1),
            )?,
            session: GatewaySession {
                principal: VerifiedPrincipal {
                    principal_id: "client".into(),
                    credential_id: "client-key".into(),
                    credential_generation: 1,
                    principal_generation: 1,
                    auth_method: GatewayAuthMethod::Bearer,
                },
                identity_path: "identity://client".into(),
                profile_name: "idempotency".into(),
                profile_rev: 1,
            },
            submission: GatewaySubmission::direct_input("echo", Value::string("hello".into())),
        })
    }

    async fn reserve(
        &self,
        store: &Arc<dyn GatewayIdempotencyStore>,
    ) -> Result<SubmissionIdempotency, GatewayError> {
        self.reserve_at(store, 42).await
    }

    async fn reserve_at(
        &self,
        store: &Arc<dyn GatewayIdempotencyStore>,
        now_ms: i64,
    ) -> Result<SubmissionIdempotency, GatewayError> {
        reserve_submission_idempotency_if_present(
            store,
            &self.profile,
            &self.session,
            &self.submission,
            Some(("idempotency_key", "same-key".into())),
            now_ms,
        )
        .await?
        .ok_or_else(|| GatewayError::Rejected("missing reservation".into()))
    }
}

fn reserved(result: SubmissionIdempotency) -> Result<Box<GatewayIdempotencyReservation>> {
    match result {
        SubmissionIdempotency::Reserved(reservation) => Ok(reservation),
        SubmissionIdempotency::Replay(_) => bail!("expected a new reservation"),
    }
}

fn accepted() -> GatewayAccepted {
    GatewayAccepted {
        submission_id: "accepted-once".into(),
        trace_root: "trace-once".into(),
        profile_rev: 1,
        surface_id: "echo".into(),
    }
}

async fn lookup_fixture() -> Result<(
    Arc<GatewayRuntime>,
    GatewaySession,
    Arc<FaultStore>,
    GatewayRequestLookup,
    GatewayProfile,
)> {
    let boot = Arc::new(Bootstrap::in_memory());
    let profile = stream_profile(&boot)?.with_limits(crate::GatewayLimitProfile {
        max_in_flight_requests: 1,
        ..Default::default()
    });
    let store = Arc::new(FaultStore::default());
    let gateway = Arc::new(GatewayRuntime::new(boot, profile.clone(), store.clone())?);
    let session = gateway
        .authenticate(PresentedCredential::bearer(
            "stream-idempotency-test-token-32-bytes",
        ))
        .await?;
    let lookup = GatewayRequestLookup {
        surface_id: "echo".into(),
        expected_request_scope: crate::tests::test_request_scope(&gateway, &session, "echo")?,
        retry_epoch: 0,
        identity: GatewayRequestIdentity::IdempotencyKey("same-key".into()),
    };
    Ok((gateway, session, store, lookup, profile))
}

async fn lookup_reservation(
    gateway: &GatewayRuntime,
    session: &GatewaySession,
    lookup: &GatewayRequestLookup,
) -> Result<Box<GatewayIdempotencyReservation>> {
    let material = match &lookup.identity {
        GatewayRequestIdentity::IdempotencyKey(material) => ("idempotency_key", material.clone()),
        GatewayRequestIdentity::SubmissionToken(material) => ("submission_token", material.clone()),
    };
    let submission = GatewaySubmission::direct_input(&lookup.surface_id, Value::from("hello"))
        .with_options(SubmitOptions {
            retry_epoch: lookup.retry_epoch,
            ..Default::default()
        });
    reserved(
        reserve_submission_idempotency_if_present(
            &gateway.idempotency,
            &gateway.profile_snapshot(),
            session,
            &submission,
            Some(material),
            42,
        )
        .await?
        .context("missing reservation")?,
    )
}

#[tokio::test]
async fn lookup_request_is_read_only_for_missing_pending_settled_retired_and_closed_epochs()
-> Result<()> {
    let (gateway, session, store, lookup, _) = lookup_fixture().await?;
    let before = store.usage().await?;
    ensure!(matches!(
        gateway.lookup_request(&session, lookup.clone()).await?,
        GatewayRequestEvidence::Unproven
    ));
    ensure!(store.usage().await? == before);
    ensure!(matches!(
        gateway
            .read_retained_request_result(&session, lookup.clone())
            .await?,
        crate::GatewayRetainedRequestResult::Unproven
    ));
    let reservation = lookup_reservation(&gateway, &session, &lookup).await?;
    ensure!(matches!(
        gateway
            .read_retained_request_result(&session, lookup.clone())
            .await?,
        crate::GatewayRetainedRequestResult::Reserved
    ));
    let before = store.usage().await?;
    ensure!(matches!(
        gateway.lookup_request(&session, lookup.clone()).await?,
        GatewayRequestEvidence::Reserved
    ));
    ensure!(store.usage().await? == before);
    let mut retirable_lookup = lookup.clone();
    retirable_lookup.identity = GatewayRequestIdentity::SubmissionToken("retirable".into());
    let retirable = lookup_reservation(&gateway, &session, &retirable_lookup).await?;
    ensure!(store.close_retry_epoch(0).await? == 1);
    ensure!(matches!(
        gateway.lookup_request(&session, lookup.clone()).await?,
        GatewayRequestEvidence::Reserved
    ));
    let accepted = GatewayAccepted {
        profile_rev: session.profile_rev,
        ..accepted()
    };
    let mut unresolved = UnresolvedOperations::default();
    ensure!(unresolved.record("original-effect"));
    unresolved.identities_incomplete = true;
    let output = ExecutionOutput::new(Outcome::Short(Value::from("retained")), TaintSet::author())
        .with_unresolved_operations(unresolved);
    commit_submission_idempotency_output(&reservation, &accepted, &output, 43).await?;
    let before = store.usage().await?;
    let GatewayRequestEvidence::Settled(result) =
        gateway.lookup_request(&session, lookup.clone()).await?
    else {
        bail!("missing settled evidence");
    };
    ensure!(result.accepted == accepted);
    ensure!(result.result_class == crate::GatewayRequestResultClass::Short);
    ensure!(result.unresolved_operations == output.unresolved_operations);
    let crate::GatewayRetainedRequestResult::Available(retained) = gateway
        .read_retained_request_result(&session, lookup.clone())
        .await?
    else {
        bail!("missing retained result");
    };
    ensure!(retained.output == output);
    ensure!(retained.origin == CompletionOrigin::CachedOutcome);
    ensure!(store.usage().await? == before);
    ensure!(store.retry_epoch().await? == 1);
    let clean_output =
        ExecutionOutput::new(Outcome::Done(Value::from("complete")), TaintSet::author());
    commit_submission_idempotency_output(&retirable, &accepted, &clean_output, 44).await?;
    let record = store
        .observe(&retirable.key)
        .await?
        .context("missing record")?;
    store.retire(&retirable.key, record.value).await?;
    ensure!(matches!(
        gateway
            .lookup_request(&session, retirable_lookup.clone())
            .await?,
        GatewayRequestEvidence::Retired
    ));
    ensure!(matches!(
        gateway
            .read_retained_request_result(&session, retirable_lookup)
            .await?,
        crate::GatewayRetainedRequestResult::Retired
    ));
    ensure!(store.retry_epoch().await? == 1);
    let mut missing = lookup;
    missing.identity = GatewayRequestIdentity::IdempotencyKey("absent".into());
    let before = store.usage().await?;
    ensure!(matches!(
        gateway.lookup_request(&session, missing).await?,
        GatewayRequestEvidence::Unproven
    ));
    ensure!(store.usage().await? == before);
    Ok(())
}

#[tokio::test]
async fn lookup_request_withholds_after_profile_scope_change_or_revocation_during_observe()
-> Result<()> {
    for deliver in [false, true] {
        for change in ["profile", "principal", "credential", "surface"] {
            let (gateway, session, store, lookup, mut profile) = lookup_fixture().await?;
            let reservation = lookup_reservation(&gateway, &session, &lookup).await?;
            let before = store.observe(&reservation.key).await?;
            let usage = store.usage().await?;
            store.pause_observe.store(true, Ordering::Release);
            let querying = {
                let gateway = gateway.clone();
                let session = session.clone();
                tokio::spawn(async move {
                    if deliver {
                        gateway
                            .read_retained_request_result(&session, lookup)
                            .await
                            .map(|_| ())
                    } else {
                        gateway.lookup_request(&session, lookup).await.map(|_| ())
                    }
                })
            };
            store.observe_entered.notified().await;
            profile = profile.with_revision(2);
            match change {
                "profile" => {}
                "principal" => profile.identity_mappings[0].enabled = false,
                "credential" => profile = profile.with_credential_revocation_floor(1),
                "surface" => profile.principal_surface_bindings.clear(),
                _ => bail!("unknown change"),
            }
            gateway.replace_profile(profile)?;
            store.observe_release.notify_one();
            ensure!(querying.await?.is_err());
            ensure!(store.observe(&reservation.key).await? == before);
            ensure!(store.usage().await? == usage);
        }
    }
    Ok(())
}

#[tokio::test]
async fn lookup_request_rejects_corruption_and_invalid_material_without_writes() -> Result<()> {
    let (gateway, session, store, lookup, _) = lookup_fixture().await?;
    let reservation = lookup_reservation(&gateway, &session, &lookup).await?;
    let original = store
        .observe(&reservation.key)
        .await?
        .context("missing record")?;
    for field in [
        "submission_hash",
        "schema",
        "state",
        "reservation_id",
        "created_at_ms",
        "profile_name",
        "effective_key_hash",
        "caller_material_hash",
        "retry_epoch",
    ] {
        let mut map = original.value.clone().into_map().context("not a map")?;
        if field == "reservation_id" {
            map.remove(field);
        } else {
            map.insert(field.into(), Value::from("INVALID"))?;
        }
        let corrupted = TaintedValue::new(Value::from(map), original.taint.clone());
        store
            .raw
            .lock()
            .insert(reservation.key.clone(), corrupted.clone());
        ensure!(
            matches!(
                gateway.lookup_request(&session, lookup.clone()).await,
                Err(GatewayError::Rejected(_))
            ),
            "{field}"
        );
        ensure!(store.observe(&reservation.key).await? == Some(corrupted));
    }
    store.raw.lock().clear();
    let mut normalized = lookup.clone();
    normalized.identity = GatewayRequestIdentity::IdempotencyKey("  same-key  ".into());
    ensure!(matches!(
        gateway.lookup_request(&session, normalized).await?,
        GatewayRequestEvidence::Reserved
    ));
    for identity in [
        GatewayRequestIdentity::IdempotencyKey(" ".into()),
        GatewayRequestIdentity::SubmissionToken("bad token".into()),
        GatewayRequestIdentity::IdempotencyKey("x".repeat(257)),
    ] {
        let mut invalid = lookup.clone();
        invalid.identity = identity;
        ensure!(gateway.lookup_request(&session, invalid).await.is_err());
    }
    let mut wrong_scope = lookup;
    wrong_scope.expected_request_scope = "0".repeat(64);
    ensure!(gateway.lookup_request(&session, wrong_scope).await.is_err());
    ensure!(store.observe(&reservation.key).await? == Some(original));
    let accepted = GatewayAccepted {
        profile_rev: session.profile_rev,
        ..accepted()
    };
    let output = ExecutionOutput::new(Outcome::Done(Value::from("retained")), TaintSet::author());
    commit_submission_idempotency_output(&reservation, &accepted, &output, 43).await?;
    let committed = store
        .observe(&reservation.key)
        .await?
        .context("missing committed record")?;
    for field in [
        "outcome_value",
        "outcome_status",
        "failure_json",
        "accepted_trace_root",
        "accepted_profile_rev",
        "accepted_surface_id",
        "unresolved_operations",
    ] {
        let mut map = committed.value.clone().into_map().context("not a map")?;
        if field == "failure_json" {
            map.insert("outcome_status".into(), Value::from("fail"))?;
            map.insert(field.into(), Value::from("invalid failure"))?;
        } else {
            map.remove(field);
        }
        let corrupted = TaintedValue::new(Value::from(map), committed.taint.clone());
        store
            .raw
            .lock()
            .insert(reservation.key.clone(), corrupted.clone());
        let lookup = GatewayRequestLookup {
            surface_id: "echo".into(),
            expected_request_scope: crate::tests::test_request_scope(&gateway, &session, "echo")?,
            retry_epoch: 0,
            identity: GatewayRequestIdentity::IdempotencyKey("same-key".into()),
        };
        if field == "failure_json" {
            let GatewayRequestEvidence::Settled(summary) =
                gateway.lookup_request(&session, lookup.clone()).await?
            else {
                bail!("missing summary");
            };
            ensure!(summary.result_class == crate::GatewayRequestResultClass::Fail);
            ensure!(matches!(
                gateway.read_retained_request_result(&session, lookup).await,
                Err(GatewayError::Rejected(_))
            ));
        } else {
            ensure!(
                matches!(
                    gateway.lookup_request(&session, lookup).await,
                    Err(GatewayError::Rejected(_))
                ),
                "{field}"
            );
        }
        ensure!(store.observe(&reservation.key).await? == Some(corrupted));
    }
    Ok(())
}

#[tokio::test]
async fn released_owner_cannot_replace_reclaimed_or_committed_reservation() -> Result<()> {
    let store = memory_store();
    let submission = Submission::new()?;
    let previous = reserved(submission.reserve(&store).await?)?;
    release_submission_idempotency_reservation(Some(&previous)).await?;
    ensure!(
        store
            .observe(&previous.key)
            .await?
            .map(|record| record.value)
            .is_none()
    );
    let current = reserved(submission.reserve(&store).await?)?;
    ensure!(previous.key == current.key);
    ensure!(previous.pending_record != current.pending_record);
    ensure!(
        release_submission_idempotency_reservation(Some(&previous))
            .await
            .is_err()
    );
    ensure!(
        store
            .observe(&current.key)
            .await?
            .map(|record| record.value)
            == Some(current.pending_record.clone())
    );

    let accepted = accepted();
    let output = ExecutionOutput::new(
        Outcome::Done(Value::string("hello".into())),
        TaintSet::author(),
    );
    commit_submission_idempotency_output(&current, &accepted, &output, 43).await?;
    let committed = store
        .observe(&current.key)
        .await?
        .context("committed record")?
        .value;
    ensure!(
        release_submission_idempotency_reservation(Some(&previous))
            .await
            .is_err()
    );
    ensure!(
        release_submission_idempotency_reservation(Some(&current))
            .await
            .is_err()
    );
    ensure!(
        store
            .observe(&current.key)
            .await?
            .map(|record| record.value)
            == Some(committed)
    );
    match submission.reserve(&store).await? {
        SubmissionIdempotency::Replay(replayed) => {
            ensure!(replayed.accepted == accepted);
            ensure!(replayed.output == output);
            ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
        }
        SubmissionIdempotency::Reserved(_) => bail!("committed result was not replayed"),
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_reservation_cas_preserves_pending() -> Result<()> {
    let port = Arc::new(FaultStore {
        pause_next: AtomicBool::new(true),
        ..Default::default()
    });
    let store: Arc<dyn GatewayIdempotencyStore> = port.clone();
    let submission = Submission::new()?;
    let mut reserving = Box::pin(submission.reserve(&store));
    ensure!(
        poll_fn(|cx| Poll::Ready(reserving.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let accepted_usage = store.usage().await?;
    ensure!(accepted_usage.records == 1);
    ensure!(matches!(
        submission.reserve(&store).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(store.usage().await? == accepted_usage);
    drop(reserving);
    ensure!(matches!(
        submission.reserve(&store).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(store.usage().await? == accepted_usage);
    Ok(())
}

#[tokio::test]
async fn record_with_wrong_fingerprint_is_not_replayed_or_removed() -> Result<()> {
    let port = Arc::new(FaultStore::default());
    let store: Arc<dyn GatewayIdempotencyStore> = port.clone();
    let submission = Submission::new()?;
    let reservation = reserved(submission.reserve(&store).await?)?;
    let before = store.usage().await?;
    let Some(mut mismatched) = reservation.pending_record.clone().into_map() else {
        bail!("pending record was not a map");
    };
    mismatched.insert("principal_id".into(), Value::string("other-client".into()))?;
    let mismatched = Value::from(mismatched);
    port.raw.lock().insert(
        reservation.key.clone(),
        TaintedValue::pristine(mismatched.clone()),
    );
    ensure!(matches!(
        submission.reserve(&store).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(
        release_submission_idempotency_reservation(Some(&reservation))
            .await
            .is_err()
    );
    ensure!(
        store
            .observe(&reservation.key)
            .await?
            .map(|record| record.value)
            == Some(mismatched)
    );
    ensure!(store.usage().await? == before);
    Ok(())
}

#[tokio::test]
async fn retained_results_preserve_typed_values_failures_and_protected_provenance() -> Result<()> {
    let blob = BlobRef {
        hash: "0123456789abcdef".repeat(6),
        size: 16,
        mime: Some("application/octet-stream".into()),
    };
    let mut items = vec![
        Value::blob(blob.clone()),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::F32,
            shape: vec![2, 2],
        }),
        Value::from(FrameRef {
            blob,
            ts_nanos: 123_456,
            kind: FrameKind::Sensor,
        }),
        Value::bytes(vec![0, 1, 255]),
    ];
    items.extend(
        [
            0,
            0x8000_0000_0000_0000,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0x7ff8_1234_5678_9abc,
        ]
        .into_iter()
        .map(|bits| Value::float(FloatBits(f64::from_bits(bits)))),
    );
    let value = Value::map(BTreeMap::from([("nested".into(), Value::list(items))]));
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/retained-result")?,
    });
    for outcome in [
        Outcome::Done(value.clone()),
        Outcome::Short(value),
        Outcome::Done(Value::null()),
        Outcome::Fail(Failure::HandlerError {
            kind: "protected-driver".into(),
            message: "retained diagnostic".into(),
        }),
        Outcome::Fail(Failure::OutcomeUnknown {
            operation_ids: vec!["typed-effect".into()],
            reason: "retained unknown effect".into(),
        }),
    ] {
        let port = Arc::new(FaultStore::default());
        let store: Arc<dyn GatewayIdempotencyStore> = port.clone();
        let submission = Submission::new()?;
        let reservation = reserved(submission.reserve(&store).await?)?;
        let accepted = accepted();
        let mut unresolved = xolotl_types::UnresolvedOperations::default();
        unresolved.record("1/2/3/4/0");
        unresolved.identities_incomplete = true;
        let output =
            ExecutionOutput::new(outcome, taint.clone()).with_unresolved_operations(unresolved);
        commit_submission_idempotency_output(&reservation, &accepted, &output, 43).await?;
        let retained = store
            .observe(&reservation.key)
            .await?
            .context("missing retained result")?;
        ensure!(
            retained
                .value
                .as_map()
                .and_then(|record| record.get("unresolved_operations"))
                .and_then(Value::as_map)
                .is_some(),
            "reconciliation state must remain a typed record"
        );
        ensure!(
            retained.taint == output.taint,
            "request store lost result provenance"
        );
        port.fail_observe.store(true, Ordering::Release);
        ensure!(store.observe(&reservation.key).await.is_err());
        let SubmissionIdempotency::Replay(replayed) = submission.reserve(&store).await? else {
            bail!("retained result was executed again");
        };
        ensure!(replayed.accepted == accepted);
        ensure!(replayed.output == output);
        ensure!(replayed.origin == CompletionOrigin::CachedOutcome);

        let mut missing_taint = serde_json::to_value(&retained)?;
        missing_taint
            .as_object_mut()
            .context("invalid envelope")?
            .remove("taint");
        ensure!(serde_json::from_value::<TaintedValue>(missing_taint).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn accepted_profile_revision_codec_is_lossless_canonical_and_request_bound() -> Result<()> {
    let signed_max = u64::try_from(i64::MAX)?;
    for revision in [1, signed_max, signed_max + 1, u64::MAX] {
        let store = memory_store();
        let mut submission = Submission::new()?;
        submission.profile.revision = revision;
        submission.session.profile_rev = revision;
        let reservation = reserved(submission.reserve(&store).await?)?;
        let accepted = GatewayAccepted {
            profile_rev: revision,
            ..accepted()
        };
        let output =
            ExecutionOutput::new(Outcome::Done(Value::from("retained")), TaintSet::author());
        commit_submission_idempotency_output(&reservation, &accepted, &output, 43).await?;
        let retained = store
            .observe(&reservation.key)
            .await?
            .context("missing record")?;
        let map = retained.value.as_map().context("record is not a map")?;
        let encoded = match i64::try_from(revision) {
            Ok(revision) => Value::integer(revision),
            Err(_) => Value::string(revision.to_string()),
        };
        ensure!(map.get("accepted_profile_rev") == Some(&encoded));
        let (_, Some(result)) = record::decode(retained.clone(), &reservation.fingerprint, true)?
        else {
            bail!("missing decoded result");
        };
        ensure!(result.accepted == accepted);
        ensure!(result.output == output);
        let SubmissionIdempotency::Replay(replay) = submission.reserve(&store).await? else {
            bail!("missing replay");
        };
        ensure!(replay == result);
        for malformed in [
            Value::integer(-1),
            Value::integer(i64::MIN),
            Value::integer(0),
            Value::float(FloatBits(1.0)),
            Value::null(),
            Value::boolean(true),
            Value::from(""),
            Value::from("0"),
            Value::from("1"),
            Value::from("9223372036854775807"),
            Value::from("+9223372036854775808"),
            Value::from("-9223372036854775808"),
            Value::from("09223372036854775808"),
            Value::from(" 9223372036854775808"),
            Value::from("9223372036854775808 "),
            Value::from("9223372036854775808.0"),
            Value::from("1e19"),
            Value::from("18446744073709551616"),
            Value::from("999999999999999999999"),
        ] {
            let mut corrupt = map.clone();
            corrupt.insert("accepted_profile_rev".into(), malformed)?;
            let corrupt = TaintedValue::new(Value::from(corrupt), retained.taint.clone());
            ensure!(matches!(
                record::decode(corrupt.clone(), &reservation.fingerprint, false),
                Err(GatewayError::Rejected(_))
            ));
            ensure!(matches!(
                record::replay(corrupt, &reservation.fingerprint),
                Err(GatewayError::Rejected(_))
            ));
        }
        for field in ["accepted_profile_rev", "profile_rev"] {
            let mut corrupt = map.clone();
            let different = if revision == 1 { 2 } else { 1 };
            let value = if field == "accepted_profile_rev" {
                Value::integer(different)
            } else {
                Value::string(different.to_string())
            };
            corrupt.insert(field.into(), value)?;
            ensure!(matches!(
                record::decode(
                    TaintedValue::new(Value::from(corrupt), retained.taint.clone()),
                    &reservation.fingerprint,
                    false
                ),
                Err(GatewayError::Rejected(_))
            ));
        }
        let zero = GatewayAccepted {
            profile_rev: 0,
            ..accepted
        };
        ensure!(matches!(
            record::committed(&reservation.fingerprint, &zero, &output, 44),
            Err(GatewayError::Rejected(_))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn old_and_malformed_committed_records_are_rejected_without_release() -> Result<()> {
    for corruption in [
        "unsupported_schema",
        "missing_schema",
        "missing_value",
        "invalid_status",
        "missing_failure",
        "invalid_failure",
        "missing_acceptance",
        "missing_reconciliation",
        "invalid_reconciliation",
        "wrong_surface",
        "wrong_revision",
    ] {
        let port = Arc::new(FaultStore::default());
        let store: Arc<dyn GatewayIdempotencyStore> = port.clone();
        let submission = Submission::new()?;
        let reservation = reserved(submission.reserve(&store).await?)?;
        let output =
            ExecutionOutput::new(Outcome::Done(Value::from("retained")), TaintSet::author());
        commit_submission_idempotency_output(&reservation, &accepted(), &output, 43).await?;
        let before = store.usage().await?;
        let retained = store
            .observe(&reservation.key)
            .await?
            .context("missing record")?;
        let retained_value = retained.value.clone();
        let Some(mut map) = retained_value.into_map() else {
            bail!("committed record was not a map");
        };
        match corruption {
            "unsupported_schema" => {
                map.insert("schema".into(), Value::from("gateway-idempotency-v99"))?;
            }
            "missing_schema" => {
                map.remove("schema");
            }
            "missing_value" => {
                map.remove("outcome_value");
            }
            "invalid_status" => {
                map.insert("outcome_status".into(), Value::from("unknown"))?;
            }
            "missing_failure" | "invalid_failure" => {
                map.insert("outcome_status".into(), Value::from("fail"))?;
                map.remove("outcome_value");
                if corruption == "invalid_failure" {
                    map.insert("failure_json".into(), Value::from("not a failure"))?;
                }
            }
            "missing_acceptance" => {
                map.remove("accepted_trace_root");
            }
            "missing_reconciliation" => {
                map.remove("unresolved_operations");
            }
            "invalid_reconciliation" => {
                map.insert(
                    "unresolved_operations".into(),
                    Value::map(BTreeMap::from([
                        (
                            "operation_ids".into(),
                            Value::list(vec![Value::from("z"), Value::from("a")]),
                        ),
                        ("identities_incomplete".into(), Value::boolean(false)),
                    ])),
                )?;
            }
            "wrong_surface" => {
                map.insert(
                    "accepted_surface_id".into(),
                    Value::from("different-surface"),
                )?;
            }
            "wrong_revision" => {
                map.insert("accepted_profile_rev".into(), Value::integer(2))?;
            }
            _ => bail!("unknown corruption case"),
        }
        let corrupted = TaintedValue::new(Value::from(map), retained.taint);
        port.raw
            .lock()
            .insert(reservation.key.clone(), corrupted.clone());
        ensure!(
            matches!(
                submission.reserve(&store).await,
                Err(GatewayError::Rejected(_))
            ),
            "{corruption}"
        );
        ensure!(
            store.observe(&reservation.key).await? == Some(corrupted),
            "{corruption}"
        );
        ensure!(
            release_submission_idempotency_reservation(Some(&reservation))
                .await
                .is_err(),
            "{corruption}"
        );
        ensure!(store.usage().await? == before, "{corruption}");
    }
    Ok(())
}

#[test]
fn equal_payloads_ignore_allocation_sharing_in_submission_fingerprints() -> Result<()> {
    let leaf = Value::list(vec![Value::from("same"), Value::integer(42)]);
    let shared = Value::list(vec![leaf.clone(), leaf]);
    let duplicated = Value::list(vec![
        Value::list(vec![Value::from("same"), Value::integer(42)]),
        Value::list(vec![Value::from("same"), Value::integer(42)]),
    ]);
    ensure!(shared == duplicated);
    let first = GatewaySubmission::direct_input("echo", shared);
    let second = GatewaySubmission::direct_input("echo", duplicated);
    let first_hash = submission_hash(&first)?;
    let second_hash = submission_hash(&second)?;
    ensure!(first_hash == second_hash);
    let fixture = Submission::new()?;
    ensure!(
        effective_idempotency_hash(
            &fixture.profile,
            &fixture.session,
            &first.surface_id,
            first.options.retry_epoch,
            "idempotency_key",
            "same-key"
        ) == effective_idempotency_hash(
            &fixture.profile,
            &fixture.session,
            &second.surface_id,
            second.options.retry_epoch,
            "idempotency_key",
            "same-key"
        )
    );
    Ok(())
}

#[tokio::test]
async fn large_result_lookup_projects_only_original_summary_without_writes() -> Result<()> {
    for outcome in [
        Outcome::Done(Value::string("retained".repeat(65_536))),
        Outcome::Fail(Failure::PolicyViolation {
            policy: "original".into(),
            detail: "private".repeat(65_536),
        }),
    ] {
        let (gateway, session, store, lookup, _) = lookup_fixture().await?;
        let reservation = lookup_reservation(&gateway, &session, &lookup).await?;
        let accepted = GatewayAccepted {
            profile_rev: session.profile_rev,
            ..accepted()
        };
        let output = ExecutionOutput::new(outcome.clone(), TaintSet::author());
        commit_submission_idempotency_output(&reservation, &accepted, &output, 43).await?;
        let original = store.observe(&reservation.key).await?;
        let usage = store.usage().await?;
        let GatewayRequestEvidence::Settled(summary) =
            gateway.lookup_request(&session, lookup.clone()).await?
        else {
            bail!("missing summary");
        };
        ensure!(summary.accepted == accepted);
        ensure!(
            summary.result_class
                == match outcome {
                    Outcome::Fail(_) => crate::GatewayRequestResultClass::Fail,
                    _ => crate::GatewayRequestResultClass::Done,
                }
        );
        let crate::GatewayRetainedRequestResult::Available(result) = gateway
            .read_retained_request_result(&session, lookup)
            .await?
        else {
            bail!("missing retained result");
        };
        ensure!(result.output == output && result.origin == CompletionOrigin::CachedOutcome);
        ensure!(store.observe(&reservation.key).await? == original);
        ensure!(store.usage().await? == usage);
    }
    Ok(())
}
