use super::*;
use std::future::{Future, poll_fn};
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;

#[tokio::test]
async fn revocation_before_first_poll_prevents_driver_dispatch() -> anyhow::Result<()> {
    let fixture = Fixture::new(StreamingDriver::new(Vec::new()), Purity::Effectful).await?;
    let mut stream = fixture
        .open(submission().with_options(SubmitOptions {
            expected_request_scope: Some(crate::tests::test_request_scope(
                &fixture.gateway,
                &fixture.session,
                "output",
            )?),
            idempotency_key: Some("revoked-before-dispatch".into()),
            ..SubmitOptions::default()
        }))
        .await?;
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 0);
    fixture
        .gateway
        .replace_profile(GatewayProfile::new("gateway-test").with_revision(2))?;
    let error = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await?
        .context("revoked stream did not terminate")?
        .err()
        .context("revoked stream disclosed a result")?;
    ensure!(matches!(error, GatewayError::Indeterminate(_)));
    ensure!(
        fixture.driver.calls.load(Ordering::Acquire) == 0,
        "revoked request dispatched an effect before rejecting delivery"
    );
    drop(stream);
    ensure!(
        fixture
            .gateway
            .boot
            .drain_cleanup()
            .await
            .failures
            .is_empty()
    );
    Ok(())
}

struct CommitStore {
    inner: MemoryGatewayIdempotencyStore,
    entered: AtomicBool,
    resume: Notify,
    pause_after_reserve: bool,
    pause_after_commit: bool,
    fail_after_commit: bool,
}

#[async_trait::async_trait]
impl GatewayIdempotencyStore for CommitStore {
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
        pending: TaintedValue,
    ) -> Result<Option<TaintedValue>, GatewayError> {
        let result = self.inner.reserve(key, pending).await?;
        if self.pause_after_reserve {
            self.entered.store(true, Ordering::Release);
            self.resume.notified().await;
        }
        Ok(result)
    }
    async fn complete(
        &self,
        key: &str,
        expected: Value,
        result: TaintedValue,
    ) -> Result<(), GatewayError> {
        self.entered.store(true, Ordering::Release);
        if self.pause_after_commit {
            self.inner.complete(key, expected, result).await?;
            self.resume.notified().await;
            if self.fail_after_commit {
                Err(GatewayError::Indeterminate("private commit failure".into()))
            } else {
                Ok(())
            }
        } else {
            if !self.pause_after_reserve {
                self.resume.notified().await;
            }
            self.inner.complete(key, expected, result).await
        }
    }
    async fn release(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        self.inner.release(key, expected).await
    }
    async fn observe(&self, key: &str) -> Result<Option<TaintedValue>, GatewayError> {
        self.inner.observe(key).await
    }
    async fn retire(&self, key: &str, expected: Value) -> Result<(), GatewayError> {
        self.inner.retire(key, expected).await
    }
    async fn usage(&self) -> Result<GatewayIdempotencyUsage, GatewayError> {
        self.inner.usage().await
    }
}

#[tokio::test]
async fn revocation_after_commit_withholds_output_without_erasing_the_commit() -> anyhow::Result<()>
{
    for (mode, fail_after_commit) in [OutputMode::Unary, OutputMode::Stream, OutputMode::SinkOnly]
        .into_iter()
        .flat_map(|mode| [false, true].map(|fail| (mode, fail)))
    {
        let store = Arc::new(CommitStore {
            inner: MemoryGatewayIdempotencyStore::default(),
            entered: AtomicBool::new(false),
            resume: Notify::new(),
            pause_after_reserve: false,
            pause_after_commit: true,
            fail_after_commit,
        });
        let mut fixture = Fixture::new(StreamingDriver::new(Vec::new()), Purity::Effectful).await?;
        fixture.gateway.idempotency = store.clone();
        let request = submission()
            .with_requested_output(mode)
            .with_options(SubmitOptions {
                expected_request_scope: Some(crate::tests::test_request_scope(
                    &fixture.gateway,
                    &fixture.session,
                    "output",
                )?),
                idempotency_key: Some("delivery-commit".into()),
                ..SubmitOptions::default()
            });
        let mut response = Box::pin(fixture.complete(request));
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            poll_fn(|cx| {
                if response.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(anyhow::anyhow!(
                        "response disclosed before commit release"
                    )))
                } else if store.entered.load(Ordering::Acquire) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await??;
        fixture
            .gateway
            .replace_profile(GatewayProfile::new("gateway-test").with_revision(2))?;
        store.resume.notify_one();
        let error = response
            .await
            .err()
            .context("revoked completion was disclosed")?;
        ensure!(matches!(
            error.downcast_ref::<GatewayError>(),
            Some(GatewayError::Indeterminate(_))
        ));
        ensure!(store.usage().await?.records == 1);
        ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
        ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    }
    Ok(())
}

#[tokio::test]
async fn input_stream_revocation_after_reserve_prevents_driver_dispatch() -> anyhow::Result<()> {
    let store = Arc::new(CommitStore {
        inner: MemoryGatewayIdempotencyStore::default(),
        entered: AtomicBool::new(false),
        resume: Notify::new(),
        pause_after_reserve: true,
        pause_after_commit: false,
        fail_after_commit: false,
    });
    let boot = Arc::new(Bootstrap::in_memory());
    let driver = Arc::new(StreamingDriver::new(Vec::new()));
    let target = boot.register_effect(
        "effect://echo/say",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver.clone(),
    )?;
    let gateway =
        GatewayRuntime::new_manual(boot, crate::tests::echo_profile(target)?, store.clone())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let stream = gateway
        .accept_input_stream_submission(
            &session,
            crate::tests::input_stream_submission("echo").with_options(SubmitOptions {
                expected_request_scope: Some(crate::tests::test_request_scope(
                    &gateway, &session, "echo",
                )?),
                idempotency_key: Some("input-revoked-before-dispatch".into()),
                ..SubmitOptions::default()
            }),
        )
        .await?;
    let mut response =
        Box::pin(gateway.complete_input_stream_submission(*stream, Value::from("input"), None));
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        poll_fn(|cx| {
            if response.as_mut().poll(cx).is_ready() {
                Poll::Ready(Err(anyhow::anyhow!(
                    "input completion returned before reserve release"
                )))
            } else if store.entered.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await??;
    ensure!(driver.calls.load(Ordering::Acquire) == 0);
    ensure!(gateway.requests.inner.lock().global_running == 1);
    gateway.replace_profile(GatewayProfile::new("gateway-test").with_revision(2))?;
    store.resume.notify_one();
    let error = tokio::time::timeout(std::time::Duration::from_secs(2), response)
        .await?
        .err()
        .context("revoked input completion disclosed a result")?;
    ensure!(matches!(
        error,
        GatewayError::Indeterminate(ref detail)
            if detail == "submission delivery access unavailable"
    ));
    ensure!(driver.calls.load(Ordering::Acquire) == 0);
    {
        let registry = gateway.requests.inner.lock();
        ensure!(registry.global_running == 0);
        ensure!(registry.budget_running == crate::request_registry::GatewayBudgetCharge::default());
    }
    ensure!(gateway.boot.drain_cleanup().await.failures.is_empty());
    ensure!(driver.live.load(Ordering::Acquire) == 0);
    Ok(())
}

#[tokio::test]
async fn input_stream_completion_reauthorizes_after_the_final_commit_await() -> anyhow::Result<()> {
    let store = Arc::new(CommitStore {
        inner: MemoryGatewayIdempotencyStore::default(),
        entered: AtomicBool::new(false),
        resume: Notify::new(),
        pause_after_reserve: false,
        pause_after_commit: true,
        fail_after_commit: false,
    });
    let boot = Arc::new(Bootstrap::in_memory());
    let driver = Arc::new(StreamingDriver::new(Vec::new()));
    let target = boot.register_effect(
        "effect://echo/say",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver.clone(),
    )?;
    let gateway =
        GatewayRuntime::new_manual(boot, crate::tests::echo_profile(target)?, store.clone())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let stream = gateway
        .accept_input_stream_submission(
            &session,
            crate::tests::input_stream_submission("echo").with_options(SubmitOptions {
                expected_request_scope: Some(crate::tests::test_request_scope(
                    &gateway, &session, "echo",
                )?),
                idempotency_key: Some("input-delivery".into()),
                ..SubmitOptions::default()
            }),
        )
        .await?;
    let mut response =
        Box::pin(gateway.complete_input_stream_submission(*stream, Value::from("input"), None));
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        poll_fn(|cx| {
            if response.as_mut().poll(cx).is_ready() {
                Poll::Ready(Err(anyhow::anyhow!(
                    "input completion disclosed before commit release"
                )))
            } else if store.entered.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await??;
    gateway.replace_profile(GatewayProfile::new("gateway-test").with_revision(2))?;
    store.resume.notify_one();
    ensure!(matches!(
        response.await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(store.usage().await?.records == 1);
    ensure!(driver.calls.load(Ordering::Acquire) == 1);
    ensure!(gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn result_is_fixed_before_idempotency_commit_finishes() -> anyhow::Result<()> {
    for mode in [OutputMode::Unary, OutputMode::Stream, OutputMode::SinkOnly] {
        for pause_after_commit in [false, true] {
            for fail in [false, true] {
                let store = Arc::new(CommitStore {
                    inner: MemoryGatewayIdempotencyStore::default(),
                    entered: AtomicBool::new(false),
                    resume: Notify::new(),
                    pause_after_reserve: false,
                    pause_after_commit,
                    fail_after_commit: false,
                });
                let mut driver = StreamingDriver::new(Vec::new());
                driver.completion.taint.add(TaintSource::Protected {
                    path: Path::parse("state://vault/committed-result")?,
                });
                if fail {
                    driver.completion.outcome = Outcome::Fail(Failure::InvalidInput {
                        reason: "protected failure".into(),
                    });
                }
                let expected = if mode == OutputMode::SinkOnly && !fail {
                    Outcome::Done(Value::null())
                } else {
                    driver.completion.outcome.clone()
                };
                let mut fixture = Fixture::with_boot(
                    Arc::new(Bootstrap::in_memory()),
                    driver,
                    Purity::Effectful,
                    GatewayLimitProfile::default(),
                )
                .await?;
                fixture.gateway.idempotency = store.clone();
                let request =
                    submission()
                        .with_requested_output(mode)
                        .with_options(SubmitOptions {
                            expected_request_scope: Some(crate::tests::test_request_scope(
                                &fixture.gateway,
                                &fixture.session,
                                "output",
                            )?),
                            idempotency_key: Some("commit-race".into()),
                            deadline_ms: Some(u64::try_from(now_millis().saturating_add(60_000))?),
                            ..SubmitOptions::default()
                        });
                let mut response = Box::pin(fixture.complete(request.clone()));
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    poll_fn(|cx| {
                        if response.as_mut().poll(cx).is_ready() {
                            Poll::Ready(Err(anyhow::anyhow!(
                                "response completed before its commit was released"
                            )))
                        } else if store.entered.load(Ordering::Acquire) {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        }
                    }),
                )
                .await??;
                let entry = fixture
                    .gateway
                    .requests
                    .inner
                    .lock()
                    .entries
                    .values()
                    .next()
                    .context("missing admitted request")?
                    .clone();
                ensure!(
                    entry.state
                        == if fail {
                            GatewayRequestState::Failed
                        } else {
                            GatewayRequestState::Completed
                        }
                );
                ensure!(!fixture.gateway.cancel(
                    &fixture.session,
                    GatewayCancelRequest {
                        submission_id: entry.accepted.submission_id.clone(),
                        trace_root: entry.accepted.trace_root.clone(),
                        reason: None,
                    },
                )?);
                ensure!(
                    fixture
                        .gateway
                        .requests
                        .expire_deadlines(entry.deadline.context("missing request deadline")?)
                        .is_empty()
                );
                store.resume.notify_one();
                let (chunks, first) = response.await?;
                ensure!(chunks == 0);
                ensure!(first.output.outcome == expected);
                ensure!(first.output.taint.has_protected());
                ensure!(first.origin == CompletionOrigin::CurrentAttempt);
                let (chunks, replayed) = fixture.complete(request).await?;
                ensure!(chunks == 0);
                ensure!(replayed.output == first.output);
                ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
                ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn driver_interruption_failures_do_not_cancel_the_gateway_request() -> anyhow::Result<()> {
    for mode in [OutputMode::Unary, OutputMode::Stream, OutputMode::SinkOnly] {
        for failure in [Failure::Timeout, Failure::Cancelled] {
            let mut driver = StreamingDriver::new(Vec::new());
            driver.completion.outcome = Outcome::Fail(failure.clone());
            driver.completion.taint.add(TaintSource::Protected {
                path: Path::parse("state://vault/driver-failure")?,
            });
            let fixture = Fixture::new(driver, Purity::Effectful).await?;
            let request = submission()
                .with_requested_output(mode)
                .with_options(SubmitOptions {
                    expected_request_scope: Some(crate::tests::test_request_scope(
                        &fixture.gateway,
                        &fixture.session,
                        "output",
                    )?),
                    idempotency_key: Some("driver-failure".into()),
                    deadline_ms: Some(u64::try_from(now_millis().saturating_add(60_000))?),
                    ..SubmitOptions::default()
                });
            let (first, process) = if mode == OutputMode::Stream {
                let mut stream = fixture.open(request.clone()).await?;
                let process = fixture.gateway.requests.inner.lock().entries
                    [&stream.accepted().submission_id]
                    .request_process;
                let (_, first) = finish(&mut stream).await?;
                (first, Some((process, stream)))
            } else {
                let (_, first) = fixture.complete(request.clone()).await?;
                (first, None)
            };
            ensure!(first.output.outcome == Outcome::Fail(failure.clone()));
            ensure!(first.output.taint.has_protected());
            if let Some((process, stream)) = process {
                ensure!(
                    fixture.gateway.boot.kernel().processes().status(process)
                        == Some(ProcessStatus::Cancelled)
                );
                drop(stream);
            }
            {
                let registry = fixture.gateway.requests.inner.lock();
                ensure!(!registry.entries.contains_key(&first.accepted.submission_id));
                ensure!(!registry.history.contains_key(&first.accepted.submission_id));
            }
            ensure!(!fixture.gateway.cancel(
                &fixture.session,
                GatewayCancelRequest {
                    submission_id: first.accepted.submission_id.clone(),
                    trace_root: first.accepted.trace_root.clone(),
                    reason: None,
                },
            )?);
            let (_, replayed) = fixture.complete(request).await?;
            ensure!(replayed.output == first.output);
            ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
            ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
        }
    }
    Ok(())
}
