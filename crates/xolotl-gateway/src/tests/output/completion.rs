use super::*;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;
use xolotl_kernel::{FactSink, Kernel};
use xolotl_state::{Backend, InMemoryBackend, StateMutation, StateRead, StateResult, StateWrite};

struct CommitState {
    inner: InMemoryBackend,
    entered: AtomicBool,
    resume: Notify,
    pause_after_commit: bool,
}

impl StateRead for CommitState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for CommitState {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let commits_result = matches!(
                &mutation,
                StateMutation::CompareSet { value, .. }
                    if value.value.as_map().and_then(|map| map.get("state"))
                        == Some(&Value::from("committed"))
            );
            if commits_result {
                self.entered.store(true, Ordering::Release);
                if self.pause_after_commit {
                    let commit = self.inner.mutate(path, mutation).await?;
                    self.resume.notified().await;
                    Ok(commit)
                } else {
                    self.resume.notified().await;
                    self.inner.mutate(path, mutation).await
                }
            } else {
                self.inner.mutate(path, mutation).await
            }
        })
    }
}

#[tokio::test]
async fn result_is_fixed_before_idempotency_commit_finishes() -> anyhow::Result<()> {
    for mode in [OutputMode::Unary, OutputMode::Stream, OutputMode::SinkOnly] {
        for pause_after_commit in [false, true] {
            for fail in [false, true] {
                let state = Arc::new(CommitState {
                    inner: InMemoryBackend::new(),
                    entered: AtomicBool::new(false),
                    resume: Notify::new(),
                    pause_after_commit,
                });
                let boot = Arc::new(Bootstrap::from_kernel(Kernel::with_backends(
                    Backend::new()
                        .with_read(state.clone())
                        .with_write(state.clone()),
                    FactSink::in_memory().0,
                )));
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
                let fixture = Fixture::with_boot(
                    boot,
                    driver,
                    Purity::Effectful,
                    GatewayLimitProfile::default(),
                )
                .await?;
                let request =
                    submission()
                        .with_requested_output(mode)
                        .with_options(SubmitOptions {
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
                        } else if state.entered.load(Ordering::Acquire) {
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
                state.resume.notify_one();
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
                    idempotency_key: Some("driver-failure".into()),
                    deadline_ms: Some(u64::try_from(now_millis().saturating_add(60_000))?),
                    ..SubmitOptions::default()
                });
            let (_, first) = fixture.complete(request.clone()).await?;
            ensure!(first.output.outcome == Outcome::Fail(failure.clone()));
            ensure!(first.output.taint.has_protected());
            let entry = fixture.gateway.requests.inner.lock().entries
                [&first.accepted.submission_id]
                .clone();
            ensure!(entry.state == GatewayRequestState::Failed);
            ensure!(
                fixture
                    .gateway
                    .boot
                    .kernel
                    .processes
                    .status(entry.request_process)
                    == Some(ProcessStatus::Cancelled)
            );
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
