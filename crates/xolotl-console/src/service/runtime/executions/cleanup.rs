//! Retry only the volatile cleanup obligations owned by this Console directory.

use super::*;
use futures_util::{StreamExt as _, stream};
use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Weak, atomic::Ordering},
    task::{Context, Poll},
};
use xolotl_kernel::CleanupProgress;
use xolotl_types::ProcessId;

/// Own cancellation as well as polling: timeout and shutdown drop this future
/// outside any poll boundary, including a backend's native captures.
struct CleanupAttempt<F> {
    process: ProcessId,
    future: Option<Pin<Box<F>>>,
}

impl<F> CleanupAttempt<F> {
    fn new(process: ProcessId, future: F) -> Self {
        Self {
            process,
            future: Some(Box::pin(future)),
        }
    }
}

impl<F: Future> Future for CleanupAttempt<F> {
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let attempt = self.get_mut();
        let Some(future) = attempt.future.as_mut() else {
            return Poll::Ready(Err(()));
        };
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(result) => result.map(Ok),
            Err(payload) => {
                report_panic(attempt.process, "poll", payload);
                Poll::Ready(Err(()))
            }
        }
    }
}

impl<F> Drop for CleanupAttempt<F> {
    fn drop(&mut self) {
        if let Some(future) = self.future.take()
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(future)))
        {
            report_panic(self.process, "drop", payload);
        }
    }
}

fn report_panic(process: ProcessId, phase: &str, payload: Box<dyn std::any::Any + Send>) {
    tracing::warn!(
        process = process.get(),
        phase,
        "Console execution cleanup panicked; custody remains pending"
    );
    // A panic payload can itself own a destructor. Isolate its disposal too.
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        let _payload = std::mem::ManuallyDrop::new(secondary);
    }
}

struct Running(Weak<crate::runtime::executions::ExecutionRegistry>);

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(registry) = self.0.upgrade() {
            registry.release_cleanup_worker();
        }
    }
}

/// Start on the first volatile submission, including when no transport is mounted.
/// Idle supervision retains neither the Console nor the kernel. Capturing the
/// running guard before spawning also covers an unpolled task being dropped.
pub(super) fn start(state: &Arc<ConsoleState>) -> Result<(), ConsoleError> {
    if !state.executions.claim_cleanup_worker() {
        return Ok(());
    }
    let running = Running(Arc::downgrade(&state.executions));
    let weak = Arc::downgrade(state);
    let _detached = state
        .boot
        .kernel()
        .host_runtime()
        .spawn(Box::pin(async move {
            let _running = running;
            let minimum = Duration::from_millis(25);
            let mut delay = minimum;
            loop {
                // Do not retain a service across the idle interval or wait forever
                // for a backend. A failed pass keeps the original records pinned.
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let changed = state.executions.cleanup_notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if state.executions.closed() {
                    return;
                }
                let progress = tokio::select! {
                    biased;
                    () = state.executions.wait_closed() => return,
                    progress = pass_inner(&state, false) => progress,
                };
                let runtime = state.boot.kernel().host_runtime().clone();
                drop(state);
                delay = if progress > 0 {
                    minimum
                } else {
                    (delay * 2).min(Duration::from_secs(1))
                };
                let Some(wake_at) = runtime.deadline_after(delay) else {
                    return;
                };
                tokio::select! {
                    () = changed => {},
                    _ = runtime.sleep_until(wake_at) => {},
                }
            }
        }))
        .map_err(|error| {
            ConsoleError::Operation(format!("cleanup worker could not start: {error}"))
        })?;
    Ok(())
}

/// One bounded pass, including contention with another pass. Candidates are
/// already limited by execution capacity. Poll them together so one stalled
/// backend cannot starve later processes; no body or admission is repeated.
pub(super) async fn pass(state: &Arc<ConsoleState>) -> usize {
    pass_inner(state, true).await
}

async fn pass_inner(state: &Arc<ConsoleState>, allow_closed: bool) -> usize {
    let completed = std::sync::atomic::AtomicUsize::new(0);
    let timeout = Duration::from_millis(state.runtime.config.executions.cleanup_timeout_ms);
    let work = async {
        let _guard = state.executions.cleanup.lock.lock().await;
        if !allow_closed && state.executions.closed() {
            return;
        }
        state.executions.maintain_volatile();
        stream::iter(state.executions.pending_cleanup())
            .for_each_concurrent(None, |candidate| {
                let completed = &completed;
                async move {
                    let attempt = CleanupAttempt::new(
                        candidate.process,
                        state.boot.resume_cleanup(&candidate.ticket),
                    )
                    .await;
                    match attempt {
                        Ok(Ok(CleanupProgress::Completed)) => {
                            if state.executions.acknowledge_cleanup(&candidate) {
                                completed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Ok(Ok(CleanupProgress::NotRequested)) => {}
                        Ok(Err(error)) => {
                            tracing::debug!(process = candidate.process.get(), %error,
                                "Console execution cleanup remains pending");
                        }
                        Err(()) => {}
                    }
                }
            })
            .await;
    };
    if let Some(deadline) = state.boot.kernel().host_runtime().deadline_after(timeout) {
        let _attempt =
            crate::host_time::timeout_at(state.boot.kernel().host_runtime(), deadline, work).await;
    }
    completed.load(Ordering::Relaxed)
}

/// Admission and attempts are already closed. Persistent backend failure must
/// not turn shutdown into an unbounded wait or silently free retained custody.
pub(in crate::service) async fn shutdown(state: &Arc<ConsoleState>) {
    state.executions.wait_cleanup_worker().await;
    pass(state).await;
}
