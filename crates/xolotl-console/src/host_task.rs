//! A joinable Console task built on the Kernel's host scheduler.
//!
//! The host's abort handle deliberately does not own completion. Keep the
//! completion sender inside the scheduled future so even a task discarded
//! before its first poll wakes a waiter after its captures are released.

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::sync::oneshot;
use xolotl_kernel::host::{AbortTask, HostRuntime, TaskSpawnError};

/// The result of a task after it has been accepted by the host scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HostTaskError {
    #[error("host task was cancelled")]
    Cancelled,
    #[error("host task panicked")]
    Panicked,
}

/// A task whose lifetime belongs to the host scheduler, not to this handle.
/// Dropping the handle detaches the task; call `abort` to request cancellation.
pub(crate) struct HostTask<T> {
    abort: Arc<dyn AbortTask>,
    result: oneshot::Receiver<Result<T, HostTaskError>>,
    #[cfg(test)]
    finished: Arc<AtomicBool>,
}

impl<T> HostTask<T> {
    pub(crate) fn abort(&self) {
        self.abort.abort();
    }

    #[cfg(test)]
    pub(crate) fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

impl<T> Future for HostTask<T> {
    type Output = Result<T, HostTaskError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().result)
            .poll(context)
            .map(|result| result.unwrap_or(Err(HostTaskError::Cancelled)))
    }
}

/// Schedule a joinable task. A synchronous scheduling failure drops `future`
/// and returns the host error. Successful scheduling retains the task when
/// its handle is dropped.
pub(crate) fn spawn<F>(
    runtime: &HostRuntime,
    future: F,
) -> Result<HostTask<F::Output>, TaskSpawnError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (sender, result) = oneshot::channel();
    #[cfg(test)]
    let finished = Arc::new(AtomicBool::new(false));
    let body = TaskBody {
        future: Some(Box::pin(future)),
        sender: Some(sender),
        #[cfg(test)]
        finished: finished.clone(),
    };
    let abort = runtime.spawn(Box::pin(body))?;
    Ok(HostTask {
        abort,
        result,
        #[cfg(test)]
        finished,
    })
}

struct TaskBody<F: Future> {
    future: Option<Pin<Box<F>>>,
    sender: Option<oneshot::Sender<Result<F::Output, HostTaskError>>>,
    #[cfg(test)]
    finished: Arc<AtomicBool>,
}

impl<F: Future> TaskBody<F> {
    fn finish(&mut self, outcome: Result<F::Output, HostTaskError>) {
        // Completion means the future and its captures have actually left the
        // scheduler. A destructor panic is still a task failure, not success.
        let outcome = match catch_unwind(AssertUnwindSafe(|| drop(self.future.take()))) {
            Ok(()) => outcome,
            Err(payload) => {
                discard_panic(payload);
                Err(HostTaskError::Panicked)
            }
        };
        #[cfg(test)]
        self.finished.store(true, Ordering::Release);
        if let Some(sender) = self.sender.take()
            && let Err(unobserved) = sender.send(outcome)
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(unobserved)))
        {
            // A detached task's result may own a panicking destructor. The
            // task has already finished, and no observer remains to receive it.
            discard_panic(payload);
        }
    }
}

impl<F: Future> Future for TaskBody<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let body = self.get_mut();
        let Some(future) = body.future.as_mut() else {
            return Poll::Ready(());
        };
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => {
                body.finish(Ok(value));
                Poll::Ready(())
            }
            Err(payload) => {
                discard_panic(payload);
                body.finish(Err(HostTaskError::Panicked));
                Poll::Ready(())
            }
        }
    }
}

impl<F: Future> Drop for TaskBody<F> {
    fn drop(&mut self) {
        if self.sender.is_some() {
            self.finish(Err(HostTaskError::Cancelled));
        }
    }
}

fn discard_panic(payload: Box<dyn Any + Send>) {
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        // A panic payload can have its own panicking destructor. Do not let it
        // prevent completion or turn cancellation into a double panic.
        let _secondary = std::mem::ManuallyDrop::new(secondary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::{
        sync::{Mutex, atomic::AtomicUsize},
        time::Instant,
    };
    use xolotl_kernel::host::{HostClock, TaskSpawner};

    type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

    #[derive(Default)]
    struct ManualTasks {
        work: Arc<Mutex<Option<Work>>>,
    }

    impl ManualTasks {
        fn poll_once(&self) {
            let Some(mut work) = self
                .work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            else {
                return;
            };
            let mut context = Context::from_waker(std::task::Waker::noop());
            if work.as_mut().poll(&mut context).is_pending() {
                *self
                    .work
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(work);
            }
        }

        fn discard(&self) {
            let work = self
                .work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            drop(work);
        }
    }

    struct ManualAbort(Arc<Mutex<Option<Work>>>);

    impl AbortTask for ManualAbort {
        fn abort(&self) {
            let work = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            drop(work);
        }
    }

    impl TaskSpawner for ManualTasks {
        fn spawn(&self, future: Work) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            *self
                .work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(future);
            Ok(Arc::new(ManualAbort(self.work.clone())))
        }
    }

    struct RejectTasks;

    impl TaskSpawner for RejectTasks {
        fn spawn(&self, _future: Work) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    struct TestClock;

    impl HostClock for TestClock {
        fn monotonic_now(&self) -> Instant {
            Instant::now()
        }

        fn unix_millis(&self) -> i64 {
            0
        }

        fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }

    fn runtime(tasks: Arc<dyn TaskSpawner>) -> HostRuntime {
        HostRuntime::new(
            Arc::new(TestClock),
            tasks,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        )
    }

    fn join<T>(task: &mut HostTask<T>) -> Poll<Result<T, HostTaskError>> {
        let mut context = Context::from_waker(std::task::Waker::noop());
        Pin::new(task).poll(&mut context)
    }

    #[test]
    fn completes_and_joins_without_a_tokio_runtime() -> anyhow::Result<()> {
        let tasks = Arc::new(ManualTasks::default());
        let mut task = spawn(&runtime(tasks.clone()), async { 7 })?;
        ensure!(!task.is_finished());
        ensure!(join(&mut task).is_pending());
        tasks.poll_once();
        ensure!(task.is_finished());
        ensure!(join(&mut task) == Poll::Ready(Ok(7)));
        Ok(())
    }

    #[test]
    fn abort_before_first_poll_drops_captures_and_wakes_joiner() -> anyhow::Result<()> {
        let tasks = Arc::new(ManualTasks::default());
        let dropped = Arc::new(AtomicUsize::new(0));
        struct CountDrop(Arc<AtomicUsize>);
        impl Drop for CountDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let capture = CountDrop(dropped.clone());
        let mut task = spawn(&runtime(tasks), async move {
            let _capture = capture;
            7
        })?;
        task.abort();
        ensure!(dropped.load(Ordering::Relaxed) == 1);
        ensure!(task.is_finished());
        ensure!(join(&mut task) == Poll::Ready(Err(HostTaskError::Cancelled)));
        Ok(())
    }

    #[test]
    fn scheduler_discard_before_poll_reports_cancellation() -> anyhow::Result<()> {
        let tasks = Arc::new(ManualTasks::default());
        let mut task = spawn(&runtime(tasks.clone()), async { 7 })?;
        tasks.discard();
        ensure!(task.is_finished());
        ensure!(join(&mut task) == Poll::Ready(Err(HostTaskError::Cancelled)));
        Ok(())
    }

    #[test]
    fn dropping_handle_detaches_task() -> anyhow::Result<()> {
        let tasks = Arc::new(ManualTasks::default());
        let ran = Arc::new(AtomicBool::new(false));
        let signal = ran.clone();
        let task = spawn(&runtime(tasks.clone()), async move {
            signal.store(true, Ordering::Relaxed);
        })?;
        drop(task);
        tasks.poll_once();
        ensure!(ran.load(Ordering::Relaxed));
        Ok(())
    }

    #[test]
    fn failed_spawn_drops_future() {
        let dropped = Arc::new(AtomicBool::new(false));
        struct MarkDrop(Arc<AtomicBool>);
        impl Drop for MarkDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let capture = MarkDrop(dropped.clone());
        let result = spawn(&runtime(Arc::new(RejectTasks)), async move {
            let _capture = capture;
        });
        assert!(matches!(result, Err(TaskSpawnError::Unavailable)));
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[test]
    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "exercise task panic reporting"
    )]
    fn poll_panic_is_joinable() -> Result<(), TaskSpawnError> {
        let tasks = Arc::new(ManualTasks::default());
        let mut task = spawn(&runtime(tasks.clone()), async {
            panic!("task failure");
        })?;
        tasks.poll_once();
        assert!(task.is_finished());
        assert_eq!(join(&mut task), Poll::Ready(Err(HostTaskError::Panicked)));
        Ok(())
    }

    #[test]
    fn destructor_panic_is_joinable() -> anyhow::Result<()> {
        struct PanickingDrop;
        impl Future for PanickingDrop {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        impl Drop for PanickingDrop {
            #[expect(clippy::panic, reason = "exercise destructor panic reporting")]
            fn drop(&mut self) {
                panic!("destructor failure");
            }
        }

        let tasks = Arc::new(ManualTasks::default());
        let mut task = spawn(&runtime(tasks.clone()), PanickingDrop)?;
        tasks.discard();
        ensure!(task.is_finished());
        ensure!(join(&mut task) == Poll::Ready(Err(HostTaskError::Panicked)));
        Ok(())
    }

    #[test]
    fn detached_result_destructor_cannot_hide_completion() -> anyhow::Result<()> {
        struct PanickingValue;
        impl Drop for PanickingValue {
            #[expect(clippy::panic, reason = "exercise a detached result destructor")]
            fn drop(&mut self) {
                panic!("result destructor failure");
            }
        }

        let tasks = Arc::new(ManualTasks::default());
        let task = spawn(&runtime(tasks.clone()), async { PanickingValue })?;
        let finished = task.finished.clone();
        drop(task);
        tasks.poll_once();
        ensure!(finished.load(Ordering::Acquire));
        Ok(())
    }
}
