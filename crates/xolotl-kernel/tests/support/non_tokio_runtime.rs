//! A minimal thread executor and manual clock for hosted Kernel integration tests.

use anyhow::ensure;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll, Wake, Waker},
    thread,
    time::{Duration, Instant},
};
use xolotl_kernel::host::{
    AbortTask, BlockingJob, BlockingSpawnError, BlockingSpawner, HostClock, TaskSpawnError,
    TaskSpawner,
};

/// A bounded synchronous-work port for tests without an ambient Tokio runtime.
#[derive(Default)]
pub(super) struct ThreadBlockingSpawner {
    in_flight: Arc<AtomicUsize>,
}

struct BlockingPermit(Arc<AtomicUsize>);

impl Drop for BlockingPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl BlockingSpawner for ThreadBlockingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |running| {
                (running < 16).then_some(running + 1)
            })
            .map_err(|_full| BlockingSpawnError::AtCapacity)?;
        let in_flight = Arc::clone(&self.in_flight);
        if thread::Builder::new()
            .spawn(move || {
                let _permit = BlockingPermit(in_flight);
                job();
            })
            .is_err()
        {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(BlockingSpawnError::Unavailable);
        }
        Ok(())
    }
}

// Deliberately run every test on an ordinary thread. Tokio's Notify, oneshot,
// and select! are executor-neutral, but Tokio's clock and spawn adapter are not.
struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

pub(super) fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
    let mut future = std::pin::pin!(future);
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = TaskContext::from_waker(&wake);
    let ceiling = Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return Ok(output);
        }
        let now = Instant::now();
        ensure!(now < ceiling, "non-Tokio future stopped making progress");
        thread::park_timeout(ceiling.saturating_duration_since(now));
    }
}

pub(super) fn wait_until(mut ready: impl FnMut() -> bool) -> anyhow::Result<()> {
    let ceiling = Instant::now() + Duration::from_secs(5);
    while !ready() {
        ensure!(
            Instant::now() < ceiling,
            "non-Tokio worker stopped making progress"
        );
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct ManualClock(Arc<ClockCore>);

struct ClockCore {
    state: Mutex<ClockState>,
    next_waiter: AtomicU64,
}

struct ClockState {
    origin: Instant,
    wall_millis: i64,
    now: Instant,
    waiters: HashMap<u64, Waker>,
}

impl ManualClock {
    pub(super) fn new() -> Self {
        Self::with_wall_millis(1_000_000)
    }

    pub(super) fn with_wall_millis(wall_millis: i64) -> Self {
        let now = Instant::now();
        Self(Arc::new(ClockCore {
            state: Mutex::new(ClockState {
                origin: now,
                wall_millis,
                now,
                waiters: HashMap::new(),
            }),
            next_waiter: AtomicU64::new(1),
        }))
    }

    pub(super) fn advance(&self, duration: Duration) {
        let wake = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.now += duration;
            state
                .waiters
                .drain()
                .map(|(_, wake)| wake)
                .collect::<Vec<_>>()
        };
        for waiter in wake {
            waiter.wake();
        }
    }

    pub(super) fn waiting(&self) -> usize {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .waiters
            .len()
    }
}

struct ManualSleep {
    clock: ManualClock,
    deadline: Instant,
    id: u64,
}

impl Future for ManualSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<()> {
        let mut state = self
            .clock
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.now >= self.deadline {
            state.waiters.remove(&self.id);
            Poll::Ready(())
        } else {
            state.waiters.insert(self.id, context.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for ManualSleep {
    fn drop(&mut self) {
        self.clock
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .waiters
            .remove(&self.id);
    }
}

impl HostClock for ManualClock {
    fn monotonic_now(&self) -> Instant {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .now
    }

    fn unix_millis(&self) -> i64 {
        let state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.wall_millis
            + i64::try_from(state.now.duration_since(state.origin).as_millis()).unwrap_or(i64::MAX)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(ManualSleep {
            clock: self.clone(),
            deadline,
            id: self.0.next_waiter.fetch_add(1, Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Default)]
pub(super) struct ThreadTasks {
    pub(super) spawned: Arc<AtomicUsize>,
    pub(super) aborted: Arc<AtomicUsize>,
    pub(super) reject: Arc<AtomicBool>,
}

struct ThreadTask {
    cancelled: AtomicBool,
    thread: Mutex<Option<thread::Thread>>,
    tasks: ThreadTasks,
}

impl AbortTask for ThreadTask {
    fn abort(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.tasks.aborted.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(worker) = self
            .thread
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            worker.unpark();
        }
    }
}

impl TaskSpawner for ThreadTasks {
    fn spawn(
        &self,
        mut future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        if self.reject.load(Ordering::SeqCst) {
            return Err(TaskSpawnError::Unavailable);
        }
        let task = Arc::new(ThreadTask {
            cancelled: AtomicBool::new(false),
            thread: Mutex::new(None),
            tasks: self.clone(),
        });
        let worker = task.clone();
        let thread = thread::Builder::new()
            .name("xolotl-test-host".into())
            .spawn(move || {
                *worker
                    .thread
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(thread::current());
                let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
                let mut context = TaskContext::from_waker(&wake);
                loop {
                    if worker.cancelled.load(Ordering::Acquire)
                        || future.as_mut().poll(&mut context).is_ready()
                    {
                        break;
                    }
                    thread::park();
                }
            })
            .map_err(|_error| TaskSpawnError::Unavailable)?;
        self.spawned.fetch_add(1, Ordering::SeqCst);
        drop(thread);
        Ok(task)
    }
}
