//! Per-store completion boundary for State and Source blocking jobs.

use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;
use xolotl_kernel::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};

pub(crate) struct TrackedBlockingSpawner {
    inner: Arc<dyn BlockingSpawner>,
    jobs: Arc<InFlightJobs>,
}

#[derive(Default)]
struct InFlightJobs {
    active: AtomicUsize,
    changed: Notify,
}

struct ActiveJob(Arc<InFlightJobs>);

impl Drop for ActiveJob {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

struct AcceptedJob {
    // Fields drop in declaration order: release a discarded job's database
    // captures before ActiveJob announces that the store is idle.
    job: Option<BlockingJob>,
    _active: ActiveJob,
}

impl AcceptedJob {
    fn run(mut self) {
        if let Some(job) = self.job.take() {
            job();
        }
    }
}

impl InFlightJobs {
    async fn wait_idle(self: Arc<Self>) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}

impl TrackedBlockingSpawner {
    pub(crate) fn new(inner: Arc<dyn BlockingSpawner>) -> Self {
        Self {
            inner,
            jobs: Arc::default(),
        }
    }

    pub(crate) fn wait_idle(&self) -> impl Future<Output = ()> + Send + 'static {
        Arc::clone(&self.jobs).wait_idle()
    }
}

impl BlockingSpawner for TrackedBlockingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        self.jobs.active.fetch_add(1, Ordering::AcqRel);
        let accepted = AcceptedJob {
            job: Some(job),
            _active: ActiveJob(Arc::clone(&self.jobs)),
        };
        self.inner.spawn(Box::new(move || accepted.run()))
    }
}
