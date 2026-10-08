//! Platform services for the hosted Kernel.

pub mod async_process;
pub mod blocking;
mod runtime;
pub mod stream;

pub use blocking::{
    BlockingCapacityError, BlockingJob, BlockingSpawnError, BlockingSpawner, BlockingTask,
    BlockingTaskError, DEFAULT_MAX_BLOCKING_JOBS, TokioBlockingSpawner,
};
pub use runtime::{
    AbortTask, ClockDomainError, HostClock, HostDeadline, HostRuntime, TaskSpawnError, TaskSpawner,
    system_now_millis,
};
