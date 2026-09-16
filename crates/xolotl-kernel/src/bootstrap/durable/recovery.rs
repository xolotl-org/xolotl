//! Bounded directory admission, independent of gateway startup and task completion.

use super::*;
use crate::executor::durable::{CheckpointInfo, CheckpointQuery};
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod admission;
use admission::{AdmissionFailure, RecoveryWork};

/// Recovery admission shared by every session created from this kernel.
#[derive(Clone, Copy, Debug)]
pub struct DurableRecoveryConfig {
    /// Maximum metadata entries inspected by one advance, without loading their programs.
    pub page_size: NonZeroUsize,
    /// Shared limit covering loading, execution, lifecycle cleanup and capture destruction.
    pub max_in_flight: NonZeroUsize,
    /// Explicitly reap at most this many finalized leaves per advance. Zero retains
    /// process history; bounded hosts may instead run their own retention policy.
    pub reap_batch: usize,
}

impl Default for DurableRecoveryConfig {
    fn default() -> Self {
        Self {
            page_size: NonZeroUsize::MIN.saturating_add(63),
            max_in_flight: NonZeroUsize::MIN.saturating_add(15),
            reap_batch: 0,
        }
    }
}

/// One bounded admission step. Counts do not imply that scheduled work has finished.
#[derive(Clone, Copy, Debug, Default)]
pub struct DurableRecoveryReport {
    /// Programs scheduled for execution or terminal cleanup.
    pub resumed: usize,
    /// Records held for reconciliation, repair, changed authority or unavailable imports.
    pub quarantined: usize,
    /// Records already owned by another task or removed since enumeration.
    pub skipped: usize,
    /// A candidate or a competing advance is waiting for admission capacity.
    pub deferred: usize,
    /// This session has examined its complete key range. Running tasks may remain.
    pub complete: bool,
}

pub(crate) struct RecoveryControl {
    config: DurableRecoveryConfig,
    active: AtomicUsize,
    advance: tokio::sync::Mutex<()>,
}

impl Default for RecoveryControl {
    fn default() -> Self {
        Self::new(DurableRecoveryConfig::default())
    }
}

impl RecoveryControl {
    pub(crate) fn new(config: DurableRecoveryConfig) -> Self {
        Self {
            config,
            active: AtomicUsize::new(0),
            advance: tokio::sync::Mutex::new(()),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<RecoveryPermit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.config.max_in_flight.get()).then(|| active + 1)
            })
            .ok()?;
        Some(RecoveryPermit(self.clone()))
    }
}

struct RecoveryPermit(Arc<RecoveryControl>);

impl Drop for RecoveryPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Advanceable scan of a fixed checkpoint key range. The session buffers metadata
/// only; each loaded record immediately transfers to a capacity-owned task.
/// Dropping a session stops admission but leaves its managed processes running.
/// Create a new session to retry quarantined rows or observe late insertions.
pub struct DurableRecovery {
    boot: Arc<Bootstrap>,
    steps: crate::StepModule,
    through: Option<ProcessId>,
    after: Option<ProcessId>,
    entries: VecDeque<CheckpointInfo>,
    last_page: bool,
}

impl Bootstrap {
    /// Start a metadata-only recovery scan after installing authority and providers.
    /// Reserve checkpoint identifiers before admitting fresh application processes.
    pub fn checkpoint_recovery(self: &Arc<Self>) -> Result<DurableRecovery, Failure> {
        let through = self
            .kernel
            .checkpoint_store
            .as_ref()
            .map(|store| store.high_water())
            .transpose()?
            .flatten();
        if let Some(through) = through {
            self.kernel.processes.reserve_ids_through(through);
        }
        Ok(DurableRecovery {
            boot: self.clone(),
            steps: crate::StepModule::default(),
            through,
            after: None,
            entries: VecDeque::new(),
            last_page: through.is_none(),
        })
    }

    /// Perform one bounded recovery advance. For a backlog, retain a
    /// [`DurableRecovery`] session and advance it from the host's background loop.
    pub async fn resume_checkpointed_processes(
        self: &Arc<Self>,
    ) -> Result<DurableRecoveryReport, Failure> {
        self.checkpoint_recovery()?.advance().await
    }
}

impl DurableRecovery {
    /// Reattach portable loaders under their persisted names and revisions.
    /// The same immutable namespace is retained from admission through execution
    /// and cancellation. Missing or changed bindings hold a journal unchanged.
    pub fn with_steps(mut self, steps: crate::StepModule) -> Self {
        self.steps = steps;
        self
    }

    /// Whether the captured key range has been examined, independently of task completion.
    pub fn is_complete(&self) -> bool {
        self.last_page && self.entries.is_empty()
    }

    /// Admit at most one metadata page without waiting for executing programs.
    /// Capacity exhaustion retains the current candidate for the next advance.
    /// Store errors leave this session retryable; held records require a new sweep.
    pub async fn advance(&mut self) -> Result<DurableRecoveryReport, Failure> {
        let mut report = DurableRecoveryReport::default();
        if self.is_complete() {
            report.complete = true;
            return Ok(report);
        }
        tokio::runtime::Handle::try_current().map_err(recovery_error)?;
        tokio::task::yield_now().await;
        let boot = self.boot.clone();
        let kernel = &boot.kernel;
        let control = kernel
            .checkpoint_recovery
            .as_ref()
            .ok_or_else(|| recovery_error("checkpoint recovery is not configured"))?
            .clone();
        let Ok(_advance) = control.advance.try_lock() else {
            report.deferred = 1;
            return Ok(report);
        };
        kernel.processes.reap_finalized(control.config.reap_batch);
        let store = kernel
            .checkpoint_store
            .as_ref()
            .ok_or_else(|| recovery_error("checkpoint store is unavailable"))?;
        if self.entries.is_empty() {
            let through = self
                .through
                .ok_or_else(|| recovery_error("missing recovery bound"))?;
            let entries = store.scan(CheckpointQuery {
                after: self.after,
                through,
                limit: control.config.page_size,
            })?;
            if entries.len() > control.config.page_size.get() {
                return Err(recovery_error("checkpoint catalog exceeded its page limit"));
            }
            let mut previous = self.after;
            for entry in &entries {
                if previous.is_some_and(|previous| entry.process <= previous)
                    || entry.process > through
                {
                    return Err(recovery_error(
                        "checkpoint catalog is not strictly ordered within its bounds",
                    ));
                }
                previous = Some(entry.process);
            }
            self.last_page = entries.len() < control.config.page_size.get();
            self.entries = entries.into();
        }
        while let Some(entry) = self.entries.front().copied() {
            let process = entry.process;
            if kernel.processes.has_task(process) {
                self.consume();
                report.skipped += 1;
                continue;
            }
            if !kernel.processes.exists(process)
                && kernel
                    .processes
                    .capacity()
                    .is_some_and(|limit| kernel.processes.len() >= limit.get())
            {
                report.deferred = 1;
                break;
            }
            let Some(permit) = control.try_acquire() else {
                report.deferred = 1;
                break;
            };
            let Some(mut journal) = store.try_acquire(process)? else {
                self.consume();
                report.skipped += 1;
                continue;
            };
            let saved = match journal.load(kernel.execution_config.max_checkpoint_bytes) {
                Ok(Some(saved)) => saved,
                Ok(None) => {
                    self.consume();
                    report.skipped += 1;
                    continue;
                }
                Err(error) => {
                    self.hold(&mut report, process, error);
                    continue;
                }
            };
            let work = match RecoveryWork::prepare(
                self.boot.clone(),
                process,
                saved,
                journal,
                permit,
                self.steps.clone(),
            ) {
                Ok(work) => work,
                Err(AdmissionFailure::Capacity) => {
                    report.deferred = 1;
                    break;
                }
                Err(AdmissionFailure::Rejected(error)) => {
                    self.hold(&mut report, process, error);
                    continue;
                }
            };
            work.spawn()
                .map_err(|error| recovery_error(task_attachment_error(process, error)))?;
            self.consume();
            report.resumed += 1;
        }
        report.complete = self.is_complete();
        Ok(report)
    }

    fn consume(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            self.after = Some(entry.process);
        }
    }

    fn hold(&mut self, report: &mut DurableRecoveryReport, process: ProcessId, error: Failure) {
        tracing::warn!(process = process.get(), %error, "checkpoint recovery held");
        self.consume();
        report.quarantined += 1;
    }
}
