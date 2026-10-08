//! Volatile cleanup custody remains in the directory after native attempt exit.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_types::ProcessId;

/// One private maintenance worker for live cleanup custody.
#[derive(Default)]
pub(crate) struct Maintenance {
    pub running: AtomicBool,
    pub lock: tokio::sync::Mutex<()>,
}

/// An internal directory entry to reconcile against its original kernel process.
/// This is a routing identity, not evidence that cleanup has completed.
#[derive(Clone)]
pub(crate) struct PendingCleanup {
    pub sequence: u64,
    pub process: ProcessId,
    pub ticket: CleanupTicket,
}

impl ExecutionRegistry {
    /// Serialize worker admission with closing the directory. Shutdown must see
    /// every admitted worker, even before its spawn has been polled.
    pub(crate) fn claim_cleanup_worker(&self) -> bool {
        let records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        !records.closed && !self.cleanup.running.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn release_cleanup_worker(&self) {
        self.cleanup.running.store(false, Ordering::Release);
        self.changed.notify_waiters();
    }

    /// The notification can wait without keeping the registry or kernel alive.
    pub(crate) fn cleanup_notified(&self) -> tokio::sync::futures::OwnedNotified {
        self.changed.clone().notified_owned()
    }

    pub(crate) async fn wait_closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed() {
                return;
            }
            changed.await;
        }
    }

    /// Closing prevents a later worker from claiming admission. The last guard
    /// wakes all concurrent shutdown callers after its async captures are gone.
    pub(crate) async fn wait_cleanup_worker(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.cleanup.running.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    /// Count all released volatile custody, including an interrupted admission
    /// whose ticket could not be bound. Shutdown never hides that obligation.
    pub(crate) fn pending_volatile_cleanup_count(&self) -> usize {
        self.records()
            .entries
            .values()
            .filter(|record| {
                matches!(&record.phase, Phase::Finished { completion, .. } if !completion.cleanup_complete)
            })
            .count()
    }

    /// Enumerate only released volatile attempts. Expired results remain hidden,
    /// but their custody and capacity cannot be discarded before confirmation.
    pub(crate) fn pending_cleanup(&self) -> Vec<PendingCleanup> {
        self.records()
            .entries
            .iter()
            .filter_map(|(sequence, record)| {
                let Phase::Finished { completion, .. } = &record.phase else {
                    return None;
                };
                if completion.cleanup_complete {
                    return None;
                }
                let ticket = record.cleanup_ticket.as_ref()?;
                Some(PendingCleanup {
                    sequence: *sequence,
                    process: ticket.process(),
                    ticket: ticket.clone(),
                })
            })
            .collect()
    }

    /// Confirm a reconciled lifecycle without replacing its body or renewing
    /// retention. Call only after the kernel confirms cleanup for this process.
    /// A stale acknowledgement never changes another record or recreates one.
    pub(crate) fn acknowledge_cleanup(&self, candidate: &PendingCleanup) -> bool {
        let Some(captured) = self.capture_finalization(candidate.sequence) else {
            return false;
        };
        // Do not perform the ordinary access refresh here: this acknowledgement
        // owns the transition and reports whether it changed the reserved slot.
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(record) = records.entries.get_mut(&candidate.sequence) else {
            return false;
        };
        if record.reference.process_id != candidate.process.get().to_string()
            || record
                .cleanup_ticket
                .as_ref()
                .is_none_or(|ticket| ticket.process() != candidate.process)
        {
            return false;
        }
        let Phase::Finished { completion, .. } = &mut record.phase else {
            return false;
        };
        if completion.cleanup_complete {
            return false;
        }
        let previous = completion.unresolved_operations.clone();
        let newly_projected = matches!(
            completion.finalization,
            finalization::FinalizationProjection::Pending
        ) && !matches!(
            captured.projection,
            finalization::FinalizationProjection::Pending
        );
        completion.retain_finalization(&captured);
        let changed =
            newly_projected || previous != completion.unresolved_operations || captured.complete;
        if let Some(output) = &mut record.output {
            output.update_finalization(completion);
        }
        completion.cleanup_complete = captured.complete;
        if captured.complete {
            record.cleanup_ticket = None;
        }
        drop(records);
        if changed {
            self.changed.notify_waiters();
        }
        captured.complete
    }
}

#[cfg(test)]
mod tests;
