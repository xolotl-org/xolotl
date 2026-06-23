//! Three-queue cooperative scheduler.
//!
//! Processes share the runtime and are dispatched by priority across three
//! queues. This is **soft** priority without a hard real-time guarantee.

use serde::{Deserialize, Serialize};

/// Scheduling queue for a unit of executor work.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Queue {
    /// Fact flush, finalizers, recovery — above business work.
    System,
    /// A conversational step the user is waiting on — FIFO, never starved by
    /// background work.
    Interactive,
    /// Long-running tasks, reactions, compaction, consolidation — fair
    /// scheduling, budget-bounded.
    #[default]
    Background,
}

impl Queue {
    /// Lower number = higher priority (System first, Background last).
    pub fn priority(self) -> u8 {
        match self {
            Queue::System => 0,
            Queue::Interactive => 1,
            Queue::Background => 2,
        }
    }
}

/// Picks the highest-priority non-empty queue. The kernel maps `Queue` to a
/// tokio task priority; this type just encodes the policy so it is testable and
/// shared. `interactive` is FIFO; `background` is round-robin fair.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scheduler;

impl Scheduler {
    /// Given the set of queues with pending work, return the one to serve next.
    pub fn pick(self, pending: &[Queue]) -> Option<Queue> {
        pending.iter().copied().min_by_key(|q| q.priority())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn system_outranks_interactive_outranks_background() -> anyhow::Result<()> {
        let s = Scheduler;
        ensure!(
            s.pick(&[Queue::Background, Queue::Interactive]) == Some(Queue::Interactive),
            "interactive should outrank background"
        );
        ensure!(
            s.pick(&[Queue::Background, Queue::Interactive, Queue::System]) == Some(Queue::System),
            "system should outrank all other queues"
        );
        ensure!(
            s.pick(&[Queue::Background]) == Some(Queue::Background),
            "background should be picked when it is the only pending queue"
        );
        ensure!(s.pick(&[]).is_none(), "empty queue set should not schedule");
        Ok(())
    }
}
