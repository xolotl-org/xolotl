//! Three-queue cooperative scheduler (§13.5).
//!
//! The Executor does not start its own thread pool; Processes share the runtime
//! and are dispatched by priority across three queues. This is **soft**
//! priority — no hard real-time guarantee (§25).

use serde::{Deserialize, Serialize};

/// Scheduling queue for a unit of executor work (§13.5).
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

    #[test]
    fn system_outranks_interactive_outranks_background() {
        let s = Scheduler;
        assert_eq!(
            s.pick(&[Queue::Background, Queue::Interactive]),
            Some(Queue::Interactive)
        );
        assert_eq!(
            s.pick(&[Queue::Background, Queue::Interactive, Queue::System]),
            Some(Queue::System)
        );
        assert_eq!(s.pick(&[Queue::Background]), Some(Queue::Background));
        assert_eq!(s.pick(&[]), None);
    }
}
