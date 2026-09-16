//! Atomic accounting over the hosted process tree.

use super::{ProcessTable, current_cleanup, current_finalizer};
use xolotl_types::{BudgetSpec, ProcessId};

impl ProcessTable {
    /// Mutate a process budget state under the table lock.
    #[cfg(test)]
    pub(crate) fn budget_mut<R>(
        &self,
        id: ProcessId,
        f: impl FnOnce(&mut xolotl_types::BudgetState) -> R,
    ) -> Option<R> {
        self.inner
            .state
            .write()
            .procs
            .get_mut(&id)
            .map(|entry| f(entry.scope.budget_mut()))
    }

    /// Set limits on the aggregate cost of this process and its descendants.
    #[must_use]
    pub fn set_budget_spec(&self, id: ProcessId, spec: BudgetSpec) -> bool {
        let mut inner = self.inner.state.write();
        let Some(entry) = inner.procs.get_mut(&id) else {
            return false;
        };
        entry.scope.set_budget_spec(spec);
        true
    }

    /// Pre-debit the owner and each ancestor atomically, including free calls.
    /// Finalizer admission uses this table's trusted task context. Completed
    /// ancestors retain their limits for already admitted descendants.
    pub(crate) fn reserve(
        &self,
        id: ProcessId,
        est_micro_usd: u64,
        est_tokens: u64,
    ) -> Result<(), String> {
        let finalizer = current_finalizer(self) == Some(id);
        let cleanup = current_cleanup(self) == Some(id);
        let mut inner = self.inner.state.write();
        let mut current = Some(id);
        let mut reserved = 0;
        let result = loop {
            let Some(account) = current else {
                break Ok(());
            };
            if reserved >= inner.procs.len() {
                break Err("process_unavailable".into());
            }
            let Some(entry) = inner.procs.get_mut(&account) else {
                break Err("process_unavailable".into());
            };
            let result = if reserved > 0 {
                entry.scope.reserve_descendant(est_micro_usd, est_tokens)
            } else if finalizer {
                entry.scope.reserve_finalizer(est_micro_usd, est_tokens)
            } else if cleanup {
                entry.scope.reserve_cleanup(est_micro_usd, est_tokens)
            } else {
                entry.scope.reserve(est_micro_usd, est_tokens)
            };
            if let Err(error) = result {
                break Err(error);
            }
            reserved += 1;
            current = entry.parent;
        };

        if result.is_err() {
            // Parent links are stable while retained. Walk only the accounts
            // successfully debited above, requiring no per-call allocation.
            let mut current = Some(id);
            for _ in 0..reserved {
                let Some(entry) = current.and_then(|id| inner.procs.get_mut(&id)) else {
                    break;
                };
                entry.scope.settle(est_micro_usd, 0, est_tokens, 0);
                current = entry.parent;
            }
        }
        result
    }

    /// Settle the owner and the same retained ancestor accounts exactly once.
    pub(crate) fn settle(
        &self,
        id: ProcessId,
        reserved_micro_usd: u64,
        actual_micro_usd: u64,
        reserved_tokens: u64,
        actual_tokens: u64,
    ) {
        let mut inner = self.inner.state.write();
        let mut current = Some(id);
        for _ in 0..inner.procs.len() {
            let Some(account) = current else {
                break;
            };
            let Some(entry) = inner.procs.get_mut(&account) else {
                break;
            };
            entry.scope.settle(
                reserved_micro_usd,
                actual_micro_usd,
                reserved_tokens,
                actual_tokens,
            );
            current = entry.parent;
            inner.queue_reap_if_eligible(account);
        }
    }
}

#[cfg(test)]
mod tests;
