use super::*;
use crate::process::{FinalizeStart, ProcessEntry, scope_cleanup, scope_finalizer};
use anyhow::{Context, ensure};
use xolotl_types::{BudgetState, IdentityRef, ProcessStatus};

fn running(table: &ProcessTable, parent: Option<ProcessId>) -> anyhow::Result<ProcessId> {
    let id = table.fresh_id()?;
    let mut entry = ProcessEntry::new(id, parent, IdentityRef::ROOT);
    ensure!(entry.scope.start());
    table.insert(entry);
    Ok(id)
}

fn budget(table: &ProcessTable, id: ProcessId) -> anyhow::Result<BudgetState> {
    table
        .budget_mut(id, |state| state.clone())
        .context("missing account")
}

fn complete(table: &ProcessTable, id: ProcessId) -> anyhow::Result<()> {
    table
        .mark_terminal_status(id, ProcessStatus::Completed)
        .context("missing process")?;
    table
        .complete_finalization(id)
        .context("completion was rejected")
}

#[test]
fn concurrent_free_siblings_share_the_ancestor_inflight_limit() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let parent = running(&table, None)?;
    let children = [
        running(&table, Some(parent))?,
        running(&table, Some(parent))?,
    ];
    ensure!(table.set_budget_spec(
        parent,
        BudgetSpec {
            max_inflight_ops: Some(1),
            ..BudgetSpec::default()
        }
    ));
    let barrier = std::sync::Barrier::new(3);
    let results = std::thread::scope(|scope| {
        let calls = children.map(|child| {
            let table = &table;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                (child, table.reserve(child, 0, 0))
            })
        });
        barrier.wait();
        calls.map(|call| call.join())
    });
    let mut admitted = None;
    for result in results {
        let (id, result) =
            result.map_err(|_payload| anyhow::anyhow!("reservation worker panicked"))?;
        match result {
            Ok(()) => {
                ensure!(
                    admitted.replace(id).is_none(),
                    "both siblings were admitted"
                );
            }
            Err(error) => ensure!(error == "inflight_ops"),
        }
    }
    ensure!(budget(&table, parent)?.inflight_ops == 1);
    let admitted = admitted.context("neither sibling was admitted")?;
    table.settle(admitted, 0, 0, 0, 0);
    for id in [parent, children[0], children[1]] {
        ensure!(budget(&table, id)? == BudgetState::default());
    }
    Ok(())
}

#[test]
fn ancestor_rejection_rolls_back_only_the_current_reservation() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = running(&table, None)?;
    let parent = running(&table, Some(root))?;
    let child = running(&table, Some(parent))?;
    ensure!(table.set_budget_spec(
        root,
        BudgetSpec {
            daily_micro_usd: Some(10),
            ..BudgetSpec::default()
        }
    ));
    ensure!(table.reserve(parent, 9, 4).is_ok());
    let before = [
        budget(&table, root)?,
        budget(&table, parent)?,
        budget(&table, child)?,
    ];
    ensure!(table.reserve(child, 2, 3) == Err("daily_micro_usd".into()));
    for (id, expected) in [root, parent, child].into_iter().zip(before) {
        ensure!(budget(&table, id)? == expected);
    }
    table.settle(parent, 9, 8, 4, 2);
    ensure!(budget(&table, root)?.spent_micro_usd == 8);
    ensure!(budget(&table, root)?.inference_tokens == 2);
    Ok(())
}

#[test]
fn completed_ancestors_keep_limits_for_independent_descendants() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let parent = running(&table, None)?;
    let child = running(&table, Some(parent))?;
    ensure!(table.set_budget_spec(
        parent,
        BudgetSpec {
            daily_micro_usd: Some(50),
            ..BudgetSpec::default()
        }
    ));
    complete(&table, parent)?;
    ensure!(table.reserve(child, 40, 3).is_ok());
    table.settle(child, 40, 35, 3, 2);
    ensure!(budget(&table, parent)? == budget(&table, child)?);
    ensure!(budget(&table, parent)?.spent_micro_usd == 35);
    ensure!(table.reserve(child, 20, 0) == Err("daily_micro_usd".into()));
    ensure!(table.reserve(parent, 0, 0) == Err("process_unavailable".into()));
    ensure!(table.reserve(ProcessId::new(u64::MAX), 0, 0) == Err("process_unavailable".into()));
    Ok(())
}

#[test]
fn reservations_pin_terminal_accounts_until_settlement() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = running(&table, None)?;
    let parent = running(&table, Some(root))?;
    let child = running(&table, Some(parent))?;
    ensure!(table.reserve(child, 10, 5).is_ok());
    complete(&table, child)?;
    complete(&table, parent)?;
    ensure!(table.reap_finalized(usize::MAX) == 0);
    table.settle(child, 10, 6, 5, 2);
    for id in [root, parent, child] {
        let state = budget(&table, id)?;
        ensure!(
            state.inflight_ops == 0 && state.spent_micro_usd == 6 && state.inference_tokens == 2
        );
    }
    ensure!(table.reap_finalized(usize::MAX) == 2);
    ensure!(table.len() == 1);
    Ok(())
}

#[tokio::test]
async fn finalizer_admission_is_bound_to_its_table_and_active_owner() -> anyhow::Result<()> {
    let first = ProcessTable::new();
    let second = ProcessTable::new();
    let process = running(&first, None)?;
    ensure!(running(&second, None)? == process);
    for table in [&first, &second] {
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started
        );
        ensure!(table.reserve(process, 0, 0) == Err("process_unavailable".into()));
    }
    scope_finalizer(&first, process, async {
        ensure!(first.reserve(process, 0, 0).is_ok());
        ensure!(second.reserve(process, 0, 0) == Err("process_unavailable".into()));
        first.settle(process, 0, 0, 0, 0);
        Ok::<_, anyhow::Error>(())
    })
    .await?;
    drop(first.finalization_guard(process));
    scope_finalizer(&first, process, async {
        ensure!(first.reserve(process, 0, 0) == Err("process_unavailable".into()));
        Ok::<_, anyhow::Error>(())
    })
    .await?;
    drop(second.finalization_guard(process));
    Ok(())
}

#[test]
fn incomplete_or_cyclic_parent_chains_do_not_leak_reservations() -> anyhow::Result<()> {
    for cyclic in [false, true] {
        let table = ProcessTable::new();
        let child = table.fresh_id()?;
        let missing = ProcessId::new(u64::MAX);
        let mut entry = ProcessEntry::new(
            child,
            Some(if cyclic { child } else { missing }),
            IdentityRef::ROOT,
        );
        ensure!(entry.scope.start());
        table.insert(entry);
        ensure!(table.reserve(child, 3, 4) == Err("process_unavailable".into()));
        ensure!(budget(&table, child)? == BudgetState::default());
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_machine_cleanup_is_scoped_and_cannot_reopen_committed_accounts()
-> anyhow::Result<()> {
    let first = ProcessTable::new();
    let second = ProcessTable::new();
    let process = running(&first, None)?;
    ensure!(running(&second, None)? == process);
    ensure!(first.cancel_if_non_terminal(process) == Some(true));
    ensure!(second.cancel_if_non_terminal(process) == Some(true));
    scope_cleanup(&first, process, async {
        ensure!(first.reserve(process, 0, 0).is_ok());
        ensure!(second.reserve(process, 0, 0) == Err("process_unavailable".into()));
        first.settle(process, 0, 0, 0, 0);
        first
            .complete_finalization(process)
            .context("cleanup commit failed")?;
        ensure!(first.reserve(process, 0, 0) == Err("process_unavailable".into()));
        Ok::<_, anyhow::Error>(())
    })
    .await?;
    ensure!(first.reserve(process, 0, 0) == Err("process_unavailable".into()));
    Ok(())
}
