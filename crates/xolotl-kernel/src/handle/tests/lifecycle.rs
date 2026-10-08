use super::*;
use crate::driver::FnDriver;
use crate::policy::{CheckCtx, CompiledCheck, PolicyDecision};
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_types::{DeriveKind, Value};

#[derive(Default)]
struct Drops {
    total: AtomicUsize,
    unlocked: AtomicUsize,
}

struct Capture {
    table: WeakHandleTable,
    drops: Arc<Drops>,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.drops.total.fetch_add(1, Ordering::SeqCst);
        if let Some(table) = self.table.upgrade()
            && table.try_write().is_some()
        {
            self.drops.unlocked.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait::async_trait]
impl CompiledCheck for Capture {
    async fn evaluate(&self, _: &CheckCtx) -> PolicyDecision {
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "handle-lifecycle-probe"
    }
}

fn captured_handle(table: &HandleTable, drops: &Arc<Drops>, process: u64) -> Handle {
    let driver = Capture {
        table: table.downgrade(),
        drops: drops.clone(),
    };
    let policy = Capture {
        table: table.downgrade(),
        drops: drops.clone(),
    };
    let mut handle = mk_handle(process);
    handle.driver_plan.insert(
        MethodId::new(0),
        MethodContract::new(0, ReplayClass::Deterministic, OutputModeSet::UNARY),
        Arc::new(FnDriver(move |_, input: Value| {
            // Retain the complete native capture in the closure.
            let _capture = &driver;
            Ok(input)
        })),
    );
    handle.fast_path = FastPath::Conditional(PolicySnapshot::new(vec![Arc::new(policy)]));
    handle.rights.flags = RightFlags::DELEGATE;
    handle
}

fn check_drops(drops: &Drops, expected: usize) -> anyhow::Result<()> {
    ensure!(
        drops.total.load(Ordering::SeqCst) == expected,
        "unexpected capture lifetime"
    );
    ensure!(
        drops.unlocked.load(Ordering::SeqCst) == expected,
        "native capture dropped under the table lock"
    );
    Ok(())
}

fn check_owner_index(table: &HandleTable) -> anyhow::Result<()> {
    let slots = table.read();
    let mut indexed = std::collections::HashSet::new();
    for (owner, indices) in &slots.by_owner {
        ensure!(indices.len() > 0, "owner index kept an empty entry");
        for position in 0..indices.len() {
            let index = indices.at(position).context("owner index position")?;
            let slot = &slots.slots[index as usize];
            ensure!(slot.owner == *owner && slot.owner_position as usize == position);
            ensure!(indexed.insert(index), "slot appears twice in owner index");
        }
    }
    for (index, slot) in slots.slots.iter().enumerate() {
        ensure!(
            indexed.contains(&(index as u32))
                == slot.authority.retains(slot.authority.generation()),
            "owner index disagrees with slot authority at {index}"
        );
    }
    Ok(())
}

#[test]
fn owner_index_tracks_released_ancestors_and_reused_slots() -> anyhow::Result<()> {
    let table = HandleTable::new();
    let first = table.insert(mk_handle(1))?;
    let second = table.insert(mk_handle(1))?;
    let mut parent_handle = mk_handle(1);
    parent_handle.rights.flags = RightFlags::DELEGATE;
    let parent = table.insert(parent_handle)?;
    let other = table.insert(mk_handle(2))?;
    let child = table.derive(
        parent,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(2),
    )?;
    check_owner_index(&table)?;

    ensure!(table.release(first));
    check_owner_index(&table)?;
    let replacement = table.insert(mk_handle(3))?;
    ensure!(replacement.index == first.index);
    check_owner_index(&table)?;

    ensure!(table.release_owned_by(ProcessId::new(1)) == 2);
    ensure!(table.get(second).is_none() && table.get(child).is_some());
    ensure!(table.get(replacement).is_some());
    check_owner_index(&table)?;

    ensure!(table.revoke_owned_by(ProcessId::new(1)) == 1);
    ensure!(table.get(child).is_none() && table.get(replacement).is_some());
    ensure!(table.revoke_owned_by(ProcessId::new(2)) == 2);
    ensure!(table.get(other).is_none() && table.get(replacement).is_some());
    check_owner_index(&table)?;
    ensure!(table.revoke_owned_by(ProcessId::new(3)) == 1);
    ensure!(table.read().by_owner.is_empty());
    check_owner_index(&table)
}

#[test]
fn rejected_child_install_keeps_single_owner_index_inline() -> anyhow::Result<()> {
    let table = HandleTable::new();
    let mut parent_handle = mk_handle(1);
    parent_handle.rights.flags = RightFlags::DELEGATE;
    let parent = table.insert(parent_handle)?;
    let child = table.derive(
        parent,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(3),
    )?;
    let existing = table.insert(mk_handle(2))?;
    ensure!(table.release(parent));
    {
        let mut slots = table.write();
        let before = slots.slots.len();
        let mut pending = Some(mk_handle(2));
        ensure!(matches!(
            slots.table.insert_with_parent(
                &mut pending,
                Some((handle_key(parent), DeriveKind::Delegate))
            ),
            Err(AuthorityError::Stale)
        ));
        ensure!(pending.is_some() && slots.slots.len() == before);
        ensure!(matches!(
            slots.by_owner.get(&ProcessId::new(2)),
            Some(OwnerSlots::One(index)) if *index == existing.index
        ));
    }
    ensure!(table.get(child).is_some() && table.get(existing).is_some());
    check_owner_index(&table)
}

#[test]
fn owner_cleanup_survives_same_owner_ancestor_reclamation() -> anyhow::Result<()> {
    let table = HandleTable::new();
    let mut parent_handle = mk_handle(1);
    parent_handle.rights.flags = RightFlags::DELEGATE;
    let parent = table.insert(parent_handle)?;
    let child = table.derive(
        parent,
        Rights::new(MethodBitmap::method(0), RightFlags::DELEGATE),
        DeriveKind::Delegate,
        ProcessId::new(1),
    )?;
    let leaf = table.derive(
        child,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(1),
    )?;
    let unrelated = table.insert(mk_handle(1))?;
    ensure!(table.release_owned_by(ProcessId::new(1)) == 4);
    ensure!(table.is_empty() && table.read().by_owner.is_empty());
    ensure!(
        [parent, child, leaf, unrelated]
            .iter()
            .all(|&id| table.get(id).is_none())
    );
    check_owner_index(&table)?;

    let table = HandleTable::new();
    let removable = table.insert(mk_handle(1))?;
    let mut parent_handle = mk_handle(1);
    parent_handle.rights.flags = RightFlags::DELEGATE;
    let parent = table.insert(parent_handle)?;
    let child = table.derive(
        parent,
        Rights::new(MethodBitmap::method(0), RightFlags::DELEGATE),
        DeriveKind::Delegate,
        ProcessId::new(1),
    )?;
    let leaf = table.derive(
        child,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(1),
    )?;
    // Swap removal moves the leaf ahead of its ancestors in the owner list.
    // Cleaning that leaf reclaims the later indexed ancestors mid-iteration.
    ensure!(table.release(removable));
    ensure!(table.release(parent) && table.release(child));
    check_owner_index(&table)?;
    ensure!(table.release_owned_by(ProcessId::new(1)) == 1);
    ensure!(table.get(leaf).is_none() && table.read().by_owner.is_empty());
    check_owner_index(&table)
}

#[test]
fn reverse_owner_cleanup_does_not_skip_slots_moved_by_ancestor_reclamation() -> anyhow::Result<()> {
    let table = HandleTable::new();
    let unrelated = table.insert(mk_handle(1))?;
    let mut root_handle = mk_handle(1);
    root_handle.rights.flags = RightFlags::DELEGATE;
    let root = table.insert(root_handle)?;
    let child = table.derive(
        root,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(1),
    )?;
    let mut tail_handle = mk_handle(1);
    tail_handle.rights.flags = RightFlags::DELEGATE;
    let tail = table.insert(tail_handle)?;
    let external = table.derive(
        tail,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(2),
    )?;
    ensure!(table.release(root));
    check_owner_index(&table)?;

    // Releasing child reclaims root and swaps the already visited tail into
    // an earlier owner position. The unrelated handle must still be released.
    ensure!(table.release_owned_by(ProcessId::new(1)) == 3);
    ensure!(table.get(unrelated).is_none() && table.get(child).is_none());
    ensure!(table.get(external).is_some());
    ensure!(
        table
            .read()
            .by_owner
            .get(&ProcessId::new(1))
            .is_some_and(|indices| { indices.len() == 1 && indices.first() == tail.index })
    );
    check_owner_index(&table)?;

    ensure!(table.revoke_owned_by(ProcessId::new(1)) == 1);
    ensure!(table.get(external).is_none());
    ensure!(table.revoke_owned_by(ProcessId::new(2)) == 1);
    ensure!(table.read().by_owner.is_empty());
    check_owner_index(&table)
}

#[test]
fn slot_limit_counts_retained_ancestry_and_reuses_reclaimed_indices() -> anyhow::Result<()> {
    let table = HandleTable::with_slot_limit(2);
    let shared = table.clone();
    ensure!(table.slot_limit() == Some(2) && table.allocated_slots() == 0);
    ensure!(shared.slot_limit() == table.slot_limit());

    let mut root_handle = mk_handle(1);
    root_handle.rights.flags = RightFlags::DELEGATE;
    let root = table.insert(root_handle)?;
    let child = shared.derive(
        root,
        Rights::new(MethodBitmap::method(0), RightFlags::DELEGATE),
        DeriveKind::Delegate,
        ProcessId::new(2),
    )?;
    ensure!(table.allocated_slots() == 2 && table.len() == 2);
    ensure!(matches!(
        table.insert(mk_handle(3)),
        Err(AuthorityError::Capacity)
    ));
    ensure!(matches!(
        shared.derive(
            child,
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            DeriveKind::Delegate,
            ProcessId::new(3),
        ),
        Err(AuthorityError::Capacity)
    ));
    ensure!(table.get(child).is_some());

    ensure!(table.release(root));
    ensure!(table.len() == 1 && table.allocated_slots() == 2);
    ensure!(matches!(
        table.insert(mk_handle(3)),
        Err(AuthorityError::Capacity)
    ));
    ensure!(table.get(child).is_some());

    ensure!(shared.release(child));
    ensure!(table.is_empty() && table.allocated_slots() == 2);
    let replacement = table.insert(mk_handle(3))?;
    ensure!(replacement.index == root.index && replacement.generation > root.generation);
    ensure!(table.get(root).is_none() && table.get(replacement).is_some());
    ensure!(table.allocated_slots() == 2);
    Ok(())
}

#[test]
fn zero_slot_limit_rejects_root_installation_without_allocating() -> anyhow::Result<()> {
    let unrestricted = HandleTable::new();
    ensure!(unrestricted.slot_limit().is_none());
    let table = HandleTable::with_slot_limit(0);
    let drops = Arc::new(Drops::default());
    ensure!(table.slot_limit() == Some(0));
    ensure!(matches!(
        table.insert(captured_handle(&table, &drops, 1)),
        Err(AuthorityError::Capacity)
    ));
    check_drops(&drops, 2)?;
    ensure!(table.allocated_slots() == 0 && table.is_empty());
    Ok(())
}

#[test]
fn exhausted_generation_cannot_reuse_an_index_at_the_limit() -> anyhow::Result<()> {
    let table = HandleTable::with_slot_limit(1);
    let first = table.insert(mk_handle(1))?;
    ensure!(table.release(first));
    {
        let mut slots = table.write();
        // Place an otherwise reusable slot one generation before exhaustion.
        slots.table.slots[first.index as usize].authority = HandleSlot::vacant(u64::MAX - 1);
    }
    let last = table.insert(mk_handle(2))?;
    ensure!(last.generation == u64::MAX && table.allocated_slots() == 1);
    ensure!(table.revoke(last));
    ensure!(table.read().free.is_empty());
    ensure!(matches!(
        table.insert(mk_handle(3)),
        Err(AuthorityError::Capacity)
    ));
    ensure!(table.allocated_slots() == 1);
    check_owner_index(&table)?;
    Ok(())
}

#[test]
fn driver_and_policy_destructors_run_after_local_or_owner_cleanup_unlocks() -> anyhow::Result<()> {
    for action in ["release", "revoke", "release-owner", "revoke-owner"] {
        let table = HandleTable::new();
        let drops = Arc::new(Drops::default());
        let first = table.insert(captured_handle(&table, &drops, 1))?;
        let second = table.insert(captured_handle(&table, &drops, 1))?;
        let other = table.insert(captured_handle(&table, &drops, 2))?;
        match action {
            "release" => ensure!(table.release(first) && table.release(second)),
            "revoke" => ensure!(table.revoke(first) && table.revoke(second)),
            "release-owner" => ensure!(table.release_owned_by(ProcessId::new(1)) == 2),
            "revoke-owner" => ensure!(table.revoke_owned_by(ProcessId::new(1)) == 2),
            _ => anyhow::bail!("unknown cleanup action"),
        }
        check_drops(&drops, 4)?;
        ensure!(table.get(first).is_none() && table.get(second).is_none());
        ensure!(table.get(other).is_some());
        ensure!(table.release(other));
        check_drops(&drops, 6)?;
    }
    Ok(())
}

#[test]
fn final_delegated_capture_is_released_after_ancestor_reclamation_unlocks() -> anyhow::Result<()> {
    let table = HandleTable::new();
    let drops = Arc::new(Drops::default());
    let root = table.insert(captured_handle(&table, &drops, 1))?;
    let child = table.derive(
        root,
        Rights::new(MethodBitmap::method(0), RightFlags::DELEGATE),
        DeriveKind::Delegate,
        ProcessId::new(2),
    )?;
    let leaf = table.derive(
        child,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        DeriveKind::Delegate,
        ProcessId::new(3),
    )?;
    ensure!(table.release(root) && table.release(child));
    check_drops(&drops, 0)?;
    ensure!(table.get(leaf).is_some());
    ensure!(table.release(leaf) && table.is_empty());
    check_drops(&drops, 2)?;
    // The last release reclaimed both retained ancestors, without recycling IDs.
    ensure!(table.read().free.len() == 3);
    ensure!(!table.revoke(root) && !table.revoke(child));
    Ok(())
}

#[test]
fn rejected_derivation_and_batch_rollback_defer_captures_until_transaction_end()
-> anyhow::Result<()> {
    let table = HandleTable::new();
    let drops = Arc::new(Drops::default());
    let root = table.insert(mk_handle(1))?;
    ensure!(table.release(root));
    ensure!(matches!(
        table.insert_derived(captured_handle(&table, &drops, 2), root),
        Err(AuthorityError::Stale)
    ));
    check_drops(&drops, 2)?;
    {
        let mut transaction = table.write();
        let first = transaction.insert(captured_handle(&table, &drops, 2))?;
        let second = transaction.insert(captured_handle(&table, &drops, 3))?;
        ensure!(matches!(
            transaction.insert_derived(captured_handle(&table, &drops, 4), root, DeriveKind::Clone),
            Err(AuthorityError::Stale)
        ));
        ensure!(transaction.revoke(first) && transaction.revoke(second));
        // No destructor may run while the batch still holds the write guard.
        check_drops(&drops, 2)?;
    }
    check_drops(&drops, 8)?;
    ensure!(table.is_empty() && table.get(root).is_none());
    Ok(())
}

#[test]
fn shared_tables_isolate_snapshots_and_weak_references_do_not_retain_authority()
-> anyhow::Result<()> {
    let table = HandleTable::new();
    let weak = table.downgrade();
    let shared = table.clone();
    let id = table.insert(mk_handle(1))?;
    let mut snapshot = table.get(id).context("snapshot")?;
    snapshot.process = ProcessId::new(99);
    snapshot.rights = Rights::new(MethodBitmap::ALL, RightFlags::all());
    snapshot.driver_plan.insert(
        MethodId::new(1),
        MethodContract::new(1, ReplayClass::NonIdempotentEffect, OutputModeSet::UNARY),
        Arc::new(EchoDriver),
    );
    let current = shared.get(id).context("shared handle")?;
    ensure!(current.process == ProcessId::new(1));
    ensure!(!current.allows_method(1) && current.rights.flags.is_empty());
    ensure!(current.driver_plan.contract(MethodId::new(1)).is_none());
    ensure!(shared.revoke(id) && table.get(id).is_none());
    drop(table);
    ensure!(weak.upgrade().is_some());
    drop(shared);
    // Owned snapshots retain native captures, but do not keep the table alive.
    ensure!(weak.upgrade().is_none());
    ensure!(current.driver_plan.supports(MethodId::new(0)));
    Ok(())
}
