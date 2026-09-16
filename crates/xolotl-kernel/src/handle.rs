//! `Handle` — the compiled form of a capability, and `HandleTable` —
//! the generational slotmap it lives in.
//!
//! A Handle is the product of `open()`: a closed, executable token carrying
//! attenuated rights, a frozen [`DriverPlan`], and a policy mode:
//! `Unconditional` or `Conditional` with a residual [`PolicySnapshot`]. Lookup
//! starts with constant-time slot lookup and checks retained delegation ancestors.
//! Reusing a slot advances its generation without wrapping.

use crate::driver::DriverPlan;
use crate::policy::PolicySnapshot;
use xolotl_core::{AuthorityError, HandleKey, HandleSlot, HandleSlotChange};
use xolotl_types::{HandleId, IdentityRef, Path, ProcessId, ResourceId, Rights};

/// Whether the data plane must run residual policy for this handle.
/// `Unconditional` carries no policy at all — "zero policy cost" is a type-level
/// fact, not a runtime branch on an empty list.
#[derive(Clone)]
pub enum FastPath {
    /// Residual checks were empty at open; the data plane skips policy.
    Unconditional,
    /// Residual checks remain; evaluated per-operation.
    Conditional(PolicySnapshot),
}

/// Lifecycle state of a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleState {
    /// Handle can be used by its owning process.
    Active,
    /// Handle was voluntarily closed but the slot still resolves.
    Closed,
    /// Handle was revoked; stale ids no longer resolve.
    Revoked,
}

/// The compiled capability token. Held by exactly one Process; carries
/// the attenuated rights, the frozen dispatch table, and the fast-path marker.
#[derive(Clone)]
pub struct Handle {
    /// Generational identifier for this handle table slot.
    pub id: HandleId,
    /// Process that owns this handle.
    pub process: ProcessId,
    /// Identity admitted by open-time policy for this handle.
    pub acting: IdentityRef,
    /// Resource this handle authorizes access to.
    pub resource: ResourceId,
    /// Attenuated method and flag rights granted by open.
    pub rights: Rights,
    /// Frozen dispatch plan selected at open time.
    pub driver_plan: DriverPlan,
    /// Residual-policy marker for the data-plane hot path.
    pub fast_path: FastPath,
    /// Current lifecycle state.
    pub state: HandleState,
    /// The concrete target path this handle was opened against. For
    /// prefix-resolved Resources (`state://**`), the driver needs the actual
    /// path, not the pattern. `None` for handles where the path is implicit in
    /// the resource id. Carried on the Handle (not the Operation) so the
    /// invariant — Operations carry no paths — still holds.
    pub bound_path: Option<Path>,
}

impl Handle {
    /// Owner check: pointer-cheap equality on the data plane.
    pub fn check_owner(&self, process: ProcessId) -> bool {
        self.process == process
    }

    /// State must be Active (not Closed/Revoked).
    pub fn is_active(&self) -> bool {
        self.state == HandleState::Active
    }

    /// Rights bitmap check for a method index.
    pub fn allows_method(&self, method_index: u32) -> bool {
        self.rights.methods.allows(method_index)
    }

    /// Whether this handle skips policy entirely.
    pub fn is_unconditional(&self) -> bool {
        matches!(self.fast_path, FastPath::Unconditional)
    }
}

/// Dispatch payload and the shared generation/ancestry state for one table slot.
struct Slot {
    authority: HandleSlot,
    /// Owner retained after the dispatch payload has been released.
    owner: ProcessId,
    handle: Option<Handle>,
}

impl Slot {
    fn owner(&self) -> ProcessId {
        self.handle
            .as_ref()
            .map_or(self.owner, |handle| handle.process)
    }
}

/// Generational slotmap with constant-time root lookup and bounded ancestor checks.
/// Revoked ancestors invalidate all descendants, including after slot reuse.
#[derive(Default)]
pub struct HandleTable {
    slots: Vec<Slot>,
    /// Free list of reusable slot indices.
    free: Vec<u32>,
}

impl HandleTable {
    /// Create an empty generational handle table.
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Install a host-authorized root handle, failing if its slot index cannot
    /// be represented. The table assigns the handle's generational identifier.
    pub fn insert(&mut self, handle: Handle) -> Result<HandleId, AuthorityError> {
        self.insert_with_parent(handle, None)
    }

    pub(crate) fn insert_derived(
        &mut self,
        handle: Handle,
        parent: HandleId,
    ) -> Result<HandleId, AuthorityError> {
        if !self.get(parent).is_some_and(Handle::is_active) {
            return Err(AuthorityError::Stale);
        }
        self.insert_with_parent(handle, Some(handle_key(parent)))
    }

    fn insert_with_parent(
        &mut self,
        mut handle: Handle,
        parent: Option<HandleKey>,
    ) -> Result<HandleId, AuthorityError> {
        let vacant = self.free.last().copied();
        let index = vacant.map_or_else(
            || u32::try_from(self.slots.len()).map_err(|_error| AuthorityError::Capacity),
            Ok,
        )?;
        let mut authority = vacant
            .map(|index| self.slots[index as usize].authority)
            .unwrap_or_default();
        let generation = authority.install(parent)?;
        if let Some(parent) = parent {
            self.slots[parent.slot as usize]
                .authority
                .attach_child(parent.generation)?;
        }
        let id = HandleId::new(index, generation);
        handle.id = id;
        let slot = Slot {
            authority,
            owner: handle.process,
            handle: Some(handle),
        };
        if vacant.is_some() {
            self.free.pop();
            self.slots[index as usize] = slot;
        } else {
            self.slots.push(slot);
        }
        Ok(id)
    }

    fn validate(&self, id: HandleId) -> Result<(), AuthorityError> {
        let slot = self
            .slots
            .get(id.index as usize)
            .ok_or(AuthorityError::Stale)?;
        slot.authority
            .validate(id.generation, self.slots.len(), |parent| {
                self.slots
                    .get(parent.slot as usize)
                    .map(|slot| &slot.authority)
            })
    }

    /// Return a retained handle only while its generation and every ancestor
    /// retain authority. Closed handles still resolve for lifecycle inspection.
    pub fn get(&self, id: HandleId) -> Option<&Handle> {
        self.validate(id).ok()?;
        self.slots.get(id.index as usize)?.handle.as_ref()
    }

    /// Mutable lookup with the same generation check as [`HandleTable::get`].
    pub fn get_mut(&mut self, id: HandleId) -> Option<&mut Handle> {
        self.validate(id).ok()?;
        self.slots.get_mut(id.index as usize)?.handle.as_mut()
    }

    /// Release local authority and its payload, preserving delegated descendants.
    /// The last descendant release reclaims any now-unused ancestor metadata.
    pub fn release(&mut self, id: HandleId) -> bool {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return false;
        };
        let change = slot.authority.release(id.generation);
        if change == HandleSlotChange::Unchanged {
            return false;
        }
        slot.owner = slot.owner();
        slot.handle = None;
        self.reclaim_ancestors(id.index, change);
        true
    }

    /// Revoke active or released authority, even after an ancestor was revoked.
    /// Repeated calls have no effect. Exhausted generations retire their slots.
    pub fn revoke(&mut self, id: HandleId) -> bool {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return false;
        };
        let change = slot.authority.revoke(id.generation);
        if change == HandleSlotChange::Unchanged {
            return false;
        }
        slot.handle = None;
        self.reclaim_ancestors(id.index, change);
        true
    }

    /// Mark a handle Closed while keeping the slot so the id still resolves to
    /// a Closed handle. Previously delegated descendants retain their authority.
    pub fn close(&mut self, id: HandleId) -> bool {
        match self.get_mut(id) {
            Some(h) => {
                h.state = HandleState::Closed;
                true
            }
            None => false,
        }
    }

    /// Number of retained payloads, including closed or ancestor-revoked handles
    /// that have not yet been explicitly reclaimed.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.handle.is_some()).count()
    }

    /// Whether no live handles are present.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Revoke all handles owned by `process`. Returns
    /// the count revoked.
    pub fn revoke_owned_by(&mut self, process: ProcessId) -> usize {
        let mut count = 0;
        for index in 0..self.slots.len() {
            let slot = &self.slots[index];
            if slot.owner() == process {
                let id = HandleId::new(index as u32, slot.authority.generation());
                count += usize::from(self.revoke(id));
            }
        }
        count
    }

    /// Release all owner payloads, keeping only anchors required by descendants.
    pub fn release_owned_by(&mut self, process: ProcessId) -> usize {
        let mut count = 0;
        for index in 0..self.slots.len() {
            let slot = &self.slots[index];
            if slot.owner() == process {
                let id = HandleId::new(index as u32, slot.authority.generation());
                count += usize::from(self.release(id));
            }
        }
        count
    }

    fn reclaim_ancestors(&mut self, mut index: u32, mut change: HandleSlotChange) {
        while let HandleSlotChange::Reclaimed { parent } = change {
            let slot = &mut self.slots[index as usize];
            slot.handle = None;
            if slot.authority.reusable() {
                self.free.push(index);
            }
            let Some(parent) = parent else {
                return;
            };
            let Some(slot) = self.slots.get_mut(parent.slot as usize) else {
                return;
            };
            change = slot.authority.detach_child(parent.generation);
            index = parent.slot;
        }
    }
}

fn handle_key(id: HandleId) -> HandleKey {
    HandleKey {
        slot: id.index,
        generation: id.generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{DriverPlan, EchoDriver};
    use anyhow::{Context, ensure};
    use std::sync::Arc;
    use xolotl_types::{
        DriverId, MethodBitmap, MethodContract, MethodId, OutputModeSet, ReplayClass, RightFlags,
    };

    fn mk_handle(process: u64) -> Handle {
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(0),
            MethodContract::new(0, ReplayClass::Deterministic, OutputModeSet::UNARY),
            Arc::new(EchoDriver),
        );
        Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(process),
            acting: xolotl_types::IdentityRef::ROOT,
            resource: ResourceId::new(1),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        }
    }

    #[test]
    fn insert_and_get_roundtrip() -> anyhow::Result<()> {
        let mut t = HandleTable::new();
        let id = t.insert(mk_handle(1))?;
        let h = t.get(id).context("inserted handle did not resolve")?;
        ensure!(h.id == id, "handle id mismatch");
        ensure!(h.check_owner(ProcessId::new(1)), "handle owner mismatch");
        ensure!(h.allows_method(0), "method 0 should be allowed");
        ensure!(!h.allows_method(1), "method 1 should not be allowed");
        Ok(())
    }

    #[test]
    fn revoke_invalidates_old_id_aba_safe() -> anyhow::Result<()> {
        let mut t = HandleTable::new();
        let id = t.insert(mk_handle(1))?;
        ensure!(t.revoke(id), "handle should revoke");
        // Old id no longer resolves (generation bumped).
        ensure!(t.get(id).is_none(), "revoked handle should not resolve");
        // Slot is reused; new handle gets a higher generation.
        let id2 = t.insert(mk_handle(2))?;
        ensure!(id2.index == id.index, "slot should be reused");
        ensure!(id2.generation != id.generation, "generation should advance");
        ensure!(t.get(id).is_none(), "stale id should still be rejected");
        ensure!(t.get(id2).is_some(), "new handle should resolve");
        Ok(())
    }

    #[test]
    fn revoke_owned_by_clears_process_handles() -> anyhow::Result<()> {
        let mut t = HandleTable::new();
        t.insert(mk_handle(1))?;
        t.insert(mk_handle(1))?;
        t.insert(mk_handle(2))?;
        ensure!(
            t.revoke_owned_by(ProcessId::new(1)) == 2,
            "process-owned revoke count mismatch"
        );
        ensure!(t.len() == 1, "unexpected handle count: {}", t.len());
        Ok(())
    }

    #[test]
    fn revoked_ancestors_invalidate_descendants_without_blocking_reclamation() -> anyhow::Result<()>
    {
        let mut table = HandleTable::new();
        let root = table.insert(mk_handle(1))?;
        let child = table.insert_derived(mk_handle(2), root)?;
        let leaf = table.insert_derived(mk_handle(3), child)?;
        ensure!(table.get(leaf).is_some());
        ensure!(table.revoke(root));
        ensure!(table.get(child).is_none() && table.get(leaf).is_none());
        ensure!(table.get_mut(leaf).is_none());
        ensure!(table.insert_derived(mk_handle(4), leaf).is_err());

        let replacement = table.insert(mk_handle(1))?;
        ensure!(replacement.index == root.index && replacement.generation > root.generation);
        ensure!(table.get(leaf).is_none());
        ensure!(table.revoke_owned_by(ProcessId::new(2)) == 1);
        ensure!(table.revoke_owned_by(ProcessId::new(3)) == 1);
        ensure!(table.len() == 1);
        Ok(())
    }

    #[test]
    fn duplicate_revoke_never_admits_two_payloads_into_the_same_slot() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let original = table.insert(mk_handle(1))?;
        ensure!(table.revoke(original));
        ensure!(!table.revoke(original));
        let forged = HandleId::new(original.index, original.generation + 1);
        ensure!(!table.revoke(forged));
        let first = table.insert(mk_handle(2))?;
        let second = table.insert(mk_handle(3))?;
        ensure!(first.index != second.index);
        ensure!(table.get(first).is_some() && table.get(second).is_some());
        Ok(())
    }

    #[test]
    fn exhausted_generations_retire_instead_of_reentering_the_free_list() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        table.slots.push(Slot {
            authority: HandleSlot::vacant(u64::MAX - 1),
            owner: ProcessId::new(1),
            handle: None,
        });
        table.free.push(0);
        let last = table.insert(mk_handle(1))?;
        ensure!(last.generation == u64::MAX);
        ensure!(table.revoke(last) && !table.revoke(last));
        ensure!(table.free.is_empty());
        let fresh = table.insert(mk_handle(2))?;
        ensure!(fresh.index == 1 && fresh.generation == 1);
        ensure!(table.get(last).is_none());
        Ok(())
    }

    #[test]
    fn closing_parent_keeps_existing_delegations_but_rejects_new_ones() -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let parent = table.insert(mk_handle(1))?;
        let child = table.insert_derived(mk_handle(2), parent)?;
        ensure!(table.close(parent));
        ensure!(table.get(parent).is_some_and(|handle| !handle.is_active()));
        ensure!(table.get(child).is_some());
        ensure!(table.insert_derived(mk_handle(3), parent).is_err());
        ensure!(table.revoke(child) && table.revoke(parent));
        Ok(())
    }

    #[test]
    fn released_anchors_drop_payloads_and_are_reclaimed_by_the_final_descendant()
    -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let parent = table.insert(mk_handle(1))?;
        let child = table.insert_derived(mk_handle(2), parent)?;
        let first = table.insert_derived(mk_handle(3), child)?;
        let last = table.insert_derived(mk_handle(4), child)?;

        ensure!(table.release_owned_by(ProcessId::new(1)) == 1);
        ensure!(table.release_owned_by(ProcessId::new(1)) == 0);
        ensure!(table.release(child) && !table.release(child));
        ensure!(table.get(parent).is_none() && table.get_mut(child).is_none());
        ensure!(table.slots[parent.index as usize].handle.is_none());
        ensure!(table.slots[child.index as usize].handle.is_none());
        ensure!(table.get(first).is_some() && table.get(last).is_some());
        ensure!(table.free.is_empty() && table.len() == 2);
        ensure!(table.insert_derived(mk_handle(5), child).is_err());

        ensure!(table.release(first));
        ensure!(table.get(last).is_some() && table.free.len() == 1);
        ensure!(table.release(last));
        ensure!(table.is_empty() && table.free.len() == 4);
        ensure!(!table.revoke(parent) && !table.release(last));
        let mut reused = std::collections::BTreeSet::new();
        for owner in 1..=4 {
            let replacement = table.insert(mk_handle(owner))?;
            ensure!(replacement.generation == 2 && reused.insert(replacement.index));
        }
        ensure!(table.slots.len() == 4);
        Ok(())
    }

    #[test]
    fn revoking_released_owners_invalidates_descendants_without_releasing_new_occupants()
    -> anyhow::Result<()> {
        let mut table = HandleTable::new();
        let original = table.insert(mk_handle(1))?;
        let old_child = table.insert_derived(mk_handle(2), original)?;
        ensure!(table.release(original));
        ensure!(table.revoke_owned_by(ProcessId::new(1)) == 1);
        ensure!(table.revoke_owned_by(ProcessId::new(1)) == 0);
        ensure!(table.get(old_child).is_none());

        let replacement = table.insert(mk_handle(3))?;
        ensure!(replacement.index == original.index);
        let new_child = table.insert_derived(mk_handle(4), replacement)?;
        ensure!(table.release(replacement));
        ensure!(table.release(old_child));
        ensure!(table.get(new_child).is_some());
        ensure!(
            table.slots[replacement.index as usize]
                .authority
                .retains(replacement.generation)
        );
        ensure!(table.release(new_child));
        ensure!(table.free.len() == 3 && table.is_empty());
        Ok(())
    }

    #[test]
    fn fixed_and_allocating_tables_agree_on_release_and_anchor_retirement() -> anyhow::Result<()> {
        let mut slots = [xolotl_core::Handle::default(); 3];
        let mut fixed = xolotl_core::HandleTable::new(&mut slots);
        let mut hosted = HandleTable::new();
        let root = hosted.insert(mk_handle(1))?;
        let fixed_root = fixed.install(1, 1, 1)?;
        let child = hosted.insert_derived(mk_handle(2), root)?;
        let fixed_child = fixed.derive(fixed_root, 1, 2, 1)?;
        let leaf = hosted.insert_derived(mk_handle(3), child)?;
        let fixed_leaf = fixed.derive(fixed_child, 2, 3, 1)?;
        ensure!(fixed.derive(fixed_leaf, 3, 4, 1) == Err(AuthorityError::Capacity));

        ensure!(hosted.release(root) && hosted.release(child));
        fixed.release(fixed_root, 1)?;
        fixed.release(fixed_child, 2)?;
        ensure!(fixed.install(4, 1, 1) == Err(AuthorityError::Capacity));
        for (id, key, owner) in [
            (root, fixed_root, 1),
            (child, fixed_child, 2),
            (leaf, fixed_leaf, 3),
        ] {
            ensure!(hosted.get(id).is_some() == fixed.authorize(key, owner, 0).is_ok());
        }
        ensure!(hosted.release(leaf));
        fixed.release(fixed_leaf, 3)?;
        ensure!(!hosted.revoke(root) && fixed.revoke(fixed_root, 1).is_err());
        for owner in 1..=3 {
            ensure!(hosted.insert(mk_handle(owner))?.generation == 2);
            ensure!(fixed.install(owner, 1, 1)?.generation == 2);
        }
        ensure!(hosted.slots.len() == 3);
        Ok(())
    }

    #[test]
    fn fixed_and_allocating_tables_agree_on_delegation_and_revocation() -> anyhow::Result<()> {
        fn hosted_authorize(
            table: &HandleTable,
            id: HandleId,
            owner: u64,
            method: u8,
        ) -> Result<u32, AuthorityError> {
            let handle = table.get(id).ok_or(AuthorityError::Stale)?;
            if !handle.check_owner(ProcessId::new(owner)) {
                return Err(AuthorityError::Owner);
            }
            if !handle.allows_method(u32::from(method)) {
                return Err(AuthorityError::Rights);
            }
            u32::try_from(handle.resource.get()).map_err(|_error| AuthorityError::Capacity)
        }

        let mut slots = [xolotl_core::Handle::default(); 4];
        let mut fixed = xolotl_core::HandleTable::new(&mut slots);
        let mut hosted = HandleTable::new();
        let mut handle = mk_handle(1);
        handle.rights = Rights::new(MethodBitmap::from_bits_retain(0b111), RightFlags::DELEGATE);
        let root = hosted.insert(handle)?;
        let fixed_root = fixed.install(1, 1, 0b111)?;
        let child = crate::derive_handle(
            &mut hosted,
            root,
            Rights::new(MethodBitmap::from_bits_retain(0b11), RightFlags::DELEGATE),
            xolotl_types::DeriveKind::Delegate,
            ProcessId::new(2),
        )?;
        let fixed_child = fixed.derive(fixed_root, 1, 2, 0b11)?;
        let leaf = crate::derive_handle(
            &mut hosted,
            child,
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            xolotl_types::DeriveKind::Delegate,
            ProcessId::new(3),
        )?;
        let fixed_leaf = fixed.derive(fixed_child, 2, 3, 1)?;
        for method in [0, 1, 2, 63, 64] {
            ensure!(
                hosted_authorize(&hosted, leaf, 3, method)
                    == fixed.authorize(fixed_leaf, 3, method)
            );
        }
        ensure!(hosted_authorize(&hosted, leaf, 9, 0) == fixed.authorize(fixed_leaf, 9, 0));
        ensure!(hosted.release(root));
        fixed.release(fixed_root, 1)?;
        ensure!(hosted_authorize(&hosted, leaf, 3, 0) == fixed.authorize(fixed_leaf, 3, 0));
        ensure!(hosted_authorize(&hosted, root, 9, 0) == fixed.authorize(fixed_root, 9, 0));
        ensure!(hosted.revoke(root));
        fixed.revoke(fixed_root, 1)?;
        for (id, key, owner) in [
            (root, fixed_root, 1),
            (child, fixed_child, 2),
            (leaf, fixed_leaf, 3),
        ] {
            ensure!(hosted_authorize(&hosted, id, owner, 0) == fixed.authorize(key, owner, 0));
        }
        hosted.insert(mk_handle(1))?;
        fixed.install(1, 1, 1)?;
        ensure!(hosted_authorize(&hosted, leaf, 3, 0) == fixed.authorize(fixed_leaf, 3, 0));
        ensure!(hosted.revoke(leaf));
        fixed.revoke(fixed_leaf, 3)?;
        ensure!(!hosted.revoke(leaf) && fixed.revoke(fixed_leaf, 3).is_err());
        Ok(())
    }
}
