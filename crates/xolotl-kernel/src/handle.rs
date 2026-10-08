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
use crate::runtime_domain::RuntimeDomain;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use xolotl_core::{AuthorityError, HandleKey, HandleSlot, HandleSlotChange};
use xolotl_types::{DeriveKind, HandleId, IdentityRef, Path, ProcessId, ResourceId, Rights};

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

/// The compiled capability token. Held by exactly one Process; carries
/// the attenuated rights, the frozen dispatch table, and the fast-path marker.
/// Its live generation and delegation state belong to the owning table; a
/// snapshot does not prove that its authority remains usable.
#[derive(Clone)]
pub struct Handle {
    /// Generational identifier for this handle table slot.
    pub id: HandleId,
    /// Process that owns this handle.
    pub process: ProcessId,
    /// Identity admitted by open-time policy for this handle.
    pub acting: IdentityRef,
    /// Original capability verb used at open. Derivation preserves this context
    /// even when attenuation removes every callable method.
    pub open_verb: String,
    /// Resource this handle authorizes access to.
    pub resource: ResourceId,
    /// Attenuated method and flag rights granted by open.
    pub rights: Rights,
    /// Frozen dispatch plan selected at open time.
    pub driver_plan: DriverPlan,
    /// Residual-policy marker for the data-plane hot path.
    pub fast_path: FastPath,
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
    /// Position in `Slots::by_owner[owner]`, also retained for released anchors.
    owner_position: u32,
    handle: Option<Handle>,
}

/// Shared generational handle table. Clones refer to the same slots; callers
/// invoke complete operations without managing the table's lock.
///
/// Root lookup is constant-time and delegation checks are bounded by the retained
/// ancestry. Revoked ancestors invalidate descendants even after slot reuse.
/// Released driver and policy captures are destroyed after unlocking the table.
#[derive(Clone, Default)]
pub struct HandleTable {
    inner: Arc<RwLock<Slots>>,
}

/// Non-owning handle-table reference for native drivers and policy callbacks.
/// Use it to avoid keeping a table alive through one of its own handles.
#[derive(Clone, Default, Debug)]
pub struct WeakHandleTable {
    inner: Weak<RwLock<Slots>>,
}

impl WeakHandleTable {
    /// Rejoin the shared table while at least one owner retains it.
    pub fn upgrade(&self) -> Option<HandleTable> {
        self.inner.upgrade().map(|inner| HandleTable { inner })
    }
}

impl HandleTable {
    /// Create an empty shared table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Slots::new())),
        }
    }

    /// Create a shared table with a fixed limit on allocated slot indices.
    /// Zero admits no handles. Vacant indices may be reused without consuming
    /// another slot, while exhausted generations permanently occupy an index.
    pub fn with_slot_limit(limit: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Slots::with_slot_limit(limit))),
        }
    }

    pub(crate) fn with_runtime_domain(self, domain: RuntimeDomain) -> Self {
        self.inner.write().runtime_domain = Some(domain);
        self
    }

    pub(crate) fn runtime_domain(&self) -> Option<RuntimeDomain> {
        self.inner.read().runtime_domain.clone()
    }

    /// Maximum number of slot indices this table may allocate, if configured.
    /// This limit is shared by all clones and cannot change after construction.
    pub fn slot_limit(&self) -> Option<usize> {
        self.read().slot_limit()
    }

    /// Number of slot indices allocated since construction, including vacant,
    /// retained-ancestor, and permanently retired slots. Unlike [`Self::len`],
    /// this count never decreases and is the value charged against `slot_limit`.
    pub fn allocated_slots(&self) -> usize {
        self.read().allocated_slots()
    }

    /// Retain a weak reference without extending the table's lifetime.
    pub fn downgrade(&self) -> WeakHandleTable {
        WeakHandleTable {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Install a host-authorized root, assigning a fresh generational identity.
    /// This low-level operation does not admit the owning process or compile policy.
    pub fn insert(&self, handle: Handle) -> Result<HandleId, AuthorityError> {
        self.write().insert(handle)
    }

    /// Inspect an owned snapshot after checking its generation and ancestry.
    /// Mutating this snapshot cannot change the table. Every new invocation
    /// resolves its own authority; keeping a snapshot does not prevent revocation.
    pub fn get(&self, id: HandleId) -> Option<Handle> {
        self.read().get(id).cloned()
    }

    /// Derive an attenuated child from a live parent in one table transaction.
    /// The propagation flag must permit `kind`. The table preserves the target,
    /// acting identity, driver declarations and policy; only owner and rights
    /// change. The trusted host manages the new owner's process admission.
    pub fn derive(
        &self,
        parent: HandleId,
        rights: Rights,
        kind: DeriveKind,
        owner: ProcessId,
    ) -> Result<HandleId, AuthorityError> {
        self.write().derive(parent, rights, kind, owner)
    }

    /// Release the owner's local payload while preserving delegated descendants.
    pub fn release(&self, id: HandleId) -> bool {
        self.write().release(id)
    }

    /// Revoke local active or released authority, invalidating its ancestry subtree.
    /// Stale and repeated revocations return false.
    pub fn revoke(&self, id: HandleId) -> bool {
        self.write().revoke(id)
    }

    /// Number of retained payloads, including ancestor-revoked handles.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the table retains no handle payloads.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// Revoke all active and released authorities owned by this process.
    pub fn revoke_owned_by(&self, process: ProcessId) -> usize {
        self.write().revoke_owned_by(process)
    }

    /// Release owner payloads, retaining the ancestors needed by descendants.
    pub fn release_owned_by(&self, process: ProcessId) -> usize {
        self.write().release_owned_by(process)
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, Slots> {
        self.inner.read()
    }

    pub(crate) fn write(&self) -> HandleWrite<'_> {
        HandleWrite {
            table: self.inner.write(),
            retired: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn try_write(&self) -> Option<HandleWrite<'_>> {
        self.inner.try_write().map(|table| HandleWrite {
            table,
            retired: Vec::new(),
        })
    }

    #[cfg(test)]
    fn insert_derived(&self, handle: Handle, parent: HandleId) -> Result<HandleId, AuthorityError> {
        self.write()
            .insert_derived(handle, parent, DeriveKind::Clone)
    }
}

/// Kernel-only transaction for lifecycle checks and atomic batch installation.
/// Field order releases the guard before dropping retired native captures.
pub(crate) struct HandleWrite<'a> {
    table: RwLockWriteGuard<'a, Slots>,
    retired: Vec<Handle>,
}

impl std::ops::Deref for HandleWrite<'_> {
    type Target = Slots;
    fn deref(&self) -> &Self::Target {
        &self.table
    }
}

impl HandleWrite<'_> {
    /// Transfer retired payloads to an enclosing transaction for drop after unlock.
    pub(crate) fn into_retired(self) -> Vec<Handle> {
        let Self { table, retired } = self;
        drop(table);
        retired
    }

    pub(crate) fn insert(&mut self, handle: Handle) -> Result<HandleId, AuthorityError> {
        let mut pending = Some(handle);
        let result = self.table.insert(&mut pending);
        self.retired.extend(pending);
        result
    }

    pub(crate) fn derive(
        &mut self,
        parent: HandleId,
        rights: Rights,
        kind: DeriveKind,
        owner: ProcessId,
    ) -> Result<HandleId, AuthorityError> {
        let source = self.table.get(parent).ok_or(AuthorityError::Stale)?;
        if !rights.is_subset_of(&source.rights) || !source.rights.allows_derive(kind) {
            return Err(AuthorityError::Rights);
        }
        let mut child = source.clone();
        child.process = owner;
        child.rights = rights;
        let mut pending = Some(child);
        let result = self
            .table
            .insert_with_parent(&mut pending, Some((handle_key(parent), kind)));
        self.retired.extend(pending);
        result
    }

    // Fault-injection fixtures may install inconsistent payloads deliberately.
    // Production derivation always copies the parent through `derive` above.
    #[cfg(test)]
    pub(crate) fn insert_derived(
        &mut self,
        handle: Handle,
        parent: HandleId,
        kind: DeriveKind,
    ) -> Result<HandleId, AuthorityError> {
        let mut pending = Some(handle);
        let result = self.table.insert_derived(&mut pending, parent, kind);
        self.retired.extend(pending);
        result
    }

    pub(crate) fn release(&mut self, id: HandleId) -> bool {
        self.table.release(id, &mut self.retired)
    }
    pub(crate) fn revoke(&mut self, id: HandleId) -> bool {
        self.table.revoke(id, &mut self.retired)
    }
    pub(crate) fn revoke_owned_by(&mut self, process: ProcessId) -> usize {
        self.table.revoke_owned_by(process, &mut self.retired)
    }
    pub(crate) fn release_owned_by(&mut self, process: ProcessId) -> usize {
        self.table.release_owned_by(process, &mut self.retired)
    }

    #[cfg(test)]
    pub(crate) fn get_mut(&mut self, id: HandleId) -> Option<&mut Handle> {
        self.table.get_mut(id)
    }
}

#[derive(Default)]
pub(crate) struct Slots {
    /// Present only for handle tables assembled into a Kernel.
    runtime_domain: Option<RuntimeDomain>,
    slots: Vec<Slot>,
    /// Free list of reusable slot indices.
    free: Vec<u32>,
    /// Only occupied or retained-ancestor indices. Process cleanup must not
    /// scan the global high-water slot array under its write lock.
    by_owner: HashMap<ProcessId, OwnerSlots>,
    slot_limit: Option<usize>,
}

/// The usual one-handle owner needs no separate heap allocation. Owners with
/// several handles gain a dense vector and constant-time swap removal.
enum OwnerSlots {
    One(u32),
    Many(Vec<u32>),
}

impl OwnerSlots {
    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(indices) => indices.len(),
        }
    }

    fn first(&self) -> u32 {
        match self {
            Self::One(index) => *index,
            Self::Many(indices) => indices[0],
        }
    }

    fn at(&self, position: usize) -> Option<u32> {
        match self {
            Self::One(index) => (position == 0).then_some(*index),
            Self::Many(indices) => indices.get(position).copied(),
        }
    }

    /// Return the moved index and its new position, if any.
    fn remove(&mut self, index: u32, position: usize) -> (Option<(u32, u32)>, bool) {
        match self {
            Self::One(only) => {
                debug_assert_eq!(*only, index);
                debug_assert_eq!(position, 0);
                (None, true)
            }
            Self::Many(indices) => {
                debug_assert_eq!(indices[position], index);
                indices.swap_remove(position);
                if indices.len() == 1 {
                    let single = indices[0];
                    *self = Self::One(single);
                    (Some((single, 0)), false)
                } else {
                    (
                        indices
                            .get(position)
                            .copied()
                            .map(|moved| (moved, position as u32)),
                        indices.is_empty(),
                    )
                }
            }
        }
    }
}

impl Slots {
    /// Create an empty generational handle table.
    pub fn new() -> Self {
        Self {
            runtime_domain: None,
            slots: Vec::new(),
            free: Vec::new(),
            by_owner: HashMap::new(),
            slot_limit: None,
        }
    }

    fn with_slot_limit(limit: usize) -> Self {
        Self {
            runtime_domain: None,
            slots: Vec::new(),
            free: Vec::new(),
            by_owner: HashMap::new(),
            slot_limit: Some(limit),
        }
    }

    fn slot_limit(&self) -> Option<usize> {
        self.slot_limit
    }

    fn allocated_slots(&self) -> usize {
        self.slots.len()
    }

    /// Install a host-authorized root handle, failing if its slot index cannot
    /// be represented. The table assigns the handle's generational identifier.
    fn insert(&mut self, handle: &mut Option<Handle>) -> Result<HandleId, AuthorityError> {
        self.insert_with_parent(handle, None)
    }

    #[cfg(test)]
    pub(crate) fn insert_derived(
        &mut self,
        handle: &mut Option<Handle>,
        parent: HandleId,
        kind: DeriveKind,
    ) -> Result<HandleId, AuthorityError> {
        if self.get(parent).is_none() {
            return Err(AuthorityError::Stale);
        }
        self.insert_with_parent(handle, Some((handle_key(parent), kind)))
    }

    fn insert_with_parent(
        &mut self,
        pending: &mut Option<Handle>,
        parent: Option<(HandleKey, DeriveKind)>,
    ) -> Result<HandleId, AuthorityError> {
        let vacant = self.free.last().copied();
        let index = match vacant {
            Some(index) => index,
            None => {
                if self
                    .slot_limit
                    .is_some_and(|limit| self.slots.len() >= limit)
                {
                    return Err(AuthorityError::Capacity);
                }
                let Ok(index) = u32::try_from(self.slots.len()) else {
                    return Err(AuthorityError::Capacity);
                };
                index
            }
        };
        let mut authority = vacant
            .map(|index| self.slots[index as usize].authority)
            .unwrap_or_default();
        let generation = authority.install(parent.map(|(key, _)| key))?;
        if vacant.is_none() && self.slots.try_reserve(1).is_err() {
            return Err(AuthorityError::Capacity);
        }
        let owner = pending.as_ref().ok_or(AuthorityError::Stale)?.process;
        // Reserve both index layers before consuming the payload or attaching
        // a child, so allocation failure cannot leave a half-installed handle.
        enum OwnerInsert<'a> {
            New,
            Promote(&'a mut OwnerSlots, Vec<u32>),
            Append(&'a mut Vec<u32>),
        }
        let (owner_insert, owner_position) = match self.by_owner.get_mut(&owner) {
            None => {
                if self.by_owner.try_reserve(1).is_err() {
                    return Err(AuthorityError::Capacity);
                }
                (OwnerInsert::New, 0)
            }
            Some(entry @ OwnerSlots::One(_)) => {
                // Keep the one-slot representation unchanged if the later
                // ancestry attachment rejects this installation.
                let mut indices = Vec::new();
                if indices.try_reserve(2).is_err() {
                    return Err(AuthorityError::Capacity);
                }
                indices.push(entry.first());
                (OwnerInsert::Promote(entry, indices), 1)
            }
            Some(OwnerSlots::Many(indices)) => {
                let position = indices.len();
                if indices.try_reserve(1).is_err() {
                    return Err(AuthorityError::Capacity);
                }
                (OwnerInsert::Append(indices), position)
            }
        };
        let Ok(owner_position) = u32::try_from(owner_position) else {
            return Err(AuthorityError::Capacity);
        };
        let mut handle = pending.take().ok_or(AuthorityError::Stale)?;
        if let Some((parent, _)) = parent
            && let Err(error) = self.slots[parent.slot as usize]
                .authority
                .attach_child(parent.generation)
        {
            *pending = Some(handle);
            return Err(error);
        }
        let id = HandleId::new(index, generation);
        // Move the payload exactly once into its slot. On rejection the caller
        // keeps it for retirement after unlock.
        handle.id = id;
        // Each occupied case retains its direct mutable index target. No
        // lookup or fallible allocation remains after ancestry attachment.
        match owner_insert {
            OwnerInsert::New => {
                self.by_owner.insert(owner, OwnerSlots::One(index));
            }
            OwnerInsert::Promote(entry, mut indices) => {
                indices.push(index);
                *entry = OwnerSlots::Many(indices);
            }
            OwnerInsert::Append(indices) => indices.push(index),
        }
        let slot = Slot {
            authority,
            owner,
            owner_position,
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
                let slot = self.slots.get(parent.slot as usize)?;
                Some(&slot.authority)
            })
    }

    /// Return a retained handle only while its generation and every ancestor
    /// retain authority. Released and revoked handles no longer resolve.
    pub fn get(&self, id: HandleId) -> Option<&Handle> {
        self.validate(id).ok()?;
        self.slots.get(id.index as usize)?.handle.as_ref()
    }

    /// Mutable lookup with the same generation check as [`HandleTable::get`].
    #[cfg(test)]
    pub fn get_mut(&mut self, id: HandleId) -> Option<&mut Handle> {
        self.validate(id).ok()?;
        self.slots.get_mut(id.index as usize)?.handle.as_mut()
    }

    /// Release local authority and its payload, preserving delegated descendants.
    /// The last descendant release reclaims any now-unused ancestor metadata.
    fn release(&mut self, id: HandleId, retired: &mut Vec<Handle>) -> bool {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return false;
        };
        let change = slot.authority.release(id.generation);
        if change == HandleSlotChange::Unchanged {
            return false;
        }
        retired.extend(slot.handle.take());
        self.reclaim_ancestors(id.index, change, retired);
        true
    }

    /// Revoke active or released authority, even after an ancestor was revoked.
    /// Repeated calls have no effect. Exhausted generations retire their slots.
    fn revoke(&mut self, id: HandleId, retired: &mut Vec<Handle>) -> bool {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return false;
        };
        let change = slot.authority.revoke(id.generation);
        if change == HandleSlotChange::Unchanged {
            return false;
        }
        retired.extend(slot.handle.take());
        self.reclaim_ancestors(id.index, change, retired);
        true
    }

    /// Number of retained payloads, including ancestor-revoked handles
    /// that have not yet been explicitly reclaimed.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.handle.is_some()).count()
    }

    /// Whether no handle payloads are retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Revoke all handles owned by `process`. Returns
    /// the count revoked.
    fn revoke_owned_by(&mut self, process: ProcessId, retired: &mut Vec<Handle>) -> usize {
        let mut count = 0;
        // Every successful revoke removes its index, including a released
        // anchor. Always take the current first index so ancestor reclamation
        // and swap removal cannot skip another handle, and no snapshot allocates.
        while let Some(index) = self.by_owner.get(&process).map(OwnerSlots::first) {
            let slot = &self.slots[index as usize];
            let id = HandleId::new(index, slot.authority.generation());
            if !self.revoke(id, retired) {
                break;
            }
            count += 1;
        }
        count
    }

    /// Release all owner payloads, keeping only anchors required by descendants.
    fn release_owned_by(&mut self, process: ProcessId, retired: &mut Vec<Handle>) -> usize {
        let mut count = 0;
        // Walk backward without copying the owner's index. Releasing a child
        // may reclaim ancestors and swap a previously visited tail entry into
        // an earlier position. Unvisited entries cannot move past the cursor;
        // revisiting a released anchor is harmless and does not affect count.
        let mut remaining = self.by_owner.get(&process).map_or(0, OwnerSlots::len);
        while let Some(indices) = self.by_owner.get(&process) {
            let Some(position) = remaining.min(indices.len()).checked_sub(1) else {
                break;
            };
            let Some(index) = indices.at(position) else {
                break;
            };
            remaining = position;
            let slot = &self.slots[index as usize];
            let id = HandleId::new(index, slot.authority.generation());
            count += usize::from(self.release(id, retired));
        }
        count
    }

    fn remove_owner_index(&mut self, index: u32) {
        let slot = &self.slots[index as usize];
        let owner = slot.owner;
        let position = slot.owner_position as usize;
        let Some(indices) = self.by_owner.get_mut(&owner) else {
            return;
        };
        let (moved, empty) = indices.remove(index, position);
        if let Some((moved, new_position)) = moved {
            self.slots[moved as usize].owner_position = new_position;
        }
        if empty {
            self.by_owner.remove(&owner);
        }
    }

    fn reclaim_ancestors(
        &mut self,
        mut index: u32,
        mut change: HandleSlotChange,
        retired: &mut Vec<Handle>,
    ) {
        while let HandleSlotChange::Reclaimed { parent } = change {
            let slot = &mut self.slots[index as usize];
            retired.extend(slot.handle.take());
            let reusable = slot.authority.reusable();
            self.remove_owner_index(index);
            if reusable {
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
    mod lifecycle;

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
            open_verb: "perform".into(),
            id: HandleId::new(0, 0),
            process: ProcessId::new(process),
            acting: xolotl_types::IdentityRef::ROOT,
            resource: ResourceId::new(1),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            bound_path: None,
        }
    }

    #[test]
    fn insert_and_get_roundtrip() -> anyhow::Result<()> {
        let t = HandleTable::new();
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
        let t = HandleTable::new();
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
        let t = HandleTable::new();
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
        let table = HandleTable::new();
        let root = table.insert(mk_handle(1))?;
        let child = table.insert_derived(mk_handle(2), root)?;
        let leaf = table.insert_derived(mk_handle(3), child)?;
        ensure!(table.get(leaf).is_some());
        ensure!(table.revoke(root));
        ensure!(table.get(child).is_none() && table.get(leaf).is_none());
        ensure!(table.write().get_mut(leaf).is_none());
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
        let table = HandleTable::new();
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
        let table = HandleTable::new();
        table.write().table.slots.push(Slot {
            authority: HandleSlot::vacant(u64::MAX - 1),
            owner: ProcessId::new(1),
            owner_position: 0,
            handle: None,
        });
        table.write().table.free.push(0);
        let last = table.insert(mk_handle(1))?;
        ensure!(last.generation == u64::MAX);
        ensure!(table.revoke(last) && !table.revoke(last));
        ensure!(table.read().free.is_empty());
        let fresh = table.insert(mk_handle(2))?;
        ensure!(fresh.index == 1 && fresh.generation == 1);
        ensure!(table.get(last).is_none());
        Ok(())
    }

    #[test]
    fn releasing_parent_keeps_existing_delegations_but_rejects_new_ones() -> anyhow::Result<()> {
        let table = HandleTable::new();
        let parent = table.insert(mk_handle(1))?;
        let child = table.insert_derived(mk_handle(2), parent)?;
        ensure!(table.release(parent));
        ensure!(table.get(parent).is_none());
        ensure!(table.get(child).is_some());
        ensure!(table.insert_derived(mk_handle(3), parent).is_err());
        ensure!(table.revoke(parent));
        ensure!(table.get(child).is_none());
        ensure!(table.release(child));
        Ok(())
    }

    #[test]
    fn released_anchors_drop_payloads_and_are_reclaimed_by_the_final_descendant()
    -> anyhow::Result<()> {
        let table = HandleTable::new();
        let parent = table.insert(mk_handle(1))?;
        let child = table.insert_derived(mk_handle(2), parent)?;
        let first = table.insert_derived(mk_handle(3), child)?;
        let last = table.insert_derived(mk_handle(4), child)?;

        ensure!(table.release_owned_by(ProcessId::new(1)) == 1);
        ensure!(table.release_owned_by(ProcessId::new(1)) == 0);
        ensure!(table.release(child) && !table.release(child));
        ensure!(table.get(parent).is_none() && table.write().get_mut(child).is_none());
        ensure!(table.read().slots[parent.index as usize].handle.is_none());
        ensure!(table.read().slots[child.index as usize].handle.is_none());
        ensure!(table.get(first).is_some() && table.get(last).is_some());
        ensure!(table.read().free.is_empty() && table.len() == 2);
        ensure!(table.insert_derived(mk_handle(5), child).is_err());

        ensure!(table.release(first));
        ensure!(table.get(last).is_some() && table.read().free.len() == 1);
        ensure!(table.release(last));
        ensure!(table.is_empty() && table.read().free.len() == 4);
        ensure!(!table.revoke(parent) && !table.release(last));
        let mut reused = std::collections::BTreeSet::new();
        for owner in 1..=4 {
            let replacement = table.insert(mk_handle(owner))?;
            ensure!(replacement.generation == 2 && reused.insert(replacement.index));
        }
        ensure!(table.read().slots.len() == 4);
        Ok(())
    }

    #[test]
    fn revoking_released_owners_invalidates_descendants_without_releasing_new_occupants()
    -> anyhow::Result<()> {
        let table = HandleTable::new();
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
            table.read().slots[replacement.index as usize]
                .authority
                .retains(replacement.generation)
        );
        ensure!(table.release(new_child));
        ensure!(table.read().free.len() == 3 && table.is_empty());
        Ok(())
    }

    #[test]
    fn fixed_and_allocating_tables_agree_on_release_and_anchor_retirement() -> anyhow::Result<()> {
        let mut slots = [xolotl_core::Handle::default(); 3];
        let mut fixed = xolotl_core::HandleTable::new(&mut slots);
        let hosted = HandleTable::new();
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
        ensure!(hosted.read().slots.len() == 3);
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
        let hosted = HandleTable::new();
        let mut handle = mk_handle(1);
        handle.rights = Rights::new(MethodBitmap::from_bits_retain(0b111), RightFlags::DELEGATE);
        let root = hosted.insert(handle)?;
        let fixed_root = fixed.install(1, 1, 0b111)?;
        let child = hosted.derive(
            root,
            Rights::new(MethodBitmap::from_bits_retain(0b11), RightFlags::DELEGATE),
            xolotl_types::DeriveKind::Delegate,
            ProcessId::new(2),
        )?;
        let fixed_child = fixed.derive(fixed_root, 1, 2, 0b11)?;
        let leaf = hosted.derive(
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
