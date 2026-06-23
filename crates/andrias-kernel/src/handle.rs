//! `Handle` — the compiled form of a capability, and `HandleTable` —
//! the generational slotmap it lives in.
//!
//! A Handle is the product of `open()`: a closed, executable token carrying
//! attenuated rights, a frozen [`DriverPlan`], and a policy mode:
//! `Unconditional` or `Conditional` with a residual [`PolicySnapshot`]. Lookup
//! is `O(1)` array indexing; revoke bumps a slot's generation so a stale
//! `HandleId` is rejected (ABA-safe), closing the use-after-revoke hole.

use crate::driver::DriverPlan;
use crate::policy::PolicySnapshot;
use andrias_types::{HandleId, Path, ProcessId, ResourceId, Rights};

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

/// One slot in the table: an optional handle plus a monotonically increasing
/// generation. Revoking bumps `generation`, invalidating any outstanding
/// `HandleId` that referenced the old generation.
struct Slot {
    generation: u32,
    handle: Option<Handle>,
}

/// Generational slotmap of live handles. `O(1)` lookup by index +
/// generation compare; revoke/reopen is ABA-safe.
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

    /// Insert a handle, allocating or reusing a slot, and return its
    /// generational [`HandleId`]. The caller patches `handle.id` to match.
    pub fn insert(&mut self, mut handle: Handle) -> HandleId {
        let (index, generation) = if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            (index, slot.generation)
        } else {
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: 1,
                handle: None,
            });
            (index, 1)
        };
        let id = HandleId::new(index, generation);
        handle.id = id;
        self.slots[index as usize].handle = Some(handle);
        id
    }

    /// `O(1)` lookup with generation match. Returns `None` if the slot is empty
    /// or the generation has moved on (stale id ⇒ use-after-revoke prevented).
    pub fn get(&self, id: HandleId) -> Option<&Handle> {
        let slot = self.slots.get(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.handle.as_ref()
    }

    /// Mutable lookup with the same generation check as [`HandleTable::get`].
    pub fn get_mut(&mut self, id: HandleId) -> Option<&mut Handle> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.handle.as_mut()
    }

    /// Revoke a handle: clear the slot and bump its generation so the old
    /// `HandleId` no longer resolves. The slot becomes reusable.
    pub fn revoke(&mut self, id: HandleId) -> bool {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return false;
        };
        if slot.generation != id.generation {
            return false;
        }
        slot.handle = None;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        self.free.push(id.index);
        true
    }

    /// Mark a handle Closed while keeping the slot so the id still resolves to
    /// a Closed handle (callers see the state).
    pub fn close(&mut self, id: HandleId) -> bool {
        match self.get_mut(id) {
            Some(h) => {
                h.state = HandleState::Closed;
                true
            }
            None => false,
        }
    }

    /// Number of live (occupied) handles.
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
        let ids: Vec<HandleId> = self
            .slots
            .iter()
            .filter_map(|s| s.handle.as_ref())
            .filter(|h| h.process == process)
            .map(|h| h.id)
            .collect();
        let n = ids.len();
        for id in ids {
            self.revoke(id);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{DriverPlan, EchoDriver};
    use andrias_types::{DriverId, MethodBitmap, MethodId, RightFlags};
    use anyhow::{Context, ensure};
    use std::sync::Arc;

    fn mk_handle(process: u64) -> Handle {
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(0), Arc::new(EchoDriver));
        Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(process),
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
        let id = t.insert(mk_handle(1));
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
        let id = t.insert(mk_handle(1));
        ensure!(t.revoke(id), "handle should revoke");
        // Old id no longer resolves (generation bumped).
        ensure!(t.get(id).is_none(), "revoked handle should not resolve");
        // Slot is reused; new handle gets a higher generation.
        let id2 = t.insert(mk_handle(2));
        ensure!(id2.index == id.index, "slot should be reused");
        ensure!(id2.generation != id.generation, "generation should advance");
        ensure!(t.get(id).is_none(), "stale id should still be rejected");
        ensure!(t.get(id2).is_some(), "new handle should resolve");
        Ok(())
    }

    #[test]
    fn revoke_owned_by_clears_process_handles() -> anyhow::Result<()> {
        let mut t = HandleTable::new();
        t.insert(mk_handle(1));
        t.insert(mk_handle(1));
        t.insert(mk_handle(2));
        ensure!(
            t.revoke_owned_by(ProcessId::new(1)) == 2,
            "process-owned revoke count mismatch"
        );
        ensure!(t.len() == 1, "unexpected handle count: {}", t.len());
        Ok(())
    }
}
