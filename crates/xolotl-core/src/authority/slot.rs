//! Storage-independent generation and delegation ancestry rules.

use super::{AuthorityError, HandleKey};

/// Lifecycle metadata shared by fixed storage and allocating handle tables.
/// Rights, owners, resources and dispatch payloads belong to the enclosing table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HandleSlot {
    generation: u64,
    state: SlotState,
    parent: Option<HandleKey>,
    children: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SlotState {
    #[default]
    Vacant,
    Active,
    Released,
}

/// Storage work required after releasing or revoking slot authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleSlotChange {
    /// The generation was already released, revoked, or replaced.
    Unchanged,
    /// Metadata remains retained; a released owner no longer needs its payload.
    Retained,
    /// Reclaim this slot and detach its one reference to the given parent.
    Reclaimed {
        /// Parent reference held by the reclaimed slot.
        parent: Option<HandleKey>,
    },
}

impl HandleSlot {
    /// Restore a vacant slot while preserving its greatest installed generation.
    /// A slot whose generation reached `u64::MAX` remains permanently retired.
    pub const fn vacant(generation: u64) -> Self {
        Self {
            generation,
            state: SlotState::Vacant,
            parent: None,
            children: 0,
        }
    }

    /// Whether this slot may admit another handle without reusing a generation.
    pub const fn reusable(&self) -> bool {
        matches!(self.state, SlotState::Vacant) && self.generation < u64::MAX
    }

    /// Greatest generation installed in this slot, including after revocation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Install a fresh generation. The table must authorize a parent first.
    pub fn install(&mut self, parent: Option<HandleKey>) -> Result<u64, AuthorityError> {
        if !self.reusable() {
            return Err(AuthorityError::Capacity);
        }
        if parent.is_some_and(|key| key.generation == 0) {
            return Err(AuthorityError::Stale);
        }
        self.generation += 1;
        self.state = SlotState::Active;
        self.parent = parent;
        Ok(self.generation)
    }

    /// Whether this generation still owns the slot, independent of its ancestors.
    pub const fn matches(&self, generation: u64) -> bool {
        matches!(self.state, SlotState::Active) && self.generation == generation
    }

    /// Active handles and released ancestors retain the same generation.
    pub const fn retains(&self, generation: u64) -> bool {
        !matches!(self.state, SlotState::Vacant) && self.generation == generation
    }

    /// Register an admitted direct child while the owner still holds authority.
    /// The enclosing table must validate the complete ancestry before admission.
    pub fn attach_child(&mut self, generation: u64) -> Result<(), AuthorityError> {
        if !self.matches(generation) {
            return Err(AuthorityError::Stale);
        }
        self.children = self
            .children
            .checked_add(1)
            .ok_or(AuthorityError::Capacity)?;
        Ok(())
    }

    /// Release local authority, preserving only the anchor needed by descendants.
    pub fn release(&mut self, generation: u64) -> HandleSlotChange {
        if !self.matches(generation) {
            return HandleSlotChange::Unchanged;
        }
        self.state = SlotState::Released;
        if self.children == 0 {
            self.reclaim()
        } else {
            HandleSlotChange::Retained
        }
    }

    /// Invalidate this generation immediately, including released ancestors.
    /// Late descendant detachments cannot affect a subsequent occupant.
    pub fn revoke(&mut self, generation: u64) -> HandleSlotChange {
        if !self.retains(generation) {
            return HandleSlotChange::Unchanged;
        }
        self.reclaim()
    }

    /// Drop one reclaimed child's reference. Reclaim a released final ancestor.
    /// The table calls this exactly once per reclaimed child generation.
    pub fn detach_child(&mut self, generation: u64) -> HandleSlotChange {
        if !self.retains(generation) || self.children == 0 {
            return HandleSlotChange::Unchanged;
        }
        self.children -= 1;
        if self.children == 0 && matches!(self.state, SlotState::Released) {
            self.reclaim()
        } else {
            HandleSlotChange::Retained
        }
    }

    fn reclaim(&mut self) -> HandleSlotChange {
        self.state = SlotState::Vacant;
        self.children = 0;
        HandleSlotChange::Reclaimed {
            parent: self.parent.take(),
        }
    }

    /// Validate the local generation and every retained delegation ancestor.
    /// `capacity` bounds traversal even if imported metadata contains a cycle.
    /// The table must keep one consistent view throughout the lookup calls.
    pub fn validate<'a>(
        &self,
        generation: u64,
        capacity: usize,
        mut lookup: impl FnMut(HandleKey) -> Option<&'a Self>,
    ) -> Result<(), AuthorityError> {
        if !self.matches(generation) {
            return Err(AuthorityError::Stale);
        }
        let mut parent = self.parent;
        let mut remaining = capacity;
        while let Some(key) = parent {
            remaining = remaining.checked_sub(1).ok_or(AuthorityError::Stale)?;
            let ancestor = lookup(key).ok_or(AuthorityError::Stale)?;
            if !ancestor.retains(key.generation) {
                return Err(AuthorityError::Stale);
            }
            parent = ancestor.parent;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn generations_are_never_reused_or_wrapped() -> anyhow::Result<()> {
        let mut slot = HandleSlot::vacant(u64::MAX - 1);
        ensure!(slot.install(None)? == u64::MAX);
        ensure!(!slot.reusable());
        ensure!(slot.revoke(u64::MAX) == HandleSlotChange::Reclaimed { parent: None });
        ensure!(slot.revoke(u64::MAX) == HandleSlotChange::Unchanged);
        ensure!(!slot.reusable());
        ensure!(slot.install(None) == Err(AuthorityError::Capacity));
        ensure!(slot.generation() == u64::MAX);
        Ok(())
    }

    #[test]
    fn invalid_ancestors_and_cycles_are_rejected() -> anyhow::Result<()> {
        let mut slot = HandleSlot::default();
        let key = HandleKey {
            slot: 0,
            generation: 1,
        };
        slot.install(Some(key))?;
        ensure!(slot.validate(1, 1, |_| Some(&slot)) == Err(AuthorityError::Stale));
        ensure!(slot.validate(1, 1, |_| None) == Err(AuthorityError::Stale));
        let replacement = HandleSlot::vacant(2);
        ensure!(slot.validate(1, 1, |_| Some(&replacement)) == Err(AuthorityError::Stale));
        Ok(())
    }

    #[test]
    fn release_preserves_delegations_until_the_final_child_detaches() -> anyhow::Result<()> {
        let mut parent = HandleSlot::default();
        let generation = parent.install(None)?;
        parent.attach_child(generation)?;
        parent.attach_child(generation)?;
        let mut child = HandleSlot::default();
        child.install(Some(HandleKey {
            slot: 0,
            generation,
        }))?;

        ensure!(parent.release(generation) == HandleSlotChange::Retained);
        ensure!(!parent.matches(generation) && parent.retains(generation));
        ensure!(parent.attach_child(generation) == Err(AuthorityError::Stale));
        ensure!(parent.validate(generation, 2, |_| None) == Err(AuthorityError::Stale));
        ensure!(child.validate(1, 2, |_| Some(&parent)) == Ok(()));
        ensure!(parent.release(generation) == HandleSlotChange::Unchanged);
        ensure!(parent.detach_child(generation) == HandleSlotChange::Retained);
        ensure!(parent.detach_child(generation) == HandleSlotChange::Reclaimed { parent: None });
        ensure!(parent.detach_child(generation) == HandleSlotChange::Unchanged);
        ensure!(parent.reusable());
        Ok(())
    }

    #[test]
    fn stale_child_detachments_cannot_release_a_new_generation() -> anyhow::Result<()> {
        let mut slot = HandleSlot::default();
        let old = slot.install(None)?;
        slot.attach_child(old)?;
        slot.revoke(old);
        let new = slot.install(None)?;
        slot.attach_child(new)?;
        ensure!(slot.release(new) == HandleSlotChange::Retained);
        ensure!(slot.detach_child(old) == HandleSlotChange::Unchanged);
        ensure!(slot.retains(new));
        ensure!(slot.detach_child(new) == HandleSlotChange::Reclaimed { parent: None });
        Ok(())
    }

    #[test]
    fn child_count_exhaustion_does_not_change_authority() -> anyhow::Result<()> {
        let mut slot = HandleSlot::default();
        let generation = slot.install(None)?;
        slot.children = usize::MAX;
        let previous = slot;
        ensure!(slot.attach_child(generation) == Err(AuthorityError::Capacity));
        ensure!(slot == previous);
        Ok(())
    }
}
