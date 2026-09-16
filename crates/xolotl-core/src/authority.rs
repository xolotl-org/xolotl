//! Fixed-capacity, generational capability handles.

mod slot;
pub use slot::{HandleSlot, HandleSlotChange};

/// A process-owned handle slot. Default slots are vacant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Handle {
    owner: u64,
    resource: u32,
    methods: u64,
    slot: HandleSlot,
}

/// Unforgeable authority comes from table validation, not possession of a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleKey {
    /// Slot in the host's table.
    pub slot: u32,
    /// Generation of the installed handle.
    pub generation: u64,
}

/// Capability operation rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    /// No reusable slots remain.
    Capacity,
    /// The key names a vacant, retired, or replaced slot.
    Stale,
    /// The caller does not own this handle.
    Owner,
    /// The requested method or delegation exceeds granted rights.
    Rights,
}

impl core::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl core::error::Error for AuthorityError {}

/// A view over storage supplied by a trusted host.
pub struct HandleTable<'a> {
    slots: &'a mut [Handle],
}

impl<'a> HandleTable<'a> {
    /// Attach existing storage, retaining its live handles and generations.
    pub fn new(slots: &'a mut [Handle]) -> Self {
        Self { slots }
    }

    /// Install host-authorized rights. Programs must use [`Self::derive`].
    pub fn install(
        &mut self,
        owner: u64,
        resource: u32,
        methods: u64,
    ) -> Result<HandleKey, AuthorityError> {
        self.install_with_parent(owner, resource, methods, None)
    }

    fn install_with_parent(
        &mut self,
        owner: u64,
        resource: u32,
        methods: u64,
        parent: Option<HandleKey>,
    ) -> Result<HandleKey, AuthorityError> {
        let (index, slot) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.slot.reusable())
            .ok_or(AuthorityError::Capacity)?;
        let index = u32::try_from(index).map_err(|_error| AuthorityError::Capacity)?;
        let mut authority = slot.slot;
        let generation = authority.install(parent)?;
        if let Some(parent) = parent {
            self.slots[parent.slot as usize]
                .slot
                .attach_child(parent.generation)?;
        }
        let slot = &mut self.slots[index as usize];
        slot.slot = authority;
        slot.owner = owner;
        slot.resource = resource;
        slot.methods = methods;
        Ok(HandleKey {
            slot: index,
            generation,
        })
    }

    fn local(&self, key: HandleKey, owner: u64) -> Result<&Handle, AuthorityError> {
        let slot = self
            .slots
            .get(key.slot as usize)
            .ok_or(AuthorityError::Stale)?;
        if !slot.slot.retains(key.generation) {
            return Err(AuthorityError::Stale);
        }
        if slot.owner != owner {
            return Err(AuthorityError::Owner);
        }
        Ok(slot)
    }

    fn get(&self, key: HandleKey, owner: u64) -> Result<&Handle, AuthorityError> {
        let slot = self
            .slots
            .get(key.slot as usize)
            .ok_or(AuthorityError::Stale)?;
        slot.slot
            .validate(key.generation, self.slots.len(), |key| {
                self.slots.get(key.slot as usize).map(|handle| &handle.slot)
            })?;
        if slot.owner != owner {
            return Err(AuthorityError::Owner);
        }
        Ok(slot)
    }

    /// Check ownership, generations, delegation ancestry and method rights.
    pub fn authorize(&self, key: HandleKey, owner: u64, method: u8) -> Result<u32, AuthorityError> {
        let slot = self.get(key, owner)?;
        let bit = 1u64
            .checked_shl(u32::from(method))
            .ok_or(AuthorityError::Rights)?;
        if slot.methods & bit == 0 {
            return Err(AuthorityError::Rights);
        }
        Ok(slot.resource)
    }

    /// Delegate only a subset of the parent's method rights.
    pub fn derive(
        &mut self,
        parent: HandleKey,
        owner: u64,
        child: u64,
        methods: u64,
    ) -> Result<HandleKey, AuthorityError> {
        let slot = self.get(parent, owner)?;
        if methods & !slot.methods != 0 {
            return Err(AuthorityError::Rights);
        }
        let resource = slot.resource;
        self.install_with_parent(child, resource, methods, Some(parent))
    }

    /// Release this owner's handle while already delegated authority remains valid.
    /// Metadata is reclaimed when the final retained descendant releases it.
    pub fn release(&mut self, key: HandleKey, owner: u64) -> Result<(), AuthorityError> {
        self.local(key, owner)?;
        let change = self.slots[key.slot as usize].slot.release(key.generation);
        if change == HandleSlotChange::Unchanged {
            return Err(AuthorityError::Stale);
        }
        self.reclaim_ancestors(change);
        Ok(())
    }

    /// Revoke a handle and invalidate its descendants. Descendants can still be
    /// explicitly revoked to reclaim their slots. Exhausted generations are retired.
    pub fn revoke(&mut self, key: HandleKey, owner: u64) -> Result<(), AuthorityError> {
        self.local(key, owner)?;
        let change = self.slots[key.slot as usize].slot.revoke(key.generation);
        self.reclaim_ancestors(change);
        Ok(())
    }

    fn reclaim_ancestors(&mut self, mut change: HandleSlotChange) {
        while let HandleSlotChange::Reclaimed {
            parent: Some(parent),
        } = change
        {
            let Some(slot) = self.slots.get_mut(parent.slot as usize) else {
                return;
            };
            change = slot.slot.detach_child(parent.generation);
        }
    }
}
