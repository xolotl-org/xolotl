//! Import linking against process-owned capability handles.

use crate::{Fault, HandleKey, HandleTable, ProgramImage};

/// One resolved import. Interface/schema negotiation happens before installing
/// this binding; the method right and handle generation remain load-bearing.
#[derive(Clone, Copy, Debug)]
pub struct ImportBinding {
    /// Handle installed by the trusted host after interface negotiation.
    pub handle: HandleKey,
    /// Method bit checked immediately before dispatch.
    pub method: u8,
}

/// Borrowed linked image. It contains no registry, names, locks, or allocator.
pub struct LinkedProgram<'a, V, E> {
    /// Validated instruction image used by the execution machine.
    pub image: ProgramImage<'a, V, E>,
    bindings: &'a [ImportBinding],
    owner: u64,
}

impl<'a, V, E> LinkedProgram<'a, V, E> {
    /// Validate every import against the owner's current handle rights.
    pub fn new(
        image: ProgramImage<'a, V, E>,
        bindings: &'a [ImportBinding],
        handles: &HandleTable<'_>,
        owner: u64,
    ) -> Result<Self, Fault> {
        image.validate()?;
        if bindings.len() != image.imports {
            return Err(Fault::InvalidImport);
        }
        let linked = Self {
            image,
            bindings,
            owner,
        };
        for import in 0..bindings.len() {
            linked.authorize(import as u32, handles)?;
        }
        Ok(linked)
    }

    /// Revalidate immediately before dispatch, including after suspension.
    pub fn authorize(&self, import: u32, handles: &HandleTable<'_>) -> Result<u32, Fault> {
        let binding = self
            .bindings
            .get(import as usize)
            .ok_or(Fault::InvalidImport)?;
        handles
            .authorize(binding.handle, self.owner, binding.method)
            .map_err(|_error| Fault::Authority)
    }
}
