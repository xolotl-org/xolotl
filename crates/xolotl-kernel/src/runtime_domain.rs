//! Identity of the mutable runtime tables assembled by one Kernel.

use std::sync::Arc;

/// A private, non-serializable identity shared by one Kernel's authority tables.
/// Independent tables have no domain and can still be composed by a trusted host.
#[derive(Clone)]
pub(crate) struct RuntimeDomain(Arc<()>);

impl RuntimeDomain {
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// A host attempted to combine incompatible mutable runtime tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeAssemblyError {
    /// A Kernel-owned table cannot be mixed with an independently created table.
    #[error("runtime tables are only partially bound to a Kernel")]
    PartiallyBound,
    /// The supplied Kernel-owned tables came from different Kernel assemblies.
    #[error("runtime tables belong to different Kernels")]
    DifferentRuntime,
    /// A data plane already attached to one process table cannot be rebound silently.
    #[error("data plane is attached to a different process table")]
    DifferentProcessTable,
    /// A process table and data plane must observe one host clock.
    #[error("runtime components use different host clock domains")]
    DifferentClockDomain,
}

pub(crate) fn check_runtime_domains(
    domains: &[Option<RuntimeDomain>],
) -> Result<(), RuntimeAssemblyError> {
    if domains.iter().all(Option::is_none) {
        return Ok(());
    }
    if domains.iter().any(Option::is_none) {
        return Err(RuntimeAssemblyError::PartiallyBound);
    }
    if let Some(first) = domains[0].as_ref()
        && domains
            .iter()
            .skip(1)
            .all(|domain| domain.as_ref().is_some_and(|domain| first.same_as(domain)))
    {
        Ok(())
    } else {
        Err(RuntimeAssemblyError::DifferentRuntime)
    }
}
