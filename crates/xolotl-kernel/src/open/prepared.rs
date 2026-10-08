//! Inspectable authorization and dispatch plan before a handle slot is allocated.

use super::{OpenError, handle_from_plan};
use crate::{
    driver::DriverPlan,
    handle::{FastPath, HandleTable, HandleWrite},
    policy::PolicySnapshot,
    registry::{CompiledOpenPlan, OpenRevision, Registry},
};
use xolotl_types::{HandleId, IdentityRef, Path, ProcessId, ResourceId, Rights};

/// An immutable, not-yet-installed open. Construct it with [`super::prepare_open`]
/// and inspect its authority or residual policy before allocating a handle slot.
/// Dropping it installs nothing. Installation borrows it and fails if the source
/// registry changed, including a grant, policy or resource update.
///
/// This is a live host object, not a portable authority token. It retains driver
/// and policy objects, and cannot be serialized or used to dispatch an Operation.
/// The trusted host remains responsible for the owning process's lifecycle and
/// any authority supplied through attached grants.
#[must_use = "inspect and install the prepared open, or discard it without allocating a handle"]
pub struct PreparedOpen {
    registry: Registry,
    revision: OpenRevision,
    process: ProcessId,
    acting: IdentityRef,
    open_verb: String,
    path: Path,
    plan: CompiledOpenPlan,
}

impl PreparedOpen {
    /// The kernel holds its handle-table transaction through this lifecycle
    /// check and installation. Finalization closes admission before taking that
    /// same lock to release handles, so it cannot miss a late installation.
    pub(crate) fn install_for(
        &self,
        handles: &mut HandleWrite<'_>,
        processes: &crate::ProcessTable,
    ) -> Result<HandleId, OpenError> {
        match processes.admits_handles(self.process) {
            None => return Err(OpenError::NoSuchProcess(self.process)),
            Some(false) => return Err(OpenError::ProcessUnavailable(self.process)),
            Some(true) => {}
        }
        self.install_locked(handles)
    }

    pub(super) fn new(
        registry: Registry,
        revision: OpenRevision,
        process: ProcessId,
        acting: IdentityRef,
        open_verb: String,
        path: Path,
        plan: CompiledOpenPlan,
    ) -> Self {
        Self {
            registry,
            revision,
            process,
            acting,
            open_verb,
            path,
            plan,
        }
    }

    /// Process that will own the installed handle.
    pub fn process(&self) -> ProcessId {
        self.process
    }

    /// Identity admitted by open-time policy.
    pub fn acting(&self) -> IdentityRef {
        self.acting
    }

    /// Original capability category, retained independently of callable rights.
    pub fn open_verb(&self) -> &str {
        &self.open_verb
    }

    /// Resolved local resource identifier.
    pub fn resource(&self) -> ResourceId {
        self.plan.resource
    }

    /// Concrete path used for authorization and driver dispatch.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Requested method and propagation rights, checked against the selected grant.
    pub fn rights(&self) -> Rights {
        self.plan.rights
    }

    /// Frozen method contracts and driver bindings. Inspecting them does not
    /// allocate a handle or evaluate any residual policy.
    pub fn driver_plan(&self) -> &DriverPlan {
        &self.plan.driver_plan
    }

    /// Ordered residual checks; `None` means unconditional admission at open.
    /// Inspect residual authority before installation without evaluating checks.
    pub fn policy(&self) -> Option<&PolicySnapshot> {
        match &self.plan.fast_path {
            FastPath::Unconditional => None,
            FastPath::Conditional(policy) => Some(policy),
        }
    }

    /// Allocate a fresh handle under a short registry revision guard. No source
    /// policy callbacks or residual checks run here. The revision check and slot
    /// insertion are atomic with respect to registry mutations; updates afterward
    /// do not rewrite an already installed handle's frozen semantics. The table
    /// manages synchronization and releases its lock before destroying any
    /// retired driver or policy captures. The prepared plan remains reusable.
    pub fn install(&self, handles: &HandleTable) -> Result<HandleId, OpenError> {
        self.install_locked(&mut handles.write())
    }

    pub(crate) fn install_locked(
        &self,
        handles: &mut HandleWrite<'_>,
    ) -> Result<HandleId, OpenError> {
        self.registry
            .with_open_revision(self.revision, || {
                handles.insert(handle_from_plan(
                    self.process,
                    self.acting,
                    self.open_verb.clone(),
                    Some(self.path.clone()),
                    self.plan.clone(),
                ))
            })
            .ok_or(OpenError::RegistryChanged)?
            .map_err(OpenError::from)
    }
}
