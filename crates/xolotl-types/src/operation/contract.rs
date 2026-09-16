//! Method admission compiled before an invocation reaches the data plane.

use crate::{CostModel, Method, OutputModeSet, ProcessId, ReplayClass};

/// Immutable execution rules for one method in an opened dispatch plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodContract {
    /// Bit position in the resource's method rights.
    pub method_index: u32,
    /// Replay and write-ahead requirements of the method.
    pub replay: ReplayClass,
    /// Output modes admitted by the method.
    pub supports: OutputModeSet,
    /// Cost estimate used before dispatch and reconciled with measured usage.
    pub cost: CostModel,
    /// Whether list inputs represent independently billed batch elements.
    pub batchable: bool,
    /// Whether the method may run during scope finalization.
    pub finalize_allowed: bool,
    /// Additional resource owner permitted to call this method during cleanup.
    /// Trusted binding fixes this identity; deriving a handle does not change it.
    pub cleanup_owner: Option<ProcessId>,
    /// Whether protected input is forbidden at this invocation boundary.
    pub requires_unprotected_input: bool,
}

impl MethodContract {
    /// Declare a method with no monetary cost, batching or finalizer permission.
    pub const fn new(method_index: u32, replay: ReplayClass, supports: OutputModeSet) -> Self {
        Self {
            method_index,
            replay,
            supports,
            cost: CostModel::FREE,
            batchable: false,
            finalize_allowed: false,
            cleanup_owner: None,
            requires_unprotected_input: false,
        }
    }

    /// Freeze an admitted interface method's execution rules at open time.
    pub fn from_method(method_index: u32, method: &Method) -> Self {
        Self {
            method_index,
            replay: method.replay,
            supports: method.supports,
            cost: method.cost,
            batchable: method.batchable,
            finalize_allowed: method.finalize_allowed,
            cleanup_owner: None,
            requires_unprotected_input: method.requires_unprotected_input,
        }
    }

    /// Whether the caller may use this method under a trusted cleanup context.
    /// Lifecycle admission, handle rights and policy still apply separately.
    pub fn permits_cleanup(&self, process: ProcessId) -> bool {
        self.finalize_allowed || self.cleanup_owner == Some(process)
    }
}
