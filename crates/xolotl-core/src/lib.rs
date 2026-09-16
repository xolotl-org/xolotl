#![no_std]
#![forbid(unsafe_code)]

//! Host-driven execution without an allocator, threads, locks, clocks or I/O.
//!
//! The host owns program images, task storage and values. [`Execution::advance`]
//! performs bounded work and yields requests; [`Execution::complete`] delivers
//! their results. Using allocating value implementations is a host choice, not
//! a requirement of the machine. No background work occurs while it is idle.

mod analysis;
mod authority;
mod frame;
mod link;
mod machine;
mod program;
mod stream;

pub use analysis::{AnalysisSlot, ResourceRequirements};
pub use authority::{AuthorityError, Handle, HandleKey, HandleSlot, HandleSlotChange, HandleTable};
pub use frame::{Frame, FramePoolMeta};
pub use link::{ImportBinding, LinkedProgram};
pub use machine::{
    Advance, CHECKPOINT_VERSION, Checkpoint, CheckpointMeta, Execution, ExecutionLimits, HostEvent,
    Request, Task,
};
pub use program::{Fault, IMAGE_VERSION, Join, Node, NodeKind, ProgramImage, Values};
pub use stream::{Channel, Receive, SendError};
