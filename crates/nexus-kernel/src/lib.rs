#![forbid(unsafe_code)]

//! `nexus-kernel` — the Direction-C kernel (syscall + ExecutionGraph).
//!
//! The control plane is a compiler: `open()` compiles a Grant against a
//! Resource into a [`Handle`](handle::Handle). The data plane is a VM that
//! executes [`Operation`](nexus_types::Operation)s through that handle's frozen
//! [`DriverPlan`](driver::DriverPlan), recording a [`Fact`](nexus_types::Fact).
//! The [`Executor`](executor::Executor) advances an
//! [`ExecutionGraph`](nexus_graph::ExecutionGraph) cursor (§13.4).
//!
//! Module map:
//!
//! - [`driver`]    — `Driver` trait, `DriverContext`, `DriverPlan` (§7).
//! - [`policy`]    — `PolicySnapshot` / `CompiledCheck` residual checks (§8).
//! - [`handle`]    — `Handle`, `FastPath`, generational `HandleTable` (§5).
//! - [`registry`]  — six control-plane registries + name resolution (§10).
//! - [`open`]      — `open()` = compile → Handle (§5.2).
//! - [`fact`]      — `FactSink` with ReplayClass barriers (§9.3).
//! - [`dataplane`] — `DataPlane::execute` fast/slow path (§6, §11).
//! - [`step`]      — named, pure step continuations (§13.3).
//! - [`executor`]  — graph stepper (§13.4).
//! - [`scheduler`] — three-queue scheduler (§13.5).
//! - [`process`]   — process table, spawn, finalize (§14).
//! - [`recovery`]  — replay + quarantine (§15).
//! - [`bootstrap`] — boot phases + assembly primitives (§14.1).
//! - [`kernel`]    — the assembled `Kernel`.

pub mod bootstrap;
pub mod dataplane;
pub mod driver;
pub mod executor;
pub mod fact;
pub mod handle;
pub mod kernel;
pub mod open;
pub mod policy;
pub mod process;
pub mod recovery;
pub mod registry;
pub mod scheduler;
pub mod step;

pub use bootstrap::{Bootstrap, BootstrapError, GatewayAudit, MethodSpec};
pub use dataplane::{DataPlane, ExecOutput};
pub use driver::{
    DispatchEntry, Driver, DriverContext, DriverDescriptor, DriverError, DriverPlan, DynDriver,
    EchoDriver, FnDriver,
};
pub use executor::{ExecError, Executor, intern_identity, now_millis};
pub use fact::{FactError, FactSink, FactStore, InMemoryFactStore, SharedFactStore};
pub use handle::{FastPath, Handle, HandleState, HandleTable};
pub use kernel::Kernel;
pub use open::{OpenError, OpenRequest, derive_handle, open_resource};
pub use policy::{
    ApprovalCheck, ApprovalDecision, ApprovalRegistry, CapabilityPolicy, CheckCtx, CompiledCheck,
    ConstraintCheck, OpenContext, PolicyCompileError, PolicyDecision, PolicySnapshot, PolicySource,
    RateLimitCheck,
};
pub use process::{ProcessEntry, ProcessTable};
pub use recovery::{
    QuarantineAction, QuarantineEntry, RecoveryReport, ReplayMap, Snapshot, classify_recovery,
    recover_process,
};
pub use registry::{AdmissionError, Registry, ResolveError};
pub use scheduler::{Queue, Scheduler};
pub use step::{StepFn, StepTable};
