#![forbid(unsafe_code)]

//! `nexus-kernel` - the Nexus runtime kernel.
//!
//! The control plane is a compiler: `open()` compiles a Grant against a
//! Resource into a [`Handle`]. The data plane is a VM that
//! executes [`Operation`](nexus_types::Operation)s through that handle's frozen
//! [`DriverPlan`], recording a [`Fact`](nexus_types::Fact).
//! The [`Executor`] advances an
//! [`ExecutionGraph`](nexus_graph::ExecutionGraph) cursor.
//!
//! Module map:
//!
//! - [`driver`]    — `Driver` trait, `DriverContext`, `DriverPlan`.
//! - [`policy`]    — `PolicySnapshot` / `CompiledCheck` residual checks.
//! - [`handle`]    — `Handle`, `FastPath`, generational `HandleTable`.
//! - [`registry`]  — six control-plane registries + name resolution.
//! - [`open`]      — `open()` = compile to Handle.
//! - [`fact`]      — `FactSink` with ReplayClass barriers.
//! - [`dataplane`] — `DataPlane::execute` fast/slow path.
//! - [`step`]      — named, pure step continuations.
//! - [`executor`]  — graph stepper.
//! - [`scheduler`] — three-queue scheduler.
//! - [`process`]   — process table, spawn, finalize.
//! - [`recovery`]  — replay + quarantine.
//! - [`bootstrap`] — startup assembly primitives.
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

pub use bootstrap::{
    Bootstrap, BootstrapError, CompiledRequestGrantTemplate, GatewayAudit, MethodSpec,
    ProcessStepBinding, RequestGrantTemplate, SpawnedActor,
};
pub use dataplane::{DataPlane, ExecOutput, ExecuteParams};
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
pub use process::ProcessTable;
pub use recovery::{
    QuarantineAction, QuarantineEntry, RecoveryReport, ReplayMap, Snapshot, classify_recovery,
    recover_process,
};
pub use registry::{AdmissionError, Registry, ResolveError};
pub use scheduler::{Queue, Scheduler};
pub use step::{StepFn, StepInstallError};
