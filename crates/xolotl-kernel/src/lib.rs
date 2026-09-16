#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "host"), no_std)]

//! Cooperative execution, invocation, scope and stream composition.
//!
//! The default `no_std + alloc` build runs linked programs with caller-owned
//! storage and static driver, Fact, account, and cooperative scheduling adapters.
//! It supplies no clock, thread, lock, or storage backend. `host` adds Tokio:
//! opened dispatch plans, process ownership, state integration and optional
//! durable execution. Both embeddings use the same admission and scope rules,
//! alongside the allocation-free control machine in `xolotl-core`.

extern crate alloc;

#[cfg(feature = "host")]
pub mod bootstrap;
#[cfg(feature = "host")]
pub mod dataplane;
#[cfg(feature = "host")]
pub mod driver;
#[cfg(feature = "host")]
pub mod execution_ids;
#[cfg(feature = "host")]
pub mod executor;
#[cfg(feature = "host")]
pub mod fact;
#[cfg(feature = "host")]
pub mod handle;
#[cfg(feature = "host")]
pub mod host;
pub mod invocation;
#[cfg(feature = "host")]
pub mod kernel;
#[cfg(feature = "host")]
pub mod open;
#[cfg(feature = "host")]
pub mod policy;
#[cfg(feature = "host")]
pub mod process;
#[cfg(feature = "host")]
pub mod recovery;
#[cfg(feature = "host")]
pub mod registry;
pub mod runtime;
#[cfg(feature = "host")]
pub mod scheduler;
pub mod scope;
#[cfg(feature = "host")]
pub mod step;
pub mod stream;
pub mod values;

#[cfg(feature = "host")]
pub use bootstrap::{
    Bootstrap, BootstrapError, CompiledRequestGrantTemplate, GatewayAudit, MethodSpec,
    ProcessCleanupFailure, ProcessCleanupReport, RequestGrantTemplate, RequestProcess,
    SpawnedActor,
};
#[cfg(feature = "durable")]
pub use bootstrap::{DurableRecovery, DurableRecoveryConfig, DurableRecoveryReport};
#[cfg(feature = "host")]
pub use dataplane::DataPlane;
#[cfg(feature = "host")]
pub use driver::{
    DispatchEntry, Driver, DriverContext, DriverDescriptor, DriverError, DriverPlan, DynDriver,
    EchoDriver, FnDriver, InputAdmission, InputRejection,
};
#[cfg(feature = "host")]
pub use execution_ids::{
    ExecutionIdError, ExecutionIdRange, ExecutionIdSource, ExecutionIds, InMemoryExecutionIdSource,
};
#[cfg(feature = "host")]
pub use executor::{
    ExecutionBuffers, ExecutionConfig, ExecutionLayout, Executor, PreparedProgram, intern_identity,
    now_millis,
};
#[cfg(feature = "host")]
pub use fact::{
    FACT_BROADCAST_CAPACITY, FactError, FactLookup, FactLookupResult, FactOrder, FactPage,
    FactQuery, FactSink, FactStore, FactStream, InMemoryFactStore, SharedFactStore,
};
#[cfg(feature = "host")]
pub use handle::{FastPath, Handle, HandleState, HandleTable};
pub use invocation::{GrantedMethod, Invocation, InvocationOptions};
#[cfg(feature = "host")]
pub use kernel::Kernel;
#[cfg(feature = "host")]
pub use open::{OpenError, OpenRequest, derive_handle, open_resource};
#[cfg(feature = "host")]
pub use policy::{
    ApprovalCheck, ApprovalDecision, ApprovalRegistry, CapabilityPolicy, CheckCtx, CompiledCheck,
    ConstraintCheck, OpenContext, PolicyCompileError, PolicyDecision, PolicySnapshot, PolicySource,
    RateLimitCheck,
};
#[cfg(feature = "host")]
pub use process::{ProcessAdmissionError, ProcessCapacityError, ProcessTable};
#[cfg(feature = "host")]
pub use recovery::{
    QuarantineAction, QuarantineEntry, RecoveryLimits, RecoveryReport, classify_recovery,
    recover_process,
};
#[cfg(feature = "host")]
pub use registry::{AdmissionError, Registry, ResolveError};
pub use runtime::{Cooperate, Cooperative, LinkedExecution, PendingCall, RequestDriver};
#[cfg(feature = "host")]
pub use scheduler::{Queue, Scheduler};
pub use scope::{CleanupScope, Scope, ScopeFinalize, ScopeRestoreError};
#[cfg(feature = "host")]
pub use step::{LoaderRevision, ProgramLoader, StepBinding, StepFn, StepModule, StepModuleError};
pub use stream::StreamSendError;
pub use values::RuntimeValues;
pub use xolotl_types::{DriverOutput, DriverUsage, MethodContract, UsageDimension};
