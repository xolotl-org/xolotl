#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "host"), no_std)]

//! Cooperative execution, invocation, scope and stream composition.
//!
//! The default `no_std + alloc` build runs linked programs with caller-owned
//! storage and static driver, Fact, account, and cooperative scheduling adapters.
//! It supplies no clock, thread, lock, or storage backend. `host` adds Tokio:
//! opened dispatch plans, process ownership and state integration.
//! Both embeddings use the same admission and scope rules,
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
#[cfg(feature = "host")]
pub mod identity;
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
pub mod registry;
pub mod runtime;
#[cfg(feature = "host")]
mod runtime_domain;
pub mod scope;
#[cfg(feature = "host")]
pub mod step;
pub mod stream;
pub mod values;

#[cfg(feature = "host")]
pub use bootstrap::{
    Bootstrap, BootstrapError, CompiledRequestGrantTemplate, GatewayAudit, MethodSpec,
    ProcessCleanupFailure, ProcessCleanupReport, RequestFinishError, RequestGrantTemplate,
    RequestProcess, SpawnedActor,
};
#[cfg(feature = "host")]
pub use dataplane::FactIoMode;
#[cfg(feature = "host")]
pub use dataplane::{DataPlane, RequestAuthorizer};
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
    ExecutionBuffers, ExecutionConfig, ExecutionLayout, Executor, HandleBindingError,
    PreparedProgram,
};
#[cfg(feature = "host")]
pub use fact::{
    FACT_BROADCAST_CAPACITY, FactError, FactErrorKind, FactLookup, FactLookupResult, FactOrder,
    FactPage, FactQuery, FactRetentionLimits, FactRetentionUsage, FactSink, FactStore, FactStream,
    InMemoryFactStore, SharedFactStore,
};
#[cfg(feature = "host")]
pub use handle::{FastPath, Handle, HandleTable, WeakHandleTable};
#[cfg(feature = "host")]
pub use identity::{IdentityDirectory, IdentityError, IdentityRegistry, InMemoryIdentityDirectory};
pub use invocation::{GrantedMethod, Invocation, InvocationOptions};
#[cfg(feature = "host")]
pub use kernel::{Kernel, KernelBuilder};
#[cfg(feature = "host")]
pub use open::{OpenError, OpenRequest, PreparedOpen, open_resource, prepare_open};
#[cfg(feature = "host")]
pub use policy::{
    ApprovalCheck, ApprovalDecision, ApprovalRegistry, CapabilityPolicy, CheckCtx, CompiledCheck,
    ConstraintCheck, OpenContext, PolicyCompileError, PolicyDecision, PolicySnapshot, PolicySource,
    RateLimitCheck,
};
#[cfg(feature = "host")]
pub use process::{
    CleanupProgress, CleanupTicket, ProcessAdmissionError, ProcessCapacityError,
    ProcessFinalizationReport, ProcessTable,
};
#[cfg(feature = "host")]
pub use registry::{AdmissionError, Registry, ResolveError, ResourceUpsert};
pub use runtime::{
    Cooperate, Cooperative, LinkedExecution, PendingCall, RequestCompletion, RequestDriver,
};
#[cfg(feature = "host")]
pub use runtime_domain::RuntimeAssemblyError;
pub use scope::{CleanupScope, Scope, ScopeFinalize};
#[cfg(feature = "host")]
pub use step::{LoaderRevision, ProgramLoader, StepBinding, StepFn, StepModule, StepModuleError};
pub use stream::StreamSendError;
pub use values::RuntimeValues;
pub use xolotl_types::{DriverOutput, DriverUsage, MethodContract, UsageDimension};
