//! Public types for the Nexus runtime (Direction C).
//!
//! This crate is leaf-level and **wasm-safe** (§24.1): no async / IO, no
//! kernel state — just the data that flows through the system, plus the
//! control-plane *descriptors* the console and wire protocols reference. The
//! live runtime objects that carry dispatch tables (`Handle` / `DriverPlan`)
//! live in `nexus-kernel`; the execution IR (`ExecutionGraph` / `Do<A>`) lives
//! in `nexus-graph`.
//!
//! Module map:
//!
//! - [`path`]   — the universal `Path` addressing primitive.
//! - [`value`]  — `Value` (incl. `Blob`/`Tensor`/`Frame`), refs, `Failure`.
//! - [`ids`]    — compact data-plane identifiers (`ProcessId`, `HandleId`, …).
//! - [`replay`] — `Purity` (declared) and `ReplayClass` (derived).
//! - [`grant`]  — `Grant`/`Rights`/`ConstraintSet`: the capability *source* form (§5.1).
//! - [`resource`] — `Resource`/`Interface`/`Method`/`Binding` descriptors (§4, §7).
//! - [`operation`] — `Operation`/`OperationId`/`Fact` data-plane records (§6, §9).
//! - [`process`]   — `Process`/lifecycle/`Outcome` (§3, §14).
//! - [`extension`] — extension installation/projection manifests and wire frames (§16).
//! - [`device`]    — provider summary DTOs (`Transport`/`TrustLevel`/…).
//! - [`chat`]      — chat message DTOs used by inference.
//! - [`skill`]     — `Skill`/`SkillScope`: knowledge + procedure unit (§20.6).
//! - [`validate`]  — path semantic validation.

pub mod audit;
pub mod cap;
pub mod chat;
pub mod device;
pub mod extension;
pub mod grant;
pub mod idempotency;
pub mod ids;
pub mod operation;
pub mod path;
pub mod process;
pub mod replay;
pub mod resource;
pub mod skill;
pub mod taint;
pub mod trace;
pub mod validate;
pub mod value;

// ── curated re-exports ────────────────────────────────────────────────

pub use audit::{AuditRules, AuditTag};
pub use cap::{CapError, CapSet, Capability, PredOp, Predicate};
pub use chat::{ChatMessage, ChatMetadata, ContentPart, MessageRole, estimate_tokens};
pub use device::{EffectCapability, EffectProvider, ProviderStatus, Transport, TrustLevel};
pub use extension::{
    AckStatus, ApplyStatus, Backoff, ConfigAxis, ControlFrame, DaemonContact, DaemonContacts,
    ErrorInfo, EventAck, EventSource, ExtensionInstallationDef, ExtensionProjectionDef,
    ExtensionTransport, FlowSignal, InboundEvent, Invoke, InvokeResult, JsonSchema, ManifestDef,
    ObservedGenerations, OutboundCommand, OverflowPolicy, PairingPayload, PairingPayloadError,
    ProcSpec, RejectReason, RestartPolicy, Role, RoleReady,
    RoleSessionClientHello, SessionContext, StreamCapacity,
};
pub use grant::{
    ConstraintSet, DeriveKind, Expiry, Grant, MethodBitmap, ResourceSelector, RightFlags, Rights,
};
pub use ids::{
    BindingId, CausalPosition, DriverId, EndpointId, GrantId, GraphId, HandleId, IdentityRef,
    InterfaceId, MethodId, NodeId, ProcessId, ResourceId, SchemaId, Timestamp,
};
pub use operation::{
    BatchSummary, DecisionTag, Fact, Operation, OperationId, OutcomeRef, ValueRef,
};
pub use path::{Path, PathError, p};
pub use process::{
    BudgetSpec, BudgetState, CompiledProgramRef, ExpireRule, GrantAttenuation, Outcome, Process,
    ProcessStatus, ProgramRef, Recoverability, SpawnRequest, StartRecord,
};
pub use replay::{Purity, ReplayClass};
pub use resource::{
    Binding, CostModel, DriverRef, Interface, InterfaceFamily, InterfaceLaw, InterfaceSet,
    Metadata, Method, ModalitySet, OutputMode, OutputModeSet, Resource, ResourceDescriptor,
    ResourceKind, ResourceName,
};
pub use skill::{Skill, SkillScope};
pub use taint::{TaintSet, TaintSource};
pub use trace::{Span, SpanId, TraceContext, TraceId};
pub use validate::{PathRegistry, PathValidator, default_registry};
pub use value::{
    BlobRef, DType, Failure, FloatBits, FrameKind, FrameRef, MergeRule, StreamMarker, TensorRef,
    Value, ValueError,
};

// ── kernel reserved path prefixes (§10.2) ──────────────────────────────

/// Path prefixes reserved for the kernel. Non-kernel Processes cannot register
/// handlers or write state under these even with an ordinary Grant; admission
/// and `open()` enforce it jointly (§10.2).
pub const KERNEL_RESERVED_PREFIXES: &[&str] = &["state://kernel/", "effect://kernel/"];

/// Credential-reserved prefix: only the credential Driver opens these (§21.6).
pub const VAULT_PREFIX: &str = "state://vault/";

/// Read-only history projection prefix (§9.4).
pub const FACT_PREFIX: &str = "state://fact/";

/// Quarantine prefix (§15.3): unsafe replays held for operator decision.
pub const QUARANTINE_PREFIX: &str = "state://quarantine/";

/// Streaming output prefix (§20.4): `state://stream/<process>/<causal_pos>`.
pub const STREAM_PREFIX: &str = "state://stream/";

/// Bootstrap phase markers (§14.1): `state://kernel/bootstrap/phase`.
pub const BOOTSTRAP_PHASE_PATH: &str = "state://kernel/bootstrap/phase";

/// Returns `true` if `path` is under a kernel-reserved prefix.
pub fn is_kernel_reserved(path: &Path) -> bool {
    let s = path.to_string();
    KERNEL_RESERVED_PREFIXES
        .iter()
        .any(|prefix| s.starts_with(prefix))
}

/// Returns `true` if `path` is under the credential-vault prefix (§21.6).
pub fn is_vault_reserved(path: &Path) -> bool {
    let s = path.to_string();
    s == "state://vault" || s.starts_with(VAULT_PREFIX)
}

/// Returns `true` if `path` is under the read-only Fact projection prefix (§9.4).
pub fn is_fact_reserved(path: &Path) -> bool {
    let s = path.to_string();
    s == "state://fact" || s.starts_with(FACT_PREFIX)
}
