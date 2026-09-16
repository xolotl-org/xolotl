#![no_std]
#![forbid(unsafe_code)]

//! Public data types for the Xolotl runtime.
//!
//! This crate supports **`no_std + alloc`**: no async / IO, no
//! kernel state — just the data that flows through the system, plus the
//! control-plane *descriptors* the console and wire protocols reference. The
//! live runtime objects that carry dispatch tables (`Handle` / `DriverPlan`)
//! live in `xolotl-kernel`; the execution IR (`ExecutionGraph` / `Do<A>`) lives
//! in `xolotl-graph`.
//!
//! Public modules:
//!
//! - [`path`]   — the universal `Path` addressing type.
//! - [`value`]  — `Value` (incl. `Blob`/`Tensor`/`Frame`) and media references.
//! - [`failure`] — structured execution failures and recovery metadata.
//! - [`ids`]    — compact data-plane identifiers (`ProcessId`, `HandleId`, …).
//! - [`replay`] — `Purity` (declared) and `ReplayClass` (derived).
//! - [`grant`]  — `Grant`/`Rights`/`ConstraintSet`: the capability *source* form.
//! - [`resource`] — `Resource`/`Interface`/`Method`/`Binding` descriptors.
//! - [`operation`] — `Operation`/`OperationId`/`Fact` data-plane records.
//! - [`process`]   — `Process`/lifecycle/`Outcome`.
//! - [`external`] — external installation/projection manifests and wire frames.
//! - [`chat`]      — chat message DTOs used by inference.
//! - [`inference`] — inference backend and routing declarations.
//! - [`in_process_projection`] — in-process projection declarations.
//! - [`validate`]  — path semantic validation.

#[macro_use]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod audit;
pub mod cap;
pub mod chat;
pub mod execution;
pub mod external;
mod external_descriptor;
pub mod failure;
pub mod grant;
pub mod idempotency;
pub mod ids;
pub mod in_process_projection;
pub mod inference;
pub mod operation;
pub mod path;
pub mod process;
pub mod replay;
pub mod resource;
pub mod tagged_value;
pub mod taint;
pub mod trace;
pub mod validate;
pub mod value;

pub use audit::{AuditRules, AuditTag};
pub use cap::{CapError, CapSet, Capability, PredOp, Predicate};
pub use chat::{ChatMessage, ChatMetadata, ContentPart, MessageRole, estimate_tokens};
pub use execution::ExecutionOutput;
pub use external::{
    AckStatus, ApplyStatus, Backoff, CommandResult, ConfigAxis, ControlFrame, DaemonContact,
    DaemonContacts, ErrorInfo, EventAck, EventSource, ExternalInstallationDef,
    ExternalProjectionDef, ExternalTransport, FlowSignal, InboundEvent, Invoke, InvokeResult,
    JsonSchema, ManifestDef, ObservedGenerations, OutboundCommand, OverflowPolicy, PairingPayload,
    PairingPayloadError, ProcSpec, RejectReason, RestartPolicy, Role, RoleReady,
    RoleSessionClientHello, SessionContext, SourceRateLimit, StreamCapacity,
    sandboxed_source_event_sink_path,
};
pub use external_descriptor::{EffectCapability, Transport, TrustLevel};
pub use failure::Failure;
pub use grant::{
    ConstraintSet, DeriveKind, Expiry, Grant, MethodBitmap, ResourceSelector, RightFlags, Rights,
};
pub use ids::{
    BindingId, CausalPosition, DriverId, EndpointId, ExecutionId, GrantId, GraphId, HandleId,
    IdentityRef, InterfaceId, InvocationId, MethodId, NodeId, ProcessId, ResourceId, SchemaId,
    Timestamp,
};
pub use in_process_projection::{
    InProcessProjectionConfigError, InProcessProjectionDef, InProcessProjectionPhase,
    InProcessProjectionStatus,
};
pub use inference::{
    InferenceApiDialect, InferenceAuthRef, InferenceBackendDef, InferenceConfigError,
    InferenceGroupDef, InferenceGroupPolicy, InferenceMethodSet, InferenceModelCapabilities,
    InferenceModelDef, InferenceResponseLimits, InferenceRoutingDef, MAX_INFERENCE_ROUTING_RETRIES,
};
pub use operation::{
    BatchSummary, CompletionOrigin, DecisionTag, DriverOutput, DriverUsage, Fact, MethodContract,
    Operation, OperationId, ParseOperationIdError, UsageDimension,
};
#[cfg(test)]
pub use path::p;
pub use path::{Path, PathError};
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
pub use taint::{TaintSet, TaintSource, TaintedFailure, TaintedValue};
pub use trace::{Span, SpanId, TraceContext, TraceId};
pub use validate::{PathRegistry, PathValidator, default_registry};
pub use value::{
    BlobRef, CollectionError, DType, FloatBits, FrameKind, FrameRef, MergeRule, StreamMarker,
    TensorRef, Value, ValueBytes, ValueError, ValueIdentity, ValueList, ValueListBuilder, ValueMap,
    ValueMapBuilder, ValueText, ValueView,
};

/// Path prefixes reserved for the kernel. Non-kernel Processes cannot register
/// handlers or write state under these even with a non-kernel Grant; admission
/// and `open()` enforce it jointly.
pub const KERNEL_RESERVED_PREFIXES: &[&str] = &["state://kernel/", "effect://kernel/"];

/// Credential-reserved prefix: only the credential Driver opens these.
pub const VAULT_PREFIX: &str = "state://vault/";

/// Read-only history projection prefix.
pub const FACT_PREFIX: &str = "state://fact/";

/// Quarantine prefix: unsafe replays held for operator decision.
pub const QUARANTINE_PREFIX: &str = "state://quarantine/";

/// Streaming output prefix: `state://stream/<process>/<causal_pos>`.
pub const STREAM_PREFIX: &str = "state://stream/";

/// Bootstrap phase markers: `state://kernel/bootstrap/phase`.
pub const BOOTSTRAP_PHASE_PATH: &str = "state://kernel/bootstrap/phase";

/// Returns `true` if `path` is under a kernel-reserved prefix.
pub fn is_kernel_reserved(path: &Path) -> bool {
    path.cluster().is_none()
        && matches!(path.scheme(), "state" | "effect")
        && path.segments().first().map(|s| s.as_str()) == Some("kernel")
}

/// Returns `true` if `path` is under the credential-vault prefix.
pub fn is_vault_reserved(path: &Path) -> bool {
    path.cluster().is_none()
        && path.scheme() == "state"
        && path.segments().first().map(|s| s.as_str()) == Some("vault")
}

/// Returns `true` if `path` is under the read-only Fact projection prefix.
pub fn is_fact_reserved(path: &Path) -> bool {
    path.cluster().is_none()
        && path.scheme() == "state"
        && path.segments().first().map(|s| s.as_str()) == Some("fact")
}

#[cfg(test)]
mod workspace_contract_guard_tests {
    use alloc::{string::ToString, vec::Vec};
    use anyhow::{Context, ensure};
    use std::path::{Path as FsPath, PathBuf};

    fn workspace_root() -> anyhow::Result<PathBuf> {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(FsPath::parent)
            .map(FsPath::to_path_buf)
            .context("xolotl-types must live under crates/xolotl-types")
    }

    fn collect_rust_sources(dir: &FsPath, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("source directory must be readable: {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!("source directory entry must be readable: {}", dir.display())
            })?;
            let path = entry.path();
            if path.is_dir() {
                collect_rust_sources(&path, out)?;
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    fn rust_sources() -> anyhow::Result<Vec<PathBuf>> {
        let mut sources = Vec::new();
        collect_rust_sources(&workspace_root()?.join("crates"), &mut sources)?;
        Ok(sources)
    }

    #[test]
    fn crate_roots_forbid_unsafe_code() -> anyhow::Result<()> {
        let crates_dir = workspace_root()?.join("crates");
        let mut missing = Vec::new();
        for entry in std::fs::read_dir(&crates_dir).with_context(|| {
            format!(
                "crates directory must be readable: {}",
                crates_dir.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "crate directory entry must be readable: {}",
                    crates_dir.display()
                )
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            for root in [path.join("src/lib.rs"), path.join("src/main.rs")] {
                if !root.exists() {
                    continue;
                }
                let text = std::fs::read_to_string(&root)
                    .with_context(|| format!("crate root must be UTF-8: {}", root.display()))?;
                if !text.contains("#![forbid(unsafe_code)]") {
                    missing.push(root.display().to_string());
                }
            }
        }
        ensure!(
            missing.is_empty(),
            "crate roots must opt into the workspace safety baseline:\n{}",
            missing.join("\n")
        );
        Ok(())
    }

    #[test]
    fn workspace_sources_have_no_placeholder_macros_or_unsafe_markers() -> anyhow::Result<()> {
        let forbidden = [
            ["todo", "!"].concat(),
            ["unimplemented", "!"].concat(),
            ["unreachable", "!"].concat(),
            ["unsafe", " {"].concat(),
            ["unsafe", " fn"].concat(),
            ["unsafe", " impl"].concat(),
            ["extern", " \""].concat(),
            ["allow", "(unsafe_code)"].concat(),
        ];
        let mut hits = Vec::new();
        for path in rust_sources()? {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("Rust source must be UTF-8: {}", path.display()))?;
            for pattern in &forbidden {
                if text.contains(pattern) {
                    hits.push(format!("{} contains {pattern:?}", path.display()));
                }
            }
        }
        ensure!(
            hits.is_empty(),
            "workspace sources must keep the safety baseline:\n{}",
            hits.join("\n")
        );
        Ok(())
    }

    #[test]
    fn data_plane_hot_path_has_no_control_plane_lookups_or_path_parsing() -> anyhow::Result<()> {
        let path = workspace_root()?.join("crates/xolotl-kernel/src/dataplane.rs");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("dataplane source must be UTF-8: {}", path.display()))?;
        let production = text.split("#[cfg(test)]").next().unwrap_or(&text);
        let forbidden = [
            "Path::parse",
            "ResourceName",
            "crate::registry",
            "Registry::",
            "resolve_resource",
            "register_resource",
            "register_driver",
            "register_binding",
            "admit_resource",
            "admit_binding",
            "PolicySource",
        ];
        let hits = forbidden
            .iter()
            .filter(|pattern| production.contains(**pattern))
            .map(|pattern| format!("{} contains {pattern:?}", path.display()))
            .collect::<Vec<_>>();
        ensure!(
            hits.is_empty(),
            "data-plane production code must keep / hot-path inputs precompiled:\n{}",
            hits.join("\n")
        );
        Ok(())
    }
}
