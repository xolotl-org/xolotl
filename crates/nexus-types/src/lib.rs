#![forbid(unsafe_code)]

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
    ProcSpec, RejectReason, RestartPolicy, Role, RoleReady, RoleSessionClientHello, SessionContext,
    StreamCapacity, sandboxed_source_event_sink_path,
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

#[cfg(test)]
mod workspace_design_guard_tests {
    use std::path::{Path as FsPath, PathBuf};

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(FsPath::parent)
            .map(FsPath::to_path_buf)
            .expect("nexus-types must live under crates/nexus-types")
    }

    fn collect_rust_sources(dir: &FsPath, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("source directory must be readable");
        for entry in entries {
            let entry = entry.expect("source directory entry must be readable");
            let path = entry.path();
            if path.is_dir() {
                collect_rust_sources(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    fn rust_sources() -> Vec<PathBuf> {
        let mut sources = Vec::new();
        collect_rust_sources(&workspace_root().join("crates"), &mut sources);
        sources
    }

    #[test]
    fn crate_roots_forbid_unsafe_code() {
        let crates_dir = workspace_root().join("crates");
        let mut missing = Vec::new();
        for entry in std::fs::read_dir(&crates_dir).expect("crates directory must be readable") {
            let entry = entry.expect("crate directory entry must be readable");
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            for root in [path.join("src/lib.rs"), path.join("src/main.rs")] {
                if !root.exists() {
                    continue;
                }
                let text = std::fs::read_to_string(&root).expect("crate root must be UTF-8");
                if !text.contains("#![forbid(unsafe_code)]") {
                    missing.push(root.display().to_string());
                }
            }
        }
        assert!(
            missing.is_empty(),
            "crate roots must opt into the design safety baseline:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn workspace_sources_have_no_placeholder_macros_or_unsafe_markers() {
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
        for path in rust_sources() {
            let text = std::fs::read_to_string(&path).expect("Rust source must be UTF-8");
            for pattern in &forbidden {
                if text.contains(pattern) {
                    hits.push(format!("{} contains {pattern:?}", path.display()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "workspace sources must keep the §0.1 safety baseline:\n{}",
            hits.join("\n")
        );
    }

    #[test]
    fn data_plane_hot_path_has_no_control_plane_lookups_or_path_parsing() {
        let path = workspace_root().join("crates/nexus-kernel/src/dataplane.rs");
        let text = std::fs::read_to_string(&path).expect("dataplane source must be UTF-8");
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
        assert!(
            hits.is_empty(),
            "data-plane production code must keep §2.3/§28 hot-path inputs precompiled:\n{}",
            hits.join("\n")
        );
    }
}
