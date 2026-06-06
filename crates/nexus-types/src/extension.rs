//! Extension projection (§16): how an external capability is declared and how
//! it lands on kernel primitives.
//!
//! An extension is **not** a kernel object. It projects onto existing ones
//! (§16.3): the external process becomes an Executor Resource (`proc://<id>`),
//! each capability it provides becomes a remote `Binding`, and its
//! configuration is plain state the console reads and writes. This module
//! holds the *declarations* (`ExtensionInstallationDef`, `ManifestDef`) and
//! the wire frames (`Invoke`, `ControlFrame`, …) — all wasm-safe data.

use crate::Timestamp;
use crate::path::Path;
use crate::replay::Purity;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub use crate::device::{EffectCapability, Transport, TrustLevel};

/// A JSON Schema, modeled as a [`Value`] (object) to stay wasm-safe and avoid
/// a schema-library dependency. Used as a config contract (§16.3.5).
pub type JsonSchema = Value;

/// One capability projection inside an installed extension package (§16.3).
///
/// A projection is deliberately single-role. A real connector may install
/// several projections under one [`ExtensionInstallationDef`], but each
/// projection still compiles to one Source stream or one set of Provider
/// Bindings. This keeps source ingest, provider authorization, flow control,
/// and binding generations independent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionProjectionDef {
    pub id: String,
    pub role: Role,
    /// Provider: every exposed effect must sit under this sandbox namespace.
    /// Source projections usually leave this as `None`.
    #[serde(default)]
    pub namespace: Option<Path>,
    /// Provider: each entry → one remote Binding.
    #[serde(default)]
    pub provides: Vec<EffectCapability>,
    /// Source: which Sequence Resource inbound events write to.
    #[serde(default)]
    pub emits: Option<EventSource>,
    /// Projection-level optimistic concurrency. Provider Binding generation and
    /// Source schema changes derive from this, not from the installation's
    /// shared runtime config.
    #[serde(default)]
    pub version: u64,
}

/// A real installed extension package/runtime (§16.3).
///
/// This is the lifecycle, pairing, process, and shared-configuration unit. It
/// may contain multiple independent projections (for example a chat connector
/// with one Source projection for inbound events and one Provider projection
/// for send/media effects), all sharing one process and credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionInstallationDef {
    pub id: String,
    pub platform: String,
    pub transport: Transport,
    pub trust: TrustLevel,
    /// Shared config contract for this installation. Projection-specific method
    /// schemas stay in `provides` / `emits`.
    pub config_schema: JsonSchema,
    /// Current shared config values; secret fields are vault refs, not
    /// plaintext.
    pub config: Value,
    /// The logical capabilities projected by this installation.
    pub projections: Vec<ExtensionProjectionDef>,
    /// Optimistic concurrency for shared runtime/config/code changes.
    pub version: u64,
}

/// What role an extension plays (§16.2). A Provider exposes effects (each →
/// a remote Binding); a Source emits an inbound event stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Provider,
    Source,
}

/// Where a Source writes its inbound events (§16.2): a Sequence Resource that
/// downstream Processes subscribe to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventSource {
    /// The Sequence Resource path inbound events are appended to, e.g.
    /// `state://chat/telegram/events`.
    pub sink: Path,
    /// Declared purity of inbound events (usually `Effectful`).
    #[serde(default)]
    pub purity: Purity,
    /// Optional schema describing the event payload.
    #[serde(default)]
    pub event_schema: Option<JsonSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ExtensionAdmissionError {
    #[error("extension installation id must not be empty")]
    EmptyInstallationId,
    #[error("extension installation id must contain only ASCII letters, digits, '_' or '-'")]
    MalformedInstallationId,
    #[error("extension projection id must not be empty")]
    EmptyProjectionId,
    #[error("extension projection id must contain only ASCII letters, digits, '_' or '-'")]
    MalformedProjectionId,
    #[error("extension installation must declare at least one projection")]
    InstallationWithoutProjections,
    #[error("extension projection id {0:?} is duplicated")]
    DuplicateProjectionId(String),
    #[error("provider extension must declare at least one provided effect")]
    ProviderWithoutCapabilities,
    #[error("provider extension must not declare a source event stream")]
    ProviderWithEventSource,
    #[error("source extension must declare an event stream")]
    SourceWithoutEventStream,
    #[error("source extension must not declare provider capabilities")]
    SourceWithCapabilities,
    #[error("provider effect path is malformed: {0}")]
    MalformedEffectPath(String),
    #[error("provider effect {effect} escapes namespace {namespace}")]
    NamespaceEscape { namespace: Path, effect: Path },
    #[error("sandboxed extension namespace must be effect://plugin/<id> or effect://mcp-tool/<id>")]
    BadSandboxNamespace,
    #[error("sandboxed extension id does not match namespace id segment")]
    SandboxIdMismatch,
    #[error("full-trust extension cannot use transport {0}")]
    FullTrustTransport(String),
    #[error("in-process transport requires full trust")]
    InProcessSandbox,
}

impl ExtensionProjectionDef {
    /// Admission check for one single-role projection. `installation_id`,
    /// `transport`, and `trust` come from the owning installation.
    pub fn validate_admission(
        &self,
        installation_id: &str,
        trust: TrustLevel,
        transport: &Transport,
    ) -> Result<(), ExtensionAdmissionError> {
        validate_installation_id(installation_id)?;
        validate_projection_id(&self.id)?;
        validate_trust_transport(trust, transport)?;

        match self.role {
            Role::Provider => {
                if self.provides.is_empty() {
                    return Err(ExtensionAdmissionError::ProviderWithoutCapabilities);
                }
                if self.emits.is_some() {
                    return Err(ExtensionAdmissionError::ProviderWithEventSource);
                }
                let namespace = self
                    .namespace
                    .as_ref()
                    .ok_or(ExtensionAdmissionError::BadSandboxNamespace)?;
                if trust == TrustLevel::Sandboxed {
                    validate_sandbox_namespace(installation_id, namespace)?;
                }
                for cap in &self.provides {
                    let effect = Path::parse(&cap.effect_path).map_err(|_| {
                        ExtensionAdmissionError::MalformedEffectPath(cap.effect_path.clone())
                    })?;
                    if !namespace.is_prefix_of(&effect) {
                        return Err(ExtensionAdmissionError::NamespaceEscape {
                            namespace: namespace.clone(),
                            effect,
                        });
                    }
                }
            }
            Role::Source => {
                if self.emits.is_none() {
                    return Err(ExtensionAdmissionError::SourceWithoutEventStream);
                }
                if !self.provides.is_empty() {
                    return Err(ExtensionAdmissionError::SourceWithCapabilities);
                }
            }
        }
        Ok(())
    }
}

impl ExtensionInstallationDef {
    /// Admission check for an installed runtime package and all of its
    /// projections. This is control-plane-only; the data-plane still sees
    /// ordinary Source ingest and Provider Bindings after reconcile.
    pub fn validate_admission(&self) -> Result<(), ExtensionAdmissionError> {
        validate_installation_id(&self.id)?;
        validate_trust_transport(self.trust, &self.transport)?;
        if self.projections.is_empty() {
            return Err(ExtensionAdmissionError::InstallationWithoutProjections);
        }
        let mut seen = std::collections::BTreeSet::new();
        for projection in &self.projections {
            if !seen.insert(projection.id.clone()) {
                return Err(ExtensionAdmissionError::DuplicateProjectionId(
                    projection.id.clone(),
                ));
            }
            projection.validate_admission(&self.id, self.trust, &self.transport)?;
        }
        Ok(())
    }

    pub fn projection(&self, id: &str) -> Option<&ExtensionProjectionDef> {
        self.projections.iter().find(|projection| projection.id == id)
    }
}

fn validate_installation_id(id: &str) -> Result<(), ExtensionAdmissionError> {
    if id.trim().is_empty() {
        return Err(ExtensionAdmissionError::EmptyInstallationId);
    }
    if !is_safe_id_segment(id) {
        return Err(ExtensionAdmissionError::MalformedInstallationId);
    }
    Ok(())
}

fn validate_projection_id(id: &str) -> Result<(), ExtensionAdmissionError> {
    if id.trim().is_empty() {
        return Err(ExtensionAdmissionError::EmptyProjectionId);
    }
    if !is_safe_id_segment(id) {
        return Err(ExtensionAdmissionError::MalformedProjectionId);
    }
    Ok(())
}

fn is_safe_id_segment(id: &str) -> bool {
    id.is_ascii()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_trust_transport(
    trust: TrustLevel,
    transport: &Transport,
) -> Result<(), ExtensionAdmissionError> {
    match (trust, transport) {
        (
            TrustLevel::Full,
            Transport::InProcess | Transport::Grpc { .. } | Transport::WebSocket { .. },
        ) => Ok(()),
        (TrustLevel::Full, other) => Err(ExtensionAdmissionError::FullTrustTransport(
            transport_name(other).into(),
        )),
        (TrustLevel::Sandboxed, Transport::InProcess) => {
            Err(ExtensionAdmissionError::InProcessSandbox)
        }
        (TrustLevel::Sandboxed, _) => Ok(()),
    }
}

fn validate_sandbox_namespace(id: &str, namespace: &Path) -> Result<(), ExtensionAdmissionError> {
    let segs = namespace.segments();
    let ok_prefix = namespace.scheme() == "effect"
        && segs.len() >= 2
        && matches!(segs[0].as_str(), "plugin" | "mcp-tool");
    if !ok_prefix {
        return Err(ExtensionAdmissionError::BadSandboxNamespace);
    }
    if segs[1].as_str() != id {
        return Err(ExtensionAdmissionError::SandboxIdMismatch);
    }
    Ok(())
}

fn transport_name(t: &Transport) -> &'static str {
    match t {
        Transport::InProcess => "in_process",
        Transport::Grpc { .. } => "grpc",
        Transport::Stdio { .. } => "stdio",
        Transport::WebSocket { .. } => "websocket",
        Transport::Http { .. } => "http",
    }
}

/// A reusable install template for a platform (§16.3.5) — pure state. Lets
/// "install N instances of the same platform" (e.g. several Telegram accounts)
/// share one config contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestDef {
    pub platform: String,
    /// Source of an installation's shared config schema.
    pub config_schema: JsonSchema,
    /// Projection templates this platform can install.
    pub projections: Vec<ExtensionProjectionDef>,
    pub supported_transports: Vec<Transport>,
    pub default_transport: Transport,
    /// Optimistic concurrency/config revision for this install template.
    pub version: u64,
}

// ── pairing payload (§16.3.4) ────────────────────────────────────────

/// Transport choices encoded in a pairing payload. This is narrower than the
/// generic provider [`Transport`]: pairing only tells an unpaired extension
/// where to submit its claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionTransport {
    WebSocket,
    Grpc,
}

/// The daemon connection choices embedded in a pairing payload. Unpaired
/// extensions must not invent defaults; they connect only to these contacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonContacts {
    pub contacts: Vec<DaemonContact>,
}

/// One daemon endpoint from a pairing payload. `authority` is the single source
/// of host/IP + port (`host:7443`, `192.168.1.20:7443`, `[fd00::12]:7443`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonContact {
    pub transport: ExtensionTransport,
    pub authority: String,
    pub service: String,
    #[serde(default)]
    pub tls_name: Option<String>,
    pub priority: u8,
}

/// The exact payload encoded by the visual pair card, manual code, and copy
/// pass. Visual encodings may compress or shard it, but must not omit contacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairingPayload {
    pub version: u32,
    pub pairing_id: String,
    pub pairing_secret: String,
    pub daemon_contacts: DaemonContacts,
    pub daemon_identity_pub: String,
    pub daemon_fingerprint: String,
    pub expires_at: Timestamp,
    pub display_checksum: String,
}

impl DaemonContact {
    pub fn validate(&self) -> Result<(), PairingPayloadError> {
        validate_authority(&self.authority)?;
        if self.service.trim().is_empty() {
            return Err(PairingPayloadError::EmptyService);
        }
        Ok(())
    }
}

impl PairingPayload {
    pub fn validate(&self) -> Result<(), PairingPayloadError> {
        if self.daemon_contacts.contacts.is_empty() {
            return Err(PairingPayloadError::MissingContacts);
        }
        for contact in &self.daemon_contacts.contacts {
            contact.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PairingPayloadError {
    #[error("pairing payload must include at least one daemon contact")]
    MissingContacts,
    #[error("daemon contact authority must be host:port or [ipv6]:port, without a scheme")]
    BadAuthority,
    #[error("daemon contact service cannot be empty")]
    EmptyService,
}

fn validate_authority(authority: &str) -> Result<(), PairingPayloadError> {
    if authority.is_empty()
        || authority.contains("://")
        || authority.contains('/')
        || authority.chars().any(char::is_whitespace)
    {
        return Err(PairingPayloadError::BadAuthority);
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or(PairingPayloadError::BadAuthority)?;
        let port = tail
            .strip_prefix(':')
            .ok_or(PairingPayloadError::BadAuthority)?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or(PairingPayloadError::BadAuthority)?
    };

    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(PairingPayloadError::BadAuthority);
    }
    Ok(())
}

// ── proc:// Executor Resource (§16.3.1) ───────────────────────────────

/// How a dead `proc://` process is restarted (§16.3.1), borrowing Erlang/OTP
/// supervision semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    Never,
    OnFailure { max: u32, window_ms: u64 },
    Always { backoff: Backoff },
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::OnFailure {
            max: 5,
            window_ms: 60_000,
        }
    }
}

/// Restart backoff strategy (§16.3.1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backoff {
    Fixed {
        ms: u64,
    },
    Exp {
        base_ms: u64,
        cap_ms: u64,
        jitter: bool,
    },
}

/// Spec for an external process projected as an Executor Resource (§16.3.1).
/// Only `ProcDriver` (privileged) consumes this; it is the sole driver that
/// can fork/exec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcSpec {
    pub id: String,
    /// Decides how to bring it up: Stdio is self-forked; Grpc/WS/Http connect.
    pub transport: Transport,
    /// argv for a Stdio child; `None` for an externally-managed process.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub restart: RestartPolicy,
}

// ── data + control frames (§16.3.3) ───────────────────────────────────

/// Flow-control signal carried on a [`ControlFrame`] (§16.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowSignal {
    Pause,
    Resume,
}

/// Generation tags an extension echoes for comparison; the daemon holds the
/// authority and chooses the real values (§16.3.3). Only the two lightweight
/// presentation/alias axes ride on each inbound event — session-level
/// generations live in [`SessionContext`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedGenerations {
    #[serde(default)]
    pub presentation_config_generation: u64,
    #[serde(default)]
    pub alias_catalog_generation: u64,
}

/// Stage 1 of the session handshake (§16.3.3): the extension opens by
/// reporting identity + locally cached generations/hash (pure echo, no
/// authority). Self-describing extensions report their config contract here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleSessionClientHello {
    pub role: Role,
    pub installation_id: String,
    pub projection_id: String,
    pub registry_hash: String,
    #[serde(default)]
    pub observed: ObservedGenerations,
    #[serde(default)]
    pub config_schema: Option<JsonSchema>,
}

/// Stage 2 of the handshake (§16.3.3): the daemon adjudicates every
/// authoritative registry hash/generation and sends them down. The extension
/// never declares or guesses these.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionContext {
    pub installation_id: String,
    pub projection_id: String,
    pub role: Role,
    pub registry_hash: String,
    pub credential_generation: u64,
    pub binding_generation: u64,
    pub extension_config_version: u64,
    pub projection_version: u64,
    pub presentation_config_generation: u64,
    pub alias_catalog_generation: u64,
}

/// Stage 3 of the handshake (§16.3.3): the extension confirms it has aligned to
/// the daemon-chosen [`SessionContext`]. Any generation/hash mismatch is
/// fail-closed; no business frames flow before this.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleReady {
    pub accepted_context: SessionContext,
}

/// Which configuration axis a [`ControlFrame::ConfigAck`] answers (§16.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigAxis {
    ExtensionConfig,
    PresentationConfig,
}

/// Why an extension rejected a config/presentation update (§16.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    ProfileMismatch,
    SchemaInvalid,
    GenerationStale,
    Unsupported,
}

/// Result of applying a config/presentation update (§16.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    Applied,
    Rejected { reason: RejectReason },
}

/// Control frames shared by both roles (§16.3.3). Configuration travels on two
/// independent axes that never mix — `ExtensionConfigUpdate` (authority: what
/// the extension may do) and `PresentationConfigUpdate` (presentation only:
/// never grants capability) — plus a profile-report axis flowing the other way.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFrame {
    Heartbeat,
    Shutdown {
        graceful: bool,
        timeout_ms: u64,
    },
    FlowControl(FlowSignal),
    /// Report axis: extension → daemon, declares what this end can render and
    /// which entry points are locally disabled. The profile body is opaque
    /// here; the platform docs (Web/Mobile) define its schema.
    PresentationProfileUpdate {
        profile_generation: u64,
        profile_hash: String,
        profile: Value,
    },
    /// Authority axis: daemon → extension, via §18.4 Value.write+Cas; advances
    /// `ExtensionInstallationDef.version` and may bump the Binding generation.
    ExtensionConfigUpdate {
        config_version: u64,
        config: Value,
    },
    /// Presentation axis: daemon → extension; pure display / entry-point /
    /// renderer budget — never grants capability, bounded by `profile_hash`.
    PresentationConfigUpdate {
        generation: u64,
        profile_hash: String,
        config: Value,
    },
    /// Shared reply loop: the extension must report how it applied an update;
    /// the daemon uses it to judge liveness and to fail closed.
    ConfigAck {
        axis: ConfigAxis,
        version: u64,
        status: ApplyStatus,
    },
}

/// Provider data frame: one remote Operation (§16.3.3 / §7.4 RPC stub).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invoke {
    /// Stable across reconnect/replay: derived from the business idempotency
    /// key when present, else from CausalPosition (§16.3.3 / §6.1).
    pub invocation_id: String,
    pub effect_path: Path,
    pub input: Value,
    #[serde(default)]
    pub deadline_ms: Option<i64>,
    #[serde(default)]
    pub output_stream_to: Option<Path>,
}

/// Error detail returned in an [`InvokeResult`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub kind: String,
    pub message: String,
}

/// Provider data frame: the result of one [`Invoke`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvokeResult {
    pub invocation_id: String,
    pub outcome: Result<Value, ErrorInfo>,
}

/// Source data frame: one inbound event (§16.3.3). Carries only the two
/// lightweight presentation/alias generation tags — session-level generations
/// are settled in the handshake [`SessionContext`], not on each event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InboundEvent {
    pub id: String,
    pub payload: Value,
    #[serde(default)]
    pub observed: ObservedGenerations,
    pub timestamp_ms: i64,
}

/// Source data frame: a command sent back out to the source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundCommand {
    pub id: String,
    pub action: Value,
    #[serde(default)]
    pub observed: ObservedGenerations,
}

/// Acknowledgement status for an inbound event (§16.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckStatus {
    Accepted,
    Duplicate,
    Rejected,
}

/// Source data frame: ack of an [`InboundEvent`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventAck {
    pub id: String,
    pub status: AckStatus,
}

// ── inbound stream capacity vs rate (§16.4) ───────────────────────────

/// What to do when an inbound stream overflows its capacity (§16.4). Distinct
/// from rate limiting, which is a policy concern.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    DropOldest,
    Backpressure {
        pause_threshold: u32,
        resume_threshold: u32,
    },
    DisconnectBridge,
}

/// Capacity of an inbound event stream (§16.4).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamCapacity {
    pub max_events: u32,
    pub on_overflow: OverflowPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_with_source_and_provider_projections_is_admitted() {
        let install = ExtensionInstallationDef {
            id: "wechat".into(),
            platform: "wechat".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![
                ExtensionProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(EventSource {
                        sink: Path::parse("state://wechat/events").unwrap(),
                        purity: Purity::Effectful,
                        event_schema: None,
                    }),
                    version: 1,
                },
                ExtensionProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(Path::parse("effect://plugin/wechat").unwrap()),
                    provides: vec![EffectCapability::new(
                        "effect://plugin/wechat/send_text",
                        Purity::Effectful,
                    )],
                    emits: None,
                    version: 1,
                },
            ],
            version: 1,
        };
        assert_eq!(install.validate_admission(), Ok(()));
    }

    #[test]
    fn installation_rejects_duplicate_projection_ids() {
        let projection = ExtensionProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            namespace: Some(Path::parse("effect://plugin/wechat").unwrap()),
            provides: vec![EffectCapability::new(
                "effect://plugin/wechat/send_text",
                Purity::Effectful,
            )],
            emits: None,
            version: 1,
        };
        let install = ExtensionInstallationDef {
            id: "wechat".into(),
            platform: "wechat".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![projection.clone(), projection],
            version: 1,
        };
        assert_eq!(
            install.validate_admission(),
            Err(ExtensionAdmissionError::DuplicateProjectionId(
                "provider".into()
            ))
        );
    }

    #[test]
    fn sandbox_provider_admission_is_structural_and_fail_closed() {
        let valid = ExtensionProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![EffectCapability::new(
                "effect://plugin/acme/search",
                Purity::Idempotent,
            )],
            emits: None,
            namespace: Some(Path::parse("effect://plugin/acme").unwrap()),
            version: 1,
        };
        assert_eq!(
            valid.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![]
                }
            ),
            Ok(())
        );

        let mut sibling_escape = valid.clone();
        sibling_escape.provides[0].effect_path = "effect://plugin/acmeevil/search".into();
        assert!(matches!(
            sibling_escape.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![]
                }
            ),
            Err(ExtensionAdmissionError::NamespaceEscape { .. })
        ));

        let mut bad_namespace = valid.clone();
        bad_namespace.namespace = Some(Path::parse("effect://x/acme").unwrap());
        assert_eq!(
            bad_namespace.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![]
                }
            ),
            Err(ExtensionAdmissionError::BadSandboxNamespace)
        );
    }

    #[test]
    fn projection_role_shape_is_fail_closed() {
        let provider_without_caps = ExtensionProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![],
            emits: None,
            namespace: Some(Path::parse("effect://plugin/acme").unwrap()),
            version: 1,
        };
        assert_eq!(
            provider_without_caps.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![]
                }
            ),
            Err(ExtensionAdmissionError::ProviderWithoutCapabilities)
        );

        let source_with_caps = ExtensionProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![EffectCapability::new(
                "effect://plugin/bridge/tool",
                Purity::Effectful,
            )],
            emits: Some(EventSource {
                sink: Path::parse("state://chat/bridge/events").unwrap(),
                purity: Purity::Effectful,
                event_schema: None,
            }),
            namespace: None,
            version: 1,
        };
        assert_eq!(
            source_with_caps.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExtensionAdmissionError::SourceWithCapabilities)
        );
    }

    #[test]
    fn trust_transport_combo_is_fail_closed() {
        let full_stdio = ExtensionInstallationDef {
            id: "local-tool".into(),
            platform: "local-tool".into(),
            transport: Transport::Stdio {
                command: Some("tool".into()),
                args: vec![],
            },
            trust: TrustLevel::Full,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![ExtensionProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(Path::parse("effect://local-tool").unwrap()),
                provides: vec![EffectCapability::new(
                    "effect://local-tool/run",
                    Purity::Effectful,
                )],
                emits: None,
                version: 1,
            }],
            version: 1,
        };
        assert!(matches!(
            full_stdio.validate_admission(),
            Err(ExtensionAdmissionError::FullTrustTransport(t)) if t == "stdio"
        ));

        let mut sandbox_in_process = full_stdio.clone();
        sandbox_in_process.id = "tool".into();
        sandbox_in_process.trust = TrustLevel::Sandboxed;
        sandbox_in_process.transport = Transport::InProcess;
        sandbox_in_process.projections[0].namespace =
            Some(Path::parse("effect://plugin/tool").unwrap());
        sandbox_in_process.projections[0].provides[0].effect_path =
            "effect://plugin/tool/run".into();
        assert_eq!(
            sandbox_in_process.validate_admission(),
            Err(ExtensionAdmissionError::InProcessSandbox)
        );
    }

    #[test]
    fn control_frame_config_ack_roundtrip() {
        let f = ControlFrame::ConfigAck {
            axis: ConfigAxis::PresentationConfig,
            version: 7,
            status: ApplyStatus::Rejected {
                reason: RejectReason::ProfileMismatch,
            },
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: ControlFrame = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn handshake_three_stages_roundtrip() {
        let hello = RoleSessionClientHello {
            role: Role::Provider,
            installation_id: "inst-1".into(),
            projection_id: "provider".into(),
            registry_hash: "abc".into(),
            observed: ObservedGenerations::default(),
            config_schema: None,
        };
        let ctx = SessionContext {
            installation_id: "inst-1".into(),
            projection_id: "provider".into(),
            role: Role::Provider,
            registry_hash: "abc".into(),
            credential_generation: 2,
            binding_generation: 3,
            extension_config_version: 1,
            projection_version: 1,
            presentation_config_generation: 4,
            alias_catalog_generation: 5,
        };
        let ready = RoleReady {
            accepted_context: ctx,
        };
        let hello_back: RoleSessionClientHello =
            serde_json::from_str(&serde_json::to_string(&hello).unwrap()).unwrap();
        let ready_back: RoleReady =
            serde_json::from_str(&serde_json::to_string(&ready).unwrap()).unwrap();
        assert_eq!(hello, hello_back);
        assert_eq!(ready, ready_back);
    }

    #[test]
    fn invoke_result_carries_error() {
        let r = InvokeResult {
            invocation_id: "x".into(),
            outcome: Err(ErrorInfo {
                kind: "timeout".into(),
                message: "deadline".into(),
            }),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: InvokeResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn pairing_payload_requires_contacts_and_valid_authorities() {
        let payload = PairingPayload {
            version: 1,
            pairing_id: "pair-1".into(),
            pairing_secret: "secret".into(),
            daemon_contacts: DaemonContacts {
                contacts: vec![
                    DaemonContact {
                        transport: ExtensionTransport::WebSocket,
                        authority: "192.168.1.20:7443".into(),
                        service: "/extension/pair".into(),
                        tls_name: None,
                        priority: 10,
                    },
                    DaemonContact {
                        transport: ExtensionTransport::Grpc,
                        authority: "[fd00::12]:7443".into(),
                        service: "NexusExtensionPairing.Pair".into(),
                        tls_name: Some("nexus.local".into()),
                        priority: 20,
                    },
                ],
            },
            daemon_identity_pub: "pub".into(),
            daemon_fingerprint: "fp".into(),
            expires_at: Timestamp::millis(1),
            display_checksum: "abcd".into(),
        };
        assert_eq!(payload.validate(), Ok(()));
    }

    #[test]
    fn pairing_payload_rejects_missing_contacts_and_scheme_authority() {
        let empty = PairingPayload {
            version: 1,
            pairing_id: "pair-1".into(),
            pairing_secret: "secret".into(),
            daemon_contacts: DaemonContacts { contacts: vec![] },
            daemon_identity_pub: "pub".into(),
            daemon_fingerprint: "fp".into(),
            expires_at: Timestamp::millis(1),
            display_checksum: "abcd".into(),
        };
        assert_eq!(empty.validate(), Err(PairingPayloadError::MissingContacts));

        let bad = DaemonContact {
            transport: ExtensionTransport::WebSocket,
            authority: "https://nexus.local:7443".into(),
            service: "/extension/pair".into(),
            tls_name: None,
            priority: 1,
        };
        assert_eq!(bad.validate(), Err(PairingPayloadError::BadAuthority));
    }
}
