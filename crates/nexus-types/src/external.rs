//! External projection: how an external capability is declared and how
//! it lands on kernel primitives.
//!
//! An external program projects onto kernel primitives: the process becomes an
//! Executor Resource (`proc://<id>`), each provided capability becomes a remote
//! `Binding`, and configuration is plain state the console reads and writes.
//! This module holds declarations and wire frames as wasm-safe data.

use crate::Timestamp;
use crate::ids::MethodId;
use crate::path::Path;
use crate::replay::Purity;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub use crate::device::{EffectCapability, Transport, TrustLevel};

/// A JSON Schema, modeled as a [`Value`] (object) to stay wasm-safe and avoid
/// a schema-library dependency. Used as a config contract.
pub type JsonSchema = Value;

/// One capability projection inside an installed external program.
///
/// A projection is deliberately single-role. A real connector may install
/// several projections under one [`ExternalInstallationDef`], but each
/// projection still compiles to one Source stream or one set of Provider
/// Bindings. This keeps source ingest, provider authorization, flow control,
/// and binding generations independent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalProjectionDef {
    /// Projection id unique within an installation.
    pub id: String,
    /// Whether this projection provides effects or emits source events.
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

/// A real installed external program runtime.
///
/// This is the lifecycle, pairing, process, and shared-configuration unit. It
/// may contain multiple independent projections (for example a chat connector
/// with one Source projection for inbound events and one Provider projection
/// for send/media effects), all sharing one process and credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalInstallationDef {
    /// Installation id used in state paths, process ids, and sandbox prefixes.
    pub id: String,
    /// Connector family name.
    pub platform: String,
    /// Transport used to communicate with the external runtime.
    pub transport: Transport,
    /// Trust level assigned by admission.
    pub trust: TrustLevel,
    /// Shared config contract for this installation. Projection-specific method
    /// schemas stay in `provides` / `emits`.
    pub config_schema: JsonSchema,
    /// Current shared config values; secret fields are vault refs, not
    /// plaintext.
    pub config: Value,
    /// The logical capabilities projected by this installation.
    pub projections: Vec<ExternalProjectionDef>,
    /// Optimistic concurrency for shared runtime/config/code changes.
    pub version: u64,
}

/// External projection role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Exposes effect resources through remote bindings.
    Provider,
    /// Emits inbound events into a state sequence.
    Source,
}

/// Where a Source writes its inbound events: a Sequence Resource that
/// downstream Processes subscribe to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventSource {
    /// The local Sequence Resource path inbound events are appended to.
    /// Sandboxed Sources must use
    /// `state://events/external/<installation>/<projection>`.
    pub sink: Path,
    /// Declared purity of inbound events (usually `Effectful`).
    #[serde(default)]
    pub purity: Purity,
    /// Optional schema describing the event payload.
    #[serde(default)]
    pub event_schema: Option<JsonSchema>,
    /// Maximum inline payload bytes accepted for one inbound event.
    pub max_inline_payload_bytes: usize,
    /// Bounded stream capacity for admitted inbound events.
    pub capacity: StreamCapacity,
    /// Optional ingress rate limit for this Source projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<SourceRateLimit>,
    /// Whether this Source may receive outbound commands.
    #[serde(default)]
    pub commands: bool,
    /// Schema for daemon-to-source command action values when `commands` is true.
    #[serde(default)]
    pub command_schema: Option<JsonSchema>,
    /// Schema for successful source-to-daemon command result values.
    #[serde(default)]
    pub command_result_schema: Option<JsonSchema>,
}

/// Admission failures for external installations and projections.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ExternalAdmissionError {
    /// Installation id was empty.
    #[error("external installation id must not be empty")]
    EmptyInstallationId,
    /// Installation id was not a safe path segment.
    #[error(
        "external installation id must start with an ASCII letter or digit and contain only ASCII letters, digits, '_' or '-'"
    )]
    MalformedInstallationId,
    /// Projection id was empty.
    #[error("external projection id must not be empty")]
    EmptyProjectionId,
    /// Projection id was not a safe path segment.
    #[error(
        "external projection id must start with an ASCII letter or digit and contain only ASCII letters, digits, '_' or '-'"
    )]
    MalformedProjectionId,
    /// Installation declared no projections.
    #[error("external installation must declare at least one projection")]
    InstallationWithoutProjections,
    /// Installation declared the same projection id more than once.
    #[error("external projection id {0:?} is duplicated")]
    DuplicateProjectionId(String),
    /// Provider projection declared no capabilities.
    #[error("provider projection must declare at least one provided effect")]
    ProviderWithoutCapabilities,
    /// Provider projection also declared source events.
    #[error("provider projection must not declare a source event stream")]
    ProviderWithEventSource,
    /// Source projection declared no event sink.
    #[error("source projection must declare an event stream")]
    SourceWithoutEventStream,
    /// Source projection also declared provider capabilities.
    #[error("source projection must not declare provider capabilities")]
    SourceWithCapabilities,
    /// Source commands were enabled without command schemas.
    #[error("source commands require command_schema and command_result_schema")]
    SourceCommandsWithoutSchemas,
    /// Source event payload size limit was invalid.
    #[error("source max_inline_payload_bytes must be greater than zero")]
    InvalidSourcePayloadLimit,
    /// Source stream capacity was invalid.
    #[error("source stream capacity max_events must be greater than zero")]
    InvalidSourceCapacity,
    /// Source backpressure thresholds were invalid.
    #[error(
        "source backpressure thresholds must satisfy resume_threshold < pause_threshold <= max_events"
    )]
    InvalidSourceBackpressureThresholds,
    /// Source ingress rate limit was invalid.
    #[error("source rate_limit window_ms and max_events must be greater than zero")]
    InvalidSourceRateLimit,
    /// Source event sink was not a concrete local state path.
    #[error("source event sink must be a concrete local state:// path: {actual}")]
    BadSourceEventSink {
        /// Event sink path supplied by the projection.
        actual: Box<Path>,
    },
    /// Sandboxed source event sink did not match its required path.
    #[error("sandboxed source event sink must be {expected}, got {actual}")]
    BadSandboxEventSink {
        /// Required sandbox sink path.
        expected: Box<Path>,
        /// Sink path supplied by the projection.
        actual: Box<Path>,
    },
    /// Provider effect path could not be parsed.
    #[error("provider effect path is malformed: {0}")]
    MalformedEffectPath(String),
    /// Provider effect path escaped the declared namespace.
    #[error("provider effect {effect} escapes namespace {namespace}")]
    NamespaceEscape {
        /// Declared provider namespace.
        namespace: Box<Path>,
        /// Escaping effect path.
        effect: Box<Path>,
    },
    /// Sandboxed provider namespace was not under the external provider prefix.
    #[error("sandboxed external provider namespace must be effect://external-provider/<id>")]
    BadSandboxNamespace,
    /// Sandboxed namespace id segment did not match installation id.
    #[error("sandboxed external id does not match namespace id segment")]
    SandboxIdMismatch,
    /// Full-trust installation used a transport reserved for sandboxed runtimes.
    #[error("full-trust external program cannot use transport {0}")]
    FullTrustTransport(String),
    /// Sandboxed installation attempted in-process transport.
    #[error("in-process transport requires full trust")]
    InProcessSandbox,
}

impl ExternalProjectionDef {
    /// Admission check for one single-role projection. `installation_id`,
    /// `transport`, and `trust` come from the owning installation.
    pub fn validate_admission(
        &self,
        installation_id: &str,
        trust: TrustLevel,
        transport: &Transport,
    ) -> Result<(), ExternalAdmissionError> {
        validate_installation_id(installation_id)?;
        validate_projection_id(&self.id)?;
        validate_trust_transport(trust, transport)?;

        match self.role {
            Role::Provider => {
                if self.provides.is_empty() {
                    return Err(ExternalAdmissionError::ProviderWithoutCapabilities);
                }
                if self.emits.is_some() {
                    return Err(ExternalAdmissionError::ProviderWithEventSource);
                }
                let namespace = self
                    .namespace
                    .as_ref()
                    .ok_or(ExternalAdmissionError::BadSandboxNamespace)?;
                if trust == TrustLevel::Sandboxed {
                    validate_sandbox_namespace(installation_id, namespace)?;
                }
                for cap in &self.provides {
                    let effect = Path::parse(&cap.effect_path).map_err(|_| {
                        ExternalAdmissionError::MalformedEffectPath(cap.effect_path.clone())
                    })?;
                    if !namespace.is_prefix_of(&effect) {
                        return Err(ExternalAdmissionError::NamespaceEscape {
                            namespace: Box::new(namespace.clone()),
                            effect: Box::new(effect),
                        });
                    }
                }
            }
            Role::Source => {
                let emits = self
                    .emits
                    .as_ref()
                    .ok_or(ExternalAdmissionError::SourceWithoutEventStream)?;
                if !self.provides.is_empty() {
                    return Err(ExternalAdmissionError::SourceWithCapabilities);
                }
                validate_source_event_sink(&emits.sink)?;
                if emits.commands
                    && (emits.command_schema.is_none() || emits.command_result_schema.is_none())
                {
                    return Err(ExternalAdmissionError::SourceCommandsWithoutSchemas);
                }
                if emits.max_inline_payload_bytes == 0 {
                    return Err(ExternalAdmissionError::InvalidSourcePayloadLimit);
                }
                validate_source_capacity(&emits.capacity)?;
                validate_source_rate_limit(emits.rate_limit.as_ref())?;
                if trust == TrustLevel::Sandboxed {
                    let expected = sandboxed_source_event_sink_path(installation_id, &self.id)?;
                    if emits.sink != expected {
                        return Err(ExternalAdmissionError::BadSandboxEventSink {
                            expected: Box::new(expected),
                            actual: Box::new(emits.sink.clone()),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

impl ExternalInstallationDef {
    /// Admission check for an installed runtime package and all of its
    /// projections. This is control-plane-only; the data-plane still sees
    /// Source ingest and Provider Bindings after reconcile.
    pub fn validate_admission(&self) -> Result<(), ExternalAdmissionError> {
        validate_installation_id(&self.id)?;
        validate_trust_transport(self.trust, &self.transport)?;
        if self.projections.is_empty() {
            return Err(ExternalAdmissionError::InstallationWithoutProjections);
        }
        let mut seen = std::collections::BTreeSet::new();
        for projection in &self.projections {
            if !seen.insert(projection.id.clone()) {
                return Err(ExternalAdmissionError::DuplicateProjectionId(
                    projection.id.clone(),
                ));
            }
            projection.validate_admission(&self.id, self.trust, &self.transport)?;
        }
        Ok(())
    }

    /// Return a projection by id.
    pub fn projection(&self, id: &str) -> Option<&ExternalProjectionDef> {
        self.projections
            .iter()
            .find(|projection| projection.id == id)
    }
}

fn validate_installation_id(id: &str) -> Result<(), ExternalAdmissionError> {
    if id.trim().is_empty() {
        return Err(ExternalAdmissionError::EmptyInstallationId);
    }
    if !is_safe_id_segment(id) {
        return Err(ExternalAdmissionError::MalformedInstallationId);
    }
    Ok(())
}

fn validate_projection_id(id: &str) -> Result<(), ExternalAdmissionError> {
    if id.trim().is_empty() {
        return Err(ExternalAdmissionError::EmptyProjectionId);
    }
    if !is_safe_id_segment(id) {
        return Err(ExternalAdmissionError::MalformedProjectionId);
    }
    Ok(())
}

fn is_safe_id_segment(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_trust_transport(
    trust: TrustLevel,
    transport: &Transport,
) -> Result<(), ExternalAdmissionError> {
    match (trust, transport) {
        (
            TrustLevel::Full,
            Transport::InProcess | Transport::Grpc { .. } | Transport::WebSocket { .. },
        ) => Ok(()),
        (TrustLevel::Full, other) => Err(ExternalAdmissionError::FullTrustTransport(
            transport_name(other).into(),
        )),
        (TrustLevel::Sandboxed, Transport::InProcess) => {
            Err(ExternalAdmissionError::InProcessSandbox)
        }
        (TrustLevel::Sandboxed, _) => Ok(()),
    }
}

fn validate_sandbox_namespace(id: &str, namespace: &Path) -> Result<(), ExternalAdmissionError> {
    let segs = namespace.segments();
    let ok_prefix = namespace.scheme() == "effect"
        && segs.len() >= 2
        && segs[0].as_str() == "external-provider";
    if !ok_prefix {
        return Err(ExternalAdmissionError::BadSandboxNamespace);
    }
    if segs[1].as_str() != id {
        return Err(ExternalAdmissionError::SandboxIdMismatch);
    }
    Ok(())
}

fn validate_source_event_sink(path: &Path) -> Result<(), ExternalAdmissionError> {
    let concrete = path
        .segments()
        .iter()
        .all(|seg| !matches!(seg.as_str(), "*" | "**"));
    if path.cluster().is_none()
        && path.scheme() == "state"
        && !path.segments().is_empty()
        && concrete
    {
        Ok(())
    } else {
        Err(ExternalAdmissionError::BadSourceEventSink {
            actual: Box::new(path.clone()),
        })
    }
}

fn validate_source_capacity(capacity: &StreamCapacity) -> Result<(), ExternalAdmissionError> {
    if capacity.max_events == 0 {
        return Err(ExternalAdmissionError::InvalidSourceCapacity);
    }
    if let OverflowPolicy::Backpressure {
        pause_threshold,
        resume_threshold,
    } = &capacity.on_overflow
        && (resume_threshold >= pause_threshold || pause_threshold > &capacity.max_events)
    {
        return Err(ExternalAdmissionError::InvalidSourceBackpressureThresholds);
    }
    Ok(())
}

fn validate_source_rate_limit(
    rate_limit: Option<&SourceRateLimit>,
) -> Result<(), ExternalAdmissionError> {
    let Some(rate_limit) = rate_limit else {
        return Ok(());
    };
    if rate_limit.window_ms == 0 || rate_limit.max_events == 0 {
        return Err(ExternalAdmissionError::InvalidSourceRateLimit);
    }
    Ok(())
}

/// Build the required source event sink for a sandboxed source projection.
pub fn sandboxed_source_event_sink_path(
    installation_id: &str,
    projection_id: &str,
) -> Result<Path, ExternalAdmissionError> {
    validate_installation_id(installation_id)?;
    validate_projection_id(projection_id)?;
    Ok(Path::try_new("state")
        .expect("static scheme is valid")
        .try_push("events")
        .expect("static segment is valid")
        .try_push("external")
        .expect("static segment is valid")
        .try_push(installation_id)
        .expect("validated installation id is a valid path segment")
        .try_push(projection_id)
        .expect("validated projection id is a valid path segment"))
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

/// A reusable install template stored as pure state. Lets multiple installations,
/// such as several Telegram accounts, share one config contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestDef {
    /// Connector name this template installs.
    pub platform: String,
    /// Source of an installation's shared config schema.
    pub config_schema: JsonSchema,
    /// Projection templates this manifest can install.
    pub projections: Vec<ExternalProjectionDef>,
    /// Transports supported by this manifest.
    pub supported_transports: Vec<Transport>,
    /// Default transport selected when an installation does not override it.
    pub default_transport: Transport,
    /// Optimistic concurrency/config revision for this install template.
    pub version: u64,
}

// Pairing payload.

/// Transport choices encoded in a pairing payload. This is narrower than the
/// generic provider [`Transport`]: pairing only tells an unpaired external
/// program where to submit its claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTransport {
    /// WebSocket pairing endpoint.
    WebSocket,
    /// gRPC pairing endpoint.
    Grpc,
}

/// The daemon connection choices embedded in a pairing payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonContacts {
    /// Ordered daemon contact candidates.
    pub contacts: Vec<DaemonContact>,
}

/// One daemon endpoint from a pairing payload. `authority` is the single source
/// of host/IP + port (`host:7443`, `192.168.1.20:7443`, `[fd00::12]:7443`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonContact {
    /// Transport used for this contact.
    pub transport: ExternalTransport,
    /// Host/IP plus port, without URL scheme.
    pub authority: String,
    /// Service name exposed at this contact.
    pub service: String,
    /// Optional TLS server name override.
    #[serde(default)]
    pub tls_name: Option<String>,
    /// Lower numbers are preferred.
    pub priority: u8,
}

/// The exact payload encoded by the visual pair card, manual code, and copy
/// pass. Visual encodings may compress or shard it, but must not omit contacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairingPayload {
    /// Pairing payload schema version.
    pub version: u32,
    /// Pairing flow id.
    pub pairing_id: String,
    /// One-time secret used to claim the pairing.
    pub pairing_secret: String,
    /// Daemon contact list.
    pub daemon_contacts: DaemonContacts,
    /// Daemon identity public key.
    pub daemon_identity_pub: String,
    /// Human-checkable daemon fingerprint.
    pub daemon_fingerprint: String,
    /// Expiry timestamp.
    pub expires_at: Timestamp,
    /// Display checksum for human/manual verification.
    pub display_checksum: String,
}

impl DaemonContact {
    /// Validate authority and service fields.
    pub fn validate(&self) -> Result<(), PairingPayloadError> {
        validate_authority(&self.authority)?;
        if self.service.trim().is_empty() {
            return Err(PairingPayloadError::EmptyService);
        }
        Ok(())
    }
}

impl PairingPayload {
    /// Validate that the payload contains usable daemon contacts.
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

/// Pairing payload validation errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PairingPayloadError {
    /// Payload had no daemon contacts.
    #[error("pairing payload must include at least one daemon contact")]
    MissingContacts,
    /// Contact authority was not `host:port` or `[ipv6]:port`.
    #[error("daemon contact authority must be host:port or [ipv6]:port, without a scheme")]
    BadAuthority,
    /// Contact service name was empty.
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

// proc:// executor resource.

/// How a dead `proc://` process is restarted, borrowing Erlang/OTP
/// supervision semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Never restart after exit.
    Never,
    /// Restart on failure up to `max` failures inside `window_ms`.
    OnFailure {
        /// Maximum failures allowed inside the window.
        max: u32,
        /// Failure-counting window in milliseconds.
        window_ms: u64,
    },
    /// Always restart using the configured backoff.
    Always {
        /// Backoff strategy between restarts.
        backoff: Backoff,
    },
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::OnFailure {
            max: 5,
            window_ms: 60_000,
        }
    }
}

/// Restart backoff strategy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backoff {
    /// Fixed delay between restarts.
    Fixed {
        /// Delay in milliseconds.
        ms: u64,
    },
    /// Exponential backoff.
    Exp {
        /// Initial delay in milliseconds.
        base_ms: u64,
        /// Maximum delay in milliseconds.
        cap_ms: u64,
        /// Whether jitter should be applied.
        jitter: bool,
    },
}

/// Spec for an external process projected as an Executor Resource.
/// Only `ProcDriver` (privileged) consumes this; it is the sole driver that
/// can fork/exec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcSpec {
    /// Process id under `proc://`.
    pub id: String,
    /// Decides how to bring it up: Stdio is self-forked; Grpc/WS/Http connect.
    pub transport: Transport,
    /// argv for a Stdio child; `None` for an externally-managed process.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Environment variables passed to a Stdio child.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Working directory for a Stdio child.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Restart policy used by supervision.
    pub restart: RestartPolicy,
}

// Data and control frames.

/// Daemon-owned flow-control signal carried on a [`ControlFrame`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowSignal {
    /// Pause delivery toward the external program.
    Pause,
    /// Resume delivery toward the external program.
    Resume,
}

/// Generation tags an external program echoes for comparison; the daemon holds the
/// authority and chooses the real values. Only the two lightweight
/// presentation/alias axes ride on each inbound event — session-level
/// generations live in [`SessionContext`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedGenerations {
    /// Presentation configuration generation observed by the external program.
    #[serde(default)]
    pub presentation_config_generation: u64,
    /// Alias catalog generation observed by the external program.
    #[serde(default)]
    pub alias_catalog_generation: u64,
}

/// Stage 1 of the session handshake: the external program opens by
/// reporting identity + locally cached generations/hash (pure echo, no
/// authority). Self-describing external programs report their config contract here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleSessionClientHello {
    /// Role requested by the external endpoint.
    pub role: Role,
    /// Installation id the endpoint claims.
    pub installation_id: String,
    /// Projection id the endpoint claims.
    pub projection_id: String,
    /// Registry hash observed by the endpoint.
    pub registry_hash: String,
    /// Lightweight generation tags observed by the endpoint.
    #[serde(default)]
    pub observed: ObservedGenerations,
    /// Optional self-described config schema.
    #[serde(default)]
    pub config_schema: Option<JsonSchema>,
}

/// Stage 2 of the handshake: the daemon adjudicates every
/// authoritative registry hash/generation and sends them down. The external program
/// never declares or guesses these.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionContext {
    /// Installation id accepted by the daemon.
    pub installation_id: String,
    /// Projection id accepted by the daemon.
    pub projection_id: String,
    /// Role accepted by the daemon.
    pub role: Role,
    /// Authoritative registry hash.
    pub registry_hash: String,
    /// Credential generation selected by the daemon.
    pub credential_generation: u64,
    /// Binding generation selected by the daemon.
    pub binding_generation: u64,
    /// Installation config version selected by the daemon.
    pub installation_config_version: u64,
    /// Projection version selected by the daemon.
    pub projection_version: u64,
    /// Presentation config generation selected by the daemon.
    pub presentation_config_generation: u64,
    /// Alias catalog generation selected by the daemon.
    pub alias_catalog_generation: u64,
    /// Daemon-selected session id for this role connection.
    pub session_id: String,
}

/// Stage 3 of the handshake: the role client confirms it has aligned to
/// the daemon-chosen [`SessionContext`]. Any generation/hash mismatch is
/// fail-closed; no business frames flow before this.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleReady {
    /// Session context accepted by the role client.
    pub accepted_context: SessionContext,
}

/// Which configuration axis a [`ControlFrame::ConfigAck`] answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigAxis {
    /// Authority/configuration axis.
    InstallationConfig,
    /// Presentation-only axis.
    PresentationConfig,
}

/// Why a role client rejected a config/presentation update.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Presentation or profile hash did not match.
    ProfileMismatch,
    /// Config payload failed schema validation.
    SchemaInvalid,
    /// Update generation was stale.
    GenerationStale,
    /// Endpoint does not support this update.
    Unsupported,
}

/// Result of applying a config/presentation update.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    /// Update was applied.
    Applied,
    /// Update was rejected.
    Rejected {
        /// Rejection reason.
        reason: RejectReason,
    },
}

/// Control frames shared by both roles. Configuration travels on two
/// independent axes that never mix — `InstallationConfigUpdate` (authority: what
/// the role client may do) and `PresentationConfigUpdate` (presentation only:
/// never grants capability) — plus a profile-report axis flowing the other way.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFrame {
    /// Liveness heartbeat.
    Heartbeat {
        /// Heartbeat timestamp in milliseconds since epoch.
        timestamp_ms: i64,
    },
    /// Daemon-to-role-client graceful or forced shutdown request.
    Shutdown {
        /// Whether the endpoint should attempt graceful shutdown.
        graceful: bool,
        /// Shutdown timeout in milliseconds.
        timeout_ms: u64,
    },
    /// Daemon-to-role-client flow-control signal.
    FlowControl(FlowSignal),
    /// Cancel one Provider invocation previously sent by the daemon.
    ProviderCancel {
        /// Invocation id being cancelled.
        invocation_id: String,
        /// Redacted cancellation reason.
        reason: String,
    },
    /// Report axis from role client to daemon. Declares what this end can render and
    /// which entry points are locally disabled. The profile body is opaque
    /// here; connector docs such as Web/Mobile define its schema.
    PresentationProfileUpdate {
        /// Profile generation reported by the role client.
        profile_generation: u64,
        /// Hash of the reported profile.
        profile_hash: String,
        /// Opaque profile body.
        profile: Value,
    },
    /// Authority axis from daemon to role client via a CAS state write. Advances
    /// `ExternalInstallationDef.version` and may bump the Binding generation.
    InstallationConfigUpdate {
        /// New external config version.
        config_version: u64,
        /// New external config body.
        config: Value,
    },
    /// Presentation axis from daemon to role client: pure display / entry-point /
    /// renderer budget — never grants capability, bounded by `profile_hash`.
    PresentationConfigUpdate {
        /// New presentation config generation.
        generation: u64,
        /// Profile hash this config targets.
        profile_hash: String,
        /// Presentation config body.
        config: Value,
    },
    /// Shared reply loop: the role client must report how it applied an update;
    /// the daemon uses it to judge liveness and to fail closed.
    ConfigAck {
        /// Config axis being acknowledged.
        axis: ConfigAxis,
        /// Version or generation being acknowledged.
        version: u64,
        /// Apply result.
        status: ApplyStatus,
    },
}

/// Provider readiness entry reported by a remote endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectHandlerSpec {
    /// Effect resource path the endpoint can handle.
    pub path: String,
    /// Declared replay safety for this handler.
    pub purity: Purity,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Provider frame declaring that startup is complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderReady {
    /// Runtime handler set reported by the endpoint.
    #[serde(default)]
    pub provides: Vec<EffectHandlerSpec>,
}

/// Provider data frame: one remote Operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invoke {
    /// Stable across reconnect/replay: derived from the business idempotency
    /// key when present, else from CausalPosition.
    pub invocation_id: String,
    /// Effect resource path invoked by the remote operation.
    pub effect_path: Path,
    /// Concrete method on the Resource interface. Remote endpoint dispatch must
    /// preserve this just like a local [`Driver`](crate::resource::Method).
    pub method_id: MethodId,
    /// Operation input value.
    pub input: Value,
    /// Optional deadline in milliseconds since epoch.
    #[serde(default)]
    pub deadline_ms: Option<i64>,
    /// Optional stream path for streaming output.
    #[serde(default)]
    pub output_stream_to: Option<Path>,
}

/// Error detail returned in an [`InvokeResult`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Stable error class.
    pub kind: String,
    /// Error message.
    pub message: String,
}

/// Provider data frame: the result of one [`Invoke`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvokeResult {
    /// Invocation id matching the request.
    pub invocation_id: String,
    /// Successful output value or endpoint error detail.
    pub outcome: Result<Value, ErrorInfo>,
}

/// Source data frame: one inbound event. Carries only the two
/// lightweight presentation/alias generation tags — session-level generations
/// are settled in the handshake [`SessionContext`], not on each event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InboundEvent {
    /// Event id used for deduplication and acknowledgement.
    pub id: String,
    /// Event payload.
    pub payload: Value,
    /// Lightweight generation tags observed when emitting the event.
    #[serde(default)]
    pub observed: ObservedGenerations,
    /// Event timestamp in milliseconds since epoch.
    pub timestamp_ms: i64,
    /// Optional stream id for ordered source delivery.
    #[serde(default)]
    pub stream_id: Option<String>,
    /// Optional stream-local sequence number. When set, the daemon admits only
    /// the next sequence for `stream_id`.
    #[serde(default)]
    pub seq: Option<u64>,
}

/// Source data frame: a command sent back out to the source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundCommand {
    /// Command id used for deduplication.
    pub id: String,
    /// Opaque command body understood by the Source.
    pub action: Value,
    /// Lightweight generation tags attached by the daemon.
    #[serde(default)]
    pub observed: ObservedGenerations,
}

/// Source data frame: the result of one [`OutboundCommand`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandResult {
    /// Command id matching the outbound command.
    pub id: String,
    /// Successful result value or endpoint error detail.
    pub outcome: Result<Value, ErrorInfo>,
}

/// Acknowledgement status for an inbound event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckStatus {
    /// Event was accepted.
    Accepted,
    /// Event was already processed.
    Duplicate,
    /// Event was rejected.
    Rejected,
}

/// Source data frame: ack of an [`InboundEvent`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventAck {
    /// Event id being acknowledged.
    pub id: String,
    /// Acknowledgement status.
    pub status: AckStatus,
    /// Redacted reason when the event was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

// Inbound stream capacity and rate limits.

/// What to do when an inbound stream overflows its capacity. Distinct
/// from rate limiting, which is a policy concern.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    /// Drop oldest buffered events.
    DropOldest,
    /// Ask the bridge to pause and resume at thresholds.
    Backpressure {
        /// Pause threshold.
        pause_threshold: u32,
        /// Resume threshold.
        resume_threshold: u32,
    },
    /// Disconnect the bridge when capacity is exceeded.
    DisconnectBridge,
}

/// Capacity of an inbound event stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamCapacity {
    /// Maximum buffered events.
    pub max_events: u32,
    /// Overflow handling policy.
    pub on_overflow: OverflowPolicy,
}

/// Rate limit for inbound events on one Source projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceRateLimit {
    /// Sliding window length in milliseconds.
    pub window_ms: u64,
    /// Maximum events admitted during the window.
    pub max_events: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_source_capacity() -> StreamCapacity {
        StreamCapacity {
            max_events: 1024,
            on_overflow: OverflowPolicy::Backpressure {
                pause_threshold: 1024,
                resume_threshold: 512,
            },
        }
    }

    #[test]
    fn installation_with_source_and_provider_projections_is_admitted() {
        let install = ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![
                ExternalProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(EventSource {
                        sink: sandboxed_source_event_sink_path(
                            "instant_messaging_platform",
                            "source",
                        )
                        .unwrap(),
                        purity: Purity::Effectful,
                        event_schema: None,
                        max_inline_payload_bytes: 65_536,
                        capacity: test_source_capacity(),
                        rate_limit: None,
                        commands: false,
                        command_schema: None,
                        command_result_schema: None,
                    }),
                    version: 1,
                },
                ExternalProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(
                        Path::parse("effect://external-provider/instant_messaging_platform")
                            .unwrap(),
                    ),
                    provides: vec![EffectCapability::new(
                        "effect://external-provider/instant_messaging_platform/send_text",
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
        let projection = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            namespace: Some(
                Path::parse("effect://external-provider/instant_messaging_platform").unwrap(),
            ),
            provides: vec![EffectCapability::new(
                "effect://external-provider/instant_messaging_platform/send_text",
                Purity::Effectful,
            )],
            emits: None,
            version: 1,
        };
        let install = ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![projection.clone(), projection],
            version: 1,
        };
        assert_eq!(
            install.validate_admission(),
            Err(ExternalAdmissionError::DuplicateProjectionId(
                "provider".into()
            ))
        );
    }

    #[test]
    fn sandbox_provider_admission_is_structural_and_fail_closed() {
        let valid = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![EffectCapability::new(
                "effect://external-provider/acme/search",
                Purity::Idempotent,
            )],
            emits: None,
            namespace: Some(Path::parse("effect://external-provider/acme").unwrap()),
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
        sibling_escape.provides[0].effect_path =
            "effect://external-provider/acmeevil/search".into();
        assert!(matches!(
            sibling_escape.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![]
                }
            ),
            Err(ExternalAdmissionError::NamespaceEscape { .. })
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
            Err(ExternalAdmissionError::BadSandboxNamespace)
        );
    }

    #[test]
    fn projection_role_shape_is_fail_closed() {
        let provider_without_caps = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![],
            emits: None,
            namespace: Some(Path::parse("effect://external-provider/acme").unwrap()),
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
            Err(ExternalAdmissionError::ProviderWithoutCapabilities)
        );

        let source_with_caps = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![EffectCapability::new(
                "effect://external-provider/bridge/tool",
                Purity::Effectful,
            )],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source").unwrap(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: test_source_capacity(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
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
            Err(ExternalAdmissionError::SourceWithCapabilities)
        );
    }

    #[test]
    fn sandbox_source_event_sink_is_canonical_and_fail_closed() {
        let valid = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source").unwrap(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: test_source_capacity(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            namespace: None,
            version: 1,
        };
        assert_eq!(
            valid.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Ok(())
        );

        let mut bad = valid.clone();
        bad.emits.as_mut().unwrap().sink = Path::parse("state://chat/bridge/events").unwrap();
        assert!(matches!(
            bad.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExternalAdmissionError::BadSandboxEventSink { .. })
        ));
    }

    #[test]
    fn source_commands_require_command_schemas() {
        let source = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source").unwrap(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: test_source_capacity(),
                rate_limit: None,
                commands: true,
                command_schema: None,
                command_result_schema: Some(Value::Map(std::collections::BTreeMap::from([(
                    "type".into(),
                    Value::Str("string".into()),
                )]))),
            }),
            namespace: None,
            version: 1,
        };

        assert_eq!(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExternalAdmissionError::SourceCommandsWithoutSchemas)
        );
    }

    #[test]
    fn source_capacity_and_rate_limit_admission_is_fail_closed() {
        let mut source = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source").unwrap(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: test_source_capacity(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            namespace: None,
            version: 1,
        };

        source.emits.as_mut().unwrap().max_inline_payload_bytes = 0;
        assert_eq!(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExternalAdmissionError::InvalidSourcePayloadLimit)
        );

        let emits = source.emits.as_mut().unwrap();
        emits.max_inline_payload_bytes = 65_536;
        emits.capacity.max_events = 0;
        assert_eq!(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExternalAdmissionError::InvalidSourceCapacity)
        );

        let emits = source.emits.as_mut().unwrap();
        emits.capacity = StreamCapacity {
            max_events: 10,
            on_overflow: OverflowPolicy::Backpressure {
                pause_threshold: 5,
                resume_threshold: 5,
            },
        };
        assert_eq!(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExternalAdmissionError::InvalidSourceBackpressureThresholds)
        );

        let emits = source.emits.as_mut().unwrap();
        emits.capacity = test_source_capacity();
        emits.rate_limit = Some(SourceRateLimit {
            window_ms: 0,
            max_events: 1,
        });
        assert_eq!(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into())
                }
            ),
            Err(ExternalAdmissionError::InvalidSourceRateLimit)
        );
    }

    #[test]
    fn source_event_sink_must_be_local_concrete_state_path() {
        let source = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: Path::parse("state://events/full/source").unwrap(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: test_source_capacity(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            namespace: None,
            version: 1,
        };
        assert_eq!(
            source.validate_admission(
                "bridge",
                TrustLevel::Full,
                &Transport::Grpc { endpoint: None }
            ),
            Ok(())
        );

        let mut wildcard = source.clone();
        wildcard.emits.as_mut().unwrap().sink = Path::parse("state://events/**").unwrap();
        assert!(matches!(
            wildcard.validate_admission(
                "bridge",
                TrustLevel::Full,
                &Transport::Grpc { endpoint: None }
            ),
            Err(ExternalAdmissionError::BadSourceEventSink { .. })
        ));

        let mut clustered = source.clone();
        clustered.emits.as_mut().unwrap().sink =
            Path::parse("path://phone/state/events/full/source").unwrap();
        assert!(matches!(
            clustered.validate_admission(
                "bridge",
                TrustLevel::Full,
                &Transport::Grpc { endpoint: None }
            ),
            Err(ExternalAdmissionError::BadSourceEventSink { .. })
        ));
    }

    #[test]
    fn trust_transport_combo_is_fail_closed() {
        let full_stdio = ExternalInstallationDef {
            id: "local-tool".into(),
            platform: "local-tool".into(),
            transport: Transport::Stdio {
                command: Some("tool".into()),
                args: vec![],
            },
            trust: TrustLevel::Full,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![ExternalProjectionDef {
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
            Err(ExternalAdmissionError::FullTrustTransport(t)) if t == "stdio"
        ));

        let mut sandbox_in_process = full_stdio.clone();
        sandbox_in_process.id = "tool".into();
        sandbox_in_process.trust = TrustLevel::Sandboxed;
        sandbox_in_process.transport = Transport::InProcess;
        sandbox_in_process.projections[0].namespace =
            Some(Path::parse("effect://external-provider/tool").unwrap());
        sandbox_in_process.projections[0].provides[0].effect_path =
            "effect://external-provider/tool/run".into();
        assert_eq!(
            sandbox_in_process.validate_admission(),
            Err(ExternalAdmissionError::InProcessSandbox)
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
            installation_config_version: 1,
            projection_version: 1,
            presentation_config_generation: 4,
            alias_catalog_generation: 5,
            session_id: "session-1".into(),
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
    fn command_result_carries_error() {
        let r = CommandResult {
            id: "cmd-1".into(),
            outcome: Err(ErrorInfo {
                kind: "bridge_error".into(),
                message: "failed".into(),
            }),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: CommandResult = serde_json::from_str(&s).unwrap();
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
                        transport: ExternalTransport::WebSocket,
                        authority: "192.168.1.20:7443".into(),
                        service: "/external/pair".into(),
                        tls_name: None,
                        priority: 10,
                    },
                    DaemonContact {
                        transport: ExternalTransport::Grpc,
                        authority: "[fd00::12]:7443".into(),
                        service: "NexusExternalPairing.Pair".into(),
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
            transport: ExternalTransport::WebSocket,
            authority: "https://nexus.local:7443".into(),
            service: "/external/pair".into(),
            tls_name: None,
            priority: 1,
        };
        assert_eq!(bad.validate(), Err(PairingPayloadError::BadAuthority));
    }
}
