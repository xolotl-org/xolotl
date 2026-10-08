//! External projection: how an external capability is declared and how
//! it lands on kernel primitives.
//!
//! An external program projects onto kernel primitives: the process becomes an
//! Executor Resource (`proc://<id>`), each provided capability becomes a remote
//! `Binding`, and configuration is plain state the console reads and writes.
//! This module holds declarations and wire frames as wasm-safe data.

use crate::Timestamp;
use crate::ids::MethodId;
use crate::path::{Path, PathError, is_simple_id_segment};
use crate::replay::Purity;
use crate::value::Value;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::external_descriptor::{EffectCapability, Transport, TrustLevel};

/// Kernel-state prefix for external pairing decisions.
pub const EXTERNAL_PAIRINGS_PREFIX: &str = "state://kernel/external-pairings";
/// Kernel-state prefix for approved external role sessions.
pub const EXTERNAL_SESSIONS_PREFIX: &str = "state://kernel/external-sessions";
/// Kernel-state prefix for external credential revocation floors.
pub const EXTERNAL_CREDENTIAL_REVOCATIONS_PREFIX: &str =
    "state://kernel/external-credential-revocations";
/// Effect namespace for commands sent to a Source projection.
pub const EXTERNAL_SOURCE_COMMANDS_PREFIX: &str = "effect://external-source";

/// Address one external pairing decision.
pub fn external_pairing_path(id: &str) -> Result<Path, PathError> {
    external_child_path(EXTERNAL_PAIRINGS_PREFIX, id)
}

/// Address one installation's approved role session.
pub fn external_session_path(installation_id: &str, role: Role) -> Result<Path, PathError> {
    external_child_path(EXTERNAL_SESSIONS_PREFIX, installation_id)?.try_push_literal(role.as_str())
}

/// Address one installation's credential revocation floor.
pub fn external_credential_revocation_path(installation_id: &str) -> Result<Path, PathError> {
    external_child_path(EXTERNAL_CREDENTIAL_REVOCATIONS_PREFIX, installation_id)
}

/// Address the command effect of one Source projection. The daemon owns this
/// path; calling its `dispatch` method still requires an ordinary Kernel grant.
pub fn external_source_command_path(
    installation_id: &str,
    projection_id: &str,
) -> Result<Path, PathError> {
    validate_external_id(installation_id)?;
    validate_external_id(projection_id)?;
    Path::parse(EXTERNAL_SOURCE_COMMANDS_PREFIX)?
        .try_push_literal(installation_id)?
        .try_push_literal(projection_id)?
        .try_push("command")
}

/// Build the required Provider namespace for a sandboxed installation.
pub fn sandboxed_provider_namespace_path(installation_id: &str) -> Result<Path, PathError> {
    validate_external_id(installation_id)?;
    Path::try_new("effect")?
        .try_push("external-provider")?
        .try_push_literal(installation_id)
}

fn external_child_path(prefix: &str, id: &str) -> Result<Path, PathError> {
    validate_external_id(id)?;
    Path::parse(prefix)?.try_push_literal(id)
}

fn validate_external_id(id: &str) -> Result<(), PathError> {
    if id.is_empty() {
        return Err(PathError::EmptySegment);
    }
    if !is_simple_id_segment(id) {
        return Err(PathError::BadSegmentChar(id.into()));
    }
    Ok(())
}

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
    /// Transport used to communicate with the external runtime. Stdio must
    /// name an absolute executable path; child startup does not inherit the
    /// daemon environment.
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

impl Role {
    /// Stable v1 role name used in state paths, pairing records, and secure
    /// envelope authenticated data.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Source => "source",
        }
    }

    /// Interpret an exact v1 role name from a pairing or session record.
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "provider" => Some(Self::Provider),
            "source" => Some(Self::Source),
            _ => None,
        }
    }
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
    /// Provider projection declared the same effect more than once.
    #[error("provider projection effect {0:?} is duplicated")]
    DuplicateProviderEffect(String),
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
    /// Source event sink was not a concrete local non-reserved state path.
    #[error("source event sink must be a concrete local non-reserved state:// path: {actual}")]
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
    /// Required sandboxed source event sink could not be built.
    #[error("sandboxed source event sink path is malformed: {0}")]
    MalformedSandboxEventSinkPath(String),
    /// Provider effect path could not be parsed.
    #[error("provider effect path {path:?} is malformed: {reason}")]
    MalformedEffectPath {
        /// Effect path supplied by the projection.
        path: String,
        /// Parse failure.
        reason: String,
    },
    /// Provider effect path was not a concrete effect resource.
    #[error("provider effect path must be a concrete effect:// path: {0}")]
    BadEffectPath(String),
    /// Provider effect path targeted a kernel-reserved effect.
    #[error("provider effect path must not target effect://kernel/*")]
    KernelEffectPath,
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
    /// Host-managed session routing is an internal driver transport, not an installation choice.
    #[error("host-session transport cannot be declared by an external installation")]
    HostSessionInstallation,
    /// Stdio installation did not name an absolute executable path.
    #[error("stdio installation command must be an absolute executable path")]
    InvalidStdioCommand,
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
                let mut effects = BTreeSet::new();
                for cap in &self.provides {
                    let effect = Path::parse(&cap.effect_path).map_err(|error| {
                        ExternalAdmissionError::MalformedEffectPath {
                            path: cap.effect_path.clone(),
                            reason: error.to_string(),
                        }
                    })?;
                    if effect.scheme() != "effect"
                        || effect.segments().is_empty()
                        || !effect.is_concrete()
                    {
                        return Err(ExternalAdmissionError::BadEffectPath(
                            cap.effect_path.clone(),
                        ));
                    }
                    if crate::is_kernel_reserved(&effect) {
                        return Err(ExternalAdmissionError::KernelEffectPath);
                    }
                    if !effects.insert(effect.clone()) {
                        return Err(ExternalAdmissionError::DuplicateProviderEffect(
                            cap.effect_path.clone(),
                        ));
                    }
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
        if let Transport::Stdio { command, .. } = &self.transport {
            let valid = command.as_deref().is_some_and(is_absolute_executable_path);
            if !valid {
                return Err(ExternalAdmissionError::InvalidStdioCommand);
            }
        }
        if self.projections.is_empty() {
            return Err(ExternalAdmissionError::InstallationWithoutProjections);
        }
        let mut seen = alloc::collections::BTreeSet::new();
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

fn is_absolute_executable_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'/' || bytes[2] == b'\\'))
}

fn validate_installation_id(id: &str) -> Result<(), ExternalAdmissionError> {
    if id.trim().is_empty() {
        return Err(ExternalAdmissionError::EmptyInstallationId);
    }
    if !crate::path::is_simple_id_segment(id) {
        return Err(ExternalAdmissionError::MalformedInstallationId);
    }
    Ok(())
}

fn validate_projection_id(id: &str) -> Result<(), ExternalAdmissionError> {
    if id.trim().is_empty() {
        return Err(ExternalAdmissionError::EmptyProjectionId);
    }
    if !crate::path::is_simple_id_segment(id) {
        return Err(ExternalAdmissionError::MalformedProjectionId);
    }
    Ok(())
}

fn validate_trust_transport(
    trust: TrustLevel,
    transport: &Transport,
) -> Result<(), ExternalAdmissionError> {
    match (trust, transport) {
        (_, Transport::HostSession) => Err(ExternalAdmissionError::HostSessionInstallation),
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
    let ok_prefix = namespace.cluster().is_none()
        && namespace.scheme() == "effect"
        && segs.len() == 2
        && segs[0].as_str() == "external-provider"
        && namespace.is_concrete();
    if !ok_prefix {
        return Err(ExternalAdmissionError::BadSandboxNamespace);
    }
    if segs[1].as_str() != id {
        return Err(ExternalAdmissionError::SandboxIdMismatch);
    }
    Ok(())
}

fn validate_source_event_sink(path: &Path) -> Result<(), ExternalAdmissionError> {
    if path.cluster().is_none()
        && path.scheme() == "state"
        && !path.segments().is_empty()
        && path.is_concrete()
        && !crate::is_kernel_reserved(path)
        && !crate::is_vault_reserved(path)
        && !crate::is_fact_reserved(path)
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

    Path::try_new("state")
        .and_then(|path| path.try_push("events"))
        .and_then(|path| path.try_push("external"))
        .and_then(|path| path.try_push_literal(installation_id))
        .and_then(|path| path.try_push_literal(projection_id))
        .map_err(|error| ExternalAdmissionError::MalformedSandboxEventSinkPath(error.to_string()))
}

fn transport_name(t: &Transport) -> &'static str {
    match t {
        Transport::InProcess => "in_process",
        Transport::HostSession => "host_session",
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
        /// Whether jitter is applied.
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

/// Client hello for an external session handshake.
///
/// The external program reports identity plus locally cached generations/hash.
/// Self-describing external programs report their config contract here.
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

/// Daemon-selected context for an external session.
///
/// The daemon adjudicates every authoritative registry hash and generation. The
/// external program echoes these values but never declares them.
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
    /// Storage-issued installation incarnation. Every role requires a nonzero
    /// value; retirement followed by reinstallation invalidates prior sessions.
    pub installation_epoch: u64,
    /// Storage-issued active Source scope epoch for this projection. Source
    /// sessions require a nonzero value; Provider sessions use zero. A removed
    /// and reinstalled Source receives a new epoch, fencing older sessions.
    pub scope_epoch: u64,
    /// Daemon-selected session id for this role connection.
    pub session_id: String,
    /// Current AEAD key epoch selected by the daemon before authenticated Ready.
    pub key_epoch: u64,
}

/// Ready acknowledgement for an external session.
///
/// The role client confirms it has aligned to the daemon-chosen
/// [`SessionContext`]. Any generation/hash mismatch is fail-closed; no
/// business frames flow before this.
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
        /// Whether the endpoint attempts graceful shutdown.
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

/// Provider data frame: one remote Operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invoke {
    /// Stable request correlation identity across reconnect or checkpoint restore.
    /// Kernel remote calls use the complete OperationId string; the data plane
    /// applies business idempotency keys separately.
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
    /// Storage-issued incarnation of an ordered stream. All of `stream_id`,
    /// `seq`, and `stream_epoch` are supplied together; data cannot open a stream.
    #[serde(default)]
    pub stream_epoch: Option<u64>,
}

/// Source request to inspect, open, or retire one ordered stream in the ready
/// Source scope. An Open's `request_id` is its stable storage open identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStreamRequest {
    /// Correlation id, also the Open idempotency identity.
    pub request_id: String,
    /// Stream-local identity; the storage-issued epoch distinguishes lives.
    pub stream_id: String,
    /// Requested lifecycle operation.
    pub operation: SourceStreamOperation,
}

/// Lifecycle operations on a Source stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStreamOperation {
    /// Read the current scope-local catalog revision and stream state.
    Inspect,
    /// Open only against an observed catalog revision.
    Open {
        /// Scope-local revision observed by the client.
        expected_revision: u64,
    },
    /// Conditionally close this exact stream incarnation.
    Retire {
        /// Storage-issued stream incarnation; zero is invalid.
        stream_epoch: u64,
    },
}

/// Current state of an active ordered Source stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStreamState {
    /// Storage-issued incarnation.
    pub stream_epoch: u64,
    /// Last accepted sequence; zero immediately after Open.
    pub last_seq: u64,
    /// Stable Open request identity, returned to distinguish a retry.
    pub open_id: String,
    /// Catalog revision observed by the successful Open. An Open retry must
    /// preserve both this revision and `open_id`.
    pub opened_at_revision: u64,
}

/// Inspection or successful Open result for a Source stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStreamSnapshot {
    /// Scope-local catalog revision; changes on each Open or Retire.
    pub revision: u64,
    /// Active stream state, if this name is currently open.
    pub active: Option<SourceStreamState>,
}

/// Machine-readable refusal of a Source stream lifecycle request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStreamRejectCode {
    /// Invalid stream path segment.
    InvalidStreamId,
    /// Invalid correlation/Open identity.
    InvalidRequestId,
    /// Zero stream epoch supplied to Retire.
    InvalidEpoch,
    /// Session's Source scope is no longer active.
    ScopeInactive,
    /// Catalog changed since Inspect; inspect again before a new Open.
    RevisionConflict,
    /// Another Open identity already owns this stream name.
    AlreadyOpen,
    /// Storage has no room for another active ordered stream.
    QuotaExceeded,
    /// Retire found no active stream with this name.
    Inactive,
    /// Retire named a prior stream incarnation.
    StaleEpoch,
    /// Storage proved that the requested operation aborted.
    StorageUnavailable,
    /// Storage could not prove whether the operation committed; inspect/retry.
    OutcomeUnknown,
}

/// Context supplied with a deterministic lifecycle rejection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStreamRejected {
    /// Stable reason code.
    pub code: SourceStreamRejectCode,
    /// Current scope catalog revision when useful for conflict resolution.
    pub current_revision: Option<u64>,
    /// Current stream incarnation if a stale Retire targeted a previous life.
    pub active_epoch: Option<u64>,
    /// Current active state when another Open identity owns the name.
    pub current: Option<SourceStreamSnapshot>,
}

/// Correlated outcome of a Source stream lifecycle request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStreamResult {
    /// Echo of the request correlation id.
    pub request_id: String,
    /// Echo of the requested stream identity.
    pub stream_id: String,
    /// One successful operation result or rejection.
    pub outcome: SourceStreamOutcome,
}

/// Successful inspection/open/retirement or a typed refusal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStreamOutcome {
    /// Current stream snapshot.
    Inspected(SourceStreamSnapshot),
    /// Stream opened, or the same open identity retried.
    Opened(SourceStreamSnapshot),
    /// Exact active stream retired at this revision.
    Retired {
        /// Scope-local catalog revision after retirement.
        revision: u64,
    },
    /// Request did not complete as requested.
    Rejected(SourceStreamRejected),
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
    /// Storage could not establish whether the event committed. This is not a
    /// rejection; preserve the same event id and inspect or retry safely.
    OutcomeUnknown,
}

/// Source data frame: ack of an [`InboundEvent`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventAck {
    /// Event id being acknowledged.
    pub id: String,
    /// Acknowledgement status.
    pub status: AckStatus,
    /// Redacted reason when the event was definitively rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    /// Ordered event's storage-issued incarnation, echoed to distinguish
    /// delayed acknowledgements after retirement and same-name reopening.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_epoch: Option<u64>,
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
    use anyhow::{Context, ensure};
    use core::fmt::Debug;

    #[test]
    fn external_paths_share_one_id_rule() -> anyhow::Result<()> {
        ensure!(
            external_pairing_path("pair_1")?.to_string()
                == "state://kernel/external-pairings/pair_1"
        );
        ensure!(
            external_session_path("installation-1", Role::Provider)?.to_string()
                == "state://kernel/external-sessions/installation-1/provider"
        );
        ensure!(
            external_credential_revocation_path("installation-1")?.to_string()
                == "state://kernel/external-credential-revocations/installation-1"
        );
        ensure!(external_pairing_path("_pair").is_err());
        ensure!(external_session_path("_installation", Role::Source).is_err());
        ensure!(
            sandboxed_provider_namespace_path("installation-1")?.to_string()
                == "effect://external-provider/installation-1"
        );
        ensure!(sandboxed_provider_namespace_path("_installation").is_err());
        ensure!(
            external_source_command_path("installation-1", "events")?.to_string()
                == "effect://external-source/installation-1/events/command"
        );
        ensure!(external_source_command_path("_installation", "events").is_err());
        ensure!(external_source_command_path("installation-1", "_events").is_err());
        Ok(())
    }

    #[test]
    fn role_names_match_v1_json_and_authority_paths() -> anyhow::Result<()> {
        for role in [Role::Provider, Role::Source] {
            ensure!(Role::from_slug(role.as_str()) == Some(role));
            ensure!(serde_json::to_string(&role)? == format!("\"{}\"", role.as_str()));
            ensure!(
                external_session_path("bridge", role)?
                    .to_string()
                    .ends_with(role.as_str())
            );
        }
        ensure!(Role::from_slug("Provider").is_none());
        ensure!(Role::from_slug("observer").is_none());
        Ok(())
    }

    fn check_eq<T>(actual: T, expected: T, label: &str) -> anyhow::Result<()>
    where
        T: Debug + PartialEq,
    {
        ensure!(
            actual == expected,
            "{label}: expected {expected:?}, got {actual:?}"
        );
        Ok(())
    }

    fn emits_mut(projection: &mut ExternalProjectionDef) -> anyhow::Result<&mut EventSource> {
        projection
            .emits
            .as_mut()
            .context("source projection has no emits")
    }

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
    fn installation_with_source_and_provider_projections_is_admitted() -> anyhow::Result<()> {
        let install = ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::null(),
            config: Value::null(),
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
                        .context("build source sink")?,
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
                            .context("parse provider namespace")?,
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
        check_eq(
            install.validate_admission(),
            Ok(()),
            "installation admission",
        )?;
        Ok(())
    }

    #[test]
    fn installation_rejects_duplicate_projection_ids() -> anyhow::Result<()> {
        let projection = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            namespace: Some(
                Path::parse("effect://external-provider/instant_messaging_platform")
                    .context("parse provider namespace")?,
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
            config_schema: Value::null(),
            config: Value::null(),
            projections: vec![projection.clone(), projection],
            version: 1,
        };
        check_eq(
            install.validate_admission(),
            Err(ExternalAdmissionError::DuplicateProjectionId(
                "provider".into(),
            )),
            "duplicate projection admission",
        )?;
        Ok(())
    }

    #[test]
    fn sandbox_provider_admission_is_structural_and_fail_closed() -> anyhow::Result<()> {
        let valid = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![EffectCapability::new(
                "effect://external-provider/acme/search",
                Purity::Idempotent,
            )],
            emits: None,
            namespace: Some(
                Path::parse("effect://external-provider/acme")
                    .context("parse provider namespace")?,
            ),
            version: 1,
        };
        check_eq(
            valid.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Ok(()),
            "valid sandbox provider",
        )?;

        let mut sibling_escape = valid.clone();
        sibling_escape.provides[0].effect_path =
            "effect://external-provider/acmeevil/search".into();
        ensure!(
            matches!(
                sibling_escape.validate_admission(
                    "acme",
                    TrustLevel::Sandboxed,
                    &Transport::Stdio {
                        command: Some("acme-plugin".into()),
                        args: vec![]
                    }
                ),
                Err(ExternalAdmissionError::NamespaceEscape { .. })
            ),
            "sibling namespace escape was accepted"
        );

        let mut wildcard_effect = valid.clone();
        wildcard_effect.provides[0].effect_path = "effect://external-provider/acme/*".into();
        check_eq(
            wildcard_effect.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::BadEffectPath(
                "effect://external-provider/acme/*".into(),
            )),
            "wildcard provider effect",
        )?;

        let mut bad_namespace = valid.clone();
        bad_namespace.namespace =
            Some(Path::parse("effect://x/acme").context("parse bad namespace")?);
        check_eq(
            bad_namespace.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::BadSandboxNamespace),
            "bad sandbox namespace",
        )?;

        let mut wildcard_namespace = valid.clone();
        wildcard_namespace.namespace = Some(
            Path::parse("effect://external-provider/acme/**")
                .context("parse wildcard namespace")?,
        );
        check_eq(
            wildcard_namespace.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::BadSandboxNamespace),
            "wildcard sandbox namespace",
        )?;

        let mut nested_namespace = valid.clone();
        nested_namespace.namespace = Some(
            Path::parse("effect://external-provider/acme/nested")
                .context("parse nested namespace")?,
        );
        check_eq(
            nested_namespace.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::BadSandboxNamespace),
            "nested sandbox namespace",
        )?;

        let mut clustered_namespace = valid.clone();
        clustered_namespace.namespace = Some(
            Path::parse("path://phone/effect/external-provider/acme")
                .context("parse clustered namespace")?,
        );
        check_eq(
            clustered_namespace.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::BadSandboxNamespace),
            "clustered sandbox namespace",
        )?;

        let mut duplicate = valid;
        duplicate.provides.push(EffectCapability::new(
            "effect://external-provider/acme/search",
            Purity::Idempotent,
        ));
        check_eq(
            duplicate.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::DuplicateProviderEffect(
                "effect://external-provider/acme/search".into(),
            )),
            "duplicate provider effect",
        )?;
        Ok(())
    }

    #[test]
    fn provider_effects_cannot_claim_kernel_namespace() -> anyhow::Result<()> {
        let projection = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![EffectCapability::new(
                "effect://kernel/process/inspect",
                Purity::Pure,
            )],
            emits: None,
            namespace: Some(Path::parse("effect://kernel").context("parse kernel namespace")?),
            version: 1,
        };
        check_eq(
            projection.validate_admission(
                "kernel_claim",
                TrustLevel::Full,
                &Transport::Grpc { endpoint: None },
            ),
            Err(ExternalAdmissionError::KernelEffectPath),
            "kernel provider effect",
        )?;
        Ok(())
    }

    #[test]
    fn projection_role_shape_is_fail_closed() -> anyhow::Result<()> {
        let provider_without_caps = ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            provides: vec![],
            emits: None,
            namespace: Some(
                Path::parse("effect://external-provider/acme")
                    .context("parse provider namespace")?,
            ),
            version: 1,
        };
        check_eq(
            provider_without_caps.validate_admission(
                "acme",
                TrustLevel::Sandboxed,
                &Transport::Stdio {
                    command: Some("acme-plugin".into()),
                    args: vec![],
                },
            ),
            Err(ExternalAdmissionError::ProviderWithoutCapabilities),
            "provider without caps",
        )?;

        let source_with_caps = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![EffectCapability::new(
                "effect://external-provider/bridge/tool",
                Purity::Effectful,
            )],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source")
                    .context("build source sink")?,
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
        check_eq(
            source_with_caps.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Err(ExternalAdmissionError::SourceWithCapabilities),
            "source with caps",
        )?;
        Ok(())
    }

    #[test]
    fn sandbox_source_event_sink_is_canonical_and_fail_closed() -> anyhow::Result<()> {
        let valid = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source")
                    .context("build source sink")?,
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
        check_eq(
            valid.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Ok(()),
            "valid sandbox source",
        )?;

        let mut bad = valid;
        emits_mut(&mut bad)?.sink =
            Path::parse("state://chat/bridge/events").context("parse bad source sink")?;
        ensure!(
            matches!(
                bad.validate_admission(
                    "bridge",
                    TrustLevel::Sandboxed,
                    &Transport::WebSocket {
                        endpoint: Some("wss://example.test".into())
                    }
                ),
                Err(ExternalAdmissionError::BadSandboxEventSink { .. })
            ),
            "bad sandbox event sink was accepted"
        );
        Ok(())
    }

    #[test]
    fn source_commands_require_command_schemas() -> anyhow::Result<()> {
        let source = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source")
                    .context("build source sink")?,
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 65_536,
                capacity: test_source_capacity(),
                rate_limit: None,
                commands: true,
                command_schema: None,
                command_result_schema: Some(Value::map(alloc::collections::BTreeMap::from([(
                    "type".into(),
                    Value::string("string".into()),
                )]))),
            }),
            namespace: None,
            version: 1,
        };

        check_eq(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Err(ExternalAdmissionError::SourceCommandsWithoutSchemas),
            "source commands without schemas",
        )?;
        Ok(())
    }

    #[test]
    fn source_capacity_and_rate_limit_admission_is_fail_closed() -> anyhow::Result<()> {
        let mut source = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: sandboxed_source_event_sink_path("bridge", "source")
                    .context("build source sink")?,
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

        emits_mut(&mut source)?.max_inline_payload_bytes = 0;
        check_eq(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Err(ExternalAdmissionError::InvalidSourcePayloadLimit),
            "invalid source payload limit",
        )?;

        let emits = emits_mut(&mut source)?;
        emits.max_inline_payload_bytes = 65_536;
        emits.capacity.max_events = 0;
        check_eq(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Err(ExternalAdmissionError::InvalidSourceCapacity),
            "invalid source capacity",
        )?;

        let emits = emits_mut(&mut source)?;
        emits.capacity = StreamCapacity {
            max_events: 10,
            on_overflow: OverflowPolicy::Backpressure {
                pause_threshold: 5,
                resume_threshold: 5,
            },
        };
        check_eq(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Err(ExternalAdmissionError::InvalidSourceBackpressureThresholds),
            "invalid source backpressure",
        )?;

        let emits = emits_mut(&mut source)?;
        emits.capacity = test_source_capacity();
        emits.rate_limit = Some(SourceRateLimit {
            window_ms: 0,
            max_events: 1,
        });
        check_eq(
            source.validate_admission(
                "bridge",
                TrustLevel::Sandboxed,
                &Transport::WebSocket {
                    endpoint: Some("wss://example.test".into()),
                },
            ),
            Err(ExternalAdmissionError::InvalidSourceRateLimit),
            "invalid source rate limit",
        )?;
        Ok(())
    }

    #[test]
    fn source_event_sink_must_be_local_concrete_state_path() -> anyhow::Result<()> {
        let source = ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            provides: vec![],
            emits: Some(EventSource {
                sink: Path::parse("state://events/full/source")
                    .context("parse full-trust source sink")?,
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
        check_eq(
            source.validate_admission(
                "bridge",
                TrustLevel::Full,
                &Transport::Grpc { endpoint: None },
            ),
            Ok(()),
            "valid full-trust source",
        )?;

        let mut wildcard = source.clone();
        emits_mut(&mut wildcard)?.sink =
            Path::parse("state://events/**").context("parse wildcard sink")?;
        ensure!(
            matches!(
                wildcard.validate_admission(
                    "bridge",
                    TrustLevel::Full,
                    &Transport::Grpc { endpoint: None }
                ),
                Err(ExternalAdmissionError::BadSourceEventSink { .. })
            ),
            "wildcard event sink was accepted"
        );

        let mut clustered = source.clone();
        emits_mut(&mut clustered)?.sink =
            Path::parse("path://phone/state/events/full/source").context("parse clustered sink")?;
        ensure!(
            matches!(
                clustered.validate_admission(
                    "bridge",
                    TrustLevel::Full,
                    &Transport::Grpc { endpoint: None }
                ),
                Err(ExternalAdmissionError::BadSourceEventSink { .. })
            ),
            "clustered event sink was accepted"
        );

        let mut reserved = source;
        emits_mut(&mut reserved)?.sink =
            Path::parse("state://kernel/external/source").context("parse reserved sink")?;
        ensure!(
            matches!(
                reserved.validate_admission(
                    "bridge",
                    TrustLevel::Full,
                    &Transport::Grpc { endpoint: None }
                ),
                Err(ExternalAdmissionError::BadSourceEventSink { .. })
            ),
            "reserved event sink was accepted"
        );
        Ok(())
    }

    #[test]
    fn trust_transport_combo_is_fail_closed() -> anyhow::Result<()> {
        let full_stdio = ExternalInstallationDef {
            id: "local-tool".into(),
            platform: "local-tool".into(),
            transport: Transport::Stdio {
                command: Some("tool".into()),
                args: vec![],
            },
            trust: TrustLevel::Full,
            config_schema: Value::null(),
            config: Value::null(),
            projections: vec![ExternalProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(
                    Path::parse("effect://local-tool").context("parse local namespace")?,
                ),
                provides: vec![EffectCapability::new(
                    "effect://local-tool/run",
                    Purity::Effectful,
                )],
                emits: None,
                version: 1,
            }],
            version: 1,
        };
        ensure!(
            matches!(
            full_stdio.validate_admission(),
            Err(ExternalAdmissionError::FullTrustTransport(t)) if t == "stdio"
            ),
            "full-trust stdio was accepted"
        );
        let mut host_session = full_stdio.clone();
        host_session.transport = Transport::HostSession;
        check_eq(
            host_session.validate_admission(),
            Err(ExternalAdmissionError::HostSessionInstallation),
            "internal host-session admission",
        )?;

        let mut sandbox_in_process = full_stdio;
        sandbox_in_process.id = "tool".into();
        sandbox_in_process.trust = TrustLevel::Sandboxed;
        sandbox_in_process.transport = Transport::InProcess;
        sandbox_in_process.projections[0].namespace = Some(
            Path::parse("effect://external-provider/tool").context("parse sandbox namespace")?,
        );
        sandbox_in_process.projections[0].provides[0].effect_path =
            "effect://external-provider/tool/run".into();
        let mut sandbox_stdio = sandbox_in_process.clone();
        sandbox_stdio.transport = Transport::Stdio {
            command: Some("tool".into()),
            args: vec![],
        };
        check_eq(
            sandbox_stdio.validate_admission(),
            Err(ExternalAdmissionError::InvalidStdioCommand),
            "relative stdio executable admission",
        )?;
        sandbox_stdio.transport = Transport::Stdio {
            command: Some("/usr/bin/tool".into()),
            args: vec![],
        };
        check_eq(
            sandbox_stdio.validate_admission(),
            Ok(()),
            "absolute stdio executable admission",
        )?;
        check_eq(
            sandbox_in_process.validate_admission(),
            Err(ExternalAdmissionError::InProcessSandbox),
            "sandbox in-process admission",
        )?;
        sandbox_in_process.transport = Transport::HostSession;
        check_eq(
            sandbox_in_process.validate_admission(),
            Err(ExternalAdmissionError::HostSessionInstallation),
            "sandbox host-session admission",
        )?;
        Ok(())
    }

    #[test]
    fn control_frame_config_ack_roundtrip() -> anyhow::Result<()> {
        let f = ControlFrame::ConfigAck {
            axis: ConfigAxis::PresentationConfig,
            version: 7,
            status: ApplyStatus::Rejected {
                reason: RejectReason::ProfileMismatch,
            },
        };
        let s = serde_json::to_string(&f)?;
        let back: ControlFrame = serde_json::from_str(&s)?;
        check_eq(f, back, "control frame serde")?;
        Ok(())
    }

    #[test]
    fn handshake_three_stages_roundtrip() -> anyhow::Result<()> {
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
            installation_epoch: 1,
            scope_epoch: 0,
            session_id: "session-1".into(),
            key_epoch: 0,
        };
        let ready = RoleReady {
            accepted_context: ctx,
        };
        let hello_json = serde_json::to_string(&hello)?;
        let hello_back: RoleSessionClientHello = serde_json::from_str(&hello_json)?;
        let ready_json = serde_json::to_string(&ready)?;
        let ready_back: RoleReady = serde_json::from_str(&ready_json)?;
        check_eq(hello, hello_back, "client hello serde")?;
        check_eq(ready, ready_back, "role ready serde")?;
        Ok(())
    }

    #[test]
    fn invoke_result_carries_error() -> anyhow::Result<()> {
        let r = InvokeResult {
            invocation_id: "x".into(),
            outcome: Err(ErrorInfo {
                kind: "timeout".into(),
                message: "deadline".into(),
            }),
        };
        let s = serde_json::to_string(&r)?;
        let back: InvokeResult = serde_json::from_str(&s)?;
        check_eq(r, back, "invoke result serde")?;
        Ok(())
    }

    #[test]
    fn command_result_carries_error() -> anyhow::Result<()> {
        let r = CommandResult {
            id: "cmd-1".into(),
            outcome: Err(ErrorInfo {
                kind: "bridge_error".into(),
                message: "failed".into(),
            }),
        };
        let s = serde_json::to_string(&r)?;
        let back: CommandResult = serde_json::from_str(&s)?;
        check_eq(r, back, "command result serde")?;
        Ok(())
    }

    #[test]
    fn pairing_payload_requires_contacts_and_valid_authorities() -> anyhow::Result<()> {
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
                        service: "XolotlExternalPairing.Pair".into(),
                        tls_name: Some("xolotl.local".into()),
                        priority: 20,
                    },
                ],
            },
            daemon_identity_pub: "pub".into(),
            daemon_fingerprint: "fp".into(),
            expires_at: Timestamp::millis(1),
            display_checksum: "abcd".into(),
        };
        check_eq(payload.validate(), Ok(()), "pairing payload validation")?;
        Ok(())
    }

    #[test]
    fn pairing_payload_rejects_missing_contacts_and_scheme_authority() -> anyhow::Result<()> {
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
        check_eq(
            empty.validate(),
            Err(PairingPayloadError::MissingContacts),
            "missing contacts",
        )?;

        let bad = DaemonContact {
            transport: ExternalTransport::WebSocket,
            authority: "https://xolotl.local:7443".into(),
            service: "/external/pair".into(),
            tls_name: None,
            priority: 1,
        };
        check_eq(
            bad.validate(),
            Err(PairingPayloadError::BadAuthority),
            "bad authority",
        )?;
        Ok(())
    }
}
