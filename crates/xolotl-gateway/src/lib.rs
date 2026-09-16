#![forbid(unsafe_code)]

//! `xolotl-gateway` - the shared Gateway runtime.
//!
//! A Gateway verifies transport credentials, maps them to Xolotl identities, and
//! submits typed requests through the kernel executor.
//!
//! Protocol adapters stay thin. They parse transport frames and credentials,
//! then call this crate so authentication, profile mapping, exposed surfaces,
//! limits, taint, audit, and Handle ownership remain one shared boundary.

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::time::Instant;
use xolotl_graph::{DoNode, OperationTemplate, WaitSpec};
use xolotl_kernel::{
    Bootstrap, CompiledRequestGrantTemplate, Executor, GatewayAudit, RequestProcess,
    intern_identity,
};
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{
    Capability, CompletionOrigin, CostModel, ExecutionOutput, Failure, MethodBitmap, Outcome,
    OutputMode, Path, ProcessId, ProcessStatus, ReplayClass, ResourceName, ResourceSelector,
    StreamMarker, TaintSet, Value, ValueMap, ValueView,
};

mod auth;
mod object;
mod profile;
mod schema;
mod submission;
mod transport;
pub mod value_inspection;

pub mod external;

use submission::idempotency::{
    GatewayIdempotencyReservation, SubmissionIdempotency, finish_request_and_release_idempotency,
    finish_request_without_idempotency_and_fail, initial_idempotency_material,
    release_submission_idempotency_reservation_and_fail, required_idempotency_material,
    reserve_submission_idempotency_if_present,
};
#[cfg(test)]
use submission::idempotency::{idempotency_path, submission_hash};
pub use submission::{GatewayOutputChunk, GatewayOutputEvent, GatewayOutputStream};
pub use xolotl_kernel::stream::StreamWindow;

/// Gateway profile revision bound to sessions and submissions.
pub type GatewayProfileRev = u64;
/// Monotonic generation for credential and principal state.
pub type GatewayGeneration = u64;

pub use auth::{
    BearerToken, BearerTokenHash, ClientCertificateCredential, ClientCertificateDerSha256,
    GatewayAuthMethod, GatewayCredential, GatewayIdentityMapping, GatewaySession,
    PresentedCredential, VerifiedPrincipal,
};
use auth::{GatewayCredentialKind, hash_bearer_token};
use object::collect_large_value_refs;
pub use object::{
    BeginObjectUploadRequest, CommitObjectUploadResponse, GatewayObjectDownload, GatewayObjectKind,
    GatewayObjectReadGrant, GatewayObjectUpload, GatewayObjectUploadTicket,
    GatewayPayloadProvenance, IssueObjectReadGrantRequest, IssueObjectUploadTicketRequest,
    ObjectStoreProof, OpenObjectReadRequest,
};
#[cfg(feature = "structured-output")]
pub use object::{
    GatewayExternalizedOutput, GatewayOutputDisclosurePolicy, GatewayOutputDisclosureRequest,
    GatewayOutputExternalizationError, GatewayOutputExternalizer, GatewayOutputKind,
    GatewayOutputObjectOptions,
};
use profile::perform_capability_for_effect;
pub use profile::{
    GatewayBudgetProfile, GatewayLimitProfile, GatewayPrincipalSurfaceBinding, GatewayProfile,
    GatewayProfileDocument, GatewayPublication, GatewaySurface,
};
use schema::{
    CompiledValueSchema, compile_value_schema, validate_surface_input, validate_surface_stream_item,
};
pub use transport::{
    GatewayAllowedHost, GatewayAllowedOrigin, GatewayTransportSecurityConfig,
    GatewayTransportSecurityMode, GatewayTrustedProxyConfig, GatewayUnsafeTransportRelaxation,
    browser_origin_allowed, gateway_host_allowed, local_trusted_browser_origin,
};

const MAX_LOWERED_SUBMISSION_NODES: usize = 4096;
const MAX_LOWERED_SUBMISSION_DEPTH: usize = 128;
const DEFAULT_MAX_LITERAL_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_COLLECT_LIMIT: usize = 1024;
const DEFAULT_MAX_DEADLINE_MS_FROM_NOW: i64 = 5 * 60 * 1000;
const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1024;
const DEFAULT_MAX_PRINCIPAL_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_SURFACE_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_RISK_CLASS_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_STREAM_ITEMS: usize = 4096;
const DEFAULT_MAX_STREAM_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_STREAM_INLINE_ITEM_BYTES: usize = 1024 * 1024;
const DEFAULT_BUDGET_MAX_INFLIGHT_OPS: u64 = 8192;
const DEFAULT_BUDGET_MAX_BYTES_IN: u64 = 64 * 1024 * 1024;
const DEFAULT_BUDGET_MAX_INLINE_VALUE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_BUDGET_MAX_STREAM_ITEMS: u64 = 64 * 1024;
const MIN_BEARER_TOKEN_BYTES: usize = 16;
const GATEWAY_REQUEST_ID_RANDOM_BYTES: usize = 16;
const COMPLETED_REQUEST_RETENTION_MS: i64 = 60_000;
const DEADLINE_SWEEP_INTERVAL_MS: u64 = 50;
const GATEWAY_EFFECT_METHOD: &str = "invoke";
const GATEWAY_EFFECT_HANDLE_VERB: &str = "perform";

/// Errors surfaced by gateway authentication, authorization, profile
/// compilation, request admission, and kernel setup.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Credentials were absent or failed validation.
    #[error("authentication failed")]
    Unauthenticated,
    /// Authenticated principal is not allowed to use this gateway.
    #[error("principal {0} is not authorized for this gateway")]
    Unauthorized(String),
    /// Gateway profile is malformed or references unavailable runtime state.
    #[error("gateway profile invalid: {0}")]
    InvalidProfile(String),
    /// The request was rejected by gateway admission or kernel setup.
    #[error("request rejected: {0}")]
    Rejected(String),
    /// The request could not start because a bounded gateway resource is full.
    #[error("gateway limit exceeded: {0}")]
    LimitExceeded(String),
}

impl GatewayError {
    /// Redacted message suitable for returning to an external client.
    pub fn public_message(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "authentication failed",
            GatewayError::Unauthorized(_) => "authorization failed",
            GatewayError::InvalidProfile(_)
            | GatewayError::Rejected(_)
            | GatewayError::LimitExceeded(_) => "request rejected",
        }
    }

    /// Stable audit outcome tag for this error.
    pub fn audit_outcome(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "auth_failed",
            GatewayError::Unauthorized(_) => "permission_denied",
            GatewayError::InvalidProfile(_) => "profile_invalid",
            GatewayError::Rejected(_) => "request_rejected",
            GatewayError::LimitExceeded(_) => "limit_exceeded",
        }
    }

    /// Stable lower-snake wire error code.
    pub fn code(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "unauthenticated",
            GatewayError::Unauthorized(_) => "permission_denied",
            GatewayError::InvalidProfile(_) => "profile_invalid",
            GatewayError::Rejected(_) => "request_rejected",
            GatewayError::LimitExceeded(_) => "limit_exceeded",
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledSurfaceDescriptor {
    surface_id: String,
    target: ResourceName,
    method_bitmap: MethodBitmap,
    grant_template: String,
    grant_capability: Capability,
    grant_selector: ResourceSelector,
    publish_capability: Option<String>,
    input_schema: Option<Value>,
    input_schema_validator: Option<CompiledValueSchema>,
    output_schema: Option<Value>,
    output_schema_validator: Option<CompiledValueSchema>,
    output_stream_schema: Option<Value>,
    output_stream_schema_validator: Option<CompiledValueSchema>,
}

#[derive(Clone, Debug)]
struct CompiledIdentityMapping {
    identity_path: String,
    enabled: bool,
    generation: GatewayGeneration,
}

#[derive(Clone, Debug, Default)]
struct CompiledPrincipalSurfaceBinding {
    visible: BTreeSet<String>,
    submit: BTreeSet<String>,
    capability_ceiling: Vec<Capability>,
    request_grants_by_surface: BTreeMap<String, CompiledRequestGrantTemplate>,
}

#[derive(Clone, Debug)]
struct CompiledGatewayProfile {
    profile_name: String,
    revision: GatewayProfileRev,
    credential_revocation_floor: GatewayGeneration,
    bearer_credentials: Vec<(BearerTokenHash, VerifiedPrincipal)>,
    client_certificate_credentials: Vec<(ClientCertificateDerSha256, VerifiedPrincipal)>,
    identity_by_principal: BTreeMap<String, CompiledIdentityMapping>,
    surfaces_by_id: BTreeMap<String, CompiledSurfaceDescriptor>,
    surface_bindings_by_principal: BTreeMap<String, CompiledPrincipalSurfaceBinding>,
    authority_anchor: Option<ProcessId>,
    surface_descriptors: Vec<CompiledSurfaceDescriptor>,
    publication_descriptors: Vec<GatewayPublicationDescriptor>,
    registered_hosts: Vec<GatewayAllowedHost>,
    registered_origins: Vec<GatewayAllowedOrigin>,
    limits: GatewayLimitProfile,
}

fn collect_binding_surface_ids(
    surfaces_by_id: &BTreeMap<String, CompiledSurfaceDescriptor>,
    ids: &[String],
    field: &'static str,
) -> Result<BTreeSet<String>, GatewayError> {
    let mut set = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() {
            return Err(GatewayError::InvalidProfile(format!(
                "{field} must not contain an empty surface id"
            )));
        }
        if !surfaces_by_id.contains_key(id) {
            return Err(GatewayError::InvalidProfile(format!(
                "{field} references unknown surface {id}"
            )));
        }
        set.insert(id.clone());
    }
    Ok(set)
}

fn validate_gateway_budget_profile(budget: &GatewayBudgetProfile) -> Result<(), GatewayError> {
    validate_optional_budget_limit(budget.max_inflight_ops, "budget.max_inflight_ops")?;
    validate_optional_budget_limit(budget.max_wall_ms, "budget.max_wall_ms")?;
    validate_optional_budget_limit(budget.max_bytes_in, "budget.max_bytes_in")?;
    validate_optional_budget_limit(budget.max_bytes_out, "budget.max_bytes_out")?;
    validate_optional_budget_limit(
        budget.max_inline_value_bytes,
        "budget.max_inline_value_bytes",
    )?;
    validate_optional_budget_limit(budget.max_stream_items, "budget.max_stream_items")?;
    validate_optional_budget_limit(
        budget.max_estimated_cost_micro_usd,
        "budget.max_estimated_cost_micro_usd",
    )?;
    Ok(())
}

fn validate_optional_budget_limit(value: Option<u64>, name: &str) -> Result<(), GatewayError> {
    if value == Some(0) {
        return Err(GatewayError::InvalidProfile(format!(
            "{name} must be positive"
        )));
    }
    Ok(())
}

impl CompiledGatewayProfile {
    fn compile(profile: GatewayProfile) -> Result<Self, GatewayError> {
        if profile.profile_name.trim().is_empty() {
            return Err(GatewayError::InvalidProfile(
                "profile_name must not be empty".into(),
            ));
        }
        if profile.revision == 0 {
            return Err(GatewayError::InvalidProfile(
                "profile revision must be positive".into(),
            ));
        }
        if profile.limits.max_in_flight_requests == 0
            || profile.limits.max_principal_in_flight_requests == 0
            || profile.limits.max_surface_in_flight_requests == 0
            || profile.limits.max_risk_class_in_flight_requests == 0
            || profile.limits.max_stream_items == 0
            || profile.limits.max_stream_bytes == 0
            || profile.limits.max_stream_inline_item_bytes == 0
        {
            return Err(GatewayError::InvalidProfile(
                "in-flight, fair-queue, and stream limits must be positive".into(),
            ));
        }
        validate_gateway_budget_profile(&profile.limits.budget)?;
        if profile.limits.max_deadline_ms_from_now < 0 {
            return Err(GatewayError::InvalidProfile(
                "max_deadline_ms_from_now must not be negative".into(),
            ));
        }
        let mut registered_host_set = BTreeSet::new();
        for host in profile.registered_hosts {
            if !registered_host_set.insert(host.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate registered host {}",
                    host.as_str()
                )));
            }
        }
        let registered_hosts = registered_host_set.into_iter().collect();

        let mut registered_origin_set = BTreeSet::new();
        for origin in profile.registered_origins {
            if !registered_origin_set.insert(origin.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate registered origin {}",
                    origin.as_str()
                )));
            }
        }
        let registered_origins = registered_origin_set.into_iter().collect();

        let credential_revocation_floor = profile.credential_revocation_floor;
        let mut identity_by_principal = BTreeMap::new();
        for mapping in profile.identity_mappings {
            if mapping.principal_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "principal_id in identity mapping must not be empty".into(),
                ));
            }
            if mapping.generation == 0 {
                return Err(GatewayError::InvalidProfile(
                    "principal generation must be positive".into(),
                ));
            }
            parse_identity_path(&mapping.identity_path)?;
            if identity_by_principal
                .insert(
                    mapping.principal_id.clone(),
                    CompiledIdentityMapping {
                        identity_path: mapping.identity_path.clone(),
                        enabled: mapping.enabled,
                        generation: mapping.generation,
                    },
                )
                .is_some()
            {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate identity mapping for principal {}",
                    mapping.principal_id
                )));
            }
        }

        let mut credential_ids = BTreeSet::new();
        let mut bearer_hashes = BTreeSet::new();
        let mut bearer_credentials = Vec::new();
        let mut client_certificate_hashes = BTreeSet::new();
        let mut client_certificate_credentials = Vec::new();
        for credential in profile.credentials {
            if credential.credential_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "credential_id must not be empty".into(),
                ));
            }
            if !credential_ids.insert(credential.credential_id.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate credential_id {}",
                    credential.credential_id
                )));
            }
            if credential.principal_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "credential principal_id must not be empty".into(),
                ));
            }
            if credential.generation == 0 {
                return Err(GatewayError::InvalidProfile(
                    "credential generation must be positive".into(),
                ));
            }
            if !identity_by_principal.contains_key(&credential.principal_id) {
                return Err(GatewayError::InvalidProfile(format!(
                    "credential {} references unmapped principal {}",
                    credential.credential_id, credential.principal_id
                )));
            }
            match credential.kind {
                GatewayCredentialKind::Bearer { token_hash } => {
                    let principal = VerifiedPrincipal {
                        principal_id: credential.principal_id,
                        credential_id: credential.credential_id,
                        credential_generation: credential.generation,
                        principal_generation: 0,
                        auth_method: GatewayAuthMethod::Bearer,
                    };
                    if !bearer_hashes.insert(token_hash.clone()) {
                        return Err(GatewayError::InvalidProfile(
                            "duplicate bearer token hash".into(),
                        ));
                    }
                    if credential.enabled && credential.generation > credential_revocation_floor {
                        bearer_credentials.push((token_hash, principal));
                    }
                }
                GatewayCredentialKind::ClientCertificate { der_sha256 } => {
                    let principal = VerifiedPrincipal {
                        principal_id: credential.principal_id,
                        credential_id: credential.credential_id,
                        credential_generation: credential.generation,
                        principal_generation: 0,
                        auth_method: GatewayAuthMethod::ClientCertificate,
                    };
                    if !client_certificate_hashes.insert(der_sha256.clone()) {
                        return Err(GatewayError::InvalidProfile(
                            "duplicate client certificate DER SHA-256".into(),
                        ));
                    }
                    if credential.enabled && credential.generation > credential_revocation_floor {
                        client_certificate_credentials.push((der_sha256, principal));
                    }
                }
            }
        }

        let mut surface_ids = BTreeSet::new();
        let mut surface_descriptors = Vec::new();
        for surface in profile.surfaces {
            if surface.surface_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "surface id must not be empty".into(),
                ));
            }
            if !surface_ids.insert(surface.surface_id.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate surface_id {}",
                    surface.surface_id
                )));
            }
            validate_surface_shape(&surface)?;
            let grant_template_literal = perform_capability_for_effect(surface.target.path());
            let grant_template = Capability::parse(&grant_template_literal)
                .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
            if !grant_template.covers(GATEWAY_EFFECT_HANDLE_VERB, surface.target.path()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "surface {} grant template does not cover {} on {}",
                    surface.surface_id,
                    GATEWAY_EFFECT_HANDLE_VERB,
                    surface.target.path()
                )));
            }
            if let Some(publish_capability) = &surface.publish_capability {
                if publish_capability.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "surface {} publish_capability must not be empty",
                        surface.surface_id
                    )));
                }
                let publish_capability = Capability::parse(publish_capability)
                    .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
                if !publish_capability.covers("publish", surface.target.path()) {
                    return Err(GatewayError::InvalidProfile(format!(
                        "surface {} publish_capability does not cover publish on {}",
                        surface.surface_id,
                        surface.target.path()
                    )));
                }
            }

            let descriptor = CompiledSurfaceDescriptor {
                surface_id: surface.surface_id.clone(),
                target: surface.target.clone(),
                method_bitmap: MethodBitmap::empty(),
                grant_template: grant_template_literal,
                grant_capability: grant_template.clone(),
                grant_selector: ResourceSelector {
                    pattern: grant_template,
                },
                publish_capability: surface.publish_capability.clone(),
                input_schema: surface.input_schema.clone(),
                input_schema_validator: match &surface.input_schema {
                    Some(schema) => Some(compile_value_schema(
                        schema,
                        &format!("surface {} input_schema", surface.surface_id),
                    )?),
                    None => None,
                },
                output_schema: surface.output_schema.clone(),
                output_schema_validator: match &surface.output_schema {
                    Some(schema) => Some(compile_value_schema(
                        schema,
                        &format!("surface {} output_schema", surface.surface_id),
                    )?),
                    None => None,
                },
                output_stream_schema: surface.output_stream_schema.clone(),
                output_stream_schema_validator: match &surface.output_stream_schema {
                    Some(schema) => Some(compile_value_schema(
                        schema,
                        &format!("surface {} output_stream_schema", surface.surface_id),
                    )?),
                    None => None,
                },
            };
            surface_descriptors.push(descriptor.clone());
        }
        let surfaces_by_id: BTreeMap<String, CompiledSurfaceDescriptor> = surface_descriptors
            .iter()
            .map(|surface| (surface.surface_id.clone(), surface.clone()))
            .collect();

        let mut publication_keys = BTreeSet::new();
        let mut publication_descriptors = Vec::new();
        for publication in profile.publications {
            validate_publication_shape(&publication)?;
            let Some(surface) = surfaces_by_id.get(&publication.surface_id) else {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} references unknown surface {}",
                    publication.protocol,
                    publication.kind,
                    publication.name,
                    publication.surface_id
                )));
            };
            if surface.publish_capability.is_none() {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} references surface {} without publish_capability",
                    publication.protocol,
                    publication.kind,
                    publication.name,
                    publication.surface_id
                )));
            }
            if let Some(title) = &publication.title
                && title.trim().is_empty()
            {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} title must not be empty",
                    publication.protocol, publication.kind, publication.name
                )));
            }
            if let Some(description) = &publication.description
                && description.trim().is_empty()
            {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} description must not be empty",
                    publication.protocol, publication.kind, publication.name
                )));
            }
            if let Some(annotations) = &publication.annotations
                && !matches!(annotations.view(), ValueView::Map(_))
            {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} annotations must be a map",
                    publication.protocol, publication.kind, publication.name
                )));
            }
            if let Some(metadata) = &publication.metadata
                && !matches!(metadata.view(), ValueView::Map(_))
            {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} metadata must be a map",
                    publication.protocol, publication.kind, publication.name
                )));
            }
            let key = (
                publication.protocol.clone(),
                publication.kind.clone(),
                publication_identity(&publication),
            );
            if !publication_keys.insert(key) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate publication {}:{}:{}",
                    publication.protocol, publication.kind, publication.name
                )));
            }
            if publication.enabled {
                publication_descriptors.push(GatewayPublicationDescriptor {
                    protocol: publication.protocol,
                    kind: publication.kind,
                    name: publication.name,
                    address: publication.address,
                    surface_id: publication.surface_id,
                    title: publication.title,
                    description: publication.description,
                    properties: publication.properties,
                    annotations: publication.annotations,
                    metadata: publication.metadata,
                });
            }
        }

        let mut surface_bindings_by_principal = BTreeMap::new();
        for binding in profile.principal_surface_bindings {
            if binding.principal_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "principal surface binding principal_id must not be empty".into(),
                ));
            }
            if !identity_by_principal.contains_key(&binding.principal_id) {
                return Err(GatewayError::InvalidProfile(format!(
                    "surface binding references unmapped principal {}",
                    binding.principal_id
                )));
            }
            if surface_bindings_by_principal.contains_key(&binding.principal_id) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate surface binding for principal {}",
                    binding.principal_id
                )));
            }

            let visible = collect_binding_surface_ids(
                &surfaces_by_id,
                &binding.visible_surfaces,
                "visible_surfaces",
            )?;
            let submit = collect_binding_surface_ids(
                &surfaces_by_id,
                &binding.submit_surfaces,
                "submit_surfaces",
            )?;
            if !submit.is_subset(&visible) {
                return Err(GatewayError::InvalidProfile(format!(
                    "submit_surfaces for principal {} must be a subset of visible_surfaces",
                    binding.principal_id
                )));
            }
            if !submit.is_empty() && binding.capability_ceiling.is_empty() {
                return Err(GatewayError::InvalidProfile(format!(
                    "capability_ceiling for principal {} must not be empty when submit_surfaces is not empty",
                    binding.principal_id
                )));
            }
            let mut capability_ceiling = Vec::new();
            for literal in &binding.capability_ceiling {
                if literal.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {} must not contain an empty capability",
                        binding.principal_id
                    )));
                }
                capability_ceiling.push(Capability::parse(literal).map_err(|e| {
                    GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {} contains invalid capability: {e}",
                        binding.principal_id
                    ))
                })?);
            }
            for surface_id in &submit {
                let Some(surface) = surfaces_by_id.get(surface_id) else {
                    continue;
                };
                if !capability_ceiling
                    .iter()
                    .any(|ceiling| ceiling.covers_cap(&surface.grant_capability))
                {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {} does not cover surface {} grant template {}",
                        binding.principal_id, surface.surface_id, surface.grant_template
                    )));
                }
            }
            surface_bindings_by_principal.insert(
                binding.principal_id,
                CompiledPrincipalSurfaceBinding {
                    visible,
                    submit,
                    capability_ceiling,
                    request_grants_by_surface: BTreeMap::new(),
                },
            );
        }

        Ok(Self {
            profile_name: profile.profile_name,
            revision: profile.revision,
            credential_revocation_floor,
            bearer_credentials,
            client_certificate_credentials,
            identity_by_principal,
            surfaces_by_id,
            surface_bindings_by_principal,
            authority_anchor: profile.authority_anchor,
            surface_descriptors,
            registered_hosts,
            registered_origins,
            limits: profile.limits,
            publication_descriptors,
        })
    }

    fn binding_for_principal(&self, principal_id: &str) -> CompiledPrincipalSurfaceBinding {
        self.surface_bindings_by_principal
            .get(principal_id)
            .cloned()
            .unwrap_or_else(CompiledPrincipalSurfaceBinding::default)
    }

    fn principal_can_submit(&self, principal_id: &str, surface_id: &str) -> bool {
        self.surface_bindings_by_principal
            .get(principal_id)
            .is_some_and(|binding| binding.submit.contains(surface_id))
    }

    fn surface_by_id(&self, surface_id: &str) -> Option<&CompiledSurfaceDescriptor> {
        self.surfaces_by_id.get(surface_id)
    }

    fn surface_descriptors_for_ids<'a>(
        &'a self,
        surface_ids: &BTreeSet<String>,
    ) -> Result<Vec<&'a CompiledSurfaceDescriptor>, GatewayError> {
        let mut surfaces = Vec::new();
        for surface_id in surface_ids {
            let Some(surface) = self.surface_by_id(surface_id) else {
                return Err(GatewayError::Rejected(format!(
                    "unknown gateway surface {surface_id}"
                )));
            };
            surfaces.push(surface);
        }
        Ok(surfaces)
    }

    fn verify_bearer(&self, token: &BearerToken) -> Result<VerifiedPrincipal, GatewayError> {
        let hash = hash_bearer_token(token.as_str());
        let mut verified = None;
        for (stored_hash, principal) in &self.bearer_credentials {
            if stored_hash.0.as_bytes().ct_eq(hash.as_bytes()).into() {
                let Some(mapping) = self.identity_by_principal.get(&principal.principal_id) else {
                    continue;
                };
                if mapping.enabled {
                    let mut principal = principal.clone();
                    principal.principal_generation = mapping.generation;
                    verified = Some(principal);
                }
            }
        }
        verified.ok_or(GatewayError::Unauthenticated)
    }

    fn verify_client_certificate(
        &self,
        credential: &ClientCertificateCredential,
    ) -> Result<VerifiedPrincipal, GatewayError> {
        let mut verified = None;
        for (stored_hash, principal) in &self.client_certificate_credentials {
            if stored_hash
                .0
                .as_bytes()
                .ct_eq(credential.der_sha256.0.as_bytes())
                .into()
            {
                let Some(mapping) = self.identity_by_principal.get(&principal.principal_id) else {
                    continue;
                };
                if mapping.enabled {
                    let mut principal = principal.clone();
                    principal.principal_generation = mapping.generation;
                    verified = Some(principal);
                }
            }
        }
        verified.ok_or(GatewayError::Unauthenticated)
    }

    fn has_authenticating_credentials(&self) -> bool {
        !self.bearer_credentials.is_empty() || !self.client_certificate_credentials.is_empty()
    }

    fn session_identity_path(&self, session: &GatewaySession) -> Result<&str, GatewayError> {
        let mapping = self
            .identity_by_principal
            .get(&session.principal.principal_id)
            .ok_or_else(|| GatewayError::Unauthorized(session.principal.principal_id.clone()))?;
        if !mapping.enabled
            || session.principal.principal_generation != mapping.generation
            || session.identity_path != mapping.identity_path
        {
            return Err(GatewayError::Rejected(
                "gateway session principal generation is stale".into(),
            ));
        }
        if session.principal.credential_generation <= self.credential_revocation_floor {
            return Err(GatewayError::Rejected(
                "gateway session credential generation is revoked".into(),
            ));
        }
        let credential_still_active = match session.principal.auth_method {
            GatewayAuthMethod::Bearer => self.bearer_credentials.iter().any(|(_, principal)| {
                principal.credential_id == session.principal.credential_id
                    && principal.credential_generation == session.principal.credential_generation
                    && principal.principal_id == session.principal.principal_id
            }),
            GatewayAuthMethod::ClientCertificate => {
                self.client_certificate_credentials
                    .iter()
                    .any(|(_, principal)| {
                        principal.credential_id == session.principal.credential_id
                            && principal.credential_generation
                                == session.principal.credential_generation
                            && principal.principal_id == session.principal.principal_id
                    })
            }
        };
        if !credential_still_active {
            return Err(GatewayError::Rejected(
                "gateway session credential generation is stale".into(),
            ));
        }
        Ok(mapping.identity_path.as_str())
    }
}

fn validate_surface_shape(surface: &GatewaySurface) -> Result<(), GatewayError> {
    if surface.target.path().scheme() != "effect" {
        return Err(GatewayError::InvalidProfile(format!(
            "effect_invoke surface {} must target effect://",
            surface.surface_id
        )));
    }
    if surface.target.path().cluster().is_some() {
        return Err(GatewayError::InvalidProfile(format!(
            "effect_invoke surface {} must target a local effect path",
            surface.surface_id
        )));
    }
    if surface.target.path().segments().is_empty() {
        return Err(GatewayError::InvalidProfile(format!(
            "effect_invoke surface {} must name an effect path",
            surface.surface_id
        )));
    }
    Ok(())
}

fn validate_publication_shape(publication: &GatewayPublication) -> Result<(), GatewayError> {
    validate_publication_segment(&publication.protocol, "publication protocol")?;
    validate_publication_segment(&publication.kind, "publication kind")?;
    validate_publication_segment(&publication.name, "publication name")?;
    if let Some(address) = &publication.address {
        validate_publication_address(address)?;
    }
    if publication.surface_id.trim().is_empty() {
        return Err(GatewayError::InvalidProfile(
            "publication surface_id must not be empty".into(),
        ));
    }
    for key in publication.properties.keys() {
        validate_publication_segment(key, "publication property name")?;
    }
    Ok(())
}

fn publication_identity(publication: &GatewayPublication) -> String {
    match &publication.address {
        Some(address) => address.clone(),
        None => publication.name.clone(),
    }
}

fn validate_publication_address(address: &str) -> Result<(), GatewayError> {
    if address.trim().is_empty()
        || address
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err(GatewayError::InvalidProfile(
            "publication address must be non-empty and contain no whitespace".into(),
        ));
    }
    Ok(())
}

fn validate_publication_segment(value: &str, label: &'static str) -> Result<(), GatewayError> {
    if !is_gateway_publication_segment(value) {
        return Err(GatewayError::InvalidProfile(format!(
            "{label} must be one stable ASCII segment"
        )));
    }
    Ok(())
}

fn is_gateway_publication_segment(value: &str) -> bool {
    if value == "*" || value == "**" {
        return false;
    }
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
}

/// Authenticated, redacted profile descriptor returned by gateway discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDescriptor {
    /// Active profile name.
    pub profile_name: String,
    /// Active profile revision.
    pub profile_rev: GatewayProfileRev,
    /// Profile surfaces visible to the authenticated session.
    pub surfaces: Vec<GatewaySurfaceDescriptor>,
    /// Protocol publications visible to the authenticated session.
    pub publications: Vec<GatewayPublicationDescriptor>,
    /// Effective gateway admission limits for this profile.
    pub limits: GatewayLimitProfile,
}

/// Readiness state for a gateway runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayReadiness {
    /// The active profile can authenticate clients.
    Ready,
    /// The active profile is serving as the last known good snapshot.
    DegradedLastKnownGood,
    /// The active profile is closed and authenticates nobody.
    NotReadyClosed,
}

impl GatewayReadiness {
    /// Return the stable status label for this readiness state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::DegradedLastKnownGood => "degraded_lkg",
            Self::NotReadyClosed => "not_ready_closed",
        }
    }
}

/// Redacted metadata for the most recent failed profile reload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProfileReloadFailure {
    /// Profile revision supplied by the failed reload attempt.
    pub attempted_profile_rev: GatewayProfileRev,
    /// Stable low-cardinality failure code.
    pub code: String,
    /// Public failure summary.
    pub public_message: String,
}

/// Redacted runtime status for health and diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRuntimeStatus {
    /// Active profile name.
    pub profile_name: String,
    /// Active profile revision.
    pub profile_rev: GatewayProfileRev,
    /// True when the runtime can authenticate at least one client.
    pub ready: bool,
    /// Current readiness class.
    pub readiness: GatewayReadiness,
    /// True when a failed reload left the previous snapshot active.
    pub lkg_active: bool,
    /// Consecutive failed reload attempts since the last successful swap.
    pub consecutive_failed_reloads: u64,
    /// Most recent redacted reload failure, if any.
    pub last_reload_failure: Option<GatewayProfileReloadFailure>,
}

/// One profile surface visible through authenticated discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySurfaceDescriptor {
    /// Stable surface id within the profile.
    pub surface_id: String,
    /// Resource target exposed through this surface.
    pub target: ResourceName,
    /// Capability literal required before this surface may be published.
    publish_capability: Option<String>,
    /// Input schema descriptor advertised for this surface.
    pub input_schema: Option<Value>,
    /// Output schema descriptor advertised for this surface.
    pub output_schema: Option<Value>,
    /// Schema for each incremental output value, independent of the final value.
    pub output_stream_schema: Option<Value>,
}

impl GatewaySurfaceDescriptor {
    /// Return whether a publishing capability is allowed for this surface.
    pub fn allows_publish_capability(&self, capability: &str) -> bool {
        let Some(surface_publish) = &self.publish_capability else {
            return false;
        };
        let Ok(surface_publish) = Capability::parse(surface_publish) else {
            return false;
        };
        let Ok(candidate) = Capability::parse(capability) else {
            return false;
        };
        surface_publish.covers_cap(&candidate)
    }
}

/// One protocol publication visible through authenticated discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPublicationDescriptor {
    /// Protocol adapter that owns this publication.
    pub protocol: String,
    /// Protocol object kind inside the adapter.
    pub kind: String,
    /// Protocol-visible stable name.
    pub name: String,
    /// Protocol-visible address when it is distinct from `name`.
    pub address: Option<String>,
    /// Published Gateway surface id.
    pub surface_id: String,
    /// Optional protocol display title.
    pub title: Option<String>,
    /// Optional human-readable protocol description.
    pub description: Option<String>,
    /// Optional protocol-specific properties.
    pub properties: BTreeMap<String, Value>,
    /// Optional protocol annotations.
    pub annotations: Option<Value>,
    /// Optional protocol metadata.
    pub metadata: Option<Value>,
}

/// Client options attached to one Gateway submission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubmitOptions {
    /// Client supplied idempotency key for non-idempotent retry boundaries.
    pub idempotency_key: Option<String>,
    /// Server-issued token for retry-safe non-idempotent submission.
    pub submission_token: Option<String>,
    /// Client requested deadline in milliseconds since unix epoch. The server
    /// clamps this against the profile; clients cannot extend server limits.
    pub deadline_ms: Option<u64>,
    /// Requested transport encoding. Runtime admission records it but does not
    /// trust it as an authorization input.
    pub requested_encoding: Option<String>,
}

/// A typed submission accepted by the gateway runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySubmission {
    surface_id: String,
    body: GatewaySubmissionBody,
    requested_output: OutputMode,
    options: SubmitOptions,
}

impl GatewaySubmission {
    /// Submit one `Value` through a declared Gateway surface.
    pub fn direct_input(surface_id: impl Into<String>, payload: Value) -> Self {
        Self {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload,
                provenance: None,
            }),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    /// Open one admitted input stream for a declared Gateway surface.
    pub fn input_stream(surface_id: impl Into<String>, open: GatewayStreamOpenRequest) -> Self {
        Self {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::InputStream(open),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    /// Attach provenance to a direct input submission.
    pub fn with_provenance(mut self, provenance: GatewayPayloadProvenance) -> Self {
        match &mut self.body {
            GatewaySubmissionBody::DirectInput(input) => input.provenance = Some(provenance),
            GatewaySubmissionBody::InputStream(_) => {}
        }
        self
    }

    /// Set the requested output mode.
    pub fn with_requested_output(mut self, output: OutputMode) -> Self {
        self.requested_output = output;
        self
    }

    /// Replace submission options.
    pub fn with_options(mut self, options: SubmitOptions) -> Self {
        self.options = options;
        self
    }

    /// Surface boundary selected by the caller.
    pub fn surface_id(&self) -> &str {
        &self.surface_id
    }

    /// Requested output mode.
    pub fn requested_output(&self) -> OutputMode {
        self.requested_output
    }

    /// Retry/deadline/encoding options.
    pub fn options(&self) -> &SubmitOptions {
        &self.options
    }
}

/// Server-generated acceptance metadata for one Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAccepted {
    /// Collision-resistant server authority for cancellation and replay.
    pub submission_id: String,
    /// Trace identity generated independently from `submission_id`.
    pub trace_root: String,
    /// Profile revision that admitted the request.
    pub profile_rev: GatewayProfileRev,
    /// Surface boundary used for admission, if one was selected.
    pub surface_id: String,
}

/// Result of a completed Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySubmitResult {
    /// Server acceptance metadata for the request.
    pub accepted: GatewayAccepted,
    /// Final execution outcome and its data and control provenance.
    pub output: ExecutionOutput,
    /// Whether this Gateway request executed or reused a retained request result.
    /// Cache hits within the executed program remain `CurrentAttempt` here.
    pub origin: CompletionOrigin,
}

/// Result of admitting the first `SubmitStream` frame.
pub enum GatewayInputStreamStart {
    /// A new stream request was admitted and chunks may now be delivered.
    Accepted(Box<GatewayAcceptedInputStream>),
    /// The idempotency record was already completed; no chunks are needed.
    Replay(Box<GatewaySubmitResult>),
}

/// Runtime-owned admission context for one accepted client input stream.
pub struct GatewayAcceptedInputStream {
    accepted: GatewayAccepted,
    open: GatewayStreamOpenRequest,
    limits: GatewayLimitProfile,
    profile: Arc<CompiledGatewayProfile>,
    session: GatewaySession,
    surface_id: String,
    requested_output: OutputMode,
    options: SubmitOptions,
    deadline: Option<Instant>,
    idempotency: Option<Box<GatewayIdempotencyReservation>>,
    request_guard: GatewayRequestGuard,
    request_process: ProcessId,
    executor: Executor,
}

impl GatewayAcceptedInputStream {
    /// Return the server acceptance metadata bound to this stream.
    pub fn accepted(&self) -> &GatewayAccepted {
        &self.accepted
    }

    /// Return the admitted stream declaration.
    pub fn open_request(&self) -> &GatewayStreamOpenRequest {
        &self.open
    }

    /// Return the profile limits that bound the stream chunks.
    pub fn limits(&self) -> &GatewayLimitProfile {
        &self.limits
    }

    /// Validate one decoded input stream item against the admitted surface.
    pub fn validate_chunk_item(&self, item: &Value) -> Result<(), GatewayError> {
        let surface = self
            .profile
            .surface_by_id(&self.surface_id)
            .ok_or_else(|| {
                GatewayError::Rejected("stream surface is no longer available".into())
            })?;
        validate_surface_stream_item(surface, self.open.modality, item)
    }
}

/// Cancellation request scoped to the authenticated principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayCancelRequest {
    /// Server-generated submission id returned by `submit`.
    pub submission_id: String,
    /// Trace root returned with the same submission.
    pub trace_root: String,
    /// Optional caller-visible reason for audit or transport delivery.
    pub reason: Option<String>,
}

/// Runtime state tracked for a Gateway request registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayRequestState {
    Running,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

/// Large-value metadata retained by the request registry.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayLargeValueRefSummary {
    hash: String,
    size: u64,
    mime: Option<String>,
}

/// In-memory request registry entry used for cancellation and short retention.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayRequestEntry {
    accepted: GatewayAccepted,
    request_process: ProcessId,
    gateway_id: String,
    principal_id: String,
    state: GatewayRequestState,
    deadline: Option<Instant>,
    retained_until_ms: i64,
    risk_class: String,
    surface_ids: Vec<String>,
    large_value_refs: Vec<GatewayLargeValueRefSummary>,
    admission_released: bool,
}

/// The body of a Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GatewaySubmissionBody {
    /// Direct kernel `Value` input lowered by the selected surface.
    DirectInput(GatewayDirectInput),
    /// Stream-open request admitted before transport chunks are folded into a
    /// direct input payload.
    InputStream(GatewayStreamOpenRequest),
}

/// Direct input payload. The payload is exactly the kernel `Value`; large refs
/// are expressed as `Value::{Blob,Tensor,Frame}` and require provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GatewayDirectInput {
    /// Kernel value supplied by the client.
    pub(crate) payload: Value,
    /// Provenance for inbound large refs.
    pub(crate) provenance: Option<GatewayPayloadProvenance>,
}

/// Stream-open request carried on streaming transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamOpenRequest {
    /// Client stream id, scoped to a single submission.
    pub stream_id: String,
    /// Declared direction.
    pub direction: GatewayStreamDirection,
    /// Declared modality.
    pub modality: GatewayModality,
    /// Profile-selected stream item schema id; client requests leave it empty.
    pub item_schema_id: String,
    /// Maximum inline item bytes requested by the client.
    pub max_inline_item_bytes: u64,
    /// Optional item cap.
    pub max_items: Option<u64>,
    /// Optional byte cap.
    pub max_bytes: Option<u64>,
}

/// Gateway stream direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayStreamDirection {
    /// Client sends items to kernel.
    ClientToKernel,
    /// Kernel sends items to client.
    KernelToClient,
    /// State subscription delivery to client.
    StateSubscriptionToClient,
}

/// Transport modality aligned to kernel `Value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayModality {
    /// General structured values accepted by the surface schema.
    Value,
    /// Text values carried inline.
    Text,
    /// Opaque byte values carried inline or by an admitted object reference.
    Bytes,
    /// Typed tensor references with a dtype and shape.
    Tensor,
    /// Timestamped audio frame references.
    AudioFrame,
    /// Timestamped video frame references.
    VideoFrame,
    /// Timestamped pose or trajectory frame references.
    PoseFrame,
    /// Timestamped sensor frame references.
    SensorFrame,
    /// Structured event items interpreted by the surface schema.
    Event,
    /// Control messages interpreted by the surface schema.
    Control,
}

/// One stream item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamChunk {
    /// Stream identifier within the active submission.
    pub stream_id: String,
    /// Sequence number used to validate ordered delivery within the stream.
    pub seq: u64,
    /// Payload validated against the stream's admitted modality and limits.
    pub item: Value,
    /// Upload ticket or store proof required when the payload contains objects.
    pub provenance: Option<GatewayPayloadProvenance>,
}

/// Terminal stream marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamEnd {
    /// Stream identifier within the active submission.
    pub stream_id: String,
    /// Terminal sequence number following the admitted stream items.
    pub seq: u64,
    /// Graceful completion or an explicit stream failure.
    pub marker: StreamMarker,
}

/// Static inspection result for a lowered submission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LoweredSubmissionInspection {
    node_count: usize,
    max_depth: usize,
    literal_bytes: usize,
    operation_count: usize,
    estimated_cost_micro_usd: u64,
    step_ref_count: usize,
    wait_signal_count: usize,
    wait_deadline_count: usize,
}

/// The shared gateway contract. Implementors verify credentials, map them to a
/// session, and run typed submissions through a profile-bound runtime.
#[async_trait]
pub trait Gateway: Send + Sync {
    /// Return redacted runtime status for transport handshakes and health.
    fn status(&self) -> GatewayRuntimeStatus;

    /// Inspect Host/SNI authorities currently registered for this listener.
    /// Request authorization must use [`Self::validate_session_authority`] so
    /// hosts and session generation come from the same profile snapshot.
    fn registered_gateway_hosts(&self) -> Vec<GatewayAllowedHost>;

    /// Return browser origins currently registered for browser transports.
    fn registered_browser_origins(&self) -> Vec<GatewayAllowedOrigin>;

    /// Verify a credential and create a Gateway session.
    async fn authenticate(
        &self,
        credential: PresentedCredential,
    ) -> Result<GatewaySession, GatewayError>;

    /// Validate the current session and its request authority against one
    /// profile snapshot. A transport resolves verified proxy headers before
    /// calling this; a separately read host list is not an authorization check.
    fn validate_session_authority(
        &self,
        session: &GatewaySession,
        authority: &str,
    ) -> Result<(), GatewayError>;

    /// Describe the active profile for an authenticated session.
    ///
    /// This is intentionally authenticated: unauthenticated discovery must not
    /// expose resource paths, effect names, capability literals, or limits.
    fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError>;

    /// Admit and run one Gateway submission as the session identity.
    async fn submit(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewaySubmitResult, GatewayError>;

    /// Admit an incremental output request. The returned owner drives execution
    /// while polled and cancels the request when dropped.
    async fn submit_output_stream(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
        window: StreamWindow,
    ) -> Result<GatewayOutputStream, GatewayError>;

    /// Admit a stream-open submission before accepting stream chunks.
    async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewayInputStreamStart, GatewayError>;

    /// Complete an admitted input stream with the folded payload.
    async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError>;

    /// Mark an admitted input stream failed before dispatch.
    async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        reason: &str,
    ) -> Result<(), GatewayError>;

    /// Cancel an admitted request owned by the authenticated principal.
    fn cancel(
        &self,
        session: &GatewaySession,
        request: GatewayCancelRequest,
    ) -> Result<bool, GatewayError>;

    /// Issue a ticket for a subsequent object upload/commit.
    async fn issue_object_upload_ticket(
        &self,
        session: &GatewaySession,
        request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError>;

    /// Begin an owned incremental upload without collecting its input.
    /// The returned upload accepts borrowed chunks and publishes its receipt at commit.
    async fn begin_object_upload(
        &self,
        session: &GatewaySession,
        request: BeginObjectUploadRequest,
    ) -> Result<GatewayObjectUpload, GatewayError>;

    /// Open an authenticated byte range using an explicitly issued read grant.
    /// A reference or upload receipt alone cannot authorize a download.
    async fn open_object_read(
        &self,
        session: &GatewaySession,
        request: OpenObjectReadRequest,
    ) -> Result<GatewayObjectDownload, GatewayError>;

    /// Record gateway-local audit metadata for an inbound request.
    fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String>;
}

/// Profile-driven in-process Gateway runtime over a [`Bootstrap`].
///
/// Every submission is statically admitted, stamped with inbound taint, then
/// executed as a fresh attenuated child Process. Handles are opened per request
/// Process from profile surfaces.
pub struct GatewayRuntime {
    boot: Arc<Bootstrap>,
    objects: ObjectStore,
    state: Arc<RwLock<GatewayRuntimeState>>,
    requests: Arc<GatewayRequestRegistry>,
}

struct GatewayRuntimeState {
    profile: Arc<CompiledGatewayProfile>,
    lkg_active: bool,
    consecutive_failed_reloads: u64,
    last_reload_failure: Option<GatewayProfileReloadFailure>,
}

#[derive(Debug, Default)]
struct GatewayRequestRegistry {
    inner: Mutex<GatewayRequestRegistryInner>,
}

#[derive(Debug, Default)]
struct GatewayRequestRegistryInner {
    entries: BTreeMap<String, GatewayRequestEntry>,
    global_running: usize,
    principal_running: BTreeMap<String, usize>,
    surface_running: BTreeMap<String, usize>,
    risk_running: BTreeMap<String, usize>,
    budget_running: GatewayBudgetCharge,
    budget_reservations: BTreeMap<u64, GatewayBudgetCharge>,
    next_budget_reservation_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GatewayExpiredRequest {
    request_process: ProcessId,
}

#[derive(Debug)]
struct GatewayAdmissionGuard {
    registry: Arc<GatewayRequestRegistry>,
    principal_id: String,
    surface_ids: Vec<String>,
    risk_class: String,
    released: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GatewayBudgetCharge {
    inflight_ops: u64,
    wall_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
    inline_value_bytes: u64,
    stream_items: u64,
    estimated_cost_micro_usd: u64,
}

#[derive(Debug)]
struct GatewayBudgetGuard {
    registry: Arc<GatewayRequestRegistry>,
    reservation_id: u64,
    released: bool,
}

#[derive(Debug)]
struct GatewayRequestLease {
    registry: Arc<GatewayRequestRegistry>,
    submission_id: String,
    admission: GatewayAdmissionGuard,
    budget: GatewayBudgetGuard,
}

#[derive(Debug)]
struct GatewayRequestGuard {
    lease: Arc<GatewayRequestLease>,
    process: Option<RequestProcess<'static>>,
    finished: bool,
}

impl GatewayRequestRegistry {
    fn new() -> Self {
        Self::default()
    }

    fn new_acceptance(
        &self,
        profile_rev: GatewayProfileRev,
        surface_id: String,
    ) -> Result<GatewayAccepted, GatewayError> {
        for _ in 0..8 {
            let accepted = GatewayAccepted {
                submission_id: random_gateway_id("gw-submission", profile_rev)?,
                trace_root: random_gateway_id("gw-trace", profile_rev)?,
                profile_rev,
                surface_id: surface_id.clone(),
            };
            if !self
                .inner
                .lock()
                .entries
                .contains_key(&accepted.submission_id)
            {
                return Ok(accepted);
            }
        }
        Err(GatewayError::LimitExceeded(
            "submission id collision retry limit exceeded".into(),
        ))
    }

    fn try_reserve_budget(
        self: &Arc<Self>,
        budget: &GatewayBudgetProfile,
        charge: GatewayBudgetCharge,
    ) -> Result<GatewayBudgetGuard, GatewayError> {
        let mut inner = self.inner.lock();
        ensure_budget_capacity(
            budget.max_inflight_ops,
            inner.budget_running.inflight_ops,
            charge.inflight_ops,
            "gateway budget in-flight ops",
        )?;
        ensure_budget_capacity(
            budget.max_wall_ms,
            inner.budget_running.wall_ms,
            charge.wall_ms,
            "gateway budget wall-ms",
        )?;
        ensure_budget_capacity(
            budget.max_bytes_in,
            inner.budget_running.bytes_in,
            charge.bytes_in,
            "gateway budget bytes-in",
        )?;
        ensure_budget_capacity(
            budget.max_bytes_out,
            inner.budget_running.bytes_out,
            charge.bytes_out,
            "gateway budget bytes-out",
        )?;
        ensure_budget_capacity(
            budget.max_inline_value_bytes,
            inner.budget_running.inline_value_bytes,
            charge.inline_value_bytes,
            "gateway budget inline value bytes",
        )?;
        ensure_budget_capacity(
            budget.max_stream_items,
            inner.budget_running.stream_items,
            charge.stream_items,
            "gateway budget stream items",
        )?;
        ensure_budget_capacity(
            budget.max_estimated_cost_micro_usd,
            inner.budget_running.estimated_cost_micro_usd,
            charge.estimated_cost_micro_usd,
            "gateway budget estimated cost",
        )?;

        inner.next_budget_reservation_id = inner.next_budget_reservation_id.saturating_add(1);
        let reservation_id = inner.next_budget_reservation_id;
        inner.budget_running = add_budget_charge(inner.budget_running, charge);
        inner.budget_reservations.insert(reservation_id, charge);
        Ok(GatewayBudgetGuard {
            registry: self.clone(),
            reservation_id,
            released: false,
        })
    }

    fn try_admit(
        self: &Arc<Self>,
        limits: &GatewayLimitProfile,
        principal_id: String,
        surface_ids: Vec<String>,
        risk_class: String,
    ) -> Result<GatewayAdmissionGuard, GatewayError> {
        let mut inner = self.inner.lock();
        if inner.global_running >= limits.max_in_flight_requests {
            return Err(GatewayError::LimitExceeded(
                "global in-flight request limit".into(),
            ));
        }
        let principal_limit = effective_fair_counter_limit(
            limits.max_principal_in_flight_requests,
            limits.max_in_flight_requests,
        );
        if counter_value(&inner.principal_running, &principal_id) >= principal_limit {
            return Err(GatewayError::LimitExceeded(
                "principal in-flight request limit".into(),
            ));
        }
        let surface_limit = effective_fair_counter_limit(
            limits.max_surface_in_flight_requests,
            limits.max_in_flight_requests,
        );
        for surface_id in &surface_ids {
            if counter_value(&inner.surface_running, surface_id) >= surface_limit {
                return Err(GatewayError::LimitExceeded(
                    "surface in-flight request limit".into(),
                ));
            }
        }
        let risk_limit = effective_fair_counter_limit(
            limits.max_risk_class_in_flight_requests,
            limits.max_in_flight_requests,
        );
        if counter_value(&inner.risk_running, &risk_class) >= risk_limit {
            return Err(GatewayError::LimitExceeded(
                "risk-class in-flight request limit".into(),
            ));
        }

        inner.global_running = inner.global_running.saturating_add(1);
        increment_counter(&mut inner.principal_running, &principal_id);
        for surface_id in &surface_ids {
            increment_counter(&mut inner.surface_running, surface_id);
        }
        increment_counter(&mut inner.risk_running, &risk_class);

        Ok(GatewayAdmissionGuard {
            registry: self.clone(),
            principal_id,
            surface_ids,
            risk_class,
            released: false,
        })
    }

    fn insert_running(
        self: &Arc<Self>,
        entry: GatewayRequestEntry,
        admission: GatewayAdmissionGuard,
        budget: GatewayBudgetGuard,
        process: RequestProcess<'static>,
    ) -> Result<GatewayRequestGuard, GatewayError> {
        let submission_id = entry.accepted.submission_id.clone();
        let mut inner = self.inner.lock();
        prune_completed_requests(&mut inner, now_millis());
        if inner.entries.contains_key(&submission_id) {
            return Err(GatewayError::LimitExceeded(
                "submission id collision".into(),
            ));
        }
        inner.entries.insert(submission_id.clone(), entry);
        Ok(GatewayRequestGuard {
            lease: Arc::new(GatewayRequestLease {
                registry: self.clone(),
                submission_id,
                admission,
                budget,
            }),
            process: Some(process),
            finished: false,
        })
    }

    fn finish(&self, submission_id: &str, state: GatewayRequestState, now_ms: i64) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.get_mut(submission_id) {
            if entry.state == GatewayRequestState::Running {
                entry.state = state;
            }
            entry.retained_until_ms = now_ms.saturating_add(COMPLETED_REQUEST_RETENTION_MS);
        }
        prune_completed_requests(&mut inner, now_ms);
    }

    fn cancel(
        &self,
        session: &GatewaySession,
        request: &GatewayCancelRequest,
        boot: &Bootstrap,
    ) -> Result<bool, GatewayError> {
        if request.submission_id.trim().is_empty() || request.trace_root.trim().is_empty() {
            return Ok(false);
        }
        let process = {
            let mut inner = self.inner.lock();
            let Some(entry) = inner.entries.get_mut(&request.submission_id) else {
                return Ok(false);
            };
            if entry.principal_id != session.principal.principal_id
                || entry.gateway_id != session.profile_name
                || entry.accepted.trace_root != request.trace_root
            {
                return Ok(false);
            }
            if entry.state != GatewayRequestState::Running {
                return Ok(matches!(entry.state, GatewayRequestState::Cancelled));
            }
            entry.state = GatewayRequestState::Cancelled;
            entry.retained_until_ms = now_millis().saturating_add(COMPLETED_REQUEST_RETENTION_MS);
            entry.request_process
        };
        boot.cancel_process(process)
            .map_err(|error| GatewayError::Rejected(error.to_string()))?;
        Ok(true)
    }

    fn release_admission(&self, admission: &GatewayAdmissionGuard) {
        let mut inner = self.inner.lock();
        decrement_admission_counters(
            &mut inner,
            &admission.principal_id,
            &admission.surface_ids,
            &admission.risk_class,
        );
    }

    fn release_entry_admission(&self, submission_id: &str, _admission: &GatewayAdmissionGuard) {
        let mut inner = self.inner.lock();
        release_entry_admission(&mut inner, submission_id);
    }

    fn release_budget(&self, reservation_id: u64) {
        let mut inner = self.inner.lock();
        release_budget_reservation(&mut inner, reservation_id);
    }

    fn expire_deadlines(&self, now: Instant) -> Vec<GatewayExpiredRequest> {
        let now_ms = now_millis();
        let mut inner = self.inner.lock();
        let mut expired = Vec::new();
        for entry in inner.entries.values_mut() {
            if entry.state != GatewayRequestState::Running {
                continue;
            }
            let Some(deadline) = entry.deadline else {
                continue;
            };
            if deadline > now {
                continue;
            }
            entry.state = GatewayRequestState::Expired;
            entry.retained_until_ms = now_ms.saturating_add(COMPLETED_REQUEST_RETENTION_MS);
            expired.push(GatewayExpiredRequest {
                request_process: entry.request_process,
            });
        }
        prune_completed_requests(&mut inner, now_ms);
        expired
    }
}

impl GatewayAdmissionGuard {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_admission(self);
        self.released = true;
    }

    fn release_for_submission(&mut self, submission_id: &str) {
        if self.released {
            return;
        }
        self.registry.release_entry_admission(submission_id, self);
        self.released = true;
    }
}

impl Drop for GatewayAdmissionGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl GatewayBudgetGuard {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_budget(self.reservation_id);
        self.released = true;
    }
}

impl Drop for GatewayBudgetGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl GatewayRequestLease {
    fn output_interruption(&self) -> Option<Failure> {
        let inner = self.registry.inner.lock();
        match inner
            .entries
            .get(&self.submission_id)
            .map(|entry| entry.state)
        {
            Some(GatewayRequestState::Cancelled) | None => Some(Failure::Cancelled),
            Some(GatewayRequestState::Expired) => Some(Failure::Timeout),
            Some(
                GatewayRequestState::Running
                | GatewayRequestState::Completed
                | GatewayRequestState::Failed,
            ) => None,
        }
    }

    /// Freeze execution's result before asynchronous persistence and cleanup.
    fn finish_execution(&self, output: &mut ExecutionOutput, boot: &Bootstrap) {
        let expired_process = {
            let mut inner = self.registry.inner.lock();
            let Some(entry) = inner.entries.get_mut(&self.submission_id) else {
                output.outcome = Outcome::Fail(Failure::Cancelled);
                return;
            };
            if entry.state == GatewayRequestState::Running {
                entry.state = if entry
                    .deadline
                    .is_some_and(|deadline| deadline <= Instant::now())
                {
                    GatewayRequestState::Expired
                } else {
                    match output.outcome {
                        Outcome::Done(_) | Outcome::Short(_) => GatewayRequestState::Completed,
                        Outcome::Fail(_) => GatewayRequestState::Failed,
                    }
                };
            }
            let expired_process = match entry.state {
                GatewayRequestState::Cancelled => {
                    output.outcome = Outcome::Fail(Failure::Cancelled);
                    None
                }
                GatewayRequestState::Expired => {
                    output.outcome = Outcome::Fail(Failure::Timeout);
                    Some(entry.request_process)
                }
                GatewayRequestState::Running
                | GatewayRequestState::Completed
                | GatewayRequestState::Failed => None,
            };
            let now_ms = now_millis();
            entry.retained_until_ms = now_ms.saturating_add(COMPLETED_REQUEST_RETENTION_MS);
            prune_completed_requests(&mut inner, now_ms);
            expired_process
        };
        if let Some(process) = expired_process
            && let Err(error) = boot.cancel_process(process)
        {
            tracing::error!(
                process = process.get(),
                error = %error,
                "request deadline cancellation failed"
            );
        }
    }
}

impl Drop for GatewayRequestLease {
    fn drop(&mut self) {
        self.admission.release_for_submission(&self.submission_id);
        self.budget.release();
    }
}

impl GatewayRequestGuard {
    async fn commit_objects(
        &self,
        runtime: &GatewayRuntime,
        session: &GatewaySession,
        objects: object::ObjectAdmission,
        deadline: Option<Instant>,
    ) -> Result<TaintSet, GatewayError> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| GatewayError::Rejected("gateway request is already finished".into()))?;
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(GatewayError::Rejected(
                "gateway request deadline expired".into(),
            ));
        }
        if runtime.boot.kernel.processes.status(process.id()) != Some(ProcessStatus::Running) {
            return Err(GatewayError::Rejected(
                "gateway request is no longer running".into(),
            ));
        }
        objects.commit(runtime, session).await
    }

    fn finish(&mut self) {
        self.finished = true;
        if let Some(process) = self.process.take() {
            process.detach();
        }
    }

    fn fail(&mut self) {
        self.lease.registry.finish(
            &self.lease.submission_id,
            GatewayRequestState::Failed,
            now_millis(),
        );
        self.finished = true;
        drop(self.process.take());
    }
}

impl Drop for GatewayRequestGuard {
    fn drop(&mut self) {
        if !self.finished {
            // Abandoning execution interrupts borrowed output too. A driver's
            // ordinary failure is still deliverable, so it is a different state.
            // `finish` preserves results already frozen before persistence.
            self.lease.registry.finish(
                &self.lease.submission_id,
                GatewayRequestState::Cancelled,
                now_millis(),
            );
        }
        drop(self.process.take());
    }
}

fn effective_fair_counter_limit(configured_limit: usize, global_limit: usize) -> usize {
    configured_limit.min(fair_counter_limit(global_limit))
}

fn fair_counter_limit(global_limit: usize) -> usize {
    match global_limit {
        0 | 1 => global_limit,
        n => n.saturating_sub(1).max(1),
    }
}

fn counter_value(map: &BTreeMap<String, usize>, key: &str) -> usize {
    map.get(key).copied().unwrap_or(0)
}

fn increment_counter(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

fn decrement_counter(map: &mut BTreeMap<String, usize>, key: &str) {
    let Some(count) = map.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        map.remove(key);
    }
}

fn decrement_admission_counters(
    inner: &mut GatewayRequestRegistryInner,
    principal_id: &str,
    surface_ids: &[String],
    risk_class: &str,
) {
    inner.global_running = inner.global_running.saturating_sub(1);
    decrement_counter(&mut inner.principal_running, principal_id);
    for surface_id in surface_ids {
        decrement_counter(&mut inner.surface_running, surface_id);
    }
    decrement_counter(&mut inner.risk_running, risk_class);
}

fn release_entry_admission(inner: &mut GatewayRequestRegistryInner, submission_id: &str) -> bool {
    let Some(entry) = inner.entries.get_mut(submission_id) else {
        return false;
    };
    if entry.admission_released {
        return false;
    }
    entry.admission_released = true;
    let principal_id = entry.principal_id.clone();
    let surface_ids = entry.surface_ids.clone();
    let risk_class = entry.risk_class.clone();
    decrement_admission_counters(inner, &principal_id, &surface_ids, &risk_class);
    true
}

fn release_budget_reservation(
    inner: &mut GatewayRequestRegistryInner,
    reservation_id: u64,
) -> bool {
    let Some(charge) = inner.budget_reservations.remove(&reservation_id) else {
        return false;
    };
    inner.budget_running = subtract_budget_charge(inner.budget_running, charge);
    true
}

fn ensure_budget_capacity(
    limit: Option<u64>,
    current: u64,
    charge: u64,
    label: &'static str,
) -> Result<(), GatewayError> {
    let Some(limit) = limit else {
        return Ok(());
    };
    if current.saturating_add(charge) > limit {
        return Err(GatewayError::LimitExceeded(format!("{label} limit")));
    }
    Ok(())
}

fn add_budget_charge(left: GatewayBudgetCharge, right: GatewayBudgetCharge) -> GatewayBudgetCharge {
    GatewayBudgetCharge {
        inflight_ops: left.inflight_ops.saturating_add(right.inflight_ops),
        wall_ms: left.wall_ms.saturating_add(right.wall_ms),
        bytes_in: left.bytes_in.saturating_add(right.bytes_in),
        bytes_out: left.bytes_out.saturating_add(right.bytes_out),
        inline_value_bytes: left
            .inline_value_bytes
            .saturating_add(right.inline_value_bytes),
        stream_items: left.stream_items.saturating_add(right.stream_items),
        estimated_cost_micro_usd: left
            .estimated_cost_micro_usd
            .saturating_add(right.estimated_cost_micro_usd),
    }
}

fn subtract_budget_charge(
    left: GatewayBudgetCharge,
    right: GatewayBudgetCharge,
) -> GatewayBudgetCharge {
    GatewayBudgetCharge {
        inflight_ops: left.inflight_ops.saturating_sub(right.inflight_ops),
        wall_ms: left.wall_ms.saturating_sub(right.wall_ms),
        bytes_in: left.bytes_in.saturating_sub(right.bytes_in),
        bytes_out: left.bytes_out.saturating_sub(right.bytes_out),
        inline_value_bytes: left
            .inline_value_bytes
            .saturating_sub(right.inline_value_bytes),
        stream_items: left.stream_items.saturating_sub(right.stream_items),
        estimated_cost_micro_usd: left
            .estimated_cost_micro_usd
            .saturating_sub(right.estimated_cost_micro_usd),
    }
}

fn prune_completed_requests(inner: &mut GatewayRequestRegistryInner, now_ms: i64) {
    inner.entries.retain(|_, entry| {
        !entry.admission_released
            || entry.state == GatewayRequestState::Running
            || entry.retained_until_ms > now_ms
    });
}

fn spawn_deadline_sweeper(boot: &Arc<Bootstrap>, registry: &Arc<GatewayRequestRegistry>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let boot = Arc::downgrade(boot);
    let registry = Arc::downgrade(registry);
    handle.spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(DEADLINE_SWEEP_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let (Some(boot), Some(registry)) = (boot.upgrade(), registry.upgrade()) else {
                break;
            };
            for expired in registry.expire_deadlines(Instant::now()) {
                if let Err(error) = boot.cancel_process(expired.request_process) {
                    tracing::error!(
                        process = expired.request_process.get(),
                        error = %error,
                        "deadline sweeper failed to cancel request process"
                    );
                }
            }
        }
    });
}

impl GatewayRuntime {
    /// Create a runtime backed by `boot` and an explicit profile.
    pub fn new(boot: Arc<Bootstrap>, profile: GatewayProfile) -> Result<Self, GatewayError> {
        let profile = Arc::new(Self::compile_profile(&boot, profile)?);
        let requests = Arc::new(GatewayRequestRegistry::new());
        spawn_deadline_sweeper(&boot, &requests);
        Ok(Self {
            boot,
            objects: ObjectStore::new(),
            state: Arc::new(RwLock::new(GatewayRuntimeState {
                profile,
                lkg_active: false,
                consecutive_failed_reloads: 0,
                last_reload_failure: None,
            })),
            requests,
        })
    }

    /// Replace the active profile snapshot.
    ///
    /// Compilation and resource resolution happen before the swap. If the new
    /// profile is malformed, the current snapshot remains active and the error
    /// is returned.
    pub fn replace_profile(
        &self,
        profile: GatewayProfile,
    ) -> Result<GatewayProfileRev, GatewayError> {
        let attempted_rev = profile.revision;
        let profile = match Self::compile_profile(&self.boot, profile) {
            Ok(profile) => Arc::new(profile),
            Err(error) => {
                self.record_reload_failure(attempted_rev, reload_failure_code(&error));
                return Err(error);
            }
        };
        let revision = profile.revision;
        let mut state = self.state.write();
        if revision <= state.profile.revision {
            state.record_reload_failure(attempted_rev, "stale_revision");
            return Err(GatewayError::InvalidProfile(format!(
                "profile revision must increase above active revision {}",
                state.profile.revision
            )));
        }
        *state = GatewayRuntimeState {
            profile,
            lkg_active: false,
            consecutive_failed_reloads: 0,
            last_reload_failure: None,
        };
        Ok(revision)
    }

    /// Return the profile name served by this runtime.
    pub fn profile_name(&self) -> String {
        self.profile_snapshot().profile_name.clone()
    }

    /// Return the profile revision served by this runtime.
    pub fn profile_rev(&self) -> GatewayProfileRev {
        self.profile_snapshot().revision
    }

    /// Whether the active profile can authenticate at least one credential.
    ///
    /// Closed profiles compile successfully so listeners can start fail-closed,
    /// but do not report production readiness.
    pub fn is_ready(&self) -> bool {
        self.profile_snapshot().has_authenticating_credentials()
    }

    /// Return redacted runtime status.
    pub fn status(&self) -> GatewayRuntimeStatus {
        self.state.read().status()
    }

    /// Reclaim running request registry entries whose server deadline expired.
    pub fn sweep_deadline_expired_requests(&self) -> usize {
        let expired = self.requests.expire_deadlines(Instant::now());
        let count = expired.len();
        for request in expired {
            if let Err(error) = self.boot.cancel_process(request.request_process) {
                tracing::error!(
                    process = request.request_process.get(),
                    error = %error,
                    "deadline sweep failed to cancel request process"
                );
            }
        }
        count
    }

    /// Describe the active profile for an authenticated session.
    ///
    /// This is intentionally authenticated: unauthenticated discovery must not
    /// expose resource paths, effect names, capability literals, or limits.
    pub fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError> {
        let profile = self.profile_snapshot();
        if session.profile_name != profile.profile_name || session.profile_rev != profile.revision {
            return Err(GatewayError::Rejected(
                "gateway session was issued by a different profile snapshot".into(),
            ));
        }
        profile.session_identity_path(session)?;
        let binding = profile.binding_for_principal(&session.principal.principal_id);
        let visible_publications = profile
            .publication_descriptors
            .iter()
            .filter(|publication| binding.visible.contains(&publication.surface_id))
            .cloned()
            .collect();
        Ok(GatewayDescriptor {
            profile_name: profile.profile_name.clone(),
            profile_rev: profile.revision,
            surfaces: profile
                .surface_descriptors
                .iter()
                .filter(|surface| binding.visible.contains(&surface.surface_id))
                .map(|surface| GatewaySurfaceDescriptor {
                    surface_id: surface.surface_id.clone(),
                    target: surface.target.clone(),
                    publish_capability: surface.publish_capability.clone(),
                    input_schema: surface.input_schema.clone(),
                    output_schema: surface.output_schema.clone(),
                    output_stream_schema: surface.output_stream_schema.clone(),
                })
                .collect(),
            publications: visible_publications,
            limits: profile.limits.clone(),
        })
    }

    /// Admit a `SubmitStream` stream-open request before any input chunk is
    /// consumed.
    pub async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewayInputStreamStart, GatewayError> {
        submission::validate_output_port(submission.requested_output, false)?;
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        let now_ms = now_millis();
        let mut idempotency = match reserve_submission_idempotency_if_present(
            &self.boot.kernel.state,
            &profile,
            session,
            &submission,
            initial_idempotency_material(&self.boot, &profile, session, &submission)?,
            now_ms,
        )
        .await?
        {
            Some(SubmissionIdempotency::Replay(result)) => {
                return Ok(GatewayInputStreamStart::Replay(result));
            }
            Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
            None => None,
        };
        if let Err(e) = validate_submit_options(&submission.options, &profile.limits, now_ms) {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_deref(),
                e,
            )
            .await;
        }
        let deadline = match request_deadline(&submission.options) {
            Ok(deadline) => deadline,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };

        let GatewaySubmission {
            surface_id,
            body,
            requested_output,
            options,
        } = submission.clone();
        let GatewaySubmissionBody::InputStream(open) = body else {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_deref(),
                GatewayError::Rejected("stream admission requires a stream_open body".into()),
            )
            .await;
        };
        let surface =
            match validate_input_stream_open_request(&profile, session, &surface_id, &open) {
                Ok(surface) => surface,
                Err(e) => {
                    return release_submission_idempotency_reservation_and_fail(
                        &self.boot.kernel.state,
                        idempotency.as_deref(),
                        e,
                    )
                    .await;
                }
            };
        let mut surface_ids = BTreeSet::new();
        surface_ids.insert(surface.surface_id.clone());
        let program = stream_open_admission_program(surface, requested_output);
        let admission = match inspect_lowered_submission(
            &program,
            &profile,
            &session.principal.principal_id,
            surface,
            &self.boot,
            false,
        ) {
            Ok(admission) => admission,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        if admission.requires_idempotency && idempotency.is_none() {
            idempotency = match reserve_submission_idempotency_if_present(
                &self.boot.kernel.state,
                &profile,
                session,
                &submission,
                required_idempotency_material(&submission)?,
                now_ms,
            )
            .await?
            {
                Some(SubmissionIdempotency::Replay(result)) => {
                    return Ok(GatewayInputStreamStart::Replay(result));
                }
                Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
                None => {
                    return Err(GatewayError::Rejected(
                        "idempotency_key or submission_token is required for non-idempotent effects"
                            .into(),
                    ));
                }
            };
        }
        let risk_class = request_risk_class(&admission);
        let fair_surface_ids = vec![surface.surface_id.clone()];
        let budget_charge = match gateway_budget_charge_for_stream_open(
            &admission,
            surface,
            &self.boot,
            &open,
            &profile.limits,
            &options,
            now_ms,
        ) {
            Ok(charge) => charge,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let budget_guard = match self
            .requests
            .try_reserve_budget(&profile.limits.budget, budget_charge)
        {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let admission_guard = match self.requests.try_admit(
            &profile.limits,
            session.principal.principal_id.clone(),
            fair_surface_ids.clone(),
            risk_class.clone(),
        ) {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let accepted = match self
            .requests
            .new_acceptance(profile.revision, surface.surface_id.clone())
        {
            Ok(accepted) => accepted,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let (request_owner, executor) =
            match self.executor_for(&profile, session, &surface_ids).await {
                Ok(ex) => ex,
                Err(e) => {
                    return release_submission_idempotency_reservation_and_fail(
                        &self.boot.kernel.state,
                        idempotency.as_deref(),
                        e,
                    )
                    .await;
                }
            };
        let request_process = request_owner.id();
        let entry = GatewayRequestEntry {
            accepted: accepted.clone(),
            request_process,
            gateway_id: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            state: GatewayRequestState::Running,
            deadline,
            retained_until_ms: i64::MAX,
            risk_class,
            surface_ids: fair_surface_ids,
            large_value_refs: Vec::new(),
            admission_released: false,
        };
        let request_guard =
            match self
                .requests
                .insert_running(entry, admission_guard, budget_guard, request_owner)
            {
                Ok(guard) => guard,
                Err(e) => {
                    return release_submission_idempotency_reservation_and_fail(
                        &self.boot.kernel.state,
                        idempotency.as_deref(),
                        e,
                    )
                    .await;
                }
            };
        Ok(GatewayInputStreamStart::Accepted(Box::new(
            GatewayAcceptedInputStream {
                accepted,
                open,
                limits: profile.limits.clone(),
                profile,
                session: session.clone(),
                surface_id,
                requested_output,
                options,
                deadline,
                idempotency,
                request_guard,
                request_process,
                executor,
            },
        )))
    }

    /// Complete an accepted input stream and run it through the same request
    /// registry entry that admitted the stream-open frame.
    /// The stream must belong to this runtime; cloned `Arc` handles share its
    /// registry, while a separately constructed runtime is rejected.
    pub async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        submission::complete_input_stream(self, stream, payload, provenance).await
    }

    /// Mark an accepted input stream failed before dispatch.
    /// The stream must belong to this runtime; cloned `Arc` handles share its
    /// registry, while a separately constructed runtime is rejected.
    pub async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        _reason: &str,
    ) -> Result<(), GatewayError> {
        self.validate_input_stream_owner(&stream)?;
        finish_request_and_release_idempotency(
            &self.boot,
            stream.request_process,
            stream.idempotency.as_deref(),
        )
        .await
    }

    fn validate_input_stream_owner(
        &self,
        stream: &GatewayAcceptedInputStream,
    ) -> Result<(), GatewayError> {
        if !Arc::ptr_eq(&self.requests, &stream.request_guard.lease.registry) {
            return Err(GatewayError::Rejected(
                "input stream belongs to a different gateway runtime".into(),
            ));
        }
        Ok(())
    }

    fn compile_profile(
        boot: &Bootstrap,
        profile: GatewayProfile,
    ) -> Result<CompiledGatewayProfile, GatewayError> {
        let mut profile = CompiledGatewayProfile::compile(profile)?;
        for surface in &mut profile.surface_descriptors {
            surface.method_bitmap =
                surface_method_bitmap(boot, &surface.target, GATEWAY_EFFECT_METHOD).map_err(
                    |e| {
                        GatewayError::InvalidProfile(format!(
                            "surface {} references missing method {} on {}: {e}",
                            surface.surface_id,
                            GATEWAY_EFFECT_METHOD,
                            surface.target.path()
                        ))
                    },
                )?;
        }
        profile.surfaces_by_id = profile
            .surface_descriptors
            .iter()
            .map(|surface| (surface.surface_id.clone(), surface.clone()))
            .collect();
        for (principal_id, binding) in &mut profile.surface_bindings_by_principal {
            binding.request_grants_by_surface.clear();
            for surface_id in &binding.submit {
                let Some(surface) = profile.surfaces_by_id.get(surface_id) else {
                    return Err(GatewayError::InvalidProfile(format!(
                        "submit surface {surface_id} for principal {principal_id} is unavailable"
                    )));
                };
                if !binding
                    .capability_ceiling
                    .iter()
                    .any(|ceiling| ceiling.covers_cap(&surface.grant_capability))
                {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {principal_id} does not cover surface {} grant template {}",
                        surface.surface_id, surface.grant_template
                    )));
                }
                binding.request_grants_by_surface.insert(
                    surface.surface_id.clone(),
                    CompiledRequestGrantTemplate {
                        selector: surface.grant_selector.clone(),
                        methods: surface.method_bitmap,
                    },
                );
            }
        }
        if let Some(anchor) = profile.authority_anchor {
            if boot.kernel.processes.identity(anchor).is_none() {
                return Err(GatewayError::InvalidProfile(format!(
                    "authority anchor process {anchor} does not exist"
                )));
            }
            let now_millis = xolotl_kernel::now_millis();
            let mut anchor_grants = boot.kernel.registry.grants_of(anchor);
            anchor_grants.extend(boot.kernel.processes.attached_grants(anchor));
            for surface in &profile.surface_descriptors {
                if !anchor_grants.iter().any(|grant| {
                    !grant.expires.is_expired(now_millis)
                        && surface.method_bitmap.is_subset_of(grant.rights.methods)
                        && grant.selector.pattern.covers_cap(&surface.grant_capability)
                }) {
                    return Err(GatewayError::InvalidProfile(format!(
                        "authority anchor does not cover surface {} grant template {}",
                        surface.surface_id, surface.grant_template
                    )));
                }
            }
        }
        Ok(profile)
    }

    fn profile_snapshot(&self) -> Arc<CompiledGatewayProfile> {
        self.state.read().profile.clone()
    }

    /// Record a failed dynamic profile reload while keeping the active snapshot.
    pub fn record_reload_failure(&self, attempted_rev: GatewayProfileRev, code: &'static str) {
        self.state
            .write()
            .record_reload_failure(attempted_rev, code);
    }

    fn spawn_gateway_request_process(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_ids: &BTreeSet<String>,
    ) -> Result<RequestProcess<'static>, GatewayError> {
        let identity_path = profile.session_identity_path(session)?;
        let id_path = parse_identity_path(identity_path)?;
        let id_ref = intern_identity(&id_path);
        let surfaces = profile.surface_descriptors_for_ids(surface_ids)?;
        let binding = if surface_ids.is_empty() {
            None
        } else {
            Some(
                profile
                    .surface_bindings_by_principal
                    .get(&session.principal.principal_id)
                    .ok_or_else(|| {
                        GatewayError::Rejected("principal has no callable surfaces".into())
                    })?,
            )
        };
        let mut grant_templates = BTreeMap::<String, (ResourceSelector, MethodBitmap)>::new();
        for surface in surfaces {
            let Some(binding) = binding else {
                continue;
            };
            if !binding.submit.contains(&surface.surface_id) {
                return Err(GatewayError::Rejected(format!(
                    "surface {} is not callable by principal",
                    surface.surface_id
                )));
            }
            let Some(request_grant) = binding.request_grants_by_surface.get(&surface.surface_id)
            else {
                return Err(GatewayError::Rejected(format!(
                    "surface {} has no compiled request grant",
                    surface.surface_id
                )));
            };
            grant_templates
                .entry(surface.grant_template.clone())
                .and_modify(|(_, methods)| *methods |= request_grant.methods)
                .or_insert((request_grant.selector.clone(), request_grant.methods));
        }
        let declared: Vec<CompiledRequestGrantTemplate> = grant_templates
            .iter()
            .map(|(_, (selector, methods))| CompiledRequestGrantTemplate {
                selector: selector.clone(),
                methods: *methods,
            })
            .collect();
        let anchor = profile.authority_anchor.unwrap_or(self.boot.root);
        self.boot
            .request_under_owned(anchor, id_ref, &declared)
            .map_err(|e| GatewayError::Rejected(e.to_string()))
    }

    async fn executor_for(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_ids: &BTreeSet<String>,
    ) -> Result<(RequestProcess<'static>, Executor), GatewayError> {
        let surfaces = profile.surface_descriptors_for_ids(surface_ids)?;
        let request = self.spawn_gateway_request_process(profile, session, surface_ids)?;
        let proc = request.id();
        let ex = request.executor();
        let mut opened = BTreeSet::new();
        for surface in surfaces {
            let key = format!("{}\0{}", surface.target.path(), GATEWAY_EFFECT_HANDLE_VERB);
            if !opened.insert(key) {
                continue;
            }
            let opened = self
                .boot
                .open_for(proc, &surface.target, GATEWAY_EFFECT_HANDLE_VERB)
                .map_err(|e| GatewayError::Rejected(e.to_string()));
            let opened = match opened {
                Ok(opened) => opened,
                Err(error) => {
                    return finish_request_without_idempotency_and_fail(&self.boot, proc, error)
                        .await;
                }
            };
            ex.bind_handle(surface.target.clone(), opened);
        }
        Ok((request, ex))
    }

    fn source_label(profile: &CompiledGatewayProfile) -> String {
        format!("gateway/{}", profile.profile_name)
    }
}

impl GatewayRuntimeState {
    fn record_reload_failure(&mut self, attempted_rev: GatewayProfileRev, code: &'static str) {
        self.lkg_active = true;
        self.consecutive_failed_reloads = self.consecutive_failed_reloads.saturating_add(1);
        self.last_reload_failure = Some(GatewayProfileReloadFailure {
            attempted_profile_rev: attempted_rev,
            code: code.into(),
            public_message: "profile reload rejected".into(),
        });
    }

    fn status(&self) -> GatewayRuntimeStatus {
        let ready = self.profile.has_authenticating_credentials();
        let readiness = if self.lkg_active && ready {
            GatewayReadiness::DegradedLastKnownGood
        } else if ready {
            GatewayReadiness::Ready
        } else {
            GatewayReadiness::NotReadyClosed
        };
        GatewayRuntimeStatus {
            profile_name: self.profile.profile_name.clone(),
            profile_rev: self.profile.revision,
            ready,
            readiness,
            lkg_active: self.lkg_active,
            consecutive_failed_reloads: self.consecutive_failed_reloads,
            last_reload_failure: self.last_reload_failure.clone(),
        }
    }
}

fn reload_failure_code(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::InvalidProfile(_) => "invalid_profile",
        GatewayError::Unauthenticated => "auth_failed",
        GatewayError::Unauthorized(_) => "permission_denied",
        GatewayError::Rejected(_) => "request_rejected",
        GatewayError::LimitExceeded(_) => "limit_exceeded",
    }
}

#[async_trait]
impl Gateway for GatewayRuntime {
    fn status(&self) -> GatewayRuntimeStatus {
        GatewayRuntime::status(self)
    }

    fn registered_gateway_hosts(&self) -> Vec<GatewayAllowedHost> {
        self.profile_snapshot().registered_hosts.clone()
    }

    fn registered_browser_origins(&self) -> Vec<GatewayAllowedOrigin> {
        self.profile_snapshot().registered_origins.clone()
    }

    fn validate_session_authority(
        &self,
        session: &GatewaySession,
        authority: &str,
    ) -> Result<(), GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        if !gateway_host_allowed(authority, &profile.registered_hosts) {
            return Err(GatewayError::Unauthorized(
                session.principal.principal_id.clone(),
            ));
        }
        Ok(())
    }

    async fn authenticate(
        &self,
        credential: PresentedCredential,
    ) -> Result<GatewaySession, GatewayError> {
        let profile = self.profile_snapshot();
        let principal = match credential {
            PresentedCredential::Bearer(token) => profile.verify_bearer(&token)?,
            PresentedCredential::ClientCertificate(credential) => {
                profile.verify_client_certificate(&credential)?
            }
        };
        let mapping = profile
            .identity_by_principal
            .get(&principal.principal_id)
            .ok_or_else(|| GatewayError::Unauthorized(principal.principal_id.clone()))?;
        if !mapping.enabled || principal.principal_generation != mapping.generation {
            return Err(GatewayError::Unauthenticated);
        }
        Ok(GatewaySession {
            principal,
            identity_path: mapping.identity_path.clone(),
            profile_name: profile.profile_name.clone(),
            profile_rev: profile.revision,
        })
    }

    fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError> {
        GatewayRuntime::describe(self, session)
    }

    async fn submit(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        submission::submit(self, session, submission).await
    }

    async fn submit_output_stream(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
        window: StreamWindow,
    ) -> Result<GatewayOutputStream, GatewayError> {
        submission::submit_output_stream(self, session, submission, window).await
    }

    async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewayInputStreamStart, GatewayError> {
        GatewayRuntime::accept_input_stream_submission(self, session, submission).await
    }

    async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        GatewayRuntime::complete_input_stream_submission(self, stream, payload, provenance).await
    }

    async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        reason: &str,
    ) -> Result<(), GatewayError> {
        GatewayRuntime::fail_input_stream_submission(self, stream, reason).await
    }

    fn cancel(
        &self,
        session: &GatewaySession,
        request: GatewayCancelRequest,
    ) -> Result<bool, GatewayError> {
        self.requests.cancel(session, &request, &self.boot)
    }

    async fn issue_object_upload_ticket(
        &self,
        session: &GatewaySession,
        request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError> {
        self.issue_upload_ticket(session, request).await
    }

    async fn begin_object_upload(
        &self,
        session: &GatewaySession,
        request: BeginObjectUploadRequest,
    ) -> Result<GatewayObjectUpload, GatewayError> {
        self.begin_upload(session, request).await
    }

    async fn open_object_read(
        &self,
        session: &GatewaySession,
        request: OpenObjectReadRequest,
    ) -> Result<GatewayObjectDownload, GatewayError> {
        self.open_read(session, request).await
    }

    fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String> {
        self.boot
            .record_gateway_audit(audit)
            .map_err(|e| e.to_string())
    }
}

fn parse_identity_path(identity: &str) -> Result<Path, GatewayError> {
    let path = Path::parse(identity)
        .map_err(|e| GatewayError::InvalidProfile(format!("invalid identity path: {e}")))?;
    if path.scheme() != "process" {
        return Err(GatewayError::InvalidProfile(
            "identity path must use the process:// scheme".into(),
        ));
    }
    if path.segments().is_empty() {
        return Err(GatewayError::InvalidProfile(
            "identity path must include at least one segment".into(),
        ));
    }
    Ok(path)
}

fn surface_method_bitmap(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<MethodBitmap, GatewayError> {
    let resource_id = boot
        .kernel
        .registry
        .resolve_resource(target)
        .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
    let Some(resource) = boot.kernel.registry.resource(resource_id) else {
        return Err(GatewayError::InvalidProfile("resource missing".into()));
    };
    let mut methods = MethodBitmap::empty();
    for interface in &resource.interfaces.interfaces {
        if let Some((index, _)) = boot.kernel.registry.method_index(*interface, method) {
            methods |= MethodBitmap::method(index);
        }
    }
    if methods.is_empty() {
        return Err(GatewayError::InvalidProfile("method missing".into()));
    }
    Ok(methods)
}

fn operation_replay_class(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<ReplayClass, GatewayError> {
    Ok(operation_method_metadata(boot, target, method)?.replay)
}

#[derive(Clone, Copy, Debug)]
struct GatewayMethodMetadata {
    replay: ReplayClass,
    cost: CostModel,
    batchable: bool,
}

fn operation_method_metadata(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<GatewayMethodMetadata, GatewayError> {
    let resource_id = boot
        .kernel
        .registry
        .resolve_resource(target)
        .map_err(|e| GatewayError::Rejected(e.to_string()))?;
    let Some(resource) = boot.kernel.registry.resource(resource_id) else {
        return Err(GatewayError::Rejected(format!(
            "operation target {} is unavailable",
            target.path()
        )));
    };
    for interface_id in &resource.interfaces.interfaces {
        let Some(interface) = boot.kernel.registry.interface(*interface_id) else {
            continue;
        };
        if let Some((_, method)) = interface.method_index(method) {
            return Ok(GatewayMethodMetadata {
                replay: method.replay,
                cost: method.cost,
                batchable: method.batchable,
            });
        }
    }
    Err(GatewayError::Rejected(format!(
        "operation method {} is unavailable on {}",
        method,
        target.path()
    )))
}

fn estimate_gateway_operation_cost(
    cost: &CostModel,
    batchable: bool,
    input: Option<&Value>,
) -> u64 {
    let Some(input) = input else {
        return cost.estimate_micro_usd(1, 1);
    };
    let in_tokens = input.approx_tokens();
    let out_tokens = in_tokens;
    match (batchable, input.view()) {
        (true, ValueView::List(items)) => {
            let flat = cost.flat_micro_usd.saturating_mul(items.len() as u64);
            let variable = CostModel {
                flat_micro_usd: 0,
                ..*cost
            }
            .estimate_micro_usd(in_tokens, out_tokens);
            flat.saturating_add(variable)
        }
        _ => cost.estimate_micro_usd(in_tokens, out_tokens),
    }
}

async fn lower_submission<'profile>(
    submission: GatewaySubmission,
    profile: &'profile CompiledGatewayProfile,
    runtime: &GatewayRuntime,
    session: &GatewaySession,
) -> Result<LoweredSubmission<'profile>, GatewayError> {
    match submission.body {
        GatewaySubmissionBody::DirectInput(input) => {
            if submission.surface_id.trim().is_empty() {
                return Err(GatewayError::Rejected(
                    "direct input requires a surface_id".into(),
                ));
            }
            let surface = profile
                .surface_by_id(&submission.surface_id)
                .ok_or_else(|| {
                    GatewayError::Rejected(format!(
                        "unknown gateway surface {}",
                        submission.surface_id
                    ))
                })?;
            if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
                return Err(GatewayError::Rejected(format!(
                    "surface {} is not callable by principal",
                    surface.surface_id
                )));
            }
            if value_any(&input.payload, |value| {
                matches!(value.view(), ValueView::StreamEnd(_))
            }) {
                return Err(GatewayError::Rejected(
                    "direct input cannot be StreamEnd".into(),
                ));
            }
            validate_surface_input(surface, &input.payload)?;
            validate_inline_value_bytes(&input.payload, &profile.limits, "direct input")?;
            let objects = runtime
                .admit_input_objects(
                    &input.payload,
                    input.provenance.as_ref(),
                    session,
                    surface,
                    submission.options.submission_token.as_deref(),
                )
                .await?;
            Ok(LoweredSubmission {
                program: DoNode::op(OperationTemplate {
                    target: surface.target.clone(),
                    method: GATEWAY_EFFECT_METHOD.into(),
                    method_id: None,
                    output: submission.requested_output,
                    literal_input: Some(input.payload),
                }),
                surface,
                objects,
            })
        }
        GatewaySubmissionBody::InputStream(open) => {
            if open.stream_id.trim().is_empty() {
                return Err(GatewayError::Rejected(
                    "stream_open requires a stream_id".into(),
                ));
            }
            Err(GatewayError::Rejected(
                "stream input must be completed by a streaming transport before dispatch".into(),
            ))
        }
    }
}

fn validate_input_stream_open_request<'a>(
    profile: &'a CompiledGatewayProfile,
    session: &GatewaySession,
    surface_id: &str,
    open: &GatewayStreamOpenRequest,
) -> Result<&'a CompiledSurfaceDescriptor, GatewayError> {
    if surface_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream input requires a surface_id".into(),
        ));
    }
    if open.stream_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream_open requires a stream_id".into(),
        ));
    }
    if open.direction != GatewayStreamDirection::ClientToKernel {
        return Err(GatewayError::Rejected(
            "stream input requires CLIENT_TO_KERNEL direction".into(),
        ));
    }
    if open.modality == GatewayModality::Control {
        return Err(GatewayError::Rejected(
            "CONTROL modality cannot be submitted as operation input".into(),
        ));
    }
    if !open.item_schema_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream item schema is selected by the gateway profile".into(),
        ));
    }
    if open.max_inline_item_bytes == 0 {
        return Err(GatewayError::Rejected(
            "stream_open max_inline_item_bytes must be non-zero".into(),
        ));
    }
    let profile_max_inline_item_bytes =
        u64::try_from(profile.limits.max_stream_inline_item_bytes).unwrap_or(u64::MAX);
    if open.max_inline_item_bytes > profile_max_inline_item_bytes {
        return Err(GatewayError::Rejected(format!(
            "stream_open max_inline_item_bytes exceeds max_stream_inline_item_bytes ({})",
            profile.limits.max_stream_inline_item_bytes
        )));
    }
    let profile_max_items = u64::try_from(profile.limits.max_stream_items).unwrap_or(u64::MAX);
    if let Some(max_items) = open.max_items {
        if max_items == 0 {
            return Err(GatewayError::Rejected(
                "stream_open max_items must be non-zero".into(),
            ));
        }
        if max_items > profile_max_items {
            return Err(GatewayError::Rejected(format!(
                "stream_open max_items exceeds max_stream_items ({})",
                profile.limits.max_stream_items
            )));
        }
    }
    let profile_max_bytes = u64::try_from(profile.limits.max_stream_bytes).unwrap_or(u64::MAX);
    if let Some(max_bytes) = open.max_bytes {
        if max_bytes == 0 {
            return Err(GatewayError::Rejected(
                "stream_open max_bytes must be non-zero".into(),
            ));
        }
        if max_bytes > profile_max_bytes {
            return Err(GatewayError::Rejected(format!(
                "stream_open max_bytes exceeds max_stream_bytes ({})",
                profile.limits.max_stream_bytes
            )));
        }
    }
    let surface = profile
        .surface_by_id(surface_id)
        .ok_or_else(|| GatewayError::Rejected(format!("unknown gateway surface {surface_id}")))?;
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(format!(
            "surface {} is not callable by principal",
            surface.surface_id
        )));
    }
    Ok(surface)
}

fn stream_open_admission_program(
    surface: &CompiledSurfaceDescriptor,
    requested_output: OutputMode,
) -> DoNode {
    DoNode::op(OperationTemplate {
        target: surface.target.clone(),
        method: GATEWAY_EFFECT_METHOD.into(),
        method_id: None,
        output: requested_output,
        literal_input: Some(Value::null()),
    })
}

struct LoweredSubmission<'profile> {
    program: DoNode,
    surface: &'profile CompiledSurfaceDescriptor,
    objects: object::ObjectAdmission,
}

fn request_deadline(options: &SubmitOptions) -> Result<Option<Instant>, GatewayError> {
    options
        .deadline_ms
        .map(|deadline| {
            let deadline = i64::try_from(deadline)
                .map_err(|_error| GatewayError::Rejected("deadline_ms is out of range".into()))?;
            let now = Instant::now();
            let remaining_ms = deadline.saturating_sub(now_millis()).max(0) as u64;
            now.checked_add(std::time::Duration::from_millis(remaining_ms))
                .ok_or_else(|| GatewayError::Rejected("deadline_ms is out of range".into()))
        })
        .transpose()
}

fn request_risk_class(admission: &LoweredSubmissionAdmission) -> String {
    if admission.requires_idempotency {
        "non_idempotent_effect".into()
    } else if admission.inspection.operation_count > 0 {
        "effect".into()
    } else if admission.inspection.wait_deadline_count > 0
        || admission.inspection.wait_signal_count > 0
    {
        "wait".into()
    } else {
        "inert".into()
    }
}

fn gateway_budget_charge_for_submit(
    admission: &LoweredSubmissionAdmission,
    options: &SubmitOptions,
    now_ms: i64,
) -> Result<GatewayBudgetCharge, GatewayError> {
    let literal_bytes = admission.inspection.literal_bytes as u64;
    Ok(GatewayBudgetCharge {
        inflight_ops: admission.inspection.operation_count as u64,
        wall_ms: request_wall_ms(options, now_ms)?,
        bytes_in: literal_bytes,
        bytes_out: 0,
        inline_value_bytes: literal_bytes,
        stream_items: 0,
        estimated_cost_micro_usd: admission.inspection.estimated_cost_micro_usd,
    })
}

fn gateway_budget_charge_for_stream_open(
    admission: &LoweredSubmissionAdmission,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    open: &GatewayStreamOpenRequest,
    limits: &GatewayLimitProfile,
    options: &SubmitOptions,
    now_ms: i64,
) -> Result<GatewayBudgetCharge, GatewayError> {
    let stream_items = open.max_items.unwrap_or(limits.max_stream_items as u64);
    let bytes_in = open.max_bytes.unwrap_or(limits.max_stream_bytes as u64);
    let declared_inline = stream_items.saturating_mul(open.max_inline_item_bytes);
    let estimated_cost_micro_usd =
        estimate_gateway_stream_cost(boot, surface, bytes_in, stream_items)?;
    Ok(GatewayBudgetCharge {
        inflight_ops: admission.inspection.operation_count as u64,
        wall_ms: request_wall_ms(options, now_ms)?,
        bytes_in,
        bytes_out: 0,
        inline_value_bytes: declared_inline.min(bytes_in),
        stream_items,
        estimated_cost_micro_usd,
    })
}

fn estimate_gateway_stream_cost(
    boot: &Bootstrap,
    surface: &CompiledSurfaceDescriptor,
    bytes_in: u64,
    stream_items: u64,
) -> Result<u64, GatewayError> {
    let metadata = operation_method_metadata(boot, &surface.target, GATEWAY_EFFECT_METHOD)?;
    let in_tokens = (bytes_in / 4).max(1);
    let out_tokens = in_tokens;
    if metadata.batchable {
        let flat = metadata
            .cost
            .flat_micro_usd
            .saturating_mul(stream_items.max(1));
        let variable = CostModel {
            flat_micro_usd: 0,
            ..metadata.cost
        }
        .estimate_micro_usd(in_tokens, out_tokens);
        return Ok(flat.saturating_add(variable));
    }
    Ok(metadata.cost.estimate_micro_usd(in_tokens, out_tokens))
}

fn request_wall_ms(options: &SubmitOptions, now_ms: i64) -> Result<u64, GatewayError> {
    let Some(deadline) = options.deadline_ms else {
        return Ok(0);
    };
    let deadline = i64::try_from(deadline)
        .map_err(|_error| GatewayError::Rejected("deadline_ms is out of range".into()))?;
    Ok(deadline.saturating_sub(now_ms) as u64)
}

fn lowered_large_value_ref_summaries(program: &DoNode) -> Vec<GatewayLargeValueRefSummary> {
    let mut summaries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![program];
    while let Some(node) = stack.pop() {
        match node {
            DoNode::Pure(value) => push_large_value_summaries(value, &mut seen, &mut summaries),
            DoNode::AndThen { d, then } => {
                if let Some(arg) = &then.arg {
                    push_large_value_summaries(arg, &mut seen, &mut summaries);
                }
                stack.push(d);
            }
            DoNode::OrElse { d, or } => {
                if let Some(arg) = &or.arg {
                    push_large_value_summaries(arg, &mut seen, &mut summaries);
                }
                stack.push(d);
            }
            DoNode::Both(left, right) | DoNode::Race(left, right) => {
                stack.push(left);
                stack.push(right);
            }
            DoNode::Let { value, body, .. } => {
                stack.push(value);
                stack.push(body);
            }
            DoNode::Acting { body, .. } => stack.push(body),
            DoNode::Op(tmpl) => {
                if let Some(input) = &tmpl.literal_input {
                    push_large_value_summaries(input, &mut seen, &mut summaries);
                }
            }
            DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) => {}
        }
    }
    summaries
}

fn push_large_value_summaries(
    value: &Value,
    seen: &mut BTreeSet<(String, u64, Option<String>)>,
    summaries: &mut Vec<GatewayLargeValueRefSummary>,
) {
    for blob in collect_large_value_refs(value) {
        let key = (blob.hash.clone(), blob.size, blob.mime.clone());
        if seen.insert(key.clone()) {
            summaries.push(GatewayLargeValueRefSummary {
                hash: key.0,
                size: key.1,
                mime: key.2,
            });
        }
    }
}

fn validate_submit_options(
    options: &SubmitOptions,
    limits: &GatewayLimitProfile,
    now_ms: i64,
) -> Result<(), GatewayError> {
    if let Some(key) = normalize_optional_string(options.idempotency_key.clone()) {
        validate_idempotency_key(&key)?;
    }
    if let Some(token) = normalize_optional_string(options.submission_token.clone()) {
        validate_submission_token(&token)?;
    }
    if let Some(deadline_ms) = options.deadline_ms {
        let deadline_ms = i64::try_from(deadline_ms)
            .map_err(|_error| GatewayError::Rejected("deadline_ms is out of range".into()))?;
        if deadline_ms <= now_ms {
            return Err(GatewayError::Rejected(
                "deadline_ms has already expired".into(),
            ));
        }
        if deadline_ms.saturating_sub(now_ms) > limits.max_deadline_ms_from_now {
            return Err(GatewayError::Rejected(format!(
                "deadline_ms exceeds max_deadline_ms_from_now ({})",
                limits.max_deadline_ms_from_now
            )));
        }
    }
    Ok(())
}

fn validate_current_session(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
) -> Result<(), GatewayError> {
    if session.profile_name != profile.profile_name || session.profile_rev != profile.revision {
        return Err(GatewayError::Rejected(
            "gateway session was issued by a different profile snapshot".into(),
        ));
    }
    profile.session_identity_path(session)?;
    Ok(())
}

fn validate_submission_token(token: &str) -> Result<(), GatewayError> {
    let ok = !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid submission token".into()))
    }
}

fn validate_idempotency_key(key: &str) -> Result<(), GatewayError> {
    let ok = !key.is_empty()
        && key.len() <= 256
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid idempotency key".into()))
    }
}

fn validate_content_hash(hash: &str) -> Result<(), GatewayError> {
    let ok = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "large object reference hash must be lowercase hex blake3".into(),
        ))
    }
}

fn state_path(segments: &[&str]) -> Result<Path, xolotl_types::PathError> {
    let mut path = Path::try_new("state")?;
    for segment in segments {
        path = path.try_push_literal(segment)?;
    }
    Ok(path)
}

fn random_gateway_id(prefix: &str, profile_rev: GatewayProfileRev) -> Result<String, GatewayError> {
    let mut bytes = [0u8; GATEWAY_REQUEST_ID_RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| GatewayError::Rejected(format!("gateway request entropy failed: {e}")))?;
    let mut id = String::with_capacity(prefix.len() + 1 + 20 + 1 + bytes.len() * 2);
    id.push_str(prefix);
    id.push('-');
    id.push_str(&profile_rev.to_string());
    id.push('-');
    for byte in bytes {
        push_hex_byte(&mut id, byte);
    }
    Ok(id)
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn required_str<'a>(map: &'a ValueMap, key: &'static str) -> Result<&'a str, GatewayError> {
    optional_str(map, key)
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

fn optional_str<'a>(map: &'a ValueMap, key: &'static str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn required_i64(map: &ValueMap, key: &'static str) -> Result<i64, GatewayError> {
    map.get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

impl GatewayModality {
    fn as_str(self) -> &'static str {
        match self {
            GatewayModality::Value => "value",
            GatewayModality::Text => "text",
            GatewayModality::Bytes => "bytes",
            GatewayModality::Tensor => "tensor",
            GatewayModality::AudioFrame => "audio_frame",
            GatewayModality::VideoFrame => "video_frame",
            GatewayModality::PoseFrame => "pose_frame",
            GatewayModality::SensorFrame => "sensor_frame",
            GatewayModality::Event => "event",
            GatewayModality::Control => "control",
        }
    }
}

impl GatewayStreamDirection {
    fn as_str(self) -> &'static str {
        match self {
            GatewayStreamDirection::ClientToKernel => "client_to_kernel",
            GatewayStreamDirection::KernelToClient => "kernel_to_client",
            GatewayStreamDirection::StateSubscriptionToClient => "state_subscription_to_client",
        }
    }
}

fn value_any(value: &Value, pred: impl Fn(&Value) -> bool) -> bool {
    use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
    if !matches!(value.view(), ValueView::List(_) | ValueView::Map(_)) {
        return pred(value);
    }
    let mut visited = BTreeSet::new();
    let mut walk = ValuePostorder::new(value);
    while let Some(node) = walk.next(|key| visited.contains(&key)) {
        if pred(node) {
            return true;
        }
        visited.insert(ValueNodeKey::of(node));
    }
    false
}

fn inspect_lowered_submission(
    program: &DoNode,
    profile: &CompiledGatewayProfile,
    principal_id: &str,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    validate_input_schema: bool,
) -> Result<LoweredSubmissionAdmission, GatewayError> {
    if !profile.principal_can_submit(principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(format!(
            "surface {} is not callable by principal",
            surface.surface_id
        )));
    }
    let limits = &profile.limits;
    let mut admission = LoweredSubmissionAdmission::default();
    let mut stack = vec![(program, 1usize)];
    while let Some((node, depth)) = stack.pop() {
        admission.inspection.node_count = admission.inspection.node_count.saturating_add(1);
        if admission.inspection.node_count > MAX_LOWERED_SUBMISSION_NODES {
            return Err(GatewayError::Rejected(format!(
                "lowered submission exceeds node limit ({})",
                MAX_LOWERED_SUBMISSION_NODES
            )));
        }
        admission.inspection.max_depth = admission.inspection.max_depth.max(depth);
        if depth > MAX_LOWERED_SUBMISSION_DEPTH {
            return Err(GatewayError::Rejected(format!(
                "lowered submission exceeds depth limit ({})",
                MAX_LOWERED_SUBMISSION_DEPTH
            )));
        }

        match node {
            DoNode::Pure(value) => add_value_bytes(&mut admission.inspection, value, limits)?,
            DoNode::AndThen { d, .. } => {
                inspect_step_ref(&mut admission.inspection)?;
                stack.push((d, depth.saturating_add(1)));
            }
            DoNode::OrElse { d, .. } => {
                inspect_step_ref(&mut admission.inspection)?;
                stack.push((d, depth.saturating_add(1)));
            }
            DoNode::Both(a, b) | DoNode::Race(a, b) => {
                stack.push((a, depth.saturating_add(1)));
                stack.push((b, depth.saturating_add(1)));
            }
            DoNode::Let { name, value, body } => {
                add_literal_bytes(&mut admission.inspection, name.len(), limits)?;
                stack.push((value, depth.saturating_add(1)));
                stack.push((body, depth.saturating_add(1)));
            }
            DoNode::Use(name) => {
                add_literal_bytes(&mut admission.inspection, name.len(), limits)?;
            }
            DoNode::Acting { .. } => {
                return Err(GatewayError::Rejected(
                    "lowered submissions cannot contain Acting".into(),
                ));
            }
            DoNode::Fail(failure) => {
                add_literal_bytes(
                    &mut admission.inspection,
                    failure_literal_bytes(failure),
                    limits,
                )?;
            }
            DoNode::Wait(spec) => inspect_wait(&mut admission.inspection, spec)?,
            DoNode::Op(tmpl) => inspect_operation(
                &mut admission,
                tmpl,
                surface,
                boot,
                limits,
                validate_input_schema,
            )?,
        }
    }
    Ok(admission)
}

#[derive(Default)]
struct LoweredSubmissionAdmission {
    inspection: LoweredSubmissionInspection,
    requires_idempotency: bool,
}

fn inspect_step_ref(inspection: &mut LoweredSubmissionInspection) -> Result<(), GatewayError> {
    inspection.step_ref_count = inspection.step_ref_count.saturating_add(1);
    Err(GatewayError::Rejected(
        "lowered submissions cannot contain StepRef".into(),
    ))
}

fn inspect_wait(
    inspection: &mut LoweredSubmissionInspection,
    spec: &WaitSpec,
) -> Result<(), GatewayError> {
    match spec {
        WaitSpec::Signal(_) => {
            inspection.wait_signal_count = inspection.wait_signal_count.saturating_add(1);
            Err(GatewayError::Rejected(
                "lowered submissions cannot contain Wait(Signal)".into(),
            ))
        }
        WaitSpec::Deadline(_) => {
            inspection.wait_deadline_count = inspection.wait_deadline_count.saturating_add(1);
            Err(GatewayError::Rejected(
                "lowered submissions cannot contain Wait(Deadline)".into(),
            ))
        }
    }
}

fn inspect_operation(
    admission: &mut LoweredSubmissionAdmission,
    tmpl: &OperationTemplate,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    limits: &GatewayLimitProfile,
    validate_input_schema: bool,
) -> Result<(), GatewayError> {
    admission.inspection.operation_count = admission.inspection.operation_count.saturating_add(1);
    if tmpl.target != surface.target || tmpl.method != GATEWAY_EFFECT_METHOD {
        return Err(GatewayError::Rejected(format!(
            "operation {}.{} does not match selected surface {}",
            tmpl.target.path(),
            tmpl.method,
            surface.surface_id,
        )));
    }
    let metadata = operation_method_metadata(boot, &surface.target, GATEWAY_EFFECT_METHOD)?;
    if matches!(metadata.replay, ReplayClass::NonIdempotentEffect) {
        admission.requires_idempotency = true;
    }
    admission.inspection.estimated_cost_micro_usd = admission
        .inspection
        .estimated_cost_micro_usd
        .saturating_add(estimate_gateway_operation_cost(
            &metadata.cost,
            metadata.batchable,
            tmpl.literal_input.as_ref(),
        ));
    if validate_input_schema && let Some(input) = &tmpl.literal_input {
        validate_surface_input(surface, input)?;
    }
    if let OutputMode::Collect { limit } = tmpl.output
        && limit > limits.max_collect_limit
    {
        return Err(GatewayError::Rejected(format!(
            "collect limit exceeds max_collect_limit ({})",
            limits.max_collect_limit
        )));
    }
    if let Some(input) = &tmpl.literal_input {
        add_value_bytes(&mut admission.inspection, input, limits)?;
    }
    Ok(())
}

fn add_value_bytes(
    inspection: &mut LoweredSubmissionInspection,
    value: &Value,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    add_value_bytes_with_label(inspection, value, limits, "submission")
}

fn validate_inline_value_bytes(
    value: &Value,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    let mut inspection = LoweredSubmissionInspection::default();
    add_value_bytes_with_label(&mut inspection, value, limits, label)
}

fn add_value_bytes_with_label(
    inspection: &mut LoweredSubmissionInspection,
    value: &Value,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    let remaining = limits
        .max_literal_bytes
        .saturating_sub(inspection.literal_bytes);
    let bytes = value_inspection::inline_bytes(value, remaining).ok_or_else(|| {
        GatewayError::Rejected(format!(
            "{label} exceeds max_literal_bytes ({})",
            limits.max_literal_bytes
        ))
    })?;
    add_literal_bytes_with_label(inspection, bytes, limits, label)
}

fn add_literal_bytes(
    inspection: &mut LoweredSubmissionInspection,
    bytes: usize,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    add_literal_bytes_with_label(inspection, bytes, limits, "submission")
}

fn add_literal_bytes_with_label(
    inspection: &mut LoweredSubmissionInspection,
    bytes: usize,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    inspection.literal_bytes = inspection.literal_bytes.saturating_add(bytes);
    if inspection.literal_bytes > limits.max_literal_bytes {
        return Err(GatewayError::Rejected(format!(
            "{label} exceeds max_literal_bytes ({})",
            limits.max_literal_bytes
        )));
    }
    Ok(())
}

fn failure_literal_bytes(failure: &Failure) -> usize {
    failure.to_string().len()
}

fn now_millis() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(now) => i64::try_from(now.as_millis()).unwrap_or(i64::MAX),
        Err(error) => {
            let before_epoch = i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX);
            before_epoch.saturating_neg()
        }
    }
}

#[cfg(test)]
mod tests;
