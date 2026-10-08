//! Compiled profile authority, surface lookup, and authenticated session binding.

use super::{
    GatewayBudgetProfile, GatewayLimitProfile, GatewayProfile, GatewayPublication, GatewaySurface,
    perform_capability_for_effect,
};
use crate::{
    BearerToken, BearerTokenHash, ClientCertificateCredential, ClientCertificateDerSha384,
    GATEWAY_EFFECT_HANDLE_VERB, GatewayAllowedHost, GatewayAllowedOrigin, GatewayAuthMethod,
    GatewayCredentialKind, GatewayError, GatewayGeneration, GatewayProfileRev,
    GatewayPublicationDescriptor, GatewaySession, VerifiedPrincipal, hash_bearer_token,
    parse_identity_path,
};
use crate::{
    object,
    schema::{CompiledValueSchema, compile_value_schema},
};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use xolotl_kernel::{CompiledRequestGrantTemplate, IdentityRegistry};
use xolotl_types::{
    Capability, IdentityRef, ProcessId, ResourceName, ResourceSelector, Value, ValueView,
};

#[derive(Clone, Debug)]
pub(crate) struct CompiledSurfaceDescriptor {
    pub(crate) request_binding_digest: [u8; 32],
    pub(crate) surface_id: String,
    pub(crate) target: ResourceName,
    pub(crate) grant_template: String,
    pub(crate) grant_capability: Capability,
    pub(crate) grant_selector: ResourceSelector,
    pub(crate) publish_capability: Option<String>,
    pub(crate) input_schema: Option<Value>,
    pub(crate) input_schema_validator: Option<CompiledValueSchema>,
    pub(crate) output_schema: Option<Value>,
    pub(crate) output_schema_validator: Option<CompiledValueSchema>,
    pub(crate) output_stream_schema: Option<Value>,
    pub(crate) output_stream_schema_validator: Option<CompiledValueSchema>,
}

#[derive(Clone, Debug)]
struct CompiledIdentityMapping {
    identity_path: String,
    identity_ref: Option<IdentityRef>,
    enabled: bool,
    generation: GatewayGeneration,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CompiledPrincipalSurfaceBinding {
    pub(crate) visible: BTreeSet<String>,
    pub(crate) submit: BTreeSet<String>,
    pub(crate) capability_ceiling: Vec<Capability>,
    pub(crate) request_grants_by_surface: BTreeMap<String, CompiledRequestGrantTemplate>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledGatewayProfile {
    pub(crate) profile_name: String,
    pub(crate) revision: GatewayProfileRev,
    pub(crate) credential_revocation_floor: GatewayGeneration,
    bearer_credentials: Vec<(BearerTokenHash, VerifiedPrincipal)>,
    client_certificate_credentials: Vec<(ClientCertificateDerSha384, VerifiedPrincipal)>,
    identity_by_principal: BTreeMap<String, CompiledIdentityMapping>,
    pub(crate) surfaces_by_id: BTreeMap<String, usize>,
    pub(crate) surface_bindings_by_principal: BTreeMap<String, CompiledPrincipalSurfaceBinding>,
    pub(crate) authority_anchor: Option<ProcessId>,
    pub(crate) surface_descriptors: Vec<CompiledSurfaceDescriptor>,
    pub(crate) publication_descriptors: Vec<GatewayPublicationDescriptor>,
    pub(crate) registered_hosts: Vec<GatewayAllowedHost>,
    pub(crate) registered_origins: Vec<GatewayAllowedOrigin>,
    pub(crate) limits: GatewayLimitProfile,
}

fn collect_binding_surface_ids(
    surfaces_by_id: &BTreeMap<String, usize>,
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
    /// Bind active profile identities before publishing the profile snapshot.
    /// Registration is outside request handling and commits before any process
    /// can retain the resulting compact identity number.
    pub(crate) fn bind_identities(
        &mut self,
        identities: &IdentityRegistry,
    ) -> Result<(), GatewayError> {
        for mapping in self.identity_by_principal.values_mut() {
            if !mapping.enabled {
                continue;
            }
            let path = parse_identity_path(&mapping.identity_path)?;
            mapping.identity_ref =
                Some(identities.resolve_or_register(&path).map_err(|error| {
                    GatewayError::Rejected(format!("identity directory: {error}"))
                })?);
        }
        Ok(())
    }

    pub(crate) fn compile(profile: GatewayProfile) -> Result<Self, GatewayError> {
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
            || profile.limits.max_ticket_objects == 0
            || profile.limits.max_ticket_objects > 4096
            || profile.limits.max_ticket_total_bytes == 0
            || profile.limits.max_ticket_total_bytes > i64::MAX as u64
            || profile.limits.max_ticket_record_bytes == 0
            || profile.limits.max_ticket_record_bytes > object::ticket_record_ceiling()
        {
            return Err(GatewayError::InvalidProfile(
                "in-flight, fair-queue, stream, or ticket limits are invalid".into(),
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
                        identity_ref: None,
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
                GatewayCredentialKind::ClientCertificate { der_sha384 } => {
                    let principal = VerifiedPrincipal {
                        principal_id: credential.principal_id,
                        credential_id: credential.credential_id,
                        credential_generation: credential.generation,
                        principal_generation: 0,
                        auth_method: GatewayAuthMethod::ClientCertificate,
                    };
                    if !client_certificate_hashes.insert(der_sha384.clone()) {
                        return Err(GatewayError::InvalidProfile(
                            "duplicate client certificate DER SHA-384".into(),
                        ));
                    }
                    if credential.enabled && credential.generation > credential_revocation_floor {
                        client_certificate_credentials.push((der_sha384, principal));
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
                request_binding_digest: crate::request_scope::surface_digest(&surface),
                surface_id: surface.surface_id.clone(),
                target: surface.target.clone(),
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
            surface_descriptors.push(descriptor);
        }
        let surfaces_by_id: BTreeMap<String, usize> = surface_descriptors
            .iter()
            .enumerate()
            .map(|(index, surface)| (surface.surface_id.clone(), index))
            .collect();

        let mut publication_keys = BTreeSet::new();
        let mut publication_descriptors = Vec::new();
        for publication in profile.publications {
            validate_publication_shape(&publication)?;
            let Some(&surface_index) = surfaces_by_id.get(&publication.surface_id) else {
                return Err(GatewayError::InvalidProfile(format!(
                    "publication {}:{}:{} references unknown surface {}",
                    publication.protocol,
                    publication.kind,
                    publication.name,
                    publication.surface_id
                )));
            };
            let surface = &surface_descriptors[surface_index];
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
                let Some(&surface_index) = surfaces_by_id.get(surface_id) else {
                    continue;
                };
                let surface = &surface_descriptors[surface_index];
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

    pub(crate) fn visible_surfaces_for_principal(
        &self,
        principal_id: &str,
    ) -> Option<&BTreeSet<String>> {
        self.surface_bindings_by_principal
            .get(principal_id)
            .map(|binding| &binding.visible)
    }

    pub(crate) fn principal_can_submit(&self, principal_id: &str, surface_id: &str) -> bool {
        self.surface_bindings_by_principal
            .get(principal_id)
            .is_some_and(|binding| binding.submit.contains(surface_id))
    }

    pub(crate) fn surface_by_id(&self, surface_id: &str) -> Option<&CompiledSurfaceDescriptor> {
        self.surface_descriptors
            .get(*self.surfaces_by_id.get(surface_id)?)
    }

    pub(crate) fn surface_descriptors_for_ids<'a>(
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

    pub(crate) fn verify_bearer(
        &self,
        token: &BearerToken,
    ) -> Result<VerifiedPrincipal, GatewayError> {
        if token.as_str().len() > crate::MAX_BEARER_TOKEN_BYTES {
            return Err(GatewayError::Unauthenticated);
        }
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

    pub(crate) fn verify_client_certificate(
        &self,
        credential: &ClientCertificateCredential,
    ) -> Result<VerifiedPrincipal, GatewayError> {
        let mut verified = None;
        for (stored_hash, principal) in &self.client_certificate_credentials {
            if stored_hash
                .0
                .as_bytes()
                .ct_eq(credential.der_sha384.0.as_bytes())
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

    pub(crate) fn has_authenticating_credentials(&self) -> bool {
        !self.bearer_credentials.is_empty() || !self.client_certificate_credentials.is_empty()
    }

    pub(crate) fn session_for_principal(
        &self,
        principal: VerifiedPrincipal,
    ) -> Result<GatewaySession, GatewayError> {
        let mapping = self
            .identity_by_principal
            .get(&principal.principal_id)
            .ok_or_else(|| GatewayError::Unauthorized(principal.principal_id.clone()))?;
        if !mapping.enabled || principal.principal_generation != mapping.generation {
            return Err(GatewayError::Unauthenticated);
        }
        Ok(GatewaySession {
            principal,
            identity_path: mapping.identity_path.clone(),
            profile_name: self.profile_name.clone(),
            profile_rev: self.revision,
        })
    }

    pub(crate) fn session_identity_path(
        &self,
        session: &GatewaySession,
    ) -> Result<&str, GatewayError> {
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

    pub(crate) fn session_identity_ref(
        &self,
        session: &GatewaySession,
    ) -> Result<IdentityRef, GatewayError> {
        self.session_identity_path(session)?;
        self.identity_by_principal
            .get(&session.principal.principal_id)
            .and_then(|mapping| mapping.identity_ref)
            .ok_or_else(|| GatewayError::Rejected("profile identity was not registered".into()))
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
