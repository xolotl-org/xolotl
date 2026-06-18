use crate::{
    DEFAULT_BUDGET_MAX_BYTES_IN, DEFAULT_BUDGET_MAX_INFLIGHT_OPS,
    DEFAULT_BUDGET_MAX_INLINE_VALUE_BYTES, DEFAULT_BUDGET_MAX_STREAM_ITEMS,
    DEFAULT_MAX_COLLECT_LIMIT, DEFAULT_MAX_DEADLINE_MS_FROM_NOW, DEFAULT_MAX_IN_FLIGHT_REQUESTS,
    DEFAULT_MAX_LITERAL_BYTES, DEFAULT_MAX_PRINCIPAL_IN_FLIGHT_REQUESTS,
    DEFAULT_MAX_RISK_CLASS_IN_FLIGHT_REQUESTS, DEFAULT_MAX_STREAM_BYTES,
    DEFAULT_MAX_STREAM_INLINE_ITEM_BYTES, DEFAULT_MAX_STREAM_ITEMS,
    DEFAULT_MAX_SURFACE_IN_FLIGHT_REQUESTS, GatewayAllowedHost, GatewayAllowedOrigin,
    GatewayCredential, GatewayError, GatewayGeneration, GatewayIdentityMapping, GatewayProfileRev,
};
use nexus_types::{Path, ProcessId, ResourceName, Value};
use std::collections::BTreeMap;

/// One resource surface exposed by a gateway profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySurface {
    /// Stable surface id within the profile.
    pub(crate) surface_id: String,
    /// Resource target exposed through this surface.
    pub(crate) target: ResourceName,
    /// Capability literal required before this surface may be published.
    pub(crate) publish_capability: Option<String>,
    /// Input schema descriptor advertised for this surface.
    pub(crate) input_schema: Option<Value>,
    /// Output schema descriptor advertised for this surface.
    pub(crate) output_schema: Option<Value>,
}

/// A protocol-level publication of one Gateway surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPublication {
    /// Protocol adapter that may publish this surface.
    pub(crate) protocol: String,
    /// Protocol object kind inside the adapter.
    pub(crate) kind: String,
    /// Protocol-visible stable name.
    pub(crate) name: String,
    /// Protocol-visible address when it is distinct from `name`.
    pub(crate) address: Option<String>,
    /// Surface id published by this protocol entry.
    pub(crate) surface_id: String,
    /// Optional protocol display title.
    pub(crate) title: Option<String>,
    /// Optional human-readable protocol description.
    pub(crate) description: Option<String>,
    /// Optional protocol-specific properties.
    pub(crate) properties: BTreeMap<String, Value>,
    /// Optional protocol annotations.
    pub(crate) annotations: Option<Value>,
    /// Optional protocol metadata.
    pub(crate) metadata: Option<Value>,
    /// Whether this publication is visible to protocol discovery.
    pub(crate) enabled: bool,
}

impl GatewayPublication {
    /// Create a protocol publication for a Gateway surface.
    pub fn new(
        protocol: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
        surface_id: impl Into<String>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            kind: kind.into(),
            name: name.into(),
            address: None,
            surface_id: surface_id.into(),
            title: None,
            description: None,
            properties: BTreeMap::new(),
            annotations: None,
            metadata: None,
            enabled: true,
        }
    }

    /// Attach a protocol address.
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Attach a protocol display title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Attach a protocol description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Attach one protocol-specific property.
    pub fn with_property(mut self, name: impl Into<String>, value: Value) -> Self {
        self.properties.insert(name.into(), value);
        self
    }

    /// Attach protocol annotations.
    pub fn with_annotations(mut self, annotations: Value) -> Self {
        self.annotations = Some(annotations);
        self
    }

    /// Attach protocol metadata.
    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Disable this publication without removing it from the host profile.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl GatewaySurface {
    /// Expose one effect path through its standard `invoke` method.
    pub fn effect_invoke(surface_id: impl Into<String>, target: ResourceName) -> Self {
        Self {
            surface_id: surface_id.into(),
            target,
            publish_capability: None,
            input_schema: None,
            output_schema: None,
        }
    }

    /// Set the publishing capability for protocol directories.
    pub fn with_publish_capability(mut self, publish_capability: impl Into<String>) -> Self {
        self.publish_capability = Some(publish_capability.into());
        self
    }

    /// Attach optional input and output schema descriptors.
    pub fn with_schema(
        mut self,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
    ) -> Self {
        self.input_schema = input_schema;
        self.output_schema = output_schema;
        self
    }
}

pub(crate) fn perform_capability_for_effect(path: &Path) -> String {
    let mut capability = String::from("perform://effect");
    for segment in path.segments() {
        capability.push('/');
        capability.push_str(segment);
    }
    capability
}

/// Surfaces a principal can see and submit through.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPrincipalSurfaceBinding {
    /// Authenticated principal id.
    pub(crate) principal_id: String,
    /// Surfaces returned by authenticated discovery for this principal.
    pub(crate) visible_surfaces: Vec<String>,
    /// Surfaces this principal may submit through.
    pub(crate) submit_surfaces: Vec<String>,
    /// Capability ceiling for submissions admitted through this binding.
    pub(crate) capability_ceiling: Vec<String>,
}

impl GatewayPrincipalSurfaceBinding {
    /// Bind a principal to explicit visible and callable surface ids.
    pub fn new(
        principal_id: impl Into<String>,
        visible_surfaces: impl IntoIterator<Item = impl Into<String>>,
        submit_surfaces: impl IntoIterator<Item = impl Into<String>>,
        capability_ceiling: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            principal_id: principal_id.into(),
            visible_surfaces: visible_surfaces.into_iter().map(Into::into).collect(),
            submit_surfaces: submit_surfaces.into_iter().map(Into::into).collect(),
            capability_ceiling: capability_ceiling.into_iter().map(Into::into).collect(),
        }
    }

    /// Bind a principal to the same visible and callable surface ids.
    pub fn allow(
        principal_id: impl Into<String>,
        surface_ids: impl IntoIterator<Item = impl Into<String>>,
        capability_ceiling: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let surface_ids: Vec<String> = surface_ids.into_iter().map(Into::into).collect();
        Self {
            principal_id: principal_id.into(),
            visible_surfaces: surface_ids.clone(),
            submit_surfaces: surface_ids,
            capability_ceiling: capability_ceiling.into_iter().map(Into::into).collect(),
        }
    }
}

/// Request limits applied before a request Process runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayLimitProfile {
    /// Maximum inline literal bytes in one lowered submission.
    pub max_literal_bytes: usize,
    /// Maximum `OutputMode::Collect` limit.
    pub max_collect_limit: usize,
    /// Maximum future deadline accepted for request deadlines and tickets.
    pub max_deadline_ms_from_now: i64,
    /// Maximum concurrently executing submissions for this runtime.
    pub max_in_flight_requests: usize,
    /// Maximum concurrently executing submissions for one principal.
    pub max_principal_in_flight_requests: usize,
    /// Maximum concurrently executing submissions for one surface.
    pub max_surface_in_flight_requests: usize,
    /// Maximum concurrently executing submissions for one risk class.
    pub max_risk_class_in_flight_requests: usize,
    /// Aggregate request budget reserved before request Process creation.
    pub budget: GatewayBudgetProfile,
    /// Maximum items accepted in one client-to-kernel input stream.
    pub max_stream_items: usize,
    /// Maximum folded inline bytes accepted in one client-to-kernel input stream.
    pub max_stream_bytes: usize,
    /// Maximum inline bytes accepted for one input stream item.
    pub max_stream_inline_item_bytes: usize,
}

impl Default for GatewayLimitProfile {
    fn default() -> Self {
        Self {
            max_literal_bytes: DEFAULT_MAX_LITERAL_BYTES,
            max_collect_limit: DEFAULT_MAX_COLLECT_LIMIT,
            max_deadline_ms_from_now: DEFAULT_MAX_DEADLINE_MS_FROM_NOW,
            max_in_flight_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            max_principal_in_flight_requests: DEFAULT_MAX_PRINCIPAL_IN_FLIGHT_REQUESTS,
            max_surface_in_flight_requests: DEFAULT_MAX_SURFACE_IN_FLIGHT_REQUESTS,
            max_risk_class_in_flight_requests: DEFAULT_MAX_RISK_CLASS_IN_FLIGHT_REQUESTS,
            budget: GatewayBudgetProfile::default(),
            max_stream_items: DEFAULT_MAX_STREAM_ITEMS,
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
            max_stream_inline_item_bytes: DEFAULT_MAX_STREAM_INLINE_ITEM_BYTES,
        }
    }
}

/// Aggregate request budget reserved during Gateway admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayBudgetProfile {
    /// Maximum outstanding operation leaves admitted across running requests.
    pub max_inflight_ops: Option<u64>,
    /// Maximum outstanding requested wall-clock milliseconds.
    pub max_wall_ms: Option<u64>,
    /// Maximum outstanding ingress bytes estimated from payload metadata.
    pub max_bytes_in: Option<u64>,
    /// Maximum outstanding egress bytes when a protocol can estimate them.
    pub max_bytes_out: Option<u64>,
    /// Maximum outstanding inline `Value` bytes.
    pub max_inline_value_bytes: Option<u64>,
    /// Maximum outstanding admitted client-to-kernel stream items.
    pub max_stream_items: Option<u64>,
    /// Maximum outstanding estimated method cost in micro-USD.
    pub max_estimated_cost_micro_usd: Option<u64>,
}

impl Default for GatewayBudgetProfile {
    fn default() -> Self {
        Self {
            max_inflight_ops: Some(DEFAULT_BUDGET_MAX_INFLIGHT_OPS),
            max_wall_ms: None,
            max_bytes_in: Some(DEFAULT_BUDGET_MAX_BYTES_IN),
            max_bytes_out: None,
            max_inline_value_bytes: Some(DEFAULT_BUDGET_MAX_INLINE_VALUE_BYTES),
            max_stream_items: Some(DEFAULT_BUDGET_MAX_STREAM_ITEMS),
            max_estimated_cost_micro_usd: None,
        }
    }
}

/// Gateway profile loaded by the host. Profiles are explicit: credentials,
/// identity mapping, exposed surfaces, and request limits all live here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProfile {
    /// Stable profile name.
    pub(crate) profile_name: String,
    /// Host-assigned profile revision.
    pub(crate) revision: GatewayProfileRev,
    /// Accepted credentials.
    pub(crate) credentials: Vec<GatewayCredential>,
    /// Credentials with generation less than or equal to this floor are revoked.
    pub(crate) credential_revocation_floor: GatewayGeneration,
    /// Principal-to-Nexus identity mappings.
    pub(crate) identity_mappings: Vec<GatewayIdentityMapping>,
    /// Resource surfaces exposed to gateway submissions.
    pub(crate) surfaces: Vec<GatewaySurface>,
    /// Protocol publications for exposed surfaces.
    pub(crate) publications: Vec<GatewayPublication>,
    /// Process whose grants bound request Process grants. `None` uses the
    /// kernel root Process.
    pub(crate) authority_anchor: Option<ProcessId>,
    /// Principal-scoped visible/callable surface bindings.
    pub(crate) principal_surface_bindings: Vec<GatewayPrincipalSurfaceBinding>,
    /// Host/SNI authorities allowed to select this gateway listener profile.
    pub(crate) registered_hosts: Vec<GatewayAllowedHost>,
    /// Browser origins allowed to initiate browser-capable transports.
    pub(crate) registered_origins: Vec<GatewayAllowedOrigin>,
    /// Admission and resource limits.
    pub(crate) limits: GatewayLimitProfile,
}

impl GatewayProfile {
    /// Create an empty profile. Without credentials it authenticates nobody;
    /// without surfaces it exposes no callable submission path.
    pub fn new(profile_name: impl Into<String>) -> Self {
        Self {
            profile_name: profile_name.into(),
            revision: 1,
            credentials: Vec::new(),
            credential_revocation_floor: 0,
            identity_mappings: Vec::new(),
            surfaces: Vec::new(),
            publications: Vec::new(),
            authority_anchor: None,
            principal_surface_bindings: Vec::new(),
            registered_hosts: Vec::new(),
            registered_origins: Vec::new(),
            limits: GatewayLimitProfile::default(),
        }
    }

    /// Explicit closed profile for listeners that should start but reject all
    /// clients until deployment config supplies credentials and surfaces.
    pub fn closed(profile_name: impl Into<String>) -> Self {
        Self::new(profile_name)
    }

    /// Set the profile revision.
    pub fn with_revision(mut self, revision: GatewayProfileRev) -> Self {
        self.revision = revision;
        self
    }

    /// Set the credential revocation floor.
    pub fn with_credential_revocation_floor(mut self, floor: GatewayGeneration) -> Self {
        self.credential_revocation_floor = floor;
        self
    }

    /// Add an accepted credential.
    pub fn with_credential(mut self, credential: GatewayCredential) -> Self {
        self.credentials.push(credential);
        self
    }

    /// Add a principal-to-identity mapping.
    pub fn with_identity_mapping(mut self, mapping: GatewayIdentityMapping) -> Self {
        self.identity_mappings.push(mapping);
        self
    }

    /// Add a bearer token and identity mapping in one call.
    pub fn with_bearer_identity(
        self,
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        token: &str,
        identity_path: impl Into<String>,
    ) -> Result<Self, GatewayError> {
        let principal_id = principal_id.into();
        Ok(self
            .with_credential(GatewayCredential::bearer_token(
                credential_id,
                principal_id.clone(),
                token,
            )?)
            .with_identity_mapping(GatewayIdentityMapping::new(principal_id, identity_path)))
    }

    /// Add an exposed surface.
    pub fn with_surface(mut self, surface: GatewaySurface) -> Self {
        self.surfaces.push(surface);
        self
    }

    /// Add a protocol publication for an exposed surface.
    pub fn with_publication(mut self, publication: GatewayPublication) -> Self {
        self.publications.push(publication);
        self
    }

    /// Use `anchor` as the parent authority for request Processes.
    pub fn with_authority_anchor(mut self, anchor: ProcessId) -> Self {
        self.authority_anchor = Some(anchor);
        self
    }

    /// Add a principal-to-surface binding.
    pub fn with_principal_surface_binding(
        mut self,
        binding: GatewayPrincipalSurfaceBinding,
    ) -> Self {
        self.principal_surface_bindings.push(binding);
        self
    }

    /// Register a gateway Host/SNI authority for this listener profile.
    pub fn with_registered_host(mut self, authority: &str) -> Result<Self, GatewayError> {
        self.registered_hosts
            .push(GatewayAllowedHost::parse(authority)?);
        Ok(self)
    }

    /// Register a browser origin for browser-capable transports.
    pub fn with_registered_origin(mut self, origin: &str) -> Result<Self, GatewayError> {
        self.registered_origins
            .push(GatewayAllowedOrigin::parse(origin)?);
        Ok(self)
    }

    /// Replace the limit profile.
    pub fn with_limits(mut self, limits: GatewayLimitProfile) -> Self {
        self.limits = limits;
        self
    }
}
