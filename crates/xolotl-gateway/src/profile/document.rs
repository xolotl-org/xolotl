//! Serializable configuration, separate from live credentials and runtime authority.

use super::{
    GatewayLimitProfile, GatewayPrincipalSurfaceBinding, GatewayProfile, GatewayPublication,
    GatewaySurface,
};
use crate::{
    BearerTokenHash, ClientCertificateDerSha256, CompiledGatewayProfile, GatewayCredential,
    GatewayError, GatewayGeneration, GatewayIdentityMapping, GatewayProfileRev,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use xolotl_types::{Path, ProcessId, ResourceName, Value};

/// State declaration at `state://kernel/gateway/profiles/<profile_name>`.
///
/// `version` is the Console config CAS revision and the installed Gateway
/// profile revision. Credential material contains hashes only. Deserialization
/// does not grant authority; admission validates the declaration and runtime
/// installation additionally resolves its resources and authority anchor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProfileDocument {
    profile_name: String,
    version: GatewayProfileRev,
    #[serde(default)]
    credentials: Vec<CredentialDocument>,
    #[serde(default)]
    credential_revocation_floor: GatewayGeneration,
    #[serde(default)]
    identity_mappings: Vec<IdentityDocument>,
    #[serde(default)]
    surfaces: Vec<SurfaceDocument>,
    #[serde(default)]
    publications: Vec<PublicationDocument>,
    #[serde(default)]
    authority_anchor: Option<ProcessId>,
    #[serde(default)]
    principal_surface_bindings: Vec<BindingDocument>,
    #[serde(default)]
    registered_hosts: Vec<String>,
    #[serde(default)]
    registered_origins: Vec<String>,
    #[serde(default)]
    limits: GatewayLimitProfile,
}

impl GatewayProfileDocument {
    /// Stable name used by the selected State path.
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Monotonic config revision installed as the Gateway profile revision.
    pub fn version(&self) -> GatewayProfileRev {
        self.version
    }

    /// Check path identity and all profile rules that do not need a live kernel.
    /// Resource registration and anchor grants are checked at runtime installation.
    pub fn validate_admission(&self, path_name: &str) -> Result<(), GatewayError> {
        Path::try_new("state")
            .and_then(|path| path.try_push_literal(path_name))
            .map_err(|error| GatewayError::InvalidProfile(error.to_string()))?;
        if self.profile_name != path_name {
            return Err(GatewayError::InvalidProfile(
                "profile_name does not match the State path".into(),
            ));
        }
        CompiledGatewayProfile::compile(self.clone().into_profile()?)?;
        Ok(())
    }

    /// Convert declared fields into a host profile, without resolving runtime resources.
    pub fn into_profile(self) -> Result<GatewayProfile, GatewayError> {
        let mut profile = GatewayProfile::new(self.profile_name)
            .with_revision(self.version)
            .with_credential_revocation_floor(self.credential_revocation_floor)
            .with_limits(self.limits);
        for credential in self.credentials {
            let verifier = match credential.verifier {
                CredentialVerifierDocument::Bearer { token_hash } => {
                    GatewayCredential::bearer_hash(
                        credential.credential_id,
                        credential.principal_id,
                        BearerTokenHash::from_hex(token_hash)?,
                    )
                }
                CredentialVerifierDocument::ClientCertificate { der_sha256 } => {
                    GatewayCredential::client_certificate_der_sha256(
                        credential.credential_id,
                        credential.principal_id,
                        ClientCertificateDerSha256::from_hex(der_sha256)?,
                    )
                }
            };
            profile = profile.with_credential(
                verifier
                    .with_enabled(credential.enabled)
                    .with_generation(credential.generation),
            );
        }
        for mapping in self.identity_mappings {
            profile = profile.with_identity_mapping(
                GatewayIdentityMapping::new(mapping.principal_id, mapping.identity_path)
                    .with_enabled(mapping.enabled)
                    .with_generation(mapping.generation),
            );
        }
        for surface in self.surfaces {
            let target = ResourceName::new(
                Path::parse(&surface.target)
                    .map_err(|error| GatewayError::InvalidProfile(error.to_string()))?,
            );
            let mut declared = GatewaySurface::effect_invoke(surface.surface_id, target)
                .with_schema(surface.input_schema, surface.output_schema);
            if let Some(schema) = surface.output_stream_schema {
                declared = declared.with_output_stream_schema(schema);
            }
            if let Some(capability) = surface.publish_capability {
                declared = declared.with_publish_capability(capability);
            }
            profile = profile.with_surface(declared);
        }
        for publication in self.publications {
            profile = profile.with_publication(GatewayPublication {
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
                enabled: publication.enabled,
            });
        }
        if let Some(anchor) = self.authority_anchor {
            profile = profile.with_authority_anchor(anchor);
        }
        for binding in self.principal_surface_bindings {
            profile = profile.with_principal_surface_binding(GatewayPrincipalSurfaceBinding::new(
                binding.principal_id,
                binding.visible_surfaces,
                binding.submit_surfaces,
                binding.capability_ceiling,
            ));
        }
        for host in self.registered_hosts {
            profile = profile.with_registered_host(&host)?;
        }
        for origin in self.registered_origins {
            profile = profile.with_registered_origin(&origin)?;
        }
        Ok(profile)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialDocument {
    credential_id: String,
    principal_id: String,
    #[serde(default = "enabled")]
    enabled: bool,
    #[serde(default = "initial_generation")]
    generation: GatewayGeneration,
    verifier: CredentialVerifierDocument,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CredentialVerifierDocument {
    Bearer { token_hash: String },
    ClientCertificate { der_sha256: String },
}

impl std::fmt::Debug for CredentialVerifierDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer { .. } => f.write_str("Bearer(<redacted>)"),
            Self::ClientCertificate { .. } => f.write_str("ClientCertificate(<redacted>)"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityDocument {
    principal_id: String,
    identity_path: String,
    #[serde(default = "enabled")]
    enabled: bool,
    #[serde(default = "initial_generation")]
    generation: GatewayGeneration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SurfaceDocument {
    surface_id: String,
    target: String,
    #[serde(default)]
    publish_capability: Option<String>,
    #[serde(default)]
    input_schema: Option<Value>,
    #[serde(default)]
    output_schema: Option<Value>,
    #[serde(default)]
    output_stream_schema: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationDocument {
    protocol: String,
    kind: String,
    name: String,
    surface_id: String,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    properties: BTreeMap<String, Value>,
    #[serde(default)]
    annotations: Option<Value>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default = "enabled")]
    enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingDocument {
    principal_id: String,
    #[serde(default)]
    visible_surfaces: Vec<String>,
    #[serde(default)]
    submit_surfaces: Vec<String>,
    #[serde(default)]
    capability_ceiling: Vec<String>,
}

fn enabled() -> bool {
    true
}

fn initial_generation() -> GatewayGeneration {
    1
}

#[cfg(test)]
mod tests;
