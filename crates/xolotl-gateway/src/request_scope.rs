//! Original request scope, checked at preparation without granting authority.

use crate::{
    CompiledGatewayProfile, CompiledSurfaceDescriptor, GatewayError, GatewayEvidenceNamespace,
    GatewayIdempotencyStore, GatewaySession, GatewaySurface, SubmitOptions,
};

fn bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub(crate) fn surface_digest(surface: &GatewaySurface) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    bytes(&mut hasher, b"xolotl-gateway-surface-binding-v1");
    bytes(&mut hasher, surface.surface_id.as_bytes());
    bytes(&mut hasher, surface.target.path().to_string().as_bytes());
    bytes(
        &mut hasher,
        surface
            .publish_capability
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    for schema in [
        &surface.input_schema,
        &surface.output_schema,
        &surface.output_stream_schema,
    ] {
        hasher.update(&[u8::from(schema.is_some())]);
        if let Some(schema) = schema {
            hasher.update(&schema.semantic_digest());
        }
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn fingerprint(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    namespace: GatewayEvidenceNamespace,
) -> String {
    digest(profile, session, surface, namespace)
        .to_hex()
        .to_string()
}

fn digest(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    namespace: GatewayEvidenceNamespace,
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    bytes(&mut hasher, b"xolotl-gateway-request-scope-v1");
    bytes(&mut hasher, namespace.as_bytes());
    bytes(&mut hasher, profile.profile_name.as_bytes());
    hasher.update(&profile.revision.to_be_bytes());
    bytes(&mut hasher, session.principal.principal_id.as_bytes());
    bytes(&mut hasher, session.identity_path.as_bytes());
    bytes(&mut hasher, &surface.request_binding_digest);
    hasher.finalize()
}

pub(crate) fn validate(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    store: &dyn GatewayIdempotencyStore,
    options: &SubmitOptions,
) -> Result<(), GatewayError> {
    let Some(expected) = options.expected_request_scope.as_deref() else {
        if options.idempotency_key.is_some() || options.submission_token.is_some() {
            return Err(GatewayError::Rejected(
                "retry identity requires its original request scope".into(),
            ));
        }
        return Ok(());
    };
    if expected.len() != 64
        || expected
            != digest(profile, session, surface, store.evidence_namespace()?)
                .to_hex()
                .as_str()
    {
        return Err(GatewayError::Rejected(
            "original request scope changed".into(),
        ));
    }
    Ok(())
}
