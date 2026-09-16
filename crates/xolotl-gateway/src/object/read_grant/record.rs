//! Versioned authority metadata; the State envelope is its only provenance source.

use serde::{Deserialize, Serialize};
use xolotl_state::object::ObjectMetadata;
use xolotl_types::{BlobRef, ResourceName, TaintedValue, Value};

use super::GatewayObjectReadGrant;
use crate::{
    CompiledGatewayProfile, GatewayAuthMethod, GatewayError, GatewaySession, validate_content_hash,
    validate_current_session,
};

const SCHEMA: &str = "gateway-object-read-grant-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::object) struct ReadGrantScope {
    profile_name: String,
    profile_rev: u64,
    principal_id: String,
    principal_generation: u64,
    credential_id: String,
    credential_generation: u64,
    auth_method: String,
    identity_path: String,
    surface_id: String,
    target: ResourceName,
}

impl ReadGrantScope {
    pub(in crate::object) fn new(
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_id: &str,
    ) -> Result<Self, GatewayError> {
        validate_current_session(profile, session)?;
        let surface = profile
            .surface_by_id(surface_id)
            .ok_or_else(|| GatewayError::Rejected("unknown object export surface".into()))?;
        Ok(Self {
            profile_name: session.profile_name.clone(),
            profile_rev: session.profile_rev,
            principal_id: session.principal.principal_id.clone(),
            principal_generation: session.principal.principal_generation,
            credential_id: session.principal.credential_id.clone(),
            credential_generation: session.principal.credential_generation,
            auth_method: auth_method(session.principal.auth_method).into(),
            identity_path: session.identity_path.clone(),
            surface_id: surface_id.into(),
            target: surface.target.clone(),
        })
    }

    pub(in crate::object) fn validate(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
    ) -> Result<(), GatewayError> {
        validate_current_session(profile, session)?;
        if self.profile_name != session.profile_name
            || self.profile_rev != session.profile_rev
            || self.principal_id != session.principal.principal_id
            || self.principal_generation != session.principal.principal_generation
            || self.credential_id != session.principal.credential_id
            || self.credential_generation != session.principal.credential_generation
            || self.auth_method != auth_method(session.principal.auth_method)
            || self.identity_path != session.identity_path
        {
            return Err(GatewayError::Unauthorized(
                "object read grant audience mismatch".into(),
            ));
        }
        let surface = profile.surface_by_id(&self.surface_id).ok_or_else(|| {
            GatewayError::Unauthorized("object read grant surface is no longer available".into())
        })?;
        if surface.target != self.target {
            return Err(GatewayError::Unauthorized(
                "object read grant surface changed".into(),
            ));
        }
        Ok(())
    }
}

fn auth_method(method: GatewayAuthMethod) -> &'static str {
    match method {
        GatewayAuthMethod::Bearer => "bearer",
        GatewayAuthMethod::ClientCertificate => "client_certificate",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    grant_id: String,
    scope: ReadGrantScope,
    blob: BlobRef,
    offset: u64,
    length: u64,
    expires_at_ms: i64,
}

pub(in crate::object) fn encode(
    scope: ReadGrantScope,
    grant: &GatewayObjectReadGrant,
) -> Result<Value, GatewayError> {
    // This fixed record has no arbitrary Values; JSON retains its full-width u64 fields.
    serde_json::to_string(&Record {
        schema: SCHEMA.into(),
        grant_id: grant.grant_id.clone(),
        scope,
        blob: grant.metadata.blob.clone(),
        offset: grant.offset,
        length: grant.length,
        expires_at_ms: grant.expires_at_ms,
    })
    .map(Value::string)
    .map_err(|error| GatewayError::Rejected(format!("object read grant encode failed: {error}")))
}

pub(in crate::object) fn decode(
    grant_id: &str,
    envelope: &TaintedValue,
) -> Result<(ReadGrantScope, GatewayObjectReadGrant), GatewayError> {
    let encoded = envelope.value.as_str().ok_or_else(|| {
        GatewayError::Rejected("object read grant record must be encoded metadata".into())
    })?;
    let record: Record = serde_json::from_str(encoded).map_err(|error| {
        GatewayError::Rejected(format!("invalid object read grant record: {error}"))
    })?;
    if record.schema != SCHEMA || record.grant_id != grant_id {
        return Err(GatewayError::Rejected(
            "object read grant identity or version mismatch".into(),
        ));
    }
    validate_content_hash(&record.blob.hash)?;
    if record
        .offset
        .checked_add(record.length)
        .is_none_or(|end| end > record.blob.size)
        || record.expires_at_ms <= 0
    {
        return Err(GatewayError::Rejected(
            "invalid object read grant range or expiry".into(),
        ));
    }
    Ok((
        record.scope,
        GatewayObjectReadGrant {
            grant_id: record.grant_id,
            metadata: ObjectMetadata {
                blob: record.blob,
                taint: envelope.taint.clone(),
            },
            offset: record.offset,
            length: record.length,
            expires_at_ms: record.expires_at_ms,
        },
    ))
}
