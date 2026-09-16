//! Trusted host delegation; transports only expose opening an existing grant.

use xolotl_state::StateError;
use xolotl_state::object::ObjectMetadata;
use xolotl_types::TaintSet;

use super::read_grant::record::{self, ReadGrantScope};
use super::read_grant::{StoredReadGrant, read_grant_path, state_error};
use super::{GatewayObjectReadGrant, IssueObjectReadGrantRequest, object_store_error};
use crate::{
    GatewayError, GatewayRuntime, GatewaySession, now_millis, push_hex_byte, validate_content_hash,
};

/// A host decision made against the same canonical source snapshot retained by
/// the grant. The public delegation API already represents that decision.
#[async_trait::async_trait]
pub(super) trait ExportAuthorization: Send + Sync {
    async fn authorize(
        &self,
        metadata: &ObjectMetadata,
        expires_at_ms: i64,
    ) -> Result<(), GatewayError>;
}

struct TrustedHost;

#[async_trait::async_trait]
impl ExportAuthorization for TrustedHost {
    async fn authorize(
        &self,
        _metadata: &ObjectMetadata,
        _expires_at_ms: i64,
    ) -> Result<(), GatewayError> {
        Ok(())
    }
}

pub(super) struct ExportFailure {
    pub(super) error: GatewayError,
    pub(super) taint: TaintSet,
}

impl GatewayRuntime {
    /// Delegate reads of one committed object to this authenticated audience.
    ///
    /// This is a trusted host API, deliberately absent from [`crate::Gateway`].
    /// The host must authorize disclosure of the supplied object before calling;
    /// knowing a reference, its sources or an execution result is not authority.
    /// The audience need not have discovery or submission rights for the surface.
    /// The grant is published only after canonical metadata and State commit succeed.
    /// A failed or cancelled commit can leave a valid but undelivered grant; content
    /// and uncertain authorization records are never deleted as compensation.
    pub async fn issue_object_read_grant(
        &self,
        session: &GatewaySession,
        request: IssueObjectReadGrantRequest,
    ) -> Result<GatewayObjectReadGrant, GatewayError> {
        self.issue_object_read_grant_authorized(session, request, &TrustedHost)
            .await
            .map_err(|failure| {
                drop(failure.taint);
                failure.error
            })
    }

    pub(super) async fn issue_object_read_grant_authorized(
        &self,
        session: &GatewaySession,
        request: IssueObjectReadGrantRequest,
        authorization: &dyn ExportAuthorization,
    ) -> Result<GatewayObjectReadGrant, ExportFailure> {
        let mut taint = request.object.taint.clone();
        self.issue_object_read_grant_inner(session, request, authorization, &mut taint)
            .await
            .map_err(|error| ExportFailure { error, taint })
    }

    async fn issue_object_read_grant_inner(
        &self,
        session: &GatewaySession,
        request: IssueObjectReadGrantRequest,
        authorization: &dyn ExportAuthorization,
        observed_sources: &mut TaintSet,
    ) -> Result<GatewayObjectReadGrant, GatewayError> {
        let profile = self.profile_snapshot();
        let scope = ReadGrantScope::new(&profile, session, &request.surface_id)?;
        let requested = request.object.value.backing_blob().ok_or_else(|| {
            GatewayError::Rejected("object export requires a direct Blob, Tensor or Frame".into())
        })?;
        validate_content_hash(&requested.hash)?;
        let ttl_ms = request
            .expires_in_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_error| {
                GatewayError::Rejected("object read grant lifetime is out of range".into())
            })?
            .unwrap_or(profile.limits.max_deadline_ms_from_now);
        if ttl_ms <= 0 || ttl_ms > profile.limits.max_deadline_ms_from_now {
            return Err(GatewayError::Rejected(
                "object read grant lifetime exceeds profile window".into(),
            ));
        }
        let expires_at_ms = now_millis().checked_add(ttl_ms).ok_or_else(|| {
            GatewayError::Rejected("object read grant expiry is out of range".into())
        })?;
        let mut metadata = self
            .objects
            .metadata(requested)
            .await
            .map_err(|failure| {
                observed_sources.union(&failure.taint);
                object_store_error(failure)
            })?
            .ok_or_else(|| {
                GatewayError::Rejected("object export content is not committed".into())
            })?;
        metadata.taint.union(&request.object.taint);
        *observed_sources = metadata.taint.clone();
        if metadata.blob != *requested {
            return Err(GatewayError::Rejected(
                "object export reference is not canonical".into(),
            ));
        }
        let available = metadata
            .blob
            .size
            .checked_sub(request.offset)
            .ok_or_else(|| {
                GatewayError::Rejected("object export range starts beyond the object".into())
            })?;
        let length = request.length.unwrap_or(available);
        if length > available {
            return Err(GatewayError::Rejected(
                "object export range exceeds the object".into(),
            ));
        }
        authorization.authorize(&metadata, expires_at_ms).await?;
        scope.validate(&self.profile_snapshot(), session)?;
        if expires_at_ms <= now_millis() {
            return Err(GatewayError::Rejected(
                "object read grant expired before commit".into(),
            ));
        }
        let grant = GatewayObjectReadGrant {
            grant_id: new_grant_id()?,
            metadata,
            offset: request.offset,
            length,
            expires_at_ms,
        };
        let path = read_grant_path(grant.grant_id())?;
        let value = record::encode(scope, &grant)?;
        self.boot
            .kernel
            .state
            .write_cas_tainted(&path, None, value, grant.metadata.taint.clone())
            .await
            .map_err(|failure| {
                observed_sources.union(&failure.taint);
                state_error(failure)
            })?;
        crate::validate_current_session(&self.profile_snapshot(), session)?;
        if expires_at_ms <= now_millis() {
            return Err(GatewayError::Rejected(
                "object read grant expired during commit".into(),
            ));
        }
        Ok(grant)
    }

    /// Revoke a matching grant without deleting its content or another record.
    ///
    /// Returns false when the grant is already absent. Active readers detect
    /// deletion at their next authority check; bytes already delivered cannot
    /// be recalled. Expired grants can still be revoked by their current audience.
    pub async fn revoke_object_read_grant(
        &self,
        session: &GatewaySession,
        grant_id: &str,
    ) -> Result<bool, GatewayError> {
        crate::validate_current_session(&self.profile_snapshot(), session)?;
        let Some(stored) = StoredReadGrant::load(&self.boot.kernel.state, grant_id).await? else {
            return Ok(false);
        };
        stored.scope.validate(&self.profile_snapshot(), session)?;
        match self
            .boot
            .kernel
            .state
            .write_compare_delete(&stored.path, Some(stored.value))
            .await
        {
            Ok(_commit) => Ok(true),
            Err(xolotl_state::StateFailure {
                error: StateError::CasFailed { .. },
                ..
            }) => Err(GatewayError::Rejected(
                "object read grant changed before revocation".into(),
            )),
            Err(error) => Err(state_error(error)),
        }
    }
}

fn new_grant_id() -> Result<String, GatewayError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        GatewayError::Rejected(format!("object read grant entropy failed: {error}"))
    })?;
    let mut id = String::with_capacity(36);
    id.push_str("org_");
    for byte in bytes {
        push_hex_byte(&mut id, byte);
    }
    Ok(id)
}
