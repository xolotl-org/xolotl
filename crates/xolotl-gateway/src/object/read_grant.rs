//! Exact object read authority, independent of references and source provenance.

use parking_lot::RwLock;
use std::sync::Arc;
use tokio::time::Instant;
use xolotl_state::object::ObjectMetadata;
use xolotl_state::{Backend, StateFailure};
use xolotl_types::{Path, TaintedValue, Value};

use crate::{
    GatewayError, GatewayRuntime, GatewayRuntimeState, GatewaySession, now_millis, state_path,
    validate_current_session,
};

pub(super) mod record;
use record::ReadGrantScope;

/// Explicit delegation requested by trusted host code with object read authority.
/// This request is not part of the transport-facing [`crate::Gateway`] trait.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueObjectReadGrantRequest {
    /// Existing profile surface fixing this delegation's target scope.
    /// Discovery and submission permissions are independent of this delegation.
    pub surface_id: String,
    /// Direct Blob, Tensor or Frame value and the sources selecting this object.
    /// Passing a reference is a host authorization decision, not proof of ownership.
    pub object: TaintedValue,
    /// First authorized byte at an absolute object offset.
    pub offset: u64,
    /// Authorized byte count; `None` selects the remainder of the object.
    pub length: Option<u64>,
    /// Fixed lifetime bounded by the profile's deadline window.
    pub expires_in_ms: Option<u64>,
}

/// One authenticated range read using a previously issued delegation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenObjectReadRequest {
    /// Opaque identifier returned by trusted grant issuance.
    pub grant_id: String,
    /// First requested byte at an absolute object offset.
    pub offset: u64,
    /// Requested byte count; `None` selects the remainder of the granted range.
    pub length: Option<u64>,
}

/// A reusable, expiring delegation for one canonical object and byte range.
/// Every read still authenticates its audience and checks the retained grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayObjectReadGrant {
    pub(super) grant_id: String,
    pub(super) metadata: ObjectMetadata,
    pub(super) offset: u64,
    pub(super) length: u64,
    pub(super) expires_at_ms: i64,
}

impl GatewayObjectReadGrant {
    /// Identifier accepted by [`crate::Gateway::open_object_read`].
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// Canonical content reference and sources retained by the export decision.
    pub fn metadata(&self) -> &ObjectMetadata {
        &self.metadata
    }

    /// First authorized byte at an absolute object offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Number of authorized bytes, independent of any resident read window.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Fixed server-clock expiry in milliseconds since the Unix epoch.
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

pub(super) struct StoredReadGrant {
    pub(super) path: Path,
    pub(super) value: Value,
    pub(super) scope: ReadGrantScope,
    pub(super) grant: GatewayObjectReadGrant,
}

impl StoredReadGrant {
    pub(super) async fn load(
        state: &Backend,
        grant_id: &str,
    ) -> Result<Option<Self>, GatewayError> {
        let path = read_grant_path(grant_id)?;
        let Some(envelope) = state.read_tainted(&path).await.map_err(state_error)? else {
            return Ok(None);
        };
        let (scope, grant) = record::decode(grant_id, &envelope)?;
        Ok(Some(Self {
            path,
            value: envelope.value,
            scope,
            grant,
        }))
    }
}

/// A download owns the issuer's State and live profile without a second registry.
pub(super) struct ReadAuthorization {
    state: Backend,
    runtime_state: Arc<RwLock<GatewayRuntimeState>>,
    session: GatewaySession,
    stored: StoredReadGrant,
    deadline: Instant,
}

impl ReadAuthorization {
    pub(super) async fn load(
        runtime: &GatewayRuntime,
        session: &GatewaySession,
        grant_id: &str,
    ) -> Result<Self, GatewayError> {
        validate_current_session(&runtime.profile_snapshot(), session)?;
        let stored = StoredReadGrant::load(&runtime.boot.kernel.state, grant_id)
            .await?
            .ok_or_else(missing_grant)?;
        let now = Instant::now();
        let remaining_ms = stored
            .grant
            .expires_at_ms
            .saturating_sub(now_millis())
            .max(0) as u64;
        let deadline = now
            .checked_add(std::time::Duration::from_millis(remaining_ms))
            .ok_or_else(|| {
                GatewayError::Rejected("object read grant expiry is out of range".into())
            })?;
        let authorization = Self {
            state: runtime.boot.kernel.state.clone(),
            runtime_state: runtime.state.clone(),
            session: session.clone(),
            stored,
            deadline,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub(super) fn grant(&self) -> &GatewayObjectReadGrant {
        &self.stored.grant
    }

    pub(super) fn validate(&self) -> Result<(), GatewayError> {
        let profile = self.runtime_state.read().profile.clone();
        self.stored.scope.validate(&profile, &self.session)?;
        if self.stored.grant.expires_at_ms <= now_millis() || self.deadline <= Instant::now() {
            return Err(GatewayError::Rejected("object read grant expired".into()));
        }
        Ok(())
    }

    /// Point-read authority around storage I/O; no watcher or retained history is needed.
    pub(super) async fn verify(&self) -> Result<(), GatewayError> {
        self.validate()?;
        let current = self
            .state
            .read_tainted(&self.stored.path)
            .await
            .map_err(state_error)?;
        if current.as_ref().is_none_or(|current| {
            current.value != self.stored.value || current.taint != self.stored.grant.metadata.taint
        }) {
            return Err(GatewayError::Rejected(
                "object read grant was revoked or changed".into(),
            ));
        }
        self.validate()
    }
}

pub(super) fn read_grant_path(grant_id: &str) -> Result<Path, GatewayError> {
    let suffix = grant_id.strip_prefix("org_").ok_or_else(invalid_id)?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_id());
    }
    state_path(&["gateway", "object-read-grant", grant_id])
        .map_err(|error| GatewayError::Rejected(format!("invalid object read grant path: {error}")))
}

pub(super) fn state_error(error: StateFailure) -> GatewayError {
    GatewayError::Rejected(format!("object read grant storage failed: {error}"))
}

fn missing_grant() -> GatewayError {
    GatewayError::Rejected("object read grant not found".into())
}

fn invalid_id() -> GatewayError {
    GatewayError::Rejected("invalid object read grant id".into())
}
