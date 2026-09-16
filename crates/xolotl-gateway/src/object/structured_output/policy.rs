use xolotl_state::object::ObjectMetadata;

use super::{GatewayOutputKind, kind, validate_event};
use crate::object::export::ExportAuthorization;
use crate::{GatewayAccepted, GatewayError, GatewayOutputEvent, GatewaySession};

/// Exact audience, result, and canonical content considered for one disclosure.
pub struct GatewayOutputDisclosureRequest<'a> {
    /// Authenticated audience; discovery/submission rights are not read grants.
    pub session: &'a GatewaySession,
    /// Original request metadata, including its selected surface.
    pub accepted: &'a GatewayAccepted,
    /// Original typed item; its owner remains private until delivery completes.
    pub event: &'a GatewayOutputEvent,
    /// Canonical metadata snapshot considered for this grant, obtained after
    /// commit. Object ports may report additional sources during later reads.
    pub metadata: &'a ObjectMetadata,
    /// Exact proposed server-clock expiry, in milliseconds since the Unix epoch.
    /// Policy waits and subsequent reads never extend this timestamp.
    pub expires_at_ms: i64,
}

impl GatewayOutputDisclosureRequest<'_> {
    /// Original semantic role, independent of encoding or media type.
    pub fn kind(&self) -> GatewayOutputKind {
        kind(self.event)
    }
}

/// Explicit host policy for issuing one complete-container read grant.
///
/// No implementation or allow-by-default policy is installed automatically.
/// Returning success authorizes this authenticated audience to read only the
/// supplied canonical object. It does not grant access to nested references.
/// A pending decision retains the original chunk's capacity; cancellation drops
/// that owner without starting a detached policy or granting later in a task.
#[async_trait::async_trait]
pub trait GatewayOutputDisclosurePolicy: Send + Sync {
    /// Authorize the final canonical sources before any read grant is committed.
    async fn authorize(
        &self,
        request: GatewayOutputDisclosureRequest<'_>,
    ) -> Result<(), GatewayError>;
}

#[async_trait::async_trait]
impl<P: GatewayOutputDisclosurePolicy + ?Sized> GatewayOutputDisclosurePolicy
    for std::sync::Arc<P>
{
    async fn authorize(
        &self,
        request: GatewayOutputDisclosureRequest<'_>,
    ) -> Result<(), GatewayError> {
        self.as_ref().authorize(request).await
    }
}

pub(super) struct Authorization<'a, P: ?Sized> {
    pub(super) session: &'a GatewaySession,
    pub(super) accepted: &'a GatewayAccepted,
    pub(super) event: &'a GatewayOutputEvent,
    pub(super) disclosure: &'a P,
}

#[async_trait::async_trait]
impl<P: GatewayOutputDisclosurePolicy + ?Sized> ExportAuthorization for Authorization<'_, P> {
    async fn authorize(
        &self,
        metadata: &ObjectMetadata,
        expires_at_ms: i64,
    ) -> Result<(), GatewayError> {
        validate_event(self.event)?;
        self.disclosure
            .authorize(GatewayOutputDisclosureRequest {
                session: self.session,
                accepted: self.accepted,
                event: self.event,
                metadata,
                expires_at_ms,
            })
            .await?;
        validate_event(self.event)
    }
}
