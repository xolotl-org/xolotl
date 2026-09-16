//! Gateway object upload, bound receipts and provenance admission.
//!
//! State retains authorization records; object content belongs exclusively to
//! the host-installed ObjectStore. Published content is never rolled back when
//! a receipt CAS fails, because other callers may already share its identity.

use std::num::NonZeroUsize;
use xolotl_state::StateFailure;
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{BlobRef, Value, ValueView};

use crate::{
    GatewayError, GatewayModality, GatewayRuntime, GatewaySession, normalize_optional_string,
    now_millis, validate_current_session,
};

mod admission;
mod download;
mod export;
mod read_grant;
#[cfg(feature = "structured-output")]
mod structured_output;
#[cfg(feature = "structured-output")]
pub use structured_output::{
    GatewayExternalizedOutput, GatewayOutputDisclosurePolicy, GatewayOutputDisclosureRequest,
    GatewayOutputExternalizationError, GatewayOutputExternalizer, GatewayOutputKind,
    GatewayOutputObjectOptions,
};
mod ticket;
mod upload;
pub(super) use admission::ObjectAdmission;
pub use download::GatewayObjectDownload;
pub use read_grant::{GatewayObjectReadGrant, IssueObjectReadGrantRequest, OpenObjectReadRequest};
pub use ticket::GatewayObjectUploadTicket;
use ticket::{new_upload_ticket_id, upload_ticket_path, validate_ticket_issue_request};
pub use upload::{BeginObjectUploadRequest, GatewayObjectKind, GatewayObjectUpload};

const GATEWAY_COMMITTED_OBJECT_STORE_ID: &str = "gateway-upload-ticket-v1";
const UPLOAD_CHUNK_BYTES: NonZeroUsize = NonZeroUsize::MIN.saturating_add(16 * 1024 - 1);

#[cfg(test)]
mod tests;

/// Source proof for inbound `Value::{Blob,Tensor,Frame}` refs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPayloadProvenance {
    /// Committed upload ticket bound to this principal and surface.
    pub upload_ticket: Option<String>,
    /// Trusted object-store proof.
    pub store_proof: Option<ObjectStoreProof>,
}

/// Opaque reference to a committed upload receipt in the gateway State backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreProof {
    /// Store identity.
    pub store_id: String,
    /// Gateway-issued receipt id; object existence alone does not authorize its use.
    pub proof: String,
}

/// Request to issue a short-lived object upload ticket for one surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueObjectUploadTicketRequest {
    /// Surface used when submitting the reserved object reference.
    pub surface_id: String,
    /// Optional submission token the ticket is bound to.
    pub submission_token: Option<String>,
    /// Expected object modality.
    pub modality: GatewayModality,
    /// Optional expected byte size.
    pub expected_size: Option<u64>,
    /// Optional expected lowercase BLAKE3 digest.
    pub expected_digest: Option<String>,
    /// Optional allowed media type patterns, for example `image/*`.
    pub allowed_media_types: Vec<String>,
    /// Requested TTL from server issue time.
    pub expires_in_ms: Option<u64>,
    /// Consume the receipt once Gateway admission succeeds, before execution.
    /// A later execution failure does not restore the receipt.
    pub single_use: bool,
}

/// Response returned after object bytes have been committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitObjectUploadResponse {
    /// Typed item to use as direct input provenance.
    pub item: Value,
    /// Store proof bound to the committed item, principal, and surface.
    pub provenance: GatewayPayloadProvenance,
    /// Lowercase BLAKE3 digest of committed bytes.
    pub digest: String,
    /// Committed byte size.
    pub size: u64,
}

impl GatewayRuntime {
    /// Install object content ports shared with the host's Blob providers.
    /// The default store is empty. Uploads need write support; submitted object
    /// references need metadata reads. State continues to hold only receipts.
    pub fn with_object_store(mut self, objects: ObjectStore) -> Self {
        self.objects = objects;
        self
    }

    pub(super) async fn issue_upload_ticket(
        &self,
        session: &GatewaySession,
        request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        let surface = profile
            .surface_by_id(&request.surface_id)
            .ok_or_else(|| GatewayError::Rejected("unknown gateway surface".into()))?;
        if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
            return Err(GatewayError::Rejected(
                "surface is not callable by principal".into(),
            ));
        }
        validate_ticket_issue_request(&request, &profile.limits)?;
        let ticket_id = new_upload_ticket_id()?;
        let ttl_ms = request
            .expires_in_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_error| {
                GatewayError::Rejected("object upload ticket ttl is out of range".into())
            })?
            .unwrap_or(profile.limits.max_deadline_ms_from_now);
        let ticket = GatewayObjectUploadTicket {
            ticket_id,
            profile_name: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            surface_id: surface.surface_id.clone(),
            submission_token: normalize_optional_string(request.submission_token),
            modality: request.modality,
            expected_size: request.expected_size,
            expected_digest: normalize_optional_string(request.expected_digest),
            allowed_media_types: request
                .allowed_media_types
                .into_iter()
                .map(|media_type| media_type.trim().to_string())
                .collect(),
            expires_at_ms: now_millis().saturating_add(ttl_ms),
            single_use: request.single_use,
            committed: false,
            used: false,
        };
        let path = upload_ticket_path(&ticket.ticket_id)?;
        self.boot
            .kernel
            .state
            .write_cas(&path, None, ticket.to_value()?)
            .await
            .map_err(|e| GatewayError::Rejected(format!("upload ticket issue failed: {e}")))?;
        Ok(ticket)
    }
}

fn committed_object_provenance(ticket_id: &str) -> GatewayPayloadProvenance {
    GatewayPayloadProvenance {
        upload_ticket: None,
        store_proof: Some(ObjectStoreProof {
            store_id: GATEWAY_COMMITTED_OBJECT_STORE_ID.into(),
            proof: ticket_id.into(),
        }),
    }
}

fn object_store_error(error: StateFailure) -> GatewayError {
    GatewayError::Rejected(format!("object store operation failed: {error}"))
}

fn collect_large_ref_values(value: &Value) -> impl Iterator<Item = &Value> {
    use std::collections::BTreeSet;
    use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
    let mut visited = BTreeSet::new();
    let mut walk = ValuePostorder::new(value);
    std::iter::from_fn(move || {
        while let Some(node) = walk.next(|key| visited.contains(&key)) {
            visited.insert(ValueNodeKey::of(node));
            if matches!(
                node.view(),
                ValueView::Blob(_) | ValueView::Tensor(_) | ValueView::Frame(_)
            ) {
                return Some(node);
            }
        }
        None
    })
}

pub(super) fn collect_large_value_refs(value: &Value) -> Vec<&BlobRef> {
    collect_large_ref_values(value)
        .filter_map(Value::backing_blob)
        .collect()
}
