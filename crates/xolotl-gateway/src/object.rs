//! Gateway object upload, bound receipts and provenance admission.
//!
//! State retains authorization records; object content belongs exclusively to
//! the host-installed ObjectStore. Published content is never rolled back when
//! a receipt CAS fails, because other callers may already share its identity.

use std::num::NonZeroUsize;
use xolotl_kernel::Bootstrap;
use xolotl_state::host::object::ObjectStore;
use xolotl_state::{StateCursor, StateFailure};
use xolotl_types::{Value, ValueView};

use crate::{
    GatewayError, GatewayModality, GatewayRuntime, GatewaySession, normalize_optional_string,
    validate_current_session,
};

mod admission;
mod download;
mod export;
mod maintenance;
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
pub(crate) use maintenance::spawn_object_maintenance;
pub(crate) use read_grant::ReadGrantMaintenance;
pub use read_grant::{GatewayObjectReadGrant, IssueObjectReadGrantRequest, OpenObjectReadRequest};
pub use ticket::GatewayObjectUploadTicket;
pub(crate) use ticket::UploadTicketMaintenance;
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
    /// Optional expected lowercase SHA-384 digest.
    pub expected_digest: Option<String>,
    /// Optional allowed media type patterns, for example `image/*`.
    pub allowed_media_types: Vec<String>,
    /// Requested TTL from server issue time.
    pub expires_in_ms: Option<u64>,
    /// Consume the receipt once Gateway admission succeeds, before execution.
    /// A later execution failure does not restore the receipt.
    pub single_use: bool,
    /// Maximum distinct typed objects allowed on this ticket. Defaults to the profile limit.
    pub max_objects: Option<usize>,
    /// Maximum aggregate canonical bytes of distinct backing blobs.
    pub max_total_bytes: Option<u64>,
    /// Maximum encoded State record bytes, bounded by the profile and hard ceiling.
    pub max_record_bytes: Option<usize>,
}

/// Response returned after object bytes have been committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitObjectUploadResponse {
    /// Typed item to use as direct input provenance.
    pub item: Value,
    /// Store proof bound to the committed item, principal, and surface.
    pub provenance: GatewayPayloadProvenance,
    /// Lowercase SHA-384 digest of committed bytes.
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
        // Check host capabilities after caller authorization, but before
        // creating a receipt that cannot be loaded safely later.
        if !self.boot.kernel().state().has_bounded_read()
            || !self.boot.kernel().state().has_bounded_write()
        {
            return Err(GatewayError::Rejected(
                "object upload tickets require bounded state reads and writes".into(),
            ));
        }
        let ticket_id = new_upload_ticket_id()?;
        let ttl_ms = request
            .expires_in_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_error| {
                GatewayError::Rejected("object upload ticket ttl is out of range".into())
            })?
            .unwrap_or(profile.limits.max_deadline_ms_from_now);
        let max_objects = request.max_objects.unwrap_or_else(|| {
            if request.expected_size.is_some() || request.expected_digest.is_some() {
                1
            } else {
                profile.limits.max_ticket_objects
            }
        });
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
            expires_at_ms: self
                .boot
                .kernel()
                .host_runtime()
                .now_millis()
                .checked_add(ttl_ms)
                .ok_or_else(|| {
                    GatewayError::Rejected("object upload ticket expiry is out of range".into())
                })?,
            single_use: request.single_use,
            max_objects,
            max_total_bytes: request
                .max_total_bytes
                .unwrap_or(profile.limits.max_ticket_total_bytes),
            max_record_bytes: request
                .max_record_bytes
                .unwrap_or(profile.limits.max_ticket_record_bytes),
            committed_items: Vec::new(),
            used_by: None,
        };
        let path = upload_ticket_path(&ticket.ticket_id)?;
        self.boot
            .kernel()
            .state()
            .write_cas_bounded(
                &path,
                None,
                ticket.to_value()?,
                ticket::ticket_state_budget(),
            )
            .await
            .map_err(|e| GatewayError::Rejected(format!("upload ticket issue failed: {e}")))?;
        Ok(ticket)
    }
}

pub(crate) const fn ticket_record_ceiling() -> usize {
    ticket::MAX_TICKET_ENCODED_BYTES
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

pub(crate) async fn maintain_upload_tickets_once(
    boot: &Bootstrap,
    cursor: &mut Option<StateCursor>,
) -> Result<UploadTicketMaintenance, GatewayError> {
    ticket::maintain_upload_tickets_step(
        boot.kernel().state(),
        cursor,
        boot.kernel().host_runtime().now_millis(),
    )
    .await
}

pub(crate) async fn maintain_read_grants_once(
    boot: &Bootstrap,
    cursor: &mut Option<StateCursor>,
) -> Result<ReadGrantMaintenance, GatewayError> {
    read_grant::maintain_read_grants_step(
        boot.kernel().state(),
        cursor,
        boot.kernel().host_runtime().now_millis(),
    )
    .await
}

fn large_ref_values(value: &Value) -> impl Iterator<Item = &Value> {
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
