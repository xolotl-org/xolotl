//! Owned incremental ingress and publication of profile-bound object receipts.

use parking_lot::RwLock;
use std::sync::Arc;
use xolotl_kernel::Bootstrap;
use xolotl_state::host::object::ObjectStore;
use xolotl_state::object::{UploadId, UploadOptions};
use xolotl_types::{BlobRef, DType, FrameKind, TaintSet, TaintSource, Value, ValueView};

use super::ticket::{
    StoredTicket, validate_media_type_pattern, validate_upload_ticket_media_type,
    validate_upload_ticket_scope, validate_upload_ticket_values,
};
use super::{
    CommitObjectUploadResponse, UPLOAD_CHUNK_BYTES, committed_object_provenance, object_store_error,
};
use crate::{
    GatewayError, GatewayRuntime, GatewayRuntimeState, GatewaySession, normalize_optional_string,
    now_millis, validate_current_session, validate_submission_token,
};

/// Metadata admitting incremental input against an issued upload ticket.
/// Total size and digest may remain unknown until the upload is committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginObjectUploadRequest {
    /// Ticket returned by [`crate::Gateway::issue_object_upload_ticket`].
    pub ticket_id: String,
    /// Optional declared media type, checked against ticket constraints.
    pub media_type: Option<String>,
    /// Optional submission token that must match a token-bound ticket.
    pub submission_token: Option<String>,
}

/// Interpretation supplied at end-of-input, without a caller-generated content reference.
/// The upload computes the digest and byte count and fills the canonical `BlobRef`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum GatewayObjectKind {
    /// Opaque object bytes, including files and encoded media.
    #[default]
    Blob,
    /// Numeric data with dimensions that may only become known at end-of-input.
    Tensor {
        /// Element type used to interpret the stored bytes.
        dtype: DType,
        /// Tensor dimensions in row-major order.
        shape: Vec<u64>,
    },
    /// One timestamped media, pose or sensor sample.
    Frame {
        /// Sample timestamp in nanoseconds.
        ts_nanos: i64,
        /// Class of media or telemetry sample.
        kind: FrameKind,
    },
}

impl GatewayObjectKind {
    fn into_value(self, blob: BlobRef) -> Value {
        match self {
            Self::Blob => Value::blob(blob),
            Self::Tensor { dtype, shape } => Value::tensor(blob, dtype, shape),
            Self::Frame { ts_nanos, kind } => Value::frame(blob, ts_nanos, kind),
        }
    }
}

struct UploadBody {
    lease: UploadId,
    hasher: blake3::Hasher,
    size: u64,
}

/// Owns unpublished object input and the authority needed to publish its receipt.
/// Input is borrowed one call at a time; no cumulative payload buffer or queue is
/// retained. Unknown total size is allowed when the ticket does not declare one.
///
/// Once a write is polled, an error or cancellation closes the upload and drops
/// its staging lease. A dropped, unpolled write does not change the upload.
/// Dropping the upload itself also abandons staging, without an awaited abort.
/// The adapter owns cleanup of work that outlives a cancelled storage request.
///
/// Session authority and absolute ticket expiry are checked around I/O; activity
/// does not extend the ticket lifetime. An idle expired upload retains its lease
/// until used, dropped or explicitly aborted. No background reaper is created.
#[must_use = "commit the upload or drop it to abandon staging"]
pub struct GatewayObjectUpload {
    boot: Arc<Bootstrap>,
    objects: ObjectStore,
    runtime_state: Arc<RwLock<GatewayRuntimeState>>,
    session: GatewaySession,
    stored: StoredTicket,
    submission_token: Option<String>,
    media_type: Option<String>,
    taint: TaintSet,
    body: Option<UploadBody>,
}

impl std::fmt::Debug for GatewayObjectUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayObjectUpload")
            .field("ticket_id", &self.stored.ticket.ticket_id)
            .field("size", &self.body.as_ref().map(|body| body.size))
            .finish_non_exhaustive()
    }
}

impl GatewayObjectUpload {
    /// Append borrowed input, returning the total bytes accepted by completed writes.
    /// Storage receives windows of at most 16 KiB and may acknowledge shorter
    /// prefixes. Window size does not limit cumulative object length. The caller
    /// may supply smaller chunks to reduce its own input and adapter buffer sizes.
    ///
    /// Errors or cancellation after polling abandon the complete upload, since
    /// the adapter may already have accepted a prefix. Further writes or commit
    /// fail explicitly; this interface does not expose resumable storage offsets.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<u64, GatewayError> {
        // The in-flight request owns staging until all acknowledgements are known.
        let mut body = self.body.take().ok_or_else(closed_upload)?;
        self.validate(None)?;
        let size = u64::try_from(bytes.len())
            .ok()
            .and_then(|length| body.size.checked_add(length))
            .filter(|size| *size <= i64::MAX as u64)
            .ok_or_else(|| GatewayError::Rejected("object upload size is out of range".into()))?;
        if self
            .stored
            .ticket
            .expected_size
            .is_some_and(|expected| size > expected)
        {
            return Err(GatewayError::Rejected("upload ticket size mismatch".into()));
        }
        let next = self
            .objects
            .write_all(&body.lease, body.size, bytes, UPLOAD_CHUNK_BYTES)
            .await
            .map_err(object_store_error)?;
        self.validate(None)?;
        body.hasher.update(bytes);
        body.size = next;
        self.body = Some(body);
        Ok(next)
    }

    /// Commit the input and publish its bound receipt, interpreting the canonical
    /// reference as the requested kind. Neither a known size nor a precomputed
    /// digest is required from the caller. Tensor shape may be supplied at EOF.
    ///
    /// Content is committed before the receipt CAS. Errors or cancellation can
    /// leave published content or an uncertain receipt result; neither is rolled
    /// back, since another caller may already share the content. The upload is
    /// consumed and cannot be retried with guessed storage progress.
    pub async fn commit(
        mut self,
        kind: GatewayObjectKind,
    ) -> Result<CommitObjectUploadResponse, GatewayError> {
        let body = self.body.take().ok_or_else(closed_upload)?;
        let digest = body.hasher.finalize().to_hex().to_string();
        let size = body.size;
        let mut item = kind.into_value(BlobRef {
            hash: digest.clone(),
            size,
            mime: self.media_type.clone(),
        });
        self.validate(Some(&item))?;
        let metadata = self
            .objects
            .commit_upload(&body.lease, &TaintSet::pristine())
            .await
            .map_err(object_store_error)?;
        if metadata.blob.hash != digest || metadata.blob.size != size {
            return Err(GatewayError::Rejected(
                "committed object metadata does not match uploaded bytes".into(),
            ));
        }
        if !metadata.taint.contains_all(&self.taint) {
            return Err(GatewayError::Rejected(
                "committed object metadata lost upload provenance".into(),
            ));
        }
        replace_backing_blob(&mut item, metadata.blob)?;
        self.validate(Some(&item))?;
        self.stored.ticket.expected_size = Some(size);
        self.stored.ticket.expected_digest = Some(digest.clone());
        self.stored.ticket.committed = true;
        let provenance = committed_object_provenance(&self.stored.ticket.ticket_id);
        self.stored.save(&self.boot.kernel.state).await?;
        Ok(CommitObjectUploadResponse {
            item,
            provenance,
            digest,
            size,
        })
    }

    /// Request early staging cleanup and consume this upload. A cancelled or
    /// failed abort still drops the staging lease. Dropping the owner directly
    /// also releases staging, so an explicit abort is optional.
    pub async fn abort(mut self) -> Result<(), GatewayError> {
        if let Some(body) = self.body.take() {
            self.objects
                .abort_upload(&body.lease)
                .await
                .map_err(object_store_error)?;
        }
        Ok(())
    }

    fn validate(&self, item: Option<&Value>) -> Result<(), GatewayError> {
        let profile = self.runtime_state.read().profile.clone();
        validate_current_session(&profile, &self.session)?;
        let ticket = &self.stored.ticket;
        let surface = profile.surface_by_id(&ticket.surface_id).ok_or_else(|| {
            GatewayError::Rejected("upload ticket surface is no longer available".into())
        })?;
        if !profile.principal_can_submit(&self.session.principal.principal_id, &surface.surface_id)
        {
            return Err(GatewayError::Rejected(
                "upload ticket surface is not callable by principal".into(),
            ));
        }
        if let Some(item) = item {
            validate_upload_ticket_values(
                &ticket.ticket_id,
                ticket,
                &[item],
                &self.session,
                surface,
                self.submission_token.as_deref(),
                now_millis(),
            )
        } else {
            validate_upload_ticket_scope(
                &ticket.ticket_id,
                ticket,
                &self.session,
                surface,
                self.submission_token.as_deref(),
                now_millis(),
            )?;
            validate_upload_ticket_media_type(ticket, self.media_type.as_deref())
        }
    }
}

impl GatewayRuntime {
    pub(crate) async fn begin_upload(
        &self,
        session: &GatewaySession,
        request: BeginObjectUploadRequest,
    ) -> Result<GatewayObjectUpload, GatewayError> {
        let source = {
            let profile = self.profile_snapshot();
            validate_current_session(&profile, session)?;
            Self::source_label(&profile)
        };
        if !self.objects.can_write() {
            return Err(GatewayError::Rejected(
                "object uploads require object.write".into(),
            ));
        }
        let submission_token = normalize_optional_string(request.submission_token);
        if let Some(token) = submission_token.as_deref() {
            validate_submission_token(token)?;
        }
        let media_type = normalize_optional_string(request.media_type);
        if let Some(mime) = media_type.as_deref() {
            validate_media_type_pattern(mime)?;
        }
        let stored = StoredTicket::load(&self.boot.kernel.state, &request.ticket_id).await?;
        if stored.ticket.committed {
            return Err(GatewayError::Rejected(
                "upload ticket was already committed".into(),
            ));
        }
        let mut upload = GatewayObjectUpload {
            boot: Arc::clone(&self.boot),
            objects: self.objects.clone(),
            runtime_state: Arc::clone(&self.state),
            session: session.clone(),
            stored,
            submission_token,
            media_type,
            taint: TaintSet::of(TaintSource::Inbound {
                source: source.into(),
                channel: "object-upload".into(),
            }),
            body: None,
        };
        upload.validate(None)?;
        let lease = upload
            .objects
            .begin_upload(UploadOptions {
                expected_size: upload.stored.ticket.expected_size,
                mime: upload.media_type.clone(),
                taint: upload.taint.clone(),
            })
            .await
            .map_err(object_store_error)?;
        upload.body = Some(UploadBody {
            lease,
            hasher: blake3::Hasher::new(),
            size: 0,
        });
        upload.validate(None)?;
        Ok(upload)
    }
}

fn closed_upload() -> GatewayError {
    GatewayError::Rejected("object upload is closed".into())
}

fn replace_backing_blob(value: &mut Value, canonical: BlobRef) -> Result<(), GatewayError> {
    *value = match value.view() {
        ValueView::Blob(_) => Value::blob(canonical),
        ValueView::Tensor(tensor) => Value::tensor(canonical, tensor.dtype, tensor.shape.clone()),
        ValueView::Frame(frame) => Value::frame(canonical, frame.ts_nanos, frame.kind),
        _ => {
            return Err(GatewayError::Rejected(
                "object upload requires a backing blob".into(),
            ));
        }
    };
    Ok(())
}
