//! Borrowed output windows under one explicit object read grant.

use xolotl_state::host::object::ObjectStore;
use xolotl_state::object::{ObjectMetadata, ObjectReadChunk};

use super::object_store_error;
use super::read_grant::{OpenObjectReadRequest, ReadAuthorization};
use crate::{GatewayError, GatewayRuntime, GatewaySession};

const READ_CHUNK_BYTES: usize = 16 * 1024;

/// Owns a fixed canonical object reference and one authorized byte range.
/// The caller owns every payload buffer; this owner retains no content or queue.
/// Individual reads offer at most 16 KiB to the adapter and may return less.
/// Object size and absolute offsets remain `u64`, independently of window size.
///
/// A polled read closes the owner on failure or cancellation. Dropping an unpolled
/// read leaves it available. Storage work that outlives a cancelled read remains
/// the adapter's responsibility. Buffers may have changed after an unsuccessful
/// read, but only bytes acknowledged by a successful read may be delivered.
///
/// Grant and session authority are checked around reads and at completion.
/// Separate reads do not pin content against deletion or freeze its provenance.
/// Each chunk combines the opening metadata and grant provenance with its own
/// sources, without retaining the provenance history of previously emitted chunks.
#[must_use = "finish the selected range or drop the download to close it"]
pub struct GatewayObjectDownload {
    objects: ObjectStore,
    authorization: ReadAuthorization,
    metadata: ObjectMetadata,
    start_offset: u64,
    end_offset: u64,
    next_offset: u64,
    open: bool,
}

impl std::fmt::Debug for GatewayObjectDownload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayObjectDownload")
            .field("start_offset", &self.start_offset)
            .field("end_offset", &self.end_offset)
            .field("next_offset", &self.next_offset)
            .field("open", &self.open)
            .finish_non_exhaustive()
    }
}

impl GatewayObjectDownload {
    /// Canonical reference and the provenance fixed when the download opened.
    pub fn metadata(&self) -> &ObjectMetadata {
        &self.metadata
    }

    /// Inclusive absolute start of the selected range.
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Exclusive absolute end of the selected range.
    pub fn end_offset(&self) -> u64 {
        self.end_offset
    }

    /// Absolute offset following the last successfully acknowledged window.
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Whether the open owner has read its complete selected range.
    /// This is independent of the full object's EOF and transport completion.
    pub fn is_complete(&self) -> bool {
        self.open && self.next_offset == self.end_offset
    }

    /// Absolute grant deadline; activity never extends it.
    pub fn expires_at_ms(&self) -> i64 {
        self.authorization.grant().expires_at_ms()
    }

    /// Check the live session, profile and expiry without another State request.
    /// Transports use this before delivering pieces of an acknowledged window.
    /// Grant changes in State are checked by each read and by [`Self::finish`].
    pub fn validate(&self) -> Result<(), GatewayError> {
        if !self.open {
            return Err(closed_download());
        }
        self.authorization.validate()
    }

    /// Fill one borrowed window and advance only after authorization is rechecked.
    /// A short successful read is valid. `end` describes the full object's EOF;
    /// [`Self::is_complete`] describes completion of the selected range.
    ///
    /// An empty window, or a range already complete, returns zero bytes without
    /// reading storage. The effective offered window is limited by range length,
    /// so a completed range may return `end: false` before the full object's EOF.
    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<ObjectReadChunk, GatewayError> {
        // Only a fully acknowledged request restores the open state.
        if !std::mem::replace(&mut self.open, false) {
            return Err(closed_download());
        }
        self.authorization.verify().await?;
        let remaining = self.end_offset - self.next_offset;
        let offered = buffer
            .len()
            .min(READ_CHUNK_BYTES)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut chunk = if offered == 0 {
            ObjectReadChunk {
                bytes_read: 0,
                end: self.next_offset == self.metadata.blob.size,
                taint: self.metadata.taint.clone(),
            }
        } else {
            self.objects
                .read_chunk(
                    &self.metadata.blob,
                    self.next_offset,
                    &mut buffer[..offered],
                )
                .await
                .map_err(object_store_error)?
        };
        let next = chunk
            .checked_next_offset(self.next_offset, offered, self.metadata.blob.size)
            .map_err(object_store_error)?;
        self.authorization.verify().await?;
        chunk.taint.union(&self.metadata.taint);
        self.next_offset = next;
        self.open = true;
        Ok(chunk)
    }

    /// Consume a completely read range after a final grant and session check.
    /// This does not claim that the transport has delivered its completion frame.
    /// Empty ranges can finish directly without requesting any object bytes.
    pub async fn finish(mut self) -> Result<(), GatewayError> {
        if !std::mem::replace(&mut self.open, false) {
            return Err(closed_download());
        }
        if self.next_offset != self.end_offset {
            return Err(GatewayError::Rejected(
                "object download range is incomplete".into(),
            ));
        }
        self.authorization.verify().await
    }
}

impl GatewayRuntime {
    pub(crate) async fn open_read(
        &self,
        session: &GatewaySession,
        request: OpenObjectReadRequest,
    ) -> Result<GatewayObjectDownload, GatewayError> {
        let authorization = ReadAuthorization::load(self, session, &request.grant_id).await?;
        let grant = authorization.grant();
        let grant_end = grant
            .offset()
            .checked_add(grant.length())
            .filter(|end| *end <= grant.metadata().blob.size)
            .ok_or_else(invalid_range)?;
        let end_offset = match request.length {
            Some(length) => request
                .offset
                .checked_add(length)
                .ok_or_else(invalid_range)?,
            None => grant_end,
        };
        if request.offset < grant.offset() || request.offset > end_offset || end_offset > grant_end
        {
            return Err(invalid_range());
        }
        let mut metadata = self
            .objects
            .metadata(&grant.metadata().blob)
            .await
            .map_err(object_store_error)?
            .ok_or_else(|| GatewayError::Rejected("object download content is missing".into()))?;
        if metadata.blob != grant.metadata().blob {
            return Err(GatewayError::Rejected(
                "object read grant does not match canonical object metadata".into(),
            ));
        }
        metadata.taint.union(&grant.metadata().taint);
        authorization.verify().await?;
        Ok(GatewayObjectDownload {
            objects: self.objects.clone(),
            authorization,
            metadata,
            start_offset: request.offset,
            end_offset,
            next_offset: request.offset,
            open: true,
        })
    }
}

fn closed_download() -> GatewayError {
    GatewayError::Rejected("object download is closed".into())
}

fn invalid_range() -> GatewayError {
    GatewayError::Rejected("object download range is outside its read grant".into())
}

#[cfg(test)]
mod tests;
