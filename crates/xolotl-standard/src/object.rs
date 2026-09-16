//! Shared bounded buffering for standard provider object offload.

use crate::error::ObservedFailure;
use std::num::NonZeroUsize;
use xolotl_kernel::DriverError;
use xolotl_state::host::object::ObjectStore;
use xolotl_state::object::{UploadId, UploadOptions};
use xolotl_types::{TaintSet, TaintedValue, Value};

pub(crate) const CHUNK_BYTES: usize = 16 * 1024;
pub(crate) const INLINE_BYTES: usize = 1024 * 1024;

/// Holds either a bounded inline prefix or an upload lease, never a whole object.
pub(crate) struct ObjectBuffer {
    objects: ObjectStore,
    inline_limit: usize,
    options: UploadOptions,
    inline: Vec<u8>,
    upload: Option<UploadId>,
    size: u64,
}

impl ObjectBuffer {
    pub(crate) fn new(
        objects: ObjectStore,
        inline_limit: usize,
        mime: Option<String>,
        taint: TaintSet,
    ) -> Self {
        Self {
            objects,
            inline_limit,
            options: UploadOptions {
                mime,
                taint,
                expected_size: None,
            },
            inline: Vec::new(),
            upload: None,
            size: 0,
        }
    }

    pub(crate) async fn push(&mut self, bytes: &[u8]) -> Result<(), ObservedFailure> {
        if self.inline_limit != 0
            && self.upload.is_none()
            && bytes.len() <= self.inline_limit - self.inline.len()
        {
            self.inline.extend_from_slice(bytes);
            self.size = self
                .size
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| DriverError::Other("object length exceeds u64".into()))?;
            return Ok(());
        }
        if self.upload.is_none() {
            let upload = self
                .objects
                .begin_upload(self.options.clone())
                .await
                .map_err(|error| ObservedFailure::from(error).with_taint(&self.options.taint))?;
            self.upload = Some(upload);
            let inline = std::mem::take(&mut self.inline);
            self.size = 0;
            self.append(&inline).await?;
        }
        self.append(bytes).await
    }

    pub(crate) async fn abort(&mut self) {
        if let Some(upload) = self.upload.take()
            && let Err(error) = self.objects.abort_upload(&upload).await
        {
            self.options.taint.union(&error.taint);
        }
    }

    pub(crate) fn failure(&self, error: DriverError) -> ObservedFailure {
        ObservedFailure::from(error).with_taint(&self.options.taint)
    }

    async fn append(&mut self, bytes: &[u8]) -> Result<(), ObservedFailure> {
        let Some(upload) = &self.upload else {
            return Err(self.failure(DriverError::Other("object upload is not open".into())));
        };
        let window = NonZeroUsize::new(CHUNK_BYTES)
            .ok_or_else(|| DriverError::Other("object write window must be nonzero".into()))?;
        match self
            .objects
            .write_all(upload, self.size, bytes, window)
            .await
        {
            Ok(next_offset) => {
                self.size = next_offset;
                Ok(())
            }
            Err(error) => {
                self.options.taint.union(&error.taint);
                self.abort().await;
                Err(ObservedFailure::from(error).with_taint(&self.options.taint))
            }
        }
    }

    pub(crate) async fn finish(mut self) -> Result<(TaintedValue, u64), ObservedFailure> {
        if self.inline_limit == 0 && self.upload.is_none() {
            self.push(&[]).await?;
        }
        let value = if let Some(upload) = &self.upload {
            match self
                .objects
                .commit_upload(upload, &TaintSet::pristine())
                .await
            {
                Ok(metadata) => {
                    let preserves_sources = metadata.taint.contains_all(&self.options.taint);
                    self.options.taint.union(&metadata.taint);
                    if metadata.blob.size != self.size {
                        return Err(self.failure(DriverError::Other(
                            "object commit reported a different byte count".into(),
                        )));
                    }
                    if !preserves_sources {
                        return Err(self.failure(DriverError::Other(
                            "object commit lost source provenance".into(),
                        )));
                    }
                    TaintedValue::new(Value::blob(metadata.blob), metadata.taint)
                }
                Err(error) => {
                    self.options.taint.union(&error.taint);
                    self.abort().await;
                    return Err(ObservedFailure::from(error).with_taint(&self.options.taint));
                }
            }
        } else {
            let value = match String::from_utf8(self.inline) {
                Ok(text) => Value::string(text),
                Err(error) => Value::bytes(error.into_bytes()),
            };
            TaintedValue::new(value, self.options.taint)
        };
        Ok((value, self.size))
    }
}
