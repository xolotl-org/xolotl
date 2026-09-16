//! Content-addressed objects behind explicit read, upload, and delete ports.
//! Reads and deletes accept Blob, Tensor and Frame values as content references.
//! Small unary reads return bytes; large reads retain the canonical reference.
//! Stream reads emit bounded chunks without accumulating content in State.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use std::borrow::Cow;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, DriverUsage, MethodSpec, UsageDimension,
};
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{
    BlobRef, MethodId, Outcome, OutputMode, Purity, TaintSet, TaintedValue, Value, ValueView,
};

pub(crate) const BLOB_METHODS: &[MethodSpec] = &[
    MethodSpec::new("write", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("read", Purity::Pure, MethodSpec::STREAM_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

pub(crate) struct BlobDriver {
    objects: ObjectStore,
}

impl BlobDriver {
    pub(crate) fn new(objects: ObjectStore) -> Self {
        Self { objects }
    }

    async fn read(
        &self,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        let requested = blob_ref(&input)?;
        let Some(metadata) = self
            .objects
            .metadata(&requested)
            .await
            .map_err(ObservedFailure::from)?
        else {
            return Ok(DriverOutput::new(Outcome::Done(Value::null())));
        };
        if output != OutputMode::Stream && metadata.blob.size > crate::object::INLINE_BYTES as u64 {
            return Ok(DriverOutput::new(Outcome::Done(Value::blob(metadata.blob)))
                .with_taint(metadata.taint));
        }
        let mut inline = Vec::new();
        let mut taint = metadata.taint.clone().merged(&ctx.taint);
        let mut offset = 0_u64;
        let mut buffer = [0_u8; crate::object::CHUNK_BYTES];
        loop {
            let chunk = self
                .objects
                .read_chunk(&metadata.blob, offset, &mut buffer)
                .await
                .map_err(|error| ObservedFailure::from(error).with_taint(&taint))?;
            let item_taint = chunk.taint.clone().merged(&taint);
            offset = chunk
                .checked_next_offset(offset, buffer.len(), metadata.blob.size)
                .map_err(|error| ObservedFailure::from(error).with_taint(&item_taint))?;
            if output == OutputMode::Stream {
                if chunk.bytes_read != 0 {
                    ctx.emit_tainted(TaintedValue::new(
                        Value::bytes(buffer[..chunk.bytes_read].to_vec()),
                        item_taint.clone(),
                    ))
                    .await
                    .map_err(|error| {
                        ObservedFailure::from(DriverError::from(error)).with_taint(&item_taint)
                    })?;
                }
            } else {
                inline.extend_from_slice(&buffer[..chunk.bytes_read]);
                taint.union(&chunk.taint);
            }
            if chunk.end {
                break;
            }
        }
        let (value, taint) = if output == OutputMode::Stream {
            (Value::null(), TaintSet::pristine())
        } else {
            (Value::bytes(inline), taint)
        };
        Ok(DriverOutput::new(Outcome::Done(value))
            .with_taint(taint)
            .with_usage(DriverUsage::from([(UsageDimension::BYTES_READ, offset)])))
    }
}

impl BlobDriver {
    async fn execute(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        match method.get() {
            0 => {
                let bytes = match input.view() {
                    ValueView::Bytes(bytes) => bytes,
                    ValueView::Str(text) => text.as_bytes(),
                    _ => {
                        return Err(DriverError::InvalidInput(
                            "blob write requires bytes or a string".into(),
                        )
                        .into());
                    }
                };
                let mut buffer = crate::object::ObjectBuffer::new(
                    self.objects.clone(),
                    0,
                    None,
                    ctx.taint.clone(),
                );
                buffer.push(bytes).await?;
                let (value, size) = buffer.finish().await?;
                Ok(DriverOutput::new(Outcome::Done(value.value))
                    .with_taint(value.taint)
                    .with_usage(DriverUsage::from([(UsageDimension::BYTES_WRITTEN, size)])))
            }
            1 => self.read(input, output, ctx).await,
            2 => {
                let requested = blob_ref(&input)?;
                self.objects
                    .delete(&requested)
                    .await
                    .map_err(ObservedFailure::from)?;
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            }
            _ => Err(DriverError::NoSuchMethod(method).into()),
        }
    }
}

#[async_trait]
impl Driver for BlobDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match self.execute(method, input, output, ctx).await {
            Ok(output) => Ok(output),
            Err(error) => error.with_taint(&ctx.taint).into_output("object"),
        }
    }
}

fn blob_ref(input: &Value) -> Result<Cow<'_, BlobRef>, DriverError> {
    if let Some(blob) = input.backing_blob() {
        return Ok(Cow::Borrowed(blob));
    }
    let hash = input
        .as_str()
        .or_else(|| input.as_map()?.get("hash")?.as_str())
        .ok_or_else(|| DriverError::InvalidInput("expected an object reference or hash".into()))?;
    Ok(Cow::Owned(BlobRef {
        hash: hash.into(),
        size: 0,
        mime: None,
    }))
}

#[cfg(test)]
mod tests;
