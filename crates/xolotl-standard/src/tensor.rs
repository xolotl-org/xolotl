//! Numeric tensor materialization through `effect://tensor/write`.
//!
//! The returned TensorRef owns its dtype and shape interpretation. Only bytes
//! are published to the installed object writer; no State catalog is required.
//! Byte reads and deletion use the independent Blob capabilities. Applications
//! can persist complete references under their own State paths when needed.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, DriverUsage, MethodSpec, UsageDimension,
};
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, TensorRef, Value, ValueView};

mod encode;
use encode::Encoding;

pub(crate) const TENSOR_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "write",
    Purity::Idempotent,
    MethodSpec::UNARY_ASYNC,
)];

pub(crate) struct TensorDriver {
    objects: ObjectStore,
}

impl TensorDriver {
    pub(crate) fn new(objects: ObjectStore) -> Self {
        Self { objects }
    }
}

impl TensorDriver {
    async fn execute(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method).into());
        }
        let fields = crate::input::map(input, "tensor")?;
        let Some(data) = fields.get("data").and_then(Value::as_list) else {
            return Err(
                DriverError::InvalidInput("tensor write requires a data list".into()).into(),
            );
        };
        let encoding = Encoding::new(data.len(), fields.get("dtype"), fields.get("shape"))?;
        let chunk_elements = crate::object::CHUNK_BYTES / encoding.element_bytes();
        let mut bytes =
            Vec::with_capacity(data.len().min(chunk_elements) * encoding.element_bytes());
        let mut buffer = crate::object::ObjectBuffer::new(
            self.objects.clone(),
            0,
            Some("application/x-xolotl-tensor".into()),
            ctx.taint.clone(),
        );
        let mut data = data.iter();
        while data.len() > 0 {
            if let Err(error) = encoding.encode(data.by_ref().take(chunk_elements), &mut bytes) {
                buffer.abort().await;
                return Err(buffer.failure(error));
            }
            buffer.push(&bytes).await?;
        }
        let (value, size) = buffer.finish().await?;
        let ValueView::Blob(blob) = value.value.view() else {
            return Err(ObservedFailure::from(DriverError::Other(
                "tensor upload returned inline content".into(),
            ))
            .with_taint(&value.taint));
        };
        let tensor = TensorRef {
            blob: blob.clone(),
            dtype: encoding.dtype,
            shape: encoding.shape,
        };
        Ok(DriverOutput::new(Outcome::Done(Value::from(tensor)))
            .with_taint(value.taint)
            .with_usage(DriverUsage::from([(UsageDimension::BYTES_WRITTEN, size)])))
    }
}

#[async_trait]
impl Driver for TensorDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match self.execute(method, input, output, ctx).await {
            Ok(output) => Ok(output),
            Err(error) => error.with_taint(&ctx.taint).into_output("tensor"),
        }
    }
}

#[cfg(test)]
mod tests;
