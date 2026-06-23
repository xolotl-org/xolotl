//! Tensor store: `effect://tensor/write`,
//! `effect://tensor/read`, `effect://tensor/delete`.
//!
//! Tensors are stored
//! by content hash like blobs, but carry dtype + shape metadata so a reader
//! reconstructs the right view. The bytes live behind a `BlobRef`; this driver
//! persists only the `TensorRef` envelope (blob + dtype + shape) under
//! `state://tensor/<hash>` and stores the bytes through the Blob Store path.
//! State and Facts never inline tensor payloads.

use async_trait::async_trait;
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use xolotl_state::Backend;
use xolotl_types::{DType, MethodId, Outcome, OutputMode, Path, Purity, TensorRef, Value};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://tensor/<method>` Resource with public method
/// `invoke`.
pub(crate) const TENSOR_METHODS: &[MethodSpec] = &[
    MethodSpec::new("write", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

/// Drives the tensor actions over the state backend.
pub(crate) struct TensorDriver {
    state: Backend,
}

impl TensorDriver {
    /// Create a tensor driver backed by the state plane.
    pub(crate) fn new(state: Backend) -> Self {
        Self { state }
    }

    fn tensor_path(hash: &str) -> Result<Path, DriverError> {
        Path::try_new("state")
            .and_then(|path| path.try_push("tensor"))
            .and_then(|path| path.try_push_literal(hash))
            .map_err(|e| DriverError::Other(format!("invalid tensor hash {hash:?}: {e}")))
    }
}

#[async_trait]
impl Driver for TensorDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = crate::input::map(input, "tensor")?;
        match method.get() {
            // write({data:[f32...], dtype?, shape?}) → TensorRef. The bytes go
            // through the shared Blob Store path; state://tensor/* stores only
            // the TensorRef envelope.
            0 => {
                let data = match m.get("data") {
                    Some(Value::List(xs)) if !xs.is_empty() => xs,
                    Some(Value::List(_)) => {
                        return Err(DriverError::Other(
                            "tensor write requires non-empty `data` list".into(),
                        ));
                    }
                    _ => {
                        return Err(DriverError::Other(
                            "tensor write requires `data` list".into(),
                        ));
                    }
                };
                let dtype = parse_dtype(m.get("dtype"))?;
                let shape = parse_shape(m.get("shape"), data.len())?;
                validate_shape_len(&shape, data.len())?;
                let bytes = serialize_tensor_bytes(data, dtype)?;
                let blob = crate::blob::write_blob_bytes(
                    &self.state,
                    bytes,
                    Some("application/x-xolotl-tensor".into()),
                )
                .await?;
                let tensor = TensorRef {
                    blob: blob.clone(),
                    dtype,
                    shape,
                };
                let mut env = BTreeMap::new();
                env.insert("tensor".into(), Value::Tensor(tensor.clone()));
                self.state
                    .write_set(&Self::tensor_path(&blob.hash)?, Value::Map(env))
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Tensor(tensor)))
            }
            // read({hash}) → {tensor} or Null. Tensor bytes live behind the
            // returned TensorRef.blob and are read through effect://blob/read.
            1 => {
                let hash = m
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DriverError::Other("tensor read requires `hash`".into()))?;
                let v = self
                    .state
                    .read(&Self::tensor_path(hash)?)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?
                    .unwrap_or(Value::Null);
                Ok(Outcome::Done(v))
            }
            // delete({hash}): remove the TensorRef envelope. Blob GC is handled
            // by effect://blob/delete over the returned TensorRef.blob; tensor
            // delete leaves referenced blob lifetime to the blob driver.
            2 => {
                let hash = m
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DriverError::Other("tensor delete requires `hash`".into()))?;
                self.state
                    .write_delete(&Self::tensor_path(hash)?)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Null))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn parse_shape(shape: Option<&Value>, default_len: usize) -> Result<Vec<u64>, DriverError> {
    match shape {
        Some(Value::List(s)) if !s.is_empty() => s
            .iter()
            .map(|v| match v.as_int() {
                Some(i) if i > 0 => Ok(i as u64),
                _ => Err(DriverError::Other(
                    "tensor shape dimensions must be positive integers".into(),
                )),
            })
            .collect(),
        Some(Value::List(_)) => Err(DriverError::Other(
            "tensor shape must contain at least one dimension".into(),
        )),
        Some(_) => Err(DriverError::Other("tensor shape must be a list".into())),
        None => Ok(vec![default_len as u64]),
    }
}

fn parse_dtype(dtype: Option<&Value>) -> Result<DType, DriverError> {
    match dtype {
        None => Ok(DType::F32),
        Some(Value::Str(dtype)) => match dtype.as_str() {
            "f32" => Ok(DType::F32),
            "f64" => Ok(DType::F64),
            "i32" => Ok(DType::I32),
            "i64" => Ok(DType::I64),
            "u8" => Ok(DType::U8),
            other => Err(DriverError::Other(format!(
                "unsupported tensor dtype {other:?}"
            ))),
        },
        Some(_) => Err(DriverError::InvalidInput(
            "tensor dtype must be a string".into(),
        )),
    }
}

fn validate_shape_len(shape: &[u64], data_len: usize) -> Result<(), DriverError> {
    let elements = shape.iter().try_fold(1usize, |acc, dim| {
        let dim = usize::try_from(*dim).map_err(|_error| {
            DriverError::Other("tensor shape dimension is too large for this platform".into())
        })?;
        acc.checked_mul(dim)
            .ok_or_else(|| DriverError::Other("tensor shape element count overflowed".into()))
    })?;
    if elements == data_len {
        Ok(())
    } else {
        Err(DriverError::InvalidInput(format!(
            "tensor shape describes {elements} elements but data has {data_len}"
        )))
    }
}

fn serialize_tensor_bytes(data: &[Value], dtype: DType) -> Result<Vec<u8>, DriverError> {
    let mut out = Vec::new();
    for v in data {
        match dtype {
            DType::F32 => {
                let n = numeric_f64(v)?;
                out.extend_from_slice(&(n as f32).to_le_bytes());
            }
            DType::F64 => {
                let n = numeric_f64(v)?;
                out.extend_from_slice(&n.to_le_bytes());
            }
            DType::I32 => {
                let n = int_i64(v)?;
                let n = i32::try_from(n).map_err(|_error| {
                    DriverError::Other("tensor i32 element out of range".into())
                })?;
                out.extend_from_slice(&n.to_le_bytes());
            }
            DType::I64 => {
                out.extend_from_slice(&int_i64(v)?.to_le_bytes());
            }
            DType::U8 => {
                let n = int_i64(v)?;
                let n = u8::try_from(n).map_err(|_error| {
                    DriverError::Other("tensor u8 element out of range".into())
                })?;
                out.push(n);
            }
            other => {
                return Err(DriverError::Other(format!(
                    "unsupported tensor dtype {other:?}"
                )));
            }
        }
    }
    Ok(out)
}

fn numeric_f64(v: &Value) -> Result<f64, DriverError> {
    match v {
        Value::Float(xolotl_types::FloatBits(f)) => Ok(*f),
        Value::Int(i) => Ok(*i as f64),
        other => Err(DriverError::Other(format!(
            "tensor data elements must be numeric, got {other:?}"
        ))),
    }
}

fn int_i64(v: &Value) -> Result<i64, DriverError> {
    match v {
        Value::Int(i) => Ok(*i),
        other => Err(DriverError::Other(format!(
            "integer tensor data elements must be ints, got {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use std::sync::Arc;
    use xolotl_state::InMemoryBackend;
    use xolotl_types::{FloatBits, IdentityRef, ProcessId};

    fn driver() -> TensorDriver {
        TensorDriver::new(Arc::new(InMemoryBackend::new()))
    }
    fn driver_with_state(state: Backend) -> TensorDriver {
        TensorDriver::new(state)
    }
    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }
    fn data(xs: &[f32]) -> Value {
        Value::List(
            xs.iter()
                .map(|x| Value::Float(FloatBits(*x as f64)))
                .collect(),
        )
    }

    #[tokio::test]
    async fn write_then_read_roundtrips() -> Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver_with_state(state.clone());
        let mut m = BTreeMap::new();
        m.insert("data".into(), data(&[1.0, 2.0, 3.0]));
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("write tensor")?;
        let hash = match out {
            Outcome::Done(Value::Tensor(t)) => {
                ensure!(t.dtype == DType::F32, "tensor dtype: {:?}", t.dtype);
                ensure!(t.shape == vec![3], "tensor shape: {:?}", t.shape);
                ensure!(t.blob.size == 12, "tensor blob size: {}", t.blob.size);
                t.blob.hash
            }
            other => bail!("expected TensorRef, got {other:?}"),
        };
        let mut r = BTreeMap::new();
        r.insert("hash".into(), Value::Str(hash.clone()));
        let read = d
            .call(MethodId::new(1), Value::Map(r), OutputMode::Unary, &ctx())
            .await
            .context("read tensor")?;
        match read {
            Outcome::Done(Value::Map(m)) => {
                ensure!(
                    matches!(m.get("tensor"), Some(Value::Tensor(_))),
                    "expected tensor metadata"
                );
                ensure!(
                    !m.contains_key("data"),
                    "tensor envelope inlined payload bytes"
                );
            }
            other => bail!("expected tensor envelope, got {other:?}"),
        }

        let blob = crate::blob::BlobDriver::new(state);
        let bytes = blob
            .call(
                MethodId::new(1),
                Value::Map(BTreeMap::from([("hash".into(), Value::Str(hash))])),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .context("read tensor blob")?;
        match bytes {
            Outcome::Done(Value::Bytes(bytes)) => {
                ensure!(bytes.len() == 12, "tensor bytes len: {}", bytes.len());
                Ok(())
            }
            other => bail!("expected tensor bytes from blob store, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_is_content_addressed() -> Result<()> {
        let d = driver();
        let mut a = BTreeMap::new();
        a.insert("data".into(), data(&[1.0, 2.0]));
        let mut b = BTreeMap::new();
        b.insert("data".into(), data(&[1.0, 2.0]));
        let h1 = match d
            .call(MethodId::new(0), Value::Map(a), OutputMode::Unary, &ctx())
            .await
            .context("write first tensor")?
        {
            Outcome::Done(Value::Tensor(t)) => t.blob.hash,
            other => bail!("expected TensorRef, got {other:?}"),
        };
        let h2 = match d
            .call(MethodId::new(0), Value::Map(b), OutputMode::Unary, &ctx())
            .await
            .context("write second tensor")?
        {
            Outcome::Done(Value::Tensor(t)) => t.blob.hash,
            other => bail!("expected TensorRef, got {other:?}"),
        };
        ensure!(h1 == h2, "identical tensor hash mismatch: {h1} != {h2}");
        Ok(())
    }

    #[tokio::test]
    async fn non_numeric_tensor_data_is_rejected() -> Result<()> {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert(
            "data".into(),
            Value::List(vec![Value::Str("not-a-number".into())]),
        );
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "non numeric tensor data must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn malformed_dtype_is_rejected() -> Result<()> {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("data".into(), data(&[1.0]));
        m.insert("dtype".into(), Value::Int(1));
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "non-string dtype defaulted to f32");
        Ok(())
    }

    #[tokio::test]
    async fn shape_must_match_data_before_blob_write() -> Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = driver_with_state(state.clone());
        let mut m = BTreeMap::new();
        m.insert("data".into(), data(&[1.0, 2.0]));
        m.insert("shape".into(), Value::List(vec![Value::Int(3)]));
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "shape/data mismatch was accepted");
        let blob_root = Path::parse("state://blob").context("parse blob root")?;
        ensure!(
            state.read_prefix(&blob_root).await?.is_empty(),
            "tensor wrote blob state before shape validation finished"
        );
        Ok(())
    }

    #[tokio::test]
    async fn caller_tensor_hash_must_be_one_path_segment() -> Result<()> {
        let d = driver();
        let bad = Value::Map(BTreeMap::from([(
            "hash".into(),
            Value::Str("bad/hash".into()),
        )]));

        let read = d
            .call(MethodId::new(1), bad.clone(), OutputMode::Unary, &ctx())
            .await;
        ensure!(read.is_err(), "bad tensor hash read was accepted");

        let delete = d
            .call(MethodId::new(2), bad, OutputMode::Unary, &ctx())
            .await;
        ensure!(delete.is_err(), "bad tensor hash delete was accepted");
        Ok(())
    }
}
