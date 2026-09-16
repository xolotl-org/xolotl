//! Consumer-specific precision, sparse invariants, and explicit tensor reads.

use super::{EmbeddingRepresentation, RetrievalConfig};
use crate::error::ObservedFailure;
use xolotl_kernel::DriverError;
use xolotl_types::{DType, FloatBits, TaintSet, TensorRef, Value, ValueList, ValueView};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    Dense,
    Sparse,
    Multi,
}

#[derive(Clone, Debug)]
pub(crate) enum Vector {
    Dense {
        values: Vec<f32>,
        inverse_norm: f64,
    },
    Sparse {
        dimensions: usize,
        indices: Vec<usize>,
        values: Vec<f32>,
        inverse_norm: f64,
    },
    Multi {
        dimensions: usize,
        values: Vec<f32>,
        inverse_norms: Vec<f64>,
    },
}

impl Vector {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Dense { .. } => Family::Dense,
            Self::Sparse { .. } => Family::Sparse,
            Self::Multi { .. } => Family::Multi,
        }
    }

    pub(crate) fn dimensions(&self) -> usize {
        match self {
            Self::Dense { values, .. } => values.len(),
            Self::Sparse { dimensions, .. } | Self::Multi { dimensions, .. } => *dimensions,
        }
    }

    pub(crate) fn dense(&self) -> Option<&[f32]> {
        match self {
            Self::Dense { values, .. } => Some(values),
            _ => None,
        }
    }
}

pub(crate) struct AdmittedVector {
    pub(crate) vector: Vector,
    pub(crate) taint: TaintSet,
}

pub(crate) fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::InvalidInput(message.into())
}

/// Counting scalar work keeps one extreme-dimensional vector cancellable too.
pub(crate) struct Work {
    quantum: usize,
    remaining: usize,
}

impl Work {
    pub(crate) fn new(config: &RetrievalConfig) -> Self {
        Self {
            quantum: config.work_quantum.get(),
            remaining: config.work_quantum.get(),
        }
    }

    pub(crate) async fn tick(&mut self) {
        self.remaining -= 1;
        if self.remaining == 0 {
            self.remaining = self.quantum;
            tokio::task::yield_now().await;
        }
    }
}

pub(crate) async fn admit(
    representation: EmbeddingRepresentation,
    config: &RetrievalConfig,
    input_taint: &TaintSet,
) -> Result<AdmittedVector, ObservedFailure> {
    admit_inner(representation, config, input_taint)
        .await
        .map_err(|error| error.with_taint(input_taint))
}

async fn admit_inner(
    representation: EmbeddingRepresentation,
    config: &RetrievalConfig,
    input_taint: &TaintSet,
) -> Result<AdmittedVector, ObservedFailure> {
    let mut work = Work::new(config);
    let mut taint = input_taint.clone();
    let vector = match representation {
        EmbeddingRepresentation::Dense(values) => {
            let values = numbers(&values, &mut work).await?;
            if values.is_empty() {
                return Err(invalid("dense vectors must not be empty").into());
            }
            let inverse_norm = inverse_norm(&values, &mut work).await;
            Vector::Dense {
                values,
                inverse_norm,
            }
        }
        EmbeddingRepresentation::Tensor(tensor) => {
            let (values, _) = read_tensor(&tensor, 1, config, &mut taint, &mut work).await?;
            let inverse_norm = inverse_norm(&values, &mut work).await;
            Vector::Dense {
                values,
                inverse_norm,
            }
        }
        EmbeddingRepresentation::Sparse {
            dimensions,
            indices,
            values,
        } => {
            if dimensions == 0 || indices.len() != values.len() {
                return Err(invalid(
                    "sparse coordinates and values require equal lengths and positive dimensions",
                )
                .into());
            }
            let mut admitted_indices = Vec::new();
            for index in &indices {
                let index = index
                    .as_int()
                    .and_then(|index| usize::try_from(index).ok())
                    .or_else(|| index.as_str().and_then(|index| index.parse().ok()))
                    .filter(|index| *index < dimensions)
                    .ok_or_else(|| invalid("sparse coordinate is outside its logical dimension"))?;
                if admitted_indices
                    .last()
                    .is_some_and(|previous| *previous >= index)
                {
                    return Err(invalid(
                        "sparse coordinates must be strictly increasing and unique",
                    )
                    .into());
                }
                admitted_indices.push(index);
                work.tick().await;
            }
            let values = numbers(&values, &mut work).await?;
            let inverse_norm = inverse_norm(&values, &mut work).await;
            Vector::Sparse {
                dimensions,
                indices: admitted_indices,
                values,
                inverse_norm,
            }
        }
        EmbeddingRepresentation::MultiVector(rows) => {
            if rows.is_empty() {
                return Err(invalid("multi-vector embeddings require at least one row").into());
            }
            let mut dimensions = None;
            let mut values = Vec::new();
            let mut inverse_norms = Vec::new();
            for row in &rows {
                let row = row
                    .as_list()
                    .ok_or_else(|| invalid("multi-vector rows must be lists"))?;
                if row.is_empty() || dimensions.is_some_and(|dimensions| dimensions != row.len()) {
                    return Err(
                        invalid("multi-vector rows require equal positive dimensions").into(),
                    );
                }
                dimensions = Some(row.len());
                let row = numbers(row, &mut work).await?;
                inverse_norms.push(inverse_norm(&row, &mut work).await);
                values.extend(row);
            }
            Vector::Multi {
                dimensions: dimensions.unwrap_or(0),
                values,
                inverse_norms,
            }
        }
        EmbeddingRepresentation::MultiTensor(tensor) => {
            let (values, dimensions) =
                read_tensor(&tensor, 2, config, &mut taint, &mut work).await?;
            let mut inverse_norms = Vec::new();
            for row in values.chunks(dimensions) {
                inverse_norms.push(inverse_norm(row, &mut work).await);
            }
            Vector::Multi {
                dimensions,
                values,
                inverse_norms,
            }
        }
    };
    Ok(AdmittedVector { vector, taint })
}

async fn numbers(values: &ValueList, work: &mut Work) -> Result<Vec<f32>, DriverError> {
    let mut admitted = Vec::new();
    for value in values {
        admitted.push(number(value)?);
        work.tick().await;
    }
    Ok(admitted)
}

fn number(value: &Value) -> Result<f32, DriverError> {
    match value.view() {
        ValueView::Int(value) => Ok(value as f32),
        ValueView::Float(FloatBits(value)) => finite(value),
        _ => Err(invalid("index values must be numeric")),
    }
}

fn finite(value: f64) -> Result<f32, DriverError> {
    if value.is_finite() && value.abs() <= f64::from(f32::MAX) {
        Ok(value as f32)
    } else {
        Err(invalid(
            "index values must be finite and representable as f32",
        ))
    }
}

async fn inverse_norm(values: &[f32], work: &mut Work) -> f64 {
    let mut squared = 0.0_f64;
    for value in values {
        let value = f64::from(*value);
        squared += value * value;
        work.tick().await;
    }
    if squared == 0.0 {
        0.0
    } else {
        1.0 / squared.sqrt()
    }
}

async fn read_tensor(
    tensor: &TensorRef,
    rank: usize,
    config: &RetrievalConfig,
    taint: &mut TaintSet,
    work: &mut Work,
) -> Result<(Vec<f32>, usize), ObservedFailure> {
    let result = read_tensor_inner(tensor, rank, config, taint, work).await;
    result.map_err(|error| ObservedFailure::from(error).with_taint(taint))
}

async fn read_tensor_inner(
    tensor: &TensorRef,
    rank: usize,
    config: &RetrievalConfig,
    taint: &mut TaintSet,
    work: &mut Work,
) -> Result<(Vec<f32>, usize), DriverError> {
    if !config.objects.can_read() {
        return Err(invalid(
            "tensor retrieval requires an explicitly installed object reader",
        ));
    }
    if tensor.shape.len() != rank || tensor.shape.contains(&0) {
        return Err(invalid(
            "retrieval tensor has incompatible rank or empty dimensions",
        ));
    }
    let dimensions = tensor
        .shape
        .last()
        .copied()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| invalid("tensor dimension does not fit this platform"))?;
    let elements = tensor
        .shape
        .iter()
        .try_fold(1_u64, |product, value| product.checked_mul(*value))
        .ok_or_else(|| invalid("tensor element count overflow"))?;
    let bytes = element_bytes(tensor.dtype);
    if elements.checked_mul(bytes as u64) != Some(tensor.blob.size) {
        return Err(invalid("tensor shape and dtype do not match its byte size"));
    }
    let metadata = config
        .objects
        .metadata(&tensor.blob)
        .await
        .map_err(|error| object_error(error, taint))?
        .ok_or_else(|| invalid("tensor object is unavailable"))?;
    taint.union(&metadata.taint);
    if metadata.blob != tensor.blob {
        return Err(invalid(
            "tensor object metadata does not match its complete reference",
        ));
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(config.io_window.get())
        .map_err(|error| DriverError::Other(format!("tensor window allocation failed: {error}")))?;
    buffer.resize(config.io_window.get(), 0);
    let mut scalar = [0_u8; 8];
    let mut scalar_len = 0;
    let mut values = Vec::new();
    let mut offset = 0;
    loop {
        let chunk = config
            .objects
            .read_chunk(&metadata.blob, offset, &mut buffer)
            .await
            .map_err(|error| object_error(error, taint))?;
        taint.union(&chunk.taint);
        offset = chunk
            .checked_next_offset(offset, buffer.len(), metadata.blob.size)
            .map_err(|error| object_error(error, taint))?;
        for byte in &buffer[..chunk.bytes_read] {
            scalar[scalar_len] = *byte;
            scalar_len += 1;
            if scalar_len == bytes {
                values.push(decode(tensor.dtype, scalar)?);
                scalar_len = 0;
                work.tick().await;
            }
        }
        if chunk.end {
            break;
        }
    }
    if scalar_len != 0 || u64::try_from(values.len()).ok() != Some(elements) {
        return Err(invalid("tensor object ended inside an element"));
    }
    Ok((values, dimensions))
}

fn element_bytes(dtype: DType) -> usize {
    match dtype {
        DType::F64 | DType::I64 => 8,
        DType::F32 | DType::I32 => 4,
        DType::F16 | DType::Bf16 | DType::I16 => 2,
        DType::I8 | DType::U8 | DType::Bool => 1,
    }
}

fn decode(dtype: DType, bytes: [u8; 8]) -> Result<f32, DriverError> {
    Ok(match dtype {
        DType::F64 => finite(f64::from_le_bytes(bytes))?,
        DType::F32 => finite(f64::from(f32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ])))?,
        DType::F16 => finite(f64::from(
            half::f16::from_le_bytes([bytes[0], bytes[1]]).to_f32(),
        ))?,
        DType::Bf16 => finite(f64::from(
            half::bf16::from_le_bytes([bytes[0], bytes[1]]).to_f32(),
        ))?,
        DType::I64 => i64::from_le_bytes(bytes) as f32,
        DType::I32 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f32,
        DType::I16 => f32::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        DType::I8 => f32::from(bytes[0] as i8),
        DType::U8 => f32::from(bytes[0]),
        DType::Bool if bytes[0] <= 1 => f32::from(bytes[0]),
        DType::Bool => return Err(invalid("boolean tensor contains a non-boolean byte")),
    })
}

fn object_error(error: xolotl_state::StateFailure, taint: &mut TaintSet) -> DriverError {
    taint.union(&error.taint);
    DriverError::Other(format!("retrieval object read failed: {}", error.error))
}
