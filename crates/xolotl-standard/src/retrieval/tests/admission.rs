use super::*;
use crate::retrieval::{
    RetrievalConfig,
    admission::{Vector, admit},
};
use std::{
    future::{Ready, ready},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use xolotl_state::{
    StateError, StateResult,
    object::{ObjectMetadata, ObjectRead, ObjectReadChunk},
};
use xolotl_types::{BlobRef, TensorRef};

struct Reader {
    bytes: Vec<u8>,
    metadata: ObjectMetadata,
    metadata_calls: AtomicUsize,
    largest_window: AtomicUsize,
    fail_at: Option<u64>,
}

impl ObjectRead for Reader {
    type Metadata<'a> = Ready<StateResult<Option<ObjectMetadata>>>;
    type ReadChunk<'a> = Ready<StateResult<ObjectReadChunk>>;

    fn metadata<'a>(&'a self, _blob: &'a BlobRef) -> Self::Metadata<'a> {
        self.metadata_calls.fetch_add(1, Ordering::Relaxed);
        ready(Ok(Some(self.metadata.clone())))
    }

    fn read_chunk<'a>(
        &'a self,
        _blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        self.largest_window
            .fetch_max(buffer.len(), Ordering::Relaxed);
        if self.fail_at.is_some_and(|failure| offset >= failure) {
            return ready(Err(
                StateError::Backend("late tensor read failed".into()).into()
            ));
        }
        let start = offset as usize;
        let bytes_read = buffer.len().min(self.bytes.len().saturating_sub(start));
        buffer[..bytes_read].copy_from_slice(&self.bytes[start..start + bytes_read]);
        let taint = if offset == 0 {
            TaintSet::of(TaintSource::Fetched {
                host: "tensor.example".into(),
            })
        } else {
            TaintSet::of(TaintSource::Protected {
                path: xolotl_types::Path::new("state"),
            })
        };
        ready(Ok(ObjectReadChunk {
            bytes_read,
            end: start + bytes_read == self.bytes.len(),
            taint,
        }))
    }
}

fn fixture(
    dtype: DType,
    shape: Vec<u64>,
    bytes: Vec<u8>,
    fail_at: Option<u64>,
) -> (TensorRef, Arc<Reader>) {
    let blob = BlobRef {
        hash: blake3::hash(&bytes).to_hex().to_string(),
        size: bytes.len() as u64,
        mime: Some("application/x-xolotl-tensor".into()),
    };
    let reader = Arc::new(Reader {
        bytes,
        metadata: ObjectMetadata {
            blob: blob.clone(),
            taint: TaintSet::of(TaintSource::AuthorConstant),
        },
        metadata_calls: AtomicUsize::new(0),
        largest_window: AtomicUsize::new(0),
        fail_at,
    });
    (TensorRef { blob, dtype, shape }, reader)
}

fn config(reader: Arc<Reader>) -> RetrievalConfig {
    RetrievalConfig::default()
        .with_object_reader(ObjectStore::new().with_read(reader))
        .with_io_window(NonZeroUsize::MIN)
        .with_work_quantum(NonZeroUsize::MIN)
}

#[tokio::test]
async fn every_tensor_dtype_decodes_through_one_byte_windows_and_retains_observations() -> Result<()>
{
    let cases = [
        (
            DType::F16,
            [
                half::f16::from_f32(1.0).to_le_bytes(),
                half::f16::from_f32(2.0).to_le_bytes(),
            ]
            .concat(),
            vec![1.0, 2.0],
        ),
        (
            DType::Bf16,
            [
                half::bf16::from_f32(1.0).to_le_bytes(),
                half::bf16::from_f32(2.0).to_le_bytes(),
            ]
            .concat(),
            vec![1.0, 2.0],
        ),
        (
            DType::F32,
            [1.0_f32.to_le_bytes(), 2.0_f32.to_le_bytes()].concat(),
            vec![1.0, 2.0],
        ),
        (
            DType::F64,
            [1.0_f64.to_le_bytes(), 2.0_f64.to_le_bytes()].concat(),
            vec![1.0, 2.0],
        ),
        (DType::I8, vec![255, 2], vec![-1.0, 2.0]),
        (
            DType::I16,
            [(-1_i16).to_le_bytes(), 2_i16.to_le_bytes()].concat(),
            vec![-1.0, 2.0],
        ),
        (
            DType::I32,
            [(-1_i32).to_le_bytes(), 2_i32.to_le_bytes()].concat(),
            vec![-1.0, 2.0],
        ),
        (
            DType::I64,
            [(-1_i64).to_le_bytes(), 2_i64.to_le_bytes()].concat(),
            vec![-1.0, 2.0],
        ),
        (DType::U8, vec![1, 255], vec![1.0, 255.0]),
        (DType::Bool, vec![0, 1], vec![0.0, 1.0]),
    ];
    for (dtype, bytes, expected) in cases {
        let (tensor, reader) = fixture(dtype, vec![2], bytes, None);
        let admitted = admit(
            EmbeddingRepresentation::Tensor(tensor),
            &config(reader.clone()),
            &TaintSet::of(TaintSource::ModelOutput),
        )
        .await?;
        ensure!(
            admitted.vector.dense() == Some(expected.as_slice()),
            "wrong {dtype:?} values"
        );
        ensure!(reader.largest_window.load(Ordering::Relaxed) == 1);
        ensure!(admitted.taint.sources().contains(&TaintSource::ModelOutput));
        ensure!(
            admitted
                .taint
                .sources()
                .contains(&TaintSource::AuthorConstant)
        );
        ensure!(admitted.taint.sources().contains(&TaintSource::Fetched {
            host: "tensor.example".into()
        }));
        ensure!(admitted.taint.has_protected());
    }
    Ok(())
}

#[tokio::test]
async fn tensor_shape_and_reader_requirements_fail_before_observing_object_content() -> Result<()> {
    for shape in [vec![1, 2], vec![0], vec![3], vec![u64::MAX]] {
        let (tensor, reader) = fixture(DType::F32, shape, vec![0; 8], None);
        ensure!(
            admit(
                EmbeddingRepresentation::Tensor(tensor),
                &config(reader.clone()),
                &TaintSet::pristine()
            )
            .await
            .is_err()
        );
        ensure!(reader.metadata_calls.load(Ordering::Relaxed) == 0);
    }
    let (tensor, reader) = fixture(DType::F32, vec![2], vec![0; 8], None);
    ensure!(
        admit(
            EmbeddingRepresentation::Tensor(tensor),
            &RetrievalConfig::default(),
            &TaintSet::pristine()
        )
        .await
        .is_err()
    );
    ensure!(reader.metadata_calls.load(Ordering::Relaxed) == 0);
    Ok(())
}

#[tokio::test]
async fn tensor_failures_keep_metadata_and_all_earlier_chunk_sources() -> Result<()> {
    let (tensor, reader) = fixture(DType::F32, vec![2], vec![0; 8], Some(4));
    let error = admit(
        EmbeddingRepresentation::Tensor(tensor),
        &config(reader),
        &TaintSet::of(TaintSource::ModelOutput),
    )
    .await
    .err()
    .context("late read unexpectedly succeeded")?;
    ensure!(error.error.to_string().contains("late tensor read"));
    ensure!(error.taint.has_protected());
    ensure!(error.taint.sources().contains(&TaintSource::AuthorConstant));
    ensure!(error.taint.sources().contains(&TaintSource::ModelOutput));
    ensure!(matches!(
        error.into_output("retrieval")?.outcome,
        Outcome::Fail(_)
    ));

    let (mut tensor, reader) = fixture(DType::F32, vec![2], vec![0; 8], None);
    tensor.blob.mime = Some("different/mime".into());
    let error = admit(
        EmbeddingRepresentation::Tensor(tensor),
        &config(reader.clone()),
        &TaintSet::pristine(),
    )
    .await
    .err()
    .context("complete reference mismatch accepted")?;
    ensure!(error.taint == TaintSet::of(TaintSource::AuthorConstant));
    ensure!(reader.largest_window.load(Ordering::Relaxed) == 0);
    Ok(())
}

#[tokio::test]
async fn tensor_and_inline_numeric_rejections_preserve_input_and_read_sources() -> Result<()> {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MAX] {
        let input_taint = TaintSet::of(TaintSource::ModelOutput);
        let error = admit(
            EmbeddingRepresentation::Dense(vec![Value::float(FloatBits(value))].into()),
            &RetrievalConfig::default(),
            &input_taint,
        )
        .await
        .err()
        .context("invalid inline value accepted")?;
        ensure!(error.taint == input_taint);
        let (tensor, reader) = fixture(DType::F64, vec![1], value.to_le_bytes().to_vec(), None);
        let error = admit(
            EmbeddingRepresentation::Tensor(tensor),
            &config(reader),
            &input_taint,
        )
        .await
        .err()
        .context("invalid tensor value accepted")?;
        ensure!(
            error.taint.has_protected()
                && error.taint.sources().contains(&TaintSource::ModelOutput)
        );
    }
    let (tensor, reader) = fixture(DType::Bool, vec![2], vec![0, 2], None);
    let error = admit(
        EmbeddingRepresentation::Tensor(tensor),
        &config(reader),
        &TaintSet::pristine(),
    )
    .await
    .err()
    .context("invalid boolean byte accepted")?;
    ensure!(error.error.to_string().contains("non-boolean"));
    ensure!(error.taint.has_protected());
    Ok(())
}

#[tokio::test]
async fn sparse_dimensions_are_logical_and_coordinates_are_strictly_validated() -> Result<()> {
    let representation = EmbeddingRepresentation::Sparse {
        dimensions: usize::MAX,
        indices: vec![Value::string((usize::MAX - 1).to_string())].into(),
        values: vec![Value::integer(7)].into(),
    };
    let parsed = EmbeddingRepresentation::from_value(representation.into_value())
        .map_err(anyhow::Error::msg)?;
    let admitted = admit(parsed, &RetrievalConfig::default(), &TaintSet::pristine()).await?;
    let Vector::Sparse {
        dimensions,
        indices,
        values,
        ..
    } = admitted.vector
    else {
        bail!("expected sparse vector");
    };
    ensure!(dimensions == usize::MAX && indices == [usize::MAX - 1] && values == [7.0]);
    for indices in [vec![0, 0], vec![2, 1], vec![-1, 0], vec![0, 4]] {
        let representation = EmbeddingRepresentation::Sparse {
            dimensions: 4,
            indices: indices.into_iter().map(Value::integer).collect(),
            values: vec![Value::integer(1); 2].into(),
        };
        ensure!(
            admit(
                representation,
                &RetrievalConfig::default(),
                &TaintSet::pristine()
            )
            .await
            .is_err()
        );
    }
    let zero = admit(
        EmbeddingRepresentation::Sparse {
            dimensions: usize::MAX,
            indices: Vec::new().into(),
            values: Vec::new().into(),
        },
        &RetrievalConfig::default(),
        &TaintSet::pristine(),
    )
    .await?;
    ensure!(zero.vector.dimensions() == usize::MAX);
    Ok(())
}

#[tokio::test]
async fn multi_tensor_and_inline_rows_share_the_same_numeric_layout() -> Result<()> {
    let values = [1.0_f32, 0.0, 0.0, -2.0, 3.0, 4.0];
    let rows = values
        .chunks(2)
        .map(|row| {
            Value::list(
                row.iter()
                    .map(|number| Value::float(FloatBits(f64::from(*number))))
                    .collect(),
            )
        })
        .collect();
    let inline = admit(
        EmbeddingRepresentation::MultiVector(rows),
        &RetrievalConfig::default(),
        &TaintSet::pristine(),
    )
    .await?;
    let bytes = values
        .iter()
        .flat_map(|number| number.to_le_bytes())
        .collect();
    let (tensor, reader) = fixture(DType::F32, vec![3, 2], bytes, None);
    let tensor = admit(
        EmbeddingRepresentation::MultiTensor(tensor),
        &config(reader),
        &TaintSet::pristine(),
    )
    .await?;
    let (
        Vector::Multi {
            dimensions: a,
            values: av,
            inverse_norms: an,
        },
        Vector::Multi {
            dimensions: b,
            values: bv,
            inverse_norms: bn,
        },
    ) = (inline.vector, tensor.vector)
    else {
        bail!("expected multi-vector layout");
    };
    ensure!(a == b && av == bv && an == bn);
    for rows in [
        vec![],
        vec![Value::list(vec![])],
        vec![
            Value::list(vec![Value::integer(1)]),
            Value::list(vec![Value::integer(1), Value::integer(2)]),
        ],
    ] {
        ensure!(
            admit(
                EmbeddingRepresentation::MultiVector(rows.into()),
                &RetrievalConfig::default(),
                &TaintSet::pristine()
            )
            .await
            .is_err()
        );
    }
    Ok(())
}
