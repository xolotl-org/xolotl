use super::{Embedding, EmbeddingRepresentation};
use crate::{inference::InferenceDriver, tensor::TensorDriver};
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext};
use xolotl_state::host::object::ObjectStore;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{
    DType, FloatBits, IdentityRef, MethodId, Outcome, OutputMode, ProcessId, TaintSet, TaintSource,
    Value,
};

mod admission;

fn context() -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
}

#[test]
fn inline_envelope_shares_vector_and_metadata_allocations() -> Result<()> {
    let vector: xolotl_types::ValueList =
        vec![Value::float(FloatBits(0.25)), Value::float(FloatBits(-0.5))].into();
    let vector_owner = Value::from(vector.clone());
    let mut space_id = String::with_capacity(64);
    space_id.push_str("embedding/allocation-test");
    let space_ptr = space_id.as_ptr();
    let mut model = String::with_capacity(64);
    model.push_str("model/allocation-test");
    let model_ptr = model.as_ptr();

    let value = Embedding {
        representation: EmbeddingRepresentation::Dense(vector),
        space_id: space_id.into(),
        embedding_model: Some(model.into()),
    }
    .into_value();
    let map = value.as_map().context("missing inline envelope")?;
    ensure!(map.len() == 3 && map.get("tensor").is_none());
    let vector_value = map
        .get("representation")
        .and_then(Value::as_map)
        .and_then(|fields| fields.get("values"))
        .context("missing inline vector")?;
    ensure!(vector_value.identity() == vector_owner.identity());
    ensure!(map.get("space_id").and_then(Value::as_str).map(str::as_ptr) == Some(space_ptr));
    ensure!(
        map.get("embedding_model")
            .and_then(Value::as_str)
            .map(str::as_ptr)
            == Some(model_ptr)
    );

    let decoded = Embedding::from_value(value).map_err(anyhow::Error::msg)?;
    let EmbeddingRepresentation::Dense(vector) = decoded.representation else {
        bail!("expected dense representation")
    };
    let decoded_vector = Value::from(vector);
    ensure!(decoded_vector.identity() == vector_owner.identity());
    ensure!(decoded_vector == vector_owner);
    ensure!(decoded.space_id.as_str() == "embedding/allocation-test");
    ensure!(decoded.space_id.as_ptr() == space_ptr);
    let model = decoded.embedding_model.context("missing embedding model")?;
    ensure!(model.as_str() == "model/allocation-test");
    ensure!(model.as_ptr() == model_ptr);
    Ok(())
}

#[tokio::test]
async fn echo_embedding_can_be_materialized_as_f32_or_f64() -> Result<()> {
    let output = InferenceDriver::baseline()
        .call(
            MethodId::new(1),
            Value::string("materialize this embedding".into()),
            OutputMode::Unary,
            &context(),
        )
        .await?;
    ensure!(output.taint == TaintSet::of(TaintSource::ModelOutput));
    let Outcome::Done(value) = output.outcome else {
        bail!("embedding did not finish");
    };
    let Some(vector) = value
        .as_map()
        .and_then(|map| map.get("representation"))
        .and_then(Value::as_map)
        .and_then(|map| map.get("values"))
        .and_then(Value::as_list)
    else {
        bail!("embedding did not return an inline vector");
    };
    let expected = vector
        .iter()
        .map(|value| match value.view() {
            xolotl_types::ValueView::Float(FloatBits(number)) => Ok(number),
            other => bail!("expected embedding number, got {other:?}"),
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(expected.len() == 8);
    assert_materialized_embedding(value, &expected).await
}

#[tokio::test]
async fn explicit_materialization_crosses_multiple_object_windows() -> Result<()> {
    let expected: Vec<_> = (0..8195)
        .map(|index| (f64::from(index) - 4096.0) / 7.0)
        .collect();
    ensure!(expected.len() * std::mem::size_of::<f32>() > 2 * crate::object::CHUNK_BYTES);
    ensure!(
        expected
            .iter()
            .any(|number| f64::from(*number as f32) != *number)
    );
    let value = Embedding {
        representation: EmbeddingRepresentation::Dense(
            expected
                .iter()
                .map(|number| Value::float(FloatBits(*number)))
                .collect(),
        ),
        space_id: "embedding/window-test".into(),
        embedding_model: Some("model/window-test".into()),
    }
    .into_value();
    assert_materialized_embedding(value, &expected).await
}

#[tokio::test]
async fn explicit_materialization_requires_an_object_writer() -> Result<()> {
    let output = InferenceDriver::baseline()
        .call(
            MethodId::new(1),
            Value::string("embedding without object capabilities".into()),
            OutputMode::Unary,
            &context(),
        )
        .await?;
    let Outcome::Done(value) = output.outcome else {
        bail!("embedding did not finish");
    };
    let embedding = Embedding::from_value(value).map_err(anyhow::Error::msg)?;
    let EmbeddingRepresentation::Dense(vector) = embedding.representation else {
        bail!("expected dense representation")
    };
    let driver = TensorDriver::new(ObjectStore::new());
    let result = driver
        .call(
            MethodId::new(0),
            Value::map(BTreeMap::from([("data".into(), Value::from(vector))])),
            OutputMode::Unary,
            &context().with_taint(output.taint),
        )
        .await;
    let error = match result {
        Err(error) => error.to_string(),
        Ok(output) => {
            ensure!(output.taint.sources().contains(&TaintSource::ModelOutput));
            let Outcome::Fail(failure) = output.outcome else {
                bail!("materialized tensor without an object writer");
            };
            failure.to_string()
        }
    };
    ensure!(error.contains("object.write"), "unexpected error: {error}");
    Ok(())
}

pub(crate) async fn assert_materialized_embedding(
    embedding: Value,
    expected: &[f64],
) -> Result<()> {
    ensure!(!expected.is_empty());
    ensure!(
        embedding
            .as_map()
            .context("missing embedding map")?
            .get("tensor")
            .is_none(),
        "inline embedding invented a tensor reference"
    );
    let embedding = Embedding::from_value(embedding).map_err(anyhow::Error::msg)?;
    let EmbeddingRepresentation::Dense(vector) = embedding.representation else {
        bail!("expected dense representation")
    };
    ensure!(vector.len() == expected.len());
    for (value, number) in vector.iter().zip(expected) {
        ensure!(
            value == &Value::float(FloatBits(*number)),
            "embedding precision changed"
        );
    }

    let directory = tempfile::tempdir()?;
    let objects = FileObjectStore::open(directory.path())?.into_object_store();
    let driver = TensorDriver::new(objects.clone());
    let taint = TaintSet::of(TaintSource::ModelOutput);
    let write_context = context().with_taint(taint.clone());
    for (name, dtype, vector) in [
        ("f32", DType::F32, vector.clone()),
        ("f64", DType::F64, vector),
    ] {
        let expected_bytes: Vec<_> = if dtype == DType::F32 {
            expected
                .iter()
                .flat_map(|number| (*number as f32).to_le_bytes())
                .collect()
        } else {
            expected
                .iter()
                .flat_map(|number| number.to_le_bytes())
                .collect()
        };
        let output = driver
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::from([
                    ("data".into(), Value::from(vector)),
                    ("dtype".into(), Value::string(name.into())),
                ])),
                OutputMode::Unary,
                &write_context,
            )
            .await
            .with_context(|| format!("materialize {name} embedding"))?;
        ensure!(output.taint == taint, "{name} output lost embedding taint");
        let Outcome::Done(tensor_value) = output.outcome else {
            bail!("expected a materialized {name} tensor");
        };
        let xolotl_types::ValueView::Tensor(tensor) = tensor_value.view() else {
            bail!("expected tensor");
        };
        ensure!(tensor.dtype == dtype);
        ensure!(tensor.shape == [expected.len() as u64]);
        ensure!(tensor.blob.size == expected_bytes.len() as u64);
        ensure!(tensor.blob.hash == blake3::hash(&expected_bytes).to_hex().as_str());
        ensure!(tensor.blob.mime.as_deref() == Some("application/x-xolotl-tensor"));

        let metadata = objects
            .metadata(&tensor.blob)
            .await?
            .context("missing tensor object")?;
        ensure!(metadata.blob == tensor.blob);
        ensure!(metadata.taint == taint);
        let mut buffer = [0_u8; 1003];
        let mut offset = 0;
        loop {
            let read = objects
                .read_chunk(&tensor.blob, offset as u64, &mut buffer)
                .await?;
            ensure!(
                read.taint == taint,
                "{name} object read lost embedding taint"
            );
            ensure!(read.bytes_read <= buffer.len());
            ensure!(
                read.bytes_read > 0 || read.end,
                "object read did not progress"
            );
            let end = offset + read.bytes_read;
            ensure!(
                end <= expected_bytes.len(),
                "object read exceeded tensor size"
            );
            ensure!(
                buffer[..read.bytes_read] == expected_bytes[offset..end],
                "{name} tensor bytes differ at offset {offset}"
            );
            offset = end;
            if read.end {
                break;
            }
        }
        ensure!(
            offset == expected_bytes.len(),
            "incomplete {name} tensor read"
        );
    }
    Ok(())
}
