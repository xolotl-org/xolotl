use super::*;
use crate::tensor::TensorDriver;
use std::num::NonZeroUsize;
use xolotl_storage_fs::FileObjectStore;

async fn put(
    driver: &IndexDriver,
    space: &str,
    id: &str,
    representation: EmbeddingRepresentation,
    metric: Option<&str>,
) -> anyhow::Result<()> {
    let prepared = driver
        .prepare(
            space,
            id.into(),
            representation,
            None,
            metric,
            &TaintSet::pristine(),
        )
        .await?;
    ensure!(driver.publish(space, prepared).await?);
    Ok(())
}

async fn query(
    driver: &IndexDriver,
    space: &str,
    representation: EmbeddingRepresentation,
) -> anyhow::Result<Vec<(String, f64)>> {
    let input: ValueMap = BTreeMap::from([
        ("space_id".into(), Value::string(space.into())),
        ("representation".into(), representation.into_value()),
    ])
    .into();
    let output = driver.search(&input, &TaintSet::pristine()).await?;
    let Outcome::Done(value) = output.outcome else {
        bail!("search failed");
    };
    value
        .as_list()
        .context("search list")?
        .iter()
        .map(|hit| {
            let fields = hit.as_map().context("hit map")?;
            let id = fields
                .get("id")
                .and_then(Value::as_str)
                .context("hit id")?
                .to_owned();
            let Some(ValueView::Float(FloatBits(score))) = fields.get("sim").map(Value::view)
            else {
                bail!("hit score");
            };
            Ok((id, score))
        })
        .collect()
}

fn sparse(index: i64, value: i64) -> EmbeddingRepresentation {
    EmbeddingRepresentation::Sparse {
        dimensions: usize::MAX,
        indices: vec![Value::integer(index)].into(),
        values: vec![Value::integer(value)].into(),
    }
}

fn multi(rows: &[&[f32]]) -> EmbeddingRepresentation {
    EmbeddingRepresentation::MultiVector(
        rows.iter()
            .map(|row| {
                Value::list(
                    row.iter()
                        .map(|value| Value::float(FloatBits(f64::from(*value))))
                        .collect(),
                )
            })
            .collect(),
    )
}

#[tokio::test]
async fn sparse_search_uses_logical_dimensions_and_explicit_space_metrics() -> anyhow::Result<()> {
    let driver = IndexDriver::new();
    for (metric, expected) in [
        ("cosine", vec![("a".into(), 1.0), ("b".into(), 0.0)]),
        ("dot", vec![("a".into(), 1.0), ("b".into(), 0.0)]),
        (
            "negative_squared_euclidean",
            vec![("a".into(), 0.0), ("b".into(), -5.0)],
        ),
    ] {
        put(&driver, metric, "a", sparse(0, 1), Some(metric)).await?;
        put(&driver, metric, "b", sparse(2, 2), Some(metric)).await?;
        ensure!(query(&driver, metric, sparse(0, 1)).await? == expected);
        ensure!(
            put(
                &driver,
                metric,
                "dense",
                EmbeddingRepresentation::Dense(vec![Value::integer(1)].into()),
                Some(metric)
            )
            .await
            .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn multi_vector_search_requires_and_applies_mean_max_cosine() -> anyhow::Result<()> {
    let driver = IndexDriver::new();
    ensure!(
        put(&driver, "multi", "a", multi(&[&[1.0, 0.0]]), None)
            .await
            .is_err()
    );
    ensure!(driver.snapshot("multi").is_none());
    put(
        &driver,
        "multi",
        "a",
        multi(&[&[1.0, 0.0], &[0.0, 1.0]]),
        Some("mean_max_cosine"),
    )
    .await?;
    put(
        &driver,
        "multi",
        "b",
        multi(&[&[1.0, 0.0]]),
        Some("mean_max_cosine"),
    )
    .await?;
    put(
        &driver,
        "multi",
        "c",
        multi(&[&[-1.0, 0.0], &[0.0, -1.0]]),
        Some("mean_max_cosine"),
    )
    .await?;
    ensure!(
        query(&driver, "multi", multi(&[&[1.0, 0.0], &[0.0, 1.0]])).await?
            == [("a".into(), 1.0), ("b".into(), 0.5), ("c".into(), 0.0)]
    );
    Ok(())
}

#[tokio::test]
async fn explicit_tensor_reader_admits_same_dense_space_without_implicit_loading()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let objects = FileObjectStore::open(directory.path())?.into_object_store();
    let output = TensorDriver::new(objects.clone())
        .call(
            MethodId::new(0),
            Value::map(BTreeMap::from([(
                "data".into(),
                Value::list(vec![Value::integer(1), Value::integer(2)]),
            )])),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    let Outcome::Done(value) = output.outcome else {
        bail!("tensor creation failed");
    };
    let ValueView::Tensor(tensor) = value.view() else {
        bail!("expected tensor reference");
    };
    let denied = IndexDriver::new();
    ensure!(
        put(
            &denied,
            "dense",
            "tensor",
            EmbeddingRepresentation::Tensor(tensor.clone()),
            None
        )
        .await
        .is_err()
    );
    ensure!(denied.snapshot("dense").is_none());
    let driver = IndexDriver::new().with_config(
        RetrievalConfig::default()
            .with_object_reader(objects)
            .with_io_window(NonZeroUsize::MIN),
    );
    put(
        &driver,
        "dense",
        "inline",
        EmbeddingRepresentation::Dense(vec![Value::integer(1), Value::integer(2)].into()),
        None,
    )
    .await?;
    put(
        &driver,
        "dense",
        "tensor",
        EmbeddingRepresentation::Tensor(tensor.clone()),
        None,
    )
    .await?;
    let hits = query(
        &driver,
        "dense",
        EmbeddingRepresentation::Tensor(tensor.clone()),
    )
    .await?;
    ensure!(hits.len() == 2 && hits[0].0 == "inline" && hits[1].0 == "tensor");
    ensure!(hits.iter().all(|(_, score)| (*score - 1.0).abs() < 1e-12));
    Ok(())
}
