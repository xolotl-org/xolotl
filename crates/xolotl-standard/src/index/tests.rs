use super::storage::{ANN_CANDIDATE_FLOOR, ANN_CANDIDATE_MULTIPLIER, EXACT_SEARCH_LIMIT};
use super::*;
use anyhow::{Context, bail, ensure};
use xolotl_types::{IdentityRef, ProcessId};

mod concurrency;
mod representations;

fn vec_val(xs: &[f32]) -> Value {
    EmbeddingRepresentation::Dense(
        xs.iter()
            .map(|x| Value::float(FloatBits(f64::from(*x))))
            .collect(),
    )
    .into_value()
}

async fn upsert(d: &IndexDriver, space: &str, id: &str, vector: &[f32]) -> anyhow::Result<()> {
    let input = Value::map(BTreeMap::from([
        ("space_id".into(), Value::string(space.into())),
        ("id".into(), Value::string(id.into())),
        ("representation".into(), vec_val(vector)),
    ]));
    d.call(MethodId::new(0), input, OutputMode::Unary, &ctx())
        .await?;
    Ok(())
}

async fn search(
    driver: &IndexDriver,
    space: &str,
    query: &[f32],
    k: i64,
) -> anyhow::Result<Vec<Value>> {
    search_with_mode(driver, space, query, k, None).await
}

async fn search_with_mode(
    driver: &IndexDriver,
    space: &str,
    query: &[f32],
    k: i64,
    mode: Option<&str>,
) -> anyhow::Result<Vec<Value>> {
    let mut fields = BTreeMap::from([
        ("space_id".into(), Value::string(space.into())),
        ("representation".into(), vec_val(query)),
        ("k".into(), Value::integer(k)),
    ]);
    if let Some(mode) = mode {
        fields.insert("mode".into(), Value::string(mode.into()));
    }
    match driver
        .call(
            MethodId::new(1),
            Value::map(fields),
            OutputMode::Unary,
            &ctx(),
        )
        .await?
        .outcome
    {
        Outcome::Done(value) => Ok(value
            .as_list()
            .context("expected search results")?
            .iter()
            .cloned()
            .collect()),
        other => bail!("expected ranked list, got {other:?}"),
    }
}

fn ctx() -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
}

fn patterned_vec(i: usize) -> Vec<f32> {
    (0..8)
        .map(|dim| {
            let n = ((i * 31) + (dim * 17)) % 97;
            (n as f32 / 48.0) - 1.0
        })
        .collect()
}

#[tokio::test]
async fn search_ranks_nearest_in_space() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "a", &[1.0, 0.0, 0.0]).await?;
    upsert(&d, "s1", "b", &[0.0, 1.0, 0.0]).await?;
    upsert(&d, "s1", "c", &[0.9, 0.1, 0.0]).await?;
    let results = search(&d, "s1", &[1.0, 0.0, 0.0], 2).await?;
    ensure!(results.len() == 2);
    let first = results
        .first()
        .and_then(Value::as_map)
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_str);
    ensure!(first == Some("a"), "expected nearest id a, got {first:?}");
    Ok(())
}

#[tokio::test]
async fn large_search_defaults_to_bounded_ann_and_can_request_exact() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    for i in 0..(EXACT_SEARCH_LIMIT + 256) {
        upsert(&d, "big", &format!("v{i}"), &patterned_vec(i)).await?;
    }
    let results = search(&d, "big", &patterned_vec(17), 10).await?;
    ensure!(results.len() == 10, "expected 10 ANN results");
    let examined = d.last_search_examined.load(Ordering::Relaxed);
    ensure!(
        examined <= ANN_CANDIDATE_FLOOR.max(10 * ANN_CANDIDATE_MULTIPLIER),
        "large search examined {examined} candidates"
    );
    ensure!(search_with_mode(&d, "big", &patterned_vec(17), 10, Some("auto")).await? == results);
    let exact = search_with_mode(&d, "big", &patterned_vec(17), 10, Some("exact")).await?;
    ensure!(exact.len() == 10);
    ensure!(d.last_search_examined.load(Ordering::Relaxed) == EXACT_SEARCH_LIMIT + 256);
    Ok(())
}

#[tokio::test]
async fn upsert_is_batchable_list_in_list_out() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    let item = |id: &str, vector: &[f32]| {
        Value::map(BTreeMap::from([
            ("space_id".into(), Value::string("s1".into())),
            ("id".into(), Value::string(id.into())),
            ("representation".into(), vec_val(vector)),
        ]))
    };
    let out = d
        .call(
            MethodId::new(0),
            Value::list(vec![
                item("a", &[1.0, 0.0, 0.0]),
                item("b", &[0.0, 1.0, 0.0]),
            ]),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(
        out.outcome
            == Outcome::Done(Value::list(vec![
                Value::boolean(true),
                Value::boolean(true)
            ]))
    );
    ensure!(search(&d, "s1", &[1.0, 0.0, 0.0], 10).await?.len() == 2);
    Ok(())
}

#[tokio::test]
async fn unknown_space_is_rejected() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "a", &[1.0, 0.0]).await?;
    ensure!(search(&d, "s2", &[1.0, 0.0], 10).await.is_err());
    Ok(())
}

#[tokio::test]
async fn dimension_mismatch_is_rejected() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "a", &[1.0, 0.0]).await?;
    ensure!(upsert(&d, "s1", "b", &[1.0, 0.0, 0.0]).await.is_err());
    ensure!(search(&d, "s1", &[1.0, 0.0, 0.0], 10).await.is_err());
    Ok(())
}

#[tokio::test]
async fn delete_removes_space_when_last_entry_is_removed() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "a", &[1.0, 0.0]).await?;
    let out = d
        .call(
            MethodId::new(2),
            Value::map(BTreeMap::from([
                ("space_id".into(), Value::string("s1".into())),
                ("id".into(), Value::string("a".into())),
            ])),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(out.outcome == Outcome::Done(Value::boolean(true)));
    ensure!(search(&d, "s1", &[1.0, 0.0], 10).await.is_err());
    ensure!(d.spaces.read().is_empty());
    Ok(())
}

#[tokio::test]
async fn missing_space_id_errors() -> anyhow::Result<()> {
    let out = IndexDriver::new()
        .call(
            MethodId::new(1),
            Value::map(BTreeMap::new()),
            OutputMode::Unary,
            &ctx(),
        )
        .await;
    ensure!(out.is_err(), "missing space id was accepted");
    Ok(())
}

#[tokio::test]
async fn malformed_search_limit_is_rejected() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "a", &[1.0, 0.0]).await?;
    for k in [Value::integer(-1), Value::string("1".into())] {
        let out = d
            .call(
                MethodId::new(1),
                Value::map(BTreeMap::from([
                    ("space_id".into(), Value::string("s1".into())),
                    ("representation".into(), vec_val(&[1.0, 0.0])),
                    ("k".into(), k),
                ])),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "malformed search k was accepted");
    }
    Ok(())
}

#[tokio::test]
async fn unknown_or_nonstring_search_modes_are_rejected() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "a", &[1.0, 0.0]).await?;
    for mode in [
        Value::string("approximate".into()),
        Value::string("Exact".into()),
        Value::string(String::new()),
        Value::integer(0),
        Value::boolean(false),
    ] {
        let result = d
            .call(
                MethodId::new(1),
                Value::map(BTreeMap::from([
                    ("space_id".into(), Value::string("s1".into())),
                    ("representation".into(), vec_val(&[1.0, 0.0])),
                    ("mode".into(), mode),
                ])),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(matches!(result, Err(DriverError::InvalidInput(_))));
    }
    Ok(())
}

#[tokio::test]
async fn public_search_handles_extreme_finite_vectors() -> anyhow::Result<()> {
    for scale in [f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1)] {
        let d = IndexDriver::new();
        upsert(&d, "extreme", "aligned", &[scale, scale]).await?;
        upsert(&d, "extreme", "opposite", &[-scale, -scale]).await?;
        upsert(&d, "extreme", "orthogonal", &[scale, -scale]).await?;
        upsert(&d, "extreme", "zero", &[0.0, 0.0]).await?;
        let results = search(&d, "extreme", &[scale, scale], 4).await?;
        ensure!(results.len() == 4);
        for (entry, (id, expected)) in results.iter().zip([
            ("aligned", 1.0),
            ("orthogonal", 0.0),
            ("zero", 0.0),
            ("opposite", -1.0),
        ]) {
            let Some(map) = entry.as_map() else {
                bail!("index result is not a map");
            };
            ensure!(map.get("id").and_then(Value::as_str) == Some(id));
            let Some(xolotl_types::ValueView::Float(FloatBits(score))) =
                map.get("sim").map(Value::view)
            else {
                bail!("index result has no numeric similarity");
            };
            ensure!(score.is_finite() && (-1.0..=1.0).contains(&score));
            ensure!((score - expected).abs() < 1e-12);
        }
    }
    Ok(())
}

#[tokio::test]
async fn ties_remain_deterministic_after_delete_and_reinsert() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    for id in ["z", "a", "m"] {
        upsert(&d, "ties", id, &[1.0, 0.0]).await?;
    }
    d.call(
        MethodId::new(2),
        Value::map(BTreeMap::from([
            ("space_id".into(), Value::string("ties".into())),
            ("id".into(), Value::string("z".into())),
        ])),
        OutputMode::Unary,
        &ctx(),
    )
    .await?;
    upsert(&d, "ties", "z", &[1.0, 0.0]).await?;
    let results = search(&d, "ties", &[1.0, 0.0], 3).await?;
    let ids: Vec<_> = results
        .iter()
        .filter_map(|entry| entry.as_map()?.get("id")?.as_str())
        .collect();
    ensure!(ids == ["a", "m", "z"]);
    Ok(())
}

#[tokio::test]
async fn nonfinite_or_out_of_range_vectors_cannot_replace_existing_entries() -> anyhow::Result<()> {
    let d = IndexDriver::new();
    upsert(&d, "s1", "kept", &[1.0, 0.0]).await?;
    for invalid in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::from(f32::MAX) * 2.0,
    ] {
        let result = d
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::from([
                    ("space_id".into(), Value::string("s1".into())),
                    ("id".into(), Value::string("kept".into())),
                    (
                        "representation".into(),
                        EmbeddingRepresentation::Dense(
                            vec![Value::float(FloatBits(invalid)), Value::integer(0)].into(),
                        )
                        .into_value(),
                    ),
                ])),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(result.is_err());
    }
    let results = search(&d, "s1", &[1.0, 0.0], 1).await?;
    ensure!(results.len() == 1);
    ensure!(
        results[0].as_map().and_then(|entry| entry.get("sim"))
            == Some(&Value::float(FloatBits(1.0)))
    );
    Ok(())
}
