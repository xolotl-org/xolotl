use super::*;
use crate::retrieval::admission::{Vector, Work};
use std::{
    future::Future,
    num::NonZeroUsize,
    task::{Context as TaskContext, Poll, Waker},
};

#[tokio::test]
async fn high_dimension_snapshot_search_yields_without_holding_writer_locks() -> anyhow::Result<()>
{
    let config = RetrievalConfig::default().with_work_quantum(NonZeroUsize::MIN);
    let driver = IndexDriver::new().with_config(config.clone());
    upsert(&driver, "wide", "old", &vec![1.0; 8192]).await?;
    let snapshot = driver.snapshot("wide").context("initial snapshot")?;
    let old_entry = Arc::downgrade(snapshot.entries.get(0).context("initial entry")?);
    let query = Vector::Dense {
        values: vec![1.0; 8192],
        inverse_norm: 1.0 / 8192.0_f64.sqrt(),
    };
    let taint = TaintSet::pristine();
    let mut search = Box::pin(snapshot.search(&query, &taint, 1, SearchMode::Exact, &config));
    ensure!(
        search
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
            .is_pending(),
        "high-dimensional score never yielded"
    );
    upsert(&driver, "wide", "old", &vec![-1.0; 8192]).await?;
    upsert(&driver, "other", "independent", &[1.0]).await?;
    ensure!(
        snapshot
            .entries
            .get(0)
            .context("snapshot entry")?
            .vector
            .dense()
            .context("dense")?[0]
            == 1.0
    );
    let result = search.await;
    ensure!(result.hits.len() == 1 && (result.hits[0].score - 1.0).abs() < 1e-12);
    drop(snapshot);
    ensure!(
        old_entry.upgrade().is_none(),
        "completed query retained an obsolete numeric payload"
    );
    Ok(())
}

#[tokio::test]
async fn dropping_ann_construction_releases_ownership_and_concurrent_mutation_progresses()
-> anyhow::Result<()> {
    let driver = IndexDriver::new()
        .with_config(RetrievalConfig::default().with_work_quantum(NonZeroUsize::MIN));
    for id in 0..EXACT_SEARCH_LIMIT + 1 {
        upsert(&driver, "large", &format!("v{id}"), &[1.0, 0.0]).await?;
    }
    let input: ValueMap = BTreeMap::from([
        ("space_id".into(), Value::string("large".into())),
        ("representation".into(), vec_val(&[1.0, 0.0])),
    ])
    .into();
    let taint = TaintSet::pristine();
    let space = driver
        .spaces
        .read()
        .get("large")
        .cloned()
        .context("large space")?;
    let mut search = Box::pin(driver.search(&input, &taint));
    let mut reached_build = false;
    for _ in 0..32 {
        ensure!(matches!(
            search
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Pending
        ));
        if space.building_ann.load(Ordering::Acquire) {
            reached_build = true;
            break;
        }
    }
    ensure!(reached_build, "query did not begin ANN construction");
    upsert(&driver, "large", "new", &[0.0, 1.0]).await?;
    upsert(&driver, "independent", "new", &[1.0]).await?;
    drop(search);
    ensure!(!space.building_ann.load(Ordering::Acquire));
    ensure!(
        driver
            .snapshot("large")
            .context("live snapshot")?
            .ann
            .is_none()
    );
    ensure!(
        search_with_mode(&driver, "large", &[0.0, 1.0], 1, Some("exact"))
            .await?
            .len()
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn publication_keeps_accelerator_created_after_admission() -> anyhow::Result<()> {
    let driver = IndexDriver::new();
    for id in 0..33 {
        upsert(&driver, "space", &format!("v{id}"), &[1.0, 0.0]).await?;
    }
    let prepared = driver
        .prepare(
            "space",
            "new".into(),
            EmbeddingRepresentation::Dense(vec![Value::integer(0), Value::integer(1)].into()),
            None,
            None,
            &TaintSet::pristine(),
        )
        .await?;
    ensure!(prepared.signature.is_none());
    let snapshot = driver.snapshot("space").context("snapshot")?;
    let ann = LshIndex::build(
        &snapshot.entries,
        snapshot.dimensions,
        &mut Work::new(&RetrievalConfig::default()),
    )
    .await;
    let space = driver
        .spaces
        .read()
        .get("space")
        .cloned()
        .context("space")?;
    if let Some(index) = space.state.lock().as_mut() {
        Arc::make_mut(&mut index.current).ann = Some(ann);
    }
    ensure!(driver.publish("space", prepared).await?);
    let current = driver.snapshot("space").context("current snapshot")?;
    current
        .ann
        .as_ref()
        .context("publication discarded ANN")?
        .validate(&current.entries)
        .map_err(anyhow::Error::msg)?;
    ensure!(current.entries.len() == 34);
    Ok(())
}

#[tokio::test]
async fn prepared_conditions_and_generation_deletes_cannot_erase_a_newer_entry()
-> anyhow::Result<()> {
    let driver = IndexDriver::new();
    let representation = || EmbeddingRepresentation::Dense(vec![Value::integer(1)].into());
    let original = driver
        .prepare(
            "s",
            "id".into(),
            representation(),
            Some("old".into()),
            None,
            &TaintSet::pristine(),
        )
        .await?;
    ensure!(driver.publish("s", original).await?);
    let stale = driver
        .prepare(
            "s",
            "id".into(),
            representation(),
            Some("stale".into()),
            None,
            &TaintSet::pristine(),
        )
        .await?
        .conditional();
    let newer = driver
        .prepare(
            "s",
            "id".into(),
            representation(),
            Some("new".into()),
            None,
            &TaintSet::pristine(),
        )
        .await?;
    ensure!(driver.publish("s", newer).await?);
    ensure!(!driver.publish("s", stale).await?);
    ensure!(!driver.delete_generation("s", "id", Some("old"))?);
    ensure!(
        driver
            .snapshot("s")
            .context("current snapshot")?
            .entries
            .get(0)
            .context("current entry")?
            .generation
            .as_deref()
            == Some("new")
    );
    Ok(())
}
