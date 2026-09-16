use super::*;
use crate::retrieval::{RetrievalConfig, admission::Work};
use anyhow::{Context, ensure};

fn vector(values: Vec<f32>) -> Vector {
    let squared: f64 = values.iter().map(|value| f64::from(*value).powi(2)).sum();
    Vector::Dense {
        values,
        inverse_norm: if squared == 0.0 {
            0.0
        } else {
            1.0 / squared.sqrt()
        },
    }
}

async fn insert(
    index: &mut SpaceIndex,
    id: String,
    values: Vec<f32>,
    taint: TaintSet,
) -> anyhow::Result<()> {
    let vector = vector(values);
    let signature = if let (Some(ann), Some(values)) = (&index.current.ann, vector.dense()) {
        Some(
            ann.signature(values, &mut Work::new(&RetrievalConfig::default()))
                .await,
        )
    } else {
        None
    };
    index
        .upsert(
            Entry {
                id,
                vector,
                taint,
                generation: None,
            },
            signature,
        )
        .map_err(anyhow::Error::msg)
}

async fn accelerate(index: &mut SpaceIndex) {
    let ann = LshIndex::build(
        &index.current.entries,
        index.current.dimensions,
        &mut Work::new(&RetrievalConfig::default()),
    )
    .await;
    Arc::make_mut(&mut index.current).ann = Some(ann);
}

fn integrity(index: &SpaceIndex) -> anyhow::Result<()> {
    ensure!(index.current.entries.len() == index.ids.len());
    for (slot, entry) in index.current.entries.iter().enumerate() {
        ensure!(index.ids.get(&entry.id) == Some(&slot));
    }
    if let Some(ann) = &index.current.ann {
        ann.validate(&index.current.entries)
            .map_err(anyhow::Error::msg)?;
    }
    for (source, count) in &index.sources {
        ensure!(index.current.sources.get(count.slot) == Some(source));
        let expected = index
            .current
            .entries
            .iter()
            .flat_map(|entry| entry.taint.sources())
            .filter(|observed| *observed == source)
            .count();
        ensure!(count.count == expected);
    }
    Ok(())
}

#[tokio::test]
async fn snapshots_share_numeric_payloads_and_isolate_slot_changes() -> anyhow::Result<()> {
    let mut index = SpaceIndex::new(2, Family::Dense, Metric::Cosine);
    for id in 0..1057 {
        insert(
            &mut index,
            format!("v{id}"),
            vec![id as f32, 1.0],
            TaintSet::pristine(),
        )
        .await?;
    }
    let snapshot = index.current.clone();
    let unchanged = snapshot.entries.get(512).context("old entry")?.clone();
    insert(
        &mut index,
        "v31".into(),
        vec![-10.0, 0.0],
        TaintSet::pristine(),
    )
    .await?;
    ensure!(index.delete("v1024", None).map_err(anyhow::Error::msg)?);
    ensure!(Arc::ptr_eq(
        index.entry("v512").context("unchanged live entry")?,
        &unchanged
    ));
    ensure!(snapshot.entries.len() == 1057 && index.current.entries.len() == 1056);
    ensure!(
        snapshot
            .entries
            .get(31)
            .and_then(|entry| entry.vector.dense())
            == Some(&[31.0, 1.0][..])
    );
    ensure!(snapshot.entries.get(1024).context("old deleted entry")?.id == "v1024");
    integrity(&index)
}

#[tokio::test]
async fn coincident_ann_buckets_keep_reverse_positions_through_churn_and_release()
-> anyhow::Result<()> {
    let mut index = SpaceIndex::new(2, Family::Dense, Metric::Cosine);
    for id in 0..EXACT_SEARCH_LIMIT + 17 {
        insert(
            &mut index,
            format!("v{id}"),
            vec![1.0, 0.0],
            TaintSet::pristine(),
        )
        .await?;
    }
    accelerate(&mut index).await;
    let snapshot = index.current.clone();
    for id in 0..65 {
        ensure!(
            index
                .delete(&format!("v{}", id * 31), None)
                .map_err(anyhow::Error::msg)?
        );
        insert(
            &mut index,
            format!("new{id}"),
            vec![0.0, 1.0],
            TaintSet::pristine(),
        )
        .await?;
        integrity(&index)?;
    }
    let ids: Vec<_> = index.ids.keys().cloned().collect();
    for id in ids {
        index.delete(&id, None).map_err(anyhow::Error::msg)?;
    }
    ensure!(index.current.entries.is_empty() && index.current.ann.is_none());
    ensure!(index.ids.is_empty() && index.sources.is_empty());
    snapshot
        .ann
        .as_ref()
        .context("retained accelerator")?
        .validate(&snapshot.entries)
        .map_err(anyhow::Error::msg)?;
    ensure!(snapshot.entries.len() == EXACT_SEARCH_LIMIT + 17);
    Ok(())
}

#[tokio::test]
async fn source_counts_do_not_retain_deleted_history_but_old_queries_keep_their_view()
-> anyhow::Result<()> {
    let protected = TaintSource::Protected {
        path: xolotl_types::Path::try_new("state")?.try_push("private")?,
    };
    let taint = TaintSet::from_recorded_sources(vec![protected.clone(), protected.clone()]);
    let mut index = SpaceIndex::new(2, Family::Dense, Metric::Cosine);
    insert(&mut index, "private".into(), vec![-1.0, 0.0], taint.clone()).await?;
    insert(
        &mut index,
        "public".into(),
        vec![1.0, 0.0],
        TaintSet::pristine(),
    )
    .await?;
    let snapshot = index.current.clone();
    let config = RetrievalConfig::default();
    for k in [0, 1] {
        let result = snapshot
            .search(
                &vector(vec![1.0, 0.0]),
                &TaintSet::pristine(),
                k,
                SearchMode::Exact,
                &config,
            )
            .await;
        ensure!(result.taint.has_protected());
    }
    index.delete("private", None).map_err(anyhow::Error::msg)?;
    integrity(&index)?;
    ensure!(index.current.sources.is_empty());
    ensure!(snapshot.sources.iter().eq([&protected]));
    Ok(())
}

#[tokio::test]
async fn cooperative_top_k_matches_full_sort_with_extremes_and_stable_ties() -> anyhow::Result<()> {
    let mut index = SpaceIndex::new(2, Family::Dense, Metric::Cosine);
    for id in 0..257 {
        insert(
            &mut index,
            format!("v{id:04}"),
            vec![(id % 17) as f32 - 8.0, (id % 13) as f32 - 6.0],
            TaintSet::pristine(),
        )
        .await?;
    }
    insert(
        &mut index,
        "huge".into(),
        vec![f32::MAX, f32::MAX],
        TaintSet::pristine(),
    )
    .await?;
    insert(
        &mut index,
        "tiny".into(),
        vec![f32::from_bits(1), f32::from_bits(1)],
        TaintSet::pristine(),
    )
    .await?;
    let query = vector(vec![1.0, 0.0]);
    let mut expected: Vec<_> = index
        .current
        .entries
        .iter()
        .map(|entry| {
            let Vector::Dense {
                values,
                inverse_norm,
            } = &entry.vector
            else {
                return (entry.id.clone(), 0.0);
            };
            (
                entry.id.clone(),
                (f64::from(values[0]) * inverse_norm).clamp(-1.0, 1.0),
            )
        })
        .collect();
    expected.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    for k in [0, 1, 10, 300, usize::MAX] {
        let result = index
            .current
            .search(
                &query,
                &TaintSet::pristine(),
                k,
                SearchMode::Exact,
                &RetrievalConfig::default(),
            )
            .await;
        ensure!(result.hits.len() == k.min(expected.len()));
        for (hit, expected) in result.hits.iter().zip(&expected) {
            ensure!(hit.id == expected.0 && (hit.score - expected.1).abs() < 1e-12);
        }
    }
    Ok(())
}
