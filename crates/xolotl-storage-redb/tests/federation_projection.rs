#![cfg(feature = "federation")]

use anyhow::{Context, Result, ensure};
use std::{num::NonZeroUsize, sync::Arc};
use xolotl_federation::{
    EventType, ExportName, FederationError, FederationNodeId, FederationStore, PublicationReceipt,
    PublishRequest, SchemaRevision, StreamId, StreamRef, StreamSpec,
};
use xolotl_state::StateHistoryTrimLimits;
use xolotl_storage_redb::{
    FederationStatePublicationPage, FederationStatePublicationStatus,
    RedbFederationStateProjection, RedbFederationStore, RedbHistory, RedbOptions, RedbStore,
};
use xolotl_types::{Path, Value};

const NODE: FederationNodeId = FederationNodeId::from_bytes([77; 48]);

fn stream(identity: u8) -> StreamRef {
    StreamRef {
        publisher: NODE,
        id: StreamId::from_bytes([identity; 16]),
    }
}

fn options() -> RedbOptions {
    RedbOptions {
        history: RedbHistory::Full,
        federation_publish_id_limit: NonZeroUsize::MIN,
        ..RedbOptions::default()
    }
}

fn declare(store: &RedbFederationStore, identity: u8) -> Result<StreamRef> {
    let stream = stream(identity);
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("published")?,
    })?;
    Ok(stream)
}

fn append_page(
    store: &RedbFederationStore,
    stream: StreamRef,
    page: &FederationStatePublicationPage,
) -> Result<Vec<PublicationReceipt>> {
    page.entries()
        .iter()
        .map(|entry| {
            let request = page_request(stream, page, entry)?;
            let record = store.append_published(request.clone())?;
            Ok(request.receipt(&record)?)
        })
        .collect()
}

fn page_request(
    stream: StreamRef,
    page: &FederationStatePublicationPage,
    entry: &xolotl_state::StateHistoryEntry,
) -> Result<PublishRequest> {
    Ok(PublishRequest {
        stream,
        retry_epoch: page.retry_epoch(),
        publish_id: RedbFederationStateProjection::publish_id(stream, entry),
        event_type: EventType::new("state")?,
        schema_revision: SchemaRevision::from_bytes([1; 32]),
        event_ref: None,
        payload: Arc::from(serde_json::to_vec(entry)?),
    })
}

#[test]
fn publication_status_distinguishes_absent_pin_from_invalid_stream() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(directory.path().join("status-absence.redb"), options())?;
    let store = db.federation_store(NODE)?;
    let projection = db.federation_state_projection(NODE)?;
    let prefix = Path::parse("state://published")?;
    ensure!(matches!(
        projection.publication_status(stream(1), &prefix),
        Err(FederationError::NotFound)
    ));
    declare(&store, 1)?;
    ensure!(projection.publication_status(stream(1), &prefix)?.is_none());
    ensure!(projection.publication_status(stream(1), &prefix)?.is_none());
    ensure!(store.publication_epoch(stream(1))? == 1);
    let foreign = StreamRef {
        publisher: FederationNodeId::from_bytes([78; 48]),
        ..stream(1)
    };
    ensure!(matches!(
        projection.publication_status(foreign, &prefix),
        Err(FederationError::Unauthorized)
    ));
    let oversized = Path::parse(&format!("state://published/{}", "x".repeat(4096)))?;
    ensure!(matches!(
        projection.publication_status(stream(1), &oversized),
        Err(FederationError::Invalid(_))
    ));
    Ok(())
}

#[tokio::test]
async fn publication_status_tracks_partial_append_reopen_settlement_and_release() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("status-lifecycle.redb");
    let settings = RedbOptions {
        federation_publish_id_limit: NonZeroUsize::new(2).context("limit")?,
        ..options()
    };
    let prefix = Path::parse("state://published")?;
    let other_prefix = Path::parse("state://other")?;
    let target = Path::parse("state://published/item")?;
    let (completed, pending) = {
        let db = RedbStore::open_with_options(&file, settings)?;
        let store = db.federation_store(NODE)?;
        declare(&store, 1)?;
        let projection = db.federation_state_projection(NODE)?;
        let state = db.state_backend().into_backend();
        state.write_set(&target, Value::integer(1)).await?;
        let completed = projection.high_watermark()?;
        while let Some(page) = projection.publication_page(stream(1), &prefix, completed)? {
            let receipts = append_page(&store, stream(1), &page)?;
            projection.commit_publication_page(&page, &receipts)?;
        }
        ensure!(
            projection.publication_status(stream(1), &prefix)?
                == Some(FederationStatePublicationStatus {
                    completed_cursor: Some(completed),
                    pending_high: None,
                })
        );
        state.write_set(&target, Value::integer(2)).await?;
        state.write_set(&target, Value::integer(3)).await?;
        let pending = projection.high_watermark()?;
        let page = projection
            .publication_page(stream(1), &prefix, pending)?
            .context("pending page")?;
        ensure!(page.entries().len() == 2);
        let request = page_request(stream(1), &page, &page.entries()[0])?;
        store.append_published(request)?;
        ensure!(
            projection.publication_status(stream(1), &prefix)?
                == Some(FederationStatePublicationStatus {
                    completed_cursor: Some(completed),
                    pending_high: Some(pending),
                })
        );
        ensure!(matches!(
            projection.publication_status(stream(1), &other_prefix),
            Err(FederationError::Conflict)
        ));
        state
            .write_set(&Path::parse("state://other/later")?, Value::integer(4))
            .await?;
        (completed, pending)
    };
    let db = RedbStore::open_with_options(&file, settings)?;
    let store = db.federation_store(NODE)?;
    let projection = db.federation_state_projection(NODE)?;
    ensure!(projection.high_watermark()? > pending);
    ensure!(
        projection.publication_status(stream(1), &prefix)?
            == Some(FederationStatePublicationStatus {
                completed_cursor: Some(completed),
                pending_high: Some(pending),
            })
    );
    while let Some(page) = projection.publication_page(stream(1), &prefix, pending)? {
        let receipts = append_page(&store, stream(1), &page)?;
        projection.commit_publication_page(&page, &receipts)?;
    }
    ensure!(
        projection.publication_status(stream(1), &prefix)?
            == Some(FederationStatePublicationStatus {
                completed_cursor: Some(pending),
                pending_high: None,
            })
    );
    ensure!(projection.release_publication(stream(1), &prefix, pending)?);
    ensure!(projection.publication_status(stream(1), &prefix)?.is_none());
    ensure!(
        projection
            .publication_status(stream(1), &other_prefix)?
            .is_none()
    );
    ensure!(matches!(
        projection.publication_page(stream(1), &prefix, pending),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn publication_status_rejects_pending_window_with_closed_epoch() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(directory.path().join("status-epoch.redb"), options())?;
    let store = db.federation_store(NODE)?;
    declare(&store, 1)?;
    let projection = db.federation_state_projection(NODE)?;
    let prefix = Path::parse("state://published")?;
    let high = projection.high_watermark()?;
    ensure!(
        projection
            .publication_page(stream(1), &prefix, high)?
            .is_some()
    );
    ensure!(
        projection.publication_status(stream(1), &prefix)?
            == Some(FederationStatePublicationStatus {
                completed_cursor: None,
                pending_high: Some(high),
            })
    );
    store.close_publication_epoch(stream(1), 1)?;
    ensure!(matches!(
        projection.publication_status(stream(1), &prefix),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[tokio::test]
async fn competing_pages_settle_exact_prefixes_and_resume_after_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("competing-pages.redb");
    let settings = RedbOptions {
        federation_publish_id_limit: NonZeroUsize::new(2).context("limit")?,
        ..options()
    };
    let prefix = Path::parse("state://published")?;
    let target = Path::parse("state://published/item")?;
    let (high, first, second) = {
        let db = RedbStore::open_with_options(&file, settings)?;
        let store = db.federation_store(NODE)?;
        declare(&store, 1)?;
        declare(&store, 2)?;
        let state = db.state_backend().into_backend();
        state.write_set(&target, Value::integer(1)).await?;
        state
            .write_set(&Path::parse("state://other/filtered")?, Value::integer(9))
            .await?;
        state.write_set(&target, Value::integer(2)).await?;
        let projection = db.federation_state_projection(NODE)?;
        let high = projection.high_watermark()?;
        let first_page = projection
            .publication_page(stream(1), &prefix, high)?
            .context("first page")?;
        let second_page = projection
            .publication_page(stream(2), &prefix, high)?
            .context("second page")?;
        ensure!(first_page.entries().len() == 2 && second_page.entries().len() == 2);
        let first = page_request(stream(1), &first_page, &first_page.entries()[0])?;
        let second = page_request(stream(2), &second_page, &second_page.entries()[0])?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let first_store = store.clone();
        let first_request = first.clone();
        let first_barrier = barrier.clone();
        let first_append = std::thread::spawn(move || {
            first_barrier.wait();
            first_store.append_published(first_request)
        });
        barrier.wait();
        let second_receipt = second.receipt(&store.append_published(second.clone())?)?;
        let first_receipt = first.receipt(
            &first_append
                .join()
                .map_err(|_panic| anyhow::anyhow!("first append panicked"))??,
        )?;
        for (identity, page) in [(1, &first_page), (2, &second_page)] {
            ensure!(matches!(
                store.append_published(page_request(stream(identity), page, &page.entries()[1])?),
                Err(FederationError::Capacity)
            ));
        }
        ensure!(matches!(
            projection.commit_publication_page(&first_page, &[first_receipt]),
            Err(FederationError::Conflict)
        ));
        ensure!(matches!(
            projection.commit_publication_prefix(&first_page, &[]),
            Err(FederationError::Conflict)
        ));
        ensure!(matches!(
            projection.commit_publication_prefix(&first_page, &[second_receipt]),
            Err(FederationError::Conflict)
        ));
        let wrong_position = PublicationReceipt {
            position: xolotl_federation::Position::new(
                first_receipt.position.sequence(),
                xolotl_federation::Digest::from_bytes([9; 48]),
            )?,
            ..first_receipt
        };
        ensure!(matches!(
            projection.commit_publication_prefix(&first_page, &[wrong_position]),
            Err(FederationError::Conflict)
        ));
        ensure!(store.publication_epoch(stream(1))? == 1);
        ensure!(
            projection
                .commit_publication_prefix(&first_page, &[first_receipt])?
                .is_some()
        );
        ensure!(matches!(
            store.append_published(page_request(
                stream(1),
                &first_page,
                &first_page.entries()[1]
            )?),
            Err(FederationError::Conflict)
        ));
        ensure!(matches!(
            projection.commit_publication_prefix(&first_page, &[first_receipt]),
            Err(FederationError::Conflict)
        ));
        ensure!(
            projection
                .commit_publication_prefix(&second_page, &[second_receipt])?
                .is_some()
        );
        ensure!(
            state
                .trim_history_before(high + 1, StateHistoryTrimLimits::default())
                .await
                .is_err()
        );
        (high, first, second)
    };
    let db = RedbStore::open_with_options(&file, settings)?;
    let store = db.federation_store(NODE)?;
    let projection = db.federation_state_projection(NODE)?;
    for request in [first, second] {
        ensure!(store.publication_epoch(request.stream)? == 2);
        ensure!(
            store
                .inspect_publication(request.stream, 1, request.publish_id)?
                .is_none()
        );
        ensure!(matches!(
            store.append_published(request),
            Err(FederationError::Conflict)
        ));
    }
    for identity in [1, 2] {
        let page = projection
            .publication_page(stream(identity), &prefix, high)?
            .context("suffix page")?;
        ensure!(page.retry_epoch() == 2 && page.entries().len() == 1);
        ensure!(matches!(&page.entries()[0].event,
            xolotl_state::StateEvent::Set { value, .. } if value.as_int() == Some(2)));
        let receipts = append_page(&store, stream(identity), &page)?;
        ensure!(receipts.len() == 1 && receipts[0].position.sequence() == 2);
        projection.commit_publication_page(&page, &receipts)?;
        while let Some(page) = projection.publication_page(stream(identity), &prefix, high)? {
            ensure!(page.entries().is_empty());
            projection.commit_publication_page(&page, &[])?;
        }
        ensure!(projection.cursor(stream(identity), &prefix)? == Some(high));
    }
    db.state_backend()
        .into_backend()
        .trim_history_before(high + 1, StateHistoryTrimLimits::default())
        .await?;
    Ok(())
}

#[tokio::test]
async fn prefix_settlement_rejects_unobserved_suffix_commit() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(
        directory.path().join("suffix-evidence.redb"),
        RedbOptions {
            federation_publish_id_limit: NonZeroUsize::new(3).context("limit")?,
            ..options()
        },
    )?;
    let store = db.federation_store(NODE)?;
    declare(&store, 1)?;
    let state = db.state_backend().into_backend();
    let prefix = Path::parse("state://published")?;
    let target = Path::parse("state://published/item")?;
    for value in 0..3 {
        state.write_set(&target, Value::integer(value)).await?;
    }
    let projection = db.federation_state_projection(NODE)?;
    let high = projection.high_watermark()?;
    let page = projection
        .publication_page(stream(1), &prefix, high)?
        .context("page")?;
    let mut receipts = Vec::new();
    for entry in [&page.entries()[0], &page.entries()[2]] {
        let request = page_request(stream(1), &page, entry)?;
        receipts.push(request.receipt(&store.append_published(request.clone())?)?);
    }
    ensure!(matches!(
        projection.commit_publication_prefix(&page, &receipts[..1]),
        Err(FederationError::Conflict)
    ));
    ensure!(store.publication_epoch(stream(1))? == 1);
    ensure!(projection.cursor(stream(1), &prefix)?.is_none());
    for receipt in &receipts {
        ensure!(
            store.inspect_publication(stream(1), 1, receipt.publish_id)? == Some(receipt.position)
        );
    }
    let recovered = projection
        .publication_page(stream(1), &prefix, high)?
        .context("recovered page")?;
    ensure!(recovered.retry_epoch() == 1);
    let recovered_receipts = append_page(&store, stream(1), &recovered)?;
    projection.commit_publication_page(&recovered, &recovered_receipts)?;
    Ok(())
}

#[tokio::test]
async fn fixed_window_reopens_without_upgrading_unknown_and_returns_low_budget_slots() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("publication.redb");
    let prefix = Path::parse("state://published")?;
    let target = Path::parse("state://published/item")?;
    let (high, identity, position) = {
        let db = RedbStore::open_with_options(&path, options())?;
        let store = db.federation_store(NODE)?;
        declare(&store, 1)?;
        let state = db.state_backend().into_backend();
        for value in 0..12 {
            state.write_set(&target, Value::integer(value)).await?;
        }
        let projection = db.federation_state_projection(NODE)?;
        let high = projection.high_watermark()?;
        let page = projection
            .publication_page(stream(1), &prefix, high)?
            .context("page missing")?;
        ensure!(page.entries().len() == 1 && page.retry_epoch() == 1);
        let receipt = append_page(&store, stream(1), &page)?
            .pop()
            .context("receipt missing")?;
        ensure!(matches!(
            projection.commit_publication_page(&page, &[]),
            Err(FederationError::Conflict)
        ));
        ensure!(store.publication_epoch(stream(1))? == 1);
        ensure!(
            projection
                .release_publication(stream(1), &prefix, high)
                .is_err()
        );
        ensure!(
            state
                .trim_history_before(high, StateHistoryTrimLimits::default())
                .await
                .is_err()
        );
        state.write_set(&target, Value::integer(99)).await?;
        (high, receipt.publish_id, receipt.position)
    };
    let db = RedbStore::open_with_options(&path, options())?;
    let store = db.federation_store(NODE)?;
    let projection = db.federation_state_projection(NODE)?;
    let committed = projection.high_watermark()?;
    ensure!(committed > high);
    let resumed = projection
        .publication_page(stream(1), &prefix, committed)?
        .context("page missing")?;
    ensure!(resumed.high() == high && resumed.retry_epoch() == 1);
    ensure!(store.inspect_publication(stream(1), 1, identity)? == Some(position));
    let receipts = append_page(&store, stream(1), &resumed)?;
    ensure!(receipts[0].position == position);
    projection.commit_publication_page(&resumed, &receipts)?;
    ensure!(store.inspect_publication(stream(1), 1, identity)?.is_none());
    ensure!(matches!(
        projection.commit_publication_page(&resumed, &receipts),
        Err(FederationError::Conflict)
    ));
    let mut total = 1;
    while projection.cursor(stream(1), &prefix)? != Some(high) {
        let page = projection
            .publication_page(stream(1), &prefix, committed)?
            .context("page missing")?;
        ensure!(page.high() == high && page.entries().len() <= 1);
        let receipts = append_page(&store, stream(1), &page)?;
        total += receipts.len();
        projection.commit_publication_page(&page, &receipts)?;
    }
    ensure!(total == 12);
    let state = db.state_backend().into_backend();
    state
        .trim_history_before(high + 1, StateHistoryTrimLimits::default())
        .await?;
    ensure!(
        state
            .trim_history_before(committed + 1, StateHistoryTrimLimits::default())
            .await
            .is_err()
    );
    drop(state);
    drop(projection);
    drop(store);
    drop(db);
    let db = RedbStore::open_with_options(&path, options())?;
    let store = db.federation_store(NODE)?;
    let projection = db.federation_state_projection(NODE)?;
    let mut total = 0;
    while let Some(page) = projection.publication_page(stream(1), &prefix, committed)? {
        let receipts = append_page(&store, stream(1), &page)?;
        total += receipts.len();
        projection.commit_publication_page(&page, &receipts)?;
    }
    ensure!(total == 1);
    ensure!(projection.release_publication(stream(1), &prefix, committed)?);
    ensure!(!projection.release_publication(stream(1), &prefix, committed)?);
    ensure!(matches!(
        projection.publication_page(stream(1), &prefix, committed),
        Err(FederationError::Conflict)
    ));
    let state = db.state_backend().into_backend();
    state
        .trim_history_before(committed + 1, StateHistoryTrimLimits::default())
        .await?;
    declare(&store, 2)?;
    ensure!(matches!(
        projection.publication_page(stream(2), &prefix, projection.high_watermark()?),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[tokio::test]
async fn publisher_pin_capacity_releases_only_completed_exact_cursor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(directory.path().join("pins.redb"), options())?;
    let store = db.federation_store(NODE)?;
    let projection = db.federation_state_projection(NODE)?;
    let prefix = Path::parse("state://published")?;
    let high = projection.high_watermark()?;
    for identity in 1..=64 {
        let stream = declare(&store, identity)?;
        let page = projection
            .publication_page(stream, &prefix, high)?
            .context("page missing")?;
        ensure!(page.entries().is_empty());
        projection.commit_publication_page(&page, &[])?;
    }
    declare(&store, 65)?;
    ensure!(matches!(
        projection.publication_page(stream(65), &prefix, high),
        Err(FederationError::Capacity)
    ));
    ensure!(
        projection
            .release_publication(stream(1), &prefix, high + 1)
            .is_err()
    );
    ensure!(projection.release_publication(stream(1), &prefix, high)?);
    ensure!(
        projection
            .publication_page(stream(1), &prefix, high)
            .is_err()
    );
    ensure!(
        projection
            .publication_page(stream(65), &prefix, high)?
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_and_trim_serialize_without_missing_prefix_acceptance() -> Result<()> {
    for _round in 0..16 {
        let directory = tempfile::tempdir()?;
        let db = RedbStore::open_with_options(directory.path().join("race.redb"), options())?;
        let store = db.federation_store(NODE)?;
        declare(&store, 1)?;
        let projection = db.federation_state_projection(NODE)?;
        let state = db.state_backend().into_backend();
        state
            .write_set(&Path::parse("state://published/item")?, Value::integer(1))
            .await?;
        let high = projection.high_watermark()?;
        let prefix = Path::parse("state://published")?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let registration_barrier = barrier.clone();
        let registration = tokio::task::spawn_blocking(move || {
            registration_barrier.wait();
            projection.publication_page(stream(1), &prefix, high)
        });
        let trimming = tokio::spawn(async move {
            barrier.wait();
            state
                .trim_history_before(high + 1, StateHistoryTrimLimits::default())
                .await
        });
        let registered = registration.await?;
        let trimmed = trimming.await?;
        ensure!(registered.is_ok() != trimmed.is_ok());
        if let Ok(page) = registered {
            ensure!(page.context("registration lost its page")?.entries().len() == 1);
        } else {
            ensure!(matches!(registered, Err(FederationError::Conflict)));
        }
    }
    Ok(())
}
