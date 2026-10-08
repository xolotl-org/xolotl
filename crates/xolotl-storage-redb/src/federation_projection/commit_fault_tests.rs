use super::*;
use crate::RedbOptions;
use anyhow::{Context as _, Result, ensure};
use redb::StorageBackend;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use xolotl_federation::{
    EventType, ExportName, FederationStore as _, PublishRequest, SchemaRevision, StreamId,
    StreamSpec,
};
use xolotl_types::Value;

#[derive(Debug)]
struct FaultingStorage {
    file: Mutex<File>,
    armed: Arc<AtomicU8>,
}

impl FaultingStorage {
    fn file(&self) -> io::Result<std::sync::MutexGuard<'_, File>> {
        self.file
            .lock()
            .map_err(|_error| io::Error::other("poisoned test storage"))
    }

    fn inject(&self, mode: u8) -> io::Result<()> {
        if self
            .armed
            .compare_exchange(mode, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Err(io::Error::other("injected federation commit uncertainty"))
        } else {
            Ok(())
        }
    }
}

impl StorageBackend for FaultingStorage {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file()?.metadata()?.len())
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.file()?.set_len(length)
    }
    fn read(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(output)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.inject(1)?;
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.file()?.sync_data()?;
        self.inject(2)
    }
}

fn options() -> RedbOptions {
    RedbOptions {
        history: RedbHistory::Full,
        federation_publish_id_limit: NonZeroUsize::MIN.saturating_add(1),
        ..RedbOptions::default()
    }
}

fn faulting_store(path: &std::path::Path, armed: Arc<AtomicU8>) -> Result<RedbStore> {
    let mut file_options = OpenOptions::new();
    file_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        file_options.mode(0o600);
    }
    let inner = redb::Database::builder().create_with_backend(FaultingStorage {
        file: Mutex::new(file_options.open(path)?),
        armed,
    })?;
    Ok(RedbStore::from_database(
        inner,
        options(),
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?)
}

#[tokio::test]
async fn uncertain_pin_release_requires_reopen_without_reopening_publication() -> Result<()> {
    for mode in [1, 2] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("uncertain-release.redb");
        let armed = Arc::new(AtomicU8::new(0));
        let db = faulting_store(&path, armed.clone())?;
        let node = FederationNodeId::from_bytes([87; 48]);
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes([1; 16]),
        };
        let store = db.federation_store(node)?;
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("published")?,
        })?;
        let prefix = Path::parse("state://federation/public/release")?;
        let state = db.state_backend().into_backend();
        state.write_set(&prefix, Value::integer(7)).await?;
        let projection = db.federation_state_projection(node)?;
        let high = projection.high_watermark()?;
        let page = projection
            .publication_page(stream, &prefix, high)?
            .context("release page missing")?;
        let entry = page.entries().first().context("release event missing")?;
        let request = PublishRequest {
            stream,
            retry_epoch: page.retry_epoch(),
            publish_id: RedbFederationStateProjection::publish_id(stream, entry),
            event_type: EventType::new("state")?,
            schema_revision: SchemaRevision::from_bytes([1; 32]),
            event_ref: None,
            payload: Arc::from(b"published".as_slice()),
        };
        let receipt = request.receipt(&store.append_published(request.clone())?)?;
        projection.commit_publication_page(&page, &[receipt])?;
        ensure!(
            projection
                .publication_status(stream, &prefix)?
                .is_some_and(|status| {
                    status.completed_cursor == Some(high) && status.pending_high.is_none()
                })
        );
        armed.store(mode, Ordering::SeqCst);
        ensure!(matches!(
            projection.release_publication(stream, &prefix, high),
            Err(FederationError::Indeterminate)
        ));
        ensure!(armed.load(Ordering::SeqCst) == 0 && db.requires_reopen());
        ensure!(projection.publication_status(stream, &prefix).is_err());
        ensure!(
            projection
                .release_publication(stream, &prefix, high)
                .is_err()
        );
        ensure!(store.publication_epoch(stream).is_err());
        drop(page);
        drop(state);
        drop(projection);
        drop(store);
        drop(db);
        let db = RedbStore::open_with_options(&path, options())?;
        let store = db.federation_store(node)?;
        let projection = db.federation_state_projection(node)?;
        let retained = projection.publication_status(stream, &prefix)?;
        ensure!(retained.is_some() == (mode == 1));
        if let Some(status) = retained {
            ensure!(status.completed_cursor == Some(high) && status.pending_high.is_none());
        }
        ensure!(projection.release_publication(stream, &prefix, high)? == (mode == 1));
        ensure!(projection.publication_status(stream, &prefix)?.is_none());
        ensure!(store.publication_epoch(stream)? == 2);
        ensure!(matches!(
            store.append_published(request),
            Err(FederationError::Conflict)
        ));
        ensure!(matches!(
            projection.publication_page(stream, &prefix, high),
            Err(FederationError::Conflict)
        ));
        db.state_backend()
            .into_backend()
            .trim_history_before(high + 1, xolotl_state::StateHistoryTrimLimits::default())
            .await?;
    }
    Ok(())
}

#[test]
fn uncertain_native_epoch_close_requires_reopen_and_preserves_inspectable_identity() -> Result<()> {
    for mode in [1, 2] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("uncertain-close.redb");
        let armed = Arc::new(AtomicU8::new(0));
        let db = faulting_store(&path, armed.clone())?;
        let node = FederationNodeId::from_bytes([89; 48]);
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes([1; 16]),
        };
        let store = db.federation_store(node)?;
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("published")?,
        })?;
        let request = PublishRequest {
            stream,
            retry_epoch: 1,
            publish_id: RequestId::from_bytes([1; 16]),
            event_type: EventType::new("state")?,
            schema_revision: SchemaRevision::from_bytes([1; 32]),
            event_ref: None,
            payload: Arc::from(b"published".as_slice()),
        };
        let receipt = request.receipt(&store.append_published(request.clone())?)?;
        armed.store(mode, Ordering::SeqCst);
        ensure!(matches!(
            store.close_publication_epoch(stream, 1),
            Err(FederationError::Indeterminate)
        ));
        ensure!(armed.load(Ordering::SeqCst) == 0 && db.requires_reopen());
        ensure!(store.publication_epoch(stream).is_err());
        ensure!(store.append_published(request.clone()).is_err());
        drop(store);
        drop(db);
        let db = RedbStore::open_with_options(&path, options())?;
        let store = db.federation_store(node)?;
        ensure!(
            store.inspect_publication(stream, 1, request.publish_id)? == Some(receipt.position)
        );
        if mode == 1 {
            ensure!(store.publication_epoch(stream)? == 1);
            ensure!(store.append_published(request.clone())?.position() == receipt.position);
            store.close_publication_epoch(stream, 1)?;
        }
        ensure!(store.publication_epoch(stream)? == 2);
        ensure!(matches!(
            store.append_published(request.clone()),
            Err(FederationError::Conflict)
        ));
        ensure!(store.retire_publication_identities(&[receipt])? == 1);
        ensure!(matches!(
            store.append_published(request),
            Err(FederationError::Conflict)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn uncertain_page_commit_reopens_atomic_epoch_identity_cursor_and_pin() -> Result<()> {
    for (mode, partial) in [(1, false), (2, false), (1, true), (2, true)] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("uncertain-page.redb");
        let armed = Arc::new(AtomicU8::new(0));
        let db = faulting_store(&path, armed.clone())?;
        let node = FederationNodeId::from_bytes([89; 48]);
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes([1; 16]),
        };
        let store = db.federation_store(node)?;
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("published")?,
        })?;
        let projection = db.federation_state_projection(node)?;
        let state = db.state_backend().into_backend();
        let prefix = Path::parse("state://published")?;
        state
            .write_set(&Path::parse("state://published/item")?, Value::integer(1))
            .await?;
        if partial {
            state
                .write_set(&Path::parse("state://published/item")?, Value::integer(2))
                .await?;
        }
        let high = projection.high_watermark()?;
        let page = projection
            .publication_page(stream, &prefix, high)?
            .context("missing page")?;
        ensure!(page.entries().len() == if partial { 2 } else { 1 });
        let request = PublishRequest {
            stream,
            retry_epoch: page.retry_epoch(),
            publish_id: RedbFederationStateProjection::publish_id(stream, &page.entries()[0]),
            event_type: EventType::new("state")?,
            schema_revision: SchemaRevision::from_bytes([1; 32]),
            event_ref: None,
            payload: Arc::from(b"published".as_slice()),
        };
        let receipt = request.receipt(&store.append_published(request.clone())?)?;
        armed.store(mode, Ordering::SeqCst);
        let result = if partial {
            projection
                .commit_publication_prefix(&page, &[receipt])
                .map(|_| ())
        } else {
            projection.commit_publication_page(&page, &[receipt])
        };
        ensure!(matches!(result, Err(FederationError::Indeterminate)));
        ensure!(armed.load(Ordering::SeqCst) == 0 && db.requires_reopen());
        ensure!(store.publication_epoch(stream).is_err());
        ensure!(projection.publication_page(stream, &prefix, high).is_err());
        ensure!(
            state
                .trim_history_before(high + 1, xolotl_state::StateHistoryTrimLimits::default())
                .await
                .is_err()
        );
        drop(page);
        drop(state);
        drop(projection);
        drop(store);
        drop(db);
        let db = RedbStore::open_with_options(&path, options())?;
        let store = db.federation_store(node)?;
        let projection = db.federation_state_projection(node)?;
        if mode == 1 {
            ensure!(store.publication_epoch(stream)? == 1);
            ensure!(projection.cursor(stream, &prefix)?.is_none());
            ensure!(
                store.inspect_publication(stream, 1, request.publish_id)? == Some(receipt.position)
            );
            let page = projection
                .publication_page(stream, &prefix, high)?
                .context("pending page missing")?;
            ensure!(page.retry_epoch() == 1);
            ensure!(store.append_published(request.clone())?.position() == receipt.position);
            if partial {
                projection.commit_publication_prefix(&page, &[receipt])?;
            } else {
                projection.commit_publication_page(&page, &[receipt])?;
            }
        }
        ensure!(store.publication_epoch(stream)? == 2);
        ensure!(projection.cursor(stream, &prefix)? == if partial { None } else { Some(high) });
        ensure!(
            store
                .inspect_publication(stream, 1, request.publish_id)?
                .is_none()
        );
        ensure!(matches!(
            store.append_published(request),
            Err(FederationError::Conflict)
        ));
        if partial {
            ensure!(
                db.state_backend()
                    .into_backend()
                    .trim_history_before(high + 1, xolotl_state::StateHistoryTrimLimits::default())
                    .await
                    .is_err()
            );
            let page = projection
                .publication_page(stream, &prefix, high)?
                .context("suffix")?;
            ensure!(page.retry_epoch() == 2 && page.entries().len() == 1);
            let request = PublishRequest {
                stream,
                retry_epoch: page.retry_epoch(),
                publish_id: RedbFederationStateProjection::publish_id(stream, &page.entries()[0]),
                event_type: EventType::new("state")?,
                schema_revision: SchemaRevision::from_bytes([1; 32]),
                event_ref: None,
                payload: Arc::from(b"suffix".as_slice()),
            };
            let record = store.append_published(request.clone())?;
            ensure!(record.sequence() == 2);
            projection.commit_publication_page(&page, &[request.receipt(&record)?])?;
            while let Some(page) = projection.publication_page(stream, &prefix, high)? {
                ensure!(page.entries().is_empty());
                projection.commit_publication_page(&page, &[])?;
            }
            ensure!(projection.cursor(stream, &prefix)? == Some(high));
        }
        db.state_backend()
            .into_backend()
            .trim_history_before(high + 1, xolotl_state::StateHistoryTrimLimits::default())
            .await?;
        ensure!(projection.release_publication(stream, &prefix, high)?);
    }
    Ok(())
}
