#![cfg(feature = "std")]

use anyhow::Context;
use std::{
    collections::VecDeque,
    future::{Ready, ready},
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard},
};
use xolotl_state::{
    StateError, StateResult,
    host::object::ObjectStore,
    object::{ObjectMetadata, ObjectWrite, ObjectWriteChunk, UploadId, UploadOptions},
};
use xolotl_types::{TaintSet, TaintSource};

struct Script {
    replies: VecDeque<StateResult<ObjectWriteChunk>>,
    calls: Vec<(u64, Vec<u8>)>,
    commits: usize,
    commit_sources: Vec<TaintSet>,
    aborts: usize,
}

struct ScriptedWriter(Mutex<Script>);

impl ScriptedWriter {
    fn new(replies: impl IntoIterator<Item = StateResult<ObjectWriteChunk>>) -> Self {
        Self(Mutex::new(Script {
            replies: replies.into_iter().collect(),
            calls: Vec::new(),
            commits: 0,
            commit_sources: Vec::new(),
            aborts: 0,
        }))
    }

    fn lock(&self) -> StateResult<MutexGuard<'_, Script>> {
        self.0
            .lock()
            .map_err(|error| StateError::Backend(error.to_string()).into())
    }
}

impl ObjectWrite for ScriptedWriter {
    type BeginUpload<'a> = Ready<StateResult<UploadId>>;
    type WriteChunk<'a> = Ready<StateResult<ObjectWriteChunk>>;
    type CommitUpload<'a> = Ready<StateResult<ObjectMetadata>>;
    type AbortUpload<'a> = Ready<StateResult<()>>;

    fn begin_upload(&self, _options: UploadOptions) -> Self::BeginUpload<'_> {
        ready(Err(StateError::Unsupported("upload already exists").into()))
    }

    fn write_chunk<'a>(
        &'a self,
        _upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        ready(self.lock().and_then(|mut script| {
            script.calls.push((offset, bytes.to_vec()));
            script
                .replies
                .pop_front()
                .unwrap_or(Err(StateError::Unsupported("unexpected write").into()))
        }))
    }

    fn commit_upload<'a>(
        &'a self,
        _upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        ready(self.lock().and_then(|mut script| {
            script.commits += 1;
            script.commit_sources.push(final_taint.clone());
            Err(StateError::Unsupported("unexpected commit").into())
        }))
    }

    fn abort_upload<'a>(&'a self, _upload: &'a UploadId) -> Self::AbortUpload<'a> {
        ready(self.lock().map(|mut script| {
            script.aborts += 1;
        }))
    }
}

#[tokio::test]
async fn host_commit_forwards_late_sources_through_both_entry_points() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("source-forwarding");
    let late = TaintSet::of(TaintSource::Fetched {
        host: "late-source".into(),
    });
    anyhow::ensure!(objects.commit_upload(&upload, &late).await.is_err());
    let empty = TaintSet::pristine();
    anyhow::ensure!(
        ObjectWrite::commit_upload(&objects, &upload, &empty)
            .await
            .is_err()
    );
    let script = writer.lock()?;
    anyhow::ensure!(script.commit_sources == [late, empty]);
    Ok(())
}

#[tokio::test]
async fn partial_writes_preserve_bytes_and_bound_every_offer() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([
        Ok(ObjectWriteChunk {
            bytes_written: 2,
            next_offset: 2,
        }),
        Ok(ObjectWriteChunk {
            bytes_written: 4,
            next_offset: 6,
        }),
        Ok(ObjectWriteChunk {
            bytes_written: 4,
            next_offset: 10,
        }),
    ]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("partial");

    let next = objects
        .write_all(
            &upload,
            0,
            b"abcdefghij",
            NonZeroUsize::new(4).context("nonzero chunk limit")?,
        )
        .await?;

    let script = writer.lock()?;
    anyhow::ensure!(next == 10);
    anyhow::ensure!(
        script.calls
            == vec![
                (0, b"abcd".to_vec()),
                (2, b"cdef".to_vec()),
                (6, b"ghij".to_vec()),
            ]
    );
    anyhow::ensure!(script.replies.is_empty() && script.commits == 0 && script.aborts == 0);
    Ok(())
}

#[tokio::test]
async fn sequential_appends_resume_from_nonzero_absolute_offsets() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([
        Ok(ObjectWriteChunk {
            bytes_written: 1,
            next_offset: 4097,
        }),
        Ok(ObjectWriteChunk {
            bytes_written: 2,
            next_offset: 4099,
        }),
        Ok(ObjectWriteChunk {
            bytes_written: 2,
            next_offset: 4101,
        }),
    ]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("resume");
    let limit = NonZeroUsize::new(2).context("nonzero chunk limit")?;

    let next = objects.write_all(&upload, 4096, b"abc", limit).await?;
    let end = objects.write_all(&upload, next, b"de", limit).await?;

    let script = writer.lock()?;
    anyhow::ensure!(next == 4099 && end == 4101);
    anyhow::ensure!(
        script.calls
            == vec![
                (4096, b"ab".to_vec()),
                (4097, b"bc".to_vec()),
                (4099, b"de".to_vec()),
            ]
    );
    Ok(())
}

#[tokio::test]
async fn invalid_acknowledgements_stop_without_cleanup_or_another_write() -> anyhow::Result<()> {
    let limit = NonZeroUsize::new(4).context("nonzero chunk limit")?;
    for (reason, written, next_offset) in [
        ("zero progress", 0, 17),
        ("zero progress with offset change", 0, 18),
        ("accepted more than the offered window", 5, 22),
        ("offset did not advance", 1, 17),
        ("offset skipped bytes", 1, 19),
        ("unrelated offset", 1, u64::MAX),
    ] {
        let writer = Arc::new(ScriptedWriter::new([Ok(ObjectWriteChunk {
            bytes_written: written,
            next_offset,
        })]));
        let objects = ObjectStore::new().with_write(Arc::clone(&writer));
        let upload = UploadId::stateless(reason);

        let result = objects.write_all(&upload, 17, b"abcdef", limit).await;

        anyhow::ensure!(
            matches!(
                result,
                Err(xolotl_state::StateFailure {
                    error: StateError::Backend(_),
                    ..
                })
            ),
            "{reason}"
        );
        let script = writer.lock()?;
        anyhow::ensure!(script.calls.len() == 1, "{reason}");
        anyhow::ensure!(script.commits == 0 && script.aborts == 0, "{reason}");
    }
    Ok(())
}

#[tokio::test]
async fn an_unrepresentable_range_is_rejected_before_any_write() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("overflow");

    let result = objects
        .write_all(&upload, u64::MAX - 1, b"ab", NonZeroUsize::MIN)
        .await;

    anyhow::ensure!(matches!(
        result,
        Err(xolotl_state::StateFailure {
            error: StateError::Unsupported(_),
            ..
        })
    ));
    let script = writer.lock()?;
    anyhow::ensure!(script.calls.is_empty() && script.commits == 0 && script.aborts == 0);
    Ok(())
}

#[tokio::test]
async fn the_maximum_offset_is_valid_but_acknowledgements_cannot_wrap() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([
        Ok(ObjectWriteChunk {
            bytes_written: 1,
            next_offset: u64::MAX,
        }),
        Ok(ObjectWriteChunk {
            bytes_written: 2,
            next_offset: 0,
        }),
    ]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("last-byte");

    let next = objects
        .write_all(&upload, u64::MAX - 1, b"a", NonZeroUsize::MIN)
        .await?;
    anyhow::ensure!(next == u64::MAX);

    let other = UploadId::stateless("overflowing-ack");
    let result = objects
        .write_all(&other, u64::MAX - 1, b"b", NonZeroUsize::MIN)
        .await;
    anyhow::ensure!(matches!(
        result,
        Err(xolotl_state::StateFailure {
            error: StateError::Backend(_),
            ..
        })
    ));
    let script = writer.lock()?;
    anyhow::ensure!(script.calls.len() == 2 && script.aborts == 0);
    Ok(())
}

#[tokio::test]
async fn adapter_errors_preserve_the_upload_for_explicit_resumption() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([
        Ok(ObjectWriteChunk {
            bytes_written: 2,
            next_offset: 2,
        }),
        Err(StateError::Unsupported("temporarily unavailable").into()),
        Ok(ObjectWriteChunk {
            bytes_written: 3,
            next_offset: 5,
        }),
    ]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("retry");
    let limit = NonZeroUsize::new(3).context("nonzero chunk limit")?;

    let result = objects.write_all(&upload, 0, b"abcde", limit).await;
    anyhow::ensure!(matches!(
        result,
        Err(xolotl_state::StateFailure {
            error: StateError::Unsupported("temporarily unavailable"),
            ..
        })
    ));
    anyhow::ensure!(writer.lock()?.aborts == 0);

    let next = objects.write_all(&upload, 2, b"cde", limit).await?;
    anyhow::ensure!(next == 5);
    let script = writer.lock()?;
    anyhow::ensure!(
        script.calls
            == vec![
                (0, b"abc".to_vec()),
                (2, b"cde".to_vec()),
                (2, b"cde".to_vec()),
            ]
    );
    anyhow::ensure!(script.commits == 0 && script.aborts == 0);
    Ok(())
}

#[tokio::test]
async fn empty_appends_require_a_writer_but_do_not_contact_it() -> anyhow::Result<()> {
    let writer = Arc::new(ScriptedWriter::new([]));
    let objects = ObjectStore::new().with_write(Arc::clone(&writer));
    let upload = UploadId::stateless("empty");

    let next = objects
        .write_all(&upload, u64::MAX, &[], NonZeroUsize::MIN)
        .await?;
    anyhow::ensure!(next == u64::MAX && writer.lock()?.calls.is_empty());

    let result = ObjectStore::new()
        .write_all(&upload, 0, &[], NonZeroUsize::MIN)
        .await;
    anyhow::ensure!(matches!(
        result,
        Err(xolotl_state::StateFailure {
            error: StateError::MissingCapability("object.write"),
            ..
        })
    ));
    Ok(())
}
