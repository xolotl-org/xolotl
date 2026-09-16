use alloc::{sync::Arc, vec::Vec};
use anyhow::{Context as _, Result, ensure};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Waker},
};
use xolotl_types::{
    TaintSet, TaintSource,
    value::event::{Atom, Event, Kind},
};
use xolotl_value_codec::{
    cbor::{DecodeStatus, Decoder},
    validation::MemoryKeyError,
};

use super::{ValueEncoding, ValueObjectWriter, WriteError, WriteFailure};

use crate::test_support::{BlockingKeys, CommitMode, Store, WriteMode, keys, run};

static NO_LATE_TAINT: TaintSet = TaintSet::pristine();

fn final_taint() -> TaintSet {
    TaintSet::of(TaintSource::Inbound {
        source: "object-tests".into(),
        channel: "upload".into(),
    })
}

fn events(payload: &[u8]) -> [Event<'_>; 8] {
    [
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::Atom(Atom::Author),
        Event::End(Kind::Taint),
        Event::Begin(Kind::Bytes),
        Event::Data(payload),
        Event::End(Kind::Bytes),
        Event::End(Kind::Document),
    ]
}

#[test]
fn partial_acknowledgements_publish_a_complete_document_with_final_provenance() -> Result<()> {
    let store = Store::new(2);
    let mut scratch = [0; 7];
    let payload = [0xa7; 257];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    {
        let data = store.shared.data();
        let options = data.options.as_ref().context("missing upload options")?;
        ensure!(options.expected_size.is_none());
        ensure!(options.mime.as_deref() == Some(ValueEncoding::CborV1.media_type()));
        ensure!(options.taint == final_taint());
    }
    for event in events(&payload) {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    let committed = run(writer.finish(&NO_LATE_TAINT))?;
    ensure!(!writer.is_open());
    ensure!(committed.reference.encoding == ValueEncoding::CborV1);
    ensure!(committed.taint == final_taint().merged(&TaintSet::of(TaintSource::ModelOutput)));
    ensure!(
        !committed
            .taint
            .sources()
            .contains(&TaintSource::AuthorConstant)
    );
    let published = {
        let data = store.shared.data();
        let mut offset = 0;
        for &(start, offered, accepted) in &data.writes {
            ensure!(start == offset);
            ensure!(offered <= 7);
            ensure!(accepted <= 2);
            offset += accepted as u64;
        }
        ensure!(offset == committed.reference.blob.size);
        data.published.clone().context("missing committed bytes")?
    };
    ensure!(committed.reference.blob.size == published.len() as u64);
    let mut decoder = Decoder::new(keys(), None);
    let mut recovered = Vec::new();
    for mut input in published.chunks(3) {
        while !input.is_empty() {
            let step = run(decoder.decode(input))?;
            ensure!(step.consumed != 0);
            input = &input[step.consumed..];
            if let DecodeStatus::Event(Event::Data(bytes)) = step.status {
                recovered.extend_from_slice(bytes);
            }
        }
    }
    decoder.finish()?;
    ensure!(decoder.is_complete());
    ensure!(recovered == payload);
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 0);
    ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn late_sources_are_published_in_storage_metadata_before_returning_the_reference() -> Result<()> {
    let store = Store::new(3);
    let mut scratch = [0; 11];
    let initial = final_taint();
    let late = TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://vault/late-source")?,
    });
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        initial.clone(),
    ))?;
    for event in events(b"content whose sources become known during input") {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    ensure!(store.shared.data().published.is_none());
    let committed = run(writer.finish(&late))?;
    let data = store.shared.data();
    let metadata = data
        .metadata
        .as_ref()
        .context("missing published metadata")?;
    ensure!(metadata.taint.contains_all(&initial));
    ensure!(metadata.taint.contains_all(&late));
    ensure!(metadata.taint == committed.taint);
    ensure!(
        !metadata
            .taint
            .sources()
            .contains(&TaintSource::AuthorConstant)
    );
    Ok(())
}

#[test]
fn rejected_events_and_sink_failures_keep_the_events_actual_sources() -> Result<()> {
    let late = TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://vault/observed-before-write")?,
    });
    for invalid_event in [false, true] {
        let store = Store::new(1);
        let mut scratch = [0; 1];
        let mut writer = run(ValueObjectWriter::begin(
            &store,
            &mut scratch,
            keys(),
            None,
            TaintSet::pristine(),
        ))?;
        let event = if invalid_event {
            Event::End(Kind::Document)
        } else {
            store.write_mode.set(WriteMode::Fail);
            Event::Begin(Kind::Document)
        };
        let error = run(writer.write(event, &late))
            .err()
            .context("expected event or write failure")?;
        let failure = error
            .downcast_ref::<WriteFailure<MemoryKeyError>>()
            .context("missing source-bearing failure")?;
        ensure!(failure.taint.contains_all(&late));
        ensure!(writer.observed_taint() == &failure.taint);
        ensure!(!writer.is_open());
        ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
        ensure!(!store.shared.live.load(Ordering::SeqCst));
    }
    Ok(())
}

#[test]
fn missing_publication_sources_are_rejected_without_compensating_deletion() -> Result<()> {
    let store = Store::new(16);
    let mut scratch = [0; 16];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        TaintSet::pristine(),
    ))?;
    for event in events(b"published content") {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    store.commit_mode.set(CommitMode::MissingProvenance);
    let error = run(writer.finish(&final_taint()))
        .err()
        .context("missing source was accepted")?;
    ensure!(matches!(
        error
            .downcast_ref::<WriteFailure<MemoryKeyError>>()
            .map(|failure| &failure.error),
        Some(WriteError::Provenance)
    ));
    let failure = error
        .downcast_ref::<WriteFailure<MemoryKeyError>>()
        .context("missing annotated failure")?;
    ensure!(failure.taint.contains_all(&final_taint()));
    ensure!(failure.taint.sources().contains(&TaintSource::ModelOutput));
    ensure!(writer.observed_taint() == &failure.taint);
    ensure!(!writer.is_open());
    ensure!(store.shared.data().published.is_some());
    ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn deep_documents_share_output_windows_across_events() -> Result<()> {
    let store = Store::new(usize::MAX);
    let mut scratch = [0; 4096];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    for event in [
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::End(Kind::Taint),
    ] {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    for _ in 0..20_000 {
        run(writer.write(Event::Begin(Kind::List), &NO_LATE_TAINT))?;
    }
    run(writer.write(Event::Atom(Atom::Null), &NO_LATE_TAINT))?;
    for _ in 0..20_000 {
        run(writer.write(Event::End(Kind::List), &NO_LATE_TAINT))?;
    }
    run(writer.write(Event::End(Kind::Document), &NO_LATE_TAINT))?;
    let committed = run(writer.finish(&NO_LATE_TAINT))?;
    let data = store.shared.data();
    ensure!(data.writes.len() as u64 == committed.reference.blob.size.div_ceil(4096));
    ensure!(data.writes.len() < 32);
    ensure!(
        data.writes[..data.writes.len() - 1]
            .iter()
            .all(|&(_, offered, _)| offered == 4096)
    );
    Ok(())
}

#[test]
fn flush_acknowledges_buffered_bytes_and_preserves_the_open_document() -> Result<()> {
    let store = Store::new(3);
    let mut scratch = [0; 64];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    run(writer.write(Event::Begin(Kind::Document), &NO_LATE_TAINT))?;
    ensure!(store.shared.data().writes.is_empty());
    run(writer.flush())?;
    ensure!(writer.is_open());
    ensure!(store.shared.data().staging.len() == 19);
    let write_count = store.shared.data().writes.len();
    run(writer.flush())?;
    ensure!(store.shared.data().writes.len() == write_count);
    for event in events(b"payload").into_iter().skip(1) {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    let committed = run(writer.finish(&NO_LATE_TAINT))?;
    ensure!(committed.reference.blob.size > 19);
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[test]
fn cancelling_flush_reclaims_bytes_accepted_by_previous_events() -> Result<()> {
    let store = Store::new(2);
    let mut scratch = [0; 64];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    run(writer.write(Event::Begin(Kind::Document), &NO_LATE_TAINT))?;
    ensure!(store.shared.data().writes.is_empty());
    store.write_mode.set(WriteMode::Pending);
    {
        let mut pending = pin!(writer.flush());
        ensure!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ensure!(store.shared.data().staging.len() == 2);
    }
    ensure!(!writer.is_open());
    ensure!(store.shared.data().staging.is_empty());
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn cancelled_key_validation_drops_both_workspace_and_upload() -> Result<()> {
    let store = Store::new(usize::MAX);
    let mut scratch = [0; 64];
    let key_drops = Arc::new(AtomicUsize::new(0));
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        BlockingKeys(Arc::clone(&key_drops)),
        None,
        final_taint(),
    ))?;
    for event in [
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::End(Kind::Taint),
        Event::Begin(Kind::Map),
    ] {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    ensure!(store.shared.data().writes.is_empty());
    {
        let mut pending = pin!(writer.write(Event::Begin(Kind::Key), &NO_LATE_TAINT));
        ensure!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    ensure!(!writer.is_open());
    ensure!(key_drops.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn empty_buffer_is_rejected_before_creating_staging() -> Result<()> {
    let store = Store::new(1);
    let result = run(ValueObjectWriter::begin(
        &store,
        &mut [],
        keys(),
        None,
        final_taint(),
    ));
    let error = result.err().context("empty output workspace accepted")?;
    ensure!(matches!(
        error
            .downcast_ref::<WriteFailure<MemoryKeyError>>()
            .map(|failure| &failure.error),
        Some(WriteError::EmptyBuffer)
    ));
    ensure!(store.shared.begins.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn cancelling_begin_cleans_an_undelivered_upload() -> Result<()> {
    let store = Store::new(1);
    store.begin_pending.set(true);
    let mut scratch = [0; 1];
    {
        let mut pending = pin!(ValueObjectWriter::begin(
            &store,
            &mut scratch,
            keys(),
            None,
            final_taint()
        ));
        ensure!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ensure!(store.shared.live.load(Ordering::SeqCst));
    }
    ensure!(!store.shared.live.load(Ordering::SeqCst));
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn unpolled_event_and_finish_futures_preserve_the_session() -> Result<()> {
    let store = Store::new(1);
    let mut scratch = [0; 1];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    drop(writer.write(Event::Begin(Kind::Document), &NO_LATE_TAINT));
    drop(writer.flush());
    drop(writer.finish(&NO_LATE_TAINT));
    ensure!(writer.is_open());
    ensure!(store.shared.data().writes.is_empty());
    for event in events(b"") {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    run(writer.finish(&NO_LATE_TAINT))?;
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[test]
fn cancelling_the_last_event_write_discards_even_fully_generated_bytes() -> Result<()> {
    let store = Store::new(usize::MAX);
    let mut scratch = [0; 19];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    store.write_mode.set(WriteMode::Pending);
    {
        let mut pending = pin!(writer.write(Event::Begin(Kind::Document), &NO_LATE_TAINT));
        ensure!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ensure!(store.shared.data().staging.len() == 19);
    }
    ensure!(!writer.is_open());
    ensure!(store.shared.data().staging.is_empty());
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    ensure!(run(writer.finish(&NO_LATE_TAINT)).is_err());
    Ok(())
}

#[test]
fn rejected_upload_creation_combines_input_and_storage_failure_sources() -> Result<()> {
    let mut store = Store::new(2);
    store.begin_fail.set(true);
    store.failure_sources = TaintSet::of(TaintSource::ModelOutput);
    let mut scratch = [0; 7];
    let error = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))
    .err()
    .context("failed upload creation was accepted")?;
    let failure = error
        .downcast_ref::<WriteFailure<MemoryKeyError>>()
        .context("missing source-bearing begin failure")?;
    ensure!(matches!(failure.error, WriteError::Storage(_)));
    ensure!(failure.taint.contains_all(&final_taint()));
    ensure!(failure.taint.contains_all(&store.failure_sources));
    ensure!(store.shared.begins.load(Ordering::SeqCst) == 1);
    ensure!(!store.shared.live.load(Ordering::SeqCst));
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn storage_errors_and_invalid_acknowledgements_close_the_upload() -> Result<()> {
    for mode in [WriteMode::Fail, WriteMode::InvalidAck] {
        let mut store = Store::new(2);
        store.failure_sources = TaintSet::of(TaintSource::ModelOutput);
        let mut scratch = [0; 7];
        let mut writer = run(ValueObjectWriter::begin(
            &store,
            &mut scratch,
            keys(),
            None,
            final_taint(),
        ))?;
        store.write_mode.set(mode);
        let error = run(writer.write(Event::Begin(Kind::Document), &NO_LATE_TAINT))
            .err()
            .context("storage failure or invalid acknowledgement was accepted")?;
        let failure = error
            .downcast_ref::<WriteFailure<MemoryKeyError>>()
            .context("missing source-bearing write failure")?;
        ensure!(matches!(failure.error, WriteError::Storage(_)));
        ensure!(failure.taint.contains_all(&final_taint()));
        ensure!(
            failure.taint.contains_all(&store.failure_sources) == matches!(mode, WriteMode::Fail)
        );
        ensure!(writer.observed_taint() == &failure.taint);
        ensure!(!writer.is_open());
        ensure!(store.shared.data().staging.is_empty());
        ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
        ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[test]
fn invalid_events_and_early_eof_never_reach_commit() -> Result<()> {
    for invalid_event in [false, true] {
        let store = Store::new(3);
        let mut scratch = [0; 8];
        let mut writer = run(ValueObjectWriter::begin(
            &store,
            &mut scratch,
            keys(),
            None,
            final_taint(),
        ))?;
        if invalid_event {
            ensure!(run(writer.write(Event::End(Kind::Document), &NO_LATE_TAINT)).is_err());
            ensure!(store.shared.data().writes.is_empty());
        } else {
            run(writer.write(Event::Begin(Kind::Document), &NO_LATE_TAINT))?;
            ensure!(run(writer.finish(&NO_LATE_TAINT)).is_err());
        }
        ensure!(!writer.is_open());
        ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
        ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[test]
fn cancelled_envelope_write_never_reaches_commit() -> Result<()> {
    let store = Store::new(usize::MAX);
    let mut scratch = [0; 64];
    let mut writer = run(ValueObjectWriter::begin(
        &store,
        &mut scratch,
        keys(),
        None,
        final_taint(),
    ))?;
    for event in events(b"payload") {
        run(writer.write(event, &NO_LATE_TAINT))?;
    }
    store.write_mode.set(WriteMode::Pending);
    {
        let mut pending = pin!(writer.finish(&NO_LATE_TAINT));
        ensure!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    ensure!(!writer.is_open());
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn commit_cancellation_keeps_published_content_and_reclaims_unpublished_staging() -> Result<()> {
    for mode in [CommitMode::Pending, CommitMode::PublishedPending] {
        let store = Store::new(usize::MAX);
        let mut scratch = [0; 64];
        let mut writer = run(ValueObjectWriter::begin(
            &store,
            &mut scratch,
            keys(),
            None,
            final_taint(),
        ))?;
        for event in events(b"payload") {
            run(writer.write(event, &NO_LATE_TAINT))?;
        }
        store.commit_mode.set(mode);
        {
            let mut pending = pin!(writer.finish(&NO_LATE_TAINT));
            ensure!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        ensure!(!writer.is_open());
        let published = matches!(mode, CommitMode::PublishedPending);
        ensure!(store.shared.data().published.is_some() == published);
        ensure!(store.shared.data().staging.is_empty());
        ensure!(store.shared.cleanups.load(Ordering::SeqCst) == usize::from(!published));
        ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[test]
fn commit_failures_close_the_owner_without_deleting_immutable_content() -> Result<()> {
    for mode in [CommitMode::Fail, CommitMode::WrongSize] {
        let mut store = Store::new(usize::MAX);
        store.failure_sources = TaintSet::of(TaintSource::Fetched {
            host: "commit-observation.fixture".into(),
        });
        let mut scratch = [0; 64];
        let mut writer = run(ValueObjectWriter::begin(
            &store,
            &mut scratch,
            keys(),
            None,
            final_taint(),
        ))?;
        for event in events(b"payload") {
            run(writer.write(event, &NO_LATE_TAINT))?;
        }
        store.commit_mode.set(mode);
        let late = TaintSet::of(TaintSource::Protected {
            path: xolotl_types::Path::parse("state://vault/commit-input")?,
        });
        let error = run(writer.finish(&late))
            .err()
            .context("commit failure or invalid receipt was accepted")?;
        let failure = error
            .downcast_ref::<WriteFailure<MemoryKeyError>>()
            .context("missing source-bearing commit failure")?;
        ensure!(failure.taint.contains_all(&final_taint()));
        ensure!(failure.taint.contains_all(&late));
        ensure!(
            failure.taint.contains_all(&store.failure_sources) == matches!(mode, CommitMode::Fail)
        );
        ensure!(writer.observed_taint() == &failure.taint);
        ensure!(!writer.is_open());
        ensure!(store.shared.data().published.is_some() == matches!(mode, CommitMode::WrongSize));
        ensure!(store.shared.commits.load(Ordering::SeqCst) == 1);
        ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}
