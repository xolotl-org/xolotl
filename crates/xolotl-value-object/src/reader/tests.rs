use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use anyhow::{Context as _, Result, ensure};
use core::{
    cell::Cell,
    future::{Future, Ready, ready},
    num::NonZeroUsize,
    pin::{Pin, pin},
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use xolotl_state::{StateResult, object::ObjectReadChunk};
use xolotl_types::{
    BlobRef, DType, FloatBits, FrameKind, Path, StreamMarker, TaintSource, TaintedValue, Value,
    value::event::{Kind, MaterializationLimits, ValueCursor},
};
use xolotl_value_codec::{cbor::Encoder, validation::MemoryKeyError};

use crate::test_support::{BlockingKeys, keys, run};

#[derive(Clone, Copy)]
enum Mode {
    Ready,
    Pending,
    Fail,
    Stall,
    Overrun,
    WrongEnd,
}

struct Store {
    bytes: Vec<u8>,
    metadata: ObjectMetadata,
    present: Cell<bool>,
    metadata_fail: Cell<bool>,
    mode: Cell<Mode>,
    metadata_reads: Cell<usize>,
    reads: Cell<usize>,
    largest_window: Cell<usize>,
    max_read: usize,
}

impl Store {
    fn new(bytes: Vec<u8>, max_read: usize) -> Self {
        Self {
            metadata: ObjectMetadata {
                blob: BlobRef {
                    hash: "sha256:reader-fixture".into(),
                    size: bytes.len() as u64,
                    // Explicit encoding still selects CBOR with unrelated MIME.
                    mime: Some("application/octet-stream".into()),
                },
                taint: metadata_sources(),
            },
            bytes,
            present: Cell::new(true),
            metadata_fail: Cell::new(false),
            mode: Cell::new(Mode::Ready),
            metadata_reads: Cell::new(0),
            reads: Cell::new(0),
            largest_window: Cell::new(0),
            max_read,
        }
    }

    fn reference(&self) -> EncodedValueRef {
        EncodedValueRef {
            blob: self.metadata.blob.clone(),
            encoding: ValueEncoding::CborV1,
        }
    }

    fn read(&self, blob: &BlobRef, offset: u64, buffer: &mut [u8]) -> StateResult<ObjectReadChunk> {
        if blob != &self.metadata.blob {
            return Err(
                StateError::Backend("reader changed the canonical reference".into()).into(),
            );
        }
        if matches!(self.mode.get(), Mode::Fail) {
            return Err(StateFailure::new(
                StateError::Backend("fixture read failed".into()),
                failure_sources(),
            ));
        }
        let offset = usize::try_from(offset)
            .map_err(|_error| StateError::Backend("fixture offset overflow".into()))?;
        let remaining = self
            .bytes
            .get(offset..)
            .ok_or_else(|| StateError::Backend("fixture offset out of range".into()))?;
        let count = buffer.len().min(self.max_read).min(remaining.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        let end = count == remaining.len();
        let mut taint = chunk_sources();
        if end {
            taint.union(&eof_sources());
        }
        Ok(ObjectReadChunk {
            bytes_read: match self.mode.get() {
                Mode::Stall => 0,
                Mode::Overrun => buffer.len() + 1,
                _ => count,
            },
            end: match self.mode.get() {
                Mode::WrongEnd => !end,
                Mode::Stall => false,
                _ => end,
            },
            taint,
        })
    }
}

struct ChunkFuture {
    result: Option<StateResult<ObjectReadChunk>>,
    pending: bool,
}

impl Future for ChunkFuture {
    type Output = StateResult<ObjectReadChunk>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.pending {
            return Poll::Pending;
        }
        Poll::Ready(this.result.take().unwrap_or_else(|| {
            Err(StateError::Backend("fixture future polled after completion".into()).into())
        }))
    }
}

impl ObjectRead for Store {
    type Metadata<'a> = Ready<StateResult<Option<ObjectMetadata>>>;
    type ReadChunk<'a> = ChunkFuture;

    fn metadata<'a>(&'a self, _blob: &'a BlobRef) -> Self::Metadata<'a> {
        self.metadata_reads.set(self.metadata_reads.get() + 1);
        if self.metadata_fail.get() {
            return ready(Err(StateFailure::new(
                StateError::Backend("fixture metadata failed".into()),
                failure_sources(),
            )));
        }
        ready(Ok(self.present.get().then(|| self.metadata.clone())))
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        self.reads.set(self.reads.get() + 1);
        self.largest_window
            .set(self.largest_window.get().max(buffer.len()));
        ChunkFuture {
            result: Some(self.read(blob, offset, buffer)),
            pending: matches!(self.mode.get(), Mode::Pending),
        }
    }
}

fn metadata_sources() -> TaintSet {
    TaintSet::of(TaintSource::Fetched {
        host: "metadata.fixture".into(),
    })
}

fn chunk_sources() -> TaintSet {
    TaintSet::of(TaintSource::Inbound {
        source: "objects/fixture".into(),
        channel: "bytes".into(),
    })
}

fn eof_sources() -> TaintSet {
    TaintSet::of(TaintSource::Fetched {
        host: "final-chunk.fixture".into(),
    })
}

fn failure_sources() -> TaintSet {
    TaintSet::of(TaintSource::Fetched {
        host: "failed-operation.fixture".into(),
    })
}

fn claims() -> Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/wire-claim")?,
    }))
}

fn wire(source: &TaintedValue) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(keys(), None);
    let mut cursor = ValueCursor::new(
        &source.value,
        &source.taint,
        NonZeroUsize::new(31).context("invalid fixture chunk size")?,
        None,
    )?;
    let mut bytes = Vec::new();
    let mut scratch = [0; 19];
    while let Some(event) = cursor.next_event()? {
        let mut pending = run(encoder.encode(event))?;
        while !pending.is_complete() {
            let count = pending.write(&mut scratch)?;
            ensure!(count != 0);
            bytes.extend_from_slice(&scratch[..count]);
        }
    }
    while !encoder.is_complete() {
        let count = encoder.finish(&mut scratch)?;
        ensure!(count != 0);
        bytes.extend_from_slice(&scratch[..count]);
    }
    Ok(bytes)
}

fn read_failure(error: &anyhow::Error) -> Result<&ReadFailure<MemoryKeyError>> {
    error
        .downcast_ref::<ReadFailure<MemoryKeyError>>()
        .context("missing reader failure")
}

fn typed_source() -> Result<TaintedValue> {
    let blob = BlobRef {
        hash: "nested-reference-only".into(),
        size: u64::MAX,
        mime: Some("model/arbitrary".into()),
    };
    Ok(TaintedValue::new(
        Value::map(BTreeMap::from([
            ("bytes".into(), Value::bytes(vec![0xa5; 1024])),
            ("blob".into(), Value::blob(blob.clone())),
            (
                "float".into(),
                Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0042))),
            ),
            (
                "frame".into(),
                Value::frame(blob.clone(), i64::MIN, FrameKind::Audio),
            ),
            (
                "tensor".into(),
                Value::tensor(blob, DType::F32, vec![u64::MAX, 0]),
            ),
            ("text".into(), Value::string("通用🧠".repeat(31))),
            (
                "values".into(),
                Value::list(vec![
                    Value::null(),
                    Value::boolean(true),
                    Value::integer(i64::MIN),
                    Value::float(FloatBits(-0.0)),
                    Value::stream_end(StreamMarker::Done),
                    Value::stream_end(StreamMarker::Error {
                        message: "typed stream failure".into(),
                    }),
                ]),
            ),
        ])),
        claims()?,
    ))
}

#[test]
fn typed_values_round_trip_through_short_windows_with_all_sources() -> Result<()> {
    let source = typed_source()?;
    for window in [1, 2, 7, 31] {
        let store = Store::new(wire(&source)?, 3);
        let mut scratch = vec![0; window];
        let value = run(read_value(
            &store,
            &store.reference(),
            &mut scratch,
            keys(),
            TaintSet::author(),
            MaterializationLimits::default(),
        ))?;
        ensure!(value.value == source.value);
        for sources in [
            TaintSet::author(),
            metadata_sources(),
            chunk_sources(),
            eof_sources(),
            claims()?,
        ] {
            ensure!(value.taint.contains_all(&sources));
        }
        ensure!(store.metadata_reads.get() == 1);
        ensure!(store.reads.get() > 100);
        ensure!(store.largest_window.get() <= window);
    }
    Ok(())
}

#[test]
fn forwarded_events_publish_final_sources_and_reopen_as_the_same_typed_value() -> Result<()> {
    let source = typed_source()?;
    let input = Store::new(wire(&source)?, 3);
    let output = crate::test_support::Store::new(2);
    let mut input_scratch = [0; 7];
    let mut output_scratch = [0; 11];
    let reader = run(ValueObjectReader::open(
        &input,
        &input.reference(),
        &mut input_scratch,
        keys(),
        None,
        TaintSet::author(),
    ))?;
    let writer = run(crate::ValueObjectWriter::begin(
        &output,
        &mut output_scratch,
        keys(),
        None,
        reader.observed_taint().clone(),
    ))?;
    let committed = run(crate::copy_value(reader, writer))?;
    ensure!(output.shared.commits.load(Ordering::SeqCst) == 1);
    ensure!(committed.taint.contains_all(&eof_sources()));

    let (bytes, metadata) = {
        let data = output.shared.data();
        (
            data.published.clone().context("forwarded object missing")?,
            data.metadata
                .clone()
                .context("forwarded metadata missing")?,
        )
    };
    ensure!(metadata.blob == committed.reference.blob);
    for sources in [
        TaintSet::author(),
        metadata_sources(),
        chunk_sources(),
        eof_sources(),
    ] {
        ensure!(metadata.taint.contains_all(&sources));
    }
    let mut reopened = Store::new(bytes, 5);
    reopened.metadata = metadata;
    let mut scratch = [0; 13];
    let restored = run(read_value(
        &reopened,
        &committed.reference,
        &mut scratch,
        keys(),
        TaintSet::pristine(),
        MaterializationLimits::default(),
    ))?;
    ensure!(restored.value == source.value);
    ensure!(restored.taint.contains_all(&source.taint));
    ensure!(restored.taint.contains_all(&committed.taint));
    Ok(())
}

#[test]
fn transfer_read_and_write_failures_preserve_both_sides_and_release_staging() -> Result<()> {
    for fail_read in [false, true] {
        let mut bytes = wire(&typed_source()?)?;
        if fail_read {
            bytes.pop();
        }
        let input = Store::new(bytes, 3);
        let output = crate::test_support::Store::new(2);
        let extra = TaintSet::of(TaintSource::Fetched {
            host: "destination-input.fixture".into(),
        });
        let mut input_scratch = [0; 7];
        let mut output_scratch = [0; 11];
        let reader = run(ValueObjectReader::open(
            &input,
            &input.reference(),
            &mut input_scratch,
            keys(),
            None,
            TaintSet::author(),
        ))?;
        let writer = run(crate::ValueObjectWriter::begin(
            &output,
            &mut output_scratch,
            keys(),
            None,
            extra.clone(),
        ))?;
        if !fail_read {
            output.write_mode.set(crate::test_support::WriteMode::Fail);
        }
        let error = run(crate::copy_value(reader, writer))
            .err()
            .context("transfer failure lost")?;
        let failure = error
            .downcast_ref::<crate::CopyFailure<MemoryKeyError, MemoryKeyError>>()
            .context("missing transfer failure")?;
        if fail_read {
            ensure!(matches!(
                failure.error,
                crate::CopyError::Read(ReadError::Codec(_))
            ));
            ensure!(failure.taint.contains_all(&eof_sources()));
        } else {
            ensure!(matches!(
                failure.error,
                crate::CopyError::Write(crate::WriteError::Storage(_))
            ));
        }
        for sources in [
            TaintSet::author(),
            metadata_sources(),
            chunk_sources(),
            extra,
        ] {
            ensure!(failure.taint.contains_all(&sources));
        }
        crate::test_support::assert_cleaned(&output)?;
    }
    Ok(())
}

#[test]
fn cancelled_transfer_owns_both_sides_until_staging_is_released() -> Result<()> {
    for poll in [false, true] {
        let input = Store::new(wire(&typed_source()?)?, 3);
        let output = crate::test_support::Store::new(2);
        let mut input_scratch = [0; 7];
        let mut output_scratch = [0; 11];
        let reader = run(ValueObjectReader::open(
            &input,
            &input.reference(),
            &mut input_scratch,
            keys(),
            None,
            TaintSet::pristine(),
        ))?;
        let writer = run(crate::ValueObjectWriter::begin(
            &output,
            &mut output_scratch,
            keys(),
            None,
            TaintSet::pristine(),
        ))?;
        output
            .write_mode
            .set(crate::test_support::WriteMode::Pending);
        if poll {
            let mut future = pin!(crate::copy_value(reader, writer));
            ensure!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        } else {
            drop(crate::copy_value(reader, writer));
        }
        crate::test_support::assert_cleaned(&output)?;
    }
    Ok(())
}

#[test]
fn a_streaming_consumer_needs_only_its_window_and_a_final_receipt() -> Result<()> {
    let source = TaintedValue::pristine(Value::bytes(vec![0x7b; 64 * 1024]));
    let store = Store::new(wire(&source)?, 13);
    let reference = store.reference();
    let mut scratch = [0; 17];
    let scratch_len = scratch.len();
    let mut reader = run(ValueObjectReader::open(
        &store,
        &reference,
        &mut scratch,
        keys(),
        None,
        TaintSet::pristine(),
    ))?;
    let mut counted = 0;
    while let Some(event) = run(reader.next_event())? {
        ensure!(event.taint.contains_all(&metadata_sources()));
        ensure!(event.taint.contains_all(&chunk_sources()));
        if let Event::Data(bytes) = event.event {
            counted += bytes.len();
        }
    }
    ensure!(counted == 64 * 1024);
    ensure!(reader.is_complete());
    let receipt = reader.finish()?;
    ensure!(receipt.reference() == &reference);
    ensure!(receipt.taint().contains_all(&eof_sources()));
    ensure!(store.largest_window.get() <= scratch_len);
    ensure!(matches!(
        reader.finish().err().context("second receipt")?.error,
        ReadError::Closed
    ));
    Ok(())
}

#[test]
fn document_end_cannot_publish_a_premature_receipt() -> Result<()> {
    let source = TaintedValue::pristine(Value::null());
    let store = Store::new(wire(&source)?, usize::MAX);
    let mut scratch = [0; 64];
    let mut reader = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        None,
        TaintSet::author(),
    ))?;
    loop {
        let event = run(reader.next_event())?.context("missing document end")?;
        if event.event == Event::End(Kind::Document) {
            break;
        }
    }
    ensure!(!reader.is_complete());
    let failure = reader.finish().err().context("premature receipt")?;
    ensure!(matches!(failure.error, ReadError::Incomplete));
    ensure!(failure.taint.contains_all(&metadata_sources()));
    ensure!(!reader.is_open());
    Ok(())
}

#[test]
fn malformed_documents_preserve_actual_sources_and_completed_wire_claims() -> Result<()> {
    let source = TaintedValue::new(Value::bytes(vec![1; 50]), claims()?);
    let bytes = wire(&source)?;
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [bytes[..bytes.len() - 1].to_vec(), trailing] {
        let store = Store::new(malformed, usize::MAX);
        let mut scratch = [0; 23];
        let error = run(read_value(
            &store,
            &store.reference(),
            &mut scratch,
            keys(),
            TaintSet::author(),
            MaterializationLimits::default(),
        ))
        .err()
        .context("malformed object accepted")?;
        let failure = read_failure(&error)?;
        ensure!(matches!(failure.error, ReadError::Codec(_)));
        for sources in [
            TaintSet::author(),
            metadata_sources(),
            chunk_sources(),
            eof_sources(),
            claims()?,
        ] {
            ensure!(failure.taint.contains_all(&sources));
        }
    }
    Ok(())
}

#[test]
fn materialization_limits_preserve_claims_and_do_not_limit_streaming() -> Result<()> {
    let source = TaintedValue::new(Value::bytes(vec![1; 4096]), claims()?);
    let store = Store::new(wire(&source)?, 11);
    let mut scratch = [0; 17];
    let error = run(read_value(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        TaintSet::author(),
        MaterializationLimits {
            max_payload_bytes: Some(100),
            ..MaterializationLimits::default()
        },
    ))
    .err()
    .context("resident byte budget ignored")?;
    let failure = read_failure(&error)?;
    ensure!(matches!(
        failure.error,
        ReadError::Materialization(BuilderError::Admission { .. })
    ));
    ensure!(failure.taint.contains_all(&claims()?));
    ensure!(failure.taint.contains_all(&metadata_sources()));
    ensure!(failure.taint.contains_all(&chunk_sources()));

    let mut reader = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        None,
        TaintSet::pristine(),
    ))?;
    while run(reader.next_event())?.is_some() {}
    reader.finish()?;
    Ok(())
}

#[test]
fn mismatched_metadata_and_missing_objects_fail_before_payload_reads() -> Result<()> {
    let store = Store::new(wire(&TaintedValue::pristine(Value::null()))?, 1);
    for dimension in 0..3 {
        let mut reference = store.reference();
        match dimension {
            0 => reference.blob.hash.push('x'),
            1 => reference.blob.size += 1,
            _ => reference.blob.mime = None,
        }
        let mut scratch = [0; 7];
        let error = run(ValueObjectReader::open(
            &store,
            &reference,
            &mut scratch,
            keys(),
            None,
            TaintSet::author(),
        ))
        .err()
        .context("mismatched metadata accepted")?;
        let failure = read_failure(&error)?;
        ensure!(matches!(failure.error, ReadError::MetadataMismatch));
        ensure!(failure.taint.contains_all(&TaintSet::author()));
        ensure!(failure.taint.contains_all(&metadata_sources()));
    }
    store.present.set(false);
    let mut scratch = [0; 7];
    let error = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        None,
        TaintSet::author(),
    ))
    .err()
    .context("missing object accepted")?;
    ensure!(matches!(read_failure(&error)?.error, ReadError::Missing));
    ensure!(store.reads.get() == 0);
    Ok(())
}

#[test]
fn invalid_read_progress_keeps_the_rejected_chunks_sources() -> Result<()> {
    for mode in [Mode::Stall, Mode::Overrun, Mode::WrongEnd] {
        let store = Store::new(wire(&TaintedValue::pristine(Value::null()))?, 3);
        store.mode.set(mode);
        let mut scratch = [0; 7];
        let mut reader = run(ValueObjectReader::open(
            &store,
            &store.reference(),
            &mut scratch,
            keys(),
            None,
            TaintSet::author(),
        ))?;
        let error = run(reader.next_event())
            .err()
            .context("invalid progress accepted")?;
        let failure = read_failure(&error)?;
        ensure!(matches!(failure.error, ReadError::Storage(_)));
        ensure!(failure.taint.contains_all(&chunk_sources()));
        ensure!(!reader.is_open());
    }
    Ok(())
}

#[test]
fn empty_object_observes_its_own_eof_then_fails_document_validation() -> Result<()> {
    let store = Store::new(Vec::new(), 1);
    let mut scratch = [0; 7];
    let error = run(read_value(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        TaintSet::author(),
        MaterializationLimits::default(),
    ))
    .err()
    .context("empty object accepted as a document")?;
    let failure = read_failure(&error)?;
    ensure!(matches!(failure.error, ReadError::Codec(_)));
    ensure!(failure.taint.contains_all(&eof_sources()));
    ensure!(store.reads.get() == 1);
    ensure!(store.largest_window.get() == 0);
    Ok(())
}

#[test]
fn only_polled_read_cancellation_closes_the_owner_and_releases_keys() -> Result<()> {
    let store = Store::new(wire(&TaintedValue::pristine(Value::null()))?, 3);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut scratch = [0; 7];
    let mut reader = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        BlockingKeys(Arc::clone(&drops)),
        None,
        TaintSet::author(),
    ))?;
    drop(reader.next_event());
    ensure!(reader.is_open());
    ensure!(store.reads.get() == 0);
    ensure!(drops.load(Ordering::SeqCst) == 0);

    store.mode.set(Mode::Pending);
    {
        let mut future = pin!(reader.next_event());
        ensure!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    ensure!(!reader.is_open());
    ensure!(drops.load(Ordering::SeqCst) == 1);
    ensure!(reader.observed_taint().contains_all(&metadata_sources()));
    ensure!(reader.observed_taint().contains_all(&TaintSet::author()));
    ensure!(matches!(
        reader.finish().err().context("cancelled receipt")?.error,
        ReadError::Closed
    ));
    Ok(())
}

#[test]
fn cancelled_key_effect_keeps_acknowledged_chunk_sources() -> Result<()> {
    let source =
        TaintedValue::pristine(Value::map(BTreeMap::from([("key".into(), Value::null())])));
    let store = Store::new(wire(&source)?, usize::MAX);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut scratch = [0; 256];
    let mut reader = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        BlockingKeys(Arc::clone(&drops)),
        None,
        TaintSet::pristine(),
    ))?;
    let mut cancelled = false;
    for _ in 0..32 {
        let pending = {
            let mut future = pin!(reader.next_event());
            match future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Pending => true,
                Poll::Ready(Ok(Some(_event))) => false,
                _ => anyhow::bail!("key workspace did not block at a valid key"),
            }
        };
        if pending {
            cancelled = true;
            break;
        }
    }
    ensure!(cancelled);
    ensure!(!reader.is_open());
    ensure!(drops.load(Ordering::SeqCst) == 1);
    ensure!(reader.observed_taint().contains_all(&chunk_sources()));
    ensure!(reader.observed_taint().contains_all(&eof_sources()));
    Ok(())
}

#[test]
fn metadata_failure_retains_input_and_new_storage_sources_without_reading_bytes() -> Result<()> {
    let store = Store::new(wire(&typed_source()?)?, 3);
    store.metadata_fail.set(true);
    let mut scratch = [0; 7];
    let error = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        None,
        TaintSet::author(),
    ))
    .err()
    .context("metadata failure was accepted")?;
    let failure = read_failure(&error)?;
    ensure!(matches!(failure.error, ReadError::Storage(_)));
    ensure!(failure.taint.contains_all(&TaintSet::author()));
    ensure!(failure.taint.contains_all(&failure_sources()));
    ensure!(store.metadata_reads.get() == 1 && store.reads.get() == 0);
    Ok(())
}

#[test]
fn storage_failure_retains_prior_and_newly_observed_sources() -> Result<()> {
    let source = TaintedValue::pristine(Value::bytes(vec![0; 100]));
    let store = Store::new(wire(&source)?, 3);
    let mut scratch = [0; 7];
    let mut reader = run(ValueObjectReader::open(
        &store,
        &store.reference(),
        &mut scratch,
        keys(),
        None,
        TaintSet::author(),
    ))?;
    ensure!(run(reader.next_event())?.is_some());
    store.mode.set(Mode::Fail);
    let failure = loop {
        match run(reader.next_event()) {
            Err(error) => break error,
            Ok(Some(_event)) => {}
            Ok(None) => anyhow::bail!("read completed after injected storage failure"),
        }
    };
    let failure = read_failure(&failure)?;
    ensure!(matches!(failure.error, ReadError::Storage(_)));
    ensure!(failure.taint.contains_all(&TaintSet::author()));
    ensure!(failure.taint.contains_all(&metadata_sources()));
    ensure!(failure.taint.contains_all(&chunk_sources()));
    ensure!(failure.taint.contains_all(&failure_sources()));
    ensure!(reader.observed_taint() == &failure.taint);
    ensure!(!reader.is_open());
    Ok(())
}

#[test]
fn deep_materialization_and_truncated_cleanup_fit_a_small_stack() -> Result<()> {
    let worker = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| -> Result<()> {
            let mut value = Value::null();
            for _ in 0..20_000 {
                value = Value::list(vec![value]);
            }
            let source = TaintedValue::pristine(value);
            let bytes = wire(&source)?;
            let store = Store::new(bytes.clone(), usize::MAX);
            let mut scratch = [0; 4096];
            let restored = run(read_value(
                &store,
                &store.reference(),
                &mut scratch,
                keys(),
                TaintSet::pristine(),
                MaterializationLimits::default(),
            ))?;
            ensure!(restored.value == source.value);
            let truncated = Store::new(bytes[..bytes.len() - 2].to_vec(), usize::MAX);
            ensure!(
                run(read_value(
                    &truncated,
                    &truncated.reference(),
                    &mut scratch,
                    keys(),
                    TaintSet::pristine(),
                    MaterializationLimits::default(),
                ))
                .is_err()
            );
            drop(restored);
            drop(source);
            Ok(())
        })?;
    match worker.join() {
        Ok(result) => result,
        Err(_panic) => anyhow::bail!("reader materialization worker panicked"),
    }
}
