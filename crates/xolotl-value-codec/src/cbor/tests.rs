use alloc::{boxed::Box, collections::BTreeMap, rc::Rc, string::String, vec, vec::Vec};
use anyhow::{Context as _, Result, bail, ensure};
use core::{
    cell::Cell,
    cmp::Ordering,
    future::{Future, pending},
    num::NonZeroUsize,
    ops::Range,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use xolotl_types::{
    BlobRef, DType, FloatBits, FrameKind, FrameRef, Path, StreamMarker, TaintSet, TaintSource,
    TensorRef, Value,
    value::event::{Atom, Event, KeyId, Kind, ValidationError, ValueCursor},
};

use super::{DecodeStatus, Decoder, Encoder, Error, WireError, WireErrorKind};
use crate::validation::{KeyStore, MemoryKeyError, MemoryKeyOptions, MemoryKeyStore};

fn memory() -> MemoryKeyStore {
    MemoryKeyStore::new(MemoryKeyOptions {
        page_bytes: NonZeroUsize::MIN,
        max_keys: None,
        max_bytes: None,
    })
}

fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn run_ready<F: Future>(future: F) -> Result<F::Output> {
    match poll_once(pin!(future)) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => bail!("resident workspace unexpectedly suspended"),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Observed {
    Begin(Kind),
    End(Kind),
    Atom(Atom),
    Data(Vec<u8>),
}

fn normalize<'event>(events: impl IntoIterator<Item = Event<'event>>) -> Vec<Observed> {
    let mut normalized = Vec::new();
    for event in events {
        match event {
            Event::Begin(kind) => normalized.push(Observed::Begin(kind)),
            Event::End(kind) => normalized.push(Observed::End(kind)),
            Event::Atom(atom) => normalized.push(Observed::Atom(atom)),
            Event::Data(bytes) => match normalized.last_mut() {
                Some(Observed::Data(previous)) => previous.extend_from_slice(bytes),
                _ => normalized.push(Observed::Data(bytes.to_vec())),
            },
        }
    }
    normalized
}

fn expected(value: &Value, taint: &TaintSet) -> Result<Vec<Observed>> {
    let mut cursor = ValueCursor::new(value, taint, NonZeroUsize::MAX, None)?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event()? {
        events.push(event);
    }
    Ok(normalize(events))
}

fn write_event<K: KeyStore<Error = MemoryKeyError>>(
    encoder: &mut Encoder<K>,
    event: Event<'_>,
    output: &mut [u8],
    bytes: &mut Vec<u8>,
) -> Result<()> {
    let mut guard = run_ready(encoder.encode(event))??;
    ensure!(guard.write(&mut [])? == 0 && !guard.is_complete());
    while !guard.is_complete() {
        let count = guard.write(output)?;
        ensure!(count > 0 && count <= output.len());
        bytes.extend_from_slice(&output[..count]);
    }
    ensure!(guard.write(output)? == 0);
    Ok(())
}

fn finish_encoder<K: KeyStore<Error = MemoryKeyError>>(
    encoder: &mut Encoder<K>,
    output: &mut [u8],
    bytes: &mut Vec<u8>,
) -> Result<()> {
    ensure!(encoder.finish(&mut [])? == 0 && !encoder.is_complete());
    while !encoder.is_complete() {
        let count = encoder.finish(output)?;
        ensure!(count > 0 && count <= output.len());
        bytes.extend_from_slice(&output[..count]);
    }
    ensure!(encoder.finish(output)? == 0);
    ensure!(encoder.bytes_written() == u64::try_from(bytes.len())?);
    Ok(())
}

struct Document {
    bytes: Vec<u8>,
    document_end: Range<usize>,
}

fn encode_value(
    value: &Value,
    taint: &TaintSet,
    event_bytes: usize,
    output_bytes: usize,
) -> Result<Document> {
    let window = NonZeroUsize::new(event_bytes).context("positive event window")?;
    let mut cursor = ValueCursor::new(value, taint, window, None)?;
    let mut encoder = Encoder::new(memory(), None);
    let mut output = vec![0; output_bytes];
    let mut bytes = Vec::new();
    let mut document_end = None;
    while let Some(event) = cursor.next_event()? {
        let start = bytes.len();
        write_event(&mut encoder, event, &mut output, &mut bytes)?;
        if event == Event::End(Kind::Document) {
            document_end = Some(start..bytes.len());
        }
    }
    finish_encoder(&mut encoder, &mut output, &mut bytes)?;
    Ok(Document {
        bytes,
        document_end: document_end.context("cursor emits document end")?,
    })
}

fn feed<'input, K: KeyStore<Error = MemoryKeyError>>(
    decoder: &mut Decoder<K>,
    mut input: &'input [u8],
    events: &mut Vec<Event<'input>>,
) -> Result<()> {
    while !input.is_empty() {
        let step = run_ready(decoder.decode(input))??;
        ensure!(step.consumed > 0 && step.consumed <= input.len());
        match step.status {
            DecodeStatus::Event(event) => {
                if let Event::Data(data) = event {
                    let address = data.as_ptr() as usize;
                    let start = input.as_ptr() as usize;
                    ensure!(address >= start && address + data.len() <= start + input.len());
                }
                events.push(event);
            }
            DecodeStatus::NeedInput | DecodeStatus::End => {
                ensure!(step.consumed == input.len());
            }
        }
        input = &input[step.consumed..];
    }
    Ok(())
}

fn fixture() -> Result<(Value, TaintSet)> {
    let blob = BlobRef {
        hash: "content-hash".into(),
        size: u64::MAX,
        mime: None,
    };
    let mut values = vec![
        Value::null(),
        Value::boolean(false),
        Value::boolean(true),
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::integer(-1),
        Value::integer(0),
        Value::string(String::new()),
        Value::string("aé🙂z".into()),
        Value::bytes(Vec::new()),
        Value::bytes(vec![0, 127, 128, 255]),
        Value::list(Vec::new()),
        Value::list(vec![Value::list(vec![Value::null()])]),
        Value::map(BTreeMap::new()),
        Value::map(BTreeMap::from([
            (String::new(), Value::null()),
            ("aa".into(), Value::boolean(false)),
            ("ab".into(), Value::boolean(true)),
            ("z".into(), Value::string("last ASCII key".into())),
            ("é🙂".into(), Value::string("Unicode key".into())),
        ])),
        Value::blob(blob.clone()),
        Value::blob(BlobRef {
            hash: "empty-object".into(),
            size: 0,
            mime: Some("application/x-test; name=é🙂".into()),
        }),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: "interrupted é🙂".into(),
        }),
    ];
    for bits in [
        0,
        0x8000_0000_0000_0000,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0xfff8_0000_0000_0042,
    ] {
        values.push(Value::float(FloatBits(f64::from_bits(bits))));
    }
    for dtype in [
        DType::F16,
        DType::Bf16,
        DType::F32,
        DType::F64,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::Bool,
    ] {
        values.push(Value::from(TensorRef {
            blob: blob.clone(),
            dtype,
            shape: vec![0, 1, u64::MAX],
        }));
    }
    values.push(Value::from(TensorRef {
        blob: blob.clone(),
        dtype: DType::F32,
        shape: Vec::new(),
    }));
    for (kind, ts_nanos) in [
        (FrameKind::Audio, i64::MIN),
        (FrameKind::Video, -1),
        (FrameKind::Pose, 0),
        (FrameKind::Sensor, i64::MAX),
    ] {
        values.push(Value::from(FrameRef {
            blob: blob.clone(),
            kind,
            ts_nanos,
        }));
    }
    let mut taint = TaintSet::author();
    for source in [
        TaintSource::ModelOutput,
        TaintSource::Inbound {
            source: "gateway/入口".into(),
            channel: "upload/é🙂".into(),
        },
        TaintSource::Fetched {
            host: "host-é.test".into(),
        },
        TaintSource::Protected {
            path: Path::parse("path://remote/state/vault/secret")?,
        },
        TaintSource::Protected {
            path: Path::try_new("state")?,
        },
    ] {
        taint.add(source);
    }
    Ok((Value::list(values), taint))
}

#[test]
fn borrowed_cursor_round_trip_preserves_all_values_taint_and_float_bits() -> Result<()> {
    let (value, taint) = fixture()?;
    let expected = expected(&value, &taint)?;
    for event_bytes in [1, 7, usize::MAX] {
        for output_bytes in [1, 29] {
            let document = encode_value(&value, &taint, event_bytes, output_bytes)?;
            for input_bytes in [1, 3, 31, document.bytes.len()] {
                let mut decoder = Decoder::new(memory(), None);
                let mut events = Vec::new();
                for input in document.bytes.chunks(input_bytes) {
                    feed(&mut decoder, input, &mut events)?;
                }
                ensure!(!decoder.is_complete());
                decoder.finish()?;
                ensure!(decoder.is_complete());
                ensure!(decoder.bytes_read() == u64::try_from(document.bytes.len())?);
                drop(decoder);
                ensure!(normalize(events) == expected);
            }
        }
    }
    Ok(())
}

#[test]
fn every_transport_split_preserves_utf8_and_borrowed_data() -> Result<()> {
    let value = Value::map(BTreeMap::from([
        ("é🙂a".into(), Value::string("xé🙂z".into())),
        ("é🙂b".into(), Value::bytes(vec![0, 255, 128])),
    ]));
    let taint = TaintSet::pristine();
    let expected = expected(&value, &taint)?;
    let document = encode_value(&value, &taint, usize::MAX, 11)?;
    for split in 0..=document.bytes.len() {
        let mut decoder = Decoder::new(memory(), None);
        let mut events = Vec::new();
        feed(&mut decoder, &document.bytes[..split], &mut events)?;
        feed(&mut decoder, &document.bytes[split..], &mut events)?;
        decoder.finish()?;
        drop(decoder);
        ensure!(normalize(events) == expected, "transport split {split}");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    Create,
    Compare,
    Append,
    Release,
}

#[derive(Default)]
struct Probe {
    pending: Cell<Option<Effect>>,
    blocked: Cell<usize>,
    dropped: Cell<usize>,
    active_effects: Cell<usize>,
    cancelled_effects: Cell<usize>,
    effects_at_drop: Cell<usize>,
    bytes_at_drop: Cell<usize>,
}

struct TrackedStore {
    memory: MemoryKeyStore,
    probe: Rc<Probe>,
}

impl TrackedStore {
    fn new() -> (Self, Rc<Probe>) {
        let probe = Rc::new(Probe::default());
        (
            Self {
                memory: memory(),
                probe: Rc::clone(&probe),
            },
            probe,
        )
    }
}

impl Drop for TrackedStore {
    fn drop(&mut self) {
        self.probe.dropped.set(self.probe.dropped.get() + 1);
        self.probe
            .effects_at_drop
            .set(self.probe.active_effects.get());
        self.probe.bytes_at_drop.set(self.memory.reserved_bytes());
    }
}

struct EffectGuard {
    probe: Rc<Probe>,
    complete: bool,
}

impl EffectGuard {
    fn new(probe: &Rc<Probe>) -> Self {
        probe.active_effects.set(probe.active_effects.get() + 1);
        Self {
            probe: Rc::clone(probe),
            complete: false,
        }
    }

    async fn acknowledge(mut self, effect: Effect) {
        if self.probe.pending.get() == Some(effect) {
            self.probe.blocked.set(self.probe.blocked.get() + 1);
            pending::<()>().await;
        }
        self.complete = true;
    }
}

impl Drop for EffectGuard {
    fn drop(&mut self) {
        self.probe
            .active_effects
            .set(self.probe.active_effects.get() - 1);
        if !self.complete {
            self.probe
                .cancelled_effects
                .set(self.probe.cancelled_effects.get() + 1);
        }
    }
}

type Request<'a, T> = Pin<Box<dyn Future<Output = Result<T, MemoryKeyError>> + 'a>>;

impl KeyStore for TrackedStore {
    type Error = MemoryKeyError;
    type Create<'a> = Request<'a, ()>;
    type ComparePrefix<'a> = Request<'a, Ordering>;
    type Append<'a> = Request<'a, ()>;
    type Release<'a> = Request<'a, ()>;

    fn create(&mut self, key: KeyId) -> Self::Create<'_> {
        Box::pin(async move {
            let guard = EffectGuard::new(&self.probe);
            self.memory.create(key).await?;
            guard.acknowledge(Effect::Create).await;
            Ok(())
        })
    }

    fn compare_prefix<'a>(
        &'a mut self,
        key: KeyId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a> {
        Box::pin(async move {
            let guard = EffectGuard::new(&self.probe);
            let ordering = self.memory.compare_prefix(key, offset, bytes).await?;
            guard.acknowledge(Effect::Compare).await;
            Ok(ordering)
        })
    }

    fn append<'a>(&'a mut self, key: KeyId, offset: u64, bytes: &'a [u8]) -> Self::Append<'a> {
        Box::pin(async move {
            let guard = EffectGuard::new(&self.probe);
            self.memory.append(key, offset, bytes).await?;
            guard.acknowledge(Effect::Append).await;
            Ok(())
        })
    }

    fn release(&mut self, key: KeyId) -> Self::Release<'_> {
        Box::pin(async move {
            let guard = EffectGuard::new(&self.probe);
            self.memory.release(key).await?;
            guard.acknowledge(Effect::Release).await;
            Ok(())
        })
    }
}

#[test]
fn document_and_envelope_end_do_not_confirm_source_eof() -> Result<()> {
    let document = encode_value(&Value::null(), &TaintSet::pristine(), 1, 1)?;
    let (store, probe) = TrackedStore::new();
    let mut decoder = Decoder::new(store, None);
    let mut events = Vec::new();
    feed(
        &mut decoder,
        &document.bytes[..document.document_end.end],
        &mut events,
    )?;
    ensure!(events.last() == Some(&Event::End(Kind::Document)));
    ensure!(!decoder.is_complete() && probe.dropped.get() == 0);
    ensure!(run_ready(decoder.decode(&[]))??.status == DecodeStatus::NeedInput);
    feed(
        &mut decoder,
        &document.bytes[document.document_end.end..],
        &mut events,
    )?;
    ensure!(run_ready(decoder.decode(&[]))??.status == DecodeStatus::End);
    ensure!(!decoder.is_complete() && probe.dropped.get() == 0);
    decoder.finish()?;
    ensure!(decoder.is_complete() && probe.dropped.get() == 1);
    ensure!(matches!(
        run_ready(decoder.decode(&[]))?,
        Err(Error::Closed)
    ));
    ensure!(matches!(decoder.finish(), Err(Error::Closed)));
    Ok(())
}

#[test]
fn document_end_without_closing_envelope_is_truncated() -> Result<()> {
    let document = encode_value(&Value::null(), &TaintSet::pristine(), 1, 1)?;
    let (store, probe) = TrackedStore::new();
    let mut decoder = Decoder::new(store, None);
    feed(
        &mut decoder,
        &document.bytes[..document.document_end.end],
        &mut Vec::new(),
    )?;
    ensure!(matches!(
        decoder.finish(),
        Err(Error::Wire(WireError {
            kind: WireErrorKind::Truncated,
            ..
        }))
    ));
    ensure!(!decoder.is_complete() && probe.dropped.get() == 1);
    ensure!(matches!(
        run_ready(decoder.decode(&document.bytes[document.document_end.end..]))?,
        Err(Error::Closed)
    ));
    Ok(())
}

#[test]
fn complete_envelope_without_document_end_is_rejected() -> Result<()> {
    let document = encode_value(&Value::null(), &TaintSet::pristine(), 1, 1)?;
    // Remove a public encoder transaction, preserving its separately generated
    // closing envelope. No private event tags or framing internals are used.
    let mut bytes = document.bytes[..document.document_end.start].to_vec();
    bytes.extend_from_slice(&document.bytes[document.document_end.end..]);
    let (store, probe) = TrackedStore::new();
    let mut decoder = Decoder::new(store, None);
    feed(&mut decoder, &bytes, &mut Vec::new())?;
    ensure!(run_ready(decoder.decode(&[]))??.status == DecodeStatus::End);
    ensure!(matches!(
        decoder.finish(),
        Err(Error::Validation(ValidationError::IncompleteDocument))
    ));
    ensure!(!decoder.is_complete() && probe.dropped.get() == 1);
    ensure!(matches!(
        run_ready(decoder.decode(&[]))?,
        Err(Error::Closed)
    ));
    Ok(())
}

#[test]
fn actual_bytes_after_envelope_fail_in_same_or_later_input_window() -> Result<()> {
    let document = encode_value(&Value::null(), &TaintSet::pristine(), 1, 1)?;
    let mut appended = document.bytes.clone();
    appended.push(0);
    for separate_window in [false, true] {
        let (store, probe) = TrackedStore::new();
        let mut decoder = Decoder::new(store, None);
        let mut input = if separate_window {
            document.bytes.as_slice()
        } else {
            appended.as_slice()
        };
        let mut failure = None;
        while !input.is_empty() {
            match run_ready(decoder.decode(input))? {
                Ok(step) => {
                    ensure!(step.consumed > 0);
                    input = &input[step.consumed..];
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if separate_window {
            ensure!(failure.is_none() && probe.dropped.get() == 0);
            failure = run_ready(decoder.decode(&[0]))?.err();
        }
        ensure!(matches!(
            failure,
            Some(Error::Wire(WireError {
                kind: WireErrorKind::TrailingData,
                ..
            }))
        ));
        ensure!(!decoder.is_complete() && probe.dropped.get() == 1);
        ensure!(matches!(decoder.finish(), Err(Error::Closed)));
    }
    Ok(())
}

#[test]
fn dropping_partial_encoded_event_releases_workspace_and_closes_encoder() -> Result<()> {
    let value = Value::map(BTreeMap::from([("long-key-payload".into(), Value::null())]));
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::new(&value, &taint, NonZeroUsize::MAX, None)?;
    let (store, probe) = TrackedStore::new();
    let mut encoder = Encoder::new(store, None);
    let mut output = [0; 17];
    let mut bytes = Vec::new();
    loop {
        let event = cursor.next_event()?.context("fixture has a key payload")?;
        if matches!(event, Event::Data(_)) {
            let mut guard = run_ready(encoder.encode(event))??;
            ensure!(guard.write(&mut output[..1])? == 1);
            ensure!(!guard.is_complete() && probe.dropped.get() == 0);
            drop(guard);
            break;
        }
        write_event(&mut encoder, event, &mut output, &mut bytes)?;
    }
    ensure!(probe.dropped.get() == 1 && probe.bytes_at_drop.get() > 0);
    ensure!(matches!(
        run_ready(encoder.encode(Event::End(Kind::Key)))?,
        Err(Error::Closed)
    ));
    ensure!(matches!(encoder.finish(&mut output), Err(Error::Closed)));
    drop(encoder);
    ensure!(probe.dropped.get() == 1);
    Ok(())
}

#[test]
fn cancelling_decoder_during_each_key_effect_drops_the_session_immediately() -> Result<()> {
    let value = Value::map(BTreeMap::from([
        ("apple".into(), Value::null()),
        ("apricot".into(), Value::null()),
    ]));
    let document = encode_value(&value, &TaintSet::pristine(), usize::MAX, 13)?;
    for effect in [
        Effect::Create,
        Effect::Compare,
        Effect::Append,
        Effect::Release,
    ] {
        let (store, probe) = TrackedStore::new();
        probe.pending.set(Some(effect));
        let mut decoder = Decoder::new(store, None);
        let mut input = document.bytes.as_slice();
        loop {
            ensure!(!input.is_empty(), "did not reach {effect:?}");
            let accepted = {
                let operation = pin!(decoder.decode(input));
                match poll_once(operation) {
                    Poll::Ready(result) => Some(result?),
                    Poll::Pending => {
                        ensure!(probe.blocked.get() == 1 && probe.dropped.get() == 0);
                        ensure!(probe.active_effects.get() == 1);
                        None
                    }
                }
                // The polled operation is dropped without another poll.
            };
            let Some(step) = accepted else {
                break;
            };
            ensure!(step.consumed > 0);
            input = &input[step.consumed..];
        }
        ensure!(
            probe.dropped.get() == 1,
            "workspace retained after {effect:?}"
        );
        ensure!(probe.active_effects.get() == 0 && probe.effects_at_drop.get() == 0);
        ensure!(probe.cancelled_effects.get() == 1);
        ensure!(matches!(
            run_ready(decoder.decode(input))?,
            Err(Error::Closed)
        ));
        ensure!(matches!(decoder.finish(), Err(Error::Closed)));
        drop(decoder);
        ensure!(probe.dropped.get() == 1);
    }
    Ok(())
}

#[test]
fn dropping_unpolled_encode_and_decode_leaves_owners_usable() -> Result<()> {
    let value = Value::map(BTreeMap::from([("key".into(), Value::integer(42))]));
    let taint = TaintSet::author();
    let (store, encoder_probe) = TrackedStore::new();
    let mut encoder = Encoder::new(store, None);
    drop(encoder.encode(Event::End(Kind::Key)));
    ensure!(encoder_probe.dropped.get() == 0 && encoder.bytes_written() == 0);
    let mut cursor = ValueCursor::new(&value, &taint, NonZeroUsize::MIN, None)?;
    let mut output = [0; 7];
    let mut bytes = Vec::new();
    while let Some(event) = cursor.next_event()? {
        write_event(&mut encoder, event, &mut output, &mut bytes)?;
    }
    finish_encoder(&mut encoder, &mut output, &mut bytes)?;
    ensure!(encoder_probe.dropped.get() == 1);

    let (store, decoder_probe) = TrackedStore::new();
    let mut decoder = Decoder::new(store, None);
    drop(decoder.decode(b"invalid input"));
    ensure!(decoder_probe.dropped.get() == 0 && decoder.bytes_read() == 0);
    let mut events = Vec::new();
    feed(&mut decoder, &bytes, &mut events)?;
    decoder.finish()?;
    ensure!(decoder.is_complete() && decoder_probe.dropped.get() == 1);
    ensure!(normalize(events) == expected(&value, &taint)?);
    Ok(())
}
