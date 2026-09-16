use super::*;
use crate::{
    BlobRef, DType, FloatBits, FrameKind, FrameRef, Path, StreamMarker, TaintSet, TaintSource,
    TensorRef, Value,
};
use alloc::collections::{BTreeMap, BTreeSet};
use anyhow::{Context, ensure};
use core::num::NonZeroUsize;

#[derive(Default)]
struct MemoryKeys {
    keys: BTreeMap<KeyId, Vec<u8>>,
    created: BTreeSet<KeyId>,
    comparisons: usize,
    max_live: usize,
}

impl MemoryKeys {
    fn complete(&mut self, effect: KeyEffect<'_>) -> anyhow::Result<KeyCompletion> {
        match effect {
            KeyEffect::Create { key } => {
                ensure!(self.created.insert(key), "reused key identity");
                ensure!(self.keys.insert(key, Vec::new()).is_none());
                self.max_live = self.max_live.max(self.keys.len());
            }
            KeyEffect::ComparePrefix { key, offset, bytes } => {
                let stored = self.keys.get(&key).context("compare missing key")?;
                let start = usize::try_from(offset)?;
                let end = start
                    .checked_add(bytes.len())
                    .context("compare range overflow")?;
                let previous = stored.get(start..end).context("compare past stored key")?;
                self.comparisons += 1;
                return Ok(KeyCompletion::Compared(previous.cmp(bytes)));
            }
            KeyEffect::Append { key, offset, bytes } => {
                let stored = self.keys.get_mut(&key).context("append missing key")?;
                ensure!(
                    u64::try_from(stored.len())? == offset,
                    "append offset diverged"
                );
                stored.extend_from_slice(bytes);
            }
            KeyEffect::Release { key } => {
                ensure!(self.keys.remove(&key).is_some(), "released absent key");
            }
        }
        Ok(KeyCompletion::Done)
    }
}

fn feed(validator: &mut Validator, keys: &mut MemoryKeys, event: Event<'_>) -> anyhow::Result<()> {
    let mut validation = validator.begin(event)?;
    let mut completion = None;
    loop {
        match validation.advance(completion)? {
            ValidationStep::Accepted => return Ok(()),
            ValidationStep::Effect(effect) => completion = Some(keys.complete(effect)?),
        }
    }
}

fn feed_all<'a>(
    validator: &mut Validator,
    keys: &mut MemoryKeys,
    events: impl IntoIterator<Item = Event<'a>>,
) -> anyhow::Result<()> {
    for event in events {
        feed(validator, keys, event)?;
    }
    Ok(())
}

fn document<'a>(body: impl IntoIterator<Item = Event<'a>>) -> Vec<Event<'a>> {
    let mut events = vec![
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::End(Kind::Taint),
    ];
    events.extend(body);
    events.push(Event::End(Kind::Document));
    events
}

fn validate<'a>(events: impl IntoIterator<Item = Event<'a>>) -> anyhow::Result<MemoryKeys> {
    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    feed_all(&mut validator, &mut keys, events)?;
    validator.finish()?;
    ensure!(keys.keys.is_empty(), "successful validation retained keys");
    Ok(keys)
}

fn rejected<'a>(
    events: impl IntoIterator<Item = Event<'a>>,
    expected: ValidationError,
) -> anyhow::Result<()> {
    let error = validate(events)
        .err()
        .context("invalid document was accepted")?;
    ensure!(
        error.downcast_ref::<ValidationError>() == Some(&expected),
        "{error}"
    );
    Ok(())
}

fn field<'a>(events: &mut Vec<Event<'a>>, kind: Kind, bytes: &'a [u8], chunk: usize) {
    events.push(Event::Begin(kind));
    events.extend(bytes.chunks(chunk).map(Event::Data));
    events.push(Event::End(kind));
}

fn map<'a>(keys: &[&'a [u8]], chunk: usize) -> Vec<Event<'a>> {
    let mut body = vec![Event::Begin(Kind::Map)];
    for key in keys {
        field(&mut body, Kind::Key, key, chunk);
        body.push(Event::Atom(Atom::Null));
    }
    body.push(Event::End(Kind::Map));
    document(body)
}

fn open_map(validator: &mut Validator, keys: &mut MemoryKeys) -> anyhow::Result<()> {
    feed_all(
        validator,
        keys,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Begin(Kind::Map),
        ],
    )
}

fn key_and_value(
    validator: &mut Validator,
    keys: &mut MemoryKeys,
    bytes: &[u8],
) -> anyhow::Result<()> {
    feed_all(
        validator,
        keys,
        [
            Event::Begin(Kind::Key),
            Event::Data(bytes),
            Event::End(Kind::Key),
            Event::Atom(Atom::Null),
        ],
    )
}

#[test]
fn deeply_nested_events_have_no_recursive_value_or_fixed_depth_limit() -> anyhow::Result<()> {
    let mut validator = Validator::new(None);
    ensure!(validator.frames.capacity() == 0);
    let mut keys = MemoryKeys::default();
    feed_all(
        &mut validator,
        &mut keys,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
        ],
    )?;
    for _ in 0..30_000 {
        feed(&mut validator, &mut keys, Event::Begin(Kind::List))?;
    }
    ensure!(validator.frames.len() == 30_001);
    feed(&mut validator, &mut keys, Event::Atom(Atom::Null))?;
    for _ in 0..30_000 {
        feed(&mut validator, &mut keys, Event::End(Kind::List))?;
    }
    feed(&mut validator, &mut keys, Event::End(Kind::Document))?;
    validator.finish()?;
    ensure!(validator.frames.capacity() == 0 && keys.created.is_empty());
    Ok(())
}

#[test]
fn frame_policy_bounds_only_simultaneously_open_records() -> anyhow::Result<()> {
    let mut zero = Validator::new(Some(0));
    let mut keys = MemoryKeys::default();
    let error = feed(&mut zero, &mut keys, Event::Begin(Kind::Document))
        .err()
        .context("zero frame budget accepted document")?;
    ensure!(
        error.downcast_ref::<ValidationError>() == Some(&ValidationError::FrameBudget { limit: 0 })
    );

    let mut validator = Validator::new(Some(2));
    feed_all(
        &mut validator,
        &mut keys,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Begin(Kind::List),
        ],
    )?;
    for _ in 0..1_000 {
        feed(&mut validator, &mut keys, Event::Atom(Atom::Bool(true)))?;
    }
    ensure!(validator.frames.capacity() <= 2);
    let error = feed(&mut validator, &mut keys, Event::Begin(Kind::List))
        .err()
        .context("third frame exceeded budget")?;
    ensure!(
        error.downcast_ref::<ValidationError>() == Some(&ValidationError::FrameBudget { limit: 2 })
    );
    ensure!(validator.frames.is_empty());
    Ok(())
}

#[test]
fn every_resident_variant_and_provenance_record_passes_the_shared_grammar() -> anyhow::Result<()> {
    let blob = BlobRef {
        hash: "hash".into(),
        size: u64::MAX,
        mime: Some("application/test".into()),
    };
    let value = Value::list(vec![
        Value::null(),
        Value::boolean(false),
        Value::integer(i64::MIN),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_1234))),
        Value::float(FloatBits(-0.0)),
        Value::string("\u{00e9}\u{1f642}".into()),
        Value::bytes(vec![0, 128, 255]),
        Value::list(Vec::new()),
        Value::map(BTreeMap::from([
            ("".into(), Value::null()),
            ("key".into(), Value::boolean(true)),
        ])),
        Value::blob(blob.clone()),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::Bf16,
            shape: vec![0, u64::MAX],
        }),
        Value::from(FrameRef {
            blob,
            ts_nanos: i64::MAX,
            kind: FrameKind::Sensor,
        }),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: "\u{1f642}".into(),
        }),
    ]);
    let mut taint = TaintSet::author();
    taint.add(TaintSource::ModelOutput);
    taint.add(TaintSource::Inbound {
        source: "source".into(),
        channel: "channel".into(),
    });
    taint.add(TaintSource::Fetched {
        host: "host".into(),
    });
    taint.add(TaintSource::Protected {
        path: Path::parse("path://remote/state/data/*/**")?,
    });
    let mut cursor = super::super::ValueCursor::new(&value, &taint, NonZeroUsize::MIN, None)?;
    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    while let Some(event) = cursor.next_event()? {
        feed(&mut validator, &mut keys, event)?;
    }
    validator.finish()?;
    ensure!(keys.keys.is_empty());
    Ok(())
}

#[test]
fn repeated_provenance_labels_preserve_the_source_sequence() -> anyhow::Result<()> {
    validate([
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::Atom(Atom::Author),
        Event::Atom(Atom::Model),
        Event::Atom(Atom::Author),
        Event::End(Kind::Taint),
        Event::Atom(Atom::Null),
        Event::End(Kind::Document),
    ])?;
    Ok(())
}

#[test]
fn utf8_matches_standard_validation_across_every_small_chunk_size() -> anyhow::Result<()> {
    let fixtures: &[&[u8]] = &[
        b"",
        b"a\0z",
        "\u{00e9}".as_bytes(),
        "\u{20ac}".as_bytes(),
        "\u{1f642}".as_bytes(),
        "\u{10ffff}".as_bytes(),
        "a\u{00e9}\u{20ac}\u{1f642}z".as_bytes(),
        &[0x80],
        &[0xc0, 0x80],
        &[0xe0, 0x80, 0x80],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xf0, 0x9f],
        &[0xe2, b'a'],
        &[0xf0, 0x9f, 0x99, b'a'],
    ];
    for &bytes in fixtures {
        for chunk in 1..=5 {
            let mut body = Vec::new();
            field(&mut body, Kind::String, bytes, chunk);
            let valid = validate(document(body));
            if core::str::from_utf8(bytes).is_ok() {
                valid?;
            } else {
                let error = valid.err().context("invalid UTF-8 passed")?;
                ensure!(error.downcast_ref::<ValidationError>() == Some(&ValidationError::Utf8));
            }
            let mut body = Vec::new();
            field(&mut body, Kind::Bytes, bytes, chunk);
            validate(document(body))?;
        }
    }
    Ok(())
}

#[test]
fn empty_data_does_not_flush_an_incomplete_utf8_tail() -> anyhow::Result<()> {
    validate(document([
        Event::Begin(Kind::String),
        Event::Data(&[0xf0]),
        Event::Data(b""),
        Event::Data(&[0x9f]),
        Event::Data(b""),
        Event::Data(&[0x99]),
        Event::Data(b""),
        Event::Data(&[0x82]),
        Event::End(Kind::String),
    ]))?;
    rejected(map(&[&[0xf0, 0x9f]], 1), ValidationError::Utf8)?;
    Ok(())
}

#[test]
fn map_order_is_strict_utf8_order_independent_of_fragmentation() -> anyhow::Result<()> {
    let cases: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"", b"a"),
        (b"a", b""),
        (b"a", b"aa"),
        (b"aa", b"a"),
        (b"aa", b"b"),
        (b"b", b"aa"),
        (b"same", b"same"),
        (b"abz", b"ac"),
        (b"abc", b"abcz"),
        (b"abcz", b"abc"),
        ("\u{00e9}".as_bytes(), "\u{1f642}".as_bytes()),
    ];
    for &(previous, current) in cases {
        for chunk in 1..=5 {
            if previous < current {
                validate(map(&[previous, current], chunk))?;
            } else {
                rejected(
                    map(&[previous, current], chunk),
                    ValidationError::MapKeyOrder,
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn map_comparison_does_not_include_an_unoffered_stored_suffix() -> anyhow::Result<()> {
    let keys = validate(map(&[b"abcdef", b"abcdefg"], 2))?;
    ensure!(keys.comparisons == 3 && keys.max_live == 2);
    let keys = validate(map(&[b"abzzzzzz", b"acaaaaaaaaaaaaaaaa"], 1))?;
    ensure!(
        keys.comparisons == 2,
        "comparison continued after decisive byte"
    );
    Ok(())
}

#[test]
fn long_common_prefix_uses_scoped_storage_without_growing_semantic_frames() -> anyhow::Result<()> {
    let mut previous = vec![b'a'; 128 * 1024];
    previous.push(b'b');
    let mut current = vec![b'a'; 128 * 1024];
    current.push(b'c');
    let mut validator = Validator::new(Some(3));
    let mut keys = MemoryKeys::default();
    feed_all(&mut validator, &mut keys, map(&[&previous, &current], 37))?;
    ensure!(validator.frames.capacity() <= 3);
    validator.finish()?;
    ensure!(keys.keys.is_empty());
    ensure!(keys.max_live == 2 && keys.created.len() == 2);
    ensure!(keys.comparisons > 3_000);
    Ok(())
}

#[test]
fn nested_maps_retain_ancestor_keys_and_release_each_scope() -> anyhow::Result<()> {
    let keys = validate(document([
        Event::Begin(Kind::Map),
        Event::Begin(Kind::Key),
        Event::Data(b"parent"),
        Event::End(Kind::Key),
        Event::Begin(Kind::Map),
        Event::Begin(Kind::Key),
        Event::Data(b"a"),
        Event::End(Kind::Key),
        Event::Atom(Atom::Null),
        Event::Begin(Kind::Key),
        Event::Data(b"b"),
        Event::End(Kind::Key),
        Event::Atom(Atom::Null),
        Event::End(Kind::Map),
        Event::Begin(Kind::Key),
        Event::Data(b"z"),
        Event::End(Kind::Key),
        Event::Atom(Atom::Null),
        Event::End(Kind::Map),
    ]))?;
    ensure!(keys.max_live == 3 && keys.created.len() == 4);
    Ok(())
}

#[test]
fn append_borrows_input_and_advances_length_only_after_acknowledgement() -> anyhow::Result<()> {
    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    open_map(&mut validator, &mut keys)?;
    feed(&mut validator, &mut keys, Event::Begin(Kind::Key))?;
    let bytes = b"borrowed key bytes";
    {
        let mut transaction = validator.begin(Event::Data(bytes))?;
        let ValidationStep::Effect(
            effect @ KeyEffect::Append {
                bytes: offered,
                offset,
                ..
            },
        ) = transaction.advance(None)?
        else {
            anyhow::bail!("expected append effect");
        };
        ensure!(offset == 0 && core::ptr::eq(offered.as_ptr(), bytes.as_ptr()));
        ensure!(
            matches!(transaction.validator.frames.last(), Some(Frame::Key(key)) if key.current.length == 0)
        );
        let completion = keys.complete(effect)?;
        ensure!(transaction.advance(Some(completion))? == ValidationStep::Accepted);
    }
    ensure!(
        matches!(validator.frames.last(), Some(Frame::Key(key)) if key.current.length == bytes.len() as u64)
    );
    feed_all(
        &mut validator,
        &mut keys,
        [
            Event::End(Kind::Key),
            Event::Atom(Atom::Null),
            Event::End(Kind::Map),
            Event::End(Kind::Document),
        ],
    )?;
    validator.finish()?;
    Ok(())
}

#[test]
fn ending_a_key_waits_for_old_key_release_before_acceptance() -> anyhow::Result<()> {
    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    open_map(&mut validator, &mut keys)?;
    key_and_value(&mut validator, &mut keys, b"a")?;
    feed_all(
        &mut validator,
        &mut keys,
        [Event::Begin(Kind::Key), Event::Data(b"b")],
    )?;
    ensure!(keys.keys.len() == 2);
    {
        let mut transaction = validator.begin(Event::End(Kind::Key))?;
        let ValidationStep::Effect(effect @ KeyEffect::Release { .. }) =
            transaction.advance(None)?
        else {
            anyhow::bail!("end key did not require release");
        };
        ensure!(keys.keys.len() == 2);
        let completion = keys.complete(effect)?;
        ensure!(keys.keys.len() == 1);
        ensure!(transaction.advance(Some(completion))? == ValidationStep::Accepted);
    }
    feed_all(
        &mut validator,
        &mut keys,
        [
            Event::Atom(Atom::Null),
            Event::End(Kind::Map),
            Event::End(Kind::Document),
        ],
    )?;
    validator.finish()?;
    ensure!(keys.keys.is_empty());
    Ok(())
}

#[test]
fn dropping_fresh_or_pending_transactions_permanently_closes_validation() -> anyhow::Result<()> {
    let mut fresh = Validator::new(None);
    drop(fresh.begin(Event::Begin(Kind::Document))?);
    ensure!(fresh.finish() == Err(ValidationError::Abandoned));
    ensure!(fresh.begin(Event::Begin(Kind::Document)).err() == Some(ValidationError::Abandoned));

    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    open_map(&mut validator, &mut keys)?;
    {
        let mut transaction = validator.begin(Event::Begin(Kind::Key))?;
        let ValidationStep::Effect(effect) = transaction.advance(None)? else {
            anyhow::bail!("expected create effect");
        };
        ensure!(keys.complete(effect)? == KeyCompletion::Done);
    }
    ensure!(validator.finish() == Err(ValidationError::Abandoned));
    ensure!(
        keys.keys.len() == 1,
        "pure validator unexpectedly owned key storage"
    );
    Ok(())
}

#[test]
fn completions_cannot_be_missing_mistyped_or_replayed() -> anyhow::Result<()> {
    for completion in [None, Some(KeyCompletion::Compared(Ordering::Equal))] {
        let mut validator = Validator::new(None);
        let mut keys = MemoryKeys::default();
        open_map(&mut validator, &mut keys)?;
        {
            let mut transaction = validator.begin(Event::Begin(Kind::Key))?;
            ensure!(matches!(
                transaction.advance(None)?,
                ValidationStep::Effect(KeyEffect::Create { .. })
            ));
            ensure!(transaction.advance(completion) == Err(ValidationError::WrongCompletion));
            ensure!(
                transaction.advance(Some(KeyCompletion::Done))
                    == Err(ValidationError::WrongCompletion)
            );
        }
        ensure!(validator.finish() == Err(ValidationError::WrongCompletion));
    }
    let mut validator = Validator::new(None);
    {
        let mut transaction = validator.begin(Event::Begin(Kind::Document))?;
        ensure!(
            transaction.advance(Some(KeyCompletion::Done)) == Err(ValidationError::WrongCompletion)
        );
    }
    let mut validator = Validator::new(None);
    {
        let mut transaction = validator.begin(Event::Begin(Kind::Document))?;
        ensure!(transaction.advance(None)? == ValidationStep::Accepted);
        ensure!(transaction.advance(None) == Err(ValidationError::WrongCompletion));
    }
    ensure!(validator.finish() == Err(ValidationError::WrongCompletion));
    Ok(())
}

#[test]
fn compare_requires_ordering_and_cancellation_never_accepts_the_fragment() -> anyhow::Result<()> {
    for abandon in [false, true] {
        let mut validator = Validator::new(None);
        let mut keys = MemoryKeys::default();
        open_map(&mut validator, &mut keys)?;
        key_and_value(&mut validator, &mut keys, b"ab")?;
        feed(&mut validator, &mut keys, Event::Begin(Kind::Key))?;
        {
            let mut transaction = validator.begin(Event::Data(b"ac"))?;
            ensure!(matches!(
                transaction.advance(None)?,
                ValidationStep::Effect(KeyEffect::ComparePrefix { bytes: b"ac", .. })
            ));
            if !abandon {
                ensure!(
                    transaction.advance(Some(KeyCompletion::Done))
                        == Err(ValidationError::WrongCompletion)
                );
            }
        }
        let expected = if abandon {
            ValidationError::Abandoned
        } else {
            ValidationError::WrongCompletion
        };
        ensure!(validator.finish() == Err(expected));
    }
    Ok(())
}

#[test]
fn scalar_atoms_and_records_are_only_accepted_in_their_declared_positions() -> anyhow::Result<()> {
    for atom in [
        Atom::U64(1),
        Atom::DType(DType::F32),
        Atom::FrameKind(FrameKind::Video),
        Atom::Author,
        Atom::Model,
    ] {
        rejected(
            document([Event::Atom(atom)]),
            ValidationError::UnexpectedEvent {
                context: Some(Kind::Document),
            },
        )?;
    }
    for kind in [
        Kind::Key,
        Kind::Taint,
        Kind::Shape,
        Kind::Path,
        Kind::PathSegments,
        Kind::Inbound,
        Kind::Fetched,
        Kind::Protected,
        Kind::Document,
    ] {
        rejected(
            document([Event::Begin(kind)]),
            ValidationError::UnexpectedEvent {
                context: Some(Kind::Document),
            },
        )?;
    }
    rejected(
        document([Event::Begin(Kind::Blob), Event::End(Kind::Blob)]),
        ValidationError::IncompleteRecord { kind: Kind::Blob },
    )?;
    rejected(
        document([Event::Begin(Kind::String), Event::End(Kind::Bytes)]),
        ValidationError::MismatchedEnd {
            expected: Kind::String,
            actual: Kind::Bytes,
        },
    )?;
    rejected(
        document([
            Event::Begin(Kind::Map),
            Event::Begin(Kind::Key),
            Event::End(Kind::Key),
            Event::End(Kind::Map),
        ]),
        ValidationError::IncompleteRecord { kind: Kind::Map },
    )?;
    rejected(
        document([Event::Data(b"not a field")]),
        ValidationError::UnexpectedEvent {
            context: Some(Kind::Document),
        },
    )?;
    Ok(())
}

#[test]
fn eof_is_required_and_cannot_be_repaired_after_finishing() -> anyhow::Result<()> {
    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    let mut events = document([Event::Atom(Atom::Null)]);
    ensure!(events.pop() == Some(Event::End(Kind::Document)));
    feed_all(&mut validator, &mut keys, events)?;
    ensure!(validator.finish() == Err(ValidationError::IncompleteDocument));
    ensure!(
        validator.begin(Event::End(Kind::Document)).err()
            == Some(ValidationError::IncompleteDocument)
    );
    let mut validator = Validator::new(None);
    feed_all(
        &mut validator,
        &mut keys,
        document([Event::Atom(Atom::Null)]),
    )?;
    validator.finish()?;
    ensure!(
        validator.begin(Event::Begin(Kind::Document)).err()
            == Some(ValidationError::UnexpectedEvent { context: None })
    );
    rejected([], ValidationError::IncompleteDocument)?;
    Ok(())
}

fn path_document<'a>(
    cluster: Option<&'a str>,
    scheme: &'a str,
    segments: &[&'a str],
    chunk: usize,
) -> Vec<Event<'a>> {
    let mut events = vec![
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::Begin(Kind::Protected),
        Event::Begin(Kind::Path),
    ];
    if let Some(cluster) = cluster {
        field(&mut events, Kind::String, cluster.as_bytes(), chunk);
    } else {
        events.push(Event::Atom(Atom::Null));
    }
    field(&mut events, Kind::String, scheme.as_bytes(), chunk);
    events.push(Event::Begin(Kind::PathSegments));
    for segment in segments {
        field(&mut events, Kind::String, segment.as_bytes(), chunk);
    }
    events.extend([
        Event::End(Kind::PathSegments),
        Event::End(Kind::Path),
        Event::End(Kind::Protected),
        Event::End(Kind::Taint),
        Event::Atom(Atom::Null),
        Event::End(Kind::Document),
    ]);
    events
}

#[test]
fn fragmented_path_identifiers_agree_with_checked_path_builders() -> anyhow::Result<()> {
    let fixtures = [
        "",
        "a",
        "1",
        "a1",
        "_",
        "-",
        "a_b-c",
        "a.b:c",
        "*",
        "**",
        "***",
        "a*",
        "*a",
        "a/b",
        "a@b",
        " a",
        "\u{00e9}",
        "state",
        "effect",
        "process",
        "proc",
        "blob",
        "tensor",
        "State",
        "statex",
        "xxxxxxxxxxxxxxxx",
    ];
    for text in fixtures {
        for chunk in [1, 2, 32] {
            let stream = validate(path_document(None, text, &[], chunk)).is_ok();
            ensure!(
                stream == Path::try_new(text).is_ok(),
                "scheme mismatch: {text:?}"
            );
            let stream = validate(path_document(None, "state", &[text], chunk)).is_ok();
            ensure!(
                stream == Path::try_new("state")?.try_push(text).is_ok(),
                "segment mismatch: {text:?}"
            );
            let stream = validate(path_document(Some(text), "state", &[], chunk)).is_ok();
            ensure!(
                stream == Path::try_new("state")?.try_with_cluster(text).is_ok(),
                "cluster mismatch: {text:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn all_six_reserved_cluster_names_and_only_complete_wildcards_keep_their_rules()
-> anyhow::Result<()> {
    for scheme in ["state", "effect", "process", "proc", "blob", "tensor"] {
        rejected(
            path_document(Some(scheme), "state", &[], 1),
            ValidationError::Path,
        )?;
        ensure!(matches!(
            Path::try_new("state")?.try_with_cluster(scheme),
            Err(crate::PathError::ReservedCluster(_))
        ));
        validate(path_document(None, scheme, &["*", "**", "a.b:c"], 1))?;
    }
    for invalid in ["***", "*a", "a*", "a**"] {
        rejected(
            path_document(None, "state", &[invalid], 1),
            ValidationError::Path,
        )?;
    }
    let parsed = Path::parse("path://remote/state/a/*/**")?;
    validate(path_document(
        parsed.cluster(),
        parsed.scheme(),
        &["a", "*", "**"],
        1,
    ))?;
    Ok(())
}

#[test]
fn key_identity_and_length_overflow_are_explicit_and_terminal() -> anyhow::Result<()> {
    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    open_map(&mut validator, &mut keys)?;
    validator.next_key = Some(u64::MAX);
    key_and_value(&mut validator, &mut keys, b"a")?;
    ensure!(keys.created.contains(&KeyId(u64::MAX)));
    let error = feed(&mut validator, &mut keys, Event::Begin(Kind::Key))
        .err()
        .context("key identity wrapped")?;
    ensure!(error.downcast_ref::<ValidationError>() == Some(&ValidationError::KeyExhausted));
    ensure!(validator.finish() == Err(ValidationError::KeyExhausted));

    let mut validator = Validator::new(None);
    let mut keys = MemoryKeys::default();
    open_map(&mut validator, &mut keys)?;
    feed(&mut validator, &mut keys, Event::Begin(Kind::Key))?;
    let Some(Frame::Key(key)) = validator.frames.last_mut() else {
        anyhow::bail!("missing key frame");
    };
    key.current.length = u64::MAX;
    let error = feed(&mut validator, &mut keys, Event::Data(b"x"))
        .err()
        .context("key length wrapped")?;
    ensure!(error.downcast_ref::<ValidationError>() == Some(&ValidationError::LengthOverflow));
    ensure!(validator.finish() == Err(ValidationError::LengthOverflow));
    Ok(())
}
