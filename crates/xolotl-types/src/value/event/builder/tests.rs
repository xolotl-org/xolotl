use super::*;
use crate::{
    BlobRef, DType, FloatBits, FrameKind, Path, StreamMarker, TaintSet, TaintSource, Value,
    ValueView,
    value::event::{Atom, Kind, ValueCursor},
};
use alloc::{collections::BTreeMap, string::String};
use anyhow::{Context, ensure};
use core::num::NonZeroUsize;
use std::thread;

fn feed<'a>(
    builder: &mut ValueBuilder,
    events: impl IntoIterator<Item = Event<'a>>,
) -> Result<(), BuilderError> {
    for event in events {
        builder.push(event)?;
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

fn events<'a>(
    input: &'a TaintedValue,
    chunk_bytes: NonZeroUsize,
) -> anyhow::Result<Vec<Event<'a>>> {
    let mut cursor = ValueCursor::new(&input.value, &input.taint, chunk_bytes, None)?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event()? {
        events.push(event);
    }
    Ok(events)
}

fn fixture() -> anyhow::Result<TaintedValue> {
    let blob = BlobRef {
        hash: "hash".into(),
        size: u64::MAX,
        mime: Some("application/test".into()),
    };
    let mut values = vec![
        Value::null(),
        Value::boolean(false),
        Value::boolean(true),
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0042))),
        Value::float(FloatBits(-0.0)),
        Value::float(FloatBits(f64::NEG_INFINITY)),
        Value::string("a\u{00e9}\u{1f642}z".into()),
        Value::string(String::new()),
        Value::bytes(vec![0, 128, 255]),
        Value::bytes(Vec::new()),
        Value::list(Vec::new()),
        Value::map(BTreeMap::new()),
        Value::map(BTreeMap::from([
            ("".into(), Value::null()),
            ("a\u{00e9}\u{1f642}".into(), Value::boolean(true)),
            ("a\u{00e9}\u{1f642}z".into(), Value::integer(7)),
        ])),
        Value::blob(blob.clone()),
        Value::blob(BlobRef {
            hash: String::new(),
            size: 0,
            mime: None,
        }),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: "\u{1f642}".into(),
        }),
    ];
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
        values.push(Value::tensor(blob.clone(), dtype, vec![0, u64::MAX]));
        values.push(Value::tensor(blob.clone(), dtype, Vec::new()));
    }
    for kind in [
        FrameKind::Audio,
        FrameKind::Video,
        FrameKind::Pose,
        FrameKind::Sensor,
    ] {
        values.push(Value::frame(blob.clone(), i64::MIN, kind));
        values.push(Value::frame(blob.clone(), i64::MAX, kind));
    }
    let taint = TaintSet::from_recorded_sources(vec![
        TaintSource::ModelOutput,
        TaintSource::AuthorConstant,
        TaintSource::ModelOutput,
        TaintSource::Inbound {
            source: "\u{00e9}source".into(),
            channel: "\u{1f642}channel".into(),
        },
        TaintSource::Fetched {
            host: "host".into(),
        },
        TaintSource::Protected {
            path: Path::parse("path://remote/state/data/*/**")?,
        },
        TaintSource::Protected {
            path: Path::try_new("state")?,
        },
    ]);
    Ok(TaintedValue::new(Value::list(values), taint))
}

#[test]
fn every_value_and_recorded_source_roundtrips_across_byte_windows() -> anyhow::Result<()> {
    let input = fixture()?;
    for width in [1, 2, 7, usize::MAX] {
        let width = NonZeroUsize::new(width).context("nonzero fixture width")?;
        let mut builder = ValueBuilder::default();
        feed(&mut builder, events(&input, width)?)?;
        let session = builder.session.as_ref().context("unpublished document")?;
        ensure!(session.frames.is_empty() && session.frames.capacity() == 0);
        ensure!(session.keys.is_empty());
        let sources = builder.observed_taint().sources().as_ptr();
        let output = builder.finish()?;
        ensure!(output.taint.sources().as_ptr() == sources);
        ensure!(output == input);
    }
    Ok(())
}

#[test]
fn failure_retains_only_completely_observed_claims_in_one_source_store() -> anyhow::Result<()> {
    let mut builder = ValueBuilder::default();
    feed(
        &mut builder,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::Atom(Atom::Model),
            Event::Atom(Atom::Model),
            Event::Begin(Kind::Inbound),
            Event::Begin(Kind::String),
            Event::Data(b"source"),
            Event::End(Kind::String),
        ],
    )?;
    ensure!(
        builder.observed_taint().sources() == [TaintSource::ModelOutput, TaintSource::ModelOutput]
    );
    feed(
        &mut builder,
        [
            Event::Begin(Kind::String),
            Event::Data(b"channel"),
            Event::End(Kind::String),
            Event::End(Kind::Inbound),
            Event::Begin(Kind::Fetched),
            Event::Begin(Kind::String),
            Event::Data(b"unfinished host"),
        ],
    )?;
    let pointer = builder.observed_taint().sources().as_ptr();
    ensure!(builder.push(Event::End(Kind::Fetched)).is_err());
    ensure!(builder.session.is_none());
    ensure!(builder.observed_taint().sources().as_ptr() == pointer);
    ensure!(
        builder.observed_taint().sources()
            == [
                TaintSource::ModelOutput,
                TaintSource::ModelOutput,
                TaintSource::Inbound {
                    source: "source".into(),
                    channel: "channel".into(),
                },
            ]
    );
    Ok(())
}

#[test]
fn utf8_fragments_and_empty_chunks_preserve_key_order_and_value_text() -> anyhow::Result<()> {
    let input = TaintedValue::pristine(Value::map(BTreeMap::from([
        (
            "a\u{00e9}\u{1f642}".into(),
            Value::string("z\u{1f642}\u{00e9}".into()),
        ),
        ("a\u{00e9}\u{1f642}z".into(), Value::string(String::new())),
    ])));
    let source = events(&input, NonZeroUsize::MAX)?;
    for split in 0..=9 {
        let mut builder = ValueBuilder::default();
        for event in &source {
            if let Event::Data(bytes) = event {
                let (left, right) = bytes.split_at(split.min(bytes.len()));
                builder.push(Event::Data(&[]))?;
                builder.push(Event::Data(left))?;
                builder.push(Event::Data(&[]))?;
                builder.push(Event::Data(right))?;
                builder.push(Event::Data(&[]))?;
            } else {
                builder.push(*event)?;
            }
        }
        ensure!(builder.finish()? == input);
    }
    Ok(())
}

#[test]
fn eof_at_every_incomplete_prefix_never_publishes() -> anyhow::Result<()> {
    let input = TaintedValue::pristine(Value::map(BTreeMap::from([
        ("alpha".into(), Value::list(vec![Value::integer(3)])),
        ("beta".into(), Value::string("\u{1f642}".into())),
    ])));
    let source = events(&input, NonZeroUsize::MIN)?;
    for end in 0..source.len() {
        let mut builder = ValueBuilder::default();
        feed(&mut builder, source[..end].iter().copied())?;
        ensure!(matches!(
            builder.finish(),
            Err(BuilderError::Validation(
                ValidationError::IncompleteDocument
            ))
        ));
    }
    let mut builder = ValueBuilder::default();
    feed(&mut builder, source)?;
    ensure!(builder.finish()? == input);
    Ok(())
}

#[test]
fn trailing_input_releases_even_a_completed_unpublished_value() -> anyhow::Result<()> {
    let mut builder = ValueBuilder::default();
    feed(&mut builder, document([Event::Atom(Atom::Null)]))?;
    let error = builder
        .push(Event::Atom(Atom::Null))
        .err()
        .context("trailing atom accepted")?;
    ensure!(matches!(error, BuilderError::Validation(_)));
    ensure!(builder.session.is_none());
    ensure!(builder.push(Event::End(Kind::Document)) == Err(error.clone()));
    ensure!(builder.finish() == Err(error));
    Ok(())
}

#[test]
fn malformed_documents_close_and_release_the_entire_session() -> anyhow::Result<()> {
    let cases = [
        vec![Event::Begin(Kind::String), Event::Data(&[0xff])],
        vec![Event::Begin(Kind::List), Event::End(Kind::Map)],
        vec![Event::Atom(Atom::U64(1))],
        vec![Event::Begin(Kind::Blob), Event::End(Kind::Blob)],
        vec![
            Event::Begin(Kind::Map),
            Event::Begin(Kind::Key),
            Event::Data(b"z"),
            Event::End(Kind::Key),
            Event::Atom(Atom::Null),
            Event::Begin(Kind::Key),
            Event::Data(b"a"),
        ],
        vec![
            Event::Begin(Kind::Map),
            Event::Begin(Kind::Key),
            Event::End(Kind::Key),
            Event::Atom(Atom::Null),
            Event::Begin(Kind::Key),
            Event::End(Kind::Key),
        ],
    ];
    for body in cases {
        let mut builder = ValueBuilder::default();
        let error = feed(&mut builder, document(body))
            .err()
            .context("malformed fixture accepted")?;
        ensure!(matches!(error, BuilderError::Validation(_)));
        ensure!(builder.session.is_none());
        ensure!(builder.finish() == Err(error));
    }
    let mut builder = ValueBuilder::default();
    let error = feed(
        &mut builder,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::Begin(Kind::Protected),
            Event::Begin(Kind::Path),
            Event::Atom(Atom::Null),
            Event::Begin(Kind::String),
            Event::Data(b"bad/scheme"),
        ],
    )
    .err()
    .context("invalid structured path accepted")?;
    ensure!(error == BuilderError::Validation(ValidationError::Path));
    ensure!(builder.session.is_none());
    Ok(())
}

#[test]
fn admission_is_opt_in_and_independent_of_chunk_boundaries() -> anyhow::Result<()> {
    let input = fixture()?;
    let source = events(&input, NonZeroUsize::MAX)?;
    let mut payload_bytes = 0_u64;
    let mut nodes = 0_u64;
    for event in &source {
        match event {
            Event::Data(bytes) => payload_bytes += u64::try_from(bytes.len())?,
            Event::Begin(_) | Event::Atom(_) => nodes += 1,
            Event::End(_) => {}
        }
    }
    let limits = MaterializationLimits {
        max_payload_bytes: Some(payload_bytes),
        max_nodes: Some(nodes),
        max_frames: None,
    };
    for width in [NonZeroUsize::MIN, NonZeroUsize::MAX] {
        let mut builder = ValueBuilder::new(limits);
        feed(&mut builder, events(&input, width)?)?;
        ensure!(builder.finish()? == input);
    }
    for (limits, dimension, limit) in [
        (
            MaterializationLimits {
                max_payload_bytes: Some(payload_bytes - 1),
                ..limits
            },
            MaterializationDimension::PayloadBytes,
            payload_bytes - 1,
        ),
        (
            MaterializationLimits {
                max_nodes: Some(nodes - 1),
                ..limits
            },
            MaterializationDimension::Nodes,
            nodes - 1,
        ),
    ] {
        let mut builder = ValueBuilder::new(limits);
        ensure!(
            feed(&mut builder, source.iter().copied())
                == Err(BuilderError::Admission { dimension, limit })
        );
        ensure!(builder.session.is_none());
    }
    Ok(())
}

#[test]
fn external_blob_size_does_not_charge_resident_payload_admission() -> anyhow::Result<()> {
    let input = TaintedValue::pristine(Value::blob(BlobRef {
        hash: String::new(),
        size: u64::MAX,
        mime: None,
    }));
    let mut builder = ValueBuilder::new(MaterializationLimits {
        max_payload_bytes: Some(0),
        ..MaterializationLimits::default()
    });
    feed(&mut builder, events(&input, NonZeroUsize::MIN)?)?;
    ensure!(builder.finish()? == input);
    let mut builder = ValueBuilder::new(MaterializationLimits {
        max_frames: Some(0),
        ..MaterializationLimits::default()
    });
    ensure!(
        builder.push(Event::Begin(Kind::Document))
            == Err(BuilderError::Validation(ValidationError::FrameBudget {
                limit: 0
            }))
    );
    ensure!(builder.session.is_none());
    Ok(())
}

#[test]
fn wide_collections_preserve_members_across_leaf_and_forest_boundaries() -> anyhow::Result<()> {
    for width in [0, 1, 31, 32, 33, 63, 64, 65, 1025, 65_537] {
        let mut builder = ValueBuilder::default();
        start_list_document(&mut builder)?;
        for index in 0..width {
            builder.push(Event::Atom(Atom::I64(i64::from(index))))?;
        }
        builder.push(Event::End(Kind::List))?;
        builder.push(Event::End(Kind::Document))?;
        let output = builder.finish()?;
        let list = output.value.as_list().context("list output")?;
        ensure!(list.len() == usize::try_from(width)?);
        for (index, value) in list.iter().enumerate() {
            ensure!(value.as_int() == Some(i64::try_from(index)?));
        }
    }
    for width in [0, 1, 31, 32, 33, 63, 64, 65, 1025] {
        let mut builder = ValueBuilder::default();
        feed(
            &mut builder,
            [
                Event::Begin(Kind::Document),
                Event::Begin(Kind::Taint),
                Event::End(Kind::Taint),
                Event::Begin(Kind::Map),
            ],
        )?;
        for index in 0..width {
            let key = format!("key-{index:05}");
            feed(
                &mut builder,
                [
                    Event::Begin(Kind::Key),
                    Event::Data(key.as_bytes()),
                    Event::End(Kind::Key),
                    Event::Atom(Atom::I64(i64::from(index))),
                ],
            )?;
        }
        builder.push(Event::End(Kind::Map))?;
        builder.push(Event::End(Kind::Document))?;
        let output = builder.finish()?;
        let map = output.value.as_map().context("map output")?;
        ensure!(map.len() == usize::try_from(width)?);
        for (index, (key, value)) in map.iter().enumerate() {
            ensure!(key == format!("key-{index:05}"));
            ensure!(value.as_int() == Some(i64::try_from(index)?));
        }
    }
    Ok(())
}

#[test]
fn invalid_input_discards_unfinished_leaf_and_completed_forest_members() -> anyhow::Result<()> {
    let mut builder = ValueBuilder::default();
    start_list_document(&mut builder)?;
    for index in 0..1057 {
        builder.push(Event::Atom(Atom::I64(index)))?;
    }
    open_nested(&mut builder, 512)?;
    builder.push(Event::Atom(Atom::Null))?;
    close_nested(&mut builder, 512)?;
    ensure!(matches!(
        builder.push(Event::Data(b"invalid outside a field")),
        Err(BuilderError::Validation(_))
    ));
    ensure!(builder.session.is_none());
    Ok(())
}

fn open_nested(builder: &mut ValueBuilder, depth: usize) -> anyhow::Result<()> {
    for level in 0..depth {
        if level % 2 == 0 {
            builder.push(Event::Begin(Kind::List))?;
        } else {
            feed(
                builder,
                [
                    Event::Begin(Kind::Map),
                    Event::Begin(Kind::Key),
                    Event::Data(b"child"),
                    Event::End(Kind::Key),
                ],
            )?;
        }
    }
    Ok(())
}

fn close_nested(builder: &mut ValueBuilder, depth: usize) -> anyhow::Result<()> {
    for level in (0..depth).rev() {
        builder.push(Event::End(if level % 2 == 0 {
            Kind::List
        } else {
            Kind::Map
        }))?;
    }
    Ok(())
}

fn start_list_document(builder: &mut ValueBuilder) -> anyhow::Result<()> {
    feed(
        builder,
        [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Begin(Kind::List),
        ],
    )?;
    Ok(())
}

#[test]
fn deep_build_failure_and_abandoned_release_use_a_small_stack() -> anyhow::Result<()> {
    thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let depth = 24_000;
            let mut builder = ValueBuilder::default();
            start_list_document(&mut builder)?;
            open_nested(&mut builder, depth)?;
            builder.push(Event::Atom(Atom::I64(7)))?;
            close_nested(&mut builder, depth)?;
            builder.push(Event::End(Kind::List))?;
            builder.push(Event::End(Kind::Document))?;
            let output = builder.finish()?;
            let mut current = output
                .value
                .as_list()
                .and_then(|v| v.first())
                .context("root")?;
            for _level in 0..depth {
                current = match current.view() {
                    ValueView::List(values) => values.first().context("list child")?,
                    ValueView::Map(values) => values.get("child").context("map child")?,
                    _ => anyhow::bail!("nested collection missing"),
                };
            }
            ensure!(current.as_int() == Some(7));
            drop(output);

            let mut builder = ValueBuilder::default();
            start_list_document(&mut builder)?;
            open_nested(&mut builder, depth)?;
            builder.push(Event::Atom(Atom::Null))?;
            close_nested(&mut builder, depth)?;
            ensure!(builder.push(Event::Data(b"invalid outside field")).is_err());
            ensure!(builder.session.is_none());
            drop(builder);

            let mut abandoned = ValueBuilder::default();
            start_list_document(&mut abandoned)?;
            open_nested(&mut abandoned, depth)?;
            abandoned.push(Event::Atom(Atom::Null))?;
            close_nested(&mut abandoned, depth)?;
            open_nested(&mut abandoned, depth)?;
            drop(abandoned);
            Ok(())
        })?
        .join()
        .map_err(|_error| anyhow::anyhow!("deep builder thread unwound"))?
}
