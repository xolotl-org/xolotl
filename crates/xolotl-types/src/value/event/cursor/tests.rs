use super::*;
use crate::{DType, FloatBits, FrameKind, FrameRef, TensorRef};
use alloc::collections::BTreeMap;
use alloc::string::String;
use anyhow::{Context, ensure};

fn events<'a>(value: &'a Value, taint: &'a TaintSet) -> anyhow::Result<Vec<Event<'a>>> {
    let mut cursor = ValueCursor::new(value, taint, NonZeroUsize::MAX, None)?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event()? {
        events.push(event);
    }
    ensure!(cursor.next_event()?.is_none());
    ensure!(cursor.frames.is_empty() && cursor.frames.capacity() == 0);
    Ok(events)
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

#[test]
fn fixed_values_preserve_type_and_float_bits() -> anyhow::Result<()> {
    let taint = TaintSet::pristine();
    let nan_bits = 0x7ff8_0000_0000_0042;
    let cases = [
        (Value::null(), Atom::Null),
        (Value::boolean(false), Atom::Bool(false)),
        (Value::boolean(true), Atom::Bool(true)),
        (Value::integer(i64::MIN), Atom::I64(i64::MIN)),
        (Value::integer(i64::MAX), Atom::I64(i64::MAX)),
        (
            Value::float(FloatBits(-0.0)),
            Atom::F64Bits((-0.0_f64).to_bits()),
        ),
        (
            Value::float(FloatBits(f64::from_bits(nan_bits))),
            Atom::F64Bits(nan_bits),
        ),
        (Value::stream_end(StreamMarker::Done), Atom::StreamDone),
    ];
    for (value, atom) in &cases {
        ensure!(events(value, &taint)? == document([Event::Atom(*atom)]));
    }
    Ok(())
}

#[test]
fn scalar_windows_borrow_bytes_and_split_utf8() -> anyhow::Result<()> {
    let text = "a\u{00e9}\u{1f642}z";
    let value = Value::string(text.into());
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::new(&value, &taint, NonZeroUsize::MIN, None)?;
    let original = value.as_str().context("string fixture")?.as_bytes();
    let mut offset = 0;
    let mut non_utf8_chunks = 0;
    let mut saw_begin = false;
    let mut saw_end = false;
    while let Some(event) = cursor.next_event()? {
        match event {
            Event::Begin(Kind::String) => saw_begin = true,
            Event::Data(chunk) => {
                ensure!(saw_begin && !saw_end);
                ensure!(chunk.len() == 1);
                ensure!(core::ptr::eq(chunk.as_ptr(), original[offset..].as_ptr()));
                ensure!(chunk == &original[offset..offset + 1]);
                non_utf8_chunks += usize::from(core::str::from_utf8(chunk).is_err());
                offset += chunk.len();
            }
            Event::End(Kind::String) => saw_end = true,
            _ => {}
        }
    }
    ensure!(offset == original.len() && saw_end && non_utf8_chunks > 0);
    let borrowed = original;
    drop(cursor);
    ensure!(borrowed == text.as_bytes());
    Ok(())
}

#[test]
fn data_events_outlive_the_cursor_that_emitted_them() -> anyhow::Result<()> {
    let value = Value::bytes(vec![0, 127, 128, 255]);
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::new(&value, &taint, NonZeroUsize::MIN, None)?;
    let chunk = loop {
        if let Event::Data(bytes) = cursor.next_event()?.context("fixture has a data field")? {
            break bytes;
        }
    };
    drop(cursor);
    ensure!(chunk == [0]);
    Ok(())
}

#[test]
fn empty_fields_and_collections_are_explicit() -> anyhow::Result<()> {
    let value = Value::list(vec![
        Value::string(String::new()),
        Value::bytes(Vec::new()),
        Value::list(Vec::new()),
        Value::map(BTreeMap::new()),
    ]);
    let taint = TaintSet::pristine();
    ensure!(
        events(&value, &taint)?
            == document([
                Event::Begin(Kind::List),
                Event::Begin(Kind::String),
                Event::End(Kind::String),
                Event::Begin(Kind::Bytes),
                Event::End(Kind::Bytes),
                Event::Begin(Kind::List),
                Event::End(Kind::List),
                Event::Begin(Kind::Map),
                Event::End(Kind::Map),
                Event::End(Kind::List),
            ])
    );
    Ok(())
}

#[test]
fn map_keys_follow_utf8_order_and_precede_their_values() -> anyhow::Result<()> {
    let value = Value::map(BTreeMap::from([
        ("z".into(), Value::integer(3)),
        ("aa".into(), Value::integer(2)),
        (String::new(), Value::integer(1)),
    ]));
    let taint = TaintSet::pristine();
    ensure!(
        events(&value, &taint)?
            == document([
                Event::Begin(Kind::Map),
                Event::Begin(Kind::Key),
                Event::End(Kind::Key),
                Event::Atom(Atom::I64(1)),
                Event::Begin(Kind::Key),
                Event::Data(b"aa"),
                Event::End(Kind::Key),
                Event::Atom(Atom::I64(2)),
                Event::Begin(Kind::Key),
                Event::Data(b"z"),
                Event::End(Kind::Key),
                Event::Atom(Atom::I64(3)),
                Event::End(Kind::Map),
            ])
    );
    Ok(())
}

#[test]
fn media_metadata_and_stream_errors_retain_every_field() -> anyhow::Result<()> {
    let blob = BlobRef {
        hash: "h".into(),
        size: u64::MAX,
        mime: None,
    };
    let value = Value::list(vec![
        Value::blob(BlobRef {
            hash: "b".into(),
            size: 0,
            mime: Some("type".into()),
        }),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::Bf16,
            shape: vec![0, u64::MAX],
        }),
        Value::from(FrameRef {
            blob,
            ts_nanos: i64::MIN,
            kind: FrameKind::Sensor,
        }),
        Value::stream_end(StreamMarker::Error {
            message: "m".into(),
        }),
    ]);
    let taint = TaintSet::pristine();
    ensure!(
        events(&value, &taint)?
            == document([
                Event::Begin(Kind::List),
                Event::Begin(Kind::Blob),
                Event::Begin(Kind::String),
                Event::Data(b"b"),
                Event::End(Kind::String),
                Event::Atom(Atom::U64(0)),
                Event::Begin(Kind::String),
                Event::Data(b"type"),
                Event::End(Kind::String),
                Event::End(Kind::Blob),
                Event::Begin(Kind::Tensor),
                Event::Begin(Kind::Blob),
                Event::Begin(Kind::String),
                Event::Data(b"h"),
                Event::End(Kind::String),
                Event::Atom(Atom::U64(u64::MAX)),
                Event::Atom(Atom::Null),
                Event::End(Kind::Blob),
                Event::Atom(Atom::DType(DType::Bf16)),
                Event::Begin(Kind::Shape),
                Event::Atom(Atom::U64(0)),
                Event::Atom(Atom::U64(u64::MAX)),
                Event::End(Kind::Shape),
                Event::End(Kind::Tensor),
                Event::Begin(Kind::Frame),
                Event::Begin(Kind::Blob),
                Event::Begin(Kind::String),
                Event::Data(b"h"),
                Event::End(Kind::String),
                Event::Atom(Atom::U64(u64::MAX)),
                Event::Atom(Atom::Null),
                Event::End(Kind::Blob),
                Event::Atom(Atom::I64(i64::MIN)),
                Event::Atom(Atom::FrameKind(FrameKind::Sensor)),
                Event::End(Kind::Frame),
                Event::Begin(Kind::StreamError),
                Event::Begin(Kind::String),
                Event::Data(b"m"),
                Event::End(Kind::String),
                Event::End(Kind::StreamError),
                Event::End(Kind::List),
            ])
    );
    Ok(())
}

#[test]
fn provenance_precedes_value_and_keeps_order_and_duplicates() -> anyhow::Result<()> {
    let taint: TaintSet = serde_json::from_str(
        r#"{"sources":["model_output",{"inbound":{"source":"s","channel":"c"}},"author_constant",{"fetched":{"host":"h"}},{"protected":{"path":"path://remote/state/key"}},"model_output"]}"#,
    )?;
    ensure!(taint.sources().len() == 6);
    ensure!(
        events(&Value::null(), &taint)?
            == vec![
                Event::Begin(Kind::Document),
                Event::Begin(Kind::Taint),
                Event::Atom(Atom::Model),
                Event::Begin(Kind::Inbound),
                Event::Begin(Kind::String),
                Event::Data(b"s"),
                Event::End(Kind::String),
                Event::Begin(Kind::String),
                Event::Data(b"c"),
                Event::End(Kind::String),
                Event::End(Kind::Inbound),
                Event::Atom(Atom::Author),
                Event::Begin(Kind::Fetched),
                Event::Begin(Kind::String),
                Event::Data(b"h"),
                Event::End(Kind::String),
                Event::End(Kind::Fetched),
                Event::Begin(Kind::Protected),
                Event::Begin(Kind::Path),
                Event::Begin(Kind::String),
                Event::Data(b"remote"),
                Event::End(Kind::String),
                Event::Begin(Kind::String),
                Event::Data(b"state"),
                Event::End(Kind::String),
                Event::Begin(Kind::PathSegments),
                Event::Begin(Kind::String),
                Event::Data(b"key"),
                Event::End(Kind::String),
                Event::End(Kind::PathSegments),
                Event::End(Kind::Path),
                Event::End(Kind::Protected),
                Event::Atom(Atom::Model),
                Event::End(Kind::Taint),
                Event::Atom(Atom::Null),
                Event::End(Kind::Document),
            ]
    );
    Ok(())
}

#[test]
fn path_without_cluster_or_segments_is_structured() -> anyhow::Result<()> {
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::try_new("state")?,
    });
    ensure!(
        events(&Value::null(), &taint)?
            == vec![
                Event::Begin(Kind::Document),
                Event::Begin(Kind::Taint),
                Event::Begin(Kind::Protected),
                Event::Begin(Kind::Path),
                Event::Atom(Atom::Null),
                Event::Begin(Kind::String),
                Event::Data(b"state"),
                Event::End(Kind::String),
                Event::Begin(Kind::PathSegments),
                Event::End(Kind::PathSegments),
                Event::End(Kind::Path),
                Event::End(Kind::Protected),
                Event::End(Kind::Taint),
                Event::Atom(Atom::Null),
                Event::End(Kind::Document),
            ]
    );
    Ok(())
}

#[test]
fn wide_containers_and_long_fields_use_only_active_frames() -> anyhow::Result<()> {
    let value = Value::map(BTreeMap::from([(
        "k".repeat(100_000),
        Value::list((0..10_000).map(Value::integer).collect()),
    )]));
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::new(&value, &taint, NonZeroUsize::MIN, Some(3))?;
    let mut key_bytes = 0;
    let mut integers = 0;
    while let Some(event) = cursor.next_event()? {
        match event {
            Event::Data(bytes) => {
                ensure!(bytes == b"k");
                key_bytes += bytes.len();
            }
            Event::Atom(Atom::I64(value)) => {
                ensure!(value == integers);
                integers += 1;
            }
            _ => {}
        }
        ensure!(cursor.frames.len() <= 3 && cursor.frames.capacity() <= 3);
    }
    ensure!(key_bytes == 100_000 && integers == 10_000);
    Ok(())
}

#[test]
fn metadata_and_provenance_fields_share_the_same_byte_window() -> anyhow::Result<()> {
    let value = Value::from(TensorRef {
        blob: BlobRef {
            hash: "h".repeat(1_001),
            size: u64::MAX,
            mime: Some("m".repeat(2_003)),
        },
        dtype: DType::F16,
        shape: vec![u64::MAX; 10_000],
    });
    let mut taint = TaintSet::of(TaintSource::Inbound {
        source: "s".repeat(3_001).into(),
        channel: "c".repeat(4_003).into(),
    });
    taint.add(TaintSource::Fetched {
        host: "h".repeat(5_003).into(),
    });
    taint.add(TaintSource::Protected {
        path: Path::try_new("state")?
            .try_with_cluster("r".repeat(6_001))?
            .try_push_literal("p".repeat(7_001))?,
    });
    let mut cursor = ValueCursor::new(
        &value,
        &taint,
        NonZeroUsize::new(7).context("nonzero fixture window")?,
        Some(6),
    )?;
    let mut byte_count = 0;
    let mut unsigned_fields = 0;
    while let Some(event) = cursor.next_event()? {
        match event {
            Event::Data(bytes) => {
                ensure!(!bytes.is_empty() && bytes.len() <= 7);
                byte_count += bytes.len();
            }
            Event::Atom(Atom::U64(value)) => {
                ensure!(value == u64::MAX);
                unsigned_fields += 1;
            }
            _ => {}
        }
    }
    ensure!(byte_count == 1_001 + 2_003 + 3_001 + 4_003 + 5_003 + 6_001 + 7_001 + 5);
    ensure!(unsigned_fields == 10_001);
    Ok(())
}

struct DeepList(Value);

impl DeepList {
    fn new(depth: usize) -> Self {
        let mut value = Value::null();
        for _ in 0..depth {
            value = Value::list(vec![value]);
        }
        Self(value)
    }
}

#[test]
fn deep_walk_and_partial_cursor_drop_do_not_use_recursive_call_stack() -> anyhow::Result<()> {
    let worker =
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let source = DeepList::new(20_000);
                let taint = TaintSet::pristine();
                let mut cursor = ValueCursor::new(&source.0, &taint, NonZeroUsize::MIN, None)?;
                let mut begins = 0;
                let mut ends = 0;
                while let Some(event) = cursor.next_event()? {
                    match event {
                        Event::Begin(Kind::List) => begins += 1,
                        Event::End(Kind::List) => ends += 1,
                        _ => {}
                    }
                }
                ensure!(begins == 20_000 && ends == begins);
                ensure!(cursor.frames.is_empty() && cursor.frames.capacity() == 0);
                let mut partial = ValueCursor::new(&source.0, &taint, NonZeroUsize::MIN, None)?;
                for _ in 0..10_000 {
                    ensure!(partial.next_event()?.is_some());
                }
                drop(partial);
                ensure!(source.0.as_list().is_some());
                Ok(())
            })?;
    match worker.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("deep cursor worker did not complete"),
    }
}

#[test]
fn frame_budget_failure_releases_work_and_is_sticky() -> anyhow::Result<()> {
    let source = DeepList::new(100);
    let taint = TaintSet::pristine();
    ensure!(matches!(
        ValueCursor::new(&source.0, &taint, NonZeroUsize::MIN, Some(0)),
        Err(CursorError::FrameBudget { limit: 0 })
    ));
    let mut cursor = ValueCursor::new(&source.0, &taint, NonZeroUsize::MIN, Some(8))?;
    let error = loop {
        match cursor.next_event() {
            Ok(Some(_)) => {}
            Ok(None) => anyhow::bail!("deep fixture unexpectedly fit the frame budget"),
            Err(error) => break error,
        }
    };
    ensure!(error == CursorError::FrameBudget { limit: 8 });
    ensure!(cursor.frames.is_empty() && cursor.frames.capacity() == 0);
    for _ in 0..3 {
        ensure!(cursor.next_event() == Err(error.clone()));
    }
    ensure!(source.0.as_list().is_some());
    Ok(())
}
