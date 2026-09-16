use alloc::{collections::BTreeMap, vec, vec::Vec};
use anyhow::{Context as _, Result, ensure};
use core::{
    future::Future,
    num::NonZeroUsize,
    pin::pin,
    sync::atomic::Ordering,
    task::{Context, Waker},
};
use xolotl_types::{
    TaintSet, TaintSource, TaintedValue, Value,
    value::event::{CursorError, Event, ValueCursor},
};
use xolotl_value_codec::{
    cbor::{DecodeStatus, Decoder},
    validation::MemoryKeyError,
};

use super::encode_value;
use crate::{
    ValueEncoding, WriteError, WriteFailure,
    test_support::{Store, WriteMode, assert_cleaned, keys, run},
};

#[test]
fn completed_values_use_the_same_borrowed_event_grammar_and_final_provenance() -> Result<()> {
    let source = TaintedValue::new(
        Value::map(BTreeMap::from([
            ("payload".into(), Value::bytes(vec![0xa5; 257])),
            (
                "values".into(),
                Value::list(vec![Value::integer(-7), Value::null()]),
            ),
            (
                "text".into(),
                Value::string("snow \u{96ea} and sun \u{2600}".into()),
            ),
        ])),
        TaintSet::of(TaintSource::Fetched {
            host: "resident.test".into(),
        }),
    );
    let store = Store::new(2);
    let mut scratch = [0; 11];
    let chunk_bytes = NonZeroUsize::new(scratch.len()).context("empty test buffer")?;
    let mut cursor = ValueCursor::new(&source.value, &source.taint, chunk_bytes, None)?;
    let mut expected = Vec::new();
    while let Some(event) = cursor.next_event()? {
        expected.push(event);
    }
    let committed = run(encode_value(&store, &mut scratch, keys(), None, &source))?;
    ensure!(committed.reference.encoding == ValueEncoding::CborV1);
    ensure!(
        committed.taint
            == source
                .taint
                .clone()
                .merged(&TaintSet::of(TaintSource::ModelOutput))
    );
    ensure!(
        store
            .shared
            .data()
            .options
            .as_ref()
            .context("missing begin provenance")?
            .taint
            == source.taint
    );
    let bytes = store
        .shared
        .data()
        .published
        .clone()
        .context("missing object")?;
    let mut input = bytes.as_slice();
    let mut actual: Vec<Event<'_>> = Vec::new();
    let mut decoder = Decoder::new(keys(), None);
    while !input.is_empty() {
        let step = run(decoder.decode(input))?;
        ensure!(step.consumed != 0);
        input = &input[step.consumed..];
        if let DecodeStatus::Event(event) = step.status {
            actual.push(event);
        }
    }
    decoder.finish()?;
    ensure!(actual == expected);
    Ok(())
}

struct DeepValue(TaintedValue);

impl DeepValue {
    fn new(depth: usize) -> Self {
        let mut value = Value::bytes(vec![0xa5; 3]);
        for _ in 0..depth {
            value = Value::list(vec![value]);
        }
        Self(TaintedValue::pristine(value))
    }
}

#[test]
fn deep_source_is_neither_cloned_nor_owned_during_completion_or_cancellation() -> Result<()> {
    let worker = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| -> Result<()> {
            let source = DeepValue::new(20_000);
            let store = Store::new(usize::MAX);
            let mut scratch = [0; 4096];
            run(encode_value(&store, &mut scratch, keys(), None, &source.0))?;
            ensure!(store.shared.commits.load(Ordering::SeqCst) == 1);

            let cancelled = Store::new(usize::MAX);
            cancelled.write_mode.set(WriteMode::Pending);
            {
                let mut pending = pin!(encode_value(
                    &cancelled,
                    &mut scratch,
                    keys(),
                    None,
                    &source.0
                ));
                ensure!(
                    pending
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            assert_cleaned(&cancelled)?;
            cancelled.write_mode.set(WriteMode::Ready);
            run(encode_value(
                &cancelled,
                &mut scratch,
                keys(),
                None,
                &source.0,
            ))?;
            ensure!(cancelled.shared.commits.load(Ordering::SeqCst) == 1);
            ensure!(source.0.value.as_list().is_some());
            Ok(())
        })?;
    match worker.join() {
        Ok(result) => result,
        Err(_panic) => anyhow::bail!("borrowed resident adapter worker failed"),
    }
}

#[test]
fn cursor_budget_failure_is_reported_without_publishing_or_owning_the_source() -> Result<()> {
    let source = DeepValue::new(100);
    for limit in [0, 3] {
        let store = Store::new(usize::MAX);
        let mut scratch = [0; 64];
        let error = run(encode_value(
            &store,
            &mut scratch,
            keys(),
            Some(limit),
            &source.0,
        ))
        .err()
        .context("cursor exceeded its budget without failing")?;
        ensure!(matches!(
            error.downcast_ref::<WriteFailure<MemoryKeyError>>().map(|failure| &failure.error),
            Some(WriteError::Cursor(CursorError::FrameBudget { limit: actual })) if *actual == limit
        ));
        if limit == 0 {
            ensure!(store.shared.begins.load(Ordering::SeqCst) == 0);
        } else {
            assert_cleaned(&store)?;
        }
        ensure!(source.0.value.as_list().is_some());
    }
    Ok(())
}
