use anyhow::{Context, ensure};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use xolotl_kernel::{FactLookup, FactLookupResult, FactQuery, FactStore};
use xolotl_state::prelude::*;
use xolotl_state::test_support::{CollectHistory, CollectState};
use xolotl_state::{StateEvent, TaintedValue};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{
    BlobRef, DType, DecisionTag, ExecutionId, Fact, FloatBits, FrameKind, HandleId, IdentityRef,
    InvocationId, MethodId, NodeId, OperationId, Path, ProcessId, ReplayClass, ResourceId,
    StreamMarker, TaintSet, TaintSource, Timestamp, Value,
};

fn values() -> Vec<Value> {
    let blob = BlobRef {
        hash: "0123456789abcdef".repeat(4),
        size: u64::MAX,
        mime: Some("application/octet-stream".into()),
    };
    let mut values = vec![
        Value::null(),
        Value::boolean(false),
        Value::boolean(true),
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::string("quotes: \"; newline: \n; unicode: \u{2603}".into()),
        Value::bytes(vec![0, 127, 128, 255]),
        Value::bytes(Vec::new()),
        Value::list(Vec::new()),
        Value::map(BTreeMap::new()),
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), DType::Bf16, vec![1, u64::MAX]),
        Value::frame(blob, i64::MIN, FrameKind::Pose),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: "stream stopped".into(),
        }),
        Value::map(BTreeMap::from([
            ("type".into(), Value::string("bytes".into())),
            ("value".into(), Value::list(vec![Value::integer(1)])),
        ])),
    ];
    values.extend(
        [
            0,
            1,
            0x8000_0000_0000_0000,
            1.0_f64.to_bits(),
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0x7ff8_1234_5678_9abc,
            0xfff8_1234_5678_9abc,
        ]
        .into_iter()
        .map(|bits| Value::float(FloatBits(f64::from_bits(bits)))),
    );
    values.push(Value::map(BTreeMap::from([(
        "nested".into(),
        Value::list(values.clone()),
    )])));
    values
}

fn taint() -> anyhow::Result<TaintSet> {
    let mut taint = TaintSet::author();
    for source in [
        TaintSource::ModelOutput,
        TaintSource::Inbound {
            source: "source/codec".into(),
            channel: "events".into(),
        },
        TaintSource::Fetched {
            host: "example.test".into(),
        },
        TaintSource::Protected {
            path: Path::parse("path://cluster/state/private/codec")?,
        },
    ] {
        taint.add(source);
    }
    Ok(taint)
}

fn value_path(index: usize) -> anyhow::Result<Path> {
    Ok(Path::parse(&format!("state://codec/values/v{index:03}"))?)
}

fn fact(index: usize, value: Value, taint: TaintSet) -> anyhow::Result<Fact> {
    Ok(Fact {
        id: OperationId::new(
            ProcessId::new(1),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(u32::try_from(index)?),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: value.clone(),
        taint,
        decision: DecisionTag::Ok,
        outcome: Some(value),
        batch: None,
        replay: ReplayClass::Observation,
        timestamp: Timestamp::millis(0),
    })
}

#[tokio::test]
async fn state_values_and_history_preserve_every_value_type_after_reopen() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("values.redb");
    let values = values();
    let taint = taint()?;
    let prefix = Path::parse("state://codec/values")?;
    let sequence = Path::parse("state://codec/sequence")?;
    {
        let store = RedbStore::open(&file)?;
        let state = store.state_backend();
        for (index, value) in values.iter().enumerate() {
            state
                .write_set_tainted(&value_path(index)?, value.clone(), taint.clone())
                .await?;
            state
                .write_append_tainted(&sequence, value.clone(), taint.clone())
                .await?;
        }
    }
    let store = RedbStore::open(&file)?;
    let state = store.state_backend();
    let rows = state.read_prefix_tainted(&prefix).await?;
    ensure!(rows.len() == values.len());
    let history = state.read_range(&prefix, 0, i64::MAX).await?;
    let appends = state.read_range(&sequence, 0, i64::MAX).await?;
    ensure!(history.len() == values.len() && appends.len() == values.len());
    for (index, value) in values.iter().enumerate() {
        let path = value_path(index)?;
        let expected = TaintedValue::new(value.clone(), taint.clone());
        ensure!(state.read_tainted(&path).await?.as_ref() == Some(&expected));
        ensure!(rows[index] == (path.clone(), expected));
        ensure!(matches!(
            &history[index].event,
            StateEvent::Set { path: found, value: stored, taint: provenance }
                if found == &path && stored == value && provenance == &taint
        ));
        ensure!(matches!(
            &appends[index].event,
            StateEvent::Append { path, item, taint: provenance }
                if path == &sequence && item == value && provenance == &taint
        ));
    }
    ensure!(
        state.read_tainted(&sequence).await? == Some(TaintedValue::new(Value::list(values), taint))
    );
    state.write_delete(&sequence).await?;
    let history = state.read_range(&sequence, 0, i64::MAX).await?;
    ensure!(matches!(
        &history.last().context("deleted sequence history is empty")?.event,
        StateEvent::Delete { path, .. } if path == &sequence
    ));
    Ok(())
}

#[tokio::test]
async fn compare_and_set_distinguishes_bytes_from_lists_after_reopen() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("cas.redb");
    let path = Path::parse("state://codec/cas")?;
    let bytes = Value::bytes(vec![1, 2]);
    {
        let store = RedbStore::open(&file)?;
        store
            .state_backend()
            .write_set(&path, bytes.clone())
            .await?;
    }
    let store = RedbStore::open(&file)?;
    let state = store.state_backend();
    ensure!(
        state
            .write_cas(
                &path,
                Some(Value::list(vec![Value::integer(1), Value::integer(2)])),
                Value::null(),
            )
            .await
            .is_err()
    );
    ensure!(state.read(&path).await? == Some(bytes.clone()));
    let replacement = Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_1234)));
    let taint = taint()?;
    state
        .write_cas_tainted(&path, Some(bytes), replacement.clone(), taint.clone())
        .await?;
    ensure!(state.read_tainted(&path).await? == Some(TaintedValue::new(replacement, taint)));
    Ok(())
}

#[test]
fn fact_inputs_and_outcomes_preserve_every_value_type_after_reopen() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("facts.redb");
    let taint = taint()?;
    let expected = values()
        .into_iter()
        .enumerate()
        .map(|(index, value)| fact(index, value, taint.clone()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    {
        let store = RedbStore::open(&file)?;
        let facts = store.fact_store()?;
        for fact in &expected {
            let mut pending = fact.clone();
            pending.outcome = None;
            facts.append(pending)?;
        }
    }
    {
        let store = RedbStore::open(&file)?;
        let facts = store.fact_store()?;
        for expected in &expected {
            let pending = facts.get(expected.id)?.context("pending fact missing")?;
            ensure!(pending.input == expected.input && pending.taint == taint);
            facts.complete(expected.clone())?;
        }
    }
    let store = RedbStore::open(&file)?;
    let facts = store.fact_store()?;
    ensure!(facts.all_facts()? == expected);
    ensure!(facts.facts_of(ProcessId::new(1))? == expected);
    for expected in &expected {
        let max_bytes = NonZeroUsize::new(serde_json::to_vec(expected)?.len())
            .context("empty fact encoding")?;
        ensure!(matches!(
            facts.lookup(FactLookup {
                id: expected.id,
                process: Some(expected.caller),
                max_encoded_bytes: max_bytes,
            })?,
            FactLookupResult::Found(found) if &found == expected
        ));
    }
    let mut query = FactQuery::new(NonZeroUsize::MIN, NonZeroUsize::MAX);
    for expected in &expected {
        let page = facts.scan(query)?;
        ensure!(page.facts.as_slice() == std::slice::from_ref(expected));
        ensure!(page.encoded_bytes == serde_json::to_vec(expected)?.len());
        if let Some(next) = query.next_page(&page) {
            query = next;
        }
    }
    Ok(())
}
