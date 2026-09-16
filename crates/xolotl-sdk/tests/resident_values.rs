#![cfg(feature = "host")]

use anyhow::{Context, ensure};
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};
use xolotl_sdk::{
    Expression, IdentityRef, InMemoryBackend, InMemoryOptions, MemoryHistory, Outcome, Path,
    Program, Transform, Value, XolotlBuilder,
};
use xolotl_types::{
    DecisionTag, ExecutionId, Fact, HandleId, InvocationId, MethodId, NodeId, OperationId,
    ProcessId, ReplayClass, ResourceId, TaintSet, TaintedValue, Timestamp,
    value::event::{Atom, Event, Kind, MaterializationLimits, ValueBuilder, ValueCursor},
};

#[tokio::test]
async fn incremental_value_composes_through_execution_state_facts_and_release() -> anyhow::Result<()>
{
    let mut builder = ValueBuilder::new(MaterializationLimits::default());
    builder.push(Event::Begin(Kind::Document))?;
    builder.push(Event::Begin(Kind::Taint))?;
    builder.push(Event::Atom(Atom::Author))?;
    builder.push(Event::End(Kind::Taint))?;
    for _ in 0..10_000 {
        builder.push(Event::Begin(Kind::List))?;
    }
    builder.push(Event::Begin(Kind::Bytes))?;
    let chunk = [42; 1024];
    for _ in 0..64 {
        builder.push(Event::Data(&chunk))?;
    }
    builder.push(Event::End(Kind::Bytes))?;
    for _ in 0..10_000 {
        builder.push(Event::End(Kind::List))?;
    }
    builder.push(Event::End(Kind::Document))?;
    let built = builder.finish()?;
    ensure!(built.taint == TaintSet::author());
    let mut rebuilt = ValueBuilder::default();
    let mut cursor = ValueCursor::new(
        &built.value,
        &built.taint,
        NonZeroUsize::new(257).context("chunk size")?,
        None,
    )?;
    while let Some(event) = cursor.next_event()? {
        rebuilt.push(event)?;
    }
    drop(cursor);
    let rebuilt = rebuilt.finish()?;
    ensure!(built == rebuilt);
    drop(built);

    let side: Arc<[u8]> = Arc::from(vec![5; 16 * 1024 * 1024]);
    let side_weak = Arc::downgrade(&side);
    let selected = rebuilt.value.clone();
    let root = Value::map(BTreeMap::from([
        ("keep".into(), rebuilt.value),
        ("side".into(), Value::shared_bytes(side)),
    ]));
    let state = InMemoryBackend::with_options(InMemoryOptions {
        history: MemoryHistory::Disabled,
        ..InMemoryOptions::default()
    })?
    .into_backend();
    let runtime = XolotlBuilder::new()
        .with_state_backend(state.clone())
        .build();
    let program = Program::new(
        Expression::Input
            .both(Expression::Input)
            .then(Expression::Transform {
                operation: Transform::Index { index: 0 },
            })
            .then(Expression::Transform {
                operation: Transform::Field {
                    name: "keep".into(),
                },
            }),
    )
    .compile()?;
    let result = runtime
        .run_program(
            IdentityRef::ROOT,
            &[],
            &program,
            TaintedValue::new(root, rebuilt.taint),
        )
        .await?;
    ensure!(result.taint == TaintSet::author());
    let Outcome::Done(value) = result.outcome else {
        anyhow::bail!("expected completed value")
    };
    ensure!(value.identity() == selected.identity());

    let path = Path::parse("state://resident/value")?;
    state
        .write_set_tainted(&path, value.clone(), result.taint.clone())
        .await?;
    let snapshot = state.read_tainted(&path).await?.context("state snapshot")?;
    ensure!(snapshot.value.identity() == value.identity());
    let pair = Value::list(vec![value.clone(), value.clone()]);
    state
        .write_cas_tainted(
            &path,
            Some(snapshot.value.clone()),
            pair.clone(),
            result.taint.clone(),
        )
        .await?;
    ensure!(snapshot.value == value);
    let sequence = Path::parse("state://resident/sequence")?;
    state
        .write_append_tainted(&sequence, pair, result.taint.clone())
        .await?;
    state
        .write_append_tainted(&sequence, value.clone(), result.taint.clone())
        .await?;
    let sequence_value = state
        .read_tainted(&sequence)
        .await?
        .context("append result")?;
    ensure!(
        sequence_value
            .value
            .as_list()
            .context("appended list")?
            .len()
            == 2
    );

    let record = Fact {
        id: OperationId::new(
            ProcessId::new(77),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(77),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: value.clone(),
        taint: result.taint,
        decision: DecisionTag::Ok,
        outcome: Some(value),
        batch: None,
        replay: ReplayClass::Observation,
        timestamp: Timestamp::millis(0),
    };
    runtime.bootstrap().kernel.facts.complete(record.clone())?;
    let retained = runtime
        .bootstrap()
        .kernel
        .facts
        .get(record.id)?
        .context("retained fact")?;
    ensure!(retained.input.identity() == record.input.identity());
    let decoded: Fact = serde_json::from_slice(&serde_json::to_vec(&retained)?)?;
    ensure!(decoded == record);
    state.write_delete(&path).await?;
    state.write_delete(&sequence).await?;
    drop((
        decoded,
        retained,
        record,
        snapshot,
        sequence_value,
        selected,
        state,
        runtime,
    ));
    ensure!(side_weak.upgrade().is_none());
    Ok(())
}
