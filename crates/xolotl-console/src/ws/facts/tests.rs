use super::*;
use anyhow::{Context, ensure};
use xolotl_kernel::FactStore;
use xolotl_types::{
    DecisionTag, ExecutionId, HandleId, IdentityRef, InvocationId, MethodId, NodeId, OperationId,
    ReplayClass, ResourceId, TaintSet, Timestamp,
};

fn fact(process: u64, position: u32) -> Fact {
    Fact {
        id: OperationId::new(
            ProcessId::new(process),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(position),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(process),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: Value::null(),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome: None,
        batch: None,
        replay: ReplayClass::Observation,
        timestamp: Timestamp::millis(0),
    }
}

fn config() -> ConsoleWsConfig {
    ConsoleWsConfig {
        max_frame_bytes: HARD_MAX_WS_FRAME_BYTES,
        ..ConsoleWsConfig::default()
    }
}

fn page(sink: &FactSink, kind: ReadKind, fields: &[(&str, Value)]) -> anyhow::Result<ValueMap> {
    let mut input = fields
        .iter()
        .map(|(key, value)| ((*key).into(), value.clone()))
        .collect();
    let query = query(&config(), kind, Some(1), &mut input)?;
    let Some(output) = read_page(sink, query, kind)?.into_map() else {
        anyhow::bail!("fact page must be a map");
    };
    Ok(output)
}

fn items(page: &ValueMap) -> anyhow::Result<&xolotl_types::ValueList> {
    match page.get("items").and_then(Value::as_list) {
        Some(items) => Ok(items),
        _ => anyhow::bail!("page items must be a list"),
    }
}

#[test]
fn detail_preserves_typed_payload_and_complete_media_metadata() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let mut record = fact(1, 0);
    let input = Value::list(vec![
        Value::bytes(vec![0, 255]),
        Value::float(xolotl_types::FloatBits(f64::from_bits(u64::MAX))),
    ]);
    record.input = input.clone();
    let blob = xolotl_types::BlobRef {
        hash: "object".into(),
        size: u64::MAX,
        mime: Some("application/octet-stream".into()),
    };
    let outcome = Value::list(vec![
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), xolotl_types::DType::F64, vec![u64::MAX, 0]),
        Value::frame(blob, i64::MIN, xolotl_types::FrameKind::Sensor),
    ]);
    record.outcome = Some(outcome.clone());
    store.append(record.clone())?;
    let output = read_detail(
        &sink,
        FactLookup {
            id: record.id,
            process: Some(record.caller),
            max_encoded_bytes: NonZeroUsize::new(4096).context("budget")?,
        },
    )?;
    let fields = output.as_map().context("detail map")?;
    ensure!(fields.get("input") == Some(&input));
    ensure!(fields.get("outcome") == Some(&outcome));
    ensure!(fields.get("completed") == Some(&Value::boolean(true)));
    Ok(())
}

#[test]
fn detail_distinguishes_pending_and_successful_null() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let mut record = fact(1, 0);
    let query = FactLookup {
        id: record.id,
        process: Some(record.caller),
        max_encoded_bytes: NonZeroUsize::new(4096).context("budget")?,
    };
    store.append(record.clone())?;
    let pending = read_detail(&sink, query)?;
    let fields = pending.as_map().context("detail map")?;
    ensure!(!fields.contains_key("outcome"));
    ensure!(fields.get("completed") == Some(&Value::boolean(false)));

    record.outcome = Some(Value::null());
    store.complete(record)?;
    let completed = read_detail(&sink, query)?;
    let fields = completed.as_map().context("detail map")?;
    ensure!(fields.get("outcome") == Some(&Value::null()));
    ensure!(fields.get("completed") == Some(&Value::boolean(true)));
    Ok(())
}

#[test]
fn sparse_pages_continue_by_append_slot_in_both_directions() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let first = fact(1, 0);
    let last = fact(1, 2);
    store.append(first.clone())?;
    store.append(fact(2, 1))?;
    store.append(last.clone())?;
    let newest = page(
        &sink,
        ReadKind::Recent,
        &[
            ("limit", Value::integer(1)),
            ("max_examined", Value::integer(1)),
        ],
    )?;
    ensure!(newest.get("next") == Some(&Value::string("2".into())));
    ensure!(newest.get("end") == Some(&Value::string("3".into())));
    ensure!(
        items(&newest)?
            .get(0)
            .context("first fact")?
            .as_map()
            .and_then(|m| m.get("op_id"))
            == Some(&Value::string(last.id.to_string()))
    );

    store.append(fact(1, 3))?;
    let empty = page(
        &sink,
        ReadKind::Recent,
        &[
            ("before", Value::string("2".into())),
            ("max_examined", Value::integer(1)),
        ],
    )?;
    ensure!(items(&empty)?.is_empty());
    ensure!(empty.get("examined") == Some(&Value::integer(1)));
    ensure!(empty.get("next") == Some(&Value::string("1".into())));
    ensure!(empty.get("complete") == Some(&Value::boolean(false)));
    let oldest = page(
        &sink,
        ReadKind::Recent,
        &[("before", Value::string("1".into()))],
    )?;
    ensure!(items(&oldest)?.len() == 1);
    ensure!(oldest.get("next") == Some(&Value::null()));
    ensure!(
        items(&oldest)?
            .get(0)
            .context("first fact")?
            .as_map()
            .and_then(|m| m.get("op_id"))
            == Some(&Value::string(first.id.to_string()))
    );

    let empty = page(
        &sink,
        ReadKind::Trace,
        &[
            ("from", Value::string("1".into())),
            ("before", Value::integer(3)),
            ("max_examined", Value::integer(1)),
        ],
    )?;
    ensure!(items(&empty)?.is_empty());
    ensure!(empty.get("next") == Some(&Value::string("2".into())));
    let next = page(
        &sink,
        ReadKind::Trace,
        &[
            ("from", Value::string("2".into())),
            ("before", Value::string("3".into())),
        ],
    )?;
    ensure!(items(&next)?.len() == 1);
    ensure!(next.get("next") == Some(&Value::null()));
    ensure!(next.get("complete") == Some(&Value::boolean(true)));
    ensure!(next.get("partial") == Some(&Value::boolean(true)));
    ensure!(!next.contains_key("total_facts"));
    Ok(())
}

#[test]
fn cursor_and_fact_identifiers_preserve_the_full_unsigned_range() -> anyhow::Result<()> {
    for cursor in [0, i64::MAX as u64 + 1, u64::MAX] {
        let value = cursor_value(cursor);
        ensure!(value.as_str() == Some(cursor.to_string().as_str()));
        let mut input = ValueMap::from(BTreeMap::from([("before".into(), value)]));
        ensure!(optional_cursor_arg(&mut input, "before")? == Some(cursor));
    }
    let record = fact(u64::MAX, 0);
    let output = fact_fields(&record);
    ensure!(output.get("caller") == Some(&Value::string(u64::MAX.to_string())));
    for invalid in [
        Value::integer(-1),
        Value::string("18446744073709551616".into()),
        Value::string("+1".into()),
        Value::string("".into()),
    ] {
        ensure!(
            optional_cursor_arg(
                &mut ValueMap::from(BTreeMap::from([("from".into(), invalid)])),
                "from"
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn reads_reject_zero_budgets_and_oversized_records() -> anyhow::Result<()> {
    let config = config();
    for field in ["limit", "max_bytes", "max_examined"] {
        let mut input = ValueMap::from(BTreeMap::from([(field.into(), Value::integer(0))]));
        ensure!(matches!(
            query(&config, ReadKind::Recent, None, &mut input),
            Err(ConsoleError::BadRequest(_))
        ));
    }
    let (sink, store) = FactSink::in_memory();
    let mut record = fact(1, 0);
    let budget = byte_limit(&config, Some(1024))?;
    record.input = Value::string("x".repeat(budget.get() + 1));
    store.append(record.clone())?;
    let mut input = ValueMap::from(BTreeMap::from([("max_bytes".into(), Value::integer(1024))]));
    let query = query(&config, ReadKind::Recent, None, &mut input)?;
    ensure!(read_page(&sink, query, ReadKind::Recent).is_err());
    ensure!(
        read_detail(
            &sink,
            FactLookup {
                id: record.id,
                process: Some(record.caller),
                max_encoded_bytes: budget,
            },
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn health_fact_sample_marks_an_incomplete_history_explicitly() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    for position in 0..70 {
        store.append(fact(1, position))?;
    }
    let output = sample(&sink, &config())?;
    let output = output.as_map().context("sample map")?;
    ensure!(output.get("sampled_facts") == Some(&Value::integer(64)));
    ensure!(output.get("complete") == Some(&Value::boolean(false)));
    ensure!(output.get("next") == Some(&Value::string("6".into())));
    ensure!(output.get("end") == Some(&Value::string("70".into())));
    ensure!(
        output
            .get("decisions")
            .and_then(Value::as_map)
            .and_then(|m| m.get("Ok"))
            == Some(&Value::integer(64))
    );
    ensure!(!output.contains_key("items"));
    Ok(())
}

#[test]
fn live_source_excludes_existing_history() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    store.append(fact(1, 0))?;
    let mut receiver = sink.store().subscribe_facts();
    ensure!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let appended = fact(1, 1);
    store.append(appended.clone())?;
    ensure!(receiver.try_recv()?.id == appended.id);
    Ok(())
}

#[test]
fn live_projection_emits_current_completion_upserts() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let mut project = live_projection(sink, Some(1), byte_limit(&config(), None)?);
    let mut record = fact(1, 1);
    store.append(record.clone())?;
    let notification = Arc::new(record.clone());
    let Some(ConsoleEvent::Audit { fact: pending }) =
        project(notification.clone()).map_err(anyhow::Error::msg)?
    else {
        anyhow::bail!("expected append event");
    };
    ensure!(pending.as_map().and_then(|m| m.get("completed")) == Some(&Value::boolean(false)));
    record.outcome = Some(Value::integer(42));
    store.complete(record.clone())?;
    let Some(ConsoleEvent::Audit { fact: completed }) =
        project(notification).map_err(anyhow::Error::msg)?
    else {
        anyhow::bail!("expected completion event");
    };
    ensure!(completed.as_map().and_then(|m| m.get("completed")) == Some(&Value::boolean(true)));
    ensure!(
        completed.as_map().and_then(|m| m.get("op_id"))
            == Some(&Value::string(record.id.to_string()))
    );
    Ok(())
}

#[test]
fn live_projection_reads_current_record_before_filtering_stale_notifications() -> anyhow::Result<()>
{
    let (sink, store) = FactSink::in_memory();
    let mut project = live_projection(sink, Some(1), byte_limit(&config(), None)?);
    let mut record = fact(1, 0);
    record.caller = ProcessId::new(2);
    store.append(record.clone())?;
    let notification = Arc::new(record.clone());
    record.caller = ProcessId::new(1);
    record.outcome = Some(Value::integer(42));
    store.complete(record)?;
    for _ in 0..2 {
        let Some(ConsoleEvent::Audit { fact }) =
            project(notification.clone()).map_err(anyhow::Error::msg)?
        else {
            anyhow::bail!("expected current record upsert");
        };
        ensure!(fact.as_map().and_then(|m| m.get("caller")) == Some(&Value::string("1".into())));
        ensure!(fact.as_map().and_then(|m| m.get("completed")) == Some(&Value::boolean(true)));
    }
    Ok(())
}

#[test]
fn live_projection_filters_current_caller_before_enforcing_record_budget() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let mut project = live_projection(sink, Some(1), nonzero(1024, "max_bytes")?);
    let mut unrelated = fact(2, 0);
    unrelated.input = Value::string("x".repeat(2048));
    store.append(unrelated.clone())?;
    ensure!(
        project(Arc::new(unrelated))
            .map_err(anyhow::Error::msg)?
            .is_none()
    );

    let mut reassigned = fact(1, 1);
    store.append(reassigned.clone())?;
    let notification = Arc::new(reassigned.clone());
    reassigned.caller = ProcessId::new(2);
    reassigned.outcome = Some(Value::string("x".repeat(2048)));
    store.complete(reassigned)?;
    ensure!(project(notification).map_err(anyhow::Error::msg)?.is_none());

    let selected = fact(1, 2);
    store.append(selected.clone())?;
    let Some(ConsoleEvent::Audit { fact }) =
        project(Arc::new(selected.clone())).map_err(anyhow::Error::msg)?
    else {
        anyhow::bail!("unrelated oversized records must not close the selected stream");
    };
    ensure!(
        fact.as_map().and_then(|m| m.get("op_id")) == Some(&Value::string(selected.id.to_string()))
    );
    Ok(())
}

#[test]
fn live_projection_reports_missing_records() -> anyhow::Result<()> {
    let (sink, _store) = FactSink::in_memory();
    let mut project = live_projection(sink, None, byte_limit(&config(), None)?);
    let error = project(Arc::new(fact(1, 0)))
        .err()
        .context("missing record error")?;
    ensure!(error.contains("no longer available") && error.contains("bounded fact pages"));
    Ok(())
}

#[test]
fn live_projection_rejects_oversized_matching_records() -> anyhow::Result<()> {
    for process in [None, Some(1)] {
        let (sink, store) = FactSink::in_memory();
        let mut project = live_projection(sink, process, nonzero(1024, "max_bytes")?);
        let mut record = fact(1, 0);
        record.input = Value::string("x".repeat(2048));
        store.append(record.clone())?;
        let error = project(Arc::new(record))
            .err()
            .context("oversized record error")?;
        ensure!(error.contains("bounded fact read failed"));
    }
    Ok(())
}
