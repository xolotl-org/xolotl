use super::*;
use crate::{BlobRef, DType, ExecutionId, FrameKind, InvocationId, NodeId, TaintSource};
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use anyhow::{Context, ensure};

fn fact(input: Value, outcome: Option<Value>) -> Fact {
    Fact {
        id: OperationId::new(
            ProcessId::new(2),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(1),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(2),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(7),
        method: MethodId::new(0),
        input,
        taint: TaintSet::of(TaintSource::ModelOutput),
        decision: DecisionTag::Ok,
        outcome,
        batch: None,
        replay: ReplayClass::Deterministic,
        timestamp: Timestamp::millis(123),
    }
}

#[test]
fn null_success_pending_and_terminal_failure_remain_distinct() -> anyhow::Result<()> {
    let mut pending = fact(Value::null(), None);
    ensure!(!pending.is_complete());
    let encoded = serde_json::to_value(&pending)?;
    ensure!(encoded["outcome"].is_null());
    let decoded: Fact = serde_json::from_value(encoded)?;
    ensure!(decoded == pending && !decoded.is_complete());

    pending.outcome = Some(Value::null());
    let encoded = serde_json::to_value(&pending)?;
    ensure!(encoded["outcome"].is_u64());
    let decoded: Fact = serde_json::from_value(encoded)?;
    ensure!(decoded.outcome.as_ref().is_some_and(Value::is_null));
    ensure!(decoded == pending && decoded.is_complete());

    pending.outcome = None;
    pending.decision = DecisionTag::DriverError;
    let decoded: Fact = serde_json::from_slice(&serde_json::to_vec(&pending)?)?;
    ensure!(decoded == pending && decoded.is_complete());
    Ok(())
}

fn overlapping() -> Fact {
    let child = Value::bytes(vec![0, 128, 255]);
    let input = Value::list(vec![child.clone(), Value::integer(1)]);
    let output = Value::map(BTreeMap::from([("shared".into(), child)]));
    let mut record = fact(input.clone(), Some(output.clone()));
    record.batch = Some(BatchSummary {
        elements: 2,
        input_tokens: 3,
        output_tokens: 1,
        input_summary: input,
        output_summary: output,
    });
    record
}

#[test]
fn input_outcome_and_batch_share_one_resident_graph_after_decode() -> anyhow::Result<()> {
    let record = overlapping();
    let encoded = serde_json::to_value(&record)?;
    ensure!(encoded["input"] == encoded["batch"]["input_summary"]);
    ensure!(encoded["outcome"] == encoded["batch"]["output_summary"]);
    ensure!(
        encoded["values"]["nodes"]
            .as_array()
            .context("shared node table")?
            .len()
            == 4
    );
    let decoded: Fact = serde_json::from_value(encoded)?;
    ensure!(decoded == record);
    let batch = decoded.batch.as_ref().context("batch summaries")?;
    ensure!(decoded.input.identity().is_some());
    ensure!(decoded.input.identity() == batch.input_summary.identity());
    let outcome = decoded.outcome.as_ref().context("completed outcome")?;
    ensure!(outcome.identity() == batch.output_summary.identity());
    let left = decoded
        .input
        .as_list()
        .and_then(|items| items.first())
        .context("input child")?;
    let right = outcome
        .as_map()
        .and_then(|map| map.get("shared"))
        .context("outcome child")?;
    ensure!(left.identity().is_some() && left.identity() == right.identity());
    Ok(())
}

#[test]
fn media_values_retain_their_complete_descriptors() -> anyhow::Result<()> {
    let blob = BlobRef {
        hash: "0123456789abcdef".repeat(4),
        size: u64::MAX,
        mime: Some("application/x-full-descriptor".into()),
    };
    for value in [
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), DType::Bf16, vec![1, u64::MAX]),
        Value::frame(blob, i64::MIN, FrameKind::Pose),
    ] {
        let record = fact(value.clone(), Some(value));
        let encoded = serde_json::to_value(&record)?;
        ensure!(
            encoded["values"]["nodes"]
                .as_array()
                .context("media node table")?
                .len()
                == 1
        );
        let decoded: Fact = serde_json::from_value(encoded)?;
        ensure!(decoded == record);
        ensure!(decoded.input.identity() == decoded.outcome.as_ref().and_then(Value::identity));
    }
    Ok(())
}

#[test]
fn invalid_roots_and_missing_taint_are_rejected() -> anyhow::Result<()> {
    let original = serde_json::to_value(overlapping())?;
    for pointer in [
        "/input",
        "/outcome",
        "/batch/input_summary",
        "/batch/output_summary",
    ] {
        let mut invalid = original.clone();
        *invalid.pointer_mut(pointer).context("root field")? = serde_json::json!(u64::MAX);
        let error = serde_json::from_value::<Fact>(invalid)
            .err()
            .context("invalid root was accepted")?;
        ensure!(error.to_string().contains("root"));
    }
    for field in ["input", "outcome", "taint", "values"] {
        let mut invalid = original.clone();
        drop(
            invalid
                .as_object_mut()
                .context("fact record")?
                .remove(field),
        );
        ensure!(
            serde_json::from_value::<Fact>(invalid).is_err(),
            "missing {field} accepted"
        );
    }
    Ok(())
}

#[test]
fn deep_shared_fact_encodes_decodes_and_releases_on_a_small_stack() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let mut value = Value::bytes(vec![1, 2, 3]);
            for _ in 0..12_000 {
                value = Value::list(vec![value]);
            }
            let record = fact(value.clone(), Some(value));
            let encoded = serde_json::to_vec(&record)?;
            let decoded: Fact = serde_json::from_slice(&encoded)?;
            ensure!(decoded == record);
            ensure!(decoded.input.identity() == decoded.outcome.as_ref().and_then(Value::identity));
            drop(decoded);
            drop(record);
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("Fact worker failed"))??;
    Ok(())
}
