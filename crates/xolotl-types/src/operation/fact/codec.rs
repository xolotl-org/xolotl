//! A typed record and one lossless node table; decoding never expands a JSON tree.

use super::{BatchSummary, DecisionTag, Fact, OperationId};
use crate::{
    HandleId, IdentityRef, MethodId, ProcessId, ReplayClass, ResourceId, TaintSet, Timestamp,
    Value,
    tagged_value::{ValueRoot, ValueTableDecoder, ValueTableEncodeError, ValueTableEncoder},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T, V> {
    id: OperationId,
    schema_version: u32,
    caller: ProcessId,
    acting: IdentityRef,
    handle: HandleId,
    resource: ResourceId,
    method: MethodId,
    input: ValueRoot,
    taint: T,
    decision: DecisionTag,
    #[serde(deserialize_with = "Option::deserialize")]
    outcome: Option<ValueRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch: Option<BatchRecord>,
    replay: ReplayClass,
    timestamp: Timestamp,
    values: V,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRecord {
    elements: u64,
    input_tokens: u64,
    output_tokens: u64,
    input_summary: ValueRoot,
    output_summary: ValueRoot,
}

impl BatchRecord {
    fn new<'a>(
        batch: &'a BatchSummary,
        values: &mut ValueTableEncoder<'a>,
    ) -> Result<Self, ValueTableEncodeError> {
        Ok(Self {
            elements: batch.elements,
            input_tokens: batch.input_tokens,
            output_tokens: batch.output_tokens,
            input_summary: values.intern(&batch.input_summary)?,
            output_summary: values.intern(&batch.output_summary)?,
        })
    }

    fn restore(self, values: &ValueTableDecoder) -> Result<BatchSummary, &'static str> {
        Ok(BatchSummary {
            elements: self.elements,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            input_summary: resolve(values, self.input_summary)?,
            output_summary: resolve(values, self.output_summary)?,
        })
    }
}

fn resolve(values: &ValueTableDecoder, root: ValueRoot) -> Result<Value, &'static str> {
    values
        .resolve(root)
        .ok_or("fact value root is outside its table")
}

impl Serialize for Fact {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = ValueTableEncoder::new();
        let input = values
            .intern(&self.input)
            .map_err(serde::ser::Error::custom)?;
        let outcome = self
            .outcome
            .as_ref()
            .map(|outcome| values.intern(outcome))
            .transpose()
            .map_err(serde::ser::Error::custom)?;
        let batch = self
            .batch
            .as_ref()
            .map(|batch| BatchRecord::new(batch, &mut values))
            .transpose()
            .map_err(serde::ser::Error::custom)?;
        Record {
            id: self.id,
            schema_version: self.schema_version,
            caller: self.caller,
            acting: self.acting,
            handle: self.handle,
            resource: self.resource,
            method: self.method,
            input,
            taint: &self.taint,
            decision: self.decision,
            outcome,
            batch,
            replay: self.replay,
            timestamp: self.timestamp,
            values,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Fact {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let record = Record::<TaintSet, ValueTableDecoder>::deserialize(deserializer)?;
        let input = resolve(&record.values, record.input).map_err(serde::de::Error::custom)?;
        let outcome = record
            .outcome
            .map(|root| resolve(&record.values, root))
            .transpose()
            .map_err(serde::de::Error::custom)?;
        let batch = record
            .batch
            .map(|batch| batch.restore(&record.values))
            .transpose()
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            id: record.id,
            schema_version: record.schema_version,
            caller: record.caller,
            acting: record.acting,
            handle: record.handle,
            resource: record.resource,
            method: record.method,
            input,
            taint: record.taint,
            decision: record.decision,
            outcome,
            batch,
            replay: record.replay,
            timestamp: record.timestamp,
        })
    }
}
