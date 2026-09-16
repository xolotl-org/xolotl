//! `Operation`, `OperationId`, and `Fact` — the data-plane records.
//!
//! An [`Operation`] is the *only* way a side effect happens. Its identity,
//! [`OperationId`], combines its process, execution scope, dynamic invocation,
//! source position, and retry attempt. A [`Fact`] records one operation attempt;
//! stores complete its pending record in place. Recovery diagnostics, audit,
//! billing and trace projections read Facts. Blob, tensor and frame payloads use
//! external references; other inline values and retained history need host limits.

use crate::ids::{
    CausalPosition, ExecutionId, HandleId, IdentityRef, InvocationId, MethodId, ProcessId,
};
use crate::value::{Value, ValueView};
use alloc::{collections::BTreeMap, string::String};
use serde::{Deserialize, Serialize};

mod contract;
mod fact;
mod output;
pub use contract::MethodContract;
pub use fact::Fact;
pub use output::{CompletionOrigin, DriverOutput, DriverUsage, UsageDimension};

/// Identity of one operation attempt within a retained allocator namespace.
///
/// Source positions remain stable when a node is visited again. Invocation
/// tickets distinguish those visits; execution scopes distinguish independent
/// evaluations. Checkpoint restoration preserves every coordinate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct OperationId {
    /// Process that owns this causal position.
    pub process: ProcessId,
    /// Scope assigned once to the hosted evaluation or administrative sequence.
    pub execution: ExecutionId,
    /// Dynamic request ticket within the execution; zero is for administrative events.
    pub invocation: InvocationId,
    /// Stable position in the compiled graph = `NodeId`.
    pub position: CausalPosition,
    /// Incremented only on explicit retry; crash-replay reuses the same value.
    pub attempt: u32,
}

impl OperationId {
    /// Create an operation id from its causal coordinates.
    pub const fn new(
        process: ProcessId,
        execution: ExecutionId,
        invocation: InvocationId,
        position: CausalPosition,
        attempt: u32,
    ) -> Self {
        Self {
            process,
            execution,
            invocation,
            position,
            attempt,
        }
    }

    /// The same invocation at the next explicit retry, or `None` at exhaustion.
    pub const fn retry(self) -> Option<Self> {
        match self.attempt.checked_add(1) {
            Some(attempt) => Some(Self { attempt, ..self }),
            None => None,
        }
    }

    /// Encode all coordinates in fixed-width, big-endian order without allocation.
    /// The byte ordering agrees with the identifier's coordinate ordering.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&self.process.get().to_be_bytes());
        bytes[8..16].copy_from_slice(&self.execution.get().to_be_bytes());
        bytes[16..24].copy_from_slice(&self.invocation.get().to_be_bytes());
        bytes[24..28].copy_from_slice(&self.position.get().to_be_bytes());
        bytes[28..].copy_from_slice(&self.attempt.to_be_bytes());
        bytes
    }
}

impl core::fmt::Display for OperationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}/{}",
            self.process.get(),
            self.execution.get(),
            self.invocation.get(),
            self.position.get(),
            self.attempt
        )
    }
}

/// An operation identifier was not five canonical unsigned decimal coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseOperationIdError;

impl core::fmt::Display for ParseOperationIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid operation id: expected process/execution/invocation/position/attempt")
    }
}

impl core::error::Error for ParseOperationIdError {}

impl core::str::FromStr for OperationId {
    type Err = ParseOperationIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        fn component(value: Option<&str>) -> Result<u64, ParseOperationIdError> {
            let value = value.ok_or(ParseOperationIdError)?;
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(ParseOperationIdError);
            }
            value.parse().map_err(|_error| ParseOperationIdError)
        }
        let mut parts = value.split('/');
        let process = ProcessId::new(component(parts.next())?);
        let execution = ExecutionId::new(component(parts.next())?).ok_or(ParseOperationIdError)?;
        let invocation = InvocationId::new(component(parts.next())?);
        let position =
            u32::try_from(component(parts.next())?).map_err(|_error| ParseOperationIdError)?;
        let attempt =
            u32::try_from(component(parts.next())?).map_err(|_error| ParseOperationIdError)?;
        if parts.next().is_some() {
            return Err(ParseOperationIdError);
        }
        Ok(Self::new(
            process,
            execution,
            invocation,
            CausalPosition::new(position),
            attempt,
        ))
    }
}

/// A single actual call — the one path through which side effects occur.
/// Carries the input `Value` for dispatch and shares it with the Fact. Large modality
/// values (`Blob`/`Tensor`/`Frame`) are *already* out-of-line refs, so passing
/// them by value here is cheap — the bytes never travel inline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    /// Causally derived operation id.
    pub id: OperationId,
    /// The calling Process.
    pub process: ProcessId,
    /// The identity this call runs as.
    pub acting: IdentityRef,
    /// Handle authorizing this call.
    pub handle: HandleId,
    /// Interface method id selected by open/dispatch.
    pub method: MethodId,
    /// The complete input passed to the driver and shared with its Fact.
    pub input: Value,
    /// Provenance of the input value. Propagates input→output: the
    /// outcome inherits this taint, and outbound/memory policies read it.
    #[serde(default)]
    pub taint: crate::taint::TaintSet,
    /// Output mode requested by the caller.
    pub output: crate::resource::OutputMode,
}

/// Why an operation ended the way it did. This is a fixed-size enum tag; the
/// detailed outcome is materialized on the projection side.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionTag {
    /// Completed successfully.
    Ok,
    /// Denied by capability / owner / rights check.
    Denied,
    /// Rejected by a residual policy check.
    RejectedByPolicy,
    /// The driver returned an error.
    DriverError,
    /// Operation timed out.
    Timeout,
    /// Operation was cancelled.
    Cancelled,
    /// Held in quarantine (unsafe replay).
    Quarantined,
}

impl DecisionTag {
    /// Returns true when the decision represents success.
    pub fn is_ok(self) -> bool {
        matches!(self, DecisionTag::Ok)
    }
}

/// Compact shape/cost metadata for one explicit batchable Operation.
/// Recovery still uses the complete outcome, so summarizing a batch preserves the
/// completed result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Number of elements in the batch input list.
    pub elements: u64,
    /// Estimated input tokens for the whole batch.
    pub input_tokens: u64,
    /// Estimated output tokens for the whole batch.
    pub output_tokens: u64,
    /// Redacted structural summary of the input.
    #[serde(with = "crate::tagged_value")]
    pub input_summary: Value,
    /// Redacted structural summary of the output.
    #[serde(with = "crate::tagged_value")]
    pub output_summary: Value,
}

impl BatchSummary {
    /// Build a summary for list-shaped batch input and optional outcome.
    pub fn new(input: &Value, output: Option<&Value>) -> Option<Self> {
        let items = input.as_list()?;
        Some(Self {
            elements: items.len() as u64,
            input_tokens: input.approx_tokens(),
            output_tokens: output.map(Value::approx_tokens).unwrap_or(0),
            input_summary: summarize_value(input),
            output_summary: output.map(summarize_value).unwrap_or_default(),
        })
    }

    /// Convert the summary to a value for audit and console projections.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("elements".into(), Value::integer(self.elements as i64));
        m.insert(
            "input_tokens".into(),
            Value::integer(self.input_tokens as i64),
        );
        m.insert(
            "output_tokens".into(),
            Value::integer(self.output_tokens as i64),
        );
        m.insert("input_summary".into(), self.input_summary.clone());
        m.insert("output_summary".into(), self.output_summary.clone());
        Value::map(m)
    }
}

fn summarize_value(v: &Value) -> Value {
    let mut current = v;
    let mut lengths = alloc::vec::Vec::new();
    while let Some(items) = current.as_list() {
        let Some(first) = items.get(0) else { break };
        lengths.push(items.len());
        current = first;
    }
    let mut summary = summarize_shallow(current);
    for length in lengths.into_iter().rev() {
        let mut map = kind_map("list");
        map.insert("len".into(), Value::integer(length as i64));
        map.insert("elem".into(), summary);
        summary = Value::map(map);
    }
    summary
}

fn summarize_shallow(v: &Value) -> Value {
    match v.view() {
        ValueView::Null => kind("null"),
        ValueView::Bool(_) => kind("bool"),
        ValueView::Int(_) => kind("int"),
        ValueView::Float(_) => kind("float"),
        ValueView::Str(s) => {
            let mut m = kind_map("str");
            m.insert("chars".into(), Value::integer(s.chars().count() as i64));
            Value::map(m)
        }
        ValueView::Bytes(b) => {
            let mut m = kind_map("bytes");
            m.insert("bytes".into(), Value::integer(b.len() as i64));
            Value::map(m)
        }
        ValueView::List(items) => {
            let mut m = kind_map("list");
            m.insert("len".into(), Value::integer(items.len() as i64));
            Value::map(m)
        }
        ValueView::Map(fields) => {
            let mut m = kind_map("map");
            m.insert("fields".into(), Value::integer(fields.len() as i64));
            m.insert(
                "keys".into(),
                Value::list(fields.keys().take(8).map(Value::from).collect()),
            );
            Value::map(m)
        }
        ValueView::Blob(b) => {
            let mut m = kind_map("blob");
            m.insert("hash".into(), Value::string(b.hash.clone()));
            m.insert("size".into(), Value::integer(b.size as i64));
            if let Some(mime) = &b.mime {
                m.insert("mime".into(), Value::string(mime.clone()));
            }
            Value::map(m)
        }
        ValueView::Tensor(t) => {
            let mut m = kind_map("tensor");
            m.insert("hash".into(), Value::string(t.blob.hash.clone()));
            m.insert("size".into(), Value::integer(t.blob.size as i64));
            m.insert(
                "shape".into(),
                Value::list(t.shape.iter().map(|n| Value::integer(*n as i64)).collect()),
            );
            m.insert("dtype".into(), Value::string(format!("{:?}", t.dtype)));
            Value::map(m)
        }
        ValueView::Frame(fr) => {
            let mut m = kind_map("frame");
            m.insert("hash".into(), Value::string(fr.blob.hash.clone()));
            m.insert("size".into(), Value::integer(fr.blob.size as i64));
            m.insert("ts_nanos".into(), Value::integer(fr.ts_nanos));
            m.insert("kind".into(), Value::string(format!("{:?}", fr.kind)));
            Value::map(m)
        }
        ValueView::StreamEnd(_) => kind("stream_end"),
    }
}

fn kind(name: &str) -> Value {
    Value::map(kind_map(name))
}

fn kind_map(name: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([("kind".into(), Value::string(name.into()))])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::NodeId;
    use crate::value::Value;
    use alloc::string::ToString;
    use anyhow::ensure;

    #[test]
    fn operation_id_distinguishes_execution_invocation_and_retry() -> anyhow::Result<()> {
        let a = OperationId::new(
            ProcessId::new(1),
            ExecutionId::FIRST,
            InvocationId::new(9),
            NodeId::new(5),
            0,
        );
        let b = a;
        ensure!(
            a == b,
            "identical execution coordinates must share an identity"
        );
        ensure!(Some(a) != a.retry(), "retry bumps attempt");
        ensure!(
            OperationId {
                attempt: u32::MAX,
                ..a
            }
            .retry()
            .is_none()
        );
        let execution =
            ExecutionId::new(2).ok_or_else(|| anyhow::anyhow!("missing execution id"))?;
        ensure!(a != OperationId { execution, ..a });
        ensure!(
            a != OperationId {
                invocation: InvocationId::new(10),
                ..a
            }
        );
        ensure!(core::mem::size_of::<OperationId>() == 32);
        Ok(())
    }

    #[test]
    fn operation_id_text_and_bytes_preserve_every_coordinate() -> anyhow::Result<()> {
        let id: OperationId = "1/2/4294967296/4/5".parse()?;
        ensure!(id.to_string() == "1/2/4294967296/4/5");
        let bytes = id.to_bytes();
        ensure!(bytes[..8] == 1u64.to_be_bytes());
        ensure!(bytes[8..16] == 2u64.to_be_bytes());
        ensure!(bytes[16..24] == 4294967296u64.to_be_bytes());
        ensure!(bytes[24..28] == 4u32.to_be_bytes());
        ensure!(bytes[28..] == 5u32.to_be_bytes());
        for invalid in [
            "1/2/3",
            "1/0/3/4/5",
            "1/2/3/4/5/6",
            "1/02/3/4/5",
            "1/+2/3/4/5",
            " 1/2/3/4/5",
            "1/2/3/4/5\n",
            "1//3/4/5",
            "1/2/3/4294967296/5",
            "1/2/3/4/4294967296",
            "1/18446744073709551616/3/4/5",
        ] {
            ensure!(
                invalid.parse::<OperationId>().is_err(),
                "accepted {invalid:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn batch_summary_summarizes_shape_without_replacing_outcome() -> anyhow::Result<()> {
        let input = Value::list(vec![
            Value::string("alpha".into()),
            Value::string("beta".into()),
        ]);
        let outcome = Value::list(vec![Value::integer(1), Value::integer(2)]);
        let summary = BatchSummary::new(&input, Some(&outcome))
            .ok_or_else(|| anyhow::anyhow!("batch summary was not created"))?;
        ensure!(
            summary.elements == 2,
            "unexpected batch elements: {}",
            summary.elements
        );
        ensure!(outcome.as_list().is_some(), "outcome was replaced");
        ensure!(
            summary.to_value().as_map().is_some(),
            "summary did not render as map"
        );
        Ok(())
    }
}
