//! Bounded fact observations shared by console actions and live subscriptions.

use super::{ConsoleError, optional_usize_arg};
use crate::protocol::ConsoleEvent;
use crate::state::{
    ConsoleWsConfig, HARD_MAX_WS_FACT_LIMIT, HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_TRACE_LIMIT,
};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use xolotl_kernel::{FactLookup, FactLookupResult, FactOrder, FactPage, FactQuery, FactSink};
use xolotl_types::{Fact, ProcessId, Value, ValueMap, ValueView};

const HARD_MAX_FACT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_EXAMINED: usize = 4096;
const HARD_MAX_EXAMINED: usize = 65_536;

#[derive(Clone, Copy)]
pub(super) enum ReadKind {
    Recent,
    Trace,
}

pub(super) fn cursor_value(cursor: u64) -> Value {
    Value::string(cursor.to_string())
}

pub(super) fn optional_cursor_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Option<u64>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Int(value)) if value >= 0 => Ok(Some(value as u64)),
        Some(ValueView::Str(value))
            if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) =>
        {
            value
                .parse()
                .map(Some)
                .map_err(|_error| ConsoleError::BadRequest(format!("{name} exceeds the u64 range")))
        }
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-negative integer or decimal u64 string"
        ))),
    }
}

fn nonzero(value: usize, name: &str) -> Result<NonZeroUsize, ConsoleError> {
    NonZeroUsize::new(value)
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} must be greater than zero")))
}

pub(super) fn byte_limit(
    config: &ConsoleWsConfig,
    requested: Option<usize>,
) -> Result<NonZeroUsize, ConsoleError> {
    // Reserve space for projection expansion, page metadata and transport framing.
    let maximum =
        (config.max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES) / 8).min(HARD_MAX_FACT_BYTES);
    nonzero(requested.unwrap_or(maximum).min(maximum), "max_bytes")
}

pub(super) fn query(
    config: &ConsoleWsConfig,
    kind: ReadKind,
    process: Option<u64>,
    input: &mut ValueMap,
) -> Result<FactQuery, ConsoleError> {
    let (default_limit, maximum, order) = match kind {
        ReadKind::Recent => (
            64,
            config.max_fact_limit.min(HARD_MAX_WS_FACT_LIMIT),
            FactOrder::Reverse,
        ),
        ReadKind::Trace => (
            128,
            config.max_trace_limit.min(HARD_MAX_WS_TRACE_LIMIT),
            FactOrder::Forward,
        ),
    };
    let limit = nonzero(
        optional_usize_arg(input, "limit")?
            .unwrap_or(default_limit)
            .min(maximum),
        "limit",
    )?;
    let max_bytes = byte_limit(config, optional_usize_arg(input, "max_bytes")?)?;
    let max_examined = nonzero(
        optional_usize_arg(input, "max_examined")?
            .unwrap_or_else(|| limit.get().max(DEFAULT_MAX_EXAMINED))
            .min(HARD_MAX_EXAMINED),
        "max_examined",
    )?;
    let mut query = FactQuery::new(limit, max_bytes);
    query.from = optional_cursor_arg(input, "from")?.unwrap_or(0);
    query.before = optional_cursor_arg(input, "before")?;
    if query.before.is_some_and(|before| query.from > before) {
        return Err(ConsoleError::BadRequest(
            "from must not exceed before".into(),
        ));
    }
    query.process = process.map(ProcessId::new);
    query.order = order;
    query.max_examined = max_examined;
    Ok(query)
}

fn page_metadata(page: &FactPage, query: FactQuery) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("from".into(), cursor_value(query.from)),
        (
            "next".into(),
            page.next.map(cursor_value).unwrap_or(Value::null()),
        ),
        ("end".into(), cursor_value(page.end)),
        (
            "order".into(),
            Value::string(
                match query.order {
                    FactOrder::Forward => "forward",
                    FactOrder::Reverse => "reverse",
                }
                .into(),
            ),
        ),
        ("complete".into(), Value::boolean(page.next.is_none())),
        ("examined".into(), Value::integer(page.examined as i64)),
        (
            "encoded_bytes".into(),
            Value::integer(page.encoded_bytes as i64),
        ),
    ])
}

pub(super) fn read_page(
    sink: &FactSink,
    query: FactQuery,
    kind: ReadKind,
) -> Result<Value, ConsoleError> {
    let page = sink.scan(query)?;
    let mut output = page_metadata(&page, query);
    output.insert(
        "items".into(),
        Value::list(page.facts.iter().map(fact_value).collect()),
    );
    if let Some(process) = query.process {
        output.insert("process".into(), cursor_value(process.get()));
    }
    if matches!(kind, ReadKind::Trace) {
        output.insert("partial".into(), Value::boolean(true));
        output.insert("partial_reason".into(), Value::string(
            "trace is an append-order fact projection; materialized lineage indexes are not included".into(),
        ));
    }
    Ok(Value::map(output))
}

pub(super) fn read_detail(sink: &FactSink, query: FactLookup) -> Result<Value, ConsoleError> {
    let fact = match sink.lookup(query)? {
        FactLookupResult::Found(fact) => fact,
        FactLookupResult::Missing | FactLookupResult::FilteredOut => {
            return Err(ConsoleError::BadRequest(format!(
                "unknown operation id: {}",
                query.id
            )));
        }
    };
    let mut output = fact_fields(&fact);
    output.insert(
        "schema_version".into(),
        Value::integer(i64::from(fact.schema_version)),
    );
    output.insert("handle".into(), Value::string(fact.handle.to_string()));
    output.insert("input".into(), fact.input.clone());
    if let Some(value) = &fact.outcome {
        output.insert("outcome".into(), value.clone());
    }
    output.insert("partial".into(), Value::boolean(true));
    output.insert("partial_reason".into(), Value::string(
        "lineage fact detail excludes object content, state revision, and driver endpoint projections".into(),
    ));
    Ok(Value::map(output))
}

pub(super) fn sample(sink: &FactSink, config: &ConsoleWsConfig) -> Result<Value, ConsoleError> {
    let query = query(config, ReadKind::Recent, None, &mut ValueMap::new())?;
    let page = sink.scan(query)?;
    let mut decisions = BTreeMap::<String, Value>::new();
    for fact in &page.facts {
        let key = format!("{:?}", fact.decision);
        let count = decisions.get(&key).and_then(Value::as_int).unwrap_or(0) + 1;
        decisions.insert(key, Value::integer(count));
    }
    let mut output = page_metadata(&page, query);
    output.insert(
        "sampled_facts".into(),
        Value::integer(page.facts.len() as i64),
    );
    output.insert("decisions".into(), Value::map(decisions));
    Ok(Value::map(output))
}

fn fact_fields(fact: &Fact) -> BTreeMap<String, Value> {
    let mut output = BTreeMap::from([
        ("op_id".into(), Value::string(fact.id.to_string())),
        ("caller".into(), cursor_value(fact.caller.get())),
        ("acting".into(), cursor_value(fact.acting.get())),
        ("resource".into(), cursor_value(fact.resource.get())),
        ("method".into(), cursor_value(fact.method.get())),
        (
            "decision".into(),
            Value::string(format!("{:?}", fact.decision)),
        ),
        ("replay".into(), Value::string(format!("{:?}", fact.replay))),
        ("timestamp".into(), Value::integer(fact.timestamp.get())),
        ("completed".into(), Value::boolean(fact.is_complete())),
        ("tainted".into(), Value::boolean(!fact.taint.is_pristine())),
        (
            "protected".into(),
            Value::boolean(fact.taint.has_protected()),
        ),
    ]);
    if let Some(batch) = &fact.batch {
        output.insert("batch".into(), batch.to_value());
    }
    output
}

fn fact_value(fact: &Fact) -> Value {
    Value::map(fact_fields(fact))
}

pub(super) fn live_projection(
    sink: FactSink,
    process: Option<u64>,
    max_bytes: NonZeroUsize,
) -> impl FnMut(Arc<Fact>) -> Result<Option<ConsoleEvent>, String> + Send + 'static {
    move |notification| {
        let id = notification.id;
        drop(notification);
        match sink.lookup(FactLookup {
            id,
            process: process.map(ProcessId::new),
            max_encoded_bytes: max_bytes,
        }) {
            Ok(FactLookupResult::Found(fact)) => Ok(Some(ConsoleEvent::Audit {
                fact: fact_value(&fact),
            })),
            Ok(FactLookupResult::FilteredOut) => Ok(None),
            Ok(FactLookupResult::Missing) => {
                Err("fact no longer available; resynchronize with bounded fact pages".into())
            }
            Err(error) => Err(format!(
                "bounded fact read failed: {error}; resynchronize with bounded fact pages"
            )),
        }
    }
}

#[cfg(test)]
mod tests;
