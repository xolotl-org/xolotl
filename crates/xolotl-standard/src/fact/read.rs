//! Query inputs and audit projections shared by the standard Fact and inspect drivers.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use xolotl_kernel::{DriverError, FactOrder, FactPage, FactQuery};
use xolotl_types::Value;
use xolotl_types::{ValueMap, ValueView};

const MAX_RECORDS: usize = 256;
const MAX_BYTES: usize = 256 * 1024;
const DEFAULT_EXAMINED: usize = 4096;
const MAX_EXAMINED: usize = 65_536;

pub(crate) fn parse_query(
    input: Value,
    default_order: FactOrder,
    default_limit: usize,
) -> Result<FactQuery, DriverError> {
    let mut input = crate::input::map(input, "fact read")?;
    let from = take_cursor(&mut input, "from")?.unwrap_or(0);
    let before = take_cursor(&mut input, "before")?;
    let order = match input.remove("order").as_ref().map(Value::view) {
        None => default_order,
        Some(ValueView::Str("forward")) => FactOrder::Forward,
        Some(ValueView::Str("reverse")) => FactOrder::Reverse,
        _ => {
            return Err(DriverError::InvalidInput(
                "fact read.order must be forward or reverse".into(),
            ));
        }
    };
    let limit = take_limit(&mut input, "limit", default_limit, MAX_RECORDS)?;
    let max_encoded_bytes = take_limit(&mut input, "max_bytes", MAX_BYTES, MAX_BYTES)?;
    let max_examined = take_limit(&mut input, "max_examined", DEFAULT_EXAMINED, MAX_EXAMINED)?;
    if let Some(field) = input.keys().next() {
        return Err(DriverError::InvalidInput(format!(
            "unknown fact read field: {field}"
        )));
    }
    if before.is_some_and(|before| from > before) {
        return Err(DriverError::InvalidInput(
            "fact read.from is after before".into(),
        ));
    }
    Ok(FactQuery {
        from,
        before,
        process: None,
        order,
        limit,
        max_examined,
        max_encoded_bytes,
    })
}

pub(crate) fn take_cursor(input: &mut ValueMap, name: &str) -> Result<Option<u64>, DriverError> {
    let Some(value) = input.remove(name) else {
        return Ok(None);
    };
    let cursor = match value.view() {
        ValueView::Int(value) => u64::try_from(value).ok(),
        ValueView::Str(value)
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse().ok()
        }
        _ => None,
    };
    cursor.map(Some).ok_or_else(|| {
        DriverError::InvalidInput(format!(
            "{name} must be a nonnegative integer or decimal string"
        ))
    })
}

fn take_limit(
    input: &mut ValueMap,
    name: &str,
    default: usize,
    maximum: usize,
) -> Result<NonZeroUsize, DriverError> {
    let value = match input.remove(name).as_ref().map(Value::view) {
        None => Some(default),
        Some(ValueView::Int(value)) => usize::try_from(value).ok(),
        _ => None,
    };
    value
        .filter(|value| *value <= maximum)
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            DriverError::InvalidInput(format!("fact read.{name} must be in 1..={maximum}"))
        })
}

pub(crate) fn page_value(query: FactQuery, page: FactPage) -> Value {
    Value::map(BTreeMap::from([
        ("from".into(), Value::string(query.from.to_string())),
        ("end".into(), Value::string(page.end.to_string())),
        (
            "next".into(),
            page.next
                .map_or(Value::null(), |next| Value::string(next.to_string())),
        ),
        ("complete".into(), Value::boolean(page.is_complete())),
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
        ("examined".into(), Value::integer(page.examined as i64)),
        (
            "encoded_bytes".into(),
            Value::integer(page.encoded_bytes as i64),
        ),
        (
            "items".into(),
            Value::list(
                page.facts
                    .into_iter()
                    .map(|fact| project_fact(&fact))
                    .collect(),
            ),
        ),
    ]))
}

/// Project one Fact into a self-describing `Value` map (audit view). Only
/// references and tags are exposed, without reconstructing business data.
fn project_fact(f: &xolotl_types::Fact) -> Value {
    let mut m = BTreeMap::new();
    m.insert("op_id".into(), Value::string(f.id.to_string()));
    m.insert("caller".into(), Value::string(f.caller.get().to_string()));
    m.insert("acting".into(), Value::string(f.acting.get().to_string()));
    m.insert(
        "resource".into(),
        Value::string(f.resource.get().to_string()),
    );
    m.insert("method".into(), Value::string(f.method.get().to_string()));
    m.insert(
        "decision".into(),
        Value::string(format!("{:?}", f.decision)),
    );
    m.insert("replay".into(), Value::string(format!("{:?}", f.replay)));
    m.insert("timestamp".into(), Value::integer(f.timestamp.get()));
    // Surface the taint lineage for why-not tooling.
    let tainted = !f.taint.is_pristine();
    m.insert("tainted".into(), Value::boolean(tainted));
    m.insert("protected".into(), Value::boolean(f.taint.has_protected()));
    // Audit tags: the rule-independent structural projection
    // (sensitive_data / cross_identity) derived from this Fact alone.
    // Rule-driven tags (high_cost / compliance / alert) come from a projector
    // reading `state://kernel/audit/rules`; the always-on ones surface here.
    let tags = xolotl_types::AuditRules::default().tags_for(f, 0);
    if !tags.is_empty() {
        let tag_strs: Vec<Value> = tags
            .iter()
            .map(|t| Value::string(format!("{t:?}")))
            .collect();
        m.insert("audit_tags".into(), Value::list(tag_strs));
    }
    Value::map(m)
}
