//! Value operations shared by current-state mutations and history replay.

use crate::{StateError, StateFailure, StateResult, TaintedValue};
use alloc::{collections::BTreeMap, string::ToString, vec::Vec};
use xolotl_types::value::MapIter;
use xolotl_types::{MergeRule, Path, TaintSet, Value, ValueIdentity, ValueList, ValueMap};

/// Append one member, retaining the existing sequence and incoming provenance.
///
/// Absence creates a sequence. A present non-list is rejected without changing
/// the current value. Existing source order is retained before adding incoming
/// sources, so replay and direct mutation produce identical snapshots. The
/// returned snapshot copies only the append path.
pub fn append_value(
    path: &Path,
    current: Option<&TaintedValue>,
    item: Value,
    taint: TaintSet,
) -> StateResult<TaintedValue> {
    let taint = match current {
        Some(current) => current.taint.clone().merged(&taint),
        None => taint,
    };
    let mut values = match current {
        Some(current) => current.value.as_list().cloned().ok_or_else(|| {
            StateFailure::new(
                StateError::Backend(alloc::format!("append on non-list at {path}")),
                taint.clone(),
            )
        })?,
        None => ValueList::new(),
    };
    values
        .push(item)
        .map_err(|error| StateFailure::from(error).with_taint(&taint))?;
    Ok(TaintedValue::new(Value::from(values), taint))
}

/// Merge root maps, concatenate root lists, or replace other values.
///
/// Deep merge also combines nested map/map and list/list collisions; other
/// incoming members replace their previous values. It uses an explicit work
/// stack and memoizes shared collection pairs, so nesting and repeated DAG
/// paths do not cause recursive calls or repeat an already completed merge.
pub fn merge_values(
    current: Option<Value>,
    incoming: Value,
    rule: MergeRule,
) -> StateResult<Value> {
    let Some(current) = current else {
        return Ok(incoming);
    };
    if let (Some(left), Some(right)) = (current.as_map(), incoming.as_map()) {
        if rule == MergeRule::Deep {
            return merge_maps(left, right, current.identity().zip(incoming.identity()));
        }
        if left.is_empty() {
            return Ok(incoming);
        }
        let mut merged = left.clone();
        for (key, value) in right {
            drop(merged.insert(key.to_string(), value.clone())?);
        }
        return Ok(Value::from(merged));
    }
    if let (Some(left), Some(right)) = (current.as_list(), incoming.as_list()) {
        return Ok(Value::from(left.concat(right)?));
    }
    Ok(incoming)
}

type MergeIdentity = (ValueIdentity, ValueIdentity);

struct MapFrame<'a> {
    left: &'a ValueMap,
    incoming: MapIter<'a>,
    output: ValueMap,
    identity: Option<MergeIdentity>,
}

impl<'a> MapFrame<'a> {
    fn new(left: &'a ValueMap, right: &'a ValueMap, identity: Option<MergeIdentity>) -> Self {
        Self {
            left,
            incoming: right.iter(),
            output: left.clone(),
            identity,
        }
    }
}

fn merge_maps(
    left: &ValueMap,
    right: &ValueMap,
    identity: Option<MergeIdentity>,
) -> StateResult<Value> {
    if right.is_empty() {
        return Ok(Value::from(left.clone()));
    }
    if left.is_empty() {
        return Ok(Value::from(right.clone()));
    }
    let mut completed = BTreeMap::<MergeIdentity, Value>::new();
    let mut parents = Vec::new();
    let mut active = MapFrame::new(left, right, identity);
    loop {
        if let Some((key, incoming)) = active.incoming.next() {
            if let Some(current) = active.left.get(key)
                && let (Some(left), Some(right)) = (current.as_map(), incoming.as_map())
            {
                let identity = current.identity().zip(incoming.identity());
                let ready = if right.is_empty() {
                    Some(current.clone())
                } else if left.is_empty() {
                    Some(incoming.clone())
                } else {
                    identity.and_then(|identity| completed.get(&identity).cloned())
                };
                if let Some(value) = ready {
                    drop(active.output.insert(key.to_string(), value)?);
                } else {
                    parents.push((active, key));
                    active = MapFrame::new(left, right, identity);
                }
            } else if let Some(current) = active.left.get(key)
                && let (Some(left), Some(right)) = (current.as_list(), incoming.as_list())
            {
                let identity = current.identity().zip(incoming.identity());
                let cached = identity.and_then(|identity| completed.get(&identity).cloned());
                let value = match cached {
                    Some(value) => value,
                    None => {
                        let value = Value::from(left.concat(right)?);
                        if let Some(identity) = identity {
                            drop(completed.insert(identity, value.clone()));
                        }
                        value
                    }
                };
                drop(active.output.insert(key.to_string(), value)?);
            } else {
                drop(active.output.insert(key.to_string(), incoming.clone())?);
            }
            continue;
        }

        let value = Value::from(active.output);
        if let Some(identity) = active.identity {
            drop(completed.insert(identity, value.clone()));
        }
        match parents.pop() {
            Some((mut parent, key)) => {
                drop(parent.output.insert(key.to_string(), value)?);
                active = parent;
            }
            None => return Ok(value),
        }
    }
}

#[cfg(test)]
mod tests;
