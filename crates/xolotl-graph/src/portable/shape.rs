//! Stack-bounded source inspection before recursive lowering or serialization.

use super::{CompileError, CompileLimits, Expression, Program, Transform};
use alloc::{collections::BTreeMap, vec::Vec};
use core::slice;
use serde_json::Value as JsonValue;
use xolotl_types::{
    BlobRef, StreamMarker, Value, ValueView,
    value::traversal::{ValueNodeKey, ValuePostorder},
};

// A JSON document also contains the Program and Expression envelopes. Keep
// literal nesting below serde_json's default 128-container decode limit.
pub(super) const MAX_LITERAL_DEPTH: usize = 120;
// Tagged resident values serialize as flat node tables. Their logical depth
// can exceed JSON document depth, but still needs a finite inspection budget.
pub(super) const MAX_RESIDENT_DEPTH: usize = 1024;

struct ShapeBudget {
    remaining: usize,
}

impl ShapeBudget {
    fn spend(&mut self, bytes: usize) -> Result<(), CompileError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(CompileError::Capacity)?;
        Ok(())
    }
}

enum ExpressionPending<'a> {
    Node(&'a Expression, usize),
    Sequence(slice::Iter<'a, Expression>, usize),
}

impl Program {
    /// Enforce structural admission before lowering or serialization and
    /// before effects are admitted. This counts a conservative
    /// lower bound on compact JSON bytes; hosts accepting Rust-built programs
    /// must additionally check their exact compact encoded size.
    /// Each distinct resident value node is charged once per embedded value;
    /// list/map reference edges are charged even when children are shared.
    /// Collection edges are admitted before iterator allocation or descent.
    /// Reference metadata strings and tensor dimensions count, not the
    /// out-of-line blob payload size. These charges are not an RSS limit.
    pub fn validate_structure_with_limits(
        &self,
        limits: CompileLimits,
    ) -> Result<(), CompileError> {
        let mut budget = ShapeBudget {
            remaining: limits.source_bytes,
        };
        budget.spend(1)?; // The Program object itself occupies source bytes.
        check_expression(&self.body, limits, &mut budget)?;
        for (name, body) in &self.functions {
            budget.spend(name.len())?;
            check_expression(body, limits, &mut budget)?;
        }
        Ok(())
    }
}

fn check_expression(
    root: &Expression,
    limits: CompileLimits,
    budget: &mut ShapeBudget,
) -> Result<(), CompileError> {
    let mut pending = Vec::from([ExpressionPending::Node(root, 0)]);
    while let Some(item) = pending.pop() {
        let (expression, depth) = match item {
            ExpressionPending::Node(expression, depth) => (expression, depth),
            ExpressionPending::Sequence(mut steps, depth) => {
                if let Some(step) = steps.next() {
                    if steps.len() != 0 {
                        pending.push(ExpressionPending::Sequence(steps, depth));
                    }
                    pending.push(ExpressionPending::Node(step, depth));
                }
                continue;
            }
        };
        if depth > limits.expression_depth {
            return Err(CompileError::Capacity);
        }
        budget.spend(1)?;
        let child_depth = depth.checked_add(1).ok_or(CompileError::Capacity)?;
        match expression {
            Expression::Literal { value } => check_json(value, budget)?,
            Expression::Constant { value } => check_value(value, budget)?,
            Expression::Use { name } => budget.spend(name.len())?,
            Expression::Let { name, value, body } => {
                budget.spend(name.len())?;
                pending.push(ExpressionPending::Node(body, child_depth));
                pending.push(ExpressionPending::Node(value, child_depth));
            }
            Expression::Sequence { steps } => {
                pending.push(ExpressionPending::Sequence(steps.iter(), child_depth));
            }
            Expression::Invoke { operation } => {
                budget.spend(
                    operation
                        .target
                        .path()
                        .canonical_len()
                        .ok_or(CompileError::Capacity)?,
                )?;
                budget.spend(operation.method.len())?;
                if let Some(value) = &operation.literal_input {
                    check_value(value, budget)?;
                }
            }
            Expression::Transform { operation } => match operation {
                Transform::Field { name } => budget.spend(name.len())?,
                Transform::Equal { value } => check_value(value, budget)?,
                _ => {}
            },
            Expression::If { condition, yes, no } => {
                pending.push(ExpressionPending::Node(no, child_depth));
                pending.push(ExpressionPending::Node(yes, child_depth));
                pending.push(ExpressionPending::Node(condition, child_depth));
            }
            Expression::While {
                condition, body, ..
            } => {
                pending.push(ExpressionPending::Node(body, child_depth));
                pending.push(ExpressionPending::Node(condition, child_depth));
            }
            Expression::Parallel { left, right } | Expression::Race { left, right } => {
                pending.push(ExpressionPending::Node(right, child_depth));
                pending.push(ExpressionPending::Node(left, child_depth));
            }
            Expression::Catch { body, recover } => {
                pending.push(ExpressionPending::Node(recover, child_depth));
                pending.push(ExpressionPending::Node(body, child_depth));
            }
            Expression::Finally { body, cleanup } => {
                pending.push(ExpressionPending::Node(cleanup, child_depth));
                pending.push(ExpressionPending::Node(body, child_depth));
            }
            Expression::Acting { identity, body } => {
                budget.spend(identity.canonical_len().ok_or(CompileError::Capacity)?)?;
                pending.push(ExpressionPending::Node(body, child_depth));
            }
            Expression::Call { function } => budget.spend(function.len())?,
            Expression::Module { module } => {
                budget.spend(module.name.len())?;
                if let Some(value) = &module.arg {
                    check_value(value, budget)?;
                }
            }
            Expression::Fail { message } => budget.spend(message.len())?,
            Expression::Wait {
                wait: crate::WaitSpec::Signal(path),
            } => budget.spend(path.canonical_len().ok_or(CompileError::Capacity)?)?,
            Expression::Input | Expression::Wait { .. } => {}
        }
    }
    Ok(())
}

enum JsonPending<'a> {
    Node(&'a JsonValue, usize),
    Array(slice::Iter<'a, JsonValue>, usize),
    Object(serde_json::map::Iter<'a>, usize),
}

fn check_json(root: &JsonValue, budget: &mut ShapeBudget) -> Result<(), CompileError> {
    let mut pending = Vec::from([JsonPending::Node(root, 1)]);
    while let Some(item) = pending.pop() {
        match item {
            JsonPending::Node(value, depth) => {
                if depth > MAX_LITERAL_DEPTH {
                    return Err(CompileError::Capacity);
                }
                budget.spend(1)?;
                match value {
                    JsonValue::String(value) => budget.spend(value.len())?,
                    JsonValue::Array(values) => {
                        pending.push(JsonPending::Array(values.iter(), depth + 1));
                    }
                    JsonValue::Object(values) => {
                        pending.push(JsonPending::Object(values.iter(), depth + 1));
                    }
                    _ => {}
                }
            }
            JsonPending::Array(mut values, depth) => {
                if let Some(value) = values.next() {
                    pending.push(JsonPending::Array(values, depth));
                    pending.push(JsonPending::Node(value, depth));
                }
            }
            JsonPending::Object(mut values, depth) => {
                if let Some((key, value)) = values.next() {
                    budget.spend(key.len())?;
                    pending.push(JsonPending::Object(values, depth));
                    pending.push(JsonPending::Node(value, depth));
                }
            }
        }
    }
    Ok(())
}

fn check_value(root: &Value, budget: &mut ShapeBudget) -> Result<(), CompileError> {
    // Tagged Value serialization records each shared resident node once.
    // Memoizing subtree depths avoids expanding a shared DAG repeatedly.
    let mut depths: BTreeMap<ValueNodeKey<'_>, usize> = BTreeMap::new();
    let mut walk = ValuePostorder::new(root);
    while let Some(value) = walk.try_next(
        |key| depths.contains_key(&key),
        |value, depth| {
            #[cfg(test)]
            super::tests::record_value_entry();
            if depth > MAX_RESIDENT_DEPTH {
                return Err(CompileError::Capacity);
            }
            budget.spend(1)?;
            match value.view() {
                ValueView::Str(text) => budget.spend(text.len())?,
                ValueView::Bytes(bytes) => budget.spend(bytes.len())?,
                ValueView::List(items) => budget.spend(items.len())?,
                ValueView::Map(entries) => {
                    budget.spend(entries.len())?;
                    for (key, _) in entries.iter() {
                        budget.spend(key.len())?;
                    }
                }
                ValueView::Blob(blob) => check_blob(blob, budget)?,
                ValueView::Tensor(tensor) => {
                    budget.spend(tensor.shape.len())?;
                    check_blob(&tensor.blob, budget)?;
                }
                ValueView::Frame(frame) => check_blob(&frame.blob, budget)?,
                ValueView::StreamEnd(StreamMarker::Error { message }) => {
                    budget.spend(message.len())?;
                }
                _ => {}
            }
            Ok(())
        },
    )? {
        let mut depth = 1usize;
        let mut include_child = |child: &Value| -> Result<(), CompileError> {
            let child_depth = depths
                .get(&ValueNodeKey::of(child))
                .ok_or_else(|| CompileError::Encoding("value traversal lost a child".into()))?;
            depth = depth.max(child_depth.saturating_add(1));
            Ok(())
        };
        match value.view() {
            ValueView::List(items) => {
                for child in items.iter() {
                    include_child(child)?;
                }
            }
            ValueView::Map(entries) => {
                for (_, child) in entries.iter() {
                    include_child(child)?;
                }
            }
            _ => {}
        }
        if depth > MAX_RESIDENT_DEPTH {
            return Err(CompileError::Capacity);
        }
        depths.insert(ValueNodeKey::of(value), depth);
    }
    Ok(())
}

fn check_blob(blob: &BlobRef, budget: &mut ShapeBudget) -> Result<(), CompileError> {
    budget.spend(blob.hash.len())?;
    if let Some(mime) = &blob.mime {
        budget.spend(mime.len())?;
    }
    Ok(())
}
