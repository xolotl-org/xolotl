//! Gateway admission accounting over resident values, with shared-node memoization.

use std::collections::BTreeMap;
use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
use xolotl_types::{BlobRef, StreamMarker, Value, ValueView};

/// Per-value admission limits chosen by a protocol adapter or gateway profile.
#[derive(Clone, Copy, Debug)]
pub struct ValueAdmissionLimits {
    /// Maximum logical node occurrences after expanding shared references.
    pub max_nodes: usize,
    /// Maximum logical nesting depth, counting the root as one.
    pub max_depth: usize,
    /// Maximum inline accounting bytes, excluding referenced object contents.
    pub max_inline_bytes: usize,
}

/// Logical work and inline footprint, independent of resident sharing layout.
#[derive(Clone, Copy, Debug)]
pub struct ValueFootprint {
    /// Logical node occurrences, including repeated references.
    pub nodes: usize,
    /// Maximum nesting depth, counting the root as one.
    pub depth: usize,
    /// Inline accounting bytes; not the final transport's encoded length.
    pub inline_bytes: usize,
}

impl ValueFootprint {
    fn fits(self, limits: ValueAdmissionLimits) -> bool {
        self.nodes <= limits.max_nodes
            && self.depth <= limits.max_depth
            && self.inline_bytes <= limits.max_inline_bytes
    }
}

/// Inspect a value under explicit caller limits without expanding shared DAGs.
///
/// Metadata is included; referenced object content is not loaded. Each resident
/// node is summarized once, and every logical edge contributes its summary.
/// Overflow or an exceeded limit returns `None`. Ordinary `alloc` failure
/// behavior applies to graph scratch; leaf inspection does not allocate.
pub fn admit(value: &Value, limits: ValueAdmissionLimits) -> Option<ValueFootprint> {
    let root_local = ValueFootprint {
        nodes: 1,
        depth: 1,
        inline_bytes: local_bytes(value)?,
    };
    if !root_local.fits(limits) {
        return None;
    }
    if !matches!(value.view(), ValueView::List(_) | ValueView::Map(_)) {
        return Some(root_local);
    }
    let mut totals = BTreeMap::<_, ValueFootprint>::new();
    let mut minimum_bytes = 0usize;
    let mut minimum_nodes = 0usize;
    let mut walk = ValuePostorder::new(value);
    while let Some(node) = walk
        .try_next(
            |key| totals.contains_key(&key),
            |node, depth| {
                // Every newly reached resident node contributes at least once
                // to the root. Reject before allocating descendant frames.
                minimum_bytes = minimum_bytes
                    .checked_add(local_bytes(node).ok_or(())?)
                    .ok_or(())?;
                minimum_nodes = minimum_nodes.checked_add(1).ok_or(())?;
                if depth > limits.max_depth
                    || minimum_bytes > limits.max_inline_bytes
                    || minimum_nodes > limits.max_nodes
                {
                    return Err(());
                }
                Ok(())
            },
        )
        .ok()?
    {
        let mut total = ValueFootprint {
            nodes: 1,
            depth: 1,
            inline_bytes: local_bytes(node)?,
        };
        let mut add = |child: &Value| -> Option<()> {
            let child = totals.get(&ValueNodeKey::of(child))?;
            total.nodes = total.nodes.checked_add(child.nodes)?;
            total.inline_bytes = total.inline_bytes.checked_add(child.inline_bytes)?;
            total.depth = total.depth.max(child.depth.checked_add(1)?);
            Some(())
        };
        match node.view() {
            ValueView::List(items) => {
                for child in items {
                    add(child)?;
                }
            }
            ValueView::Map(entries) => {
                for child in entries.values() {
                    add(child)?;
                }
            }
            _ => {}
        }
        if !total.fits(limits) {
            return None;
        }
        totals.insert(ValueNodeKey::of(node), total);
    }
    totals.get(&ValueNodeKey::of(value)).copied()
}

pub(crate) fn inline_bytes(value: &Value, limit: usize) -> Option<usize> {
    admit(
        value,
        ValueAdmissionLimits {
            max_nodes: usize::MAX,
            max_depth: usize::MAX,
            max_inline_bytes: limit,
        },
    )
    .map(|size| size.inline_bytes)
}

fn blob_bytes(blob: &BlobRef, metadata: usize) -> Option<usize> {
    blob.hash
        .len()
        .checked_add(metadata)?
        .checked_add(blob.mime.as_ref().map_or(0, String::len))
}

fn local_bytes(value: &Value) -> Option<usize> {
    match value.view() {
        ValueView::Null | ValueView::Bool(_) => Some(1),
        ValueView::Int(_) | ValueView::Float(_) => Some(8),
        ValueView::Str(text) => Some(text.len()),
        ValueView::Bytes(bytes) => Some(bytes.len()),
        ValueView::Blob(blob) => blob_bytes(blob, 16),
        ValueView::Tensor(tensor) => {
            blob_bytes(&tensor.blob, 24)?.checked_add(tensor.shape.len().checked_mul(8)?)
        }
        ValueView::Frame(frame) => blob_bytes(&frame.blob, 32),
        ValueView::StreamEnd(StreamMarker::Done) => Some(1),
        ValueView::StreamEnd(StreamMarker::Error { message }) => Some(message.len()),
        ValueView::List(items) => Some(items.len()),
        ValueView::Map(entries) => entries
            .keys()
            .try_fold(entries.len(), |sum, key| sum.checked_add(key.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_counts_every_occurrence_without_expanding_the_graph() {
        let mut shared = Value::bytes(vec![0; 16]);
        for _ in 0..192 {
            shared = Value::list(vec![shared.clone(), shared]);
        }
        assert_eq!(inline_bytes(&shared, usize::MAX), None);
        let leaf = Value::list(vec![Value::integer(1), Value::from("hello")]);
        let shared = Value::list(vec![leaf.clone(), leaf]);
        let duplicated = Value::list(vec![
            Value::list(vec![Value::integer(1), Value::from("hello")]),
            Value::list(vec![Value::integer(1), Value::from("hello")]),
        ]);
        assert_eq!(inline_bytes(&shared, 32), Some(32));
        assert_eq!(inline_bytes(&duplicated, 32), Some(32));
        assert_eq!(inline_bytes(&shared, 31), None);
        let limits = ValueAdmissionLimits {
            max_nodes: 7,
            max_depth: 3,
            max_inline_bytes: 32,
        };
        assert_eq!(
            admit(&shared, limits).map(|size| (size.nodes, size.depth, size.inline_bytes)),
            Some((7, 3, 32))
        );
        assert!(
            admit(
                &shared,
                ValueAdmissionLimits {
                    max_nodes: 6,
                    ..limits
                }
            )
            .is_none()
        );

        let leaf = Value::list(vec![Value::null()]);
        let different_depths = Value::list(vec![leaf.clone(), Value::list(vec![leaf])]);
        // A subtree first completed at depth 2 is then reused at depth 3.
        // Its cached summary must still contribute depth at the second use.
        assert!(admit(&different_depths, limits).is_none());
        assert!(
            admit(
                &different_depths,
                ValueAdmissionLimits {
                    max_depth: 4,
                    ..limits
                }
            )
            .is_some()
        );
    }
}
