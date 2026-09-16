//! Resident-only semantics. Memo keys never become value or wire identities.
//!
//! These operations use an iterative DAG walk and temporary storage proportional
//! to the visited graph. Their ordinary `alloc` failure behavior is the same as
//! the owning Value constructors; they impose no hidden depth or node limit.

use super::traversal::{ValueNodeKey, ValuePostorder};
use super::{StreamMarker, Value, ValueView};
use alloc::collections::BTreeMap;
use core::{fmt, hash::Hash};

mod equality;
mod fingerprint;
mod local;

#[cfg(test)]
mod tests;

fn is_leaf(value: &Value) -> bool {
    !matches!(value.view(), ValueView::List(_) | ValueView::Map(_))
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        if core::ptr::eq(self, other)
            || self
                .identity()
                .zip(other.identity())
                .is_some_and(|(left, right)| left == right)
        {
            return true;
        }
        equality::equal(self, other)
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.semantic_digest().hash(state);
    }
}

impl Value {
    /// Versioned BLAKE3 semantic digest, independent of sharing and wire chunks.
    ///
    /// This hashes resident types, exact fields and ordered children. Media
    /// references contribute their complete metadata; it never reads content.
    /// Digest equality is not a replacement for exact [`Eq`].
    pub fn semantic_digest(&self) -> [u8; 32] {
        fingerprint::digest(self)
    }

    /// Token reservation estimate, saturating at `u64::MAX`.
    ///
    /// Shared children contribute once per logical edge. Their summaries are
    /// computed once per resident node, so a small DAG is not expanded. Media
    /// references have a nominal cost of 256; providers report actual usage.
    pub fn approx_tokens(&self) -> u64 {
        if is_leaf(self) {
            return leaf_tokens(self);
        }
        let mut totals = BTreeMap::new();
        let mut walk = ValuePostorder::new(self);
        while let Some(value) = walk.next(|key| totals.contains_key(&key)) {
            let count = match value.view() {
                ValueView::List(items) => items
                    .iter()
                    .fold(0u64, |sum, child| {
                        sum.saturating_add(totals[&ValueNodeKey::of(child)])
                    })
                    .max(1),
                ValueView::Map(entries) => entries
                    .iter()
                    .fold(entries.len() as u64, |sum, (_, child)| {
                        sum.saturating_add(totals[&ValueNodeKey::of(child)])
                    })
                    .max(1),
                _ => leaf_tokens(value),
            };
            totals.insert(ValueNodeKey::of(value), count);
        }
        // The postorder walk always completes its root before terminating.
        totals[&ValueNodeKey::of(self)]
    }
}

fn leaf_tokens(value: &Value) -> u64 {
    match value.view() {
        ValueView::Str(text) => (text.chars().count() as u64 / 4).max(1),
        ValueView::Bytes(bytes) => (bytes.len() as u64 / 4).max(1),
        ValueView::Blob(_) | ValueView::Tensor(_) | ValueView::Frame(_) => 256,
        _ => 1,
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.view() {
            ValueView::Null => formatter.write_str("Null"),
            ValueView::Bool(value) => formatter.debug_tuple("Bool").field(&value).finish(),
            ValueView::Int(value) => formatter.debug_tuple("Int").field(&value).finish(),
            ValueView::Float(value) => formatter.debug_tuple("Float").field(&value).finish(),
            ValueView::Str(text) => formatter
                .debug_struct("Str")
                .field("bytes", &text.len())
                .field("prefix", &text_prefix(text))
                .finish_non_exhaustive(),
            ValueView::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("len", &bytes.len())
                .field("prefix", &&bytes[..bytes.len().min(16)])
                .finish_non_exhaustive(),
            ValueView::List(items) => formatter
                .debug_struct("List")
                .field("len", &items.len())
                .finish(),
            ValueView::Map(entries) => formatter
                .debug_struct("Map")
                .field("len", &entries.len())
                .finish(),
            ValueView::Blob(blob) => formatter
                .debug_struct("Blob")
                .field("size", &blob.size)
                .finish_non_exhaustive(),
            ValueView::Tensor(tensor) => formatter
                .debug_struct("Tensor")
                .field("dtype", &tensor.dtype)
                .field("rank", &tensor.shape.len())
                .field("bytes", &tensor.blob.size)
                .finish_non_exhaustive(),
            ValueView::Frame(frame) => formatter
                .debug_struct("Frame")
                .field("kind", &frame.kind)
                .field("ts_nanos", &frame.ts_nanos)
                .field("bytes", &frame.blob.size)
                .finish_non_exhaustive(),
            ValueView::StreamEnd(StreamMarker::Done) => formatter.write_str("StreamEnd(Done)"),
            ValueView::StreamEnd(StreamMarker::Error { message }) => formatter
                .debug_struct("StreamEnd(Error)")
                .field("prefix", &text_prefix(message))
                .finish_non_exhaustive(),
        }
    }
}

fn text_prefix(text: &str) -> &str {
    let end = text
        .char_indices()
        .nth(64)
        .map_or(text.len(), |(offset, _)| offset);
    &text[..end]
}
