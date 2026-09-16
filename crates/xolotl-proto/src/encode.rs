//! Budgeted admission checks for canonical `Value` wire conversion.

use thiserror::Error;
use xolotl_types::{BlobRef, StreamMarker, Value, ValueView};

use crate::convert::{dtype_str, frame_kind_str, value_to_pb};
use crate::xolotl::v1 as pb;

mod failure;
pub use failure::{FailureEncodeError, failure_to_pb_bounded};

/// Hard limit on `Value` nesting, counting the root as depth one.
///
/// Each nested map also adds protobuf map and entry messages. Thirty `Value`
/// levels leave room for Console frame envelopes and multimodal references
/// within prost's default decoding recursion limit of 100. Other envelopes
/// may require a lower limit.
pub const MAX_VALUE_ENCODE_DEPTH: usize = 30;

/// Work and inline allocation limits checked before converting a `Value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueEncodeLimits {
    /// Maximum number of values, including the root and empty collections.
    pub max_nodes: usize,
    /// Maximum nesting depth, with the root at one.
    ///
    /// Values above [`MAX_VALUE_ENCODE_DEPTH`] use that hard limit instead.
    pub max_depth: usize,
    /// Maximum cumulative bytes copied into variable-length wire fields.
    ///
    /// Includes strings, byte arrays, map keys, reference metadata, and tensor
    /// shape storage (`shape.len() * size_of::<u64>()`). External content sizes
    /// in `BlobRef::size` are excluded. Fixed per-value storage is bounded by
    /// `max_nodes`; this limit is not the final protobuf encoded length.
    pub max_inline_bytes: usize,
}

/// A `Value` exceeded a conversion budget before any wire data was cloned.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueEncodeError {
    /// The value tree contains too many nodes.
    #[error("value node limit exceeded: {limit}")]
    Nodes {
        /// Configured node limit.
        limit: usize,
    },
    /// The value tree is too deeply nested.
    #[error("value depth limit exceeded: {limit}")]
    Depth {
        /// Effective depth limit, including the shared hard limit.
        limit: usize,
    },
    /// The total inline payload is too large or its size overflows.
    #[error("value inline byte limit exceeded: {limit}")]
    InlineBytes {
        /// Configured inline byte limit.
        limit: usize,
    },
}

/// Convert a value losslessly after checking its work and allocation budgets.
///
/// Admission borrows payloads and uses collection iterator scratch. Once it
/// succeeds, the canonical [`value_to_pb`] converter constructs the wire value.
/// A zero node or depth limit rejects every value. A zero inline byte limit
/// still permits scalars and collections without variable-length payloads.
/// Callers must check the completed message's `prost::Message::encoded_len`
/// separately before allocating an encoded frame.
pub fn value_to_pb_bounded(
    value: &Value,
    limits: ValueEncodeLimits,
) -> Result<pb::Value, ValueEncodeError> {
    ValueEncodeBudget::new(limits).visit(value, 1)?;
    Ok(value_to_pb(value))
}

struct ValueEncodeBudget {
    limits: ValueEncodeLimits,
    remaining_nodes: usize,
    remaining_inline_bytes: usize,
}

impl ValueEncodeBudget {
    fn new(mut limits: ValueEncodeLimits) -> Self {
        limits.max_depth = limits.max_depth.min(MAX_VALUE_ENCODE_DEPTH);
        Self {
            remaining_nodes: limits.max_nodes,
            remaining_inline_bytes: limits.max_inline_bytes,
            limits,
        }
    }

    fn visit(&mut self, value: &Value, depth: usize) -> Result<(), ValueEncodeError> {
        if depth > self.limits.max_depth {
            return Err(ValueEncodeError::Depth {
                limit: self.limits.max_depth,
            });
        }
        self.remaining_nodes =
            self.remaining_nodes
                .checked_sub(1)
                .ok_or(ValueEncodeError::Nodes {
                    limit: self.limits.max_nodes,
                })?;
        match value.view() {
            ValueView::Null | ValueView::Bool(_) | ValueView::Int(_) | ValueView::Float(_) => {
                Ok(())
            }
            ValueView::Str(text) => self.charge_bytes(text.len()),
            ValueView::Bytes(bytes) => self.charge_bytes(bytes.len()),
            ValueView::List(items) => {
                self.check_children(items.len(), depth)?;
                for item in items {
                    self.visit(item, depth + 1)?;
                }
                Ok(())
            }
            ValueView::Map(entries) => {
                self.check_children(entries.len(), depth)?;
                for (key, value) in entries {
                    self.charge_bytes(key.len())?;
                    self.visit(value, depth + 1)?;
                }
                Ok(())
            }
            ValueView::Blob(blob) => self.charge_blob(blob),
            ValueView::Tensor(tensor) => {
                self.charge_blob(&tensor.blob)?;
                self.charge_bytes(dtype_str(tensor.dtype).len())?;
                self.charge_tensor_shape(tensor.shape.len())
            }
            ValueView::Frame(frame) => {
                self.charge_blob(&frame.blob)?;
                self.charge_bytes(frame_kind_str(frame.kind).len())
            }
            ValueView::StreamEnd(StreamMarker::Done) => Ok(()),
            ValueView::StreamEnd(StreamMarker::Error { message }) => {
                self.charge_bytes(message.len())
            }
        }
    }

    fn check_children(&self, count: usize, depth: usize) -> Result<(), ValueEncodeError> {
        if count > self.remaining_nodes {
            return Err(ValueEncodeError::Nodes {
                limit: self.limits.max_nodes,
            });
        }
        if count != 0 && depth >= self.limits.max_depth {
            return Err(ValueEncodeError::Depth {
                limit: self.limits.max_depth,
            });
        }
        Ok(())
    }

    fn charge_bytes(&mut self, bytes: usize) -> Result<(), ValueEncodeError> {
        self.remaining_inline_bytes = self.remaining_inline_bytes.checked_sub(bytes).ok_or(
            ValueEncodeError::InlineBytes {
                limit: self.limits.max_inline_bytes,
            },
        )?;
        Ok(())
    }

    fn charge_blob(&mut self, blob: &BlobRef) -> Result<(), ValueEncodeError> {
        self.charge_bytes(blob.hash.len())?;
        if let Some(mime) = &blob.mime {
            self.charge_bytes(mime.len())?;
        }
        Ok(())
    }

    fn charge_tensor_shape(&mut self, dimensions: usize) -> Result<(), ValueEncodeError> {
        let bytes =
            dimensions
                .checked_mul(size_of::<u64>())
                .ok_or(ValueEncodeError::InlineBytes {
                    limit: self.limits.max_inline_bytes,
                })?;
        self.charge_bytes(bytes)
    }
}

#[cfg(test)]
mod tests;
