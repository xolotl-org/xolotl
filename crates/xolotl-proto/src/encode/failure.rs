//! Size admission for lossless failures before any diagnostic field is cloned.

use thiserror::Error;
use xolotl_types::{Failure, Path};

use crate::{convert::failure_to_pb, xolotl::v1 as pb};

/// A structured failure cannot fit in the caller's encoded message allowance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("failure encoded byte limit exceeded: {limit}")]
pub struct FailureEncodeError {
    /// Maximum admitted encoded bytes, including protobuf tags and lengths.
    pub limit: usize,
}

/// Convert a complete failure after checking its exact protobuf encoded size.
///
/// Admission borrows all fields and stops as soon as the budget is exhausted.
/// Repeated empty labels still consume their tags and length prefixes, so their
/// count cannot escape admission. No `Display` string or intermediate tree is
/// constructed. This bounds a wire message, not allocator overhead or host RSS.
pub fn failure_to_pb_bounded(
    failure: &Failure,
    max_encoded_bytes: usize,
) -> Result<pb::Failure, FailureEncodeError> {
    let mut payload = Size::new(max_encoded_bytes);
    match failure {
        Failure::PermissionDenied { required, actual } => {
            for label in required.iter().chain(actual) {
                payload.field(label.len())?;
            }
        }
        Failure::NoHandler { path } => payload.path(path)?,
        Failure::BudgetExhausted { dim } => payload.add(dim.len())?,
        Failure::RateLimited
        | Failure::Timeout
        | Failure::Cancelled
        | Failure::KernelNamespaceProtected => {}
        Failure::ApprovalPending {
            approval_key,
            reason,
        } => {
            payload.text(approval_key)?;
            payload.text(reason)?;
        }
        Failure::Quarantined { op_id, reason } => {
            payload.text(op_id)?;
            payload.text(reason)?;
        }
        Failure::InvalidInput { reason } => payload.add(reason.len())?,
        Failure::HandlerError { kind, message } | Failure::Custom { kind, message } => {
            payload.text(kind)?;
            payload.text(message)?;
        }
        Failure::PolicyViolation { policy, detail } => {
            payload.text(policy)?;
            payload.text(detail)?;
        }
        Failure::PathInvalid { path, reason } => {
            let mut nested = Size::new(max_encoded_bytes);
            nested.path(path)?;
            payload.field(nested.bytes)?;
            payload.text(reason)?;
        }
    }
    // Every oneof alternative is present, including empty strings and markers.
    // All current field numbers fit in a one-byte tag.
    let mut result = Size::new(max_encoded_bytes);
    result.field(payload.bytes)?;
    Ok(failure_to_pb(failure))
}

struct Size {
    bytes: usize,
    limit: usize,
}

impl Size {
    fn new(limit: usize) -> Self {
        Self { bytes: 0, limit }
    }

    fn add(&mut self, bytes: usize) -> Result<(), FailureEncodeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|size| *size <= self.limit)
            .ok_or(FailureEncodeError { limit: self.limit })?;
        Ok(())
    }

    fn field(&mut self, bytes: usize) -> Result<(), FailureEncodeError> {
        self.add(1 + prost::encoding::encoded_len_varint(bytes as u64))?;
        self.add(bytes)
    }

    fn text(&mut self, text: &str) -> Result<(), FailureEncodeError> {
        if !text.is_empty() {
            self.field(text.len())?;
        }
        Ok(())
    }

    fn path(&mut self, path: &Path) -> Result<(), FailureEncodeError> {
        if let Some(cluster) = path.cluster() {
            self.field(cluster.len())?;
        }
        self.text(path.scheme())?;
        for segment in path.segments() {
            self.field(segment.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
