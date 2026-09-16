//! Borrowed ordinary-Value projection of the complete failure schema.

use super::{Kind, Node};
use crate::Failure;

pub(super) struct Projection<'a> {
    pub(super) tag: &'static str,
    pub(super) fields: Option<Fields<'a>>,
}

/// Existing failure records have at most two fields. This is fixed schema
/// storage, independent of the length of strings or lists in those fields.
pub(super) struct Fields<'a> {
    entries: [Option<(&'static str, Node<'a>)>; 2],
    next: usize,
}

impl<'a> Fields<'a> {
    pub(super) fn next(&mut self) -> Option<Node<'a>> {
        let (key, value) = self.entries.get(self.next / 2).copied().flatten()?;
        let node = if self.next.is_multiple_of(2) {
            Node::Data(Kind::Key, key.as_bytes())
        } else {
            value
        };
        self.next += 1;
        Some(node)
    }
}

fn unit(tag: &'static str) -> Projection<'static> {
    Projection { tag, fields: None }
}

fn record<'a>(
    tag: &'static str,
    first: (&'static str, Node<'a>),
    second: Option<(&'static str, Node<'a>)>,
) -> Projection<'a> {
    Projection {
        tag,
        fields: Some(Fields {
            entries: [Some(first), second],
            next: 0,
        }),
    }
}

pub(super) fn project(failure: &Failure) -> Projection<'_> {
    match failure {
        Failure::PermissionDenied { required, actual } => record(
            "PermissionDenied",
            ("actual", Node::Strings(actual)),
            Some(("required", Node::Strings(required))),
        ),
        Failure::NoHandler { path } => record("NoHandler", ("path", Node::PathText(path)), None),
        Failure::BudgetExhausted { dim } => {
            record("BudgetExhausted", ("dim", Node::text(dim)), None)
        }
        Failure::RateLimited => unit("RateLimited"),
        Failure::ApprovalPending {
            approval_key,
            reason,
        } => record(
            "ApprovalPending",
            ("approval_key", Node::text(approval_key)),
            Some(("reason", Node::text(reason))),
        ),
        Failure::Timeout => unit("Timeout"),
        Failure::Cancelled => unit("Cancelled"),
        Failure::Quarantined { op_id, reason } => record(
            "Quarantined",
            ("op_id", Node::text(op_id)),
            Some(("reason", Node::text(reason))),
        ),
        Failure::InvalidInput { reason } => {
            record("InvalidInput", ("reason", Node::text(reason)), None)
        }
        Failure::HandlerError { kind, message } => record(
            "HandlerError",
            ("kind", Node::text(kind)),
            Some(("message", Node::text(message))),
        ),
        Failure::KernelNamespaceProtected => unit("KernelNamespaceProtected"),
        Failure::PolicyViolation { policy, detail } => record(
            "PolicyViolation",
            ("detail", Node::text(detail)),
            Some(("policy", Node::text(policy))),
        ),
        Failure::PathInvalid { path, reason } => record(
            "PathInvalid",
            ("path", Node::PathText(path)),
            Some(("reason", Node::text(reason))),
        ),
        Failure::Custom { kind, message } => record(
            "Custom",
            ("kind", Node::text(kind)),
            Some(("message", Node::text(message))),
        ),
    }
}
