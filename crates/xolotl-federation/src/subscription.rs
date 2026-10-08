//! Subscription control is distinct from transport request correlation. A
//! history baseline excludes earlier records but is not an acceptance receipt.

use crate::{ExportName, FederationNodeId, Position, RequestId, StreamRef, SubscriptionRef};

/// The history window fixed when a publisher accepts a new subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryStart {
    /// Read all history retained and authorized for this export view.
    All,
    /// Begin strictly after one immutable record proven in this stream.
    After(Position),
    /// Begin after the stream head committed at the Open decision point.
    FromNow,
}

/// Request to inspect one durable publisher-side subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectSubscriptionRequest {
    /// Node proven by the current transport Session.
    pub authenticated_subscriber: FederationNodeId,
    /// Exact subscriber-owned subscription identity.
    pub subscription: SubscriptionRef,
}

/// A publisher-side view of the durable delivery contract. `start` only
/// constrains history; `acknowledged` proves receiver inbox acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionInspection {
    /// Subscription whose delivery state was inspected.
    pub subscription: SubscriptionRef,
    /// Immutable stream selected at Open.
    pub stream: StreamRef,
    /// Export name whose current authority governs disclosure.
    pub export: ExportName,
    /// Revision of this subscription's control contract.
    pub subscription_revision: u64,
    /// History exclusion baseline; not proof of receipt.
    pub start: Option<Position>,
    /// Highest position accepted and reported by the receiver.
    pub acknowledged: Option<Position>,
    /// Publisher's current committed stream head.
    pub head: Option<Position>,
    /// Earliest sequence whose payload remains available.
    pub minimum_available: u64,
    /// Whether this subscription can admit new reads and acknowledgements.
    pub closed: bool,
}

/// Idempotent request to close one subscription revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseSubscriptionRequest {
    /// Node proven by the current transport Session.
    pub authenticated_subscriber: FederationNodeId,
    /// Stable control request ID to reconcile a lost response.
    pub request_id: RequestId,
    /// Exact subscription to close.
    pub subscription: SubscriptionRef,
    /// Optional CAS fence against closing a newer subscription contract.
    pub expected_subscription_revision: Option<u64>,
}

/// Publisher's persisted receipt for a Close request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseSubscriptionResult {
    /// Original stable control request ID.
    pub request_id: RequestId,
    /// Subscription closed by the request.
    pub subscription: SubscriptionRef,
    /// Resulting publisher-side control revision.
    pub subscription_revision: u64,
}
