//! Invitation-backed hosted-subject delivery for a proven guest session.
//! The caller must verify the node and subject holder before invoking this
//! port. The store separately checks invitation provenance at every decision.

use crate::{
    AcknowledgeRequest, CloseSubscriptionRequest, CloseSubscriptionResult, FederationError,
    HostedSubject, InspectSubscriptionRequest, OpenRequest, OpenResult, Position, ReadPage,
    ReadRequest, SubscriptionInspection,
};

/// Publisher-side authority for an authenticated, holder-proven guest. An
/// invitation redemption is checked again at each exact stream operation.
pub trait FederationGuestStore: Send + Sync {
    /// Read-only revalidation of a holder-admitted delivery against current
    /// invitation/grant fences. No time persistence, payload read or quota
    /// charge. Potentially blocking stores require bounded host work; custom
    /// implementations without this contract fail closed.
    fn authorize_guest_delivery(
        &self,
        _subject: &HostedSubject,
        _request: InspectSubscriptionRequest,
        _payload: bool,
        _now_ms: u64,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_guest_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationGuestStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Open an exact invited stream under the current guest grant.
    fn open_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError>;

    /// Inspect one guest subscription under current grant and trusted time.
    fn inspect_guest_subscription(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError>;

    /// Close one guest subscription using its stable control request ID.
    fn close_guest_subscription(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError>;

    /// Disclose a bounded page under the guest's current exact grant.
    fn read_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError>;

    /// Record a guest receiver's durable accepted position.
    fn acknowledge_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError>;
}

impl<T: FederationGuestStore + ?Sized> FederationGuestStore for std::sync::Arc<T> {
    fn authorize_guest_delivery(
        &self,
        subject: &HostedSubject,
        request: InspectSubscriptionRequest,
        payload: bool,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        (**self).authorize_guest_delivery(subject, request, payload, now_ms)
    }

    fn bind_guest_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationGuestStore>, crate::FederationError> {
        (**self).bind_guest_decision(decision)
    }
    fn open_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError> {
        (**self).open_guest(subject, now_ms, request)
    }

    fn inspect_guest_subscription(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        (**self).inspect_guest_subscription(subject, now_ms, request)
    }

    fn close_guest_subscription(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        (**self).close_guest_subscription(subject, now_ms, request)
    }

    fn read_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError> {
        (**self).read_guest(subject, now_ms, request)
    }

    fn acknowledge_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError> {
        (**self).acknowledge_guest(subject, now_ms, request)
    }
}
