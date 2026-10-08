//! Local, bounded reads of records already accepted into a receiver's inbox.
//! Acceptance, projection and remote acknowledgement are distinct positions.
//! Private acceptance is a reliable durable inbox, not a rolling cache:
//! maintenance must preserve unconsumed records and unresolved evidence.
//! A sealed byte archive can independently establish a delivery baseline and
//! contiguous post-archive coverage without an application projection. It
//! does not authorize projected-inbox retirement or claim missing events were
//! accepted. Public and Guest stock follower caches have separate retention
//! contracts and do not acquire private replica commitments from a cursor.

use crate::{OpenResult, Position, Record, StreamRef, SubscriptionRef};

/// A trusted local projector asks for one immutable receiver subscription.
/// `after` is an exact record position; `None` starts at the Open baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxReadRequest {
    /// Local subscription whose accepted records are read.
    pub subscription: SubscriptionRef,
    /// Stream expected by the projector; mismatches are rejected.
    pub expected_stream: StreamRef,
    /// Exact cursor after which to read, or the subscription baseline.
    pub after: Option<Position>,
    /// Maximum number of records in the returned page.
    pub max_records: usize,
    /// Maximum payload bytes in the returned page.
    pub max_bytes: usize,
}

/// Local accepted page and independent receiver/application progress evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxReadPage {
    /// Publisher's fixed Open contract installed by this receiver.
    pub opened: OpenResult,
    /// Highest durably accepted receiver position.
    pub received: Option<Position>,
    /// Highest durably projected application position.
    pub projected: Option<Position>,
    /// Ordered, bounded accepted records after the requested cursor.
    pub records: Vec<Record>,
}
