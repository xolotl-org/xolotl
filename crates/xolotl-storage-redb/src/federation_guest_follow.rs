//! Invitation-only receiver state. Neither private peer authority nor public
//! stream policy can install or read these rows.
//! The inbox is a bounded rolling cache, not private reliable retention. Its
//! cursor and Guest ACK attest durable acceptance, not application consumption
//! or perpetual payload availability. Old rows may be evicted without an
//! application projection; readers must observe the local retention floor.

use std::sync::Arc;

use crate::database::Database;
use redb::{ReadableTable as _, ReadableTableMetadata as _};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    AuthorityRevision, Digest, ExportName, FederationError, FederationNodeId, HostedSubject,
    InvitationId, OpenResult, Position, ReadPage, Record, RequestId, StreamRef, SubscriptionRef,
};

use crate::{
    federation_public_follow::{decode_record, encode_record},
    schema::{FEDERATION_GUEST_FOLLOWER_INBOX_TABLE, FEDERATION_GUEST_FOLLOWERS_TABLE},
};

const KEY_BYTES: usize = FederationNodeId::LEN + 16;
const RECORD_KEY_BYTES: usize = KEY_BYTES + 8;
const MAX_FOLLOWS: u64 = 64;
/// Maximum locally retained records for one invited stream.
pub const MAX_GUEST_FOLLOW_INBOX_RECORDS: usize = 4096;
/// Maximum locally retained payload bytes for one invited stream.
pub const MAX_GUEST_FOLLOW_INBOX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_PAYLOAD: usize = 512 * 1024;

/// Exact immutable local relationship to one invitation and Hosted subject.
/// Changing any field requires a new subscription ID (the daemon derives one
/// from its explicit generation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFollowSpec {
    /// Exact publisher stream.
    pub stream: StreamRef,
    /// Locally owned stable subscription identity.
    pub subscription: SubscriptionRef,
    /// Publisher invitation to redeem.
    pub invitation: InvitationId,
    /// Pinned revision of that invitation.
    pub invitation_revision: u64,
    /// Stable redemption ID, persisted before the wire exchange.
    pub redeem_request: RequestId,
    /// Stable Open ID, persisted before the wire exchange.
    pub open_request: RequestId,
    /// Hosted Sync subject proven by the holder key.
    pub subject: HostedSubject,
    /// Local rolling inbox record bound.
    pub max_inbox_records: usize,
    /// Local rolling inbox payload bound.
    pub max_inbox_bytes: usize,
}

impl GuestFollowSpec {
    fn validate(&self, local: FederationNodeId) -> Result<(), FederationError> {
        if self.stream.publisher == local
            || self.subscription.subscriber != local
            || self.subscription.id.as_bytes() == &[0; 16]
            || self.invitation.as_bytes() == [0; 16]
            || self.invitation_revision == 0
            || self.redeem_request.as_bytes() == &[0; 16]
            || self.open_request.as_bytes() == &[0; 16]
            || self.redeem_request == self.open_request
            || self.subject.namespace.is_empty()
            || self.subject.subject.is_empty()
            || self.subject.namespace.len() > 256
            || self.subject.subject.len() > 256
            || self.subject.namespace.chars().any(char::is_control)
            || self.subject.subject.chars().any(char::is_control)
            || !(1..=MAX_GUEST_FOLLOW_INBOX_RECORDS).contains(&self.max_inbox_records)
            || !(MAX_RECORD_PAYLOAD..=MAX_GUEST_FOLLOW_INBOX_BYTES).contains(&self.max_inbox_bytes)
        {
            return Err(FederationError::Invalid("invalid guest follow"));
        }
        Ok(())
    }
}

/// Durable progress for one exact invited stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFollowView {
    /// Relationship selected by the local host.
    pub spec: GuestFollowSpec,
    /// Whether a valid redemption receipt was durably observed.
    pub redeemed: bool,
    /// Publisher Open result durably installed by this receiver.
    pub opened: Option<OpenResult>,
    /// Highest record accepted into the local inbox.
    pub cursor: Option<Position>,
    /// Earliest publisher payload available at the last read.
    pub publisher_minimum_available: u64,
    /// Earliest local record payload retained.
    pub local_minimum_available: u64,
    /// Number of locally retained records.
    pub retained_records: usize,
    /// Locally retained payload bytes.
    pub retained_bytes: usize,
}

/// Bounded local page of accepted Guest records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFollowInboxPage {
    /// Durable row observed with the page.
    pub view: GuestFollowView,
    /// Ordered local records after the caller's exact cursor.
    pub records: Vec<Record>,
}

/// redb-backed invited stream receiver, separate from managed subscriptions.
#[derive(Clone)]
pub struct RedbGuestFollowerStore {
    db: Arc<Database>,
    local: FederationNodeId,
    authority: Option<crate::federation::RedbFederationStore>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSpec {
    publisher: Vec<u8>,
    stream_id: [u8; 16],
    subscriber: Vec<u8>,
    subscription_id: [u8; 16],
    invitation: [u8; 16],
    invitation_revision: u64,
    redeem_request: [u8; 16],
    open_request: [u8; 16],
    issuer: Vec<u8>,
    namespace: String,
    subject: String,
    max_inbox_records: usize,
    max_inbox_bytes: usize,
}

impl From<&GuestFollowSpec> for StoredSpec {
    fn from(spec: &GuestFollowSpec) -> Self {
        Self {
            publisher: spec.stream.publisher.as_bytes().to_vec(),
            stream_id: *spec.stream.id.as_bytes(),
            subscriber: spec.subscription.subscriber.as_bytes().to_vec(),
            subscription_id: *spec.subscription.id.as_bytes(),
            invitation: spec.invitation.as_bytes(),
            invitation_revision: spec.invitation_revision,
            redeem_request: *spec.redeem_request.as_bytes(),
            open_request: *spec.open_request.as_bytes(),
            issuer: spec.subject.issuer.as_bytes().to_vec(),
            namespace: spec.subject.namespace.clone(),
            subject: spec.subject.subject.clone(),
            max_inbox_records: spec.max_inbox_records,
            max_inbox_bytes: spec.max_inbox_bytes,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPosition {
    sequence: u64,
    digest: Vec<u8>,
}

impl StoredPosition {
    fn from_position(position: Position) -> Self {
        Self {
            sequence: position.sequence(),
            digest: position.digest().as_bytes().to_vec(),
        }
    }

    fn position(&self) -> Result<Position, FederationError> {
        let digest = <[u8; 48]>::try_from(self.digest.as_slice())
            .map_err(|_error| FederationError::Corrupt)?;
        Position::new(self.sequence, Digest::from_bytes(digest))
            .map_err(|_error| FederationError::Corrupt)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOpen {
    request_id: [u8; 16],
    export: String,
    publisher_peer_revision: u64,
    publisher_export_revision: u64,
    subscription_revision: u64,
    start: Option<StoredPosition>,
}

impl StoredOpen {
    fn from_open(opened: &OpenResult) -> Self {
        Self {
            request_id: *opened.request_id.as_bytes(),
            export: opened.export.as_str().to_owned(),
            publisher_peer_revision: opened.publisher_authority.peer,
            publisher_export_revision: opened.publisher_authority.export,
            subscription_revision: opened.subscription_revision,
            start: opened.start.map(StoredPosition::from_position),
        }
    }

    fn open(&self, spec: &GuestFollowSpec) -> Result<OpenResult, FederationError> {
        if self.request_id != *spec.open_request.as_bytes()
            || self.subscription_revision == 0
            || self.publisher_export_revision == 0
        {
            return Err(FederationError::Corrupt);
        }
        Ok(OpenResult {
            request_id: spec.open_request,
            subscription: spec.subscription,
            stream: spec.stream,
            export: ExportName::new(self.export.clone())
                .map_err(|_error| FederationError::Corrupt)?,
            publisher_authority: AuthorityRevision {
                peer: self.publisher_peer_revision,
                export: self.publisher_export_revision,
            },
            subscription_revision: self.subscription_revision,
            start: self
                .start
                .as_ref()
                .map(StoredPosition::position)
                .transpose()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FollowRow {
    spec: StoredSpec,
    redeemed: bool,
    opened: Option<StoredOpen>,
    cursor: Option<StoredPosition>,
    publisher_minimum_available: u64,
    local_minimum_available: u64,
    retained_records: usize,
    retained_bytes: usize,
}

impl FollowRow {
    fn view(&self, spec: &GuestFollowSpec) -> Result<GuestFollowView, FederationError> {
        if self.spec != StoredSpec::from(spec)
            || self.publisher_minimum_available == 0
            || self.local_minimum_available == 0
            || self.retained_records > spec.max_inbox_records
            || self.retained_bytes > spec.max_inbox_bytes
            || (self.opened.is_some() && !self.redeemed)
            || (self.cursor.is_some() && self.opened.is_none())
        {
            return Err(FederationError::Corrupt);
        }
        let opened = self
            .opened
            .as_ref()
            .map(|value| value.open(spec))
            .transpose()?;
        let baseline = opened.as_ref().and_then(|value| value.start);
        let cursor = self
            .cursor
            .as_ref()
            .map(StoredPosition::position)
            .transpose()?;
        let next = cursor
            .or(baseline)
            .map_or(Some(1), |position| position.sequence().checked_add(1))
            .ok_or(FederationError::Corrupt)?;
        if self.local_minimum_available > next
            || Some(self.retained_records)
                != usize::try_from(next - self.local_minimum_available).ok()
            || cursor.is_some_and(|position| {
                baseline.is_some_and(|baseline| position.sequence() <= baseline.sequence())
            })
        {
            return Err(FederationError::Corrupt);
        }
        Ok(GuestFollowView {
            spec: spec.clone(),
            redeemed: self.redeemed,
            opened,
            cursor,
            publisher_minimum_available: self.publisher_minimum_available,
            local_minimum_available: self.local_minimum_available,
            retained_records: self.retained_records,
            retained_bytes: self.retained_bytes,
        })
    }
}

fn key(subscription: SubscriptionRef) -> [u8; KEY_BYTES] {
    let mut key = [0; KEY_BYTES];
    key[..FederationNodeId::LEN].copy_from_slice(subscription.subscriber.as_bytes());
    key[FederationNodeId::LEN..].copy_from_slice(subscription.id.as_bytes());
    key
}

fn record_key(subscription: SubscriptionRef, sequence: u64) -> [u8; RECORD_KEY_BYTES] {
    let mut key = [0; RECORD_KEY_BYTES];
    key[..KEY_BYTES].copy_from_slice(&self::key(subscription));
    key[KEY_BYTES..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn decode(bytes: &[u8]) -> Result<FollowRow, FederationError> {
    if bytes.len() > 8192 {
        return Err(FederationError::Corrupt);
    }
    serde_json::from_slice(bytes).map_err(|_error| FederationError::Corrupt)
}

fn encode(row: &FollowRow) -> Result<Vec<u8>, FederationError> {
    serde_json::to_vec(row).map_err(storage)
}

fn storage(error: impl ToString) -> FederationError {
    FederationError::Storage(error.to_string())
}

impl RedbGuestFollowerStore {
    /// Bind remote evidence to the same database transaction as every receipt
    /// and inbox update. No identity is reverified inside the trusted backend.
    pub fn with_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Self, FederationError> {
        if self.authority.is_some() {
            return Err(FederationError::Unauthorized);
        }
        let authority = crate::federation::RedbFederationStore::bound_view(
            Arc::clone(&self.db),
            self.local,
            decision,
        )?;
        Ok(Self {
            authority: Some(authority),
            ..self.clone()
        })
    }

    fn decision_peer(&self, peer: FederationNodeId) -> Result<(), FederationError> {
        self.authority
            .as_ref()
            .map_or(Ok(()), |owner| owner.decision_peer(peer))
    }

    fn begin_read(&self) -> Result<redb::ReadTransaction, FederationError> {
        match &self.authority {
            Some(owner) => owner.begin_decision_read().map(|(txn, _)| txn),
            None => self.db.begin_read().map_err(storage),
        }
    }

    fn with_write<Output>(
        &self,
        operation: impl FnOnce(&mut crate::federation::DecisionWrite) -> Result<Output, FederationError>,
    ) -> Result<Output, FederationError> {
        match &self.authority {
            Some(owner) => owner.with_decision_write(|txn, _| operation(txn)),
            None => operation(&mut crate::federation::DecisionWrite::new(
                self.db.begin_write().map_err(storage)?,
            )),
        }
    }

    pub(crate) fn new(db: Arc<Database>, local: FederationNodeId) -> Self {
        Self {
            db,
            local,
            authority: None,
        }
    }

    /// Return this database's immutable subscriber node identity.
    pub fn local_node(&self) -> FederationNodeId {
        self.local
    }

    /// Durably stage the immutable redemption and Open IDs before sending
    /// either wire request. Repeated preparation verifies the same spec.
    pub fn prepare(&self, spec: &GuestFollowSpec) -> Result<GuestFollowView, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        spec.validate(self.local)?;
        self.with_write(|txn| {
            let mut table = txn
                .open_table(FEDERATION_GUEST_FOLLOWERS_TABLE)
                .map_err(storage)?;
            let saved = table
                .get(key(spec.subscription).as_slice())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            if let Some(row) = saved {
                if row.spec != StoredSpec::from(spec) {
                    return Err(FederationError::Conflict);
                }
                return row.view(spec);
            }
            if table.len().map_err(storage)? >= MAX_FOLLOWS {
                return Err(FederationError::Capacity);
            }
            let row = FollowRow {
                spec: StoredSpec::from(spec),
                redeemed: false,
                opened: None,
                cursor: None,
                publisher_minimum_available: 1,
                local_minimum_available: 1,
                retained_records: 0,
                retained_bytes: 0,
            };
            let view = row.view(spec)?;
            table
                .insert(key(spec.subscription).as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(view)
        })
    }

    /// Remember a checked publisher redemption receipt. A lost response may
    /// be retried with the staged request ID without consuming another use.
    pub fn mark_redeemed(
        &self,
        spec: &GuestFollowSpec,
    ) -> Result<GuestFollowView, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        self.update(spec, |row| {
            row.redeemed = true;
            Ok(())
        })
    }

    /// Install only the exact Open result for this staged subscription.
    pub fn install_open(
        &self,
        spec: &GuestFollowSpec,
        opened: &OpenResult,
    ) -> Result<GuestFollowView, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        if opened.request_id != spec.open_request
            || opened.subscription != spec.subscription
            || opened.stream != spec.stream
        {
            return Err(FederationError::Conflict);
        }
        self.update(spec, |row| {
            if !row.redeemed {
                return Err(FederationError::Unauthorized);
            }
            if let Some(existing) = &row.opened {
                if existing.open(spec)? != *opened {
                    return Err(FederationError::Conflict);
                }
                return Ok(());
            }
            row.local_minimum_available = opened
                .start
                .map_or(Some(1), |position| position.sequence().checked_add(1))
                .ok_or(FederationError::Capacity)?;
            row.opened = Some(StoredOpen::from_open(opened));
            Ok(())
        })
    }

    fn update(
        &self,
        spec: &GuestFollowSpec,
        operation: impl FnOnce(&mut FollowRow) -> Result<(), FederationError>,
    ) -> Result<GuestFollowView, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        spec.validate(self.local)?;
        self.with_write(|txn| {
            let mut table = txn
                .open_table(FEDERATION_GUEST_FOLLOWERS_TABLE)
                .map_err(storage)?;
            let mut row = table
                .get(key(spec.subscription).as_slice())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            row.view(spec)?;
            operation(&mut row)?;
            let view = row.view(spec)?;
            table
                .insert(key(spec.subscription).as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(view)
        })
    }

    /// Return an exact durable row without changing its state.
    pub fn inspect(&self, spec: &GuestFollowSpec) -> Result<GuestFollowView, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        spec.validate(self.local)?;
        let txn = self.begin_read()?;
        let table = txn
            .open_table(FEDERATION_GUEST_FOLLOWERS_TABLE)
            .map_err(storage)?;
        let row = table
            .get(key(spec.subscription).as_slice())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?
            .ok_or(FederationError::NotFound)?;
        if row.spec != StoredSpec::from(spec) {
            return Err(FederationError::Conflict);
        }
        row.view(spec)
    }

    /// Atomically accept and bound a verified page. The returned cursor may be
    /// ACKed only after this transaction commits; an old publisher floor that
    /// skips the next local position is reported as a gap.
    pub fn accept_page(
        &self,
        spec: &GuestFollowSpec,
        page: &ReadPage,
    ) -> Result<GuestFollowView, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        spec.validate(self.local)?;
        self.with_write(|txn| {
            let mut follows = txn
                .open_table(FEDERATION_GUEST_FOLLOWERS_TABLE)
                .map_err(storage)?;
            let mut row = follows
                .get(key(spec.subscription).as_slice())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            let view = row.view(spec)?;
            if view.opened.is_none() || page.minimum_available == 0 {
                return Err(FederationError::Unauthorized);
            }
            let mut next = view
                .cursor
                .or(view.opened.as_ref().and_then(|opened| opened.start))
                .map_or(Some(1), |position| position.sequence().checked_add(1))
                .ok_or(FederationError::Capacity)?;
            if page.minimum_available < row.publisher_minimum_available {
                return Err(FederationError::Conflict);
            }
            if page.minimum_available > next {
                return Err(FederationError::ResyncRequired {
                    minimum_available: page.minimum_available,
                });
            }
            if view.cursor.is_some() && page.head.is_none()
                || page.head.is_some_and(|head| {
                    view.cursor.is_some_and(|cursor| {
                        head.sequence() < cursor.sequence()
                            || (head.sequence() == cursor.sequence() && head != cursor)
                    })
                })
            {
                return Err(FederationError::Conflict);
            }
            if page.records.len() > 128 {
                return Err(FederationError::Capacity);
            }
            let mut inbox = txn
                .open_table(FEDERATION_GUEST_FOLLOWER_INBOX_TABLE)
                .map_err(storage)?;
            let mut prior_sequence = None;
            for record in &page.records {
                if record.stream() != spec.stream
                    || prior_sequence
                        .is_some_and(|prior: u64| prior.checked_add(1) != Some(record.sequence()))
                {
                    return Err(FederationError::Conflict);
                }
                prior_sequence = Some(record.sequence());
                if record.sequence() < next {
                    if record.sequence() < row.local_minimum_available {
                        return Err(FederationError::Indeterminate);
                    }
                    let saved = inbox
                        .get(record_key(spec.subscription, record.sequence()).as_slice())
                        .map_err(storage)?
                        .ok_or(FederationError::Corrupt)?;
                    if decode_record(spec.stream, record.sequence(), saved.value())?.position()
                        != record.position()
                    {
                        return Err(FederationError::Conflict);
                    }
                    continue;
                }
                if record.sequence() != next {
                    return Err(FederationError::Gap {
                        expected: next,
                        received: record.sequence(),
                    });
                }
                let encoded = encode_record(record)?;
                inbox
                    .insert(
                        record_key(spec.subscription, next).as_slice(),
                        encoded.as_slice(),
                    )
                    .map_err(storage)?;
                row.cursor = Some(StoredPosition::from_position(record.position()));
                row.retained_records += 1;
                row.retained_bytes = row
                    .retained_bytes
                    .checked_add(record.payload().len())
                    .ok_or(FederationError::Capacity)?;
                next = next.checked_add(1).ok_or(FederationError::Capacity)?;
            }
            if row.cursor.is_some() && page.head.is_none()
                || page.head.is_some_and(|head| {
                    row.cursor.as_ref().is_some_and(|cursor| {
                        head.sequence() < cursor.sequence
                            || (head.sequence() == cursor.sequence
                                && head.digest().as_bytes() != cursor.digest.as_slice())
                    })
                })
            {
                return Err(FederationError::Conflict);
            }
            while row.retained_records > spec.max_inbox_records
                || row.retained_bytes > spec.max_inbox_bytes
            {
                let sequence = row.local_minimum_available;
                let removed = inbox
                    .remove(record_key(spec.subscription, sequence).as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let record = decode_record(spec.stream, sequence, removed.value())?;
                row.retained_records -= 1;
                row.retained_bytes -= record.payload().len();
                row.local_minimum_available += 1;
            }
            row.publisher_minimum_available = page.minimum_available;
            let view = row.view(spec)?;
            follows
                .insert(key(spec.subscription).as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(inbox);
            drop(follows);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(view)
        })
    }

    /// Read retained private Guest bytes only through the exact configured
    /// subject, invitation and subscription binding.
    pub fn read_inbox(
        &self,
        spec: &GuestFollowSpec,
        after: Option<Position>,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<GuestFollowInboxPage, FederationError> {
        self.decision_peer(spec.stream.publisher)?;
        if max_records == 0
            || max_records > MAX_GUEST_FOLLOW_INBOX_RECORDS
            || max_bytes == 0
            || max_bytes > MAX_GUEST_FOLLOW_INBOX_BYTES
        {
            return Err(FederationError::Capacity);
        }
        spec.validate(self.local)?;
        let txn = self.begin_read()?;
        let follows = txn
            .open_table(FEDERATION_GUEST_FOLLOWERS_TABLE)
            .map_err(storage)?;
        let row = follows
            .get(key(spec.subscription).as_slice())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?
            .ok_or(FederationError::NotFound)?;
        if row.spec != StoredSpec::from(spec) {
            return Err(FederationError::Conflict);
        }
        let view = row.view(spec)?;
        let first = if let Some(after) = after {
            if after.sequence() < view.local_minimum_available {
                return Err(FederationError::ResyncRequired {
                    minimum_available: view.local_minimum_available,
                });
            }
            let inbox = txn
                .open_table(FEDERATION_GUEST_FOLLOWER_INBOX_TABLE)
                .map_err(storage)?;
            let saved = inbox
                .get(record_key(spec.subscription, after.sequence()).as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Conflict)?;
            if decode_record(spec.stream, after.sequence(), saved.value())?.position() != after {
                return Err(FederationError::Conflict);
            }
            after
                .sequence()
                .checked_add(1)
                .ok_or(FederationError::Capacity)?
        } else {
            view.local_minimum_available
        };
        let inbox = txn
            .open_table(FEDERATION_GUEST_FOLLOWER_INBOX_TABLE)
            .map_err(storage)?;
        let last = view.cursor.map_or(0, |position| position.sequence());
        let mut records = Vec::new();
        let mut bytes: usize = 0;
        for sequence in first..=last {
            if records.len() == max_records {
                break;
            }
            let saved = inbox
                .get(record_key(spec.subscription, sequence).as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Corrupt)?;
            let record = decode_record(spec.stream, sequence, saved.value())?;
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Corrupt)?;
            if next > max_bytes {
                if records.is_empty() {
                    return Err(FederationError::Capacity);
                }
                break;
            }
            bytes = next;
            records.push(record);
        }
        Ok(GuestFollowInboxPage { view, records })
    }
}
