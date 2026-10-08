//! Receiver-owned public stream cursor and bounded inbox. These tables are
//! deliberately separate from private peer/subscription delivery state.
//! This rolling cache evicts oldest payloads within its record/byte bounds;
//! its durable cursor is delivery progress, not a promise of complete local
//! history or application consumption. Readers below its local retention floor
//! must resynchronize. It is not a private reliable inbox or replica commitment.

use std::sync::Arc;

use crate::database::Database;
use redb::{ReadableTable as _, ReadableTableMetadata as _};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    Digest, EventRef, EventType, FederationError, FederationNodeId, MAX_PUBLIC_READ_BYTES,
    MAX_PUBLIC_READ_RECORDS, Position, PublicReadPage, PublicStreamView, Record, RecordParts,
    RequestId, SchemaRevision, StreamRef,
};

use crate::schema::{FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE, FEDERATION_PUBLIC_FOLLOWERS_TABLE};

const KEY_BYTES: usize = FederationNodeId::LEN + 16;
const RECORD_KEY_BYTES: usize = KEY_BYTES + 8;
const MAX_FOLLOWS: u64 = 64;
/// Maximum records held by one stock public follower's rolling inbox.
pub const MAX_PUBLIC_FOLLOW_INBOX_RECORDS: usize = 4096;
/// Maximum payload bytes held by one stock public follower's rolling inbox.
pub const MAX_PUBLIC_FOLLOW_INBOX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_PAYLOAD: usize = 512 * 1024;

/// Durable local progress and independent publisher/local retention limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicFollowerView {
    /// Exact public stream followed by this local node.
    pub stream: StreamRef,
    /// Publisher policy revision used to fence each stateless read.
    pub policy_revision: u64,
    /// Highest record committed to this follower's inbox.
    pub cursor: Option<Position>,
    /// Earliest sequence whose payload the publisher still offers.
    pub publisher_minimum_available: u64,
    /// Earliest sequence whose payload this rolling local inbox retains.
    pub local_minimum_available: u64,
    /// Current number of local inbox records.
    pub retained_records: usize,
    /// Current local inbox payload bytes.
    pub retained_bytes: usize,
}

/// Bounded local page from records already received by a public follower.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicFollowerInboxPage {
    /// Durable follower state observed with the returned records.
    pub view: PublicFollowerView,
    /// Ordered local records after the requested exact cursor.
    pub records: Vec<Record>,
}

/// redb-backed stock public follower, separate from private subscriptions.
#[derive(Clone)]
pub struct RedbPublicFollowerStore {
    db: Arc<Database>,
    local: FederationNodeId,
    authority: Option<crate::federation::RedbFederationStore>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPosition {
    sequence: u64,
    digest: Vec<u8>,
}

impl StoredPosition {
    fn from_position(value: Position) -> Self {
        Self {
            sequence: value.sequence(),
            digest: value.digest().as_bytes().to_vec(),
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
struct FollowRow {
    policy_revision: u64,
    cursor: Option<StoredPosition>,
    publisher_minimum_available: u64,
    local_minimum_available: u64,
    retained_records: usize,
    retained_bytes: usize,
}

impl FollowRow {
    fn validate(&self) -> Result<(), FederationError> {
        if self.policy_revision == 0
            || self.publisher_minimum_available == 0
            || self.local_minimum_available == 0
            || self.retained_records > MAX_PUBLIC_FOLLOW_INBOX_RECORDS
            || self.retained_bytes > MAX_PUBLIC_FOLLOW_INBOX_BYTES
        {
            return Err(FederationError::Corrupt);
        }
        let next = match self.cursor.as_ref() {
            Some(position) => position
                .position()?
                .sequence()
                .checked_add(1)
                .ok_or(FederationError::Corrupt)?,
            None => 1,
        };
        if self.local_minimum_available > next
            || self.retained_records != (next - self.local_minimum_available) as usize
        {
            return Err(FederationError::Corrupt);
        }
        Ok(())
    }

    fn view(&self, stream: StreamRef) -> Result<PublicFollowerView, FederationError> {
        self.validate()?;
        Ok(PublicFollowerView {
            stream,
            policy_revision: self.policy_revision,
            cursor: self
                .cursor
                .as_ref()
                .map(StoredPosition::position)
                .transpose()?,
            publisher_minimum_available: self.publisher_minimum_available,
            local_minimum_available: self.local_minimum_available,
            retained_records: self.retained_records,
            retained_bytes: self.retained_bytes,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEventRef {
    origin: Vec<u8>,
    namespace: String,
    id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecordHeader {
    publish_id: [u8; 16],
    event_type: String,
    schema_revision: [u8; 32],
    event_ref: Option<StoredEventRef>,
    digest: Vec<u8>,
}

pub(crate) fn encode_record(record: &Record) -> Result<Vec<u8>, FederationError> {
    if record.payload().len() > MAX_RECORD_PAYLOAD {
        return Err(FederationError::Capacity);
    }
    let header = StoredRecordHeader {
        publish_id: *record.publish_id().as_bytes(),
        event_type: record.event_type().as_str().to_owned(),
        schema_revision: *record.schema_revision().as_bytes(),
        event_ref: record.event_ref().map(|event| StoredEventRef {
            origin: event.origin().as_bytes().to_vec(),
            namespace: event.namespace().to_owned(),
            id: event.id().to_owned(),
        }),
        digest: record.digest().as_bytes().to_vec(),
    };
    let header = serde_json::to_vec(&header).map_err(storage)?;
    if header.len() > 16 * 1024 {
        return Err(FederationError::Capacity);
    }
    let mut encoded = Vec::with_capacity(4 + header.len() + record.payload().len());
    encoded.extend_from_slice(&(header.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(record.payload());
    Ok(encoded)
}

pub(crate) fn decode_record(
    stream: StreamRef,
    sequence: u64,
    encoded: &[u8],
) -> Result<Record, FederationError> {
    if encoded.len() > 4 + 16 * 1024 + MAX_RECORD_PAYLOAD {
        return Err(FederationError::Corrupt);
    }
    let length = encoded
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .ok_or(FederationError::Corrupt)? as usize;
    if length > 16 * 1024 || encoded.len() < 4 + length {
        return Err(FederationError::Corrupt);
    }
    let header: StoredRecordHeader = serde_json::from_slice(&encoded[4..4 + length])
        .map_err(|_error| FederationError::Corrupt)?;
    let event_ref = header
        .event_ref
        .map(|event| {
            let origin =
                <[u8; 48]>::try_from(event.origin).map_err(|_error| FederationError::Corrupt)?;
            EventRef::new(
                FederationNodeId::from_bytes(origin),
                event.namespace,
                event.id,
            )
            .map_err(|_error| FederationError::Corrupt)
        })
        .transpose()?;
    let digest = <[u8; 48]>::try_from(header.digest).map_err(|_error| FederationError::Corrupt)?;
    Record::from_parts(
        RecordParts {
            stream,
            sequence,
            publish_id: RequestId::from_bytes(header.publish_id),
            event_type: EventType::new(header.event_type)
                .map_err(|_error| FederationError::Corrupt)?,
            schema_revision: SchemaRevision::from_bytes(header.schema_revision),
            event_ref,
            payload: Arc::from(&encoded[4 + length..]),
        },
        Digest::from_bytes(digest),
    )
    .map_err(|_error| FederationError::Corrupt)
}

fn stream_key(stream: StreamRef) -> [u8; KEY_BYTES] {
    let mut key = [0; KEY_BYTES];
    key[..FederationNodeId::LEN].copy_from_slice(stream.publisher.as_bytes());
    key[FederationNodeId::LEN..].copy_from_slice(stream.id.as_bytes());
    key
}

fn record_key(stream: StreamRef, sequence: u64) -> [u8; RECORD_KEY_BYTES] {
    let mut key = [0; RECORD_KEY_BYTES];
    key[..KEY_BYTES].copy_from_slice(&stream_key(stream));
    key[KEY_BYTES..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn decode_row(bytes: &[u8]) -> Result<FollowRow, FederationError> {
    if bytes.len() > 4096 {
        return Err(FederationError::Corrupt);
    }
    let row: FollowRow =
        serde_json::from_slice(bytes).map_err(|_error| FederationError::Corrupt)?;
    row.validate()?;
    Ok(row)
}

fn encode_row(row: &FollowRow) -> Result<Vec<u8>, FederationError> {
    row.validate()?;
    serde_json::to_vec(row).map_err(storage)
}

fn storage(error: impl ToString) -> FederationError {
    FederationError::Storage(error.to_string())
}

impl RedbPublicFollowerStore {
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

    /// Local node that owns this follower inbox.
    pub fn local_node(&self) -> FederationNodeId {
        self.local
    }

    /// Inspect one configured public stream's persisted local cursor.
    pub fn inspect(
        &self,
        stream: StreamRef,
    ) -> Result<Option<PublicFollowerView>, FederationError> {
        self.decision_peer(stream.publisher)?;
        if stream.publisher == self.local {
            return Err(FederationError::Invalid(
                "public follower cannot follow its own stream",
            ));
        }
        let txn = self.begin_read()?;
        let table = txn
            .open_table(FEDERATION_PUBLIC_FOLLOWERS_TABLE)
            .map_err(storage)?;
        table
            .get(stream_key(stream).as_slice())
            .map_err(storage)?
            .map(|saved| decode_row(saved.value())?.view(stream))
            .transpose()
    }

    /// Observe the exact current policy before reading. A revision change is
    /// persisted, but a retired publisher range that skips our cursor is not.
    pub fn observe(&self, view: &PublicStreamView) -> Result<PublicFollowerView, FederationError> {
        self.decision_peer(view.stream.publisher)?;
        if view.stream.publisher == self.local
            || view.policy_revision == 0
            || view.minimum_available == 0
        {
            return Err(FederationError::Invalid("invalid public follower view"));
        }
        self.with_write(|txn| {
            let mut table = txn
                .open_table(FEDERATION_PUBLIC_FOLLOWERS_TABLE)
                .map_err(storage)?;
            let key = stream_key(view.stream);
            let current = table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|saved| decode_row(saved.value()))
                .transpose()?;
            let exists = current.is_some();
            let mut row = current.unwrap_or(FollowRow {
                policy_revision: view.policy_revision,
                cursor: None,
                publisher_minimum_available: 1,
                local_minimum_available: 1,
                retained_records: 0,
                retained_bytes: 0,
            });
            if !exists && table.len().map_err(storage)? >= MAX_FOLLOWS {
                return Err(FederationError::Capacity);
            }
            if view.policy_revision < row.policy_revision
                || view.minimum_available < row.publisher_minimum_available
            {
                return Err(FederationError::Conflict);
            }
            let next = row
                .cursor
                .as_ref()
                .map(StoredPosition::position)
                .transpose()?
                .map_or(Some(1), |position| position.sequence().checked_add(1))
                .ok_or(FederationError::Capacity)?;
            if view.minimum_available > next {
                return Err(FederationError::ResyncRequired {
                    minimum_available: view.minimum_available,
                });
            }
            if row.cursor.is_some() && view.head.is_none()
                || view.head.is_some_and(|head| {
                    row.cursor
                        .as_ref()
                        .is_some_and(|cursor| head.sequence() < cursor.sequence)
                })
            {
                return Err(FederationError::Conflict);
            }
            if exists
                && row.policy_revision == view.policy_revision
                && row.publisher_minimum_available == view.minimum_available
            {
                return row.view(view.stream);
            }
            row.policy_revision = view.policy_revision;
            row.publisher_minimum_available = view.minimum_available;
            let result = row.view(view.stream)?;
            table
                .insert(key.as_slice(), encode_row(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    /// Commit one verified remote page and prune the oldest local records in
    /// the same transaction. `cursor` remains a digest anchor after pruning.
    pub fn accept_page(
        &self,
        stream: StreamRef,
        page: &PublicReadPage,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<PublicFollowerView, FederationError> {
        self.decision_peer(stream.publisher)?;
        if max_records == 0
            || max_records > MAX_PUBLIC_FOLLOW_INBOX_RECORDS
            || !(MAX_RECORD_PAYLOAD..=MAX_PUBLIC_FOLLOW_INBOX_BYTES).contains(&max_bytes)
            || page.records.len() > MAX_PUBLIC_READ_RECORDS
            || page.minimum_available == 0
        {
            return Err(FederationError::Capacity);
        }
        self.with_write(|txn| {
            let key = stream_key(stream);
            let mut follows = txn
                .open_table(FEDERATION_PUBLIC_FOLLOWERS_TABLE)
                .map_err(storage)?;
            let mut row = follows
                .get(key.as_slice())
                .map_err(storage)?
                .map(|saved| decode_row(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            if page.policy_revision != row.policy_revision
                || page.minimum_available < row.publisher_minimum_available
            {
                return Err(FederationError::Conflict);
            }
            let mut next = row
                .cursor
                .as_ref()
                .map(StoredPosition::position)
                .transpose()?
                .map_or(Some(1), |position| position.sequence().checked_add(1))
                .ok_or(FederationError::Capacity)?;
            if page.minimum_available > next {
                return Err(FederationError::ResyncRequired {
                    minimum_available: page.minimum_available,
                });
            }
            if row.cursor.is_some() && page.head.is_none()
                || page.head.is_some_and(|head| {
                    row.cursor
                        .as_ref()
                        .is_some_and(|cursor| head.sequence() < cursor.sequence)
                })
            {
                return Err(FederationError::Conflict);
            }
            if page.records.is_empty() && page.minimum_available == row.publisher_minimum_available
            {
                return row.view(stream);
            }
            let mut inbox = txn
                .open_table(FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE)
                .map_err(storage)?;
            let mut batch_bytes = 0usize;
            for record in &page.records {
                if record.stream() != stream || record.sequence() != next {
                    return Err(FederationError::Conflict);
                }
                batch_bytes = batch_bytes
                    .checked_add(record.payload().len())
                    .ok_or(FederationError::Capacity)?;
                if batch_bytes > MAX_PUBLIC_READ_BYTES {
                    return Err(FederationError::Capacity);
                }
                let encoded = encode_record(record)?;
                inbox
                    .insert(record_key(stream, next).as_slice(), encoded.as_slice())
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
                    row.cursor
                        .as_ref()
                        .is_some_and(|cursor| head.sequence() < cursor.sequence)
                })
            {
                return Err(FederationError::Conflict);
            }
            while row.retained_records > max_records || row.retained_bytes > max_bytes {
                let oldest = record_key(stream, row.local_minimum_available);
                let removed = inbox
                    .remove(oldest.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let record = decode_record(stream, row.local_minimum_available, removed.value())?;
                row.retained_records -= 1;
                row.retained_bytes -= record.payload().len();
                row.local_minimum_available += 1;
            }
            row.publisher_minimum_available = page.minimum_available;
            let result = row.view(stream)?;
            follows
                .insert(key.as_slice(), encode_row(&row)?.as_slice())
                .map_err(storage)?;
            drop(inbox);
            drop(follows);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    /// Read a bounded page of locally retained public records. A pruned
    /// cursor reports a history gap rather than implying old bytes remain.
    pub fn read_inbox(
        &self,
        stream: StreamRef,
        after: Option<Position>,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<PublicFollowerInboxPage, FederationError> {
        self.decision_peer(stream.publisher)?;
        if max_records == 0
            || max_records > MAX_PUBLIC_READ_RECORDS
            || max_bytes == 0
            || max_bytes > MAX_PUBLIC_READ_BYTES
        {
            return Err(FederationError::Capacity);
        }
        let txn = self.begin_read()?;
        let follows = txn
            .open_table(FEDERATION_PUBLIC_FOLLOWERS_TABLE)
            .map_err(storage)?;
        let row = follows
            .get(stream_key(stream).as_slice())
            .map_err(storage)?
            .map(|saved| decode_row(saved.value()))
            .transpose()?
            .ok_or(FederationError::NotFound)?;
        let first = if let Some(after) = after {
            if after.sequence() < row.local_minimum_available {
                return Err(FederationError::ResyncRequired {
                    minimum_available: row.local_minimum_available,
                });
            }
            let inbox = txn
                .open_table(FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE)
                .map_err(storage)?;
            let saved = inbox
                .get(record_key(stream, after.sequence()).as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Conflict)?;
            if decode_record(stream, after.sequence(), saved.value())?.position() != after {
                return Err(FederationError::Conflict);
            }
            after
                .sequence()
                .checked_add(1)
                .ok_or(FederationError::Capacity)?
        } else {
            row.local_minimum_available
        };
        let inbox = txn
            .open_table(FEDERATION_PUBLIC_FOLLOWER_INBOX_TABLE)
            .map_err(storage)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let last = row
            .cursor
            .as_ref()
            .map(StoredPosition::position)
            .transpose()?
            .map_or(0, |position| position.sequence());
        for sequence in first..=last {
            if records.len() == max_records {
                break;
            }
            let saved = inbox
                .get(record_key(stream, sequence).as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Corrupt)?;
            let record = decode_record(stream, sequence, saved.value())?;
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
        Ok(PublicFollowerInboxPage {
            view: row.view(stream)?,
            records,
        })
    }
}
