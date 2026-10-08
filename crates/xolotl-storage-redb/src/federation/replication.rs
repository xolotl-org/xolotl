//! Explicit publisher-side replica commitments and bounded history retirement.

use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    Digest, ExportName, FederationError, FederationNodeId, FederationReplicaRetentionStore,
    FederationSubject, MAX_REPLICA_LEASE_MS, MAX_REPLICA_MEMBERS, MAX_RETIRE_BYTES,
    MAX_RETIRE_RECORDS, Position, PublishedRetirement, ReplicaMemberSpec, ReplicaMemberView,
    ReplicaRetentionTerm, StreamRef, SubscriptionRef,
};

use super::{
    FEDERATION_RECORDS_TABLE, FEDERATION_REPLICA_MEMBERS_TABLE, FEDERATION_STREAMS_TABLE,
    FEDERATION_SUBSCRIPTIONS_TABLE, NODE_ID_LEN, RecordHeader, RedbFederationStore, STREAM_KEY_LEN,
    StoredSubscriptionRef, StreamRow, SubscriptionRow, authority_in_write, decode, decode_record,
    encode, object, record_key, snapshot, storage, stored_record_payload_bytes, stream_key,
    subscription_key,
};

const MEMBER_KEY_LEN: usize = STREAM_KEY_LEN + NODE_ID_LEN;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum StoredTerm {
    Permanent,
    LeaseUntilMs(u64),
}

impl From<ReplicaRetentionTerm> for StoredTerm {
    fn from(term: ReplicaRetentionTerm) -> Self {
        match term {
            ReplicaRetentionTerm::Permanent => Self::Permanent,
            ReplicaRetentionTerm::LeaseUntilMs(deadline) => Self::LeaseUntilMs(deadline),
        }
    }
}

impl From<StoredTerm> for ReplicaRetentionTerm {
    fn from(term: StoredTerm) -> Self {
        match term {
            StoredTerm::Permanent => Self::Permanent,
            StoredTerm::LeaseUntilMs(deadline) => Self::LeaseUntilMs(deadline),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberRow {
    revision: u64,
    subscription: StoredSubscriptionRef,
    term: StoredTerm,
    retired: bool,
}

impl MemberRow {
    fn validate(&self) -> Result<(), FederationError> {
        if self.revision == 0 || matches!(self.term, StoredTerm::LeaseUntilMs(0)) {
            return Err(FederationError::Corrupt);
        }
        Ok(())
    }
}

fn member_key(stream: StreamRef, member: FederationNodeId) -> [u8; MEMBER_KEY_LEN] {
    let mut key = [0; MEMBER_KEY_LEN];
    key[..STREAM_KEY_LEN].copy_from_slice(&stream_key(stream));
    key[STREAM_KEY_LEN..].copy_from_slice(member.as_bytes());
    key
}

fn parse_member_key(stream: StreamRef, key: &[u8]) -> Result<FederationNodeId, FederationError> {
    let key = <[u8; MEMBER_KEY_LEN]>::try_from(key).map_err(|_error| FederationError::Corrupt)?;
    if key[..STREAM_KEY_LEN] != stream_key(stream) {
        return Err(FederationError::Corrupt);
    }
    Ok(FederationNodeId::from_bytes(
        key[STREAM_KEY_LEN..]
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ))
}

fn validate_term(term: ReplicaRetentionTerm, now_ms: u64) -> Result<(), FederationError> {
    if let ReplicaRetentionTerm::LeaseUntilMs(deadline) = term {
        let remaining = deadline
            .checked_sub(now_ms)
            .ok_or(FederationError::Conflict)?;
        if remaining == 0 || remaining > MAX_REPLICA_LEASE_MS {
            return Err(FederationError::Invalid("invalid replica lease deadline"));
        }
    }
    Ok(())
}

fn load_member_write(
    txn: &WriteTransaction,
    stream: StreamRef,
    member: FederationNodeId,
) -> Result<Option<MemberRow>, FederationError> {
    let key = member_key(stream, member);
    txn.open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()
}

fn load_member_read(
    txn: &ReadTransaction,
    stream: StreamRef,
    member: FederationNodeId,
) -> Result<Option<MemberRow>, FederationError> {
    let key = member_key(stream, member);
    txn.open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()
}

fn save_member(
    txn: &WriteTransaction,
    stream: StreamRef,
    member: FederationNodeId,
    row: &MemberRow,
) -> Result<(), FederationError> {
    let key = member_key(stream, member);
    txn.open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
        .map_err(storage)?
        .insert(key.as_slice(), encode(row)?.as_slice())
        .map_err(storage)?;
    Ok(())
}

fn stream_row(txn: &WriteTransaction, stream: StreamRef) -> Result<StreamRow, FederationError> {
    let row: StreamRow = txn
        .open_table(FEDERATION_STREAMS_TABLE)
        .map_err(storage)?
        .get(stream_key(stream).as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    row.validate()?;
    Ok(row)
}

fn stored_position(sequence: u64, bytes: &[u8]) -> Result<Position, FederationError> {
    stored_record_payload_bytes(bytes)?;
    let header_len = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    let header_end = 4usize
        .checked_add(header_len)
        .ok_or(FederationError::Corrupt)?;
    let header: RecordHeader = decode(bytes.get(4..header_end).ok_or(FederationError::Corrupt)?)?;
    Position::new(sequence, Digest::from_bytes(header.digest))
        .map_err(|_error| FederationError::Corrupt)
}

fn receipt(
    row: SubscriptionRow,
    stream: StreamRef,
    member: FederationNodeId,
    subscription: SubscriptionRef,
    require_live: bool,
) -> Result<
    (
        Option<Position>,
        Option<Position>,
        ExportName,
        xolotl_federation::AuthorityRevision,
    ),
    FederationError,
> {
    let SubscriptionRow::Publisher {
        request,
        opened,
        subject,
        guest,
        acknowledged,
        closed_revision,
    } = row
    else {
        return Err(FederationError::Corrupt);
    };
    let opened = xolotl_federation::OpenResult::try_from(opened)?;
    let request = xolotl_federation::OpenRequest::try_from(*request)?;
    if opened.subscription != subscription
        || opened.stream != stream
        || request.subscription != subscription
        || request.stream != stream
        || request.authenticated_subscriber != member
        || subscription.subscriber != member
        || guest
        || subject.as_ref().is_some_and(|subject| {
            FederationSubject::from(subject.clone()) != FederationSubject::Node(member)
        })
    {
        return Err(FederationError::Corrupt);
    }
    if require_live && closed_revision.is_some() {
        return Err(FederationError::Conflict);
    }
    let baseline = opened.start;
    let acknowledged = acknowledged.map(Position::try_from).transpose()?;
    if acknowledged
        .is_some_and(|ack| baseline.is_some_and(|start| ack.sequence() <= start.sequence()))
    {
        return Err(FederationError::Corrupt);
    }
    Ok((
        baseline,
        acknowledged,
        opened.export,
        opened.publisher_authority,
    ))
}

fn subscription_receipt_write(
    txn: &WriteTransaction,
    stream: StreamRef,
    member: FederationNodeId,
    subscription: SubscriptionRef,
    require_live: bool,
) -> Result<
    (
        Option<Position>,
        Option<Position>,
        ExportName,
        xolotl_federation::AuthorityRevision,
    ),
    FederationError,
> {
    let key = subscription_key(subscription);
    let row = txn
        .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::Corrupt)?;
    receipt(row, stream, member, subscription, require_live)
}

fn subscription_receipt_read(
    txn: &ReadTransaction,
    stream: StreamRef,
    member: FederationNodeId,
    subscription: SubscriptionRef,
) -> Result<
    (
        Option<Position>,
        Option<Position>,
        ExportName,
        xolotl_federation::AuthorityRevision,
    ),
    FederationError,
> {
    let key = subscription_key(subscription);
    let row = txn
        .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::Corrupt)?;
    receipt(row, stream, member, subscription, false)
}

fn view_write(
    txn: &WriteTransaction,
    stream: StreamRef,
    member: FederationNodeId,
    row: &MemberRow,
) -> Result<ReplicaMemberView, FederationError> {
    row.validate()?;
    let subscription = row.subscription.into();
    let (baseline, acknowledged, _, _) =
        subscription_receipt_write(txn, stream, member, subscription, false)?;
    let snapshot_covered = snapshot::publisher_snapshot_coverage_write(txn, subscription)?;
    Ok(ReplicaMemberView {
        spec: ReplicaMemberSpec {
            stream,
            member,
            subscription,
            term: row.term.into(),
        },
        revision: row.revision,
        baseline,
        acknowledged,
        snapshot_covered,
        retired: row.retired,
    })
}

fn view_read(
    txn: &ReadTransaction,
    stream: StreamRef,
    member: FederationNodeId,
    row: &MemberRow,
) -> Result<ReplicaMemberView, FederationError> {
    row.validate()?;
    let subscription = row.subscription.into();
    let (baseline, acknowledged, _, _) =
        subscription_receipt_read(txn, stream, member, subscription)?;
    let snapshot_covered = snapshot::publisher_snapshot_coverage_read(txn, subscription)?;
    Ok(ReplicaMemberView {
        spec: ReplicaMemberSpec {
            stream,
            member,
            subscription,
            term: row.term.into(),
        },
        revision: row.revision,
        baseline,
        acknowledged,
        snapshot_covered,
        retired: row.retired,
    })
}

fn highest_confirmed(
    baseline: Option<Position>,
    acknowledged: Option<Position>,
    snapshot_covered: Option<Position>,
) -> Result<Option<Position>, FederationError> {
    let mut highest = baseline;
    for candidate in [acknowledged, snapshot_covered].into_iter().flatten() {
        if let Some(old) = highest
            && old.sequence() == candidate.sequence()
            && old.digest() != candidate.digest()
        {
            return Err(FederationError::Corrupt);
        }
        if highest.is_none_or(|old| candidate.sequence() > old.sequence()) {
            highest = Some(candidate);
        }
    }
    Ok(highest)
}

fn active_frontier(
    txn: &WriteTransaction,
    stream: StreamRef,
) -> Result<Option<Option<Position>>, FederationError> {
    let prefix = stream_key(stream);
    let table = txn
        .open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
        .map_err(storage)?;
    let mut lowest: Option<Option<Position>> = None;
    let mut count = 0;
    for entry in table.range(prefix.as_slice()..).map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        count += 1;
        if count > MAX_REPLICA_MEMBERS {
            return Err(FederationError::Corrupt);
        }
        let member = parse_member_key(stream, key.value())?;
        let row: MemberRow = decode(value.value())?;
        row.validate()?;
        if row.retired {
            continue;
        }
        let view = view_write(txn, stream, member, &row)?;
        let frontier = highest_confirmed(view.baseline, view.acknowledged, view.snapshot_covered)?;
        lowest = Some(match (lowest, frontier) {
            (None, frontier) => frontier,
            (Some(None), _) | (_, None) => None,
            (Some(Some(old)), Some(current)) if old.sequence() <= current.sequence() => Some(old),
            (Some(Some(_)), Some(current)) => Some(current),
        });
    }
    Ok(lowest)
}

fn permitted_through(
    txn: &WriteTransaction,
    stream: StreamRef,
    through: Position,
) -> Result<(), FederationError> {
    if let Some(frontier) = active_frontier(txn, stream)? {
        let Some(frontier) = frontier else {
            return Err(FederationError::Conflict);
        };
        if through.sequence() > frontier.sequence()
            || (through.sequence() == frontier.sequence() && through.digest() != frontier.digest())
        {
            return Err(FederationError::Conflict);
        }
    }
    if snapshot::earliest_publisher_offer_pin(txn, stream)?
        .is_some_and(|pin| through.sequence() > pin.sequence())
    {
        return Err(FederationError::Conflict);
    }
    Ok(())
}

fn retire_core(
    txn: &WriteTransaction,
    local: FederationNodeId,
    stream: StreamRef,
    through: Position,
    max_records: usize,
) -> Result<PublishedRetirement, FederationError> {
    if stream.publisher != local {
        return Err(FederationError::Unauthorized);
    }
    if max_records == 0 || max_records > MAX_RETIRE_RECORDS {
        return Err(FederationError::Capacity);
    }
    let mut row = stream_row(txn, stream)?;
    let head = row.head.map(Position::try_from).transpose()?;
    let retired = row.retired_through.map(Position::try_from).transpose()?;
    if retired == Some(through) {
        return Ok(PublishedRetirement {
            stream,
            head,
            minimum_available: row.minimum_available,
            retired_through: retired,
            removed: 0,
        });
    }
    if through.sequence() < row.minimum_available
        || head.is_none_or(|head| through.sequence() > head.sequence())
    {
        return Err(FederationError::Conflict);
    }
    permitted_through(txn, stream, through)?;
    let count = through
        .sequence()
        .checked_sub(row.minimum_available)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(FederationError::Capacity)?;
    if count > max_records {
        return Err(FederationError::Capacity);
    }
    let mut keys = Vec::with_capacity(count);
    let mut bytes = 0usize;
    let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
    for sequence in row.minimum_available..=through.sequence() {
        let key = record_key(stream, sequence);
        let saved = table
            .get(key.as_slice())
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?;
        bytes = bytes
            .checked_add(stored_record_payload_bytes(saved.value())?)
            .ok_or(FederationError::Capacity)?;
        if bytes > MAX_RETIRE_BYTES {
            return Err(FederationError::Capacity);
        }
        if sequence == through.sequence() {
            let record = decode_record(stream, sequence, saved.value())?;
            if record.digest() != through.digest() {
                return Err(FederationError::Conflict);
            }
        }
        keys.push(key);
    }
    drop(table);
    let mut table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
    for key in &keys {
        table
            .remove(key.as_slice())
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?;
    }
    drop(table);
    row.minimum_available = through
        .sequence()
        .checked_add(1)
        .ok_or(FederationError::Capacity)?;
    row.retired_through = Some(through.into());
    txn.open_table(FEDERATION_STREAMS_TABLE)
        .map_err(storage)?
        .insert(stream_key(stream).as_slice(), encode(&row)?.as_slice())
        .map_err(storage)?;
    Ok(PublishedRetirement {
        stream,
        head,
        minimum_available: row.minimum_available,
        retired_through: Some(through),
        removed: count,
    })
}

pub(super) fn retire_in_transaction(
    txn: &mut super::DecisionWrite,
    local: FederationNodeId,
    stream: StreamRef,
    through: Position,
    max_records: usize,
) -> Result<PublishedRetirement, FederationError> {
    let result = retire_core(txn, local, stream, through, max_records)?;
    txn.commit()
        .map_err(|_error| FederationError::Indeterminate)?;
    Ok(result)
}

fn expire_leases(
    txn: &WriteTransaction,
    stream: StreamRef,
    now_ms: u64,
) -> Result<(), FederationError> {
    let prefix = stream_key(stream);
    let table = txn
        .open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
        .map_err(storage)?;
    let mut expired = Vec::new();
    let mut count = 0;
    for entry in table.range(prefix.as_slice()..).map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        count += 1;
        if count > MAX_REPLICA_MEMBERS {
            return Err(FederationError::Corrupt);
        }
        let member = parse_member_key(stream, key.value())?;
        let mut row: MemberRow = decode(value.value())?;
        row.validate()?;
        if !row.retired
            && matches!(row.term, StoredTerm::LeaseUntilMs(deadline) if now_ms >= deadline)
        {
            row.retired = true;
            row.revision = row
                .revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            expired.push((member, row));
        }
    }
    drop(table);
    for (member, row) in expired {
        save_member(txn, stream, member, &row)?;
    }
    Ok(())
}

impl FederationReplicaRetentionStore for RedbFederationStore {
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn join_replica(
        &self,
        spec: ReplicaMemberSpec,
        expected_revision: Option<u64>,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError> {
        if spec.stream.publisher != self.node
            || spec.member == self.node
            || spec.subscription.subscriber != spec.member
        {
            return Err(FederationError::Unauthorized);
        }
        validate_term(spec.term, now_ms)?;
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            object::checked_object_time(txn, now_ms)?;
            let stream = stream_row(txn, spec.stream)?;
            let old = load_member_write(txn, spec.stream, spec.member)?;
            if let Some(old) = &old {
                old.validate()?;
            }
            let revision = match (old.as_ref(), expected_revision) {
                (None, None) => 1,
                (Some(old), Some(expected))
                    if old.retired
                        && old.revision == expected
                        && SubscriptionRef::from(old.subscription) != spec.subscription =>
                {
                    old.revision
                        .checked_add(1)
                        .ok_or(FederationError::Capacity)?
                }
                _ => return Err(FederationError::Conflict),
            };
            if old.is_none() {
                let prefix = stream_key(spec.stream);
                let table = txn
                    .open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
                    .map_err(storage)?;
                let mut count = 0;
                for entry in table.range(prefix.as_slice()..).map_err(storage)? {
                    let (key, _) = entry.map_err(storage)?;
                    if !key.value().starts_with(&prefix) {
                        break;
                    }
                    count += 1;
                    if count >= MAX_REPLICA_MEMBERS {
                        return Err(FederationError::Capacity);
                    }
                }
            }
            let (baseline, acknowledged, export, authority) =
                subscription_receipt_write(txn, spec.stream, spec.member, spec.subscription, true)?;
            let snapshot_covered =
                snapshot::publisher_snapshot_coverage_write(txn, spec.subscription)?;
            let confirmed = highest_confirmed(baseline, acknowledged, snapshot_covered)?;
            if confirmed.map_or(0, |position| position.sequence())
                < stream.minimum_available.saturating_sub(1)
            {
                return Err(FederationError::ResyncRequired {
                    minimum_available: stream.minimum_available,
                });
            }
            if let Some(frontier) = confirmed
                && stream.retired_through.is_some_and(|anchor| {
                    frontier.sequence() == anchor.sequence
                        && frontier.digest().as_bytes() != &anchor.digest
                })
            {
                return Err(FederationError::Conflict);
            }
            if authority_in_write(txn, spec.member, &export, true)? != authority {
                return Err(FederationError::Conflict);
            }
            let row = MemberRow {
                revision,
                subscription: spec.subscription.into(),
                term: spec.term.into(),
                retired: false,
            };
            save_member(txn, spec.stream, spec.member, &row)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(ReplicaMemberView {
                spec,
                revision,
                baseline,
                acknowledged,
                snapshot_covered,
                retired: false,
            })
        })
    }

    fn extend_replica(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
        expected_revision: u64,
        term: ReplicaRetentionTerm,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        validate_term(term, now_ms)?;
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            object::checked_object_time(txn, now_ms)?;
            let mut row =
                load_member_write(txn, stream, member)?.ok_or(FederationError::NotFound)?;
            row.validate()?;
            if row.retired || row.revision != expected_revision {
                return Err(FederationError::Conflict);
            }
            match (row.term, term) {
                (StoredTerm::Permanent, ReplicaRetentionTerm::Permanent) => {}
                (StoredTerm::Permanent, _) => return Err(FederationError::Conflict),
                (StoredTerm::LeaseUntilMs(old), _) if now_ms >= old => {
                    return Err(FederationError::Conflict);
                }
                (StoredTerm::LeaseUntilMs(old), ReplicaRetentionTerm::LeaseUntilMs(next))
                    if next <= old =>
                {
                    return Err(FederationError::Conflict);
                }
                _ => {}
            }
            row.term = term.into();
            row.revision = row
                .revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            let view = view_write(txn, stream, member, &row)?;
            save_member(txn, stream, member, &row)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(view)
        })
    }

    fn retire_replica(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
        expected_revision: u64,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            object::checked_object_time(txn, now_ms)?;
            let mut row =
                load_member_write(txn, stream, member)?.ok_or(FederationError::NotFound)?;
            row.validate()?;
            if row.retired || row.revision != expected_revision {
                return Err(FederationError::Conflict);
            }
            row.retired = true;
            row.revision = row
                .revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            let view = view_write(txn, stream, member, &row)?;
            save_member(txn, stream, member, &row)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(view)
        })
    }

    fn replica_member(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
    ) -> Result<Option<ReplicaMemberView>, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        load_member_read(&txn, stream, member)?
            .as_ref()
            .map(|row| view_read(&txn, stream, member, row))
            .transpose()
    }

    fn scan_replica_members(
        &self,
        stream: StreamRef,
        after: Option<FederationNodeId>,
        max: usize,
    ) -> Result<Vec<ReplicaMemberView>, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        if max == 0 || max > MAX_REPLICA_MEMBERS {
            return Err(FederationError::Capacity);
        }
        let (txn, _) = self.begin_decision_read()?;
        let prefix = stream_key(stream);
        let start = after.map_or_else(
            || prefix.to_vec(),
            |member| member_key(stream, member).to_vec(),
        );
        let table = txn
            .open_table(FEDERATION_REPLICA_MEMBERS_TABLE)
            .map_err(storage)?;
        let mut views = Vec::with_capacity(max);
        for entry in table.range(start.as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            if !key.value().starts_with(&prefix) {
                break;
            }
            let member = parse_member_key(stream, key.value())?;
            if after == Some(member) {
                continue;
            }
            let row: MemberRow = decode(value.value())?;
            views.push(view_read(&txn, stream, member, &row)?);
            if views.len() == max {
                break;
            }
        }
        Ok(views)
    }

    fn retire_replica_safe_history(
        &self,
        stream: StreamRef,
        now_ms: u64,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        if max_records == 0 || max_records > MAX_RETIRE_RECORDS {
            return Err(FederationError::Capacity);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            object::checked_object_time(txn, now_ms)?;
            let row = stream_row(txn, stream)?;
            expire_leases(txn, stream, now_ms)?;
            let frontier = active_frontier(txn, stream)?;
            let pin = snapshot::earliest_publisher_offer_pin(txn, stream)?;
            let head = row.head.map(Position::try_from).transpose()?;
            let retired = row.retired_through.map(Position::try_from).transpose()?;
            let mut end = head.map_or(0, |head| head.sequence());
            if let Some(frontier) = frontier {
                end = end.min(frontier.map_or(0, |position| position.sequence()));
            }
            if let Some(pin) = pin {
                end = end.min(pin.sequence());
            }
            end = end.min(row.minimum_available.saturating_add(max_records as u64 - 1));
            let mut last = None;
            let mut bytes = 0usize;
            if end >= row.minimum_available {
                let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                for sequence in row.minimum_available..=end {
                    let key = record_key(stream, sequence);
                    let saved = table
                        .get(key.as_slice())
                        .map_err(storage)?
                        .ok_or(FederationError::Corrupt)?;
                    let next = bytes
                        .checked_add(stored_record_payload_bytes(saved.value())?)
                        .ok_or(FederationError::Capacity)?;
                    if next > MAX_RETIRE_BYTES {
                        break;
                    }
                    bytes = next;
                    last = Some(stored_position(sequence, saved.value())?);
                }
            }
            let result = if let Some(last) = last {
                retire_core(txn, self.node, stream, last, max_records)?
            } else {
                PublishedRetirement {
                    stream,
                    head,
                    minimum_available: row.minimum_available,
                    retired_through: retired,
                    removed: 0,
                }
            };
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }
}
