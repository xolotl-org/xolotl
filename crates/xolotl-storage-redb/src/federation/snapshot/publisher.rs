//! Publisher-owned offer metadata; immutable bytes remain in the application.

use std::sync::Arc;

use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    Digest, FederationError, FederationNodeId, FederationSnapshotPublisherStore, FederationSubject,
    MAX_SNAPSHOT_CHUNK_BYTES, OpenResult, Position, SnapshotContentSource, SnapshotManifest,
    SnapshotOffer, SnapshotOfferRequest, SnapshotReadChunk, SnapshotReadRequest, SnapshotReceived,
    SnapshotReceivedRequest, SnapshotSuffixCoverage, StreamRef, SubscriptionRef,
};

use super::StoredManifest;
use crate::federation::{
    FEDERATION_RECORDS_TABLE, FEDERATION_SNAPSHOT_OFFER_PINS_TABLE,
    FEDERATION_SNAPSHOT_OFFERS_TABLE, FEDERATION_SNAPSHOT_RECEIPTS_TABLE, FEDERATION_STREAMS_TABLE,
    FEDERATION_SUBSCRIPTIONS_TABLE, RedbFederationStore, STREAM_KEY_LEN, StoredPosition, StreamRow,
    SubscriptionRow, authority_in_read, authority_in_write, decode, decode_record, encode,
    fixed_bytes_48, publisher_subject_matches, record_key, storage, stream_key, subscription_key,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOffer {
    manifest: StoredManifest,
    #[serde(with = "fixed_bytes_48")]
    publication_digest: [u8; 48],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceived {
    #[serde(with = "fixed_bytes_48")]
    manifest_digest: [u8; 48],
    #[serde(with = "fixed_bytes_48")]
    publication_digest: [u8; 48],
    position: StoredPosition,
    install_id: [u8; 16],
    #[serde(with = "fixed_bytes_48")]
    archive_digest: [u8; 48],
    federation_generation: u64,
    suffix: Option<StoredSuffix>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSuffix {
    after: StoredPosition,
    through: StoredPosition,
}

impl StoredReceived {
    fn view(&self, subscription: SubscriptionRef) -> Result<SnapshotReceived, FederationError> {
        if self.manifest_digest == [0; 48]
            || self.publication_digest == [0; 48]
            || self.install_id == [0; 16]
            || self.archive_digest == [0; 48]
            || self.federation_generation == 0
        {
            return Err(FederationError::Corrupt);
        }
        let suffix = self
            .suffix
            .as_ref()
            .map(|suffix| {
                Ok::<_, FederationError>(SnapshotSuffixCoverage {
                    after: suffix.after.try_into()?,
                    through: suffix.through.try_into()?,
                })
            })
            .transpose()?;
        let position: Position = self.position.try_into()?;
        if suffix.is_some_and(|suffix| {
            suffix.after.sequence() < position.sequence()
                || suffix.after.sequence() == position.sequence() && suffix.after != position
                || suffix.through.sequence() <= suffix.after.sequence()
        }) {
            return Err(FederationError::Corrupt);
        }
        Ok(SnapshotReceived {
            subscription,
            manifest_digest: Digest::from_bytes(self.manifest_digest),
            publication_digest: Digest::from_bytes(self.publication_digest),
            position,
            install_id: xolotl_federation::SnapshotId::from_bytes(self.install_id),
            archive_digest: Digest::from_bytes(self.archive_digest),
            federation_generation: self.federation_generation,
            suffix,
        })
    }
}

impl From<SnapshotReceived> for StoredReceived {
    fn from(value: SnapshotReceived) -> Self {
        Self {
            manifest_digest: *value.manifest_digest.as_bytes(),
            publication_digest: *value.publication_digest.as_bytes(),
            position: value.position.into(),
            install_id: *value.install_id.as_bytes(),
            archive_digest: *value.archive_digest.as_bytes(),
            federation_generation: value.federation_generation,
            suffix: value.suffix.map(|suffix| StoredSuffix {
                after: suffix.after.into(),
                through: suffix.through.into(),
            }),
        }
    }
}

fn load_received_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<SnapshotReceived>, FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_RECEIPTS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StoredReceived>(saved.value())?.view(subscription))
        .transpose()
}

pub(super) fn snapshot_coverage_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<Position>, FederationError> {
    load_received_write(txn, subscription).map(|received| received.map(coverage))
}

fn coverage(received: SnapshotReceived) -> Position {
    received
        .suffix
        .map_or(received.position, |suffix| suffix.through)
}

fn same_archive(previous: SnapshotReceived, received: SnapshotReceived) -> bool {
    previous.subscription == received.subscription
        && previous.manifest_digest == received.manifest_digest
        && previous.publication_digest == received.publication_digest
        && previous.position == received.position
        && previous.install_id == received.install_id
        && previous.archive_digest == received.archive_digest
        && previous.federation_generation == received.federation_generation
}

pub(super) fn snapshot_coverage_read(
    txn: &ReadTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<Position>, FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_RECEIPTS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StoredReceived>(saved.value())?.view(subscription))
        .transpose()
        .map(|received| received.map(coverage))
}

pub(super) fn check_event_ack_against_offer(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
    position: Position,
) -> Result<(), FederationError> {
    let Some(offer) = load_offer_write(txn, subscription)? else {
        return Ok(());
    };
    if position.sequence() < offer.manifest.position.sequence() {
        return Ok(());
    }
    let covered = snapshot_coverage_write(txn, subscription)?;
    if covered.is_none_or(|covered| covered.sequence() < offer.manifest.position.sequence()) {
        return Err(FederationError::Conflict);
    }
    Ok(())
}

const PIN_KEY_LEN: usize = STREAM_KEY_LEN + 8 + STREAM_KEY_LEN;

fn pin_key(
    stream: StreamRef,
    position: Position,
    subscription: SubscriptionRef,
) -> [u8; PIN_KEY_LEN] {
    let mut key = [0; PIN_KEY_LEN];
    key[..STREAM_KEY_LEN].copy_from_slice(&stream_key(stream));
    key[STREAM_KEY_LEN..STREAM_KEY_LEN + 8].copy_from_slice(&position.sequence().to_be_bytes());
    key[STREAM_KEY_LEN + 8..].copy_from_slice(&subscription_key(subscription));
    key
}

/// The first ordered key supplies the lowest offered B for this stream.
pub(super) fn earliest_publisher_offer_pin(
    txn: &WriteTransaction,
    stream: StreamRef,
) -> Result<Option<Position>, FederationError> {
    let prefix = stream_key(stream);
    let table = txn
        .open_table(FEDERATION_SNAPSHOT_OFFER_PINS_TABLE)
        .map_err(storage)?;
    let mut rows = table.range(prefix.as_slice()..).map_err(storage)?;
    let Some(entry) = rows.next() else {
        return Ok(None);
    };
    let (key, digest) = entry.map_err(storage)?;
    if !key.value().starts_with(&prefix) {
        return Ok(None);
    }
    let key =
        <[u8; PIN_KEY_LEN]>::try_from(key.value()).map_err(|_error| FederationError::Corrupt)?;
    let sequence = u64::from_be_bytes(
        key[STREAM_KEY_LEN..STREAM_KEY_LEN + 8]
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let digest = Digest::from_bytes(
        digest
            .value()
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    Position::new(sequence, digest)
        .map(Some)
        .map_err(|_error| FederationError::Corrupt)
}

impl StoredOffer {
    fn view(&self) -> Result<SnapshotOffer, FederationError> {
        Ok(SnapshotOffer {
            manifest: self.manifest.clone().try_into()?,
            publication_digest: Digest::from_bytes(self.publication_digest),
        })
    }
}

impl From<&SnapshotOffer> for StoredOffer {
    fn from(value: &SnapshotOffer) -> Self {
        Self {
            manifest: (&value.manifest).into(),
            publication_digest: *value.publication_digest.as_bytes(),
        }
    }
}

fn publisher_open(
    row: SubscriptionRow,
    subscriber: FederationNodeId,
    subscription: SubscriptionRef,
    node: FederationNodeId,
) -> Result<(OpenResult, Option<Position>), FederationError> {
    let SubscriptionRow::Publisher {
        opened,
        subject,
        guest: false,
        acknowledged,
        closed_revision: None,
        ..
    } = row
    else {
        return Err(FederationError::Conflict);
    };
    if !publisher_subject_matches(
        subject.as_ref(),
        subscriber,
        &FederationSubject::Node(subscriber),
    ) {
        return Err(FederationError::Unauthorized);
    }
    let opened = OpenResult::try_from(opened)?;
    if opened.subscription != subscription || opened.stream.publisher != node {
        return Err(FederationError::Corrupt);
    }
    // The first snapshot contract has no application proof of a filtered
    // post-grant view. It must never disclose a full-state snapshot for one.
    if opened.start.is_some() {
        return Err(FederationError::Conflict);
    }
    Ok((opened, acknowledged.map(Position::try_from).transpose()?))
}

fn load_open_read(
    txn: &ReadTransaction,
    subscriber: FederationNodeId,
    subscription: SubscriptionRef,
    node: FederationNodeId,
) -> Result<OpenResult, FederationError> {
    let key = subscription_key(subscription);
    let row = txn
        .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    let (opened, _) = publisher_open(row, subscriber, subscription, node)?;
    if authority_in_read(txn, subscriber, &opened.export, true)? != opened.publisher_authority {
        return Err(FederationError::Conflict);
    }
    Ok(opened)
}

fn load_open_write(
    txn: &WriteTransaction,
    subscriber: FederationNodeId,
    subscription: SubscriptionRef,
    node: FederationNodeId,
) -> Result<(OpenResult, Option<Position>), FederationError> {
    let key = subscription_key(subscription);
    let row = txn
        .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    let (opened, acknowledged) = publisher_open(row, subscriber, subscription, node)?;
    if authority_in_write(txn, subscriber, &opened.export, true)? != opened.publisher_authority {
        return Err(FederationError::Conflict);
    }
    Ok((opened, acknowledged))
}

fn load_offer_read(
    txn: &ReadTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<SnapshotOffer>, FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_OFFERS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StoredOffer>(saved.value())?.view())
        .transpose()
}

fn load_offer_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<SnapshotOffer>, FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_OFFERS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StoredOffer>(saved.value())?.view())
        .transpose()
}

fn offer_matches_open(offer: &SnapshotOffer, opened: &OpenResult) -> bool {
    offer.manifest.subscription == opened.subscription
        && offer.manifest.stream == opened.stream
        && offer.manifest.subscription_revision == opened.subscription_revision
        && offer.manifest.publisher_authority == opened.publisher_authority
        && offer.publication_digest.as_bytes() != &[0; 48]
}

fn current_offer(
    txn: &ReadTransaction,
    subscriber: FederationNodeId,
    subscription: SubscriptionRef,
    node: FederationNodeId,
) -> Result<Option<SnapshotOffer>, FederationError> {
    let opened = load_open_read(txn, subscriber, subscription, node)?;
    let offer = load_offer_read(txn, subscription)?;
    if offer
        .as_ref()
        .is_some_and(|offer| !offer_matches_open(offer, &opened))
    {
        return Err(FederationError::Corrupt);
    }
    Ok(offer)
}

fn verify_publication_position(
    txn: &WriteTransaction,
    opened: &OpenResult,
    position: Position,
) -> Result<(), FederationError> {
    let stream: StreamRow = txn
        .open_table(FEDERATION_STREAMS_TABLE)
        .map_err(storage)?
        .get(stream_key(opened.stream).as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::Corrupt)?;
    stream.validate()?;
    if stream.export != opened.export.as_str() {
        return Err(FederationError::Corrupt);
    }
    let head = stream.head.map(Position::try_from).transpose()?;
    if head.is_none_or(|head| position.sequence() > head.sequence()) {
        return Err(FederationError::Conflict);
    }
    if stream.verify_retired_cursor(position)? {
        return Ok(());
    }
    let key = record_key(opened.stream, position.sequence());
    let record = txn
        .open_table(FEDERATION_RECORDS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode_record(opened.stream, position.sequence(), saved.value()))
        .transpose()?
        .ok_or(FederationError::Conflict)?;
    if record.position() != position {
        return Err(FederationError::Conflict);
    }
    Ok(())
}

impl FederationSnapshotPublisherStore for RedbFederationStore {
    fn authorize_snapshot_receipt_delivery(
        &self,
        peer: FederationNodeId,
        received: SnapshotReceived,
    ) -> Result<(), FederationError> {
        self.decision_peer(peer)?;
        if peer != received.subscription.subscriber || peer == self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_delivery_read(0)?;
        load_open_read(&txn, peer, received.subscription, self.node)?;
        let key = subscription_key(received.subscription);
        let previous = txn
            .open_table(FEDERATION_SNAPSHOT_RECEIPTS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode::<StoredReceived>(saved.value())?.view(received.subscription))
            .transpose()?
            .ok_or(FederationError::Unauthorized)?;
        let current = coverage(previous);
        let claimed = coverage(received);
        if !same_archive(previous, received)
            || claimed.sequence() > current.sequence()
            || claimed.sequence() == current.sequence() && claimed != current
        {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }
    fn authorize_snapshot_delivery(
        &self,
        peer: FederationNodeId,
        subscription: SubscriptionRef,
        manifest: Digest,
        publication: Option<Digest>,
    ) -> Result<(), FederationError> {
        self.decision_peer(peer)?;
        if peer != subscription.subscriber || peer == self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_delivery_read(0)?;
        let offer = current_offer(&txn, peer, subscription, self.node)?
            .ok_or(FederationError::Unauthorized)?;
        if offer.manifest.binding_digest() != manifest
            || publication.is_some_and(|expected| expected != offer.publication_digest)
        {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }

    fn bind_snapshot_publisher_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationSnapshotPublisherStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn publish_snapshot_offer(
        &self,
        request: SnapshotOfferRequest,
    ) -> Result<SnapshotOffer, FederationError> {
        request.proof.validate()?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
            || request.proof.stream.publisher != self.node
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let (opened, acknowledged) = load_open_write(
                txn,
                request.authenticated_subscriber,
                request.subscription,
                self.node,
            )?;
            if opened.stream != request.proof.stream {
                return Err(FederationError::Conflict);
            }
            let manifest = SnapshotManifest {
                id: request.proof.snapshot_id,
                subscription: request.subscription,
                stream: request.proof.stream,
                subscription_revision: opened.subscription_revision,
                publisher_authority: opened.publisher_authority,
                position: request.proof.position,
                schema_revision: request.proof.schema_revision,
                content_digest: request.proof.content_digest,
                content_bytes: request.proof.content_bytes,
            };
            manifest.validate()?;
            let offer = SnapshotOffer {
                manifest,
                publication_digest: request.proof.publication_digest,
            };
            if let Some(existing) = load_offer_write(txn, request.subscription)? {
                return if existing == offer {
                    Ok(existing)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            if acknowledged.is_some_and(|acknowledged| {
                request.proof.position.sequence() < acknowledged.sequence()
                    || request.proof.position.sequence() == acknowledged.sequence()
                        && request.proof.position.digest() != acknowledged.digest()
            }) {
                return Err(FederationError::Conflict);
            }
            verify_publication_position(txn, &opened, request.proof.position)?;
            let key = subscription_key(request.subscription);
            txn.open_table(FEDERATION_SNAPSHOT_OFFERS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&StoredOffer::from(&offer))?.as_slice(),
                )
                .map_err(storage)?;
            let pin = pin_key(
                request.proof.stream,
                request.proof.position,
                request.subscription,
            );
            txn.open_table(FEDERATION_SNAPSHOT_OFFER_PINS_TABLE)
                .map_err(storage)?
                .insert(
                    pin.as_slice(),
                    request.proof.position.digest().as_bytes().as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(offer)
        })
    }

    fn receive_snapshot(
        &self,
        request: SnapshotReceivedRequest,
    ) -> Result<SnapshotReceived, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
            || request.manifest_digest.as_bytes() == &[0; 48]
            || request.publication_digest.as_bytes() == &[0; 48]
            || request.install_id.as_bytes() == &[0; 16]
            || request.archive_digest.as_bytes() == &[0; 48]
            || request.federation_generation == 0
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let (opened, _) = load_open_write(
                txn,
                request.authenticated_subscriber,
                request.subscription,
                self.node,
            )?;
            let received = SnapshotReceived::from(request);
            if let Some(previous) = load_received_write(txn, request.subscription)? {
                if same_archive(previous, received) {
                    let Some(suffix) = received.suffix else {
                        return Ok(received);
                    };
                    let frontier = coverage(previous);
                    if suffix.after != received.position && suffix.after != frontier
                        || suffix.through.sequence() <= suffix.after.sequence()
                        || suffix.through.sequence() < frontier.sequence()
                        || suffix.through.sequence() == frontier.sequence()
                            && suffix.through != frontier
                    {
                        return Err(FederationError::Conflict);
                    }
                    if suffix.through == frontier {
                        return Ok(received);
                    }
                    let count = suffix.through.sequence() - frontier.sequence();
                    if count > xolotl_federation::MAX_SNAPSHOT_SUFFIX_RECORDS as u64 {
                        return Err(FederationError::Capacity);
                    }
                    let records = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                    let mut payload_bytes = 0usize;
                    for sequence in frontier.sequence() + 1..=suffix.through.sequence() {
                        let key = record_key(opened.stream, sequence);
                        let saved = records
                            .get(key.as_slice())
                            .map_err(storage)?
                            .ok_or(FederationError::Conflict)?;
                        let record = decode_record(opened.stream, sequence, saved.value())?;
                        payload_bytes = payload_bytes
                            .checked_add(record.payload().len())
                            .ok_or(FederationError::Capacity)?;
                        if payload_bytes > xolotl_federation::MAX_SNAPSHOT_SUFFIX_BYTES {
                            return Err(FederationError::Capacity);
                        }
                        if sequence == suffix.through.sequence()
                            && record.position() != suffix.through
                        {
                            return Err(FederationError::Conflict);
                        }
                    }
                    drop(records);
                    let key = subscription_key(request.subscription);
                    txn.open_table(FEDERATION_SNAPSHOT_RECEIPTS_TABLE)
                        .map_err(storage)?
                        .insert(
                            key.as_slice(),
                            encode(&StoredReceived::from(received))?.as_slice(),
                        )
                        .map_err(storage)?;
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)?;
                    return Ok(received);
                }
                if received.position.sequence() <= coverage(previous).sequence()
                    || received.federation_generation <= previous.federation_generation
                {
                    return Err(FederationError::Conflict);
                }
            }
            if received.suffix.is_some() {
                return Err(FederationError::Conflict);
            }
            let offer =
                load_offer_write(txn, request.subscription)?.ok_or(FederationError::Conflict)?;
            if !offer_matches_open(&offer, &opened)
                || offer.manifest.binding_digest() != request.manifest_digest
                || offer.publication_digest != request.publication_digest
                || offer.manifest.position != request.position
            {
                return Err(FederationError::Conflict);
            }
            verify_publication_position(txn, &opened, request.position)?;
            let key = subscription_key(request.subscription);
            txn.open_table(FEDERATION_SNAPSHOT_RECEIPTS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&StoredReceived::from(received))?.as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(received)
        })
    }

    fn snapshot_offer(
        &self,
        authenticated_subscriber: FederationNodeId,
        subscription: SubscriptionRef,
    ) -> Result<Option<SnapshotOffer>, FederationError> {
        self.decision_peer(authenticated_subscriber)?;
        if authenticated_subscriber != subscription.subscriber
            || authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        current_offer(&txn, authenticated_subscriber, subscription, self.node)
    }

    fn local_snapshot_offer(
        &self,
        subscription: SubscriptionRef,
    ) -> Result<Option<SnapshotOffer>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        load_offer_read(&txn, subscription)
    }

    fn retire_snapshot_offer(&self, expected: &SnapshotOffer) -> Result<(), FederationError> {
        expected.manifest.validate()?;
        if expected.manifest.stream.publisher != self.node
            || expected.manifest.subscription.subscriber == self.node
            || expected.publication_digest.as_bytes() == &[0; 48]
        {
            return Err(FederationError::Unauthorized);
        }
        let subscription = expected.manifest.subscription;
        let pin = pin_key(
            expected.manifest.stream,
            expected.manifest.position,
            subscription,
        );
        self.with_decision_write(|txn, _| {
            match load_offer_write(txn, subscription)? {
                Some(current) if current != *expected => return Err(FederationError::Conflict),
                None => {
                    if txn
                        .open_table(FEDERATION_SNAPSHOT_OFFER_PINS_TABLE)
                        .map_err(storage)?
                        .get(pin.as_slice())
                        .map_err(storage)?
                        .is_some()
                    {
                        return Err(FederationError::Corrupt);
                    }
                    return Ok(());
                }
                Some(_) => {}
            }
            {
                let mut pins = txn
                    .open_table(FEDERATION_SNAPSHOT_OFFER_PINS_TABLE)
                    .map_err(storage)?;
                let saved = pins
                    .get(pin.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                if saved.value() != expected.manifest.position.digest().as_bytes() {
                    return Err(FederationError::Corrupt);
                }
                drop(saved);
                pins.remove(pin.as_slice()).map_err(storage)?;
            }
            txn.open_table(FEDERATION_SNAPSHOT_OFFERS_TABLE)
                .map_err(storage)?
                .remove(subscription_key(subscription).as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)
        })
    }

    fn read_snapshot_chunk(
        &self,
        request: SnapshotReadRequest,
        source: &dyn SnapshotContentSource,
    ) -> Result<SnapshotReadChunk, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        if request.max_bytes == 0 || request.max_bytes > MAX_SNAPSHOT_CHUNK_BYTES {
            return Err(FederationError::Capacity);
        }
        let (offer, bytes) = {
            let (txn, _) = self.begin_decision_read()?;
            let offer = current_offer(
                &txn,
                request.authenticated_subscriber,
                request.subscription,
                self.node,
            )?
            .ok_or(FederationError::NotFound)?;
            if offer.manifest.binding_digest() != request.manifest_digest
                || request.offset > offer.manifest.content_bytes
            {
                return Err(FederationError::Conflict);
            }
            let remaining = offer.manifest.content_bytes - request.offset;
            (offer, remaining.min(request.max_bytes as u64) as usize)
        };
        let content = if bytes == 0 {
            Arc::<[u8]>::from([])
        } else {
            source.read_snapshot_chunk(&offer, request.offset, bytes)?
        };
        if content.len() != bytes {
            return Err(FederationError::Conflict);
        }
        // Do not hold redb's read transaction across an application callback.
        // Discard bytes if authority or the pinned offer changed in between.
        let (txn, _) = self.begin_decision_read()?;
        if current_offer(
            &txn,
            request.authenticated_subscriber,
            request.subscription,
            self.node,
        )?
        .as_ref()
            != Some(&offer)
        {
            return Err(FederationError::Conflict);
        }
        Ok(SnapshotReadChunk {
            complete: request.offset + bytes as u64 == offer.manifest.content_bytes,
            offer,
            offset: request.offset,
            bytes: content,
        })
    }
}
