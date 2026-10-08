//! Atomic receiver-side snapshot installation and generation fencing.

mod publisher;

use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    AcceptRequest, AcceptResult, AuthorityRevision, Digest, FederationError,
    FederationSnapshotStore, FederationSubject, InboxReadPage, InboxReadRequest, InboxRetirement,
    MAX_RETIRE_BYTES, MAX_RETIRE_RECORDS, Position, ProjectionProgress, SchemaRevision,
    SnapshotAnchor, SnapshotArchiveAnchor, SnapshotArchiveCompletion, SnapshotId,
    SnapshotInboxRetirement, SnapshotInstallRequest, SnapshotInstallView, SnapshotManifest,
    SnapshotProjectionCompletion, SnapshotReaderRelease, StreamRef, SubscriptionRef,
};

use super::{
    FEDERATION_INBOX_TABLE, FEDERATION_SNAPSHOT_INSTALLS_TABLE, FEDERATION_SUBSCRIPTIONS_TABLE,
    OpenResult, RECORD_KEY_LEN, RedbFederationStore, StoredAuthorityRevision, StoredOpenResult,
    StoredPosition, StoredStreamRef, StoredSubscriptionRef, SubscriptionRow, authority_in_read,
    authority_in_write, decode, encode, fixed_bytes_48, inbox_key, storage, subscription_key,
};

pub(super) fn earliest_publisher_offer_pin(
    txn: &WriteTransaction,
    stream: StreamRef,
) -> Result<Option<Position>, FederationError> {
    publisher::earliest_publisher_offer_pin(txn, stream)
}

pub(super) fn publisher_snapshot_coverage_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<Position>, FederationError> {
    publisher::snapshot_coverage_write(txn, subscription)
}

pub(super) fn publisher_snapshot_coverage_read(
    txn: &ReadTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<Position>, FederationError> {
    publisher::snapshot_coverage_read(txn, subscription)
}

pub(super) fn check_event_ack_against_offer(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
    position: Position,
) -> Result<(), FederationError> {
    publisher::check_event_ack_against_offer(txn, subscription, position)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredManifest {
    id: [u8; 16],
    subscription: StoredSubscriptionRef,
    stream: StoredStreamRef,
    subscription_revision: u64,
    publisher_authority: StoredAuthorityRevision,
    position: StoredPosition,
    schema_revision: [u8; 32],
    #[serde(with = "fixed_bytes_48")]
    content_digest: [u8; 48],
    content_bytes: u64,
}

impl From<&SnapshotManifest> for StoredManifest {
    fn from(value: &SnapshotManifest) -> Self {
        Self {
            id: *value.id.as_bytes(),
            subscription: value.subscription.into(),
            stream: value.stream.into(),
            subscription_revision: value.subscription_revision,
            publisher_authority: value.publisher_authority.into(),
            position: value.position.into(),
            schema_revision: *value.schema_revision.as_bytes(),
            content_digest: *value.content_digest.as_bytes(),
            content_bytes: value.content_bytes,
        }
    }
}

impl TryFrom<StoredManifest> for SnapshotManifest {
    type Error = FederationError;

    fn try_from(value: StoredManifest) -> Result<Self, Self::Error> {
        let manifest = Self {
            id: SnapshotId::from_bytes(value.id),
            subscription: value.subscription.into(),
            stream: value.stream.into(),
            subscription_revision: value.subscription_revision,
            publisher_authority: value.publisher_authority.into(),
            position: value.position.try_into()?,
            schema_revision: SchemaRevision::from_bytes(value.schema_revision),
            content_digest: Digest::from_bytes(value.content_digest),
            content_bytes: value.content_bytes,
        };
        manifest
            .validate()
            .map_err(|_error| FederationError::Corrupt)?;
        Ok(manifest)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPending {
    install_id: [u8; 16],
    manifest: StoredManifest,
    #[serde(with = "fixed_bytes_48")]
    publication_digest: [u8; 48],
    expected_generation: u64,
    opened: StoredOpenResult,
    local_authority: StoredAuthorityRevision,
    received: Option<StoredPosition>,
    projected: Option<StoredPosition>,
}

impl StoredPending {
    fn request(&self) -> Result<SnapshotInstallRequest, FederationError> {
        let manifest: SnapshotManifest = self.manifest.clone().try_into()?;
        Ok(SnapshotInstallRequest {
            install_id: SnapshotId::from_bytes(self.install_id),
            subject: FederationSubject::Node(manifest.subscription.subscriber),
            manifest,
            publication_digest: Digest::from_bytes(self.publication_digest),
            expected_generation: self.expected_generation,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAnchor {
    install_id: [u8; 16],
    manifest: StoredManifest,
    #[serde(with = "fixed_bytes_48")]
    publication_digest: [u8; 48],
    federation_generation: u64,
    application_generation: u64,
    #[serde(with = "fixed_bytes_48")]
    completion_digest: [u8; 48],
}

impl StoredAnchor {
    fn view(&self) -> Result<SnapshotAnchor, FederationError> {
        if self.federation_generation == 0 || self.application_generation == 0 {
            return Err(FederationError::Corrupt);
        }
        Ok(SnapshotAnchor {
            install_id: SnapshotId::from_bytes(self.install_id),
            manifest: self.manifest.clone().try_into()?,
            publication_digest: Digest::from_bytes(self.publication_digest),
            federation_generation: self.federation_generation,
            application_generation: self.application_generation,
            completion_digest: Digest::from_bytes(self.completion_digest),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredArchiveAnchor {
    install_id: [u8; 16],
    manifest: StoredManifest,
    #[serde(with = "fixed_bytes_48")]
    publication_digest: [u8; 48],
    federation_generation: u64,
    #[serde(with = "fixed_bytes_48")]
    archive_digest: [u8; 48],
}

impl StoredArchiveAnchor {
    fn view(&self) -> Result<SnapshotArchiveAnchor, FederationError> {
        if self.federation_generation == 0 || self.archive_digest == [0; 48] {
            return Err(FederationError::Corrupt);
        }
        Ok(SnapshotArchiveAnchor {
            install_id: SnapshotId::from_bytes(self.install_id),
            manifest: self.manifest.clone().try_into()?,
            publication_digest: Digest::from_bytes(self.publication_digest),
            federation_generation: self.federation_generation,
            archive_digest: Digest::from_bytes(self.archive_digest),
        })
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLedger {
    generation: u64,
    active: Option<StoredAnchor>,
    archived: Option<StoredArchiveAnchor>,
    pending: Option<StoredPending>,
    closed: bool,
}

impl StoredLedger {
    fn view(&self) -> Result<SnapshotInstallView, FederationError> {
        if self.active.as_ref().is_some_and(|anchor| {
            anchor.federation_generation != self.generation || self.generation == 0
        }) || self.archived.as_ref().is_some_and(|anchor| {
            anchor.federation_generation != self.generation || self.generation == 0
        }) || self.active.is_none() && self.archived.is_none() && self.generation != 0
        {
            return Err(FederationError::Corrupt);
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.expected_generation != self.generation)
        {
            return Err(FederationError::Corrupt);
        }
        let active = self.active.as_ref().map(StoredAnchor::view).transpose()?;
        let archived = self
            .archived
            .as_ref()
            .map(StoredArchiveAnchor::view)
            .transpose()?;
        if let (Some(active), Some(archived)) = (&active, &archived)
            && (active.install_id != archived.install_id
                || active.manifest != archived.manifest
                || active.publication_digest != archived.publication_digest
                || active.federation_generation != archived.federation_generation)
        {
            return Err(FederationError::Corrupt);
        }
        Ok(SnapshotInstallView {
            active,
            archived,
            pending: self
                .pending
                .as_ref()
                .map(StoredPending::request)
                .transpose()?,
            generation: self.generation,
            closed: self.closed,
        })
    }
}

fn load_read(
    txn: &ReadTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<StoredLedger>, FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_INSTALLS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()
}

fn load_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
) -> Result<Option<StoredLedger>, FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_INSTALLS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()
}

fn save(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
    ledger: &StoredLedger,
) -> Result<(), FederationError> {
    let key = subscription_key(subscription);
    txn.open_table(FEDERATION_SNAPSHOT_INSTALLS_TABLE)
        .map_err(storage)?
        .insert(key.as_slice(), encode(ledger)?.as_slice())
        .map_err(storage)?;
    Ok(())
}

/// A missing sidecar is an ordinary generation-zero receiver. An active
/// sidecar requires an explicit generation; pending and closed rows deny all
/// delivery work even to callers that know the old generation.
fn gate(
    ledger: Option<StoredLedger>,
    expected_generation: Option<u64>,
) -> Result<Option<Position>, FederationError> {
    let Some(ledger) = ledger else {
        return if expected_generation.is_none_or(|generation| generation == 0) {
            Ok(None)
        } else {
            Err(FederationError::Conflict)
        };
    };
    let view = ledger.view()?;
    if view.closed || view.pending.is_some() {
        return Err(FederationError::Conflict);
    }
    if view.active.is_none() && view.archived.is_none() {
        return if expected_generation.is_none_or(|generation| generation == 0) {
            Ok(None)
        } else {
            Err(FederationError::Conflict)
        };
    }
    if expected_generation != Some(view.generation) {
        return Err(FederationError::Conflict);
    }
    Ok(view
        .active
        .map(|anchor| anchor.manifest.position)
        .or_else(|| view.archived.map(|anchor| anchor.manifest.position)))
}

pub(super) fn gate_read(
    txn: &ReadTransaction,
    subscription: SubscriptionRef,
    expected_generation: Option<u64>,
) -> Result<Option<Position>, FederationError> {
    gate(load_read(txn, subscription)?, expected_generation)
}

pub(super) fn gate_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
    expected_generation: Option<u64>,
) -> Result<Option<Position>, FederationError> {
    gate(load_write(txn, subscription)?, expected_generation)
}

/// An archived delivery baseline permits reception but is not an application
/// projection. Progress and both forms of projected-row retirement require a
/// real application completion bound to the active generation.
pub(super) fn gate_projected_write(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
    expected_generation: Option<u64>,
) -> Result<Option<Position>, FederationError> {
    let ledger = load_write(txn, subscription)?;
    if let Some(ledger) = &ledger
        && ledger.archived.is_some()
        && ledger.active.is_none()
    {
        return Err(FederationError::Conflict);
    }
    gate(ledger, expected_generation)
}

fn receiver_row(
    txn: &WriteTransaction,
    subscription: SubscriptionRef,
) -> Result<
    (
        OpenResult,
        StoredAuthorityRevision,
        Option<StoredPosition>,
        Option<StoredPosition>,
    ),
    FederationError,
> {
    let key = subscription_key(subscription);
    let row: SubscriptionRow = txn
        .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    let SubscriptionRow::Receiver {
        opened,
        local_authority,
        received,
        projected,
        ..
    } = row
    else {
        return Err(FederationError::Conflict);
    };
    let opened = OpenResult::try_from(opened)?;
    if opened.subscription != subscription {
        return Err(FederationError::Corrupt);
    }
    Ok((opened, local_authority, received, projected))
}

impl FederationSnapshotStore for RedbFederationStore {
    fn bind_snapshot_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationSnapshotStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn snapshot_install(
        &self,
        subscription: SubscriptionRef,
    ) -> Result<Option<SnapshotInstallView>, FederationError> {
        if subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        load_read(&txn, subscription)?
            .map(|row| row.view())
            .transpose()
    }

    fn receiver_cursor_in_generation(
        &self,
        generation: u64,
        subscription: SubscriptionRef,
    ) -> Result<Option<Position>, FederationError> {
        if subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        let baseline = gate_read(&txn, subscription, Some(generation))?;
        let key = subscription_key(subscription);
        let row: SubscriptionRow = txn
            .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode(saved.value()))
            .transpose()?
            .ok_or(FederationError::NotFound)?;
        let SubscriptionRow::Receiver {
            opened,
            local_authority,
            received,
            ..
        } = row
        else {
            return Err(FederationError::Conflict);
        };
        let opened = OpenResult::try_from(opened)?;
        if opened.subscription != subscription {
            return Err(FederationError::Corrupt);
        }
        let current = authority_in_read(&txn, opened.stream.publisher, &opened.export, false)?;
        if current != AuthorityRevision::from(local_authority) {
            return Err(FederationError::Conflict);
        }
        let received = received.map(Position::try_from).transpose()?;
        if received.is_some_and(|head| {
            baseline
                .or(opened.start)
                .is_some_and(|start| head.sequence() <= start.sequence())
        }) {
            return Err(FederationError::Corrupt);
        }
        Ok(received.or(baseline).or(opened.start))
    }

    fn begin_snapshot_install(
        &self,
        request: SnapshotInstallRequest,
    ) -> Result<SnapshotInstallView, FederationError> {
        request.manifest.validate()?;
        if request.install_id.as_bytes() == &[0; 16]
            || request.publication_digest.as_bytes() == &[0; 48]
            || request.manifest.subscription.subscriber != self.node
            || request.manifest.stream.publisher == self.node
            || request.subject != FederationSubject::Node(self.node)
        {
            return Err(FederationError::Unauthorized);
        }
        let subscription = request.manifest.subscription;
        self.with_decision_write(|txn, _| {
            let mut ledger = load_write(txn, subscription)?.unwrap_or_default();
            let current_view = ledger.view()?;
            if current_view.closed {
                return Err(FederationError::Conflict);
            }
            if let Some(pending) = &current_view.pending {
                return if pending == &request {
                    Ok(current_view)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            if current_view
                .active
                .as_ref()
                .is_some_and(|anchor| anchor.install_id == request.install_id)
            {
                return if current_view.active.as_ref().is_some_and(|anchor| {
                    anchor.manifest == request.manifest
                        && anchor.publication_digest == request.publication_digest
                        && request
                            .expected_generation
                            .checked_add(1)
                            .is_some_and(|next| anchor.federation_generation == next)
                }) {
                    Ok(current_view)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            if let Some(archived) = &current_view.archived
                && archived.install_id == request.install_id
            {
                return if archived.manifest == request.manifest
                    && archived.publication_digest == request.publication_digest
                    && request
                        .expected_generation
                        .checked_add(1)
                        .is_some_and(|next| archived.federation_generation == next)
                {
                    Ok(current_view)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            // A byte archive cannot replace an earlier archive without retaining
            // the former reader generation. This first archive contract fails
            // closed on another install, even after application binding.
            if current_view.archived.is_some() {
                return Err(FederationError::Conflict);
            }
            if request.expected_generation != ledger.generation {
                return Err(FederationError::Conflict);
            }
            let (opened, local_authority, received, projected) = receiver_row(txn, subscription)?;
            let manifest = &request.manifest;
            if opened.stream != manifest.stream
                || opened.subscription_revision != manifest.subscription_revision
                || opened.publisher_authority != manifest.publisher_authority
                // The first slice accepts only a full-history private node-self
                // view. A nonempty Open floor needs an application proof that the
                // snapshot contains no excluded pre-grant state.
                || opened.start.is_some()
            {
                return Err(FederationError::Conflict);
            }
            let current =
                authority_in_write(txn, manifest.stream.publisher, &opened.export, false)?;
            if current != AuthorityRevision::from(local_authority) {
                return Err(FederationError::Conflict);
            }
            if let Some(received) = received.map(Position::try_from).transpose()?
                && (manifest.position.sequence() < received.sequence()
                    || manifest.position.sequence() == received.sequence()
                        && manifest.position.digest() != received.digest())
            {
                return Err(FederationError::Conflict);
            }
            if current_view
                .active
                .as_ref()
                .map(|active| active.manifest.position.sequence())
                .or_else(|| {
                    current_view
                        .archived
                        .as_ref()
                        .map(|archived| archived.manifest.position.sequence())
                })
                .is_some_and(|baseline| manifest.position.sequence() <= baseline)
            {
                return Err(FederationError::Conflict);
            }
            ledger.pending = Some(StoredPending {
                install_id: *request.install_id.as_bytes(),
                manifest: manifest.into(),
                publication_digest: *request.publication_digest.as_bytes(),
                expected_generation: request.expected_generation,
                opened: (&opened).into(),
                local_authority,
                received,
                projected,
            });
            save(txn, subscription, &ledger)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            ledger.view()
        })
    }

    fn commit_snapshot_anchor(
        &self,
        subscription: SubscriptionRef,
        completion: SnapshotProjectionCompletion,
    ) -> Result<SnapshotAnchor, FederationError> {
        if subscription.subscriber != self.node
            || completion.application_generation == 0
            || completion.completion_digest.as_bytes() == &[0; 48]
        {
            return Err(FederationError::Invalid("invalid snapshot completion"));
        }
        self.with_decision_write(|txn, _| {
            let mut ledger = load_write(txn, subscription)?.ok_or(FederationError::NotFound)?;
            let view = ledger.view()?;
            if view.closed {
                return Err(FederationError::Conflict);
            }
            if let Some(active) = &view.active
                && active.install_id == completion.install_id
            {
                return if active.manifest.id == completion.snapshot_id
                    && active.manifest.content_digest == completion.content_digest
                    && active.manifest.binding_digest() == completion.manifest_digest
                    && active.application_generation == completion.application_generation
                    && active.completion_digest == completion.completion_digest
                {
                    Ok(active.clone())
                } else {
                    Err(FederationError::Conflict)
                };
            }
            let pending = ledger.pending.as_ref().ok_or(FederationError::NotFound)?;
            let request = pending.request()?;
            if request.install_id != completion.install_id
                || request.manifest.id != completion.snapshot_id
                || request.manifest.content_digest != completion.content_digest
                || request.manifest.binding_digest() != completion.manifest_digest
                || request.expected_generation != ledger.generation
            {
                return Err(FederationError::Conflict);
            }
            let (opened, local_authority, received, projected) = receiver_row(txn, subscription)?;
            if opened != OpenResult::try_from(pending.opened.clone())?
                || local_authority.peer != pending.local_authority.peer
                || local_authority.export != pending.local_authority.export
                || received != pending.received
                || projected != pending.projected
            {
                return Err(FederationError::Conflict);
            }
            let current = authority_in_write(txn, opened.stream.publisher, &opened.export, false)?;
            if current != AuthorityRevision::from(local_authority) {
                return Err(FederationError::Conflict);
            }
            let next = ledger
                .generation
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            let anchor = SnapshotAnchor {
                install_id: completion.install_id,
                manifest: request.manifest,
                publication_digest: request.publication_digest,
                federation_generation: next,
                application_generation: completion.application_generation,
                completion_digest: completion.completion_digest,
            };
            let key = subscription_key(subscription);
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Receiver {
                        opened: (&opened).into(),
                        local_authority,
                        received: None,
                        projected: None,
                        // Older inbox rows are quarantined below the new baseline.
                        // Their bounded physical retirement is a separate task.
                        retired_through: None,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            ledger.generation = next;
            ledger.active = Some(StoredAnchor {
                install_id: *anchor.install_id.as_bytes(),
                manifest: (&anchor.manifest).into(),
                publication_digest: *anchor.publication_digest.as_bytes(),
                federation_generation: next,
                application_generation: anchor.application_generation,
                completion_digest: *anchor.completion_digest.as_bytes(),
            });
            ledger.archived = None;
            ledger.pending = None;
            save(txn, subscription, &ledger)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(anchor)
        })
    }

    fn commit_snapshot_archive(
        &self,
        subscription: SubscriptionRef,
        completion: SnapshotArchiveCompletion,
    ) -> Result<SnapshotArchiveAnchor, FederationError> {
        if subscription.subscriber != self.node || completion.archive_digest.as_bytes() == &[0; 48]
        {
            return Err(FederationError::Invalid(
                "invalid snapshot archive completion",
            ));
        }
        self.with_decision_write(|txn, _| {
            let mut ledger = load_write(txn, subscription)?.ok_or(FederationError::NotFound)?;
            let view = ledger.view()?;
            if view.closed {
                return Err(FederationError::Conflict);
            }
            if let Some(archived) = view.archived
                && archived.install_id == completion.install_id
            {
                return if archived.manifest.id == completion.snapshot_id
                    && archived.manifest.content_digest == completion.content_digest
                    && archived.manifest.binding_digest() == completion.manifest_digest
                    && archived.archive_digest == completion.archive_digest
                {
                    Ok(archived)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            let pending = ledger.pending.as_ref().ok_or(FederationError::NotFound)?;
            if ledger.active.is_some() || ledger.archived.is_some() {
                return Err(FederationError::Conflict);
            }
            let request = pending.request()?;
            if request.install_id != completion.install_id
                || request.manifest.id != completion.snapshot_id
                || request.manifest.content_digest != completion.content_digest
                || request.manifest.binding_digest() != completion.manifest_digest
                || request.expected_generation != ledger.generation
            {
                return Err(FederationError::Conflict);
            }
            let (opened, local_authority, received, projected) = receiver_row(txn, subscription)?;
            if opened != OpenResult::try_from(pending.opened.clone())?
                || local_authority.peer != pending.local_authority.peer
                || local_authority.export != pending.local_authority.export
                || received != pending.received
                || projected != pending.projected
            {
                return Err(FederationError::Conflict);
            }
            let current = authority_in_write(txn, opened.stream.publisher, &opened.export, false)?;
            if current != AuthorityRevision::from(local_authority) {
                return Err(FederationError::Conflict);
            }
            let next = ledger
                .generation
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            let anchor = SnapshotArchiveAnchor {
                install_id: completion.install_id,
                manifest: request.manifest,
                publication_digest: request.publication_digest,
                federation_generation: next,
                archive_digest: completion.archive_digest,
            };
            let key = subscription_key(subscription);
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Receiver {
                        opened: (&opened).into(),
                        local_authority,
                        received: None,
                        projected: None,
                        retired_through: None,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            ledger.generation = next;
            ledger.active = None;
            ledger.archived = Some(StoredArchiveAnchor {
                install_id: *anchor.install_id.as_bytes(),
                manifest: (&anchor.manifest).into(),
                publication_digest: *anchor.publication_digest.as_bytes(),
                federation_generation: next,
                archive_digest: *anchor.archive_digest.as_bytes(),
            });
            ledger.pending = None;
            save(txn, subscription, &ledger)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(anchor)
        })
    }

    fn bind_archived_snapshot_projection(
        &self,
        subscription: SubscriptionRef,
        completion: SnapshotProjectionCompletion,
    ) -> Result<SnapshotAnchor, FederationError> {
        if subscription.subscriber != self.node
            || completion.application_generation == 0
            || completion.completion_digest.as_bytes() == &[0; 48]
        {
            return Err(FederationError::Invalid(
                "invalid snapshot projection completion",
            ));
        }
        self.with_decision_write(|txn, _| {
            let mut ledger = load_write(txn, subscription)?.ok_or(FederationError::NotFound)?;
            let view = ledger.view()?;
            if view.closed || view.pending.is_some() {
                return Err(FederationError::Conflict);
            }
            let archived = view.archived.ok_or(FederationError::NotFound)?;
            if archived.install_id != completion.install_id
                || archived.manifest.id != completion.snapshot_id
                || archived.manifest.content_digest != completion.content_digest
                || archived.manifest.binding_digest() != completion.manifest_digest
            {
                return Err(FederationError::Conflict);
            }
            if let Some(active) = view.active {
                return if active.install_id == completion.install_id
                    && active.application_generation == completion.application_generation
                    && active.completion_digest == completion.completion_digest
                {
                    Ok(active)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            let (opened, local_authority, _, _) = receiver_row(txn, subscription)?;
            if opened.stream != archived.manifest.stream
                || opened.subscription_revision != archived.manifest.subscription_revision
                || opened.publisher_authority != archived.manifest.publisher_authority
                || authority_in_write(txn, opened.stream.publisher, &opened.export, false)?
                    != AuthorityRevision::from(local_authority)
            {
                return Err(FederationError::Conflict);
            }
            let anchor = SnapshotAnchor {
                install_id: completion.install_id,
                manifest: archived.manifest,
                publication_digest: archived.publication_digest,
                federation_generation: archived.federation_generation,
                application_generation: completion.application_generation,
                completion_digest: completion.completion_digest,
            };
            ledger.active = Some(StoredAnchor {
                install_id: *anchor.install_id.as_bytes(),
                manifest: (&anchor.manifest).into(),
                publication_digest: *anchor.publication_digest.as_bytes(),
                federation_generation: anchor.federation_generation,
                application_generation: anchor.application_generation,
                completion_digest: *anchor.completion_digest.as_bytes(),
            });
            save(txn, subscription, &ledger)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(anchor)
        })
    }

    fn abort_snapshot_install(
        &self,
        subscription: SubscriptionRef,
        install_id: SnapshotId,
    ) -> Result<(), FederationError> {
        if subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let mut ledger = load_write(txn, subscription)?.ok_or(FederationError::NotFound)?;
            if ledger
                .active
                .as_ref()
                .is_some_and(|active| active.install_id == *install_id.as_bytes())
            {
                return Err(FederationError::Conflict);
            }
            if ledger
                .archived
                .as_ref()
                .is_some_and(|archived| archived.install_id == *install_id.as_bytes())
            {
                return Err(FederationError::Conflict);
            }
            if ledger
                .pending
                .as_ref()
                .is_none_or(|pending| pending.install_id != *install_id.as_bytes())
            {
                return Err(FederationError::NotFound);
            }
            ledger.pending = None;
            save(txn, subscription, &ledger)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)
        })
    }

    fn close_snapshot_receiver(
        &self,
        subscription: SubscriptionRef,
    ) -> Result<(), FederationError> {
        if subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            receiver_row(txn, subscription)?;
            let mut ledger = load_write(txn, subscription)?.unwrap_or_default();
            if ledger.closed {
                return Ok(());
            }
            ledger.closed = true;
            save(txn, subscription, &ledger)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)
        })
    }

    fn accept_in_generation(
        &self,
        generation: u64,
        request: AcceptRequest,
    ) -> Result<AcceptResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        self.accept_inner(request, Some(generation))
    }

    fn read_inbox_in_generation(
        &self,
        generation: u64,
        request: InboxReadRequest,
    ) -> Result<InboxReadPage, FederationError> {
        self.read_inbox_inner(request, Some(generation))
    }

    fn record_projection_progress_in_generation(
        &self,
        generation: u64,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError> {
        self.record_projection_progress_inner(request, Some(generation))
    }

    fn retire_projected_inbox_in_generation(
        &self,
        generation: u64,
        subscription: SubscriptionRef,
        max_records: usize,
    ) -> Result<InboxRetirement, FederationError> {
        self.retire_projected_inbox_inner(subscription, max_records, Some(generation))
    }

    fn retire_snapshotted_inbox(
        &self,
        release: SnapshotReaderRelease,
        max_records: usize,
    ) -> Result<SnapshotInboxRetirement, FederationError> {
        if release.subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        if max_records == 0 || max_records > MAX_RETIRE_RECORDS {
            return Err(FederationError::Capacity);
        }
        if release.release_digest.as_bytes() == &[0; 48] {
            return Err(FederationError::Invalid("missing reader release evidence"));
        }
        self.with_decision_write(|txn, _| {
            let ledger = load_write(txn, release.subscription)?.ok_or(FederationError::NotFound)?;
            let view = ledger.view()?;
            if view.pending.is_some() {
                return Err(FederationError::Conflict);
            }
            if view.archived.is_some() && view.active.is_none() {
                return Err(FederationError::Conflict);
            }
            let anchor = view.active.ok_or(FederationError::NotFound)?;
            if anchor.install_id != release.install_id
                || anchor.federation_generation != release.federation_generation
                || anchor.application_generation != release.application_generation
                || anchor.completion_digest != release.completion_digest
                || anchor.federation_generation.checked_sub(1)
                    != Some(release.released_through_generation)
            {
                return Err(FederationError::Conflict);
            }
            let (opened, _, _, _) = receiver_row(txn, release.subscription)?;
            if opened.stream != anchor.manifest.stream
                || opened.subscription_revision != anchor.manifest.subscription_revision
                || opened.publisher_authority != anchor.manifest.publisher_authority
            {
                return Err(FederationError::Corrupt);
            }

            // B >= the old received head and post-anchor acceptance starts at B+1.
            // Consequently every key in this interval belongs to an older delivery
            // generation. The caller supplies the separate reader-quiescence fact.
            let start = inbox_key(release.subscription, 1);
            let end = inbox_key(release.subscription, anchor.manifest.position.sequence());
            let mut inbox = txn.open_table(FEDERATION_INBOX_TABLE).map_err(storage)?;
            let mut keys = Vec::with_capacity(max_records);
            let mut bytes = 0_usize;
            let mut drained = true;
            for entry in inbox
                .range(start.as_slice()..=end.as_slice())
                .map_err(storage)?
            {
                let (key, value) = entry.map_err(storage)?;
                if keys.len() == max_records {
                    drained = false;
                    break;
                }
                let key = <[u8; RECORD_KEY_LEN]>::try_from(key.value())
                    .map_err(|_error| FederationError::Corrupt)?;
                let next = bytes
                    .checked_add(value.value().len())
                    .ok_or(FederationError::Capacity)?;
                if next > MAX_RETIRE_BYTES {
                    drained = false;
                    break;
                }
                keys.push(key);
                bytes = next;
            }
            if keys.is_empty() && !drained {
                return Err(FederationError::Capacity);
            }
            for key in &keys {
                inbox.remove(key.as_slice()).map_err(storage)?;
            }
            drop(inbox);
            if !keys.is_empty() {
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
            }
            Ok(SnapshotInboxRetirement {
                subscription: release.subscription,
                covered_through: anchor.manifest.position,
                removed: keys.len(),
                drained,
            })
        })
    }
}
