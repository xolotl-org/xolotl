//! Volatile semantic reference store. This is not a durable federation backend.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

mod object;
mod public;
mod receive;
mod replication;

use crate::{
    AcceptRequest, AcceptResult, AcknowledgeRequest, AuthorityRevision, CloseSubscriptionRequest,
    CloseSubscriptionResult, ExportAccess, ExportName, FederationError, FederationNodeId,
    FederationStore, FederationSubject, GrantHistory, HistoryStart, HostedSubject, InboxReadPage,
    InboxReadRequest, InboxRetirement, InspectSubscriptionRequest, InstallSubscriptionRequest,
    MAX_RETIRE_BYTES, MAX_RETIRE_RECORDS, OpenRequest, OpenResult, PeerAdmission, Position,
    ProjectionProgress, PublicationReceipt, PublishRequest, PublishedRetirement, ReadPage,
    ReadRequest, Record, RequestId, StreamRef, StreamSpec, SubjectGrant, SubjectGrantEntry,
    SubjectGrantKey, SubscriptionInspection, SubscriptionRef,
};

struct PeerAuthority {
    revision: u64,
    enabled: bool,
}

struct ExportAuthority {
    revision: u64,
    access: ExportAccess,
}

struct SubjectGrantRow {
    revision: u64,
    grant: SubjectGrant,
    floor: u64,
}

struct PublishedStream {
    spec: StreamSpec,
    records: VecDeque<Record>,
    requests: HashMap<(u64, RequestId), Position>,
    retry_epoch: u64,
    head: Option<Position>,
    minimum_available: u64,
    retired_through: Option<Position>,
}

struct PublicPolicyRow {
    revision: u64,
    enabled: bool,
    max_read_records: usize,
    max_read_bytes: usize,
}

struct PublishedSubscription {
    request: OpenRequest,
    subject: FederationSubject,
    result: OpenResult,
    acknowledged: Option<Position>,
    closed_revision: Option<u64>,
}

struct ReceivedSubscription {
    opened: OpenResult,
    local_authority: AuthorityRevision,
    inbox: VecDeque<Record>,
    received: Option<Position>,
    projected: Option<Position>,
    retired_through: Option<Position>,
}

#[derive(Default)]
struct State {
    publish_id_limit: usize,
    publish_id_count: usize,
    trusted_time_ms: u64,
    peers: HashMap<FederationNodeId, PeerAuthority>,
    admissions: HashMap<FederationNodeId, (u64, PeerAdmission)>,
    exports: HashMap<(FederationNodeId, ExportName), ExportAuthority>,
    subject_grants: HashMap<(HostedSubject, FederationNodeId, StreamRef), SubjectGrantRow>,
    streams: HashMap<StreamRef, PublishedStream>,
    public_policies: HashMap<StreamRef, PublicPolicyRow>,
    object_grants: HashMap<crate::ObjectGrantId, crate::ObjectGrantView>,
    object_transfers:
        HashMap<(FederationNodeId, crate::ObjectTransferId), (crate::ObjectGrantId, u64, u64)>,
    next_object_grant_id: u64,
    object_trusted_time_ms: u64,
    object_receives: HashMap<crate::ObjectTransferId, crate::ObjectReceiveView>,
    next_object_receive_id: u64,
    object_gc_fences: HashMap<String, u64>,
    next_object_gc_fence_id: u64,
    published_subscriptions: HashMap<SubscriptionRef, PublishedSubscription>,
    open_requests: HashMap<(FederationNodeId, RequestId), OpenResult>,
    close_requests:
        HashMap<(FederationNodeId, RequestId), (CloseSubscriptionRequest, CloseSubscriptionResult)>,
    control_revisions: HashMap<FederationNodeId, u64>,
    received_subscriptions: HashMap<SubscriptionRef, ReceivedSubscription>,
    replica_members: HashMap<(StreamRef, FederationNodeId), replication::ReplicaMember>,
}

/// Single-process reference implementation for contract tests. It loses all
/// state on restart and must not be used for production federation.
#[derive(Clone)]
pub struct MemoryFederationStore {
    local_node: FederationNodeId,
    state: Arc<Mutex<State>>,
    decision: Option<crate::FederationDecision>,
}

impl MemoryFederationStore {
    /// Create an empty, transient federation store for one local node.
    pub fn new(local_node: FederationNodeId) -> Self {
        Self::with_publish_id_limit(local_node, NonZeroUsize::MIN.saturating_add(65_535))
    }

    /// Create a transient store with a retained publish identity bound shared
    /// by all streams, clones and bound views. Payload retirement returns no slots.
    /// Close the retry epoch and retire exact confirmed receipts to release
    /// identity slots; unknown evidence remains charged and inspectable.
    pub fn with_publish_id_limit(local_node: FederationNodeId, limit: NonZeroUsize) -> Self {
        Self {
            local_node,
            state: Arc::new(Mutex::new(State {
                publish_id_limit: limit.get(),
                ..State::default()
            })),
            decision: None,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, FederationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if let Some(decision) = &self.decision {
            let now_ms = decision.now_ms()?;
            let floor_ms = state.trusted_time_ms;
            state.trusted_time_ms = floor_ms.max(now_ms);
            decision.check(
                state.peers.get(&decision.peer()).map(|row| row.enabled),
                state
                    .admissions
                    .get(&decision.peer())
                    .map(|(_, policy)| policy),
                floor_ms,
                now_ms,
            )?;
        }
        Ok(state)
    }

    fn delivery_lock(
        &self,
        fallback_ms: u64,
    ) -> Result<(std::sync::MutexGuard<'_, State>, u64), FederationError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let now_ms = if let Some(decision) = &self.decision {
            let now_ms = decision.now_ms()?;
            decision.check(
                state.peers.get(&decision.peer()).map(|row| row.enabled),
                state
                    .admissions
                    .get(&decision.peer())
                    .map(|(_, policy)| policy),
                state.trusted_time_ms,
                now_ms,
            )?;
            now_ms
        } else {
            let now_ms = if fallback_ms == 0 {
                state.trusted_time_ms
            } else {
                fallback_ms
            };
            if now_ms < state.trusted_time_ms {
                return Err(FederationError::ClockRollback);
            }
            now_ms
        };
        Ok((state, now_ms))
    }

    /// Create an immutable remote view sharing the same authority lock.
    pub fn with_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<Self, FederationError> {
        if self.decision.is_some() || decision.peer() == self.local_node {
            return Err(FederationError::Unauthorized);
        }
        Ok(Self {
            decision: Some(decision),
            ..self.clone()
        })
    }

    fn decision_time(&self, state: &State, fallback: u64) -> u64 {
        if self.decision.is_some() {
            state.trusted_time_ms
        } else {
            fallback
        }
    }

    fn decision_peer(&self, peer: FederationNodeId) -> Result<(), FederationError> {
        self.decision
            .as_ref()
            .map_or(Ok(()), |decision| decision.check_peer(peer))
    }

    /// Configure a peer's online authorization policy in the reference store.
    pub fn set_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        admission.validate()?;
        let mut state = self.lock()?;
        if !state.peers.contains_key(&peer) {
            return Err(FederationError::NotFound);
        }
        let current = state.admissions.get(&peer);
        if current.is_some_and(|(_, previous)| {
            admission.minimum_online_generation < previous.minimum_online_generation
        }) {
            return Err(FederationError::Conflict);
        }
        let next = next_revision(current.map(|(revision, _)| *revision), expected_revision)?;
        state.admissions.insert(peer, (next, admission));
        Ok(next)
    }
}

fn next_revision(current: Option<u64>, expected: Option<u64>) -> Result<u64, FederationError> {
    if current != expected {
        return Err(FederationError::Conflict);
    }
    match current {
        Some(revision) => revision.checked_add(1).ok_or(FederationError::Capacity),
        None => Ok(1),
    }
}

fn authority(
    state: &State,
    peer: FederationNodeId,
    export: &ExportName,
    serve: bool,
) -> Result<AuthorityRevision, FederationError> {
    let peer_authority = state
        .peers
        .get(&peer)
        .ok_or(FederationError::Unauthorized)?;
    let export_authority = state
        .exports
        .get(&(peer, export.clone()))
        .ok_or(FederationError::Unauthorized)?;
    if !peer_authority.enabled
        || !(if serve {
            export_authority.access.serve
        } else {
            export_authority.access.receive
        })
    {
        return Err(FederationError::Unauthorized);
    }
    Ok(AuthorityRevision {
        peer: peer_authority.revision,
        export: export_authority.revision,
    })
}

fn subject_authority(
    state: &State,
    subject: &FederationSubject,
    presenter: FederationNodeId,
    stream: StreamRef,
    export: &ExportName,
    now_ms: u64,
) -> Result<(AuthorityRevision, u64), FederationError> {
    match subject {
        FederationSubject::Node(node) if *node == presenter => {
            Ok((authority(state, presenter, export, true)?, 0))
        }
        FederationSubject::Hosted(hosted) => {
            let peer = state
                .peers
                .get(&presenter)
                .ok_or(FederationError::Unauthorized)?;
            let row = state
                .subject_grants
                .get(&(hosted.clone(), presenter, stream))
                .ok_or(FederationError::Unauthorized)?;
            if !peer.enabled
                || !row.grant.enabled
                || now_ms < row.grant.not_before_ms
                || now_ms >= row.grant.expires_ms
            {
                return Err(FederationError::Unauthorized);
            }
            Ok((
                AuthorityRevision {
                    peer: peer.revision,
                    export: row.revision,
                },
                row.floor,
            ))
        }
        _ => Err(FederationError::Unauthorized),
    }
}

impl PublishedStream {
    fn at(&self, position: Position) -> Result<(), FederationError> {
        if self.retired_through == Some(position) {
            return Ok(());
        }
        if self
            .retired_through
            .is_some_and(|retired| retired.sequence() == position.sequence())
        {
            return Err(FederationError::Conflict);
        }
        if position.sequence() < self.minimum_available {
            return Err(FederationError::ResyncRequired {
                minimum_available: self.minimum_available,
            });
        }
        let index = position
            .sequence()
            .checked_sub(self.minimum_available)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(FederationError::Conflict)?;
        let record = self.records.get(index).ok_or(FederationError::Conflict)?;
        if record.digest() != position.digest() {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }
}

impl ReceivedSubscription {
    fn first_retained(&self) -> Result<u64, FederationError> {
        self.retired_through
            .or(self.opened.start)
            .map_or(Ok(1), |position| {
                position
                    .sequence()
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)
            })
    }

    fn at(&self, position: Position) -> Result<(), FederationError> {
        if self.retired_through == Some(position) || self.opened.start == Some(position) {
            return Ok(());
        }
        if self
            .retired_through
            .is_some_and(|retired| retired.sequence() == position.sequence())
        {
            return Err(FederationError::Conflict);
        }
        if self
            .opened
            .start
            .is_some_and(|start| start.sequence() == position.sequence())
        {
            return Err(FederationError::Conflict);
        }
        let first = self.first_retained()?;
        if position.sequence() < first {
            return Err(FederationError::ResyncRequired {
                minimum_available: first,
            });
        }
        let index = position
            .sequence()
            .checked_sub(first)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(FederationError::Conflict)?;
        let record = self.inbox.get(index).ok_or(FederationError::Conflict)?;
        if record.digest() != position.digest() {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }
}

impl FederationStore for MemoryFederationStore {
    fn authorize_subscription_delivery(
        &self,
        subject: &FederationSubject,
        request: InspectSubscriptionRequest,
        payload: bool,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber {
            return Err(FederationError::Unauthorized);
        }
        let (state, now_ms) = self.delivery_lock(now_ms)?;
        let subscription = state
            .published_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        if &subscription.subject != subject || (payload && subscription.closed_revision.is_some()) {
            return Err(FederationError::Unauthorized);
        }
        let opened = &subscription.result;
        let (current, _) = subject_authority(
            &state,
            subject,
            request.authenticated_subscriber,
            opened.stream,
            &opened.export,
            now_ms,
        )?;
        if current != opened.publisher_authority {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }

    fn set_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        MemoryFederationStore::set_peer_admission(self, peer, expected_revision, admission)
    }

    fn bind_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.local_node
    }

    fn set_peer_authority(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        if peer == self.local_node {
            return Err(FederationError::Invalid("peer cannot be local node"));
        }
        let mut state = self.lock()?;
        let next = next_revision(
            state.peers.get(&peer).map(|value| value.revision),
            expected_revision,
        )?;
        state.peers.insert(
            peer,
            PeerAuthority {
                revision: next,
                enabled,
            },
        );
        Ok(next)
    }

    fn set_export_authority(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError> {
        if peer == self.local_node {
            return Err(FederationError::Invalid("peer cannot be local node"));
        }
        let mut state = self.lock()?;
        if !state.peers.contains_key(&peer) {
            return Err(FederationError::NotFound);
        }
        let key = (peer, export);
        let next = next_revision(
            state.exports.get(&key).map(|value| value.revision),
            expected_revision,
        )?;
        state.exports.insert(
            key,
            ExportAuthority {
                revision: next,
                access,
            },
        );
        Ok(next)
    }

    fn set_subject_grant(
        &self,
        expected_revision: Option<u64>,
        grant: SubjectGrant,
    ) -> Result<u64, FederationError> {
        grant.validate(self.local_node)?;
        let mut state = self.lock()?;
        if !state.peers.contains_key(&grant.presenter) {
            return Err(FederationError::NotFound);
        }
        let stream = state
            .streams
            .get(&grant.stream)
            .ok_or(FederationError::NotFound)?;
        let floor = match grant.history {
            GrantHistory::All => 0,
            GrantHistory::FromGrant => stream.head.map_or(0, Position::sequence),
        };
        let key = (grant.subject.clone(), grant.presenter, grant.stream);
        let revision = next_revision(
            state.subject_grants.get(&key).map(|row| row.revision),
            expected_revision,
        )?;
        state.subject_grants.insert(
            key,
            SubjectGrantRow {
                revision,
                grant,
                floor,
            },
        );
        Ok(revision)
    }

    fn subject_grant(
        &self,
        subject: &HostedSubject,
        presenter: FederationNodeId,
        stream: StreamRef,
    ) -> Result<Option<SubjectGrantEntry>, FederationError> {
        Ok(self
            .lock()?
            .subject_grants
            .get(&(subject.clone(), presenter, stream))
            .map(|row| SubjectGrantEntry {
                grant: row.grant.clone(),
                revision: row.revision,
                history_floor: row.floor,
            }))
    }

    fn scan_subject_grants(
        &self,
        after: Option<&SubjectGrantKey>,
        max: usize,
    ) -> Result<Vec<SubjectGrantEntry>, FederationError> {
        if max == 0 || max > 256 {
            return Err(FederationError::Invalid("invalid subject grant page size"));
        }
        let after = after.map(SubjectGrantKey::encoded).transpose()?;
        let state = self.lock()?;
        let mut entries = state
            .subject_grants
            .values()
            .map(|row| {
                let entry = SubjectGrantEntry {
                    grant: row.grant.clone(),
                    revision: row.revision,
                    history_floor: row.floor,
                };
                Ok((SubjectGrantKey::from_grant(&entry.grant).encoded()?, entry))
            })
            .collect::<Result<Vec<_>, FederationError>>()?;
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Ok(entries
            .into_iter()
            .filter(|(key, _)| after.as_ref().is_none_or(|after| key > after))
            .take(max)
            .map(|(_, entry)| entry)
            .collect())
    }

    fn declare_stream(&self, spec: StreamSpec) -> Result<(), FederationError> {
        if spec.stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        match state.streams.get(&spec.stream) {
            Some(existing) if existing.spec == spec => Ok(()),
            Some(_) => Err(FederationError::Conflict),
            None => {
                state.streams.insert(
                    spec.stream,
                    PublishedStream {
                        spec,
                        records: VecDeque::new(),
                        requests: HashMap::new(),
                        retry_epoch: 1,
                        head: None,
                        minimum_available: 1,
                        retired_through: None,
                    },
                );
                Ok(())
            }
        }
    }

    fn append_published(&self, request: PublishRequest) -> Result<Record, FederationError> {
        if request.stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let State {
            streams,
            publish_id_count,
            publish_id_limit,
            ..
        } = &mut *state;
        let stream = streams
            .get_mut(&request.stream)
            .ok_or(FederationError::NotFound)?;
        if request.retry_epoch == 0 || request.retry_epoch != stream.retry_epoch {
            return Err(FederationError::Conflict);
        }
        if let Some(position) = stream
            .requests
            .get(&(request.retry_epoch, request.publish_id))
        {
            let sequence = position.sequence();
            if sequence < stream.minimum_available {
                return Err(FederationError::Indeterminate);
            }
            let index = sequence
                .checked_sub(stream.minimum_available)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or(FederationError::Corrupt)?;
            let record = stream.records.get(index).ok_or(FederationError::Corrupt)?;
            return if request.matches_record(record) {
                Ok(record.clone())
            } else {
                Err(FederationError::Conflict)
            };
        }
        if *publish_id_count >= *publish_id_limit {
            return Err(FederationError::Capacity);
        }
        let sequence = stream
            .head
            .map_or(Some(1), |head| head.sequence().checked_add(1))
            .ok_or(FederationError::Capacity)?;
        let publish_id = request.publish_id;
        let retry_epoch = request.retry_epoch;
        let record = Record::new(request.into_parts(sequence))?;
        stream.head = Some(record.position());
        stream.records.push_back(record.clone());
        stream
            .requests
            .insert((retry_epoch, publish_id), record.position());
        *publish_id_count += 1;
        Ok(record)
    }

    fn publication_epoch(&self, stream: StreamRef) -> Result<u64, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        self.lock()?
            .streams
            .get(&stream)
            .map(|row| row.retry_epoch)
            .ok_or(FederationError::NotFound)
    }

    fn close_publication_epoch(
        &self,
        stream: StreamRef,
        expected: u64,
    ) -> Result<u64, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let row = state
            .streams
            .get_mut(&stream)
            .ok_or(FederationError::NotFound)?;
        if expected == 0 || expected != row.retry_epoch {
            return Err(FederationError::Conflict);
        }
        row.retry_epoch = expected.checked_add(1).ok_or(FederationError::Capacity)?;
        Ok(row.retry_epoch)
    }

    fn inspect_publication(
        &self,
        stream: StreamRef,
        retry_epoch: u64,
        publish_id: RequestId,
    ) -> Result<Option<Position>, FederationError> {
        if stream.publisher != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let state = self.lock()?;
        let row = state
            .streams
            .get(&stream)
            .ok_or(FederationError::NotFound)?;
        if retry_epoch == 0 || retry_epoch > row.retry_epoch {
            return Err(FederationError::Conflict);
        }
        Ok(row.requests.get(&(retry_epoch, publish_id)).copied())
    }

    fn retire_publication_identities(
        &self,
        receipts: &[PublicationReceipt],
    ) -> Result<usize, FederationError> {
        if receipts.len() > crate::MAX_PUBLICATION_RETIRE_IDS {
            return Err(FederationError::Capacity);
        }
        let mut state = self.lock()?;
        for receipt in receipts {
            if receipt.stream.publisher != self.local_node {
                return Err(FederationError::Unauthorized);
            }
            let row = state
                .streams
                .get(&receipt.stream)
                .ok_or(FederationError::NotFound)?;
            if receipt.retry_epoch == 0
                || receipt.retry_epoch >= row.retry_epoch
                || row
                    .requests
                    .get(&(receipt.retry_epoch, receipt.publish_id))
                    .is_some_and(|position| *position != receipt.position)
            {
                return Err(FederationError::Conflict);
            }
        }
        let mut removed = 0;
        for receipt in receipts {
            let row = state
                .streams
                .get_mut(&receipt.stream)
                .ok_or(FederationError::Corrupt)?;
            removed += usize::from(
                row.requests
                    .remove(&(receipt.retry_epoch, receipt.publish_id))
                    .is_some(),
            );
        }
        state.publish_id_count = state
            .publish_id_count
            .checked_sub(removed)
            .ok_or(FederationError::Corrupt)?;
        Ok(removed)
    }

    fn retire_published_history(
        &self,
        stream: StreamRef,
        through: Position,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError> {
        let mut state = self.lock()?;
        replication::retire_explicit(&mut state, self.local_node, stream, through, max_records)
    }

    fn open(&self, request: OpenRequest) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.open_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    fn open_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.stream.publisher != self.local_node
            || request.authenticated_subscriber != request.subscription.subscriber
        {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        if state
            .close_requests
            .contains_key(&(request.authenticated_subscriber, request.request_id))
        {
            return Err(FederationError::Conflict);
        }
        if let Some(previous) = state
            .open_requests
            .get(&(request.authenticated_subscriber, request.request_id))
        {
            let existing = state
                .published_subscriptions
                .get(&previous.subscription)
                .ok_or(FederationError::Corrupt)?;
            if existing.request != request || existing.subject != subject {
                return Err(FederationError::Conflict);
            }
            let (current, _) = subject_authority(
                &state,
                &subject,
                request.authenticated_subscriber,
                previous.stream,
                &previous.export,
                now_ms,
            )?;
            return if current == previous.publisher_authority {
                Ok(previous.clone())
            } else {
                Err(FederationError::Conflict)
            };
        }
        let spec = &state
            .streams
            .get(&request.stream)
            .ok_or(FederationError::NotFound)?
            .spec;
        let stream = state
            .streams
            .get(&request.stream)
            .ok_or(FederationError::Corrupt)?;
        let (current, floor) = subject_authority(
            &state,
            &subject,
            request.authenticated_subscriber,
            request.stream,
            &spec.export,
            now_ms,
        )?;
        let start = match request.history {
            HistoryStart::All if floor == 0 && stream.minimum_available > 1 => {
                return Err(FederationError::ResyncRequired {
                    minimum_available: stream.minimum_available,
                });
            }
            HistoryStart::All => None,
            HistoryStart::After(position) => {
                if position.sequence() < floor {
                    return Err(FederationError::Unauthorized);
                }
                stream.at(position)?;
                Some(position)
            }
            HistoryStart::FromNow => stream.head,
        };
        let start = match start {
            Some(start) if start.sequence() >= floor => Some(start),
            _ if floor == 0 => None,
            _ if floor < stream.minimum_available.saturating_sub(1) => {
                return Err(FederationError::ResyncRequired {
                    minimum_available: stream.minimum_available,
                });
            }
            _ if floor == stream.minimum_available.saturating_sub(1) => stream.retired_through,
            _ => stream
                .records
                .get(
                    usize::try_from(floor - stream.minimum_available)
                        .map_err(|_error| FederationError::Capacity)?,
                )
                .map(Record::position)
                .ok_or(FederationError::Corrupt)
                .map(Some)?,
        };
        if state
            .published_subscriptions
            .contains_key(&request.subscription)
        {
            return Err(FederationError::Conflict);
        }
        let control = *state
            .control_revisions
            .get(&request.authenticated_subscriber)
            .unwrap_or(&0);
        if request
            .expected_control_revision
            .is_some_and(|expected| expected != control)
        {
            return Err(FederationError::Conflict);
        }
        let next = control.checked_add(1).ok_or(FederationError::Capacity)?;
        let result = OpenResult {
            request_id: request.request_id,
            subscription: request.subscription,
            stream: request.stream,
            export: spec.export.clone(),
            publisher_authority: current,
            subscription_revision: next,
            start,
        };
        state
            .control_revisions
            .insert(request.authenticated_subscriber, next);
        state.open_requests.insert(
            (request.authenticated_subscriber, request.request_id),
            result.clone(),
        );
        state.published_subscriptions.insert(
            request.subscription,
            PublishedSubscription {
                request,
                subject,
                result: result.clone(),
                acknowledged: None,
                closed_revision: None,
            },
        );
        Ok(result)
    }

    fn inspect_subscription(
        &self,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.inspect_subscription_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    fn inspect_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber {
            return Err(FederationError::Unauthorized);
        }
        let state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        let subscription = state
            .published_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        if subscription.subject != subject {
            return Err(FederationError::Unauthorized);
        }
        let opened = &subscription.result;
        let (current, _) = subject_authority(
            &state,
            &subject,
            request.authenticated_subscriber,
            opened.stream,
            &opened.export,
            now_ms,
        )?;
        if current != opened.publisher_authority {
            return Err(FederationError::Conflict);
        }
        let stream = state
            .streams
            .get(&opened.stream)
            .ok_or(FederationError::Corrupt)?;
        Ok(SubscriptionInspection {
            subscription: request.subscription,
            stream: opened.stream,
            export: opened.export.clone(),
            subscription_revision: subscription
                .closed_revision
                .unwrap_or(opened.subscription_revision),
            start: opened.start,
            acknowledged: subscription.acknowledged,
            head: stream.head,
            minimum_available: stream.minimum_available.max(
                opened
                    .start
                    .map_or(1, |start| start.sequence().saturating_add(1)),
            ),
            closed: subscription.closed_revision.is_some(),
        })
    }

    fn close_subscription(
        &self,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.close_subscription_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    fn close_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        if state
            .open_requests
            .contains_key(&(request.authenticated_subscriber, request.request_id))
        {
            return Err(FederationError::Conflict);
        }
        let subscription = state
            .published_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        if subscription.subject != subject {
            return Err(FederationError::Unauthorized);
        }
        let (current, _) = subject_authority(
            &state,
            &subject,
            request.authenticated_subscriber,
            subscription.result.stream,
            &subscription.result.export,
            now_ms,
        )?;
        if current != subscription.result.publisher_authority {
            return Err(FederationError::Conflict);
        }
        if let Some((previous, result)) = state
            .close_requests
            .get(&(request.authenticated_subscriber, request.request_id))
        {
            return if *previous == request {
                Ok(*result)
            } else {
                Err(FederationError::Conflict)
            };
        }
        if subscription.closed_revision.is_some()
            || request
                .expected_subscription_revision
                .is_some_and(|revision| revision != subscription.result.subscription_revision)
        {
            return Err(FederationError::Conflict);
        }
        let control = *state
            .control_revisions
            .get(&request.authenticated_subscriber)
            .unwrap_or(&0);
        let next = control.checked_add(1).ok_or(FederationError::Capacity)?;
        let result = CloseSubscriptionResult {
            request_id: request.request_id,
            subscription: request.subscription,
            subscription_revision: next,
        };
        state
            .control_revisions
            .insert(request.authenticated_subscriber, next);
        state
            .published_subscriptions
            .get_mut(&request.subscription)
            .ok_or(FederationError::Corrupt)?
            .closed_revision = Some(next);
        state.close_requests.insert(
            (request.authenticated_subscriber, request.request_id),
            (request, result),
        );
        Ok(result)
    }

    fn install_subscription(
        &self,
        request: InstallSubscriptionRequest,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        let opened = request.opened;
        if opened.subscription.subscriber != self.local_node
            || opened.stream.publisher != request.authenticated_publisher
            || opened.subscription_revision == 0
        {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let current = authority(
            &state,
            request.authenticated_publisher,
            &opened.export,
            false,
        )?;
        if let Some(existing) = state.received_subscriptions.get(&opened.subscription) {
            return if existing.opened == opened && existing.local_authority == current {
                Ok(opened)
            } else {
                Err(FederationError::Conflict)
            };
        }
        state.received_subscriptions.insert(
            opened.subscription,
            ReceivedSubscription {
                opened: opened.clone(),
                local_authority: current,
                inbox: VecDeque::new(),
                received: None,
                projected: None,
                retired_through: None,
            },
        );
        Ok(opened)
    }

    fn read(&self, request: ReadRequest) -> Result<ReadPage, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.read_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    fn read_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.max_records == 0
            || request.max_bytes == 0
        {
            return Err(FederationError::Invalid("invalid read request"));
        }
        let state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        let subscription = state
            .published_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        if subscription.subject != subject {
            return Err(FederationError::Unauthorized);
        }
        if subscription.closed_revision.is_some() {
            return Err(FederationError::Conflict);
        }
        let (current, _) = subject_authority(
            &state,
            &subject,
            request.authenticated_subscriber,
            subscription.result.stream,
            &subscription.result.export,
            now_ms,
        )?;
        if current != subscription.result.publisher_authority {
            return Err(FederationError::Conflict);
        }
        let stream = state
            .streams
            .get(&subscription.result.stream)
            .ok_or(FederationError::Corrupt)?;
        if request.after.is_some_and(|after| {
            subscription
                .result
                .start
                .is_some_and(|baseline| after.sequence() < baseline.sequence())
        }) {
            return Err(FederationError::Unauthorized);
        }
        let after = request.after.or(subscription.result.start);
        let first = match after {
            Some(position) => {
                stream.at(position)?;
                position
                    .sequence()
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?
            }
            None => 1,
        };
        if first < stream.minimum_available {
            return Err(FederationError::ResyncRequired {
                minimum_available: stream.minimum_available,
            });
        }
        let offset = usize::try_from(first - stream.minimum_available)
            .map_err(|_error| FederationError::Capacity)?;
        let head = stream.head;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for record in stream.records.iter().skip(offset).take(request.max_records) {
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)?;
            if next > request.max_bytes {
                if records.is_empty() {
                    return Err(FederationError::Capacity);
                }
                break;
            }
            bytes = next;
            records.push(record.clone());
        }
        Ok(ReadPage {
            records,
            head,
            minimum_available: stream.minimum_available.max(
                subscription
                    .result
                    .start
                    .map_or(1, |position| position.sequence().saturating_add(1)),
            ),
        })
    }

    fn accept(&self, request: AcceptRequest) -> Result<AcceptResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        if request.subscription.subscriber != self.local_node
            || request.record.stream().publisher != request.authenticated_publisher
        {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let existing = state
            .received_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        let current = authority(
            &state,
            request.authenticated_publisher,
            &existing.opened.export,
            false,
        )?;
        if current != existing.local_authority {
            return Err(FederationError::Conflict);
        }
        let subscription = state
            .received_subscriptions
            .get_mut(&request.subscription)
            .ok_or(FederationError::Corrupt)?;
        if request.record.stream() != subscription.opened.stream {
            return Err(FederationError::Conflict);
        }
        let expected = subscription
            .received
            .or(subscription.opened.start)
            .map_or(Some(1), |position| position.sequence().checked_add(1))
            .ok_or(FederationError::Capacity)?;
        if subscription
            .opened
            .start
            .is_some_and(|start| request.record.sequence() <= start.sequence())
        {
            return Err(FederationError::Conflict);
        }
        if request.record.sequence() < expected {
            let position = request.record.position();
            if subscription
                .retired_through
                .is_some_and(|retired| position.sequence() <= retired.sequence())
                && subscription.retired_through != Some(position)
            {
                return Err(FederationError::Indeterminate);
            }
            subscription.at(position)?;
            return Ok(AcceptResult {
                position: subscription.received.ok_or(FederationError::Corrupt)?,
                newly_accepted: false,
            });
        }
        if request.record.sequence() != expected {
            return Err(FederationError::Gap {
                expected,
                received: request.record.sequence(),
            });
        }
        let position = request.record.position();
        subscription.inbox.push_back(request.record);
        subscription.received = Some(position);
        Ok(AcceptResult {
            position,
            newly_accepted: true,
        })
    }

    fn read_inbox(&self, request: InboxReadRequest) -> Result<InboxReadPage, FederationError> {
        if request.subscription.subscriber != self.local_node
            || request.max_records == 0
            || request.max_records > 256
            || request.max_bytes == 0
            || request.max_bytes > 4 * 1024 * 1024
        {
            return Err(FederationError::Capacity);
        }
        let state = self.lock()?;
        let subscription = state
            .received_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        let opened = &subscription.opened;
        if opened.stream != request.expected_stream {
            return Err(FederationError::Conflict);
        }
        let current = authority(&state, opened.stream.publisher, &opened.export, false)?;
        if current != subscription.local_authority {
            return Err(FederationError::Conflict);
        }
        let baseline = opened.start;
        if let Some(after) = request.after {
            if baseline.is_some_and(|start| after.sequence() < start.sequence()) {
                return Err(FederationError::Unauthorized);
            }
            subscription.at(after)?;
        }
        let after = request.after.or(subscription.retired_through).or(baseline);
        let first = after.map_or(Some(1), |after| after.sequence().checked_add(1));
        let first_retained = subscription.first_retained()?;
        let offset = match first {
            Some(first) => first
                .checked_sub(first_retained)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or(FederationError::ResyncRequired {
                    minimum_available: first_retained,
                })?,
            None => subscription.inbox.len(),
        };
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for record in subscription
            .inbox
            .iter()
            .skip(offset)
            .take(request.max_records)
        {
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)?;
            if next > request.max_bytes {
                if records.is_empty() {
                    return Err(FederationError::Capacity);
                }
                break;
            }
            bytes = next;
            records.push(record.clone());
        }
        Ok(InboxReadPage {
            opened: opened.clone(),
            received: subscription.received,
            projected: subscription.projected,
            records,
        })
    }

    fn acknowledge(&self, request: AcknowledgeRequest) -> Result<Position, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.acknowledge_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    fn acknowledge_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let now_ms = self.decision_time(&state, now_ms);
        let existing = state
            .published_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        if existing.subject != subject {
            return Err(FederationError::Unauthorized);
        }
        if existing.closed_revision.is_some()
            || existing
                .result
                .start
                .is_some_and(|start| request.position.sequence() <= start.sequence())
        {
            return Err(FederationError::Conflict);
        }
        let (current, _) = subject_authority(
            &state,
            &subject,
            request.authenticated_subscriber,
            existing.result.stream,
            &existing.result.export,
            now_ms,
        )?;
        if current != existing.result.publisher_authority {
            return Err(FederationError::Conflict);
        }
        let stream = state
            .streams
            .get(&existing.result.stream)
            .ok_or(FederationError::Corrupt)?;
        stream.at(request.position)?;
        let subscription = state
            .published_subscriptions
            .get_mut(&request.subscription)
            .ok_or(FederationError::Corrupt)?;
        if subscription
            .acknowledged
            .is_none_or(|current| request.position.sequence() > current.sequence())
        {
            subscription.acknowledged = Some(request.position);
        }
        subscription.acknowledged.ok_or(FederationError::Corrupt)
    }

    fn record_projection_progress(
        &self,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError> {
        if request.subscription.subscriber != self.local_node {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let existing = state
            .received_subscriptions
            .get(&request.subscription)
            .ok_or(FederationError::NotFound)?;
        let current = authority(
            &state,
            existing.opened.stream.publisher,
            &existing.opened.export,
            false,
        )?;
        if current != existing.local_authority {
            return Err(FederationError::Conflict);
        }
        let subscription = state
            .received_subscriptions
            .get_mut(&request.subscription)
            .ok_or(FederationError::Corrupt)?;
        if subscription
            .retired_through
            .is_some_and(|retired| request.position.sequence() <= retired.sequence())
            && subscription.retired_through != Some(request.position)
        {
            return Err(FederationError::Indeterminate);
        }
        subscription.at(request.position)?;
        let expected = subscription.projected.map_or(
            subscription
                .opened
                .start
                .map_or(1, |start| start.sequence().saturating_add(1)),
            |current| current.sequence().saturating_add(1),
        );
        if request.position.sequence() > expected {
            return Err(FederationError::Gap {
                expected,
                received: request.position.sequence(),
            });
        }
        if subscription
            .projected
            .is_none_or(|current| request.position.sequence() > current.sequence())
        {
            subscription.projected = Some(request.position);
        }
        subscription.projected.ok_or(FederationError::Corrupt)
    }

    fn retire_projected_inbox(
        &self,
        subscription: SubscriptionRef,
        max_records: usize,
    ) -> Result<InboxRetirement, FederationError> {
        if subscription.subscriber != self.local_node
            || max_records == 0
            || max_records > MAX_RETIRE_RECORDS
        {
            return Err(FederationError::Capacity);
        }
        let mut state = self.lock()?;
        let row = state
            .received_subscriptions
            .get_mut(&subscription)
            .ok_or(FederationError::NotFound)?;
        let first = row.first_retained()?;
        let eligible = row
            .projected
            .map(|position| position.sequence())
            .and_then(|projected| projected.checked_sub(first))
            .and_then(|distance| distance.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(0)
            .min(max_records);
        let mut count = 0usize;
        let mut bytes = 0usize;
        for record in row.inbox.iter().take(eligible) {
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)?;
            if next > MAX_RETIRE_BYTES {
                break;
            }
            bytes = next;
            count += 1;
        }
        if eligible > 0 && count == 0 {
            return Err(FederationError::Capacity);
        }
        let mut retired = row.retired_through;
        for _ in 0..count {
            let record = row.inbox.pop_front().ok_or(FederationError::Corrupt)?;
            retired = Some(record.position());
        }
        row.retired_through = retired;
        Ok(InboxRetirement {
            subscription,
            received: row.received,
            projected: row.projected,
            retired_through: retired,
            removed: count,
        })
    }
}
