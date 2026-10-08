//! Private, same-database authority and delivery state for node federation.

mod call;
mod invite;
mod management;
mod object;
mod public;
pub(crate) mod publication;
mod receive;
mod replication;
mod snapshot;

use crate::database::{Database, WriteTransaction};
use std::num::NonZeroUsize;
use std::sync::Arc;

use redb::{Durability, ReadTransaction, ReadableTable, ReadableTableMetadata};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    AcceptRequest, AcceptResult, AcknowledgeRequest, AuthorityRevision, CloseSubscriptionRequest,
    CloseSubscriptionResult, Digest, EventRef, EventType, ExportAccess, ExportName,
    FederationError, FederationGuestStore, FederationNodeId, FederationStore, FederationSubject,
    GrantHistory, HistoryStart, HostedSubject, InboxReadPage, InboxReadRequest, InboxRetirement,
    InspectSubscriptionRequest, InstallSubscriptionRequest, MAX_RETIRE_BYTES, MAX_RETIRE_RECORDS,
    OpenRequest, OpenResult, PeerAdmission, Position, ProjectionProgress, PublicationReceipt,
    PublishRequest, PublishedRetirement, ReadPage, ReadRequest, Record, RecordParts, RequestId,
    SchemaRevision, StreamId, StreamRef, StreamSpec, SubjectGrant, SubjectGrantEntry,
    SubjectGrantKey, SubjectIssuerId, SubscriptionId, SubscriptionInspection, SubscriptionRef,
    VerifiedFederationPeerProof,
};

use crate::schema::{
    FEDERATION_ADMISSIONS_TABLE, FEDERATION_CONTROL_REQUESTS_TABLE, FEDERATION_EXPORTS_TABLE,
    FEDERATION_GUEST_CONTROLS_TABLE, FEDERATION_INBOX_TABLE, FEDERATION_INVITATIONS_TABLE,
    FEDERATION_INVITE_ISSUERS_TABLE, FEDERATION_INVITE_RECEIPTS_TABLE, FEDERATION_NODE_TABLE,
    FEDERATION_OBJECT_GRANTS_TABLE, FEDERATION_OBJECT_RECEIVE_GC_FENCES_TABLE,
    FEDERATION_OBJECT_RECEIVE_INDEX_TABLE, FEDERATION_OBJECT_RECEIVES_TABLE,
    FEDERATION_OBJECT_SEND_TRANSFERS_TABLE, FEDERATION_PEERS_TABLE,
    FEDERATION_PUBLIC_STREAMS_TABLE, FEDERATION_PUBLISH_REQUESTS_TABLE, FEDERATION_RECORDS_TABLE,
    FEDERATION_REPLICA_MEMBERS_TABLE, FEDERATION_SNAPSHOT_INSTALLS_TABLE,
    FEDERATION_SNAPSHOT_OFFER_PINS_TABLE, FEDERATION_SNAPSHOT_OFFERS_TABLE,
    FEDERATION_SNAPSHOT_RECEIPTS_TABLE, FEDERATION_STREAMS_TABLE, FEDERATION_SUBJECT_GRANTS_TABLE,
    FEDERATION_SUBSCRIPTIONS_TABLE,
};

const LOCAL_NODE_KEY: &str = "local_node";
const PUBLISH_ID_LIMIT_KEY: &str = "publish_id_limit";
const KERNEL_CALL_NAMESPACE_KEY: &str = "kernel_call_namespace";
const TRUSTED_TIME_KEY: &str = "trusted_time_high_water_ms";
const NODE_ID_LEN: usize = FederationNodeId::LEN;
const DIGEST_LEN: usize = Digest::LEN;
const STREAM_KEY_LEN: usize = NODE_ID_LEN + 16;
const RECORD_KEY_LEN: usize = STREAM_KEY_LEN + 8;
const REQUEST_KEY_LEN: usize = STREAM_KEY_LEN + 8 + 16;
const MAX_ROW_BYTES: usize = 16 * 1024;
const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum AccessPath {
    Managed,
    Guest,
}

// Serde only implements fixed-size array traits through length 32. Keep the
// JSON representation as a fixed sequence and reject truncated/extra bytes.
mod fixed_bytes_48 {
    use std::fmt;

    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(48)?;
        for byte in bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 48], D::Error> {
        struct Bytes48;

        impl<'de> Visitor<'de> for Bytes48 {
            type Value = [u8; 48];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 48 bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = [0; 48];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(49, &self));
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_tuple(48, Bytes48)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRow {
    revision: u64,
    enabled: bool,
    control_revision: u64,
    manifest_owned: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAuthorizationDigest {
    #[serde(with = "fixed_bytes_48")]
    bytes: [u8; DIGEST_LEN],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRow {
    revision: u64,
    minimum_online_generation: u64,
    allowed_authorization_digests: Vec<StoredAuthorizationDigest>,
}

impl AdmissionRow {
    fn policy(&self) -> Result<PeerAdmission, FederationError> {
        if self.revision == 0 {
            return Err(FederationError::Corrupt);
        }
        let policy = PeerAdmission {
            minimum_online_generation: self.minimum_online_generation,
            allowed_authorization_digests: self
                .allowed_authorization_digests
                .iter()
                .map(|digest| digest.bytes)
                .collect(),
        };
        policy
            .validate()
            .map_err(|_error| FederationError::Corrupt)?;
        Ok(policy)
    }

    fn new(revision: u64, policy: PeerAdmission) -> Self {
        Self {
            revision,
            minimum_online_generation: policy.minimum_online_generation,
            allowed_authorization_digests: policy
                .allowed_authorization_digests
                .into_iter()
                .map(|bytes| StoredAuthorizationDigest { bytes })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRow {
    revision: u64,
    serve: bool,
    receive: bool,
    manifest_owned: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectGrantRow {
    revision: u64,
    enabled: bool,
    not_before_ms: u64,
    expires_ms: u64,
    from_grant: bool,
    floor: u64,
    #[serde(default)]
    invitation: Option<[u8; 16]>,
}

impl SubjectGrantRow {
    fn validate(&self) -> Result<(), FederationError> {
        if self.revision == 0
            || self.not_before_ms >= self.expires_ms
            || (!self.from_grant && self.floor != 0)
            || self.invitation == Some([0; 16])
        {
            return Err(FederationError::Corrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum StoredFederationSubject {
    Node(#[serde(with = "fixed_bytes_48")] [u8; NODE_ID_LEN]),
    Hosted {
        #[serde(with = "fixed_bytes_48")]
        issuer: [u8; NODE_ID_LEN],
        namespace: String,
        subject: String,
    },
}

impl From<&FederationSubject> for StoredFederationSubject {
    fn from(value: &FederationSubject) -> Self {
        match value {
            FederationSubject::Node(node) => Self::Node(*node.as_bytes()),
            FederationSubject::Hosted(hosted) => Self::Hosted {
                issuer: hosted.issuer.as_bytes(),
                namespace: hosted.namespace.clone(),
                subject: hosted.subject.clone(),
            },
        }
    }
}

impl From<StoredFederationSubject> for FederationSubject {
    fn from(value: StoredFederationSubject) -> Self {
        match value {
            StoredFederationSubject::Node(node) => Self::Node(FederationNodeId::from_bytes(node)),
            StoredFederationSubject::Hosted {
                issuer,
                namespace,
                subject,
            } => Self::Hosted(HostedSubject {
                issuer: SubjectIssuerId::from_bytes(issuer),
                namespace,
                subject,
            }),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPosition {
    sequence: u64,
    #[serde(with = "fixed_bytes_48")]
    digest: [u8; DIGEST_LEN],
}

impl From<Position> for StoredPosition {
    fn from(value: Position) -> Self {
        Self {
            sequence: value.sequence(),
            digest: *value.digest().as_bytes(),
        }
    }
}

impl TryFrom<StoredPosition> for Position {
    type Error = FederationError;

    fn try_from(value: StoredPosition) -> Result<Self, Self::Error> {
        Position::new(value.sequence, Digest::from_bytes(value.digest))
            .map_err(|_error| FederationError::Corrupt)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamRow {
    export: String,
    retry_epoch: u64,
    head: Option<StoredPosition>,
    minimum_available: u64,
    #[serde(default)]
    retired_through: Option<StoredPosition>,
}

impl StreamRow {
    fn validate(&self) -> Result<(), FederationError> {
        if self.retry_epoch == 0
            || self.minimum_available == 0
            || self
                .retired_through
                .map_or(self.minimum_available != 1, |retired| {
                    retired.sequence == 0
                        || retired.sequence.checked_add(1) != Some(self.minimum_available)
                        || self
                            .head
                            .is_none_or(|head| retired.sequence > head.sequence)
                })
        {
            return Err(FederationError::Corrupt);
        }
        match self.head {
            None if self.minimum_available != 1 => Err(FederationError::Corrupt),
            Some(head)
                if head.sequence == 0
                    || self.minimum_available > head.sequence.saturating_add(1) =>
            {
                Err(FederationError::Corrupt)
            }
            _ => Ok(()),
        }
    }

    /// True means the exact cursor is the digest-only retirement anchor.
    fn verify_retired_cursor(&self, cursor: Position) -> Result<bool, FederationError> {
        if cursor.sequence() >= self.minimum_available {
            return Ok(false);
        }
        let anchor = self.retired_through.map(Position::try_from).transpose()?;
        if anchor.is_some_and(|anchor| anchor.sequence() == cursor.sequence()) {
            return if anchor == Some(cursor) {
                Ok(true)
            } else {
                Err(FederationError::Conflict)
            };
        }
        Err(FederationError::ResyncRequired {
            minimum_available: self.minimum_available,
        })
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredStreamRef {
    #[serde(with = "fixed_bytes_48")]
    publisher: [u8; NODE_ID_LEN],
    id: [u8; 16],
}

impl From<StreamRef> for StoredStreamRef {
    fn from(value: StreamRef) -> Self {
        Self {
            publisher: *value.publisher.as_bytes(),
            id: *value.id.as_bytes(),
        }
    }
}

impl From<StoredStreamRef> for StreamRef {
    fn from(value: StoredStreamRef) -> Self {
        Self {
            publisher: FederationNodeId::from_bytes(value.publisher),
            id: StreamId::from_bytes(value.id),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSubscriptionRef {
    #[serde(with = "fixed_bytes_48")]
    subscriber: [u8; NODE_ID_LEN],
    id: [u8; 16],
}

impl From<SubscriptionRef> for StoredSubscriptionRef {
    fn from(value: SubscriptionRef) -> Self {
        Self {
            subscriber: *value.subscriber.as_bytes(),
            id: *value.id.as_bytes(),
        }
    }
}

impl From<StoredSubscriptionRef> for SubscriptionRef {
    fn from(value: StoredSubscriptionRef) -> Self {
        Self {
            subscriber: FederationNodeId::from_bytes(value.subscriber),
            id: SubscriptionId::from_bytes(value.id),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAuthorityRevision {
    peer: u64,
    export: u64,
}

impl From<AuthorityRevision> for StoredAuthorityRevision {
    fn from(value: AuthorityRevision) -> Self {
        Self {
            peer: value.peer,
            export: value.export,
        }
    }
}

impl From<StoredAuthorityRevision> for AuthorityRevision {
    fn from(value: StoredAuthorityRevision) -> Self {
        Self {
            peer: value.peer,
            export: value.export,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOpenRequest {
    #[serde(with = "fixed_bytes_48")]
    authenticated_subscriber: [u8; NODE_ID_LEN],
    request_id: [u8; 16],
    subscription: StoredSubscriptionRef,
    stream: StoredStreamRef,
    expected_control_revision: Option<u64>,
    history: StoredHistoryStart,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum StoredHistoryStart {
    All,
    After(StoredPosition),
    FromNow,
}

impl From<HistoryStart> for StoredHistoryStart {
    fn from(value: HistoryStart) -> Self {
        match value {
            HistoryStart::All => Self::All,
            HistoryStart::After(position) => Self::After(position.into()),
            HistoryStart::FromNow => Self::FromNow,
        }
    }
}

impl TryFrom<StoredHistoryStart> for HistoryStart {
    type Error = FederationError;

    fn try_from(value: StoredHistoryStart) -> Result<Self, Self::Error> {
        Ok(match value {
            StoredHistoryStart::All => Self::All,
            StoredHistoryStart::After(position) => Self::After(position.try_into()?),
            StoredHistoryStart::FromNow => Self::FromNow,
        })
    }
}

impl From<&OpenRequest> for StoredOpenRequest {
    fn from(value: &OpenRequest) -> Self {
        Self {
            authenticated_subscriber: *value.authenticated_subscriber.as_bytes(),
            request_id: *value.request_id.as_bytes(),
            subscription: value.subscription.into(),
            stream: value.stream.into(),
            expected_control_revision: value.expected_control_revision,
            history: value.history.into(),
        }
    }
}

impl TryFrom<StoredOpenRequest> for OpenRequest {
    type Error = FederationError;

    fn try_from(value: StoredOpenRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            authenticated_subscriber: FederationNodeId::from_bytes(value.authenticated_subscriber),
            request_id: RequestId::from_bytes(value.request_id),
            subscription: value.subscription.into(),
            stream: value.stream.into(),
            expected_control_revision: value.expected_control_revision,
            history: value.history.try_into()?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOpenResult {
    request_id: [u8; 16],
    subscription: StoredSubscriptionRef,
    stream: StoredStreamRef,
    export: String,
    publisher_authority: StoredAuthorityRevision,
    subscription_revision: u64,
    start: Option<StoredPosition>,
}

impl From<&OpenResult> for StoredOpenResult {
    fn from(value: &OpenResult) -> Self {
        Self {
            request_id: *value.request_id.as_bytes(),
            subscription: value.subscription.into(),
            stream: value.stream.into(),
            export: value.export.as_str().to_owned(),
            publisher_authority: value.publisher_authority.into(),
            subscription_revision: value.subscription_revision,
            start: value.start.map(Into::into),
        }
    }
}

impl TryFrom<StoredOpenResult> for OpenResult {
    type Error = FederationError;

    fn try_from(value: StoredOpenResult) -> Result<Self, Self::Error> {
        if value.subscription_revision == 0
            || value.publisher_authority.peer == 0
            || value.publisher_authority.export == 0
        {
            return Err(FederationError::Corrupt);
        }
        Ok(Self {
            request_id: RequestId::from_bytes(value.request_id),
            subscription: value.subscription.into(),
            stream: value.stream.into(),
            export: ExportName::new(value.export).map_err(|_error| FederationError::Corrupt)?,
            publisher_authority: value.publisher_authority.into(),
            subscription_revision: value.subscription_revision,
            start: value.start.map(TryInto::try_into).transpose()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum SubscriptionRow {
    Publisher {
        request: Box<StoredOpenRequest>,
        opened: StoredOpenResult,
        #[serde(default)]
        subject: Option<StoredFederationSubject>,
        #[serde(default)]
        guest: bool,
        acknowledged: Option<StoredPosition>,
        closed_revision: Option<u64>,
    },
    Receiver {
        opened: StoredOpenResult,
        local_authority: StoredAuthorityRevision,
        received: Option<StoredPosition>,
        projected: Option<StoredPosition>,
        #[serde(default)]
        retired_through: Option<StoredPosition>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum ControlRequestRow {
    Open {
        subscription: StoredSubscriptionRef,
    },
    Close {
        request: StoredCloseRequest,
        result_revision: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCloseRequest {
    request_id: [u8; 16],
    subscription: StoredSubscriptionRef,
    expected_subscription_revision: Option<u64>,
}

impl From<CloseSubscriptionRequest> for StoredCloseRequest {
    fn from(value: CloseSubscriptionRequest) -> Self {
        Self {
            request_id: *value.request_id.as_bytes(),
            subscription: value.subscription.into(),
            expected_subscription_revision: value.expected_subscription_revision,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordHeader {
    publish_id: [u8; 16],
    event_type: String,
    schema_revision: [u8; 32],
    event_ref: Option<EventRefRow>,
    #[serde(with = "fixed_bytes_48")]
    digest: [u8; DIGEST_LEN],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventRefRow {
    #[serde(with = "fixed_bytes_48")]
    origin: [u8; NODE_ID_LEN],
    namespace: String,
    id: String,
}

fn encode_record(record: &Record) -> Result<Vec<u8>, FederationError> {
    if record.payload().len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(FederationError::Capacity);
    }
    let event_ref = record.event_ref().map(|reference| EventRefRow {
        origin: *reference.origin().as_bytes(),
        namespace: reference.namespace().to_owned(),
        id: reference.id().to_owned(),
    });
    let header = encode(&RecordHeader {
        publish_id: *record.publish_id().as_bytes(),
        event_type: record.event_type().as_str().to_owned(),
        schema_revision: *record.schema_revision().as_bytes(),
        event_ref,
        digest: *record.digest().as_bytes(),
    })?;
    let header_len = u32::try_from(header.len()).map_err(|_error| FederationError::Capacity)?;
    let capacity = 4usize
        .checked_add(header.len())
        .and_then(|size| size.checked_add(record.payload().len()))
        .ok_or(FederationError::Capacity)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&header_len.to_be_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(record.payload());
    Ok(bytes)
}

fn decode_record(
    stream: StreamRef,
    sequence: u64,
    bytes: &[u8],
) -> Result<Record, FederationError> {
    if bytes.len() > 4 + MAX_ROW_BYTES + MAX_RECORD_PAYLOAD_BYTES {
        return Err(FederationError::Corrupt);
    }
    let prefix = bytes.get(..4).ok_or(FederationError::Corrupt)?;
    let header_len = u32::from_be_bytes(
        prefix
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    if header_len > MAX_ROW_BYTES {
        return Err(FederationError::Corrupt);
    }
    let header_end = 4usize
        .checked_add(header_len)
        .ok_or(FederationError::Corrupt)?;
    let header = decode::<RecordHeader>(bytes.get(4..header_end).ok_or(FederationError::Corrupt)?)?;
    let payload = bytes.get(header_end..).ok_or(FederationError::Corrupt)?;
    if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(FederationError::Corrupt);
    }
    let event_ref = header
        .event_ref
        .map(|reference| {
            EventRef::new(
                FederationNodeId::from_bytes(reference.origin),
                reference.namespace,
                reference.id,
            )
        })
        .transpose()
        .map_err(|_error| FederationError::Corrupt)?;
    Record::from_parts(
        RecordParts {
            stream,
            sequence,
            publish_id: RequestId::from_bytes(header.publish_id),
            event_type: EventType::new(header.event_type)
                .map_err(|_error| FederationError::Corrupt)?,
            schema_revision: SchemaRevision::from_bytes(header.schema_revision),
            event_ref,
            payload: Arc::from(payload),
        },
        Digest::from_bytes(header.digest),
    )
    .map_err(|_error| FederationError::Corrupt)
}

fn stored_record_payload_bytes(bytes: &[u8]) -> Result<usize, FederationError> {
    if bytes.len() > 4 + MAX_ROW_BYTES + MAX_RECORD_PAYLOAD_BYTES {
        return Err(FederationError::Corrupt);
    }
    let header_len = bytes
        .get(..4)
        .and_then(|prefix| <[u8; 4]>::try_from(prefix).ok())
        .map(u32::from_be_bytes)
        .ok_or(FederationError::Corrupt)? as usize;
    if header_len > MAX_ROW_BYTES {
        return Err(FederationError::Corrupt);
    }
    bytes
        .len()
        .checked_sub(4 + header_len)
        .ok_or(FederationError::Corrupt)
}

fn stream_key(stream: StreamRef) -> [u8; STREAM_KEY_LEN] {
    let mut key = [0; STREAM_KEY_LEN];
    key[..NODE_ID_LEN].copy_from_slice(stream.publisher.as_bytes());
    key[NODE_ID_LEN..].copy_from_slice(stream.id.as_bytes());
    key
}

fn subscription_key(subscription: SubscriptionRef) -> [u8; STREAM_KEY_LEN] {
    let mut key = [0; STREAM_KEY_LEN];
    key[..NODE_ID_LEN].copy_from_slice(subscription.subscriber.as_bytes());
    key[NODE_ID_LEN..].copy_from_slice(subscription.id.as_bytes());
    key
}

fn export_key(peer: FederationNodeId, export: &ExportName) -> Vec<u8> {
    let mut key = Vec::with_capacity(NODE_ID_LEN + export.as_str().len());
    key.extend_from_slice(peer.as_bytes());
    key.extend_from_slice(export.as_str().as_bytes());
    key
}

fn subject_grant_key(
    subject: &HostedSubject,
    presenter: FederationNodeId,
    stream: StreamRef,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        48 + 2 + subject.namespace.len() + 2 + subject.subject.len() + 48 + STREAM_KEY_LEN,
    );
    key.extend_from_slice(&subject.issuer.as_bytes());
    key.extend_from_slice(&(subject.namespace.len() as u16).to_be_bytes());
    key.extend_from_slice(subject.namespace.as_bytes());
    key.extend_from_slice(&(subject.subject.len() as u16).to_be_bytes());
    key.extend_from_slice(subject.subject.as_bytes());
    key.extend_from_slice(presenter.as_bytes());
    key.extend_from_slice(&stream_key(stream));
    key
}

fn parse_subject_grant_key(mut remaining: &[u8]) -> Result<SubjectGrantKey, FederationError> {
    fn take<'a>(remaining: &mut &'a [u8], len: usize) -> Result<&'a [u8], FederationError> {
        if remaining.len() < len {
            return Err(FederationError::Corrupt);
        }
        let (head, tail) = remaining.split_at(len);
        *remaining = tail;
        Ok(head)
    }

    let original = remaining;
    let issuer = SubjectIssuerId::from_bytes(
        take(&mut remaining, NODE_ID_LEN)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let namespace_len = u16::from_be_bytes(
        take(&mut remaining, 2)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    let namespace = std::str::from_utf8(take(&mut remaining, namespace_len)?)
        .map_err(|_error| FederationError::Corrupt)?
        .to_owned();
    let subject_len = u16::from_be_bytes(
        take(&mut remaining, 2)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    let subject = std::str::from_utf8(take(&mut remaining, subject_len)?)
        .map_err(|_error| FederationError::Corrupt)?
        .to_owned();
    let presenter = FederationNodeId::from_bytes(
        take(&mut remaining, NODE_ID_LEN)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let publisher = FederationNodeId::from_bytes(
        take(&mut remaining, NODE_ID_LEN)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let id = StreamId::from_bytes(
        take(&mut remaining, 16)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    if !remaining.is_empty() {
        return Err(FederationError::Corrupt);
    }
    let key = SubjectGrantKey {
        subject: HostedSubject {
            issuer,
            namespace,
            subject,
        },
        presenter,
        stream: StreamRef { publisher, id },
    };
    if key.encoded().map_err(|_error| FederationError::Corrupt)? != original {
        return Err(FederationError::Corrupt);
    }
    Ok(key)
}

fn subject_grant_entry(
    row: SubjectGrantRow,
    key: SubjectGrantKey,
    local_node: FederationNodeId,
) -> Result<SubjectGrantEntry, FederationError> {
    row.validate()?;
    let grant = SubjectGrant {
        subject: key.subject,
        presenter: key.presenter,
        stream: key.stream,
        not_before_ms: row.not_before_ms,
        expires_ms: row.expires_ms,
        history: if row.from_grant {
            GrantHistory::FromGrant
        } else {
            GrantHistory::All
        },
        enabled: row.enabled,
    };
    grant
        .validate(local_node)
        .map_err(|_error| FederationError::Corrupt)?;
    Ok(SubjectGrantEntry {
        grant,
        revision: row.revision,
        history_floor: row.floor,
    })
}

fn record_key(stream: StreamRef, sequence: u64) -> [u8; RECORD_KEY_LEN] {
    let mut key = [0; RECORD_KEY_LEN];
    key[..STREAM_KEY_LEN].copy_from_slice(&stream_key(stream));
    key[STREAM_KEY_LEN..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn inbox_key(subscription: SubscriptionRef, sequence: u64) -> [u8; RECORD_KEY_LEN] {
    let mut key = [0; RECORD_KEY_LEN];
    key[..STREAM_KEY_LEN].copy_from_slice(&subscription_key(subscription));
    key[STREAM_KEY_LEN..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn publish_request_key(
    stream: StreamRef,
    retry_epoch: u64,
    request: RequestId,
) -> [u8; REQUEST_KEY_LEN] {
    let mut key = [0; REQUEST_KEY_LEN];
    key[..STREAM_KEY_LEN].copy_from_slice(&stream_key(stream));
    key[STREAM_KEY_LEN..STREAM_KEY_LEN + 8].copy_from_slice(&retry_epoch.to_be_bytes());
    key[STREAM_KEY_LEN + 8..].copy_from_slice(request.as_bytes());
    key
}

fn control_request_key(peer: FederationNodeId, request: RequestId) -> [u8; STREAM_KEY_LEN] {
    let mut key = [0; STREAM_KEY_LEN];
    key[..NODE_ID_LEN].copy_from_slice(peer.as_bytes());
    key[NODE_ID_LEN..].copy_from_slice(request.as_bytes());
    key
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, FederationError> {
    let bytes = serde_json::to_vec(value).map_err(storage)?;
    if bytes.len() > MAX_ROW_BYTES {
        return Err(FederationError::Capacity);
    }
    Ok(bytes)
}

fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, FederationError> {
    if bytes.len() > MAX_ROW_BYTES {
        return Err(FederationError::Corrupt);
    }
    serde_json::from_slice(bytes).map_err(|_error| FederationError::Corrupt)
}

/// Durable federation state bound to one stable local node identity.
#[derive(Clone)]
pub struct RedbFederationStore {
    db: Arc<Database>,
    node: FederationNodeId,
    decision: Option<xolotl_federation::FederationDecision>,
    local_clock: Option<Arc<dyn xolotl_federation::FederationObjectClock>>,
}

macro_rules! check_decision_rows {
    ($store:expr, $txn:expr, $now:expr) => {{
        let decision = $store.decision.as_ref().ok_or(FederationError::Corrupt)?;
        let peer = decision.peer();
        let peer_row = $txn
            .open_table(FEDERATION_PEERS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<PeerRow>(value.value()))
            .transpose()?;
        let admission = $txn
            .open_table(FEDERATION_ADMISSIONS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<AdmissionRow>(value.value()))
            .transpose()?
            .map(|row| row.policy())
            .transpose()?;
        let floor = $txn
            .open_table(FEDERATION_NODE_TABLE)
            .map_err(storage)?
            .get(TRUSTED_TIME_KEY)
            .map_err(storage)?
            .map(|value| decode_trusted_time(value.value()))
            .transpose()?
            .unwrap_or(0);
        if peer_row.as_ref().is_some_and(|row| row.revision == 0) {
            return Err(FederationError::Corrupt);
        }
        decision.check(
            peer_row.map(|row| row.enabled),
            admission.as_ref(),
            floor,
            $now,
        )?;
    }};
}

mod decision;
pub(crate) use decision::DecisionWrite;

impl RedbFederationStore {
    pub(crate) fn bound_view(
        db: Arc<Database>,
        node: FederationNodeId,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Self, FederationError> {
        Self {
            db,
            node,
            decision: None,
            local_clock: None,
        }
        .with_decision(decision)
    }
    /// Immutable remote view sharing the same database and commit domains.
    pub fn with_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Self, FederationError> {
        if self.decision.is_some() || decision.peer() == self.node {
            return Err(FederationError::Unauthorized);
        }
        Ok(Self {
            decision: Some(decision),
            ..self.clone()
        })
    }

    /// Bind a trusted clock for local decision reads and writes, sampled only
    /// after acquiring the database writer. This view lets a live Kernel bridge
    /// record its own receipts without treating a queued timestamp as current
    /// time. It supplies no remote authority and does not bypass rollback checks;
    /// remote operations still require their separate decision binding. Local
    /// receipt persistence remains possible after remote authority is revoked.
    /// Delivery authorization keeps its separate read-only clock/floor contract.
    /// The callback must be fast and must not reenter this database.
    pub(crate) fn with_local_clock(
        &self,
        clock: Arc<dyn xolotl_federation::FederationObjectClock>,
    ) -> Result<Self, FederationError> {
        if self.decision.is_some() || self.local_clock.is_some() {
            return Err(FederationError::Unauthorized);
        }
        Ok(Self {
            local_clock: Some(clock),
            ..self.clone()
        })
    }

    pub(crate) fn decision_peer(&self, peer: FederationNodeId) -> Result<(), FederationError> {
        self.decision
            .as_ref()
            .map_or(Ok(()), |decision| decision.check_peer(peer))
    }

    pub(crate) fn bind(
        db: Arc<Database>,
        node: FederationNodeId,
        publish_id_limit: NonZeroUsize,
    ) -> Result<Self, FederationError> {
        let mut txn = db.begin_write().map_err(storage)?;
        txn.set_durability(Durability::Immediate).map_err(storage)?;
        call::init_tables(&txn)?;
        let mut table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
        let saved = table
            .get(LOCAL_NODE_KEY)
            .map_err(storage)?
            .map(|value| {
                <[u8; NODE_ID_LEN]>::try_from(value.value())
                    .map_err(|_error| FederationError::Corrupt)
            })
            .transpose()?;
        match saved {
            Some(saved) if saved == *node.as_bytes() => {}
            Some(_) => return Err(FederationError::Conflict),
            None => {
                table
                    .insert(LOCAL_NODE_KEY, node.as_bytes().as_slice())
                    .map_err(storage)?;
            }
        }
        let publish_id_limit =
            u64::try_from(publish_id_limit.get()).map_err(|_error| FederationError::Capacity)?;
        table
            .insert(
                PUBLISH_ID_LIMIT_KEY,
                publish_id_limit.to_be_bytes().as_slice(),
            )
            .map_err(storage)?;
        let namespace = table
            .get(KERNEL_CALL_NAMESPACE_KEY)
            .map_err(storage)?
            .map(|value| {
                <[u8; 32]>::try_from(value.value()).map_err(|_error| FederationError::Corrupt)
            })
            .transpose()?;
        match namespace {
            Some(value) if value == [0; 32] => return Err(FederationError::Corrupt),
            Some(_) => {}
            None => {
                let mut namespace = [0; 32];
                getrandom::fill(&mut namespace).map_err(|_error| {
                    FederationError::Storage("operation namespace RNG unavailable".into())
                })?;
                if namespace == [0; 32] {
                    return Err(FederationError::Corrupt);
                }
                table
                    .insert(KERNEL_CALL_NAMESPACE_KEY, namespace.as_slice())
                    .map_err(storage)?;
            }
        }
        drop(table);
        txn.commit()
            .map_err(|_error| FederationError::Indeterminate)?;
        Ok(Self {
            db,
            node,
            decision: None,
            local_clock: None,
        })
    }

    /// Persistent, database-lifetime namespace for Kernel-originated Call
    /// RequestIds. Pair it with this database's `execution_id_source()`;
    /// another or ephemeral allocator cannot reuse these call identities.
    pub fn kernel_call_namespace(&self) -> Result<[u8; 32], FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
        let value = table
            .get(KERNEL_CALL_NAMESPACE_KEY)
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?;
        let namespace =
            <[u8; 32]>::try_from(value.value()).map_err(|_error| FederationError::Corrupt)?;
        if namespace == [0; 32] {
            return Err(FederationError::Corrupt);
        }
        Ok(namespace)
    }

    /// Read operator-owned peer enablement for idempotent host provisioning.
    pub fn peer_authority(
        &self,
        peer: FederationNodeId,
    ) -> Result<Option<(u64, bool)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let row = txn
            .open_table(FEDERATION_PEERS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<PeerRow>(value.value()))
            .transpose()?;
        row.map(|row| {
            if row.revision == 0 {
                Err(FederationError::Corrupt)
            } else {
                Ok((row.revision, row.enabled))
            }
        })
        .transpose()
    }

    /// Enumerate current peer rows so a stock host can disable removed peers
    /// before accepting new sessions from its declarative configuration.
    pub fn list_peer_authorities(
        &self,
    ) -> Result<Vec<(FederationNodeId, u64, bool)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
        let mut peers = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let node = FederationNodeId::from_bytes(
                <[u8; NODE_ID_LEN]>::try_from(key.value())
                    .map_err(|_error| FederationError::Corrupt)?,
            );
            let row: PeerRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            peers.push((node, row.revision, row.enabled));
        }
        Ok(peers)
    }

    /// Read one directional export rule without changing its revision.
    pub fn export_authority(
        &self,
        peer: FederationNodeId,
        export: &ExportName,
    ) -> Result<Option<(u64, ExportAccess)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let key = export_key(peer, export);
        let row = txn
            .open_table(FEDERATION_EXPORTS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|value| decode::<ExportRow>(value.value()))
            .transpose()?;
        row.map(|row| {
            if row.revision == 0 {
                Err(FederationError::Corrupt)
            } else {
                Ok((
                    row.revision,
                    ExportAccess {
                        serve: row.serve,
                        receive: row.receive,
                    },
                ))
            }
        })
        .transpose()
    }

    /// Enumerate a peer's current directional rules for configuration reconciliation.
    pub fn list_export_authorities(
        &self,
        peer: FederationNodeId,
    ) -> Result<Vec<(ExportName, u64, ExportAccess)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_EXPORTS_TABLE).map_err(storage)?;
        let mut exports = Vec::new();
        for entry in table.range(peer.as_bytes().as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let raw = key.value();
            if !raw.starts_with(peer.as_bytes()) {
                break;
            }
            let name = std::str::from_utf8(&raw[NODE_ID_LEN..])
                .map_err(|_error| FederationError::Corrupt)?;
            let export = ExportName::new(name).map_err(|_error| FederationError::Corrupt)?;
            let row: ExportRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            exports.push((
                export,
                row.revision,
                ExportAccess {
                    serve: row.serve,
                    receive: row.receive,
                },
            ));
        }
        Ok(exports)
    }

    /// Compare-and-set the exact online authorizations admitted for one peer.
    /// The peer must already have a local authority row, but may be disabled
    /// while its policy is prepared. The generation floor cannot be lowered.
    pub fn set_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        self.set_peer_admission_inner(peer, expected_revision, admission, false)
    }

    /// Configuration-owned online admission. A runtime row cannot be claimed
    /// by a manifest, even when its revision is known.
    pub fn set_manifest_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        self.set_peer_admission_inner(peer, expected_revision, admission, true)
    }

    fn set_peer_admission_inner(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
        manifest_owned: bool,
    ) -> Result<u64, FederationError> {
        if peer == self.node {
            return Err(FederationError::Invalid("peer cannot be the local node"));
        }
        admission.validate()?;
        self.with_decision_write(|txn, _| {
            let peer_row = txn
                .open_table(FEDERATION_PEERS_TABLE)
                .map_err(storage)?
                .get(peer.as_bytes().as_slice())
                .map_err(storage)?
                .map(|value| decode::<PeerRow>(value.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            if peer_row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            if peer_row.manifest_owned != manifest_owned {
                return Err(FederationError::Conflict);
            }
            let mut table = txn
                .open_table(FEDERATION_ADMISSIONS_TABLE)
                .map_err(storage)?;
            let current = table
                .get(peer.as_bytes().as_slice())
                .map_err(storage)?
                .map(|value| decode::<AdmissionRow>(value.value()))
                .transpose()?;
            let previous = current.as_ref().map(AdmissionRow::policy).transpose()?;
            if previous.is_some_and(|previous| {
                admission.minimum_online_generation < previous.minimum_online_generation
            }) {
                return Err(FederationError::Conflict);
            }
            let revision =
                next_revision(current.as_ref().map(|row| row.revision), expected_revision)?;
            table
                .insert(
                    peer.as_bytes().as_slice(),
                    encode(&AdmissionRow::new(revision, admission))?.as_slice(),
                )
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(revision)
        })
    }

    /// Read the current operator-owned admission rule without granting access.
    pub fn peer_admission(
        &self,
        peer: FederationNodeId,
    ) -> Result<Option<(u64, PeerAdmission)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let row = txn
            .open_table(FEDERATION_ADMISSIONS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<AdmissionRow>(value.value()))
            .transpose()?;
        row.map(|row| Ok((row.revision, row.policy()?))).transpose()
    }

    /// Persist the highest trusted wall-clock observation. A backward jump is
    /// rejected rather than extending the life of an expired authorization.
    pub fn checked_time_ms(&self, wall_now_ms: u64) -> Result<u64, FederationError> {
        self.sample_time_ms(|| Ok(wall_now_ms))
    }

    /// Check live peer enablement, key policy and trusted time from one redb
    /// snapshot. Call for every authenticated business frame, not just Hello.
    pub fn check_peer_admission(
        &self,
        proof: VerifiedFederationPeerProof,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        let (txn, decision_time) = self.begin_decision_read()?;
        let now_ms = decision_time.unwrap_or(now_ms);
        let trusted_time = txn
            .open_table(FEDERATION_NODE_TABLE)
            .map_err(storage)?
            .get(TRUSTED_TIME_KEY)
            .map_err(storage)?
            .map(|value| decode_trusted_time(value.value()))
            .transpose()?
            .ok_or(FederationError::ClockRollback)?;
        if now_ms < trusted_time {
            return Err(FederationError::ClockRollback);
        }
        let peer = proof.node_id();
        let peer_row = txn
            .open_table(FEDERATION_PEERS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<PeerRow>(value.value()))
            .transpose()?
            .ok_or(FederationError::Unauthorized)?;
        let admission_row = txn
            .open_table(FEDERATION_ADMISSIONS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<AdmissionRow>(value.value()))
            .transpose()?
            .ok_or(FederationError::Unauthorized)?;
        let admission = admission_row.policy()?;
        if peer_row.revision == 0 {
            return Err(FederationError::Corrupt);
        }
        if !peer_row.enabled
            || now_ms >= proof.expires_ms()
            || proof.online_generation() < admission.minimum_online_generation
            || !admission
                .allowed_authorization_digests
                .contains(&proof.authorization_digest())
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }

    fn set_peer_authority_inner(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
        manifest_owned: bool,
    ) -> Result<u64, FederationError> {
        if peer == self.node {
            return Err(FederationError::Invalid("peer cannot be the local node"));
        }
        self.with_decision_write(|txn, _| {
            let mut table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
            let current = table
                .get(peer.as_bytes().as_slice())
                .map_err(storage)?
                .map(|value| decode::<PeerRow>(value.value()))
                .transpose()?;
            if current
                .as_ref()
                .is_some_and(|row| row.manifest_owned != manifest_owned)
            {
                return Err(FederationError::Conflict);
            }
            let revision =
                next_revision(current.as_ref().map(|row| row.revision), expected_revision)?;
            table
                .insert(
                    peer.as_bytes().as_slice(),
                    encode(&PeerRow {
                        revision,
                        enabled,
                        control_revision: current.map_or(0, |row| row.control_revision),
                        manifest_owned,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(revision)
        })
    }

    fn set_export_authority_inner(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
        manifest_owned: bool,
    ) -> Result<u64, FederationError> {
        if peer == self.node {
            return Err(FederationError::Invalid("peer cannot be the local node"));
        }
        self.with_decision_write(|txn, _| {
            let peer_row = txn
                .open_table(FEDERATION_PEERS_TABLE)
                .map_err(storage)?
                .get(peer.as_bytes().as_slice())
                .map_err(storage)?
                .map(|value| decode::<PeerRow>(value.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            if peer_row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            if peer_row.manifest_owned != manifest_owned {
                return Err(FederationError::Conflict);
            }
            let key = export_key(peer, &export);
            let mut table = txn.open_table(FEDERATION_EXPORTS_TABLE).map_err(storage)?;
            let current = table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|value| decode::<ExportRow>(value.value()))
                .transpose()?;
            if current
                .as_ref()
                .is_some_and(|row| row.manifest_owned != manifest_owned)
            {
                return Err(FederationError::Conflict);
            }
            let revision =
                next_revision(current.as_ref().map(|row| row.revision), expected_revision)?;
            table
                .insert(
                    key.as_slice(),
                    encode(&ExportRow {
                        revision,
                        serve: access.serve,
                        receive: access.receive,
                        manifest_owned,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(revision)
        })
    }

    fn declare_stream_inner(&self, spec: StreamSpec) -> Result<(), FederationError> {
        if spec.stream.publisher != self.node {
            return Err(FederationError::Invalid(
                "stream publisher is not the local node",
            ));
        }
        self.with_decision_write(|txn, _| {
            let key = stream_key(spec.stream);
            let mut table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
            let current = table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|value| decode::<StreamRow>(value.value()))
                .transpose()?;
            if let Some(row) = current {
                row.validate()?;
                if row.export == spec.export.as_str() {
                    return Ok(());
                }
                return Err(FederationError::Conflict);
            }
            table
                .insert(
                    key.as_slice(),
                    encode(&StreamRow {
                        export: spec.export.as_str().to_owned(),
                        retry_epoch: 1,
                        head: None,
                        minimum_available: 1,
                        retired_through: None,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)
        })
    }

    fn append_published_inner(&self, request: PublishRequest) -> Result<Record, FederationError> {
        if request.stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let stream_key = stream_key(request.stream);
            let mut stream: StreamRow = {
                let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
                let value = table
                    .get(stream_key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(value.value())?
            };
            stream.validate()?;
            if request.retry_epoch == 0 || request.retry_epoch != stream.retry_epoch {
                return Err(FederationError::Conflict);
            }
            let request_key =
                publish_request_key(request.stream, request.retry_epoch, request.publish_id);
            let prior_position = {
                let table = txn
                    .open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
                    .map_err(storage)?;
                table
                    .get(request_key.as_slice())
                    .map_err(storage)?
                    .map(|value| Position::try_from(decode::<StoredPosition>(value.value())?))
                    .transpose()?
            };
            if let Some(position) = prior_position {
                let sequence = position.sequence();
                if sequence < stream.minimum_available {
                    return Err(FederationError::Indeterminate);
                }
                let key = record_key(request.stream, sequence);
                let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let record = decode_record(request.stream, sequence, saved.value())?;
                if record.position() != position {
                    return Err(FederationError::Corrupt);
                }
                return if request.matches_record(&record) {
                    Ok(record)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            let publish_id_limit = {
                let table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
                let value = table
                    .get(PUBLISH_ID_LIMIT_KEY)
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let limit = u64::from_be_bytes(
                    value
                        .value()
                        .try_into()
                        .map_err(|_error| FederationError::Corrupt)?,
                );
                if limit == 0 {
                    return Err(FederationError::Corrupt);
                }
                limit
            };
            if txn
                .open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
                .map_err(storage)?
                .len()
                .map_err(storage)?
                >= publish_id_limit
            {
                return Err(FederationError::Capacity);
            }
            let sequence = stream
                .head
                .map_or(Some(1), |head| head.sequence.checked_add(1))
                .ok_or(FederationError::Capacity)?;
            let record = Record::new(request.into_parts(sequence))?;
            let encoded = encode_record(&record)?;
            txn.open_table(FEDERATION_RECORDS_TABLE)
                .map_err(storage)?
                .insert(
                    record_key(record.stream(), sequence).as_slice(),
                    encoded.as_slice(),
                )
                .map_err(storage)?;
            txn.open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
                .map_err(storage)?
                .insert(
                    request_key.as_slice(),
                    encode(&StoredPosition::from(record.position()))?.as_slice(),
                )
                .map_err(storage)?;
            stream.head = Some(record.position().into());
            txn.open_table(FEDERATION_STREAMS_TABLE)
                .map_err(storage)?
                .insert(stream_key.as_slice(), encode(&stream)?.as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(record)
        })
    }

    fn open_inner(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: OpenRequest,
        access: AccessPath,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.stream.publisher != self.node
            || request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            if access == AccessPath::Guest {
                object::checked_object_time(txn, now_ms)?;
            }
            let request_key =
                control_request_key(request.authenticated_subscriber, request.request_id);
            let previous_control = {
                let table = txn
                    .open_table(FEDERATION_CONTROL_REQUESTS_TABLE)
                    .map_err(storage)?;
                table
                    .get(request_key.as_slice())
                    .map_err(storage)?
                    .map(|value| decode::<ControlRequestRow>(value.value()))
                    .transpose()?
            };
            if let Some(previous_control) = previous_control {
                let ControlRequestRow::Open { subscription } = previous_control else {
                    return Err(FederationError::Conflict);
                };
                let previous_key = subscription_key(subscription.into());
                let table = txn
                    .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                    .map_err(storage)?;
                let value = table
                    .get(previous_key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let row: SubscriptionRow = decode(value.value())?;
                return match row {
                    SubscriptionRow::Publisher {
                        request: previous,
                        opened,
                        subject: stored_subject,
                        guest,
                        ..
                    } => {
                        let previous = OpenRequest::try_from(*previous)?;
                        let opened = OpenResult::try_from(opened)?;
                        if guest != (access == AccessPath::Guest)
                            || previous != request
                            || !publisher_subject_matches(
                                stored_subject.as_ref(),
                                request.authenticated_subscriber,
                                &subject,
                            )
                        {
                            Err(FederationError::Conflict)
                        } else {
                            let (current, _) = subject_authority_in_write(
                                txn,
                                &subject,
                                request.authenticated_subscriber,
                                opened.stream,
                                &opened.export,
                                now_ms,
                                access,
                            )?;
                            if current == opened.publisher_authority {
                                Ok(opened)
                            } else {
                                Err(FederationError::Conflict)
                            }
                        }
                    }
                    SubscriptionRow::Receiver { .. } => Err(FederationError::Corrupt),
                };
            }
            let spec: StreamRow = {
                let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
                let key = stream_key(request.stream);
                let value = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(value.value())?
            };
            spec.validate()?;
            let export =
                ExportName::new(spec.export.clone()).map_err(|_error| FederationError::Corrupt)?;
            let (current, floor) = subject_authority_in_write(
                txn,
                &subject,
                request.authenticated_subscriber,
                request.stream,
                &export,
                now_ms,
                access,
            )?;
            let subscription_key = subscription_key(request.subscription);
            if txn
                .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .get(subscription_key.as_slice())
                .map_err(storage)?
                .is_some()
            {
                return Err(FederationError::Conflict);
            }
            let control_revision =
                control_revision_in_write(txn, request.authenticated_subscriber, access)?;
            if request
                .expected_control_revision
                .is_some_and(|expected| expected != control_revision)
            {
                return Err(FederationError::Conflict);
            }
            let next = control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            let start = match request.history {
                HistoryStart::All if floor == 0 && spec.minimum_available > 1 => {
                    return Err(FederationError::ResyncRequired {
                        minimum_available: spec.minimum_available,
                    });
                }
                HistoryStart::All => None,
                HistoryStart::FromNow => spec.head.map(TryInto::try_into).transpose()?,
                HistoryStart::After(position) => {
                    if position.sequence() < floor {
                        return Err(FederationError::Unauthorized);
                    }
                    if !spec.verify_retired_cursor(position)? {
                        let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                        let key = record_key(request.stream, position.sequence());
                        let saved = table
                            .get(key.as_slice())
                            .map_err(storage)?
                            .ok_or(FederationError::Conflict)?;
                        let record =
                            decode_record(request.stream, position.sequence(), saved.value())?;
                        if record.digest() != position.digest() {
                            return Err(FederationError::Conflict);
                        }
                    }
                    Some(position)
                }
            };
            let start = match start {
                Some(start) if start.sequence() >= floor => Some(start),
                _ if floor == 0 => None,
                _ if floor == spec.minimum_available.saturating_sub(1) => {
                    spec.retired_through.map(Position::try_from).transpose()?
                }
                _ => {
                    let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                    let key = record_key(request.stream, floor);
                    let saved = table.get(key.as_slice()).map_err(storage)?.ok_or(
                        FederationError::ResyncRequired {
                            minimum_available: spec.minimum_available,
                        },
                    )?;
                    Some(decode_record(request.stream, floor, saved.value())?.position())
                }
            };
            if start
                .is_some_and(|start| start.sequence() < spec.minimum_available.saturating_sub(1))
            {
                return Err(FederationError::ResyncRequired {
                    minimum_available: spec.minimum_available,
                });
            }
            let result = OpenResult {
                request_id: request.request_id,
                subscription: request.subscription,
                stream: request.stream,
                export,
                publisher_authority: current,
                subscription_revision: next,
                start,
            };
            set_control_revision_in_write(txn, request.authenticated_subscriber, access, next)?;
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    subscription_key.as_slice(),
                    encode(&SubscriptionRow::Publisher {
                        request: Box::new((&request).into()),
                        opened: (&result).into(),
                        subject: Some((&subject).into()),
                        guest: access == AccessPath::Guest,
                        acknowledged: None,
                        closed_revision: None,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.open_table(FEDERATION_CONTROL_REQUESTS_TABLE)
                .map_err(storage)?
                .insert(
                    request_key.as_slice(),
                    encode(&ControlRequestRow::Open {
                        subscription: request.subscription.into(),
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    fn inspect_subscription_inner(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
        access: AccessPath,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.inspect_subscription_read(subject, now_ms, request, access, false)
    }

    fn inspect_subscription_read(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
        access: AccessPath,
        delivery: bool,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        let (txn, decision_time) = if delivery {
            let (txn, time) = self.begin_delivery_read(now_ms)?;
            (txn, Some(time))
        } else {
            self.begin_decision_read()?
        };
        let now_ms = decision_time.unwrap_or(now_ms);
        let key = subscription_key(request.subscription);
        let row: SubscriptionRow = {
            let table = txn
                .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?;
            let saved = table
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::NotFound)?;
            decode(saved.value())?
        };
        let SubscriptionRow::Publisher {
            opened,
            subject: stored_subject,
            guest,
            acknowledged,
            closed_revision,
            ..
        } = row
        else {
            return Err(FederationError::Corrupt);
        };
        if guest != (access == AccessPath::Guest)
            || !publisher_subject_matches(
                stored_subject.as_ref(),
                request.authenticated_subscriber,
                &subject,
            )
        {
            return Err(FederationError::Unauthorized);
        }
        let opened = OpenResult::try_from(opened)?;
        if opened.subscription != request.subscription {
            return Err(FederationError::Corrupt);
        }
        let (current, _) = subject_authority_in_read(
            &txn,
            &subject,
            request.authenticated_subscriber,
            opened.stream,
            &opened.export,
            now_ms,
            access,
        )?;
        if current != opened.publisher_authority {
            return Err(FederationError::Conflict);
        }
        let stream: StreamRow = {
            let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
            let key = stream_key(opened.stream);
            let saved = table
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Corrupt)?;
            decode(saved.value())?
        };
        stream.validate()?;
        if stream.export != opened.export.as_str() || closed_revision == Some(0) {
            return Err(FederationError::Corrupt);
        }
        Ok(SubscriptionInspection {
            subscription: request.subscription,
            stream: opened.stream,
            export: opened.export,
            subscription_revision: closed_revision.unwrap_or(opened.subscription_revision),
            start: opened.start,
            acknowledged: acknowledged.map(TryInto::try_into).transpose()?,
            head: stream.head.map(TryInto::try_into).transpose()?,
            minimum_available: stream.minimum_available.max(
                opened
                    .start
                    .map_or(1, |start| start.sequence().saturating_add(1)),
            ),
            closed: closed_revision.is_some(),
        })
    }

    fn close_subscription_inner(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
        access: AccessPath,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            if access == AccessPath::Guest {
                object::checked_object_time(txn, now_ms)?;
            }
            let key = subscription_key(request.subscription);
            let row: SubscriptionRow = {
                let table = txn
                    .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                    .map_err(storage)?;
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(saved.value())?
            };
            let SubscriptionRow::Publisher {
                request: opened_request,
                opened,
                subject: stored_subject,
                guest,
                acknowledged,
                closed_revision,
            } = row
            else {
                return Err(FederationError::Corrupt);
            };
            if guest != (access == AccessPath::Guest)
                || !publisher_subject_matches(
                    stored_subject.as_ref(),
                    request.authenticated_subscriber,
                    &subject,
                )
            {
                return Err(FederationError::Unauthorized);
            }
            let opened = OpenResult::try_from(opened)?;
            if opened.subscription != request.subscription {
                return Err(FederationError::Corrupt);
            }
            let (current, _) = subject_authority_in_write(
                txn,
                &subject,
                request.authenticated_subscriber,
                opened.stream,
                &opened.export,
                now_ms,
                access,
            )?;
            if current != opened.publisher_authority {
                return Err(FederationError::Conflict);
            }
            let receipt_key =
                control_request_key(request.authenticated_subscriber, request.request_id);
            let prior = {
                let table = txn
                    .open_table(FEDERATION_CONTROL_REQUESTS_TABLE)
                    .map_err(storage)?;
                table
                    .get(receipt_key.as_slice())
                    .map_err(storage)?
                    .map(|row| decode::<ControlRequestRow>(row.value()))
                    .transpose()?
            };
            if let Some(prior) = prior {
                return match prior {
                    ControlRequestRow::Close {
                        request: prior,
                        result_revision,
                    } if prior.request_id == *request.request_id.as_bytes()
                        && SubscriptionRef::from(prior.subscription) == request.subscription
                        && prior.expected_subscription_revision
                            == request.expected_subscription_revision
                        && closed_revision == Some(result_revision) =>
                    {
                        Ok(CloseSubscriptionResult {
                            request_id: request.request_id,
                            subscription: request.subscription,
                            subscription_revision: result_revision,
                        })
                    }
                    _ => Err(FederationError::Conflict),
                };
            }
            if closed_revision.is_some()
                || request
                    .expected_subscription_revision
                    .is_some_and(|revision| revision != opened.subscription_revision)
            {
                return Err(FederationError::Conflict);
            }
            let next = control_revision_in_write(txn, request.authenticated_subscriber, access)?
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            set_control_revision_in_write(txn, request.authenticated_subscriber, access, next)?;
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Publisher {
                        request: opened_request,
                        opened: (&opened).into(),
                        subject: stored_subject,
                        guest,
                        acknowledged,
                        closed_revision: Some(next),
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.open_table(FEDERATION_CONTROL_REQUESTS_TABLE)
                .map_err(storage)?
                .insert(
                    receipt_key.as_slice(),
                    encode(&ControlRequestRow::Close {
                        request: request.into(),
                        result_revision: next,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(CloseSubscriptionResult {
                request_id: request.request_id,
                subscription: request.subscription,
                subscription_revision: next,
            })
        })
    }

    fn install_subscription_inner(
        &self,
        request: InstallSubscriptionRequest,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        let opened = request.opened;
        if opened.subscription.subscriber != self.node
            || opened.stream.publisher != request.authenticated_publisher
            || request.authenticated_publisher == self.node
            || opened.subscription_revision == 0
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let current =
                authority_in_write(txn, request.authenticated_publisher, &opened.export, false)?;
            let key = subscription_key(opened.subscription);
            let existing = txn
                .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .get(key.as_slice())
                .map_err(storage)?
                .map(|value| decode::<SubscriptionRow>(value.value()))
                .transpose()?;
            if let Some(row) = existing {
                return match row {
                    SubscriptionRow::Receiver {
                        opened: previous,
                        local_authority,
                        ..
                    } => {
                        if OpenResult::try_from(previous)? == opened
                            && AuthorityRevision::from(local_authority) == current
                        {
                            Ok(opened)
                        } else {
                            Err(FederationError::Conflict)
                        }
                    }
                    _ => Err(FederationError::Conflict),
                };
            }
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Receiver {
                        opened: (&opened).into(),
                        local_authority: current.into(),
                        received: None,
                        projected: None,
                        retired_through: None,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(opened)
        })
    }

    fn read_inner(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: ReadRequest,
        access: AccessPath,
    ) -> Result<ReadPage, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        if request.max_records == 0 || request.max_bytes == 0 {
            return Err(FederationError::Invalid("read limits must be positive"));
        }
        let (txn, decision_time) = self.begin_decision_read()?;
        let now_ms = decision_time.unwrap_or(now_ms);
        let key = subscription_key(request.subscription);
        let subscription: SubscriptionRow = {
            let table = txn
                .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?;
            let saved = table
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::NotFound)?;
            decode(saved.value())?
        };
        let opened = match subscription {
            SubscriptionRow::Publisher {
                opened,
                subject: stored_subject,
                guest,
                closed_revision: None,
                ..
            } => {
                if guest != (access == AccessPath::Guest)
                    || !publisher_subject_matches(
                        stored_subject.as_ref(),
                        request.authenticated_subscriber,
                        &subject,
                    )
                {
                    return Err(FederationError::Unauthorized);
                }
                OpenResult::try_from(opened)?
            }
            SubscriptionRow::Publisher {
                closed_revision: Some(_),
                ..
            } => return Err(FederationError::Conflict),
            SubscriptionRow::Receiver { .. } => return Err(FederationError::Corrupt),
        };
        let (current, _) = subject_authority_in_read(
            &txn,
            &subject,
            request.authenticated_subscriber,
            opened.stream,
            &opened.export,
            now_ms,
            access,
        )?;
        if current != opened.publisher_authority {
            return Err(FederationError::Conflict);
        }
        let stream: StreamRow = {
            let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
            let key = stream_key(opened.stream);
            let saved = table
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Corrupt)?;
            decode(saved.value())?
        };
        stream.validate()?;
        if stream.export != opened.export.as_str() || stream.minimum_available == 0 {
            return Err(FederationError::Corrupt);
        }
        let head = stream.head.map(TryInto::try_into).transpose()?;
        if request.after.is_some_and(|after| {
            opened
                .start
                .is_some_and(|start| after.sequence() < start.sequence())
        }) {
            return Err(FederationError::Unauthorized);
        }
        let after = request.after.or(opened.start);
        if let Some(after) = after
            && !stream.verify_retired_cursor(after)?
        {
            let key = record_key(opened.stream, after.sequence());
            let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
            let saved = table
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Conflict)?;
            let record = decode_record(opened.stream, after.sequence(), saved.value())?;
            if record.digest() != after.digest() {
                return Err(FederationError::Conflict);
            }
        }
        let first = after.map_or(1, |after| after.sequence().saturating_add(1));
        if first < stream.minimum_available {
            return Err(FederationError::ResyncRequired {
                minimum_available: stream.minimum_available,
            });
        }
        if first == 0 {
            return Err(FederationError::Capacity);
        }
        let start = record_key(opened.stream, first);
        let prefix = stream_key(opened.stream);
        let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let mut expected = first;
        for entry in table.range(start.as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key = key.value();
            if !key.starts_with(&prefix) {
                break;
            }
            let raw =
                <[u8; RECORD_KEY_LEN]>::try_from(key).map_err(|_error| FederationError::Corrupt)?;
            let sequence = u64::from_be_bytes(
                raw[STREAM_KEY_LEN..]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            );
            if sequence != expected {
                return Err(FederationError::Corrupt);
            }
            let record = decode_record(opened.stream, sequence, value.value())?;
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
            records.push(record);
            if records.len() >= request.max_records {
                break;
            }
            expected = expected.checked_add(1).ok_or(FederationError::Capacity)?;
        }
        if records.is_empty() && head.is_some_and(|position: Position| position.sequence() >= first)
        {
            return Err(FederationError::Corrupt);
        }
        Ok(ReadPage {
            records,
            head,
            minimum_available: stream.minimum_available.max(
                opened
                    .start
                    .map_or(1, |start| start.sequence().saturating_add(1)),
            ),
        })
    }

    fn accept_inner(
        &self,
        request: AcceptRequest,
        expected_generation: Option<u64>,
    ) -> Result<AcceptResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        if request.subscription.subscriber != self.node
            || request.record.stream().publisher != request.authenticated_publisher
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let baseline = snapshot::gate_write(txn, request.subscription, expected_generation)?;
            let key = subscription_key(request.subscription);
            let row: SubscriptionRow = {
                let table = txn
                    .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                    .map_err(storage)?;
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(saved.value())?
            };
            let SubscriptionRow::Receiver {
                opened,
                local_authority,
                received,
                projected,
                retired_through,
            } = row
            else {
                return Err(FederationError::Corrupt);
            };
            let opened = OpenResult::try_from(opened)?;
            if opened.subscription != request.subscription {
                return Err(FederationError::Corrupt);
            }
            let current =
                authority_in_write(txn, request.authenticated_publisher, &opened.export, false)?;
            if current != AuthorityRevision::from(local_authority)
                || opened.stream != request.record.stream()
            {
                return Err(FederationError::Conflict);
            }
            let received = received.map(Position::try_from).transpose()?;
            let projected_position = projected.map(Position::try_from).transpose()?;
            let retired_position = retired_through.map(Position::try_from).transpose()?;
            if projected_position.is_some_and(|projected| {
                received.is_none_or(|head| {
                    projected.sequence() > head.sequence()
                        || (projected.sequence() == head.sequence()
                            && projected.digest() != head.digest())
                })
            }) {
                return Err(FederationError::Corrupt);
            }
            if retired_position.is_some_and(|retired| {
                projected_position.is_none_or(|projected| {
                    retired.sequence() > projected.sequence()
                        || (retired.sequence() == projected.sequence() && retired != projected)
                })
            }) {
                return Err(FederationError::Corrupt);
            }
            let expected = received
                .map_or_else(
                    || {
                        baseline
                            .or(opened.start)
                            .map_or(Some(1), |start| start.sequence().checked_add(1))
                    },
                    |head| head.sequence().checked_add(1),
                )
                .ok_or(FederationError::Capacity)?;
            let position = request.record.position();
            if baseline
                .or(opened.start)
                .is_some_and(|start| position.sequence() <= start.sequence())
            {
                return Err(FederationError::Conflict);
            }
            if position.sequence() < expected {
                if retired_position.is_some_and(|retired| position.sequence() <= retired.sequence())
                {
                    if retired_position == Some(position) {
                        return Ok(AcceptResult {
                            position: received.ok_or(FederationError::Corrupt)?,
                            newly_accepted: false,
                        });
                    }
                    return Err(FederationError::Indeterminate);
                }
                let saved = {
                    let table = txn.open_table(FEDERATION_INBOX_TABLE).map_err(storage)?;
                    let key = inbox_key(request.subscription, position.sequence());
                    let saved = table
                        .get(key.as_slice())
                        .map_err(storage)?
                        .ok_or(FederationError::Corrupt)?;
                    decode_record(opened.stream, position.sequence(), saved.value())?
                };
                if saved.digest() != position.digest() {
                    return Err(FederationError::Conflict);
                }
                return Ok(AcceptResult {
                    position: received.ok_or(FederationError::Corrupt)?,
                    newly_accepted: false,
                });
            }
            if position.sequence() != expected {
                return Err(FederationError::Gap {
                    expected,
                    received: position.sequence(),
                });
            }
            let encoded = encode_record(&request.record)?;
            {
                let mut table = txn.open_table(FEDERATION_INBOX_TABLE).map_err(storage)?;
                let key = inbox_key(request.subscription, position.sequence());
                if table.get(key.as_slice()).map_err(storage)?.is_some() {
                    return Err(FederationError::Corrupt);
                }
                table
                    .insert(key.as_slice(), encoded.as_slice())
                    .map_err(storage)?;
            }
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Receiver {
                        opened: (&opened).into(),
                        local_authority,
                        received: Some(position.into()),
                        projected,
                        retired_through,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(AcceptResult {
                position,
                newly_accepted: true,
            })
        })
    }

    fn acknowledge_inner(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
        access: AccessPath,
    ) -> Result<Position, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.node
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            if access == AccessPath::Guest {
                object::checked_object_time(txn, now_ms)?;
            }
            let key = subscription_key(request.subscription);
            let row: SubscriptionRow = {
                let table = txn
                    .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                    .map_err(storage)?;
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(saved.value())?
            };
            let SubscriptionRow::Publisher {
                request: opened_request,
                opened,
                subject: stored_subject,
                guest,
                acknowledged,
                closed_revision,
            } = row
            else {
                return Err(FederationError::Corrupt);
            };
            if guest != (access == AccessPath::Guest)
                || !publisher_subject_matches(
                    stored_subject.as_ref(),
                    request.authenticated_subscriber,
                    &subject,
                )
            {
                return Err(FederationError::Unauthorized);
            }
            let opened = OpenResult::try_from(opened)?;
            if closed_revision.is_some()
                || opened
                    .start
                    .is_some_and(|start| request.position.sequence() <= start.sequence())
            {
                return Err(FederationError::Conflict);
            }
            if opened.subscription != request.subscription || opened.stream.publisher != self.node {
                return Err(FederationError::Corrupt);
            }
            let (current, _) = subject_authority_in_write(
                txn,
                &subject,
                request.authenticated_subscriber,
                opened.stream,
                &opened.export,
                now_ms,
                access,
            )?;
            if current != opened.publisher_authority {
                return Err(FederationError::Conflict);
            }
            snapshot::check_event_ack_against_offer(txn, request.subscription, request.position)?;
            let stream: StreamRow = txn
                .open_table(FEDERATION_STREAMS_TABLE)
                .map_err(storage)?
                .get(stream_key(opened.stream).as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::Corrupt)?;
            stream.validate()?;
            if !stream.verify_retired_cursor(request.position)? {
                let saved = {
                    let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                    let key = record_key(opened.stream, request.position.sequence());
                    let saved = table
                        .get(key.as_slice())
                        .map_err(storage)?
                        .ok_or(FederationError::Conflict)?;
                    decode_record(opened.stream, request.position.sequence(), saved.value())?
                };
                if saved.digest() != request.position.digest() {
                    return Err(FederationError::Conflict);
                }
            }
            let previous = acknowledged.map(Position::try_from).transpose()?;
            if previous.is_some_and(|position| position.sequence() >= request.position.sequence()) {
                return previous.ok_or(FederationError::Corrupt);
            }
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Publisher {
                        request: opened_request,
                        opened: (&opened).into(),
                        subject: stored_subject,
                        guest,
                        acknowledged: Some(request.position.into()),
                        closed_revision,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(request.position)
        })
    }

    fn record_projection_progress_inner(
        &self,
        request: ProjectionProgress,
        expected_generation: Option<u64>,
    ) -> Result<Position, FederationError> {
        if request.subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let baseline =
                snapshot::gate_projected_write(txn, request.subscription, expected_generation)?;
            let key = subscription_key(request.subscription);
            let row: SubscriptionRow = {
                let table = txn
                    .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                    .map_err(storage)?;
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(saved.value())?
            };
            let SubscriptionRow::Receiver {
                opened,
                local_authority,
                received,
                projected,
                retired_through,
            } = row
            else {
                return Err(FederationError::Corrupt);
            };
            let opened = OpenResult::try_from(opened)?;
            if opened.subscription != request.subscription {
                return Err(FederationError::Corrupt);
            }
            let current = authority_in_write(txn, opened.stream.publisher, &opened.export, false)?;
            if current != AuthorityRevision::from(local_authority) {
                return Err(FederationError::Conflict);
            }
            if baseline
                .or(opened.start)
                .is_some_and(|start| request.position.sequence() <= start.sequence())
            {
                return Err(FederationError::Conflict);
            }
            let retired_position = retired_through.map(Position::try_from).transpose()?;
            let previous = projected.map(Position::try_from).transpose()?;
            if retired_position
                .is_some_and(|retired| request.position.sequence() <= retired.sequence())
            {
                return if retired_position == Some(request.position) {
                    previous.ok_or(FederationError::Corrupt)
                } else {
                    Err(FederationError::Indeterminate)
                };
            }
            let saved = {
                let table = txn.open_table(FEDERATION_INBOX_TABLE).map_err(storage)?;
                let key = inbox_key(request.subscription, request.position.sequence());
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Conflict)?;
                decode_record(opened.stream, request.position.sequence(), saved.value())?
            };
            if saved.digest() != request.position.digest() {
                return Err(FederationError::Conflict);
            }
            let received_position = received.map(Position::try_from).transpose()?;
            if received_position.is_none_or(|head| {
                request.position.sequence() > head.sequence()
                    || (request.position.sequence() == head.sequence()
                        && request.position.digest() != head.digest())
            }) {
                return Err(FederationError::Corrupt);
            }
            let expected = previous
                .map_or_else(
                    || {
                        baseline
                            .or(opened.start)
                            .map_or(Some(1), |start| start.sequence().checked_add(1))
                    },
                    |position| position.sequence().checked_add(1),
                )
                .ok_or(FederationError::Capacity)?;
            if request.position.sequence() > expected {
                return Err(FederationError::Gap {
                    expected,
                    received: request.position.sequence(),
                });
            }
            if previous.is_some_and(|position| position.sequence() >= request.position.sequence()) {
                return previous.ok_or(FederationError::Corrupt);
            }
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Receiver {
                        opened: (&opened).into(),
                        local_authority,
                        received,
                        projected: Some(request.position.into()),
                        retired_through,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(request.position)
        })
    }
    fn read_inbox_inner(
        &self,
        request: InboxReadRequest,
        expected_generation: Option<u64>,
    ) -> Result<InboxReadPage, FederationError> {
        if request.subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        if request.max_records == 0
            || request.max_records > 256
            || request.max_bytes == 0
            || request.max_bytes > 4 * 1024 * 1024
        {
            return Err(FederationError::Capacity);
        }
        let (txn, _) = self.begin_decision_read()?;
        let baseline = snapshot::gate_read(&txn, request.subscription, expected_generation)?;
        let subscription_key = subscription_key(request.subscription);
        let row: SubscriptionRow = {
            let table = txn
                .open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?;
            let saved = table
                .get(subscription_key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::NotFound)?;
            decode(saved.value())?
        };
        let SubscriptionRow::Receiver {
            opened,
            local_authority,
            received,
            projected,
            retired_through,
        } = row
        else {
            return Err(FederationError::Corrupt);
        };
        let opened = OpenResult::try_from(opened)?;
        if opened.subscription != request.subscription {
            return Err(FederationError::Corrupt);
        }
        if opened.stream != request.expected_stream {
            return Err(FederationError::Conflict);
        }
        let current = authority_in_read(&txn, opened.stream.publisher, &opened.export, false)?;
        if current != AuthorityRevision::from(local_authority) {
            return Err(FederationError::Conflict);
        }
        let received = received.map(Position::try_from).transpose()?;
        let projected = projected.map(Position::try_from).transpose()?;
        let retired_through = retired_through.map(Position::try_from).transpose()?;
        if received.is_some_and(|head| {
            opened
                .start
                .is_some_and(|start| head.sequence() <= start.sequence())
        }) {
            return Err(FederationError::Corrupt);
        }
        if projected.is_some_and(|projected| {
            received.is_none_or(|head| {
                projected.sequence() > head.sequence()
                    || (projected.sequence() == head.sequence()
                        && projected.digest() != head.digest())
            })
        }) {
            return Err(FederationError::Corrupt);
        }
        if retired_through.is_some_and(|retired| {
            projected.is_none_or(|projected| {
                retired.sequence() > projected.sequence()
                    || (retired.sequence() == projected.sequence() && retired != projected)
            })
        }) {
            return Err(FederationError::Corrupt);
        }
        let after = request
            .after
            .or(retired_through)
            .or(baseline)
            .or(opened.start);
        let inbox = txn.open_table(FEDERATION_INBOX_TABLE).map_err(storage)?;
        if let Some(cursor) = after {
            if baseline
                .or(opened.start)
                .is_some_and(|start| cursor.sequence() < start.sequence())
            {
                return Err(FederationError::Unauthorized);
            }
            if retired_through.is_some_and(|retired| cursor.sequence() < retired.sequence()) {
                return Err(FederationError::ResyncRequired {
                    minimum_available: retired_through
                        .and_then(|retired| retired.sequence().checked_add(1))
                        .ok_or(FederationError::Capacity)?,
                });
            }
            if retired_through.is_some_and(|retired| cursor.sequence() == retired.sequence()) {
                if retired_through != Some(cursor) {
                    return Err(FederationError::Conflict);
                }
            } else if baseline
                .or(opened.start)
                .is_some_and(|start| cursor.sequence() == start.sequence())
            {
                if baseline.or(opened.start) != Some(cursor) {
                    return Err(FederationError::Conflict);
                }
                // The Open baseline is an exclusion bound, not an inbox row.
            } else {
                if received.is_none_or(|head| cursor.sequence() > head.sequence()) {
                    return Err(FederationError::Conflict);
                }
                let key = inbox_key(request.subscription, cursor.sequence());
                let saved = inbox
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let record = decode_record(opened.stream, cursor.sequence(), saved.value())?;
                if record.digest() != cursor.digest() {
                    return Err(FederationError::Conflict);
                }
            }
        }
        let mut sequence = after.map_or(Some(1), |cursor| cursor.sequence().checked_add(1));
        let head_sequence = received.map_or(0, Position::sequence);
        let mut records = Vec::with_capacity(request.max_records);
        let mut bytes = 0usize;
        while let Some(current_sequence) = sequence {
            if current_sequence > head_sequence || records.len() == request.max_records {
                break;
            }
            let key = inbox_key(request.subscription, current_sequence);
            let saved = inbox
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Corrupt)?;
            let payload_bytes = stored_record_payload_bytes(saved.value())?;
            let next_bytes = bytes
                .checked_add(payload_bytes)
                .ok_or(FederationError::Capacity)?;
            if next_bytes > request.max_bytes {
                if records.is_empty() {
                    return Err(FederationError::Capacity);
                }
                break;
            }
            records.push(decode_record(
                opened.stream,
                current_sequence,
                saved.value(),
            )?);
            bytes = next_bytes;
            sequence = current_sequence.checked_add(1);
        }
        Ok(InboxReadPage {
            opened,
            received,
            projected,
            records,
        })
    }

    fn retire_projected_inbox_inner(
        &self,
        subscription: SubscriptionRef,
        max_records: usize,
        expected_generation: Option<u64>,
    ) -> Result<InboxRetirement, FederationError> {
        if subscription.subscriber != self.node {
            return Err(FederationError::Unauthorized);
        }
        if max_records == 0 || max_records > MAX_RETIRE_RECORDS {
            return Err(FederationError::Capacity);
        }
        self.with_decision_write(|txn, _| {
            let baseline = snapshot::gate_projected_write(txn, subscription, expected_generation)?;
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
                retired_through,
            } = row
            else {
                return Err(FederationError::Corrupt);
            };
            let opened = OpenResult::try_from(opened)?;
            if opened.subscription != subscription {
                return Err(FederationError::Corrupt);
            }
            let received_position = received.map(Position::try_from).transpose()?;
            let projected_position = projected.map(Position::try_from).transpose()?;
            let retired_position = retired_through.map(Position::try_from).transpose()?;
            if projected_position.is_some_and(|projected| {
                received_position.is_none_or(|received| {
                    projected.sequence() > received.sequence()
                        || (projected.sequence() == received.sequence() && projected != received)
                })
            }) || retired_position.is_some_and(|retired| {
                projected_position.is_none_or(|projected| {
                    retired.sequence() > projected.sequence()
                        || (retired.sequence() == projected.sequence() && retired != projected)
                })
            }) {
                return Err(FederationError::Corrupt);
            }
            let first = retired_position
                .or(baseline)
                .or(opened.start)
                .map_or(Some(1), |position| position.sequence().checked_add(1))
                .ok_or(FederationError::Capacity)?;
            let count = projected_position
                .and_then(|projected| projected.sequence().checked_sub(first))
                .and_then(|distance| distance.checked_add(1))
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0)
                .min(max_records);
            if count == 0 {
                return Ok(InboxRetirement {
                    subscription,
                    received: received_position,
                    projected: projected_position,
                    retired_through: retired_position,
                    removed: 0,
                });
            }
            let mut inbox = txn.open_table(FEDERATION_INBOX_TABLE).map_err(storage)?;
            let mut keys = Vec::with_capacity(count);
            let mut bytes = 0usize;
            for offset in 0..count {
                let sequence = first
                    .checked_add(offset as u64)
                    .ok_or(FederationError::Capacity)?;
                let row_key = inbox_key(subscription, sequence);
                let saved = inbox
                    .get(row_key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                let next = bytes
                    .checked_add(stored_record_payload_bytes(saved.value())?)
                    .ok_or(FederationError::Capacity)?;
                if next > MAX_RETIRE_BYTES {
                    break;
                }
                bytes = next;
                keys.push(row_key);
            }
            let removed = keys.len();
            if removed == 0 {
                return Err(FederationError::Capacity);
            }
            let last_sequence = first
                .checked_add((removed - 1) as u64)
                .ok_or(FederationError::Capacity)?;
            let last = {
                let saved = inbox
                    .get(keys.last().ok_or(FederationError::Corrupt)?.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                decode_record(opened.stream, last_sequence, saved.value())?.position()
            };
            if projected_position.is_some_and(|projected| {
                projected.sequence() == last.sequence() && projected != last
            }) {
                return Err(FederationError::Corrupt);
            }
            for key in &keys {
                inbox.remove(key.as_slice()).map_err(storage)?;
            }
            txn.open_table(FEDERATION_SUBSCRIPTIONS_TABLE)
                .map_err(storage)?
                .insert(
                    key.as_slice(),
                    encode(&SubscriptionRow::Receiver {
                        opened: (&opened).into(),
                        local_authority,
                        received,
                        projected,
                        retired_through: Some(last.into()),
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            drop(inbox);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(InboxRetirement {
                subscription,
                received: received_position,
                projected: projected_position,
                retired_through: Some(last),
                removed,
            })
        })
    }
}

fn decode_trusted_time(bytes: &[u8]) -> Result<u64, FederationError> {
    let bytes = <[u8; 8]>::try_from(bytes).map_err(|_error| FederationError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

impl FederationStore for RedbFederationStore {
    fn authorize_subscription_delivery(
        &self,
        subject: &FederationSubject,
        request: InspectSubscriptionRequest,
        payload: bool,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        let view = self.inspect_subscription_read(
            subject.clone(),
            now_ms,
            request,
            AccessPath::Managed,
            true,
        )?;
        if payload && view.closed {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }

    fn set_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        RedbFederationStore::set_peer_admission(self, peer, expected_revision, admission)
    }

    fn bind_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn set_peer_authority(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        self.set_peer_authority_inner(peer, expected_revision, enabled, false)
    }

    fn set_export_authority(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError> {
        self.set_export_authority_inner(peer, export, expected_revision, access, false)
    }

    fn set_subject_grant(
        &self,
        expected_revision: Option<u64>,
        grant: SubjectGrant,
    ) -> Result<u64, FederationError> {
        grant.validate(self.node)?;
        self.with_decision_write(|txn, _| {
            let peer = {
                let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
                table
                    .get(grant.presenter.as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| decode::<PeerRow>(value.value()))
                    .transpose()?
            };
            if peer.as_ref().is_some_and(|peer| peer.revision == 0) {
                return Err(FederationError::Corrupt);
            }
            let stream: StreamRow = {
                let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
                let key = stream_key(grant.stream);
                let value = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(value.value())?
            };
            stream.validate()?;
            let key = subject_grant_key(&grant.subject, grant.presenter, grant.stream);
            let current = {
                let table = txn
                    .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
                    .map_err(storage)?;
                table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .map(|value| decode::<SubjectGrantRow>(value.value()))
                    .transpose()?
            };
            if let Some(row) = &current {
                row.validate()?;
                if row.invitation.is_some()
                    && (grant.enabled
                        || grant.not_before_ms != row.not_before_ms
                        || grant.expires_ms != row.expires_ms
                        || (grant.history == GrantHistory::FromGrant) != row.from_grant)
                {
                    return Err(FederationError::Unauthorized);
                }
            }
            if peer.is_none() && current.as_ref().is_none_or(|row| row.invitation.is_none()) {
                return Err(FederationError::NotFound);
            }
            let revision =
                next_revision(current.as_ref().map(|row| row.revision), expected_revision)?;
            let row = SubjectGrantRow {
                revision,
                enabled: grant.enabled,
                not_before_ms: grant.not_before_ms,
                expires_ms: grant.expires_ms,
                from_grant: grant.history == GrantHistory::FromGrant,
                floor: if grant.history == GrantHistory::FromGrant {
                    current
                        .as_ref()
                        .filter(|row| row.invitation.is_some())
                        .map_or_else(
                            || stream.head.map_or(0, |head| head.sequence),
                            |row| row.floor,
                        )
                } else {
                    0
                },
                invitation: current.as_ref().and_then(|row| row.invitation),
            };
            txn.open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
                .map_err(storage)?
                .insert(key.as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(revision)
        })
    }

    fn subject_grant(
        &self,
        subject: &HostedSubject,
        presenter: FederationNodeId,
        stream: StreamRef,
    ) -> Result<Option<SubjectGrantEntry>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let key = subject_grant_key(subject, presenter, stream);
        let row = {
            let table = txn
                .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|value| decode::<SubjectGrantRow>(value.value()))
                .transpose()?
        };
        row.map(|row| {
            subject_grant_entry(
                row,
                SubjectGrantKey {
                    subject: subject.clone(),
                    presenter,
                    stream,
                },
                self.node,
            )
        })
        .transpose()
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
        let start = after.as_deref().unwrap_or_default();
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
            .map_err(storage)?;
        let mut entries = Vec::with_capacity(max);
        for result in table.range(start..).map_err(storage)? {
            let (key, value) = result.map_err(storage)?;
            if after.as_deref() == Some(key.value()) {
                continue;
            }
            let key = parse_subject_grant_key(key.value())?;
            let row = decode::<SubjectGrantRow>(value.value())?;
            entries.push(subject_grant_entry(row, key, self.node)?);
            if entries.len() == max {
                break;
            }
        }
        Ok(entries)
    }

    fn declare_stream(&self, spec: StreamSpec) -> Result<(), FederationError> {
        self.declare_stream_inner(spec)
    }

    fn append_published(&self, request: PublishRequest) -> Result<Record, FederationError> {
        self.append_published_inner(request)
    }

    fn publication_epoch(&self, stream: StreamRef) -> Result<u64, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        publication::epoch_read(&txn, stream)
    }

    fn close_publication_epoch(
        &self,
        stream: StreamRef,
        expected: u64,
    ) -> Result<u64, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let next = publication::close_epoch(txn, stream, expected)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(next)
        })
    }

    fn inspect_publication(
        &self,
        stream: StreamRef,
        retry_epoch: u64,
        publish_id: RequestId,
    ) -> Result<Option<Position>, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        let epoch = publication::epoch_read(&txn, stream)?;
        if retry_epoch == 0 || retry_epoch > epoch {
            return Err(FederationError::Conflict);
        }
        let key = publish_request_key(stream, retry_epoch, publish_id);
        txn.open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| Position::try_from(decode::<StoredPosition>(saved.value())?))
            .transpose()
    }

    fn retire_publication_identities(
        &self,
        receipts: &[PublicationReceipt],
    ) -> Result<usize, FederationError> {
        if receipts
            .iter()
            .any(|receipt| receipt.stream.publisher != self.node)
        {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let removed = publication::retire_identities(txn, receipts)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(removed)
        })
    }

    fn retire_published_history(
        &self,
        stream: StreamRef,
        through: Position,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError> {
        self.with_decision_write(|txn, _| {
            replication::retire_in_transaction(txn, self.node, stream, through, max_records)
        })
    }

    fn open(&self, request: OpenRequest) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.open_inner(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
            AccessPath::Managed,
        )
    }

    fn open_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.open_inner(subject, now_ms, request, AccessPath::Managed)
    }

    fn inspect_subscription(
        &self,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.inspect_subscription_inner(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
            AccessPath::Managed,
        )
    }

    fn inspect_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.inspect_subscription_inner(subject, now_ms, request, AccessPath::Managed)
    }

    fn close_subscription(
        &self,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.close_subscription_inner(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
            AccessPath::Managed,
        )
    }

    fn close_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.close_subscription_inner(subject, now_ms, request, AccessPath::Managed)
    }

    fn install_subscription(
        &self,
        request: InstallSubscriptionRequest,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        self.install_subscription_inner(request)
    }

    fn read(&self, request: ReadRequest) -> Result<ReadPage, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.read_inner(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
            AccessPath::Managed,
        )
    }

    fn read_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.read_inner(subject, now_ms, request, AccessPath::Managed)
    }

    fn accept(&self, request: AcceptRequest) -> Result<AcceptResult, FederationError> {
        self.decision_peer(request.authenticated_publisher)?;
        self.accept_inner(request, None)
    }

    fn read_inbox(&self, request: InboxReadRequest) -> Result<InboxReadPage, FederationError> {
        self.read_inbox_inner(request, None)
    }

    fn acknowledge(&self, request: AcknowledgeRequest) -> Result<Position, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.acknowledge_inner(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
            AccessPath::Managed,
        )
    }

    fn acknowledge_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.acknowledge_inner(subject, now_ms, request, AccessPath::Managed)
    }

    fn record_projection_progress(
        &self,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError> {
        self.record_projection_progress_inner(request, None)
    }

    fn retire_projected_inbox(
        &self,
        subscription: SubscriptionRef,
        max_records: usize,
    ) -> Result<InboxRetirement, FederationError> {
        self.retire_projected_inbox_inner(subscription, max_records, None)
    }
}

impl FederationGuestStore for RedbFederationStore {
    fn authorize_guest_delivery(
        &self,
        subject: &HostedSubject,
        request: InspectSubscriptionRequest,
        payload: bool,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        let view = self.inspect_subscription_read(
            FederationSubject::Hosted(subject.clone()),
            now_ms,
            request,
            AccessPath::Guest,
            true,
        )?;
        if payload && view.closed {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }

    fn bind_guest_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationGuestStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn open_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.open_inner(
            FederationSubject::Hosted(subject),
            now_ms,
            request,
            AccessPath::Guest,
        )
    }

    fn inspect_guest_subscription(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if self.decision.is_none() {
            self.checked_time_ms(now_ms)?;
        }
        self.inspect_subscription_inner(
            FederationSubject::Hosted(subject),
            now_ms,
            request,
            AccessPath::Guest,
        )
    }

    fn close_guest_subscription(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.close_subscription_inner(
            FederationSubject::Hosted(subject),
            now_ms,
            request,
            AccessPath::Guest,
        )
    }

    fn read_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        if self.decision.is_none() {
            self.checked_time_ms(now_ms)?;
        }
        self.read_inner(
            FederationSubject::Hosted(subject),
            now_ms,
            request,
            AccessPath::Guest,
        )
    }

    fn acknowledge_guest(
        &self,
        subject: HostedSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError> {
        self.decision_peer(request.authenticated_subscriber)?;
        self.acknowledge_inner(
            FederationSubject::Hosted(subject),
            now_ms,
            request,
            AccessPath::Guest,
        )
    }
}

fn next_revision(current: Option<u64>, expected: Option<u64>) -> Result<u64, FederationError> {
    if current == Some(0) {
        return Err(FederationError::Corrupt);
    }
    match (current, expected) {
        (None, None) => Ok(1),
        (Some(current), Some(expected)) if current == expected => {
            current.checked_add(1).ok_or(FederationError::Capacity)
        }
        _ => Err(FederationError::Conflict),
    }
}

fn authority_from_rows(
    peer: Option<PeerRow>,
    export: Option<ExportRow>,
    serve: bool,
) -> Result<AuthorityRevision, FederationError> {
    let peer = peer.ok_or(FederationError::Unauthorized)?;
    let export = export.ok_or(FederationError::Unauthorized)?;
    if peer.revision == 0 || export.revision == 0 {
        return Err(FederationError::Corrupt);
    }
    if !peer.enabled || !(if serve { export.serve } else { export.receive }) {
        return Err(FederationError::Unauthorized);
    }
    Ok(AuthorityRevision {
        peer: peer.revision,
        export: export.revision,
    })
}

fn authority_in_read(
    txn: &ReadTransaction,
    peer: FederationNodeId,
    export: &ExportName,
    serve: bool,
) -> Result<AuthorityRevision, FederationError> {
    let peer_row = txn
        .open_table(FEDERATION_PEERS_TABLE)
        .map_err(storage)?
        .get(peer.as_bytes().as_slice())
        .map_err(storage)?
        .map(|value| decode(value.value()))
        .transpose()?;
    let key = export_key(peer, export);
    let export_row = txn
        .open_table(FEDERATION_EXPORTS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|value| decode(value.value()))
        .transpose()?;
    authority_from_rows(peer_row, export_row, serve)
}

fn authority_in_write(
    txn: &redb::WriteTransaction,
    peer: FederationNodeId,
    export: &ExportName,
    serve: bool,
) -> Result<AuthorityRevision, FederationError> {
    let peer_row = txn
        .open_table(FEDERATION_PEERS_TABLE)
        .map_err(storage)?
        .get(peer.as_bytes().as_slice())
        .map_err(storage)?
        .map(|value| decode(value.value()))
        .transpose()?;
    let key = export_key(peer, export);
    let export_row = txn
        .open_table(FEDERATION_EXPORTS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|value| decode(value.value()))
        .transpose()?;
    authority_from_rows(peer_row, export_row, serve)
}

fn publisher_subject_matches(
    stored: Option<&StoredFederationSubject>,
    presenter: FederationNodeId,
    presented: &FederationSubject,
) -> bool {
    stored
        .cloned()
        .map(FederationSubject::from)
        .unwrap_or(FederationSubject::Node(presenter))
        == *presented
}

fn hosted_subject_authority(
    peer: Option<PeerRow>,
    grant: SubjectGrantRow,
    now_ms: u64,
    access: AccessPath,
) -> Result<(AuthorityRevision, u64), FederationError> {
    grant.validate()?;
    if peer.as_ref().is_some_and(|peer| peer.revision == 0) {
        return Err(FederationError::Corrupt);
    }
    // A Guest presenter must remain unconfigured in this grant transaction.
    if (access == AccessPath::Managed && (peer.is_none() || grant.invitation.is_some()))
        || (access == AccessPath::Guest && (peer.is_some() || grant.invitation.is_none()))
        || peer.as_ref().is_some_and(|peer| !peer.enabled)
        || !grant.enabled
        || now_ms < grant.not_before_ms
        || now_ms >= grant.expires_ms
    {
        return Err(FederationError::Unauthorized);
    }
    Ok((
        AuthorityRevision {
            peer: peer.map_or(1, |peer| peer.revision),
            export: grant.revision,
        },
        grant.floor,
    ))
}

fn control_revision_in_write(
    txn: &WriteTransaction,
    presenter: FederationNodeId,
    access: AccessPath,
) -> Result<u64, FederationError> {
    match access {
        AccessPath::Managed => {
            let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
            let row = table
                .get(presenter.as_bytes().as_slice())
                .map_err(storage)?
                .map(|value| decode::<PeerRow>(value.value()))
                .transpose()?
                .ok_or(FederationError::Corrupt)?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            Ok(row.control_revision)
        }
        AccessPath::Guest => Ok(txn
            .open_table(FEDERATION_GUEST_CONTROLS_TABLE)
            .map_err(storage)?
            .get(presenter.as_bytes().as_slice())
            .map_err(storage)?
            .map_or(0, |value| value.value())),
    }
}

fn set_control_revision_in_write(
    txn: &WriteTransaction,
    presenter: FederationNodeId,
    access: AccessPath,
    revision: u64,
) -> Result<(), FederationError> {
    match access {
        AccessPath::Managed => {
            let mut table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
            let saved = table
                .get(presenter.as_bytes().as_slice())
                .map_err(storage)?
                .ok_or(FederationError::Corrupt)?;
            let mut row: PeerRow = decode(saved.value())?;
            drop(saved);
            row.control_revision = revision;
            table
                .insert(presenter.as_bytes().as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
        }
        AccessPath::Guest => {
            txn.open_table(FEDERATION_GUEST_CONTROLS_TABLE)
                .map_err(storage)?
                .insert(presenter.as_bytes().as_slice(), revision)
                .map_err(storage)?;
        }
    }
    Ok(())
}

fn subject_authority_in_read(
    txn: &ReadTransaction,
    subject: &FederationSubject,
    presenter: FederationNodeId,
    stream: StreamRef,
    export: &ExportName,
    now_ms: u64,
    access: AccessPath,
) -> Result<(AuthorityRevision, u64), FederationError> {
    match subject {
        FederationSubject::Node(node) if access == AccessPath::Managed && *node == presenter => {
            Ok((authority_in_read(txn, presenter, export, true)?, 0))
        }
        FederationSubject::Hosted(hosted) => {
            let peer = {
                let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
                table
                    .get(presenter.as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| decode::<PeerRow>(value.value()))
                    .transpose()?
            };
            let grant = {
                let table = txn
                    .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
                    .map_err(storage)?;
                let key = subject_grant_key(hosted, presenter, stream);
                let value = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Unauthorized)?;
                decode::<SubjectGrantRow>(value.value())?
            };
            hosted_subject_authority(peer, grant, now_ms, access)
        }
        _ => Err(FederationError::Unauthorized),
    }
}

fn subject_authority_in_write(
    txn: &WriteTransaction,
    subject: &FederationSubject,
    presenter: FederationNodeId,
    stream: StreamRef,
    export: &ExportName,
    now_ms: u64,
    access: AccessPath,
) -> Result<(AuthorityRevision, u64), FederationError> {
    match subject {
        FederationSubject::Node(node) if access == AccessPath::Managed && *node == presenter => {
            Ok((authority_in_write(txn, presenter, export, true)?, 0))
        }
        FederationSubject::Hosted(hosted) => {
            let peer = {
                let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
                table
                    .get(presenter.as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| decode::<PeerRow>(value.value()))
                    .transpose()?
            };
            let grant = {
                let table = txn
                    .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
                    .map_err(storage)?;
                let key = subject_grant_key(hosted, presenter, stream);
                let value = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Unauthorized)?;
                decode::<SubjectGrantRow>(value.value())?
            };
            hosted_subject_authority(peer, grant, now_ms, access)
        }
        _ => Err(FederationError::Unauthorized),
    }
}

fn storage(error: impl ToString) -> FederationError {
    FederationError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, ensure};

    use super::*;

    #[test]
    fn stored_record_codecs_reject_tampered_payload_and_position() -> anyhow::Result<()> {
        let stream = StreamRef {
            publisher: FederationNodeId::from_bytes([7; 48]),
            id: StreamId::from_bytes([8; 16]),
        };
        let record = Record::new(RecordParts {
            stream,
            sequence: 1,
            publish_id: RequestId::from_bytes([9; 16]),
            event_type: EventType::new("event")?,
            schema_revision: SchemaRevision::from_bytes([10; 32]),
            event_ref: Some(EventRef::new(stream.publisher, "events", "one")?),
            payload: Arc::from(&b"payload"[..]),
        })?;
        for public_follow in [false, true] {
            let mut encoded = if public_follow {
                crate::federation_public_follow::encode_record(&record)?
            } else {
                encode_record(&record)?
            };
            let decode = |stream, sequence, bytes: &[u8]| {
                if public_follow {
                    crate::federation_public_follow::decode_record(stream, sequence, bytes)
                } else {
                    decode_record(stream, sequence, bytes)
                }
            };
            ensure!(decode(stream, 1, &encoded)? == record);
            ensure!(matches!(
                decode(stream, 2, &encoded),
                Err(FederationError::Corrupt)
            ));
            let mut other_stream = stream;
            other_stream.id = StreamId::from_bytes([11; 16]);
            ensure!(matches!(
                decode(other_stream, 1, &encoded),
                Err(FederationError::Corrupt)
            ));
            let last = encoded.last_mut().context("encoded payload")?;
            *last ^= 1;
            ensure!(matches!(
                decode(stream, 1, &encoded),
                Err(FederationError::Corrupt)
            ));
        }
        Ok(())
    }

    #[test]
    fn persistent_keys_and_positions_use_v1_48_byte_ids_and_digests() -> anyhow::Result<()> {
        let node = FederationNodeId::from_bytes([7; 48]);
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes([8; 16]),
        };
        let key = stream_key(stream);
        ensure!(key.len() == 64);
        ensure!(&key[..48] == node.as_bytes());
        ensure!(&key[48..] == stream.id.as_bytes());
        ensure!(record_key(stream, 1).len() == 72);

        let position = StoredPosition {
            sequence: 1,
            digest: [9; 48],
        };
        let encoded = serde_json::to_vec(&position)?;
        let decoded: StoredPosition = serde_json::from_slice(&encoded)?;
        ensure!(decoded.digest == [9; 48]);

        let obsolete = serde_json::json!({"sequence": 1, "digest": vec![9u8; 32]});
        ensure!(serde_json::from_value::<StoredPosition>(obsolete).is_err());
        Ok(())
    }

    #[test]
    fn corrupt_or_oversized_authority_rows_fail_closed() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("federation.redb"))?;
        let node = FederationNodeId::from_bytes([1; NODE_ID_LEN]);
        let peer = FederationNodeId::from_bytes([2; NODE_ID_LEN]);
        let federation = db.federation_store(node)?;
        ensure!(federation.set_peer_authority(peer, None, true)? == 1);

        for corrupt in [
            br#"{"revision":1,"enabled":true,"control_revision":0,"unknown":true}"#.to_vec(),
            vec![b' '; MAX_ROW_BYTES + 1],
        ] {
            let txn = db.db.begin_write()?;
            txn.open_table(FEDERATION_PEERS_TABLE)?
                .insert(peer.as_bytes().as_slice(), corrupt.as_slice())?;
            txn.commit()?;
            ensure!(matches!(
                federation.set_peer_authority(peer, Some(1), false),
                Err(FederationError::Corrupt)
            ));
        }

        let txn = db.db.begin_write()?;
        txn.open_table(FEDERATION_PEERS_TABLE)?.insert(
            peer.as_bytes().as_slice(),
            encode(&PeerRow {
                revision: 1,
                enabled: true,
                control_revision: 0,
                manifest_owned: false,
            })?
            .as_slice(),
        )?;
        txn.commit()?;
        ensure!(federation.set_peer_authority(peer, Some(1), false)? == 2);
        Ok(())
    }

    #[test]
    fn changed_persisted_record_rejects_replay_read_and_acknowledgement() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("federation.redb"))?;
        let node = FederationNodeId::from_bytes([11; NODE_ID_LEN]);
        let peer = FederationNodeId::from_bytes([12; NODE_ID_LEN]);
        let federation = db.federation_store(node)?;
        let export = ExportName::new("notes")?;
        federation.set_peer_authority(peer, None, true)?;
        federation.set_export_authority(
            peer,
            export.clone(),
            None,
            ExportAccess {
                serve: true,
                receive: false,
            },
        )?;
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes([13; 16]),
        };
        let subscription = SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([14; 16]),
        };
        federation.declare_stream(StreamSpec { stream, export })?;
        federation.open(OpenRequest {
            authenticated_subscriber: peer,
            request_id: RequestId::from_bytes([15; 16]),
            subscription,
            stream,
            expected_control_revision: Some(0),
            history: HistoryStart::All,
        })?;
        let request = PublishRequest {
            retry_epoch: 1,
            stream,
            publish_id: RequestId::from_bytes([16; 16]),
            event_type: EventType::new("note.created")?,
            schema_revision: SchemaRevision::from_bytes([17; 32]),
            event_ref: None,
            payload: Arc::from(b"first".as_slice()),
        };
        let record = federation.append_published(request.clone())?;
        let original = encode_record(&record)?;
        let mut changed = original.clone();
        *changed.last_mut().context("empty encoded record")? ^= 1;
        let txn = db.db.begin_write()?;
        txn.open_table(FEDERATION_RECORDS_TABLE)?.insert(
            record_key(stream, record.sequence()).as_slice(),
            changed.as_slice(),
        )?;
        txn.commit()?;
        ensure!(matches!(
            federation.append_published(request.clone()),
            Err(FederationError::Corrupt)
        ));
        ensure!(matches!(
            federation.read(ReadRequest {
                authenticated_subscriber: peer,
                subscription,
                after: None,
                max_records: 1,
                max_bytes: 32,
            }),
            Err(FederationError::Corrupt)
        ));
        ensure!(matches!(
            federation.acknowledge(AcknowledgeRequest {
                authenticated_subscriber: peer,
                subscription,
                position: record.position(),
            }),
            Err(FederationError::Corrupt)
        ));
        let txn = db.db.begin_write()?;
        txn.open_table(FEDERATION_RECORDS_TABLE)?.insert(
            record_key(stream, record.sequence()).as_slice(),
            original.as_slice(),
        )?;
        txn.commit()?;
        ensure!(federation.append_published(request)? == record);
        Ok(())
    }

    #[test]
    fn admitted_guest_read_survives_another_sessions_later_clock_observation() -> anyhow::Result<()>
    {
        use xolotl_federation::{
            FederationInvitationStore, InvitationAudience, InvitationId, InvitationSpec,
            RedeemInvitationRequest,
        };

        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("federation.redb"))?;
        let node = FederationNodeId::from_bytes([71; NODE_ID_LEN]);
        let guest = FederationNodeId::from_bytes([72; NODE_ID_LEN]);
        let subject = HostedSubject {
            issuer: SubjectIssuerId::from_bytes([73; NODE_ID_LEN]),
            namespace: "people".into(),
            subject: "guest".into(),
        };
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes([74; 16]),
        };
        let subscription = SubscriptionRef {
            subscriber: guest,
            id: SubscriptionId::from_bytes([75; 16]),
        };
        let invitation = InvitationId::from_sequence(1);
        let federation = db.federation_store(node)?;
        federation.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("pictures")?,
        })?;
        federation.set_invitation_issuer_authority(&subject, stream, None, true)?;
        federation.create_invitation(
            invitation,
            InvitationSpec {
                issuer: subject.clone(),
                stream,
                audience: InvitationAudience::Named {
                    presenter: guest,
                    subject: subject.clone(),
                },
                not_before_ms: 10,
                expires_ms: 100,
                grant_expires_ms: 100,
                max_redemptions: 1,
                history: GrantHistory::All,
            },
            10,
        )?;
        federation.redeem_invitation(RedeemInvitationRequest {
            invitation,
            request_id: RequestId::from_bytes([76; 16]),
            authenticated_presenter: guest,
            subject: subject.clone(),
            expected_invitation_revision: 1,
            secret: None,
            now_ms: 20,
        })?;
        federation.open_guest(
            subject.clone(),
            21,
            OpenRequest {
                authenticated_subscriber: guest,
                request_id: RequestId::from_bytes([77; 16]),
                subscription,
                stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            },
        )?;
        let read = ReadRequest {
            authenticated_subscriber: guest,
            subscription,
            after: None,
            max_records: 1,
            max_bytes: 32,
        };
        federation.checked_time_ms(22)?;
        federation.checked_time_ms(23)?;
        // The first session already passed its durable time admission at 22.
        // Its later read can complete; a new request at 22 is a rollback.
        ensure!(
            federation
                .read_inner(
                    FederationSubject::Hosted(subject.clone()),
                    22,
                    read.clone(),
                    AccessPath::Guest,
                )?
                .records
                .is_empty()
        );
        ensure!(
            federation
                .inspect_subscription_inner(
                    FederationSubject::Hosted(subject.clone()),
                    22,
                    InspectSubscriptionRequest {
                        authenticated_subscriber: guest,
                        subscription,
                    },
                    AccessPath::Guest,
                )
                .is_ok()
        );
        ensure!(matches!(
            federation.read_guest(subject, 22, read),
            Err(FederationError::ClockRollback)
        ));
        Ok(())
    }
}
