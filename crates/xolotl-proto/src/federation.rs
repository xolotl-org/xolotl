// Hand-maintained prost/tonic bindings for proto/xolotl/v1/federation.proto.
// Keep this module synchronized with the v1 schema; builds do not use protoc.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncFrame {
    #[prost(
        oneof = "sync_frame::Body",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37"
    )]
    pub body: Option<sync_frame::Body>,
}

pub mod sync_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "1")]
        Hello(super::Hello),
        #[prost(message, tag = "2")]
        Open(super::Open),
        #[prost(message, tag = "3")]
        Opened(super::Opened),
        #[prost(message, tag = "4")]
        Read(super::Read),
        #[prost(message, tag = "5")]
        Batch(super::Batch),
        #[prost(message, tag = "6")]
        Acknowledge(super::Acknowledge),
        #[prost(message, tag = "7")]
        Acknowledged(super::Acknowledged),
        #[prost(message, tag = "8")]
        Failure(super::SyncFailure),
        #[prost(message, tag = "9")]
        Authenticate(super::Authenticate),
        #[prost(message, tag = "10")]
        Inspect(super::Inspect),
        #[prost(message, tag = "11")]
        Inspected(super::Inspected),
        #[prost(message, tag = "12")]
        Close(super::Close),
        #[prost(message, tag = "13")]
        Closed(super::Closed),
        #[prost(message, tag = "14")]
        RegisterSubject(super::RegisterSubject),
        #[prost(message, tag = "15")]
        SubjectRegistered(super::SubjectRegistered),
        #[prost(message, tag = "16")]
        PrepareCall(super::PrepareCall),
        #[prost(message, tag = "17")]
        CallPrepared(super::CallPrepared),
        #[prost(message, tag = "18")]
        InvokeCall(super::InvokeCall),
        #[prost(message, tag = "19")]
        CallInvoked(super::CallInvoked),
        #[prost(message, tag = "20")]
        InspectCall(super::InspectCall),
        #[prost(message, tag = "21")]
        CallInspected(super::CallInspected),
        #[prost(message, tag = "22")]
        CancelCall(super::CancelCall),
        #[prost(message, tag = "23")]
        CallCancelled(super::CallCancelled),
        #[prost(message, tag = "24")]
        InspectPublic(super::InspectPublic),
        #[prost(message, tag = "25")]
        PublicInspected(super::PublicInspected),
        #[prost(message, tag = "26")]
        ReadPublic(super::ReadPublic),
        #[prost(message, tag = "27")]
        PublicBatch(super::PublicBatch),
        #[prost(message, tag = "28")]
        ReadObject(super::ReadObject),
        #[prost(message, tag = "29")]
        ObjectChunk(super::ObjectChunk),
        #[prost(message, tag = "30")]
        RedeemInvitation(super::RedeemInvitation),
        #[prost(message, tag = "31")]
        InvitationRedeemed(super::InvitationRedeemed),
        #[prost(message, tag = "32")]
        InspectSnapshot(super::InspectSnapshot),
        #[prost(message, tag = "33")]
        SnapshotOffered(super::SnapshotOffered),
        #[prost(message, tag = "34")]
        ReadSnapshot(super::ReadSnapshot),
        #[prost(message, tag = "35")]
        SnapshotChunk(super::SnapshotChunk),
        #[prost(message, tag = "36")]
        ReceiveSnapshot(super::ReceiveSnapshot),
        #[prost(message, tag = "37")]
        SnapshotReceived(super::SnapshotReceived),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Hello {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub node_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub max_frame_bytes: u64,
    #[prost(uint32, tag = "4")]
    pub max_in_flight: u32,
    #[prost(uint32, tag = "5")]
    pub max_batch_records: u32,
    #[prost(uint64, tag = "6")]
    pub max_batch_bytes: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub root_descriptor: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub online_authorization: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub root_signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub nonce: Vec<u8>,
    #[prost(uint32, repeated, tag = "11")]
    pub required_features: Vec<u32>,
    #[prost(uint32, tag = "12")]
    pub served_capabilities: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Authenticate {
    #[prost(bytes = "vec", tag = "1")]
    pub online_signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum SubjectPurpose {
    Unspecified = 0,
    Discover = 1,
    Sync = 2,
    Invoke = 3,
    ObjectRead = 4,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterSubject {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(uint32, tag = "2")]
    pub context_id: u32,
    #[prost(enumeration = "SubjectPurpose", tag = "3")]
    pub purpose: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub issuer_descriptor: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub assertion: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub issuer_signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub holder_presentation: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubjectRegistered {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(uint32, tag = "2")]
    pub context_id: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RedeemInvitation {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub invitation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub request_id: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub expected_revision: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub secret: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvitationRedeemed {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub invitation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub request_id: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub stream: Option<StreamRef>,
    #[prost(uint64, tag = "5")]
    pub grant_revision: u64,
    #[prost(uint64, tag = "6")]
    pub grant_expires_ms: u64,
    #[prost(uint64, tag = "7")]
    pub history_floor: u64,
    #[prost(bool, tag = "8")]
    pub currently_authorized: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamRef {
    #[prost(bytes = "vec", tag = "1")]
    pub publisher: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscriptionRef {
    #[prost(bytes = "vec", tag = "1")]
    pub subscriber: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Position {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub digest: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum HistoryMode {
    Unspecified = 0,
    All = 1,
    After = 2,
    FromNow = 3,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Open {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, optional, tag = "4")]
    pub stream: Option<StreamRef>,
    #[prost(uint64, optional, tag = "5")]
    pub expected_control_revision: Option<u64>,
    #[prost(enumeration = "HistoryMode", tag = "6")]
    pub history_mode: i32,
    #[prost(message, optional, tag = "7")]
    pub history_after: Option<Position>,
    #[prost(uint32, tag = "8")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "9")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Opened {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, optional, tag = "4")]
    pub stream: Option<StreamRef>,
    #[prost(string, tag = "5")]
    pub export_name: String,
    #[prost(uint64, tag = "6")]
    pub publisher_peer_revision: u64,
    #[prost(uint64, tag = "7")]
    pub publisher_export_revision: u64,
    #[prost(uint64, tag = "8")]
    pub subscription_revision: u64,
    #[prost(message, optional, tag = "9")]
    pub start: Option<Position>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Read {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, optional, tag = "3")]
    pub after: Option<Position>,
    #[prost(uint32, tag = "4")]
    pub max_records: u32,
    #[prost(uint64, tag = "5")]
    pub max_bytes: u64,
    #[prost(uint32, tag = "6")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventRef {
    #[prost(bytes = "vec", tag = "1")]
    pub origin: Vec<u8>,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(string, tag = "3")]
    pub id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Record {
    #[prost(message, optional, tag = "1")]
    pub stream: Option<StreamRef>,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub publish_id: Vec<u8>,
    #[prost(string, tag = "4")]
    pub event_type: String,
    #[prost(bytes = "vec", tag = "5")]
    pub schema_revision: Vec<u8>,
    #[prost(message, optional, tag = "6")]
    pub event_ref: Option<EventRef>,
    #[prost(bytes = "vec", tag = "7")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub digest: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Batch {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, repeated, tag = "3")]
    pub records: Vec<Record>,
    #[prost(message, optional, tag = "4")]
    pub head: Option<Position>,
    #[prost(uint64, tag = "5")]
    pub minimum_available: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotManifest {
    #[prost(bytes = "vec", tag = "1")]
    pub snapshot_id: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, optional, tag = "3")]
    pub stream: Option<StreamRef>,
    #[prost(uint64, tag = "4")]
    pub subscription_revision: u64,
    #[prost(uint64, tag = "5")]
    pub publisher_peer_revision: u64,
    #[prost(uint64, tag = "6")]
    pub publisher_export_revision: u64,
    #[prost(message, optional, tag = "7")]
    pub position: Option<Position>,
    #[prost(bytes = "vec", tag = "8")]
    pub schema_revision: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub content_digest: Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub content_bytes: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotOffer {
    #[prost(message, optional, tag = "1")]
    pub manifest: Option<SnapshotManifest>,
    #[prost(bytes = "vec", tag = "2")]
    pub publication_digest: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InspectSnapshot {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(uint32, tag = "3")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotOffered {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub offer: Option<SnapshotOffer>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadSnapshot {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(bytes = "vec", tag = "3")]
    pub manifest_digest: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub offset: u64,
    #[prost(uint32, tag = "5")]
    pub max_bytes: u32,
    #[prost(uint32, tag = "6")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotChunk {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(bytes = "vec", tag = "3")]
    pub manifest_digest: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub offset: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub data: Vec<u8>,
    #[prost(bool, tag = "6")]
    pub complete: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReceiveSnapshot {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(bytes = "vec", tag = "3")]
    pub manifest_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub publication_digest: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub position: Option<Position>,
    #[prost(uint32, tag = "6")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub holder_request_signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub install_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub archive_digest: Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub federation_generation: u64,
    #[prost(message, optional, tag = "11")]
    pub suffix: Option<SnapshotSuffixCoverage>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotSuffixCoverage {
    #[prost(message, optional, tag = "1")]
    pub after: Option<Position>,
    #[prost(message, optional, tag = "2")]
    pub through: Option<Position>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotReceived {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(bytes = "vec", tag = "3")]
    pub manifest_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub publication_digest: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub position: Option<Position>,
    #[prost(bytes = "vec", tag = "6")]
    pub install_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub archive_digest: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub federation_generation: u64,
    #[prost(message, optional, tag = "9")]
    pub suffix: Option<SnapshotSuffixCoverage>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InspectPublic {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub stream: Option<StreamRef>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicInspected {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub stream: Option<StreamRef>,
    #[prost(string, tag = "3")]
    pub export_name: String,
    #[prost(uint64, tag = "4")]
    pub policy_revision: u64,
    #[prost(message, optional, tag = "5")]
    pub head: Option<Position>,
    #[prost(uint64, tag = "6")]
    pub minimum_available: u64,
    #[prost(uint32, tag = "7")]
    pub max_read_records: u32,
    #[prost(uint64, tag = "8")]
    pub max_read_bytes: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadPublic {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub stream: Option<StreamRef>,
    #[prost(uint64, tag = "3")]
    pub expected_policy_revision: u64,
    #[prost(message, optional, tag = "4")]
    pub after: Option<Position>,
    #[prost(uint32, tag = "5")]
    pub max_records: u32,
    #[prost(uint64, tag = "6")]
    pub max_bytes: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicBatch {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub stream: Option<StreamRef>,
    #[prost(uint64, tag = "3")]
    pub policy_revision: u64,
    #[prost(message, repeated, tag = "4")]
    pub records: Vec<Record>,
    #[prost(message, optional, tag = "5")]
    pub head: Option<Position>,
    #[prost(uint64, tag = "6")]
    pub minimum_available: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectBlobRef {
    #[prost(bytes = "vec", tag = "1")]
    pub sha384: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub size: u64,
    #[prost(string, optional, tag = "3")]
    pub mime: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadObject {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub transfer_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub grant_id: u64,
    #[prost(uint64, tag = "4")]
    pub expected_revision: u64,
    #[prost(message, optional, tag = "5")]
    pub blob: Option<ObjectBlobRef>,
    #[prost(uint64, tag = "6")]
    pub offset: u64,
    #[prost(uint32, tag = "7")]
    pub max_bytes: u32,
    #[prost(uint32, tag = "8")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "9")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectChunk {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub transfer_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub grant_id: u64,
    #[prost(uint64, tag = "4")]
    pub revision: u64,
    #[prost(uint64, tag = "5")]
    pub offset: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub data: Vec<u8>,
    #[prost(bool, tag = "7")]
    pub end_of_object: bool,
    #[prost(bool, tag = "8")]
    pub end_of_range: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acknowledge {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, optional, tag = "3")]
    pub position: Option<Position>,
    #[prost(uint32, tag = "4")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acknowledged {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub position: Option<Position>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Inspect {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(uint32, tag = "3")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Inspected {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(message, optional, tag = "3")]
    pub stream: Option<StreamRef>,
    #[prost(string, tag = "4")]
    pub export_name: String,
    #[prost(uint64, tag = "5")]
    pub subscription_revision: u64,
    #[prost(message, optional, tag = "6")]
    pub start: Option<Position>,
    #[prost(message, optional, tag = "7")]
    pub acknowledged: Option<Position>,
    #[prost(message, optional, tag = "8")]
    pub head: Option<Position>,
    #[prost(uint64, tag = "9")]
    pub minimum_available: u64,
    #[prost(bool, tag = "10")]
    pub closed: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Close {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(uint64, optional, tag = "4")]
    pub expected_subscription_revision: Option<u64>,
    #[prost(uint32, tag = "5")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Closed {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub subscription: Option<SubscriptionRef>,
    #[prost(uint64, tag = "4")]
    pub subscription_revision: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallRef {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum CallStatus {
    Unspecified = 0,
    Reserved = 1,
    Preparing = 2,
    Accepted = 3,
    Finished = 4,
    Closed = 5,
    Unproven = 6,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrepareCall {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub origin_request_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub export_name: String,
    #[prost(string, tag = "4")]
    pub relative_path: String,
    #[prost(string, tag = "5")]
    pub method: String,
    #[prost(bytes = "vec", tag = "6")]
    pub contract_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub input_digest: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub input_bytes: u64,
    #[prost(uint64, tag = "9")]
    pub prepare_deadline_ms: u64,
    #[prost(uint64, tag = "10")]
    pub execution_deadline_ms: u64,
    #[prost(uint64, tag = "11")]
    pub result_retention_ms: u64,
    #[prost(uint32, tag = "12")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "13")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallPrepared {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub origin_request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub call: Option<CallRef>,
    #[prost(enumeration = "CallStatus", tag = "4")]
    pub status: i32,
    #[prost(uint64, tag = "5")]
    pub reserved_until_ms: u64,
    #[prost(uint64, tag = "6")]
    pub execution_deadline_ms: u64,
    #[prost(uint64, tag = "7")]
    pub result_retention_ms: u64,
    #[prost(uint64, tag = "8")]
    pub authority_revision: u64,
    #[prost(uint64, tag = "9")]
    pub control_revision: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvokeCall {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub origin_request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub call: Option<CallRef>,
    #[prost(bytes = "vec", tag = "4")]
    pub input: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallInvoked {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub call: Option<CallRef>,
    #[prost(enumeration = "CallStatus", tag = "3")]
    pub status: i32,
    #[prost(uint64, tag = "4")]
    pub control_revision: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InspectCall {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub call: Option<CallRef>,
    #[prost(uint32, tag = "3")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PersistedCallResult {
    #[prost(bool, tag = "1")]
    pub succeeded: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub output: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub output_digest: Vec<u8>,
    #[prost(string, tag = "4")]
    pub failure_code: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallInspected {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(message, optional, tag = "2")]
    pub call: Option<CallRef>,
    #[prost(enumeration = "CallStatus", tag = "3")]
    pub status: i32,
    #[prost(uint64, tag = "4")]
    pub control_revision: u64,
    #[prost(uint64, tag = "5")]
    pub authority_revision: u64,
    #[prost(uint64, tag = "6")]
    pub reserved_until_ms: u64,
    #[prost(uint64, tag = "7")]
    pub execution_deadline_ms: u64,
    #[prost(uint64, tag = "8")]
    pub result_retained_until_ms: u64,
    #[prost(message, optional, tag = "9")]
    pub result: Option<PersistedCallResult>,
    #[prost(bytes = "vec", repeated, tag = "10")]
    pub unresolved_effect_ids: Vec<Vec<u8>>,
    #[prost(bool, tag = "11")]
    pub cancellation_requested: bool,
    #[prost(bool, tag = "12")]
    pub kernel_cancel_accepted: bool,
    #[prost(bool, tag = "13")]
    pub execution_stopped: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CancelCall {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub control_request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub call: Option<CallRef>,
    #[prost(uint64, optional, tag = "4")]
    pub expected_control_revision: Option<u64>,
    #[prost(uint32, tag = "5")]
    pub context_id: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub holder_request_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallCancelled {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub control_request_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub call: Option<CallRef>,
    #[prost(enumeration = "CallStatus", tag = "4")]
    pub status: i32,
    #[prost(uint64, tag = "5")]
    pub control_revision: u64,
    #[prost(bool, tag = "6")]
    pub cancellation_requested: bool,
    #[prost(bool, tag = "7")]
    pub kernel_cancel_accepted: bool,
    #[prost(bool, tag = "8")]
    pub execution_stopped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum FailureCode {
    Unspecified = 0,
    Invalid = 1,
    Forbidden = 2,
    Conflict = 3,
    ResyncRequired = 4,
    Capacity = 5,
    Unavailable = 6,
    Internal = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CommitVerdict {
    Unspecified = 0,
    NotCommitted = 1,
    Committed = 2,
    Indeterminate = 3,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncFailure {
    #[prost(uint64, tag = "1")]
    pub request: u64,
    #[prost(enumeration = "FailureCode", tag = "2")]
    pub code: i32,
    #[prost(string, tag = "3")]
    pub message: String,
    #[prost(enumeration = "CommitVerdict", tag = "4")]
    pub commit_verdict: i32,
}

#[cfg(feature = "grpc")]
pub mod federation_service_server {
    use tonic::codegen::*;
    /// Server implementation of the peer session protocol.
    #[async_trait]
    pub trait FederationService: std::marker::Send + std::marker::Sync + 'static {
        /// Peer-to-peer frames for one session; stream errors terminate the RPC.
        type SessionStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::SyncFrame, tonic::Status>,
            > + std::marker::Send
            + 'static;
        /// Accept a bidirectional peer connection.
        /// Both peers exchange `Hello` before processing control or record frames.
        async fn session(
            &self,
            request: tonic::Request<tonic::Streaming<super::SyncFrame>>,
        ) -> std::result::Result<tonic::Response<Self::SessionStream>, tonic::Status>;
    }
    /// Peer synchronization service.
    #[derive(Debug)]
    pub struct FederationServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T> FederationServiceServer<T> {
        /// Wrap an owned session implementation in a tonic service.
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        /// Wrap a shared session implementation without creating another instance.
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        /// Intercept each incoming RPC request before session handling.
        /// The interceptor does not validate individual frames inside the stream.
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Accept and decompress request messages using this encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Enable response compression when the client advertises this encoding.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limit the decoded bytes of each incoming gRPC message.
        /// This is a per-frame limit, independent of cumulative session traffic.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limit the encoded bytes of each outgoing gRPC message.
        /// This does not grant flow credits or bound total session traffic.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for FederationServiceServer<T>
    where
        T: FederationService,
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/xolotl.v1.federation.FederationService/Session" => {
                    struct SessionSvc<T: FederationService>(pub Arc<T>);
                    impl<T: FederationService> tonic::server::StreamingService<super::SyncFrame> for SessionSvc<T> {
                        type Response = super::SyncFrame;
                        type ResponseStream = T::SessionStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::SyncFrame>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as FederationService>::session(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SessionSvc(inner);
                        let codec = tonic_prost::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    let headers = response.headers_mut();
                    headers.insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    headers.insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                }),
            }
        }
    }
    impl<T> Clone for FederationServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    /// Fully qualified protobuf service name used for tonic routing.
    pub const SERVICE_NAME: &str = "xolotl.v1.federation.FederationService";
    impl<T> tonic::server::NamedService for FederationServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
/// Tonic client binding for the bidirectional federation session RPC.
#[cfg(feature = "grpc")]
pub mod federation_service_client {
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    /// Client for a peer's federation session service.
    #[derive(Debug, Clone)]
    pub struct FederationServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    #[cfg(feature = "transport")]
    impl FederationServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> FederationServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        /// Create a client over an existing tonic-compatible gRPC transport.
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        /// Create a client with an explicit URI origin for outgoing RPC requests.
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        /// Intercept outgoing RPC metadata before sending the session request.
        /// Individual stream frames still require the protocol handshake and validation.
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> FederationServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                    http::Request<tonic::body::Body>,
                    Response = http::Response<
                        <T as tonic::client::GrpcService<tonic::body::Body>>::ResponseBody,
                    >,
                >,
            <T as tonic::codegen::Service<http::Request<tonic::body::Body>>>::Error:
                Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            FederationServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress outgoing request messages with the selected encoding.
        /// The peer must accept that encoding.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Advertise support for responses compressed with this encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limit the decoded bytes of each peer-to-client gRPC message.
        /// The limit does not accumulate across frames in the session.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limit the encoded bytes of each client-to-peer gRPC message.
        /// This is separate from protocol flow-control signals.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Open the bidirectional federation session RPC and return peer frames.
        /// The first frame from each peer must be `Hello`; opening the RPC alone
        /// does not authenticate a peer.
        pub async fn session(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::SyncFrame>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::SyncFrame>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.federation.FederationService/Session",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.federation.FederationService",
                "Session",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
