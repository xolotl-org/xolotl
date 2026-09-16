// @generated - hand-maintained to match `tonic-prost-build` output for
// `proto/xolotl/v1/application.proto` (package `xolotl.v1.application`).
// Included in `xolotl::v1::application`; keep in sync with the schema.

/// Request the authenticated caller's visible profile descriptor.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribeRequest {}

/// Redacted Gateway discovery; authorization policy remains server-owned.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribeResponse {
    /// Active profile name.
    #[prost(string, tag = "1")]
    pub profile_name: ::prost::alloc::string::String,
    /// Active profile revision, without floating-point narrowing.
    #[prost(uint64, tag = "2")]
    pub profile_rev: u64,
    /// Surfaces visible to the authenticated caller.
    #[prost(message, repeated, tag = "3")]
    pub surfaces: ::prost::alloc::vec::Vec<SurfaceDescriptor>,
    /// Protocol publications visible to the authenticated caller.
    #[prost(message, repeated, tag = "4")]
    pub publications: ::prost::alloc::vec::Vec<PublicationDescriptor>,
    /// Effective admission limits for the active profile.
    #[prost(message, optional, tag = "5")]
    pub limits: ::core::option::Option<LimitProfile>,
}

/// Public description of one authenticated surface.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SurfaceDescriptor {
    /// Stable id used by ticket and submission requests.
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    /// Resource name exposed by the surface.
    #[prost(message, optional, tag = "2")]
    pub target: ::core::option::Option<super::Path>,
    /// Optional input schema in the common typed value format.
    #[prost(message, optional, tag = "3")]
    pub input_schema: ::core::option::Option<super::Value>,
    /// Optional output schema in the common typed value format.
    #[prost(message, optional, tag = "4")]
    pub output_schema: ::core::option::Option<super::Value>,
    /// Optional schema for each incremental output, independent of the final value.
    #[prost(message, optional, tag = "5")]
    pub output_stream_schema: ::core::option::Option<super::Value>,
}

/// Protocol metadata published for one visible surface.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicationDescriptor {
    /// Owning protocol adapter.
    #[prost(string, tag = "1")]
    pub protocol: ::prost::alloc::string::String,
    /// Protocol object category.
    #[prost(string, tag = "2")]
    pub kind: ::prost::alloc::string::String,
    /// Stable protocol-visible name.
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    /// Address when distinct from the name.
    #[prost(string, optional, tag = "4")]
    pub address: ::core::option::Option<::prost::alloc::string::String>,
    /// Gateway surface selected by this publication.
    #[prost(string, tag = "5")]
    pub surface_id: ::prost::alloc::string::String,
    /// Optional display title.
    #[prost(string, optional, tag = "6")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    /// Optional description.
    #[prost(string, optional, tag = "7")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    /// Adapter-specific properties preserving the common value types.
    #[prost(map = "string, message", tag = "8")]
    pub properties: ::std::collections::HashMap<::prost::alloc::string::String, super::Value>,
    /// Optional protocol annotations.
    #[prost(message, optional, tag = "9")]
    pub annotations: ::core::option::Option<super::Value>,
    /// Optional protocol metadata.
    #[prost(message, optional, tag = "10")]
    pub metadata: ::core::option::Option<super::Value>,
}

/// Typed admission limits; unsigned fields preserve their full range.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LimitProfile {
    /// Maximum inline literal bytes per submission.
    #[prost(uint64, tag = "1")]
    pub max_literal_bytes: u64,
    /// Maximum requested collection limit.
    #[prost(uint64, tag = "2")]
    pub max_collect_limit: u64,
    /// Maximum future offset for deadlines and ticket expiry.
    #[prost(int64, tag = "3")]
    pub max_deadline_ms_from_now: i64,
    /// Maximum concurrently executing submissions.
    #[prost(uint64, tag = "4")]
    pub max_in_flight_requests: u64,
    /// Maximum concurrently executing submissions per principal.
    #[prost(uint64, tag = "5")]
    pub max_principal_in_flight_requests: u64,
    /// Maximum concurrently executing submissions per surface.
    #[prost(uint64, tag = "6")]
    pub max_surface_in_flight_requests: u64,
    /// Maximum concurrently executing submissions per risk class.
    #[prost(uint64, tag = "7")]
    pub max_risk_class_in_flight_requests: u64,
    /// Aggregate request budgets reserved before execution.
    #[prost(message, optional, tag = "8")]
    pub budget: ::core::option::Option<BudgetProfile>,
    /// Maximum items in one input stream.
    #[prost(uint64, tag = "9")]
    pub max_stream_items: u64,
    /// Maximum folded inline bytes in one input stream.
    #[prost(uint64, tag = "10")]
    pub max_stream_bytes: u64,
    /// Maximum inline bytes per input stream item.
    #[prost(uint64, tag = "11")]
    pub max_stream_inline_item_bytes: u64,
}

/// Optional aggregate budgets, independent of transport frame size.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetProfile {
    /// Maximum outstanding operation leaves.
    #[prost(uint64, optional, tag = "1")]
    pub max_inflight_ops: ::core::option::Option<u64>,
    /// Maximum outstanding requested wall time in milliseconds.
    #[prost(uint64, optional, tag = "2")]
    pub max_wall_ms: ::core::option::Option<u64>,
    /// Maximum outstanding ingress bytes.
    #[prost(uint64, optional, tag = "3")]
    pub max_bytes_in: ::core::option::Option<u64>,
    /// Maximum outstanding estimated egress bytes.
    #[prost(uint64, optional, tag = "4")]
    pub max_bytes_out: ::core::option::Option<u64>,
    /// Maximum outstanding inline value bytes.
    #[prost(uint64, optional, tag = "5")]
    pub max_inline_value_bytes: ::core::option::Option<u64>,
    /// Maximum outstanding input stream items.
    #[prost(uint64, optional, tag = "6")]
    pub max_stream_items: ::core::option::Option<u64>,
    /// Maximum outstanding estimated method cost in micro-USD.
    #[prost(uint64, optional, tag = "7")]
    pub max_estimated_cost_micro_usd: ::core::option::Option<u64>,
}

/// Expected input modality, aligned with the Gateway's common value model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Modality {
    /// Missing modality, rejected by checked conversion.
    Unspecified = 0,
    /// Structured value.
    Value = 1,
    /// Inline text.
    Text = 2,
    /// Opaque bytes or blob reference.
    Bytes = 3,
    /// Numeric tensor reference.
    Tensor = 4,
    /// Timestamped audio sample.
    AudioFrame = 5,
    /// Timestamped video sample.
    VideoFrame = 6,
    /// Timestamped pose sample.
    PoseFrame = 7,
    /// Timestamped sensor sample.
    SensorFrame = 8,
    /// Structured event.
    Event = 9,
    /// Structured control message.
    Control = 10,
}

/// Reserve an object upload bound to a principal, surface and optional token.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IssueUploadTicketRequest {
    /// Surface that will admit the committed object.
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    /// Optional submission token bound to the ticket.
    #[prost(string, optional, tag = "2")]
    pub submission_token: ::core::option::Option<::prost::alloc::string::String>,
    /// Expected object modality, validated against the Gateway profile.
    #[prost(enumeration = "Modality", tag = "3")]
    pub modality: i32,
    /// Expected size, or absent when unknown before upload.
    #[prost(uint64, optional, tag = "4")]
    pub expected_size: ::core::option::Option<u64>,
    /// Expected lowercase BLAKE3 digest, when known.
    #[prost(string, optional, tag = "5")]
    pub expected_digest: ::core::option::Option<::prost::alloc::string::String>,
    /// Allowed media types or media type patterns.
    #[prost(string, repeated, tag = "6")]
    pub allowed_media_types: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Requested time to live, bounded by the profile.
    #[prost(uint64, optional, tag = "7")]
    pub expires_in_ms: ::core::option::Option<u64>,
    /// Consume the committed receipt on successful submission admission.
    #[prost(bool, tag = "8")]
    pub single_use: bool,
}

/// Server-issued upload reservation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IssueUploadTicketResponse {
    /// Opaque ticket id used in the first upload frame.
    #[prost(string, tag = "1")]
    pub ticket_id: ::prost::alloc::string::String,
    /// Absolute expiry in milliseconds since the Unix epoch.
    #[prost(int64, tag = "2")]
    pub expires_at_ms: i64,
    /// Whether successful submission admission consumes the receipt.
    #[prost(bool, tag = "3")]
    pub single_use: bool,
}

/// One frame in the strict Begin, Chunk*, Finish, EOF upload sequence.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UploadObjectRequest {
    /// Upload stage; an absent frame is invalid.
    #[prost(oneof = "upload_object_request::Frame", tags = "1, 2, 3")]
    pub frame: ::core::option::Option<upload_object_request::Frame>,
}

/// Upload request frame variants.
pub mod upload_object_request {
    /// One upload's start metadata, borrowed byte chunk or final interpretation.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Frame {
        /// First and only upload-start frame.
        #[prost(message, tag = "1")]
        Begin(super::BeginObjectUpload),
        /// Next bytes; per-frame limits do not bound cumulative object size.
        #[prost(bytes, tag = "2")]
        Chunk(::prost::alloc::vec::Vec<u8>),
        /// Final interpretation; publication still waits for clean transport EOF.
        #[prost(message, tag = "3")]
        Finish(super::FinishObjectUpload),
    }
}

/// Metadata admitting a streamed upload against an existing ticket.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BeginObjectUpload {
    /// Ticket issued for this authenticated principal and surface.
    #[prost(string, tag = "1")]
    pub ticket_id: ::prost::alloc::string::String,
    /// Optional media type checked against ticket constraints.
    #[prost(string, optional, tag = "2")]
    pub media_type: ::core::option::Option<::prost::alloc::string::String>,
    /// Token required when the ticket is token-bound.
    #[prost(string, optional, tag = "3")]
    pub submission_token: ::core::option::Option<::prost::alloc::string::String>,
}

/// Interpret received content without a client-supplied blob reference or digest.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinishObjectUpload {
    /// Required interpretation of the bytes already received.
    #[prost(oneof = "finish_object_upload::Kind", tags = "1, 2, 3")]
    pub kind: ::core::option::Option<finish_object_upload::Kind>,
}

/// Final object interpretation variants.
pub mod finish_object_upload {
    /// Blob, numeric tensor or timestamped frame metadata.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Opaque file or media bytes.
        #[prost(message, tag = "1")]
        Blob(super::BlobUpload),
        /// Numeric interpretation with final dimensions.
        #[prost(message, tag = "2")]
        Tensor(super::TensorUpload),
        /// Timestamp and category for a sample.
        #[prost(message, tag = "3")]
        Frame(super::FrameUpload),
    }
}

/// Opaque object interpretation; all reference metadata is derived by the Gateway.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobUpload {}

/// Numeric interpretation supplied at the end of an upload.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TensorUpload {
    /// Canonical common TensorRef dtype; unknown strings are invalid.
    #[prost(string, tag = "1")]
    pub dtype: ::prost::alloc::string::String,
    /// Final dimensions, retaining unsigned 64-bit values.
    #[prost(uint64, repeated, tag = "2")]
    pub shape: ::prost::alloc::vec::Vec<u64>,
}

/// Timestamp and category of one media, pose or telemetry sample.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FrameUpload {
    /// Timestamp in nanoseconds, without JSON number narrowing.
    #[prost(int64, tag = "1")]
    pub ts_nanos: i64,
    /// Canonical common FrameRef kind: audio, video, pose or sensor.
    #[prost(string, tag = "2")]
    pub kind: ::prost::alloc::string::String,
}

/// Committed typed object and its Gateway-issued submission proof.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UploadObjectResponse {
    /// Blob, tensor or frame reference with derived content identity.
    #[prost(message, optional, tag = "1")]
    pub item: ::core::option::Option<super::Value>,
    /// Common provenance bound to this principal and surface.
    #[prost(message, optional, tag = "2")]
    pub provenance: ::core::option::Option<super::PayloadProvenance>,
    /// Lowercase BLAKE3 digest of committed bytes.
    #[prost(string, tag = "3")]
    pub digest: ::prost::alloc::string::String,
    /// Committed byte count.
    #[prost(uint64, tag = "4")]
    pub size: u64,
}

/// Request a byte range using an explicit, host-issued read grant.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DownloadObjectRequest {
    /// Opaque read authority; hashes and upload receipts are not read grants.
    #[prost(string, tag = "1")]
    pub read_grant_id: ::prost::alloc::string::String,
    /// Absolute byte offset within the object and the granted range.
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    /// Omission reads through the grant's end; zero requests an empty range.
    #[prost(uint64, optional, tag = "3")]
    pub length: ::core::option::Option<u64>,
}

/// One event of an authenticated, incrementally polled object download.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DownloadObjectResponse {
    /// Required header, byte chunk, or range completion.
    #[prost(oneof = "download_object_response::Event", tags = "1, 2, 3")]
    pub event: ::core::option::Option<download_object_response::Event>,
}

/// Ordered object download events.
pub mod download_object_response {
    /// Header, Chunk*, Completed, followed by successful gRPC EOF.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        /// Frozen canonical object metadata and authorized request range.
        #[prost(message, tag = "1")]
        Header(super::ObjectReadHeader),
        /// The next contiguous bytes and their current provenance.
        #[prost(message, tag = "2")]
        Chunk(super::ObjectReadChunk),
        /// The selected range completed and its authorization was rechecked.
        #[prost(message, tag = "3")]
        Completed(super::ObjectReadCompleted),
    }
}

/// Canonical metadata frozen when an authorized download is opened.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectReadHeader {
    /// Complete backing object reference, independent of the selected range.
    #[prost(message, optional, tag = "1")]
    pub blob: ::core::option::Option<super::BlobRef>,
    /// Absolute first byte of the selected range.
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    /// Number of selected bytes, independent of per-message admission.
    #[prost(uint64, tag = "3")]
    pub length: u64,
    /// Initial object sources combined with the grant's State provenance.
    #[prost(message, optional, tag = "4")]
    pub taint: ::core::option::Option<super::TaintSet>,
    /// Fixed grant expiry in milliseconds since the Unix epoch.
    #[prost(int64, tag = "5")]
    pub expires_at_ms: i64,
}

/// One contiguous byte chunk; its size does not constrain cumulative length.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectReadChunk {
    /// Absolute offset of the first byte in this chunk.
    #[prost(uint64, tag = "1")]
    pub offset: u64,
    /// Shared bytes permit frame slicing without copying the object window.
    #[prost(bytes = "bytes", tag = "2")]
    pub data: ::prost::bytes::Bytes,
    /// Initial object/grant sources plus this read's sources, without history.
    #[prost(message, optional, tag = "3")]
    pub taint: ::core::option::Option<super::TaintSet>,
}

/// Successful completion of the selected range, which may precede object EOF.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectReadCompleted {
    /// Absolute offset immediately after the final selected byte.
    #[prost(uint64, tag = "1")]
    pub next_offset: u64,
    /// Total number of bytes delivered in this response.
    #[prost(uint64, tag = "2")]
    pub bytes_read: u64,
}

/// Submit one typed input to an authenticated Gateway surface.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitRequest {
    /// Declared surface selected for admission.
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    /// Required outer value message; an explicitly empty Value means null.
    #[prost(message, optional, tag = "2")]
    pub payload: ::core::option::Option<super::Value>,
    /// Common upload ticket or object-store proof for object references.
    #[prost(message, optional, tag = "3")]
    pub provenance: ::core::option::Option<super::PayloadProvenance>,
    /// Submit accepts Unary (the default) and Collect; SubmitOutput requires Stream.
    #[prost(message, optional, tag = "4")]
    pub output: ::core::option::Option<super::OutputMode>,
    /// Optional retry, deadline and requested encoding metadata.
    #[prost(message, optional, tag = "5")]
    pub options: ::core::option::Option<SubmitOptions>,
}

/// Client options that do not grant identity or authorization.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitOptions {
    /// Idempotency key for retry boundaries.
    #[prost(string, optional, tag = "1")]
    pub idempotency_key: ::core::option::Option<::prost::alloc::string::String>,
    /// Server-issued token for retry-safe non-idempotent submission.
    #[prost(string, optional, tag = "2")]
    pub submission_token: ::core::option::Option<::prost::alloc::string::String>,
    /// Requested absolute deadline in Unix milliseconds, clamped by the profile.
    #[prost(uint64, optional, tag = "3")]
    pub deadline_ms: ::core::option::Option<u64>,
    /// Requested transport encoding, not an authorization input.
    #[prost(string, optional, tag = "4")]
    pub requested_encoding: ::core::option::Option<::prost::alloc::string::String>,
}

/// Server-generated acceptance identity for a completed submission.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GatewayAccepted {
    /// Submission identity assigned during admission.
    #[prost(string, tag = "1")]
    pub submission_id: ::prost::alloc::string::String,
    /// Independently generated trace identity.
    #[prost(string, tag = "2")]
    pub trace_root: ::prost::alloc::string::String,
    /// Profile revision that admitted the request.
    #[prost(uint64, tag = "3")]
    pub profile_rev: u64,
    /// Surface used for admission.
    #[prost(string, tag = "4")]
    pub surface_id: ::prost::alloc::string::String,
}

/// Acceptance metadata and the shared complete submission result.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitResponse {
    /// Server-owned admission metadata.
    #[prost(message, optional, tag = "1")]
    pub accepted: ::core::option::Option<GatewayAccepted>,
    /// Required final outcome, provenance and request cache origin.
    #[prost(message, optional, tag = "2")]
    pub completion: ::core::option::Option<SubmissionCompletion>,
}

/// One ordered event of a request-owned output stream.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitOutputResponse {
    /// Acceptance, one typed chunk, or final request completion.
    #[prost(oneof = "submit_output_response::Event", tags = "1, 2, 3")]
    pub event: ::core::option::Option<submit_output_response::Event>,
}

/// Ordered application output events.
pub mod submit_output_response {
    /// Accepted, Chunk*, Completed, followed by successful gRPC EOF.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        /// Admission completed, including input receipt consumption.
        #[prost(message, tag = "1")]
        Accepted(super::GatewayAccepted),
        /// Incremental output with its server-owned lineage.
        #[prost(message, tag = "2")]
        Chunk(super::OutputChunk),
        /// Final outcome after Gateway persistence and request cleanup.
        #[prost(message, tag = "3")]
        Completed(super::SubmissionCompletion),
    }
}

/// A typed incremental output with independent provenance.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputChunk {
    /// Exactly one inline value or explicitly authorized container object.
    #[prost(message, optional, tag = "1")]
    pub item: ::core::option::Option<OutputValue>,
    /// Server-owned lineage; this does not grant object read authority.
    #[prost(message, optional, tag = "2")]
    pub taint: ::core::option::Option<super::TaintSet>,
}

/// A committed document and explicit read authority for its complete container.
/// Nested references receive no read grants. MIME does not select the codec.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncodedOutputObject {
    /// Exact versioned document encoding identifier.
    #[prost(string, tag = "1")]
    pub encoding: ::prost::alloc::string::String,
    /// Immutable content identity and encoded size.
    #[prost(message, optional, tag = "2")]
    pub blob: ::core::option::Option<super::BlobRef>,
    /// Audience-bound identifier accepted by DownloadObject.
    #[prost(string, tag = "3")]
    pub read_grant_id: ::prost::alloc::string::String,
    /// Fixed server-clock grant expiry, in Unix milliseconds.
    #[prost(int64, tag = "4")]
    pub expires_at_ms: i64,
}

/// Exactly one inline value or encoded document; absent content is invalid.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputValue {
    /// Selected representation of the original value.
    #[prost(oneof = "output_value::Content", tags = "1, 2")]
    pub content: ::core::option::Option<output_value::Content>,
}

/// Value representations with no implicit object dereferencing.
pub mod output_value {
    /// Exactly one representation of a value.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        /// Complete inline typed value.
        #[prost(message, tag = "1")]
        Inline(super::super::Value),
        /// Complete document with explicit download authority.
        #[prost(message, tag = "2")]
        Object(super::EncodedOutputObject),
    }
}

/// Exactly one lossless inline or encoded failure; this remains a failure.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputFailure {
    /// Object form uses the shared externally tagged Failure value layout.
    #[prost(oneof = "output_failure::Content", tags = "1, 2")]
    pub content: ::core::option::Option<output_failure::Content>,
}

/// Failure representations preserve their complete diagnostic fields.
pub mod output_failure {
    /// Exactly one representation of a failure.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        /// Complete inline typed failure.
        #[prost(message, tag = "1")]
        Inline(super::super::Failure),
        /// Failure document with explicit download authority.
        #[prost(message, tag = "2")]
        Object(super::EncodedOutputObject),
    }
}

/// Original outcome semantics, independent of the chosen representation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputOutcome {
    /// Required final result kind.
    #[prost(oneof = "output_outcome::Kind", tags = "1, 2, 3")]
    pub kind: ::core::option::Option<output_outcome::Kind>,
}

/// Final application outcome variants.
pub mod output_outcome {
    /// Representation changes do not change the execution result kind.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Successful final value.
        #[prost(message, tag = "1")]
        Done(super::OutputValue),
        /// Short-circuiting final value.
        #[prost(message, tag = "2")]
        Short(super::OutputValue),
        /// Complete typed failure.
        #[prost(message, tag = "3")]
        Fail(super::OutputFailure),
    }
}

/// Whether the final outcome came from this attempt or an idempotency record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CompletionOrigin {
    /// No valid origin was supplied.
    Unspecified = 0,
    /// The program ran in this request; individual calls may have used caches.
    CurrentAttempt = 1,
    /// The entire request reused a saved result without replaying historical chunks.
    CachedOutcome = 2,
}

impl CompletionOrigin {
    /// Stable protobuf enum field name.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "COMPLETION_ORIGIN_UNSPECIFIED",
            Self::CurrentAttempt => "COMPLETION_ORIGIN_CURRENT_ATTEMPT",
            Self::CachedOutcome => "COMPLETION_ORIGIN_CACHED_OUTCOME",
        }
    }

    /// Resolve an exact protobuf enum field name.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "COMPLETION_ORIGIN_UNSPECIFIED" => Some(Self::Unspecified),
            "COMPLETION_ORIGIN_CURRENT_ATTEMPT" => Some(Self::CurrentAttempt),
            "COMPLETION_ORIGIN_CACHED_OUTCOME" => Some(Self::CachedOutcome),
            _ => None,
        }
    }
}

/// Shared final result of unary and streamed submissions after request cleanup.
/// Outcome and taint are required by the application contract on every path.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmissionCompletion {
    /// Final value or failure, published after persistence and cleanup.
    #[prost(message, optional, tag = "1")]
    pub outcome: ::core::option::Option<OutputOutcome>,
    /// Cached outcomes contain no historical stream replay.
    #[prost(enumeration = "CompletionOrigin", tag = "2")]
    pub origin: i32,
    /// Required result lineage, including failures and cached outcomes.
    #[prost(message, optional, tag = "3")]
    pub taint: ::core::option::Option<super::TaintSet>,
}

/// Tonic server bindings for authenticated application requests.
pub mod application_gateway_server {
    use tonic::codegen::*;

    /// Application surface protocol, separate from External role sessions.
    #[async_trait]
    pub trait ApplicationGateway: std::marker::Send + std::marker::Sync + 'static {
        /// Discover the authenticated caller's visible surfaces and limits.
        async fn describe(
            &self,
            request: tonic::Request<super::DescribeRequest>,
        ) -> std::result::Result<tonic::Response<super::DescribeResponse>, tonic::Status>;
        /// Reserve an object upload against a declared surface.
        async fn issue_upload_ticket(
            &self,
            request: tonic::Request<super::IssueUploadTicketRequest>,
        ) -> std::result::Result<tonic::Response<super::IssueUploadTicketResponse>, tonic::Status>;
        /// Receive Begin, Chunk*, Finish and clean EOF before publishing a receipt.
        async fn upload_object(
            &self,
            request: tonic::Request<tonic::Streaming<super::UploadObjectRequest>>,
        ) -> std::result::Result<tonic::Response<super::UploadObjectResponse>, tonic::Status>;
        /// Request-owned object bytes, polled under transport backpressure.
        type DownloadObjectStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::DownloadObjectResponse, tonic::Status>,
            > + std::marker::Send
            + 'static;
        /// Read a range authorized by a separately issued opaque read grant.
        async fn download_object(
            &self,
            request: tonic::Request<super::DownloadObjectRequest>,
        ) -> std::result::Result<tonic::Response<Self::DownloadObjectStream>, tonic::Status>;
        /// Submit direct input with Unary or Collect output.
        async fn submit(
            &self,
            request: tonic::Request<super::SubmitRequest>,
        ) -> std::result::Result<tonic::Response<super::SubmitResponse>, tonic::Status>;
        /// Request-owned incremental output, polled under transport backpressure.
        type SubmitOutputStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::SubmitOutputResponse, tonic::Status>,
            > + std::marker::Send
            + 'static;
        /// Submit direct typed input with an explicit Stream output mode.
        async fn submit_output(
            &self,
            request: tonic::Request<super::SubmitRequest>,
        ) -> std::result::Result<tonic::Response<Self::SubmitOutputStream>, tonic::Status>;
    }

    /// Routable application Gateway service with per-message transport limits.
    #[derive(Debug)]
    pub struct ApplicationGatewayServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }

    impl<T> ApplicationGatewayServer<T> {
        /// Wrap an owned implementation in a tonic service.
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        /// Wrap a shared implementation without duplicating its state.
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        /// Intercept each RPC before its handler authenticates and validates it.
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Accept compressed request messages using the selected encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses when supported by the client.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Bound each decoded protobuf message, independently of total upload size.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Bound each encoded protobuf response.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }

    impl<T, B> tonic::codegen::Service<http::Request<B>> for ApplicationGatewayServer<T>
    where
        T: ApplicationGateway,
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
                "/xolotl.v1.application.ApplicationGateway/Describe" => {
                    struct DescribeSvc<T: ApplicationGateway>(pub Arc<T>);
                    impl<T: ApplicationGateway> tonic::server::UnaryService<super::DescribeRequest> for DescribeSvc<T> {
                        type Response = super::DescribeResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DescribeRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as ApplicationGateway>::describe(&inner, request).await
                            })
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
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
                        Ok(grpc.unary(DescribeSvc(inner), req).await)
                    })
                }
                "/xolotl.v1.application.ApplicationGateway/IssueUploadTicket" => {
                    struct IssueUploadTicketSvc<T: ApplicationGateway>(pub Arc<T>);
                    impl<T: ApplicationGateway>
                        tonic::server::UnaryService<super::IssueUploadTicketRequest>
                        for IssueUploadTicketSvc<T>
                    {
                        type Response = super::IssueUploadTicketResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::IssueUploadTicketRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as ApplicationGateway>::issue_upload_ticket(&inner, request)
                                    .await
                            })
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
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
                        Ok(grpc.unary(IssueUploadTicketSvc(inner), req).await)
                    })
                }
                "/xolotl.v1.application.ApplicationGateway/UploadObject" => {
                    struct UploadObjectSvc<T: ApplicationGateway>(pub Arc<T>);
                    impl<T: ApplicationGateway>
                        tonic::server::ClientStreamingService<super::UploadObjectRequest>
                        for UploadObjectSvc<T>
                    {
                        type Response = super::UploadObjectResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::UploadObjectRequest>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as ApplicationGateway>::upload_object(&inner, request).await
                            })
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
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
                        Ok(grpc.client_streaming(UploadObjectSvc(inner), req).await)
                    })
                }
                "/xolotl.v1.application.ApplicationGateway/DownloadObject" => {
                    struct DownloadObjectSvc<T: ApplicationGateway>(pub Arc<T>);
                    impl<T: ApplicationGateway>
                        tonic::server::ServerStreamingService<super::DownloadObjectRequest>
                        for DownloadObjectSvc<T>
                    {
                        type Response = super::DownloadObjectResponse;
                        type ResponseStream = T::DownloadObjectStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DownloadObjectRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as ApplicationGateway>::download_object(&inner, request).await
                            })
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
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
                        Ok(grpc.server_streaming(DownloadObjectSvc(inner), req).await)
                    })
                }
                "/xolotl.v1.application.ApplicationGateway/Submit" => {
                    struct SubmitSvc<T: ApplicationGateway>(pub Arc<T>);
                    impl<T: ApplicationGateway> tonic::server::UnaryService<super::SubmitRequest> for SubmitSvc<T> {
                        type Response = super::SubmitResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SubmitRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as ApplicationGateway>::submit(&inner, request).await
                            })
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
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
                        Ok(grpc.unary(SubmitSvc(inner), req).await)
                    })
                }
                "/xolotl.v1.application.ApplicationGateway/SubmitOutput" => {
                    struct SubmitOutputSvc<T: ApplicationGateway>(pub Arc<T>);
                    impl<T: ApplicationGateway>
                        tonic::server::ServerStreamingService<super::SubmitRequest>
                        for SubmitOutputSvc<T>
                    {
                        type Response = super::SubmitOutputResponse;
                        type ResponseStream = T::SubmitOutputStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SubmitRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as ApplicationGateway>::submit_output(&inner, request).await
                            })
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
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
                        Ok(grpc.server_streaming(SubmitOutputSvc(inner), req).await)
                    })
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

    impl<T> Clone for ApplicationGatewayServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }

    /// Fully qualified service name used for tonic routing.
    pub const SERVICE_NAME: &str = "xolotl.v1.application.ApplicationGateway";
    impl<T> tonic::server::NamedService for ApplicationGatewayServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}

/// Tonic client bindings for application discovery, objects and submission.
pub mod application_gateway_client {
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;

    /// Client for an authenticated application Gateway endpoint.
    #[derive(Debug, Clone)]
    pub struct ApplicationGatewayClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl ApplicationGatewayClient<tonic::transport::Channel> {
        /// Connect to an application Gateway endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> ApplicationGatewayClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        /// Use an existing tonic-compatible transport.
        pub fn new(inner: T) -> Self {
            Self {
                inner: tonic::client::Grpc::new(inner),
            }
        }
        /// Use an explicit URI origin for outgoing requests.
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            Self {
                inner: tonic::client::Grpc::with_origin(inner, origin),
            }
        }
        /// Attach authentication or other metadata to every RPC.
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ApplicationGatewayClient<InterceptedService<T, F>>
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
            ApplicationGatewayClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress outgoing request messages using the selected encoding.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Advertise support for compressed responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Bound each decoded response message.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Bound each encoded request frame, independently of total upload size.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Discover surfaces and limits visible to the authenticated caller.
        pub async fn describe(
            &mut self,
            request: impl tonic::IntoRequest<super::DescribeRequest>,
        ) -> std::result::Result<tonic::Response<super::DescribeResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|error| {
                tonic::Status::unknown(format!("Service was not ready: {}", error.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.application.ApplicationGateway/Describe",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.application.ApplicationGateway",
                "Describe",
            ));
            self.inner.unary(req, path, codec).await
        }
        /// Reserve an upload ticket using the active Gateway profile.
        pub async fn issue_upload_ticket(
            &mut self,
            request: impl tonic::IntoRequest<super::IssueUploadTicketRequest>,
        ) -> std::result::Result<tonic::Response<super::IssueUploadTicketResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|error| {
                tonic::Status::unknown(format!("Service was not ready: {}", error.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.application.ApplicationGateway/IssueUploadTicket",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.application.ApplicationGateway",
                "IssueUploadTicket",
            ));
            self.inner.unary(req, path, codec).await
        }
        /// Send Begin, Chunk*, Finish, then close the stream cleanly to commit.
        pub async fn upload_object(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::UploadObjectRequest>,
        ) -> std::result::Result<tonic::Response<super::UploadObjectResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|error| {
                tonic::Status::unknown(format!("Service was not ready: {}", error.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.application.ApplicationGateway/UploadObject",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.application.ApplicationGateway",
                "UploadObject",
            ));
            self.inner.client_streaming(req, path, codec).await
        }
        /// Receive authorized Header, Chunk*, Completed and the final gRPC status.
        pub async fn download_object(
            &mut self,
            request: impl tonic::IntoRequest<super::DownloadObjectRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::Streaming<super::DownloadObjectResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|error| {
                tonic::Status::unknown(format!("Service was not ready: {}", error.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.application.ApplicationGateway/DownloadObject",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.application.ApplicationGateway",
                "DownloadObject",
            ));
            self.inner.server_streaming(req, path, codec).await
        }
        /// Submit direct typed input and await a Unary or Collect outcome.
        pub async fn submit(
            &mut self,
            request: impl tonic::IntoRequest<super::SubmitRequest>,
        ) -> std::result::Result<tonic::Response<super::SubmitResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|error| {
                tonic::Status::unknown(format!("Service was not ready: {}", error.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.application.ApplicationGateway/Submit",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.application.ApplicationGateway",
                "Submit",
            ));
            self.inner.unary(req, path, codec).await
        }
        /// Receive Accepted, Chunk*, Completed and the final gRPC status.
        pub async fn submit_output(
            &mut self,
            request: impl tonic::IntoRequest<super::SubmitRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::Streaming<super::SubmitOutputResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|error| {
                tonic::Status::unknown(format!("Service was not ready: {}", error.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.application.ApplicationGateway/SubmitOutput",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.application.ApplicationGateway",
                "SubmitOutput",
            ));
            self.inner.server_streaming(req, path, codec).await
        }
    }
}
