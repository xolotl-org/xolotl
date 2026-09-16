// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/xolotl/v1/common.proto`. This file is `include!`d into the `xolotl::v1`
// module so the crate builds without `protoc`. Keep it in sync with the
// `.proto` spec if either changes.

/// Universal addressing type.
/// String form: `path://[cluster/]<scheme>/<seg>[/<seg>...]`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Path {
    /// Optional routing cluster; absent when the path has no cluster qualifier.
    #[prost(string, optional, tag = "1")]
    pub cluster: ::core::option::Option<::prost::alloc::string::String>,
    /// Resource namespace, such as `state`; checked conversion validates its syntax.
    #[prost(string, tag = "2")]
    pub scheme: ::prost::alloc::string::String,
    /// Ordered path components, each validated separately during checked conversion.
    #[prost(string, repeated, tag = "3")]
    pub segments: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

/// Server-owned lineage, independent of object upload or download authority.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaintSet {
    /// Recorded sources; an explicitly present empty set is pristine.
    #[prost(message, repeated, tag = "1")]
    pub sources: ::prost::alloc::vec::Vec<TaintSource>,
}

/// One source that participated in producing a value.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaintSource {
    /// Server-assigned source identity, never a client authorization claim.
    #[prost(oneof = "taint_source::Kind", tags = "1, 2, 3, 4, 5")]
    pub kind: ::core::option::Option<taint_source::Kind>,
}

/// Typed lineage labels.
pub mod taint_source {
    /// Marker for a source with no associated metadata.
    #[derive(Clone, Copy, PartialEq, ::prost::Message)]
    pub struct Marker {}

    /// Trusted ingress attribution assigned by the host.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Inbound {
        /// Host-owned source label.
        #[prost(string, tag = "1")]
        pub source: ::prost::alloc::string::String,
        /// Host-owned ingress channel.
        #[prost(string, tag = "2")]
        pub channel: ::prost::alloc::string::String,
    }

    /// Canonical source alternatives.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Literal supplied by the program's author.
        #[prost(message, tag = "1")]
        AuthorConstant(Marker),
        /// Content produced by an inference model.
        #[prost(message, tag = "2")]
        ModelOutput(Marker),
        /// External input admitted by a host boundary.
        #[prost(message, tag = "3")]
        Inbound(Inbound),
        /// Remote host from which content was fetched.
        #[prost(string, tag = "4")]
        FetchedHost(::prost::alloc::string::String),
        /// Protected resource whose data contributed to the value.
        #[prost(message, tag = "5")]
        ProtectedPath(super::Path),
    }
}

/// Self-describing value (mirrors `xolotl_types::Value`, including multimodal refs).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Value {
    /// Selected value representation. An absent oneof is decoded as `Null`.
    #[prost(oneof = "value::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12")]
    pub kind: ::core::option::Option<value::Kind>,
}
/// Nested message and enum types in `Value`.
pub mod value {
    /// Typed protobuf alternatives preserving scalar, collection, and media distinctions.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Explicit null singleton; checked conversion rejects unknown enum numbers.
        #[prost(enumeration = "super::NullValue", tag = "1")]
        NullVal(i32),
        /// Boolean scalar, distinct from numeric zero and one.
        #[prost(bool, tag = "2")]
        BoolVal(bool),
        /// Signed 64-bit integer, without a floating-point conversion.
        #[prost(int64, tag = "3")]
        IntVal(i64),
        /// IEEE 754 double, preserving floating-point rather than integer identity.
        #[prost(double, tag = "4")]
        FloatVal(f64),
        /// UTF-8 text carried inline in the message.
        #[prost(string, tag = "5")]
        StrVal(::prost::alloc::string::String),
        /// Opaque inline bytes, distinct from text and out-of-line blob references.
        #[prost(bytes, tag = "6")]
        BytesVal(::prost::alloc::vec::Vec<u8>),
        /// Ordered collection whose elements retain their individual wire kinds.
        #[prost(message, tag = "7")]
        ListVal(super::ListValue),
        /// String-keyed collection; protobuf map iteration order is not significant.
        #[prost(message, tag = "8")]
        MapVal(super::MapValue),
        /// Reference to stored opaque content; the payload is not embedded here.
        #[prost(message, tag = "9")]
        BlobVal(super::BlobRef),
        /// Stored numeric content together with its element type and shape.
        #[prost(message, tag = "10")]
        TensorVal(super::TensorRef),
        /// Stored media or sensor sample with a timestamp and frame category.
        #[prost(message, tag = "11")]
        FrameVal(super::FrameRef),
        /// Terminal marker for a sequence of streamed values.
        #[prost(message, tag = "12")]
        StreamEndVal(super::StreamMarker),
    }
}
/// End-of-stream sentinel for streamed value sequences.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamMarker {
    /// Terminal reason. Checked conversion requires a marker and accepts
    /// graceful completion only when its boolean payload is `true`.
    #[prost(oneof = "stream_marker::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<stream_marker::Kind>,
}
/// Nested message and enum types in `StreamMarker`.
pub mod stream_marker {
    /// Distinguishes normal stream completion from an explicit producer error.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Graceful end encoded as `true`; `false` is not a valid terminal marker.
        #[prost(bool, tag = "1")]
        Done(bool),
        /// Aborted stream with a diagnostic message from its producer.
        #[prost(string, tag = "2")]
        Error(::prost::alloc::string::String),
    }
}
/// Protobuf wrapper preserving the order of a heterogeneous value sequence.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListValue {
    /// Elements in source order; an empty list remains distinct from null.
    #[prost(message, repeated, tag = "1")]
    pub items: ::prost::alloc::vec::Vec<Value>,
}
/// Protobuf wrapper for a string-keyed value collection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MapValue {
    /// Key/value associations; conversion to domain values restores ordered map storage.
    #[prost(map = "string, message", tag = "1")]
    pub entries: ::std::collections::HashMap<::prost::alloc::string::String, Value>,
}
/// Pointer to large opaque content in blob storage.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobRef {
    /// Content hash identifying stored bytes. Wire conversion does not verify
    /// storage ownership, provenance, or the existence of this object.
    #[prost(string, tag = "1")]
    pub hash: ::prost::alloc::string::String,
    /// Declared payload length in bytes, without carrying the payload itself.
    #[prost(uint64, tag = "2")]
    pub size: u64,
    /// Optional media type used by routing and display consumers.
    #[prost(string, optional, tag = "3")]
    pub mime: ::core::option::Option<::prost::alloc::string::String>,
}
/// Numeric tensor reference (embedding / waveform / frame / action vector).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TensorRef {
    /// Reference to tensor storage; required by checked domain conversion.
    #[prost(message, optional, tag = "1")]
    pub blob: ::core::option::Option<BlobRef>,
    /// Element type: `f16`, `bf16`, `f32`, `f64`, `i8`, `i16`, `i32`, `i64`,
    /// `u8`, or `bool`. Other strings are rejected by checked conversion.
    #[prost(string, tag = "2")]
    pub dtype: ::prost::alloc::string::String,
    /// Tensor dimensions in row-major order; conversion preserves them without
    /// loading the object or checking its byte length against the shape.
    #[prost(uint64, repeated, tag = "3")]
    pub shape: ::prost::alloc::vec::Vec<u64>,
}
/// A single timestamped media / trajectory / sensor frame.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FrameRef {
    /// Reference to the sample payload; required by checked domain conversion.
    #[prost(message, optional, tag = "1")]
    pub blob: ::core::option::Option<BlobRef>,
    /// Sample timestamp in nanoseconds, retained without rescaling.
    #[prost(int64, tag = "2")]
    pub ts_nanos: i64,
    /// Frame category: `audio`, `video`, `pose`, or `sensor`. Checked conversion
    /// rejects an unrecognized category.
    #[prost(string, tag = "3")]
    pub kind: ::prost::alloc::string::String,
}
/// Lossless domain failure retaining its selected variant and every field.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Failure {
    /// Required domain variant. Missing or unknown alternatives are rejected.
    #[prost(
        oneof = "failure::Kind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14"
    )]
    pub kind: ::core::option::Option<failure::Kind>,
}
/// Structured failure variants and their metadata.
pub mod failure {
    /// Presence marker for a failure without fields.
    #[derive(Clone, Copy, PartialEq, ::prost::Message)]
    pub struct Marker {}
    /// Required and actually held capability labels, without normalization.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PermissionDenied {
        /// Required labels, preserving order and duplicates.
        #[prost(string, repeated, tag = "1")]
        pub required: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        /// Held labels, preserving order and duplicates.
        #[prost(string, repeated, tag = "2")]
        pub actual: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    }
    /// A suspended operation's approval identity and reason.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ApprovalPending {
        /// State or broker key awaited by the operation.
        #[prost(string, tag = "1")]
        pub approval_key: ::prost::alloc::string::String,
        /// Approval diagnostic.
        #[prost(string, tag = "2")]
        pub reason: ::prost::alloc::string::String,
    }
    /// Operation retained for explicit recovery review.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Quarantined {
        /// Identity of the uncertain operation.
        #[prost(string, tag = "1")]
        pub op_id: ::prost::alloc::string::String,
        /// Quarantine diagnostic.
        #[prost(string, tag = "2")]
        pub reason: ::prost::alloc::string::String,
    }
    /// Handler or application error with its own class and diagnostic.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ClassifiedError {
        /// Domain-specific error class, independent of the enclosing variant.
        #[prost(string, tag = "1")]
        pub kind: ::prost::alloc::string::String,
        /// Original diagnostic, without adding a display prefix.
        #[prost(string, tag = "2")]
        pub message: ::prost::alloc::string::String,
    }
    /// Policy identity and the detail of its rejected condition.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PolicyViolation {
        /// Policy name.
        #[prost(string, tag = "1")]
        pub policy: ::prost::alloc::string::String,
        /// Rejection detail.
        #[prost(string, tag = "2")]
        pub detail: ::prost::alloc::string::String,
    }
    /// A syntactically valid path rejected by semantic admission.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PathInvalid {
        /// Required structured path.
        #[prost(message, optional, tag = "1")]
        pub path: ::core::option::Option<super::Path>,
        /// Semantic rejection reason.
        #[prost(string, tag = "2")]
        pub reason: ::prost::alloc::string::String,
    }
    /// Every supported domain failure, with no lossy fallback alternative.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Required and held capabilities.
        #[prost(message, tag = "1")]
        PermissionDenied(PermissionDenied),
        /// Unhandled target path.
        #[prost(message, tag = "2")]
        NoHandler(super::Path),
        /// Exhausted budget dimension.
        #[prost(string, tag = "3")]
        BudgetExhausted(::prost::alloc::string::String),
        /// Rate admission rejected this attempt.
        #[prost(message, tag = "4")]
        RateLimited(Marker),
        /// Explicit approval suspension.
        #[prost(message, tag = "5")]
        ApprovalPending(ApprovalPending),
        /// Deadline expired.
        #[prost(message, tag = "6")]
        Timeout(Marker),
        /// Execution was cancelled.
        #[prost(message, tag = "7")]
        Cancelled(Marker),
        /// Uncertain operation held for recovery review.
        #[prost(message, tag = "8")]
        Quarantined(Quarantined),
        /// Input validation detail.
        #[prost(string, tag = "9")]
        InvalidInput(::prost::alloc::string::String),
        /// Driver-specific failure.
        #[prost(message, tag = "10")]
        HandlerError(ClassifiedError),
        /// Mutation of a reserved namespace was rejected.
        #[prost(message, tag = "11")]
        KernelNamespaceProtected(Marker),
        /// Named policy rejected the operation.
        #[prost(message, tag = "12")]
        PolicyViolation(PolicyViolation),
        /// Semantic target path rejection.
        #[prost(message, tag = "13")]
        PathInvalid(PathInvalid),
        /// Application-defined error class and diagnostic.
        #[prost(message, tag = "14")]
        Custom(ClassifiedError),
    }
}
/// Outcome of evaluating an Operation / program node.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Outcome {
    /// Successful value, failure, or short-circuit value selected by the producer.
    #[prost(oneof = "outcome::Result", tags = "1, 2, 3")]
    pub result: ::core::option::Option<outcome::Result>,
}
/// Nested message and enum types in `Outcome`.
pub mod outcome {
    /// Operation result alternatives; failures remain distinct from successful null.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// Normal successful completion carrying the operation's value.
        #[prost(message, tag = "1")]
        Done(super::Value),
        /// Failed operation carrying its complete typed failure.
        #[prost(message, tag = "2")]
        Fail(super::Failure),
        /// Successful short-circuit result for consumers honoring short outcomes.
        #[prost(message, tag = "3")]
        Short(super::Value),
    }
}
/// Capability literal: `<verb>://<scheme>/<segs>[@<predicate>]`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Capability {
    /// Requested operation verb, validated when constructing a domain capability.
    #[prost(string, tag = "1")]
    pub verb: ::prost::alloc::string::String,
    /// Resource namespace to which the capability applies.
    #[prost(string, tag = "2")]
    pub scheme: ::prost::alloc::string::String,
    /// Ordered target pattern components, including supported wildcard segments.
    #[prost(string, repeated, tag = "3")]
    pub segments: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Optional predicate expression in the domain predicate parser's canonical syntax.
    #[prost(string, optional, tag = "4")]
    pub predicate: ::core::option::Option<::prost::alloc::string::String>,
}
/// Wire collection of capability declarations; transport alone grants no authority.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CapSet {
    /// Capability declarations that an admission layer may evaluate or attenuate.
    #[prost(message, repeated, tag = "1")]
    pub capabilities: ::prost::alloc::vec::Vec<Capability>,
}
/// Null singleton.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NullValue {
    /// The sole valid enum number representing an explicit null value.
    NullValue = 0,
}
impl NullValue {
    /// Return the stable protobuf schema name `NULL_VALUE`.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::NullValue => "NULL_VALUE",
        }
    }
    /// Parse the exact protobuf schema name; other strings return `None`.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NULL_VALUE" => Some(Self::NullValue),
            _ => None,
        }
    }
}
/// Side-effect / replay classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Purity {
    /// No side-effect classification was declared; this does not imply purity.
    Unspecified = 0,
    /// Declares computation without externally observable side effects.
    Pure = 1,
    /// Declares that repeating the same operation has the same intended external effect.
    Idempotent = 2,
    /// Declares an operation whose repetition may produce additional external effects.
    Effectful = 3,
}
impl Purity {
    /// Return the stable uppercase name used by the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "PURITY_UNSPECIFIED",
            Self::Pure => "PURITY_PURE",
            Self::Idempotent => "PURITY_IDEMPOTENT",
            Self::Effectful => "PURITY_EFFECTFUL",
        }
    }
    /// Parse an exact protobuf schema name; unknown or differently cased names fail.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PURITY_UNSPECIFIED" => Some(Self::Unspecified),
            "PURITY_PURE" => Some(Self::Pure),
            "PURITY_IDEMPOTENT" => Some(Self::Idempotent),
            "PURITY_EFFECTFUL" => Some(Self::Effectful),
            _ => None,
        }
    }
}
