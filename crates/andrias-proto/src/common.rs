// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/andrias/v1/common.proto`. This file is `include!`d into the `andrias::v1`
// module so the crate builds without `protoc`. Keep it in sync with the
// `.proto` spec if either changes.

/// Universal addressing type.
/// String form: `path://[cluster/]<scheme>/<seg>[/<seg>...]`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Path {
    #[prost(string, optional, tag = "1")]
    pub cluster: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, tag = "2")]
    pub scheme: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "3")]
    pub segments: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Self-describing value (mirrors `andrias_types::Value`, including multimodal refs).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Value {
    #[prost(oneof = "value::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12")]
    pub kind: ::core::option::Option<value::Kind>,
}
/// Nested message and enum types in `Value`.
pub mod value {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(enumeration = "super::NullValue", tag = "1")]
        NullVal(i32),
        #[prost(bool, tag = "2")]
        BoolVal(bool),
        #[prost(int64, tag = "3")]
        IntVal(i64),
        #[prost(double, tag = "4")]
        FloatVal(f64),
        #[prost(string, tag = "5")]
        StrVal(::prost::alloc::string::String),
        #[prost(bytes, tag = "6")]
        BytesVal(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "7")]
        ListVal(super::ListValue),
        #[prost(message, tag = "8")]
        MapVal(super::MapValue),
        #[prost(message, tag = "9")]
        BlobVal(super::BlobRef),
        #[prost(message, tag = "10")]
        TensorVal(super::TensorRef),
        #[prost(message, tag = "11")]
        FrameVal(super::FrameRef),
        #[prost(message, tag = "12")]
        StreamEndVal(super::StreamMarker),
    }
}
/// End-of-stream sentinel for streamed value sequences.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamMarker {
    #[prost(oneof = "stream_marker::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<stream_marker::Kind>,
}
/// Nested message and enum types in `StreamMarker`.
pub mod stream_marker {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// graceful end
        #[prost(bool, tag = "1")]
        Done(bool),
        /// aborted with this message
        #[prost(string, tag = "2")]
        Error(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListValue {
    #[prost(message, repeated, tag = "1")]
    pub items: ::prost::alloc::vec::Vec<Value>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MapValue {
    #[prost(map = "string, message", tag = "1")]
    pub entries: ::std::collections::HashMap<::prost::alloc::string::String, Value>,
}
/// Pointer to large opaque content in blob storage.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlobRef {
    #[prost(string, tag = "1")]
    pub hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub size: u64,
    #[prost(string, optional, tag = "3")]
    pub mime: ::core::option::Option<::prost::alloc::string::String>,
}
/// Numeric tensor reference (embedding / waveform / frame / action vector).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TensorRef {
    #[prost(message, optional, tag = "1")]
    pub blob: ::core::option::Option<BlobRef>,
    /// f16/bf16/f32/f64/i8/i16/i32/i64/u8/bool
    #[prost(string, tag = "2")]
    pub dtype: ::prost::alloc::string::String,
    #[prost(uint64, repeated, tag = "3")]
    pub shape: ::prost::alloc::vec::Vec<u64>,
}
/// A single timestamped media / trajectory / sensor frame.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FrameRef {
    #[prost(message, optional, tag = "1")]
    pub blob: ::core::option::Option<BlobRef>,
    #[prost(int64, tag = "2")]
    pub ts_nanos: i64,
    /// audio/video/pose/sensor
    #[prost(string, tag = "3")]
    pub kind: ::prost::alloc::string::String,
}
/// Outcome failure (detail in the message string).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Failure {
    #[prost(string, tag = "1")]
    pub kind: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
/// Outcome of evaluating an Operation / program node.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Outcome {
    #[prost(oneof = "outcome::Result", tags = "1, 2, 3")]
    pub result: ::core::option::Option<outcome::Result>,
}
/// Nested message and enum types in `Outcome`.
pub mod outcome {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Done(super::Value),
        #[prost(message, tag = "2")]
        Fail(super::Failure),
        #[prost(message, tag = "3")]
        Short(super::Value),
    }
}
/// Capability literal: `<verb>://<scheme>/<segs>[@<predicate>]`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Capability {
    #[prost(string, tag = "1")]
    pub verb: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub scheme: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "3")]
    pub segments: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub predicate: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CapSet {
    #[prost(message, repeated, tag = "1")]
    pub capabilities: ::prost::alloc::vec::Vec<Capability>,
}
/// Null singleton.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NullValue {
    NullValue = 0,
}
impl NullValue {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::NullValue => "NULL_VALUE",
        }
    }
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
    Unspecified = 0,
    Pure = 1,
    Idempotent = 2,
    Effectful = 3,
}
impl Purity {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "PURITY_UNSPECIFIED",
            Self::Pure => "PURITY_PURE",
            Self::Idempotent => "PURITY_IDEMPOTENT",
            Self::Effectful => "PURITY_EFFECTFUL",
        }
    }
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
