// @generated: hand-maintained prost bindings for proto/andrias/v1/program.proto.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Program {
    #[prost(message, optional, tag = "1")]
    pub root: ::core::option::Option<DoNode>,
    #[prost(message, optional, tag = "2")]
    pub provenance: ::core::option::Option<PayloadProvenance>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PayloadProvenance {
    #[prost(string, optional, tag = "1")]
    pub upload_ticket: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "2")]
    pub store_proof: ::core::option::Option<ObjectStoreProof>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectStoreProof {
    #[prost(string, tag = "1")]
    pub store_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub proof: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DoNode {
    #[prost(oneof = "do_node::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub kind: ::core::option::Option<do_node::Kind>,
}

pub mod do_node {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Pure(super::Value),
        #[prost(message, tag = "2")]
        AndThen(super::AndThen),
        #[prost(message, tag = "3")]
        OrElse(super::OrElse),
        #[prost(message, tag = "4")]
        Both(super::Parallel),
        #[prost(message, tag = "5")]
        Race(super::Parallel),
        #[prost(message, tag = "6")]
        Let(super::Let),
        #[prost(string, tag = "7")]
        UseName(::prost::alloc::string::String),
        #[prost(message, tag = "8")]
        Acting(super::Acting),
        #[prost(message, tag = "9")]
        Fail(super::Failure),
        #[prost(message, tag = "10")]
        Wait(super::WaitSpec),
        #[prost(message, tag = "11")]
        Op(super::OperationTemplate),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndThen {
    #[prost(message, optional, boxed, tag = "1")]
    pub d: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, tag = "2")]
    pub then: ::core::option::Option<StepRef>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OrElse {
    #[prost(message, optional, boxed, tag = "1")]
    pub d: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, tag = "2")]
    pub or: ::core::option::Option<StepRef>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parallel {
    #[prost(message, optional, boxed, tag = "1")]
    pub left: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, boxed, tag = "2")]
    pub right: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Let {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, boxed, tag = "2")]
    pub value: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, boxed, tag = "3")]
    pub body: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acting {
    #[prost(message, optional, tag = "1")]
    pub identity: ::core::option::Option<Path>,
    #[prost(message, optional, boxed, tag = "2")]
    pub body: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WaitSpec {
    #[prost(oneof = "wait_spec::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<wait_spec::Kind>,
}

pub mod wait_spec {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Signal(super::Path),
        #[prost(int64, tag = "2")]
        DeadlineMillis(i64),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StepRef {
    #[prost(uint64, tag = "1")]
    pub process_id: u64,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub arg: ::core::option::Option<Value>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OperationTemplate {
    #[prost(message, optional, tag = "1")]
    pub target: ::core::option::Option<Path>,
    #[prost(string, tag = "2")]
    pub method: ::prost::alloc::string::String,
    #[prost(uint64, optional, tag = "3")]
    pub method_id: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "4")]
    pub output: ::core::option::Option<OutputMode>,
    #[prost(message, optional, tag = "5")]
    pub literal_input: ::core::option::Option<Value>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputMode {
    #[prost(enumeration = "OutputModeKind", tag = "1")]
    pub kind: i32,
    #[prost(uint64, tag = "2")]
    pub collect_limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OutputModeKind {
    Unspecified = 0,
    Unary = 1,
    Stream = 2,
    Collect = 3,
    AsyncProcess = 4,
    SinkOnly = 5,
}

impl OutputModeKind {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "OUTPUT_MODE_KIND_UNSPECIFIED",
            Self::Unary => "OUTPUT_MODE_UNARY",
            Self::Stream => "OUTPUT_MODE_STREAM",
            Self::Collect => "OUTPUT_MODE_COLLECT",
            Self::AsyncProcess => "OUTPUT_MODE_ASYNC_PROCESS",
            Self::SinkOnly => "OUTPUT_MODE_SINK_ONLY",
        }
    }

    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "OUTPUT_MODE_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "OUTPUT_MODE_UNARY" => Some(Self::Unary),
            "OUTPUT_MODE_STREAM" => Some(Self::Stream),
            "OUTPUT_MODE_COLLECT" => Some(Self::Collect),
            "OUTPUT_MODE_ASYNC_PROCESS" => Some(Self::AsyncProcess),
            "OUTPUT_MODE_SINK_ONLY" => Some(Self::SinkOnly),
            _ => None,
        }
    }
}
