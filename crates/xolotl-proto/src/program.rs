// @generated: hand-maintained prost bindings for proto/xolotl/v1/program.proto.

/// Versioned portable source envelope; execution admission belongs to the host.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PortableProgram {
    /// UTF-8 source document, bounded and validated by the shared compiler.
    #[prost(bytes = "vec", tag = "1")]
    pub json_source: ::prost::alloc::vec::Vec<u8>,
    /// Compiler identity of the source, exactly 32 bytes.
    #[prost(bytes = "vec", tag = "2")]
    pub program_id: ::prost::alloc::vec::Vec<u8>,
}

/// Native composition tree plus optional evidence for its referenced input objects.
/// Decoding the tree does not authorize execution or verify the attached evidence.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Program {
    /// Required entry node; checked program conversion rejects an absent root.
    #[prost(message, optional, tag = "1")]
    pub root: ::core::option::Option<DoNode>,
    /// Ingress evidence consumed by gateway admission, separately from tree conversion.
    #[prost(message, optional, tag = "2")]
    pub provenance: ::core::option::Option<PayloadProvenance>,
}

/// Source evidence accompanying inbound blob, tensor, or frame references.
/// Its presence is a claim requiring gateway validation, not trusted value taint.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PayloadProvenance {
    /// Upload ticket issued by the receiving gateway or profile for this input.
    #[prost(string, optional, tag = "1")]
    pub upload_ticket: ::core::option::Option<::prost::alloc::string::String>,
    /// Receipt from an object store recognized by the receiving gateway.
    #[prost(message, optional, tag = "2")]
    pub store_proof: ::core::option::Option<ObjectStoreProof>,
}

/// Opaque object-store receipt whose issuer and payload are validated at ingress.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObjectStoreProof {
    /// Store identity selecting the trusted proof-verification policy.
    #[prost(string, tag = "1")]
    pub store_id: ::prost::alloc::string::String,
    /// Store-generated token, receipt identifier, or proof data.
    #[prost(string, tag = "2")]
    pub proof: ::prost::alloc::string::String,
}

/// One node of the native composition algebra, including references to host-bound steps.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DoNode {
    /// Selected instruction; checked conversion rejects an absent alternative.
    #[prost(oneof = "do_node::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub kind: ::core::option::Option<do_node::Kind>,
}

/// Wire alternatives for the native composition tree.
pub mod do_node {
    /// Instruction payloads lowered into the shared execution graph after validation.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Produce a constant without invoking a resource.
        #[prost(message, tag = "1")]
        Pure(super::Value),
        /// Run a node and pass its successful result to a named host continuation.
        #[prost(message, tag = "2")]
        AndThen(super::AndThen),
        /// Recover an ordinary node failure through a named host continuation.
        #[prost(message, tag = "3")]
        OrElse(super::OrElse),
        /// Evaluate both branches and pair their successful results in source order.
        #[prost(message, tag = "4")]
        Both(super::Parallel),
        /// Keep the first branch result after cancelling and cleaning up the loser.
        #[prost(message, tag = "5")]
        Race(super::Parallel),
        /// Bind a computed value for the lexical body.
        #[prost(message, tag = "6")]
        Let(super::Let),
        /// Load a lexical binding by a nonblank name without surrounding whitespace.
        #[prost(string, tag = "7")]
        UseName(::prost::alloc::string::String),
        /// Request an authorized acting-identity scope around a body.
        #[prost(message, tag = "8")]
        Acting(super::Acting),
        /// Raise a failure for the surrounding execution or recovery handler.
        #[prost(message, tag = "9")]
        Fail(super::Failure),
        /// Suspend on a host signal or absolute deadline.
        #[prost(message, tag = "10")]
        Wait(super::WaitSpec),
        /// Invoke a resource method through capability admission.
        #[prost(message, tag = "11")]
        Op(super::OperationTemplate),
    }
}

/// Sequence a native node with a continuation resolved by the executing host.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndThen {
    /// Required first computation; its successful value becomes continuation input.
    #[prost(message, optional, boxed, tag = "1")]
    pub d: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    /// Required continuation reference in the executing process's native module.
    #[prost(message, optional, tag = "2")]
    pub then: ::core::option::Option<StepRef>,
}

/// Handle an ordinary failure using a native continuation; cancellation bypasses recovery.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OrElse {
    /// Required guarded computation whose success passes through unchanged.
    #[prost(message, optional, boxed, tag = "1")]
    pub d: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    /// Required recovery continuation receiving the host's failure representation.
    #[prost(message, optional, tag = "2")]
    pub or: ::core::option::Option<StepRef>,
}

/// Two required branches whose join behavior is selected by `Both` or `Race`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parallel {
    /// First branch; its result occupies the first element of a successful `Both`.
    #[prost(message, optional, boxed, tag = "1")]
    pub left: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    /// Second branch, evaluated with its own lexical execution state.
    #[prost(message, optional, boxed, tag = "2")]
    pub right: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}

/// Lexically bind a computed value and restore any shadowed binding after the body.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Let {
    /// Binding name; checked conversion rejects blank names or surrounding whitespace.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Required computation producing the value retained by this binding.
    #[prost(message, optional, boxed, tag = "2")]
    pub value: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    /// Required computation in which `UseName` can refer to the bound value.
    #[prost(message, optional, boxed, tag = "3")]
    pub body: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}

/// Scoped request to act as another identity, subject to the host's authority checks.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acting {
    /// Required identity path; a syntactically valid path is not an authorization grant.
    #[prost(message, optional, tag = "1")]
    pub identity: ::core::option::Option<Path>,
    /// Required computation evaluated only after the host admits the identity change.
    #[prost(message, optional, boxed, tag = "2")]
    pub body: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}

/// A host-managed condition on which execution can suspend.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WaitSpec {
    /// Required wait condition; checked conversion rejects an absent alternative.
    #[prost(oneof = "wait_spec::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<wait_spec::Kind>,
}

/// Wire conditions supported by a native wait instruction.
pub mod wait_spec {
    /// Selects a path-based signal or a host-clock deadline.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Signal path interpreted by the embedding's wait adapter.
        #[prost(message, tag = "1")]
        Signal(super::Path),
        /// Absolute deadline in milliseconds, interpreted using the host's clock.
        #[prost(int64, tag = "2")]
        DeadlineMillis(i64),
    }
}

/// Reference to a native continuation in the executing process's module.
/// This reference cannot select another process's code.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StepRef {
    /// Local continuation name, nonblank and without surrounding whitespace.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Optional constant argument supplied alongside the flowing input value.
    #[prost(message, optional, tag = "2")]
    pub arg: ::core::option::Option<Value>,
}

/// Resource invocation descriptor resolved into an owned capability handle by the host.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OperationTemplate {
    /// Required resource path used for resolution, not a preauthorized handle.
    #[prost(message, optional, tag = "1")]
    pub target: ::core::option::Option<Path>,
    /// Required method name, nonblank and without surrounding whitespace.
    #[prost(string, tag = "2")]
    pub method: ::prost::alloc::string::String,
    /// Optional method identifier retained through conversion for interface linking.
    #[prost(uint64, optional, tag = "3")]
    pub method_id: ::core::option::Option<u64>,
    /// Required delivery mode; checked conversion rejects unspecified or unknown modes.
    #[prost(message, optional, tag = "4")]
    pub output: ::core::option::Option<OutputMode>,
    /// Constant input override; absence selects the value flowing into this node.
    #[prost(message, optional, tag = "5")]
    pub literal_input: ::core::option::Option<Value>,
}

/// Requested result delivery, with collection capacity carried separately.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputMode {
    /// Numeric [`OutputModeKind`]; checked conversion rejects zero and unknown values.
    #[prost(enumeration = "OutputModeKind", tag = "1")]
    pub kind: i32,
    /// Maximum values retained by `Collect`, including zero. Other modes ignore
    /// this field; decoding a collection rejects values that exceed host `usize`.
    #[prost(uint64, tag = "2")]
    pub collect_limit: u64,
}

/// Delivery choices checked against the opened resource method's output support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OutputModeKind {
    /// Missing choice; checked conversion rejects it instead of assuming unary output.
    Unspecified = 0,
    /// Return one completed response value.
    Unary = 1,
    /// Deliver produced values through an attached stream channel.
    Stream = 2,
    /// Aggregate supported unary or streaming output into a bounded value list.
    Collect = 3,
    /// Return an asynchronous process handle for separate observation or waiting.
    AsyncProcess = 4,
    /// Perform the operation without returning a success payload body.
    SinkOnly = 5,
}

impl OutputModeKind {
    /// Return the stable uppercase name defined by the protobuf schema.
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

    /// Parse an exact protobuf schema name; unknown or differently cased names fail.
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
