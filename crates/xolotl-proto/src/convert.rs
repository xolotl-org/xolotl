//! Canonical conversions between domain types and protobuf wire messages.
//! Typed values, paths, capabilities, and composition trees retain their wire
//! structure. Failures preserve their exact variants and recovery metadata.
//! Checked decoders validate required fields and enum representations. They do
//! not replace execution admission or verify ownership of referenced objects.

use crate::xolotl::v1 as pb;
use thiserror::Error;
use xolotl_graph::{DoNode, OperationTemplate, StepRef, WaitSpec};
use xolotl_types::{
    BlobRef, CapError, Capability, DType, Failure, FloatBits, FrameKind, FrameRef, MethodId,
    Outcome, OutputMode, Path, PathError, ResourceName, StreamMarker, TensorRef, Value, ValueView,
};

/// Rejection of malformed, unsupported, or unrepresentable wire-domain data.
#[derive(Debug, Error)]
pub enum ConvertError {
    /// Invalid portable source document or source identity.
    #[error("portable program: {0}")]
    Portable(#[from] xolotl_graph::portable::CompileError),
    /// A path component violates the domain path syntax.
    #[error("path: {0}")]
    Path(#[from] PathError),
    /// A capability target, verb, or predicate cannot be parsed or validated.
    #[error("capability: {0}")]
    Capability(#[from] CapError),
    /// Required message or oneof is absent, or a required string is blank or
    /// has surrounding whitespace. The diagnostic identifies the field.
    #[error("missing required field: {0}")]
    Missing(&'static str),
    /// A named discriminant or its sentinel value is not supported by the domain.
    #[error("unsupported wire enum value: {0}")]
    Enum(&'static str),
    /// An unknown numeric protobuf enum value, retaining the rejected number.
    #[error("unsupported wire enum value for field {field}: {value}")]
    EnumValue {
        /// Wire field whose discriminant could not be interpreted.
        field: &'static str,
        /// Raw enum number received from the peer.
        value: i32,
    },
    /// A numeric field cannot be represented in the destination domain type.
    #[error("numeric value out of range for field: {0}")]
    Range(&'static str),
    /// A numeric conversion failed, retaining both the field and received value.
    #[error("numeric value out of range for field {field}: {value}")]
    RangeValue {
        /// Wire field whose value exceeded the destination type's range.
        field: &'static str,
        /// Unsigned value received before conversion to the destination type.
        value: u64,
    },
}

fn enum_value<T>(field: &'static str, value: i32) -> Result<T, ConvertError>
where
    T: TryFrom<i32>,
{
    T::try_from(value).map_err(|_conversion| ConvertError::EnumValue { field, value })
}

// Value conversions.

/// `xolotl_types::Value` → wire `Value`. Total and lossless.
pub fn value_to_pb(v: &Value) -> pb::Value {
    use pb::value::Kind;
    let kind = match v.view() {
        ValueView::Null => Kind::NullVal(pb::NullValue::NullValue as i32),
        ValueView::Bool(b) => Kind::BoolVal(b),
        ValueView::Int(i) => Kind::IntVal(i),
        ValueView::Float(FloatBits(f)) => Kind::FloatVal(f),
        ValueView::Str(s) => Kind::StrVal(s.to_owned()),
        ValueView::Bytes(b) => Kind::BytesVal(b.to_vec()),
        ValueView::List(xs) => Kind::ListVal(pb::ListValue {
            items: xs.iter().map(value_to_pb).collect(),
        }),
        ValueView::Map(m) => Kind::MapVal(pb::MapValue {
            entries: m
                .iter()
                .map(|(k, v)| (k.to_owned(), value_to_pb(v)))
                .collect(),
        }),
        ValueView::Blob(b) => Kind::BlobVal(blob_to_pb(b)),
        ValueView::Tensor(t) => Kind::TensorVal(tensor_to_pb(t)),
        ValueView::Frame(fr) => Kind::FrameVal(frame_to_pb(fr)),
        ValueView::StreamEnd(m) => Kind::StreamEndVal(stream_marker_to_pb(m)),
    };
    pb::Value { kind: Some(kind) }
}

/// Decode a wire value using permissive fallbacks. An absent oneof, invalid
/// tensor/frame metadata, or invalid stream marker maps to `Null`; unrecognized
/// null enum numbers are also accepted as null. Use [`value_from_pb_checked`]
/// when invalid input must be reported rather than replaced.
pub fn value_from_pb(v: &pb::Value) -> Value {
    use pb::value::Kind;
    match &v.kind {
        None => Value::null(),
        Some(Kind::NullVal(_)) => Value::null(),
        Some(Kind::BoolVal(b)) => Value::boolean(*b),
        Some(Kind::IntVal(i)) => Value::integer(*i),
        Some(Kind::FloatVal(f)) => Value::float(FloatBits(*f)),
        Some(Kind::StrVal(s)) => Value::string(s.clone()),
        Some(Kind::BytesVal(b)) => Value::bytes(b.clone()),
        Some(Kind::ListVal(l)) => Value::list(l.items.iter().map(value_from_pb).collect()),
        Some(Kind::MapVal(m)) => Value::map(
            m.entries
                .iter()
                .map(|(k, v)| (k.clone(), value_from_pb(v)))
                .collect(),
        ),
        Some(Kind::BlobVal(b)) => Value::blob(blob_from_pb(b)),
        Some(Kind::TensorVal(t)) => tensor_from_pb(t).map_or(Value::null(), Value::from),
        Some(Kind::FrameVal(fr)) => frame_from_pb(fr).map_or(Value::null(), Value::from),
        Some(Kind::StreamEndVal(m)) => {
            stream_marker_from_pb(m).map_or(Value::null(), Value::stream_end)
        }
    }
}

/// Wire `Value` → `xolotl_types::Value` with canonical field validation.
/// Recursively validates null enum numbers, tensor/frame metadata and stream
/// markers. An absent outer value oneof still means null. Blob identifiers and
/// declared lengths are retained without loading or authenticating stored data.
pub fn value_from_pb_checked(v: &pb::Value) -> Result<Value, ConvertError> {
    use pb::value::Kind;
    Ok(match &v.kind {
        None => Value::null(),
        Some(Kind::NullVal(raw)) => {
            enum_value::<pb::NullValue>("value.null", *raw)?;
            Value::null()
        }
        Some(Kind::BoolVal(b)) => Value::boolean(*b),
        Some(Kind::IntVal(i)) => Value::integer(*i),
        Some(Kind::FloatVal(f)) => Value::float(FloatBits(*f)),
        Some(Kind::StrVal(s)) => Value::string(s.clone()),
        Some(Kind::BytesVal(b)) => Value::bytes(b.clone()),
        Some(Kind::ListVal(l)) => Value::list(
            l.items
                .iter()
                .map(value_from_pb_checked)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(Kind::MapVal(m)) => Value::map(
            m.entries
                .iter()
                .map(|(k, v)| Ok((k.clone(), value_from_pb_checked(v)?)))
                .collect::<Result<_, ConvertError>>()?,
        ),
        Some(Kind::BlobVal(b)) => Value::blob(blob_from_pb(b)),
        Some(Kind::TensorVal(t)) => Value::from(tensor_from_pb_checked(t)?),
        Some(Kind::FrameVal(fr)) => Value::from(frame_from_pb_checked(fr)?),
        Some(Kind::StreamEndVal(m)) => Value::stream_end(stream_marker_from_pb_checked(m)?),
    })
}

// Multimodal reference conversions.

fn blob_to_pb(b: &BlobRef) -> pb::BlobRef {
    pb::BlobRef {
        hash: b.hash.clone(),
        size: b.size,
        mime: b.mime.clone(),
    }
}
fn blob_from_pb(b: &pb::BlobRef) -> BlobRef {
    BlobRef {
        hash: b.hash.clone(),
        size: b.size,
        mime: b.mime.clone(),
    }
}

fn tensor_to_pb(t: &TensorRef) -> pb::TensorRef {
    pb::TensorRef {
        blob: Some(blob_to_pb(&t.blob)),
        dtype: dtype_str(t.dtype).to_string(),
        shape: t.shape.clone(),
    }
}
fn tensor_from_pb(t: &pb::TensorRef) -> Option<TensorRef> {
    Some(TensorRef {
        blob: blob_from_pb(t.blob.as_ref()?),
        dtype: dtype_from_str(&t.dtype)?,
        shape: t.shape.clone(),
    })
}

fn tensor_from_pb_checked(t: &pb::TensorRef) -> Result<TensorRef, ConvertError> {
    Ok(TensorRef {
        blob: blob_from_pb(
            t.blob
                .as_ref()
                .ok_or(ConvertError::Missing("tensor.blob"))?,
        ),
        dtype: dtype_from_str(&t.dtype).ok_or(ConvertError::Enum("tensor.dtype"))?,
        shape: t.shape.clone(),
    })
}

fn frame_to_pb(fr: &FrameRef) -> pb::FrameRef {
    pb::FrameRef {
        blob: Some(blob_to_pb(&fr.blob)),
        ts_nanos: fr.ts_nanos,
        kind: frame_kind_str(fr.kind).to_string(),
    }
}
fn frame_from_pb(fr: &pb::FrameRef) -> Option<FrameRef> {
    Some(FrameRef {
        blob: blob_from_pb(fr.blob.as_ref()?),
        ts_nanos: fr.ts_nanos,
        kind: frame_kind_from_str(&fr.kind)?,
    })
}

fn frame_from_pb_checked(fr: &pb::FrameRef) -> Result<FrameRef, ConvertError> {
    Ok(FrameRef {
        blob: blob_from_pb(
            fr.blob
                .as_ref()
                .ok_or(ConvertError::Missing("frame.blob"))?,
        ),
        ts_nanos: fr.ts_nanos,
        kind: frame_kind_from_str(&fr.kind).ok_or(ConvertError::Enum("frame.kind"))?,
    })
}

fn stream_marker_to_pb(m: &StreamMarker) -> pb::StreamMarker {
    use pb::stream_marker::Kind;
    let kind = match m {
        StreamMarker::Done => Kind::Done(true),
        StreamMarker::Error { message } => Kind::Error(message.clone()),
    };
    pb::StreamMarker { kind: Some(kind) }
}
fn stream_marker_from_pb(m: &pb::StreamMarker) -> Option<StreamMarker> {
    use pb::stream_marker::Kind;
    Some(match &m.kind {
        Some(Kind::Done(true)) => StreamMarker::Done,
        Some(Kind::Error(message)) => StreamMarker::Error {
            message: message.clone(),
        },
        Some(Kind::Done(false)) | None => return None,
    })
}

fn stream_marker_from_pb_checked(m: &pb::StreamMarker) -> Result<StreamMarker, ConvertError> {
    use pb::stream_marker::Kind;
    match &m.kind {
        Some(Kind::Done(true)) => Ok(StreamMarker::Done),
        Some(Kind::Done(false)) => Err(ConvertError::Enum("stream_marker.done")),
        Some(Kind::Error(message)) => Ok(StreamMarker::Error {
            message: message.clone(),
        }),
        None => Err(ConvertError::Missing("stream_marker.kind")),
    }
}

pub(crate) fn dtype_str(d: DType) -> &'static str {
    match d {
        DType::F16 => "f16",
        DType::Bf16 => "bf16",
        DType::F32 => "f32",
        DType::F64 => "f64",
        DType::I8 => "i8",
        DType::I16 => "i16",
        DType::I32 => "i32",
        DType::I64 => "i64",
        DType::U8 => "u8",
        DType::Bool => "bool",
    }
}
/// Decode the canonical protobuf tensor dtype shared by references and upload
/// descriptors. Unknown strings, aliases and noncanonical casing return `None`.
pub fn dtype_from_str(s: &str) -> Option<DType> {
    Some(match s {
        "f16" => DType::F16,
        "bf16" => DType::Bf16,
        "f32" => DType::F32,
        "f64" => DType::F64,
        "i8" => DType::I8,
        "i16" => DType::I16,
        "i32" => DType::I32,
        "i64" => DType::I64,
        "u8" => DType::U8,
        "bool" => DType::Bool,
        _ => return None,
    })
}

pub(crate) fn frame_kind_str(k: FrameKind) -> &'static str {
    match k {
        FrameKind::Audio => "audio",
        FrameKind::Video => "video",
        FrameKind::Pose => "pose",
        FrameKind::Sensor => "sensor",
    }
}
/// Decode the canonical protobuf frame category shared by references and upload
/// descriptors. Unknown strings, aliases and noncanonical casing return `None`.
pub fn frame_kind_from_str(s: &str) -> Option<FrameKind> {
    Some(match s {
        "audio" => FrameKind::Audio,
        "video" => FrameKind::Video,
        "pose" => FrameKind::Pose,
        "sensor" => FrameKind::Sensor,
        _ => return None,
    })
}

// Path conversions.

/// `Path` → wire `Path` (preserves cluster, scheme, and segments).
pub fn path_to_pb(p: &Path) -> pb::Path {
    pb::Path {
        cluster: p.cluster().map(|c| c.to_string()),
        scheme: p.scheme().to_string(),
        segments: p.segments().iter().map(|s| s.to_string()).collect(),
    }
}

/// Wire `Path` → `Path`.
pub fn path_from_pb(p: &pb::Path) -> Result<Path, ConvertError> {
    let mut path = Path::try_new(&p.scheme)?;
    if let Some(cluster) = &p.cluster {
        path = path.try_with_cluster(cluster)?;
    }
    for segment in &p.segments {
        path = path.try_push(segment)?;
    }
    Ok(path)
}

// Capability conversions.

/// `Capability` → wire `Capability`. The predicate is carried in its canonical
/// string form (`Predicate: Display`); decode with [`capability_from_pb`].
pub fn capability_to_pb(c: &Capability) -> pb::Capability {
    pb::Capability {
        verb: c.verb.clone(),
        scheme: c.scheme.clone(),
        segments: c.segments.iter().map(|s| s.to_string()).collect(),
        predicate: c.predicate.as_ref().map(|p| p.to_string()),
    }
}

/// Wire `Capability` → `Capability`.
pub fn capability_from_pb(c: &pb::Capability) -> Result<Capability, ConvertError> {
    let predicate = c
        .predicate
        .as_deref()
        .map(xolotl_types::Predicate::parse)
        .transpose()?;
    Ok(Capability::try_new(
        c.verb.as_str(),
        c.scheme.as_str(),
        c.segments.iter().map(String::as_str),
        predicate,
    )?)
}

// Program and DoNode conversions.

/// Encode a portable source document using the shared compiler and source identity.
/// This envelope does not grant permission to submit arbitrary code to a Gateway.
pub fn portable_program_to_pb(
    program: &xolotl_graph::portable::Program,
) -> Result<pb::PortableProgram, ConvertError> {
    use xolotl_graph::portable::CompileError;
    let compiled = program.compile()?;
    let source =
        serde_json::to_vec(program).map_err(|error| CompileError::Encoding(error.to_string()))?;
    if source.len() > 1024 * 1024 {
        return Err(CompileError::Capacity.into());
    }
    Ok(pb::PortableProgram {
        json_source: source,
        program_id: compiled.id().to_vec(),
    })
}

/// Decode, compile and verify a portable program before the host considers admission.
pub fn portable_program_from_pb(
    program: &pb::PortableProgram,
) -> Result<xolotl_graph::portable::Program, ConvertError> {
    use xolotl_graph::portable::{CompileError, Program};
    let source = Program::from_json(&program.json_source)?;
    if source.compile()?.id().as_slice() != program.program_id {
        return Err(CompileError::Encoding("source identity mismatch".into()).into());
    }
    Ok(source)
}

/// `DoNode` → wire `Program`.
pub fn program_to_pb(root: &DoNode) -> pb::Program {
    pb::Program {
        root: Some(do_node_to_pb(root)),
        provenance: None,
    }
}

/// Decode the required program root using checked node conversion. Attached
/// payload provenance is left to ingress admission and is not consumed here.
pub fn program_from_pb(program: &pb::Program) -> Result<DoNode, ConvertError> {
    do_node_from_pb(
        program
            .root
            .as_ref()
            .ok_or(ConvertError::Missing("program.root"))?,
    )
}

/// Recursively encode a native composition tree, retaining named step references
/// and typed constants. Failure nodes preserve their structured metadata.
pub fn do_node_to_pb(node: &DoNode) -> pb::DoNode {
    use pb::do_node::Kind;
    let kind = match node {
        DoNode::Pure(v) => Kind::Pure(value_to_pb(v)),
        DoNode::AndThen { d, then } => Kind::AndThen(pb::AndThen {
            d: Some(Box::new(do_node_to_pb(d))),
            then: Some(step_ref_to_pb(then)),
        }),
        DoNode::OrElse { d, or } => Kind::OrElse(pb::OrElse {
            d: Some(Box::new(do_node_to_pb(d))),
            or: Some(step_ref_to_pb(or)),
        }),
        DoNode::Both(a, b) => Kind::Both(pb::Parallel {
            left: Some(Box::new(do_node_to_pb(a))),
            right: Some(Box::new(do_node_to_pb(b))),
        }),
        DoNode::Race(a, b) => Kind::Race(pb::Parallel {
            left: Some(Box::new(do_node_to_pb(a))),
            right: Some(Box::new(do_node_to_pb(b))),
        }),
        DoNode::Let { name, value, body } => Kind::Let(pb::Let {
            name: name.clone(),
            value: Some(Box::new(do_node_to_pb(value))),
            body: Some(Box::new(do_node_to_pb(body))),
        }),
        DoNode::Use(name) => Kind::UseName(name.clone()),
        DoNode::Acting { identity, body } => Kind::Acting(pb::Acting {
            identity: Some(path_to_pb(identity)),
            body: Some(Box::new(do_node_to_pb(body))),
        }),
        DoNode::Fail(f) => Kind::Fail(failure_to_pb(f)),
        DoNode::Wait(spec) => Kind::Wait(wait_spec_to_pb(spec)),
        DoNode::Op(op) => Kind::Op(operation_template_to_pb(op)),
    };
    pb::DoNode { kind: Some(kind) }
}

/// Recursively decode a native composition tree, checking required children,
/// canonical nonblank names, typed values, paths, and output modes. This does
/// not resolve lexical names or native steps, impose a tree-size budget, or
/// authorize resource access; those checks belong to compilation and admission.
pub fn do_node_from_pb(node: &pb::DoNode) -> Result<DoNode, ConvertError> {
    use pb::do_node::Kind;
    Ok(
        match node
            .kind
            .as_ref()
            .ok_or(ConvertError::Missing("do_node.kind"))?
        {
            Kind::Pure(v) => DoNode::Pure(value_from_pb_checked(v)?),
            Kind::AndThen(x) => DoNode::AndThen {
                d: Box::new(do_node_from_pb(
                    x.d.as_deref().ok_or(ConvertError::Missing("and_then.d"))?,
                )?),
                then: step_ref_from_pb(
                    x.then
                        .as_ref()
                        .ok_or(ConvertError::Missing("and_then.then"))?,
                )?,
            },
            Kind::OrElse(x) => DoNode::OrElse {
                d: Box::new(do_node_from_pb(
                    x.d.as_deref().ok_or(ConvertError::Missing("or_else.d"))?,
                )?),
                or: step_ref_from_pb(x.or.as_ref().ok_or(ConvertError::Missing("or_else.or"))?)?,
            },
            Kind::Both(x) => DoNode::Both(
                Box::new(do_node_from_pb(
                    x.left
                        .as_deref()
                        .ok_or(ConvertError::Missing("both.left"))?,
                )?),
                Box::new(do_node_from_pb(
                    x.right
                        .as_deref()
                        .ok_or(ConvertError::Missing("both.right"))?,
                )?),
            ),
            Kind::Race(x) => DoNode::Race(
                Box::new(do_node_from_pb(
                    x.left
                        .as_deref()
                        .ok_or(ConvertError::Missing("race.left"))?,
                )?),
                Box::new(do_node_from_pb(
                    x.right
                        .as_deref()
                        .ok_or(ConvertError::Missing("race.right"))?,
                )?),
            ),
            Kind::Let(x) => DoNode::Let {
                name: required_nonblank(&x.name, "let.name")?,
                value: Box::new(do_node_from_pb(
                    x.value
                        .as_deref()
                        .ok_or(ConvertError::Missing("let.value"))?,
                )?),
                body: Box::new(do_node_from_pb(
                    x.body.as_deref().ok_or(ConvertError::Missing("let.body"))?,
                )?),
            },
            Kind::UseName(name) => DoNode::Use(required_nonblank(name, "use.name")?),
            Kind::Acting(x) => DoNode::Acting {
                identity: path_from_pb(
                    x.identity
                        .as_ref()
                        .ok_or(ConvertError::Missing("acting.identity"))?,
                )?,
                body: Box::new(do_node_from_pb(
                    x.body
                        .as_deref()
                        .ok_or(ConvertError::Missing("acting.body"))?,
                )?),
            },
            Kind::Fail(f) => DoNode::Fail(failure_from_pb(f)?),
            Kind::Wait(spec) => DoNode::Wait(wait_spec_from_pb(spec)?),
            Kind::Op(op) => DoNode::Op(operation_template_from_pb(op)?),
        },
    )
}

fn step_ref_to_pb(step: &StepRef) -> pb::StepRef {
    pb::StepRef {
        name: step.name.clone(),
        arg: step.arg.as_ref().map(value_to_pb),
    }
}

fn step_ref_from_pb(step: &pb::StepRef) -> Result<StepRef, ConvertError> {
    Ok(StepRef {
        name: required_nonblank(&step.name, "step.name")?,
        arg: step.arg.as_ref().map(value_from_pb_checked).transpose()?,
    })
}

fn wait_spec_to_pb(spec: &WaitSpec) -> pb::WaitSpec {
    use pb::wait_spec::Kind;
    let kind = match spec {
        WaitSpec::Signal(path) => Kind::Signal(path_to_pb(path)),
        WaitSpec::Deadline(ms) => Kind::DeadlineMillis(*ms),
    };
    pb::WaitSpec { kind: Some(kind) }
}

fn wait_spec_from_pb(spec: &pb::WaitSpec) -> Result<WaitSpec, ConvertError> {
    use pb::wait_spec::Kind;
    match spec
        .kind
        .as_ref()
        .ok_or(ConvertError::Missing("wait.kind"))?
    {
        Kind::Signal(path) => Ok(WaitSpec::Signal(path_from_pb(path)?)),
        Kind::DeadlineMillis(ms) => Ok(WaitSpec::Deadline(*ms)),
    }
}

fn operation_template_to_pb(op: &OperationTemplate) -> pb::OperationTemplate {
    pb::OperationTemplate {
        target: Some(path_to_pb(&op.target.0)),
        method: op.method.clone(),
        method_id: op.method_id.map(|id| id.get()),
        output: Some(output_mode_to_pb(op.output)),
        literal_input: op.literal_input.as_ref().map(value_to_pb),
    }
}

fn operation_template_from_pb(
    op: &pb::OperationTemplate,
) -> Result<OperationTemplate, ConvertError> {
    Ok(OperationTemplate {
        target: ResourceName::new(path_from_pb(
            op.target
                .as_ref()
                .ok_or(ConvertError::Missing("operation.target"))?,
        )?),
        method: required_nonblank(&op.method, "operation.method")?,
        method_id: op.method_id.map(MethodId::new),
        output: output_mode_from_pb(
            op.output
                .as_ref()
                .ok_or(ConvertError::Missing("operation.output"))?,
        )?,
        literal_input: op
            .literal_input
            .as_ref()
            .map(value_from_pb_checked)
            .transpose()?,
    })
}

/// Encode a concrete delivery mode. Collection limits are retained; all other
/// modes use zero for the otherwise ignored `collect_limit` field.
pub fn output_mode_to_pb(mode: OutputMode) -> pb::OutputMode {
    let (kind, collect_limit) = match mode {
        OutputMode::Unary => (pb::OutputModeKind::Unary, 0),
        OutputMode::Stream => (pb::OutputModeKind::Stream, 0),
        OutputMode::Collect { limit } => (pb::OutputModeKind::Collect, limit as u64),
        OutputMode::AsyncProcess => (pb::OutputModeKind::AsyncProcess, 0),
        OutputMode::SinkOnly => (pb::OutputModeKind::SinkOnly, 0),
    };
    pb::OutputMode {
        kind: kind as i32,
        collect_limit,
    }
}

/// Decode a delivery mode, rejecting unspecified or unknown enum numbers.
/// A collection limit must fit the host's `usize`; zero is valid. The limit
/// field is ignored for other modes, and method output support is checked later.
pub fn output_mode_from_pb(mode: &pb::OutputMode) -> Result<OutputMode, ConvertError> {
    let kind = enum_value::<pb::OutputModeKind>("output.kind", mode.kind)?;
    Ok(match kind {
        pb::OutputModeKind::Unspecified => return Err(ConvertError::Enum("output.kind")),
        pb::OutputModeKind::Unary => OutputMode::Unary,
        pb::OutputModeKind::Stream => OutputMode::Stream,
        pb::OutputModeKind::Collect => OutputMode::Collect {
            limit: usize::try_from(mode.collect_limit).map_err(|_conversion| {
                ConvertError::RangeValue {
                    field: "output.collect_limit",
                    value: mode.collect_limit,
                }
            })?,
        },
        pb::OutputModeKind::AsyncProcess => OutputMode::AsyncProcess,
        pb::OutputModeKind::SinkOnly => OutputMode::SinkOnly,
    })
}

// Failure and outcome conversions.

/// Stable wire tag for each [`Failure`] variant.
pub fn failure_kind(f: &Failure) -> &'static str {
    match f {
        Failure::PermissionDenied { .. } => "permission_denied",
        Failure::NoHandler { .. } => "no_handler",
        Failure::BudgetExhausted { .. } => "budget_exhausted",
        Failure::RateLimited => "rate_limited",
        Failure::ApprovalPending { .. } => "approval_pending",
        Failure::Timeout => "timeout",
        Failure::Cancelled => "cancelled",
        Failure::Quarantined { .. } => "quarantined",
        Failure::InvalidInput { .. } => "invalid_input",
        Failure::HandlerError { .. } => "handler_error",
        Failure::KernelNamespaceProtected => "kernel_namespace_protected",
        Failure::PolicyViolation { .. } => "policy_violation",
        Failure::PathInvalid { .. } => "path_invalid",
        Failure::Custom { .. } => "custom",
    }
}

/// `Failure` → wire `Failure`, retaining every structured field.
pub fn failure_to_pb(f: &Failure) -> pb::Failure {
    use pb::failure::{self as wire, Kind, Marker};
    let kind = match f {
        Failure::PermissionDenied { required, actual } => {
            Kind::PermissionDenied(wire::PermissionDenied {
                required: required.clone(),
                actual: actual.clone(),
            })
        }
        Failure::NoHandler { path } => Kind::NoHandler(path_to_pb(path)),
        Failure::BudgetExhausted { dim } => Kind::BudgetExhausted(dim.clone()),
        Failure::RateLimited => Kind::RateLimited(Marker {}),
        Failure::ApprovalPending {
            approval_key,
            reason,
        } => Kind::ApprovalPending(wire::ApprovalPending {
            approval_key: approval_key.clone(),
            reason: reason.clone(),
        }),
        Failure::Timeout => Kind::Timeout(Marker {}),
        Failure::Cancelled => Kind::Cancelled(Marker {}),
        Failure::Quarantined { op_id, reason } => Kind::Quarantined(wire::Quarantined {
            op_id: op_id.clone(),
            reason: reason.clone(),
        }),
        Failure::InvalidInput { reason } => Kind::InvalidInput(reason.clone()),
        Failure::HandlerError { kind, message } => Kind::HandlerError(wire::ClassifiedError {
            kind: kind.clone(),
            message: message.clone(),
        }),
        Failure::KernelNamespaceProtected => Kind::KernelNamespaceProtected(Marker {}),
        Failure::PolicyViolation { policy, detail } => {
            Kind::PolicyViolation(wire::PolicyViolation {
                policy: policy.clone(),
                detail: detail.clone(),
            })
        }
        Failure::PathInvalid { path, reason } => Kind::PathInvalid(wire::PathInvalid {
            path: Some(path_to_pb(path)),
            reason: reason.clone(),
        }),
        Failure::Custom { kind, message } => Kind::Custom(wire::ClassifiedError {
            kind: kind.clone(),
            message: message.clone(),
        }),
    };
    pb::Failure { kind: Some(kind) }
}

/// Wire `Failure` → `Failure`, rejecting absent variants and malformed paths.
/// Text fields are preserved verbatim, including empty strings and whitespace.
pub fn failure_from_pb(f: &pb::Failure) -> Result<Failure, ConvertError> {
    use pb::failure::Kind;
    Ok(
        match f
            .kind
            .as_ref()
            .ok_or(ConvertError::Missing("failure.kind"))?
        {
            Kind::PermissionDenied(detail) => Failure::PermissionDenied {
                required: detail.required.clone(),
                actual: detail.actual.clone(),
            },
            Kind::NoHandler(path) => Failure::NoHandler {
                path: path_from_pb(path)?,
            },
            Kind::BudgetExhausted(dim) => Failure::BudgetExhausted { dim: dim.clone() },
            Kind::RateLimited(_) => Failure::RateLimited,
            Kind::ApprovalPending(detail) => Failure::ApprovalPending {
                approval_key: detail.approval_key.clone(),
                reason: detail.reason.clone(),
            },
            Kind::Timeout(_) => Failure::Timeout,
            Kind::Cancelled(_) => Failure::Cancelled,
            Kind::Quarantined(detail) => Failure::Quarantined {
                op_id: detail.op_id.clone(),
                reason: detail.reason.clone(),
            },
            Kind::InvalidInput(reason) => Failure::InvalidInput {
                reason: reason.clone(),
            },
            Kind::HandlerError(detail) => Failure::HandlerError {
                kind: detail.kind.clone(),
                message: detail.message.clone(),
            },
            Kind::KernelNamespaceProtected(_) => Failure::KernelNamespaceProtected,
            Kind::PolicyViolation(detail) => Failure::PolicyViolation {
                policy: detail.policy.clone(),
                detail: detail.detail.clone(),
            },
            Kind::PathInvalid(detail) => Failure::PathInvalid {
                path: path_from_pb(
                    detail
                        .path
                        .as_ref()
                        .ok_or(ConvertError::Missing("failure.path_invalid.path"))?,
                )?,
                reason: detail.reason.clone(),
            },
            Kind::Custom(detail) => Failure::Custom {
                kind: detail.kind.clone(),
                message: detail.message.clone(),
            },
        },
    )
}

/// `Outcome` → wire `Outcome`, structurally (Done/Fail/Short).
pub fn outcome_to_pb(o: &Outcome) -> pb::Outcome {
    let result = match o {
        Outcome::Done(v) => Some(pb::outcome::Result::Done(value_to_pb(v))),
        Outcome::Short(v) => Some(pb::outcome::Result::Short(value_to_pb(v))),
        Outcome::Fail(f) => Some(pb::outcome::Result::Fail(failure_to_pb(f))),
    };
    pb::Outcome { result }
}

// External frame conversions.
//
// The `xolotl_types::external` frames ⇄ the generated `pb::external` wire
// messages. These are the marshalling used by the gRPC `ExternalService`
// session stream. The three-stage handshake frames are represented directly in
// the wire schema; the business frames map cleanly and are bridged here.

use pb::external as ext;
use xolotl_types::external::{
    AckStatus, ApplyStatus, CommandResult, ConfigAxis, ControlFrame, ErrorInfo, EventAck,
    FlowSignal, InboundEvent, Invoke, InvokeResult, OutboundCommand, RejectReason, Role, RoleReady,
    RoleSessionClientHello, SessionContext,
};

fn required_value_from_pb(
    value: Option<&pb::Value>,
    field: &'static str,
) -> Result<Value, ConvertError> {
    value
        .ok_or(ConvertError::Missing(field))
        .and_then(value_from_pb_checked)
}

fn required_nonblank(value: &str, field: &'static str) -> Result<String, ConvertError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(ConvertError::Missing(field));
    }
    Ok(value.to_string())
}

/// `RoleSessionClientHello` → wire `RoleSessionClientHello`.
pub fn role_session_client_hello_to_pb(
    hello: &RoleSessionClientHello,
) -> ext::RoleSessionClientHello {
    ext::RoleSessionClientHello {
        role: role_to_pb(hello.role) as i32,
        installation_id: hello.installation_id.clone(),
        projection_id: hello.projection_id.clone(),
        registry_hash: hello.registry_hash.clone(),
        observed: Some(observed_generations_to_pb(&hello.observed)),
        config_schema: hello.config_schema.as_ref().map(value_to_pb),
    }
}

/// Wire `RoleSessionClientHello` → `RoleSessionClientHello`.
pub fn role_session_client_hello_from_pb(
    hello: &ext::RoleSessionClientHello,
) -> Result<RoleSessionClientHello, ConvertError> {
    Ok(RoleSessionClientHello {
        role: role_from_pb(hello.role)?,
        installation_id: hello.installation_id.clone(),
        projection_id: hello.projection_id.clone(),
        registry_hash: hello.registry_hash.clone(),
        observed: observed_generations_from_pb(
            hello
                .observed
                .as_ref()
                .ok_or(ConvertError::Missing("hello.observed"))?,
        ),
        config_schema: hello
            .config_schema
            .as_ref()
            .map(value_from_pb_checked)
            .transpose()?,
    })
}

/// `SessionContext` → wire `SessionContext`.
pub fn session_context_to_pb(ctx: &SessionContext) -> ext::SessionContext {
    ext::SessionContext {
        installation_id: ctx.installation_id.clone(),
        projection_id: ctx.projection_id.clone(),
        role: role_to_pb(ctx.role) as i32,
        registry_hash: ctx.registry_hash.clone(),
        credential_generation: ctx.credential_generation,
        binding_generation: ctx.binding_generation,
        installation_config_version: ctx.installation_config_version,
        projection_version: ctx.projection_version,
        presentation_config_generation: ctx.presentation_config_generation,
        alias_catalog_generation: ctx.alias_catalog_generation,
        session_id: ctx.session_id.clone(),
    }
}

/// Wire `SessionContext` → `SessionContext`.
pub fn session_context_from_pb(ctx: &ext::SessionContext) -> Result<SessionContext, ConvertError> {
    if ctx.session_id.trim().is_empty() {
        return Err(ConvertError::Missing("session_id"));
    }
    Ok(SessionContext {
        installation_id: ctx.installation_id.clone(),
        projection_id: ctx.projection_id.clone(),
        role: role_from_pb(ctx.role)?,
        registry_hash: ctx.registry_hash.clone(),
        credential_generation: ctx.credential_generation,
        binding_generation: ctx.binding_generation,
        installation_config_version: ctx.installation_config_version,
        projection_version: ctx.projection_version,
        presentation_config_generation: ctx.presentation_config_generation,
        alias_catalog_generation: ctx.alias_catalog_generation,
        session_id: ctx.session_id.clone(),
    })
}

/// `RoleReady` → wire `RoleReady`.
pub fn role_ready_to_pb(ready: &RoleReady) -> ext::RoleReady {
    ext::RoleReady {
        accepted_context: Some(session_context_to_pb(&ready.accepted_context)),
    }
}

/// Wire `RoleReady` → `RoleReady`.
pub fn role_ready_from_pb(ready: &ext::RoleReady) -> Result<RoleReady, ConvertError> {
    Ok(RoleReady {
        accepted_context: session_context_from_pb(
            ready
                .accepted_context
                .as_ref()
                .ok_or(ConvertError::Missing("accepted_context"))?,
        )?,
    })
}

/// `InboundEvent` → wire `InboundEvent`.
pub fn inbound_event_to_pb(event: &InboundEvent) -> ext::InboundEvent {
    ext::InboundEvent {
        id: event.id.clone(),
        payload: Some(value_to_pb(&event.payload)),
        timestamp_ms: event.timestamp_ms,
        observed: Some(observed_generations_to_pb(&event.observed)),
        stream_id: event.stream_id.clone(),
        seq: event.seq,
    }
}

/// Wire `InboundEvent` → `InboundEvent`.
pub fn inbound_event_from_pb(event: &ext::InboundEvent) -> Result<InboundEvent, ConvertError> {
    Ok(InboundEvent {
        id: event.id.clone(),
        payload: required_value_from_pb(event.payload.as_ref(), "inbound_event.payload")?,
        timestamp_ms: event.timestamp_ms,
        observed: observed_generations_from_pb(
            event
                .observed
                .as_ref()
                .ok_or(ConvertError::Missing("inbound_event.observed"))?,
        ),
        stream_id: event.stream_id.clone(),
        seq: event.seq,
    })
}

/// `Invoke` to wire `Invoke`: daemon to Provider client dispatch.
pub fn invoke_to_pb(i: &Invoke) -> ext::Invoke {
    ext::Invoke {
        invocation_id: i.invocation_id.clone(),
        effect_path: Some(path_to_pb(&i.effect_path)),
        input: Some(value_to_pb(&i.input)),
        deadline_ms: i.deadline_ms,
        output_stream_to: i.output_stream_to.as_ref().map(|p| p.to_string()),
        method_id: Some(i.method_id.get()),
    }
}

/// Wire `Invoke` → `Invoke`. Missing or malformed required fields fail closed.
pub fn invoke_from_pb(i: &ext::Invoke) -> Result<Invoke, ConvertError> {
    Ok(Invoke {
        invocation_id: i.invocation_id.clone(),
        effect_path: path_from_pb(
            i.effect_path
                .as_ref()
                .ok_or(ConvertError::Missing("effect_path"))?,
        )?,
        method_id: MethodId::new(i.method_id.ok_or(ConvertError::Missing("method_id"))?),
        input: required_value_from_pb(i.input.as_ref(), "invoke.input")?,
        deadline_ms: i.deadline_ms,
        output_stream_to: i
            .output_stream_to
            .as_ref()
            .map(|s| Path::parse(s))
            .transpose()?,
    })
}

/// `InvokeResult` to wire `InvokeResult`: Provider client to daemon result.
pub fn invoke_result_to_pb(r: &InvokeResult) -> ext::InvokeResult {
    let outcome = match &r.outcome {
        Ok(v) => Some(ext::invoke_result::Outcome::Success(value_to_pb(v))),
        Err(e) => Some(ext::invoke_result::Outcome::Error(error_info_to_pb(e))),
    };
    ext::InvokeResult {
        invocation_id: r.invocation_id.clone(),
        outcome,
    }
}

/// Wire `InvokeResult` → `InvokeResult`.
pub fn invoke_result_from_pb(r: &ext::InvokeResult) -> Result<InvokeResult, ConvertError> {
    let outcome = match &r.outcome {
        Some(ext::invoke_result::Outcome::Success(v)) => Ok(value_from_pb_checked(v)?),
        Some(ext::invoke_result::Outcome::Error(e)) => Err(error_info_from_pb(e)?),
        None => return Err(ConvertError::Missing("invoke_result.outcome")),
    };
    Ok(InvokeResult {
        invocation_id: r.invocation_id.clone(),
        outcome,
    })
}

/// `OutboundCommand` -> wire `OutboundCommand`: daemon->Source dispatch.
pub fn outbound_command_to_pb(c: &OutboundCommand) -> ext::OutboundCommand {
    ext::OutboundCommand {
        id: c.id.clone(),
        action: Some(value_to_pb(&c.action)),
        observed: Some(observed_generations_to_pb(&c.observed)),
    }
}

/// Wire `OutboundCommand` -> `OutboundCommand`.
pub fn outbound_command_from_pb(c: &ext::OutboundCommand) -> Result<OutboundCommand, ConvertError> {
    Ok(OutboundCommand {
        id: c.id.clone(),
        action: required_value_from_pb(c.action.as_ref(), "outbound_command.action")?,
        observed: observed_generations_from_pb(
            c.observed
                .as_ref()
                .ok_or(ConvertError::Missing("outbound_command.observed"))?,
        ),
    })
}

/// `CommandResult` -> wire `CommandResult`: Source->daemon command result.
pub fn command_result_to_pb(r: &CommandResult) -> ext::CommandResult {
    let outcome = match &r.outcome {
        Ok(v) => Some(ext::command_result::Outcome::Success(value_to_pb(v))),
        Err(e) => Some(ext::command_result::Outcome::Error(error_info_to_pb(e))),
    };
    ext::CommandResult {
        id: r.id.clone(),
        outcome,
    }
}

/// Wire `CommandResult` -> `CommandResult`.
pub fn command_result_from_pb(r: &ext::CommandResult) -> Result<CommandResult, ConvertError> {
    let outcome = match &r.outcome {
        Some(ext::command_result::Outcome::Success(v)) => Ok(value_from_pb_checked(v)?),
        Some(ext::command_result::Outcome::Error(e)) => Err(error_info_from_pb(e)?),
        None => return Err(ConvertError::Missing("command_result.outcome")),
    };
    Ok(CommandResult {
        id: r.id.clone(),
        outcome,
    })
}

/// `EventAck` → wire `EventAck`.
pub fn event_ack_to_pb(ack: &EventAck) -> ext::EventAck {
    ext::EventAck {
        id: ack.id.clone(),
        status: ack_status_to_pb(ack.status) as i32,
        reject_reason: ack.reject_reason.clone(),
    }
}

/// Wire `EventAck` → `EventAck`.
pub fn event_ack_from_pb(ack: &ext::EventAck) -> Result<EventAck, ConvertError> {
    Ok(EventAck {
        id: ack.id.clone(),
        status: ack_status_from_pb(ack.status)?,
        reject_reason: ack.reject_reason.clone(),
    })
}

/// `ControlFrame` → wire `ControlFrame`.
pub fn control_frame_to_pb(frame: &ControlFrame) -> ext::ControlFrame {
    let kind = match frame {
        ControlFrame::Heartbeat { timestamp_ms } => {
            ext::control_frame::Kind::Heartbeat(ext::Heartbeat {
                timestamp_ms: *timestamp_ms,
            })
        }
        ControlFrame::Shutdown {
            graceful,
            timeout_ms,
        } => ext::control_frame::Kind::Shutdown(ext::Shutdown {
            graceful: *graceful,
            timeout_ms: *timeout_ms,
        }),
        ControlFrame::FlowControl(signal) => {
            ext::control_frame::Kind::FlowControl(ext::FlowControl {
                signal: flow_signal_to_pb(*signal) as i32,
            })
        }
        ControlFrame::ProviderCancel {
            invocation_id,
            reason,
        } => ext::control_frame::Kind::ProviderCancel(ext::ProviderCancel {
            invocation_id: invocation_id.clone(),
            reason: reason.clone(),
        }),
        ControlFrame::PresentationProfileUpdate {
            profile_generation,
            profile_hash,
            profile,
        } => ext::control_frame::Kind::PresentationProfileUpdate(ext::PresentationProfileUpdate {
            profile_generation: *profile_generation,
            profile_hash: profile_hash.clone(),
            profile: Some(value_to_pb(profile)),
        }),
        ControlFrame::InstallationConfigUpdate {
            config_version,
            config,
        } => ext::control_frame::Kind::InstallationConfigUpdate(ext::InstallationConfigUpdate {
            config_version: *config_version,
            config: Some(value_to_pb(config)),
        }),
        ControlFrame::PresentationConfigUpdate {
            generation,
            profile_hash,
            config,
        } => ext::control_frame::Kind::PresentationConfigUpdate(ext::PresentationConfigUpdate {
            generation: *generation,
            profile_hash: profile_hash.clone(),
            config: Some(value_to_pb(config)),
        }),
        ControlFrame::ConfigAck {
            axis,
            version,
            status,
        } => ext::control_frame::Kind::ConfigAck(config_ack_to_pb(*axis, *version, *status)),
    };
    ext::ControlFrame { kind: Some(kind) }
}

/// Wire `ControlFrame` → `ControlFrame`.
pub fn control_frame_from_pb(frame: &ext::ControlFrame) -> Result<ControlFrame, ConvertError> {
    Ok(
        match frame
            .kind
            .as_ref()
            .ok_or(ConvertError::Missing("control.kind"))?
        {
            ext::control_frame::Kind::Heartbeat(heartbeat) => ControlFrame::Heartbeat {
                timestamp_ms: heartbeat.timestamp_ms,
            },
            ext::control_frame::Kind::Shutdown(shutdown) => ControlFrame::Shutdown {
                graceful: shutdown.graceful,
                timeout_ms: shutdown.timeout_ms,
            },
            ext::control_frame::Kind::FlowControl(flow) => {
                ControlFrame::FlowControl(flow_signal_from_pb(flow.signal)?)
            }
            ext::control_frame::Kind::ProviderCancel(cancel) => ControlFrame::ProviderCancel {
                invocation_id: cancel.invocation_id.clone(),
                reason: cancel.reason.clone(),
            },
            ext::control_frame::Kind::PresentationProfileUpdate(update) => {
                ControlFrame::PresentationProfileUpdate {
                    profile_generation: update.profile_generation,
                    profile_hash: update.profile_hash.clone(),
                    profile: required_value_from_pb(
                        update.profile.as_ref(),
                        "presentation_profile_update.profile",
                    )?,
                }
            }
            ext::control_frame::Kind::InstallationConfigUpdate(update) => {
                ControlFrame::InstallationConfigUpdate {
                    config_version: update.config_version,
                    config: required_value_from_pb(
                        update.config.as_ref(),
                        "installation_config_update.config",
                    )?,
                }
            }
            ext::control_frame::Kind::PresentationConfigUpdate(update) => {
                ControlFrame::PresentationConfigUpdate {
                    generation: update.generation,
                    profile_hash: update.profile_hash.clone(),
                    config: required_value_from_pb(
                        update.config.as_ref(),
                        "presentation_config_update.config",
                    )?,
                }
            }
            ext::control_frame::Kind::ConfigAck(ack) => {
                let (axis, version, status) = config_ack_from_pb(ack)?;
                ControlFrame::ConfigAck {
                    axis,
                    version,
                    status,
                }
            }
        },
    )
}

fn observed_generations_to_pb(
    observed: &xolotl_types::external::ObservedGenerations,
) -> ext::ObservedGenerations {
    ext::ObservedGenerations {
        presentation_config_generation: observed.presentation_config_generation,
        alias_catalog_generation: observed.alias_catalog_generation,
    }
}

fn observed_generations_from_pb(
    observed: &ext::ObservedGenerations,
) -> xolotl_types::external::ObservedGenerations {
    xolotl_types::external::ObservedGenerations {
        presentation_config_generation: observed.presentation_config_generation,
        alias_catalog_generation: observed.alias_catalog_generation,
    }
}

fn role_to_pb(role: Role) -> ext::ExternalRole {
    match role {
        Role::Source => ext::ExternalRole::Source,
        Role::Provider => ext::ExternalRole::Provider,
    }
}

fn role_from_pb(role: i32) -> Result<Role, ConvertError> {
    match enum_value::<ext::ExternalRole>("external.role", role)? {
        ext::ExternalRole::Source => Ok(Role::Source),
        ext::ExternalRole::Provider => Ok(Role::Provider),
        ext::ExternalRole::Unspecified => Err(ConvertError::Enum("external.role")),
    }
}

fn ack_status_to_pb(status: AckStatus) -> ext::AckStatus {
    match status {
        AckStatus::Accepted => ext::AckStatus::Accepted,
        AckStatus::Duplicate => ext::AckStatus::Duplicate,
        AckStatus::Rejected => ext::AckStatus::Rejected,
    }
}

fn ack_status_from_pb(status: i32) -> Result<AckStatus, ConvertError> {
    match enum_value::<ext::AckStatus>("ack.status", status)? {
        ext::AckStatus::Accepted => Ok(AckStatus::Accepted),
        ext::AckStatus::Duplicate => Ok(AckStatus::Duplicate),
        ext::AckStatus::Rejected => Ok(AckStatus::Rejected),
        ext::AckStatus::Unspecified => Err(ConvertError::Enum("ack.status")),
    }
}

fn flow_signal_to_pb(signal: FlowSignal) -> ext::FlowSignal {
    match signal {
        FlowSignal::Pause => ext::FlowSignal::Pause,
        FlowSignal::Resume => ext::FlowSignal::Resume,
    }
}

fn flow_signal_from_pb(signal: i32) -> Result<FlowSignal, ConvertError> {
    match enum_value::<ext::FlowSignal>("flow.signal", signal)? {
        ext::FlowSignal::Pause => Ok(FlowSignal::Pause),
        ext::FlowSignal::Resume => Ok(FlowSignal::Resume),
        ext::FlowSignal::Unspecified => Err(ConvertError::Enum("flow.signal")),
    }
}

fn config_axis_to_pb(axis: ConfigAxis) -> ext::ConfigAxis {
    match axis {
        ConfigAxis::InstallationConfig => ext::ConfigAxis::InstallationConfig,
        ConfigAxis::PresentationConfig => ext::ConfigAxis::PresentationConfig,
    }
}

fn config_axis_from_pb(axis: i32) -> Result<ConfigAxis, ConvertError> {
    match enum_value::<ext::ConfigAxis>("config.axis", axis)? {
        ext::ConfigAxis::InstallationConfig => Ok(ConfigAxis::InstallationConfig),
        ext::ConfigAxis::PresentationConfig => Ok(ConfigAxis::PresentationConfig),
        ext::ConfigAxis::Unspecified => Err(ConvertError::Enum("config.axis")),
    }
}

fn reject_reason_to_pb(reason: RejectReason) -> ext::RejectReason {
    match reason {
        RejectReason::ProfileMismatch => ext::RejectReason::ProfileMismatch,
        RejectReason::SchemaInvalid => ext::RejectReason::SchemaInvalid,
        RejectReason::GenerationStale => ext::RejectReason::GenerationStale,
        RejectReason::Unsupported => ext::RejectReason::Unsupported,
    }
}

fn reject_reason_from_pb(reason: i32) -> Result<RejectReason, ConvertError> {
    match enum_value::<ext::RejectReason>("config.reject_reason", reason)? {
        ext::RejectReason::ProfileMismatch => Ok(RejectReason::ProfileMismatch),
        ext::RejectReason::SchemaInvalid => Ok(RejectReason::SchemaInvalid),
        ext::RejectReason::GenerationStale => Ok(RejectReason::GenerationStale),
        ext::RejectReason::Unsupported => Ok(RejectReason::Unsupported),
        ext::RejectReason::Unspecified => Err(ConvertError::Enum("config.reject_reason")),
    }
}

fn config_ack_to_pb(axis: ConfigAxis, version: u64, status: ApplyStatus) -> ext::ConfigAck {
    let (status, reject_reason) = match status {
        ApplyStatus::Applied => (ext::ApplyStatus::Applied, None),
        ApplyStatus::Rejected { reason } => (
            ext::ApplyStatus::Rejected,
            Some(reject_reason_to_pb(reason) as i32),
        ),
    };
    ext::ConfigAck {
        axis: config_axis_to_pb(axis) as i32,
        version,
        status: status as i32,
        reject_reason,
    }
}

fn config_ack_from_pb(
    ack: &ext::ConfigAck,
) -> Result<(ConfigAxis, u64, ApplyStatus), ConvertError> {
    let axis = config_axis_from_pb(ack.axis)?;
    let status = match enum_value::<ext::ApplyStatus>("config.apply_status", ack.status)? {
        ext::ApplyStatus::Applied => ApplyStatus::Applied,
        ext::ApplyStatus::Rejected => {
            let reason = reject_reason_from_pb(
                ack.reject_reason
                    .ok_or(ConvertError::Missing("config.reject_reason"))?,
            )?;
            ApplyStatus::Rejected { reason }
        }
        ext::ApplyStatus::Unspecified => Err(ConvertError::Enum("config.apply_status"))?,
    };
    Ok((axis, ack.version, status))
}

/// `ErrorInfo` → wire `ErrorInfo`. The kernel uses `kind`; the wire uses `code`.
pub fn error_info_to_pb(e: &ErrorInfo) -> ext::ErrorInfo {
    ext::ErrorInfo {
        code: e.kind.clone(),
        message: e.message.clone(),
        details: Default::default(),
    }
}

/// Wire `ErrorInfo` → `ErrorInfo`.
pub fn error_info_from_pb(e: &ext::ErrorInfo) -> Result<ErrorInfo, ConvertError> {
    Ok(ErrorInfo {
        kind: required_nonblank(&e.code, "error_info.code")?,
        message: e.message.clone(),
    })
}
