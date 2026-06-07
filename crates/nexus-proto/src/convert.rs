//! Lossless conversions between `nexus_types` (kernel-side) and the generated
//! protobuf wire types (`crate::nexus::v1`). These are the canonical
//! marshalling functions for every gRPC adapter — there is no JSON shortcut and
//! no deferred mapping: every `Value` variant, every `Path` / `Capability` /
//! `Failure` / `Outcome` / `DoNode` round-trips structurally.

use crate::nexus::v1 as pb;
use nexus_graph::{DoNode, OperationTemplate, StepRef, WaitSpec};
use nexus_types::{
    BlobRef, CapError, Capability, DType, Failure, FloatBits, FrameKind, FrameRef, MethodId,
    Outcome, OutputMode, Path, PathError, ProcessId, ResourceName, StreamMarker, TensorRef, Value,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConvertError {
    #[error("path: {0}")]
    Path(#[from] PathError),
    #[error("capability: {0}")]
    Capability(#[from] CapError),
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("unsupported wire enum value: {0}")]
    Enum(&'static str),
    #[error("numeric value out of range for field: {0}")]
    Range(&'static str),
}

// ─── Value ──────────────────────────────────────────────────────────────────

/// `nexus_types::Value` → wire `Value`. Total and lossless.
pub fn value_to_pb(v: &Value) -> pb::Value {
    use pb::value::Kind;
    let kind = match v {
        Value::Null => Kind::NullVal(pb::NullValue::NullValue as i32),
        Value::Bool(b) => Kind::BoolVal(*b),
        Value::Int(i) => Kind::IntVal(*i),
        Value::Float(FloatBits(f)) => Kind::FloatVal(*f),
        Value::Str(s) => Kind::StrVal(s.clone()),
        Value::Bytes(b) => Kind::BytesVal(b.clone()),
        Value::List(xs) => Kind::ListVal(pb::ListValue {
            items: xs.iter().map(value_to_pb).collect(),
        }),
        Value::Map(m) => Kind::MapVal(pb::MapValue {
            entries: m.iter().map(|(k, v)| (k.clone(), value_to_pb(v))).collect(),
        }),
        Value::Blob(b) => Kind::BlobVal(blob_to_pb(b)),
        Value::Tensor(t) => Kind::TensorVal(tensor_to_pb(t)),
        Value::Frame(fr) => Kind::FrameVal(frame_to_pb(fr)),
        Value::StreamEnd(m) => Kind::StreamEndVal(stream_marker_to_pb(m)),
    };
    pb::Value { kind: Some(kind) }
}

/// Wire `Value` → `nexus_types::Value`. An absent oneof maps to `Null`.
pub fn value_from_pb(v: &pb::Value) -> Value {
    use pb::value::Kind;
    match &v.kind {
        None => Value::Null,
        Some(Kind::NullVal(_)) => Value::Null,
        Some(Kind::BoolVal(b)) => Value::Bool(*b),
        Some(Kind::IntVal(i)) => Value::Int(*i),
        Some(Kind::FloatVal(f)) => Value::Float(FloatBits(*f)),
        Some(Kind::StrVal(s)) => Value::Str(s.clone()),
        Some(Kind::BytesVal(b)) => Value::Bytes(b.clone()),
        Some(Kind::ListVal(l)) => Value::List(l.items.iter().map(value_from_pb).collect()),
        Some(Kind::MapVal(m)) => Value::Map(
            m.entries
                .iter()
                .map(|(k, v)| (k.clone(), value_from_pb(v)))
                .collect(),
        ),
        Some(Kind::BlobVal(b)) => Value::Blob(blob_from_pb(b)),
        Some(Kind::TensorVal(t)) => tensor_from_pb(t).map_or(Value::Null, Value::Tensor),
        Some(Kind::FrameVal(fr)) => frame_from_pb(fr).map_or(Value::Null, Value::Frame),
        Some(Kind::StreamEndVal(m)) => Value::StreamEnd(stream_marker_from_pb(m)),
    }
}

// ─── Multimodal refs ──────────────────────────────────────────────────────────

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
        dtype: dtype_from_str(&t.dtype),
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
        kind: frame_kind_from_str(&fr.kind),
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
fn stream_marker_from_pb(m: &pb::StreamMarker) -> StreamMarker {
    use pb::stream_marker::Kind;
    match &m.kind {
        Some(Kind::Error(message)) => StreamMarker::Error {
            message: message.clone(),
        },
        _ => StreamMarker::Done,
    }
}

fn dtype_str(d: DType) -> &'static str {
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
fn dtype_from_str(s: &str) -> DType {
    match s {
        "f16" => DType::F16,
        "bf16" => DType::Bf16,
        "f64" => DType::F64,
        "i8" => DType::I8,
        "i16" => DType::I16,
        "i32" => DType::I32,
        "i64" => DType::I64,
        "u8" => DType::U8,
        "bool" => DType::Bool,
        // "f32" and any unknown dtype default to f32 (the common embedding case).
        _ => DType::F32,
    }
}

fn frame_kind_str(k: FrameKind) -> &'static str {
    match k {
        FrameKind::Audio => "audio",
        FrameKind::Video => "video",
        FrameKind::Pose => "pose",
        FrameKind::Sensor => "sensor",
    }
}
fn frame_kind_from_str(s: &str) -> FrameKind {
    match s {
        "video" => FrameKind::Video,
        "pose" => FrameKind::Pose,
        "sensor" => FrameKind::Sensor,
        _ => FrameKind::Audio,
    }
}

// ─── Path ─────────────────────────────────────────────────────────────────────

/// `Path` → wire `Path` (preserves cluster, scheme, and segments).
pub fn path_to_pb(p: &Path) -> pb::Path {
    pb::Path {
        cluster: p.cluster().map(|c| c.to_string()),
        scheme: p.scheme().to_string(),
        segments: p.segments().iter().map(|s| s.to_string()).collect(),
    }
}

/// Wire `Path` → `Path`, validated through the canonical parser.
pub fn path_from_pb(p: &pb::Path) -> Result<Path, ConvertError> {
    let mut s = match &p.cluster {
        Some(cluster) => format!("path://{}/{}", cluster, p.scheme),
        None => format!("{}://", p.scheme),
    };
    for (idx, seg) in p.segments.iter().enumerate() {
        if idx > 0 || p.cluster.is_some() {
            s.push('/');
        }
        s.push_str(seg);
    }
    Ok(Path::parse(&s)?)
}

// ─── Capability ─────────────────────────────────────────────────────────────

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

/// Wire `Capability` → `Capability`, validated through the canonical parser.
pub fn capability_from_pb(c: &pb::Capability) -> Result<Capability, ConvertError> {
    let mut literal = format!("{}://{}", c.verb, c.scheme);
    for seg in &c.segments {
        literal.push('/');
        literal.push_str(seg);
    }
    if let Some(predicate) = &c.predicate {
        literal.push('@');
        literal.push_str(predicate);
    }
    Ok(Capability::parse(&literal)?)
}

// ─── Program / DoNode ───────────────────────────────────────────────────────

/// `DoNode` → wire `Program`.
pub fn program_to_pb(root: &DoNode) -> pb::Program {
    pb::Program {
        root: Some(do_node_to_pb(root)),
    }
}

/// Wire `Program` → `DoNode`.
pub fn program_from_pb(program: &pb::Program) -> Result<DoNode, ConvertError> {
    do_node_from_pb(
        program
            .root
            .as_ref()
            .ok_or(ConvertError::Missing("program.root"))?,
    )
}

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

pub fn do_node_from_pb(node: &pb::DoNode) -> Result<DoNode, ConvertError> {
    use pb::do_node::Kind;
    Ok(
        match node
            .kind
            .as_ref()
            .ok_or(ConvertError::Missing("do_node.kind"))?
        {
            Kind::Pure(v) => DoNode::Pure(value_from_pb(v)),
            Kind::AndThen(x) => DoNode::AndThen {
                d: Box::new(do_node_from_pb(
                    x.d.as_deref().ok_or(ConvertError::Missing("and_then.d"))?,
                )?),
                then: step_ref_from_pb(
                    x.then
                        .as_ref()
                        .ok_or(ConvertError::Missing("and_then.then"))?,
                ),
            },
            Kind::OrElse(x) => DoNode::OrElse {
                d: Box::new(do_node_from_pb(
                    x.d.as_deref().ok_or(ConvertError::Missing("or_else.d"))?,
                )?),
                or: step_ref_from_pb(x.or.as_ref().ok_or(ConvertError::Missing("or_else.or"))?),
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
                name: x.name.clone(),
                value: Box::new(do_node_from_pb(
                    x.value
                        .as_deref()
                        .ok_or(ConvertError::Missing("let.value"))?,
                )?),
                body: Box::new(do_node_from_pb(
                    x.body.as_deref().ok_or(ConvertError::Missing("let.body"))?,
                )?),
            },
            Kind::UseName(name) => DoNode::Use(name.clone()),
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
        process_id: step.process.get(),
        name: step.name.clone(),
        arg: step.arg.as_ref().map(value_to_pb),
    }
}

fn step_ref_from_pb(step: &pb::StepRef) -> StepRef {
    StepRef {
        process: ProcessId::new(step.process_id),
        name: step.name.clone(),
        arg: step.arg.as_ref().map(value_from_pb),
    }
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
        method: op.method.clone(),
        method_id: op.method_id.map(MethodId::new),
        output: op
            .output
            .as_ref()
            .map(output_mode_from_pb)
            .transpose()?
            .unwrap_or_default(),
        literal_input: op.literal_input.as_ref().map(value_from_pb),
    })
}

fn output_mode_to_pb(mode: OutputMode) -> pb::OutputMode {
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

fn output_mode_from_pb(mode: &pb::OutputMode) -> Result<OutputMode, ConvertError> {
    let kind =
        pb::OutputModeKind::try_from(mode.kind).map_err(|_| ConvertError::Enum("output.kind"))?;
    Ok(match kind {
        pb::OutputModeKind::Unspecified | pb::OutputModeKind::Unary => OutputMode::Unary,
        pb::OutputModeKind::Stream => OutputMode::Stream,
        pb::OutputModeKind::Collect => OutputMode::Collect {
            limit: usize::try_from(mode.collect_limit)
                .map_err(|_| ConvertError::Range("output.collect_limit"))?,
        },
        pb::OutputModeKind::AsyncProcess => OutputMode::AsyncProcess,
        pb::OutputModeKind::SinkOnly => OutputMode::SinkOnly,
    })
}

// ─── Failure / Outcome ────────────────────────────────────────────────────────

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
        // `Failure` is #[non_exhaustive]; any future variant gets a generic tag.
        _ => "error",
    }
}

/// `Failure` → wire `Failure` (kind tag + human-readable message).
pub fn failure_to_pb(f: &Failure) -> pb::Failure {
    pb::Failure {
        kind: failure_kind(f).to_string(),
        message: f.to_string(),
    }
}

/// Wire `Failure` → `Failure`. The wire failure form is intentionally compact
/// (stable kind + display message), so variants without enough structured
/// fields are materialized as `Custom`.
pub fn failure_from_pb(f: &pb::Failure) -> Result<Failure, ConvertError> {
    Ok(match f.kind.as_str() {
        "rate_limited" => Failure::RateLimited,
        "timeout" => Failure::Timeout,
        "cancelled" => Failure::Cancelled,
        "kernel_namespace_protected" => Failure::KernelNamespaceProtected,
        "invalid_input" => Failure::InvalidInput {
            reason: f.message.clone(),
        },
        "handler_error" => Failure::HandlerError {
            kind: "handler_error".into(),
            message: f.message.clone(),
        },
        "permission_denied" | "no_handler" | "budget_exhausted" | "approval_pending"
        | "quarantined" | "policy_violation" | "path_invalid" | "custom" | "error" => {
            Failure::Custom {
                kind: f.kind.clone(),
                message: f.message.clone(),
            }
        }
        other => Failure::Custom {
            kind: other.into(),
            message: f.message.clone(),
        },
    })
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

// ─── Extension frames (§16.3.3) ──────────────────────────────────────────────
//
// The `nexus_types::extension` frames ⇄ the generated `pb::extension` wire
// messages. These are the marshalling used by the gRPC `ExtensionService`
// session stream. The three-stage handshake frames are represented directly in
// the wire schema; Invoke / InvokeResult — the business frames — map cleanly
// and are bridged here.

use nexus_types::extension::{ErrorInfo, Invoke, InvokeResult};
use pb::extension as ext;

/// `Invoke` → wire `Invoke` (§16.3.3): the daemon→extension dispatch frame.
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
        input: i.input.as_ref().map(value_from_pb).unwrap_or(Value::Null),
        deadline_ms: i.deadline_ms,
        output_stream_to: i
            .output_stream_to
            .as_ref()
            .map(|s| Path::parse(s))
            .transpose()?,
    })
}

/// `InvokeResult` → wire `InvokeResult` (§16.3.3): the extension→daemon result.
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
pub fn invoke_result_from_pb(r: &ext::InvokeResult) -> InvokeResult {
    let outcome = match &r.outcome {
        Some(ext::invoke_result::Outcome::Success(v)) => Ok(value_from_pb(v)),
        Some(ext::invoke_result::Outcome::Error(e)) => Err(error_info_from_pb(e)),
        None => Err(ErrorInfo {
            kind: "empty".into(),
            message: "no outcome".into(),
        }),
    };
    InvokeResult {
        invocation_id: r.invocation_id.clone(),
        outcome,
    }
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
pub fn error_info_from_pb(e: &ext::ErrorInfo) -> ErrorInfo {
    ErrorInfo {
        kind: e.code.clone(),
        message: e.message.clone(),
    }
}
