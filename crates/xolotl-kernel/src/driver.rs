//! `Driver` — the implementation behind a Resource's interface methods,
//! plus the restricted [`DriverContext`] facade and the compiled
//! [`DriverPlan`] dispatch table.
//!
//! A Driver handles one dispatched method and returns its value, provenance,
//! and optional usage measurements together. Operation admission, policy,
//! accounting, and Fact recording belong to the kernel execution path.

use crate::host::stream::DynStreamSink;
pub use crate::stream::StreamSendError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::TaintedValue;
use xolotl_types::{
    DriverId, EndpointId, Failure, IdentityRef, InterfaceSet, Invoke, InvokeResult, MethodContract,
    MethodId, OperationId, Outcome, OutputMode, Path, ResourceId, TaintSet, TaintSource, Transport,
    Value,
};
pub use xolotl_types::{DriverOutput, DriverUsage, UsageDimension};

/// Error a Driver may return. Distinct from [`xolotl_types::Failure`]: a
/// `DriverError` is mapped to a `Failure`/`DecisionTag` by the data plane.
/// Text diagnostics inherit input provenance and must not expose data read
/// from additional sources. Return a [`DriverOutput`] with `Outcome::Fail`
/// and explicit taint for those failures. Stream errors already retain the
/// rejected value's provenance.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DriverError {
    /// Requested method is not present in this driver plan.
    #[error("method {0} not implemented by this driver")]
    NoSuchMethod(MethodId),
    /// Driver cannot produce the requested output mode.
    #[error("output mode {0:?} not supported")]
    UnsupportedOutput(OutputMode),
    /// Caller supplied malformed input for the requested method.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Transport or endpoint failure while reaching the driver.
    #[error("transport error: {0}")]
    Transport(String),
    /// A stream rejected a chunk, retaining ownership for an explicit retry.
    #[error("stream sink rejected an output chunk")]
    Stream(StreamSendError<TaintedValue>),
    /// Driver-specific failure that does not fit a narrower category.
    #[error("driver error: {0}")]
    Other(String),
}

impl From<StreamSendError<TaintedValue>> for DriverError {
    fn from(error: StreamSendError<TaintedValue>) -> Self {
        Self::Stream(error)
    }
}

/// Context for one [`Driver::call`]: originating caller metadata, input
/// provenance, the resolved target, and an optional output stream sink.
/// Further operations require admission through the kernel execution path.
pub struct DriverContext {
    /// The identity the originating operation runs as (for sub-operations and
    /// audit). The driver cannot widen it.
    pub acting: xolotl_types::IdentityRef,
    /// The calling Process (sub-operations inherit this caller).
    pub caller: xolotl_types::ProcessId,
    /// The originating Operation id. Remote endpoint stubs use this to derive a
    /// replay-stable invocation id.
    pub operation_id: Option<OperationId>,
    /// Optional stream sink path for `OutputMode::Stream` results.
    pub stream_to: Option<xolotl_types::Path>,
    /// The provenance of the operation's input. Drivers that persist
    /// data (memory) consult this to derive low-trust flags from lineage rather
    /// than trusting a caller-supplied flag.
    pub taint: xolotl_types::TaintSet,
    /// The concrete target path of the operation. For prefix-resolved
    /// Resources like `state://**`, the driver needs the actual path it was
    /// invoked against (the registered Resource name is just the pattern).
    pub target_path: Option<xolotl_types::Path>,
    /// Sink for streaming chunks; the driver pushes incremental values here.
    stream_sink: Option<DynStreamSink>,
}

impl DriverContext {
    /// Create a context for a call acting as `acting` on behalf of `caller`.
    pub fn new(acting: xolotl_types::IdentityRef, caller: xolotl_types::ProcessId) -> Self {
        Self {
            acting,
            caller,
            operation_id: None,
            stream_to: None,
            taint: xolotl_types::TaintSet::pristine(),
            target_path: None,
            stream_sink: None,
        }
    }

    /// Attach the originating Operation id. Drivers that do not need
    /// cross-process transport ignore it; remote endpoint stubs require it.
    pub fn with_operation_id(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

    /// Attach the operation's input taint.
    pub fn with_taint(mut self, taint: xolotl_types::TaintSet) -> Self {
        self.taint = taint;
        self
    }

    /// Attach the concrete target path.
    pub fn with_target_path(mut self, path: xolotl_types::Path) -> Self {
        self.target_path = Some(path);
        self
    }

    /// Attach an output edge without a transport routing path.
    pub fn with_stream_sink(mut self, sink: DynStreamSink) -> Self {
        self.stream_sink = Some(sink);
        self
    }

    /// Whether this call has an explicit output edge.
    pub fn has_stream_sink(&self) -> bool {
        self.stream_sink.is_some()
    }

    /// Attach a streaming sink and a logical transport routing path.
    pub fn with_stream(mut self, to: xolotl_types::Path, sink: DynStreamSink) -> Self {
        self.stream_to = Some(to);
        self.stream_sink = Some(sink);
        self
    }

    /// Wait for capacity and emit a chunk. A closed or missing sink returns
    /// the original value; cancellation drops the pending send with its call.
    pub async fn emit(&self, chunk: Value) -> Result<(), StreamSendError<TaintedValue>> {
        self.emit_tainted(TaintedValue::pristine(chunk)).await
    }

    /// Emit a value with its source provenance, retaining the originating
    /// operation's input provenance as well.
    pub async fn emit_tainted(
        &self,
        mut chunk: TaintedValue,
    ) -> Result<(), StreamSendError<TaintedValue>> {
        chunk.taint.union(&self.taint);
        let Some(sink) = &self.stream_sink else {
            return Err(StreamSendError::Closed(chunk));
        };
        crate::stream::send(sink.as_ref(), chunk).await
    }

    /// Attempt one send without waiting, retaining rejected values for retry.
    pub fn try_emit(&self, chunk: Value) -> Result<(), StreamSendError<TaintedValue>> {
        self.try_emit_tainted(TaintedValue::pristine(chunk))
    }

    /// Attempt one tainted send without waiting, retaining the full envelope
    /// when the sink is full or closed.
    pub fn try_emit_tainted(
        &self,
        mut chunk: TaintedValue,
    ) -> Result<(), StreamSendError<TaintedValue>> {
        chunk.taint.union(&self.taint);
        let Some(sink) = &self.stream_sink else {
            return Err(StreamSendError::Closed(chunk));
        };
        crate::stream::try_send(sink.as_ref(), chunk)
    }
}

/// The implementation behind interface methods. Local drivers run
/// in-process; remote drivers are reached through an endpoint (the
/// [`DriverPlan`] holds the dispatch detail).
#[async_trait]
pub trait Driver: Send + Sync + 'static {
    /// Select a pure input guard when a method is compiled into a dispatch plan.
    /// The frozen guard runs outside registry locks and before policy or records.
    /// Drivers without a guard add no per-invocation allocation or virtual call.
    fn input_admission(&self, _method: MethodId) -> Option<InputAdmission> {
        None
    }

    /// Invoke `method` with `input`, producing a [`DriverOutput`]. The driver does
    /// not receive a continuation: it returns once.
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError>;
}

/// Shared driver handle.
pub type DynDriver = Arc<dyn Driver>;

/// An input rejected before dispatch, with an explicitly safe audit projection.
#[derive(Debug)]
pub struct InputRejection {
    /// Failure delivered to the caller.
    pub failure: Failure,
    /// Input projection retained in the denied operation's Fact.
    pub recorded_input: Value,
}

/// Pure, method-specific input admission. Only rejection allocates its envelope.
pub type InputAdmission = fn(&Value) -> Result<(), Box<InputRejection>>;

/// Transport edge for a remote endpoint. Concrete gRPC,
/// WebSocket, stdio, or test transports implement this; `DriverPlan` compiles
/// endpoint bindings to a [`RemoteDriver`] that calls this interface.
#[async_trait]
pub trait RemoteEndpoint: Send + Sync + 'static {
    /// Send an invoke request to a remote provider endpoint.
    async fn invoke(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: Invoke,
    ) -> Result<InvokeResult, DriverError>;
}

/// Shared remote endpoint handle.
pub type DynRemoteEndpoint = Arc<dyn RemoteEndpoint>;

/// Internal dispatch identity captured by `open()` for a remote endpoint call.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RemoteInvokeDispatch {
    /// Remote endpoint transport selected by the binding.
    pub endpoint_id: EndpointId,
    /// Resource selected by `open()`.
    pub resource_id: ResourceId,
    /// Method being invoked.
    pub method_id: MethodId,
    /// Binding generation captured by the opened handle.
    pub binding_generation: u64,
    /// Acting identity captured from the originating operation.
    pub acting: IdentityRef,
}

/// RPC stub compiled into a [`DriverPlan`] for `Binding.endpoint = Some(_)`.
/// It turns a local data-plane call into a provider `Invoke` frame while keeping
/// the same authorization, policy, budget, taint, and Fact path around it.
pub struct RemoteDriver {
    endpoint_id: EndpointId,
    resource_id: ResourceId,
    binding_generation: u64,
    effect_path: Path,
    endpoint: DynRemoteEndpoint,
}

impl RemoteDriver {
    /// Create a remote driver stub for one endpoint and effect path.
    pub fn new(
        endpoint_id: EndpointId,
        resource_id: ResourceId,
        binding_generation: u64,
        effect_path: Path,
        endpoint: DynRemoteEndpoint,
    ) -> Self {
        Self {
            endpoint_id,
            resource_id,
            binding_generation,
            effect_path,
            endpoint,
        }
    }
}

#[async_trait]
impl Driver for RemoteDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let Some(op_id) = ctx.operation_id else {
            return Err(DriverError::Transport(format!(
                "endpoint {} invoke missing OperationId",
                self.endpoint_id.get()
            )));
        };
        let invoke = Invoke {
            invocation_id: op_id.to_string(),
            effect_path: self.effect_path.clone(),
            method_id: method,
            input,
            deadline_ms: None,
            output_stream_to: matches!(output, OutputMode::Stream)
                .then(|| ctx.stream_to.clone())
                .flatten(),
        };
        let dispatch = RemoteInvokeDispatch {
            endpoint_id: self.endpoint_id,
            resource_id: self.resource_id,
            method_id: method,
            binding_generation: self.binding_generation,
            acting: ctx.acting,
        };
        let result = self.endpoint.invoke(dispatch, invoke).await?;
        match result.outcome {
            Ok(v) => {
                let taint = TaintSet::of(TaintSource::Inbound {
                    source: format!(
                        "provider/endpoint/{}/resource/{}/method/{}/binding/{}",
                        self.endpoint_id.get(),
                        self.resource_id.get(),
                        method.get(),
                        self.binding_generation
                    )
                    .into(),
                    channel: self.effect_path.to_string().into(),
                });
                Ok(DriverOutput::new(Outcome::Done(v)).with_taint(taint))
            }
            Err(e) => Ok(DriverOutput::new(Outcome::Fail(Failure::HandlerError {
                kind: e.kind,
                message: e.message,
            }))),
        }
    }
}

/// Descriptor of a driver implementation.
#[derive(Clone)]
pub struct DriverDescriptor {
    /// Stable driver id assigned by the registry.
    pub id: DriverId,
    /// Human-readable driver name for registry and console views.
    pub name: String,
    /// Interfaces this driver implements.
    pub implements: InterfaceSet,
    /// Local or remote transport shape used by this driver.
    pub transport: Transport,
    /// The live implementation.
    pub driver: DynDriver,
}

/// Per-method dispatch entry within a [`DriverPlan`].
#[derive(Clone)]
pub struct DispatchEntry {
    /// Immutable authorization, replay and accounting rules selected at open.
    pub contract: MethodContract,
    /// Driver implementation used for the method.
    pub driver: DynDriver,
    /// Optional input admission selected once when this method was opened.
    pub input_admission: Option<InputAdmission>,
}

/// A compiled dispatch table for one opened Resource. Produced at
/// `open()` and frozen into the Handle; the data plane calls through it with no
/// further resolution. `generation` matches the Binding link epoch.
#[derive(Clone)]
pub struct DriverPlan {
    /// Driver descriptor selected by open.
    pub driver_id: DriverId,
    /// Remote endpoint selected by the binding, if this plan dispatches over a
    /// transport boundary.
    pub endpoint: Option<xolotl_types::EndpointId>,
    /// method id → live driver. Local inline or a remote RPC stub driver.
    ///
    /// Handles, the open-plan cache, and the data plane all clone DriverPlan.
    /// Keep the frozen dispatch table shared so those clones stay O(1) Arc
    /// bumps per operation.
    table: Arc<HashMap<MethodId, DispatchEntry>>,
    /// Binding generation captured when the handle was opened.
    pub generation: u64,
}

impl DriverPlan {
    /// Create an empty dispatch plan for a driver and optional endpoint.
    pub fn new(
        driver_id: DriverId,
        endpoint: Option<xolotl_types::EndpointId>,
        generation: u64,
    ) -> Self {
        Self {
            driver_id,
            endpoint,
            table: Arc::new(HashMap::new()),
            generation,
        }
    }

    /// Add or replace a per-method driver entry.
    pub fn insert(&mut self, method: MethodId, contract: MethodContract, driver: DynDriver) {
        let input_admission = driver.input_admission(method);
        Arc::make_mut(&mut self.table).insert(
            method,
            DispatchEntry {
                contract,
                driver,
                input_admission,
            },
        );
    }

    pub(crate) fn entry(&self, method: MethodId) -> Option<&DispatchEntry> {
        self.table.get(&method)
    }

    /// Read the execution contract frozen into this plan for the selected method.
    pub fn contract(&self, method: MethodId) -> Option<MethodContract> {
        self.table.get(&method).map(|entry| entry.contract)
    }

    /// Dispatch `method`. The data plane has already checked rights and policy
    ///; the plan only resolves and calls.
    pub async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let entry = self
            .table
            .get(&method)
            .ok_or(DriverError::NoSuchMethod(method))?;
        entry.driver.call(method, input, output, ctx).await
    }

    /// Whether this plan contains a dispatch entry for `method`.
    pub fn supports(&self, method: MethodId) -> bool {
        self.table.contains_key(&method)
    }

    /// Whether this plan calls a remote endpoint.
    pub fn is_remote(&self) -> bool {
        self.endpoint.is_some()
    }
}

/// A trivial driver that echoes its input — used in bootstrap/tests.
pub struct EchoDriver;

#[async_trait]
impl Driver for EchoDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        Ok(DriverOutput::new(Outcome::Done(input)))
    }
}

/// A driver that applies a synchronous closure. Convenient for in-process
/// effects whose logic is pure or self-contained.
pub struct FnDriver<F>(pub F);

#[async_trait]
impl<F> Driver for FnDriver<F>
where
    F: Fn(MethodId, Value) -> Result<Value, DriverError> + Send + Sync + 'static,
{
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        (self.0)(method, input).map(|value| DriverOutput::new(Outcome::Done(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::stream::{StreamItem, channel};
    use crate::stream::StreamWindow;
    use anyhow::{Context, bail, ensure};
    use parking_lot::Mutex;
    use xolotl_types::{ErrorInfo, ExecutionId, IdentityRef, InvocationId, NodeId, ProcessId};

    #[tokio::test]
    async fn driver_plan_dispatches_to_method() -> anyhow::Result<()> {
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(0),
            MethodContract::new(
                0,
                xolotl_types::ReplayClass::Deterministic,
                xolotl_types::OutputModeSet::UNARY,
            ),
            Arc::new(EchoDriver),
        );
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = plan
            .call(MethodId::new(0), Value::integer(7), OutputMode::Unary, &ctx)
            .await
            .context("driver call failed")?;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(7)),
            "unexpected driver output: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_method_errors() -> anyhow::Result<()> {
        let plan = DriverPlan::new(DriverId::new(1), None, 0);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let err = match plan
            .call(MethodId::new(9), Value::null(), OutputMode::Unary, &ctx)
            .await
        {
            Ok(out) => bail!("expected missing method error, got {out:?}"),
            Err(err) => err,
        };
        ensure!(
            err == DriverError::NoSuchMethod(MethodId::new(9)),
            "unexpected driver error: {err:?}"
        );
        Ok(())
    }

    struct RecordingEndpoint {
        seen: Arc<Mutex<Vec<(RemoteInvokeDispatch, Invoke)>>>,
        result: Result<Value, ErrorInfo>,
    }

    #[async_trait]
    impl RemoteEndpoint for RecordingEndpoint {
        async fn invoke(
            &self,
            dispatch: RemoteInvokeDispatch,
            invoke: Invoke,
        ) -> Result<InvokeResult, DriverError> {
            self.seen.lock().push((dispatch, invoke.clone()));
            Ok(InvokeResult {
                invocation_id: invoke.invocation_id,
                outcome: self.result.clone(),
            })
        }
    }

    #[tokio::test]
    async fn remote_driver_sends_stable_invoke_frame() -> anyhow::Result<()> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let endpoint = Arc::new(RecordingEndpoint {
            seen: seen.clone(),
            result: Ok(Value::string("remote-ok".into())),
        });
        let driver = RemoteDriver::new(
            EndpointId::new(7),
            xolotl_types::ResourceId::new(11),
            3,
            Path::parse("effect://external-provider/acme/search")
                .context("effect path did not parse")?,
            endpoint,
        );
        let (tx, _rx) = channel(StreamWindow::default());
        let stream = Path::parse("state://stream/1/9").context("stream path did not parse")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(OperationId::new(
                ProcessId::new(1),
                ExecutionId::FIRST,
                InvocationId::new(10),
                NodeId::new(9),
                0,
            ))
            .with_stream(stream.clone(), tx);
        let out = driver
            .call(
                MethodId::new(0),
                Value::integer(1),
                OutputMode::Stream,
                &ctx,
            )
            .await
            .context("remote driver call failed")?;
        ensure!(
            out.outcome == Outcome::Done(Value::string("remote-ok".into())),
            "unexpected remote driver output: {out:?}"
        );
        ensure!(
            out.taint.sources().iter().any(|taint_source| {
                matches!(
                    taint_source,
                    TaintSource::Inbound {
                        source,
                        channel
                    } if source.as_str() == "provider/endpoint/7/resource/11/method/0/binding/3"
                        && channel.as_str() == "effect://external-provider/acme/search"
                )
            }),
            "remote driver did not tag inbound taint"
        );

        let seen = seen.lock();
        ensure!(
            seen.len() == 1,
            "unexpected remote invoke count: {}",
            seen.len()
        );
        let (dispatch, invoke) = seen.first().context("missing remote invoke")?;
        ensure!(
            dispatch.endpoint_id == EndpointId::new(7),
            "endpoint id mismatch"
        );
        ensure!(
            dispatch.resource_id == xolotl_types::ResourceId::new(11),
            "resource id mismatch"
        );
        ensure!(dispatch.method_id == MethodId::new(0), "method id mismatch");
        ensure!(
            dispatch.binding_generation == 3,
            "binding generation mismatch"
        );
        ensure!(
            dispatch.acting == IdentityRef::ROOT,
            "acting identity mismatch"
        );
        ensure!(
            invoke.invocation_id == "1/1/10/9/0",
            "invocation id mismatch"
        );
        ensure!(
            invoke.effect_path.to_string() == "effect://external-provider/acme/search",
            "effect path mismatch"
        );
        ensure!(
            invoke.method_id == MethodId::new(0),
            "invoke method id mismatch"
        );
        ensure!(
            invoke.output_stream_to == Some(stream),
            "invoke stream target mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn emit_waits_for_capacity_and_try_emit_retains_rejected_value() -> anyhow::Result<()> {
        let (tx, mut rx) = channel(StreamWindow {
            max_chunks: core::num::NonZeroUsize::MIN,
            ..StreamWindow::default()
        });
        let stream = Path::parse("state://stream/1/10").context("stream path did not parse")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream(stream, tx);
        ctx.emit(Value::integer(1))
            .await
            .map_err(DriverError::from)?;
        ensure!(
            ctx.try_emit(Value::integer(2))
                == Err(StreamSendError::Full(TaintedValue::pristine(
                    Value::integer(2)
                )))
        );
        let pending = ctx.emit(Value::integer(2));
        tokio::pin!(pending);
        let first_poll = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(pending.as_mut(), cx))
        })
        .await;
        ensure!(first_poll.is_pending());
        let Some(StreamItem::Chunk(first)) = rx.recv().await else {
            bail!("first emitted chunk was not preserved");
        };
        ensure!(first.into_value() == TaintedValue::pristine(Value::integer(1)));
        pending.await.map_err(DriverError::from)?;
        let Some(StreamItem::Chunk(second)) = rx.recv().await else {
            bail!("second emitted chunk was not preserved");
        };
        ensure!(second.into_value() == TaintedValue::pristine(Value::integer(2)));
        drop(rx);
        ensure!(
            ctx.emit(Value::integer(3)).await
                == Err(StreamSendError::Closed(TaintedValue::pristine(
                    Value::integer(3)
                )))
        );
        ensure!(
            ctx.try_emit(Value::integer(4))
                == Err(StreamSendError::Closed(TaintedValue::pristine(
                    Value::integer(4)
                )))
        );
        Ok(())
    }

    #[tokio::test]
    async fn emit_without_a_stream_returns_the_value() -> anyhow::Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        ensure!(
            ctx.emit(Value::integer(1)).await
                == Err(StreamSendError::Closed(TaintedValue::pristine(
                    Value::integer(1)
                )))
        );
        ensure!(
            ctx.try_emit(Value::integer(2))
                == Err(StreamSendError::Closed(TaintedValue::pristine(
                    Value::integer(2)
                )))
        );
        Ok(())
    }
}
