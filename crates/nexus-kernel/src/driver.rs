//! `Driver` — the implementation behind a Resource's interface methods,
//! plus the restricted [`DriverContext`] facade and the compiled
//! [`DriverPlan`] dispatch table.
//!
//! A Driver is the handler side of a restricted effect: it receives an input
//! and returns an [`Outcome`]. Sub-operations a driver issues run with the
//! *caller's* authority and re-pass policy independently, which prevents a
//! low-privilege Process from escalating through a high-privilege Driver.

use async_trait::async_trait;
use nexus_types::{
    DriverId, EndpointId, Failure, IdentityRef, InterfaceSet, Invoke, InvokeResult, MethodId,
    OperationId, Outcome, OutputMode, Path, ResourceId, TaintSet, TaintSource, Transport, Value,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Error a Driver may return. Distinct from [`nexus_types::Failure`]: a
/// `DriverError` is mapped to a `Failure`/`DecisionTag` by the data plane.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DriverError {
    /// Requested method is not present in this driver plan.
    #[error("method {0} not implemented by this driver")]
    NoSuchMethod(MethodId),
    /// Driver cannot produce the requested output mode.
    #[error("output mode {0:?} not supported")]
    UnsupportedOutput(OutputMode),
    /// Transport or endpoint failure while reaching the driver.
    #[error("transport error: {0}")]
    Transport(String),
    /// Driver-specific failure that does not fit a narrower category.
    #[error("driver error: {0}")]
    Other(String),
}

/// Restricted facade handed to a [`Driver::call`]. It does **not** grant
/// the driver any ambient authority: to cause further effects, a driver issues
/// sub-operations through `submit`, which run with the original caller's
/// identity and re-pass policy. Reads/writes of driver-local scratch go through
/// the provided helpers, never raw state access.
pub struct DriverContext {
    /// The identity the originating operation runs as (for sub-operations and
    /// audit). The driver cannot widen it.
    pub acting: nexus_types::IdentityRef,
    /// The calling Process (sub-operations inherit this caller).
    pub caller: nexus_types::ProcessId,
    /// The originating Operation id. Remote endpoint stubs use this to derive a
    /// replay-stable invocation id.
    pub operation_id: Option<OperationId>,
    /// Optional stream sink path for `OutputMode::Stream` results.
    pub stream_to: Option<nexus_types::Path>,
    /// The provenance of the operation's input. Drivers that persist
    /// data (memory) consult this to derive low-trust flags from lineage rather
    /// than trusting a caller-supplied flag.
    pub taint: nexus_types::TaintSet,
    /// The concrete target path of the operation. For prefix-resolved
    /// Resources like `state://**`, the driver needs the actual path it was
    /// invoked against (the registered Resource name is just the pattern).
    pub target_path: Option<nexus_types::Path>,
    /// Sink for streaming chunks; the driver pushes incremental values here.
    stream_tx: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    /// Provenance of the value produced by this driver call. State-like drivers
    /// set this from the same backend read that produced the returned Value, so
    /// the data plane never performs a second provenance read that could race.
    output_taint: Arc<Mutex<nexus_types::TaintSet>>,
}

impl DriverContext {
    /// Create a context for a call acting as `acting` on behalf of `caller`.
    pub fn new(acting: nexus_types::IdentityRef, caller: nexus_types::ProcessId) -> Self {
        Self {
            acting,
            caller,
            operation_id: None,
            stream_to: None,
            taint: nexus_types::TaintSet::pristine(),
            target_path: None,
            stream_tx: None,
            output_taint: Arc::new(Mutex::new(nexus_types::TaintSet::pristine())),
        }
    }

    /// Attach the originating Operation id. Drivers that do not need
    /// cross-process transport ignore it; remote endpoint stubs require it.
    pub fn with_operation_id(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

    /// Attach the operation's input taint.
    pub fn with_taint(mut self, taint: nexus_types::TaintSet) -> Self {
        self.taint = taint;
        self
    }

    /// Attach the concrete target path.
    pub fn with_target_path(mut self, path: nexus_types::Path) -> Self {
        self.target_path = Some(path);
        self
    }

    /// Attach a streaming sink for `OutputMode::Stream` results.
    pub fn with_stream(
        mut self,
        to: nexus_types::Path,
        tx: tokio::sync::mpsc::UnboundedSender<Value>,
    ) -> Self {
        self.stream_to = Some(to);
        self.stream_tx = Some(tx);
        self
    }

    /// Emit a streaming chunk (no-op if this op is not streaming). Returns
    /// `false` if the receiver has dropped (caller cancelled / disconnected).
    pub fn emit(&self, chunk: Value) -> bool {
        match &self.stream_tx {
            Some(tx) => tx.send(chunk).is_ok(),
            None => true,
        }
    }

    /// Record the provenance of the returned value. Ordinary drivers leave this
    /// pristine; state projections set it from the same read envelope as the
    /// output value.
    pub fn set_output_taint(&self, taint: nexus_types::TaintSet) {
        *self.output_taint.lock() = taint;
    }

    /// Return the output taint recorded by the driver.
    pub fn output_taint(&self) -> nexus_types::TaintSet {
        self.output_taint.lock().clone()
    }
}

/// The implementation behind interface methods. Local drivers run
/// in-process; remote drivers are reached through an endpoint (the
/// [`DriverPlan`] holds the dispatch detail).
#[async_trait]
pub trait Driver: Send + Sync + 'static {
    /// Invoke `method` with `input`, producing an [`Outcome`]. The driver does
    /// not receive a continuation: it returns once.
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError>;
}

/// Shared driver handle.
pub type DynDriver = Arc<dyn Driver>;

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
    ) -> Result<Outcome, DriverError> {
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
                ctx.set_output_taint(TaintSet::of(TaintSource::Inbound {
                    source: format!(
                        "provider/endpoint/{}/resource/{}/method/{}/binding/{}",
                        self.endpoint_id.get(),
                        self.resource_id.get(),
                        method.get(),
                        self.binding_generation
                    )
                    .into(),
                    channel: self.effect_path.to_string().into(),
                }));
                Ok(Outcome::Done(v))
            }
            Err(e) => Ok(Outcome::Fail(Failure::HandlerError {
                kind: e.kind,
                message: e.message,
            })),
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
    /// Method id this dispatch entry serves.
    pub method: MethodId,
    /// Driver implementation used for the method.
    pub driver: DynDriver,
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
    pub endpoint: Option<nexus_types::EndpointId>,
    /// method id → live driver. Local inline or a remote RPC stub driver.
    ///
    /// Handles, the open-plan cache, and the data plane all clone DriverPlan.
    /// Keep the frozen dispatch table shared so those clones stay O(1) Arc
    /// bumps per operation.
    table: Arc<HashMap<MethodId, DynDriver>>,
    /// Binding generation captured when the handle was opened.
    pub generation: u64,
}

impl DriverPlan {
    /// Create an empty dispatch plan for a driver and optional endpoint.
    pub fn new(
        driver_id: DriverId,
        endpoint: Option<nexus_types::EndpointId>,
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
    pub fn insert(&mut self, method: MethodId, driver: DynDriver) {
        Arc::make_mut(&mut self.table).insert(method, driver);
    }

    /// Dispatch `method`. The data plane has already checked rights and policy
    ///; the plan only resolves and calls.
    pub async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let driver = self
            .table
            .get(&method)
            .ok_or(DriverError::NoSuchMethod(method))?;
        driver.call(method, input, output, ctx).await
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
    ) -> Result<Outcome, DriverError> {
        Ok(Outcome::Done(input))
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
    ) -> Result<Outcome, DriverError> {
        (self.0)(method, input).map(Outcome::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{ErrorInfo, IdentityRef, NodeId, ProcessId};
    use parking_lot::Mutex;

    #[tokio::test]
    async fn driver_plan_dispatches_to_method() {
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(MethodId::new(0), Arc::new(EchoDriver));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = plan
            .call(MethodId::new(0), Value::Int(7), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Int(7)));
    }

    #[tokio::test]
    async fn missing_method_errors() {
        let plan = DriverPlan::new(DriverId::new(1), None, 0);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let err = plan
            .call(MethodId::new(9), Value::Null, OutputMode::Unary, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err, DriverError::NoSuchMethod(MethodId::new(9)));
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
    async fn remote_driver_sends_stable_invoke_frame() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let endpoint = Arc::new(RecordingEndpoint {
            seen: seen.clone(),
            result: Ok(Value::Str("remote-ok".into())),
        });
        let driver = RemoteDriver::new(
            EndpointId::new(7),
            nexus_types::ResourceId::new(11),
            3,
            Path::parse("effect://external-provider/acme/search").unwrap(),
            endpoint,
        );
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let stream = Path::parse("state://stream/1/9").unwrap();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(OperationId::new(ProcessId::new(1), NodeId::new(9), 0))
            .with_stream(stream.clone(), tx);
        let out = driver
            .call(MethodId::new(0), Value::Int(1), OutputMode::Stream, &ctx)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("remote-ok".into())));
        assert!(ctx.output_taint().sources().iter().any(|taint_source| {
            matches!(
                taint_source,
                TaintSource::Inbound {
                    source,
                    channel
                } if source.as_str() == "provider/endpoint/7/resource/11/method/0/binding/3"
                    && channel.as_str() == "effect://external-provider/acme/search"
            )
        }));

        let seen = seen.lock();
        assert_eq!(seen.len(), 1);
        let (dispatch, invoke) = &seen[0];
        assert_eq!(dispatch.endpoint_id, EndpointId::new(7));
        assert_eq!(dispatch.resource_id, nexus_types::ResourceId::new(11));
        assert_eq!(dispatch.method_id, MethodId::new(0));
        assert_eq!(dispatch.binding_generation, 3);
        assert_eq!(dispatch.acting, IdentityRef::ROOT);
        assert_eq!(invoke.invocation_id, "1/9/0");
        assert_eq!(
            invoke.effect_path.to_string(),
            "effect://external-provider/acme/search"
        );
        assert_eq!(invoke.method_id, MethodId::new(0));
        assert_eq!(invoke.output_stream_to, Some(stream));
    }
}
