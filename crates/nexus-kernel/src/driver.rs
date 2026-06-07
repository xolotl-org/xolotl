//! `Driver` — the implementation behind a Resource's interface methods (§7.2),
//! plus the restricted [`DriverContext`] facade and the compiled
//! [`DriverPlan`] dispatch table.
//!
//! A Driver is the handler side of a restricted effect (§1.1): it receives an
//! input and returns an [`Outcome`], it does **not** receive a continuation and
//! cannot resume. Sub-operations a driver issues run with the *caller's*
//! authority and re-pass policy independently (§7.3) — a low-privilege Process
//! calling a high-privilege Driver cannot escalate.

use async_trait::async_trait;
use nexus_types::{
    DriverId, EndpointId, Failure, InterfaceSet, Invoke, InvokeResult, MethodId, OperationId,
    Outcome, OutputMode, Path, Transport, Value,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Error a Driver may return. Distinct from [`nexus_types::Failure`]: a
/// `DriverError` is mapped to a `Failure`/`DecisionTag` by the data plane.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DriverError {
    #[error("method {0} not implemented by this driver")]
    NoSuchMethod(MethodId),
    #[error("output mode {0:?} not supported")]
    UnsupportedOutput(OutputMode),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("driver error: {0}")]
    Other(String),
}

/// Restricted facade handed to a [`Driver::call`] (§7.3). It does **not** grant
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
    /// replay-stable invocation id (§16.3.3 / §6.1).
    pub operation_id: Option<OperationId>,
    /// Optional stream sink path for `OutputMode::Stream` results (§4.3).
    pub stream_to: Option<nexus_types::Path>,
    /// The provenance of the operation's input (§21.5). Drivers that persist
    /// data (memory) consult this to derive low-trust flags from lineage rather
    /// than trusting a caller-supplied flag.
    pub taint: nexus_types::TaintSet,
    /// The concrete target path of the operation (§12). For prefix-resolved
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

    /// Attach the originating Operation id (§6.1). Drivers that do not need
    /// cross-process transport ignore it; remote endpoint stubs require it.
    pub fn with_operation_id(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

    /// Attach the operation's input taint (§21.5).
    pub fn with_taint(mut self, taint: nexus_types::TaintSet) -> Self {
        self.taint = taint;
        self
    }

    /// Attach the concrete target path (§12 state-as-Operation).
    pub fn with_target_path(mut self, path: nexus_types::Path) -> Self {
        self.target_path = Some(path);
        self
    }

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
    /// output value (§21.5).
    pub fn set_output_taint(&self, taint: nexus_types::TaintSet) {
        *self.output_taint.lock() = taint;
    }

    pub fn output_taint(&self) -> nexus_types::TaintSet {
        self.output_taint.lock().clone()
    }
}

/// The implementation behind interface methods (§7.2). Local drivers run
/// in-process; remote drivers are reached through an endpoint (the
/// [`DriverPlan`] holds the dispatch detail).
#[async_trait]
pub trait Driver: Send + Sync + 'static {
    /// Invoke `method` with `input`, producing an [`Outcome`]. The driver does
    /// not receive a continuation (§1.1): it returns once.
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

/// Transport edge for a remote endpoint (§7.4 / §16.3.3). Concrete gRPC,
/// WebSocket, stdio, or test transports implement this; `DriverPlan` compiles
/// endpoint bindings to a [`RemoteDriver`] that calls this interface.
#[async_trait]
pub trait RemoteEndpoint: Send + Sync + 'static {
    async fn invoke(&self, invoke: Invoke) -> Result<InvokeResult, DriverError>;
}

pub type DynRemoteEndpoint = Arc<dyn RemoteEndpoint>;

/// RPC stub compiled into a [`DriverPlan`] for `Binding.endpoint = Some(_)`.
/// It turns a local data-plane call into a provider `Invoke` frame while keeping
/// the same authorization, policy, budget, taint, and Fact path around it.
pub struct RemoteDriver {
    endpoint_id: EndpointId,
    effect_path: Path,
    endpoint: DynRemoteEndpoint,
}

impl RemoteDriver {
    pub fn new(endpoint_id: EndpointId, effect_path: Path, endpoint: DynRemoteEndpoint) -> Self {
        Self {
            endpoint_id,
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
        let result = self.endpoint.invoke(invoke).await?;
        match result.outcome {
            Ok(v) => Ok(Outcome::Done(v)),
            Err(e) => Ok(Outcome::Fail(Failure::HandlerError {
                kind: e.kind,
                message: e.message,
            })),
        }
    }
}

/// Descriptor of a driver implementation (control plane, §7.2).
#[derive(Clone)]
pub struct DriverDescriptor {
    pub id: DriverId,
    pub name: String,
    /// Interfaces this driver implements (admission checks coverage, §7.2).
    pub implements: InterfaceSet,
    pub transport: Transport,
    /// The live implementation.
    pub driver: DynDriver,
}

/// Per-method dispatch entry within a [`DriverPlan`].
#[derive(Clone)]
pub struct DispatchEntry {
    pub method: MethodId,
    pub driver: DynDriver,
}

/// A compiled dispatch table for one opened Resource (§7.1). Produced at
/// `open()` and frozen into the Handle; the data plane calls through it with no
/// further resolution. `generation` matches the Binding link epoch (§14.3).
#[derive(Clone)]
pub struct DriverPlan {
    pub driver_id: DriverId,
    pub endpoint: Option<nexus_types::EndpointId>,
    /// method id → live driver. Local inline or a remote RPC stub driver.
    ///
    /// Handles, the open-plan cache, and the data plane all clone DriverPlan.
    /// Keep the frozen dispatch table shared so those clones stay O(1) Arc
    /// bumps instead of duplicating the HashMap on every operation.
    table: Arc<HashMap<MethodId, DynDriver>>,
    pub generation: u64,
}

impl DriverPlan {
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

    pub fn insert(&mut self, method: MethodId, driver: DynDriver) {
        Arc::make_mut(&mut self.table).insert(method, driver);
    }

    /// Dispatch `method`. The data plane has already checked rights and policy
    /// (§6); the plan only resolves and calls.
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

    pub fn supports(&self, method: MethodId) -> bool {
        self.table.contains_key(&method)
    }

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
        seen: Arc<Mutex<Vec<Invoke>>>,
        result: Result<Value, ErrorInfo>,
    }

    #[async_trait]
    impl RemoteEndpoint for RecordingEndpoint {
        async fn invoke(&self, invoke: Invoke) -> Result<InvokeResult, DriverError> {
            self.seen.lock().push(invoke.clone());
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
            Path::parse("effect://plugin/acme/search").unwrap(),
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

        let seen = seen.lock();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].invocation_id, "1/9/0");
        assert_eq!(
            seen[0].effect_path.to_string(),
            "effect://plugin/acme/search"
        );
        assert_eq!(seen[0].method_id, MethodId::new(0));
        assert_eq!(seen[0].output_stream_to, Some(stream));
    }
}
