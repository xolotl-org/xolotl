#![forbid(unsafe_code)]

//! Live Kernel execution for federated calls. The business call store owns
//! deduplication and retained results, not program continuation across restarts.

use std::{
    array,
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use sha2::{Digest as _, Sha256, Sha384};
use xolotl_federation::{
    CallCancelled, CallInvoked, CallKernelBinding, CallRef, CallStatus, CallTarget,
    CancelCallRequest, Digest, FederationCallStore, FederationError, InvokeCallRequest,
    MAX_CALL_UNRESOLVED_EFFECT_IDS, PersistedCallResult, PrepareCallRequest,
};
use xolotl_kernel::{
    Bootstrap, CleanupTicket, CompiledRequestGrantTemplate, PreparedProgram, RequestAuthorizer,
    StepModule,
};
use xolotl_types::{
    ExecutionOutput, Failure, IdentityRef, Outcome, ProcessId, TaintSource, TaintedValue, Value,
};

const STRIPES: usize = 64;
const STORE_WAIT: Duration = Duration::from_secs(15);
/// Maximum requests owned by one bridge, including execution and result publication.
pub const MAX_LIVE_CALLS: usize = 256;

/// Codec for one exact exported contract. Retained business results remain
/// readable after a restart; no serialized execution state is involved.
pub trait FederationCallCodec: Send + Sync {
    /// Decode input without removing its provenance at the Kernel boundary.
    fn decode_input(&self, bytes: Arc<[u8]>) -> Result<TaintedValue, FederationError>;
    /// Encode the actual live terminal output, not an acceptance receipt.
    fn encode_terminal(
        &self,
        output: &ExecutionOutput,
    ) -> Result<PersistedCallResult, FederationError>;
}

/// Byte-to-byte method codec. Failures expose a stable code, not internal text.
pub struct BytesCallCodec;

impl FederationCallCodec for BytesCallCodec {
    fn decode_input(&self, bytes: Arc<[u8]>) -> Result<TaintedValue, FederationError> {
        Ok(TaintedValue::pristine(Value::shared_bytes(bytes)))
    }

    fn encode_terminal(
        &self,
        output: &ExecutionOutput,
    ) -> Result<PersistedCallResult, FederationError> {
        match &output.outcome {
            Outcome::Done(value) | Outcome::Short(value) => {
                let bytes = value.as_bytes().ok_or(FederationError::Invalid(
                    "federated method returned a non-byte value",
                ))?;
                PersistedCallResult::new(true, Arc::from(bytes), None)
            }
            Outcome::Fail(failure) => PersistedCallResult::new(
                false,
                Arc::from([]),
                Some(xolotl_federation::CallFailureCode::new(
                    if *failure == Failure::Cancelled {
                        "kernel.cancelled"
                    } else {
                        "kernel.failed"
                    },
                )?),
            ),
        }
    }
}

/// Local implementation and attenuated authority for one exported contract.
pub struct FederationKernelMethod {
    /// Exact remote contract key.
    pub target: CallTarget,
    /// Prepared instructions executed within the current host lifecycle.
    pub program: PreparedProgram,
    /// Local identity chosen by the host, never by the remote caller.
    pub identity: IdentityRef,
    /// Request grants intersected with local authority by Bootstrap.
    pub grants: Vec<CompiledRequestGrantTemplate>,
    /// Input and terminal encoding for the contract.
    pub codec: Arc<dyn FederationCallCodec>,
}

/// Host-owned immutable catalog of current executable contracts.
pub trait FederationKernelCatalog: Send + Sync {
    /// Resolve an exact exported method before allocating its call reference.
    fn resolve(&self, target: &CallTarget) -> Result<Arc<FederationKernelMethod>, FederationError>;
    /// Native steps available to live programs, without recovery bindings.
    fn steps(&self) -> StepModule {
        StepModule::default()
    }
}

struct LiveCall {
    process: ProcessId,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct LiveState {
    closed: bool,
    calls: HashMap<CallRef, LiveCall>,
}

struct LiveOwner {
    state: Arc<Mutex<LiveState>>,
    call: CallRef,
    _cleanup: CleanupTicket,
    _capacity: tokio::sync::OwnedSemaphorePermit,
    exited: Arc<AtomicBool>,
}

struct FederationAuthorization {
    boot: Weak<Bootstrap>,
    store: Arc<dyn FederationCallStore>,
    call: CallRef,
}

#[async_trait::async_trait]
impl RequestAuthorizer for FederationAuthorization {
    async fn authorize(&self) -> Result<(), Failure> {
        let store = Arc::clone(&self.store);
        let boot = self.boot.upgrade().ok_or_else(|| Failure::Custom {
            kind: "federation.call.authorization".into(),
            message: "federation host is unavailable".into(),
        })?;
        let admission_boot = Arc::clone(&boot);
        let call = self.call;
        blocking(&boot, move || {
            store.authorize_kernel_execution(call, host_now(&admission_boot)?)
        })
        .await
        .map_err(|error| Failure::Custom {
            kind: "federation.call.authorization".into(),
            message: error.to_string(),
        })
    }
}

impl Drop for LiveOwner {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.exited.store(true, Ordering::Release);
        state.calls.remove(&self.call);
    }
}

/// Owns bounded live tasks. Persisted acceptance without a live owner is
/// unknown and is never replayed. Hosts explicitly close and drain this bridge.
pub struct FederationKernelCallBridge {
    boot: Arc<Bootstrap>,
    store: Arc<dyn FederationCallStore>,
    catalog: Arc<dyn FederationKernelCatalog>,
    admission: [tokio::sync::Mutex<()>; STRIPES],
    state: Arc<Mutex<LiveState>>,
    capacity: Arc<tokio::sync::Semaphore>,
    shutdown_tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl FederationKernelCallBridge {
    /// Bind a live Kernel, a business call store, and the host method catalog.
    /// Construction binds the host clock through the store's local decision
    /// port, so queued work samples current time under the owner lock instead
    /// of trusting a pre-queue timestamp. Unsupported stores reject creation.
    /// This clock is not remote admission proof; subsequent remote operations
    /// retain their separately verified decision, and delivery remains checked.
    /// Supply an unbound store, not an already clock/proof-bound view.
    pub fn new(
        boot: Arc<Bootstrap>,
        store: Arc<dyn FederationCallStore>,
        catalog: Arc<dyn FederationKernelCatalog>,
    ) -> Result<Arc<Self>, FederationError> {
        let host = boot.kernel().host_runtime().clone();
        let store = store.bind_local_call_clock(Arc::new(move || {
            u64::try_from(host.now_millis()).map_err(|_error| FederationError::ClockRollback)
        }))?;
        Ok(Arc::new(Self {
            boot,
            store,
            catalog,
            admission: array::from_fn(|_| tokio::sync::Mutex::new(())),
            state: Arc::new(Mutex::new(LiveState::default())),
            capacity: Arc::new(tokio::sync::Semaphore::new(MAX_LIVE_CALLS)),
            shutdown_tasks: tokio::sync::Mutex::new(Vec::new()),
        }))
    }

    /// Locally clock-bound business store for concurrent host inspection and
    /// receipt decisions. Remote transport admission must still bind its proof.
    pub fn store(&self) -> &Arc<dyn FederationCallStore> {
        &self.store
    }

    /// Validate implementation availability independently of remote authority.
    pub fn validate_prepare(&self, request: &PrepareCallRequest) -> Result<(), FederationError> {
        self.resolve_method(&request.target)?;
        Ok(())
    }

    fn resolve_method(
        &self,
        target: &CallTarget,
    ) -> Result<Arc<FederationKernelMethod>, FederationError> {
        let method = self.catalog.resolve(target)?;
        if method.target != *target {
            return Err(FederationError::Invalid(
                "federated method contract is unavailable",
            ));
        }
        method
            .program
            .layout(&self.boot.kernel().execution_config())
            .map_err(|_error| {
                FederationError::Invalid("federated method exceeds host execution limits")
            })?;
        Ok(method)
    }

    /// Accept at most one live execution for the original CallRef. A bound
    /// row from another host lifecycle is returned unchanged, never resubmitted.
    pub async fn invoke(
        self: &Arc<Self>,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Result<CallInvoked, FederationError> {
        self.invoke_admitted(request, now_ms, Arc::clone(&self.store))
            .await
    }

    /// Carry session authority to every admission decision, including the
    /// queued task's Kernel identity binding and execution authorization.
    pub async fn invoke_with_decision(
        self: &Arc<Self>,
        request: InvokeCallRequest,
        now_ms: u64,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<CallInvoked, FederationError> {
        decision.check_peer(request.authenticated_origin)?;
        let remote_store = self.store.bind_call_decision(decision)?;
        self.invoke_admitted(request, now_ms, remote_store).await
    }

    async fn invoke_admitted(
        self: &Arc<Self>,
        request: InvokeCallRequest,
        now_ms: u64,
        remote_store: Arc<dyn FederationCallStore>,
    ) -> Result<CallInvoked, FederationError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(kernel_error)?;
        let call = request.call;
        let _admission = self.admission[usize::from(call.id[0]) % STRIPES]
            .lock()
            .await;
        if self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
        {
            return Err(FederationError::Invalid(
                "federation call admission is closed",
            ));
        }
        let store = Arc::clone(&remote_store);
        let claimed = blocking(&self.boot, move || store.invoke_call(request, now_ms)).await?;
        if claimed.status != CallStatus::Preparing {
            return Ok(claimed);
        }
        let store = Arc::clone(&remote_store);
        let view = blocking(&self.boot, move || store.kernel_call(call, now_ms)).await?;
        if view.binding.is_some()
            || self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .calls
                .contains_key(&call)
        {
            return Ok(claimed);
        }
        if view.cancellation_requested
            || host_now(&self.boot)? >= view.request.execution_deadline_ms
        {
            let store = Arc::clone(&remote_store);
            return blocking(&self.boot, move || {
                let closed = store.close_unaccepted_call(call, now_ms)?;
                Ok(CallInvoked {
                    call,
                    status: closed.status,
                    control_revision: closed.control_revision,
                })
            })
            .await;
        }
        let capacity = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_error| FederationError::Capacity)?;
        let input = view.input.as_ref().ok_or(FederationError::Corrupt)?;
        if input.len() as u64 != view.request.input_bytes
            || Digest::from_bytes(Sha384::digest(input).into()) != view.request.input_digest
        {
            return Err(FederationError::Corrupt);
        }
        let method = self.resolve_method(&view.request.target)?;
        let mut decoded = method.codec.decode_input(Arc::clone(input))?;
        decoded.taint.add(TaintSource::Inbound {
            source: format!("federation/{:?}", view.request.authenticated_origin).into(),
            channel: "invoke".into(),
        });
        let scope = self
            .boot
            .request_under_owned(self.boot.root(), method.identity, &method.grants)
            .map_err(kernel_error)?;
        let process = scope.id();
        let remaining = view
            .request
            .execution_deadline_ms
            .saturating_sub(host_now(&self.boot)?);
        if remaining == 0 {
            return Err(FederationError::Conflict);
        }
        let deadline = self
            .boot
            .kernel()
            .host_runtime()
            .deadline_after(Duration::from_millis(remaining.saturating_sub(1)))
            .ok_or(FederationError::Invalid("call deadline is out of range"))?;
        let mut executor = scope
            .executor()
            .with_steps(self.catalog.steps())
            .with_request_authorizer(Arc::new(FederationAuthorization {
                boot: Arc::downgrade(&self.boot),
                store: Arc::clone(&remote_store),
                call,
            }))
            .with_deadline(deadline)
            .map_err(kernel_error)?;
        let boot = Arc::clone(&self.boot);
        let store = Arc::clone(&self.store);
        let execution_admission = Arc::clone(&remote_store);
        let exited = Arc::new(AtomicBool::new(false));
        let owner = LiveOwner {
            state: Arc::clone(&self.state),
            call,
            _cleanup: scope.cleanup_ticket(),
            _capacity: capacity,
            exited: Arc::clone(&exited),
        };
        let (start, ready) = tokio::sync::oneshot::channel();
        let (receipt, response) = tokio::sync::oneshot::channel();
        let task = runtime.spawn(async move {
            let _owner = owner;
            if ready.await.is_err() { return; }
            let admission_store = Arc::clone(&execution_admission);
            let admission_boot = Arc::clone(&boot);
            let acceptance = async {
                let lifecycle = executor.reserve_lifecycle().await.map_err(kernel_error)?;
                let binding = CallKernelBinding { process: process.get(), lifecycle: lifecycle.get() };
                let mut hash = Sha384::new();
                hash.update(b"xolotl:federation:live-admission:v1\0");
                hash.update(call.target.as_bytes());
                hash.update(call.id);
                hash.update(binding.process.to_be_bytes());
                hash.update(binding.lifecycle.to_be_bytes());
                hash.update(method.program.id());
                hash.update(view.request.input_digest.as_bytes());
                let digest = Digest::from_bytes(hash.finalize().into());
                blocking(&boot, move || {
                    let now = host_now(&admission_boot)?;
                    admission_store.bind_kernel_identity(call, binding, now)?;
                    admission_store.authorize_kernel_execution(call, now)?;
                    admission_store.record_kernel_acceptance(call, digest)
                }).await
            };
            let accepted = match tokio::time::timeout(Duration::from_millis(remaining), acceptance).await {
                Ok(result) => result,
                Err(_) => Err(FederationError::Storage("live admission timed out; inspect original call identity".into())),
            };
            let admitted = accepted.is_ok();
            drop(receipt.send(accepted));
            if !admitted { return; }
            let mut output = executor.eval_prepared(&method.program, decoded).await;
            let cleanup_wait = boot.kernel().execution_config().cleanup_timeout;
            let stopped = match tokio::time::timeout(cleanup_wait, scope.finish(&output)).await {
                Ok(Ok(report)) => {
                    output.taint.union(&report.taint);
                    output.unresolved_operations.merge(&report.unresolved_operations);
                    true
                }
                Ok(Err(error)) => {
                    tracing::warn!(?call, %error, "federated call cleanup remains pending");
                    false
                }
                Err(_) => {
                    tracing::warn!(?call, "federated call cleanup wait expired; Bootstrap retains responsibility");
                    false
                }
            };
            let result = method.codec.encode_terminal(&output);
            let effects = unresolved_effect_ids(&output);
            let result_store = Arc::clone(&store);
            let publication = async {
                let now = host_now(&boot)?;
                blocking(&boot, move || {
                    if stopped {
                        result_store.record_execution_stopped(call, now)?;
                    }
                    result_store.record_call_result(call, result?, effects?, now)?;
                    Ok(())
                }).await
            }.await;
            if let Err(error) = publication { tracing::warn!(?call, %error, "federated call terminal unavailable; original call remains unknown"); }
        });
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed || exited.load(Ordering::Acquire) {
                drop(state);
                task.abort();
                return Err(FederationError::Storage(
                    "live admission interrupted before registration".into(),
                ));
            }
            state.calls.insert(call, LiveCall { process, task });
            if start.send(()).is_err() {
                tracing::warn!(
                    ?call,
                    "registered federation task exited before admission began"
                );
            }
        }
        response.await.map_err(|_error| {
            FederationError::Storage(
                "live admission interrupted; inspect original call identity".into(),
            )
        })?
    }

    /// Persist the remote cancellation intent, then select cancellation only
    /// for an owned live process. Missing owners never justify a stopped claim.
    pub async fn cancel(
        self: &Arc<Self>,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Result<CallCancelled, FederationError> {
        self.cancel_admitted(request, now_ms, Arc::clone(&self.store))
            .await
    }

    /// Check current remote authority at cancellation selection, while keeping
    /// local Kernel receipts independent of subsequent peer revocation.
    pub async fn cancel_with_decision(
        self: &Arc<Self>,
        request: CancelCallRequest,
        now_ms: u64,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<CallCancelled, FederationError> {
        decision.check_peer(request.authenticated_origin)?;
        let remote_store = self.store.bind_call_decision(decision)?;
        self.cancel_admitted(request, now_ms, remote_store).await
    }

    async fn cancel_admitted(
        self: &Arc<Self>,
        request: CancelCallRequest,
        now_ms: u64,
        remote_store: Arc<dyn FederationCallStore>,
    ) -> Result<CallCancelled, FederationError> {
        let call = request.call;
        let _admission = self.admission[usize::from(call.id[0]) % STRIPES]
            .lock()
            .await;
        let store = Arc::clone(&remote_store);
        let receipt = blocking(&self.boot, move || store.cancel_call(request, now_ms)).await?;
        if !receipt.cancellation_requested || receipt.kernel_cancel_accepted {
            return Ok(receipt);
        }
        let process = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .calls
            .get(&call)
            .map(|live| live.process);
        if let Some(process) = process {
            if self.boot.cancel_process(process).map_err(kernel_error)? {
                let store = Arc::clone(&self.store);
                blocking(&self.boot, move || {
                    let view = store.kernel_call(call, now_ms)?;
                    if view.binding.is_some() {
                        store.record_kernel_cancel_accepted(call, now_ms)?;
                    } else if view.status == CallStatus::Preparing {
                        store.close_unaccepted_call(call, now_ms)?;
                    }
                    Ok(())
                })
                .await?;
            }
        } else {
            let store = Arc::clone(&self.store);
            blocking(&self.boot, move || {
                let view = store.kernel_call(call, now_ms)?;
                if view.binding.is_none() && view.status == CallStatus::Preparing {
                    store.close_unaccepted_call(call, now_ms)?;
                }
                Ok(())
            })
            .await?;
        }
        Ok(receipt)
    }

    /// Idempotently close new call admission without waiting for admitted work.
    pub fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
    }

    /// Close admission, abort owned tasks, and observe their termination.
    /// Aborted execution leaves its original business identity unresolved.
    pub async fn shutdown(&self) {
        self.close();
        let mut admissions = Vec::with_capacity(STRIPES);
        for admission in &self.admission {
            admissions.push(admission.lock().await);
        }
        let mut tasks = self.shutdown_tasks.lock().await;
        let calls = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut state.calls)
        };
        tasks.extend(calls.into_values().map(|live| live.task));
        for task in tasks.iter() {
            task.abort();
        }
        while let Some(task) = tasks.last_mut() {
            drop(task.await);
            tasks.pop();
        }
    }
}

impl Drop for FederationKernelCallBridge {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        for live in state.calls.values() {
            live.task.abort();
        }
        for task in self.shutdown_tasks.get_mut() {
            task.abort();
        }
    }
}

async fn blocking<T: Send + 'static>(
    boot: &Bootstrap,
    work: impl FnOnce() -> Result<T, FederationError> + Send + 'static,
) -> Result<T, FederationError> {
    let accepted = boot
        .kernel()
        .host_runtime()
        .dispatch_blocking(work)
        .map_err(kernel_error)?;
    tokio::time::timeout(STORE_WAIT, accepted)
        .await
        .map_err(|_error| {
            FederationError::Storage(
                "accepted call store job timed out; inspect original identity".into(),
            )
        })?
        .map_err(kernel_error)?
}

fn unresolved_effect_ids(output: &ExecutionOutput) -> Result<Vec<[u8; 32]>, FederationError> {
    let unresolved = &output.unresolved_operations;
    if unresolved.identities_incomplete
        || unresolved.operation_ids.len() > MAX_CALL_UNRESOLVED_EFFECT_IDS
    {
        return Err(FederationError::Capacity);
    }
    Ok(unresolved
        .operation_ids
        .iter()
        .map(|id| Sha256::digest(id.as_bytes()).into())
        .collect())
}

fn host_now(boot: &Bootstrap) -> Result<u64, FederationError> {
    u64::try_from(boot.kernel().host_runtime().now_millis())
        .map_err(|_error| FederationError::ClockRollback)
}

fn kernel_error(error: impl std::fmt::Display) -> FederationError {
    FederationError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use xolotl_federation::{
        CallAuthorityRule, CallMethod, CallPath, ExportName, FederationNodeId, FederationSubject,
        MemoryFederationCallStore, RequestId,
    };
    use xolotl_sdk::{Expression, Program};

    struct Catalog(Arc<FederationKernelMethod>);

    struct ExitGate {
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Drop for ExitGate {
        fn drop(&mut self) {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap_or(());
            }
            self.release.recv().unwrap_or(());
        }
    }

    impl FederationKernelCatalog for Catalog {
        fn resolve(
            &self,
            target: &CallTarget,
        ) -> Result<Arc<FederationKernelMethod>, FederationError> {
            if self.0.target != *target {
                return Err(FederationError::NotFound);
            }
            Ok(Arc::clone(&self.0))
        }
    }

    #[tokio::test]
    async fn installed_authorizer_does_not_retain_its_host() -> Result<()> {
        let node = FederationNodeId::from_bytes([1; 48]);
        let boot = Arc::new(Bootstrap::in_memory());
        let host = Arc::downgrade(&boot);
        let authorizer = Arc::new(FederationAuthorization {
            boot: host.clone(),
            store: Arc::new(MemoryFederationCallStore::new(node)),
            call: CallRef::new(node, [2; 32])?,
        });
        let executor = boot
            .kernel()
            .executor_for(boot.root())
            .with_request_authorizer(authorizer.clone());
        drop(boot);
        ensure!(
            host.upgrade().is_none(),
            "installed authorizer retained its host"
        );
        ensure!(
            matches!(authorizer.authorize().await, Err(Failure::Custom { message, .. }) if message == "federation host is unavailable")
        );
        drop(executor);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_shutdown_retains_handles_until_task_termination() -> Result<()> {
        use std::future::Future as _;
        use std::task::Poll;
        let node = FederationNodeId::from_bytes([1; 48]);
        let boot = Arc::new(Bootstrap::in_memory());
        let method = Arc::new(FederationKernelMethod {
            target: CallTarget {
                export: ExportName::new("tools")?,
                path: CallPath::new("/echo")?,
                method: CallMethod::new("echo")?,
                contract_digest: [3; 32],
            },
            program: PreparedProgram::new(&Program::new(Expression::Input).compile()?)?,
            identity: IdentityRef::ROOT,
            grants: Vec::new(),
            codec: Arc::new(BytesCallCodec),
        });
        let bridge = FederationKernelCallBridge::new(
            boot.clone(),
            Arc::new(MemoryFederationCallStore::new(node)),
            Arc::new(Catalog(method)),
        )?;
        let (entered, exiting) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (ready, running) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _gate = ExitGate {
                entered: Some(entered),
                release: released,
            };
            ready.send(()).unwrap_or(());
            std::future::pending::<()>().await;
        });
        running.await?;
        bridge
            .state
            .lock()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .calls
            .insert(
                CallRef::new(node, [4; 32])?,
                LiveCall {
                    process: boot.root(),
                    task,
                },
            );
        bridge.close();
        bridge.close();
        let admission = bridge.admission[0].lock().await;
        let mut shutdown = Box::pin(bridge.shutdown());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context)))
                .await
                .is_pending()
        );
        drop(shutdown);
        {
            let state = bridge
                .state
                .lock()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            ensure!(state.closed && state.calls.len() == 1);
        }
        ensure!(bridge.shutdown_tasks.try_lock()?.is_empty());
        let rejected = bridge
            .invoke(
                InvokeCallRequest {
                    authenticated_origin: node,
                    subject: FederationSubject::Node(node),
                    origin_request_id: RequestId::from_bytes([5; 16]),
                    call: CallRef::new(node, [5; 32])?,
                    input: Arc::from([]),
                },
                0,
            )
            .await;
        ensure!(matches!(
            rejected,
            Err(FederationError::Invalid(
                "federation call admission is closed"
            ))
        ));
        drop(admission);
        let mut shutdown = Box::pin(bridge.shutdown());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context)))
                .await
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(5), exiting).await??;
        drop(shutdown);
        ensure!(bridge.shutdown_tasks.try_lock()?.len() == 1);
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), bridge.shutdown()).await?;
        ensure!(bridge.shutdown_tasks.try_lock()?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn repeated_completed_calls_release_task_owners_and_capacity() -> Result<()> {
        let node = FederationNodeId::from_bytes([1; 48]);
        let peer = FederationNodeId::from_bytes([2; 48]);
        let store = Arc::new(MemoryFederationCallStore::new(node));
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::in_memory()
                .with_process_capacity(
                    std::num::NonZeroUsize::new(2).context("zero process capacity")?,
                )
                .build(),
        ));
        let target = CallTarget {
            export: ExportName::new("tools")?,
            path: CallPath::new("/echo")?,
            method: CallMethod::new("echo")?,
            contract_digest: [3; 32],
        };
        let now = host_now(&boot)?;
        store.set_call_authority(
            None,
            CallAuthorityRule {
                subject: FederationSubject::Node(peer),
                presenter: peer,
                target: target.clone(),
                enabled: true,
                expires_ms: now + 120_000,
                max_input_bytes: 1024,
                max_prepare_window_ms: 30_000,
                max_result_retention_ms: 30_000,
            },
        )?;
        let method = Arc::new(FederationKernelMethod {
            target: target.clone(),
            program: PreparedProgram::new(&Program::new(Expression::Input).compile()?)?,
            identity: IdentityRef::ROOT,
            grants: Vec::new(),
            codec: Arc::new(BytesCallCodec),
        });
        let bridge =
            FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
        for sequence in 1_u64..=MAX_LIVE_CALLS as u64 + 1 {
            let now = host_now(&bridge.boot)?;
            let mut id = [0; 16];
            id[..8].copy_from_slice(&sequence.to_be_bytes());
            let origin_request_id = RequestId::from_bytes(id);
            let call = store
                .prepare_call(
                    PrepareCallRequest {
                        authenticated_origin: peer,
                        subject: FederationSubject::Node(peer),
                        origin_request_id,
                        target: target.clone(),
                        input_digest: Digest::from_bytes(Sha384::digest(b"input").into()),
                        input_bytes: 5,
                        prepare_deadline_ms: now + 30_000,
                        execution_deadline_ms: now + 60_000,
                        result_retention_ms: 30_000,
                    },
                    now,
                )?
                .call;
            bridge
                .invoke(
                    InvokeCallRequest {
                        authenticated_origin: peer,
                        subject: FederationSubject::Node(peer),
                        origin_request_id,
                        call,
                        input: Arc::from(b"input".as_slice()),
                    },
                    now,
                )
                .await?;
            tokio::time::timeout(Duration::from_secs(5), async {
                while bridge.capacity.available_permits() != MAX_LIVE_CALLS {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .context("completed request retained execution capacity")?;
            ensure!(
                bridge
                    .state
                    .lock()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    .calls
                    .is_empty(),
                "completed request retained task owner"
            );
            ensure!(
                store
                    .kernel_call(call, host_now(&bridge.boot)?)?
                    .execution_stopped
            );
        }
        bridge.shutdown().await;
        Ok(())
    }
}
