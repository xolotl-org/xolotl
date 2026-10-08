use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256, Sha384};
use xolotl_federation::{
    CallAuthorityRule, CallKernelBinding, CallMethod, CallPath, CallStatus, CallTarget,
    CancelCallRequest, Digest, ExportAccess, ExportName, FederationCallStore, FederationError,
    FederationNodeId, FederationStore, FederationSubject, InspectCallRequest, InvokeCallRequest,
    PersistedCallResult, PrepareCallRequest, RequestId,
};
use xolotl_federation_kernel::{
    BytesCallCodec, FederationCallCodec, FederationKernelCallBridge, FederationKernelCatalog,
    FederationKernelMethod,
};
use xolotl_kernel::{Bootstrap, FactSink, KernelBuilder, PreparedProgram};
use xolotl_sdk::{Expression, Program};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{IdentityRef, TaintedValue};

struct FlakyCodec(AtomicBool);

struct PublicationGate {
    inner: xolotl_kernel::host::TokioBlockingSpawner,
    queued: AtomicBool,
    entered: AtomicBool,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl FederationCallCodec for PublicationGate {
    fn decode_input(&self, bytes: Arc<[u8]>) -> Result<TaintedValue, FederationError> {
        BytesCallCodec.decode_input(bytes)
    }

    fn encode_terminal(
        &self,
        output: &xolotl_types::ExecutionOutput,
    ) -> Result<PersistedCallResult, FederationError> {
        let result = BytesCallCodec.encode_terminal(output)?;
        self.queued.store(true, Ordering::SeqCst);
        Ok(result)
    }
}

impl xolotl_kernel::host::BlockingSpawner for PublicationGate {
    fn spawn(
        &self,
        job: xolotl_kernel::host::BlockingJob,
    ) -> Result<(), xolotl_kernel::host::BlockingSpawnError> {
        if self.queued.swap(false, Ordering::SeqCst) {
            let release = self
                .release
                .lock()
                .map_err(|_error| xolotl_kernel::host::BlockingSpawnError::Unavailable)?
                .take()
                .ok_or(xolotl_kernel::host::BlockingSpawnError::Unavailable)?;
            self.entered.store(true, Ordering::SeqCst);
            self.inner.spawn(Box::new(move || {
                if release.recv_timeout(Duration::from_secs(5)).is_ok() {
                    job();
                }
            }))
        } else {
            self.inner.spawn(job)
        }
    }
}

#[derive(Default)]
struct TerminalObserver(Mutex<Option<xolotl_types::Outcome>>);

impl FederationCallCodec for TerminalObserver {
    fn decode_input(&self, bytes: Arc<[u8]>) -> Result<TaintedValue, FederationError> {
        BytesCallCodec.decode_input(bytes)
    }

    fn encode_terminal(
        &self,
        output: &xolotl_types::ExecutionOutput,
    ) -> Result<PersistedCallResult, FederationError> {
        *self.0.lock().map_err(|_error| FederationError::Corrupt)? = Some(output.outcome.clone());
        BytesCallCodec.encode_terminal(output)
    }
}

impl FederationCallCodec for FlakyCodec {
    fn decode_input(&self, bytes: Arc<[u8]>) -> Result<TaintedValue, FederationError> {
        BytesCallCodec.decode_input(bytes)
    }

    fn encode_terminal(
        &self,
        terminal: &xolotl_types::ExecutionOutput,
    ) -> Result<PersistedCallResult, FederationError> {
        if self.0.load(Ordering::SeqCst) {
            return Err(FederationError::Storage(
                "test publisher unavailable".into(),
            ));
        }
        BytesCallCodec.encode_terminal(terminal)
    }
}

#[derive(Default)]
struct WaitingDriver {
    entered: AtomicBool,
    dropped: AtomicBool,
    operation: Mutex<Option<xolotl_types::OperationId>>,
    unknown: bool,
}

struct DriverOwner<'a>(&'a AtomicBool);

#[derive(Default)]
struct FirstCallGate {
    calls: AtomicUsize,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl xolotl_kernel::Driver for FirstCallGate {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        input: xolotl_types::Value,
        _output: xolotl_types::OutputMode,
        _context: &xolotl_kernel::DriverContext,
    ) -> Result<xolotl_types::DriverOutput, xolotl_kernel::DriverError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.release.notified().await;
        }
        Ok(xolotl_types::DriverOutput::new(
            xolotl_types::Outcome::Done(input),
        ))
    }
}

struct AdmissionGate {
    inner: xolotl_kernel::host::TokioBlockingSpawner,
    jobs: AtomicUsize,
    entered: Arc<AtomicBool>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl xolotl_kernel::host::BlockingSpawner for AdmissionGate {
    fn spawn(
        &self,
        job: xolotl_kernel::host::BlockingJob,
    ) -> Result<(), xolotl_kernel::host::BlockingSpawnError> {
        if self.jobs.fetch_add(1, Ordering::SeqCst) == 2 {
            let release = self
                .release
                .lock()
                .map_err(|_error| xolotl_kernel::host::BlockingSpawnError::Unavailable)?
                .take()
                .ok_or(xolotl_kernel::host::BlockingSpawnError::Unavailable)?;
            let entered = Arc::clone(&self.entered);
            self.inner.spawn(Box::new(move || {
                entered.store(true, Ordering::SeqCst);
                if release.recv().is_ok() {
                    job();
                }
            }))
        } else {
            self.inner.spawn(job)
        }
    }
}

impl Drop for DriverOwner<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl xolotl_kernel::Driver for WaitingDriver {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        _input: xolotl_types::Value,
        _output: xolotl_types::OutputMode,
        context: &xolotl_kernel::DriverContext,
    ) -> Result<xolotl_types::DriverOutput, xolotl_kernel::DriverError> {
        let _owner = DriverOwner(&self.dropped);
        *self
            .operation
            .lock()
            .map_err(|error| xolotl_kernel::DriverError::Transport(error.to_string()))? =
            context.operation_id;
        self.entered.store(true, Ordering::SeqCst);
        if self.unknown {
            return Err(xolotl_kernel::DriverError::OutcomeUnknown {
                operation_id: context
                    .operation_id
                    .ok_or_else(|| {
                        xolotl_kernel::DriverError::Transport(
                            "missing dispatched operation identity".into(),
                        )
                    })?
                    .to_string(),
                reason: "remote disconnected after dispatch".into(),
            });
        }
        std::future::pending().await
    }
}

fn operation_method(
    boot: &Bootstrap,
    driver: Arc<dyn xolotl_kernel::Driver>,
    grant: bool,
) -> Result<Arc<FederationKernelMethod>> {
    use xolotl_kernel::{CompiledRequestGrantTemplate, MethodSpec};
    use xolotl_sdk::OperationTemplate;
    use xolotl_types::{
        GrantMethods, GrantRights, MethodAuthority, OutputMode, Purity, ResourceSelector,
        RightFlags,
    };
    let target = boot.register_effect(
        "effect://federation-test",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver,
    )?;
    let mut implementation = method()?;
    let method = Arc::get_mut(&mut implementation).context("unique method")?;
    method.program = PreparedProgram::new(
        &Program::new(Expression::Invoke {
            operation: OperationTemplate {
                target: target.clone(),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            },
        })
        .compile()?,
    )?;
    if grant {
        method.grants.push(CompiledRequestGrantTemplate {
            selector: ResourceSelector::exact("perform", target.path())?,
            rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
        });
    }
    Ok(implementation)
}

async fn wait_until(mut condition: impl FnMut() -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

async fn wait_stopped(
    store: &(impl FederationCallStore + ?Sized),
    call: xolotl_federation::CallRef,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !store.kernel_call(call, now_ms()?)?.execution_stopped {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_federation_authority_fences_the_next_resource_dispatch() -> Result<()> {
    use xolotl_sdk::OperationTemplate;
    use xolotl_types::{OutputMode, Path, ResourceName};
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([60; 48]);
    let peer = FederationNodeId::from_bytes([61; 48]);
    let boot = runtime(&db)?;
    let driver = Arc::new(FirstCallGate::default());
    let terminal = Arc::new(TerminalObserver::default());
    let mut method = operation_method(&boot, driver.clone(), true)?;
    Arc::get_mut(&mut method).context("unique method")?.codec = terminal.clone();
    let operation = Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://federation-test")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    };
    Arc::get_mut(&mut method).context("unique method")?.program = PreparedProgram::new(
        &Program::new(Expression::Sequence {
            steps: vec![operation.clone(), operation],
        })
        .compile()?,
    )?;
    let target = method.target.clone();
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, target.clone(), now_ms()?, 62)?;
    let bridge = FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
    bridge
        .invoke(
            InvokeCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                origin_request_id: request.origin_request_id,
                call,
                input: Arc::from(b"input".as_slice()),
            },
            now_ms()?,
        )
        .await?;
    wait_until(|| driver.calls.load(Ordering::SeqCst) == 1).await?;
    store.set_call_authority(
        Some(1),
        CallAuthorityRule {
            subject: FederationSubject::Node(peer),
            presenter: peer,
            target,
            enabled: false,
            expires_ms: now_ms()? + 120_000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 30_000,
            max_result_retention_ms: 30_000,
        },
    )?;
    driver.release.notify_one();
    wait_stopped(bridge.store().as_ref(), call).await?;
    ensure!(
        driver.calls.load(Ordering::SeqCst) == 1,
        "revocation allowed a second resource dispatch"
    );
    let inspection = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    );
    ensure!(matches!(inspection, Err(FederationError::Unauthorized)));
    ensure!(matches!(
        terminal
            .0
            .lock()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .as_ref(),
        Some(xolotl_types::Outcome::Fail(_))
    ));
    bridge.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_missing_owner_cannot_cancel_a_reused_process_coordinate() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([70; 48]);
    let peer = FederationNodeId::from_bytes([71; 48]);
    let boot = runtime(&db)?;
    let unrelated = boot.request_under_owned(boot.root(), IdentityRef::ROOT, &[])?;
    let mut unrelated_executor = unrelated.executor();
    let binding = CallKernelBinding {
        process: unrelated.id().get(),
        lifecycle: unrelated_executor.reserve_lifecycle().await?.get(),
    };
    let initial = boot.kernel().processes().status(unrelated.id());
    let method = method()?;
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 72)?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    store.invoke_call(invoke.clone(), now_ms()?)?;
    store.bind_kernel_identity(call, binding, now_ms()?)?;
    store.record_kernel_acceptance(call, Digest::from_bytes([73; 48]))?;
    let bridge =
        FederationKernelCallBridge::new(boot.clone(), store.clone(), Arc::new(Catalog(method)))?;
    ensure!(bridge.invoke(invoke, now_ms()?).await?.status == CallStatus::Accepted);
    bridge
        .cancel(
            CancelCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                control_request_id: RequestId::from_bytes([74; 16]),
                call,
                expected_control_revision: None,
            },
            now_ms()?,
        )
        .await?;
    ensure!(boot.kernel().processes().status(unrelated.id()) == initial);
    let inspection = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(
        inspection.status == CallStatus::Accepted
            && inspection.cancellation_requested
            && !inspection.kernel_cancel_accepted
            && !inspection.execution_stopped
            && inspection.result.is_none()
    );
    drop(unrelated);
    bridge.shutdown().await;
    ensure!(boot.drain_cleanup().await.failures.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_admission_observer_keeps_registered_live_owner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([50; 48]);
    let peer = FederationNodeId::from_bytes([51; 48]);
    let (release, gate) = std::sync::mpsc::channel();
    let entered = Arc::new(AtomicBool::new(false));
    let spawner = Arc::new(AdmissionGate {
        inner: xolotl_kernel::host::TokioBlockingSpawner::default(),
        jobs: AtomicUsize::new(0),
        entered: entered.clone(),
        release: Mutex::new(Some(gate)),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(db.state_backend().into_backend())
            .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                spawner.clone(),
            ))
            .build(),
    ));
    let method = method()?;
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 52)?;
    let bridge = FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    let caller_bridge = Arc::clone(&bridge);
    let caller_invoke = invoke.clone();
    let admission_now = now_ms()?;
    let caller =
        tokio::spawn(async move { caller_bridge.invoke(caller_invoke, admission_now).await });
    wait_until(|| entered.load(Ordering::SeqCst)).await?;
    caller.abort();
    ensure!(caller.await.is_err_and(|error| error.is_cancelled()));
    release.send(())?;
    finished(bridge.store().as_ref(), &request, call).await?;
    ensure!(bridge.invoke(invoke, now_ms()?).await?.status == CallStatus::Finished);
    bridge.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_admission_closes_unbound_call_before_delayed_commit() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([80; 48]);
    let peer = FederationNodeId::from_bytes([81; 48]);
    let (release, gate) = std::sync::mpsc::channel();
    let entered = Arc::new(AtomicBool::new(false));
    let spawner = Arc::new(AdmissionGate {
        inner: xolotl_kernel::host::TokioBlockingSpawner::default(),
        jobs: AtomicUsize::new(0),
        entered: entered.clone(),
        release: Mutex::new(Some(gate)),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(db.state_backend().into_backend())
            .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                spawner.clone(),
            ))
            .build(),
    ));
    let driver = Arc::new(WaitingDriver::default());
    let method = operation_method(&boot, driver.clone(), true)?;
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 82)?;
    let bridge = FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    let observer_bridge = bridge.clone();
    let observer_request = invoke.clone();
    let admission_now = now_ms()?;
    let observer = tokio::spawn(async move {
        observer_bridge
            .invoke(observer_request, admission_now)
            .await
    });
    wait_until(|| entered.load(Ordering::SeqCst)).await?;
    observer.abort();
    ensure!(observer.await.is_err_and(|error| error.is_cancelled()));
    let cancelled = bridge
        .cancel(
            CancelCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                control_request_id: RequestId::from_bytes([83; 16]),
                call,
                expected_control_revision: None,
            },
            now_ms()?,
        )
        .await?;
    ensure!(cancelled.cancellation_requested);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(5), spawner.inner.wait_idle()).await?;
    bridge.shutdown().await;
    let inspected = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspected.status == CallStatus::Closed);
    ensure!(!inspected.kernel_cancel_accepted && inspected.result.is_none());
    ensure!(!driver.entered.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn publication_failure_does_not_restart_program() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([10; 48]);
    let peer = FederationNodeId::from_bytes([11; 48]);
    let codec = Arc::new(FlakyCodec(AtomicBool::new(true)));
    let method = method_with_codec(codec.clone())?;
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 12)?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    let bridge = FederationKernelCallBridge::new(
        runtime(&db)?,
        store.clone(),
        Arc::new(Catalog(method.clone())),
    )?;
    ensure!(bridge.invoke(invoke.clone(), now_ms()?).await?.status == CallStatus::Accepted);
    wait_stopped(bridge.store().as_ref(), call).await?;
    bridge.shutdown().await;
    codec.0.store(false, Ordering::SeqCst);
    let next_host =
        FederationKernelCallBridge::new(runtime(&db)?, store.clone(), Arc::new(Catalog(method)))?;
    ensure!(next_host.invoke(invoke, now_ms()?).await?.status == CallStatus::Accepted);
    let view = store.kernel_call(call, now_ms()?)?;
    ensure!(view.execution_stopped && view.status == CallStatus::Accepted);
    let inspected = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspected.result.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn live_cancel_stops_driver_and_publishes_terminal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([30; 48]);
    let peer = FederationNodeId::from_bytes([31; 48]);
    let boot = runtime(&db)?;
    let driver = Arc::new(WaitingDriver::default());
    let method = operation_method(&boot, driver.clone(), true)?;
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 32)?;
    let bridge = FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
    bridge
        .invoke(
            InvokeCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                origin_request_id: request.origin_request_id,
                call,
                input: Arc::from(b"input".as_slice()),
            },
            now_ms()?,
        )
        .await?;
    wait_until(|| driver.entered.load(Ordering::SeqCst)).await?;
    bridge
        .cancel(
            CancelCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                control_request_id: RequestId::from_bytes([33; 16]),
                call,
                expected_control_revision: None,
            },
            now_ms()?,
        )
        .await?;
    wait_stopped(bridge.store().as_ref(), call).await?;
    ensure!(driver.dropped.load(Ordering::SeqCst));
    let inspected = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspected.cancellation_requested && inspected.kernel_cancel_accepted);
    ensure!(!inspected.result.context("cancelled terminal")?.succeeded);
    let operation = driver
        .operation
        .lock()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .context("dispatched operation")?;
    ensure!(
        inspected.unresolved_effect_ids
            == vec![<[u8; 32]>::from(Sha256::digest(
                operation.to_string().as_bytes()
            ))]
    );
    bridge.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn live_deadline_stops_driver_and_retains_original_effect_identity() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([70; 48]);
    let peer = FederationNodeId::from_bytes([71; 48]);
    let boot = runtime(&db)?;
    let driver = Arc::new(WaitingDriver::default());
    let terminal = Arc::new(TerminalObserver::default());
    let mut method = operation_method(&boot, driver.clone(), true)?;
    Arc::get_mut(&mut method).context("unique method")?.codec = terminal.clone();
    let store = Arc::new(db.federation_store(node)?);
    authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 72)?;
    let bridge = FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    ensure!(bridge.invoke(invoke.clone(), now_ms()?).await?.status == CallStatus::Accepted);
    wait_until(|| driver.entered.load(Ordering::SeqCst)).await?;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::time::resume();
    wait_stopped(bridge.store().as_ref(), call).await?;
    ensure!(driver.dropped.load(Ordering::SeqCst));
    let inspected = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspected.status == CallStatus::Finished);
    ensure!(!inspected.cancellation_requested && !inspected.kernel_cancel_accepted);
    let result = inspected.result.context("deadline terminal")?;
    ensure!(!result.succeeded);
    ensure!(matches!(
        terminal.0.lock().map_err(|error| anyhow::anyhow!(error.to_string()))?.as_ref(),
        Some(xolotl_types::Outcome::Fail(xolotl_types::Failure::OutcomeUnknown { reason, .. }))
            if reason == "deadline_exceeded"
    ));
    let operation = driver
        .operation
        .lock()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .context("dispatched operation")?;
    ensure!(
        inspected.unresolved_effect_ids
            == vec![<[u8; 32]>::from(Sha256::digest(
                operation.to_string().as_bytes()
            ))]
    );
    ensure!(bridge.invoke(invoke, now_ms()?).await?.status == CallStatus::Finished);
    bridge.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn local_grants_are_required_and_unknown_effects_keep_identity() -> Result<()> {
    for granted in [false, true] {
        let dir = tempfile::tempdir()?;
        let db = RedbStore::open(dir.path().join("federation.redb"))?;
        let node = FederationNodeId::from_bytes([40; 48]);
        let peer = FederationNodeId::from_bytes([41; 48]);
        let boot = runtime(&db)?;
        let driver = Arc::new(WaitingDriver {
            unknown: true,
            ..WaitingDriver::default()
        });
        let method = operation_method(&boot, driver.clone(), granted)?;
        let store = Arc::new(db.federation_store(node)?);
        authorize_call(store.as_ref(), peer, &method.target, now_ms()?)?;
        let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now_ms()?, 42)?;
        let bridge =
            FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
        bridge
            .invoke(
                InvokeCallRequest {
                    authenticated_origin: peer,
                    subject: FederationSubject::Node(peer),
                    origin_request_id: request.origin_request_id,
                    call,
                    input: Arc::from(b"input".as_slice()),
                },
                now_ms()?,
            )
            .await?;
        wait_stopped(bridge.store().as_ref(), call).await?;
        let inspected = store.inspect_call(
            InspectCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                call,
            },
            now_ms()?,
        )?;
        ensure!(!inspected.result.context("failure result")?.succeeded);
        ensure!(driver.entered.load(Ordering::SeqCst) == granted);
        ensure!(inspected.unresolved_effect_ids.len() == usize::from(granted));
        bridge.shutdown().await;
    }
    Ok(())
}

struct Catalog(Arc<FederationKernelMethod>);

impl FederationKernelCatalog for Catalog {
    fn resolve(&self, target: &CallTarget) -> Result<Arc<FederationKernelMethod>, FederationError> {
        if target != &self.0.target {
            return Err(FederationError::NotFound);
        }
        Ok(Arc::clone(&self.0))
    }
}

fn method() -> Result<Arc<FederationKernelMethod>> {
    method_with_codec(Arc::new(BytesCallCodec))
}

fn method_with_codec(codec: Arc<dyn FederationCallCodec>) -> Result<Arc<FederationKernelMethod>> {
    let program = Program::new(Expression::Input);
    Ok(Arc::new(FederationKernelMethod {
        target: CallTarget {
            export: ExportName::new("tools")?,
            path: CallPath::new("/echo")?,
            method: CallMethod::new("echo")?,
            contract_digest: [7; 32],
        },
        program: PreparedProgram::new(&program.compile()?)?,
        identity: IdentityRef::ROOT,
        grants: Vec::new(),
        codec,
    }))
}

fn runtime(db: &RedbStore) -> Result<Arc<Bootstrap>> {
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(db.state_backend().into_backend())
            .with_fact_sink(FactSink::new(Arc::new(db.fact_store()?)))
            .build(),
    ));
    Ok(boot)
}

fn authorize_call<S: FederationStore + FederationCallStore>(
    store: &S,
    peer: FederationNodeId,
    target: &CallTarget,
    now: u64,
) -> Result<()> {
    store.set_peer_authority(peer, None, true)?;
    store.set_export_authority(
        peer,
        target.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
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
    Ok(())
}

fn prepared(
    store: &impl FederationCallStore,
    peer: FederationNodeId,
    target: CallTarget,
    now: u64,
    id: u8,
) -> Result<(PrepareCallRequest, xolotl_federation::CallRef)> {
    prepared_with_deadlines(store, peer, target, now, id, 30_000, 60_000)
}

fn prepared_with_deadlines(
    store: &impl FederationCallStore,
    peer: FederationNodeId,
    target: CallTarget,
    now: u64,
    id: u8,
    prepare_after_ms: u64,
    execute_after_ms: u64,
) -> Result<(PrepareCallRequest, xolotl_federation::CallRef)> {
    let request = PrepareCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: RequestId::from_bytes([id; 16]),
        target,
        input_digest: Digest::from_bytes(Sha384::digest(b"input").into()),
        input_bytes: 5,
        prepare_deadline_ms: now + prepare_after_ms,
        execution_deadline_ms: now + execute_after_ms,
        result_retention_ms: 30_000,
    };
    let call = store.prepare_call(request.clone(), now)?.call;
    Ok((request, call))
}

async fn finished(
    store: &(impl FederationCallStore + ?Sized),
    request: &PrepareCallRequest,
    call: xolotl_federation::CallRef,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let now = now_ms()?;
            let inspection = store.inspect_call(
                InspectCallRequest {
                    authenticated_origin: request.authenticated_origin,
                    subject: request.subject.clone(),
                    call,
                },
                now,
            )?;
            if inspection.status == CallStatus::Finished && inspection.execution_stopped {
                ensure!(
                    inspection
                        .result
                        .as_ref()
                        .is_some_and(|result| result.output.as_ref() == b"input")
                );
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

#[tokio::test(flavor = "multi_thread")]
async fn prepare_requires_an_exact_method_before_call_ref_allocation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([19; 48]);
    let peer = FederationNodeId::from_bytes([20; 48]);
    let store = Arc::new(db.federation_store(node)?);
    let boot = runtime(&db)?;
    let implementation = method()?;
    let now = now_ms()?;
    let mut request = PrepareCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: RequestId::from_bytes([21; 16]),
        target: implementation.target.clone(),
        input_digest: Digest::from_bytes(Sha384::digest(b"input").into()),
        input_bytes: 5,
        prepare_deadline_ms: now + 30_000,
        execution_deadline_ms: now + 60_000,
        result_retention_ms: 30_000,
    };
    let bridge = FederationKernelCallBridge::new(boot, store, Arc::new(Catalog(implementation)))?;
    bridge.validate_prepare(&request)?;
    request.target.contract_digest = [8; 32];
    ensure!(matches!(
        bridge.validate_prepare(&request),
        Err(FederationError::NotFound)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_redb_bridge_samples_terminal_time_after_queued_publication() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("publication-clock.redb"))?;
    let node = FederationNodeId::from_bytes([90; 48]);
    let peer = FederationNodeId::from_bytes([91; 48]);
    let (release, wait) = std::sync::mpsc::channel();
    let gate = Arc::new(PublicationGate {
        inner: xolotl_kernel::host::TokioBlockingSpawner::default(),
        queued: AtomicBool::new(false),
        entered: AtomicBool::new(false),
        release: Mutex::new(Some(wait)),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(db.state_backend().into_backend())
            .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                gate.clone(),
            ))
            .build(),
    ));
    let mut method = method()?;
    Arc::get_mut(&mut method).context("unique method")?.codec = gate.clone();
    let store = Arc::new(db.federation_store(node)?);
    let now = now_ms()?;
    authorize_call(store.as_ref(), peer, &method.target, now)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now, 92)?;
    let bridge = FederationKernelCallBridge::new(boot, store.clone(), Arc::new(Catalog(method)))?;
    let accepted = bridge
        .invoke(
            InvokeCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                origin_request_id: request.origin_request_id,
                call,
                input: Arc::from(b"input".as_slice()),
            },
            now_ms()?,
        )
        .await?;
    ensure!(accepted.status == CallStatus::Accepted);
    wait_until(|| gate.entered.load(Ordering::SeqCst)).await?;
    let queued_at = now_ms()?;
    wait_until(|| now_ms().is_ok_and(|now| now > queued_at)).await?;
    store.checked_time_ms(now_ms()?)?;
    release.send(())?;
    finished(bridge.store().as_ref(), &request, call).await?;
    ensure!(store.scan_pending_kernel_calls(None, 8)?.is_empty());
    bridge.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn call_acceptance_executes_once_and_publishes_durable_result() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let method = method()?;
    let store = Arc::new(db.federation_store(node)?);
    let now = now_ms()?;
    authorize_call(store.as_ref(), peer, &method.target, now)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now, 3)?;
    let bridge =
        FederationKernelCallBridge::new(runtime(&db)?, store.clone(), Arc::new(Catalog(method)))?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    let first = bridge
        .invoke(invoke.clone(), now_ms()?)
        .await
        .context("initial invoke")?;
    ensure!(first.status == CallStatus::Accepted);
    finished(bridge.store().as_ref(), &request, call)
        .await
        .context("terminal publication")?;
    let binding = store.kernel_call(call, now_ms()?)?.binding;
    let repeated = bridge
        .invoke(invoke, now_ms()?)
        .await
        .context("repeat invoke")?;
    ensure!(repeated.status == CallStatus::Finished);
    ensure!(store.kernel_call(call, now_ms()?)?.binding == binding);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bound_call_without_live_owner_is_never_replayed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("federation.redb");
    let db = RedbStore::open(&path)?;
    let node = FederationNodeId::from_bytes([3; 48]);
    let peer = FederationNodeId::from_bytes([4; 48]);
    let method = method()?;
    let store = Arc::new(db.federation_store(node)?);
    let now = now_ms()?;
    authorize_call(store.as_ref(), peer, &method.target, now)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now, 5)?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    };
    store.invoke_call(invoke.clone(), now_ms()?)?;
    let old = CallKernelBinding {
        process: 10,
        lifecycle: 10,
    };
    store.bind_kernel_identity(call, old, now_ms()?)?;
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = Arc::new(db.federation_store(node)?);
    let bridge =
        FederationKernelCallBridge::new(runtime(&db)?, store.clone(), Arc::new(Catalog(method)))?;
    let repeated = bridge.invoke(invoke, now_ms()?).await?;
    ensure!(repeated.status == CallStatus::Preparing);
    let view = store.kernel_call(call, now_ms()?)?;
    ensure!(view.binding == Some(old) && view.accepted_digest.is_none());
    let inspected = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspected.result.is_none() && !inspected.execution_stopped);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_before_kernel_binding_closes_without_execution() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([5; 48]);
    let peer = FederationNodeId::from_bytes([6; 48]);
    let method = method()?;
    let store = Arc::new(db.federation_store(node)?);
    let now = now_ms()?;
    authorize_call(store.as_ref(), peer, &method.target, now)?;
    let (request, call) = prepared(store.as_ref(), peer, method.target.clone(), now, 8)?;
    store.invoke_call(
        InvokeCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            origin_request_id: request.origin_request_id,
            call,
            input: Arc::from(b"input".as_slice()),
        },
        now_ms()?,
    )?;
    let bridge =
        FederationKernelCallBridge::new(runtime(&db)?, store.clone(), Arc::new(Catalog(method)))?;
    let cancel = CancelCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        control_request_id: RequestId::from_bytes([9; 16]),
        call,
        expected_control_revision: None,
    };
    let receipt = bridge.cancel(cancel.clone(), now_ms()?).await?;
    ensure!(receipt.status == CallStatus::Preparing && receipt.cancellation_requested);
    ensure!(bridge.cancel(cancel, now_ms()?).await? == receipt);
    let inspection = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspection.status == CallStatus::Closed && inspection.execution_stopped);
    ensure!(inspection.result.is_none());
    ensure!(store.kernel_call(call, now_ms()?)?.binding.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_preparing_call_closes_without_kernel_submission() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let node = FederationNodeId::from_bytes([16; 48]);
    let peer = FederationNodeId::from_bytes([17; 48]);
    let method = method()?;
    let store = Arc::new(db.federation_store(node)?);
    let now = now_ms()?;
    authorize_call(store.as_ref(), peer, &method.target, now)?;
    let (request, call) = prepared_with_deadlines(
        store.as_ref(),
        peer,
        method.target.clone(),
        now,
        18,
        500,
        500,
    )?;
    store.invoke_call(
        InvokeCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            origin_request_id: request.origin_request_id,
            call,
            input: Arc::from(b"input".as_slice()),
        },
        now_ms()?,
    )?;
    tokio::time::sleep(Duration::from_millis(550)).await;
    let bridge =
        FederationKernelCallBridge::new(runtime(&db)?, store.clone(), Arc::new(Catalog(method)))?;
    bridge
        .invoke(
            InvokeCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                origin_request_id: request.origin_request_id,
                call,
                input: Arc::from(b"input".as_slice()),
            },
            now_ms()?,
        )
        .await?;
    let inspection = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call,
        },
        now_ms()?,
    )?;
    ensure!(inspection.status == CallStatus::Closed);
    ensure!(!inspection.cancellation_requested && inspection.execution_stopped);
    ensure!(inspection.result.is_none());
    ensure!(store.kernel_call(call, now_ms()?)?.binding.is_none());
    ensure!(store.scan_pending_kernel_calls(None, 8)?.is_empty());
    Ok(())
}
