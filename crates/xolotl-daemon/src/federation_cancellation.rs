//! Source-side retry of persisted business call cancellation controls.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use xolotl_federation::{
    CallPrepared, CallStatus, CancelCallRequest, FederationNodeId,
    FederationOutboundCallStore as _, OutboundCallRecord, PrepareCallRequest, RequestId,
};
use xolotl_federation_grpc::FederationCallSessionProvider;
use xolotl_kernel::host::HostRuntime;
use xolotl_storage_redb::RedbFederationStore;

const SOURCE_PAGE: usize = 32;
const WIRE_TIMEOUT: Duration = Duration::from_secs(15);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

enum ControlWork {
    None,
    Cancel(Option<Box<CancelCallRequest>>),
    Inspect,
}

pub(crate) struct SourceControl {
    target_node: FederationNodeId,
    request: PrepareCallRequest,
    prepared: Option<CallPrepared>,
    work: ControlWork,
}

impl From<OutboundCallRecord> for SourceControl {
    fn from(record: OutboundCallRecord) -> Self {
        let work = if record.terminal.is_some() || !record.cancellation_requested {
            ControlWork::None
        } else if record.cancel_acknowledged.is_some() {
            ControlWork::Inspect
        } else {
            ControlWork::Cancel(record.cancel_request().map(Box::new))
        };
        Self {
            target_node: record.intent.target_node,
            request: record.intent.request,
            prepared: record.prepared,
            work,
        }
    }
}

/// Recover accepted controls independently of the Kernel operation that may
/// already have reached a terminal status. Each pass is a bounded keyset page.
pub(crate) fn start_remote_retries(
    runtime: HostRuntime,
    source: RedbFederationStore,
    sessions: Arc<dyn FederationCallSessionProvider>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut pending_after = None;
        let mut unsettled_after = None;
        loop {
            match pending_page(&runtime, source.clone(), pending_after).await {
                Ok(page) => {
                    pending_after = page.last().map(|row| row.request.origin_request_id);
                    if page.is_empty() {
                        pending_after = None;
                    }
                    for row in page {
                        if let Err(error) =
                            retry_cancellation(&runtime, &source, sessions.as_ref(), row).await
                        {
                            tracing::warn!(%error, "federation remote cancellation deferred");
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "federation cancellation source scan failed"),
            }
            match unsettled_page(&runtime, source.clone(), unsettled_after).await {
                Ok(page) => {
                    unsettled_after = page.last().map(|row| row.request.origin_request_id);
                    if page.is_empty() {
                        unsettled_after = None;
                    }
                    for row in page {
                        if matches!(row.work, ControlWork::Inspect)
                            && let Err(error) =
                                inspect_cancelled(&source, sessions.as_ref(), row).await
                        {
                            tracing::warn!(%error, "federation cancelled call inspection deferred");
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "federation unsettled call scan failed"),
            }
            tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        }
    })
}

async fn pending_page(
    runtime: &HostRuntime,
    source: RedbFederationStore,
    after: Option<RequestId>,
) -> Result<Vec<SourceControl>> {
    runtime
        .dispatch_blocking(move || {
            source
                .pending_outbound_cancellations(after, SOURCE_PAGE)
                .map(|page| page.into_iter().map(SourceControl::from).collect())
        })?
        .await
        .context("federation cancellation read worker failed")?
        .map_err(Into::into)
}

async fn unsettled_page(
    runtime: &HostRuntime,
    source: RedbFederationStore,
    after: Option<RequestId>,
) -> Result<Vec<SourceControl>> {
    runtime
        .dispatch_blocking(move || {
            source
                .unsettled_outbound(after, SOURCE_PAGE)
                .map(|page| page.into_iter().map(SourceControl::from).collect())
        })?
        .await
        .context("federation unsettled read worker failed")?
        .map_err(Into::into)
}

pub(crate) async fn retry_cancellation(
    runtime: &HostRuntime,
    source: &RedbFederationStore,
    sessions: &dyn FederationCallSessionProvider,
    mut row: SourceControl,
) -> Result<()> {
    if !matches!(row.work, ControlWork::Cancel(_)) {
        return Ok(());
    }
    let id = row.request.origin_request_id;
    let target = row.target_node;
    // Session acquisition includes Hosted RegisterSubject. Its own bounded
    // response timeout may exceed WIRE_TIMEOUT; dropping that registration
    // midway could leave the peer context accepted but locally unobserved.
    let session = sessions
        .session(target, &row.request.subject)
        .await
        .context("federation cancellation Session unavailable")?;
    let client = &session.client;
    let context_id = session.context_id;
    if row.prepared.is_none() {
        // The source cancellation barrier forbids restaging this call. Ask the
        // target about the original Prepare ID, then persist its CallRef. No
        // Invoke is permitted after cancellation was requested.
        let prepared = tokio::time::timeout(
            WIRE_TIMEOUT,
            client.prepare_call_as(context_id, row.request.clone()),
        )
        .await
        .context("cancelled call Prepare reconciliation timed out")?
        .context("cancelled call Prepare reconciliation failed")?;
        let source = source.clone();
        row = runtime
            .dispatch_blocking(move || {
                source
                    .bind_outbound_prepared(id, prepared)
                    .map(SourceControl::from)
            })?
            .await
            .context("cancelled call Prepare binding worker failed")??;
    }
    let ControlWork::Cancel(request) = row.work else {
        return Ok(());
    };
    if let Some(request) = request {
        let response =
            tokio::time::timeout(WIRE_TIMEOUT, client.cancel_call_as(context_id, *request))
                .await
                .context("remote CancelCall timed out")?
                .context("remote CancelCall failed")?;
        let source = source.clone();
        runtime
            .dispatch_blocking(move || {
                source
                    .record_outbound_cancellation(id, response)
                    .map(|_record| ())
            })?
            .await
            .context("remote CancelCall receipt worker failed")??;
    } else if row
        .prepared
        .as_ref()
        .is_some_and(|receipt| receipt.status == CallStatus::Closed)
    {
        tokio::time::timeout(
            WIRE_TIMEOUT,
            client.inspect_call_persisted(context_id, id, Arc::new(source.clone())),
        )
        .await
        .context("closed cancelled call inspection timed out")?
        .context("closed cancelled call inspection failed")?;
    }
    Ok(())
}

async fn inspect_cancelled(
    source: &RedbFederationStore,
    sessions: &dyn FederationCallSessionProvider,
    row: SourceControl,
) -> Result<()> {
    let session = sessions
        .session(row.target_node, &row.request.subject)
        .await
        .context("cancelled call inspection Session unavailable")?;
    tokio::time::timeout(
        WIRE_TIMEOUT,
        session.client.inspect_call_persisted(
            session.context_id,
            row.request.origin_request_id,
            Arc::new(source.clone()),
        ),
    )
    .await
    .context("cancelled call inspection timed out")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    use anyhow::ensure;
    use async_trait::async_trait;
    use sha2::{Digest as _, Sha384};
    use xolotl_federation::{
        CallCancelled, CallInspection, CallMethod, CallPath, CallRef, CallTarget, Digest,
        ExportName, FederationSubject, HostedSubject, OutboundCallIntent, PersistedCallResult,
        PrepareCallRequest, SubjectIssuerId,
    };
    use xolotl_federation_grpc::FederationCallSession;
    use xolotl_kernel::driver::DriverError;
    use xolotl_kernel::host::{
        BlockingJob, BlockingSpawnError, BlockingSpawner, TokioBlockingSpawner,
    };

    struct WorkGate {
        entered: tokio::sync::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    struct GatedHost {
        inner: Arc<TokioBlockingSpawner>,
        gate: Mutex<Option<WorkGate>>,
        completed: Arc<AtomicBool>,
    }

    impl BlockingSpawner for GatedHost {
        fn spawn(&self, job: BlockingJob) -> std::result::Result<(), BlockingSpawnError> {
            let gate = self
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let completed = Arc::clone(&self.completed);
            self.inner.spawn(Box::new(move || {
                if let Some(gate) = gate {
                    let _entered = gate.entered.send(());
                    let _released = gate.release.recv_timeout(Duration::from_secs(5));
                }
                job();
                completed.store(true, Ordering::Release);
            }))
        }
    }

    #[tokio::test]
    async fn cancellation_source_work_uses_host_admission_and_outlives_its_waiter() -> Result<()> {
        use std::future::Future as _;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.redb");
        let database = xolotl_storage_redb::RedbStore::open(&path)?;
        let local = xolotl_federation::FederationNodeId::from_bytes([9; 48]);
        let source = database.federation_store(local)?;
        let blocking = Arc::new(TokioBlockingSpawner::new(1)?);
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let runtime = HostRuntime::tokio_with_blocking(Arc::new(GatedHost {
            inner: Arc::clone(&blocking),
            gate: Mutex::new(Some(WorkGate {
                entered,
                release: gate,
            })),
            completed: Arc::clone(&completed),
        }));
        let mut read = Box::pin(pending_page(&runtime, source, None));
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(read.as_mut().poll(context)))
                .await
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .context("cancellation source work bypassed host admission")??;
        drop(read);
        drop(database);
        blocking.close();
        let mut idle = std::pin::pin!(blocking.wait_idle());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(idle.as_mut().poll(context)))
                .await
                .is_pending()
        );
        ensure!(xolotl_storage_redb::RedbStore::open(&path).is_err());
        ensure!(!completed.load(Ordering::Acquire));
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), idle).await?;
        ensure!(completed.load(Ordering::Acquire));
        let reopened = xolotl_storage_redb::RedbStore::open(&path)?;
        let rejected = pending_page(&runtime, reopened.federation_store(local)?, None).await;
        ensure!(
            rejected
                .err()
                .and_then(|error| error.downcast::<BlockingSpawnError>().ok())
                == Some(BlockingSpawnError::Unavailable)
        );
        Ok(())
    }

    struct DelayedHostedRegistration {
        subject: FederationSubject,
        completed: AtomicBool,
        input: std::sync::Weak<[u8]>,
    }

    #[test]
    fn control_projection_preserves_directive_and_releases_input_and_terminal_bytes() -> Result<()>
    {
        #[derive(Clone, Copy)]
        enum Scenario {
            Pending,
            Unprepared,
            Accepted,
            Settled,
            Uncancelled,
        }
        let local = FederationNodeId::from_bytes([1; 48]);
        let peer = FederationNodeId::from_bytes([2; 48]);
        let request_id = RequestId::from_bytes([3; 16]);
        let call = CallRef::new(peer, [4; 32])?;
        for scenario in [
            Scenario::Pending,
            Scenario::Unprepared,
            Scenario::Accepted,
            Scenario::Settled,
            Scenario::Uncancelled,
        ] {
            let input: Arc<[u8]> = Arc::from(b"input".as_slice());
            let weak_input = Arc::downgrade(&input);
            let mut record = OutboundCallRecord {
                intent: OutboundCallIntent {
                    target_node: peer,
                    request: PrepareCallRequest {
                        authenticated_origin: local,
                        subject: FederationSubject::Node(local),
                        origin_request_id: request_id,
                        target: CallTarget {
                            export: ExportName::new("tools")?,
                            path: CallPath::new("/echo")?,
                            method: CallMethod::new("echo")?,
                            contract_digest: [5; 32],
                        },
                        input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                        input_bytes: input.len() as u64,
                        prepare_deadline_ms: 200,
                        execution_deadline_ms: 800,
                        result_retention_ms: 300,
                    },
                    input,
                },
                prepared: if matches!(scenario, Scenario::Unprepared) {
                    None
                } else {
                    Some(CallPrepared {
                        origin_request_id: request_id,
                        call,
                        status: CallStatus::Reserved,
                        reserved_until_ms: 200,
                        execution_deadline_ms: 800,
                        result_retention_ms: 300,
                        authority_revision: 1,
                        control_revision: 1,
                    })
                },
                invoke_possible: !matches!(scenario, Scenario::Unprepared),
                terminal: None,
                cancellation_requested: !matches!(scenario, Scenario::Uncancelled),
                cancel_acknowledged: None,
            };
            record.intent.validate(local, 100)?;
            if matches!(scenario, Scenario::Accepted) {
                let cancel = record
                    .cancel_request()
                    .context("missing stable cancellation")?;
                record.record_cancellation(CallCancelled {
                    control_request_id: cancel.control_request_id,
                    call,
                    status: CallStatus::Closed,
                    control_revision: 2,
                    cancellation_requested: true,
                    kernel_cancel_accepted: false,
                    execution_stopped: true,
                })?;
            }
            let weak_output = if matches!(scenario, Scenario::Settled) {
                let output: Arc<[u8]> = Arc::from(b"done".as_slice());
                let weak = Arc::downgrade(&output);
                record.settle(CallInspection {
                    call,
                    status: CallStatus::Finished,
                    control_revision: 2,
                    authority_revision: 1,
                    reserved_until_ms: 200,
                    execution_deadline_ms: 800,
                    result_retained_until_ms: 500,
                    result: Some(PersistedCallResult::new(true, output, None)?),
                    unresolved_effect_ids: Vec::new(),
                    cancellation_requested: true,
                    kernel_cancel_accepted: false,
                    execution_stopped: true,
                })?;
                Some(weak)
            } else {
                None
            };
            let expected = record.cancel_request();
            let projected = SourceControl::from(record);
            ensure!(weak_input.upgrade().is_none());
            ensure!(
                projected.target_node == peer
                    && projected.request.origin_request_id == request_id
                    && projected.request.input_bytes == 5
            );
            match scenario {
                Scenario::Pending | Scenario::Unprepared => {
                    let ControlWork::Cancel(request) = projected.work else {
                        anyhow::bail!("cancellation lost its directive")
                    };
                    ensure!(request.as_deref() == expected.as_ref());
                }
                Scenario::Accepted => ensure!(matches!(projected.work, ControlWork::Inspect)),
                Scenario::Settled | Scenario::Uncancelled => {
                    ensure!(matches!(projected.work, ControlWork::None))
                }
            }
            if let Some(output) = weak_output {
                ensure!(output.upgrade().is_none());
            }
        }
        Ok(())
    }

    #[async_trait]
    impl FederationCallSessionProvider for DelayedHostedRegistration {
        async fn session(
            &self,
            _target: xolotl_federation::FederationNodeId,
            subject: &FederationSubject,
        ) -> std::result::Result<FederationCallSession, DriverError> {
            if self.input.upgrade().is_some() {
                return Err(DriverError::Transport(
                    "call input retained across Session acquisition".into(),
                ));
            }
            if subject != &self.subject {
                return Err(DriverError::Transport("subject downgraded".into()));
            }
            tokio::time::sleep(WIRE_TIMEOUT + Duration::from_secs(1)).await;
            self.completed.store(true, Ordering::SeqCst);
            Err(DriverError::Transport(
                "registration rejected after delay".into(),
            ))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_hosted_registration_is_not_cancelled_by_wire_timeout() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let local = xolotl_federation::FederationNodeId::from_bytes([1; 48]);
        let target = xolotl_federation::FederationNodeId::from_bytes([2; 48]);
        let store = xolotl_storage_redb::RedbStore::open(temp.path().join("calls.redb"))?
            .federation_store(local)?;
        let subject = FederationSubject::Hosted(HostedSubject {
            issuer: SubjectIssuerId::from_bytes([3; 48]),
            namespace: "people".into(),
            subject: "caller".into(),
        });
        let input: Arc<[u8]> = Arc::from(vec![29; xolotl_federation::MAX_CALL_INPUT_BYTES]);
        let delayed = DelayedHostedRegistration {
            subject: subject.clone(),
            completed: AtomicBool::new(false),
            input: Arc::downgrade(&input),
        };
        let row = OutboundCallRecord {
            intent: OutboundCallIntent {
                target_node: target,
                request: PrepareCallRequest {
                    authenticated_origin: local,
                    subject,
                    origin_request_id: RequestId::from_bytes([4; 16]),
                    target: CallTarget {
                        export: ExportName::new("tools")?,
                        path: CallPath::new("/echo")?,
                        method: CallMethod::new("echo")?,
                        contract_digest: [5; 32],
                    },
                    input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                    input_bytes: input.len() as u64,
                    prepare_deadline_ms: 1,
                    execution_deadline_ms: 2,
                    result_retention_ms: 1,
                },
                input,
            },
            prepared: None,
            invoke_possible: false,
            terminal: None,
            cancellation_requested: true,
            cancel_acknowledged: None,
        };
        ensure!(
            retry_cancellation(&HostRuntime::default(), &store, &delayed, row.into())
                .await
                .is_err()
        );
        ensure!(delayed.completed.load(Ordering::SeqCst));
        Ok(())
    }
}
