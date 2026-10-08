use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use xolotl_kernel::host::{
    AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
};
use xolotl_kernel::{EchoDriver, KernelBuilder, MethodSpec};
use xolotl_types::{MethodAuthority, Purity, TaintSource, TaintedValue};

struct ManualClock {
    base: Instant,
    wall_ms: AtomicI64,
    monotonic_ms: AtomicU64,
    changed: watch::Sender<()>,
}

impl ManualClock {
    fn new(wall_ms: i64) -> Self {
        let (changed, _) = watch::channel(());
        Self {
            base: Instant::now(),
            wall_ms: AtomicI64::new(wall_ms),
            monotonic_ms: AtomicU64::new(0),
            changed,
        }
    }

    fn advance(&self, millis: u64) {
        self.monotonic_ms.fetch_add(millis, Ordering::SeqCst);
        self.wall_ms.fetch_add(millis as i64, Ordering::SeqCst);
        self.changed.send_replace(());
    }

    fn rewind_wall(&self, millis: i64) {
        self.wall_ms.fetch_sub(millis, Ordering::SeqCst);
        self.changed.send_replace(());
    }
}

impl HostClock for ManualClock {
    fn monotonic_now(&self) -> Instant {
        self.base + Duration::from_millis(self.monotonic_ms.load(Ordering::SeqCst))
    }

    fn unix_millis(&self) -> i64 {
        self.wall_ms.load(Ordering::SeqCst)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let mut changes = self.changed.subscribe();
            while self.monotonic_now() < deadline {
                if changes.changed().await.is_err() {
                    break;
                }
            }
        })
    }
}

struct TokioTask(tokio::task::AbortHandle);

impl AbortTask for TokioTask {
    fn abort(&self) {
        self.0.abort();
    }
}

struct TokioSpawner(tokio::runtime::Handle);

impl TaskSpawner for TokioSpawner {
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        let task = self.0.spawn(future);
        Ok(Arc::new(TokioTask(task.abort_handle())))
    }
}

async fn fixture() -> anyhow::Result<(Fixture, Arc<ManualClock>)> {
    let clock = Arc::new(ManualClock::new(1_000));
    let runtime = HostRuntime::new(
        clock.clone(),
        Arc::new(TokioSpawner(tokio::runtime::Handle::current())),
        Arc::new(TokioBlockingSpawner::default()),
    );
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    let fixture = Fixture::with_boot(
        boot,
        MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        ),
        Arc::new(EchoDriver),
    )
    .await?;
    Ok((fixture, clock))
}

async fn wait_for_removal(
    state: &xolotl_state::Backend,
    path: &xolotl_types::Path,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.read(path).await?.is_none() {
                break Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn installed_clock_expires_and_maintains_upload_tickets() -> anyhow::Result<()> {
    let (fixture, clock) = fixture().await?;
    let ticket = fixture.issue(false).await?;
    ensure!(ticket.expires_at_ms() == 61_000);
    let path = upload_ticket_path(ticket.ticket_id())?;
    clock.advance(60_001);
    ensure!(fixture.begin(&ticket, None).await.is_err());
    wait_for_removal(fixture.boot.kernel().state(), &path).await?;
    Ok(())
}

#[tokio::test]
async fn read_grant_monotonic_cap_survives_wall_rewind_and_cleanup_uses_host_time()
-> anyhow::Result<()> {
    let (fixture, clock) = fixture().await?;
    let metadata = fixture
        .seed(b"clock", "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            IssueObjectReadGrantRequest {
                surface_id: "echo".into(),
                object: TaintedValue::pristine(Value::blob(metadata.blob)),
                offset: 0,
                length: None,
                expires_in_ms: Some(1_000),
            },
        )
        .await?;
    ensure!(grant.expires_at_ms() == 2_000);
    let read = fixture
        .gateway
        .open_object_read(
            &fixture.session,
            OpenObjectReadRequest {
                grant_id: grant.grant_id().into(),
                offset: 0,
                length: None,
            },
        )
        .await?;
    let path = read_grant::read_grant_path(grant.grant_id())?;
    clock.advance(1_001);
    clock.rewind_wall(1_001);
    ensure!(read.validate().is_err());
    ensure!(fixture.boot.kernel().state().read(&path).await?.is_some());
    clock.advance(4_001);
    wait_for_removal(fixture.boot.kernel().state(), &path).await?;
    Ok(())
}

#[tokio::test]
async fn expired_read_grant_maintenance_is_bounded_and_restartable() -> anyhow::Result<()> {
    let (fixture, clock) = fixture().await?;
    let metadata = fixture
        .seed(b"page", "text/plain", TaintSet::pristine())
        .await?;
    for _ in 0..17 {
        fixture
            .gateway
            .issue_object_read_grant(
                &fixture.session,
                IssueObjectReadGrantRequest {
                    surface_id: "echo".into(),
                    object: TaintedValue::pristine(Value::blob(metadata.blob.clone())),
                    offset: 0,
                    length: None,
                    expires_in_ms: Some(1_000),
                },
            )
            .await?;
    }
    clock.advance(1_001);
    let mut cursor = None;
    let first = maintain_read_grants_once(&fixture.boot, &mut cursor).await?;
    ensure!(first.examined == 16 && first.removed == 16 && cursor.is_some());
    let second = maintain_read_grants_once(&fixture.boot, &mut cursor).await?;
    ensure!(second.examined == 1 && second.removed == 1 && cursor.is_none());
    Ok(())
}

#[tokio::test]
async fn read_grant_cleanup_does_not_delete_concurrent_replacement() -> anyhow::Result<()> {
    let (fixture, clock) = fixture().await?;
    let metadata = fixture
        .seed(b"cas", "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            IssueObjectReadGrantRequest {
                surface_id: "echo".into(),
                object: TaintedValue::pristine(Value::blob(metadata.blob)),
                offset: 0,
                length: None,
                expires_in_ms: Some(1_000),
            },
        )
        .await?;
    let path = read_grant::read_grant_path(grant.grant_id())?;
    let state = fixture.boot.kernel().state();
    let stale = state.read_tainted(&path).await?;
    let stale_value = stale.value.clone().context("missing grant")?;
    clock.advance(1_001);
    let replacement = Value::string("replacement".into());
    state.write_set(&path, replacement.clone()).await?;
    ensure!(
        !read_grant::maintenance::prune_read_grant_entry(
            state,
            &path,
            xolotl_types::TaintedValue::new(stale_value, stale.taint),
            clock.unix_millis()
        )
        .await?
    );
    ensure!(state.read(&path).await? == Some(replacement));
    Ok(())
}

#[tokio::test]
async fn issued_read_grants_fit_the_maintenance_page_budget() -> anyhow::Result<()> {
    let (fixture, _) = fixture().await?;
    let metadata = fixture
        .seed(b"cap", "text/plain", TaintSet::pristine())
        .await?;
    let taint = TaintSet::of(TaintSource::Inbound {
        source: "x".repeat(maintenance::PAGE_BYTES).into(),
        channel: "large-test".into(),
    });
    let result = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            IssueObjectReadGrantRequest {
                surface_id: "echo".into(),
                object: TaintedValue::new(Value::blob(metadata.blob), taint),
                offset: 0,
                length: None,
                expires_in_ms: Some(1_000),
            },
        )
        .await;
    ensure!(
        matches!(result, Err(GatewayError::Rejected(message)) if message.contains("maintenance page budget"))
    );
    let prefix = crate::paths::gateway_state_path(&["object-read-grant"])?;
    let page = fixture
        .boot
        .kernel()
        .state()
        .query(&xolotl_state::StateScan::new(prefix))
        .await?;
    ensure!(page.entries.is_empty());
    Ok(())
}
