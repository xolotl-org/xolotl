use super::*;
use anyhow::ensure;
use serde_json::json;
use xolotl_gateway::{GatewayProfile, GatewayTransportSecurityConfig};
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_state::host::Backend;
use xolotl_state::{StateEvent, StateStream, StateSubscription, StateWatchError};
use xolotl_types::{Path, Value};

mod connections;
mod objects;
mod retry_epochs;
#[cfg(feature = "federation-grpc")]
mod shutdown;

struct Released(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for Released {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _sent = sender.send(());
        }
    }
}

fn config() -> XolotlConfig {
    let mut config = XolotlConfig::default();
    config.application_gateway.profile = Some("app".into());
    config
}

fn value(version: u64) -> Result<Value> {
    Ok(serde_json::from_value(json!({
        "profile_name": "app", "version": version
    }))?)
}

async fn until(mut predicate: impl FnMut() -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("condition did not become true")
}

#[test]
fn application_config_is_disabled_by_default_and_preserves_transport_windows() -> Result<()> {
    let config: XolotlConfig = toml::from_str("")?;
    ensure!(config.server.application_grpc_addr.is_none());
    ensure!(config.application_gateway.profile.is_none());
    ensure!(
        config
            .application_gateway
            .grpc
            .service_config(GatewayTransportSecurityConfig::default())
            == ApplicationGrpcConfig::default()
    );
    let config: XolotlConfig = toml::from_str(
        r#"
        [server]
        application_grpc_addr = "127.0.0.1:9445"
        [application_gateway]
        profile = "app"
        [application_gateway.grpc]
        max_frame_bytes = 4096
        max_concurrent_uploads = 1
        max_concurrent_output_responses = 2
        output_window_chunks = 3
        output_window_bytes = 8192
        first_frame_timeout_ms = 0
        "#,
    )?;
    let transport = config
        .application_gateway
        .grpc
        .service_config(GatewayTransportSecurityConfig::default());
    ensure!(transport.max_frame_bytes == 4096);
    ensure!(transport.max_concurrent_uploads == 1);
    ensure!(transport.max_concurrent_output_responses == 2);
    ensure!(transport.output_window_chunks == 3 && transport.output_window_bytes == 8192);
    let runtime = Arc::new(GatewayRuntime::new_manual(
        Arc::new(Bootstrap::in_memory()),
        GatewayProfile::closed("app"),
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )?);
    ensure!(ApplicationGrpcService::from_arc_with_config(runtime, transport).is_err());
    ensure!(profile::profile_path("**").is_err());
    ensure!(profile::profile_path("app/nested").is_err());
    Ok(())
}

#[tokio::test]
async fn disabled_application_does_not_require_state_or_objects() -> Result<()> {
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_sdk::KernelBuilder::new(Backend::new())
            .with_fact_sink(xolotl_sdk::FactSink::in_memory().0)
            .build(),
    ));
    let mut config = config();
    config.application_gateway.profile = Some("**".into());
    config.application_gateway.grpc.max_concurrent_uploads = 0;
    ensure!(
        ApplicationGateway::start_at(
            &config,
            None,
            boot,
            ObjectStore::new(),
            Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default())
        )
        .await?
        .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn enabled_application_requires_a_present_valid_resolvable_profile() -> Result<()> {
    let requests: Arc<dyn xolotl_gateway::GatewayIdempotencyStore> =
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default());
    let boot = Arc::new(Bootstrap::in_memory());
    let config = config();
    ensure!(
        ApplicationGateway::start_at(
            &config,
            Some("127.0.0.1:0"),
            boot.clone(),
            ObjectStore::new(),
            requests.clone()
        )
        .await
        .is_err()
    );
    let path = profile::profile_path("app")?;
    for invalid in [
        Value::null(),
        serde_json::from_value(json!({"profile_name": "other", "version": 1}))?,
        serde_json::from_value(json!({
            "profile_name": "app", "version": 1,
            "surfaces": [{"surface_id": "missing", "target": "effect://missing/invoke"}]
        }))?,
    ] {
        boot.kernel().state().write_set(&path, invalid).await?;
        ensure!(
            ApplicationGateway::start_at(
                &config,
                Some("127.0.0.1:0"),
                boot.clone(),
                ObjectStore::new(),
                requests.clone()
            )
            .await
            .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn application_bind_failure_is_reported_before_startup_returns() -> Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let address = occupied.local_addr()?.to_string();
    let result = ApplicationGateway::start_at(
        &config(),
        Some(&address),
        Arc::new(Bootstrap::in_memory()),
        ObjectStore::new(),
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )
    .await;
    let error = match result {
        Ok(_) => anyhow::bail!("occupied listener must fail startup"),
        Err(error) => error,
    };
    ensure!(error.to_string().contains("bind application gRPC listener"));
    Ok(())
}

#[tokio::test]
async fn cancelled_shutdown_keeps_tasks_owned_until_gateway_drop() -> Result<()> {
    use std::future::Future;
    use std::task::Poll;

    let boot = Arc::new(Bootstrap::in_memory());
    boot.kernel()
        .state()
        .write_set(&profile::profile_path("app")?, value(1)?)
        .await?;
    let mut application = ApplicationGateway::start_at(
        &config(),
        Some("127.0.0.1:0"),
        boot,
        ObjectStore::new(),
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )
    .await?
    .context("enabled application should start")?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (released, finished) = tokio::sync::oneshot::channel();
    let owned = Released(Some(released));
    let task = tokio::spawn(async move {
        let _owned = owned;
        let _sent = entered.send(());
        std::future::pending::<Result<()>>().await
    });
    let abort = task.abort_handle();
    application.tasks.push(task);
    ready.await?;
    let expected = application.tasks.len();
    let mut shutdown = Box::pin(application.shutdown());
    let pending = std::future::poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context)))
        .await
        .is_pending();
    drop(shutdown);
    let retained = application.tasks.len();
    let closed = *application.shutdown.borrow();
    drop(application);
    let mut finished = finished;
    let stopped = tokio::time::timeout(Duration::from_secs(1), &mut finished).await;
    let released_by_drop = matches!(stopped, Ok(Ok(())));
    if !released_by_drop {
        abort.abort();
        tokio::time::timeout(Duration::from_secs(5), finished).await??;
    }
    ensure!(
        pending && closed && retained == expected,
        "cancelled shutdown lost task ownership or left admission open"
    );
    ensure!(
        released_by_drop,
        "Gateway drop detached a task after shutdown cancellation"
    );
    Ok(())
}

#[tokio::test]
async fn application_listener_abort_drives_host_teardown_without_an_exit_signal() -> Result<()> {
    use crate::host_lifecycle::supervise_host;
    use xolotl_kernel::host::TokioBlockingSpawner;

    let boot = Arc::new(Bootstrap::in_memory());
    boot.kernel()
        .state()
        .write_set(&profile::profile_path("app")?, value(1)?)
        .await?;
    let application = ApplicationGateway::start_at(
        &config(),
        Some("127.0.0.1:0"),
        boot.clone(),
        ObjectStore::new(),
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )
    .await?
    .context("enabled application should start")?;
    let listener_abort = application.tasks[0].abort_handle();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let (released, mut finished) = tokio::sync::oneshot::channel();
    let owned = Released(Some(released));
    let producer = tokio::spawn(async move {
        let _owned = owned;
        let _sent = entered.send(());
        std::future::pending::<()>().await;
    });
    let producer_abort = producer.abort_handle();
    let blocking = TokioBlockingSpawner::default();
    let mut scope = tokio::spawn(async move {
        supervise_host(&boot, &blocking, async |services| {
            services.application = Some(application);
            services.background.push("live producer", producer);
            started.await?;
            let _sent = ready.send(());
            services
                .wait_for_shutdown(std::future::pending::<Result<()>>())
                .await
        })
        .await
    });
    waiting.await?;
    listener_abort.abort();
    let result = match tokio::time::timeout(Duration::from_secs(5), &mut scope).await {
        Ok(result) => Some(result?),
        Err(_) => {
            scope.abort();
            let _joined = scope.await;
            None
        }
    };
    let released_before_return = finished.try_recv().is_ok();
    if !released_before_return {
        producer_abort.abort();
        tokio::time::timeout(Duration::from_secs(5), finished).await??;
    }
    ensure!(
        result.is_some_and(|result| result.is_err_and(|error| {
            error
                .to_string()
                .contains("application Gateway task failed")
                && error
                    .downcast_ref::<tokio::task::JoinError>()
                    .is_some_and(tokio::task::JoinError::is_cancelled)
        })),
        "application listener abort did not reach the host"
    );
    ensure!(
        released_before_return,
        "host failure returned before its producer released ownership"
    );
    Ok(())
}

#[tokio::test]
async fn profile_delete_closes_listener_tasks_and_restart_fails() -> Result<()> {
    let requests: Arc<dyn xolotl_gateway::GatewayIdempotencyStore> =
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default());
    use std::task::Poll;
    let boot = Arc::new(Bootstrap::in_memory());
    let path = profile::profile_path("app")?;
    boot.kernel().state().write_set(&path, value(1)?).await?;
    let config = config();
    let mut application = ApplicationGateway::start_at(
        &config,
        Some("127.0.0.1:0"),
        boot.clone(),
        ObjectStore::new(),
        requests.clone(),
    )
    .await?
    .context("enabled application should start")?;
    boot.kernel().state().write_delete(&path).await?;
    until(|| application.tasks.iter().all(JoinHandle::is_finished)).await?;
    ensure!(*application.shutdown.borrow());
    ensure!(
        std::future::poll_fn(|context| Poll::Ready(application.poll_failure(context)))
            .await
            .is_pending(),
        "profile deletion was misclassified as a host failure"
    );
    application.shutdown().await;
    ensure!(
        ApplicationGateway::start_at(
            &config,
            Some("127.0.0.1:0"),
            boot,
            ObjectStore::new(),
            requests
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn profile_reload_is_monotonic_and_invalid_replacements_keep_last_good() -> Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let state = boot.kernel().state().clone();
    let path = profile::profile_path("app")?;
    let events = state.subscribe(&path).await?;
    state.write_set(&path, value(1)?).await?;
    let runtime = Arc::new(GatewayRuntime::new(
        boot,
        profile::load_profile(&state, &path, "app").await?,
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )?);
    let service = ApplicationGrpcService::from_arc_with_config(
        runtime.clone(),
        ApplicationGrpcConfig::default(),
    )?;
    let (shutdown, _) = watch::channel(false);
    let task = tokio::spawn(profile::watch_profile(
        state.clone(),
        path.clone(),
        "app".into(),
        events,
        runtime.clone(),
        service,
        shutdown.clone(),
    ));
    state.write_set(&path, value(2)?).await?;
    until(|| runtime.profile_rev() == 2).await?;
    let invalid = serde_json::from_value(json!({
        "profile_name": "app", "version": 3,
        "surfaces": [{"surface_id": "missing", "target": "effect://missing/invoke"}]
    }))?;
    state.write_set(&path, invalid).await?;
    until(|| runtime.status().lkg_active).await?;
    ensure!(runtime.profile_rev() == 2);
    state.write_set(&path, value(1)?).await?;
    until(|| {
        runtime
            .status()
            .last_reload_failure
            .is_some_and(|failure| failure.code == "stale_revision")
    })
    .await?;
    ensure!(runtime.profile_rev() == 2);
    state.write_set(&path, value(4)?).await?;
    until(|| runtime.profile_rev() == 4).await?;
    ensure!(!runtime.status().lkg_active);
    state.write_delete(&path).await?;
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    ensure!(*shutdown.borrow());
    Ok(())
}

struct ScriptedEvents {
    events: std::collections::VecDeque<Result<StateEvent, StateWatchError>>,
    delivered: Arc<std::sync::atomic::AtomicUsize>,
}

impl StateSubscription for ScriptedEvents {
    fn poll_next(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<StateEvent>, StateWatchError>> {
        let event = self.events.pop_front();
        if event.is_some() {
            self.delivered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        std::task::Poll::Ready(event.transpose())
    }
}

#[tokio::test]
async fn lost_profile_watch_closes_authority_and_ignores_other_paths() -> Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let state = boot.kernel().state().clone();
    let path = profile::profile_path("app")?;
    state.write_set(&path, value(1)?).await?;
    let runtime = Arc::new(GatewayRuntime::new(
        boot,
        GatewayProfile::closed("app"),
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )?);
    let service = ApplicationGrpcService::from_arc_with_config(
        runtime.clone(),
        ApplicationGrpcConfig::default(),
    )?;
    let (shutdown, _) = watch::channel(false);
    let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let events = StateStream::new(ScriptedEvents {
        events: [
            Ok(StateEvent::Delete {
                path: Path::parse("state://kernel/gateway/profiles/other")?,
                taint: xolotl_types::TaintSet::pristine(),
            }),
            Err(StateWatchError::Lagged(1)),
        ]
        .into(),
        delivered: delivered.clone(),
    });
    let result = profile::watch_profile(
        state,
        path,
        "app".into(),
        events,
        runtime,
        service,
        shutdown.clone(),
    )
    .await;
    ensure!(result.is_err_and(|error| error.to_string().contains("profile watch lost")));
    ensure!(*shutdown.borrow());
    ensure!(delivered.load(std::sync::atomic::Ordering::Relaxed) == 2);
    Ok(())
}
