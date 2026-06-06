//! `nexusd` — the long-running Nexus host process, and the Layer-0 command
//! line (§24.1).
//!
//! `nexusd` is both the command you run and the process that runs: like
//! `sshd`/`dockerd`, the binary *is* the launcher. There is no separate CLI
//! crate — that would only forward to this process. Per §18.4 the command line
//! is for **launching the daemon only** and never a management channel;
//! runtime management is the Web Console's job, over an audited,
//! capability-bound Operation path.
//!
//! Usage:
//!   nexusd                 launch the host (default)
//!   nexusd up              launch the host (explicit)
//!   nexusd info            print version / build info and exit
//!   nexusd --version | -V  print the version and exit
//!   nexusd --help | -h     print usage and exit
//!
//! Bootstrap phases (§14.1): parse config → open state backend → mount
//! FactSink → build registries + root Process → install in-process Drivers →
//! (recover) → start Gateways (console, websocket, optional gRPC) → ready.

mod config;

use anyhow::Result;
use config::NexusConfig;
use nexus_actors::{StandardConfig, install_standard};
use nexus_console::{BootstrapOutcome, ConsoleState, RootProvisioning};
use nexus_gateway::InProcessGateway;
use nexus_gateway_websocket::WsGateway;
use nexus_sdk::{Backend, Bootstrap, FactSink, Kernel};
use nexus_storage_redb::RedbStore;
use std::sync::Arc;
use tokio::net::TcpListener;

const CONSOLE_ADDR_ENV: &str = "NEXUS_CONSOLE_ADDR";
const WS_ADDR_ENV: &str = "NEXUS_WS_ADDR";

const USAGE: &str = "\
nexusd — the Nexus host process (Layer-0 launcher, §24.1)

Usage:
  nexusd [up]            launch the host (default)
  nexusd info            print version / build info and exit
  nexusd --version, -V   print the version and exit
  nexusd --help, -h      print this help and exit

Management is the Web Console's job (§18.4); the command line only launches.";

fn main() -> Result<()> {
    // Layer-0 command-line dispatch (§18.4: launch only, never management).
    // Hand-rolled to keep the daemon's dependency set minimal — no clap.
    match std::env::args().nth(1).as_deref() {
        Some("--version") | Some("-V") => {
            println!("nexusd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help") | Some("-h") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("info") => {
            println!("nexus {} — Direction-C kernel", env!("CARGO_PKG_VERSION"));
            println!(
                "management: Web Console only (§18.4); the command line only launches the host"
            );
            Ok(())
        }
        // Default and explicit `up` both launch the host.
        None | Some("up") => run(),
        Some(other) => {
            eprintln!("nexusd: unknown command '{other}'\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Launch the long-running host process. Owns the tokio runtime so the
/// argument-dispatch paths above stay synchronous and cheap.
fn run() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

async fn serve() -> Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting nexusd");

    let cfg = NexusConfig::load()?.unwrap_or_default();

    // Phase 1-2: open the state backend + fact sink.
    let (state, facts): (Backend, FactSink) = match cfg.storage.kind.as_str() {
        "memory" => {
            tracing::info!("state + facts: in-memory (non-persistent)");
            (
                Arc::new(nexus_sdk::InMemoryBackend::new()),
                FactSink::in_memory().0,
            )
        }
        _ => {
            let store = RedbStore::open(&cfg.storage.path)
                .map_err(|e| anyhow::anyhow!("open storage '{}': {e}", cfg.storage.path))?;
            tracing::info!(path = %cfg.storage.path, "state + facts: redb");
            let fact_store = store
                .fact_store()
                .map_err(|e| anyhow::anyhow!("open fact store: {e}"))?;
            (
                Arc::new(store.state_backend()),
                FactSink::new(Arc::new(fact_store)),
            )
        }
    };

    // Phase 3-5: kernel, root Process, standard providers.
    let kernel = Kernel::with_backends(state, facts);
    let boot = Arc::new(Bootstrap::from_kernel(kernel));
    install_standard(
        &boot,
        &StandardConfig {
            fs_root: None,
            terminal_allowlist: vec![],
            enable_fetch: false,
            ..Default::default()
        },
    );
    tracing::info!(
        resources = boot.kernel.registry.resource_count(),
        "kernel ready"
    );

    let root_bootstrap = nexus_console::bootstrap_root_account(
        &boot,
        RootProvisioning {
            password_hash: cfg.console.root.password_hash.clone(),
            pubkeys: cfg.console.root.pubkeys.clone(),
        },
    )
    .await?;
    match root_bootstrap {
        BootstrapOutcome::AlreadyPresent => {}
        BootstrapOutcome::CreatedPreseeded { username } => {
            tracing::info!(%username, "console root account bootstrapped from config");
        }
        BootstrapOutcome::CreatedRandomPassword { username, password } => {
            eprintln!();
            eprintln!("Nexus Console bootstrap account created");
            eprintln!("username: {username}");
            eprintln!("password: {password}");
            eprintln!("Change this password after first login and enable MFA.");
            eprintln!();
        }
    }

    // Phase 6: recover any unfinished Processes from their Fact streams,
    // quarantining unsafe non-idempotent replays (§14.1 / §15.2).
    let recovery = boot.recover_all().await;
    if recovery.skipped + recovery.retried + recovery.quarantined > 0 {
        tracing::info!(
            skipped = recovery.skipped,
            retried = recovery.retried,
            quarantined = recovery.quarantined,
            "recovery complete"
        );
    }

    // Phase 7: start gateways.
    let mut handles = Vec::new();

    if let Some(addr) = cfg
        .server
        .console_addr
        .clone()
        .or_else(|| std::env::var(CONSOLE_ADDR_ENV).ok())
    {
        let listener = TcpListener::bind(&addr).await?;
        let state = ConsoleState::shared(boot.clone());
        tracing::info!(%addr, "console (management Gateway) listening");
        handles.push(tokio::spawn(async move {
            if let Err(e) = nexus_console::serve(listener, state).await {
                tracing::error!(?e, "console exited");
            }
        }));
    } else {
        tracing::info!("{CONSOLE_ADDR_ENV} unset; console disabled");
    }

    if let Some(addr) = cfg
        .server
        .ws_addr
        .clone()
        .or_else(|| std::env::var(WS_ADDR_ENV).ok())
    {
        let listener = TcpListener::bind(&addr).await?;
        let gw = Arc::new(WsGateway::new(Arc::new(InProcessGateway::new(
            boot.clone(),
        ))));
        tracing::info!(%addr, "websocket gateway listening");
        handles.push(tokio::spawn(async move {
            if let Err(e) = nexus_gateway_websocket::serve(gw, listener).await {
                tracing::error!(?e, "websocket gateway exited");
            }
        }));
    } else {
        tracing::info!("{WS_ADDR_ENV} unset; websocket gateway disabled");
    }

    #[cfg(feature = "grpc")]
    start_grpc(&cfg, &boot, &mut handles).await?;

    // Phase 8: ready.
    tracing::info!("nexusd ready");
    wait_for_shutdown().await?;
    for h in handles {
        h.abort();
    }
    tracing::info!("graceful shutdown");
    Ok(())
}

#[cfg(feature = "grpc")]
async fn start_grpc(
    cfg: &NexusConfig,
    boot: &Arc<Bootstrap>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let Some(addr) = cfg
        .server
        .grpc_addr
        .clone()
        .or_else(|| std::env::var("NEXUS_GRPC_ADDR").ok())
    else {
        tracing::info!("gRPC gateway disabled");
        return Ok(());
    };
    let listen_addr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid gRPC addr: {e}"))?;
    let gateway = nexus_gateway_grpc::GrpcGateway::new(boot.clone());
    tracing::info!(%addr, "gRPC gateway listening");
    handles.push(tokio::spawn(async move {
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(gateway.into_server())
            .serve(listen_addr)
            .await
        {
            tracing::error!(?e, "gRPC server exited");
        }
    }));
    Ok(())
}

async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| anyhow::anyhow!("install SIGINT handler: {e}"))?;
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("install SIGTERM handler: {e}"))?;
    tokio::select! {
        _ = sigint.recv() => tracing::info!("SIGINT received"),
        _ = sigterm.recv() => tracing::info!("SIGTERM received"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kernel_boots_with_standard_providers() {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default());
        assert!(boot.kernel.registry.resource_count() >= 5);
    }
}
