#![forbid(unsafe_code)]

//! `xolotld` - the long-running Xolotl host process and bootstrap command line.
//!
//! `xolotld` is both the command you run and the process that runs: like
//! `sshd`/`dockerd`, the binary *is* the launcher. There is no separate CLI
//! crate; that would only forward to this process. The command line is for
//! **launching the daemon only** and never a management channel;
//! runtime management is the Web Console's job.
//!
//! Usage:
//!   xolotld                 launch the host (default)
//!   xolotld up              launch the host (explicit)
//!   xolotld info            print version / build info and exit
//!   xolotld --version | -V  print the version and exit
//!   xolotld --help | -h     print usage and exit
//!
//! Bootstrap sequence: parse config, open state and FactStore backends, build
//! registries and the root Process, install in-process implementations, recover, start
//! gateways, and report ready.

#[cfg(feature = "application-grpc")]
mod application;
mod config;
mod console_maintenance;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
mod external;
#[cfg(feature = "federation-grpc")]
mod federation;
#[cfg(feature = "federation-grpc")]
mod federation_cancellation;
#[cfg(feature = "federation-grpc")]
mod federation_catalog;
#[cfg(feature = "federation-grpc")]
mod federation_outbound;
mod host_lifecycle;
mod projection;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
mod source_maintenance;
mod state_maintenance;
#[cfg(any(
    feature = "external-grpc",
    feature = "external-websocket",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
mod transport;

use anyhow::Result;
use config::{StorageHistoryMode, StorageKind, XolotlConfig};
use std::fmt;
use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use xolotl_console::{
    BootstrapOutcome, ConsoleState, ConsoleTransportSecurityConfig, PairingSecretDisplay,
    RootProvisioning,
};
use xolotl_sdk::{Backend, Bootstrap, FactSink, InMemoryOptions, KernelBuilder, MemoryHistory};
use xolotl_source::SourceStore;
use xolotl_standard::{
    PairingDisplayEdge, StandardConfig, install_declared_in_process_projections, install_standard,
};
use xolotl_storage_redb::{RedbHistory, RedbOptions, RedbStore};

const CONSOLE_ADDR_ENV: &str = "XOLOTL_CONSOLE_ADDR";

const USAGE: &str = "\
xolotld — the Xolotl host process

Usage:
  xolotld [up]            launch the host (default)
  xolotld info            print version / build info and exit
  xolotld --version, -V   print the version and exit
  xolotld --help, -h      print this help and exit

Management is the Web Console's job; the command line only launches.";

fn optional_env_var(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow::anyhow!("{name} is invalid: {error}")),
    }
}

fn main() -> ExitCode {
    match dispatch_main() {
        Ok(code) => code,
        Err(error) => {
            if let Err(stderr_error) = write_stderr_line(format_args!("xolotld: {error:#}")) {
                return match stderr_error.kind() {
                    std::io::ErrorKind::BrokenPipe => ExitCode::from(141),
                    _ => ExitCode::from(74),
                };
            }
            ExitCode::FAILURE
        }
    }
}

fn dispatch_main() -> Result<ExitCode> {
    // Command-line dispatch is hand-rolled to keep the daemon's dependency set
    // minimal.
    match std::env::args().nth(1).as_deref() {
        Some("--version") | Some("-V") => {
            write_stdout_line(format_args!("xolotld {}", env!("CARGO_PKG_VERSION")))?;
            Ok(ExitCode::SUCCESS)
        }
        Some("--help") | Some("-h") => {
            write_stdout_line(format_args!("{USAGE}"))?;
            Ok(ExitCode::SUCCESS)
        }
        Some("info") => {
            write_stdout_line(format_args!(
                "xolotl {} runtime kernel",
                env!("CARGO_PKG_VERSION")
            ))?;
            write_stdout_line(format_args!(
                "management: Web Console only; the command line only launches the host"
            ))?;
            Ok(ExitCode::SUCCESS)
        }
        // Default and explicit `up` both launch the host.
        None | Some("up") => {
            run()?;
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => {
            write_stderr_line(format_args!(
                "xolotld: unknown command '{other}'\n\n{USAGE}"
            ))?;
            Ok(ExitCode::from(2))
        }
    }
}

fn write_stdout_line(args: fmt::Arguments<'_>) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_fmt(args)?;
    stdout.write_all(b"\n")
}

fn write_stderr_line(args: fmt::Arguments<'_>) -> std::io::Result<()> {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    stderr.write_fmt(args)?;
    stderr.write_all(b"\n")
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
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(error) if error.not_found() => {}
        Err(error) => return Err(error.into()),
    }
    let env_filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) if std::env::var_os("RUST_LOG").is_none() => {
            tracing_subscriber::EnvFilter::new("info")
        }
        Err(error) => return Err(error.into()),
    };
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting xolotld");

    let cfg = XolotlConfig::load()?.unwrap_or_default();
    #[cfg(feature = "federation-grpc")]
    let federation_publisher = federation::prepare(&cfg)?;
    let credential_sealer = cfg
        .console
        .load_credential_sealer(cfg.storage.kind == StorageKind::Redb)?;
    let history_maintenance = cfg.storage.history_maintenance()?;
    #[cfg(not(feature = "application-grpc"))]
    if optional_env_var("XOLOTL_APPLICATION_GRPC_ADDR")?.is_some() {
        anyhow::bail!("XOLOTL_APPLICATION_GRPC_ADDR requires the application-grpc build feature");
    }

    // Select one blocking admission domain for Kernel work and redb State reads.
    let host_blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
    let host_runtime = xolotl_kernel::host::HostRuntime::tokio_with_blocking(host_blocking.clone());
    // Open the state backend and fact sink.
    let mut identity_directory: Option<Arc<dyn xolotl_kernel::IdentityDirectory>> = None;
    #[cfg(feature = "federation-grpc")]
    let mut federation_store: Option<xolotl_storage_redb::RedbFederationStore> = None;
    #[cfg(feature = "federation-grpc")]
    let mut federation_public_follow_store: Option<
        xolotl_storage_redb::RedbPublicFollowerStore,
    > = None;
    #[cfg(feature = "federation-grpc")]
    let mut federation_guest_follow_store: Option<xolotl_storage_redb::RedbGuestFollowerStore> =
        None;
    #[cfg(feature = "federation-grpc")]
    let mut federation_projection: Option<xolotl_storage_redb::RedbFederationStateProjection> =
        None;
    #[cfg(feature = "application-grpc")]
    let application_requests: Arc<dyn xolotl_gateway::GatewayIdempotencyStore>;
    let session_policy = cfg.console.auth.session_policy()?;
    let console_sessions: Arc<dyn xolotl_console::session_store::ConsoleSessionStore>;
    let observation_limits = cfg
        .storage
        .observations
        .map(|settings| settings.limits())
        .transpose()?;
    let (state, facts, execution_ids, source_store): (
        Backend,
        FactSink,
        xolotl_sdk::runtime::ExecutionIds,
        Arc<dyn SourceStore>,
    ) = match cfg.storage.kind {
        StorageKind::Memory => {
            console_sessions = Arc::new(
                xolotl_console::session_store::MemoryConsoleSessionStore::new(session_policy),
            );
            #[cfg(feature = "application-grpc")]
            {
                application_requests =
                    Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::new(
                        cfg.application_gateway.request_storage.limits()?,
                    )?);
            }
            tracing::info!(
                observations = observation_limits.is_some(),
                "state: in-memory (non-persistent)"
            );
            let history = match cfg.storage.state_history {
                StorageHistoryMode::CurrentOnly => MemoryHistory::Disabled,
                StorageHistoryMode::Full => MemoryHistory::Full,
            };
            let memory = xolotl_sdk::InMemoryBackend::with_options(InMemoryOptions {
                history,
                source_stream_limit: cfg.storage.source_stream_limit,
                source_retention_limit: cfg.storage.source_retention_limit,
                absence_limits: cfg.storage.absence_limits(),
                ..InMemoryOptions::default()
            })?;
            let (state, source) = memory.into_source_parts();
            let execution_ids = xolotl_sdk::runtime::ExecutionIds::new(Arc::new(
                xolotl_sdk::runtime::InMemoryExecutionIdSource::default(),
            ));
            let facts = match observation_limits {
                Some(limits) => FactSink::new(Arc::new(
                    xolotl_sdk::runtime::InMemoryFactStore::with_limits(limits)?,
                )),
                None => FactSink::disabled(execution_ids.clone()),
            };
            (state, facts, execution_ids, source)
        }
        StorageKind::Redb => {
            let history = match cfg.storage.state_history {
                StorageHistoryMode::CurrentOnly => RedbHistory::CurrentOnly,
                StorageHistoryMode::Full => RedbHistory::Full,
            };
            let store = RedbStore::open_with_options_and_spawner(
                &cfg.storage.path,
                RedbOptions {
                    history,
                    source_stream_limit: cfg.storage.source_stream_limit,
                    source_retention_limit: cfg.storage.source_retention_limit,
                    federation_publish_id_limit: cfg.storage.federation_publish_id_limit,
                    absence_limits: cfg.storage.absence_limits(),
                },
                host_runtime.blocking_spawner(),
            )
            .map_err(|e| anyhow::anyhow!("open storage '{}': {e}", cfg.storage.path))?;
            console_sessions = Arc::new(store.console_session_store(session_policy)?);
            #[cfg(feature = "application-grpc")]
            {
                application_requests = Arc::new(store.gateway_idempotency_store(
                    cfg.application_gateway.request_storage.limits()?,
                )?);
            }
            #[cfg(feature = "federation-grpc")]
            if let Some(publisher) = &federation_publisher {
                federation_store = Some(store.federation_store(publisher.node_id())?);
                if publisher.needs_public_follow_store() {
                    federation_public_follow_store =
                        Some(store.public_follower_store(publisher.node_id())?);
                }
                if publisher.needs_guest_follow_store() {
                    federation_guest_follow_store =
                        Some(store.guest_follower_store(publisher.node_id())?);
                }
                if publisher.needs_projection() {
                    federation_projection =
                        Some(store.federation_state_projection(publisher.node_id())?);
                }
            }
            identity_directory = Some(Arc::new(store.identity_directory()));
            tracing::info!(path = %cfg.storage.path, observations = observation_limits.is_some(), "state: redb");
            let execution_ids =
                xolotl_sdk::runtime::ExecutionIds::new(Arc::new(store.execution_id_source()));
            let facts = match observation_limits {
                Some(limits) => FactSink::new(Arc::new(store.fact_store_with_limits(limits)?)),
                None => FactSink::disabled(execution_ids.clone()),
            };
            let (state, source) = store.state_backend().into_source_parts();
            (state, facts, execution_ids, source)
        }
    };
    if history_maintenance.is_some() && !state.has_history_retention() {
        anyhow::bail!("configured State history maintenance requires a retention capability");
    }
    let maintenance_state = history_maintenance.map(|_| state.clone());
    // Build the kernel, root Process, and standard providers.
    let builder = KernelBuilder::new(state)
        .with_handle_slot_limit(cfg.kernel.max_handle_slots.get())
        .with_host_runtime(host_runtime)
        .with_fact_sink(facts)
        .with_execution_ids(execution_ids)
        .with_fact_io_mode(match cfg.storage.kind {
            StorageKind::Memory => xolotl_sdk::FactIoMode::Inline,
            StorageKind::Redb => xolotl_sdk::FactIoMode::Blocking,
        });
    let builder = match identity_directory {
        Some(directory) => builder.with_identity_directory(directory),
        None => builder,
    };
    let boot = Arc::new(Bootstrap::from_kernel(builder.build()));
    host_lifecycle::supervise_host(&boot, &host_blocking, async |services| {
        boot.kernel().identities().validate()?;
        #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
        let shared_source_commands = external::SharedSourceCommands::new(
            boot.kernel().state().clone(),
            source_store.clone(),
            boot.kernel().registry().clone(),
            cfg.external_gateway.source_command_limit,
        );
        let pairing_display = match cfg.storage.kind {
            StorageKind::Memory => PairingDisplayEdge::default(),
            StorageKind::Redb => {
                let path =
                    std::path::Path::new(&cfg.storage.path).with_extension("external-credentials");
                let key = cfg.external_credentials.load_key(&cfg.console)?;
                PairingDisplayEdge::open(&path, &key).map_err(|error| {
                    anyhow::anyhow!(
                        "open external credential vault '{}': {error}",
                        path.display()
                    )
                })?
            }
        };
        let object_path = cfg
            .storage
            .object_path
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(&cfg.storage.path).with_extension("objects"));
        let objects = xolotl_storage_fs::FileObjectStore::open(&object_path).map_err(|error| {
            anyhow::anyhow!("open object storage '{}': {error}", object_path.display())
        })?;
        let objects = objects.into_object_store();
        #[cfg(feature = "application-grpc")]
        let application_objects = objects.clone();
        #[cfg(feature = "federation-grpc")]
        let federation_objects = objects.clone();
        let standard_config = standard_config(pairing_display.clone())
            .with_object_store(objects)
            .with_external_installations(source_store.clone());
        #[cfg(feature = "terminal")]
        let standard_config = standard_config.with_terminal_runtime(services.terminal.clone());
        install_standard(&boot, &standard_config)?;
        let projection_report =
            install_declared_in_process_projections(&boot, &standard_config).await?;
        let declared_projections = projection_report.installed_count();
        let rejected_projections = projection_report.rejected_count();
        projection::reconcile_in_process_projection_report_status(&boot, projection_report.entries)
            .await?;
        if declared_projections > 0 || rejected_projections > 0 {
            tracing::info!(
                projections = declared_projections,
                rejected = rejected_projections,
                "in-process projection declarations reconciled"
            );
        }
        tracing::info!(
            resources = boot.kernel().registry().resource_count(),
            "kernel ready"
        );

        let root_provisioning = RootProvisioning {
            credential_sealer: Some(credential_sealer.clone()),
            password_hash: cfg.console.root.password_hash.clone(),
            password: cfg.console.root.password.clone(),
            pubkeys: cfg.console.root.pubkeys.clone(),
            additional_grants: cfg.console.root.additional_grants.clone(),
        };
        if xolotl_console::root_random_password_needed(&boot, &root_provisioning).await?
            && !std::io::stderr().is_terminal()
        {
            anyhow::bail!(
                "refusing to bootstrap root with a random password because stderr is not a TTY; set console.root.password_hash, console.root.password, or console.root.pubkeys in xolotl.toml"
            );
        }
        let blocking_spawner = boot.kernel().host_runtime().blocking_spawner();
        let root_bootstrap =
            xolotl_console::bootstrap_root_account(&boot, blocking_spawner.as_ref(), root_provisioning)
                .await?;
        match root_bootstrap {
            BootstrapOutcome::AlreadyPresent => {}
            BootstrapOutcome::CreatedPreseeded { username } => {
                tracing::info!(%username, "console root account bootstrapped from config");
            }
            BootstrapOutcome::CreatedFromProvisionedPassword { username } => {
                tracing::info!(%username, "console root account bootstrapped from provisioned password");
            }
            BootstrapOutcome::CreatedRandomPassword { username, password } => {
                write_bootstrap_credentials(&username, &password)?;
            }
        }

        #[cfg(feature = "federation-grpc")]
        if let (Some(prepared), Some(store)) = (&federation_publisher, &federation_store) {
            services.federation_runtime = Some(prepared.transport_runtime(boot.kernel().host_runtime())?);
            prepared.install_outbound(&boot, store)?;
        }
        #[cfg(feature = "federation-grpc")]
        let federation_retirement_cursor = if let Some(store) = federation_store.as_ref() {
            federation::retire_completed_outbound_pages(
                boot.kernel().host_runtime(),
                store.clone(),
                None,
            )
            .await?
        } else {
            None
        };

        #[cfg(feature = "application-grpc")]
        {
            services.application =
                application::ApplicationGateway::start(
                    &cfg,
                    boot.clone(),
                    application_objects,
                    application_requests,
                ).await?;
        }

        // Start gateways.
        #[cfg(feature = "federation-grpc")]
        if let Some(store) = federation_store.as_ref() {
            services.background.push(
                "federation outbound retirement",
                federation::start_outbound_retirement(
                    boot.kernel().host_runtime().clone(),
                    store.clone(),
                    federation_retirement_cursor,
                ),
            );
            services.background.push(
                "federation invitation retirement",
                federation::start_invitation_retirement(
                    boot.kernel().host_runtime().clone(),
                    store.clone(),
                ),
            );
            if let Some(publisher) = federation_publisher.as_ref() {
                services.background.push(
                    "federation cancellation retries",
                    publisher.start_remote_cancellation_retries(
                        boot.kernel().host_runtime().clone(),
                        store.clone(),
                    )?,
                );
            }
        }
        if let (Some(state), Some(settings)) = (maintenance_state, history_maintenance) {
            services.background.push(
                "State history maintenance",
                state_maintenance::start(state, settings),
            );
        }
        services.background.serve(
            "in-process projection reconciler",
            projection::start_in_process_projection_reconciler(boot.clone(), standard_config.clone())
                .await?,
        );
        #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
        services.background.push(
            "Source maintenance",
            source_maintenance::start(source_store.clone(), shared_source_commands.clone(), &cfg.external_gateway, {
                let runtime = boot.kernel().host_runtime().clone();
                Arc::new(move || runtime.now_millis())
            }),
        );

        let console_addr = match cfg.server.console_addr.clone() {
            Some(addr) => Some(addr),
            None => optional_env_var(CONSOLE_ADDR_ENV)?,
        };
        if let Some(addr) = console_addr {
            let retry_epoch_period = cfg.console.submission_retry_epoch_period()?;
            let security = cfg
                .console
                .transport_security
                .validate_plain_listener("console", &addr)?;
            let listener = TcpListener::bind(security.listen_addr).await?;
            log_console_transport_security(&addr, &security.config);
            let state = ConsoleState::shared_with_pairing_display_and_config(
                boot.clone(),
                Arc::new(StandardPairingSecretDisplay(pairing_display.clone())),
                xolotl_console::ConsoleConfig {
                    session_store: Some(console_sessions.clone()),
                    blocking_spawner: Some(Arc::clone(&blocking_spawner)),
                    request_anchor: None,
                    streams: cfg.console.streams.clone(),
                    runtime: cfg.console.runtime.clone(),
                    modules: Default::default(),
                    auth: xolotl_console::ConsoleAuthConfig {
                        credential_sealer: Some(credential_sealer.clone()),
                        ..cfg.console.auth.clone().into()
                    },
                    queries: cfg.console.queries.clone(),
                    max_concurrent_calls: cfg.console.max_concurrent_calls,
                    max_concurrent_authentications: cfg.console.max_concurrent_authentications,
                    // The stock daemon does not bundle an IdP verifier. Embedding
                    // hosts can install one on ConsoleConfig before serving HTTP.
                    external_authentication: None,
                    account_authority: None,
                    source_management: Some(source_store.clone()),
                    federation_management: {
                        #[cfg(feature = "federation-grpc")]
                        {
                            federation_store.as_ref().map(|store| {
                                Arc::new(store.clone())
                                    as Arc<dyn xolotl_federation::FederationManagement>
                            })
                        }
                        #[cfg(not(feature = "federation-grpc"))]
                        {
                            None
                        }
                    },
                    config_admissions: config::console_config_admissions()?,
                },
            )
            .map_err(|e| anyhow::anyhow!("console initialization failed: {e}"))?;
            let service = xolotl_console::ConsoleService::new(state.clone());
            services.console = Some(service.clone());
            services.background.serve(
                "Console session expiry maintenance",
                console_maintenance::start(
                    service,
                    console_sessions.clone(),
                    boot.kernel().host_runtime().clone(),
                    retry_epoch_period,
                    cfg.console.runtime.enabled && cfg.console.runtime.executions.enabled,
                ),
            );
            let adapter = xolotl_console::http::HttpState::new(
                state,
                xolotl_console::http::HttpConfig {
                    request_body_timeout: std::time::Duration::from_millis(
                        cfg.console.request_body_timeout_ms,
                    ),
                    ws: cfg.console.ws.clone().into(),
                    transport_security: security.config,
                    originless_clients: Default::default(),
                },
            );
            tracing::info!(%addr, "console (management Gateway) listening");
            services.background.serve(
                "Console HTTP listener",
                tokio::spawn(async move {
                    xolotl_console::http::serve(listener, adapter).await?;
                    Ok(())
                }),
            );
        } else {
            tracing::info!("{CONSOLE_ADDR_ENV} unset; console disabled");
        }

        #[cfg(feature = "external-websocket")]
        external::start_external_websocket(
            &cfg,
            &boot,
            source_store.clone(),
            pairing_display.clone(),
            shared_source_commands.clone(),
            services.external_sessions.clone(),
            &mut services.background,
        )
        .await?;
        #[cfg(feature = "external-grpc")]
        external::start_external_grpc(
            &cfg,
            &boot,
            source_store,
            pairing_display,
            shared_source_commands,
            services.external_sessions.clone(),
            &mut services.background,
        )
        .await?;
        #[cfg(feature = "federation-grpc")]
        if let Some(publisher) = federation_publisher {
            let store = federation_store
                .ok_or_else(|| anyhow::anyhow!("federation redb store was not initialized"))?;
            if let Some(follow_store) = federation_public_follow_store {
                services.background.extend(
                    "federation public follow",
                    publisher.start_public_follows(
                        boot.kernel().host_runtime(),
                        store.clone(),
                        follow_store,
                    )?,
                );
            }
            if let Some(guest_store) = federation_guest_follow_store {
                services.background.extend(
                    "federation guest follow",
                    publisher.start_guest_follows(
                        boot.kernel().host_runtime(),
                        store.clone(),
                        guest_store,
                    )?,
                );
            }
            let federation = federation::start_with_objects(
                publisher,
                store,
                federation_projection,
                boot.clone(),
                federation_objects,
            ).await?;
            services.federation_calls = federation.calls;
            services.federation_runtime = Some(federation.runtime);
            services.background.serve("federation services", federation.task);
        }
        services.check_running().await?;
        // Mark the daemon ready.
        tracing::info!("xolotld ready");
        services.wait_for_shutdown(wait_for_shutdown()).await
    }).await?;
    tracing::info!("graceful shutdown");
    Ok(())
}

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
fn pqc_tls_crypto_provider() -> Result<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // A TLS 1.2 handshake cannot select a suite without TLS 1.2 suites, even
    // when a library uses rustls' default protocol-version list.
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let algorithms = provider.signature_verification_algorithms.mapping;
    let position = algorithms
        .iter()
        .position(|(scheme, _)| *scheme == rustls::SignatureScheme::ML_DSA_65)
        .ok_or_else(|| anyhow::anyhow!("AWS-LC must support ML-DSA-65"))?;
    provider.signature_verification_algorithms.mapping = &algorithms[position..position + 1];
    provider.signature_verification_algorithms.all = algorithms[position].1;
    Ok(provider)
}

#[cfg(all(test, any(feature = "external-grpc", feature = "application-grpc")))]
fn is_pqc_tls_crypto_provider(provider: &rustls::crypto::CryptoProvider) -> bool {
    !provider.cipher_suites.is_empty()
        && provider.cipher_suites.iter().all(|suite| {
            matches!(
                suite.suite(),
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            )
        })
        && provider.kx_groups.len() == 1
        && provider.kx_groups[0].name() == rustls::NamedGroup::X25519MLKEM768
        && provider.signature_verification_algorithms.mapping.len() == 1
        && provider.signature_verification_algorithms.mapping[0].0
            == rustls::SignatureScheme::ML_DSA_65
        && provider.signature_verification_algorithms.all.len() == 1
}

#[cfg(all(test, any(feature = "external-grpc", feature = "application-grpc")))]
mod tls_crypto_provider_tests {
    use std::io;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use futures_util::StreamExt;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tonic::transport::server::{Connected, TcpConnectInfo};

    const ML_DSA_CERT: &[u8] = include_bytes!("../tests/fixtures/ml-dsa-65-cert.pem");
    const ML_DSA_KEY: &[u8] = include_bytes!("../tests/fixtures/ml-dsa-65-key.pem");
    const ML_DSA_CA_CERT: &[u8] = include_bytes!("../tests/fixtures/ml-dsa-65-ca-cert.pem");
    const ECDSA_CERT: &[u8] = include_bytes!("../tests/fixtures/ecdsa-cert.pem");
    const ECDSA_KEY: &[u8] = include_bytes!("../tests/fixtures/ecdsa-key.pem");

    struct MemoryConnection(tokio::io::DuplexStream);

    impl Connected for MemoryConnection {
        type ConnectInfo = TcpConnectInfo;

        fn connect_info(&self) -> Self::ConnectInfo {
            TcpConnectInfo {
                local_addr: Some(([127, 0, 0, 1], 7443).into()),
                remote_addr: Some(([127, 0, 0, 1], 50000).into()),
            }
        }
    }

    impl AsyncRead for MemoryConnection {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for MemoryConnection {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    #[test]
    fn grpc_tls_provider_and_server_disable_resumption() -> anyhow::Result<()> {
        let previous = rustls::crypto::CryptoProvider::get_default().cloned();
        let config = server_config()?;
        anyhow::ensure!(super::is_pqc_tls_crypto_provider(config.crypto_provider()));
        let current = rustls::crypto::CryptoProvider::get_default();
        anyhow::ensure!(
            match (previous.as_ref(), current) {
                (None, None) => true,
                (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
                _ => false,
            },
            "TLS construction changed the process-global provider"
        );
        anyhow::ensure!(
            config.send_tls13_tickets == 0
                && config.max_tls13_tickets == 0
                && config.max_early_data_size == 0
                && !config.ticketer.enabled(),
            "gRPC TLS resumed sessions or early data remain enabled"
        );
        Ok(())
    }

    #[test]
    fn tls_handshake_accepts_hybrid_and_rejects_classical_or_aes128() -> anyhow::Result<()> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(ML_DSA_CA_CERT)?)?;

        let hybrid = super::pqc_tls_crypto_provider()?;
        let mut client = new_client(hybrid.clone(), roots.clone(), &[&rustls::version::TLS13])?;
        let mut server = new_server()?;
        negotiate(&mut client, &mut server)?;
        anyhow::ensure!(
            server.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
                && client.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
                && server.handshake_kind() == Some(rustls::HandshakeKind::Full)
                && server.alpn_protocol() == Some(b"h2".as_slice())
                && server
                    .negotiated_key_exchange_group()
                    .is_some_and(|group| group.name() == rustls::NamedGroup::X25519MLKEM768)
                && client
                    .negotiated_key_exchange_group()
                    .is_some_and(|group| group.name() == rustls::NamedGroup::X25519MLKEM768),
            "TLS peers did not negotiate TLS 1.3 X25519MLKEM768"
        );

        let mut classical = hybrid.clone();
        classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let mut client = new_client(classical, roots.clone(), &[&rustls::version::TLS13])?;
        anyhow::ensure!(
            negotiate(&mut client, &mut new_server()?).is_err(),
            "classical X25519 unexpectedly negotiated"
        );

        let mut aes128 = hybrid;
        aes128.cipher_suites =
            vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
        let mut client = new_client(aes128, roots, &[&rustls::version::TLS13])?;
        anyhow::ensure!(
            negotiate(&mut client, &mut new_server()?).is_err(),
            "AES-128-GCM unexpectedly negotiated"
        );

        Ok(())
    }

    #[test]
    fn grpc_listener_requires_ml_dsa_identity_and_roots() -> anyhow::Result<()> {
        let valid = super::transport::GatewayListenerTlsMaterial {
            certificate_chain_pem: ML_DSA_CERT.to_vec(),
            private_key_pem: ML_DSA_KEY.to_vec().into(),
            client_trust_roots_pem: ML_DSA_CA_CERT.to_vec(),
        };
        let _tls =
            super::transport::grpc_tls_server_config(&super::transport::GatewayListenerSecurity {
                listen_addr: "127.0.0.1:0".parse()?,
                config: xolotl_gateway::GatewayTransportSecurityConfig {
                    mode: xolotl_gateway::GatewayTransportSecurityMode::MutualTls,
                    ..Default::default()
                },
                tls: Some(valid.clone()),
            })?;

        let mut classical_key = valid.clone();
        classical_key.private_key_pem = ECDSA_KEY.to_vec().into();
        anyhow::ensure!(
            super::transport::grpc_tls_server_config(&super::transport::GatewayListenerSecurity {
                listen_addr: "127.0.0.1:0".parse()?,
                config: Default::default(),
                tls: Some(classical_key),
            })
            .is_err(),
            "classical server private key unexpectedly accepted"
        );

        let mut classical_certificate = valid.clone();
        classical_certificate.certificate_chain_pem = ECDSA_CERT.to_vec();
        classical_certificate.private_key_pem = ECDSA_KEY.to_vec().into();
        anyhow::ensure!(
            super::transport::grpc_tls_server_config(&super::transport::GatewayListenerSecurity {
                listen_addr: "127.0.0.1:0".parse()?,
                config: Default::default(),
                tls: Some(classical_certificate),
            })
            .is_err(),
            "classical server certificate unexpectedly accepted"
        );

        let mut classical_root = valid;
        classical_root.client_trust_roots_pem = ECDSA_CERT.to_vec();
        anyhow::ensure!(
            super::transport::grpc_tls_server_config(&super::transport::GatewayListenerSecurity {
                listen_addr: "127.0.0.1:0".parse()?,
                config: Default::default(),
                tls: Some(classical_root),
            })
            .is_err(),
            "classical client trust root unexpectedly accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn outer_tls_admission_reports_verified_handshake_and_client_certificate()
    -> anyhow::Result<()> {
        for mutual in [false, true] {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let address = "127.0.0.1:7443".parse()?;
            let security = super::transport::GatewayListenerSecurity {
                listen_addr: address,
                config: xolotl_gateway::GatewayTransportSecurityConfig {
                    mode: if mutual {
                        xolotl_gateway::GatewayTransportSecurityMode::MutualTls
                    } else {
                        xolotl_gateway::GatewayTransportSecurityMode::ProductionTls
                    },
                    ..Default::default()
                },
                tls: Some(super::transport::GatewayListenerTlsMaterial {
                    certificate_chain_pem: ML_DSA_CERT.to_vec(),
                    private_key_pem: ML_DSA_KEY.to_vec().into(),
                    client_trust_roots_pem: if mutual {
                        ML_DSA_CA_CERT.to_vec()
                    } else {
                        Vec::new()
                    },
                }),
            };
            let incoming = futures_util::stream::once(async {
                Ok::<_, io::Error>(MemoryConnection(server_io))
            });
            let incoming = super::transport::incoming::grpc_incoming(
                incoming,
                super::transport::grpc_tls_server_config(&security)?,
            );
            tokio::pin!(incoming);

            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from_pem_slice(ML_DSA_CA_CERT)?)?;
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
                super::pqc_tls_crypto_provider()?,
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots);
            let mut client_config = if mutual {
                let certs = CertificateDer::pem_reader_iter(&mut Cursor::new(ML_DSA_CERT))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let key = PrivateKeyDer::from_pem_reader(&mut Cursor::new(ML_DSA_KEY))?;
                builder.with_client_auth_cert(certs, key)?
            } else {
                builder.with_no_client_auth()
            };
            client_config.alpn_protocols = vec![b"h2".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let client = async move {
                let stream = connector
                    .connect(ServerName::try_from("localhost")?, client_io)
                    .await?;
                Ok::<_, anyhow::Error>(stream)
            };
            let server = async {
                let connection = tokio::time::timeout(Duration::from_secs(5), incoming.next())
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("gRPC incoming stream ended"))??;
                Ok::<_, anyhow::Error>(connection)
            };
            let (client, server) = tokio::join!(client, server);
            let client = client?;
            let server = server?;
            let (_, client_session) = client.get_ref();
            anyhow::ensure!(
                client_session
                    .negotiated_key_exchange_group()
                    .is_some_and(|group| group.name() == rustls::NamedGroup::X25519MLKEM768)
            );
            let info = server.connect_info();
            anyhow::ensure!(info.remote_addr().is_some());
            let tls = info
                .tls
                .ok_or_else(|| anyhow::anyhow!("TLS facts absent"))?;
            anyhow::ensure!(!tls.peer_certificates().is_empty() == mutual);
        }
        Ok(())
    }

    fn new_server() -> anyhow::Result<rustls::ServerConnection> {
        Ok(rustls::ServerConnection::new(server_config()?)?)
    }

    fn server_config() -> anyhow::Result<Arc<rustls::ServerConfig>> {
        let security = super::transport::GatewayListenerSecurity {
            listen_addr: "127.0.0.1:0".parse()?,
            config: xolotl_gateway::GatewayTransportSecurityConfig {
                mode: xolotl_gateway::GatewayTransportSecurityMode::ProductionTls,
                ..Default::default()
            },
            tls: Some(super::transport::GatewayListenerTlsMaterial {
                certificate_chain_pem: ML_DSA_CERT.to_vec(),
                private_key_pem: ML_DSA_KEY.to_vec().into(),
                client_trust_roots_pem: Vec::new(),
            }),
        };
        super::transport::grpc_tls_server_config(&security)?
            .ok_or_else(|| anyhow::anyhow!("gRPC TLS config absent"))
    }

    fn new_client(
        provider: rustls::crypto::CryptoProvider,
        roots: rustls::RootCertStore,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> anyhow::Result<rustls::ClientConnection> {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost")?,
        )?)
    }

    fn negotiate(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> anyhow::Result<()> {
        for _ in 0..16 {
            let mut client_bytes = Vec::new();
            client.write_tls(&mut client_bytes)?;
            let mut from_client = client_bytes.as_slice();
            while !from_client.is_empty() {
                server.read_tls(&mut from_client)?;
                server.process_new_packets()?;
            }
            let mut server_bytes = Vec::new();
            server.write_tls(&mut server_bytes)?;
            let mut from_server = server_bytes.as_slice();
            while !from_server.is_empty() {
                client.read_tls(&mut from_server)?;
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        anyhow::bail!("TLS handshake did not complete")
    }
}

fn standard_config(pairing_display: PairingDisplayEdge) -> StandardConfig {
    StandardConfig::default().with_pairing_display(pairing_display)
}

struct StandardPairingSecretDisplay(PairingDisplayEdge);

impl PairingSecretDisplay for StandardPairingSecretDisplay {
    fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        self.0.take_display_secret(pairing_id)
    }
}

fn write_bootstrap_credentials(username: &str, password: &str) -> std::io::Result<()> {
    write_stderr_line(format_args!(""))?;
    write_stderr_line(format_args!("Xolotl Console bootstrap account created"))?;
    write_stderr_line(format_args!("username: {username}"))?;
    write_stderr_line(format_args!("password: {password}"))?;
    write_stderr_line(format_args!(
        "Change this password after first login and enable MFA."
    ))?;
    write_stderr_line(format_args!(""))
}

fn now_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => {
            let before_epoch = i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX);
            before_epoch.saturating_neg()
        }
    }
}

fn log_console_transport_security(addr: &str, config: &ConsoleTransportSecurityConfig) {
    if config.is_unsafe() {
        tracing::warn!(
            %addr,
            mode = config.mode.as_str(),
            unsafe_relaxations = ?config.unsafe_relaxation_names(),
            "console unsafe transport enabled"
        );
    } else {
        tracing::info!(%addr, mode = config.mode.as_str(), "console transport");
    }
}

#[cfg(unix)]
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

#[cfg(not(unix))]
async fn wait_for_shutdown() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!("install Ctrl-C handler: {e}"))?;
    tracing::info!("Ctrl-C received");
    Ok(())
}

#[cfg(test)]
mod tests;
