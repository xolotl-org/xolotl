#![forbid(unsafe_code)]

//! `nexusd` - the long-running Nexus host process and bootstrap command line.
//!
//! `nexusd` is both the command you run and the process that runs: like
//! `sshd`/`dockerd`, the binary *is* the launcher. There is no separate CLI
//! crate; that would only forward to this process. The command line is for
//! **launching the daemon only** and never a management channel;
//! runtime management is the Web Console's job.
//!
//! Usage:
//!   nexusd                 launch the host (default)
//!   nexusd up              launch the host (explicit)
//!   nexusd info            print version / build info and exit
//!   nexusd --version | -V  print the version and exit
//!   nexusd --help | -h     print usage and exit
//!
//! Bootstrap sequence: parse config, open state and FactStore backends, build
//! registries and the root Process, install in-process implementations, recover, start
//! gateways, and report ready.

mod config;

use anyhow::Result;
use config::NexusConfig;
use nexus_console::{
    BootstrapOutcome, ConsoleState, ConsoleTransportSecurityConfig, PairingSecretDisplay,
    RootProvisioning,
};
#[cfg(feature = "external-gateway")]
use nexus_gateway::GatewayTransportSecurityConfig;
#[cfg(all(test, feature = "external-gateway"))]
use nexus_gateway::external::SourceCommandRegister;
#[cfg(feature = "external-gateway")]
use nexus_gateway::external::{
    EndpointSession, ExternalCredential, ExternalSessionHandler, ExternalSessionOutbound,
    ProviderInvocationError, ProviderInvocationRegister, ProviderInvocationRegistry,
    ProviderInvocationResolve, SecureEnvelope, SecureEnvelopeEpochGate, SecureEnvelopeReplayWindow,
    SourceCommandError, SourceCommandRegistry, SourceCommandResolve, SourceIngest,
    SourceIngestError, ingest_source_event, validate_json_schema,
};
#[cfg(feature = "external-websocket")]
use nexus_gateway_websocket::{ExternalWebSocketConfig, ExternalWebSocketService};
#[cfg(feature = "external-gateway")]
use nexus_kernel::PolicySnapshot;
#[cfg(feature = "external-gateway")]
use nexus_kernel::driver::{DriverDescriptor, DriverError, RemoteEndpoint, RemoteInvokeDispatch};
#[cfg(feature = "external-gateway")]
use nexus_kernel::{EchoDriver, Registry, ResolveError};
use nexus_sdk::{Backend, Bootstrap, FactSink, Kernel};
use nexus_standard::{
    IN_PROCESS_PROJECTION_CONFIG_PREFIX, PairingDisplayEdge, StandardConfig,
    install_declared_in_process_projections, install_in_process_projection_value, install_standard,
};
use nexus_state::StateEvent;
use nexus_storage_redb::RedbStore;
#[cfg(all(test, feature = "external-gateway"))]
use nexus_types::external::ObservedGenerations;
#[cfg(all(test, feature = "external-gateway"))]
use nexus_types::external::OutboundCommand;
#[cfg(feature = "external-gateway")]
use nexus_types::external::{
    AckStatus, EventAck, ExternalInstallationDef, ExternalProjectionDef, InboundEvent, Role,
    RoleSessionClientHello, SessionContext,
};
#[cfg(feature = "external-gateway")]
use nexus_types::external::{
    CommandResult, ConfigAxis, ControlFrame, EffectCapability, Invoke, InvokeResult,
};
#[cfg(feature = "external-gateway")]
use nexus_types::{
    Binding, CostModel, DriverRef, Interface, InterfaceFamily, InterfaceSet, Metadata, Method,
    MethodId, ModalitySet, OutputModeSet, Resource, ResourceDescriptor, ResourceKind, ResourceName,
    ResourceSelector, SchemaId, Transport,
};
#[cfg(feature = "external-gateway")]
use nexus_types::{IdentityRef, ResourceId};
use nexus_types::{Path, Value};
#[cfg(feature = "external-gateway")]
use std::collections::BTreeMap;
#[cfg(feature = "external-gateway")]
use std::collections::HashMap;
#[cfg(feature = "external-gateway")]
use std::collections::btree_map::Entry;
use std::fmt;
use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
#[cfg(feature = "external-gateway")]
use std::time::Duration;
#[cfg(feature = "external-gateway")]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
#[cfg(feature = "external-gateway")]
use tokio::sync::oneshot;

const CONSOLE_ADDR_ENV: &str = "NEXUS_CONSOLE_ADDR";
#[cfg(feature = "external-websocket")]
const EXTERNAL_WEBSOCKET_ADDR_ENV: &str = "NEXUS_EXTERNAL_WEBSOCKET_ADDR";
#[cfg(feature = "external-grpc")]
const EXTERNAL_GRPC_ADDR_ENV: &str = "NEXUS_EXTERNAL_GRPC_ADDR";

const USAGE: &str = "\
nexusd — the Nexus host process

Usage:
  nexusd [up]            launch the host (default)
  nexusd info            print version / build info and exit
  nexusd --version, -V   print the version and exit
  nexusd --help, -h      print this help and exit

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
            if let Err(stderr_error) = write_stderr_line(format_args!("nexusd: {error:#}")) {
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
            write_stdout_line(format_args!("nexusd {}", env!("CARGO_PKG_VERSION")))?;
            Ok(ExitCode::SUCCESS)
        }
        Some("--help") | Some("-h") => {
            write_stdout_line(format_args!("{USAGE}"))?;
            Ok(ExitCode::SUCCESS)
        }
        Some("info") => {
            write_stdout_line(format_args!(
                "nexus {} runtime kernel",
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
            write_stderr_line(format_args!("nexusd: unknown command '{other}'\n\n{USAGE}"))?;
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
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting nexusd");

    let cfg = NexusConfig::load()?.unwrap_or_default();

    // Open the state backend and fact sink.
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

    // Build the kernel, root Process, and standard providers.
    let kernel = Kernel::with_backends(state, facts);
    let boot = Arc::new(Bootstrap::from_kernel(kernel));
    let pairing_display = PairingDisplayEdge::default();
    let standard_config = standard_config(pairing_display.clone());
    install_standard(&boot, &standard_config)?;
    let declared_projections = install_declared_in_process_projections(&boot).await?;
    if declared_projections > 0 {
        tracing::info!(
            projections = declared_projections,
            "in-process projection declarations installed"
        );
    }
    tracing::info!(
        resources = boot.kernel.registry.resource_count(),
        "kernel ready"
    );

    let root_provisioning = RootProvisioning {
        password_hash: cfg.console.root.password_hash.clone(),
        pubkeys: cfg.console.root.pubkeys.clone(),
    };
    if nexus_console::root_random_password_needed(&boot, &root_provisioning).await?
        && !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "refusing to bootstrap root with a random password because stderr is not a TTY; set console.root.password_hash or console.root.pubkeys in nexus.toml"
        );
    }
    let root_bootstrap = nexus_console::bootstrap_root_account(&boot, root_provisioning).await?;
    match root_bootstrap {
        BootstrapOutcome::AlreadyPresent => {}
        BootstrapOutcome::CreatedPreseeded { username } => {
            tracing::info!(%username, "console root account bootstrapped from config");
        }
        BootstrapOutcome::CreatedRandomPassword { username, password } => {
            write_bootstrap_credentials(&username, &password)?;
        }
    }

    // Recover unfinished Processes from their Fact streams, quarantining unsafe
    // non-idempotent replays.
    let recovery = boot.recover_all().await?;
    if recovery.skipped + recovery.retried + recovery.quarantined > 0 {
        tracing::info!(
            skipped = recovery.skipped,
            retried = recovery.retried,
            quarantined = recovery.quarantined,
            schema_mismatched = recovery.schema_mismatched,
            "recovery complete"
        );
    }

    // Start gateways.
    let mut handles = Vec::new();
    handles.push(start_in_process_projection_reconciler(boot.clone()).await?);

    let console_addr = match cfg.server.console_addr.clone() {
        Some(addr) => Some(addr),
        None => optional_env_var(CONSOLE_ADDR_ENV)?,
    };
    if let Some(addr) = console_addr {
        let security = cfg
            .console
            .transport_security
            .validate_plain_listener("console", &addr)?;
        let listener = TcpListener::bind(security.listen_addr).await?;
        log_console_transport_security(&addr, &security.config);
        let state = ConsoleState::shared_with_pairing_display_and_config(
            boot.clone(),
            Arc::new(StandardPairingSecretDisplay(pairing_display.clone())),
            cfg.console.auth.clone().into(),
            cfg.console.ws.clone().into(),
            security.config,
        )
        .map_err(|e| anyhow::anyhow!("console auth initialization failed: {e}"))?;
        tracing::info!(%addr, "console (management Gateway) listening");
        handles.push(tokio::spawn(async move {
            if let Err(e) = nexus_console::serve(listener, state).await {
                tracing::error!(?e, "console exited");
            }
        }));
    } else {
        tracing::info!("{CONSOLE_ADDR_ENV} unset; console disabled");
    }

    #[cfg(feature = "external-websocket")]
    start_external_websocket(&cfg, &boot, &mut handles).await?;
    #[cfg(feature = "external-grpc")]
    start_external_grpc(&cfg, &boot, &mut handles).await?;

    // Mark the daemon ready.
    tracing::info!("nexusd ready");
    wait_for_shutdown().await?;
    for h in handles {
        h.abort();
    }
    tracing::info!("graceful shutdown");
    Ok(())
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

async fn start_in_process_projection_reconciler(
    boot: Arc<Bootstrap>,
) -> Result<tokio::task::JoinHandle<()>> {
    let pattern = Path::parse(&format!("{IN_PROCESS_PROJECTION_CONFIG_PREFIX}/**"))
        .map_err(|error| anyhow::anyhow!("parse in-process projection watch pattern: {error}"))?;
    let mut events = boot.kernel.state.subscribe(&pattern).await?;
    Ok(tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(StateEvent::Set { path, value, .. }) => {
                    if let Err(error) = install_in_process_projection_value(&boot, &path, value) {
                        tracing::error!(
                            path = %path,
                            error = %error,
                            "in-process projection declaration rejected"
                        );
                    }
                }
                Ok(StateEvent::Append { path, .. }) => {
                    tracing::error!(
                        path = %path,
                        "in-process projection declaration path received append event"
                    );
                }
                Ok(StateEvent::Delete { path }) => {
                    tracing::error!(
                        path = %path,
                        "in-process projection declaration was deleted; live registry entries remain until restart"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::error!(
                        skipped,
                        "in-process projection declaration watcher lagged; reconciling declarations"
                    );
                    if let Err(error) = install_declared_in_process_projections(&boot).await {
                        tracing::error!(
                            error = %error,
                            "in-process projection declaration reconcile failed"
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::error!("in-process projection declaration watcher closed");
                    break;
                }
            }
        }
    }))
}

fn write_bootstrap_credentials(username: &str, password: &str) -> std::io::Result<()> {
    write_stderr_line(format_args!(""))?;
    write_stderr_line(format_args!("Nexus Console bootstrap account created"))?;
    write_stderr_line(format_args!("username: {username}"))?;
    write_stderr_line(format_args!("password: {password}"))?;
    write_stderr_line(format_args!(
        "Change this password after first login and enable MFA."
    ))?;
    write_stderr_line(format_args!(""))
}

#[cfg(feature = "external-gateway")]
fn external_registry_hash_value(
    installation: &ExternalInstallationDef,
    projection: &ExternalProjectionDef,
) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(&(installation, projection))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[cfg(feature = "external-websocket")]
async fn start_external_websocket(
    cfg: &NexusConfig,
    boot: &Arc<Bootstrap>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let external_websocket_addr = match cfg.server.external_websocket_addr.clone() {
        Some(addr) => Some(addr),
        None => optional_env_var(EXTERNAL_WEBSOCKET_ADDR_ENV)?,
    };
    let Some(addr) = external_websocket_addr else {
        tracing::info!("{EXTERNAL_WEBSOCKET_ADDR_ENV} unset; external WebSocket gateway disabled");
        return Ok(());
    };
    let external_cfg = cfg.external_gateway.websocket.clone().bounded();
    let security = external_cfg
        .transport_security
        .validate_plain_listener("external WebSocket gateway", &addr)?;
    let listen_addr = security.listen_addr;
    log_external_transport_security("external WebSocket gateway", &addr, &security.config);
    let listener = TcpListener::bind(listen_addr).await?;
    let handler = DaemonExternalSessionHandler::with_limits(
        boot.kernel.state.clone(),
        boot.kernel.registry.clone(),
        external_cfg.session_limits(),
    );
    let mut ws_config: ExternalWebSocketConfig = external_cfg.transport.into();
    ws_config.transport_security = security.config;
    let service = Arc::new(ExternalWebSocketService::with_config(handler, ws_config));
    tracing::info!(%addr, "external WebSocket gateway listening");
    handles.push(tokio::spawn(async move {
        if let Err(e) = nexus_gateway_websocket::serve(service, listener).await {
            tracing::error!(?e, "external WebSocket gateway exited");
        }
    }));
    Ok(())
}

#[cfg(feature = "external-grpc")]
async fn start_external_grpc(
    cfg: &NexusConfig,
    boot: &Arc<Bootstrap>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let external_grpc_addr = match cfg.server.external_grpc_addr.clone() {
        Some(addr) => Some(addr),
        None => optional_env_var(EXTERNAL_GRPC_ADDR_ENV)?,
    };
    let Some(addr) = external_grpc_addr else {
        tracing::info!("{EXTERNAL_GRPC_ADDR_ENV} unset; external gRPC gateway disabled");
        return Ok(());
    };
    let external_cfg = cfg.external_gateway.grpc.clone().bounded();
    let security = external_cfg
        .transport_security
        .validate_grpc_listener("external gRPC gateway", &addr)?;
    let listen_addr = security.listen_addr;
    log_external_transport_security("external gRPC gateway", &addr, &security.config);
    let handler = DaemonExternalSessionHandler::with_limits(
        boot.kernel.state.clone(),
        boot.kernel.registry.clone(),
        external_cfg.session_limits(),
    );
    let service = nexus_gateway_grpc::ExternalGrpcService::with_config(
        handler,
        nexus_gateway_grpc::ExternalGrpcConfig {
            transport_security: security.config.clone(),
        },
    );
    tracing::info!(%addr, "external gRPC gateway listening");
    let mut server = grpc_server_builder(&security)?;
    handles.push(tokio::spawn(async move {
        if let Err(e) = server
            .add_service(service.into_server())
            .serve(listen_addr)
            .await
        {
            tracing::error!(?e, "external gRPC server exited");
        }
    }));
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn grpc_server_builder(
    security: &config::GatewayListenerSecurity,
) -> Result<tonic::transport::Server> {
    let server = tonic::transport::Server::builder();
    if let Some(tls) = security.tls.as_ref() {
        return server
            .tls_config(tonic_server_tls_config(tls)?)
            .map_err(|error| anyhow::anyhow!("configure gRPC TLS listener: {error}"));
    }
    Ok(server)
}

#[cfg(feature = "external-grpc")]
fn tonic_server_tls_config(
    tls: &config::GatewayListenerTlsMaterial,
) -> Result<tonic::transport::ServerTlsConfig> {
    let identity = tonic::transport::Identity::from_pem(
        tls.certificate_chain_pem.clone(),
        tls.private_key_pem.clone(),
    );
    let mut config = tonic::transport::ServerTlsConfig::new().identity(identity);
    if !tls.client_trust_roots_pem.is_empty() {
        config = config.client_ca_root(tonic::transport::Certificate::from_pem(
            tls.client_trust_roots_pem.clone(),
        ));
    }
    Ok(config)
}

#[cfg(feature = "external-gateway")]
struct DaemonExternalSessionHandler {
    state: Backend,
    registry: Registry,
    session_limits: config::ExternalGatewaySessionLimits,
    provider_sessions: Arc<std::sync::Mutex<BTreeMap<ProviderSessionKey, ProviderSessionRecord>>>,
    source_sessions: Arc<std::sync::Mutex<BTreeMap<SourceSessionKey, SourceSessionRecord>>>,
    provider_invocations: Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    provider_waiters: Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    source_commands: Arc<std::sync::Mutex<SourceCommandRegistry>>,
    source_waiters: Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    external_credentials: Arc<std::sync::Mutex<BTreeMap<(String, u64), ExternalCredential>>>,
    secure_replay_windows:
        Arc<std::sync::Mutex<BTreeMap<SecureReplayKey, SecureEnvelopeReplayWindow>>>,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone)]
struct ExternalAuthority {
    context: SessionContext,
    projection: ExternalProjectionDef,
    provider_capabilities: BTreeMap<Path, EffectCapability>,
    key_epoch: u64,
}

#[cfg(feature = "external-gateway")]
struct ExternalSessionState {
    credential_generation: u64,
    key_epoch: u64,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProviderSessionKey {
    installation_id: String,
    projection_id: String,
    session_id: String,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone)]
struct ProviderSessionRecord {
    endpoint_id: nexus_types::EndpointId,
    context: SessionContext,
    ready_endpoints: HashMap<ProviderEndpointKey, Path>,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProviderEndpointKey {
    resource_id: ResourceId,
    method_id: MethodId,
    binding_generation: u64,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone)]
struct ProviderBindingDeclaration {
    path: Path,
    purity: nexus_types::Purity,
    selector: ResourceSelector,
}

#[cfg(feature = "external-gateway")]
impl ProviderEndpointKey {
    fn from_dispatch(dispatch: RemoteInvokeDispatch) -> Self {
        Self {
            resource_id: dispatch.resource_id,
            method_id: dispatch.method_id,
            binding_generation: dispatch.binding_generation,
        }
    }
}

#[cfg(feature = "external-gateway")]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceSessionKey {
    installation_id: String,
    projection_id: String,
    session_id: String,
}

#[cfg(feature = "external-gateway")]
struct SourceSessionRecord {
    context: SessionContext,
    #[cfg(test)]
    outbound: ExternalSessionOutboundHandle,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SecureReplayKey {
    installation_id: String,
    projection_id: String,
    role: &'static str,
    session_id: String,
    key_epoch: u64,
}

#[cfg(feature = "external-gateway")]
struct ProviderRoleEndpoint {
    state: Backend,
    context: SessionContext,
    session: EndpointSession,
    outbound: ExternalSessionOutboundHandle,
    provider_invocations: Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    provider_waiters: Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    provider_sessions: Arc<std::sync::Mutex<BTreeMap<ProviderSessionKey, ProviderSessionRecord>>>,
    session_limits: config::ExternalGatewaySessionLimits,
}

#[cfg(feature = "external-gateway")]
type ExternalSessionOutboundHandle = Arc<dyn ExternalSessionOutbound<Error = tonic::Status>>;

#[cfg(feature = "external-gateway")]
#[async_trait::async_trait]
impl RemoteEndpoint for ProviderRoleEndpoint {
    async fn invoke(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: Invoke,
    ) -> Result<InvokeResult, DriverError> {
        let authority = load_external_authority(
            &self.state,
            &self.context.installation_id,
            &self.context.projection_id,
            Role::Provider,
        )
        .await
        .map_err(status_to_driver_error)?;
        if !context_matches_authority(&authority.context, &self.context) {
            return Err(DriverError::Transport("provider authority changed".into()));
        }
        let capability = self.admit_invoke(dispatch, &invoke, &authority)?;
        validate_json_schema(capability.input_schema.as_ref(), &invoke.input).map_err(|error| {
            DriverError::Transport(format!("provider invoke input rejected: {error}"))
        })?;
        let output_schema = capability.output_schema.as_ref();
        let invocation_id = invoke.invocation_id.clone();
        let deadline_ms = invoke.deadline_ms;

        let (tx, rx) = oneshot::channel();
        {
            let mut invocations = self.provider_invocations.lock().map_err(|_| {
                DriverError::Transport("provider invocation registry unavailable".into())
            })?;
            invocations
                .register(ProviderInvocationRegister {
                    session: &self.session,
                    invoke: &invoke,
                    current_registry_hash: &authority.context.registry_hash,
                    credential_generation: authority.context.credential_generation,
                    current_binding_generation: authority.context.binding_generation,
                    current_projection_version: authority.context.projection_version,
                    now_millis: now_millis(),
                    acting: dispatch.acting,
                    max_in_flight: Some(self.session_limits.provider_max_in_flight_invocations),
                    max_identity_in_flight: Some(
                        self.session_limits.provider_max_in_flight_per_identity,
                    ),
                    max_effect_in_flight: Some(
                        self.session_limits.provider_max_in_flight_per_effect,
                    ),
                    max_inline_result_bytes: None,
                    output_schema,
                })
                .map_err(|error| DriverError::Transport(error.to_string()))?;
        }
        let waiter_inserted = self
            .provider_waiters
            .lock()
            .map_err(|_| DriverError::Transport("provider invocation waiter unavailable".into()))
            .and_then(|mut waiters| match waiters.entry(invocation_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(tx);
                    Ok(())
                }
                Entry::Occupied(_) => Err(DriverError::Transport(
                    "provider invocation waiter duplicate".into(),
                )),
            });
        if let Err(error) = waiter_inserted {
            remove_provider_invocation_registry_entry(&self.provider_invocations, &invocation_id)
                .map_err(|cleanup| {
                DriverError::Transport(format!(
                    "{error}; provider invocation cleanup failed: {cleanup}"
                ))
            })?;
            return Err(error);
        }

        if let Err(status) = self.outbound.send_invoke(invoke).await {
            let invoke_error = status_to_driver_error(status);
            remove_provider_invocation_pending(
                &self.provider_invocations,
                &self.provider_waiters,
                &invocation_id,
            )
            .map_err(|cleanup| {
                DriverError::Transport(format!(
                    "{invoke_error}; provider invocation cleanup failed: {cleanup}"
                ))
            })?;
            return Err(invoke_error);
        }

        match await_provider_result(rx, deadline_ms).await {
            Ok(result) => Ok(result),
            Err(error) => {
                match error {
                    ProviderAwaitError::DeadlineExceeded => {
                        if let Err(status) = self
                            .outbound
                            .send_control(ControlFrame::ProviderCancel {
                                invocation_id: invocation_id.clone(),
                                reason: "deadline_exceeded".into(),
                            })
                            .await
                        {
                            tracing::warn!(
                                ?status,
                                %invocation_id,
                                "provider invocation cancel frame was not delivered"
                            );
                        }
                    }
                    ProviderAwaitError::ProviderUnavailable => {}
                }
                remove_provider_invocation_pending(
                    &self.provider_invocations,
                    &self.provider_waiters,
                    &invocation_id,
                )
                .map_err(|cleanup| {
                    DriverError::Transport(format!(
                        "{}; provider invocation cleanup failed: {cleanup}",
                        error.into_driver_error()
                    ))
                })?;
                Err(error.into_driver_error())
            }
        }
    }
}

#[cfg(feature = "external-gateway")]
impl ProviderRoleEndpoint {
    fn admit_invoke<'a>(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: &Invoke,
        authority: &'a ExternalAuthority,
    ) -> Result<&'a EffectCapability, DriverError> {
        if invoke.method_id != dispatch.method_id {
            return Err(DriverError::Transport(
                "provider invoke method rejected".into(),
            ));
        }
        let sessions = self
            .provider_sessions
            .lock()
            .map_err(|_| DriverError::Transport("provider session registry unavailable".into()))?;
        let session = sessions
            .get(&provider_session_key(&self.context))
            .ok_or_else(|| DriverError::Transport("provider session not ready".into()))?;
        if session.context != self.context {
            return Err(DriverError::Transport(
                "provider session context rejected".into(),
            ));
        }
        if dispatch.endpoint_id != session.endpoint_id {
            return Err(DriverError::Transport(
                "provider invoke effect rejected".into(),
            ));
        }
        let Some(ready_path) = session
            .ready_endpoints
            .get(&ProviderEndpointKey::from_dispatch(dispatch))
        else {
            if session.ready_endpoints.keys().any(|key| {
                key.resource_id == dispatch.resource_id
                    && key.binding_generation == dispatch.binding_generation
            }) {
                return Err(DriverError::Transport(
                    "provider invoke method rejected".into(),
                ));
            }
            return Err(DriverError::Transport(
                "provider invoke effect rejected".into(),
            ));
        };
        if ready_path != &invoke.effect_path {
            return Err(DriverError::Transport(
                "provider invoke effect rejected".into(),
            ));
        }
        authority
            .provider_capabilities
            .get(ready_path)
            .ok_or_else(|| DriverError::Transport("provider invoke effect rejected".into()))
    }
}

#[cfg(feature = "external-gateway")]
fn remove_provider_invocation_pending(
    provider_invocations: &Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    provider_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    invocation_id: &str,
) -> Result<(), DriverError> {
    remove_provider_invocation_registry_entry(provider_invocations, invocation_id)?;
    provider_waiters
        .lock()
        .map_err(|_| DriverError::Transport("provider invocation waiter unavailable".into()))
        .map(|mut waiters| {
            waiters.remove(invocation_id);
        })
}

#[cfg(feature = "external-gateway")]
fn remove_provider_invocation_registry_entry(
    provider_invocations: &Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    invocation_id: &str,
) -> Result<(), DriverError> {
    provider_invocations
        .lock()
        .map_err(|_| DriverError::Transport("provider invocation registry unavailable".into()))
        .map(|mut invocations| {
            invocations.remove(invocation_id);
        })
}

#[cfg(feature = "external-gateway")]
async fn await_provider_result(
    rx: oneshot::Receiver<InvokeResult>,
    deadline_ms: Option<i64>,
) -> Result<InvokeResult, ProviderAwaitError> {
    let Some(deadline_ms) = deadline_ms else {
        return rx
            .await
            .map_err(|_| ProviderAwaitError::ProviderUnavailable);
    };
    let now = now_millis();
    if deadline_ms <= now {
        return Err(ProviderAwaitError::DeadlineExceeded);
    }
    match tokio::time::timeout(Duration::from_millis((deadline_ms - now) as u64), rx).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(ProviderAwaitError::ProviderUnavailable),
        Err(_) => Err(ProviderAwaitError::DeadlineExceeded),
    }
}

#[cfg(feature = "external-gateway")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderAwaitError {
    DeadlineExceeded,
    ProviderUnavailable,
}

#[cfg(feature = "external-gateway")]
impl ProviderAwaitError {
    fn into_driver_error(self) -> DriverError {
        match self {
            ProviderAwaitError::DeadlineExceeded => {
                DriverError::Transport("provider invocation deadline exceeded".into())
            }
            ProviderAwaitError::ProviderUnavailable => {
                DriverError::Transport("provider unavailable".into())
            }
        }
    }
}

#[cfg(all(test, feature = "external-gateway"))]
fn remove_source_command_pending(
    source_commands: &Arc<std::sync::Mutex<SourceCommandRegistry>>,
    source_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    command_id: &str,
) -> Result<(), tonic::Status> {
    remove_source_command_registry_entry(source_commands, command_id)?;
    remove_source_command_waiter(source_waiters, command_id)
}

#[cfg(feature = "external-gateway")]
fn remove_source_command_waiter(
    source_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    command_id: &str,
) -> Result<(), tonic::Status> {
    source_waiters
        .lock()
        .map_err(|_| tonic::Status::internal("source command waiter unavailable"))
        .map(|mut waiters| {
            waiters.remove(command_id);
        })
}

#[cfg(all(test, feature = "external-gateway"))]
fn remove_source_command_registry_entry(
    source_commands: &Arc<std::sync::Mutex<SourceCommandRegistry>>,
    command_id: &str,
) -> Result<(), tonic::Status> {
    source_commands
        .lock()
        .map_err(|_| tonic::Status::internal("source command registry unavailable"))
        .map(|mut commands| {
            commands.remove(command_id);
        })
}

#[cfg(all(test, feature = "external-gateway"))]
fn remove_source_command_waiters(
    source_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    command_ids: Vec<String>,
) -> Result<(), tonic::Status> {
    if command_ids.is_empty() {
        return Ok(());
    }
    source_waiters
        .lock()
        .map_err(|_| tonic::Status::internal("source command waiter unavailable"))
        .map(|mut waiters| {
            for command_id in command_ids {
                waiters.remove(&command_id);
            }
        })
}

#[cfg(all(test, feature = "external-gateway"))]
fn schedule_source_command_deadline(
    source_commands: Arc<std::sync::Mutex<SourceCommandRegistry>>,
    source_waiters: Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    deadline_ms: i64,
) {
    tokio::spawn(async move {
        let now = now_millis();
        if deadline_ms > now {
            tokio::time::sleep(Duration::from_millis((deadline_ms - now) as u64)).await;
        }
        let expired = match source_commands.lock() {
            Ok(mut commands) => commands.expire(now_millis()),
            Err(_) => {
                tracing::warn!("source command deadline registry unavailable");
                return;
            }
        };
        if let Err(status) = remove_source_command_waiters(&source_waiters, expired) {
            tracing::warn!(?status, "source command deadline waiter cleanup failed");
        }
    });
}

#[cfg(feature = "external-gateway")]
impl DaemonExternalSessionHandler {
    #[cfg(all(test, feature = "external-grpc"))]
    fn new(state: Backend, registry: Registry, source_dedupe_window_ms: u64) -> Self {
        Self::with_limits(
            state,
            registry,
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms,
                ..Default::default()
            },
        )
    }

    fn with_limits(
        state: Backend,
        registry: Registry,
        session_limits: config::ExternalGatewaySessionLimits,
    ) -> Self {
        let session_limits = session_limits.bounded();
        Self {
            state,
            registry,
            session_limits,
            provider_sessions: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            source_sessions: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            provider_invocations: Arc::new(
                std::sync::Mutex::new(ProviderInvocationRegistry::new()),
            ),
            provider_waiters: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            source_commands: Arc::new(std::sync::Mutex::new(SourceCommandRegistry::new())),
            source_waiters: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            external_credentials: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            secure_replay_windows: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    #[cfg(all(test, feature = "external-grpc"))]
    async fn register_provider_invoke(
        &self,
        invoke: &Invoke,
        session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<oneshot::Receiver<InvokeResult>, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Provider,
            )
            .await?;
        let (tx, rx) = oneshot::channel();
        let capability = authority
            .provider_capabilities
            .get(&invoke.effect_path)
            .ok_or_else(|| tonic::Status::permission_denied("provider invocation rejected"))?;
        validate_json_schema(capability.input_schema.as_ref(), &invoke.input).map_err(|error| {
            tonic::Status::invalid_argument(format!("provider invocation rejected: {error}"))
        })?;
        let output_schema = capability.output_schema.as_ref();
        {
            let mut invocations = self
                .provider_invocations
                .lock()
                .map_err(|_| tonic::Status::internal("provider invocation registry unavailable"))?;
            invocations
                .register(ProviderInvocationRegister {
                    session,
                    invoke,
                    current_registry_hash: &authority.context.registry_hash,
                    credential_generation: authority.context.credential_generation,
                    current_binding_generation: authority.context.binding_generation,
                    current_projection_version: authority.context.projection_version,
                    now_millis: now_millis(),
                    acting: IdentityRef::ROOT,
                    max_in_flight: Some(self.session_limits.provider_max_in_flight_invocations),
                    max_identity_in_flight: Some(
                        self.session_limits.provider_max_in_flight_per_identity,
                    ),
                    max_effect_in_flight: Some(
                        self.session_limits.provider_max_in_flight_per_effect,
                    ),
                    max_inline_result_bytes: None,
                    output_schema,
                })
                .map_err(provider_invocation_status)?;
        }
        let waiter_inserted = self
            .provider_waiters
            .lock()
            .map_err(|_| tonic::Status::internal("provider invocation waiter unavailable"))
            .and_then(
                |mut waiters| match waiters.entry(invoke.invocation_id.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(tx);
                        Ok(())
                    }
                    Entry::Occupied(_) => Err(tonic::Status::failed_precondition(
                        "provider invocation waiter duplicate",
                    )),
                },
            );
        if let Err(error) = waiter_inserted {
            remove_provider_invocation_registry_entry(
                &self.provider_invocations,
                &invoke.invocation_id,
            )
            .map_err(|cleanup| {
                tonic::Status::internal(format!(
                    "{}; provider invocation cleanup failed: {cleanup}",
                    error.message()
                ))
            })?;
            return Err(error);
        }
        Ok(rx)
    }

    #[cfg(test)]
    async fn send_source_command(
        &self,
        mut command: OutboundCommand,
        session: &EndpointSession,
        context: &SessionContext,
        deadline_ms: Option<i64>,
    ) -> Result<oneshot::Receiver<CommandResult>, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Source,
            )
            .await?;
        if !context_matches_authority(&authority.context, context) {
            return Err(tonic::Status::permission_denied("source command rejected"));
        }
        let emits = authority
            .projection
            .emits
            .as_ref()
            .filter(|emits| emits.commands)
            .ok_or_else(|| tonic::Status::permission_denied("source command rejected"))?;

        let outbound = {
            let sessions = self
                .source_sessions
                .lock()
                .map_err(|_| tonic::Status::internal("source session registry unavailable"))?;
            let record = sessions
                .get(&source_session_key(context))
                .ok_or_else(|| tonic::Status::failed_precondition("source session not ready"))?;
            if record.context != *context {
                return Err(tonic::Status::permission_denied(
                    "source session context rejected",
                ));
            }
            record.outbound.clone()
        };

        command.observed = ObservedGenerations {
            presentation_config_generation: context.presentation_config_generation,
            alias_catalog_generation: context.alias_catalog_generation,
        };
        let command_id = command.id.clone();
        let (tx, rx) = oneshot::channel();
        {
            let mut commands = self
                .source_commands
                .lock()
                .map_err(|_| tonic::Status::internal("source command registry unavailable"))?;
            commands
                .register(SourceCommandRegister {
                    session,
                    command: &command,
                    current_registry_hash: &authority.context.registry_hash,
                    credential_generation: authority.context.credential_generation,
                    current_binding_generation: authority.context.binding_generation,
                    current_installation_config_version: authority
                        .context
                        .installation_config_version,
                    current_projection_version: authority.context.projection_version,
                    now_millis: now_millis(),
                    deadline_ms,
                    max_in_flight: Some(self.session_limits.source_max_in_flight_commands),
                    max_inline_result_bytes: None,
                    idempotency_window_ms: self.session_limits.source_dedupe_window_ms,
                    rate_limit_window_ms: self.session_limits.source_command_rate_limit_window_ms,
                    rate_limit_max_commands: self.session_limits.source_command_rate_limit_max,
                    command_schema: emits.command_schema.as_ref(),
                    command_result_schema: emits.command_result_schema.as_ref(),
                })
                .map_err(source_command_dispatch_status)?;
        }
        let waiter_inserted = self
            .source_waiters
            .lock()
            .map_err(|_| tonic::Status::internal("source command waiter unavailable"))
            .and_then(|mut waiters| match waiters.entry(command_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(tx);
                    Ok(())
                }
                Entry::Occupied(_) => Err(tonic::Status::failed_precondition(
                    "source command waiter duplicate",
                )),
            });
        if let Err(error) = waiter_inserted {
            remove_source_command_registry_entry(&self.source_commands, &command_id).map_err(
                |cleanup| {
                    tonic::Status::internal(format!(
                        "{}; source command cleanup failed: {}",
                        error.message(),
                        cleanup.message()
                    ))
                },
            )?;
            return Err(error);
        }

        if let Err(status) = outbound.send_outbound_command(command).await {
            remove_source_command_pending(&self.source_commands, &self.source_waiters, &command_id)
                .map_err(|cleanup| {
                    tonic::Status::internal(format!(
                        "{}; source command cleanup failed: {}",
                        status.message(),
                        cleanup.message()
                    ))
                })?;
            return Err(status);
        }

        if let Some(deadline_ms) = deadline_ms {
            schedule_source_command_deadline(
                self.source_commands.clone(),
                self.source_waiters.clone(),
                deadline_ms,
            );
        }

        Ok(rx)
    }
}

#[cfg(feature = "external-gateway")]
impl DaemonExternalSessionHandler {
    async fn adjudicate_external_session(
        &self,
        hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, tonic::Status> {
        let mut authority = self
            .load_authority(&hello.installation_id, &hello.projection_id, hello.role)
            .await?
            .context;
        authority.session_id = new_external_session_id()?;
        Ok(authority)
    }

    async fn close_external_session(
        &self,
        _session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        match context.role {
            Role::Provider => {
                let key = provider_session_key(&context);
                let mut sessions = self.provider_sessions.lock().map_err(|_| {
                    tonic::Status::internal("provider session registry unavailable")
                })?;
                if sessions
                    .get(&key)
                    .is_some_and(|record| record.context == context)
                {
                    let record = sessions.remove(&key);
                    drop(sessions);
                    if let Some(record) = record {
                        self.registry.unregister_endpoint(record.endpoint_id);
                    }
                } else {
                    drop(sessions);
                }
                let pending = self
                    .provider_invocations
                    .lock()
                    .map_err(|_| {
                        tonic::Status::internal("provider invocation registry unavailable")
                    })?
                    .drain_for_session(&context);
                if !pending.is_empty() {
                    let mut waiters = self.provider_waiters.lock().map_err(|_| {
                        tonic::Status::internal("provider invocation waiter unavailable")
                    })?;
                    for invocation_id in pending {
                        waiters.remove(&invocation_id);
                    }
                }
            }
            Role::Source => {
                let key = source_session_key(&context);
                let mut sessions = self
                    .source_sessions
                    .lock()
                    .map_err(|_| tonic::Status::internal("source session registry unavailable"))?;
                if sessions
                    .get(&key)
                    .is_some_and(|record| record.context == context)
                {
                    sessions.remove(&key);
                }
                drop(sessions);
                let pending = self
                    .source_commands
                    .lock()
                    .map_err(|_| tonic::Status::internal("source command registry unavailable"))?
                    .drain_for_session(&context, now_millis());
                if !pending.is_empty() {
                    let mut waiters = self.source_waiters.lock().map_err(|_| {
                        tonic::Status::internal("source command waiter unavailable")
                    })?;
                    for command_id in pending {
                        waiters.remove(&command_id);
                    }
                }
            }
        }
        remove_secure_replay_windows_for_context(&self.secure_replay_windows, &context)?;
        Ok(())
    }

    async fn handle_inbound_event(
        &self,
        event: InboundEvent,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<EventAck, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Source,
            )
            .await?;
        let policy = PolicySnapshot::empty();
        let event_id = event.id.clone();
        match ingest_source_event(
            SourceIngest {
                state: self.state.clone(),
                session,
                installation_id: &context.installation_id,
                projection: &authority.projection,
                current_registry_hash: &authority.context.registry_hash,
                credential_generation: authority.context.credential_generation,
                current_binding_generation: authority.context.binding_generation,
                current_installation_config_version: authority.context.installation_config_version,
                policy: &policy,
                acting: IdentityRef::ROOT,
                target: ResourceId::new(0),
                now_millis: now_millis(),
                dedupe_window_ms: self.session_limits.source_dedupe_window_ms,
            },
            event,
        )
        .await
        {
            Ok(ack) => Ok(ack),
            Err(error) => match source_ingest_rejection_ack(event_id, &error) {
                Some(ack) => Ok(ack),
                None => Err(source_ingest_status(error)),
            },
        }
    }

    async fn handle_command_result(
        &self,
        result: CommandResult,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        let result_id = result.id.clone();
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Source,
            )
            .await?;
        let accepted = {
            let mut commands = self
                .source_commands
                .lock()
                .map_err(|_| tonic::Status::internal("source command registry unavailable"))?;
            match commands.resolve(SourceCommandResolve {
                session,
                result,
                current_registry_hash: &authority.context.registry_hash,
                credential_generation: authority.context.credential_generation,
                current_binding_generation: authority.context.binding_generation,
                current_installation_config_version: authority.context.installation_config_version,
                current_projection_version: authority.context.projection_version,
                now_millis: now_millis(),
            }) {
                Ok(accepted) => accepted,
                Err(error) => {
                    drop(commands);
                    if source_command_error_removes_entry(&error) {
                        remove_source_command_waiter(&self.source_waiters, &result_id)?;
                    }
                    return Err(source_command_status(error));
                }
            }
        };
        let waiter = self
            .source_waiters
            .lock()
            .map_err(|_| tonic::Status::internal("source command waiter unavailable"))?
            .remove(&accepted.id)
            .ok_or_else(|| tonic::Status::failed_precondition("source command waiter missing"))?;
        waiter
            .send(accepted)
            .map_err(|_| tonic::Status::unavailable("source command receiver closed"))
    }

    async fn handle_invoke_result(
        &self,
        result: InvokeResult,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        let invocation_id = result.invocation_id.clone();
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Provider,
            )
            .await?;
        let accepted = {
            let mut invocations = self
                .provider_invocations
                .lock()
                .map_err(|_| tonic::Status::internal("provider invocation registry unavailable"))?;
            match invocations.resolve(ProviderInvocationResolve {
                session,
                result,
                current_registry_hash: &authority.context.registry_hash,
                credential_generation: authority.context.credential_generation,
                current_binding_generation: authority.context.binding_generation,
                current_projection_version: authority.context.projection_version,
                now_millis: now_millis(),
            }) {
                Ok(accepted) => accepted,
                Err(error) => {
                    drop(invocations);
                    if provider_invocation_error_removes_entry(&error) {
                        remove_provider_invocation_pending(
                            &self.provider_invocations,
                            &self.provider_waiters,
                            &invocation_id,
                        )
                        .map_err(|cleanup| tonic::Status::internal(cleanup.to_string()))?;
                    }
                    return Err(provider_invocation_status(error));
                }
            }
        };
        let waiter = self
            .provider_waiters
            .lock()
            .map_err(|_| tonic::Status::internal("provider invocation waiter unavailable"))?
            .remove(&accepted.invocation_id)
            .ok_or_else(|| {
                tonic::Status::failed_precondition("provider invocation waiter missing")
            })?;
        waiter
            .send(accepted)
            .map_err(|_| tonic::Status::unavailable("provider invocation receiver closed"))
    }

    async fn handle_control(
        &self,
        frame: ControlFrame,
        _session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, &context) {
            return Err(tonic::Status::permission_denied(
                "external control frame rejected",
            ));
        }
        validate_external_control_frame(&frame, &context)
    }

    async fn open_external_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        _session: &EndpointSession,
        context: SessionContext,
    ) -> Result<Vec<u8>, tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, &context) {
            return Err(tonic::Status::permission_denied("secure envelope rejected"));
        }
        let credential = self
            .external_credentials
            .lock()
            .map_err(|_| tonic::Status::internal("external credential store unavailable"))?
            .get(&(
                context.installation_id.clone(),
                context.credential_generation,
            ))
            .cloned()
            .ok_or_else(|| tonic::Status::unauthenticated("external credential unavailable"))?;
        let replay_key = SecureReplayKey {
            installation_id: context.installation_id.clone(),
            projection_id: context.projection_id.clone(),
            role: role_slug(context.role),
            session_id: envelope.aad().session_id.clone(),
            key_epoch: envelope.aad().key_epoch,
        };
        let mut replay_windows = self
            .secure_replay_windows
            .lock()
            .map_err(|_| tonic::Status::internal("secure envelope replay state unavailable"))?;
        let replay_window = replay_windows.entry(replay_key).or_default();
        let epoch_gate = SecureEnvelopeEpochGate::new(authority.key_epoch);
        credential
            .open_with_replay_window_and_epoch_gate(
                envelope,
                authority.context.credential_generation,
                replay_window,
                &epoch_gate,
            )
            .map_err(|_| tonic::Status::permission_denied("secure envelope rejected"))
    }
}

#[cfg(feature = "external-gateway")]
#[tonic::async_trait]
impl ExternalSessionHandler for DaemonExternalSessionHandler {
    type Error = tonic::Status;
    type OutboundError = tonic::Status;

    async fn adjudicate_session(
        &self,
        hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, tonic::Status> {
        self.adjudicate_external_session(hello).await
    }

    async fn on_ready(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: ExternalSessionOutboundHandle,
    ) -> Result<(), tonic::Status> {
        self.register_ready_session(session, context, outbound)
            .await
    }

    async fn on_closed(
        &self,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.close_external_session(session, context).await
    }

    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<EventAck, tonic::Status> {
        self.handle_inbound_event(event, session, context).await
    }

    async fn on_command_result(
        &self,
        result: CommandResult,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_command_result(result, session, context).await
    }

    async fn on_invoke_result(
        &self,
        result: InvokeResult,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_invoke_result(result, session, context).await
    }

    async fn on_control(
        &self,
        frame: ControlFrame,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_control(frame, session, context).await
    }

    async fn open_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<Vec<u8>, tonic::Status> {
        self.open_external_secure_envelope(envelope, session, context)
            .await
    }
}

#[cfg(feature = "external-gateway")]
impl DaemonExternalSessionHandler {
    async fn register_ready_session(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: ExternalSessionOutboundHandle,
    ) -> Result<(), tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                context.role,
            )
            .await?;
        if !context_matches_authority(&authority.context, &context) {
            return Err(tonic::Status::permission_denied(
                "external session context rejected",
            ));
        }
        match context.role {
            Role::Provider => {
                let binding_declarations =
                    validate_provider_projection_bindings(&authority.projection)?;
                let mut provider_sessions = self.provider_sessions.lock().map_err(|_| {
                    tonic::Status::internal("provider session registry unavailable")
                })?;
                let endpoint_id = self.registry.next_endpoint_id();
                let endpoint = ProviderRoleEndpoint {
                    state: self.state.clone(),
                    context: context.clone(),
                    session: session.clone(),
                    outbound,
                    provider_invocations: self.provider_invocations.clone(),
                    provider_waiters: self.provider_waiters.clone(),
                    provider_sessions: self.provider_sessions.clone(),
                    session_limits: self.session_limits,
                };
                self.registry
                    .register_endpoint(endpoint_id, Arc::new(endpoint));
                let ready_endpoints = match register_provider_bindings(
                    &self.registry,
                    &binding_declarations,
                    endpoint_id,
                    &context,
                ) {
                    Ok(ready_endpoints) => ready_endpoints,
                    Err(error) => {
                        self.registry.unregister_endpoint(endpoint_id);
                        return Err(error);
                    }
                };
                if let Some(old) = provider_sessions.insert(
                    provider_session_key(&context),
                    ProviderSessionRecord {
                        endpoint_id,
                        context,
                        ready_endpoints,
                    },
                ) {
                    self.registry.unregister_endpoint(old.endpoint_id);
                }
            }
            Role::Source => {
                self.source_sessions
                    .lock()
                    .map_err(|_| tonic::Status::internal("source session registry unavailable"))?
                    .insert(
                        source_session_key(&context),
                        SourceSessionRecord {
                            context,
                            #[cfg(test)]
                            outbound,
                        },
                    );
            }
        }
        Ok(())
    }

    async fn load_authority(
        &self,
        installation_id: &str,
        projection_id: &str,
        role: Role,
    ) -> Result<ExternalAuthority, tonic::Status> {
        load_external_authority(&self.state, installation_id, projection_id, role).await
    }
}

#[cfg(feature = "external-gateway")]
async fn load_external_authority(
    state: &Backend,
    installation_id: &str,
    projection_id: &str,
    role: Role,
) -> Result<ExternalAuthority, tonic::Status> {
    let installation = load_external_installation(state, installation_id).await?;
    let role_session = load_external_session(state, installation_id, role).await?;
    let projection = installation
        .projection(projection_id)
        .cloned()
        .ok_or_else(|| tonic::Status::not_found("external projection not found"))?;
    if projection.role != role {
        return Err(tonic::Status::permission_denied(
            "external projection role mismatch",
        ));
    }
    let provider_capabilities = provider_capability_index(&projection)?;
    let registry_hash = external_registry_hash(&installation, &projection)?;
    Ok(ExternalAuthority {
        context: SessionContext {
            installation_id: installation.id.clone(),
            projection_id: projection.id.clone(),
            role: projection.role,
            registry_hash,
            credential_generation: role_session.credential_generation,
            binding_generation: projection.version,
            installation_config_version: installation.version,
            projection_version: projection.version,
            presentation_config_generation: 0,
            alias_catalog_generation: 0,
            session_id: String::new(),
        },
        projection,
        provider_capabilities,
        key_epoch: role_session.key_epoch,
    })
}

#[cfg(feature = "external-gateway")]
fn provider_capability_index(
    projection: &ExternalProjectionDef,
) -> Result<BTreeMap<Path, EffectCapability>, tonic::Status> {
    if projection.role != Role::Provider {
        return Ok(BTreeMap::new());
    }
    let mut capabilities = BTreeMap::new();
    for capability in &projection.provides {
        let path = Path::parse(&capability.effect_path).map_err(|error| {
            tonic::Status::failed_precondition(format!("external projection is invalid: {error}"))
        })?;
        if capabilities.insert(path, capability.clone()).is_some() {
            return Err(tonic::Status::failed_precondition(
                "external projection is invalid",
            ));
        }
    }
    Ok(capabilities)
}

#[cfg(feature = "external-gateway")]
async fn load_external_installation(
    state: &Backend,
    installation_id: &str,
) -> Result<ExternalInstallationDef, tonic::Status> {
    validate_external_path_segment(installation_id, "external installation id")?;
    let path = Path::parse(&format!(
        "state://kernel/external-installations/{installation_id}"
    ))
    .map_err(|error| {
        tonic::Status::invalid_argument(format!("external installation id is invalid: {error}"))
    })?;
    let Some(value) = state.read(&path).await.map_err(|error| {
        tonic::Status::unavailable(format!("external state read failed: {error}"))
    })?
    else {
        return Err(tonic::Status::not_found("external installation not found"));
    };
    let json = serde_json::to_value(value).map_err(|error| {
        tonic::Status::failed_precondition(format!("external state is invalid: {error}"))
    })?;
    let installation: ExternalInstallationDef = serde_json::from_value(json).map_err(|error| {
        tonic::Status::failed_precondition(format!("external installation is invalid: {error}"))
    })?;
    if installation.id != installation_id {
        return Err(tonic::Status::failed_precondition(
            "external installation id mismatch",
        ));
    }
    installation.validate_admission().map_err(|error| {
        tonic::Status::failed_precondition(format!(
            "external installation admission failed: {error}"
        ))
    })?;
    Ok(installation)
}

#[cfg(feature = "external-gateway")]
async fn load_external_session(
    state: &Backend,
    installation_id: &str,
    role: Role,
) -> Result<ExternalSessionState, tonic::Status> {
    validate_external_path_segment(installation_id, "external installation id")?;
    let role = role_slug(role);
    let path = Path::parse(&format!(
        "state://kernel/external-sessions/{installation_id}/{role}"
    ))
    .map_err(|error| {
        tonic::Status::invalid_argument(format!("external session id is invalid: {error}"))
    })?;
    let Some(value) = state.read(&path).await.map_err(|error| {
        tonic::Status::unavailable(format!("external session state read failed: {error}"))
    })?
    else {
        return Err(tonic::Status::unauthenticated(
            "external session is not approved",
        ));
    };
    let record = value
        .as_map()
        .ok_or_else(|| tonic::Status::failed_precondition("external session is invalid"))?;
    if record.get("installation_id").and_then(Value::as_str) != Some(installation_id)
        || record.get("role").and_then(Value::as_str) != Some(role)
    {
        return Err(tonic::Status::failed_precondition(
            "external session mismatch",
        ));
    }
    if record.get("state").and_then(Value::as_str) != Some("ready") {
        return Err(tonic::Status::unauthenticated(
            "external session is not ready",
        ));
    }
    let generation = credential_generation_from_record(record)?;
    ensure_external_not_revoked(state, installation_id, generation).await?;
    let key_epoch = key_epoch_from_record(record)?;
    Ok(ExternalSessionState {
        credential_generation: generation,
        key_epoch,
    })
}

#[cfg(feature = "external-gateway")]
async fn ensure_external_not_revoked(
    state: &Backend,
    installation_id: &str,
    credential_generation: u64,
) -> Result<(), tonic::Status> {
    validate_external_path_segment(installation_id, "external installation id")?;
    let path = Path::parse(&format!(
        "state://kernel/external-credential-revocations/{installation_id}"
    ))
    .map_err(|error| {
        tonic::Status::invalid_argument(format!("external revocation id is invalid: {error}"))
    })?;
    let Some(value) = state.read(&path).await.map_err(|error| {
        tonic::Status::unavailable(format!("external revocation state read failed: {error}"))
    })?
    else {
        return Ok(());
    };
    let record = value.as_map().ok_or_else(|| {
        tonic::Status::failed_precondition("external revocation state is invalid")
    })?;
    if let Some(id) = record.get("installation_id").and_then(Value::as_str)
        && id != installation_id
    {
        return Err(tonic::Status::failed_precondition(
            "external revocation id mismatch",
        ));
    }
    if let Some(state) = record.get("state").and_then(Value::as_str)
        && state != "revoked"
    {
        return Err(tonic::Status::failed_precondition(
            "external revocation state is invalid",
        ));
    }
    let floor = record
        .get("credential_generation_floor")
        .and_then(Value::as_int)
        .ok_or_else(|| {
            tonic::Status::failed_precondition("external revocation floor is invalid")
        })?;
    if floor < 0 {
        return Err(tonic::Status::failed_precondition(
            "external revocation floor is invalid",
        ));
    }
    if credential_generation <= floor as u64 {
        return Err(tonic::Status::unauthenticated(
            "external credential revoked",
        ));
    }
    Ok(())
}

#[cfg(feature = "external-gateway")]
fn external_registry_hash(
    installation: &ExternalInstallationDef,
    projection: &ExternalProjectionDef,
) -> Result<String, tonic::Status> {
    external_registry_hash_value(installation, projection).map_err(|error| {
        tonic::Status::failed_precondition(format!("external registry is invalid: {error}"))
    })
}

#[cfg(feature = "external-gateway")]
fn credential_generation_from_record(
    record: &std::collections::BTreeMap<String, Value>,
) -> Result<u64, tonic::Status> {
    let generation = record
        .get("credential_generation")
        .and_then(Value::as_int)
        .ok_or_else(|| {
            tonic::Status::failed_precondition("external session generation is invalid")
        })?;
    if generation <= 0 {
        return Err(tonic::Status::failed_precondition(
            "external session generation is invalid",
        ));
    }
    Ok(generation as u64)
}

#[cfg(feature = "external-gateway")]
fn key_epoch_from_record(
    record: &std::collections::BTreeMap<String, Value>,
) -> Result<u64, tonic::Status> {
    let Some(value) = record.get("key_epoch") else {
        return Ok(0);
    };
    let Some(epoch) = value.as_int() else {
        return Err(tonic::Status::failed_precondition(
            "external session key epoch is invalid",
        ));
    };
    if epoch < 0 {
        return Err(tonic::Status::failed_precondition(
            "external session key epoch is invalid",
        ));
    }
    Ok(epoch as u64)
}

#[cfg(feature = "external-gateway")]
fn role_slug(role: Role) -> &'static str {
    match role {
        Role::Provider => "provider",
        Role::Source => "source",
    }
}

#[cfg(feature = "external-gateway")]
fn is_valid_external_path_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(feature = "external-gateway")]
fn validate_external_path_segment(segment: &str, label: &'static str) -> Result<(), tonic::Status> {
    if is_valid_external_path_segment(segment) {
        Ok(())
    } else {
        Err(tonic::Status::invalid_argument(format!(
            "{label} is invalid"
        )))
    }
}

#[cfg(feature = "external-gateway")]
fn provider_session_key(context: &SessionContext) -> ProviderSessionKey {
    ProviderSessionKey {
        installation_id: context.installation_id.clone(),
        projection_id: context.projection_id.clone(),
        session_id: context.session_id.clone(),
    }
}

#[cfg(feature = "external-gateway")]
fn source_session_key(context: &SessionContext) -> SourceSessionKey {
    SourceSessionKey {
        installation_id: context.installation_id.clone(),
        projection_id: context.projection_id.clone(),
        session_id: context.session_id.clone(),
    }
}

#[cfg(feature = "external-gateway")]
fn remove_secure_replay_windows_for_context(
    replay_windows: &std::sync::Mutex<BTreeMap<SecureReplayKey, SecureEnvelopeReplayWindow>>,
    context: &SessionContext,
) -> Result<(), tonic::Status> {
    let role = role_slug(context.role);
    replay_windows
        .lock()
        .map_err(|_| tonic::Status::internal("secure envelope replay state unavailable"))?
        .retain(|key, _| {
            key.installation_id != context.installation_id
                || key.projection_id != context.projection_id
                || key.role != role
                || key.session_id != context.session_id
        });
    Ok(())
}

#[cfg(feature = "external-gateway")]
fn context_matches_authority(authority: &SessionContext, context: &SessionContext) -> bool {
    !context.session_id.trim().is_empty()
        && authority.installation_id == context.installation_id
        && authority.projection_id == context.projection_id
        && authority.role == context.role
        && authority.registry_hash == context.registry_hash
        && authority.credential_generation == context.credential_generation
        && authority.binding_generation == context.binding_generation
        && authority.installation_config_version == context.installation_config_version
        && authority.projection_version == context.projection_version
        && authority.presentation_config_generation == context.presentation_config_generation
        && authority.alias_catalog_generation == context.alias_catalog_generation
}

#[cfg(feature = "external-gateway")]
fn new_external_session_id() -> Result<String, tonic::Status> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        tonic::Status::unavailable(format!("external session id unavailable: {error}"))
    })?;
    Ok(format!("s_{}", hex_lower(&bytes)))
}

#[cfg(feature = "external-gateway")]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "external-gateway")]
fn validate_provider_projection_bindings(
    projection: &ExternalProjectionDef,
) -> Result<Vec<ProviderBindingDeclaration>, tonic::Status> {
    if projection.role != Role::Provider {
        return Err(tonic::Status::permission_denied(
            "provider projection rejected",
        ));
    }
    if projection.provides.is_empty() {
        return Err(tonic::Status::failed_precondition(
            "provider projection rejected",
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut bindings = Vec::with_capacity(projection.provides.len());
    for capability in &projection.provides {
        let path = Path::parse(&capability.effect_path).map_err(|error| {
            tonic::Status::invalid_argument(format!("provider binding rejected: {error}"))
        })?;
        if !seen.insert(path.clone()) {
            return Err(tonic::Status::failed_precondition(
                "provider binding rejected",
            ));
        }
        let selector_literal = format!("perform://{}", strip_scheme(&path.to_string()));
        let selector = ResourceSelector::parse(&selector_literal).map_err(|error| {
            tonic::Status::failed_precondition(format!("provider binding rejected: {error}"))
        })?;
        bindings.push(ProviderBindingDeclaration {
            path,
            purity: capability.purity,
            selector,
        });
    }
    Ok(bindings)
}

#[cfg(feature = "external-gateway")]
fn register_provider_bindings(
    registry: &Registry,
    declarations: &[ProviderBindingDeclaration],
    endpoint_id: nexus_types::EndpointId,
    context: &SessionContext,
) -> Result<HashMap<ProviderEndpointKey, Path>, tonic::Status> {
    let mut ready_endpoints = HashMap::new();
    for declaration in declarations {
        let (key, path) = register_provider_binding(
            registry,
            declaration,
            endpoint_id,
            context.binding_generation,
        )?;
        if ready_endpoints.insert(key, path).is_some() {
            return Err(tonic::Status::failed_precondition(
                "provider binding rejected",
            ));
        }
    }
    Ok(ready_endpoints)
}

#[cfg(feature = "external-gateway")]
fn register_provider_binding(
    registry: &Registry,
    declaration: &ProviderBindingDeclaration,
    endpoint_id: nexus_types::EndpointId,
    binding_generation: u64,
) -> Result<(ProviderEndpointKey, Path), tonic::Status> {
    let effect_path = declaration.path.to_string();
    let iface_id = registry.next_interface_id();
    let interfaces = InterfaceSet::new(vec![iface_id]);
    registry.register_interface(Interface {
        id: iface_id,
        family: InterfaceFamily::Callable,
        methods: vec![Method {
            id: MethodId::new(0),
            name: "invoke".into(),
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity: declaration.purity,
            replay: declaration.purity.replay_class(false),
            supports: OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
            cost: CostModel::default(),
            batchable: false,
        }],
        laws: Vec::new(),
    });

    let driver_id = registry.next_driver_id();
    registry.register_driver(DriverDescriptor {
        id: driver_id,
        name: effect_path.clone(),
        implements: interfaces.clone(),
        transport: Transport::Grpc { endpoint: None },
        driver: Arc::new(EchoDriver),
    });

    let binding_id = registry.next_binding_id();
    registry
        .admit_binding(Binding {
            id: binding_id,
            selector: declaration.selector.clone(),
            interfaces: interfaces.clone(),
            driver: DriverRef {
                id: driver_id,
                name: effect_path,
            },
            endpoint: Some(endpoint_id),
            generation: binding_generation,
        })
        .map_err(|error| {
            tonic::Status::failed_precondition(format!("provider binding rejected: {error}"))
        })?;

    let resource_name = ResourceName::new(declaration.path.clone());
    let rid = match registry.resolve_resource(&resource_name) {
        Ok(_) => registry
            .relink_resource(&resource_name, interfaces, binding_id)
            .map_err(|error| {
                tonic::Status::failed_precondition(format!("provider binding rejected: {error}"))
            })?,
        Err(ResolveError::NoSuchResource(_)) => {
            let rid = registry.next_resource_id();
            registry
                .admit_resource(
                    Resource {
                        id: rid,
                        descriptor: ResourceDescriptor {
                            name: resource_name,
                            kind: ResourceKind::Effect,
                            metadata: Metadata::default(),
                        },
                        interfaces,
                        binding: binding_id,
                    },
                    true,
                )
                .map_err(|error| {
                    tonic::Status::failed_precondition(format!(
                        "provider binding rejected: {error}"
                    ))
                })?
        }
    };
    Ok((
        ProviderEndpointKey {
            resource_id: rid,
            method_id: MethodId::new(0),
            binding_generation,
        },
        declaration.path.clone(),
    ))
}

#[cfg(feature = "external-gateway")]
fn strip_scheme(path: &str) -> String {
    path.replacen("://", "/", 1)
}

#[cfg(feature = "external-gateway")]
fn status_to_driver_error(status: tonic::Status) -> DriverError {
    DriverError::Transport(status.message().to_string())
}

#[cfg(feature = "external-gateway")]
fn validate_external_control_frame(
    frame: &ControlFrame,
    context: &SessionContext,
) -> Result<(), tonic::Status> {
    match frame {
        ControlFrame::Heartbeat { timestamp_ms } if *timestamp_ms >= 0 => Ok(()),
        ControlFrame::Heartbeat { .. } => Err(tonic::Status::invalid_argument(
            "external control frame rejected",
        )),
        ControlFrame::FlowControl(_) => Err(tonic::Status::permission_denied(
            "external control frame rejected",
        )),
        ControlFrame::PresentationProfileUpdate {
            profile_generation: _,
            profile_hash,
            profile: _,
        } if !profile_hash.trim().is_empty() => Ok(()),
        ControlFrame::PresentationProfileUpdate { .. } => Err(tonic::Status::invalid_argument(
            "external control frame rejected",
        )),
        ControlFrame::ConfigAck {
            axis: ConfigAxis::InstallationConfig,
            version,
            status: _,
        } if *version == context.installation_config_version => Ok(()),
        ControlFrame::ConfigAck {
            axis: ConfigAxis::PresentationConfig,
            version,
            status: _,
        } if *version == context.presentation_config_generation => Ok(()),
        ControlFrame::ConfigAck { .. } => Err(tonic::Status::permission_denied(
            "external control frame rejected",
        )),
        ControlFrame::Shutdown { .. }
        | ControlFrame::ProviderCancel { .. }
        | ControlFrame::InstallationConfigUpdate { .. }
        | ControlFrame::PresentationConfigUpdate { .. } => Err(tonic::Status::permission_denied(
            "external control frame rejected",
        )),
    }
}

#[cfg(feature = "external-gateway")]
fn now_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => match i64::try_from(duration.as_millis()) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(?error, "system time milliseconds overflowed i64");
                i64::MAX
            }
        },
        Err(error) => {
            tracing::warn!(?error, "system time is before the Unix epoch");
            0
        }
    }
}

#[cfg(feature = "external-gateway")]
fn source_ingest_status(error: SourceIngestError) -> tonic::Status {
    let message = format!("source event rejected: {error}");
    match error {
        SourceIngestError::Session(_)
        | SourceIngestError::ProjectionMismatch(_)
        | SourceIngestError::RegistryHashMismatch
        | SourceIngestError::CredentialGenerationMismatch
        | SourceIngestError::BindingGenerationMismatch
        | SourceIngestError::InstallationConfigVersionMismatch
        | SourceIngestError::ProjectionVersionMismatch
        | SourceIngestError::NotSource
        | SourceIngestError::MissingEmits => tonic::Status::permission_denied(message),
        SourceIngestError::InvalidEventId
        | SourceIngestError::InvalidStreamId
        | SourceIngestError::InvalidSequence
        | SourceIngestError::SequenceReplay { .. }
        | SourceIngestError::SequenceGap { .. }
        | SourceIngestError::Schema(_)
        | SourceIngestError::PayloadTooLarge
        | SourceIngestError::ForbiddenPayloadField { .. }
        | SourceIngestError::Policy(_) => tonic::Status::invalid_argument(message),
        SourceIngestError::RateLimited
        | SourceIngestError::Backpressured
        | SourceIngestError::CapacityExceeded => tonic::Status::resource_exhausted(message),
        SourceIngestError::State(_) => tonic::Status::unavailable(message),
    }
}

#[cfg(feature = "external-gateway")]
fn source_ingest_rejection_ack(event_id: String, error: &SourceIngestError) -> Option<EventAck> {
    let reason = match error {
        SourceIngestError::InvalidEventId => "invalid_event_id",
        SourceIngestError::InvalidStreamId => "invalid_stream_id",
        SourceIngestError::InvalidSequence
        | SourceIngestError::SequenceReplay { .. }
        | SourceIngestError::SequenceGap { .. } => "ordering_rejected",
        SourceIngestError::Schema(_) => "schema_rejected",
        SourceIngestError::PayloadTooLarge => "payload_too_large",
        SourceIngestError::ForbiddenPayloadField { .. } => "forbidden_payload_field",
        SourceIngestError::Policy(_) => "policy_rejected",
        SourceIngestError::RateLimited => "rate_limited",
        SourceIngestError::Backpressured => "backpressured",
        SourceIngestError::CapacityExceeded => "capacity_exceeded",
        SourceIngestError::Session(_)
        | SourceIngestError::ProjectionMismatch(_)
        | SourceIngestError::RegistryHashMismatch
        | SourceIngestError::CredentialGenerationMismatch
        | SourceIngestError::BindingGenerationMismatch
        | SourceIngestError::InstallationConfigVersionMismatch
        | SourceIngestError::ProjectionVersionMismatch
        | SourceIngestError::NotSource
        | SourceIngestError::MissingEmits
        | SourceIngestError::State(_) => return None,
    };
    Some(EventAck {
        id: event_id,
        status: AckStatus::Rejected,
        reject_reason: Some(reason.into()),
    })
}

#[cfg(feature = "external-gateway")]
fn provider_invocation_status(error: ProviderInvocationError) -> tonic::Status {
    let message = format!("provider invocation result rejected: {error}");
    match error {
        ProviderInvocationError::InvocationNotFound
        | ProviderInvocationError::SessionMismatch
        | ProviderInvocationError::NotProvider
        | ProviderInvocationError::RegistryHashMismatch
        | ProviderInvocationError::CredentialGenerationMismatch
        | ProviderInvocationError::BindingGenerationMismatch
        | ProviderInvocationError::ProjectionVersionMismatch => {
            tonic::Status::permission_denied(message)
        }
        ProviderInvocationError::Session(_) => tonic::Status::failed_precondition(message),
        ProviderInvocationError::EmptyInvocationId
        | ProviderInvocationError::DuplicateInvocationId
        | ProviderInvocationError::Schema(_) => tonic::Status::invalid_argument(message),
        ProviderInvocationError::DeadlineExceeded => tonic::Status::deadline_exceeded(message),
        ProviderInvocationError::ResultTooLarge
        | ProviderInvocationError::InFlightLimitExceeded => {
            tonic::Status::resource_exhausted(message)
        }
    }
}

#[cfg(feature = "external-gateway")]
fn provider_invocation_error_removes_entry(error: &ProviderInvocationError) -> bool {
    matches!(
        error,
        ProviderInvocationError::DeadlineExceeded
            | ProviderInvocationError::ResultTooLarge
            | ProviderInvocationError::Schema(_)
    )
}

#[cfg(feature = "external-gateway")]
fn source_command_status(error: SourceCommandError) -> tonic::Status {
    source_command_error_status(error, "source command result rejected")
}

#[cfg(all(test, feature = "external-gateway"))]
fn source_command_dispatch_status(error: SourceCommandError) -> tonic::Status {
    source_command_error_status(error, "source command rejected")
}

#[cfg(feature = "external-gateway")]
fn source_command_error_status(error: SourceCommandError, message: &'static str) -> tonic::Status {
    let message = format!("{message}: {error}");
    match error {
        SourceCommandError::CommandNotFound
        | SourceCommandError::SessionMismatch
        | SourceCommandError::NotSource
        | SourceCommandError::RegistryHashMismatch
        | SourceCommandError::CredentialGenerationMismatch
        | SourceCommandError::BindingGenerationMismatch
        | SourceCommandError::InstallationConfigVersionMismatch
        | SourceCommandError::ProjectionVersionMismatch => {
            tonic::Status::permission_denied(message)
        }
        SourceCommandError::Session(_) => tonic::Status::failed_precondition(message),
        SourceCommandError::EmptyCommandId
        | SourceCommandError::DuplicateCommandId
        | SourceCommandError::Schema(_) => tonic::Status::invalid_argument(message),
        SourceCommandError::DeadlineExceeded => tonic::Status::deadline_exceeded(message),
        SourceCommandError::ResultTooLarge
        | SourceCommandError::InFlightLimitExceeded
        | SourceCommandError::RateLimited => tonic::Status::resource_exhausted(message),
    }
}

#[cfg(feature = "external-gateway")]
fn source_command_error_removes_entry(error: &SourceCommandError) -> bool {
    matches!(
        error,
        SourceCommandError::DeadlineExceeded
            | SourceCommandError::ResultTooLarge
            | SourceCommandError::Schema(_)
    )
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

#[cfg(feature = "external-gateway")]
fn log_external_transport_security(
    label: &'static str,
    addr: &str,
    config: &GatewayTransportSecurityConfig,
) {
    if config.is_unsafe() {
        tracing::warn!(
            %label,
            %addr,
            mode = config.mode.as_str(),
            unsafe_relaxations = ?config.unsafe_relaxation_names(),
            "external gateway unsafe transport enabled"
        );
    } else {
        tracing::info!(%label, %addr, mode = config.mode.as_str(), "external gateway transport");
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
mod tests {
    use super::*;
    use anyhow::{Context as _, bail};
    #[cfg(feature = "external-grpc")]
    use nexus_gateway::external::EnvelopeAad;
    #[cfg(feature = "external-grpc")]
    use serde_json::json;
    #[cfg(feature = "external-grpc")]
    use std::sync::{Mutex, MutexGuard};

    macro_rules! assert {
        ($condition:expr $(,)?) => {
            anyhow::ensure!($condition, "assertion failed: {}", stringify!($condition));
        };
        ($condition:expr, $($arg:tt)+) => {
            anyhow::ensure!($condition, $($arg)+);
        };
    }

    macro_rules! assert_eq {
        ($left:expr, $right:expr $(,)?) => {
            match (&$left, &$right) {
                (left, right) => anyhow::ensure!(
                    left == right,
                    "assertion failed: left != right\nleft: {left:?}\nright: {right:?}"
                ),
            }
        };
        ($left:expr, $right:expr, $($arg:tt)+) => {
            anyhow::ensure!($left == $right, $($arg)+);
        };
    }

    macro_rules! assert_ne {
        ($left:expr, $right:expr $(,)?) => {
            match (&$left, &$right) {
                (left, right) => anyhow::ensure!(
                    left != right,
                    "assertion failed: left == right\nleft: {left:?}\nright: {right:?}"
                ),
            }
        };
        ($left:expr, $right:expr, $($arg:tt)+) => {
            anyhow::ensure!($left != $right, $($arg)+);
        };
    }

    #[cfg(feature = "external-grpc")]
    const TEST_EXTERNAL_PSK: [u8; 32] = [0x41; 32];

    #[cfg(feature = "external-grpc")]
    fn lock_test<'a, T>(mutex: &'a Mutex<T>, name: &str) -> anyhow::Result<MutexGuard<'a, T>> {
        mutex
            .lock()
            .map_err(|_| anyhow::anyhow!("{name} mutex poisoned"))
    }

    #[cfg(feature = "external-grpc")]
    fn parse_test_path(path: &str) -> anyhow::Result<Path> {
        Path::parse(path).map_err(|error| anyhow::anyhow!("parsing test path {path}: {error}"))
    }

    #[cfg(feature = "external-grpc")]
    fn install_test_external_credential(
        handler: &DaemonExternalSessionHandler,
        credential: ExternalCredential,
    ) -> anyhow::Result<()> {
        let mut credentials = lock_test(&handler.external_credentials, "external_credentials")?;
        credentials.insert(
            (
                credential.installation_id().to_owned(),
                credential.generation(),
            ),
            credential,
        );
        Ok(())
    }

    #[tokio::test]
    async fn kernel_boots_with_standard_providers() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())
            .map_err(|error| anyhow::anyhow!("installing standard providers: {error}"))?;
        assert!(boot.kernel.registry.resource_count() >= 5);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    fn external_installation_value() -> anyhow::Result<Value> {
        source_external_installation_value(false)
    }

    #[cfg(feature = "external-grpc")]
    fn source_external_installation_value(commands: bool) -> anyhow::Result<Value> {
        serde_json::from_value(source_external_installation_json(commands))
            .context("building source external installation value")
    }

    #[cfg(feature = "external-grpc")]
    fn source_external_installation_json(commands: bool) -> serde_json::Value {
        json!({
            "id": "chat",
            "platform": "chat",
            "transport": { "grpc": { "endpoint": null } },
            "trust": "sandboxed",
            "config_schema": null,
            "config": null,
            "projections": [{
                "id": "source",
                "role": "source",
                "namespace": null,
                "provides": [],
                "emits": {
                    "sink": "state://events/external/chat/source",
                    "purity": "effectful",
                    "event_schema": null,
                    "max_inline_payload_bytes": 65536,
                    "capacity": { "max_events": 1024, "on_overflow": "drop_oldest" },
                    "rate_limit": null,
                    "commands": commands,
                    "command_schema": if commands { json!({ "type": "string" }) } else { serde_json::Value::Null },
                    "command_result_schema": if commands { json!({ "type": "string" }) } else { serde_json::Value::Null }
                },
                "version": 7
            }],
            "version": 11
        })
    }

    #[cfg(feature = "external-grpc")]
    fn provider_external_installation_value() -> anyhow::Result<Value> {
        serde_json::from_value(json!({
            "id": "chat",
            "platform": "chat",
            "transport": { "grpc": { "endpoint": null } },
            "trust": "sandboxed",
            "config_schema": null,
            "config": null,
            "projections": [{
                "id": "provider",
                "role": "provider",
                "namespace": "effect://external-provider/chat",
                "provides": [{
                    "effect_path": "effect://external-provider/chat/search",
                    "purity": "idempotent",
                    "input_schema": { "type": "string" },
                    "output_schema": { "type": "string" }
                }, {
                    "effect_path": "effect://external-provider/chat/summarize",
                    "purity": "effectful"
                }],
                "emits": null,
                "version": 13
            }],
            "version": 17
        }))
        .context("building provider external installation value")
    }

    #[cfg(feature = "external-grpc")]
    fn provider_external_installation_without_capabilities_value() -> anyhow::Result<Value> {
        serde_json::from_value(json!({
            "id": "chat",
            "platform": "chat",
            "transport": { "grpc": { "endpoint": null } },
            "trust": "sandboxed",
            "config_schema": null,
            "config": null,
            "projections": [{
                "id": "provider",
                "role": "provider",
                "namespace": "effect://external-provider/chat",
                "provides": [],
                "emits": null,
                "version": 13
            }],
            "version": 17
        }))
        .context("building provider installation without capabilities value")
    }

    #[cfg(feature = "external-grpc")]
    async fn write_external_session(
        state: &Backend,
        installation_id: &str,
        role: &str,
        credential_generation: i64,
    ) -> anyhow::Result<()> {
        write_external_session_with_key_epoch(
            state,
            installation_id,
            role,
            credential_generation,
            0,
        )
        .await
    }

    #[cfg(feature = "external-grpc")]
    async fn write_external_session_with_key_epoch(
        state: &Backend,
        installation_id: &str,
        role: &str,
        credential_generation: i64,
        key_epoch: i64,
    ) -> anyhow::Result<()> {
        state
            .write_set(
                &parse_test_path(&format!(
                    "state://kernel/external-sessions/{installation_id}/{role}"
                ))?,
                serde_json::from_value(json!({
                    "installation_id": installation_id,
                    "role": role,
                    "pairing_id": "pair-1",
                    "credential_generation": credential_generation,
                    "key_epoch": key_epoch,
                    "state": "ready"
                }))
                .context("building external session state value")?,
            )
            .await
            .map_err(|error| anyhow::anyhow!("writing external session state: {error}"))?;
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    async fn write_chat_installation(state: &Backend, value: Value) -> anyhow::Result<()> {
        state
            .write_set(
                &parse_test_path("state://kernel/external-installations/chat")?,
                value,
            )
            .await
            .map_err(|error| anyhow::anyhow!("writing chat external installation: {error}"))?;
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    fn external_outbound_channel() -> (
        ExternalSessionOutboundHandle,
        tokio::sync::mpsc::Receiver<
            Result<nexus_proto::nexus::v1::external::ExternalFrame, tonic::Status>,
        >,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        (Arc::new(TestExternalOutbound { tx }), rx)
    }

    #[cfg(feature = "external-grpc")]
    async fn recv_external_frame(
        rx: &mut tokio::sync::mpsc::Receiver<
            Result<nexus_proto::nexus::v1::external::ExternalFrame, tonic::Status>,
        >,
        label: &'static str,
    ) -> anyhow::Result<nexus_proto::nexus::v1::external::ExternalFrame> {
        rx.recv()
            .await
            .with_context(|| format!("receiving {label} frame"))?
            .map_err(|status| anyhow::anyhow!("receiving {label} frame: {status}"))
    }

    #[cfg(feature = "external-grpc")]
    fn expect_outbound_command_frame(
        frame: nexus_proto::nexus::v1::external::ExternalFrame,
    ) -> anyhow::Result<nexus_proto::nexus::v1::external::OutboundCommand> {
        match frame.frame {
            Some(nexus_proto::nexus::v1::external::external_frame::Frame::OutboundCommand(
                command,
            )) => Ok(command),
            Some(other) => bail!("expected source outbound command frame, got {other:?}"),
            None => bail!("expected source outbound command frame, got empty frame"),
        }
    }

    #[cfg(feature = "external-grpc")]
    fn expect_invoke_frame(
        frame: nexus_proto::nexus::v1::external::ExternalFrame,
    ) -> anyhow::Result<nexus_proto::nexus::v1::external::Invoke> {
        match frame.frame {
            Some(nexus_proto::nexus::v1::external::external_frame::Frame::Invoke(invoke)) => {
                Ok(invoke)
            }
            Some(other) => bail!("expected provider invoke frame, got {other:?}"),
            None => bail!("expected provider invoke frame, got empty frame"),
        }
    }

    #[cfg(feature = "external-grpc")]
    fn expect_control_frame(
        frame: nexus_proto::nexus::v1::external::ExternalFrame,
    ) -> anyhow::Result<nexus_proto::nexus::v1::external::ControlFrame> {
        match frame.frame {
            Some(nexus_proto::nexus::v1::external::external_frame::Frame::Control(control)) => {
                Ok(control)
            }
            Some(other) => bail!("expected provider control frame, got {other:?}"),
            None => bail!("expected provider control frame, got empty frame"),
        }
    }

    #[cfg(feature = "external-grpc")]
    struct TestExternalOutbound {
        tx: tokio::sync::mpsc::Sender<
            Result<nexus_proto::nexus::v1::external::ExternalFrame, tonic::Status>,
        >,
    }

    #[cfg(feature = "external-grpc")]
    impl TestExternalOutbound {
        async fn send_frame(
            &self,
            frame: nexus_proto::nexus::v1::external::external_frame::Frame,
        ) -> Result<(), tonic::Status> {
            self.tx
                .send(Ok(nexus_proto::nexus::v1::external::ExternalFrame {
                    frame: Some(frame),
                }))
                .await
                .map_err(|_| tonic::Status::unavailable("test external session closed"))
        }
    }

    #[cfg(feature = "external-grpc")]
    #[tonic::async_trait]
    impl ExternalSessionOutbound for TestExternalOutbound {
        type Error = tonic::Status;

        async fn send_invoke(&self, invoke: Invoke) -> Result<(), Self::Error> {
            self.send_frame(
                nexus_proto::nexus::v1::external::external_frame::Frame::Invoke(
                    nexus_proto::invoke_to_pb(&invoke),
                ),
            )
            .await
        }

        async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Self::Error> {
            self.send_frame(
                nexus_proto::nexus::v1::external::external_frame::Frame::OutboundCommand(
                    nexus_proto::outbound_command_to_pb(&command),
                ),
            )
            .await
        }

        async fn send_control(&self, frame: ControlFrame) -> Result<(), Self::Error> {
            self.send_frame(
                nexus_proto::nexus::v1::external::external_frame::Frame::Control(
                    nexus_proto::control_frame_to_pb(&frame),
                ),
            )
            .await
        }
    }

    #[cfg(feature = "external-grpc")]
    async fn write_external_revocation(
        state: &Backend,
        installation_id: &str,
        credential_generation_floor: i64,
    ) -> anyhow::Result<()> {
        state
            .write_set(
                &parse_test_path(&format!(
                    "state://kernel/external-credential-revocations/{installation_id}"
                ))?,
                serde_json::from_value(json!({
                    "installation_id": installation_id,
                    "state": "revoked",
                    "credential_generation_floor": credential_generation_floor
                }))
                .context("building external revocation state value")?,
            )
            .await
            .map_err(|error| anyhow::anyhow!("writing external revocation state: {error}"))?;
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    fn hello_from_context(context: &SessionContext) -> RoleSessionClientHello {
        RoleSessionClientHello {
            role: context.role,
            installation_id: context.installation_id.clone(),
            projection_id: context.projection_id.clone(),
            registry_hash: context.registry_hash.clone(),
            observed: nexus_types::external::ObservedGenerations {
                presentation_config_generation: context.presentation_config_generation,
                alias_catalog_generation: context.alias_catalog_generation,
            },
            config_schema: None,
        }
    }

    #[cfg(feature = "external-grpc")]
    struct ExternalTestFixture {
        boot: Arc<Bootstrap>,
        handler: DaemonExternalSessionHandler,
        session: EndpointSession,
        context: SessionContext,
    }

    #[cfg(feature = "external-grpc")]
    async fn ready_source_fixture(
        commands: bool,
        limits: Option<config::ExternalGatewaySessionLimits>,
    ) -> anyhow::Result<ExternalTestFixture> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(
            &boot.kernel.state,
            source_external_installation_value(commands)?,
        )
        .await?;
        write_external_session(&boot.kernel.state, "chat", "source", 5).await?;
        ready_fixture(boot, Role::Source, "source", limits).await
    }

    #[cfg(feature = "external-grpc")]
    async fn ready_provider_fixture(
        installation: Value,
        limits: Option<config::ExternalGatewaySessionLimits>,
        key_epoch: i64,
    ) -> anyhow::Result<ExternalTestFixture> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(&boot.kernel.state, installation).await?;
        write_external_session_with_key_epoch(&boot.kernel.state, "chat", "provider", 9, key_epoch)
            .await?;
        ready_fixture(boot, Role::Provider, "provider", limits).await
    }

    #[cfg(feature = "external-grpc")]
    async fn ready_fixture(
        boot: Arc<Bootstrap>,
        role: Role,
        projection_id: &'static str,
        limits: Option<config::ExternalGatewaySessionLimits>,
    ) -> anyhow::Result<ExternalTestFixture> {
        let handler = match limits {
            Some(limits) => DaemonExternalSessionHandler::with_limits(
                boot.kernel.state.clone(),
                boot.kernel.registry.clone(),
                limits,
            ),
            None => DaemonExternalSessionHandler::new(
                boot.kernel.state.clone(),
                boot.kernel.registry.clone(),
                60_000,
            ),
        };
        let hello = hello_from_context(
            &handler
                .load_authority("chat", projection_id, role)
                .await
                .with_context(|| format!("loading {projection_id} authority"))?
                .context,
        );
        let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .with_context(|| format!("adjudicating {projection_id} session"))?;
        let mut session = EndpointSession::new();
        session
            .on_hello(&hello, |_| context.clone())
            .with_context(|| format!("accepting {projection_id} hello"))?;
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .with_context(|| format!("marking {projection_id} session ready"))?;
        Ok(ExternalTestFixture {
            boot,
            handler,
            session,
            context,
        })
    }

    #[cfg(feature = "external-grpc")]
    fn secure_envelope_aad(context: &SessionContext, seq: u64) -> EnvelopeAad {
        secure_envelope_aad_with(context, seq, "control.config_ack", 0)
    }

    #[cfg(feature = "external-grpc")]
    fn secure_envelope_aad_with(
        context: &SessionContext,
        seq: u64,
        frame_type: &str,
        key_epoch: u64,
    ) -> EnvelopeAad {
        EnvelopeAad {
            projection_id: context.projection_id.clone(),
            role: role_slug(context.role).into(),
            session_id: context.session_id.clone(),
            seq,
            frame_type: frame_type.into(),
            binding_generation: context.binding_generation,
            credential_generation: context.credential_generation,
            transcript_hash: vec![0x42; 32],
            key_epoch,
            ..EnvelopeAad::default()
        }
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_adjudicates_from_installation_state() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(&boot.kernel.state, external_installation_value()?).await?;
        write_external_session(&boot.kernel.state, "chat", "source", 5).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );

        let hello = RoleSessionClientHello {
            role: Role::Source,
            installation_id: "chat".into(),
            projection_id: "source".into(),
            registry_hash: "client-observed".into(),
            observed: Default::default(),
            config_schema: None,
        };
        let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .context("adjudicating source session")?;

        assert_eq!(context.installation_id, "chat");
        assert_eq!(context.projection_id, "source");
        assert_eq!(context.role, Role::Source);
        assert_eq!(context.credential_generation, 5);
        assert_eq!(context.binding_generation, 7);
        assert_eq!(context.installation_config_version, 11);
        assert_ne!(context.registry_hash, "client-observed");
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_requires_approved_role_session() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(&boot.kernel.state, external_installation_value()?).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );

        let hello = RoleSessionClientHello {
            role: Role::Source,
            installation_id: "chat".into(),
            projection_id: "source".into(),
            registry_hash: String::new(),
            observed: Default::default(),
            config_schema: None,
        };
        let err = match ExternalSessionHandler::adjudicate_session(&handler, &hello).await {
            Ok(_context) => bail!("expected unauthenticated source session"),
            Err(error) => error,
        };

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_revoked_role_session() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(&boot.kernel.state, external_installation_value()?).await?;
        write_external_session(&boot.kernel.state, "chat", "source", 2).await?;
        write_external_revocation(&boot.kernel.state, "chat", 2).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );

        let hello = RoleSessionClientHello {
            role: Role::Source,
            installation_id: "chat".into(),
            projection_id: "source".into(),
            registry_hash: String::new(),
            observed: Default::default(),
            config_schema: None,
        };
        let err = match ExternalSessionHandler::adjudicate_session(&handler, &hello).await {
            Ok(_context) => bail!("expected revoked source session rejection"),
            Err(error) => error,
        };

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_ingests_source_event() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(&boot.kernel.state, external_installation_value()?).await?;
        write_external_session(&boot.kernel.state, "chat", "source", 5).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .context("loading source authority")?
                .context,
        );
        let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .context("adjudicating source session")?;
        let mut session = EndpointSession::new();
        session
            .on_hello(&hello, |_| context.clone())
            .context("accepting source hello")?;
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .context("marking source session ready")?;

        let ack = ExternalSessionHandler::on_inbound_event(
            &handler,
            InboundEvent {
                id: "evt-1".into(),
                payload: Value::Str("hello".into()),
                observed: Default::default(),
                timestamp_ms: 1,
                stream_id: None,
                seq: None,
            },
            &session,
            context,
        )
        .await
        .context("ingesting source event")?;

        assert_eq!(ack.status, nexus_types::external::AckStatus::Accepted);
        let rows = boot
            .kernel
            .state
            .read_prefix(&parse_test_path("state://events/external/chat/source")?)
            .await
            .map_err(|error| anyhow::anyhow!("reading source event sink: {error}"))?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, Value::List(vec![Value::Str("hello".into())]));
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn source_ingest_event_errors_are_rejected_acks() -> anyhow::Result<()> {
        let policy = source_ingest_rejection_ack(
            "evt-1".into(),
            &SourceIngestError::Policy("private detail".into()),
        )
        .context("policy ingest error should map to rejected ack")?;
        assert_eq!(
            policy,
            EventAck {
                id: "evt-1".into(),
                status: AckStatus::Rejected,
                reject_reason: Some("policy_rejected".into()),
            }
        );

        assert_eq!(
            source_ingest_rejection_ack("evt-2".into(), &SourceIngestError::RateLimited)
                .context("rate limit ingest error should map to rejected ack")?
                .reject_reason,
            Some("rate_limited".into())
        );
        assert_eq!(
            source_ingest_rejection_ack("evt-3".into(), &SourceIngestError::PayloadTooLarge)
                .context("payload size ingest error should map to rejected ack")?
                .reject_reason,
            Some("payload_too_large".into())
        );
        assert_eq!(
            source_ingest_rejection_ack(
                "evt-4".into(),
                &SourceIngestError::ForbiddenPayloadField {
                    field: "access_token".into()
                }
            )
            .context("forbidden field ingest error should map to rejected ack")?
            .reject_reason,
            Some("forbidden_payload_field".into())
        );
        assert_eq!(
            source_ingest_rejection_ack("evt-5".into(), &SourceIngestError::RegistryHashMismatch),
            None
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_returns_rejected_ack_for_source_schema_error()
    -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let mut install = source_external_installation_json(false);
        install["projections"][0]["emits"]["event_schema"] = json!({ "type": "string" });
        write_chat_installation(
            &boot.kernel.state,
            serde_json::from_value(install)
                .context("building source installation with event schema")?,
        )
        .await?;
        write_external_session(&boot.kernel.state, "chat", "source", 5).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .context("loading source authority")?
                .context,
        );
        let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .context("adjudicating source session")?;
        let mut session = EndpointSession::new();
        session
            .on_hello(&hello, |_| context.clone())
            .context("accepting source hello")?;
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .context("marking source session ready")?;

        let ack = ExternalSessionHandler::on_inbound_event(
            &handler,
            InboundEvent {
                id: "evt-schema".into(),
                payload: Value::Int(1),
                observed: Default::default(),
                timestamp_ms: 1,
                stream_id: None,
                seq: None,
            },
            &session,
            context,
        )
        .await
        .context("ingesting schema-invalid source event")?;

        assert_eq!(ack.status, AckStatus::Rejected);
        assert_eq!(ack.reject_reason, Some("schema_rejected".into()));
        assert_eq!(
            boot.kernel
                .state
                .read(&parse_test_path("state://events/external/chat/source")?)
                .await
                .map_err(|error| anyhow::anyhow!("reading source event sink: {error}"))?,
            None
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_gates_external_control_frames() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(&boot.kernel.state, external_installation_value()?).await?;
        write_external_session(&boot.kernel.state, "chat", "source", 5).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .context("loading source authority")?
                .context,
        );
        let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .context("adjudicating source session")?;
        let mut session = EndpointSession::new();
        session
            .on_hello(&hello, |_| context.clone())
            .context("accepting source hello")?;
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .context("marking source session ready")?;

        ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::Heartbeat { timestamp_ms: 10 },
            &session,
            context.clone(),
        )
        .await
        .context("accepting heartbeat control frame")?;
        ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::ConfigAck {
                axis: ConfigAxis::InstallationConfig,
                version: context.installation_config_version,
                status: nexus_types::external::ApplyStatus::Applied,
            },
            &session,
            context.clone(),
        )
        .await
        .context("accepting matching config ack")?;

        let err = match ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::ConfigAck {
                axis: ConfigAxis::InstallationConfig,
                version: context.installation_config_version + 1,
                status: nexus_types::external::ApplyStatus::Applied,
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected mismatched config ack rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = match ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::InstallationConfigUpdate {
                config_version: context.installation_config_version + 1,
                config: Value::Null,
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected installation config update rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = match ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::Shutdown {
                graceful: true,
                timeout_ms: 1_000,
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected shutdown control frame rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = match ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::FlowControl(nexus_types::external::FlowSignal::Pause),
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected flow-control frame rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = match ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::PresentationProfileUpdate {
                profile_generation: 1,
                profile_hash: String::new(),
                profile: Value::Null,
            },
            &session,
            context,
        )
        .await
        {
            Ok(()) => bail!("expected presentation update validation rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_resolves_only_registered_source_commands() -> anyhow::Result<()>
    {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_source_fixture(true, None).await?;
        let (outbound, mut outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering source outbound channel")?;

        let command = nexus_types::external::OutboundCommand {
            id: "cmd-1".into(),
            action: Value::Str("sync".into()),
            observed: Default::default(),
        };
        let receiver = handler
            .send_source_command(command, &session, &context, None)
            .await
            .context("sending source command")?;
        let sent = expect_outbound_command_frame(
            recv_external_frame(&mut outbound_rx, "source command").await?,
        )?;
        let sent = nexus_proto::outbound_command_from_pb(&sent)
            .context("decoding outbound command frame")?;
        assert_eq!(sent.id, "cmd-1");
        assert_eq!(sent.action, Value::Str("sync".into()));
        assert_eq!(
            sent.observed.presentation_config_generation,
            context.presentation_config_generation
        );

        let expected = CommandResult {
            id: "cmd-1".into(),
            outcome: Ok(Value::Str("ok".into())),
        };
        ExternalSessionHandler::on_command_result(
            &handler,
            expected.clone(),
            &session,
            context.clone(),
        )
        .await
        .context("resolving source command result")?;
        assert_eq!(
            receiver.await.context("awaiting source command receiver")?,
            expected
        );

        let err = match ExternalSessionHandler::on_command_result(
            &handler,
            CommandResult {
                id: "cmd-1".into(),
                outcome: Ok(Value::Str("again".into())),
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected duplicate command result rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = match handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-bad-action".into(),
                    action: Value::Int(7),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
        {
            Ok(_receiver) => bail!("expected invalid source command action rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(outbound_rx.try_recv().is_err());

        let receiver = handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-bad-result".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
            .context("sending source command with invalid result payload")?;
        recv_external_frame(&mut outbound_rx, "source command with invalid result").await?;
        let err = match ExternalSessionHandler::on_command_result(
            &handler,
            CommandResult {
                id: "cmd-bad-result".into(),
                outcome: Ok(Value::Int(7)),
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected invalid command result rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(receiver.await.is_err());
        assert!(lock_test(&handler.source_commands, "source_commands")?.is_empty());
        assert!(lock_test(&handler.source_waiters, "source_waiters")?.is_empty());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_expires_pending_source_commands() -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_source_fixture(true, None).await?;
        let (outbound, mut outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering source outbound channel")?;

        let deadline_ms = now_millis() + 200;
        let receiver = handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-timeout".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                Some(deadline_ms),
            )
            .await
            .context("sending source command with deadline")?;
        let sent = expect_outbound_command_frame(
            recv_external_frame(&mut outbound_rx, "timed source command").await?,
        )?;
        assert_eq!(
            nexus_proto::outbound_command_from_pb(&sent)
                .context("decoding timed source command frame")?
                .id,
            "cmd-timeout"
        );

        assert!(receiver.await.is_err());
        assert!(lock_test(&handler.source_commands, "source_commands")?.is_empty());
        assert!(lock_test(&handler.source_waiters, "source_waiters")?.is_empty());

        let err = match ExternalSessionHandler::on_command_result(
            &handler,
            CommandResult {
                id: "cmd-timeout".into(),
                outcome: Ok(Value::Str("late".into())),
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected late command result rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_source_command_in_flight_limit() -> anyhow::Result<()>
    {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_source_fixture(
            true,
            Some(config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                source_max_in_flight_commands: 1,
                ..Default::default()
            }),
        )
        .await?;
        let (outbound, mut outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering source outbound channel")?;

        let _receiver = handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-1".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
            .context("sending first source command")?;
        recv_external_frame(&mut outbound_rx, "first source command").await?;

        let err = match handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-2".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
        {
            Ok(_receiver) => bail!("expected source command in-flight limit rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            lock_test(&handler.source_commands, "source_commands")?.len(),
            1
        );
        assert_eq!(
            lock_test(&handler.source_waiters, "source_waiters")?.len(),
            1
        );
        assert!(outbound_rx.try_recv().is_err());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_source_command_rate_limit() -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_source_fixture(
            true,
            Some(config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                source_command_rate_limit_window_ms: 60_000,
                source_command_rate_limit_max: 1,
                ..Default::default()
            }),
        )
        .await?;
        let (outbound, mut outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering source outbound channel")?;

        let _receiver = handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-1".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
            .context("sending first source command")?;
        recv_external_frame(&mut outbound_rx, "first source command").await?;

        let err = match handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-2".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
        {
            Ok(_receiver) => bail!("expected source command rate limit rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            lock_test(&handler.source_commands, "source_commands")?.len(),
            1
        );
        assert!(outbound_rx.try_recv().is_err());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_source_commands_when_projection_disables_them()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_source_fixture(false, None).await?;
        let (outbound, _outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering source outbound channel")?;

        let err = match handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-1".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
        {
            Ok(_receiver) => bail!("expected disabled source commands rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_drains_source_commands_on_close() -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_source_fixture(true, None).await?;
        let (outbound, _outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering source outbound channel")?;

        let receiver = handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-close".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
            .context("sending source command before close")?;

        ExternalSessionHandler::on_closed(&handler, &session, context.clone())
            .await
            .context("closing source session")?;

        assert!(receiver.await.is_err());
        assert!(lock_test(&handler.source_sessions, "source_sessions")?.is_empty());
        assert!(lock_test(&handler.source_commands, "source_commands")?.is_empty());
        assert!(lock_test(&handler.source_waiters, "source_waiters")?.is_empty());

        let err = match handler
            .send_source_command(
                nexus_types::external::OutboundCommand {
                    id: "cmd-after-close".into(),
                    action: Value::Str("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await
        {
            Ok(_receiver) => bail!("expected source command after close rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_resolves_only_registered_provider_invocations()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;

        let invoke = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let receiver = handler
            .register_provider_invoke(&invoke, &session, &context)
            .await
            .context("registering provider invocation")?;

        let expected = InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: Ok(Value::Str("result".into())),
        };
        ExternalSessionHandler::on_invoke_result(
            &handler,
            expected.clone(),
            &session,
            context.clone(),
        )
        .await
        .context("resolving provider invocation result")?;
        assert_eq!(
            receiver
                .await
                .context("awaiting provider invocation receiver")?,
            expected
        );

        let err = match ExternalSessionHandler::on_invoke_result(
            &handler,
            InvokeResult {
                invocation_id: "invoke-1".into(),
                outcome: Ok(Value::Str("again".into())),
            },
            &session,
            context.clone(),
        )
        .await
        {
            Ok(()) => bail!("expected duplicate provider invoke result rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let invoke = nexus_types::external::Invoke {
            invocation_id: "invoke-schema".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let receiver = handler
            .register_provider_invoke(&invoke, &session, &context)
            .await
            .context("registering provider invocation with invalid result payload")?;
        let err = match ExternalSessionHandler::on_invoke_result(
            &handler,
            InvokeResult {
                invocation_id: "invoke-schema".into(),
                outcome: Ok(Value::Int(7)),
            },
            &session,
            context,
        )
        .await
        {
            Ok(()) => bail!("expected invalid provider invoke result rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(receiver.await.is_err());
        assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
        assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rolls_back_provider_invocation_on_waiter_duplicate()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;

        let (stale_tx, _stale_rx) = oneshot::channel();
        lock_test(&handler.provider_waiters, "provider_waiters")?
            .insert("invoke-stale".into(), stale_tx);
        let invoke = nexus_types::external::Invoke {
            invocation_id: "invoke-stale".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };

        let err = match handler
            .register_provider_invoke(&invoke, &session, &context)
            .await
        {
            Ok(_receiver) => bail!("expected duplicate provider waiter rejection"),
            Err(error) => error,
        };

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
        assert_eq!(
            lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
            1
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_provider_invocation_in_flight_limit()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(
            provider_external_installation_value()?,
            Some(config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                provider_max_in_flight_invocations: 1,
                ..Default::default()
            }),
            0,
        )
        .await?;

        let first = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let _receiver = handler
            .register_provider_invoke(&first, &session, &context)
            .await
            .context("registering first provider invocation")?;

        let second = nexus_types::external::Invoke {
            invocation_id: "invoke-2".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let err = match handler
            .register_provider_invoke(&second, &session, &context)
            .await
        {
            Ok(_receiver) => bail!("expected provider invocation in-flight limit rejection"),
            Err(error) => error,
        };

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            lock_test(&handler.provider_invocations, "provider_invocations")?.len(),
            1
        );
        assert_eq!(
            lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
            1
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_provider_identity_in_flight_limit()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(
            provider_external_installation_value()?,
            Some(config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                provider_max_in_flight_per_identity: 1,
                ..Default::default()
            }),
            0,
        )
        .await?;

        let first = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let _receiver = handler
            .register_provider_invoke(&first, &session, &context)
            .await
            .context("registering first provider invocation")?;

        let second = nexus_types::external::Invoke {
            invocation_id: "invoke-2".into(),
            effect_path: parse_test_path("effect://external-provider/chat/summarize")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let err = match handler
            .register_provider_invoke(&second, &session, &context)
            .await
        {
            Ok(_receiver) => bail!("expected provider identity in-flight limit rejection"),
            Err(error) => error,
        };

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            lock_test(&handler.provider_invocations, "provider_invocations")?.len(),
            1
        );
        assert_eq!(
            lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
            1
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_provider_effect_in_flight_limit() -> anyhow::Result<()>
    {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(
            provider_external_installation_value()?,
            Some(config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                provider_max_in_flight_per_effect: 1,
                ..Default::default()
            }),
            0,
        )
        .await?;

        let first = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let _receiver = handler
            .register_provider_invoke(&first, &session, &context)
            .await
            .context("registering first provider invocation")?;

        let second = nexus_types::external::Invoke {
            invocation_id: "invoke-2".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let err = match handler
            .register_provider_invoke(&second, &session, &context)
            .await
        {
            Ok(_receiver) => bail!("expected provider effect in-flight limit rejection"),
            Err(error) => error,
        };

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            lock_test(&handler.provider_invocations, "provider_invocations")?.len(),
            1
        );
        assert_eq!(
            lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
            1
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_opens_secure_envelope_with_installed_credential()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
        let credential =
            ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
        let envelope = credential
            .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
            .context("sealing secure envelope")?;
        install_test_external_credential(&handler, credential)?;

        let plaintext = ExternalSessionHandler::open_secure_envelope(
            &handler,
            &envelope,
            &session,
            context.clone(),
        )
        .await
        .context("opening secure envelope")?;
        assert_eq!(plaintext, b"frame-bytes");

        let err = match ExternalSessionHandler::open_secure_envelope(
            &handler, &envelope, &session, context,
        )
        .await
        {
            Ok(_plaintext) => bail!("expected replayed secure envelope rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_old_epoch_business_envelope_after_rekey()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(provider_external_installation_value()?, None, 1).await?;
        let credential =
            ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
        let envelope = credential
            .seal_with_aad(
                b"frame-bytes",
                secure_envelope_aad_with(&context, 0, "invoke", 0),
            )
            .context("sealing old-epoch invoke envelope")?;
        let generic_control_envelope = credential
            .seal_with_aad(
                b"frame-bytes",
                secure_envelope_aad_with(&context, 0, "control", 0),
            )
            .context("sealing old-epoch control envelope")?;
        install_test_external_credential(&handler, credential)?;

        let err = match ExternalSessionHandler::open_secure_envelope(
            &handler, &envelope, &session, context,
        )
        .await
        {
            Ok(_plaintext) => bail!("expected old-epoch business envelope rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let session_context = session
            .context()
            .context("session context should remain available")?
            .clone();
        let err = match ExternalSessionHandler::open_secure_envelope(
            &handler,
            &generic_control_envelope,
            &session,
            session_context,
        )
        .await
        {
            Ok(_plaintext) => bail!("expected old-epoch generic control envelope rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_clears_secure_replay_state_on_close() -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
        let credential =
            ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
        let envelope = credential
            .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
            .context("sealing secure envelope")?;
        install_test_external_credential(&handler, credential)?;

        ExternalSessionHandler::open_secure_envelope(
            &handler,
            &envelope,
            &session,
            context.clone(),
        )
        .await
        .context("opening secure envelope")?;
        assert_eq!(
            lock_test(&handler.secure_replay_windows, "secure_replay_windows")?.len(),
            1
        );

        ExternalSessionHandler::on_closed(&handler, &session, context)
            .await
            .context("closing provider session")?;
        assert!(lock_test(&handler.secure_replay_windows, "secure_replay_windows")?.is_empty());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_secure_envelope_without_credential()
    -> anyhow::Result<()> {
        let ExternalTestFixture {
            handler,
            session,
            context,
            ..
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
        let credential =
            ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
        let envelope = credential
            .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
            .context("sealing secure envelope")?;

        let err = match ExternalSessionHandler::open_secure_envelope(
            &handler, &envelope, &session, context,
        )
        .await
        {
            Ok(_plaintext) => bail!("expected missing credential rejection"),
            Err(error) => error,
        };
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_ready_provider_registers_declared_projection_bindings() -> anyhow::Result<()> {
        let ExternalTestFixture {
            boot,
            handler,
            session,
            context,
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
        let (outbound, _rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering provider outbound channel")?;

        let search = ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
        let summarize = ResourceName::new(parse_test_path(
            "effect://external-provider/chat/summarize",
        )?);
        let admin = ResourceName::new(parse_test_path("effect://external-provider/chat/admin")?);

        let search_id = boot
            .kernel
            .registry
            .resolve_resource(&search)
            .context("search resource should be registered")?;
        let summarize_id = boot
            .kernel
            .registry
            .resolve_resource(&summarize)
            .context("summarize resource should be registered")?;
        assert!(boot.kernel.registry.resolve_resource(&admin).is_err());

        let search_binding = boot
            .kernel
            .registry
            .binding(
                boot.kernel
                    .registry
                    .resource(search_id)
                    .context("search resource descriptor should exist")?
                    .binding,
            )
            .context("search binding should exist")?;
        let summarize_binding = boot
            .kernel
            .registry
            .binding(
                boot.kernel
                    .registry
                    .resource(summarize_id)
                    .context("summarize resource descriptor should exist")?
                    .binding,
            )
            .context("summarize binding should exist")?;
        assert_eq!(search_binding.endpoint, summarize_binding.endpoint);
        let endpoint_id = search_binding
            .endpoint
            .context("search binding should expose remote endpoint")?;
        assert!(boot.kernel.registry.remote_endpoint(endpoint_id).is_some());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn daemon_provider_binding_relink_keeps_resource_id() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let registry = &boot.kernel.registry;
        let path = parse_test_path("effect://external-provider/chat/search")?;
        let declaration = ProviderBindingDeclaration {
            path: path.clone(),
            purity: nexus_types::Purity::Effectful,
            selector: ResourceSelector::parse("perform://effect/external-provider/chat/search")?,
        };

        let endpoint = registry.next_endpoint_id();
        let (first, _) = register_provider_binding(registry, &declaration, endpoint, 1)
            .map_err(|error| anyhow::anyhow!("first provider binding failed: {error}"))?;
        let (second, _) = register_provider_binding(registry, &declaration, endpoint, 2)
            .map_err(|error| anyhow::anyhow!("second provider binding failed: {error}"))?;

        assert_eq!(first.resource_id, second.resource_id);
        assert_eq!(second.binding_generation, 2);
        let resource_name = ResourceName::new(path);
        let resource_id = registry
            .resolve_resource(&resource_name)
            .context("provider resource should resolve after relink")?;
        assert_eq!(resource_id, first.resource_id);
        let binding = registry
            .binding(
                registry
                    .resource(resource_id)
                    .context("provider resource descriptor should exist")?
                    .binding,
            )
            .context("provider binding should exist")?;
        assert_eq!(binding.generation, 2);

        let stale = register_provider_binding(registry, &declaration, endpoint, 1);
        assert!(
            stale.is_err(),
            "stale provider binding generation should be rejected"
        );
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_rejects_provider_projection_without_declared_bindings_before_ready()
    -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        write_chat_installation(
            &boot.kernel.state,
            provider_external_installation_without_capabilities_value()?,
        )
        .await?;
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await?;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let err = match handler
            .load_authority("chat", "provider", Role::Provider)
            .await
        {
            Ok(_authority) => bail!("expected provider projection admission failure"),
            Err(err) => err,
        };

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(lock_test(&handler.provider_sessions, "provider_sessions")?.is_empty());
        let search = ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
        assert!(boot.kernel.registry.resolve_resource(&search).is_err());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_ready_provider_routes_declared_remote_endpoint_binding() -> anyhow::Result<()> {
        let ExternalTestFixture {
            boot,
            handler,
            session,
            context,
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
        let (outbound, mut outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering provider outbound channel")?;

        let resource_name =
            ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&resource_name)
            .context("search resource should be registered")?;
        let resource = boot
            .kernel
            .registry
            .resource(resource_id)
            .context("search resource descriptor should exist")?;
        let binding = boot
            .kernel
            .registry
            .binding(resource.binding)
            .context("search binding should exist")?;
        let endpoint_id = binding
            .endpoint
            .context("search binding should expose remote endpoint")?;
        let dispatch = RemoteInvokeDispatch {
            endpoint_id,
            resource_id,
            method_id: MethodId::new(0),
            binding_generation: binding.generation,
            acting: IdentityRef::ROOT,
        };
        let endpoint = boot
            .kernel
            .registry
            .remote_endpoint(endpoint_id)
            .context("remote endpoint should be registered")?;

        let invoke = Invoke {
            invocation_id: "invoke-remote".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let pending = tokio::spawn(async move { endpoint.invoke(dispatch, invoke).await });
        let sent =
            expect_invoke_frame(recv_external_frame(&mut outbound_rx, "provider invoke").await?)?;
        let sent = nexus_proto::invoke_from_pb(&sent).context("decoding provider invoke frame")?;
        assert_eq!(sent.invocation_id, "invoke-remote");
        assert_eq!(
            sent.effect_path,
            parse_test_path("effect://external-provider/chat/search")?
        );

        let expected = InvokeResult {
            invocation_id: "invoke-remote".into(),
            outcome: Ok(Value::Str("result".into())),
        };
        ExternalSessionHandler::on_invoke_result(
            &handler,
            expected.clone(),
            &session,
            context.clone(),
        )
        .await
        .context("resolving remote provider invocation")?;
        let pending = pending.await.context("joining remote invoke task")?;
        assert_eq!(
            pending.map_err(|error| anyhow::anyhow!("remote invoke failed: {error:?}"))?,
            expected
        );

        let endpoint = boot
            .kernel
            .registry
            .remote_endpoint(endpoint_id)
            .context("remote endpoint should remain registered")?;
        let err = match endpoint
            .invoke(
                dispatch,
                Invoke {
                    invocation_id: "invoke-undeclared-effect".into(),
                    effect_path: parse_test_path("effect://external-provider/chat/admin")?,
                    method_id: MethodId::new(0),
                    input: Value::Str("query".into()),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
        {
            Ok(result) => bail!("expected undeclared effect rejection, got {result:?}"),
            Err(error) => error,
        };
        assert_eq!(
            err,
            DriverError::Transport("provider invoke effect rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());

        let endpoint = boot
            .kernel
            .registry
            .remote_endpoint(endpoint_id)
            .context("remote endpoint should remain registered")?;
        let wrong_method_dispatch = RemoteInvokeDispatch {
            method_id: MethodId::new(99),
            ..dispatch
        };
        let err = match endpoint
            .invoke(
                wrong_method_dispatch,
                Invoke {
                    invocation_id: "invoke-wrong-method".into(),
                    effect_path: parse_test_path("effect://external-provider/chat/search")?,
                    method_id: MethodId::new(99),
                    input: Value::Str("query".into()),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
        {
            Ok(result) => bail!("expected wrong method rejection, got {result:?}"),
            Err(error) => error,
        };
        assert_eq!(
            err,
            DriverError::Transport("provider invoke method rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());

        let endpoint = boot
            .kernel
            .registry
            .remote_endpoint(endpoint_id)
            .context("remote endpoint should remain registered")?;
        let stale_generation_dispatch = RemoteInvokeDispatch {
            binding_generation: binding.generation + 1,
            ..dispatch
        };
        let err = match endpoint
            .invoke(
                stale_generation_dispatch,
                Invoke {
                    invocation_id: "invoke-stale-generation".into(),
                    effect_path: parse_test_path("effect://external-provider/chat/search")?,
                    method_id: MethodId::new(0),
                    input: Value::Str("query".into()),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
        {
            Ok(result) => bail!("expected stale generation rejection, got {result:?}"),
            Err(error) => error,
        };
        assert_eq!(
            err,
            DriverError::Transport("provider invoke effect rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());

        let endpoint = boot
            .kernel
            .registry
            .remote_endpoint(endpoint_id)
            .context("remote endpoint should remain registered")?;
        let err = match endpoint
            .invoke(
                dispatch,
                Invoke {
                    invocation_id: "invoke-bad-input".into(),
                    effect_path: parse_test_path("effect://external-provider/chat/search")?,
                    method_id: MethodId::new(0),
                    input: Value::Int(7),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
        {
            Ok(result) => bail!("expected invalid input rejection, got {result:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            err,
            DriverError::Transport(message)
                if message.starts_with("provider invoke input rejected:")
                    && message.contains("expected `string`")
        ));
        assert!(outbound_rx.try_recv().is_err());
        assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
        assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());

        ExternalSessionHandler::on_closed(&handler, &session, context)
            .await
            .context("closing provider session")?;
        assert!(boot.kernel.registry.remote_endpoint(endpoint_id).is_none());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_provider_endpoint_times_out_pending_invocation() -> anyhow::Result<()> {
        let ExternalTestFixture {
            boot,
            handler,
            session,
            context,
        } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
        let (outbound, mut outbound_rx) = external_outbound_channel();
        ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
            .await
            .context("registering provider outbound channel")?;

        let resource_name =
            ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&resource_name)
            .context("search resource should be registered")?;
        let resource = boot
            .kernel
            .registry
            .resource(resource_id)
            .context("search resource descriptor should exist")?;
        let binding = boot
            .kernel
            .registry
            .binding(resource.binding)
            .context("search binding should exist")?;
        let endpoint_id = binding
            .endpoint
            .context("search binding should expose remote endpoint")?;
        let dispatch = RemoteInvokeDispatch {
            endpoint_id,
            resource_id,
            method_id: MethodId::new(0),
            binding_generation: binding.generation,
            acting: IdentityRef::ROOT,
        };
        let endpoint = boot
            .kernel
            .registry
            .remote_endpoint(endpoint_id)
            .context("remote endpoint should be registered")?;

        let deadline_ms = now_millis() + 200;
        let invoke = Invoke {
            invocation_id: "invoke-timeout".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: Some(deadline_ms),
            output_stream_to: None,
        };
        let pending = tokio::spawn(async move { endpoint.invoke(dispatch, invoke).await });
        let sent = expect_invoke_frame(
            recv_external_frame(&mut outbound_rx, "timed provider invoke").await?,
        )?;
        let sent =
            nexus_proto::invoke_from_pb(&sent).context("decoding timed provider invoke frame")?;
        assert_eq!(sent.invocation_id, "invoke-timeout");
        assert_eq!(sent.deadline_ms, Some(deadline_ms));

        let error = match pending
            .await
            .context("joining timed provider invoke task")?
        {
            Ok(result) => bail!("expected provider invocation timeout, got {result:?}"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            DriverError::Transport("provider invocation deadline exceeded".into())
        );
        let control = expect_control_frame(
            recv_external_frame(&mut outbound_rx, "provider cancel control").await?,
        )?;
        let control = nexus_proto::control_frame_from_pb(&control)
            .context("decoding provider cancel control frame")?;
        assert_eq!(
            control,
            ControlFrame::ProviderCancel {
                invocation_id: "invoke-timeout".into(),
                reason: "deadline_exceeded".into(),
            }
        );
        assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
        assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn provider_waiter_drop_reports_provider_unavailable() -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        drop(tx);

        let error = match await_provider_result(rx, None).await {
            Ok(result) => bail!("expected provider unavailable error, got {result:?}"),
            Err(error) => error,
        };

        assert_eq!(
            error.into_driver_error(),
            DriverError::Transport("provider unavailable".into())
        );
        Ok(())
    }
}
