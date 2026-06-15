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
//! registries and the root Process, install in-process Drivers, recover, start
//! gateways, and report ready.

mod config;

use anyhow::Result;
use config::NexusConfig;
#[cfg(feature = "external-gateway")]
use nexus_actors::endpoint::{
    EndpointSession, SourceIngest, SourceIngestError, ingest_source_event,
};
#[cfg(feature = "external-gateway")]
use nexus_actors::endpoint::{
    ProviderInvocationError, ProviderInvocationRegistry, ProviderInvocationResolve,
    SourceCommandError, SourceCommandRegister, SourceCommandRegistry, SourceCommandResolve,
    validate_json_schema,
};
#[cfg(all(feature = "external-grpc", test))]
use nexus_actors::pairing::EnvelopeAad;
#[cfg(feature = "external-gateway")]
use nexus_actors::pairing::{
    ExternalCredential, SecureEnvelope, SecureEnvelopeEpochGate, SecureEnvelopeReplayWindow,
};
use nexus_actors::{PairingDisplayEdge, StandardConfig, install_standard};
use nexus_console::{BootstrapOutcome, ConsoleState, RootProvisioning};
#[cfg(feature = "external-gateway")]
use nexus_gateway::GatewayTransportSecurityConfig;
#[cfg(feature = "external-websocket")]
use nexus_gateway_websocket::{
    ExternalWebSocketConfig, ExternalWebSocketOutbound, ExternalWebSocketService,
};
#[cfg(feature = "external-gateway")]
use nexus_kernel::PolicySnapshot;
#[cfg(feature = "external-gateway")]
use nexus_kernel::driver::{DriverDescriptor, DriverError, RemoteEndpoint, RemoteInvokeDispatch};
#[cfg(feature = "external-gateway")]
use nexus_kernel::{EchoDriver, Registry};
use nexus_sdk::{Backend, Bootstrap, FactSink, Kernel};
#[cfg(feature = "external-gateway")]
use nexus_sdk::{Path, Value};
use nexus_storage_redb::RedbStore;
#[cfg(feature = "external-gateway")]
use nexus_types::external::{
    AckStatus, EventAck, ExternalInstallationDef, ExternalProjectionDef, InboundEvent,
    ObservedGenerations, Role, RoleSessionClientHello, SessionContext,
};
#[cfg(feature = "external-gateway")]
use nexus_types::external::{
    CommandResult, ConfigAxis, ControlFrame, EffectCapability, Invoke, InvokeResult,
    OutboundCommand, ProviderReady,
};
#[cfg(feature = "external-gateway")]
use nexus_types::{
    Binding, CostModel, DriverRef, Interface, InterfaceFamily, InterfaceSet, Metadata, Method,
    MethodId, ModalitySet, OutputModeSet, Resource, ResourceDescriptor, ResourceKind, ResourceName,
    ResourceSelector, SchemaId, Transport,
};
#[cfg(feature = "external-gateway")]
use nexus_types::{IdentityRef, ResourceId};
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

fn main() -> ExitCode {
    match dispatch_main() {
        Ok(code) => code,
        Err(error) => {
            let _ = write_stderr_line(format_args!("nexusd: {error:#}"));
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
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
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
    install_standard(
        &boot,
        &StandardConfig {
            fs_root: None,
            terminal_allowlist: vec![],
            enable_fetch: false,
            pairing_display: pairing_display.clone(),
            ..Default::default()
        },
    )?;
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

    if let Some(addr) = cfg
        .server
        .console_addr
        .clone()
        .or_else(|| std::env::var(CONSOLE_ADDR_ENV).ok())
    {
        let listener = TcpListener::bind(&addr).await?;
        let state = ConsoleState::shared_with_pairing_display_and_config(
            boot.clone(),
            pairing_display.clone(),
            cfg.console.auth.clone().into(),
            cfg.console.ws.clone().into(),
            cfg.console
                .transport_security
                .to_console_transport_security_config()?,
        );
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
    let Some(addr) = cfg
        .server
        .external_websocket_addr
        .clone()
        .or_else(|| std::env::var(EXTERNAL_WEBSOCKET_ADDR_ENV).ok())
    else {
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
    let Some(addr) = cfg
        .server
        .external_grpc_addr
        .clone()
        .or_else(|| std::env::var(EXTERNAL_GRPC_ADDR_ENV).ok())
    else {
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
pub struct DaemonExternalSessionHandler {
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
    bindings_registered: bool,
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
    outbound: ExternalSessionOutbound,
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
    outbound: ExternalSessionOutbound,
    provider_invocations: Arc<std::sync::Mutex<ProviderInvocationRegistry>>,
    provider_waiters: Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<InvokeResult>>>>,
    provider_sessions: Arc<std::sync::Mutex<BTreeMap<ProviderSessionKey, ProviderSessionRecord>>>,
    session_limits: config::ExternalGatewaySessionLimits,
}

#[cfg(feature = "external-gateway")]
#[derive(Clone)]
enum ExternalSessionOutbound {
    #[cfg(feature = "external-grpc")]
    Grpc(nexus_gateway_grpc::ExternalOutbound),
    #[cfg(feature = "external-websocket")]
    WebSocket(ExternalWebSocketOutbound),
}

#[cfg(feature = "external-gateway")]
impl ExternalSessionOutbound {
    async fn send_invoke(&self, invoke: Invoke) -> Result<(), tonic::Status> {
        match self {
            #[cfg(feature = "external-grpc")]
            Self::Grpc(outbound) => outbound.send_invoke(invoke).await,
            #[cfg(feature = "external-websocket")]
            Self::WebSocket(outbound) => outbound.send_invoke(invoke).await,
        }
    }

    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), tonic::Status> {
        match self {
            #[cfg(feature = "external-grpc")]
            Self::Grpc(outbound) => outbound.send_outbound_command(command).await,
            #[cfg(feature = "external-websocket")]
            Self::WebSocket(outbound) => outbound.send_outbound_command(command).await,
        }
    }

    async fn send_control(&self, frame: ControlFrame) -> Result<(), tonic::Status> {
        match self {
            #[cfg(feature = "external-grpc")]
            Self::Grpc(outbound) => outbound.send_control(frame).await,
            #[cfg(feature = "external-websocket")]
            Self::WebSocket(outbound) => outbound.send_control(frame).await,
        }
    }
}

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
        validate_json_schema(capability.input_schema.as_ref(), &invoke.input)
            .map_err(|_| DriverError::Transport("provider invoke input rejected".into()))?;
        let output_schema = capability.output_schema.as_ref();
        let invocation_id = invoke.invocation_id.clone();
        let deadline_ms = invoke.deadline_ms;

        let (tx, rx) = oneshot::channel();
        {
            let mut invocations = self.provider_invocations.lock().map_err(|_| {
                DriverError::Transport("provider invocation registry unavailable".into())
            })?;
            invocations
                .register(nexus_actors::endpoint::ProviderInvocationRegister {
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
            self.provider_invocations
                .lock()
                .map(|mut invocations| {
                    invocations.remove(&invocation_id);
                })
                .ok();
            return Err(error);
        }

        if let Err(status) = self.outbound.send_invoke(invoke).await {
            remove_provider_invocation_pending(
                &self.provider_invocations,
                &self.provider_waiters,
                &invocation_id,
            );
            return Err(status_to_driver_error(status));
        }

        match await_provider_result(rx, deadline_ms).await {
            Ok(result) => Ok(result),
            Err(error) => {
                if matches!(error, ProviderAwaitError::DeadlineExceeded) {
                    let _ = self
                        .outbound
                        .send_control(ControlFrame::ProviderCancel {
                            invocation_id: invocation_id.clone(),
                            reason: "deadline_exceeded".into(),
                        })
                        .await;
                }
                remove_provider_invocation_pending(
                    &self.provider_invocations,
                    &self.provider_waiters,
                    &invocation_id,
                );
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
) {
    provider_waiters
        .lock()
        .map(|mut waiters| {
            waiters.remove(invocation_id);
        })
        .ok();
    provider_invocations
        .lock()
        .map(|mut invocations| {
            invocations.remove(invocation_id);
        })
        .ok();
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

#[cfg(feature = "external-gateway")]
fn remove_source_command_pending(
    source_commands: &Arc<std::sync::Mutex<SourceCommandRegistry>>,
    source_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    command_id: &str,
) {
    source_commands
        .lock()
        .map(|mut commands| {
            commands.remove(command_id);
        })
        .ok();
    remove_source_command_waiter(source_waiters, command_id);
}

#[cfg(feature = "external-gateway")]
fn remove_source_command_waiter(
    source_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    command_id: &str,
) {
    source_waiters
        .lock()
        .map(|mut waiters| {
            waiters.remove(command_id);
        })
        .ok();
}

#[cfg(feature = "external-gateway")]
fn remove_source_command_waiters(
    source_waiters: &Arc<std::sync::Mutex<BTreeMap<String, oneshot::Sender<CommandResult>>>>,
    command_ids: Vec<String>,
) {
    if command_ids.is_empty() {
        return;
    }
    source_waiters
        .lock()
        .map(|mut waiters| {
            for command_id in command_ids {
                waiters.remove(&command_id);
            }
        })
        .ok();
}

#[cfg(feature = "external-gateway")]
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
        let expired = source_commands
            .lock()
            .map(|mut commands| commands.expire(now_millis()))
            .unwrap_or_default();
        remove_source_command_waiters(&source_waiters, expired);
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
    fn install_external_credential(&self, credential: ExternalCredential) {
        self.external_credentials.lock().unwrap().insert(
            (credential.installation_id.clone(), credential.generation),
            credential,
        );
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
        validate_json_schema(capability.input_schema.as_ref(), &invoke.input)
            .map_err(|_| tonic::Status::invalid_argument("provider invocation rejected"))?;
        let output_schema = capability.output_schema.as_ref();
        {
            let mut invocations = self
                .provider_invocations
                .lock()
                .map_err(|_| tonic::Status::internal("provider invocation registry unavailable"))?;
            invocations
                .register(nexus_actors::endpoint::ProviderInvocationRegister {
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
            self.provider_invocations
                .lock()
                .map(|mut invocations| {
                    invocations.remove(&invoke.invocation_id);
                })
                .ok();
            return Err(error);
        }
        Ok(rx)
    }

    pub async fn send_source_command(
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
            self.source_commands
                .lock()
                .map(|mut commands| {
                    commands.remove(&command_id);
                })
                .ok();
            return Err(error);
        }

        if let Err(status) = outbound.send_outbound_command(command).await {
            remove_source_command_pending(&self.source_commands, &self.source_waiters, &command_id);
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
                        remove_source_command_waiter(&self.source_waiters, &result_id);
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
                        );
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

    async fn handle_provider_ready(
        &self,
        ready: ProviderReady,
        _session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        let authority = self
            .load_authority(
                &context.installation_id,
                &context.projection_id,
                Role::Provider,
            )
            .await?;
        if !context_matches_authority(&authority.context, &context) {
            return Err(tonic::Status::permission_denied(
                "provider context rejected",
            ));
        }
        validate_provider_ready(&ready, &authority.projection)?;
        let mut sessions = self
            .provider_sessions
            .lock()
            .map_err(|_| tonic::Status::internal("provider session registry unavailable"))?;
        let session = sessions
            .get_mut(&provider_session_key(&context))
            .ok_or_else(|| tonic::Status::failed_precondition("provider session not ready"))?;
        if session.context != context {
            return Err(tonic::Status::permission_denied(
                "provider session context rejected",
            ));
        }
        if session.bindings_registered {
            return Err(tonic::Status::failed_precondition(
                "provider session already ready",
            ));
        }
        let ready_endpoints =
            register_provider_bindings(&self.registry, &ready, session.endpoint_id, &context)?;
        session.bindings_registered = true;
        session.ready_endpoints = ready_endpoints;
        Ok(())
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
            session_id: envelope.aad.session_id.clone(),
            key_epoch: envelope.aad.key_epoch,
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

#[cfg(feature = "external-grpc")]
#[tonic::async_trait]
impl nexus_gateway_grpc::ExternalSessionHandler for DaemonExternalSessionHandler {
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
        outbound: nexus_gateway_grpc::ExternalOutbound,
    ) -> Result<(), tonic::Status> {
        self.register_ready_session(session, context, ExternalSessionOutbound::Grpc(outbound))
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

    async fn on_provider_ready(
        &self,
        ready: ProviderReady,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_provider_ready(ready, session, context).await
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

#[cfg(feature = "external-websocket")]
#[tonic::async_trait]
impl nexus_gateway_websocket::ExternalWebSocketSessionHandler for DaemonExternalSessionHandler {
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
        outbound: ExternalWebSocketOutbound,
    ) -> Result<(), tonic::Status> {
        self.register_ready_session(
            session,
            context,
            ExternalSessionOutbound::WebSocket(outbound),
        )
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

    async fn on_provider_ready(
        &self,
        ready: ProviderReady,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), tonic::Status> {
        self.handle_provider_ready(ready, session, context).await
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
        outbound: ExternalSessionOutbound,
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
                self.provider_sessions
                    .lock()
                    .map_err(|_| tonic::Status::internal("provider session registry unavailable"))?
                    .insert(
                        provider_session_key(&context),
                        ProviderSessionRecord {
                            endpoint_id,
                            context,
                            bindings_registered: false,
                            ready_endpoints: HashMap::new(),
                        },
                    );
            }
            Role::Source => {
                self.source_sessions
                    .lock()
                    .map_err(|_| tonic::Status::internal("source session registry unavailable"))?
                    .insert(
                        source_session_key(&context),
                        SourceSessionRecord { context, outbound },
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
        let path = Path::parse(&capability.effect_path)
            .map_err(|_| tonic::Status::failed_precondition("external projection is invalid"))?;
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
    .map_err(|_| tonic::Status::invalid_argument("external installation id is invalid"))?;
    let Some(value) = state
        .read(&path)
        .await
        .map_err(|_| tonic::Status::unavailable("external state read failed"))?
    else {
        return Err(tonic::Status::not_found("external installation not found"));
    };
    let json = serde_json::to_value(value)
        .map_err(|_| tonic::Status::failed_precondition("external state is invalid"))?;
    let installation: ExternalInstallationDef = serde_json::from_value(json)
        .map_err(|_| tonic::Status::failed_precondition("external installation is invalid"))?;
    if installation.id != installation_id {
        return Err(tonic::Status::failed_precondition(
            "external installation id mismatch",
        ));
    }
    installation.validate_admission().map_err(|_| {
        tonic::Status::failed_precondition("external installation admission failed")
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
    .map_err(|_| tonic::Status::invalid_argument("External session id is invalid"))?;
    let Some(value) = state
        .read(&path)
        .await
        .map_err(|_| tonic::Status::unavailable("External session state read failed"))?
    else {
        return Err(tonic::Status::unauthenticated(
            "External session is not approved",
        ));
    };
    let record = value
        .as_map()
        .ok_or_else(|| tonic::Status::failed_precondition("External session is invalid"))?;
    if record.get("installation_id").and_then(Value::as_str) != Some(installation_id)
        || record.get("role").and_then(Value::as_str) != Some(role)
    {
        return Err(tonic::Status::failed_precondition(
            "External session mismatch",
        ));
    }
    if record.get("state").and_then(Value::as_str) != Some("ready") {
        return Err(tonic::Status::unauthenticated(
            "External session is not ready",
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
    .map_err(|_| tonic::Status::invalid_argument("external revocation id is invalid"))?;
    let Some(value) = state
        .read(&path)
        .await
        .map_err(|_| tonic::Status::unavailable("external revocation state read failed"))?
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
    external_registry_hash_value(installation, projection)
        .map_err(|_| tonic::Status::failed_precondition("external registry is invalid"))
}

#[cfg(feature = "external-gateway")]
fn credential_generation_from_record(
    record: &std::collections::BTreeMap<String, Value>,
) -> Result<u64, tonic::Status> {
    let generation = record
        .get("credential_generation")
        .and_then(Value::as_int)
        .ok_or_else(|| {
            tonic::Status::failed_precondition("External session generation is invalid")
        })?;
    if generation <= 0 {
        return Err(tonic::Status::failed_precondition(
            "External session generation is invalid",
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
            "External session key epoch is invalid",
        ));
    };
    if epoch < 0 {
        return Err(tonic::Status::failed_precondition(
            "External session key epoch is invalid",
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
    getrandom::fill(&mut bytes)
        .map_err(|_| tonic::Status::unavailable("External session id unavailable"))?;
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
fn register_provider_bindings(
    registry: &Registry,
    ready: &ProviderReady,
    endpoint_id: nexus_types::EndpointId,
    context: &SessionContext,
) -> Result<HashMap<ProviderEndpointKey, Path>, tonic::Status> {
    let mut ready_endpoints = HashMap::new();
    for handler in &ready.provides {
        let (key, path) = register_provider_binding(
            registry,
            &handler.path,
            handler.purity,
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
    effect_path: &str,
    purity: nexus_types::Purity,
    endpoint_id: nexus_types::EndpointId,
    binding_generation: u64,
) -> Result<(ProviderEndpointKey, Path), tonic::Status> {
    let path = Path::parse(effect_path)
        .map_err(|_| tonic::Status::invalid_argument("provider readiness rejected"))?;
    let iface_id = registry.next_interface_id();
    registry.register_interface(Interface {
        id: iface_id,
        family: InterfaceFamily::Callable,
        methods: vec![Method {
            id: MethodId::new(0),
            name: "invoke".into(),
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity,
            replay: purity.replay_class(false),
            supports: OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
            cost: CostModel::default(),
            batchable: false,
        }],
        laws: Vec::new(),
    });

    let driver_id = registry.next_driver_id();
    registry.register_driver(DriverDescriptor {
        id: driver_id,
        name: effect_path.into(),
        implements: InterfaceSet::new(vec![iface_id]),
        transport: Transport::Grpc { endpoint: None },
        driver: Arc::new(EchoDriver),
    });

    let selector_literal = format!("perform://{}", strip_scheme(effect_path));
    let selector = ResourceSelector::parse(&selector_literal)
        .map_err(|_| tonic::Status::failed_precondition("provider binding rejected"))?;
    let binding_id = registry.next_binding_id();
    registry
        .admit_binding(Binding {
            id: binding_id,
            selector,
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: DriverRef {
                id: driver_id,
                name: effect_path.into(),
            },
            endpoint: Some(endpoint_id),
            generation: binding_generation,
        })
        .map_err(|_| tonic::Status::failed_precondition("provider binding rejected"))?;

    let rid = registry.next_resource_id();
    registry
        .admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: ResourceName::new(path.clone()),
                    kind: ResourceKind::Effect,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            true,
        )
        .map_err(|_| tonic::Status::failed_precondition("provider binding rejected"))?;
    Ok((
        ProviderEndpointKey {
            resource_id: rid,
            method_id: MethodId::new(0),
            binding_generation,
        },
        path,
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
fn validate_provider_ready(
    ready: &ProviderReady,
    projection: &ExternalProjectionDef,
) -> Result<(), tonic::Status> {
    if projection.role != Role::Provider {
        return Err(tonic::Status::permission_denied(
            "provider readiness rejected",
        ));
    }
    let mut admitted = std::collections::BTreeMap::new();
    for cap in &projection.provides {
        Path::parse(&cap.effect_path)
            .map_err(|_| tonic::Status::failed_precondition("external projection is invalid"))?;
        if admitted
            .insert(cap.effect_path.as_str(), cap.purity)
            .is_some()
        {
            return Err(tonic::Status::failed_precondition(
                "external projection is invalid",
            ));
        }
    }

    let mut reported = std::collections::BTreeSet::new();
    for handler in &ready.provides {
        Path::parse(&handler.path)
            .map_err(|_| tonic::Status::invalid_argument("provider readiness rejected"))?;
        if !reported.insert(handler.path.as_str()) {
            return Err(tonic::Status::invalid_argument(
                "provider readiness rejected",
            ));
        }
        let Some(purity) = admitted.get(handler.path.as_str()) else {
            return Err(tonic::Status::permission_denied(
                "provider readiness rejected",
            ));
        };
        if *purity != handler.purity {
            return Err(tonic::Status::permission_denied(
                "provider readiness rejected",
            ));
        }
    }
    Ok(())
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(feature = "external-gateway")]
fn source_ingest_status(error: SourceIngestError) -> tonic::Status {
    match error {
        SourceIngestError::Session(_)
        | SourceIngestError::ProjectionMismatch(_)
        | SourceIngestError::RegistryHashMismatch
        | SourceIngestError::CredentialGenerationMismatch
        | SourceIngestError::BindingGenerationMismatch
        | SourceIngestError::InstallationConfigVersionMismatch
        | SourceIngestError::ProjectionVersionMismatch
        | SourceIngestError::NotSource
        | SourceIngestError::MissingEmits => {
            tonic::Status::permission_denied("source event rejected")
        }
        SourceIngestError::InvalidEventId
        | SourceIngestError::InvalidStreamId
        | SourceIngestError::InvalidSequence
        | SourceIngestError::SequenceReplay { .. }
        | SourceIngestError::SequenceGap { .. }
        | SourceIngestError::Schema(_)
        | SourceIngestError::PayloadTooLarge
        | SourceIngestError::ForbiddenPayloadField { .. }
        | SourceIngestError::Policy(_) => tonic::Status::invalid_argument("source event rejected"),
        SourceIngestError::RateLimited
        | SourceIngestError::Backpressured
        | SourceIngestError::CapacityExceeded => {
            tonic::Status::resource_exhausted("source event rejected")
        }
        SourceIngestError::State(_) => tonic::Status::unavailable("source event rejected"),
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
    match error {
        ProviderInvocationError::InvocationNotFound
        | ProviderInvocationError::SessionMismatch
        | ProviderInvocationError::NotProvider
        | ProviderInvocationError::RegistryHashMismatch
        | ProviderInvocationError::CredentialGenerationMismatch
        | ProviderInvocationError::BindingGenerationMismatch
        | ProviderInvocationError::ProjectionVersionMismatch => {
            tonic::Status::permission_denied("provider invocation result rejected")
        }
        ProviderInvocationError::Session(_) => {
            tonic::Status::failed_precondition("provider invocation result rejected")
        }
        ProviderInvocationError::EmptyInvocationId
        | ProviderInvocationError::DuplicateInvocationId
        | ProviderInvocationError::Schema(_) => {
            tonic::Status::invalid_argument("provider invocation result rejected")
        }
        ProviderInvocationError::DeadlineExceeded => {
            tonic::Status::deadline_exceeded("provider invocation result rejected")
        }
        ProviderInvocationError::ResultTooLarge
        | ProviderInvocationError::InFlightLimitExceeded => {
            tonic::Status::resource_exhausted("provider invocation result rejected")
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

#[cfg(feature = "external-gateway")]
fn source_command_dispatch_status(error: SourceCommandError) -> tonic::Status {
    source_command_error_status(error, "source command rejected")
}

#[cfg(feature = "external-gateway")]
fn source_command_error_status(error: SourceCommandError, message: &'static str) -> tonic::Status {
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
    #[cfg(feature = "external-grpc")]
    use serde_json::json;

    #[tokio::test]
    async fn kernel_boots_with_standard_providers() {
        let boot = Arc::new(Bootstrap::in_memory());
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());
        assert!(boot.kernel.registry.resource_count() >= 5);
    }

    #[cfg(feature = "external-grpc")]
    fn external_installation_value() -> Value {
        source_external_installation_value(false)
    }

    #[cfg(feature = "external-grpc")]
    fn source_external_installation_value(commands: bool) -> Value {
        serde_json::from_value(source_external_installation_json(commands)).unwrap()
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
    fn provider_external_installation_value() -> Value {
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
        .unwrap()
    }

    #[cfg(feature = "external-grpc")]
    async fn write_external_session(
        state: &Backend,
        installation_id: &str,
        role: &str,
        credential_generation: i64,
    ) {
        write_external_session_with_key_epoch(
            state,
            installation_id,
            role,
            credential_generation,
            0,
        )
        .await;
    }

    #[cfg(feature = "external-grpc")]
    async fn write_external_session_with_key_epoch(
        state: &Backend,
        installation_id: &str,
        role: &str,
        credential_generation: i64,
        key_epoch: i64,
    ) {
        state
            .write_set(
                &Path::parse(&format!(
                    "state://kernel/external-sessions/{installation_id}/{role}"
                ))
                .unwrap(),
                serde_json::from_value(json!({
                    "installation_id": installation_id,
                    "role": role,
                    "pairing_id": "pair-1",
                    "credential_generation": credential_generation,
                    "key_epoch": key_epoch,
                    "state": "ready"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }

    #[cfg(feature = "external-grpc")]
    fn external_outbound_channel() -> (
        nexus_gateway_grpc::ExternalOutbound,
        tokio::sync::mpsc::Receiver<
            Result<nexus_proto::nexus::v1::external::ExternalFrame, tonic::Status>,
        >,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        (nexus_gateway_grpc::ExternalOutbound::from_sender(tx), rx)
    }

    #[cfg(feature = "external-grpc")]
    async fn write_external_revocation(
        state: &Backend,
        installation_id: &str,
        credential_generation_floor: i64,
    ) {
        state
            .write_set(
                &Path::parse(&format!(
                    "state://kernel/external-credential-revocations/{installation_id}"
                ))
                .unwrap(),
                serde_json::from_value(json!({
                    "installation_id": installation_id,
                    "state": "revoked",
                    "credential_generation_floor": credential_generation_floor
                }))
                .unwrap(),
            )
            .await
            .unwrap();
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
    async fn daemon_external_handler_adjudicates_from_installation_state() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
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
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();

        assert_eq!(context.installation_id, "chat");
        assert_eq!(context.projection_id, "source");
        assert_eq!(context.role, Role::Source);
        assert_eq!(context.credential_generation, 5);
        assert_eq!(context.binding_generation, 7);
        assert_eq!(context.installation_config_version, 11);
        assert_ne!(context.registry_hash, "client-observed");
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_requires_approved_role_session() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                external_installation_value(),
            )
            .await
            .unwrap();
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
        let err = nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_revoked_role_session() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 2).await;
        write_external_revocation(&boot.kernel.state, "chat", 2).await;
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
        let err = nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_ingests_source_event() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let ack = nexus_gateway_grpc::ExternalSessionHandler::on_inbound_event(
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
        .unwrap();

        assert_eq!(ack.status, nexus_types::external::AckStatus::Accepted);
        let rows = boot
            .kernel
            .state
            .read_prefix(&Path::parse("state://events/external/chat/source").unwrap())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, Value::List(vec![Value::Str("hello".into())]));
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn source_ingest_event_errors_are_rejected_acks() {
        let policy = source_ingest_rejection_ack(
            "evt-1".into(),
            &SourceIngestError::Policy("private detail".into()),
        )
        .unwrap();
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
                .unwrap()
                .reject_reason,
            Some("rate_limited".into())
        );
        assert_eq!(
            source_ingest_rejection_ack("evt-3".into(), &SourceIngestError::PayloadTooLarge)
                .unwrap()
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
            .unwrap()
            .reject_reason,
            Some("forbidden_payload_field".into())
        );
        assert_eq!(
            source_ingest_rejection_ack("evt-5".into(), &SourceIngestError::RegistryHashMismatch),
            None
        );
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_returns_rejected_ack_for_source_schema_error() {
        let boot = Arc::new(Bootstrap::in_memory());
        let mut install = source_external_installation_json(false);
        install["projections"][0]["emits"]["event_schema"] = json!({ "type": "string" });
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                serde_json::from_value(install).unwrap(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let ack = nexus_gateway_grpc::ExternalSessionHandler::on_inbound_event(
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
        .unwrap();

        assert_eq!(ack.status, AckStatus::Rejected);
        assert_eq!(ack.reject_reason, Some("schema_rejected".into()));
        assert_eq!(
            boot.kernel
                .state
                .read(&Path::parse("state://events/external/chat/source").unwrap())
                .await
                .unwrap(),
            None
        );
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_gates_external_control_frames() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        nexus_gateway_grpc::ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::Heartbeat { timestamp_ms: 10 },
            &session,
            context.clone(),
        )
        .await
        .unwrap();
        nexus_gateway_grpc::ExternalSessionHandler::on_control(
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
        .unwrap();

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_control(
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
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::InstallationConfigUpdate {
                config_version: context.installation_config_version + 1,
                config: Value::Null,
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::Shutdown {
                graceful: true,
                timeout_ms: 1_000,
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_control(
            &handler,
            ControlFrame::FlowControl(nexus_types::external::FlowSignal::Pause),
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_control(
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
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_resolves_only_registered_source_commands() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                source_external_installation_value(true),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, mut outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

        let command = nexus_types::external::OutboundCommand {
            id: "cmd-1".into(),
            action: Value::Str("sync".into()),
            observed: Default::default(),
        };
        let receiver = handler
            .send_source_command(command, &session, &context, None)
            .await
            .unwrap();
        let sent = outbound_rx.recv().await.unwrap().unwrap();
        let Some(nexus_proto::nexus::v1::external::external_frame::Frame::OutboundCommand(sent)) =
            sent.frame
        else {
            panic!("expected source outbound command frame");
        };
        let sent = nexus_proto::outbound_command_from_pb(&sent).unwrap();
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
        nexus_gateway_grpc::ExternalSessionHandler::on_command_result(
            &handler,
            expected.clone(),
            &session,
            context.clone(),
        )
        .await
        .unwrap();
        assert_eq!(receiver.await.unwrap(), expected);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_command_result(
            &handler,
            CommandResult {
                id: "cmd-1".into(),
                outcome: Ok(Value::Str("again".into())),
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = handler
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
            .unwrap_err();
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
            .unwrap();
        assert!(outbound_rx.recv().await.unwrap().is_ok());
        let err = nexus_gateway_grpc::ExternalSessionHandler::on_command_result(
            &handler,
            CommandResult {
                id: "cmd-bad-result".into(),
                outcome: Ok(Value::Int(7)),
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(receiver.await.is_err());
        assert!(handler.source_commands.lock().unwrap().is_empty());
        assert!(handler.source_waiters.lock().unwrap().is_empty());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_expires_pending_source_commands() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                source_external_installation_value(true),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, mut outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

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
            .unwrap();
        let sent = outbound_rx.recv().await.unwrap().unwrap();
        let Some(nexus_proto::nexus::v1::external::external_frame::Frame::OutboundCommand(sent)) =
            sent.frame
        else {
            panic!("expected source outbound command frame");
        };
        assert_eq!(
            nexus_proto::outbound_command_from_pb(&sent).unwrap().id,
            "cmd-timeout"
        );

        assert!(receiver.await.is_err());
        assert!(handler.source_commands.lock().unwrap().is_empty());
        assert!(handler.source_waiters.lock().unwrap().is_empty());

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_command_result(
            &handler,
            CommandResult {
                id: "cmd-timeout".into(),
                outcome: Ok(Value::Str("late".into())),
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_source_command_in_flight_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                source_external_installation_value(true),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::with_limits(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                source_max_in_flight_commands: 1,
                ..Default::default()
            },
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, mut outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

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
            .unwrap();
        assert!(outbound_rx.recv().await.unwrap().is_ok());

        let err = handler
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
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(handler.source_commands.lock().unwrap().len(), 1);
        assert_eq!(handler.source_waiters.lock().unwrap().len(), 1);
        assert!(outbound_rx.try_recv().is_err());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_source_command_rate_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                source_external_installation_value(true),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::with_limits(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                source_command_rate_limit_window_ms: 60_000,
                source_command_rate_limit_max: 1,
                ..Default::default()
            },
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, mut outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

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
            .unwrap();
        assert!(outbound_rx.recv().await.unwrap().is_ok());

        let err = handler
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
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(handler.source_commands.lock().unwrap().len(), 1);
        assert!(outbound_rx.try_recv().is_err());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_source_commands_when_projection_disables_them() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, _outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

        let err = handler
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
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_drains_source_commands_on_close() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                source_external_installation_value(true),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "source", 5).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "source", Role::Source)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, _outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

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
            .unwrap();

        nexus_gateway_grpc::ExternalSessionHandler::on_closed(&handler, &session, context.clone())
            .await
            .unwrap();

        assert!(receiver.await.is_err());
        assert!(handler.source_sessions.lock().unwrap().is_empty());
        assert!(handler.source_commands.lock().unwrap().is_empty());
        assert!(handler.source_waiters.lock().unwrap().is_empty());

        let err = handler
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
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_resolves_only_registered_provider_invocations() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let invoke = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let receiver = handler
            .register_provider_invoke(&invoke, &session, &context)
            .await
            .unwrap();

        let expected = InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: Ok(Value::Str("result".into())),
        };
        nexus_gateway_grpc::ExternalSessionHandler::on_invoke_result(
            &handler,
            expected.clone(),
            &session,
            context.clone(),
        )
        .await
        .unwrap();
        assert_eq!(receiver.await.unwrap(), expected);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_invoke_result(
            &handler,
            InvokeResult {
                invocation_id: "invoke-1".into(),
                outcome: Ok(Value::Str("again".into())),
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let invoke = nexus_types::external::Invoke {
            invocation_id: "invoke-schema".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let receiver = handler
            .register_provider_invoke(&invoke, &session, &context)
            .await
            .unwrap();
        let err = nexus_gateway_grpc::ExternalSessionHandler::on_invoke_result(
            &handler,
            InvokeResult {
                invocation_id: "invoke-schema".into(),
                outcome: Ok(Value::Int(7)),
            },
            &session,
            context,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(receiver.await.is_err());
        assert!(handler.provider_invocations.lock().unwrap().is_empty());
        assert!(handler.provider_waiters.lock().unwrap().is_empty());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rolls_back_provider_invocation_on_waiter_duplicate() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let (stale_tx, _stale_rx) = oneshot::channel();
        handler
            .provider_waiters
            .lock()
            .unwrap()
            .insert("invoke-stale".into(), stale_tx);
        let invoke = nexus_types::external::Invoke {
            invocation_id: "invoke-stale".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };

        let err = handler
            .register_provider_invoke(&invoke, &session, &context)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(handler.provider_invocations.lock().unwrap().is_empty());
        assert_eq!(handler.provider_waiters.lock().unwrap().len(), 1);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_provider_invocation_in_flight_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::with_limits(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                provider_max_in_flight_invocations: 1,
                ..Default::default()
            },
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let first = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let _receiver = handler
            .register_provider_invoke(&first, &session, &context)
            .await
            .unwrap();

        let second = nexus_types::external::Invoke {
            invocation_id: "invoke-2".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let err = handler
            .register_provider_invoke(&second, &session, &context)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(handler.provider_invocations.lock().unwrap().len(), 1);
        assert_eq!(handler.provider_waiters.lock().unwrap().len(), 1);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_provider_identity_in_flight_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::with_limits(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                provider_max_in_flight_per_identity: 1,
                ..Default::default()
            },
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let first = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let _receiver = handler
            .register_provider_invoke(&first, &session, &context)
            .await
            .unwrap();

        let second = nexus_types::external::Invoke {
            invocation_id: "invoke-2".into(),
            effect_path: Path::parse("effect://external-provider/chat/summarize").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let err = handler
            .register_provider_invoke(&second, &session, &context)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(handler.provider_invocations.lock().unwrap().len(), 1);
        assert_eq!(handler.provider_waiters.lock().unwrap().len(), 1);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_enforces_provider_effect_in_flight_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::with_limits(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            config::ExternalGatewaySessionLimits {
                source_dedupe_window_ms: 60_000,
                provider_max_in_flight_per_effect: 1,
                ..Default::default()
            },
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();

        let first = nexus_types::external::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let _receiver = handler
            .register_provider_invoke(&first, &session, &context)
            .await
            .unwrap();

        let second = nexus_types::external::Invoke {
            invocation_id: "invoke-2".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: nexus_types::MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let err = handler
            .register_provider_invoke(&second, &session, &context)
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(handler.provider_invocations.lock().unwrap().len(), 1);
        assert_eq!(handler.provider_waiters.lock().unwrap().len(), 1);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_opens_secure_envelope_with_installed_credential() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let credential = ExternalCredential::from_pairing(
            "chat",
            "pairing-secret",
            context.credential_generation,
        );
        let envelope = credential
            .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
            .unwrap();
        handler.install_external_credential(credential);

        let plaintext = nexus_gateway_grpc::ExternalSessionHandler::open_secure_envelope(
            &handler,
            &envelope,
            &session,
            context.clone(),
        )
        .await
        .unwrap();
        assert_eq!(plaintext, b"frame-bytes");

        let err = nexus_gateway_grpc::ExternalSessionHandler::open_secure_envelope(
            &handler, &envelope, &session, context,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_old_epoch_business_envelope_after_rekey() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session_with_key_epoch(&boot.kernel.state, "chat", "provider", 9, 1).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let credential = ExternalCredential::from_pairing(
            "chat",
            "pairing-secret",
            context.credential_generation,
        );
        let envelope = credential
            .seal_with_aad(
                b"frame-bytes",
                secure_envelope_aad_with(&context, 0, "invoke", 0),
            )
            .unwrap();
        let generic_control_envelope = credential
            .seal_with_aad(
                b"frame-bytes",
                secure_envelope_aad_with(&context, 0, "control", 0),
            )
            .unwrap();
        handler.install_external_credential(credential);

        let err = nexus_gateway_grpc::ExternalSessionHandler::open_secure_envelope(
            &handler, &envelope, &session, context,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::open_secure_envelope(
            &handler,
            &generic_control_envelope,
            &session,
            session.context().unwrap().clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_clears_secure_replay_state_on_close() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let credential = ExternalCredential::from_pairing(
            "chat",
            "pairing-secret",
            context.credential_generation,
        );
        let envelope = credential
            .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
            .unwrap();
        handler.install_external_credential(credential);

        nexus_gateway_grpc::ExternalSessionHandler::open_secure_envelope(
            &handler,
            &envelope,
            &session,
            context.clone(),
        )
        .await
        .unwrap();
        assert_eq!(handler.secure_replay_windows.lock().unwrap().len(), 1);

        nexus_gateway_grpc::ExternalSessionHandler::on_closed(&handler, &session, context)
            .await
            .unwrap();
        assert!(handler.secure_replay_windows.lock().unwrap().is_empty());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_rejects_secure_envelope_without_credential() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let credential = ExternalCredential::from_pairing(
            "chat",
            "pairing-secret",
            context.credential_generation,
        );
        let envelope = credential
            .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
            .unwrap();

        let err = nexus_gateway_grpc::ExternalSessionHandler::open_secure_envelope(
            &handler, &envelope, &session, context,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_external_handler_validates_provider_ready_against_projection() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, _rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();

        nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![nexus_types::external::EffectHandlerSpec {
                    path: "effect://external-provider/chat/search".into(),
                    purity: nexus_types::Purity::Idempotent,
                    description: None,
                }],
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap();

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![nexus_types::external::EffectHandlerSpec {
                    path: "effect://external-provider/chat/search".into(),
                    purity: nexus_types::Purity::Idempotent,
                    description: None,
                }],
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![nexus_types::external::EffectHandlerSpec {
                    path: "effect://external-provider/chat/admin".into(),
                    purity: nexus_types::Purity::Idempotent,
                    description: None,
                }],
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![nexus_types::external::EffectHandlerSpec {
                    path: "effect://external-provider/chat/search".into(),
                    purity: nexus_types::Purity::Effectful,
                    description: None,
                }],
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![
                    nexus_types::external::EffectHandlerSpec {
                        path: "effect://external-provider/chat/search".into(),
                        purity: nexus_types::Purity::Idempotent,
                        description: None,
                    },
                    nexus_types::external::EffectHandlerSpec {
                        path: "effect://external-provider/chat/search".into(),
                        purity: nexus_types::Purity::Idempotent,
                        description: None,
                    },
                ],
            },
            &session,
            context,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_provider_ready_registers_remote_endpoint_binding() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, mut outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();
        nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![nexus_types::external::EffectHandlerSpec {
                    path: "effect://external-provider/chat/search".into(),
                    purity: nexus_types::Purity::Idempotent,
                    description: None,
                }],
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap();

        let resource_name =
            ResourceName::new(Path::parse("effect://external-provider/chat/search").unwrap());
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&resource_name)
            .unwrap();
        let resource = boot.kernel.registry.resource(resource_id).unwrap();
        let binding = boot.kernel.registry.binding(resource.binding).unwrap();
        let endpoint_id = binding.endpoint.unwrap();
        let dispatch = RemoteInvokeDispatch {
            endpoint_id,
            resource_id,
            method_id: MethodId::new(0),
            binding_generation: binding.generation,
            acting: IdentityRef::ROOT,
        };
        let endpoint = boot.kernel.registry.remote_endpoint(endpoint_id).unwrap();

        let invoke = Invoke {
            invocation_id: "invoke-remote".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: None,
            output_stream_to: None,
        };
        let pending = tokio::spawn(async move { endpoint.invoke(dispatch, invoke).await.unwrap() });
        let sent = outbound_rx.recv().await.unwrap().unwrap();
        let Some(nexus_proto::nexus::v1::external::external_frame::Frame::Invoke(sent)) =
            sent.frame
        else {
            panic!("expected provider invoke frame");
        };
        let sent = nexus_proto::invoke_from_pb(&sent).unwrap();
        assert_eq!(sent.invocation_id, "invoke-remote");
        assert_eq!(
            sent.effect_path,
            Path::parse("effect://external-provider/chat/search").unwrap()
        );

        let expected = InvokeResult {
            invocation_id: "invoke-remote".into(),
            outcome: Ok(Value::Str("result".into())),
        };
        nexus_gateway_grpc::ExternalSessionHandler::on_invoke_result(
            &handler,
            expected.clone(),
            &session,
            context.clone(),
        )
        .await
        .unwrap();
        assert_eq!(pending.await.unwrap(), expected);

        let endpoint = boot.kernel.registry.remote_endpoint(endpoint_id).unwrap();
        let err = endpoint
            .invoke(
                dispatch,
                Invoke {
                    invocation_id: "invoke-unready-effect".into(),
                    effect_path: Path::parse("effect://external-provider/chat/summarize").unwrap(),
                    method_id: MethodId::new(0),
                    input: Value::Str("query".into()),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            DriverError::Transport("provider invoke effect rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());

        let endpoint = boot.kernel.registry.remote_endpoint(endpoint_id).unwrap();
        let wrong_method_dispatch = RemoteInvokeDispatch {
            method_id: MethodId::new(99),
            ..dispatch
        };
        let err = endpoint
            .invoke(
                wrong_method_dispatch,
                Invoke {
                    invocation_id: "invoke-wrong-method".into(),
                    effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
                    method_id: MethodId::new(99),
                    input: Value::Str("query".into()),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            DriverError::Transport("provider invoke method rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());

        let endpoint = boot.kernel.registry.remote_endpoint(endpoint_id).unwrap();
        let stale_generation_dispatch = RemoteInvokeDispatch {
            binding_generation: binding.generation + 1,
            ..dispatch
        };
        let err = endpoint
            .invoke(
                stale_generation_dispatch,
                Invoke {
                    invocation_id: "invoke-stale-generation".into(),
                    effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
                    method_id: MethodId::new(0),
                    input: Value::Str("query".into()),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            DriverError::Transport("provider invoke effect rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());

        let endpoint = boot.kernel.registry.remote_endpoint(endpoint_id).unwrap();
        let err = endpoint
            .invoke(
                dispatch,
                Invoke {
                    invocation_id: "invoke-bad-input".into(),
                    effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
                    method_id: MethodId::new(0),
                    input: Value::Int(7),
                    deadline_ms: Some(now_millis() + 200),
                    output_stream_to: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            DriverError::Transport("provider invoke input rejected".into())
        );
        assert!(outbound_rx.try_recv().is_err());
        assert!(handler.provider_invocations.lock().unwrap().is_empty());
        assert!(handler.provider_waiters.lock().unwrap().is_empty());

        nexus_gateway_grpc::ExternalSessionHandler::on_closed(&handler, &session, context)
            .await
            .unwrap();
        assert!(boot.kernel.registry.remote_endpoint(endpoint_id).is_none());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn daemon_provider_endpoint_times_out_pending_invocation() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel
            .state
            .write_set(
                &Path::parse("state://kernel/external-installations/chat").unwrap(),
                provider_external_installation_value(),
            )
            .await
            .unwrap();
        write_external_session(&boot.kernel.state, "chat", "provider", 9).await;
        let handler = DaemonExternalSessionHandler::new(
            boot.kernel.state.clone(),
            boot.kernel.registry.clone(),
            60_000,
        );
        let hello = hello_from_context(
            &handler
                .load_authority("chat", "provider", Role::Provider)
                .await
                .unwrap()
                .context,
        );
        let context =
            nexus_gateway_grpc::ExternalSessionHandler::adjudicate_session(&handler, &hello)
                .await
                .unwrap();
        let mut session = EndpointSession::new();
        session.on_hello(&hello, |_| context.clone()).unwrap();
        session
            .on_ready(&nexus_types::external::RoleReady {
                accepted_context: context.clone(),
            })
            .unwrap();
        let (outbound, mut outbound_rx) = external_outbound_channel();
        nexus_gateway_grpc::ExternalSessionHandler::on_ready(
            &handler,
            &session,
            context.clone(),
            outbound,
        )
        .await
        .unwrap();
        nexus_gateway_grpc::ExternalSessionHandler::on_provider_ready(
            &handler,
            ProviderReady {
                provides: vec![nexus_types::external::EffectHandlerSpec {
                    path: "effect://external-provider/chat/search".into(),
                    purity: nexus_types::Purity::Idempotent,
                    description: None,
                }],
            },
            &session,
            context.clone(),
        )
        .await
        .unwrap();

        let resource_name =
            ResourceName::new(Path::parse("effect://external-provider/chat/search").unwrap());
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&resource_name)
            .unwrap();
        let resource = boot.kernel.registry.resource(resource_id).unwrap();
        let binding = boot.kernel.registry.binding(resource.binding).unwrap();
        let endpoint_id = binding.endpoint.unwrap();
        let dispatch = RemoteInvokeDispatch {
            endpoint_id,
            resource_id,
            method_id: MethodId::new(0),
            binding_generation: binding.generation,
            acting: IdentityRef::ROOT,
        };
        let endpoint = boot.kernel.registry.remote_endpoint(endpoint_id).unwrap();

        let deadline_ms = now_millis() + 200;
        let invoke = Invoke {
            invocation_id: "invoke-timeout".into(),
            effect_path: Path::parse("effect://external-provider/chat/search").unwrap(),
            method_id: MethodId::new(0),
            input: Value::Str("query".into()),
            deadline_ms: Some(deadline_ms),
            output_stream_to: None,
        };
        let pending = tokio::spawn(async move { endpoint.invoke(dispatch, invoke).await });
        let sent = outbound_rx.recv().await.unwrap().unwrap();
        let Some(nexus_proto::nexus::v1::external::external_frame::Frame::Invoke(sent)) =
            sent.frame
        else {
            panic!("expected provider invoke frame");
        };
        let sent = nexus_proto::invoke_from_pb(&sent).unwrap();
        assert_eq!(sent.invocation_id, "invoke-timeout");
        assert_eq!(sent.deadline_ms, Some(deadline_ms));

        let error = pending.await.unwrap().unwrap_err();
        assert_eq!(
            error,
            DriverError::Transport("provider invocation deadline exceeded".into())
        );
        let sent = outbound_rx.recv().await.unwrap().unwrap();
        let Some(nexus_proto::nexus::v1::external::external_frame::Frame::Control(control)) =
            sent.frame
        else {
            panic!("expected provider cancel control frame");
        };
        let control = nexus_proto::control_frame_from_pb(&control).unwrap();
        assert_eq!(
            control,
            ControlFrame::ProviderCancel {
                invocation_id: "invoke-timeout".into(),
                reason: "deadline_exceeded".into(),
            }
        );
        assert!(handler.provider_invocations.lock().unwrap().is_empty());
        assert!(handler.provider_waiters.lock().unwrap().is_empty());
    }

    #[cfg(feature = "external-grpc")]
    #[tokio::test]
    async fn provider_waiter_drop_reports_provider_unavailable() {
        let (tx, rx) = oneshot::channel();
        drop(tx);

        let error = await_provider_result(rx, None).await.unwrap_err();

        assert_eq!(
            error.into_driver_error(),
            DriverError::Transport("provider unavailable".into())
        );
    }
}
