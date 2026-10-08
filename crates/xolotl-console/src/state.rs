//! Transport-independent Console authentication, admission and execution state.
//!
//! The Console Protocol host maps authenticated console users to management
//! identities and then dispatches descriptor-named actions through authorization,
//! state, and audited visibility gates. Actions that invoke runtime effects use
//! capability-scoped Operations. This state object owns shared execution state.

use std::sync::Arc;
use xolotl_kernel::{Bootstrap, RequestProcess};
use xolotl_state::Backend;

use crate::auth::{AuthError, ConsoleAuth, ConsoleAuthConfig};
use xolotl_kernel::host::BlockingSpawner;

/// Host-provided sink for one-time pairing display secrets.
pub trait PairingSecretDisplay: Send + Sync + 'static {
    /// Consume and remove the display secret for `pairing_id`.
    fn take_display_secret(&self, pairing_id: &str) -> Option<String>;
}

/// Empty display sink for hosts without pairing support.
#[derive(Default)]
pub struct NoPairingSecretDisplay;

impl PairingSecretDisplay for NoPairingSecretDisplay {
    fn take_display_secret(&self, _pairing_id: &str) -> Option<String> {
        None
    }
}

/// Default maximum entries returned by state list actions.
pub const DEFAULT_QUERY_MAX_STATE_LIST_LIMIT: usize = 512;
/// Default maximum facts returned by fact list actions.
pub const DEFAULT_QUERY_MAX_FACT_LIMIT: usize = 256;
/// Default maximum trace entries returned by trace actions.
pub const DEFAULT_QUERY_MAX_TRACE_LIMIT: usize = 512;
/// Minimum accepted state-list limit.
pub const MIN_QUERY_MAX_STATE_LIST_LIMIT: usize = 1;
/// Hard upper bound for state-list limit.
pub const HARD_MAX_QUERY_STATE_LIST_LIMIT: usize = 16_384;
/// Minimum accepted fact-list limit.
pub const MIN_QUERY_MAX_FACT_LIMIT: usize = 1;
/// Hard upper bound for fact-list limit.
pub const HARD_MAX_QUERY_FACT_LIMIT: usize = 4_096;
/// Minimum accepted trace-list limit.
pub const MIN_QUERY_MAX_TRACE_LIMIT: usize = 1;
/// Hard upper bound for trace-list limit.
pub const HARD_MAX_QUERY_TRACE_LIMIT: usize = 8_192;

/// Shared console backend state.
pub struct ConsoleState {
    /// Shared kernel bootstrap handle.
    pub(crate) boot: Arc<Bootstrap>,
    /// Host-owned parent scope for runtime requests, when narrower than root.
    /// Retaining the scope keeps its lifecycle ownership until Console stops.
    pub(crate) request_anchor: Option<Arc<RequestProcess<'static>>>,
    /// State-backed management configuration. The external installation
    /// catalog is owned by its dedicated storage port instead.
    pub(crate) state: Backend,
    /// Authentication service.
    pub(crate) auth: ConsoleAuth,
    /// Host-selected scheduler and shared admission for synchronous service work.
    pub(crate) blocking_spawner: Arc<dyn BlockingSpawner>,
    /// One-time pairing display edge.
    pub(crate) pairing_display: Arc<dyn PairingSecretDisplay>,
    /// Limits for bounded observations, shared by every transport.
    pub(crate) queries: ConsoleQueryConfig,
    /// Shared active action execution capacity.
    pub(crate) calls: Arc<tokio::sync::Semaphore>,
    /// Shared admission for credential checks and authentication flows.
    pub(crate) authentications: Arc<tokio::sync::Semaphore>,
    /// Subscription capacity shared by every adapter.
    pub(crate) streams: Arc<crate::streams::StreamAdmission>,
    /// Action/stream descriptor registry with a real, deterministic revision.
    pub(crate) registry: crate::registry::DescriptorRegistry,
    /// Host exposure and resource bounds for portable execution.
    pub(crate) runtime: crate::runtime::RuntimeAdmission,
    /// Service-owned jobs and bounded volatile results, shared by all adapters.
    pub(crate) executions: Arc<crate::runtime::executions::ExecutionRegistry>,
    /// Trusted, manifest-bounded portable program loaders.
    pub(crate) modules: crate::runtime::ConsoleModules,
    /// One storage owner's narrow Source management facets, without event
    /// commit or maintenance authority.
    pub(crate) source_management: Option<Arc<dyn xolotl_source::SourceManagement>>,
    /// Optional local federation catalog authority; remote peers cannot invoke it.
    pub(crate) federation_management: Option<Arc<dyn xolotl_federation::FederationManagement>>,
    /// Immutable host-owned configuration namespace admission.
    pub(crate) config_admissions: crate::mgmt::ConfigAdmissionRegistry,
}

/// A Console host could not be built from its declared configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleConfigError {
    /// A host must explicitly choose its session storage domain.
    #[error("console session store is required")]
    SessionStoreRequired,
    /// Shared request capacity is outside the supported range.
    #[error("console request capacity: {0} must be between 1 and 4096")]
    InvalidCapacity(&'static str),
    /// The host-owned runtime parent is from another Kernel or is unavailable.
    #[error("console request anchor: {0}")]
    RequestAnchor(&'static str),
    /// Authentication or credential provider configuration is invalid.
    #[error("console authentication configuration: {0}")]
    Authentication(#[from] AuthError),
    /// Runtime exposure or execution budgets are invalid.
    #[error("console runtime configuration: {0}")]
    Runtime(#[from] crate::runtime::RuntimeConfigError),
    /// Module manifests or their dependency graph are invalid.
    #[error("console module configuration: {0}")]
    Modules(#[from] crate::runtime::ModuleConfigError),
    /// Host configuration namespaces are invalid or overlap.
    #[error("console config admission: {0}")]
    ConfigAdmission(#[from] crate::mgmt::ConfigAdmissionConfigError),
}

/// Host configuration; query budgets are independent of transport framing.
#[derive(Clone)]
pub struct ConsoleConfig {
    /// Explicit shared session storage domain. None is rejected; no fallback.
    pub session_store: Option<Arc<dyn crate::session_store::ConsoleSessionStore>>,
    /// Authentication and credential policy.
    pub auth: ConsoleAuthConfig,
    /// Override the Kernel host's blocking-work scheduler for Console service
    /// work. `None` shares the Kernel's admission domain; an explicit scheduler
    /// must enforce its own queue and worker bounds.
    pub blocking_spawner: Option<Arc<dyn BlockingSpawner>>,
    /// Optional live, host-created parent scope for runtime calls. Console
    /// retains one owner. It must come from the same Kernel and remain available
    /// while Console accepts calls.
    pub request_anchor: Option<Arc<RequestProcess<'static>>>,
    /// Bounds applied to every management query.
    pub queries: ConsoleQueryConfig,
    /// Maximum active management calls across every adapter; excess calls fail promptly.
    pub max_concurrent_calls: usize,
    /// Maximum concurrent authentication requests across Rust, HTTP and WebSocket
    /// adapters, including bearer checks and host-installed verifiers.
    /// Admitted transport bodies retain the same slot through service dispatch;
    /// continuations release it between client requests.
    pub max_concurrent_authentications: usize,
    /// Subscription admission shared by every transport and embedded caller.
    pub streams: crate::ConsoleStreamConfig,
    /// Exposure and execution budgets for general kernel resource calls.
    pub runtime: crate::runtime::ConsoleRuntimeConfig,
    /// Host-assembled portable loaders, independent of transport configuration.
    pub modules: crate::runtime::ConsoleModules,
    /// Storage-owned Source management capability, installed from the same
    /// owner as ingress. It combines declaration admission, the typed
    /// installation catalog, and audited claim inspection without granting
    /// Console event commit or maintenance authority.
    pub source_management: Option<Arc<dyn xolotl_source::SourceManagement>>,
    /// Host-owned federation catalog management. It shares the authoritative
    /// store with the federation Session but is never exposed to that Session.
    pub federation_management: Option<Arc<dyn xolotl_federation::FederationManagement>>,
    /// Trusted verifier and binding resolver for external primary assertions.
    /// The service never accepts preconstructed verified identity facts.
    pub external_authentication: Option<Arc<dyn crate::ExternalPrimaryAuthentication>>,
    /// The single account authority for externally authenticated accounts.
    /// Its stable source ID must be restored unchanged after a restart.
    pub account_authority: Option<Arc<dyn crate::AccountAuthority>>,
    /// Host validators for versioned `state://kernel` configuration namespaces.
    /// Unknown paths remain unwritable through Console configuration actions.
    pub config_admissions: Vec<crate::ConfigNamespaceAdmission>,
}

impl std::fmt::Debug for ConsoleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ConsoleConfig");
        debug.field("auth", &self.auth).field(
            "request_anchor",
            &self.request_anchor.as_ref().map(|anchor| anchor.id()),
        );
        debug
            .field("queries", &self.queries)
            .field("max_concurrent_calls", &self.max_concurrent_calls)
            .field(
                "max_concurrent_authentications",
                &self.max_concurrent_authentications,
            )
            .field("streams", &self.streams)
            .field("runtime", &self.runtime)
            .field("modules", &self.modules)
            .field(
                "source_management_installed",
                &self.source_management.is_some(),
            )
            .field(
                "federation_management_installed",
                &self.federation_management.is_some(),
            )
            .field(
                "external_authentication_installed",
                &self.external_authentication.is_some(),
            )
            .field(
                "account_authority_installed",
                &self.account_authority.is_some(),
            )
            .field("config_admissions", &self.config_admissions)
            .finish()
    }
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            session_store: None,
            auth: ConsoleAuthConfig::default(),
            blocking_spawner: None,
            request_anchor: None,
            queries: ConsoleQueryConfig::default(),
            max_concurrent_calls: 64,
            max_concurrent_authentications: 64,
            streams: crate::ConsoleStreamConfig::default(),
            runtime: crate::runtime::ConsoleRuntimeConfig::default(),
            modules: crate::runtime::ConsoleModules::default(),
            source_management: None,
            federation_management: None,
            external_authentication: None,
            account_authority: None,
            config_admissions: Vec::new(),
        }
    }
}

impl ConsoleState {
    pub(crate) fn runtime_anchor(&self) -> xolotl_types::ProcessId {
        self.request_anchor
            .as_ref()
            .map(|anchor| anchor.id())
            .unwrap_or_else(|| self.boot.root())
    }

    /// Borrow the host-selected blocking-work scheduler shared by this Console.
    pub fn blocking_spawner(&self) -> &dyn BlockingSpawner {
        self.blocking_spawner.as_ref()
    }

    /// Build a shared host with default authentication and service budgets,
    /// inheriting the Kernel host's blocking-work port.
    pub fn shared(
        boot: Arc<Bootstrap>,
        session_store: Arc<dyn crate::session_store::ConsoleSessionStore>,
    ) -> Result<Arc<Self>, ConsoleConfigError> {
        Self::with_config(
            boot,
            ConsoleConfig {
                session_store: Some(session_store),
                ..ConsoleConfig::default()
            },
        )
    }

    /// Build a shared host without a pairing display edge.
    pub fn with_config(
        boot: Arc<Bootstrap>,
        config: ConsoleConfig,
    ) -> Result<Arc<Self>, ConsoleConfigError> {
        Self::shared_with_pairing_display_and_config(boot, Arc::new(NoPairingSecretDisplay), config)
    }

    /// Share one host across adapters, including a custom pairing display edge.
    pub fn shared_with_pairing_display_and_config(
        boot: Arc<Bootstrap>,
        pairing_display: Arc<dyn PairingSecretDisplay>,
        config: ConsoleConfig,
    ) -> Result<Arc<Self>, ConsoleConfigError> {
        if !(1..=4096).contains(&config.max_concurrent_calls) {
            return Err(ConsoleConfigError::InvalidCapacity("max_concurrent_calls"));
        }
        if !(1..=4096).contains(&config.max_concurrent_authentications) {
            return Err(ConsoleConfigError::InvalidCapacity(
                "max_concurrent_authentications",
            ));
        }
        let state = boot.kernel().state().clone();
        let config_admissions =
            crate::mgmt::ConfigAdmissionRegistry::new(config.config_admissions)?;
        let runtime = crate::runtime::RuntimeAdmission::new(config.runtime)?;
        if let Some(anchor) = config.request_anchor.as_ref() {
            if !anchor.belongs_to(&boot) {
                return Err(ConsoleConfigError::RequestAnchor(
                    "parent belongs to another Kernel",
                ));
            }
            if !boot
                .kernel()
                .processes()
                .status(anchor.id())
                .is_some_and(|status| {
                    !status.is_terminal() && status != xolotl_types::ProcessStatus::Finalizing
                })
            {
                return Err(ConsoleConfigError::RequestAnchor(
                    "parent process is unavailable",
                ));
            }
        }
        let host_runtime = boot.kernel().host_runtime().clone();
        let blocking_spawner = config
            .blocking_spawner
            .unwrap_or_else(|| host_runtime.blocking_spawner());
        if i64::try_from(runtime.config.max_duration_ms)
            .ok()
            .and_then(|duration| host_runtime.now_millis().checked_add(duration))
            .is_none()
            || host_runtime
                .deadline_after(std::time::Duration::from_millis(
                    runtime.config.max_duration_ms,
                ))
                .is_none()
        {
            return Err(crate::runtime::RuntimeConfigError::Limit("max_duration_ms").into());
        }
        let executions = crate::runtime::executions::ExecutionRegistry::new_with_host_runtime(
            runtime.config.executions.clone(),
            host_runtime.clone(),
        )?;
        config.modules.link()?;
        let streams = crate::streams::StreamAdmission::new(config.streams);
        let registry = crate::registry::DescriptorRegistry::with_config(
            &runtime.config,
            streams.config(),
            &config.modules,
            config.account_authority.is_none(),
            &config_admissions,
            config.federation_management.is_some(),
            boot.kernel().facts().is_enabled(),
        );
        Ok(Arc::new(Self {
            boot,
            request_anchor: config.request_anchor,
            state,
            pairing_display,
            auth: ConsoleAuth::with_external(
                config.auth,
                config
                    .session_store
                    .ok_or(ConsoleConfigError::SessionStoreRequired)?,
                config.external_authentication,
                config.account_authority,
                Arc::clone(&blocking_spawner),
                host_runtime,
            )?,
            blocking_spawner,
            queries: config.queries.bounded(),
            calls: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_calls)),
            authentications: Arc::new(tokio::sync::Semaphore::new(
                config.max_concurrent_authentications,
            )),
            streams,
            registry,
            runtime,
            executions,
            modules: config.modules,
            source_management: config.source_management,
            federation_management: config.federation_management,
            config_admissions,
        }))
    }
}

/// Resource budgets for live observations through any Console adapter.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleQueryConfig {
    /// Maximum state or session entries in one page.
    pub max_state_list_limit: usize,
    /// Maximum facts in a recent page.
    pub max_fact_limit: usize,
    /// Maximum facts in a trace page.
    pub max_trace_limit: usize,
    /// Maximum processes in a metadata page.
    pub max_process_limit: usize,
    /// Maximum backend encoded bytes in one page, before response projection.
    pub max_page_bytes: usize,
}

impl Default for ConsoleQueryConfig {
    fn default() -> Self {
        Self {
            max_state_list_limit: DEFAULT_QUERY_MAX_STATE_LIST_LIMIT,
            max_fact_limit: DEFAULT_QUERY_MAX_FACT_LIMIT,
            max_trace_limit: DEFAULT_QUERY_MAX_TRACE_LIMIT,
            max_process_limit: 256,
            max_page_bytes: 128 * 1024,
        }
    }
}

impl ConsoleQueryConfig {
    /// Enforce server work and allocation bounds independent of client inputs.
    pub fn bounded(self) -> Self {
        Self {
            max_state_list_limit: self.max_state_list_limit.clamp(
                MIN_QUERY_MAX_STATE_LIST_LIMIT,
                HARD_MAX_QUERY_STATE_LIST_LIMIT,
            ),
            max_fact_limit: self
                .max_fact_limit
                .clamp(MIN_QUERY_MAX_FACT_LIMIT, HARD_MAX_QUERY_FACT_LIMIT),
            max_trace_limit: self
                .max_trace_limit
                .clamp(MIN_QUERY_MAX_TRACE_LIMIT, HARD_MAX_QUERY_TRACE_LIMIT),
            max_process_limit: self.max_process_limit.clamp(1, 4096),
            max_page_bytes: self.max_page_bytes.clamp(1024, 256 * 1024),
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn default_blocking_spawner_is_kernel_host_port() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let blocking_spawner = boot.kernel().host_runtime().blocking_spawner();
        let state = ConsoleState::with_config(
            boot,
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                ..Default::default()
            },
        )?;
        ensure!(Arc::ptr_eq(&state.blocking_spawner, &blocking_spawner));
        Ok(())
    }

    #[test]
    fn shared_request_capacity_requires_an_explicit_valid_range() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        for value in [0, 4097, usize::MAX] {
            for field in ["max_concurrent_calls", "max_concurrent_authentications"] {
                let mut config = ConsoleConfig {
                    session_store: Some(std::sync::Arc::new(
                        crate::session_store::MemoryConsoleSessionStore::new(
                            crate::session_store::ConsoleSessionPolicy::default(),
                        ),
                    )),
                    ..Default::default()
                };
                match field {
                    "max_concurrent_calls" => config.max_concurrent_calls = value,
                    _ => config.max_concurrent_authentications = value,
                }
                let Err(ConsoleConfigError::InvalidCapacity(rejected)) =
                    ConsoleState::with_config(boot.clone(), config)
                else {
                    anyhow::bail!("invalid {field}={value} was accepted");
                };
                ensure!(rejected == field);
            }
        }
        Ok(())
    }

    #[test]
    fn configured_blocking_spawner_is_shared_with_console_state() -> anyhow::Result<()> {
        let blocking_spawner: Arc<dyn BlockingSpawner> =
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
        let state = ConsoleState::with_config(
            Arc::new(Bootstrap::in_memory()),
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                blocking_spawner: Some(Arc::clone(&blocking_spawner)),
                ..ConsoleConfig::default()
            },
        )?;
        ensure!(Arc::ptr_eq(&state.blocking_spawner, &blocking_spawner));
        Ok(())
    }
}
