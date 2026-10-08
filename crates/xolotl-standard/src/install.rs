//! Install standard in-process implementations into a [`Bootstrap`].
//!
//! Every provider is registered with [`Bootstrap::register_effect`].
//! Standard callable effects are registered one Resource per public effect
//! path, each exposing a single `invoke` method, so `perform://effect/foo/bar`
//! grants exactly that effect path.

use crate::{
    approval::{APPROVAL_METHODS, ApprovalDriver},
    blob::{BLOB_METHODS, BlobDriver},
    deliberation::{DELIBERATION_METHODS, DeliberationDriver},
    events::{EVENTS_METHODS, EventBusDriver},
    fact::{FACT_METHODS, FactDriver},
    index::{INDEX_METHODS, IndexDriver},
    inference::{INFERENCE_METHODS, InferenceBackend, InferenceDriver},
    inspect::{INSPECT_METHODS, KernelInspectDriver},
    lock::{LOCK_METHODS, LockDriver},
    memory::{MEMORY_METHODS, MemoryDriver},
    pairing::{PAIRING_METHODS, PairingDisplayEdge, PairingDriver},
    rank::{RANK_METHODS, RankerDriver},
    time::{TIME_METHODS, TimeDriver},
};
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;
#[cfg(test)]
use xolotl_kernel::RequestGrantTemplate;
use xolotl_kernel::{
    Bootstrap, BootstrapError, Driver, DriverContext, DriverError, DriverOutput, MethodSpec,
};
use xolotl_source::ExternalInstallationAuthority;
use xolotl_types::in_process_projection::{
    IN_PROCESS_PROJECTION_CONFIG_PREFIX, in_process_projection_declaration_id,
};
use xolotl_types::{CostModel, InProcessProjectionDef, MethodId, OutputMode, Path, Role, Value};
#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
use xolotl_types::{EffectCapability, Metadata, Purity};
#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
use xolotl_types::{ValueMap, ValueView};

/// Configuration for the standard provider set.
#[derive(Clone, Default)]
pub struct StandardConfig {
    /// Shared host-owned Terminal lifecycle; required for Terminal declarations.
    #[cfg(feature = "terminal")]
    terminal_runtime: Option<crate::TerminalRuntime>,
    /// Standard modules installed by [`install_standard`].
    modules: StandardModules,
    /// Host-provided inference backend.
    inference_backend: Option<Arc<dyn InferenceBackend>>,
    /// Internal effect overrides used by crate tests.
    #[cfg(test)]
    effect_overrides: Vec<TestEffectOverride>,
    /// Host-local edges that cannot be represented as runtime state.
    host_edges: StandardHostEdges,
    /// Optional chunked object storage used by blob, tensor, filesystem, and fetch.
    objects: xolotl_state::host::object::ObjectStore,
    /// Retrieval windows and its separately admitted tensor read capability.
    retrieval: crate::RetrievalConfig,
    /// Per-call admission for memory namespace consolidation.
    memory_consolidation: crate::memory::consolidation::ConsolidationLimits,
}

/// One standard-core module that can be installed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum StandardModule {
    /// Expose `effect://inference/*`.
    Inference,
    /// Expose `effect://memory/*`.
    Memory,
    /// Expose `effect://blob/*`.
    Blob,
    /// Expose `effect://time/*`.
    Time,
    /// Expose `effect://approval/*`.
    Approval,
    /// Expose `effect://events/*`.
    Events,
    /// Expose `effect://lock/*`.
    Lock,
    /// Expose `effect://deliberation/run`.
    Deliberation,
    /// Expose read-only `state://fact/*`.
    Fact,
    /// Expose `effect://kernel/process/inspect`.
    Inspect,
    /// Expose `effect://index/*`.
    Index,
    /// Expose `effect://rank/*`.
    Rank,
    /// Expose `effect://compress/*`.
    Compress,
    /// Expose `effect://tensor/write` without requiring a State catalog.
    Tensor,
    /// Expose `effect://proc/*`.
    Proc,
    /// Expose `effect://external/pairing/*`.
    Pairing,
    /// Expose `effect://context/assemble`.
    Context,
    /// Expose `state://**` through the StateDriver.
    State,
}

const STANDARD_CORE_MODULES: &[StandardModule] = &[
    StandardModule::Inference,
    StandardModule::Memory,
    StandardModule::Blob,
    StandardModule::Time,
    StandardModule::Approval,
    StandardModule::Events,
    StandardModule::Lock,
    StandardModule::Deliberation,
    StandardModule::Fact,
    StandardModule::Inspect,
    StandardModule::Index,
    StandardModule::Rank,
    StandardModule::Compress,
    StandardModule::Tensor,
    StandardModule::Proc,
    StandardModule::Pairing,
    StandardModule::Context,
    StandardModule::State,
];

/// In-process standard modules to install.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardModules {
    selected: BTreeSet<StandardModule>,
}

impl Default for StandardModules {
    fn default() -> Self {
        Self::all()
    }
}

impl StandardModules {
    /// Install every standard-core module.
    pub fn all() -> Self {
        Self {
            selected: STANDARD_CORE_MODULES.iter().copied().collect(),
        }
    }

    /// Install no standard-core modules.
    pub fn none() -> Self {
        Self {
            selected: BTreeSet::new(),
        }
    }

    /// Install only durable state access.
    pub fn state_only() -> Self {
        Self::none().with(StandardModule::State)
    }

    /// Add one module to this selection.
    pub fn with(mut self, module: StandardModule) -> Self {
        self.selected.insert(module);
        self
    }

    /// Remove one module from this selection.
    pub fn without(mut self, module: StandardModule) -> Self {
        self.selected.remove(&module);
        self
    }

    /// Whether this selection contains `module`.
    pub fn contains(&self, module: StandardModule) -> bool {
        self.selected.contains(&module)
    }

    fn needs_model_backend(&self) -> bool {
        self.contains(StandardModule::Inference)
            || self.contains(StandardModule::Memory)
            || self.contains(StandardModule::Deliberation)
            || self.contains(StandardModule::Compress)
    }
}

/// Host-local edges used by standard implementations.
#[derive(Clone, Default)]
struct StandardHostEdges {
    /// One-shot display edge for external pairing secrets. The secret does not
    /// enter Operation input/outcome, state, or Facts.
    pairing_display: PairingDisplayEdge,
    /// Private installation catalog owned by the Source storage domain.
    external_installations: Option<Arc<dyn ExternalInstallationAuthority>>,
}

/// Test-only effect override backed by one driver.
#[cfg(test)]
#[derive(Clone)]
struct TestEffectOverride {
    driver: Arc<dyn Driver>,
    effects: Vec<TestEffectResource>,
}

/// One effect resource exposed by a test override.
#[cfg(test)]
#[derive(Clone)]
struct TestEffectResource {
    path: String,
    methods: Vec<MethodSpec>,
    cost: Option<CostModel>,
    mode: TestEffectOverrideMode,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestEffectOverrideMode {
    InvokeByPathTail,
}

/// Errors returned while installing standard implementations.
#[derive(Debug, Error)]
pub enum InstallError {
    /// State path parsing failed.
    #[error("path {literal:?} is invalid: {source}")]
    Path {
        /// Path literal that failed parsing.
        literal: String,
        #[source]
        /// Parser error.
        source: xolotl_types::PathError,
    },
    /// State backend operation failed.
    #[error("state operation failed: {0}")]
    State(#[source] Box<xolotl_state::StateFailure>),
    /// Declaration value could not be decoded.
    #[error("in-process projection {id:?} is malformed: {source}")]
    Decode {
        /// Projection declaration id.
        id: String,
        #[source]
        /// Decode error.
        source: serde_json::Error,
    },
    /// Declaration failed shared admission.
    #[error("in-process projection {id:?} admission failed: {message}")]
    Declaration {
        /// Projection declaration id.
        id: String,
        /// Admission failure.
        message: String,
    },
    /// The implementation id is not known to this host.
    #[error("in-process projection implementation {implementation:?} is not available")]
    ImplementationUnavailable {
        /// Implementation id.
        implementation: String,
    },
    /// The implementation id is known but was not compiled into this host.
    #[error("in-process projection implementation {implementation:?} requires feature {feature:?}")]
    FeatureNotEnabled {
        /// Implementation id.
        implementation: String,
        /// Required Cargo feature.
        feature: &'static str,
    },
    /// The implementation id does not support the declared projection role.
    #[error("in-process projection {implementation:?} does not support role {role:?}")]
    RoleUnsupported {
        /// Implementation id.
        implementation: String,
        /// Declared projection role.
        role: Role,
    },
    /// Implementation-specific config failed validation.
    #[error("in-process projection {implementation:?} config rejected: {message}")]
    InvalidConfig {
        /// Implementation id.
        implementation: String,
        /// Validation failure.
        message: String,
    },
    /// Implementation-specific capability declaration failed validation.
    #[error("in-process projection {implementation:?} provides rejected: {message}")]
    InvalidProvides {
        /// Implementation id.
        implementation: String,
        /// Validation failure.
        message: String,
    },
    /// Kernel bootstrap registration failed.
    #[error("bootstrap registration failed: {0}")]
    Bootstrap(#[source] Box<BootstrapError>),
    /// Effect path could not be matched to an internal method descriptor.
    #[error("standard effect path {path:?} has no matching method")]
    MethodNotFound {
        /// Effect path being registered.
        path: String,
    },
    /// Standard package assembly failed before registration.
    #[error("standard package assembly failed: {message}")]
    Assembly {
        /// Assembly failure.
        message: String,
    },
}

impl From<BootstrapError> for InstallError {
    fn from(source: BootstrapError) -> Self {
        Self::Bootstrap(Box::new(source))
    }
}

impl From<xolotl_state::StateFailure> for InstallError {
    fn from(source: xolotl_state::StateFailure) -> Self {
        Self::State(Box::new(source))
    }
}

impl StandardConfig {
    /// Share one admission and cleanup domain across all Terminal declarations.
    /// The host must close and shut down this runtime before stopping Tokio.
    #[cfg(feature = "terminal")]
    pub fn with_terminal_runtime(mut self, runtime: crate::TerminalRuntime) -> Self {
        self.terminal_runtime = Some(runtime);
        self
    }

    /// Bound each memory consolidation call before any summary is written.
    /// Defaults are 1024 namespace records, 16 MiB of cumulative lossless
    /// encoded records (including provenance), and 4 MiB of projected UTF-8
    /// text (including separators). All tiers count toward admission; these
    /// are not RSS limits. Exceeding these exact admission limits returns
    /// InvalidInput without summary writes. Retained input and counters are released on return or
    /// cancellation; admitted summary writes remain individually committed.
    /// Consolidation pages use remaining admission. Oversized-row fallback
    /// requires the bounded State read port and caps backend envelope bytes
    /// at the configured encoded-byte maximum before materializing the row;
    /// the exact record encoding is still charged against remaining admission.
    /// Backend envelope-limit or missing-capability failures retain the State
    /// failure semantics and observed sources, also without summary writes.
    pub fn with_memory_consolidation_limits(
        mut self,
        records: std::num::NonZeroUsize,
        encoded_bytes: std::num::NonZeroUsize,
        text_bytes: std::num::NonZeroUsize,
    ) -> Self {
        self.memory_consolidation = crate::memory::consolidation::ConsolidationLimits {
            records,
            encoded_bytes,
            text_bytes,
        };
        self
    }

    /// Configure retrieval's cooperative windows and explicit tensor reader.
    /// Installing general Blob object ports does not silently enable index reads.
    pub fn with_retrieval(mut self, retrieval: crate::RetrievalConfig) -> Self {
        self.retrieval = retrieval;
        self
    }

    /// Install object capabilities independently of the State backend.
    pub fn with_object_store(mut self, objects: xolotl_state::host::object::ObjectStore) -> Self {
        self.objects = objects;
        self
    }

    /// Use a specific set of standard modules.
    pub fn with_modules(mut self, modules: StandardModules) -> Self {
        self.modules = modules;
        self
    }

    /// Standard modules selected for installation.
    pub fn modules(&self) -> &StandardModules {
        &self.modules
    }

    /// Use a host-provided inference backend for standard model-backed effects.
    pub fn with_inference_backend(mut self, backend: Arc<dyn InferenceBackend>) -> Self {
        self.inference_backend = Some(backend);
        self
    }

    /// Use a host-local pairing display edge.
    pub fn with_pairing_display(mut self, pairing_display: PairingDisplayEdge) -> Self {
        self.host_edges.pairing_display = pairing_display;
        self
    }

    /// Bind external pairing and process launch to the Source storage owner's
    /// typed installation catalog. Ordinary State declarations are not trusted.
    pub fn with_external_installations(
        mut self,
        installations: Arc<dyn ExternalInstallationAuthority>,
    ) -> Self {
        self.host_edges.external_installations = Some(installations);
        self
    }

    #[cfg(test)]
    fn with_effect_override(mut self, effect_override: TestEffectOverride) -> Self {
        self.effect_overrides.push(effect_override);
        self
    }
}

#[cfg(test)]
impl TestEffectOverride {
    /// Create an override backed by one driver.
    #[cfg(test)]
    fn new(driver: Arc<dyn Driver>) -> Self {
        Self {
            driver,
            effects: Vec::new(),
        }
    }

    /// Expose one effect resource with a cost model.
    #[cfg(test)]
    fn effect_with_cost(
        mut self,
        path: impl Into<String>,
        methods: &[MethodSpec],
        cost: CostModel,
    ) -> Self {
        self.effects.push(TestEffectResource {
            path: path.into(),
            methods: methods.to_vec(),
            cost: Some(cost),
            mode: TestEffectOverrideMode::InvokeByPathTail,
        });
        self
    }

    /// Effect resources supplied by this override.
    fn effects(&self) -> &[TestEffectResource] {
        &self.effects
    }
}

#[cfg(test)]
impl TestEffectResource {
    /// Effect resource path exposed by this override.
    fn path(&self) -> &str {
        &self.path
    }
}

/// Install the core in-process providers on `boot`, sharing its kernel's
/// state backend.
pub fn install_standard(boot: &Bootstrap, config: &StandardConfig) -> Result<(), InstallError> {
    let state = boot.kernel().state().clone();
    #[cfg(test)]
    let configured_paths = configured_override_paths(&config.effect_overrides);
    #[cfg(not(test))]
    let configured_paths = BTreeSet::new();

    let model_backend = if config.modules.needs_model_backend() {
        Some(Arc::new(build_inference_driver(state.clone(), config)))
    } else {
        None
    };
    if config.modules.contains(StandardModule::Inference)
        && let Some(inference_driver) = model_backend.as_ref()
    {
        // Inference carries a modeled cost so the budget reserve/settle path has a
        // real estimate.
        let inference: Arc<dyn Driver> = inference_driver.clone();
        let methods: Vec<_> = INFERENCE_METHODS
            .iter()
            .map(|method| {
                if inference_driver.requires_unprotected_input() {
                    method.unprotected_input()
                } else {
                    *method
                }
            })
            .collect();
        for path in [
            "effect://inference/infer",
            "effect://inference/embed",
            "effect://inference/rerank",
            "effect://inference/plan",
        ] {
            register_standard_effect_with_cost(
                boot,
                path,
                &methods,
                inference.clone(),
                inference_cost_model(),
                &configured_paths,
            )?;
        }
    }
    install_core_standard(boot, config, state, model_backend, configured_paths)
}

fn build_inference_driver(
    state: xolotl_state::Backend,
    config: &StandardConfig,
) -> InferenceDriver {
    match config.inference_backend.clone() {
        Some(backend) => InferenceDriver::with_backend(backend),
        None => default_inference_driver(state),
    }
}

#[cfg(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
fn default_inference_driver(state: xolotl_state::Backend) -> InferenceDriver {
    InferenceDriver::with_state_config(state)
}

#[cfg(not(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
)))]
fn default_inference_driver(_: xolotl_state::Backend) -> InferenceDriver {
    InferenceDriver::baseline()
}

fn model_backend_for(
    backend: &Option<Arc<InferenceDriver>>,
    module: StandardModule,
) -> Result<Arc<dyn InferenceBackend>, InstallError> {
    match backend {
        Some(backend) => {
            let backend: Arc<dyn InferenceBackend> = backend.clone();
            Ok(backend)
        }
        None => Err(InstallError::Assembly {
            message: format!("{module:?} requires an inference backend"),
        }),
    }
}

fn index_driver_for(
    driver: &Option<Arc<IndexDriver>>,
    module: StandardModule,
) -> Result<Arc<IndexDriver>, InstallError> {
    driver.clone().ok_or_else(|| InstallError::Assembly {
        message: format!("{module:?} requires an index driver"),
    })
}

fn rank_driver_for(
    driver: &Option<Arc<RankerDriver>>,
    module: StandardModule,
) -> Result<Arc<RankerDriver>, InstallError> {
    driver.clone().ok_or_else(|| InstallError::Assembly {
        message: format!("{module:?} requires a rank driver"),
    })
}

/// Install every in-process projection declaration currently stored in kernel
/// state.
pub async fn install_declared_in_process_projections(
    boot: &Bootstrap,
    config: &StandardConfig,
) -> Result<InProcessProjectionInstallReport, InstallError> {
    let prefix = parse_path(IN_PROCESS_PROJECTION_CONFIG_PREFIX)?;
    let mut pages = boot
        .kernel()
        .state()
        .pages(xolotl_state::StateScan::new(prefix));
    let mut entries = Vec::new();
    while let Some(page) = pages.next().await? {
        for (path, value) in page.entries {
            let (id, desired, result) =
                install_in_process_projection_report_entry(boot, &path, value.value, config);
            entries.push(InProcessProjectionInstallEntry {
                id,
                path,
                desired,
                result,
            });
        }
    }
    Ok(InProcessProjectionInstallReport { entries })
}

fn install_in_process_projection_report_entry(
    boot: &Bootstrap,
    path: &Path,
    value: Value,
    config: &StandardConfig,
) -> (
    String,
    Option<InProcessProjectionInstalled>,
    Result<InProcessProjectionInstalled, InstallError>,
) {
    let id = match in_process_projection_path_id(path) {
        Ok(id) => id.to_string(),
        Err(error) => return (path.to_string(), None, Err(error)),
    };
    let def = match decode_in_process_projection_def(&id, value) {
        Ok(def) => def,
        Err(error) => return (id, None, Err(error)),
    };
    let desired = InProcessProjectionInstalled::from_def(&def);
    let result =
        install_decoded_in_process_projection(boot, &def, config).map(|()| desired.clone());
    (id, Some(desired), result)
}

/// Install or relink one in-process projection declaration from a state value.
pub fn install_in_process_projection_value(
    boot: &Bootstrap,
    path: &Path,
    value: Value,
    config: &StandardConfig,
) -> Result<InProcessProjectionInstalled, InstallError> {
    let id = in_process_projection_path_id(path)?.to_string();
    let def = decode_in_process_projection_def(&id, value)?;
    install_decoded_in_process_projection(boot, &def, config)?;
    Ok(InProcessProjectionInstalled::from_def(&def))
}

/// Result of reconciling all stored in-process projection declarations.
pub struct InProcessProjectionInstallReport {
    /// Per-declaration reconcile results.
    pub entries: Vec<InProcessProjectionInstallEntry>,
}

impl InProcessProjectionInstallReport {
    /// Number of declarations installed successfully.
    pub fn installed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.result.is_ok())
            .count()
    }

    /// Number of declarations rejected during reconciliation.
    pub fn rejected_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.result.is_err())
            .count()
    }
}

/// Reconcile result for one in-process projection declaration.
pub struct InProcessProjectionInstallEntry {
    /// Declaration id.
    pub id: String,
    /// Declaration state path.
    pub path: Path,
    /// Desired declaration metadata, when decoding succeeded.
    pub desired: Option<InProcessProjectionInstalled>,
    /// Install result for this declaration.
    pub result: Result<InProcessProjectionInstalled, InstallError>,
}

/// Metadata for an active in-process projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InProcessProjectionInstalled {
    /// Declaration id.
    pub id: String,
    /// Implementation id.
    pub implementation: String,
    /// Projection role.
    pub role: Role,
    /// Declaration version installed into the live registry.
    pub version: u64,
}

impl InProcessProjectionInstalled {
    fn from_def(def: &InProcessProjectionDef) -> Self {
        Self {
            id: def.id.clone(),
            implementation: def.implementation.clone(),
            role: def.role,
            version: def.version,
        }
    }
}

/// Install or relink one in-process projection declaration.
fn install_decoded_in_process_projection(
    _boot: &Bootstrap,
    def: &InProcessProjectionDef,
    _config: &StandardConfig,
) -> Result<(), InstallError> {
    def.validate_admission(&def.id)
        .map_err(|error| InstallError::Declaration {
            id: def.id.clone(),
            message: error.to_string(),
        })?;
    match def.implementation.as_str() {
        "standard.fetch" => {
            require_provider_role(def)?;
            #[cfg(feature = "fetch")]
            {
                install_fetch_driver(_boot, def, _config)
            }
            #[cfg(not(feature = "fetch"))]
            {
                Err(InstallError::FeatureNotEnabled {
                    implementation: def.implementation.clone(),
                    feature: "fetch",
                })
            }
        }
        "standard.fs" => {
            require_provider_role(def)?;
            #[cfg(feature = "fs")]
            {
                install_fs_driver(_boot, def, _config)
            }
            #[cfg(not(feature = "fs"))]
            {
                Err(InstallError::FeatureNotEnabled {
                    implementation: def.implementation.clone(),
                    feature: "fs",
                })
            }
        }
        "standard.terminal" => {
            require_provider_role(def)?;
            #[cfg(feature = "terminal")]
            {
                install_terminal_driver(_boot, def, _config)
            }
            #[cfg(not(feature = "terminal"))]
            {
                Err(InstallError::FeatureNotEnabled {
                    implementation: def.implementation.clone(),
                    feature: "terminal",
                })
            }
        }
        _ => Err(InstallError::ImplementationUnavailable {
            implementation: def.implementation.clone(),
        }),
    }
}

fn install_core_standard(
    boot: &Bootstrap,
    config: &StandardConfig,
    state: xolotl_state::Backend,
    model_backend: Option<Arc<InferenceDriver>>,
    configured_paths: BTreeSet<&str>,
) -> Result<(), InstallError> {
    let index = if config.modules.contains(StandardModule::Memory)
        || config.modules.contains(StandardModule::Index)
    {
        Some(Arc::new(
            IndexDriver::new().with_config(config.retrieval.clone()),
        ))
    } else {
        None
    };
    let rank = if config.modules.contains(StandardModule::Memory)
        || config.modules.contains(StandardModule::Rank)
    {
        Some(Arc::new(RankerDriver::new().with_state(state.clone())))
    } else {
        None
    };
    if config.modules.contains(StandardModule::Memory) {
        let embedder = model_backend_for(&model_backend, StandardModule::Memory)?;
        let methods: Vec<_> = MEMORY_METHODS
            .iter()
            .map(|method| {
                if embedder.requires_unprotected_input() && method.name != "forget" {
                    method.unprotected_input()
                } else {
                    *method
                }
            })
            .collect();
        let index_for_memory = index_driver_for(&index, StandardModule::Memory)?;
        let rank_for_memory = rank_driver_for(&rank, StandardModule::Memory)?;
        let memory: Arc<dyn Driver> = Arc::new(
            MemoryDriver::new(state.clone())
                .with_retrieval_stack(index_for_memory, rank_for_memory)
                .with_embedder(embedder)
                .with_consolidation_limits(config.memory_consolidation)
                .with_repair_attempts(config.retrieval.repair_attempts),
        );
        for path in [
            "effect://memory/store",
            "effect://memory/recall",
            "effect://memory/forget",
            "effect://memory/commit",
            "effect://memory/consolidate",
            "effect://memory/rebuild",
        ] {
            register_standard_effect(boot, path, &methods, memory.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Blob) {
        let blob: Arc<dyn Driver> = Arc::new(BlobDriver::new(config.objects.clone()));
        for path in [
            "effect://blob/write",
            "effect://blob/read",
            "effect://blob/delete",
        ] {
            register_standard_effect(boot, path, BLOB_METHODS, blob.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Time) {
        let time: Arc<dyn Driver> = Arc::new(TimeDriver::new(boot.kernel().host_runtime().clone()));
        for path in [
            "effect://time/now",
            "effect://time/sleep",
            "effect://time/cron",
        ] {
            register_standard_effect(boot, path, TIME_METHODS, time.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Approval) {
        let approval: Arc<dyn Driver> = Arc::new(ApprovalDriver::new(
            state.clone(),
            boot.kernel().host_runtime().clone(),
        ));
        for path in [
            "effect://approval/ask",
            "effect://approval/check",
            "effect://approval/respond",
        ] {
            register_standard_effect(
                boot,
                path,
                APPROVAL_METHODS,
                approval.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Events) {
        let events: Arc<dyn Driver> = Arc::new(EventBusDriver::new(state.clone()));
        for path in ["effect://events/publish", "effect://events/subscribe"] {
            register_standard_effect(
                boot,
                path,
                EVENTS_METHODS,
                events.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Lock) {
        let lock: Arc<dyn Driver> = Arc::new(LockDriver::new(state.clone()));
        for path in ["effect://lock/acquire", "effect://lock/release"] {
            register_standard_effect(boot, path, LOCK_METHODS, lock.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Deliberation) {
        let backend = model_backend_for(&model_backend, StandardModule::Deliberation)?;
        let methods: Vec<_> = DELIBERATION_METHODS
            .iter()
            .map(|method| {
                if backend.requires_unprotected_input() {
                    method.unprotected_input()
                } else {
                    *method
                }
            })
            .collect();
        register_standard_effect(
            boot,
            "effect://deliberation/run",
            &methods,
            Arc::new(DeliberationDriver::new(backend)),
            &configured_paths,
        )?;
    }
    // Fact reads use a capability-gated, read-only state://fact/* projection.
    if config.modules.contains(StandardModule::Fact) {
        boot.register_subtree_resource_at(
            "state://fact",
            "read://state/fact/**",
            xolotl_types::InterfaceFamily::Sequence,
            FACT_METHODS,
            Arc::new(FactDriver::new(boot.kernel().facts().store().clone())),
        )?;
    }
    if config.modules.contains(StandardModule::Inspect) {
        register_standard_effect(
            boot,
            xolotl_types::effect_targets::KERNEL_PROCESS_INSPECT,
            INSPECT_METHODS,
            Arc::new(KernelInspectDriver::new(
                boot.kernel().processes().clone(),
                boot.kernel().facts().store().clone(),
            )),
            &configured_paths,
        )?;
    }
    // Expose the vector index as effect Resources.
    if config.modules.contains(StandardModule::Index) {
        let index_driver: Arc<dyn Driver> = index_driver_for(&index, StandardModule::Index)?;
        for path in [
            "effect://index/upsert",
            "effect://index/search",
            "effect://index/delete",
        ] {
            register_standard_effect(
                boot,
                path,
                INDEX_METHODS,
                index_driver.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Rank) {
        let rank_driver: Arc<dyn Driver> = rank_driver_for(&rank, StandardModule::Rank)?;
        for path in ["effect://rank/score", "effect://rank/fuse"] {
            register_standard_effect(
                boot,
                path,
                RANK_METHODS,
                rank_driver.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Compress) {
        let backend = model_backend_for(&model_backend, StandardModule::Compress)?;
        let methods: Vec<_> = crate::compress::COMPRESS_METHODS
            .iter()
            .map(|method| {
                if backend.requires_unprotected_input() && method.name == "summarize" {
                    method.unprotected_input()
                } else {
                    *method
                }
            })
            .collect();
        let compress: Arc<dyn Driver> = Arc::new(crate::compress::CompressDriver::new(backend));
        for path in ["effect://compress/summarize", "effect://compress/trim-plan"] {
            register_standard_effect(boot, path, &methods, compress.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Tensor) {
        let tensor: Arc<dyn Driver> =
            Arc::new(crate::tensor::TensorDriver::new(config.objects.clone()));
        register_standard_effect(
            boot,
            "effect://tensor/write",
            crate::tensor::TENSOR_METHODS,
            tensor,
            &configured_paths,
        )?;
    }
    if config.modules.contains(StandardModule::Proc) {
        let proc: Arc<dyn Driver> = Arc::new(crate::proc::ProcDriver::with_installations(
            state.clone(),
            config.host_edges.external_installations.clone(),
        ));
        for path in xolotl_types::effect_targets::PROC_TARGETS {
            register_standard_effect(
                boot,
                path,
                crate::proc::PROC_METHODS,
                proc.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Pairing) {
        let pairing: Arc<dyn Driver> = Arc::new(PairingDriver::with_display_edge(
            state.clone(),
            config.host_edges.pairing_display.clone(),
            config.host_edges.external_installations.clone(),
        ));
        for path in xolotl_types::effect_targets::PAIRING_TARGETS {
            register_standard_effect(
                boot,
                path,
                PAIRING_METHODS,
                pairing.clone(),
                &configured_paths,
            )?;
        }
    }
    // Register layered context assembly under a token budget.
    if config.modules.contains(StandardModule::Context) {
        register_standard_effect(
            boot,
            "effect://context/assemble",
            crate::context::CONTEXT_METHODS,
            Arc::new(crate::context::ContextDriver::new()),
            &configured_paths,
        )?;
    }

    // Install one Prefix Resource at `state://` so a Process reads and writes
    // durable state through Value/Sequence Operations, with taint persisted
    // and capability checks applied to each requested path.
    if config.modules.contains(StandardModule::State) {
        boot.register_subtree_resource(
            "state",
            xolotl_types::InterfaceFamily::Value,
            crate::state::STATE_METHODS,
            Arc::new(crate::state::StateDriver::new(state)),
        )?;
    }

    #[cfg(test)]
    for effect_override in &config.effect_overrides {
        for effect in effect_override.effects() {
            match (effect.mode, effect.cost) {
                (TestEffectOverrideMode::InvokeByPathTail, Some(cost)) => {
                    register_single_effect_with_cost(
                        boot,
                        effect.path(),
                        &effect.methods,
                        effect_override.driver.clone(),
                        cost,
                    )?
                }
                (TestEffectOverrideMode::InvokeByPathTail, None) => register_single_effect(
                    boot,
                    effect.path(),
                    &effect.methods,
                    effect_override.driver.clone(),
                )?,
            };
        }
    }
    Ok(())
}

#[cfg(feature = "fetch")]
fn install_fetch_driver(
    boot: &Bootstrap,
    def: &InProcessProjectionDef,
    host: &StandardConfig,
) -> Result<(), InstallError> {
    require_expected_provides(def, &[("effect://fetch/get", Purity::Effectful)])?;
    let config = optional_config_map(def)?;
    reject_unknown_config_fields(def, config, &[])?;
    let driver: Arc<dyn Driver> = Arc::new(
        crate::fetch::FetchDriver::new(host.objects.clone()).map_err(|error| {
            InstallError::InvalidConfig {
                implementation: def.implementation.clone(),
                message: error.to_string(),
            }
        })?,
    );
    for capability in &def.provides {
        register_declared_effect(
            boot,
            def,
            capability,
            crate::fetch::FETCH_METHODS,
            driver.clone(),
            CostModel::default(),
        )?;
    }
    Ok(())
}

#[cfg(feature = "fs")]
fn install_fs_driver(
    boot: &Bootstrap,
    def: &InProcessProjectionDef,
    host: &StandardConfig,
) -> Result<(), InstallError> {
    require_expected_provides(
        def,
        &[
            ("effect://fs/read", Purity::Pure),
            ("effect://fs/write", Purity::Effectful),
            ("effect://fs/list", Purity::Pure),
            ("effect://fs/delete", Purity::Effectful),
            ("effect://fs/glob", Purity::Pure),
        ],
    )?;
    let config = required_config_map(def)?;
    reject_unknown_config_fields(def, config, &["root"])?;
    let root = required_string(def, config, "root")?;
    let driver: Arc<dyn Driver> = Arc::new(
        crate::fs::FsDriver::new(root, host.objects.clone()).map_err(|error| {
            InstallError::InvalidConfig {
                implementation: def.implementation.clone(),
                message: error.to_string(),
            }
        })?,
    );
    for capability in &def.provides {
        register_declared_effect(
            boot,
            def,
            capability,
            crate::fs::FS_METHODS,
            driver.clone(),
            CostModel::default(),
        )?;
    }
    Ok(())
}

#[cfg(feature = "terminal")]
fn install_terminal_driver(
    boot: &Bootstrap,
    def: &InProcessProjectionDef,
    standard: &StandardConfig,
) -> Result<(), InstallError> {
    require_expected_provides(def, &[("effect://terminal/run", Purity::Effectful)])?;
    let config = required_config_map(def)?;
    reject_unknown_config_fields(def, config, &["allowlist", "denylist"])?;
    let allowlist = required_string_list(def, config, "allowlist")?;
    if allowlist.is_empty() {
        return Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: "allowlist must not be empty".into(),
        });
    }
    let runtime = standard
        .terminal_runtime
        .clone()
        .ok_or_else(|| InstallError::Assembly {
            message: "Terminal requires a host-owned TerminalRuntime".into(),
        })?;
    let mut terminal = crate::terminal::TerminalDriver::new(allowlist, runtime);
    if let Some(denylist) = optional_string_list(def, config, "denylist")? {
        terminal = terminal.with_denylist(denylist);
    }
    let driver: Arc<dyn Driver> = Arc::new(terminal);
    for capability in &def.provides {
        register_declared_effect(
            boot,
            def,
            capability,
            crate::terminal::TERMINAL_METHODS,
            driver.clone(),
            CostModel::default(),
        )?;
    }
    Ok(())
}

fn parse_path(literal: &str) -> Result<Path, InstallError> {
    Path::parse(literal).map_err(|source| InstallError::Path {
        literal: literal.to_string(),
        source,
    })
}

fn in_process_projection_path_id(path: &Path) -> Result<&str, InstallError> {
    in_process_projection_declaration_id(path).ok_or_else(|| InstallError::Declaration {
        id: path.to_string(),
        message: "path must be state://kernel/projections/in-process/<id>".into(),
    })
}

fn decode_in_process_projection_def(
    id: &str,
    value: Value,
) -> Result<InProcessProjectionDef, InstallError> {
    let json = serde_json::to_value(value).map_err(|source| InstallError::Decode {
        id: id.to_string(),
        source,
    })?;
    let def: InProcessProjectionDef =
        serde_json::from_value(json).map_err(|source| InstallError::Decode {
            id: id.to_string(),
            source,
        })?;
    def.validate_admission(id)
        .map_err(|error| InstallError::Declaration {
            id: id.to_string(),
            message: error.to_string(),
        })?;
    Ok(def)
}

#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
fn require_expected_provides(
    def: &InProcessProjectionDef,
    expected: &[(&str, Purity)],
) -> Result<(), InstallError> {
    require_provider_role(def)?;
    if def.provides.len() != expected.len() {
        return Err(InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!(
                "expected {} effect declarations, got {}",
                expected.len(),
                def.provides.len()
            ),
        });
    }
    for (path, purity) in expected {
        let Some(capability) = def
            .provides
            .iter()
            .find(|capability| capability.effect_path == *path)
        else {
            return Err(InstallError::InvalidProvides {
                implementation: def.implementation.clone(),
                message: format!("missing effect declaration {path:?}"),
            });
        };
        if capability.purity != *purity {
            return Err(InstallError::InvalidProvides {
                implementation: def.implementation.clone(),
                message: format!(
                    "effect {path:?} must declare purity {:?}, got {:?}",
                    purity, capability.purity
                ),
            });
        }
    }
    Ok(())
}

fn require_provider_role(def: &InProcessProjectionDef) -> Result<(), InstallError> {
    if def.role == Role::Provider {
        Ok(())
    } else {
        Err(InstallError::RoleUnsupported {
            implementation: def.implementation.clone(),
            role: def.role,
        })
    }
}

#[cfg(feature = "fetch")]
fn optional_config_map(def: &InProcessProjectionDef) -> Result<&ValueMap, InstallError> {
    match def.config.view() {
        ValueView::Map(map) => Ok(map),
        ValueView::Null => Ok(empty_config_map()),
        _ => Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: "config must be an object".into(),
        }),
    }
}

#[cfg(any(feature = "fs", feature = "terminal"))]
fn required_config_map(def: &InProcessProjectionDef) -> Result<&ValueMap, InstallError> {
    match def.config.view() {
        ValueView::Map(map) => Ok(map),
        _ => Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: "config must be an object".into(),
        }),
    }
}

#[cfg(feature = "fetch")]
fn empty_config_map() -> &'static ValueMap {
    static EMPTY: std::sync::OnceLock<ValueMap> = std::sync::OnceLock::new();
    EMPTY.get_or_init(ValueMap::new)
}

#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
fn reject_unknown_config_fields(
    def: &InProcessProjectionDef,
    config: &ValueMap,
    allowed: &[&str],
) -> Result<(), InstallError> {
    for key in config.keys() {
        if !allowed.contains(&key) {
            return Err(InstallError::InvalidConfig {
                implementation: def.implementation.clone(),
                message: format!("unknown config field {key:?}"),
            });
        }
    }
    Ok(())
}

#[cfg(feature = "fs")]
fn required_string<'a>(
    def: &InProcessProjectionDef,
    config: &'a ValueMap,
    field: &'static str,
) -> Result<&'a str, InstallError> {
    let value = config
        .get(field)
        .ok_or_else(|| InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: format!("{field} is required"),
        })?;
    let value = value.as_str().ok_or_else(|| InstallError::InvalidConfig {
        implementation: def.implementation.clone(),
        message: format!("{field} must be a string"),
    })?;
    if value.trim().is_empty() {
        return Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: format!("{field} must not be empty"),
        });
    }
    Ok(value)
}

#[cfg(feature = "terminal")]
fn required_string_list(
    def: &InProcessProjectionDef,
    config: &ValueMap,
    field: &'static str,
) -> Result<Vec<String>, InstallError> {
    let value = config
        .get(field)
        .ok_or_else(|| InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: format!("{field} is required"),
        })?;
    string_list(def, field, value)
}

#[cfg(feature = "terminal")]
fn optional_string_list(
    def: &InProcessProjectionDef,
    config: &ValueMap,
    field: &'static str,
) -> Result<Option<Vec<String>>, InstallError> {
    config
        .get(field)
        .map(|value| string_list(def, field, value))
        .transpose()
}

#[cfg(feature = "terminal")]
fn string_list(
    def: &InProcessProjectionDef,
    field: &'static str,
    value: &Value,
) -> Result<Vec<String>, InstallError> {
    let Some(values) = value.as_list() else {
        return Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: format!("{field} must be a list of strings"),
        });
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let item = value.as_str().ok_or_else(|| InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: format!("{field} must contain only strings"),
        })?;
        if item.trim().is_empty() {
            return Err(InstallError::InvalidConfig {
                implementation: def.implementation.clone(),
                message: format!("{field} must not contain empty strings"),
            });
        }
        out.push(item.to_string());
    }
    Ok(out)
}

fn inference_cost_model() -> CostModel {
    CostModel {
        per_1k_in_micro_usd: 3000,
        per_1k_out_micro_usd: 15000,
        ..Default::default()
    }
}

#[cfg(test)]
fn configured_override_paths(overrides: &[TestEffectOverride]) -> BTreeSet<&str> {
    overrides
        .iter()
        .flat_map(|effect_override| {
            effect_override
                .effects()
                .iter()
                .map(TestEffectResource::path)
        })
        .collect()
}

fn register_standard_effect(
    boot: &Bootstrap,
    path: &str,
    methods: &[MethodSpec],
    driver: Arc<dyn Driver>,
    configured_paths: &BTreeSet<&str>,
) -> Result<(), InstallError> {
    if configured_paths.contains(path) {
        Ok(())
    } else {
        register_single_effect(boot, path, methods, driver).map(|_| ())
    }
}

fn register_standard_effect_with_cost(
    boot: &Bootstrap,
    path: &str,
    methods: &[MethodSpec],
    driver: Arc<dyn Driver>,
    cost: CostModel,
    configured_paths: &BTreeSet<&str>,
) -> Result<(), InstallError> {
    if configured_paths.contains(path) {
        Ok(())
    } else {
        register_single_effect_with_cost(boot, path, methods, driver, cost).map(|_| ())
    }
}

#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
fn register_declared_effect(
    boot: &Bootstrap,
    def: &InProcessProjectionDef,
    capability: &EffectCapability,
    methods: &[MethodSpec],
    driver: Arc<dyn Driver>,
    cost: CostModel,
) -> Result<(), InstallError> {
    ensure_declared_effect_owner(boot, def, &capability.effect_path)?;
    let mut spec = invoke_spec_for_path(&capability.effect_path, methods).ok_or_else(|| {
        InstallError::MethodNotFound {
            path: capability.effect_path.clone(),
        }
    })?;
    if spec.purity != capability.purity {
        return Err(InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!(
                "effect {:?} declared purity {:?}, implementation uses {:?}",
                capability.effect_path, capability.purity, spec.purity
            ),
        });
    }
    if capability.finalize_allowed && !spec.finalize_allowed {
        return Err(InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!(
                "effect {:?} is not implemented as finalizer-safe",
                capability.effect_path
            ),
        });
    }
    spec.finalize_allowed = capability.finalize_allowed;
    let inner_method =
        method_index_for_path(&capability.effect_path, methods).ok_or_else(|| {
            InstallError::MethodNotFound {
                path: capability.effect_path.clone(),
            }
        })?;
    let metadata = Metadata {
        display_name: None,
        provider_id: Some(def.id.clone()),
        tags: vec!["in-process".into(), def.implementation.clone()],
    };
    boot.register_or_relink_effect_with_cost(
        &capability.effect_path,
        &[spec],
        Arc::new(SingleMethodDriver::new(driver, inner_method)),
        cost,
        metadata,
        def.version,
    )?;
    Ok(())
}

#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
fn ensure_declared_effect_owner(
    boot: &Bootstrap,
    def: &InProcessProjectionDef,
    effect_path: &str,
) -> Result<(), InstallError> {
    let name = xolotl_types::ResourceName::new(parse_path(effect_path)?);
    let resource_id = match boot.kernel().registry().resolve_resource(&name) {
        Ok(resource_id) => resource_id,
        Err(xolotl_kernel::ResolveError::NoSuchResource(_)) => return Ok(()),
    };
    let resource = boot
        .kernel()
        .registry()
        .resource(resource_id)
        .ok_or_else(|| InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!("effect path {effect_path:?} disappeared during ownership check"),
        })?;
    match resource.descriptor.metadata.provider_id.as_deref() {
        Some(owner) if owner == def.id => Ok(()),
        Some(owner) => Err(InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!(
                "effect path {effect_path:?} is already owned by projection {owner:?}"
            ),
        }),
        None => Err(InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!(
                "effect path {effect_path:?} is already registered outside an in-process projection"
            ),
        }),
    }
}

fn register_single_effect(
    boot: &Bootstrap,
    path: &str,
    methods: &[MethodSpec],
    driver: Arc<dyn Driver>,
) -> Result<xolotl_types::ResourceName, InstallError> {
    let spec = invoke_spec_for_path(path, methods).ok_or_else(|| InstallError::MethodNotFound {
        path: path.to_string(),
    })?;
    let inner_method =
        method_index_for_path(path, methods).ok_or_else(|| InstallError::MethodNotFound {
            path: path.to_string(),
        })?;
    Ok(boot.register_effect(
        path,
        &[spec],
        Arc::new(SingleMethodDriver::new(driver, inner_method)),
    )?)
}

fn register_single_effect_with_cost(
    boot: &Bootstrap,
    path: &str,
    methods: &[MethodSpec],
    driver: Arc<dyn Driver>,
    cost: xolotl_types::CostModel,
) -> Result<xolotl_types::ResourceName, InstallError> {
    let spec = invoke_spec_for_path(path, methods).ok_or_else(|| InstallError::MethodNotFound {
        path: path.to_string(),
    })?;
    let inner_method =
        method_index_for_path(path, methods).ok_or_else(|| InstallError::MethodNotFound {
            path: path.to_string(),
        })?;
    Ok(boot.register_effect_with_cost(
        path,
        &[spec],
        Arc::new(SingleMethodDriver::new(driver, inner_method)),
        cost,
    )?)
}

fn invoke_spec_for_path(path: &str, methods: &[MethodSpec]) -> Option<MethodSpec> {
    let idx = method_index_for_path(path, methods)?;
    Some(MethodSpec {
        name: "invoke",
        ..methods[idx]
    })
}

fn method_index_for_path(path: &str, methods: &[MethodSpec]) -> Option<usize> {
    let name = path.rsplit('/').next()?;
    methods.iter().position(|method| method.name == name)
}

struct SingleMethodDriver {
    inner: Arc<dyn Driver>,
    inner_method: MethodId,
}

impl SingleMethodDriver {
    fn new(inner: Arc<dyn Driver>, inner_method: usize) -> Self {
        Self {
            inner,
            inner_method: MethodId::new(inner_method as u64),
        }
    }
}

#[async_trait]
impl Driver for SingleMethodDriver {
    fn input_admission(&self, method: MethodId) -> Option<xolotl_kernel::driver::InputAdmission> {
        if method.get() == 0 {
            self.inner.input_admission(self.inner_method)
        } else {
            None
        }
    }

    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        self.inner.call(self.inner_method, input, output, ctx).await
    }
}

#[cfg(test)]
mod tests;
