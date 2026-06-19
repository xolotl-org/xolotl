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
#[cfg(test)]
use nexus_kernel::RequestGrantTemplate;
use nexus_kernel::{Bootstrap, BootstrapError, Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{
    CostModel, InProcessProjectionDef, MethodId, Outcome, OutputMode, Path, Role, Value,
};
#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
use nexus_types::{EffectCapability, Metadata, Purity};
#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;

/// Kernel-state prefix for in-process projection declarations.
pub const IN_PROCESS_PROJECTION_CONFIG_PREFIX: &str = "state://kernel/projections/in-process";

/// Configuration for the standard provider set.
#[derive(Default)]
pub struct StandardConfig {
    /// Standard modules installed by [`install_standard`].
    modules: StandardModules,
    /// Host-provided inference backend.
    inference_backend: Option<Arc<dyn InferenceBackend>>,
    /// Internal effect overrides used by crate tests.
    #[cfg(test)]
    effect_overrides: Vec<TestEffectOverride>,
    /// Host-local edges that cannot be represented as runtime state.
    host_edges: StandardHostEdges,
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
    /// Expose `effect://tensor/*`.
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
        source: nexus_types::PathError,
    },
    /// State backend operation failed.
    #[error("state operation failed: {0}")]
    State(#[source] Box<nexus_state::StateError>),
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

impl From<nexus_state::StateError> for InstallError {
    fn from(source: nexus_state::StateError) -> Self {
        Self::State(Box::new(source))
    }
}

impl StandardConfig {
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
    let state = boot.kernel.state.clone();
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
        for path in [
            "effect://inference/infer",
            "effect://inference/embed",
            "effect://inference/rerank",
            "effect://inference/plan",
        ] {
            register_standard_effect_with_cost(
                boot,
                path,
                INFERENCE_METHODS,
                inference.clone(),
                inference_cost_model(),
                &configured_paths,
            )?;
        }
    }
    install_core_standard(boot, config, state, model_backend, configured_paths)
}

fn build_inference_driver(state: nexus_state::Backend, config: &StandardConfig) -> InferenceDriver {
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
fn default_inference_driver(state: nexus_state::Backend) -> InferenceDriver {
    InferenceDriver::with_state_config(state)
}

#[cfg(not(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
)))]
fn default_inference_driver(_: nexus_state::Backend) -> InferenceDriver {
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
) -> Result<InProcessProjectionInstallReport, InstallError> {
    let prefix = parse_path(IN_PROCESS_PROJECTION_CONFIG_PREFIX)?;
    let declarations = boot.kernel.state.read_prefix(&prefix).await?;
    let mut entries = Vec::with_capacity(declarations.len());
    for (path, value) in declarations {
        let (id, desired, result) = install_in_process_projection_report_entry(boot, &path, value);
        entries.push(InProcessProjectionInstallEntry {
            id,
            path,
            desired,
            result,
        });
    }
    Ok(InProcessProjectionInstallReport { entries })
}

fn install_in_process_projection_report_entry(
    boot: &Bootstrap,
    path: &Path,
    value: Value,
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
    let result = install_decoded_in_process_projection(boot, &def).map(|()| desired.clone());
    (id, Some(desired), result)
}

/// Install or relink one in-process projection declaration from a state value.
pub fn install_in_process_projection_value(
    boot: &Bootstrap,
    path: &Path,
    value: Value,
) -> Result<InProcessProjectionInstalled, InstallError> {
    let id = in_process_projection_path_id(path)?.to_string();
    let def = decode_in_process_projection_def(&id, value)?;
    install_decoded_in_process_projection(boot, &def)?;
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
                install_fetch_driver(_boot, def)
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
                install_fs_driver(_boot, def)
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
                install_terminal_driver(_boot, def)
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
    state: nexus_state::Backend,
    model_backend: Option<Arc<InferenceDriver>>,
    configured_paths: BTreeSet<&str>,
) -> Result<(), InstallError> {
    let index = if config.modules.contains(StandardModule::Memory)
        || config.modules.contains(StandardModule::Index)
    {
        Some(Arc::new(IndexDriver::new()))
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
        let index_for_memory = index_driver_for(&index, StandardModule::Memory)?;
        let rank_for_memory = rank_driver_for(&rank, StandardModule::Memory)?;
        let memory: Arc<dyn Driver> = Arc::new(
            MemoryDriver::new(state.clone())
                .with_retrieval_stack(index_for_memory, rank_for_memory)
                .with_embedder(embedder),
        );
        for path in [
            "effect://memory/store",
            "effect://memory/recall",
            "effect://memory/forget",
            "effect://memory/commit",
            "effect://memory/consolidate",
        ] {
            register_standard_effect(
                boot,
                path,
                MEMORY_METHODS,
                memory.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Blob) {
        let blob: Arc<dyn Driver> = Arc::new(BlobDriver::new(state.clone()));
        for path in [
            "effect://blob/write",
            "effect://blob/read",
            "effect://blob/delete",
        ] {
            register_standard_effect(boot, path, BLOB_METHODS, blob.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Time) {
        let time: Arc<dyn Driver> = Arc::new(TimeDriver);
        for path in [
            "effect://time/now",
            "effect://time/sleep",
            "effect://time/cron",
        ] {
            register_standard_effect(boot, path, TIME_METHODS, time.clone(), &configured_paths)?;
        }
    }
    if config.modules.contains(StandardModule::Approval) {
        let approval: Arc<dyn Driver> = Arc::new(ApprovalDriver::new(state.clone()));
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
        register_standard_effect(
            boot,
            "effect://deliberation/run",
            DELIBERATION_METHODS,
            Arc::new(DeliberationDriver::new(backend)),
            &configured_paths,
        )?;
    }
    // Fact reads use a capability-gated, read-only state://fact/* projection.
    if config.modules.contains(StandardModule::Fact) {
        boot.register_subtree_resource_at(
            "state://fact",
            "read://state/fact/**",
            nexus_types::InterfaceFamily::Sequence,
            FACT_METHODS,
            Arc::new(FactDriver::new(boot.kernel.facts.store().clone())),
        )?;
    }
    if config.modules.contains(StandardModule::Inspect) {
        register_standard_effect(
            boot,
            "effect://kernel/process/inspect",
            INSPECT_METHODS,
            Arc::new(KernelInspectDriver::new(
                boot.kernel.processes.clone(),
                boot.kernel.facts.clone(),
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
        let compress: Arc<dyn Driver> = Arc::new(crate::compress::CompressDriver::new(backend));
        for path in ["effect://compress/summarize", "effect://compress/trim-plan"] {
            register_standard_effect(
                boot,
                path,
                crate::compress::COMPRESS_METHODS,
                compress.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Tensor) {
        let tensor: Arc<dyn Driver> = Arc::new(crate::tensor::TensorDriver::new(state.clone()));
        for path in [
            "effect://tensor/write",
            "effect://tensor/read",
            "effect://tensor/delete",
        ] {
            register_standard_effect(
                boot,
                path,
                crate::tensor::TENSOR_METHODS,
                tensor.clone(),
                &configured_paths,
            )?;
        }
    }
    if config.modules.contains(StandardModule::Proc) {
        let proc: Arc<dyn Driver> = Arc::new(crate::proc::ProcDriver::new(state.clone()));
        for path in [
            "effect://proc/spawn",
            "effect://proc/kill",
            "effect://proc/signal",
            "effect://proc/status",
            "effect://proc/heartbeat",
        ] {
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
        ));
        for path in [
            "effect://external/pairing/create",
            "effect://external/pairing/approve",
            "effect://external/pairing/deny",
            "effect://external/pairing/replace",
            "effect://external/revoke",
        ] {
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

    // Expose `state://**` as one Resource so a Process reads and writes durable
    // state through Value/Sequence Operations, with taint persisted
    // and capability checks applied uniformly.
    if config.modules.contains(StandardModule::State) {
        boot.register_subtree_resource(
            "state",
            nexus_types::InterfaceFamily::Value,
            crate::state::STATE_METHODS,
            Arc::new(crate::state::StateDriver::new(state.clone())),
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
) -> Result<(), InstallError> {
    require_expected_provides(def, &[("effect://fetch/get", Purity::Effectful)])?;
    let config = optional_config_map(def)?;
    reject_unknown_config_fields(def, config, &[])?;
    let driver: Arc<dyn Driver> = Arc::new(
        crate::fetch::FetchDriver::new(boot.kernel.state.clone()).map_err(|error| {
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
fn install_fs_driver(boot: &Bootstrap, def: &InProcessProjectionDef) -> Result<(), InstallError> {
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
        crate::fs::FsDriver::new(root, boot.kernel.state.clone()).map_err(|error| {
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
) -> Result<(), InstallError> {
    require_expected_provides(def, &[("effect://terminal/run", Purity::Effectful)])?;
    let config = required_config_map(def)?;
    reject_unknown_config_fields(def, config, &["allowlist", "denylist", "high_risk"])?;
    let allowlist = required_string_list(def, config, "allowlist")?;
    if allowlist.is_empty() {
        return Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: "allowlist must not be empty".into(),
        });
    }
    let mut terminal = crate::terminal::TerminalDriver::new(allowlist);
    if let Some(denylist) = optional_string_list(def, config, "denylist")? {
        terminal = terminal.with_denylist(denylist);
    }
    if let Some(high_risk) = optional_string_list(def, config, "high_risk")? {
        terminal = terminal.with_high_risk(high_risk);
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
    let segs = path.segments();
    match segs {
        [kernel, projections, in_process, id]
            if path.scheme() == "state"
                && path.cluster().is_none()
                && kernel.as_str() == "kernel"
                && projections.as_str() == "projections"
                && in_process.as_str() == "in-process" =>
        {
            Ok(id.as_str())
        }
        _ => Err(InstallError::Declaration {
            id: path.to_string(),
            message: "path must be state://kernel/projections/in-process/<id>".into(),
        }),
    }
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
fn optional_config_map(
    def: &InProcessProjectionDef,
) -> Result<&BTreeMap<String, Value>, InstallError> {
    match &def.config {
        Value::Map(map) => Ok(map),
        Value::Null => Ok(empty_config_map()),
        _ => Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: "config must be an object".into(),
        }),
    }
}

#[cfg(any(feature = "fs", feature = "terminal"))]
fn required_config_map(
    def: &InProcessProjectionDef,
) -> Result<&BTreeMap<String, Value>, InstallError> {
    match &def.config {
        Value::Map(map) => Ok(map),
        _ => Err(InstallError::InvalidConfig {
            implementation: def.implementation.clone(),
            message: "config must be an object".into(),
        }),
    }
}

#[cfg(feature = "fetch")]
fn empty_config_map() -> &'static BTreeMap<String, Value> {
    static EMPTY: std::sync::OnceLock<BTreeMap<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

#[cfg(any(feature = "fetch", feature = "fs", feature = "terminal"))]
fn reject_unknown_config_fields(
    def: &InProcessProjectionDef,
    config: &BTreeMap<String, Value>,
    allowed: &[&str],
) -> Result<(), InstallError> {
    for key in config.keys() {
        if !allowed.iter().any(|allowed_key| key == allowed_key) {
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
    config: &'a BTreeMap<String, Value>,
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
    config: &BTreeMap<String, Value>,
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
    config: &BTreeMap<String, Value>,
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
    let Value::List(values) = value else {
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
    let name = nexus_types::ResourceName::new(parse_path(effect_path)?);
    let resource_id = match boot.kernel.registry.resolve_resource(&name) {
        Ok(resource_id) => resource_id,
        Err(nexus_kernel::ResolveError::NoSuchResource(_)) => return Ok(()),
    };
    let resource = boot.kernel.registry.resource(resource_id).ok_or_else(|| {
        InstallError::InvalidProvides {
            implementation: def.implementation.clone(),
            message: format!("effect path {effect_path:?} disappeared during ownership check"),
        }
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
) -> Result<nexus_types::ResourceName, InstallError> {
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
    cost: nexus_types::CostModel,
) -> Result<nexus_types::ResourceName, InstallError> {
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
    let method = methods[idx];
    let mut spec = MethodSpec::new("invoke", method.purity, method.supports);
    spec.batchable = method.batchable;
    spec.observes_external = method.observes_external;
    spec.finalize_allowed = method.finalize_allowed;
    Some(spec)
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
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        self.inner.call(self.inner_method, input, output, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::{InferenceBackend, ModelCapabilities};
    use crate::router::{ModelEntry, Router};
    use anyhow::{Context, bail, ensure};
    use nexus_graph::{DoNode, OperationTemplate};
    use nexus_types::{
        EffectCapability, InProcessProjectionDef, Outcome, OutputMode, Purity, Value,
    };

    struct StaticBackend;

    #[async_trait::async_trait]
    impl InferenceBackend for StaticBackend {
        async fn infer(&self, _input: &Value) -> Result<Value, String> {
            Ok(Value::Str("configured-router".into()))
        }

        async fn embed(&self, _input: &Value) -> Result<Value, String> {
            Err("not supported".into())
        }

        fn capabilities(&self) -> ModelCapabilities {
            ModelCapabilities {
                methods: crate::inference::InferenceMethodSupport {
                    infer: true,
                    embed: false,
                    rerank: false,
                    plan: true,
                },
                ..Default::default()
            }
        }
    }

    fn resource_name(path: &str) -> anyhow::Result<nexus_types::ResourceName> {
        nexus_types::Path::parse(path)
            .map(nexus_types::ResourceName::new)
            .with_context(|| format!("parse resource name {path}"))
    }

    fn install_default(boot: &Bootstrap) -> anyhow::Result<()> {
        install_standard(boot, &StandardConfig::default()).context("install standard package")
    }

    fn fetch_projection_def() -> InProcessProjectionDef {
        InProcessProjectionDef {
            id: "fetch".into(),
            role: Role::Provider,
            implementation: "standard.fetch".into(),
            provides: vec![EffectCapability::new(
                "effect://fetch/get",
                Purity::Effectful,
            )],
            emits: None,
            config: Value::Null,
            version: 1,
        }
    }

    #[cfg(not(feature = "fetch"))]
    #[test]
    fn in_process_projection_declaration_fails_when_feature_is_absent() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;
        let err = match install_decoded_in_process_projection(&boot, &fetch_projection_def()) {
            Ok(()) => bail!("fetch projection unexpectedly installed without fetch feature"),
            Err(error) => error,
        };
        ensure!(
            matches!(
                err,
                InstallError::FeatureNotEnabled {
                    feature: "fetch",
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn in_process_projection_reinstall_relinks_existing_resource() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;
        let def = fetch_projection_def();
        install_decoded_in_process_projection(&boot, &def).context("install fetch projection")?;
        let name = resource_name("effect://fetch/get")?;
        let first = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context("resolve first fetch resource")?;

        install_decoded_in_process_projection(&boot, &def).context("reinstall fetch projection")?;
        let second = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context("resolve second fetch resource")?;

        ensure!(first == second, "resource id changed on relink");
        Ok(())
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn in_process_projection_rejects_duplicate_effect_owner() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;
        let def = fetch_projection_def();
        install_decoded_in_process_projection(&boot, &def).context("install fetch projection")?;

        let mut duplicate = fetch_projection_def();
        duplicate.id = "other_fetch".into();
        let err = match install_decoded_in_process_projection(&boot, &duplicate) {
            Ok(()) => bail!("duplicate projection unexpectedly relinked fetch effect"),
            Err(error) => error,
        };
        match err {
            InstallError::InvalidProvides { message, .. } => {
                ensure!(
                    message.contains("already owned by projection"),
                    "unexpected duplicate error message: {message}"
                );
            }
            other => bail!("unexpected duplicate error: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn in_process_projection_rejects_clustered_declaration_path() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let err = match install_in_process_projection_value(
            &boot,
            &Path::parse("path://remote/state/kernel/projections/in-process/fetch")?,
            Value::Null,
        ) {
            Ok(_) => bail!("clustered declaration path was unexpectedly accepted"),
            Err(error) => error,
        };
        ensure!(
            matches!(err, InstallError::Declaration { .. }),
            "unexpected clustered path error: {err:?}"
        );
        Ok(())
    }

    async fn run_standard_inference(boot: &Bootstrap) -> anyhow::Result<Outcome> {
        run_standard_effect(boot, "effect://inference/infer", Value::Str("hello".into())).await
    }

    async fn run_standard_effect(
        boot: &Bootstrap,
        path: &str,
        input: Value,
    ) -> anyhow::Result<Outcome> {
        let name = resource_name(path)?;
        boot.kernel
            .registry
            .resolve_resource(&name)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .with_context(|| format!("resolve resource {path}"))?;
        let handle = boot
            .open_for(boot.root, &name, "perform")
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .with_context(|| format!("open resource {path}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);

        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        });
        Ok(ex.eval(&prog).await)
    }

    #[cfg(not(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    )))]
    #[tokio::test]
    async fn standard_inference_runs_end_to_end() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;
        let out = run_standard_inference(&boot).await?;
        ensure!(
            matches!(out, Outcome::Done(Value::Str(_))),
            "expected inference text output, got {out:?}"
        );
        Ok(())
    }

    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    #[tokio::test]
    async fn standard_inference_requires_provider_state_when_http_inferences_are_enabled()
    -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;
        let out = run_standard_inference(&boot).await?;
        ensure!(
            matches!(out, Outcome::Fail(_)),
            "expected failure, got {out:?}"
        );
        ensure!(
            format!("{out:?}").contains("HTTP inference provider state config is not declared"),
            "unexpected failure: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn standard_inference_uses_configured_router() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let router = Router::new(vec![ModelEntry::new(
            "test/static",
            Arc::new(StaticBackend),
        )]);
        let driver: Arc<dyn Driver> = Arc::new(InferenceDriver::with_router_arc(Arc::new(router)));
        let config = StandardConfig::default().with_effect_override(
            TestEffectOverride::new(driver)
                .effect_with_cost(
                    "effect://inference/infer",
                    INFERENCE_METHODS,
                    inference_cost_model(),
                )
                .effect_with_cost(
                    "effect://inference/embed",
                    INFERENCE_METHODS,
                    inference_cost_model(),
                )
                .effect_with_cost(
                    "effect://inference/rerank",
                    INFERENCE_METHODS,
                    inference_cost_model(),
                )
                .effect_with_cost(
                    "effect://inference/plan",
                    INFERENCE_METHODS,
                    inference_cost_model(),
                ),
        );
        install_standard(&boot, &config).map_err(anyhow::Error::msg)?;

        let name = resource_name("effect://inference/infer")?;
        let handle = boot
            .open_for(boot.root, &name, "perform")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let out = ex
            .eval(&DoNode::Op(OperationTemplate {
                target: name,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Str("hello".into())),
            }))
            .await;
        ensure!(
            matches!(out, Outcome::Done(Value::Str(ref text)) if text == "configured-router"),
            "expected configured router output, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn standard_inference_uses_host_backend() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let config = StandardConfig::default().with_inference_backend(Arc::new(StaticBackend));
        install_standard(&boot, &config).map_err(anyhow::Error::msg)?;
        let out = run_standard_inference(&boot).await?;
        ensure!(
            matches!(out, Outcome::Done(Value::Str(ref text)) if text == "configured-router"),
            "expected host backend output, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn standard_model_backed_effects_use_host_backend() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let config = StandardConfig::default().with_inference_backend(Arc::new(StaticBackend));
        install_standard(&boot, &config).map_err(anyhow::Error::msg)?;

        let mut deliberation_input = std::collections::BTreeMap::new();
        deliberation_input.insert("question".into(), Value::Str("choose".into()));
        deliberation_input.insert("panelists".into(), Value::Int(1));
        let deliberation = run_standard_effect(
            &boot,
            "effect://deliberation/run",
            Value::Map(deliberation_input),
        )
        .await?;
        ensure!(
            matches!(deliberation, Outcome::Done(Value::Map(ref map)) if map
                .get("answer")
                .and_then(Value::as_str)
                == Some("configured-router")),
            "expected deliberation to use host backend, got {deliberation:?}"
        );

        let mut compress_input = std::collections::BTreeMap::new();
        compress_input.insert("text".into(), Value::Str("word ".repeat(500)));
        compress_input.insert("max_tokens".into(), Value::Int(1));
        let compress = run_standard_effect(
            &boot,
            "effect://compress/summarize",
            Value::Map(compress_input),
        )
        .await?;
        ensure!(
            matches!(compress, Outcome::Done(Value::Map(ref map)) if map
                .get("summary")
                .and_then(Value::as_str)
                == Some("configured-router")),
            "expected compress to use host backend, got {compress:?}"
        );
        Ok(())
    }

    #[test]
    fn standard_modules_state_only_exposes_only_state_driver() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let config = StandardConfig::default().with_modules(StandardModules::state_only());
        install_standard(&boot, &config).map_err(anyhow::Error::msg)?;

        boot.kernel
            .registry
            .resolve_resource(&resource_name("state://scratch/value")?)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context("state resource should resolve")?;
        let time = boot
            .kernel
            .registry
            .resolve_resource(&resource_name("effect://time/now")?);
        ensure!(time.is_err(), "time resource should not be installed");
        Ok(())
    }

    #[test]
    fn standard_modules_default_installs_all_modules() -> anyhow::Result<()> {
        ensure!(
            StandardModules::default() == StandardModules::all(),
            "default standard module set must match all modules"
        );
        Ok(())
    }

    #[tokio::test]
    async fn state_read_write_as_operations() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let target = resource_name("state://scratch/note")?;
        let write_handle = boot
            .open_for(boot.root, &target, "write")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(target.clone(), write_handle);

        let write = DoNode::Op(OperationTemplate {
            target: target.clone(),
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hello-state".into())),
        });
        let written = ex.eval(&write).await;
        ensure!(
            written == Outcome::Done(Value::Bool(true)),
            "state write outcome: {written:?}"
        );

        let read_handle = boot
            .open_for(boot.root, &target, "read")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        ex.bind_handle(target.clone(), read_handle);

        let read = DoNode::Op(OperationTemplate {
            target,
            method: "read".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        let read_out = ex.eval(&read).await;
        ensure!(
            read_out == Outcome::Done(Value::Str("hello-state".into())),
            "state read outcome: {read_out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn state_write_persists_taint() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let target = resource_name("state://scratch/tainted")?;
        let handle = boot
            .open_for(boot.root, &target, "write")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(target.clone(), handle);

        let write = DoNode::Op(OperationTemplate {
            target: target.clone(),
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("from-the-web".into())),
        });
        let entry_taint = nexus_types::TaintSet::of(nexus_types::TaintSource::Fetched {
            host: "evil.example".into(),
        });
        let outcome = ex.eval_tainted(&write, entry_taint).await;
        ensure!(
            outcome == Outcome::Done(Value::Bool(true)),
            "tainted write outcome: {outcome:?}"
        );

        let tv = boot
            .kernel
            .state
            .read_tainted(target.path())
            .await
            .map_err(anyhow::Error::msg)?
            .context("expected tainted value to be present")?;
        ensure!(
            tv.taint.has_untrusted_content(),
            "taint persisted with the value"
        );
        Ok(())
    }

    #[tokio::test]
    async fn root_can_lazy_open_write_after_cached_read_handle() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let target = resource_name("state://scratch/root-lazy-write")?;
        let read_handle = boot
            .open_for(boot.root, &target, "read")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(target.clone(), read_handle);
        let target_path = target.path().clone();

        let write = DoNode::Op(OperationTemplate {
            target,
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("lazy-write".into())),
        });
        let out = ex.eval(&write).await;
        ensure!(
            out == Outcome::Done(Value::Bool(true)),
            "root should lazy-open a write handle when it has write grant: {out:?}"
        );
        let persisted = boot.kernel.state.read(&target_path).await?;
        ensure!(
            persisted == Some(Value::Str("lazy-write".into())),
            "lazy write did not persist: {persisted:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_only_request_process_cannot_write_state() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let target = resource_name("state://scratch/read-only")?;
        let read_methods = boot
            .request_method_bitmap(&target, "read")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            nexus_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "read://state/scratch/read-only",
                methods: read_methods,
            }],
        )?;
        let read_handle = boot
            .open_for(child, &target, "read")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(child);
        ex.bind_handle(target.clone(), read_handle);

        let write = DoNode::Op(OperationTemplate {
            target: target.clone(),
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("must-not-write".into())),
        });
        let out = ex.eval(&write).await;
        ensure!(
            matches!(
                out,
                Outcome::Fail(nexus_types::Failure::PolicyViolation { .. })
            ),
            "read-only request process accepted write: {out:?}"
        );
        let persisted = boot.kernel.state.read(target.path()).await?;
        ensure!(
            persisted.is_none(),
            "denied write should not persist state: {persisted:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fact_read_side_is_state_projection_not_effect_alias() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let fact_effect = resource_name("effect://fact/read")?;
        ensure!(
            boot.kernel.registry.resolve_resource(&fact_effect).is_err(),
            "Fact read side must not be exposed as effect://fact/read"
        );

        let fact_path = resource_name(&format!("state://fact/{}", boot.root.get()))?;
        let handle = boot
            .open_for(boot.root, &fact_path, "read")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(fact_path.clone(), handle);
        let read = DoNode::Op(OperationTemplate {
            target: fact_path,
            method: "read".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        match ex.eval(&read).await {
            Outcome::Done(Value::List(_)) => {}
            other => bail!("expected fact projection list, got {other:?}"),
        }

        let global_fact_path = resource_name("state://fact")?;
        let handle = boot
            .open_for(boot.root, &global_fact_path, "read")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(global_fact_path.clone(), handle);
        let read_global = DoNode::Op(OperationTemplate {
            target: global_fact_path,
            method: "read".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        match ex.eval(&read_global).await {
            Outcome::Done(Value::List(_)) => {}
            other => {
                bail!("expected global fact projection list, got {other:?}");
            }
        }

        let vault = resource_name("state://vault/console/root/password")?;
        let err = boot
            .open_for(boot.root, &vault, "read")
            .err()
            .context("vault path should be reserved")?;
        ensure!(
            matches!(err, nexus_kernel::OpenError::ReservedPath(_)),
            "unexpected vault open error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn batchable_methods_are_registered_as_metadata() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        assert_method_batchable(&boot, "effect://inference/infer", "invoke", false)?;
        assert_method_batchable(&boot, "effect://inference/embed", "invoke", true)?;
        assert_method_batchable(&boot, "effect://inference/rerank", "invoke", true)?;
        assert_method_batchable(&boot, "effect://index/upsert", "invoke", true)?;
        Ok(())
    }

    #[test]
    fn finalizer_allowed_methods_are_registered_as_metadata() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        assert_method_finalize_allowed(&boot, "effect://events/publish", "invoke", true)?;
        assert_method_finalize_allowed(&boot, "effect://lock/release", "invoke", true)?;
        assert_method_finalize_allowed(&boot, "effect://proc/kill", "invoke", true)?;
        assert_method_finalize_allowed(&boot, "effect://proc/signal", "invoke", true)?;
        assert_method_finalize_allowed(&boot, "effect://proc/spawn", "invoke", false)?;
        assert_method_finalize_allowed(&boot, "effect://inference/infer", "invoke", false)?;
        assert_method_finalize_allowed(&boot, "state://scratch/finalizer", "write", false)?;
        Ok(())
    }

    #[test]
    fn external_observation_methods_are_registered_as_observation_replay() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        assert_method_replay(
            &boot,
            "state://fact/1",
            "read",
            nexus_types::ReplayClass::Observation,
        )?;
        assert_method_replay(
            &boot,
            "effect://time/now",
            "invoke",
            nexus_types::ReplayClass::Observation,
        )?;
        assert_method_replay(
            &boot,
            "effect://approval/check",
            "invoke",
            nexus_types::ReplayClass::Observation,
        )?;
        assert_method_replay(
            &boot,
            "effect://blob/read",
            "invoke",
            nexus_types::ReplayClass::Observation,
        )?;
        assert_method_replay(
            &boot,
            "effect://memory/recall",
            "invoke",
            nexus_types::ReplayClass::Observation,
        )?;
        assert_method_replay(
            &boot,
            "effect://rank/score",
            "invoke",
            nexus_types::ReplayClass::Observation,
        )?;
        assert_method_replay(
            &boot,
            "effect://rank/fuse",
            "invoke",
            nexus_types::ReplayClass::Deterministic,
        )?;
        Ok(())
    }

    #[test]
    fn external_pairing_effects_are_registered_as_distinct_resources() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        for path in [
            "effect://external/pairing/create",
            "effect://external/pairing/approve",
            "effect://external/pairing/deny",
            "effect://external/pairing/replace",
            "effect://external/revoke",
        ] {
            let name = resource_name(path)?;
            ensure!(
                boot.kernel.registry.resolve_resource(&name).is_ok(),
                "{path} should resolve"
            );
            assert_method_replay(
                &boot,
                path,
                "invoke",
                nexus_types::ReplayClass::NonIdempotentEffect,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn standard_effect_paths_do_not_accept_sibling_methods() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let name = resource_name("effect://approval/ask")?;
        let handle = boot
            .open_for(boot.root, &name, "perform")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);

        let sibling_check_on_ask = DoNode::Op(OperationTemplate {
            target: name,
            method: "check".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        let sibling_out = ex.eval(&sibling_check_on_ask).await;
        ensure!(
            matches!(
                sibling_out,
                Outcome::Fail(nexus_types::Failure::NoHandler { .. })
            ),
            "sibling method was accepted: {sibling_out:?}"
        );

        let blob_unref = resource_name("effect://blob/unref")?;
        ensure!(
            boot.kernel.registry.resolve_resource(&blob_unref).is_err(),
            "blob unref alias must not be registered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pairing_secret_is_not_an_operation_input() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_default(&boot)?;

        let name = resource_name("effect://external/pairing/create")?;
        let handle = boot
            .open_for(boot.root, &name, "perform")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);

        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Map(std::collections::BTreeMap::from([
                ("pairing_id".into(), Value::Str("pair-old".into())),
                ("pairing_secret".into(), Value::Str("old-secret".into())),
            ]))),
        });
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(
                out,
                Outcome::Fail(nexus_types::Failure::InvalidInput { .. })
            ),
            "pairing secret input was accepted: {out:?}"
        );

        let facts = boot.kernel.facts.all_facts().map_err(anyhow::Error::msg)?;
        ensure!(facts.len() == 1, "fact count: {}", facts.len());
        let Some(Value::Map(input)) = facts[0].input_ref.as_inline() else {
            bail!("expected inline redacted input");
        };
        ensure!(
            input.get("pairing_secret") == Some(&Value::Str("<redacted>".into())),
            "pairing_secret was not redacted"
        );
        ensure!(
            !input
                .values()
                .any(|v| v == &Value::Str("old-secret".into())),
            "raw pairing secret leaked into facts"
        );
        Ok(())
    }

    fn assert_method_batchable(
        boot: &Bootstrap,
        path: &str,
        method: &str,
        expected: bool,
    ) -> anyhow::Result<()> {
        let name = resource_name(path)?;
        let rid = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let resource = boot
            .kernel
            .registry
            .resource(rid)
            .with_context(|| format!("resource {path} is not registered"))?;
        let mut actual = None;
        for iface_id in &resource.interfaces.interfaces {
            let Some(iface) = boot.kernel.registry.interface(*iface_id) else {
                continue;
            };
            if let Some(method) = iface.methods.iter().find(|m| m.name == method) {
                actual = Some(method.batchable);
                break;
            }
        }
        let actual = actual.with_context(|| format!("method {method} not registered on {path}"))?;
        ensure!(
            actual == expected,
            "{path}.{method}: expected {expected}, got {actual}"
        );
        Ok(())
    }

    fn assert_method_finalize_allowed(
        boot: &Bootstrap,
        path: &str,
        method: &str,
        expected: bool,
    ) -> anyhow::Result<()> {
        let name = resource_name(path)?;
        let rid = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let resource = boot
            .kernel
            .registry
            .resource(rid)
            .with_context(|| format!("resource {path} is not registered"))?;
        let mut actual = None;
        for iface_id in &resource.interfaces.interfaces {
            let Some(iface) = boot.kernel.registry.interface(*iface_id) else {
                continue;
            };
            if let Some(method) = iface.methods.iter().find(|m| m.name == method) {
                actual = Some(method.finalize_allowed);
                break;
            }
        }
        let actual = actual.with_context(|| format!("method {method} not registered on {path}"))?;
        ensure!(
            actual == expected,
            "{path}.{method}: expected {expected}, got {actual}"
        );
        Ok(())
    }

    fn assert_method_replay(
        boot: &Bootstrap,
        path: &str,
        method: &str,
        expected: nexus_types::ReplayClass,
    ) -> anyhow::Result<()> {
        let name = resource_name(path)?;
        let rid = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let resource = boot
            .kernel
            .registry
            .resource(rid)
            .with_context(|| format!("resource {path} is not registered"))?;
        let mut actual = None;
        for iface_id in &resource.interfaces.interfaces {
            let Some(iface) = boot.kernel.registry.interface(*iface_id) else {
                continue;
            };
            if let Some(method) = iface.methods.iter().find(|m| m.name == method) {
                actual = Some(method.replay);
                break;
            }
        }
        let actual = actual.with_context(|| format!("method {method} not registered on {path}"))?;
        ensure!(
            actual == expected,
            "{path}.{method}: expected {expected:?}, got {actual:?}"
        );
        Ok(())
    }
}
