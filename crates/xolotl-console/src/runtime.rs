//! Host admission for portable runtime calls. Exposure attenuates Console users'
//! capabilities; it never grants authority or installs resources into the kernel.

use serde::{Deserialize, Serialize};
use xolotl_graph::portable::CompileLimits;
use xolotl_kernel::ExecutionConfig;
use xolotl_types::value::inspection::ValueAdmissionLimits;
use xolotl_types::{BudgetSpec, CapSet};

pub(crate) mod budget;
pub(crate) mod executions;
mod modules;
mod request;
pub use executions::ConsoleExecutionConfig;
pub(crate) use modules::valid_identity;
pub use modules::{
    ConsoleModule, ConsoleModules, ModuleConfigError, ModuleManifest, ModuleOperation,
};
pub use request::{RuntimeCode, RuntimeRequest, RuntimeSubmissionIdentity};

/// Host-controlled bounds for runtime execution on every adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleRuntimeConfig {
    /// Enable resource invocation and portable program execution.
    pub enabled: bool,
    /// Service-owned execution admission, persistence and bounded result retention.
    pub executions: ConsoleExecutionConfig,
    /// Unconditional capability selectors admitted by this host, intersected with the user.
    /// Empty by default. Local kernel, vault and Fact paths remain unavailable.
    pub capabilities: Vec<String>,
    /// Per-execution process-tree ceilings, shared by all admitted descendants.
    /// Calls may tighten them. Spending never resets at a calendar boundary.
    /// Cost and token limits serialize as decimal strings to preserve all u64 values.
    #[serde(with = "budget")]
    pub budget: BudgetSpec,
    /// Maximum portable JSON source bytes.
    pub max_source_bytes: usize,
    /// Maximum logical outer-input Value nodes, counting shared occurrences.
    pub max_input_nodes: usize,
    /// Maximum outer-input Value nesting, counting the root as depth one.
    pub max_input_depth: usize,
    /// Maximum logical inline bytes in the outer input, including keys and
    /// reference metadata but excluding referenced object contents.
    /// This is an admission charge, not process memory or wire size.
    pub max_input_inline_bytes: usize,
    /// Maximum compiled instructions, including named functions.
    pub max_instructions: usize,
    /// Maximum expression nesting during compilation.
    pub max_expression_depth: usize,
    /// Maximum operation imports admitted before any effect executes.
    pub max_operations: usize,
    /// Maximum compiled account-grant alternatives across one execution.
    pub max_request_grants: usize,
    /// Maximum distinct identities imported by Acting scopes, including modules.
    pub max_identities: usize,
    /// Maximum distinct host modules in an execution's transitive import graph.
    pub max_modules: usize,
    /// Cumulative interpreter transition budget, including repeated operations.
    pub max_steps: u64,
    /// Maximum simultaneous interpreter tasks, including suspended parents.
    pub max_tasks: usize,
    /// Maximum execution container bytes, excluding driver-owned payload memory.
    pub max_storage_bytes: usize,
    /// Host ceiling for one execution, including independent submissions.
    /// Attached calls and subscriptions also end when their shorter visibility
    /// grant expires. An accepted submission retains its own absolute deadline.
    pub max_duration_ms: u64,
    /// Maximum number of collected output values per operation.
    pub max_collect_items: usize,
    /// Maximum simultaneously open output ports in one streamed execution.
    pub max_output_streams: usize,
    /// Maximum resident chunks in each kernel output port.
    pub stream_window_chunks: usize,
    /// Maximum tagged inline bytes in each kernel output port.
    pub stream_window_bytes: usize,
}

/// Runtime discovery omits host selectors, which can name resources beyond
/// the requesting account's authority. This view borrows the remaining limits.
#[derive(Serialize)]
pub(crate) struct PublicRuntimeConfig<'a> {
    enabled: bool,
    executions: &'a ConsoleExecutionConfig,
    #[serde(serialize_with = "budget::serialize")]
    budget: &'a BudgetSpec,
    max_source_bytes: usize,
    max_input_nodes: usize,
    max_input_depth: usize,
    max_input_inline_bytes: usize,
    max_instructions: usize,
    max_expression_depth: usize,
    max_operations: usize,
    max_request_grants: usize,
    max_identities: usize,
    max_modules: usize,
    max_steps: u64,
    max_tasks: usize,
    max_storage_bytes: usize,
    max_duration_ms: u64,
    max_collect_items: usize,
    max_output_streams: usize,
    stream_window_chunks: usize,
    stream_window_bytes: usize,
}

impl<'a> From<&'a ConsoleRuntimeConfig> for PublicRuntimeConfig<'a> {
    fn from(config: &'a ConsoleRuntimeConfig) -> Self {
        Self {
            enabled: config.enabled,
            executions: &config.executions,
            budget: &config.budget,
            max_source_bytes: config.max_source_bytes,
            max_input_nodes: config.max_input_nodes,
            max_input_depth: config.max_input_depth,
            max_input_inline_bytes: config.max_input_inline_bytes,
            max_instructions: config.max_instructions,
            max_expression_depth: config.max_expression_depth,
            max_operations: config.max_operations,
            max_request_grants: config.max_request_grants,
            max_identities: config.max_identities,
            max_modules: config.max_modules,
            max_steps: config.max_steps,
            max_tasks: config.max_tasks,
            max_storage_bytes: config.max_storage_bytes,
            max_duration_ms: config.max_duration_ms,
            max_collect_items: config.max_collect_items,
            max_output_streams: config.max_output_streams,
            stream_window_chunks: config.stream_window_chunks,
            stream_window_bytes: config.stream_window_bytes,
        }
    }
}

impl Default for ConsoleRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            executions: ConsoleExecutionConfig::default(),
            capabilities: Vec::new(),
            budget: BudgetSpec::default(),
            max_source_bytes: 256 * 1024,
            max_input_nodes: 16_384,
            max_input_depth: 128,
            max_input_inline_bytes: 4 * 1024 * 1024,
            max_instructions: 8192,
            max_expression_depth: 64,
            max_operations: 128,
            max_request_grants: 4096,
            max_identities: 128,
            max_modules: 64,
            max_steps: 100_000,
            max_tasks: 33,
            max_storage_bytes: 4 * 1024 * 1024,
            max_duration_ms: 30_000,
            max_collect_items: 256,
            max_output_streams: 16,
            stream_window_chunks: 16,
            stream_window_bytes: 256 * 1024,
        }
    }
}

/// Invalid host runtime admission or resource budgets.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeConfigError {
    /// The host could not allocate an unpredictable execution namespace.
    #[error("console execution identity entropy is unavailable")]
    Entropy,
    /// A configured ceiling lies outside the supported host range.
    #[error("invalid console runtime limit: {0}")]
    Limit(&'static str),
    /// Exposure selectors must use the kernel's capability syntax.
    #[error("invalid console runtime capability: {0}")]
    Capability(#[from] xolotl_types::CapError),
    /// Runtime exposure declares structural scope; residual policy belongs to the kernel.
    #[error("console runtime exposure does not accept capability predicates")]
    ConditionalExposure,
}

pub(crate) struct RuntimeAdmission {
    pub config: ConsoleRuntimeConfig,
    pub capabilities: CapSet,
}

impl RuntimeAdmission {
    pub fn new(mut config: ConsoleRuntimeConfig) -> Result<Self, RuntimeConfigError> {
        config.executions.validate()?;
        for (name, value, ceiling) in [
            (
                "max_source_bytes",
                config.max_source_bytes as u64,
                1024 * 1024,
            ),
            ("max_input_nodes", config.max_input_nodes as u64, 65_536),
            ("max_input_depth", config.max_input_depth as u64, 1024),
            (
                "max_input_inline_bytes",
                config.max_input_inline_bytes as u64,
                64 * 1024 * 1024,
            ),
            ("max_instructions", config.max_instructions as u64, 65_536),
            (
                "max_expression_depth",
                config.max_expression_depth as u64,
                128,
            ),
            ("max_operations", config.max_operations as u64, 1024),
            (
                "max_request_grants",
                config.max_request_grants as u64,
                16_384,
            ),
            ("max_identities", config.max_identities as u64, 1024),
            ("max_modules", config.max_modules as u64, 1024),
            ("max_steps", config.max_steps, 10_000_000),
            ("max_tasks", config.max_tasks as u64, 257),
            (
                "max_storage_bytes",
                config.max_storage_bytes as u64,
                64 * 1024 * 1024,
            ),
            ("max_collect_items", config.max_collect_items as u64, 4096),
            ("max_output_streams", config.max_output_streams as u64, 256),
            (
                "stream_window_chunks",
                config.stream_window_chunks as u64,
                4096,
            ),
            (
                "stream_window_bytes",
                config.stream_window_bytes as u64,
                4 * 1024 * 1024,
            ),
        ] {
            if value == 0 || value > ceiling {
                return Err(RuntimeConfigError::Limit(name));
            }
        }
        // The host chooses this ceiling. Check the configured range here;
        // ConsoleState checks it against the installed Kernel clock.
        let Ok(millis) = i64::try_from(config.max_duration_ms) else {
            return Err(RuntimeConfigError::Limit("max_duration_ms"));
        };
        if millis == 0 {
            return Err(RuntimeConfigError::Limit("max_duration_ms"));
        }
        if config.capabilities.len() > 1024
            || config
                .capabilities
                .iter()
                .any(|literal| literal.len() > 4096)
        {
            return Err(RuntimeConfigError::Limit("capabilities"));
        }
        config.capabilities.sort();
        config.capabilities.dedup();
        let capabilities = CapSet::from_strs(config.capabilities.iter().map(String::as_str))?;
        if capabilities
            .iter()
            .any(|capability| capability.predicate.is_some())
        {
            return Err(RuntimeConfigError::ConditionalExposure);
        }
        Ok(Self {
            config,
            capabilities,
        })
    }

    pub fn compile_limits(&self) -> CompileLimits {
        CompileLimits {
            source_bytes: self.config.max_source_bytes,
            instructions: self.config.max_instructions,
            expression_depth: self.config.max_expression_depth,
        }
    }

    pub fn input_limits(&self) -> ValueAdmissionLimits {
        ValueAdmissionLimits {
            max_nodes: self.config.max_input_nodes,
            max_depth: self.config.max_input_depth,
            max_inline_bytes: self.config.max_input_inline_bytes,
        }
    }

    pub fn execution_config(&self, host: ExecutionConfig) -> ExecutionConfig {
        ExecutionConfig {
            max_tasks: self.config.max_tasks.min(host.max_tasks),
            max_instructions: self.config.max_instructions.min(host.max_instructions),
            max_storage_bytes: self.config.max_storage_bytes.min(host.max_storage_bytes),
            max_steps: Some(
                self.config
                    .max_steps
                    .min(host.max_steps.unwrap_or(u64::MAX)),
            ),
            ..host
        }
    }
}
