//! Assembly: install the standard Drivers into a [`Bootstrap`].
//!
//! Every provider goes through the kernel's standard `register_effect` face.
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
    inference::{EchoBackend, INFERENCE_METHODS, InferenceDriver},
    inspect::{INSPECT_METHODS, KernelInspectDriver},
    lock::{LOCK_METHODS, LockDriver},
    mcp::{MCP_STREAM_TOOL_METHODS, MCP_TOOL_METHODS, McpToolDriver},
    memory::{MEMORY_METHODS, MemoryDriver},
    pairing::{PAIRING_METHODS, PairingDisplayEdge, PairingDriver},
    rank::{RANK_METHODS, RankerDriver},
    time::{TIME_METHODS, TimeDriver},
};
use async_trait::async_trait;
use nexus_kernel::{Bootstrap, BootstrapError, Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Value};
use std::sync::Arc;
use thiserror::Error;

/// Configuration for the standard provider set.
#[derive(Default)]
pub struct StandardConfig {
    /// Filesystem sandbox root for `effect://fs/*`. `None` disables fs.
    pub fs_root: Option<std::path::PathBuf>,
    /// Allowlisted commands for `effect://terminal/run`. Empty disables exec.
    pub terminal_allowlist: Vec<String>,
    /// Enable the network fetch provider.
    pub enable_fetch: bool,
    /// MCP tools to mount as sandboxed Providers. Each entry registers
    /// one concrete `effect://external-provider/<server>/<tool>` Resource. Empty means no
    /// MCP tools. The offline baseline backs entries with deterministic echo
    /// clients; runtime integrations can call `register_mcp_tool` with a
    /// stdio/SSE client.
    pub mcp_tools: Vec<McpToolMount>,
    /// One-shot display edge for external pairing secrets. The secret does not
    /// enter Operation input/outcome, state, or Facts.
    pub pairing_display: PairingDisplayEdge,
}

/// One MCP host-side tool mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpToolMount {
    /// MCP server namespace segment.
    pub server: String,
    /// MCP tool namespace segment.
    pub tool: String,
    /// Whether this tool should be mounted with stream-capable method specs.
    pub streaming: bool,
}

/// Errors returned while installing standard actors and providers.
#[derive(Debug, Error)]
pub enum InstallError {
    /// Kernel bootstrap registration failed.
    #[error("bootstrap registration failed: {0}")]
    Bootstrap(#[from] BootstrapError),
    /// Effect path could not be matched to an internal method descriptor.
    #[error("standard effect path {path:?} has no matching method")]
    MethodNotFound {
        /// Effect path being registered.
        path: String,
    },
    /// MCP server or tool segment is not safe for a resource path.
    #[error("invalid MCP {label} path segment: {segment:?}")]
    InvalidMcpPathSegment {
        /// Segment kind, such as `server` or `tool`.
        label: &'static str,
        /// Invalid segment value.
        segment: String,
    },
}

impl McpToolMount {
    /// Create a unary MCP tool mount.
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            streaming: false,
        }
    }

    /// Mark this MCP tool mount as stream-capable.
    pub fn streaming(mut self) -> Self {
        self.streaming = true;
        self
    }
}

/// Install the core in-process providers on `boot`, sharing its kernel's
/// state backend.
pub fn install_standard(boot: &Bootstrap, config: &StandardConfig) -> Result<(), InstallError> {
    let state = boot.kernel.state.clone();

    // Inference carries a modeled cost so the budget reserve/settle path has a
    // real estimate (the baseline EchoBackend is free at runtime, but other
    // backends populate the same CostModel shape).
    let inference: Arc<dyn Driver> = Arc::new(InferenceDriver::baseline());
    for path in [
        "effect://inference/infer",
        "effect://inference/embed",
        "effect://inference/rerank",
        "effect://inference/plan",
    ] {
        register_single_effect_with_cost(
            boot,
            path,
            INFERENCE_METHODS,
            inference.clone(),
            nexus_types::CostModel {
                per_1k_in_micro_usd: 3000,
                per_1k_out_micro_usd: 15000,
                ..Default::default()
            },
        )?;
    }
    // The retrieval stack uses a vector index plus a pluggable ranker. Memory
    // uses these exact instances, and they are also exposed as effect
    // Resources below.
    let index = Arc::new(IndexDriver::new());
    let rank = Arc::new(RankerDriver::new().with_state(state.clone()));
    let memory: Arc<dyn Driver> = Arc::new(
        MemoryDriver::new(state.clone()).with_retrieval_stack(index.clone(), rank.clone()),
    );
    for path in [
        "effect://memory/store",
        "effect://memory/recall",
        "effect://memory/forget",
        "effect://memory/commit",
        "effect://memory/consolidate",
    ] {
        register_single_effect(boot, path, MEMORY_METHODS, memory.clone())?;
    }
    let blob: Arc<dyn Driver> = Arc::new(BlobDriver::new(state.clone()));
    for path in [
        "effect://blob/write",
        "effect://blob/read",
        "effect://blob/delete",
    ] {
        register_single_effect(boot, path, BLOB_METHODS, blob.clone())?;
    }
    let time: Arc<dyn Driver> = Arc::new(TimeDriver);
    for path in [
        "effect://time/now",
        "effect://time/sleep",
        "effect://time/cron",
    ] {
        register_single_effect(boot, path, TIME_METHODS, time.clone())?;
    }
    let approval: Arc<dyn Driver> = Arc::new(ApprovalDriver::new(state.clone()));
    for path in [
        "effect://approval/ask",
        "effect://approval/check",
        "effect://approval/respond",
    ] {
        register_single_effect(boot, path, APPROVAL_METHODS, approval.clone())?;
    }
    let events: Arc<dyn Driver> = Arc::new(EventBusDriver::new(state.clone()));
    for path in ["effect://events/publish", "effect://events/subscribe"] {
        register_single_effect(boot, path, EVENTS_METHODS, events.clone())?;
    }
    let lock: Arc<dyn Driver> = Arc::new(LockDriver::new(state.clone()));
    for path in ["effect://lock/acquire", "effect://lock/release"] {
        register_single_effect(boot, path, LOCK_METHODS, lock.clone())?;
    }
    register_single_effect(
        boot,
        "effect://deliberation/run",
        DELIBERATION_METHODS,
        Arc::new(DeliberationDriver::new(Arc::new(EchoBackend))),
    )?;
    // Fact reads use a capability-gated, read-only state://fact/* projection.
    boot.register_subtree_resource_at(
        "state://fact",
        "read://state/fact/**",
        nexus_types::InterfaceFamily::Sequence,
        FACT_METHODS,
        Arc::new(FactDriver::new(boot.kernel.facts.store().clone())),
    )?;
    register_single_effect(
        boot,
        "effect://kernel/process/inspect",
        INSPECT_METHODS,
        Arc::new(KernelInspectDriver::new(
            boot.kernel.processes.clone(),
            boot.kernel.facts.clone(),
        )),
    )?;
    // Expose the vector index as effect Resources.
    let index_driver: Arc<dyn Driver> = index.clone();
    for path in [
        "effect://index/upsert",
        "effect://index/search",
        "effect://index/delete",
    ] {
        register_single_effect(boot, path, INDEX_METHODS, index_driver.clone())?;
    }
    let rank_driver: Arc<dyn Driver> = rank.clone();
    for path in ["effect://rank/score", "effect://rank/fuse"] {
        register_single_effect(boot, path, RANK_METHODS, rank_driver.clone())?;
    }
    // / Token Compressor: model-backed summarize + structural plan trim.
    let compress: Arc<dyn Driver> =
        Arc::new(crate::compress::CompressDriver::new(Arc::new(EchoBackend)));
    for path in ["effect://compress/summarize", "effect://compress/trim-plan"] {
        register_single_effect(
            boot,
            path,
            crate::compress::COMPRESS_METHODS,
            compress.clone(),
        )?;
    }
    // Register the content-addressed tensor store.
    let tensor: Arc<dyn Driver> = Arc::new(crate::tensor::TensorDriver::new(state.clone()));
    for path in [
        "effect://tensor/write",
        "effect://tensor/read",
        "effect://tensor/delete",
    ] {
        register_single_effect(boot, path, crate::tensor::TENSOR_METHODS, tensor.clone())?;
    }
    // Register the external process-lifecycle driver.
    let proc: Arc<dyn Driver> = Arc::new(crate::proc::ProcDriver::new(state.clone()));
    for path in [
        "effect://proc/spawn",
        "effect://proc/kill",
        "effect://proc/signal",
        "effect://proc/status",
        "effect://proc/heartbeat",
    ] {
        register_single_effect(boot, path, crate::proc::PROC_METHODS, proc.clone())?;
    }
    // Register external pairing management as capability-scoped effects.
    let pairing: Arc<dyn Driver> = Arc::new(PairingDriver::with_display_edge(
        state.clone(),
        config.pairing_display.clone(),
    ));
    for path in [
        "effect://external/pairing/create",
        "effect://external/pairing/approve",
        "effect://external/pairing/deny",
        "effect://external/pairing/replace",
        "effect://external/revoke",
    ] {
        register_single_effect(boot, path, PAIRING_METHODS, pairing.clone())?;
    }
    // Register layered context assembly under a token budget.
    register_single_effect(
        boot,
        "effect://context/assemble",
        crate::context::CONTEXT_METHODS,
        Arc::new(crate::context::ContextDriver::new()),
    )?;

    // Expose `state://**` as one Resource so a Process reads and writes durable
    // state through Value/Sequence Operations, with taint persisted
    // and capability checks applied uniformly.
    boot.register_subtree_resource(
        "state",
        nexus_types::InterfaceFamily::Value,
        crate::state::STATE_METHODS,
        Arc::new(crate::state::StateDriver::new(state.clone())),
    )?;

    if let Some(root) = &config.fs_root {
        let fs: Arc<dyn Driver> = Arc::new(crate::fs::FsDriver::new(root.clone(), state.clone()));
        for path in [
            "effect://fs/read",
            "effect://fs/write",
            "effect://fs/list",
            "effect://fs/delete",
            "effect://fs/glob",
        ] {
            register_single_effect(boot, path, crate::fs::FS_METHODS, fs.clone())?;
        }
    }
    if !config.terminal_allowlist.is_empty() {
        register_single_effect(
            boot,
            "effect://terminal/run",
            crate::terminal::TERMINAL_METHODS,
            Arc::new(crate::terminal::TerminalDriver::new(
                config.terminal_allowlist.clone(),
            )),
        )?;
    }
    if config.enable_fetch {
        register_single_effect(
            boot,
            "effect://fetch/get",
            crate::fetch::FETCH_METHODS,
            Arc::new(crate::fetch::FetchDriver::new(state.clone())),
        )?;
    }
    // Mount each configured MCP tool as a sandboxed Provider at
    // `effect://external-provider/<server>/<tool>`.
    for mount in &config.mcp_tools {
        register_mcp_tool(
            boot,
            &mount.server,
            &mount.tool,
            mount.streaming,
            Arc::new(crate::mcp::EchoMcpClient),
        )?;
    }
    Ok(())
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

/// Register one MCP tool as a sandboxed Provider at
/// `effect://external-provider/<server>/<tool>`. Each tool call is an Operation, so
/// taint / audit / budget apply. `client` supplies the MCP transport:
/// [`crate::mcp::EchoMcpClient`] for tests, or a stdio/SSE client for live
/// integrations.
pub fn register_mcp_tool(
    boot: &Bootstrap,
    server: &str,
    tool: &str,
    streaming: bool,
    client: Arc<dyn crate::mcp::McpClient>,
) -> Result<nexus_types::ResourceName, InstallError> {
    validate_mcp_path_segment("server", server)?;
    validate_mcp_path_segment("tool", tool)?;
    // Every MCP effect lives under the sandbox prefix
    // `effect://external-provider/<id>/*`.
    let path = format!("effect://external-provider/{server}/{tool}");
    Ok(boot.register_effect(
        &path,
        if streaming {
            MCP_STREAM_TOOL_METHODS
        } else {
            MCP_TOOL_METHODS
        },
        Arc::new(McpToolDriver::new(tool, client)),
    )?)
}

fn validate_mcp_path_segment(label: &'static str, segment: &str) -> Result<(), InstallError> {
    if segment.is_empty() || segment.contains('/') || segment.contains('@') {
        return Err(InstallError::InvalidMcpPathSegment {
            label,
            segment: segment.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_graph::{DoNode, OperationTemplate};
    use nexus_types::{Outcome, OutputMode, Value};

    #[tokio::test]
    async fn standard_inference_runs_end_to_end() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let name = boot
            .kernel
            .registry
            .resolve_resource(&nexus_types::ResourceName::new(
                nexus_types::Path::parse("effect://inference/infer").unwrap(),
            ))
            .map(|_| {
                nexus_types::ResourceName::new(
                    nexus_types::Path::parse("effect://inference/infer").unwrap(),
                )
            })
            .unwrap();
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);

        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hello".into())),
        });
        let out = ex.eval(&prog).await;
        assert!(matches!(out, Outcome::Done(Value::Str(_))));
    }

    #[tokio::test]
    async fn state_read_write_as_operations() {
        // A Process writes then reads `state://memory/note` through
        // Operations against the prefix-resolved state Resource.
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let target = nexus_types::ResourceName::new(
            nexus_types::Path::parse("state://scratch/note").unwrap(),
        );
        // open_for prefix-resolves to the `state://` subtree Resource; read and
        // write are distinct method rights.
        let write_handle = boot.open_for(boot.root, &target, "write").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(target.clone(), write_handle);

        // write (method 1).
        let write = DoNode::Op(OperationTemplate {
            target: target.clone(),
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hello-state".into())),
        });
        assert_eq!(ex.eval(&write).await, Outcome::Done(Value::Bool(true)));

        let read_handle = boot.open_for(boot.root, &target, "read").unwrap();
        ex.bind_handle(target.clone(), read_handle);

        // read (method 0) returns what we wrote.
        let read = DoNode::Op(OperationTemplate {
            target,
            method: "read".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        assert_eq!(
            ex.eval(&read).await,
            Outcome::Done(Value::Str("hello-state".into()))
        );
    }

    #[tokio::test]
    async fn state_write_persists_taint() {
        // A write carrying untrusted-content taint persists that taint in the
        // backend envelope; provenance is not dropped at the state boundary.
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let target = nexus_types::ResourceName::new(
            nexus_types::Path::parse("state://scratch/tainted").unwrap(),
        );
        let handle = boot.open_for(boot.root, &target, "write").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(target.clone(), handle);

        // An Acting/inbound-tainted program: write a value derived from inbound
        // taint. We use eval_tainted to seed the entry taint.
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
        ex.eval_tainted(&write, entry_taint).await;

        // The persisted value carries the taint (read it straight from the
        // backend to inspect provenance).
        let tv = boot
            .kernel
            .state
            .read_tainted(target.path())
            .await
            .unwrap()
            .expect("value present");
        assert!(
            tv.taint.has_untrusted_content(),
            "taint persisted with the value"
        );
    }

    #[tokio::test]
    async fn state_read_handle_cannot_write() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let target = nexus_types::ResourceName::new(
            nexus_types::Path::parse("state://scratch/read-only").unwrap(),
        );
        let read_handle = boot.open_for(boot.root, &target, "read").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(target.clone(), read_handle);

        let write = DoNode::Op(OperationTemplate {
            target,
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("must-not-write".into())),
        });
        assert!(matches!(
            ex.eval(&write).await,
            Outcome::Fail(nexus_types::Failure::PermissionDenied { .. })
        ));
    }

    #[tokio::test]
    async fn fact_read_side_is_state_projection_not_effect_alias() {
        // Fact reads use a capability-gated state://fact/* projection, not a
        // callable effect alias.
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let fact_effect =
            nexus_types::ResourceName::new(nexus_types::Path::parse("effect://fact/read").unwrap());
        assert!(
            boot.kernel.registry.resolve_resource(&fact_effect).is_err(),
            "Fact read side must not be exposed as effect://fact/read"
        );

        let fact_path = nexus_types::ResourceName::new(
            nexus_types::Path::parse(&format!("state://fact/{}", boot.root.get())).unwrap(),
        );
        let handle = boot.open_for(boot.root, &fact_path, "read").unwrap();
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
            other => panic!("expected fact projection list, got {other:?}"),
        }

        let global_fact_path =
            nexus_types::ResourceName::new(nexus_types::Path::parse("state://fact").unwrap());
        let handle = boot.open_for(boot.root, &global_fact_path, "read").unwrap();
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
            other => panic!("expected global fact projection list, got {other:?}"),
        }

        let vault = nexus_types::ResourceName::new(
            nexus_types::Path::parse("state://vault/console/root/password").unwrap(),
        );
        let err = boot.open_for(boot.root, &vault, "read").unwrap_err();
        assert!(matches!(err, nexus_kernel::OpenError::ReservedPath(_)));
    }

    #[tokio::test]
    async fn mcp_tools_are_off_by_default() {
        // With no `mcp_tools`, no `effect://external-provider/*` resource is registered;
        // existing assemblies are unaffected.
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());
        let name = nexus_types::ResourceName::new(
            nexus_types::Path::parse("effect://external-provider/files/list_dir").unwrap(),
        );
        assert!(
            boot.kernel.registry.resolve_resource(&name).is_err(),
            "no MCP resource without explicit config"
        );
    }

    #[tokio::test]
    async fn registered_mcp_tool_resolves_and_invokes_end_to_end() {
        // A configured MCP tool is reachable through the standard
        // open/bind/eval path, backed offline by EchoMcpClient.
        let boot = Bootstrap::in_memory();
        let config = StandardConfig {
            mcp_tools: vec![McpToolMount::new("files", "list_dir")],
            ..Default::default()
        };
        assert!(install_standard(&boot, &config).is_ok());

        let name = nexus_types::ResourceName::new(
            nexus_types::Path::parse("effect://external-provider/files/list_dir").unwrap(),
        );
        // Resolvable under its sandbox prefix.
        assert!(
            boot.kernel.registry.resolve_resource(&name).is_ok(),
            "MCP resource resolvable"
        );
        let aggregate_call = nexus_types::ResourceName::new(
            nexus_types::Path::parse("effect://external-provider/files/call").unwrap(),
        );
        assert!(
            boot.kernel
                .registry
                .resolve_resource(&aggregate_call)
                .is_err(),
            "aggregate /call resource must not be registered"
        );

        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);

        // Invoke the concrete tool's `invoke` method. The tool name comes from
        // the registered Resource, not caller-controlled input.
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("/tmp".into())),
        });
        match ex.eval(&prog).await {
            Outcome::Done(Value::Map(m)) => {
                assert_eq!(m.get("tool").and_then(|v| v.as_str()), Some("list_dir"));
                assert_eq!(m.get("echo"), Some(&Value::Str("/tmp".into())));
            }
            other => panic!("expected echo map from MCP tool, got {other:?}"),
        }
    }

    #[test]
    fn mcp_tool_registration_rejects_bad_path_segments() {
        let boot = Bootstrap::in_memory();
        assert!(
            register_mcp_tool(
                &boot,
                "files/../../x",
                "list_dir",
                false,
                Arc::new(crate::mcp::EchoMcpClient),
            )
            .is_err()
        );
        assert!(
            register_mcp_tool(
                &boot,
                "files",
                "list/dir",
                false,
                Arc::new(crate::mcp::EchoMcpClient),
            )
            .is_err()
        );
    }

    #[test]
    fn batchable_methods_are_registered_as_metadata() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        assert_method_batchable(&boot, "effect://inference/infer", "invoke", false);
        assert_method_batchable(&boot, "effect://inference/embed", "invoke", true);
        assert_method_batchable(&boot, "effect://inference/rerank", "invoke", true);
        assert_method_batchable(&boot, "effect://index/upsert", "invoke", true);
    }

    #[test]
    fn external_observation_methods_are_registered_as_observation_replay() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        assert_method_replay(
            &boot,
            "state://fact/1",
            "read",
            nexus_types::ReplayClass::Observation,
        );
        assert_method_replay(
            &boot,
            "effect://time/now",
            "invoke",
            nexus_types::ReplayClass::Observation,
        );
        assert_method_replay(
            &boot,
            "effect://approval/check",
            "invoke",
            nexus_types::ReplayClass::Observation,
        );
        assert_method_replay(
            &boot,
            "effect://blob/read",
            "invoke",
            nexus_types::ReplayClass::Observation,
        );
        assert_method_replay(
            &boot,
            "effect://memory/recall",
            "invoke",
            nexus_types::ReplayClass::Observation,
        );
        assert_method_replay(
            &boot,
            "effect://rank/score",
            "invoke",
            nexus_types::ReplayClass::Observation,
        );
        assert_method_replay(
            &boot,
            "effect://rank/fuse",
            "invoke",
            nexus_types::ReplayClass::Deterministic,
        );
    }

    #[test]
    fn external_pairing_effects_are_registered_as_distinct_resources() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        for path in [
            "effect://external/pairing/create",
            "effect://external/pairing/approve",
            "effect://external/pairing/deny",
            "effect://external/pairing/replace",
            "effect://external/revoke",
        ] {
            let name = nexus_types::ResourceName::new(nexus_types::Path::parse(path).unwrap());
            assert!(
                boot.kernel.registry.resolve_resource(&name).is_ok(),
                "{path} should resolve"
            );
            assert_method_replay(
                &boot,
                path,
                "invoke",
                nexus_types::ReplayClass::NonIdempotentEffect,
            );
        }
    }

    #[tokio::test]
    async fn standard_effect_paths_do_not_accept_sibling_methods() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let name = nexus_types::ResourceName::new(
            nexus_types::Path::parse("effect://approval/ask").unwrap(),
        );
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);

        let sibling_check_on_ask = DoNode::Op(OperationTemplate {
            target: name,
            method: "check".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        assert!(matches!(
            ex.eval(&sibling_check_on_ask).await,
            Outcome::Fail(nexus_types::Failure::NoHandler { .. })
        ));

        let blob_unref = nexus_types::ResourceName::new(
            nexus_types::Path::parse("effect://blob/unref").unwrap(),
        );
        assert!(
            boot.kernel.registry.resolve_resource(&blob_unref).is_err(),
            "blob unref alias must not be registered"
        );
    }

    #[tokio::test]
    async fn pairing_secret_is_not_an_operation_input() {
        let boot = Bootstrap::in_memory();
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());

        let name = nexus_types::ResourceName::new(
            nexus_types::Path::parse("effect://external/pairing/create").unwrap(),
        );
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
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
        assert!(matches!(
            out,
            Outcome::Fail(nexus_types::Failure::InvalidInput { .. })
        ));

        let facts = boot.kernel.facts.all_facts().unwrap();
        assert_eq!(facts.len(), 1);
        let Some(Value::Map(input)) = facts[0].input_ref.as_inline() else {
            panic!("expected inline redacted input");
        };
        assert_eq!(
            input.get("pairing_secret"),
            Some(&Value::Str("<redacted>".into()))
        );
        assert!(
            !input
                .values()
                .any(|v| v == &Value::Str("old-secret".into()))
        );
    }

    fn assert_method_batchable(boot: &Bootstrap, path: &str, method: &str, expected: bool) {
        let name = nexus_types::ResourceName::new(nexus_types::Path::parse(path).unwrap());
        let rid = boot.kernel.registry.resolve_resource(&name).unwrap();
        let resource = boot.kernel.registry.resource(rid).unwrap();
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
        assert_eq!(
            actual.unwrap_or_else(|| panic!("method {method} not registered on {path}")),
            expected,
            "{path}.{method}"
        );
    }

    fn assert_method_replay(
        boot: &Bootstrap,
        path: &str,
        method: &str,
        expected: nexus_types::ReplayClass,
    ) {
        let name = nexus_types::ResourceName::new(nexus_types::Path::parse(path).unwrap());
        let rid = boot.kernel.registry.resolve_resource(&name).unwrap();
        let resource = boot.kernel.registry.resource(rid).unwrap();
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
        assert_eq!(
            actual.unwrap_or_else(|| panic!("method {method} not registered on {path}")),
            expected,
            "{path}.{method}"
        );
    }
}
