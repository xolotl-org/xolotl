use super::*;
use crate::inference::{InferenceBackend, ModelCapabilities};
use crate::router::{ModelEntry, Router};
use anyhow::{Context, bail, ensure};
use xolotl_graph::{DoNode, OperationTemplate};
use xolotl_types::{
    EffectCapability, InProcessProjectionDef, Outcome, OutputMode, Purity, ResourceAddressing,
    ResourceKind, Value,
};

#[cfg(feature = "terminal")]
#[tokio::test]
async fn terminal_install_requires_host_runtime_and_rejects_pseudo_approval_config()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let mut def = InProcessProjectionDef {
        id: "terminal".into(),
        role: Role::Provider,
        implementation: "standard.terminal".into(),
        provides: vec![EffectCapability::new(
            "effect://terminal/run",
            Purity::Effectful,
        )],
        emits: None,
        config: Value::map(std::collections::BTreeMap::from([(
            "allowlist".into(),
            Value::list(vec![Value::string("echo".into())]),
        )])),
        version: 1,
    };
    ensure!(matches!(
        install_decoded_in_process_projection(&boot, &def, &StandardConfig::default()),
        Err(InstallError::Assembly { .. })
    ));
    let runtime = crate::TerminalRuntime::default();
    let config = StandardConfig::default().with_terminal_runtime(runtime.clone());
    let mut fields = def.config.clone().into_map().context("config map")?;
    fields.insert(
        "high_risk".into(),
        Value::list(vec![Value::string("echo".into())]),
    )?;
    def.config = Value::from(fields);
    ensure!(install_decoded_in_process_projection(&boot, &def, &config).is_err());
    let mut fields = def.config.into_map().context("config map")?;
    fields.remove("high_risk");
    def.config = Value::from(fields);
    install_decoded_in_process_projection(&boot, &def, &config)?;
    runtime.close();
    install_decoded_in_process_projection(&boot, &def, &config)?;
    let result = run_standard_effect(
        &boot,
        "effect://terminal/run",
        Value::map(std::collections::BTreeMap::from([(
            "command".into(),
            Value::string("echo".into()),
        )])),
    )
    .await?;
    ensure!(
        matches!(result, Outcome::Fail(ref failure) if failure.to_string().contains("closed")),
        "reinstall replaced host lifecycle: {result:?}"
    );
    runtime.shutdown().await;
    Ok(())
}

#[cfg(all(feature = "terminal", unix))]
#[tokio::test]
async fn installed_terminal_timeout_retains_original_identity_even_when_handled()
-> anyhow::Result<()> {
    use xolotl_graph::portable::{Expression, Program};
    use xolotl_types::{Failure, ReplayClass, TaintedValue};
    let boot = Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
            .with_fact_sink(xolotl_kernel::FactSink::new(Arc::new(
                xolotl_kernel::InMemoryFactStore::new(),
            )))
            .build(),
    );
    let runtime = crate::TerminalRuntime::default();
    let config = StandardConfig::default().with_terminal_runtime(runtime.clone());
    let def = InProcessProjectionDef {
        id: "terminal".into(),
        role: Role::Provider,
        implementation: "standard.terminal".into(),
        provides: vec![EffectCapability::new(
            "effect://terminal/run",
            Purity::Effectful,
        )],
        emits: None,
        version: 1,
        config: Value::map(std::collections::BTreeMap::from([(
            "allowlist".into(),
            Value::list(vec![Value::string("sh".into())]),
        )])),
    };
    install_decoded_in_process_projection(&boot, &def, &config)?;
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("effects");
    let target = resource_name("effect://terminal/run")?;
    let handle = boot.open_for(boot.root(), &target, "perform")?;
    let executor = boot
        .kernel()
        .executor_for(boot.root())
        .with_fact_recording(true);
    executor.bind_handle(target.clone(), handle)?;
    for (index, handled) in [false, true].into_iter().enumerate() {
        let operation = OperationTemplate {
            target: target.clone(),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::map(std::collections::BTreeMap::from([
                ("command".into(), Value::string("sh".into())),
                ("timeout_ms".into(), Value::integer(100)),
                (
                    "args".into(),
                    Value::list(vec![
                        Value::string("-c".into()),
                        Value::string("printf x >> \"$1\"; exec sleep 30".into()),
                        Value::string("terminal-effect".into()),
                        Value::string(marker.display().to_string()),
                    ]),
                ),
            ]))),
        };
        let invocation = Expression::Invoke { operation };
        let expression = if handled {
            Expression::Catch {
                body: Box::new(invocation),
                recover: Box::new(Expression::literal(true)),
            }
        } else {
            invocation
        };
        let compiled = Program::new(expression).compile()?;
        let output = executor
            .eval_program(&compiled, TaintedValue::pristine(Value::null()))
            .await;
        let facts = boot.kernel().facts().facts_of(boot.root())?;
        ensure!(facts.len() == index + 1, "timeout was replayed");
        let original = facts.last().context("original dispatched operation")?.id;
        ensure!(facts.iter().all(|fact| fact.replay == ReplayClass::NonIdempotentEffect && fact.id.attempt == 0));
        ensure!(output.unresolved_operations.operation_ids == vec![original.to_string()]);
        ensure!(!output.unresolved_operations.identities_incomplete);
        if handled {
            ensure!(output.outcome == Outcome::Done(Value::boolean(true)));
        } else {
            ensure!(
                matches!(output.outcome, Outcome::Fail(Failure::OutcomeUnknown { operation_ids, reason })
                if operation_ids == vec![original.to_string()] && reason.contains("timeout_ms"))
            );
        }
        ensure!(
            std::fs::read(&marker)?.len() == index + 1,
            "effect missing or replayed"
        );
    }
    runtime.shutdown().await;
    Ok(())
}

#[test]
fn memory_consolidation_defaults_and_host_limits() {
    let defaults = StandardConfig::default();
    assert_eq!(defaults.memory_consolidation.records.get(), 1024);
    assert_eq!(
        defaults.memory_consolidation.encoded_bytes.get(),
        16 * 1024 * 1024
    );
    assert_eq!(
        defaults.memory_consolidation.text_bytes.get(),
        4 * 1024 * 1024
    );
    let configured = defaults.with_memory_consolidation_limits(
        std::num::NonZeroUsize::MIN.saturating_add(6),
        std::num::NonZeroUsize::MIN.saturating_add(2047),
        std::num::NonZeroUsize::MIN.saturating_add(511),
    );
    assert_eq!(configured.memory_consolidation.records.get(), 7);
    assert_eq!(configured.memory_consolidation.encoded_bytes.get(), 2048);
    assert_eq!(configured.memory_consolidation.text_bytes.get(), 512);
}

#[tokio::test]
async fn installed_memory_honors_host_consolidation_admission() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let config = StandardConfig::default()
        .with_inference_backend(Arc::new(crate::EchoBackend))
        .with_memory_consolidation_limits(
            std::num::NonZeroUsize::new(1).context("positive record limit")?,
            std::num::NonZeroUsize::new(16 * 1024 * 1024).context("positive encoded limit")?,
            std::num::NonZeroUsize::new(4 * 1024 * 1024).context("positive text limit")?,
        );
    install_standard(&boot, &config)?;
    for id in ["a", "b"] {
        let input = Value::map(std::collections::BTreeMap::from([
            ("owner".into(), Value::string("bounded".into())),
            ("id".into(), Value::string(id.into())),
            ("content".into(), Value::string("coffee morning".into())),
        ]));
        let outcome = run_standard_effect(&boot, "effect://memory/store", input).await?;
        ensure!(
            matches!(&outcome, Outcome::Done(_)),
            "memory fixture store failed: {outcome:?}"
        );
    }
    let outcome = run_standard_effect(
        &boot,
        "effect://memory/consolidate",
        Value::map(std::collections::BTreeMap::from([(
            "owner".into(),
            Value::string("bounded".into()),
        )])),
    )
    .await?;
    ensure!(
        matches!(outcome, Outcome::Fail(ref failure) if failure.to_string().contains("record limit"))
    );
    let page = boot
        .kernel()
        .state()
        .query(&xolotl_state::StateScan::new(Path::parse(
            "state://memory/bounded/general",
        )?))
        .await?;
    ensure!(page.entries.len() == 2 && page.next.is_none());
    Ok(())
}

struct StaticBackend;

#[async_trait::async_trait]
impl InferenceBackend for StaticBackend {
    async fn infer(&self, _input: &Value) -> Result<Value, String> {
        Ok(Value::string("configured-router".into()))
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

fn resource_name(path: &str) -> anyhow::Result<xolotl_types::ResourceName> {
    xolotl_types::Path::parse(path)
        .map(xolotl_types::ResourceName::new)
        .with_context(|| format!("parse resource name {path}"))
}

fn install_default(boot: &Bootstrap) -> anyhow::Result<()> {
    install_standard(boot, &StandardConfig::default()).context("install standard package")
}

#[test]
fn standard_state_and_effects_have_explicit_addressing() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let modules = StandardModules::state_only().with(StandardModule::Time);
    install_standard(&boot, &StandardConfig::default().with_modules(modules))?;
    let registry = boot.kernel().registry();

    let state = registry.resolve_resource(&resource_name("state://")?)?;
    ensure!(
        registry.resolve_resource(&resource_name("state://app/profile")?)? == state,
        "state descendants should resolve through the State Resource"
    );
    let state = registry
        .resource(state)
        .context("installed State Resource")?;
    ensure!(state.descriptor.kind == ResourceKind::State);
    ensure!(state.descriptor.addressing == ResourceAddressing::Prefix);

    let effect = registry.resolve_resource(&resource_name("effect://time/now")?)?;
    let effect = registry
        .resource(effect)
        .context("installed Time Resource")?;
    ensure!(effect.descriptor.kind == ResourceKind::Effect);
    ensure!(effect.descriptor.addressing == ResourceAddressing::Exact);
    ensure!(
        registry
            .resolve_resource(&resource_name("effect://time/now/child")?)
            .is_err(),
        "standard effects should not implicitly serve descendants"
    );
    Ok(())
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
        config: Value::null(),
        version: 1,
    }
}

#[cfg(not(feature = "fetch"))]
#[test]
fn in_process_projection_declaration_fails_when_feature_is_absent() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    install_default(&boot)?;
    let err = match install_decoded_in_process_projection(
        &boot,
        &fetch_projection_def(),
        &StandardConfig::default(),
    ) {
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
    install_decoded_in_process_projection(&boot, &def, &StandardConfig::default())
        .context("install fetch projection")?;
    let name = resource_name("effect://fetch/get")?;
    let first = boot
        .kernel()
        .registry()
        .resolve_resource(&name)
        .map_err(|error| anyhow::anyhow!("{error:?}"))
        .context("resolve first fetch resource")?;

    install_decoded_in_process_projection(&boot, &def, &StandardConfig::default())
        .context("reinstall fetch projection")?;
    let second = boot
        .kernel()
        .registry()
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
    install_decoded_in_process_projection(&boot, &def, &StandardConfig::default())
        .context("install fetch projection")?;

    let mut duplicate = fetch_projection_def();
    duplicate.id = "other_fetch".into();
    let err = match install_decoded_in_process_projection(
        &boot,
        &duplicate,
        &StandardConfig::default(),
    ) {
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
fn in_process_projection_requires_an_exact_local_declaration_path() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    for path in [
        "path://remote/state/kernel/projections/in-process/fetch",
        "state://kernel/projections/in-process/fetch.bad",
        "state://kernel/projections/in-process/fetch/child",
    ] {
        let err = match install_in_process_projection_value(
            &boot,
            &Path::parse(path)?,
            Value::null(),
            &StandardConfig::default(),
        ) {
            Ok(_) => bail!("invalid declaration path {path} was unexpectedly accepted"),
            Err(error) => error,
        };
        ensure!(
            matches!(err, InstallError::Declaration { .. }),
            "unexpected path error for {path}: {err:?}"
        );
    }
    Ok(())
}

async fn run_standard_inference(boot: &Bootstrap) -> anyhow::Result<Outcome> {
    run_standard_effect(
        boot,
        "effect://inference/infer",
        Value::string("hello".into()),
    )
    .await
}

async fn run_standard_effect(
    boot: &Bootstrap,
    path: &str,
    input: Value,
) -> anyhow::Result<Outcome> {
    run_standard_effect_with_fact_recording(boot, path, input, false).await
}

async fn run_standard_effect_with_fact_recording(
    boot: &Bootstrap,
    path: &str,
    input: Value,
    record: bool,
) -> anyhow::Result<Outcome> {
    let name = resource_name(path)?;
    boot.kernel()
        .registry()
        .resolve_resource(&name)
        .map_err(|error| anyhow::anyhow!("{error:?}"))
        .with_context(|| format!("resolve resource {path}"))?;
    let handle = boot
        .open_for(boot.root(), &name, "perform")
        .map_err(|error| anyhow::anyhow!("{error:?}"))
        .with_context(|| format!("open resource {path}"))?;
    let ex = boot
        .kernel()
        .executor_for(boot.root())
        .with_fact_recording(record);
    ex.bind_handle(name.clone(), handle)?;

    let prog = DoNode::Op(OperationTemplate {
        target: name,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(input),
    });
    Ok(ex.eval(&prog).await.outcome)
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
        matches!(out, Outcome::Done(ref value) if value.as_str().is_some()),
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
        .open_for(boot.root(), &name, "perform")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_handle(name.clone(), handle)?;
    let out = ex
        .eval(&DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::string("hello".into())),
        }))
        .await;
    ensure!(
        matches!(out.outcome, Outcome::Done(ref value) if value.as_str() == Some("configured-router")),
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
        matches!(out, Outcome::Done(ref value) if value.as_str() == Some("configured-router")),
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
    deliberation_input.insert("question".into(), Value::string("choose".into()));
    deliberation_input.insert("panelists".into(), Value::integer(1));
    let deliberation = run_standard_effect(
        &boot,
        "effect://deliberation/run",
        Value::map(deliberation_input),
    )
    .await?;
    ensure!(
        matches!(deliberation, Outcome::Done(ref value) if value.as_map().and_then(|map| map.get("answer"))
            .and_then(Value::as_str)
            == Some("configured-router")),
        "expected deliberation to use host backend, got {deliberation:?}"
    );

    let mut compress_input = std::collections::BTreeMap::new();
    compress_input.insert("text".into(), Value::string("word ".repeat(500)));
    compress_input.insert("max_tokens".into(), Value::integer(1));
    let compress = run_standard_effect(
        &boot,
        "effect://compress/summarize",
        Value::map(compress_input),
    )
    .await?;
    ensure!(
        matches!(compress, Outcome::Done(ref value) if value.as_map().and_then(|map| map.get("summary"))
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

    boot.kernel()
        .registry()
        .resolve_resource(&resource_name("state://scratch/value")?)
        .map_err(|error| anyhow::anyhow!("{error:?}"))
        .context("state resource should resolve")?;
    let time = boot
        .kernel()
        .registry()
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
        .open_for(boot.root(), &target, "write")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_handle(target.clone(), write_handle)?;

    let write = DoNode::Op(OperationTemplate {
        target: target.clone(),
        method: "write".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::string("hello-state".into())),
    });
    let written = ex.eval(&write).await.outcome;
    ensure!(
        written == Outcome::Done(Value::boolean(true)),
        "state write outcome: {written:?}"
    );

    let read_handle = boot
        .open_for(boot.root(), &target, "read")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    ex.bind_handle(target.clone(), read_handle)?;

    let read = DoNode::Op(OperationTemplate {
        target,
        method: "read".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::null()),
    });
    let read_out = ex.eval(&read).await.outcome;
    ensure!(
        read_out == Outcome::Done(Value::string("hello-state".into())),
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
        .open_for(boot.root(), &target, "write")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_handle(target.clone(), handle)?;

    let write = DoNode::Op(OperationTemplate {
        target: target.clone(),
        method: "write".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::string("from-the-web".into())),
    });
    let entry_taint = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Fetched {
        host: "evil.example".into(),
    });
    let outcome = ex.eval_tainted(&write, entry_taint).await.outcome;
    ensure!(
        outcome == Outcome::Done(Value::boolean(true)),
        "tainted write outcome: {outcome:?}"
    );

    let tv = boot
        .kernel()
        .state()
        .read_tainted(target.path())
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(tv.value.is_some(), "expected tainted value to be present");
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
        .open_for(boot.root(), &target, "read")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_method_handle(target.clone(), "read", read_handle)?;
    let target_path = target.path().clone();

    let write = DoNode::Op(OperationTemplate {
        target,
        method: "write".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::string("lazy-write".into())),
    });
    let out = ex.eval(&write).await.outcome;
    ensure!(
        out == Outcome::Done(Value::boolean(true)),
        "root should lazy-open a write handle when it has write grant: {out:?}"
    );
    let persisted = boot.kernel().state().read(&target_path).await?;
    ensure!(
        persisted == Some(Value::string("lazy-write".into())),
        "lazy write did not persist: {persisted:?}"
    );
    Ok(())
}

#[tokio::test]
async fn state_collection_grant_is_distinct_from_descendant_point_read_authority()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    install_standard(
        &boot,
        &StandardConfig::default().with_modules(StandardModules::state_only()),
    )?;
    let collection = resource_name("state://collection")?;
    let descendant = resource_name("state://collection/a")?;
    let neighbor = resource_name("state://collection-neighbor/b")?;
    boot.kernel()
        .state()
        .write_set(descendant.path(), Value::integer(1))
        .await?;
    boot.kernel()
        .state()
        .write_set(neighbor.path(), Value::integer(2))
        .await?;
    let child = boot.spawn_request_process_under_with_request_grants(
        boot.root(),
        xolotl_types::IdentityRef::ROOT,
        &[RequestGrantTemplate {
            literal: "read://state/collection",
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::names(["read", "list"]),
                xolotl_types::RightFlags::empty(),
            ),
        }],
    )?;
    ensure!(boot.open_for(child, &descendant, "read").is_err());
    ensure!(boot.open_for(child, &neighbor, "list").is_err());
    let executor = boot.kernel().executor_for(child);
    let list = |input| {
        DoNode::Op(OperationTemplate {
            target: collection.clone(),
            method: "list".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        })
    };
    let Outcome::Done(value) = executor.eval(&list(Value::null())).await.outcome else {
        bail!("collection grant did not authorize listing");
    };
    let entries = value
        .as_map()
        .and_then(|fields| fields.get("entries"))
        .and_then(Value::as_list)
        .context("list entries")?;
    ensure!(entries.len() == 1);
    ensure!(
        entries
            .get(0)
            .and_then(Value::as_map)
            .and_then(|fields| fields.get("path"))
            .and_then(Value::as_str)
            == Some("state://collection/a")
    );
    let invalid_cursor = Value::map(std::collections::BTreeMap::from([(
        "cursor".into(),
        Value::bytes(neighbor.path().to_string().into_bytes()),
    )]));
    ensure!(matches!(
        executor.eval(&list(invalid_cursor)).await.outcome,
        Outcome::Fail(_)
    ));
    Ok(())
}

#[tokio::test]
async fn read_only_request_process_cannot_write_state() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    install_default(&boot)?;

    let target = resource_name("state://scratch/read-only")?;
    let child = boot.spawn_request_process_under_with_request_grants(
        boot.root(),
        xolotl_types::IdentityRef::ROOT,
        &[RequestGrantTemplate {
            literal: "read://state/scratch/read-only",
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::names(["read", "list"]),
                xolotl_types::RightFlags::empty(),
            ),
        }],
    )?;
    let read_handle = boot
        .open_for(child, &target, "read")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(child);
    ex.bind_handle(target.clone(), read_handle)?;

    let write = DoNode::Op(OperationTemplate {
        target: target.clone(),
        method: "write".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::string("must-not-write".into())),
    });
    let out = ex.eval(&write).await.outcome;
    ensure!(
        matches!(
            out,
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { .. })
        ),
        "read-only request process accepted write: {out:?}"
    );
    let persisted = boot.kernel().state().read(target.path()).await?;
    ensure!(
        persisted.is_none(),
        "denied write should not persist state: {persisted:?}"
    );
    Ok(())
}

#[tokio::test]
async fn state_root_collection_cannot_expose_reserved_values() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    install_standard(
        &boot,
        &StandardConfig::default().with_modules(StandardModules::state_only()),
    )?;
    for literal in [
        "state://kernel/idempotency/private",
        "state://vault/private",
        "state://fact/private",
    ] {
        boot.kernel()
            .state()
            .write_set(
                &xolotl_types::Path::parse(literal)?,
                Value::string("reserved-content".into()),
            )
            .await?;
    }
    let public = resource_name("state://vaultish/public")?;
    boot.kernel()
        .state()
        .write_set(public.path(), Value::integer(7))
        .await?;
    let child = boot.spawn_request_process_under_with_request_grants(
        boot.root(),
        xolotl_types::IdentityRef::ROOT,
        &[RequestGrantTemplate {
            literal: "read://state/**",
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::names(["read", "list"]),
                xolotl_types::RightFlags::empty(),
            ),
        }],
    )?;
    let executor = boot.kernel().executor_for(child);
    let listing = |target| {
        DoNode::Op(OperationTemplate {
            target,
            method: "list".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::null()),
        })
    };
    let outcome = executor
        .eval(&listing(resource_name("state://")?))
        .await
        .outcome;
    ensure!(
        matches!(outcome, Outcome::Fail(_)),
        "root collection exposed reserved values: {outcome:?}"
    );
    let outcome = executor
        .eval(&listing(resource_name("state://vaultish")?))
        .await
        .outcome;
    ensure!(
        matches!(outcome, Outcome::Done(_)),
        "segment-bound public collection denied: {outcome:?}"
    );
    Ok(())
}

#[tokio::test]
async fn state_driver_cannot_expose_kernel_idempotency_records() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    install_standard(
        &boot,
        &StandardConfig::default().with_modules(StandardModules::state_only()),
    )?;

    let record = resource_name("state://kernel/idemp/forged")?;
    let prefix = resource_name("state://kernel/idemp")?;
    let identity = boot
        .kernel()
        .identities()
        .resolve_or_register(&xolotl_types::Path::parse(
            "identity://standard/idempotency-test",
        )?)?;
    let child = boot.spawn_request_process_under_with_request_grants(
        boot.root(),
        identity,
        &[
            RequestGrantTemplate {
                literal: "read://state/**",
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::names(["read", "list"]),
                    xolotl_types::RightFlags::empty(),
                ),
            },
            RequestGrantTemplate {
                literal: "write://state/**",
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::names(["write", "append", "delete", "compare_set"]),
                    xolotl_types::RightFlags::empty(),
                ),
            },
        ],
    )?;
    let executor = boot.kernel().executor_for(child);
    for (target, method, input) in [
        (record.clone(), "read", Value::null()),
        (record.clone(), "write", Value::string("forged".into())),
        (record.clone(), "delete", Value::null()),
        (prefix, "list", Value::null()),
    ] {
        let program = DoNode::Op(OperationTemplate {
            target,
            method: method.into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        });
        let outcome = executor.eval(&program).await.outcome;
        ensure!(
            matches!(outcome, Outcome::Fail(ref error) if error.to_string().contains("reserved path")),
            "StateDriver {method} reached a kernel idempotency path: {outcome:?}"
        );
    }
    ensure!(
        boot.kernel().state().read(record.path()).await?.is_none(),
        "denied write must not create an idempotency record"
    );
    Ok(())
}

#[tokio::test]
async fn fact_read_side_is_state_projection_not_effect_alias() -> anyhow::Result<()> {
    let boot = Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    );
    install_default(&boot)?;

    let fact_effect = resource_name("effect://fact/read")?;
    ensure!(
        boot.kernel()
            .registry()
            .resolve_resource(&fact_effect)
            .is_err(),
        "Fact read side must not be exposed as effect://fact/read"
    );

    let fact_path = resource_name(&format!("state://fact/{}", boot.root().get()))?;
    let handle = boot
        .open_for(boot.root(), &fact_path, "read")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_handle(fact_path.clone(), handle)?;
    let read = DoNode::Op(OperationTemplate {
        target: fact_path,
        method: "read".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::null()),
    });
    match ex.eval(&read).await.outcome {
        Outcome::Done(value)
            if value
                .as_map()
                .and_then(|page| page.get("items"))
                .and_then(Value::as_list)
                .is_some() => {}
        other => bail!("expected fact projection page, got {other:?}"),
    }

    let global_fact_path = resource_name("state://fact")?;
    let handle = boot
        .open_for(boot.root(), &global_fact_path, "read")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_handle(global_fact_path.clone(), handle)?;
    let read_global = DoNode::Op(OperationTemplate {
        target: global_fact_path,
        method: "read".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::null()),
    });
    match ex.eval(&read_global).await.outcome {
        Outcome::Done(value)
            if value
                .as_map()
                .and_then(|page| page.get("items"))
                .and_then(Value::as_list)
                .is_some() => {}
        other => {
            bail!("expected global fact projection page, got {other:?}");
        }
    }

    let vault = resource_name("state://vault/console/root/password")?;
    let err = boot
        .open_for(boot.root(), &vault, "read")
        .err()
        .context("vault path should be reserved")?;
    ensure!(
        matches!(err, xolotl_kernel::OpenError::ReservedPath(_)),
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
        xolotl_types::ReplayClass::Observation,
    )?;
    assert_method_replay(
        &boot,
        "effect://time/now",
        "invoke",
        xolotl_types::ReplayClass::Observation,
    )?;
    assert_method_replay(
        &boot,
        "effect://approval/check",
        "invoke",
        xolotl_types::ReplayClass::Observation,
    )?;
    assert_method_replay(
        &boot,
        "effect://blob/read",
        "invoke",
        xolotl_types::ReplayClass::Observation,
    )?;
    assert_method_replay(
        &boot,
        "effect://memory/recall",
        "invoke",
        xolotl_types::ReplayClass::Observation,
    )?;
    assert_method_replay(
        &boot,
        "effect://rank/score",
        "invoke",
        xolotl_types::ReplayClass::Observation,
    )?;
    assert_method_replay(
        &boot,
        "effect://rank/fuse",
        "invoke",
        xolotl_types::ReplayClass::Deterministic,
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
        "effect://external/revoke",
    ] {
        let name = resource_name(path)?;
        ensure!(
            boot.kernel().registry().resolve_resource(&name).is_ok(),
            "{path} should resolve"
        );
        assert_method_replay(
            &boot,
            path,
            "invoke",
            xolotl_types::ReplayClass::NonIdempotentEffect,
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
        .open_for(boot.root(), &name, "perform")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot.kernel().executor_for(boot.root());
    ex.bind_handle(name.clone(), handle)?;

    let sibling_check_on_ask = DoNode::Op(OperationTemplate {
        target: name,
        method: "check".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::null()),
    });
    let sibling_out = ex.eval(&sibling_check_on_ask).await.outcome;
    ensure!(
        matches!(
            sibling_out,
            Outcome::Fail(xolotl_types::Failure::NoHandler { .. })
        ),
        "sibling method was accepted: {sibling_out:?}"
    );

    let blob_unref = resource_name("effect://blob/unref")?;
    ensure!(
        boot.kernel()
            .registry()
            .resolve_resource(&blob_unref)
            .is_err(),
        "blob unref alias must not be registered"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_secret_is_not_an_operation_input() -> anyhow::Result<()> {
    let boot = Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    );
    install_default(&boot)?;

    let name = resource_name("effect://external/pairing/create")?;
    let handle = boot
        .open_for(boot.root(), &name, "perform")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let ex = boot
        .kernel()
        .executor_for(boot.root())
        .with_fact_recording(true);
    ex.bind_handle(name.clone(), handle)?;

    let prog = DoNode::Op(OperationTemplate {
        target: name,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::map(std::collections::BTreeMap::from([
            ("pairing_id".into(), Value::string("pair-old".into())),
            ("pairing_secret".into(), Value::string("old-secret".into())),
        ]))),
    });
    let out = ex.eval(&prog).await.outcome;
    ensure!(
        matches!(
            out,
            Outcome::Fail(xolotl_types::Failure::InvalidInput { .. })
        ),
        "pairing secret input was accepted: {out:?}"
    );

    let facts = boot
        .kernel()
        .facts()
        .all_facts()
        .map_err(anyhow::Error::msg)?;
    ensure!(facts.len() == 1, "fact count: {}", facts.len());
    let Some(input) = facts[0].input.as_map() else {
        bail!("expected inline redacted input");
    };
    ensure!(
        input.get("pairing_secret") == Some(&Value::string("<redacted>".into())),
        "pairing_secret was not redacted"
    );
    ensure!(
        !input
            .values()
            .any(|v| v == &Value::string("old-secret".into())),
        "raw pairing secret leaked into facts"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_admission_follows_the_driver_when_mounted_at_another_path() -> anyhow::Result<()> {
    let boot = Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    );
    let path = "effect://custom/onboarding";
    boot.register_effect(
        path,
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(SingleMethodDriver::new(
            Arc::new(PairingDriver::new(boot.kernel().state().clone(), None)),
            0,
        )),
    )?;
    let output = run_standard_effect_with_fact_recording(
        &boot,
        path,
        Value::map(std::collections::BTreeMap::from([
            ("pairing_id".into(), Value::string("pair-old".into())),
            (
                "pairing_secret".into(),
                Value::string("secret-value".into()),
            ),
        ])),
        true,
    )
    .await?;
    ensure!(matches!(
        output,
        Outcome::Fail(xolotl_types::Failure::InvalidInput { .. })
    ));
    let facts = boot
        .kernel()
        .facts()
        .all_facts()
        .map_err(anyhow::Error::msg)?;
    ensure!(facts.len() == 1);
    let Some(input) = facts[0].input.as_map() else {
        bail!("missing recorded input")
    };
    ensure!(input.get("pairing_secret") == Some(&Value::string("<redacted>".into())));
    ensure!(input.get("pairing_id") == Some(&Value::string("pair-old".into())));
    Ok(())
}

#[tokio::test]
async fn remote_input_requirement_survives_standard_method_remapping() -> anyhow::Result<()> {
    struct RemoteBackend;
    #[async_trait::async_trait]
    impl InferenceBackend for RemoteBackend {
        fn requires_unprotected_input(&self) -> bool {
            true
        }
        async fn infer(&self, _input: &Value) -> Result<Value, String> {
            Err("backend was invoked".into())
        }
        async fn embed(&self, _input: &Value) -> Result<Value, String> {
            Err("backend was invoked".into())
        }
    }
    let boot = Bootstrap::in_memory();
    install_standard(
        &boot,
        &StandardConfig::default().with_inference_backend(Arc::new(RemoteBackend)),
    )?;
    for path in [
        "effect://inference/infer",
        "effect://compress/summarize",
        "effect://deliberation/run",
        "effect://memory/store",
    ] {
        let name = resource_name(path)?;
        let handle = boot
            .open_for(boot.root(), &name, "perform")
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let executor = boot.kernel().executor_for(boot.root());
        executor.bind_handle(name.clone(), handle)?;
        let operation = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let taint = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
            path: Path::parse("state://vault/private")?,
        });
        let output = executor.eval_tainted(&operation, taint).await.outcome;
        ensure!(
            output
                == Outcome::Fail(xolotl_types::Failure::policy(
                    "taint",
                    "method requires unprotected input"
                )),
            "{path}: {output:?}"
        );
    }
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
        .kernel()
        .registry()
        .resolve_resource(&name)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let resource = boot
        .kernel()
        .registry()
        .resource(rid)
        .with_context(|| format!("resource {path} is not registered"))?;
    let mut actual = None;
    for iface_id in &resource.interfaces.interfaces {
        let Some(iface) = boot.kernel().registry().interface(*iface_id) else {
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
        .kernel()
        .registry()
        .resolve_resource(&name)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let resource = boot
        .kernel()
        .registry()
        .resource(rid)
        .with_context(|| format!("resource {path} is not registered"))?;
    let mut actual = None;
    for iface_id in &resource.interfaces.interfaces {
        let Some(iface) = boot.kernel().registry().interface(*iface_id) else {
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
    expected: xolotl_types::ReplayClass,
) -> anyhow::Result<()> {
    let name = resource_name(path)?;
    let rid = boot
        .kernel()
        .registry()
        .resolve_resource(&name)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let resource = boot
        .kernel()
        .registry()
        .resource(rid)
        .with_context(|| format!("resource {path} is not registered"))?;
    let mut actual = None;
    for iface_id in &resource.interfaces.interfaces {
        let Some(iface) = boot.kernel().registry().interface(*iface_id) else {
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
