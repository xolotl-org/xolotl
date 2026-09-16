use super::*;
use crate::{Bootstrap, EchoDriver, MethodSpec};
use anyhow::{Context, ensure};
use futures_util::FutureExt;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_graph::portable::{Expression as E, Program, Transform};
use xolotl_state::TaintedValue;
use xolotl_types::{Failure, OutputMode, Path, Purity, TaintSet, TaintSource};

fn module(name: &str) -> E {
    E::Module {
        module: StepRef::new(name),
    }
}

fn prepare(body: E) -> anyhow::Result<PreparedProgram> {
    Ok(PreparedProgram::new(&Program::new(body).compile()?)?)
}

fn increment() -> E {
    E::Let {
        name: "value".into(),
        value: Box::new(E::Transform {
            operation: Transform::Add { value: 1 },
        }),
        body: Box::new(E::Use {
            name: "value".into(),
        }),
    }
}

fn iterations(count: u64) -> E {
    E::While {
        condition: Box::new(E::Transform {
            operation: Transform::LessThan {
                value: count as i64,
            },
        }),
        body: Box::new(module("increment")),
        max_iterations: count,
    }
}

#[tokio::test]
async fn repeated_module_calls_reuse_code_and_bindings_with_bounded_storage() -> anyhow::Result<()>
{
    let boot = Bootstrap::in_memory();
    let program = prepare(iterations(4096))?;
    let loaded = prepare(increment())?;
    let max_instructions = program.inner.nodes.len() + loaded.inner.nodes.len();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let steps = StepModule::program(
        "increment",
        crate::LoaderRevision::from_bytes([1; 32]),
        move |input, arg| {
            if input.as_int().is_none() || arg.is_some() {
                return Err(machine_error("unexpected loader input"));
            }
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(loaded.clone())
        },
    )?;
    let executor = boot
        .kernel
        .executor_for(boot.root)
        .with_steps(steps)
        .with_execution_config(ExecutionConfig {
            max_instructions,
            bindings_per_task: 1,
            max_storage_bytes: 4096,
            ..ExecutionConfig::default()
        });
    let mut buffers = ExecutionBuffers::default();
    let output = executor
        .eval_prepared_with_buffers(
            &program,
            TaintedValue::pristine(Value::integer(0)),
            &mut buffers,
        )
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(4096)),
        "{output:?}"
    );
    ensure!(calls.load(Ordering::Relaxed) == 4096);
    ensure!(buffers.retained_bytes() <= 4096);
    Ok(())
}

#[tokio::test]
async fn portable_and_native_modules_nest_in_one_lexical_execution() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let outer = prepare(E::Let {
        name: "value".into(),
        value: Box::new(E::literal(7)),
        body: Box::new(
            E::Use {
                name: "value".into(),
            }
            .then(module("native"))
            .both(E::Use {
                name: "value".into(),
            }),
        ),
    })?;
    let mut source = Program::new(E::Call {
        function: "increment".into(),
    });
    source.functions.insert("increment".into(), increment());
    let loaded = PreparedProgram::new(&source.compile()?)?;
    let steps = StepModule::compose([
        StepModule::program(
            "outer",
            crate::LoaderRevision::from_bytes([1; 32]),
            move |_, _| Ok(outer.clone()),
        )?,
        StepModule::single("native", |value, _| {
            DoNode::pure(value)
                .and_then(StepRef::new("portable").with_arg(Value::integer(17)))
                .and_then(StepRef::new("twice"))
        })?,
        StepModule::program(
            "portable",
            crate::LoaderRevision::from_bytes([1; 32]),
            move |_, arg| {
                if arg != Some(&Value::integer(17)) {
                    return Err(machine_error("missing loader argument"));
                }
                Ok(loaded.clone())
            },
        )?,
        StepModule::single("twice", |value, _| match value.as_int() {
            Some(value) => DoNode::pure(Value::integer(value * 2)),
            _ => DoNode::fail(machine_error("expected integer")),
        })?,
    ])?;
    let source = Program::new(module("outer"));
    let decoded = Program::from_json(&serde_json::to_vec(&source)?)?;
    ensure!(decoded == source);
    let output = boot
        .kernel
        .executor_for(boot.root)
        .with_steps(steps)
        .eval_program(&decoded.compile()?, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::list(vec![Value::integer(16), Value::integer(7)])),
        "{output:?}"
    );
    Ok(())
}

#[tokio::test]
async fn waiting_modules_keep_their_code_while_completed_modules_are_reused() -> anyhow::Result<()>
{
    for quantum in [1, 256] {
        let boot = Bootstrap::in_memory();
        let signal = Path::parse("state://signal/module-reuse")?;
        let waiting = prepare(E::Let {
            name: "value".into(),
            value: Box::new(E::literal(777)),
            body: Box::new(
                E::Wait {
                    wait: WaitSpec::Signal(signal.clone()),
                }
                .then(E::Use {
                    name: "value".into(),
                }),
            ),
        })?;
        let loaded = prepare(increment())?;
        let program = prepare(iterations(64).both(module("wait")))?;
        let max_instructions =
            program.inner.nodes.len() + waiting.inner.nodes.len() + loaded.inner.nodes.len();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let steps = StepModule::compose([
            StepModule::program(
                "increment",
                crate::LoaderRevision::from_bytes([1; 32]),
                move |_, _| {
                    observed.fetch_add(1, Ordering::Relaxed);
                    Ok(loaded.clone())
                },
            )?,
            StepModule::program(
                "wait",
                crate::LoaderRevision::from_bytes([1; 32]),
                move |_, _| Ok(waiting.clone()),
            )?,
        ])?;
        let executor = boot
            .kernel
            .executor_for(boot.root)
            .with_steps(steps)
            .with_execution_config(ExecutionConfig {
                max_instructions,
                bindings_per_task: 2,
                quantum,
                ..ExecutionConfig::default()
            });
        let run = executor.eval_prepared(&program, TaintedValue::pristine(Value::integer(0)));
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while calls.load(Ordering::Relaxed) != 64 {
                tokio::select! {
                    biased;
                    output = &mut run => anyhow::bail!("wait ended early: {output:?}"),
                    () = tokio::task::yield_now() => {}
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        boot.kernel
            .state
            .write_set(&signal, Value::boolean(true))
            .await?;
        let output = tokio::time::timeout(std::time::Duration::from_secs(1), run).await?;
        ensure!(
            output.outcome
                == Outcome::Done(Value::list(vec![Value::integer(64), Value::integer(777)])),
            "{output:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejected_module_admission_rolls_back_and_reaches_the_next_loader() -> anyhow::Result<()> {
    for reason in ["instruction capacity", "binding capacity", "storage budget"] {
        let boot = Bootstrap::in_memory();
        let loaded = prepare(increment())?;
        let recovery = prepare(E::literal(42))?;
        let program = prepare(E::Catch {
            body: Box::new(module("too-large")),
            recover: Box::new(module("recover")),
        })?;
        let mut config = ExecutionConfig::default();
        match reason {
            "instruction capacity" => config.max_instructions = program.inner.nodes.len() + 1,
            "binding capacity" => config.bindings_per_task = 0,
            _ => {
                config.max_storage_bytes =
                    super::config::buffer_bytes(1, 5, 0).context("layout overflow")?;
            }
        }
        let steps = StepModule::compose([
            StepModule::program(
                "too-large",
                crate::LoaderRevision::from_bytes([1; 32]),
                move |_, _| Ok(loaded.clone()),
            )?,
            StepModule::program(
                "recover",
                crate::LoaderRevision::from_bytes([1; 32]),
                move |input, _| {
                    if !input
                        .as_str()
                        .is_some_and(|message| message.contains(reason))
                    {
                        return Err(machine_error(format!("unexpected failure: {input:?}")));
                    }
                    Ok(recovery.clone())
                },
            )?,
        ])?;
        let output = boot
            .kernel
            .executor_for(boot.root)
            .with_steps(steps)
            .with_execution_config(config)
            .eval_prepared(&program, TaintedValue::pristine(Value::integer(1)))
            .await;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(42)),
            "{reason}: {output:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn loader_failure_and_panic_are_ordinary_catchable_failures() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let steps = StepModule::compose([
        StepModule::program(
            "failed",
            crate::LoaderRevision::from_bytes([1; 32]),
            |_, _| Err(machine_error("loader failed")),
        )?,
        StepModule::program(
            "panicked",
            crate::LoaderRevision::from_bytes([1; 32]),
            |_, _| std::panic::resume_unwind(Box::new("loader panic")),
        )?,
    ])?;
    let executor = boot.kernel.executor_for(boot.root).with_steps(steps);
    for (name, expected) in [
        ("missing", "not found"),
        ("failed", "loader failed"),
        ("panicked", "loader panic"),
    ] {
        let program = Program::new(E::Catch {
            body: Box::new(module(name)),
            recover: Box::new(E::Input),
        })
        .compile()?;
        let output = executor
            .eval_program(&program, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(
            matches!(&output.outcome, Outcome::Done(value) if value.as_str().is_some_and(|message| message.contains(expected)))
        );
    }
    Ok(())
}

#[tokio::test]
async fn dynamic_modules_reject_durable_images_before_dispatch() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let mut source = Program::new(E::literal(42));
    source.durable = true;
    let loaded = PreparedProgram::new(&source.compile()?)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let steps = StepModule::program(
        "durable",
        crate::LoaderRevision::from_bytes([1; 32]),
        move |_, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(loaded.clone())
        },
    )?;
    let executor = boot.kernel.executor_for(boot.root).with_steps(steps);
    let mut source = Program::new(module("durable"));
    let output = executor
        .eval_program(&source.compile()?, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        matches!(output.outcome, Outcome::Fail(Failure::PolicyViolation { detail, .. }) if detail.contains("durable"))
    );
    ensure!(calls.load(Ordering::Relaxed) == 1);
    source.durable = true;
    let output = executor
        .eval_program(&source.compile()?, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        matches!(output.outcome, Outcome::Fail(Failure::PolicyViolation { detail, .. }) if detail.contains("durable") || detail.contains("Durable"))
    );
    ensure!(calls.load(Ordering::Relaxed) == 1);
    Ok(())
}

#[tokio::test]
async fn module_calls_keep_input_authority_provenance_and_one_execution_namespace()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let target = boot.register_effect(
        "effect://modules/echo",
        &[MethodSpec::unary_async("invoke", Purity::Effectful)],
        Arc::new(EchoDriver),
    )?;
    let effect = OperationTemplate {
        target,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let portable = prepare(E::Invoke {
        operation: effect.clone(),
    })?;
    let position = portable.inner.nodes[portable.inner.entry as usize].position;
    let steps = StepModule::compose([
        StepModule::program(
            "portable",
            crate::LoaderRevision::from_bytes([1; 32]),
            move |_, _| Ok(portable.clone()),
        )?,
        StepModule::single("native", move |_, _| DoNode::op(effect.clone()))?,
    ])?;
    let body = (0..32).fold(E::Input, |body, _| {
        body.then(module("portable")).then(module("native"))
    });
    let identity = Path::parse("process/module-caller")?;
    boot.kernel.registry.register_grant(xolotl_types::Grant {
        id: boot.kernel.registry.next_grant_id(),
        holder: boot.root,
        selector: xolotl_types::ResourceSelector::parse("act-as://process/module-caller")?,
        rights: Rights::new(MethodBitmap::ALL, RightFlags::DELEGATE),
        constraints: xolotl_types::ConstraintSet::empty(),
        expires: xolotl_types::Expiry::Never,
    });
    let acting = intern_identity(&identity);
    let program = prepare(E::Acting {
        identity,
        body: Box::new(body),
    })?;
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/module-input")?,
    });
    let output = boot
        .kernel
        .executor_for(boot.root)
        .with_steps(steps)
        .eval_prepared(
            &program,
            TaintedValue::new(Value::integer(17), taint.clone()),
        )
        .await;
    ensure!(output.outcome == Outcome::Done(Value::null()), "{output:?}");
    let facts = boot.kernel.facts.facts_of(boot.root)?;
    ensure!(facts.len() == 64);
    ensure!(facts.iter().all(|fact| fact.caller == boot.root
        && fact.acting == acting
        && fact.taint.has_protected()));
    ensure!(facts.first().context("missing first effect")?.input == Value::integer(17));
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id.execution)
            .collect::<BTreeSet<_>>()
            .len()
            == 1
    );
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id)
            .collect::<BTreeSet<_>>()
            .len()
            == 64
    );
    ensure!(
        facts
            .iter()
            .all(|fact| u64::from(fact.id.position.get()) == position)
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_module_keeps_parent_code_until_loaded_cleanup_finishes() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let target = boot.register_effect(
        "effect://modules/cleanup",
        &[MethodSpec::unary_async("invoke", Purity::Effectful).finalize_allowed()],
        Arc::new(EchoDriver),
    )?;
    let signal = Path::parse("state://signal/module-cleanup")?;
    let waiting = prepare(
        E::Wait {
            wait: WaitSpec::Signal(signal),
        }
        .finally(module("cleanup")),
    )?;
    let cleanup = prepare(E::Invoke {
        operation: OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::integer(42)),
        },
    })?;
    let program = prepare(module("work"))?;
    let max_instructions =
        program.inner.nodes.len() + waiting.inner.nodes.len() + cleanup.inner.nodes.len();
    let steps = StepModule::compose([
        StepModule::program(
            "work",
            crate::LoaderRevision::from_bytes([1; 32]),
            move |_, _| Ok(waiting.clone()),
        )?,
        StepModule::program(
            "cleanup",
            crate::LoaderRevision::from_bytes([1; 32]),
            move |_, _| Ok(cleanup.clone()),
        )?,
    ])?;
    let executor = boot
        .kernel
        .executor_for(boot.root)
        .with_steps(steps)
        .with_execution_config(ExecutionConfig {
            max_instructions,
            ..ExecutionConfig::default()
        });
    let mut run = Box::pin(executor.eval_prepared(&program, TaintedValue::pristine(Value::null())));
    ensure!(run.as_mut().now_or_never().is_none());
    boot.cancel_process(boot.root)?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(1), run).await?;
    ensure!(
        output.outcome == Outcome::Fail(Failure::Cancelled),
        "{output:?}"
    );
    let facts = boot.kernel.facts.facts_of(boot.root)?;
    ensure!(facts.len() == 1);
    ensure!(facts[0].outcome == Some(Value::integer(42)));
    Ok(())
}
