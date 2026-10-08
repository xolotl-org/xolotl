use anyhow::ensure;
use std::sync::{Arc, Mutex};
use xolotl_graph::{DoNode, ExecutionGraph, compile_do};
use xolotl_kernel::{Bootstrap, DriverError, FnDriver, MethodSpec, StepModule};
use xolotl_plan::{Plan, PlanError, Step, StepRefSpec, WriteModeSpec, compile};
use xolotl_types::{
    Failure, InterfaceFamily, MethodAuthority, Outcome, OutputModeSet, Purity, Value,
};

fn plan(steps: Vec<Step>) -> Plan {
    Plan {
        id: "bindings".into(),
        version: 1,
        description: None,
        steps,
    }
}

fn bind(name: &str, value: i64) -> Step {
    Step::Let {
        name: name.into(),
        value: serde_json::json!(value),
    }
}

fn load(name: &str) -> Step {
    Step::Use { name: name.into() }
}

fn pure(value: i64) -> Step {
    Step::Pure {
        value: serde_json::json!(value),
    }
}

fn graph(steps: Vec<Step>) -> anyhow::Result<ExecutionGraph> {
    Ok(compile_do(&compile(&plan(steps))?)?)
}

async fn evaluate(steps: Vec<Step>) -> anyhow::Result<Outcome> {
    let boot = Bootstrap::in_memory();
    let graph = graph(steps)?;
    Ok(boot
        .kernel()
        .executor_for(boot.root())
        .eval_graph(&graph)
        .await
        .outcome)
}

#[tokio::test]
async fn let_and_read_bind_values_used_by_later_steps() -> anyhow::Result<()> {
    ensure!(
        evaluate(vec![bind("x", 7), pure(0), load("x")]).await? == Outcome::Done(Value::integer(7))
    );
    let boot = Bootstrap::in_memory();
    boot.register_subtree_resource_at(
        "state://plan/value",
        "read://state/plan/value/**",
        InterfaceFamily::Value,
        &[MethodSpec::new(
            "read",
            MethodAuthority::Read,
            Purity::Pure,
            OutputModeSet::UNARY,
        )
        .observes_external()],
        Arc::new(FnDriver(|_, _| Ok(Value::integer(41)))),
    )?;
    let graph = graph(vec![
        Step::Read {
            path: "state://plan/value/item".into(),
            r#as: "x".into(),
        },
        pure(0),
        load("x"),
    ])?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .eval_graph(&graph)
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(41)),
        "{output:?}"
    );
    Ok(())
}

#[tokio::test]
async fn shadowing_and_generated_sequence_names_preserve_outer_values() -> anyhow::Result<()> {
    ensure!(
        evaluate(vec![bind("x", 1), bind("x", 2), load("x")]).await?
            == Outcome::Done(Value::integer(2))
    );
    ensure!(
        evaluate(vec![
            bind("_plan_sequence_0", 7),
            Step::Parallel {
                left: vec![bind("_plan_sequence_0", 8), load("_plan_sequence_0")],
                right: vec![load("_plan_sequence_0")]
            },
            load("_plan_sequence_0"),
        ])
        .await?
            == Outcome::Done(Value::integer(7))
    );
    ensure!(
        evaluate(vec![
            bind("x", 7),
            Step::Acting {
                identity: "identity://plan/inner".into(),
                body: vec![bind("x", 8), load("x")]
            },
            load("x"),
        ])
        .await?
            == Outcome::Done(Value::integer(7))
    );
    Ok(())
}

#[tokio::test]
async fn late_outer_load_survives_reused_slots_and_parallel_local_bindings() -> anyhow::Result<()> {
    for local in [
        Step::Acting {
            identity: "identity://plan/inner".into(),
            body: vec![bind("x", 8), load("x")],
        },
        Step::Parallel {
            left: vec![bind("left", 8), load("left")],
            right: vec![bind("right", 9), load("right")],
        },
    ] {
        ensure!(
            evaluate(vec![bind("x", 7), local, load("x")]).await?
                == Outcome::Done(Value::integer(7))
        );
    }
    Ok(())
}

#[test]
fn local_names_do_not_escape_blocks_or_cross_sibling_branches() -> anyhow::Result<()> {
    for step in [
        Step::Parallel {
            left: vec![bind("x", 1), load("x")],
            right: vec![load("x")],
        },
        Step::Race {
            left: vec![bind("x", 1), load("x")],
            right: vec![load("x")],
        },
        Step::Parallel {
            left: vec![bind("x", 1), load("x")],
            right: vec![pure(0)],
        },
        Step::Race {
            left: vec![bind("x", 1), load("x")],
            right: vec![pure(0)],
        },
        Step::Acting {
            identity: "identity://plan/inner".into(),
            body: vec![bind("x", 1), load("x")],
        },
        Step::Bracket {
            acquire: Box::new(pure(0)),
            body: vec![bind("x", 1), load("x")],
            release: StepRefSpec {
                name: "release".into(),
                arg: None,
            },
        },
    ] {
        ensure!(
            matches!(compile(&plan(vec![step, load("x")])), Err(PlanError::UnboundName(name)) if name == "x")
        );
    }
    ensure!(
        matches!(compile(&plan(vec![load("later"), bind("later", 1)])), Err(PlanError::UnboundName(name)) if name == "later")
    );
    Ok(())
}

#[tokio::test]
async fn explicit_parallel_and_race_inherit_bindings() -> anyhow::Result<()> {
    ensure!(
        evaluate(vec![
            bind("x", 7),
            Step::Parallel {
                left: vec![load("x")],
                right: vec![bind("x", 8), load("x")]
            }
        ])
        .await?
            == Outcome::Done(Value::list(vec![Value::integer(7), Value::integer(8)]))
    );
    ensure!(
        evaluate(vec![
            bind("x", 7),
            Step::Race {
                left: vec![load("x")],
                right: vec![load("x")]
            }
        ])
        .await?
            == Outcome::Done(Value::integer(7))
    );
    Ok(())
}

#[tokio::test]
async fn writes_run_in_document_order_without_implicit_parallelism() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let writes = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&writes);
    boot.register_subtree_resource_at(
        "state://plan/writes",
        "write://state/plan/writes/**",
        InterfaceFamily::Value,
        &[MethodSpec::new(
            "write",
            MethodAuthority::Write,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        Arc::new(FnDriver(move |_, input: Value| {
            observed
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(input);
            Ok(Value::null())
        })),
    )?;
    let graph = graph(
        (1..=300)
            .map(|value| Step::Write {
                path: "state://plan/writes/item".into(),
                value: serde_json::json!(value),
                mode: WriteModeSpec::Set,
            })
            .collect(),
    )?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .eval_graph(&graph)
        .await;
    ensure!(output.outcome == Outcome::Done(Value::null()), "{output:?}");
    ensure!(
        *writes.lock().unwrap_or_else(|error| error.into_inner())
            == (1..=300).map(Value::integer).collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_write_prevents_later_effects() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let writes = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&writes);
    boot.register_subtree_resource_at(
        "state://plan/writes",
        "write://state/plan/writes/**",
        InterfaceFamily::Value,
        &[MethodSpec::new(
            "write",
            MethodAuthority::Write,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        Arc::new(FnDriver(move |_, input: Value| {
            let value = input.as_int();
            observed
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(input);
            if value == Some(149) {
                Err(DriverError::Other("rejected write".into()))
            } else {
                Ok(Value::null())
            }
        })),
    )?;
    let graph = graph(
        (1..=300)
            .map(|value| Step::Write {
                path: "state://plan/writes/item".into(),
                value: serde_json::json!(value),
                mode: WriteModeSpec::Set,
            })
            .collect(),
    )?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .eval_graph(&graph)
        .await;
    ensure!(output.outcome.is_fail(), "{output:?}");
    ensure!(
        *writes.lock().unwrap_or_else(|error| error.into_inner())
            == (1..=149).map(Value::integer).collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
async fn balanced_sequences_preserve_dynamic_input_flow() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&seen);
    boot.register_subtree_resource_at(
        "effect://plan/increment",
        "perform://effect/plan/increment/**",
        InterfaceFamily::Callable,
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        Arc::new(FnDriver(move |_, input: Value| {
            let value = input
                .as_int()
                .ok_or_else(|| DriverError::Other("expected integer input".into()))?;
            observed
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(value);
            Ok(Value::integer(value + 1))
        })),
    )?;
    let mut steps = vec![pure(0)];
    steps.extend((0..300).map(|_| Step::Perform {
        target: "effect://plan/increment/item".into(),
        input: None,
    }));
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .eval_graph(&graph(steps)?)
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(300)),
        "{output:?}"
    );
    ensure!(
        *seen.lock().unwrap_or_else(|error| error.into_inner()) == (0..300).collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
async fn then_receives_the_prefix_result_and_not_the_suffix() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&seen);
    let module = StepModule::single("capture", move |value, _| {
        observed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(value);
        DoNode::pure(99)
    })?;
    let mut steps: Vec<_> = (0..300).map(pure).collect();
    steps.extend([
        Step::Then {
            name: "capture".into(),
            arg: None,
        },
        pure(3),
    ]);
    let graph = graph(steps)?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .with_steps(module)
        .eval_graph(&graph)
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(3)),
        "{output:?}"
    );
    ensure!(*seen.lock().unwrap_or_else(|error| error.into_inner()) == vec![Value::integer(299)]);
    Ok(())
}

#[tokio::test]
async fn recovery_handles_the_prefix_but_not_later_failures() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let recovered = Arc::new(Mutex::new(0));
    let observed = Arc::clone(&recovered);
    let recover = StepModule::single("recover", move |_, _| {
        *observed.lock().unwrap_or_else(|error| error.into_inner()) += 1;
        DoNode::pure(42)
    })?;
    let fail = StepModule::single("fail", |_, _| DoNode::fail(Failure::Cancelled))?;
    let executor = boot
        .kernel()
        .executor_for(boot.root())
        .with_steps(StepModule::compose([recover, fail])?);
    let output = executor
        .eval_graph(&graph(vec![
            pure(1),
            Step::Then {
                name: "fail".into(),
                arg: None,
            },
            pure(2),
            Step::OnFail {
                name: "recover".into(),
                arg: None,
            },
            pure(3),
        ])?)
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(3)),
        "{output:?}"
    );
    let output = executor
        .eval_graph(&graph(vec![
            pure(1),
            Step::OnFail {
                name: "recover".into(),
                arg: None,
            },
            pure(2),
            Step::Then {
                name: "fail".into(),
                arg: None,
            },
        ])?)
        .await;
    ensure!(
        output.outcome == Outcome::Fail(Failure::Cancelled),
        "{output:?}"
    );
    ensure!(*recovered.lock().unwrap_or_else(|error| error.into_inner()) == 1);
    Ok(())
}

#[tokio::test]
async fn bracket_release_receives_acquired_value_despite_body_shadowing() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let released = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&released);
    let module = StepModule::single("release", move |value, _| {
        observed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(value);
        DoNode::pure(0)
    })?;
    let graph = graph(vec![Step::Bracket {
        acquire: Box::new(pure(7)),
        body: vec![bind("_resource", 8), load("_resource")],
        release: StepRefSpec {
            name: "release".into(),
            arg: None,
        },
    }])?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .with_steps(module)
        .eval_graph(&graph)
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(8)),
        "{output:?}"
    );
    ensure!(*released.lock().unwrap_or_else(|error| error.into_inner()) == vec![Value::integer(7)]);
    Ok(())
}

#[tokio::test]
async fn read_recovery_is_bound_before_the_suffix_runs() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let module = StepModule::single("recover", |_, _| DoNode::pure(42))?;
    let graph = graph(vec![
        Step::Read {
            path: "state://plan/missing".into(),
            r#as: "x".into(),
        },
        Step::OnFail {
            name: "recover".into(),
            arg: None,
        },
        pure(0),
        load("x"),
    ])?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .with_steps(module)
        .eval_graph(&graph)
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(42)),
        "{output:?}"
    );
    Ok(())
}

#[test]
fn modifiers_cannot_start_nested_sequences() -> anyhow::Result<()> {
    for modifier in [
        Step::Then {
            name: "step".into(),
            arg: None,
        },
        Step::OnFail {
            name: "step".into(),
            arg: None,
        },
    ] {
        ensure!(matches!(
            compile(&plan(vec![
                pure(1),
                Step::Parallel {
                    left: vec![modifier, pure(2)],
                    right: vec![pure(3)],
                }
            ])),
            Err(PlanError::BadFirstStep(_))
        ));
    }
    Ok(())
}
