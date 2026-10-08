use anyhow::{Context, ensure};
use xolotl_plan::{
    CompileLimits, Plan, PlanError, Step, StepRefSpec, WriteModeSpec, compile, compile_with_limits,
    parse_json_with_limits, parse_yaml_with_limits,
};

fn plan(steps: Vec<Step>) -> Plan {
    Plan {
        id: "escaped\n\"\\\u{1}".into(),
        version: 1,
        description: Some("中文".into()),
        steps,
    }
}

fn pure() -> Step {
    Step::Pure {
        value: serde_json::json!({"\n": [true, null, "\u{0}\t中文", 1.5]}),
    }
}

#[test]
fn shallow_sequences_balance_and_many_bindings_compile() -> anyhow::Result<()> {
    for stages in [300, 4096] {
        let source = plan(
            (0..stages)
                .map(|index| Step::Pure {
                    value: serde_json::json!(index),
                })
                .collect(),
        );
        let node = compile(&source)?;
        ensure!(node.size() == stages * 2 - 1);
        ensure!(!node.exceeds_depth(14));
        let graph = xolotl_graph::compile_do(&node)?;
        ensure!(graph.nodes.len() == stages * 2 - 1);
        ensure!(graph.graph_hash == xolotl_graph::compile_do(&compile(&source)?)?.graph_hash);
    }
    let mut steps: Vec<_> = (0..1024)
        .map(|index| Step::Let {
            name: format!("binding_{index}"),
            value: serde_json::json!(index),
        })
        .collect();
    steps.extend((0..1024).map(|index| Step::Use {
        name: format!("binding_{index}"),
    }));
    let source = plan(steps);
    let node = compile(&source)?;
    ensure!(node.size() == 4095);
    ensure!(xolotl_graph::compile_do(&node)?.nodes.len() == 4095);
    compile_with_limits(
        &source,
        CompileLimits {
            instructions: 4095,
            ..CompileLimits::default()
        },
    )?;
    ensure!(matches!(
        compile_with_limits(
            &source,
            CompileLimits {
                instructions: 4094,
                ..CompileLimits::default()
            }
        ),
        Err(PlanError::Capacity)
    ));
    Ok(())
}

fn reference() -> StepRefSpec {
    StepRefSpec {
        name: "step".into(),
        arg: Some(serde_json::json!([false])),
    }
}

#[test]
fn exact_compact_source_admission_covers_every_envelope() -> anyhow::Result<()> {
    let steps = vec![
        Step::Perform {
            target: "effect://x/post".into(),
            input: None,
        },
        Step::Read {
            path: "state://plan/value".into(),
            r#as: "read".into(),
        },
        Step::Use {
            name: "read".into(),
        },
        Step::Subscribe {
            path: "state://plan/events".into(),
            step: reference(),
        },
        Step::Write {
            path: "state://plan/value".into(),
            value: serde_json::json!(1),
            mode: WriteModeSpec::Set,
        },
        Step::Write {
            path: "state://plan/events".into(),
            value: serde_json::json!(null),
            mode: WriteModeSpec::Append,
        },
        Step::Let {
            name: "bound".into(),
            value: serde_json::json!(true),
        },
        Step::Then {
            name: "step".into(),
            arg: None,
        },
        Step::OnFail {
            name: "recover".into(),
            arg: Some(serde_json::json!({})),
        },
        Step::Parallel {
            left: vec![pure()],
            right: vec![pure()],
        },
        Step::Race {
            left: vec![pure()],
            right: vec![pure()],
        },
        Step::Acting {
            identity: "identity://plan/inner".into(),
            body: vec![pure()],
        },
        Step::Bracket {
            acquire: Box::new(pure()),
            body: vec![pure()],
            release: reference(),
        },
        pure(),
    ];
    for steps in [
        steps,
        vec![Step::Perform {
            target: "effect://x/post".into(),
            input: Some(serde_json::json!(42)),
        }],
    ] {
        let plan = plan(steps);
        let size = serde_json::to_vec(&plan)?.len();
        compile_with_limits(
            &plan,
            CompileLimits {
                source_bytes: size,
                ..CompileLimits::default()
            },
        )?;
        ensure!(matches!(
            compile_with_limits(
                &plan,
                CompileLimits {
                    source_bytes: size - 1,
                    ..CompileLimits::default()
                }
            ),
            Err(PlanError::Capacity)
        ));
    }
    Ok(())
}

#[test]
fn synthetic_nodes_and_literal_depth_are_charged_before_lowering() -> anyhow::Result<()> {
    let plan = plan(vec![Step::Bracket {
        acquire: Box::new(Step::Pure {
            value: serde_json::json!(1),
        }),
        body: vec![Step::Use {
            name: "_resource".into(),
        }],
        release: StepRefSpec {
            name: "release".into(),
            arg: None,
        },
    }]);
    compile_with_limits(
        &plan,
        CompileLimits {
            instructions: 6,
            expression_depth: 3,
            ..CompileLimits::default()
        },
    )?;
    ensure!(matches!(
        compile_with_limits(
            &plan,
            CompileLimits {
                instructions: 5,
                ..CompileLimits::default()
            }
        ),
        Err(PlanError::Capacity)
    ));
    ensure!(matches!(
        compile_with_limits(
            &plan,
            CompileLimits {
                expression_depth: 2,
                ..CompileLimits::default()
            }
        ),
        Err(PlanError::Capacity)
    ));
    let wide = self::plan(
        (0..100)
            .map(|_| Step::Pure {
                value: serde_json::json!(0),
            })
            .collect(),
    );
    compile_with_limits(
        &wide,
        CompileLimits {
            instructions: 199,
            ..CompileLimits::default()
        },
    )?;
    ensure!(matches!(
        compile_with_limits(
            &wide,
            CompileLimits {
                instructions: 198,
                ..CompileLimits::default()
            }
        ),
        Err(PlanError::Capacity)
    ));
    Ok(())
}

#[test]
fn parse_rejects_raw_bytes_before_decoder_and_compiler_borrows_source() -> anyhow::Result<()> {
    let limits = CompileLimits {
        source_bytes: 1,
        ..CompileLimits::default()
    };
    ensure!(matches!(
        parse_json_with_limits("invalid", limits),
        Err(PlanError::Capacity)
    ));
    ensure!(matches!(
        parse_yaml_with_limits("invalid", limits),
        Err(PlanError::Capacity)
    ));
    let source = plan(vec![pure()]);
    let snapshot = serde_json::to_vec(&source)?;
    let first = compile(&source)?;
    let second = compile(&source)?;
    ensure!(serde_json::to_vec(&source)? == snapshot);
    ensure!(serde_json::to_vec(&first)? == serde_json::to_vec(&second)?);
    Ok(())
}

#[test]
fn raised_depth_uses_small_native_stack_for_validation_lowering_and_conversion()
-> anyhow::Result<()> {
    let depth = 2048;
    let mut literal = serde_json::json!(7);
    for _ in 0..depth {
        literal = serde_json::Value::Array(vec![literal]);
    }
    let mut step = Step::Pure { value: literal };
    for _ in 0..depth {
        step = Step::Acting {
            identity: "identity://plan/inner".into(),
            body: vec![step],
        };
    }
    let source = plan(vec![step]);
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn_scoped(scope, || {
                ensure!(matches!(compile(&source), Err(PlanError::Capacity)));
                let node = compile_with_limits(
                    &source,
                    CompileLimits {
                        expression_depth: depth * 2 + 2,
                        ..CompileLimits::default()
                    },
                )?;
                drop(node);
                Ok::<_, anyhow::Error>(())
            })?
            .join()
            .map_err(|_panic_payload| anyhow::anyhow!("compiler worker panicked"))?
    });
    let mut steps = source.steps;
    while let Some(step) = steps.pop() {
        match step {
            Step::Acting { body, .. } => steps.extend(body),
            Step::Pure { value } => {
                let mut values = vec![value];
                while let Some(value) = values.pop() {
                    if let serde_json::Value::Array(children) = value {
                        values.extend(children);
                    }
                }
            }
            _ => {}
        }
    }
    result.context("bounded borrowed compiler on small stack")
}
