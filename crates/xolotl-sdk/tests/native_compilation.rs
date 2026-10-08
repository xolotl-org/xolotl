#![cfg(feature = "host")]

use anyhow::ensure;
use xolotl_sdk::{
    DoNode, ExecutionConfig, IdentityRef, KernelBuilder, Outcome, StepModule, StepRef, Value,
    Xolotl,
};

#[tokio::test]
async fn deep_native_request_compiles_and_runs_with_named_steps() -> anyhow::Result<()> {
    let sdk = Xolotl::from_kernel(
        KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
            .with_execution_config(ExecutionConfig {
                frames_per_task: 1024,
                max_frames: 2048,
                ..ExecutionConfig::default()
            })
            .build(),
    );
    let mut program = DoNode::pure(37);
    for _ in 0..300 {
        program = program.and_then(StepRef::new("identity"));
    }
    let steps = StepModule::single("identity", |value, _| DoNode::pure(value))?;
    let result = sdk
        .run_with_steps(IdentityRef::ROOT, &[], program, steps)
        .await?;
    ensure!(
        result.output.outcome == Outcome::Done(Value::integer(37)),
        "{:?}",
        result.output
    );
    Ok(())
}

#[cfg(feature = "plan")]
#[tokio::test]
async fn shallow_plan_runs_through_the_sdk_compiler() -> anyhow::Result<()> {
    let sdk = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
    for stages in [300, 4096] {
        let plan = xolotl_sdk::Plan {
            id: format!("shallow-{stages}"),
            version: 1,
            description: None,
            steps: (0..stages)
                .map(|index| xolotl_sdk::Step::Pure {
                    value: serde_json::json!(index),
                })
                .collect(),
        };
        let result = sdk.run_plan(IdentityRef::ROOT, &[], &plan).await?;
        ensure!(
            result.output.outcome == Outcome::Done(Value::integer(stages - 1)),
            "{:?}",
            result.output
        );
    }
    Ok(())
}

#[cfg(feature = "plan")]
#[tokio::test]
async fn many_live_plan_bindings_execute_and_shadow_without_losing_outer_values()
-> anyhow::Result<()> {
    use std::sync::{Arc, Mutex};
    use xolotl_sdk::{Plan, Step};

    let sdk = Xolotl::from_kernel(
        KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
            .with_execution_config(ExecutionConfig {
                max_tasks: 3,
                frames_per_task: 8192,
                max_frames: 16_384,
                bindings_per_task: 2048,
                ..ExecutionConfig::default()
            })
            .build(),
    );
    let name = |index| {
        if index == 0 {
            "_plan_sequence_0".to_string()
        } else {
            format!("binding_{index}")
        }
    };
    let mut steps: Vec<_> = (0..1024)
        .map(|index| Step::Let {
            name: name(index),
            value: serde_json::json!(index),
        })
        .collect();
    for index in 0..1024 {
        steps.push(Step::Use { name: name(index) });
        steps.push(Step::Then {
            name: "observe".into(),
            arg: None,
        });
    }
    steps.extend([
        Step::Parallel {
            left: vec![
                Step::Let {
                    name: name(1023),
                    value: serde_json::json!(-1),
                },
                Step::Use { name: name(1023) },
            ],
            right: vec![Step::Use { name: name(1023) }],
        },
        Step::Then {
            name: "observe".into(),
            arg: None,
        },
        Step::Use { name: name(0) },
        Step::Then {
            name: "observe".into(),
            arg: None,
        },
    ]);
    let plan = Plan {
        id: "many-live-bindings".into(),
        version: 1,
        description: None,
        steps,
    };
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    let module = StepModule::single("observe", move |value, _| {
        captured
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(value.clone());
        DoNode::pure(value)
    })?;
    let result = sdk
        .run_plan_with_steps(IdentityRef::ROOT, &[], &plan, module)
        .await?;
    ensure!(
        result.output.outcome == Outcome::Done(Value::integer(0)),
        "{:?}",
        result.output
    );
    let mut expected: Vec<_> = (0..1024).map(Value::integer).collect();
    expected.push(Value::list(vec![Value::integer(-1), Value::integer(1023)]));
    expected.push(Value::integer(0));
    ensure!(*observed.lock().unwrap_or_else(|error| error.into_inner()) == expected);
    Ok(())
}
