#![cfg(feature = "host")]

use xolotl_sdk::{
    Expression as E, IdentityRef, Outcome, Program, TaintedValue, Transform, Value, Xolotl,
};
macro_rules! assert {
    ($condition:expr $(,)?) => {
        anyhow::ensure!($condition, "{}", stringify!($condition));
    };
}
macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        anyhow::ensure!(
            $left == $right,
            "{} != {}",
            stringify!($left),
            stringify!($right)
        );
    };
}

async fn evaluate(program: Program, input: Value) -> anyhow::Result<Outcome> {
    let compiled = program.compile()?;
    Ok(Xolotl::new()
        .run_program(
            IdentityRef::ROOT,
            &[],
            &compiled,
            TaintedValue::pristine(input),
        )
        .await?
        .outcome)
}

#[tokio::test]
async fn code_and_json_compile_to_identical_programs() -> anyhow::Result<()> {
    let code = Program::new(E::literal(3).then(E::Transform {
        operation: Transform::Add { value: 4 },
    }));
    let json = r#"{"version":1,"body":{"kind":"sequence","steps":[{"kind":"literal","value":3},{"kind":"transform","operation":{"op":"add","value":4}}]}}"#;
    let document: Program = serde_json::from_str(json)?;
    let a = code.compile()?;
    let b = document.compile()?;
    assert_eq!(a.id(), b.id());
    assert_eq!(a.image().nodes, b.image().nodes);
    assert_eq!(
        evaluate(document, Value::null()).await?,
        Outcome::Done(Value::integer(7))
    );
    Ok(())
}

#[tokio::test]
async fn loop_and_parallel_compose_without_native_steps() -> anyhow::Result<()> {
    let count = E::While {
        condition: Box::new(E::Transform {
            operation: Transform::LessThan { value: 20 },
        }),
        body: Box::new(E::Transform {
            operation: Transform::Add { value: 1 },
        }),
        max_iterations: 20,
    };
    let body = E::literal(0).then(count).both(E::literal("ready"));
    assert_eq!(
        evaluate(Program::new(body), Value::null()).await?,
        Outcome::Done(Value::list(vec![
            Value::integer(20),
            Value::string("ready".into())
        ]))
    );
    Ok(())
}

#[tokio::test]
async fn long_nested_sequences_use_bounded_stack_space() -> anyhow::Result<()> {
    let step = E::Transform {
        operation: Transform::Add { value: 1 },
    };
    let body = E::Sequence {
        steps: vec![
            E::Sequence {
                steps: vec![step; 4096],
            },
            E::Input,
        ],
    };
    assert_eq!(
        evaluate(Program::new(body), Value::integer(0)).await?,
        Outcome::Done(Value::integer(4096))
    );
    Ok(())
}

#[tokio::test]
async fn disjoint_lexical_scopes_reuse_one_binding_slot() -> anyhow::Result<()> {
    use xolotl_sdk::{ExecutionConfig, PreparedProgram, XolotlBuilder};
    let stage = E::Let {
        name: "current".into(),
        value: Box::new(E::Input),
        body: Box::new(
            E::Use {
                name: "current".into(),
            }
            .then(E::Transform {
                operation: Transform::Add { value: 1 },
            }),
        ),
    };
    let compiled = Program::new(E::Sequence {
        steps: vec![stage; 2048],
    })
    .compile()?;
    let prepared = PreparedProgram::new(&compiled)?;
    let layout = prepared.layout(&ExecutionConfig::default())?;
    assert_eq!(layout.bindings_per_task, 1);
    assert_eq!(layout.frames_per_task, 2);
    let runtime = XolotlBuilder::new()
        .with_execution_config(ExecutionConfig {
            bindings_per_task: 1,
            ..ExecutionConfig::default()
        })
        .build();
    assert_eq!(
        runtime
            .run_prepared(
                IdentityRef::ROOT,
                &[],
                &prepared,
                TaintedValue::pristine(Value::integer(0))
            )
            .await?
            .outcome,
        Outcome::Done(Value::integer(2048))
    );
    Ok(())
}

#[tokio::test]
async fn sequential_forks_fit_peak_storage_budget() -> anyhow::Result<()> {
    use xolotl_sdk::{ExecutionConfig, PreparedProgram, XolotlBuilder};
    let compiled = Program::new(E::Sequence {
        steps: vec![E::literal(1).both(E::literal(2)); 64],
    })
    .compile()?;
    let prepared = PreparedProgram::new(&compiled)?;
    let layout = prepared.layout(&ExecutionConfig::default())?;
    assert_eq!(layout.tasks, 3);
    assert_eq!(layout.frames_per_task, 0);
    let runtime = XolotlBuilder::new()
        .with_execution_config(ExecutionConfig {
            max_storage_bytes: 1024,
            ..ExecutionConfig::default()
        })
        .build();
    assert_eq!(
        runtime
            .run_prepared(
                IdentityRef::ROOT,
                &[],
                &prepared,
                TaintedValue::pristine(Value::null())
            )
            .await?
            .outcome,
        Outcome::Done(Value::list(vec![Value::integer(1), Value::integer(2)]))
    );
    Ok(())
}

#[tokio::test]
async fn shared_frames_and_reusable_buffers_support_independent_requests() -> anyhow::Result<()> {
    use xolotl_sdk::{ExecutionBuffers, ExecutionConfig, PreparedProgram, XolotlBuilder};
    let source = Program::new(
        (0..32)
            .fold(E::Input, |body, _| body.finally(E::Input))
            .both(E::Input),
    );
    let prepared = PreparedProgram::new(&source.compile()?)?;
    let config = ExecutionConfig {
        max_frames: 64,
        max_storage_bytes: 16_384,
        ..ExecutionConfig::default()
    };
    let layout = prepared.layout(&config)?;
    assert_eq!(layout.tasks, 3);
    assert_eq!(layout.frames_per_task, 64);
    assert_eq!(layout.frames, 64);
    let runtime = XolotlBuilder::new().with_execution_config(config).build();
    let mut buffers = ExecutionBuffers::default();
    buffers.reserve_for(&prepared, &config)?;
    let retained = buffers.retained_bytes();
    for input in [1, 40, -7] {
        let result = runtime
            .run_prepared_with_buffers(
                IdentityRef::ROOT,
                &[],
                &prepared,
                TaintedValue::pristine(Value::integer(input)),
                &mut buffers,
            )
            .await?;
        assert_eq!(
            result.outcome,
            Outcome::Done(Value::list(vec![
                Value::integer(input),
                Value::integer(input)
            ]))
        );
        assert_eq!(buffers.retained_bytes(), retained);
    }
    buffers.release();
    assert_eq!(buffers.retained_bytes(), 0);
    Ok(())
}

#[tokio::test]
async fn reused_bindings_preserve_callers_during_parallelism_and_recovery() -> anyhow::Result<()> {
    use xolotl_sdk::{ExecutionConfig, PreparedProgram, XolotlBuilder};
    let call = E::Call {
        function: "worker".into(),
    };
    let mut source = Program::new(E::Let {
        name: "outer".into(),
        value: Box::new(E::literal(10)),
        body: Box::new(
            call.clone()
                .then(E::Use {
                    name: "outer".into(),
                })
                .both(call),
        ),
    });
    source.functions.insert(
        "worker".into(),
        E::Let {
            name: "inner".into(),
            value: Box::new(E::literal(20)),
            body: Box::new(
                E::Catch {
                    body: Box::new(E::Let {
                        name: "inner".into(),
                        value: Box::new(E::literal(30)),
                        body: Box::new(E::Fail {
                            message: "recover".into(),
                        }),
                    }),
                    recover: Box::new(E::Use {
                        name: "inner".into(),
                    }),
                }
                .finally(E::literal(0)),
            ),
        },
    );
    let prepared = PreparedProgram::new(&source.compile()?)?;
    let config = ExecutionConfig {
        bindings_per_task: 2,
        ..ExecutionConfig::default()
    };
    let layout = prepared.layout(&config)?;
    assert_eq!(layout.tasks, 3);
    assert!(layout.frames_per_task < config.frames_per_task);
    let runtime = XolotlBuilder::new().with_execution_config(config).build();
    assert_eq!(
        runtime
            .run_prepared(
                IdentityRef::ROOT,
                &[],
                &prepared,
                TaintedValue::pristine(Value::null())
            )
            .await?
            .outcome,
        Outcome::Done(Value::list(vec![Value::integer(10), Value::integer(20)]))
    );
    Ok(())
}

#[tokio::test]
async fn typed_constants_and_operation_inputs_survive_json_roundtrips() -> anyhow::Result<()> {
    use xolotl_sdk::{OperationTemplate, Path, ResourceName};
    use xolotl_types::{BlobRef, DType, FloatBits, FrameKind, StreamMarker};
    let blob = BlobRef {
        hash: "a".repeat(64),
        size: 4,
        mime: None,
    };
    let value = Value::list(vec![
        Value::bytes(vec![0, 255]),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0001))),
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), DType::F32, vec![1]),
        Value::frame(blob, 7, FrameKind::Audio),
        Value::stream_end(StreamMarker::Done),
        Value::map(std::collections::BTreeMap::from([(
            "type".into(),
            Value::string("blob".into()),
        )])),
    ]);
    let program = Program::new(E::Constant {
        value: value.clone(),
    });
    let decoded: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
    assert_eq!(program.compile()?.id(), decoded.compile()?.id());
    assert_eq!(
        evaluate(decoded, Value::null()).await?,
        Outcome::Done(value.clone())
    );
    let program = Program::new(E::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://echo/typed")?),
            method: "invoke".into(),
            method_id: None,
            output: Default::default(),
            literal_input: Some(value),
        },
    });
    let decoded: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
    assert_eq!(program, decoded);
    Ok(())
}

#[tokio::test]
async fn recursive_subprograms_restore_lexical_bindings() -> anyhow::Result<()> {
    let mut program = Program::new(E::Call {
        function: "count".into(),
    });
    program.functions.insert(
        "count".into(),
        E::If {
            condition: Box::new(E::Transform {
                operation: Transform::LessThan { value: 1 },
            }),
            yes: Box::new(E::literal(0)),
            no: Box::new(E::Let {
                name: "saved".into(),
                value: Box::new(E::Input),
                body: Box::new(
                    E::Transform {
                        operation: Transform::Add { value: -1 },
                    }
                    .then(E::Call {
                        function: "count".into(),
                    })
                    .then(E::Use {
                        name: "saved".into(),
                    }),
                ),
            }),
        },
    );
    assert_eq!(
        evaluate(program, Value::integer(40)).await?,
        Outcome::Done(Value::integer(40))
    );
    Ok(())
}

#[tokio::test]
async fn catch_and_finally_preserve_the_body_result() -> anyhow::Result<()> {
    let body = E::Catch {
        body: Box::new(E::Fail {
            message: "retry".into(),
        }),
        recover: Box::new(E::literal(42)),
    }
    .finally(E::literal(0));
    assert_eq!(
        evaluate(Program::new(body), Value::null()).await?,
        Outcome::Done(Value::integer(42))
    );
    Ok(())
}

#[tokio::test]
async fn durable_programs_cannot_silently_run_in_memory() -> anyhow::Result<()> {
    let mut program = Program::new(E::literal(1));
    program.durable = true;
    let result = evaluate(program, Value::null()).await?;
    assert!(matches!(result, Outcome::Fail(_)));
    Ok(())
}

#[tokio::test]
async fn prepared_programs_reuse_code_with_independent_input_and_storage_limits()
-> anyhow::Result<()> {
    use xolotl_sdk::{ExecutionConfig, PreparedProgram, XolotlBuilder};
    let compiled = Program::new(E::Transform {
        operation: Transform::Add { value: 2 },
    })
    .compile()?;
    let prepared = PreparedProgram::new(&compiled)?;
    let runtime = Xolotl::new();
    for input in [1, 40] {
        assert_eq!(
            runtime
                .run_prepared(
                    IdentityRef::ROOT,
                    &[],
                    &prepared,
                    TaintedValue::pristine(Value::integer(input))
                )
                .await?
                .outcome,
            Outcome::Done(Value::integer(input + 2))
        );
    }
    let bounded = XolotlBuilder::new()
        .with_execution_config(ExecutionConfig {
            max_storage_bytes: 1,
            ..ExecutionConfig::default()
        })
        .build();
    let result = bounded
        .run_prepared(
            IdentityRef::ROOT,
            &[],
            &prepared,
            TaintedValue::pristine(Value::integer(1)),
        )
        .await?;
    assert!(
        matches!(result.outcome, Outcome::Fail(xolotl_sdk::Failure::PolicyViolation { ref detail, .. }) if detail.contains("storage budget"))
    );
    let boot = XolotlBuilder::new()
        .with_execution_config(ExecutionConfig {
            max_storage_bytes: 1,
            ..ExecutionConfig::default()
        })
        .build_bootstrap();
    let result = boot
        .kernel
        .executor_for(boot.root)
        .eval_program(&compiled, TaintedValue::pristine(Value::integer(1)))
        .await;
    assert!(matches!(result.outcome, Outcome::Fail(_)));
    Ok(())
}

#[tokio::test]
async fn recursive_parallel_calls_use_configured_task_capacity() -> anyhow::Result<()> {
    let mut program = Program::new(E::Call {
        function: "tree".into(),
    });
    program.functions.insert(
        "tree".into(),
        E::If {
            condition: Box::new(E::Transform {
                operation: Transform::LessThan { value: 1 },
            }),
            yes: Box::new(E::Input),
            no: Box::new(
                E::Transform {
                    operation: Transform::Add { value: -1 },
                }
                .then(
                    E::Call {
                        function: "tree".into(),
                    }
                    .both(E::Call {
                        function: "tree".into(),
                    }),
                ),
            ),
        },
    );
    let leaf = Value::list(vec![Value::integer(0), Value::integer(0)]);
    assert_eq!(
        evaluate(program, Value::integer(2)).await?,
        Outcome::Done(Value::list(vec![leaf.clone(), leaf]))
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_wakes_a_waiting_program() -> anyhow::Result<()> {
    use xolotl_graph::WaitSpec;
    use xolotl_sdk::Path;
    let runtime = Xolotl::new();
    let boot = runtime.bootstrap();
    let process = boot.spawn_request_process_under_with_compiled_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[],
    )?;
    let compiled = Program::new(
        E::Wait {
            wait: WaitSpec::Signal(Path::parse("state://signal/never")?),
        }
        .finally(E::literal(1)),
    )
    .compile()?;
    let executor = boot.kernel.executor_for(process);
    let run = executor.eval_program(&compiled, TaintedValue::pristine(Value::null()));
    tokio::pin!(run);
    tokio::select! {
        result = &mut run => anyhow::bail!("wait returned before cancellation: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    boot.cancel_process(process)?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), run).await?;
    assert_eq!(
        result.outcome,
        Outcome::Fail(xolotl_sdk::Failure::Cancelled)
    );
    boot.finish_request_process(process, &result).await?;
    Ok(())
}

#[test]
fn compiler_rejects_unknown_names_versions_and_oversized_integers() -> anyhow::Result<()> {
    assert!(
        Program::new(E::Use {
            name: "missing".into()
        })
        .compile()
        .is_err()
    );
    assert!(
        Program::new(E::Call {
            function: "missing".into()
        })
        .compile()
        .is_err()
    );
    assert!(Program::new(E::literal(u64::MAX)).compile().is_err());
    let mut program = Program::new(E::Input);
    program.version = 99;
    assert!(program.compile().is_err());
    Ok(())
}

#[tokio::test]
async fn dropping_prepared_request_cleans_lifecycle_and_releases_buffers() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::task::Poll;
    use xolotl_graph::WaitSpec;
    use xolotl_sdk::{ExecutionBuffers, Path, PreparedProgram};
    let runtime = Xolotl::new();
    let prepared = PreparedProgram::new(
        &Program::new(E::Wait {
            wait: WaitSpec::Signal(Path::parse("state://signal/drop-prepared")?),
        })
        .compile()?,
    )?;
    let mut buffers = ExecutionBuffers::default();
    let mut run = Box::pin(runtime.run_prepared_with_buffers(
        IdentityRef::ROOT,
        &[],
        &prepared,
        TaintedValue::pristine(Value::null()),
        &mut buffers,
    ));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let boot = runtime.bootstrap();
    let process = boot
        .kernel
        .processes
        .children_of(boot.root)
        .into_iter()
        .next()
        .context("missing request")?;
    drop(run);
    assert_eq!(
        boot.kernel.processes.status(process),
        Some(xolotl_types::ProcessStatus::Cancelled)
    );
    let report = runtime.drain_cleanup().await;
    assert!(report.failures.is_empty());
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        boot.kernel
            .processes
            .lifecycle_execution(process)
            .context("missing lifecycle scope")?
            .get()
    ))?;
    assert!(boot.kernel.state.read(&marker).await?.is_some());

    let next = PreparedProgram::new(&Program::new(E::Input).compile()?)?;
    assert_eq!(
        runtime
            .run_prepared_with_buffers(
                IdentityRef::ROOT,
                &[],
                &next,
                TaintedValue::pristine(Value::integer(41)),
                &mut buffers,
            )
            .await?
            .outcome,
        Outcome::Done(Value::integer(41))
    );
    Ok(())
}

#[cfg(feature = "standard")]
#[tokio::test]
async fn portable_effects_use_existing_resource_authority() -> anyhow::Result<()> {
    use xolotl_sdk::{OperationTemplate, Path, ResourceName, StandardConfig};
    let runtime = Xolotl::with_standard(&StandardConfig::default())?;
    let program = Program::new(E::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: Default::default(),
            literal_input: None,
        },
    })
    .compile()?;
    assert!(matches!(
        runtime
            .run_program(
                IdentityRef::ROOT,
                &[],
                &program,
                TaintedValue::pristine(Value::null())
            )
            .await?
            .outcome,
        Outcome::Fail(_)
    ));
    assert!(matches!(
        runtime
            .run_program(
                IdentityRef::ROOT,
                &["effect://time/now"],
                &program,
                TaintedValue::pristine(Value::null())
            )
            .await?
            .outcome,
        Outcome::Done(_)
    ));
    Ok(())
}
