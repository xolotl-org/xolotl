use super::*;
use anyhow::{Context, bail, ensure};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AdmissionWork {
    value_entries: usize,
    leaves: usize,
    imports: usize,
}

std::thread_local! {
    static ADMISSION_WORK: core::cell::Cell<AdmissionWork> = const {
        core::cell::Cell::new(AdmissionWork {
            value_entries: 0,
            leaves: 0,
            imports: 0,
        })
    };
}

pub(super) fn record_value_entry() {
    ADMISSION_WORK.with(|work| {
        let mut counts = work.get();
        counts.value_entries += 1;
        work.set(counts);
    });
}

pub(super) fn record_leaf() {
    ADMISSION_WORK.with(|work| {
        let mut counts = work.get();
        counts.leaves += 1;
        work.set(counts);
    });
}

pub(super) fn record_import() {
    ADMISSION_WORK.with(|work| {
        let mut counts = work.get();
        counts.imports += 1;
        work.set(counts);
    });
}

fn reset_work() {
    ADMISSION_WORK.with(|work| work.set(AdmissionWork::default()));
}

fn admission_work() -> AdmissionWork {
    ADMISSION_WORK.with(core::cell::Cell::get)
}

fn compiler<'source>(instructions: usize) -> Compiler<'source> {
    Compiler {
        limits: CompileLimits {
            instructions,
            ..CompileLimits::default()
        },
        nodes: Vec::new(),
        reserved: 0,
        imports: Vec::new(),
        bindings: 0,
        live_bindings: 0,
        names: BTreeMap::new(),
        functions: BTreeMap::new(),
        calls: Vec::new(),
    }
}

#[test]
fn sequences_preserve_binding_restoration_and_function_relocations() -> anyhow::Result<()> {
    let mut source = Program::new(Expression::Let {
        name: "value".into(),
        value: Box::new(Expression::literal(1)),
        body: Box::new(Expression::Sequence {
            steps: vec![
                Expression::Use {
                    name: "value".into(),
                },
                Expression::Let {
                    name: "value".into(),
                    value: Box::new(Expression::literal(2)),
                    body: Box::new(Expression::Use {
                        name: "value".into(),
                    }),
                },
                Expression::Use {
                    name: "value".into(),
                },
                Expression::Call {
                    function: "helper".into(),
                },
            ],
        }),
    });
    source
        .functions
        .insert("helper".into(), Expression::literal(3));
    let compiled = source.compile()?;
    let image = compiled.image();
    image.validate()?;
    ensure!(image.entry == 7 && image.bindings == 2 && image.nodes.len() == 9);
    let slots: Vec<_> = image
        .nodes
        .iter()
        .filter_map(|node| match node.kind {
            NodeKind::Load(slot) => Some(slot),
            _ => None,
        })
        .collect();
    ensure!(slots == [0, 1, 0]);
    ensure!(matches!(image.nodes[1].kind, NodeKind::Call(8)));
    ensure!(image.nodes[6].next == Some(5));
    ensure!(image.nodes[5].next == Some(2));
    ensure!(image.nodes[2].next == Some(1));
    ensure!(image.nodes[4].next.is_none());
    ensure!(matches!(
        image.nodes[7].kind,
        NodeKind::Let {
            slot: 0,
            value: 0,
            body: 6
        }
    ));
    Ok(())
}

#[test]
fn raised_depth_compiles_on_small_stack_and_preserves_admission_limits() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let depth = 10_000;
            let mut body = Expression::Input;
            for _ in 0..depth {
                body = Expression::Sequence { steps: vec![body] };
            }
            let program = Program::new(body);
            ensure!(matches!(program.compile(), Err(CompileError::Capacity)));
            let limits = CompileLimits {
                expression_depth: depth,
                ..CompileLimits::default()
            };
            let compiled = program.compile_with_limits(limits)?;
            ensure!(compiled.image().nodes.len() == 1);
            ensure!(compiled.id() == Program::new(Expression::Input).compile()?.id());
            ensure!(matches!(
                program.compile_with_limits(CompileLimits {
                    instructions: 0,
                    ..limits
                }),
                Err(CompileError::Capacity)
            ));
            ensure!(matches!(
                program.compile_with_limits(CompileLimits {
                    expression_depth: depth - 1,
                    ..limits
                }),
                Err(CompileError::Capacity)
            ));
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("small-stack compiler worker panicked"))?
}

#[test]
fn deep_composite_lowering_restores_shadowed_names_and_import_order() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let identity = Path::parse("identity://compiler-test")?;
            let depth = 4_000;
            let mut body = Expression::Use {
                name: "value".into(),
            };
            for level in 0..depth {
                body = match level % 4 {
                    0 => Expression::Let {
                        name: "value".into(),
                        value: Box::new(Expression::Input),
                        body: Box::new(body),
                    },
                    1 => Expression::If {
                        condition: Box::new(Expression::Input),
                        yes: Box::new(body),
                        no: Box::new(Expression::Use {
                            name: "value".into(),
                        }),
                    },
                    2 => Expression::Acting {
                        identity: identity.clone(),
                        body: Box::new(body),
                    },
                    _ => Expression::Sequence {
                        steps: vec![
                            body,
                            Expression::Use {
                                name: "value".into(),
                            },
                        ],
                    },
                };
            }
            let program = Program::new(Expression::Let {
                name: "value".into(),
                value: Box::new(Expression::Input),
                body: Box::new(body),
            });
            let compiled = program.compile_with_limits(CompileLimits {
                expression_depth: depth + 1,
                ..CompileLimits::default()
            })?;
            let image = compiled.image();
            image.validate()?;
            ensure!(image.bindings == 1_001);
            ensure!(compiled.imports().len() == 1_000);
            let scopes: Vec<_> = image
                .nodes
                .iter()
                .filter_map(|node| match node.kind {
                    NodeKind::Scope { import, .. } => Some(import),
                    _ => None,
                })
                .collect();
            ensure!(scopes == (0..1_000).rev().collect::<Vec<_>>());
            ensure!(
                image
                    .nodes
                    .iter()
                    .any(|node| matches!(node.kind, NodeKind::Load(1_000)))
            );
            ensure!(
                image
                    .nodes
                    .iter()
                    .any(|node| matches!(node.kind, NodeKind::Load(0)))
            );
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("small-stack composite worker panicked"))?
}

#[test]
fn nested_sequences_link_tails_without_changing_allocation_order() -> anyhow::Result<()> {
    let compiled = Program::new(Expression::Sequence {
        steps: vec![
            Expression::Sequence {
                steps: vec![Expression::literal(1), Expression::literal(2)],
            },
            Expression::Sequence {
                steps: vec![Expression::literal(3), Expression::literal(4)],
            },
        ],
    })
    .compile()?;
    let image = compiled.image();
    ensure!(image.entry == 3 && image.nodes.len() == 4);
    for (index, node) in image.nodes.iter().enumerate() {
        let NodeKind::Literal(value) = &node.kind else {
            bail!("expected literal");
        };
        ensure!(*value == Value::integer(4 - index as i64));
        ensure!(node.next == index.checked_sub(1).map(|previous| previous as u32));
    }
    Ok(())
}

#[test]
fn host_import_binding_fingerprints_effective_code_and_preserves_request_kinds()
-> anyhow::Result<()> {
    use xolotl_types::{OutputMode, ResourceName};
    let path = Path::parse("state://signals/ready")?;
    let operation = OperationTemplate {
        target: ResourceName::new(path.clone()),
        method: "subscribe".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let source = Program::new(Expression::Wait {
        wait: WaitSpec::Signal(path.clone()),
    })
    .compile()?;
    let identity = source.id();
    ensure!(source.clone().map_imports(|import| import)?.id() == identity);
    let bound = source
        .clone()
        .map_imports(|_| Import::Operation(operation.clone()))?;
    let explicit = Program::new(Expression::Invoke { operation }).compile()?;
    ensure!(bound.id() != identity && bound.id() == explicit.id());
    bound.image().validate()?;
    ensure!(bound.image().entry == source.image().entry);
    ensure!(matches!(
        source.map_imports(|_| Import::Scope(path.clone())),
        Err(CompileError::ImportKind)
    ));
    let scope = Program::new(Expression::Acting {
        identity: path,
        body: Box::new(Expression::Input),
    })
    .compile()?;
    ensure!(matches!(
        scope.map_imports(|_| Import::Wait(WaitSpec::Deadline(0))),
        Err(CompileError::ImportKind)
    ));
    Ok(())
}

#[test]
fn runtime_preparation_moves_payloads_and_preserves_artifact_identity() -> anyhow::Result<()> {
    let compiled = Program::new(Expression::Constant {
        value: Value::bytes(vec![42; 1024 * 1024]),
    })
    .compile_with_limits(CompileLimits {
        source_bytes: 2 * 1024 * 1024,
        ..CompileLimits::default()
    })?;
    let identity = compiled.id();
    let NodeKind::Literal(value) = &compiled.image().nodes[0].kind else {
        bail!("expected a byte constant");
    };
    let bytes = value.as_bytes().context("expected byte payload")?;
    let payload = bytes.as_ptr();
    let prepared = compiled.with_provenance();
    let NodeKind::Literal(value) = &prepared.image().nodes[0].kind else {
        bail!("expected the prepared constant");
    };
    let bytes = value
        .value
        .as_bytes()
        .context("expected original byte payload")?;
    ensure!(
        bytes.as_ptr() == payload,
        "preparation cloned the payload buffer"
    );
    ensure!(bytes.len() == 1024 * 1024);
    ensure!(value.taint == xolotl_types::TaintSet::author());
    ensure!(prepared.id() == identity);
    prepared.image().validate()?;
    Ok(())
}

#[test]
fn runtime_preparation_preserves_static_failures_in_the_tainted_error_type() -> anyhow::Result<()> {
    let compiled = Program::new(Expression::Fail {
        message: "authored failure".into(),
    })
    .compile()?;
    let identity = compiled.id();
    let prepared = compiled.with_provenance();
    let NodeKind::Fail(error) = &prepared.image().nodes[0].kind else {
        bail!("expected the prepared failure");
    };
    ensure!(error.failure == Failure::policy("program", "authored failure"));
    ensure!(error.taint.is_pristine());
    ensure!(prepared.id() == identity);
    prepared.image().validate()?;
    Ok(())
}

#[test]
fn large_module_uses_explicit_admission() -> anyhow::Result<()> {
    let program = Program::new(Expression::Sequence {
        steps: vec![Expression::Input; 65_537],
    });
    ensure!(matches!(program.compile(), Err(CompileError::Capacity)));
    let compiled = program.compile_with_limits(CompileLimits {
        instructions: 65_537,
        ..CompileLimits::default()
    })?;
    ensure!(compiled.image().nodes.len() == 65_537);
    Ok(())
}

#[test]
fn source_bytes_are_a_host_selected_module_budget() -> anyhow::Result<()> {
    let program = Program::new(Expression::literal("x".repeat(1024 * 1024)));
    let encoded = serde_json::to_vec(&program)?;
    ensure!(matches!(
        Program::from_json(&encoded),
        Err(CompileError::Capacity)
    ));
    let limits = CompileLimits {
        source_bytes: encoded.len(),
        ..CompileLimits::default()
    };
    let decoded = Program::from_json_with_limits(&encoded, limits)?;
    ensure!(decoded == program);
    ensure!(matches!(
        Program::from_json_with_limits(
            &encoded,
            CompileLimits {
                source_bytes: encoded.len() - 1,
                ..limits
            }
        ),
        Err(CompileError::Capacity)
    ));
    Ok(())
}

#[test]
fn admission_does_not_change_program_identity() -> anyhow::Result<()> {
    let program = Program::new(Expression::literal(7));
    let default = program.compile()?;
    let small = program.compile_with_limits(CompileLimits {
        instructions: 1,
        expression_depth: 0,
        ..CompileLimits::default()
    })?;
    ensure!(default.id() == small.id());
    ensure!(default.image().nodes == small.image().nodes);
    ensure!(matches!(
        program.compile_with_limits(CompileLimits {
            instructions: 0,
            ..CompileLimits::default()
        }),
        Err(CompileError::Capacity)
    ));
    Ok(())
}

#[test]
fn resident_source_shape_is_checked_before_lowering() -> anyhow::Result<()> {
    let limits = CompileLimits {
        expression_depth: 4,
        ..CompileLimits::default()
    };
    let mut expression = Expression::Input;
    let identity = Path::parse("identity://tests/actor")?;
    for _ in 0..5 {
        expression = Expression::Acting {
            identity: identity.clone(),
            body: Box::new(expression),
        };
    }
    let program = Program::new(expression);
    ensure!(matches!(
        program.validate_structure_with_limits(limits),
        Err(CompileError::Capacity)
    ));
    ensure!(matches!(
        program.compile_with_limits(limits),
        Err(CompileError::Capacity)
    ));

    let mut literal = serde_json::Value::Null;
    for _ in 0..shape::MAX_LITERAL_DEPTH {
        literal = serde_json::Value::Array(vec![literal]);
    }
    let program = Program::new(Expression::Literal { value: literal });
    ensure!(matches!(
        program.validate_structure_with_limits(CompileLimits::default()),
        Err(CompileError::Capacity)
    ));
    Ok(())
}

#[test]
fn every_embedded_value_location_has_the_same_depth_admission() -> anyhow::Result<()> {
    use xolotl_types::{OutputMode, ResourceName};

    let mut value = Value::null();
    for _ in 0..shape::MAX_RESIDENT_DEPTH {
        value = Value::list(vec![value]);
    }
    let operation = OperationTemplate {
        target: ResourceName::new(Path::parse("state://tests/resource")?),
        method: "read".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(value.clone()),
    };
    for expression in [
        Expression::Constant {
            value: value.clone(),
        },
        Expression::Invoke { operation },
        Expression::Module {
            module: StepRef::new("module").with_arg(value.clone()),
        },
        Expression::Transform {
            operation: Transform::Equal { value },
        },
    ] {
        ensure!(matches!(
            Program::new(expression).validate_structure_with_limits(CompileLimits::default()),
            Err(CompileError::Capacity)
        ));
    }
    Ok(())
}

#[test]
fn source_lower_bound_rejects_oversized_constants_without_serializing() -> anyhow::Result<()> {
    use xolotl_types::{OutputMode, ResourceName};

    let limits = CompileLimits {
        source_bytes: 256,
        ..CompileLimits::default()
    };
    let long_path = Path::parse(&format!("effect://{}", "x".repeat(257)))?;
    for program in [
        Program::new(Expression::literal("x".repeat(257))),
        Program::new(Expression::Constant {
            value: Value::bytes(vec![42; 257]),
        }),
        Program::new(Expression::Invoke {
            operation: OperationTemplate {
                target: ResourceName::new(long_path.clone()),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            },
        }),
        Program::new(Expression::Wait {
            wait: WaitSpec::Signal(long_path.clone()),
        }),
        Program::new(Expression::Acting {
            identity: long_path,
            body: Box::new(Expression::Input),
        }),
    ] {
        ensure!(matches!(
            program.validate_structure_with_limits(limits),
            Err(CompileError::Capacity)
        ));
        ensure!(matches!(
            program.compile_with_limits(limits),
            Err(CompileError::Capacity)
        ));
    }
    Ok(())
}

#[test]
fn reference_edges_refuse_wide_collections_before_descending() -> anyhow::Result<()> {
    let shared = Value::list(vec![Value::null()]);
    let list = Value::list((0..512).map(|_| shared.clone()).collect());
    let map = Value::map(
        (0..512)
            .map(|index| (index.to_string(), shared.clone()))
            .collect(),
    );
    for value in [list, map] {
        let program = Program::new(Expression::Constant { value });
        reset_work();
        ensure!(matches!(
            program.compile_with_limits(CompileLimits {
                source_bytes: 32,
                ..CompileLimits::default()
            }),
            Err(CompileError::Capacity)
        ));
        ensure!(
            admission_work()
                == AdmissionWork {
                    value_entries: 1,
                    ..AdmissionWork::default()
                }
        );
    }
    Ok(())
}

#[test]
fn shared_nodes_are_memoized_but_each_reference_is_charged() -> anyhow::Result<()> {
    let shared = Value::list(vec![Value::null()]);
    let program = Program::new(Expression::Constant {
        value: Value::list((0..512).map(|_| shared.clone()).collect()),
    });
    let limits = CompileLimits {
        source_bytes: 518,
        ..CompileLimits::default()
    };
    reset_work();
    program.validate_structure_with_limits(limits)?;
    ensure!(admission_work().value_entries == 3);
    ensure!(serde_json::to_vec(&program)?.len() > limits.source_bytes);
    ensure!(matches!(
        program.validate_structure_with_limits(CompileLimits {
            source_bytes: 517,
            ..limits
        }),
        Err(CompileError::Capacity)
    ));
    Ok(())
}

#[test]
fn reference_metadata_is_admitted_before_lowering_or_hashing() -> anyhow::Result<()> {
    use xolotl_types::{BlobRef, DType, FrameKind, StreamMarker};

    let short = BlobRef {
        hash: "h".into(),
        size: u64::MAX,
        mime: None,
    };
    let long_hash = BlobRef {
        hash: "h".repeat(257),
        ..short.clone()
    };
    let long_mime = BlobRef {
        mime: Some("m".repeat(257)),
        ..short.clone()
    };
    let values = [
        Value::blob(long_hash.clone()),
        Value::blob(long_mime.clone()),
        Value::tensor(long_hash.clone(), DType::U8, vec![]),
        Value::tensor(long_mime.clone(), DType::U8, vec![]),
        Value::tensor(short.clone(), DType::U8, vec![0; 257]),
        Value::frame(long_hash, 0, FrameKind::Audio),
        Value::frame(long_mime, 0, FrameKind::Video),
        Value::stream_end(StreamMarker::Error {
            message: "e".repeat(257),
        }),
    ];
    let limits = CompileLimits {
        source_bytes: 256,
        ..CompileLimits::default()
    };
    for value in values {
        let program = Program::new(Expression::Constant { value });
        reset_work();
        ensure!(matches!(
            program.compile_with_limits(limits),
            Err(CompileError::Capacity)
        ));
        ensure!(
            admission_work()
                == AdmissionWork {
                    value_entries: 1,
                    ..AdmissionWork::default()
                }
        );
    }
    Program::new(Expression::Constant {
        value: Value::blob(short),
    })
    .validate_structure_with_limits(limits)?;
    Ok(())
}

#[test]
fn instruction_refusal_precedes_payload_work_and_import_registration() -> anyhow::Result<()> {
    use xolotl_types::{OutputMode, ResourceName};

    let identity = Path::parse("identity://tests/actor")?;
    let expressions = [
        Expression::literal("x".repeat(4096)),
        Expression::Constant {
            value: Value::bytes(vec![42; 4096]),
        },
        Expression::Invoke {
            operation: OperationTemplate {
                target: ResourceName::new(Path::parse("effect://tests/resource")?),
                method: "x".repeat(4096),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::bytes(vec![42; 4096])),
            },
        },
        Expression::Module {
            module: StepRef::new("x".repeat(4096)),
        },
        Expression::Transform {
            operation: Transform::Field {
                name: "x".repeat(4096),
            },
        },
        Expression::Wait {
            wait: WaitSpec::Signal(identity.clone()),
        },
        Expression::Acting {
            identity,
            body: Box::new(Expression::literal("x".repeat(4096))),
        },
        Expression::Sequence { steps: vec![] },
        Expression::Call {
            function: "helper".into(),
        },
        Expression::Fail {
            message: "x".repeat(4096),
        },
    ];
    for expression in expressions {
        let mut compiler = compiler(0);
        reset_work();
        ensure!(matches!(
            compiler.lower(&expression, 0),
            Err(CompileError::Capacity)
        ));
        ensure!(admission_work() == AdmissionWork::default());
        ensure!(compiler.nodes.is_empty() && compiler.imports.is_empty());
        ensure!(compiler.calls.is_empty() && compiler.reserved == 0);
    }
    Ok(())
}

#[test]
fn parent_and_synthetic_instructions_reserve_capacity_before_child_work() -> anyhow::Result<()> {
    let expressions = [
        Expression::Let {
            name: "value".into(),
            value: Box::new(Expression::literal("x".repeat(4096))),
            body: Box::new(Expression::Input),
        },
        Expression::If {
            condition: Box::new(Expression::literal("x".repeat(4096))),
            yes: Box::new(Expression::Input),
            no: Box::new(Expression::Input),
        },
    ];
    for expression in expressions {
        let mut compiler = compiler(1);
        reset_work();
        ensure!(matches!(
            compiler.lower(&expression, 0),
            Err(CompileError::Capacity)
        ));
        ensure!(admission_work() == AdmissionWork::default());
        ensure!(compiler.nodes.is_empty() && compiler.imports.is_empty());
        ensure!(compiler.reserved == 1);
    }

    let expression = Expression::Sequence {
        steps: vec![
            Expression::Module {
                module: StepRef::new("x".repeat(4096)),
            },
            Expression::Sequence { steps: vec![] },
        ],
    };
    let mut compiler = compiler(1);
    reset_work();
    ensure!(matches!(
        compiler.lower(&expression, 0),
        Err(CompileError::Capacity)
    ));
    ensure!(admission_work() == AdmissionWork::default());
    ensure!(compiler.nodes.len() == 1 && compiler.imports.is_empty());
    ensure!(matches!(compiler.nodes[0].kind, NodeKind::Input));
    Ok(())
}
