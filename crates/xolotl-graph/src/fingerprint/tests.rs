use crate::{
    DoNode, OperationTemplate, StepRef, compile_do,
    portable::{Expression, Program, Transform},
};
use anyhow::ensure;
use xolotl_types::{OutputMode, Path, ResourceName, Value};

fn operation(value: Value) -> anyhow::Result<OperationTemplate> {
    Ok(OperationTemplate {
        target: ResourceName::new(Path::parse("effect://test/invoke")?),
        method: "run".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(value),
    })
}

fn equal_layouts() -> (Value, Value) {
    let leaf = Value::list(vec![Value::string("shared".into()), Value::integer(42)]);
    let shared = Value::list(vec![leaf.clone(), leaf]);
    let separate = Value::list(vec![
        Value::list(vec![Value::string("shared".into()), Value::integer(42)]),
        Value::list(vec![Value::string("shared".into()), Value::integer(42)]),
    ]);
    (shared, separate)
}

#[test]
fn native_identity_uses_value_semantics_for_every_literal_location() -> anyhow::Result<()> {
    let (shared, separate) = equal_layouts();
    ensure!(shared == separate);
    let native = |value: Value| -> anyhow::Result<_> {
        let left = DoNode::pure(value.clone())
            .and_then(StepRef::new("next").with_arg(value.clone()))
            .or_else(StepRef::new("recover").with_arg(value.clone()));
        Ok(compile_do(&DoNode::both(left, DoNode::op(operation(value)?)))?.graph_hash)
    };
    ensure!(native(shared)? == native(separate)?);
    Ok(())
}

#[test]
fn portable_identity_uses_value_semantics_for_constants_and_imports() -> anyhow::Result<()> {
    let (shared, separate) = equal_layouts();
    let portable = |value: Value| -> anyhow::Result<_> {
        Ok(Program::new(
            Expression::Constant {
                value: value.clone(),
            }
            .then(Expression::Invoke {
                operation: operation(value.clone())?,
            })
            .then(Expression::Transform {
                operation: Transform::Equal {
                    value: value.clone(),
                },
            })
            .then(Expression::Module {
                module: StepRef::new("next").with_arg(value),
            }),
        )
        .compile()?
        .id())
    };
    ensure!(portable(shared)? == portable(separate)?);
    Ok(())
}

#[test]
fn program_fingerprints_do_not_expand_repeated_subgraphs() -> anyhow::Result<()> {
    let mut value = Value::bytes(vec![7; 1024]);
    for _ in 0..128 {
        value = Value::list(vec![value.clone(), value]);
    }
    let graph = compile_do(&DoNode::pure(value.clone()))?;
    let program = Program::new(Expression::Constant { value });
    ensure!(graph.graph_hash != [0; 32]);
    ensure!(program.compile()?.id() != [0; 32]);
    Ok(())
}

#[test]
fn portable_identity_binds_metadata_control_and_durability() -> anyhow::Result<()> {
    let program = Program::new(Expression::Invoke {
        operation: operation(Value::integer(1))?,
    });
    let original = program.compile()?.id();
    let mut durable = program.clone();
    durable.durable = true;
    ensure!(original != durable.compile()?.id());
    let mut changed = operation(Value::integer(1))?;
    changed.method = "another".into();
    ensure!(
        original
            != Program::new(Expression::Invoke { operation: changed })
                .compile()?
                .id()
    );
    ensure!(
        original
            != Program::new(program.body.then(Expression::Input))
                .compile()?
                .id()
    );
    Ok(())
}
