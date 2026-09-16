//! Compose native functions and loaded portable programs in the same execution.
use std::io::Write;
use xolotl_sdk::{
    DoNode, ExecutionConfig, Expression, Failure, LoaderRevision, Outcome, PreparedProgram,
    Program, StepModule, StepRef, Transform, Value, XolotlBuilder,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let math = StepModule::single("math/double", |input, _| match input.as_int() {
        Some(value) => match value.checked_mul(2) {
            Some(value) => DoNode::pure(value),
            None => DoNode::fail(Failure::InvalidInput {
                reason: "integer overflow".into(),
            }),
        },
        _ => DoNode::fail(Failure::InvalidInput {
            reason: "expected integer".into(),
        }),
    })?;
    let pipeline = StepModule::single("pipeline", |input, _| {
        DoNode::pure(input).and_then(StepRef::new("math/double"))
    })?;
    let prepared = PreparedProgram::from_compiled(
        Program::new(
            Expression::Transform {
                operation: Transform::Add { value: 1 },
            }
            .then(Expression::Module {
                module: StepRef::new("math/double"),
            }),
        )
        .compile()?,
    )?;
    let portable = StepModule::program(
        "portable/math",
        LoaderRevision::from_bytes([1; 32]),
        move |_, _| Ok(prepared.clone()),
    )?;
    let module = StepModule::compose([math, pipeline, portable])?;
    let runtime = XolotlBuilder::new()
        .with_execution_config(ExecutionConfig {
            max_storage_bytes: 2048,
            ..ExecutionConfig::default()
        })
        .build();
    for input in [21, 7] {
        for (entry, expected) in [("pipeline", input * 2), ("portable/math", (input + 1) * 2)] {
            let program = DoNode::pure(input).and_then(StepRef::new(entry));
            let output = runtime.run_with_steps(&[], program, module.clone()).await?;
            anyhow::ensure!(output.outcome == Outcome::Done(Value::integer(expected)));
            writeln!(
                std::io::stdout().lock(),
                "entry={entry}, input={input}, output={output:?}"
            )?;
        }
    }
    Ok(())
}
