//! Run the same composed program from Rust or JSON, reusing prepared instructions.

use std::io::Write;
use xolotl_sdk::{
    ExecutionBuffers, ExecutionConfig, Expression as E, IdentityRef, PreparedProgram, Program,
    TaintedValue, Transform, Value, Xolotl,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let source = Program::new(
        E::While {
            condition: Box::new(E::Transform {
                operation: Transform::LessThan { value: 5 },
            }),
            body: Box::new(E::Transform {
                operation: Transform::Add { value: 1 },
            }),
            max_iterations: 5,
        }
        .both(E::literal("ready")),
    );
    let json = serde_json::to_vec(&source)?;
    let decoded = Program::from_json(&json)?;
    let compiled = decoded.compile()?;
    anyhow::ensure!(source.compile()?.id() == compiled.id());
    let prepared = PreparedProgram::new(&compiled)?;
    let mut buffers = ExecutionBuffers::default();
    writeln!(
        std::io::stdout().lock(),
        "execution layout: {:?}",
        buffers.reserve_for(&prepared, &ExecutionConfig::default())?
    )?;
    let runtime = Xolotl::new();
    for input in [0, 3] {
        let output = runtime
            .run_prepared_with_buffers(
                IdentityRef::ROOT,
                &[],
                &prepared,
                TaintedValue::pristine(Value::integer(input)),
                &mut buffers,
            )
            .await?;
        writeln!(std::io::stdout().lock(), "input={input}, output={output:?}")?;
    }
    Ok(())
}
