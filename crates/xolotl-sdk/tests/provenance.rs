#![cfg(feature = "host")]

use anyhow::ensure;
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_kernel::{DriverOutput, FnDriver, MethodSpec};
use xolotl_sdk::{
    Driver, DriverContext, DriverError, ExecutionConfig, Expression, Failure, IdentityRef,
    KernelBuilder, OperationTemplate, Outcome, Path, PreparedProgram, Program, TaintSet,
    TaintedValue, Value, Xolotl,
};
use xolotl_types::{MethodId, OutputMode, Purity, ResourceName, TaintSource};

struct ProtectedRead(TaintSet);

#[async_trait]
impl Driver for ProtectedRead {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        _context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let outcome = if input == Value::boolean(true) {
            Outcome::Fail(Failure::HandlerError {
                kind: "private-report".into(),
                message: "protected diagnostic".into(),
            })
        } else {
            Outcome::Done(Value::string("protected value".into()))
        };
        Ok(DriverOutput::new(outcome).with_taint(self.0.clone()))
    }
}

fn invoke(target: ResourceName) -> anyhow::Result<PreparedProgram> {
    let source = Program::new(Expression::Invoke {
        operation: OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    });
    Ok(PreparedProgram::from_compiled(source.compile()?)?)
}

#[tokio::test]
async fn separate_requests_cannot_clear_success_or_failure_lineage() -> anyhow::Result<()> {
    let runtime = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/report")?,
    });
    let source = runtime.bootstrap().register_effect(
        "effect://provenance/read",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(ProtectedRead(taint.clone())),
    )?;
    let sent = Arc::new(AtomicUsize::new(0));
    let observed = sent.clone();
    let sink = runtime.bootstrap().register_effect(
        "effect://provenance/send",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )
        .unprotected_input()],
        Arc::new(FnDriver(move |_, input| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    let source = invoke(source)?;
    let sink = invoke(sink)?;
    for failure in [false, true] {
        let first = runtime
            .run_prepared(
                IdentityRef::ROOT,
                &["effect://provenance/read"],
                &source,
                TaintedValue::pristine(Value::boolean(failure)),
            )
            .await?
            .output;
        ensure!(first.taint == taint);
        let (first_result, unresolved) = first.into_parts();
        ensure!(unresolved.is_empty());
        let input = match first_result {
            Ok(value) => {
                ensure!(!failure && value.value == Value::string("protected value".into()));
                value
            }
            Err(error) => {
                ensure!(failure);
                let value = error.into_value();
                ensure!(
                    value
                        .value
                        .as_str()
                        .is_some_and(|text| text.contains("protected diagnostic"))
                );
                value
            }
        };
        let second = runtime
            .run_prepared(
                IdentityRef::ROOT,
                &["effect://provenance/send"],
                &sink,
                input,
            )
            .await?
            .output;
        ensure!(
            matches!(second.outcome, Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "taint")
        );
        ensure!(second.taint == taint);
    }
    ensure!(sent.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn program_admission_failure_preserves_submitted_input_lineage() -> anyhow::Result<()> {
    let runtime = Xolotl::from_kernel(
        KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
            .with_execution_config(ExecutionConfig {
                max_storage_bytes: 1,
                ..ExecutionConfig::default()
            })
            .build(),
    );
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/input")?,
    });
    let program = Program::new(Expression::Input).compile()?;
    let result = runtime
        .run_program(
            IdentityRef::ROOT,
            &[],
            &program,
            TaintedValue::new(Value::integer(23), taint.clone()),
        )
        .await?
        .output;
    ensure!(matches!(
        result.outcome,
        Outcome::Fail(Failure::PolicyViolation { .. })
    ));
    ensure!(result.taint == taint);
    Ok(())
}
