//! Test provider for the named subscribe method used by Signal waits.

use crate::{Bootstrap, Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use std::sync::Arc;
use xolotl_state::Backend;
use xolotl_types::{
    Failure, InterfaceFamily, MethodAuthority, MethodId, Outcome, OutputMode, Purity, Value,
};

struct SignalDriver(Backend);

pub(crate) fn signal_driver(state: Backend) -> crate::driver::DynDriver {
    Arc::new(SignalDriver(state))
}

#[async_trait::async_trait]
impl Driver for SignalDriver {
    async fn call(
        &self,
        method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let path = ctx
            .target_path
            .as_ref()
            .ok_or_else(|| DriverError::Other("missing signal target".into()))?;
        let (current, mut events) = match self.0.observe_signal(path).await {
            Ok(observation) => observation,
            Err(error) => {
                return Ok(DriverOutput::new(Outcome::Fail(Failure::policy(
                    "state",
                    error.to_string(),
                )))
                .with_taint(error.taint));
            }
        };
        let mut observed = current.taint;
        if let Some(value) = current.value {
            return Ok(DriverOutput::new(Outcome::Done(value)).with_taint(observed));
        }
        loop {
            match events.recv().await {
                Ok(event) if event.path() != path => continue,
                Ok(event) => {
                    observed.union(event.taint());
                    let current = match self.0.observe_signal_current(path).await {
                        Ok(current) => current,
                        Err(error) => {
                            observed.union(&error.taint);
                            return Ok(DriverOutput::new(Outcome::Fail(Failure::policy(
                                "state",
                                error.to_string(),
                            )))
                            .with_taint(observed));
                        }
                    };
                    observed.union(&current.taint);
                    if let Some(value) = current.value {
                        return Ok(DriverOutput::new(Outcome::Done(value)).with_taint(observed));
                    }
                }
                Err(error) => {
                    return Ok(DriverOutput::new(Outcome::Fail(Failure::policy(
                        "state",
                        error.to_string(),
                    )))
                    .with_taint(observed));
                }
            }
        }
    }
}

pub(crate) fn install_signal_resource(boot: &Bootstrap, state: Backend) -> anyhow::Result<()> {
    boot.register_subtree_resource(
        "state",
        InterfaceFamily::Value,
        &[MethodSpec::new(
            "subscribe",
            MethodAuthority::Subscribe,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )
        .observes_external()
        .finalize_allowed()],
        signal_driver(state),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompiledRequestGrantTemplate;
    use anyhow::ensure;
    use std::collections::BTreeMap;
    use xolotl_graph::{
        OperationTemplate, WaitSpec,
        portable::{Expression, Program},
    };
    use xolotl_types::{
        Capability, ConstraintSet, Expiry, Grant, IdentityRef, Path, ResourceName,
        ResourceSelector, RightFlags, TaintedValue, cap::Predicate,
    };

    fn signal_program(path: &Path) -> anyhow::Result<xolotl_graph::portable::CompiledProgram> {
        Ok(Program::new(Expression::Wait {
            wait: WaitSpec::Signal(path.clone()),
        })
        .compile()?)
    }

    fn input(tenant: &str, purpose: &str) -> Value {
        Value::map(BTreeMap::from([
            ("tenant".into(), Value::string(tenant.into())),
            ("purpose".into(), Value::string(purpose.into())),
        ]))
    }

    #[tokio::test]
    async fn native_signal_wait_checks_grant_and_source_policy_against_its_input()
    -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
        install_signal_resource(&boot, boot.kernel().state().clone())?;
        let path = Path::parse("state://signal/conditional")?;
        boot.kernel()
            .state()
            .write_set(&path, Value::integer(42))
            .await?;
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root(),
            IdentityRef::ROOT,
            &[CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse(
                    "subscribe://state/signal/conditional@tenant=alice",
                )?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name("subscribe"),
                    RightFlags::empty(),
                ),
            }],
        )?;
        boot.kernel()
            .registry()
            .register_policy(Arc::new(crate::CapabilityPolicy {
                pattern: Capability::parse("subscribe://state/signal/conditional")?,
                constraints: ConstraintSet {
                    predicates: vec![Predicate::parse("purpose=analysis")?],
                },
            }));
        let executor = boot
            .kernel()
            .executor_for(process)
            .with_fact_recording(true);
        let program = signal_program(&path)?;
        for denied in [input("bob", "analysis"), input("alice", "sale")] {
            let output = executor
                .eval_program(&program, TaintedValue::pristine(denied))
                .await;
            ensure!(matches!(output.outcome, Outcome::Fail(_)), "{output:?}");
        }
        let allowed = input("alice", "analysis");
        let output = executor
            .eval_program(&program, TaintedValue::pristine(allowed.clone()))
            .await;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(42)),
            "{output:?}"
        );
        let facts = boot.kernel().facts().facts_of(process)?;
        ensure!(facts.len() == 3 && facts.last().is_some_and(|fact| fact.input == allowed));
        Ok(())
    }

    #[tokio::test]
    async fn native_signal_wait_rechecks_expiry_on_each_invocation() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_signal_resource(&boot, boot.kernel().state().clone())?;
        let path = Path::parse("state://signal/expires")?;
        boot.kernel()
            .state()
            .write_set(&path, Value::integer(7))
            .await?;
        let until = boot
            .kernel()
            .host_runtime()
            .now_millis()
            .saturating_add(300);
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root(),
            IdentityRef::ROOT,
            &[CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse(&format!(
                    "subscribe://state/signal/expires@until={until}"
                ))?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name("subscribe"),
                    RightFlags::empty(),
                ),
            }],
        )?;
        let executor = boot.kernel().executor_for(process);
        let template = OperationTemplate {
            target: ResourceName::new(path.clone()),
            method: "subscribe".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        };
        executor.prepare_operation_for(IdentityRef::ROOT, &template)?;
        while boot.kernel().host_runtime().now_millis() <= until {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let output = executor
            .eval_program(
                &signal_program(&path)?,
                TaintedValue::pristine(Value::null()),
            )
            .await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)), "{output:?}");
        Ok(())
    }

    #[tokio::test]
    async fn native_signal_wait_denies_after_source_and_open_handle_are_revoked()
    -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        install_signal_resource(&boot, boot.kernel().state().clone())?;
        let path = Path::parse("state://signal/revoked")?;
        boot.kernel()
            .state()
            .write_set(&path, Value::integer(7))
            .await?;
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root(),
            IdentityRef::ROOT,
            &[],
        )?;
        let registry = boot.kernel().registry();
        let grant_id = registry.next_grant_id();
        let mut grant = Grant {
            id: grant_id,
            holder: process,
            selector: ResourceSelector::parse("subscribe://state/signal/revoked")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("subscribe"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        };
        registry.register_grant(grant.clone());
        let executor = boot.kernel().executor_for(process);
        let template = OperationTemplate {
            target: ResourceName::new(path.clone()),
            method: "subscribe".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        };
        let (handle, _) = executor.prepare_operation_as(&template, IdentityRef::ROOT)?;
        grant.selector = ResourceSelector::parse("subscribe://state/signal/other")?;
        registry.register_grant(grant);
        ensure!(boot.kernel().handles().revoke(handle));
        let output = executor
            .eval_program(
                &signal_program(&path)?,
                TaintedValue::pristine(Value::null()),
            )
            .await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)), "{output:?}");
        Ok(())
    }
}
