//! A real state-backed Signal provider for SDK integration tests.

use std::sync::Arc;
use xolotl_kernel::{CompiledRequestGrantTemplate, DriverOutput, MethodSpec};
use xolotl_sdk::{Bootstrap, Driver, DriverContext, DriverError, Failure, Outcome, Path, Value};
use xolotl_state::Backend;
use xolotl_types::{
    GrantMethods, GrantRights, InterfaceFamily, MethodAuthority, MethodId, OutputMode,
    ResourceSelector, RightFlags,
};

struct SignalDriver(Backend);

#[async_trait::async_trait]
impl Driver for SignalDriver {
    async fn call(
        &self,
        method: MethodId,
        _input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let path = context
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

pub(crate) fn install_signal_resource(boot: &Bootstrap) -> anyhow::Result<()> {
    boot.register_subtree_resource(
        "state",
        InterfaceFamily::Value,
        &[MethodSpec::new(
            "subscribe",
            MethodAuthority::Subscribe,
            xolotl_sdk::Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )
        .observes_external()
        .finalize_allowed()],
        Arc::new(SignalDriver(boot.kernel().state().clone())),
    )?;
    Ok(())
}

pub(crate) fn signal_grant(path: &Path) -> anyhow::Result<CompiledRequestGrantTemplate> {
    let selector = ResourceSelector::parse(&format!(
        "subscribe://{}/{}",
        path.scheme(),
        path.segments().join("/")
    ))?;
    Ok(CompiledRequestGrantTemplate {
        selector,
        rights: GrantRights::new(GrantMethods::name("subscribe"), RightFlags::empty()),
    })
}
