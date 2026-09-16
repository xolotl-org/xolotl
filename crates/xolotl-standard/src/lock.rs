//! Lock provider: `effect://lock/acquire`, `effect://lock/release`.
//!
//! A cooperative advisory lock over the state plane: `acquire` is a
//! `Cas{expected:None}` create on `state://kernel/locks/<name>` (no-lock = free,
//! held = present). Pairs with the `bracket` idiom so the lock is
//! released on any exit path.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::{Backend, StateError, StateFailure};
use xolotl_types::{MethodId, Outcome, OutputMode, Path, Purity, Value};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://lock/<method>` Resource with public method
/// `invoke`.
pub(crate) const LOCK_METHODS: &[MethodSpec] = &[
    MethodSpec::new("acquire", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("release", Purity::Effectful, MethodSpec::UNARY_ASYNC).finalize_allowed(),
];

/// Drives the lock actions.
pub(crate) struct LockDriver {
    state: Backend,
}

impl LockDriver {
    /// Create a lock driver backed by the state plane.
    pub(crate) fn new(state: Backend) -> Self {
        Self { state }
    }
    /// Build the lock's state path. `name` arrives from Operation input, so an
    /// illegal path segment is a caller error (returned as `DriverError`), never
    /// a panic.
    fn lock_path(name: &str) -> Result<Path, DriverError> {
        Path::try_new("state")
            .and_then(|path| path.try_push("kernel"))
            .and_then(|path| path.try_push("locks"))
            .and_then(|path| path.try_push_literal(name))
            .map_err(|e| DriverError::Other(format!("invalid lock name {name:?}: {e}")))
    }
}

#[async_trait]
impl Driver for LockDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let name = input
            .as_str()
            .map(str::to_string)
            .or_else(|| {
                input
                    .as_map()
                    .and_then(|m| m.get("name"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .ok_or_else(|| DriverError::Other("lock requires a name".into()))?;
        let path = Self::lock_path(&name)?;
        match method.get() {
            // acquire: create-if-absent; fail if already held.
            0 => {
                let holder = Value::string(format!("p{}", ctx.caller.get()));
                match self
                    .state
                    .write_cas_tainted(&path, None, holder, ctx.taint.clone())
                    .await
                {
                    Ok(commit) => Ok(DriverOutput::new(Outcome::Done(Value::boolean(true)))
                        .with_taint(commit.taint)),
                    Err(StateFailure {
                        error: StateError::CasFailed { .. },
                        taint,
                    }) => {
                        Ok(DriverOutput::new(Outcome::Done(Value::boolean(false)))
                            .with_taint(taint))
                    }
                    Err(error) => ObservedFailure::from(error)
                        .with_taint(&ctx.taint)
                        .into_output("lock"),
                }
            }
            // release: delete the lock.
            1 => match self.state.write_delete(&path).await {
                Ok(commit) => {
                    Ok(DriverOutput::new(Outcome::Done(Value::null())).with_taint(commit.taint))
                }
                Err(error) => ObservedFailure::from(error)
                    .with_taint(&ctx.taint)
                    .into_output("lock"),
            },
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use xolotl_state::InMemoryBackend;
    use xolotl_types::{IdentityRef, ProcessId};

    #[tokio::test]
    async fn acquire_is_exclusive_until_released() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = LockDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let a = d
            .call(
                MethodId::new(0),
                Value::string("job".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("initial acquire")?;
        ensure!(
            a.outcome == Outcome::Done(Value::boolean(true)),
            "initial acquire: {a:?}"
        );
        let b = d
            .call(
                MethodId::new(0),
                Value::string("job".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("held acquire")?;
        ensure!(
            b.outcome == Outcome::Done(Value::boolean(false)),
            "held acquire: {b:?}"
        );
        d.call(
            MethodId::new(1),
            Value::string("job".into()),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .context("release lock")?;
        let c = d
            .call(
                MethodId::new(0),
                Value::string("job".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("re-acquire")?;
        ensure!(
            c.outcome == Outcome::Done(Value::boolean(true)),
            "re-acquire: {c:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn illegal_lock_name_is_a_driver_error_not_a_panic() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = LockDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let r = d
            .call(
                MethodId::new(0),
                Value::string("bad/name".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(r.is_err(), "illegal lock name must be a DriverError");
        Ok(())
    }
}
