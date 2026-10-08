//! Lock provider: `effect://lock/acquire`, `effect://lock/release`.
//!
//! A cooperative advisory lock over the state plane. An acquisition stores a
//! fresh, random owner token and returns it with the lock name. Release compares
//! that exact token before deleting, so a late release cannot remove a later
//! holder's lock. The acquisition result can be passed directly to release by
//! a `bracket` program. This is an advisory ownership token, not a monotonic
//! fencing number for an unrelated external resource.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::{Backend, StateError, StateFailure};
use xolotl_types::{MethodId, OperationId, Outcome, OutputMode, Path, Purity, Value};

const HEX: &[u8; 16] = b"0123456789abcdef";

fn new_token(operation: OperationId) -> Result<String, DriverError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_error| DriverError::Other("lock token entropy unavailable".into()))?;
    let mut token = format!("{operation}:");
    token.reserve(32);
    for byte in nonce {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(token)
}

fn token_owner(token: &str) -> Result<OperationId, DriverError> {
    let (owner, nonce) = token
        .rsplit_once(':')
        .ok_or_else(|| DriverError::Other("lock token is invalid".into()))?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DriverError::Other("lock token is invalid".into()));
    }
    owner
        .parse::<OperationId>()
        .map_err(|_error| DriverError::Other("lock token owner is invalid".into()))
}

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://lock/<method>` Resource with public method
/// `invoke`.
pub(crate) const LOCK_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "acquire",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "release",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    )
    .finalize_allowed(),
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

    fn acquisition(name: &str, token: Option<&str>) -> Value {
        Value::map(BTreeMap::from([
            ("acquired".into(), Value::boolean(token.is_some())),
            ("name".into(), Value::string(name.to_owned())),
            (
                "token".into(),
                token.map_or_else(Value::null, |token| Value::string(token.to_owned())),
            ),
        ]))
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
            .or_else(|| input.as_map()?.get("name")?.as_str())
            .ok_or_else(|| DriverError::Other("lock requires a name".into()))?;
        let path = Self::lock_path(name)?;
        match method.get() {
            // A retry of the same Operation observes its own token and returns
            // the same acquisition result, including after a lost commit ack.
            0 => {
                let operation = ctx.operation_id.ok_or_else(|| {
                    DriverError::Other("lock acquisition requires an Operation identity".into())
                })?;
                if operation.process != ctx.caller {
                    return Err(DriverError::Other(
                        "lock Operation identity does not match its caller".into(),
                    ));
                }
                let token = new_token(operation)?;
                match self
                    .state
                    .write_cas_tainted(&path, None, Value::string(token.clone()), ctx.taint.clone())
                    .await
                {
                    Ok(commit) => Ok(DriverOutput::new(Outcome::Done(Self::acquisition(
                        name,
                        Some(&token),
                    )))
                    .with_taint(commit.taint)),
                    Err(StateFailure {
                        error: StateError::CasFailed { actual, .. },
                        taint,
                    }) => {
                        let current_token = actual.as_deref().and_then(Value::as_str);
                        let owned = match current_token.map(token_owner).transpose() {
                            Ok(owner) => owner == Some(operation),
                            Err(error) => {
                                return ObservedFailure::from(error)
                                    .with_taint(&taint)
                                    .with_taint(&ctx.taint)
                                    .into_output("lock");
                            }
                        };
                        Ok(DriverOutput::new(Outcome::Done(Self::acquisition(
                            name,
                            current_token.filter(|_token| owned),
                        )))
                        .with_taint(taint))
                    }
                    Err(error) => ObservedFailure::from(error)
                        .with_taint(&ctx.taint)
                        .into_output("lock"),
                }
            }
            1 => {
                let token = input
                    .as_map()
                    .and_then(|map| map.get("token"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| DriverError::Other("lock release requires a token".into()))?;
                token_owner(token)?;
                match self
                    .state
                    .write_compare_delete_tainted(
                        &path,
                        Some(Value::string(token.to_owned())),
                        ctx.taint.clone(),
                    )
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
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use xolotl_state::{InMemoryBackend, StateCommit, StateMutation, StateResult, StateWrite};
    use xolotl_types::{
        ExecutionId, Failure, IdentityRef, InvocationId, NodeId, ProcessId, TaintSet, TaintSource,
    };

    fn ctx(process: u64, ticket: u64) -> DriverContext {
        let process = ProcessId::new(process);
        DriverContext::new(IdentityRef::ROOT, process).with_operation_id(OperationId::new(
            process,
            ExecutionId::FIRST,
            InvocationId::new(ticket),
            NodeId::new(1),
            0,
        ))
    }

    fn acquired(output: &DriverOutput) -> Result<Option<&str>> {
        let value = done(output)?;
        let fields = value.as_map().context("lock acquisition is not a map")?;
        let acquired = fields
            .get("acquired")
            .and_then(Value::as_bool)
            .context("lock acquisition has no acquired flag")?;
        let token = fields.get("token").and_then(Value::as_str);
        ensure!(acquired == token.is_some());
        Ok(token)
    }

    fn released(output: &DriverOutput) -> Result<bool> {
        done(output)?
            .as_bool()
            .context("lock release is not a boolean")
    }

    fn done(output: &DriverOutput) -> Result<&Value> {
        let Outcome::Done(value) = &output.outcome else {
            anyhow::bail!("lock operation failed: {output:?}");
        };
        Ok(value)
    }

    fn commit_uncertain(result: &Result<DriverOutput>) -> bool {
        matches!(
            result,
            Ok(DriverOutput {
                    outcome: Outcome::Fail(Failure::HandlerError { kind, .. }),
                    ..
                }) if kind == "state_commit_uncertain"
        )
    }

    async fn acquire(driver: &LockDriver, ctx: &DriverContext) -> Result<DriverOutput> {
        Ok(driver
            .call(
                MethodId::new(0),
                Value::string("job".into()),
                OutputMode::Unary,
                ctx,
            )
            .await?)
    }

    async fn release(
        driver: &LockDriver,
        ctx: &DriverContext,
        acquisition: &Value,
    ) -> Result<DriverOutput> {
        Ok(driver
            .call(
                MethodId::new(1),
                acquisition.clone(),
                OutputMode::Unary,
                ctx,
            )
            .await?)
    }

    #[tokio::test]
    async fn acquire_is_exclusive_until_released() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = LockDriver::new(state.clone());
        let first = ctx(1, 1).with_taint(TaintSet::of(TaintSource::ModelOutput));
        let second = ctx(2, 1);
        let later_same_process = ctx(1, 2);
        let a = acquire(&d, &first).await?;
        let first_token = acquired(&a)?
            .context("initial acquire was refused")?
            .to_owned();
        let a_input = done(&a)?.clone();
        let retry = acquire(&d, &first).await?;
        ensure!(acquired(&retry)? == Some(first_token.as_str()));
        ensure!(acquired(&acquire(&d, &second).await?)?.is_none());
        let path = LockDriver::lock_path("job")?;
        let mut events = state.subscribe(&path).await?;
        let release_ctx = ctx(1, 1).with_taint(TaintSet::of(TaintSource::Fetched {
            host: "release.example".into(),
        }));
        let expected = release_ctx.taint.clone().merged(&first.taint);
        let output = release(&d, &release_ctx, &a_input).await?;
        ensure!(released(&output)? && output.taint == expected);
        ensure!(
            events.try_recv()?
                == xolotl_state::StateEvent::Delete {
                    path,
                    taint: expected,
                }
        );
        let b = acquire(&d, &second).await?;
        let second_token = acquired(&b)?
            .context("second acquire was refused")?
            .to_owned();
        let b_input = done(&b)?.clone();
        ensure!(first_token != second_token);
        ensure!(!released(&release(&d, &first, &a_input).await?)?);
        ensure!(acquired(&acquire(&d, &later_same_process).await?)?.is_none());
        ensure!(released(&release(&d, &second, &b_input).await?)?);
        let c = acquire(&d, &later_same_process).await?;
        let third_token = acquired(&c)?.context("same-process reacquire was refused")?;
        ensure!(third_token != first_token && third_token != second_token);
        ensure!(!released(&release(&d, &first, &a_input).await?)?);
        ensure!(acquired(&acquire(&d, &second).await?)?.is_none());
        Ok(())
    }

    struct LostAck {
        state: Backend,
        acquire: AtomicBool,
        release: AtomicBool,
    }

    impl StateWrite for LostAck {
        type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

        fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
            Box::pin(async move {
                let acquire = matches!(&mutation, StateMutation::CompareSet { .. });
                let release = matches!(&mutation, StateMutation::CompareDelete { .. });
                let committed = self.state.mutate(path, mutation).await?;
                if (acquire && self.acquire.swap(false, Ordering::SeqCst))
                    || (release && self.release.swap(false, Ordering::SeqCst))
                {
                    Err(StateError::CommitUncertain("injected lost acknowledgement".into()).into())
                } else {
                    Ok(committed)
                }
            })
        }
    }

    #[tokio::test]
    async fn lost_ack_retries_do_not_release_a_new_holder() -> Result<()> {
        let state = InMemoryBackend::new().into_backend();
        let writer = Arc::new(LostAck {
            state: state.clone(),
            acquire: AtomicBool::new(true),
            release: AtomicBool::new(true),
        });
        let driver = LockDriver::new(state.with_write(writer));
        let first = ctx(1, 1);
        let second = ctx(2, 1);

        ensure!(commit_uncertain(&acquire(&driver, &first).await));
        let recovered = acquire(&driver, &first).await?;
        let token = acquired(&recovered)?.context("lost acquisition not recovered")?;
        ensure!(token_owner(token)? == first.operation_id.context("missing operation id")?);
        let input = done(&recovered)?.clone();
        ensure!(commit_uncertain(&release(&driver, &first, &input).await));
        ensure!(!released(&release(&driver, &first, &input).await?)?);
        let next = acquire(&driver, &second).await?;
        ensure!(acquired(&next)?.is_some());
        ensure!(!released(&release(&driver, &first, &input).await?)?);
        ensure!(acquired(&acquire(&driver, &first).await?)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn illegal_lock_name_is_a_driver_error_not_a_panic() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = LockDriver::new(state);
        let ctx = ctx(1, 1);
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
