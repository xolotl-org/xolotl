//! State Driver: exposes `state://**` as a Resource so a Process reads
//! and writes durable state through Operations (`read`, `write`,
//! `append`, `delete`, and `list`).
//!
//! State access traverses the same Handle → Policy → Fact path as any effect,
//! so capability checks, taint propagation, and audit apply uniformly. The
//! concrete path the Process targets arrives in [`DriverContext::target_path`];
//! the registered Resource is the `state://` prefix, and the handle records the
//! real path.
//!
//! Taint persists with the value: a write carries the operation's input taint
//! into the backend envelope, preserving provenance across the state boundary.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::Backend;
use xolotl_types::ValueView;
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, Value};

/// Method names in registration order for `state://**`. The kernel derives the
/// rights-bitmap bit and ReplayClass from each; `read` is an Observation,
/// `write`/`append`/`delete` are effects on durable state. Unary `subscribe`
/// waits for a present complete current value on the exact bound path.
/// Topic event streams are exposed by `effect://events/subscribe`.
pub(crate) const STATE_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "read",
        xolotl_types::MethodAuthority::Read,
        Purity::Pure,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
    MethodSpec::new(
        "write",
        xolotl_types::MethodAuthority::Write,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "append",
        xolotl_types::MethodAuthority::Write,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "delete",
        xolotl_types::MethodAuthority::Write,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "list",
        xolotl_types::MethodAuthority::Read,
        Purity::Pure,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
    MethodSpec::new(
        "compare_set",
        xolotl_types::MethodAuthority::Write,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "subscribe",
        xolotl_types::MethodAuthority::Subscribe,
        Purity::Pure,
        xolotl_types::OutputModeSet::UNARY,
    )
    .observes_external(),
];

/// Drives `state://**` over the kernel's state [`Backend`].
pub(crate) struct StateDriver {
    state: Backend,
}

impl StateDriver {
    /// Create a state driver over `state`.
    pub(crate) fn new(state: Backend) -> Self {
        Self { state }
    }
}

impl StateDriver {
    async fn execute(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, ObservedFailure> {
        // The concrete path comes from the handle's bound path; the
        // Operation itself carries no path. Refuse if absent — a state op
        // with no resolved path is a kernel wiring error, not a runtime input.
        let path = ctx
            .target_path
            .clone()
            .ok_or_else(|| DriverError::Other("state operation has no bound path".into()))?;

        match method.get() {
            // read: return the current value (None → Null).
            0 => {
                let tv = self
                    .state
                    .read_tainted(&path)
                    .await
                    .map_err(ObservedFailure::from)?;
                let value = tv.value.unwrap_or_else(Value::null);
                let taint = tv.taint;
                Ok(DriverOutput::new(Outcome::Done(value)).with_taint(taint))
            }
            // write: set the value, persisting the operation's input taint
            // alongside it — provenance is never dropped here.
            1 => {
                let commit = self
                    .state
                    .write_set_tainted(&path, input, ctx.taint.clone())
                    .await
                    .map_err(ObservedFailure::from)?;
                Ok(DriverOutput::new(Outcome::Done(Value::boolean(true))).with_taint(commit.taint))
            }
            // append: push onto the sequence at `path`, carrying taint.
            2 => {
                let commit = self
                    .state
                    .write_append_tainted(&path, input, ctx.taint.clone())
                    .await
                    .map_err(ObservedFailure::from)?;
                Ok(DriverOutput::new(Outcome::Done(Value::boolean(true))).with_taint(commit.taint))
            }
            // delete.
            3 => {
                let commit = self
                    .state
                    .write_delete_tainted(&path, ctx.taint.clone())
                    .await
                    .map_err(ObservedFailure::from)?;
                Ok(DriverOutput::new(Outcome::Done(Value::null())).with_taint(commit.taint))
            }
            // list: return one bounded page under the bound prefix.
            4 => {
                if path.cluster().is_none()
                    && path.scheme() == "state"
                    && path.segments().is_empty()
                {
                    return Err(DriverError::InvalidInput(
                        "state root collection contains reserved namespaces".into(),
                    )
                    .into());
                }
                let query = state_scan(path, input)?;
                let page = self
                    .state
                    .query(&query)
                    .await
                    .map_err(ObservedFailure::from)?;
                let taint = page.taint;
                let values = page
                    .entries
                    .into_iter()
                    .map(|(p, tv)| {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert("path".into(), Value::string(p.to_string()));
                        m.insert("value".into(), tv.value);
                        Value::map(m)
                    })
                    .collect();
                let output = Value::map(std::collections::BTreeMap::from([
                    ("entries".into(), Value::list(values)),
                    (
                        "next".into(),
                        page.next
                            .map_or(Value::null(), |cursor| Value::bytes(cursor.0)),
                    ),
                    (
                        "examined".into(),
                        Value::integer(i64::try_from(page.examined).map_err(|error| {
                            ObservedFailure::from(DriverError::Other(error.to_string()))
                                .with_taint(&taint)
                        })?),
                    ),
                    (
                        "encoded_bytes".into(),
                        Value::integer(i64::try_from(page.encoded_bytes).map_err(|error| {
                            ObservedFailure::from(DriverError::Other(error.to_string()))
                                .with_taint(&taint)
                        })?),
                    ),
                ]));
                Ok(DriverOutput::new(Outcome::Done(output)).with_taint(taint))
            }
            5 => {
                let (expected, value) = compare_set_input(input)?;
                let commit = self
                    .state
                    .write_cas_tainted(&path, expected, value, ctx.taint.clone())
                    .await
                    .map_err(ObservedFailure::from)?;
                Ok(DriverOutput::new(Outcome::Done(Value::boolean(true))).with_taint(commit.taint))
            }
            6 => self.wait_signal(&path).await,
            _ => Err(DriverError::NoSuchMethod(method).into()),
        }
    }

    async fn wait_signal(
        &self,
        path: &xolotl_types::Path,
    ) -> Result<DriverOutput, ObservedFailure> {
        // The paired port registers before reading from the same commit domain.
        // Dropping the driver future releases the observer; the owning
        // operation supplies cancellation.
        let (current, mut events) = self
            .state
            .observe_signal(path)
            .await
            .map_err(ObservedFailure::from)?;
        let mut observed = current.taint;
        if let Some(value) = current.value {
            return Ok(DriverOutput::new(Outcome::Done(value)).with_taint(observed));
        }
        loop {
            match events.recv().await {
                Ok(event) if event.path() != path => continue,
                Ok(event) => {
                    observed.union(event.taint());
                    let current = self
                        .state
                        .observe_signal_current(path)
                        .await
                        .map_err(|error| ObservedFailure::from(error).with_taint(&observed))?;
                    observed.union(&current.taint);
                    if let Some(value) = current.value {
                        return Ok(DriverOutput::new(Outcome::Done(value)).with_taint(observed));
                    }
                }
                Err(error) => {
                    return Err(ObservedFailure::from(DriverError::Other(format!(
                        "state subscription failed: {error}"
                    )))
                    .with_taint(&observed));
                }
            }
        }
    }
}

#[async_trait]
impl Driver for StateDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match self.execute(method, input, output, ctx).await {
            Ok(output) => Ok(output),
            Err(error) => error.with_taint(&ctx.taint).into_output("state"),
        }
    }
}

fn state_scan(
    path: xolotl_types::Path,
    input: Value,
) -> Result<xolotl_state::StateScan, DriverError> {
    let mut query = xolotl_state::StateScan::new(path);
    let mut fields = match input.view() {
        ValueView::Null => return Ok(query),
        ValueView::Map(fields) => fields.clone(),
        _ => {
            return Err(DriverError::InvalidInput(
                "state list expects an options map".into(),
            ));
        }
    };
    if let Some(cursor) = fields.remove("cursor") {
        query.cursor = match cursor.view() {
            ValueView::Null => None,
            ValueView::Bytes(bytes) => Some(xolotl_state::StateCursor(bytes.to_vec())),
            _ => {
                return Err(DriverError::InvalidInput(
                    "state list cursor must be bytes".into(),
                ));
            }
        };
    }
    for (name, target) in [
        ("limit", &mut query.limits.entries),
        ("max_examined", &mut query.limits.examined),
        ("max_encoded_bytes", &mut query.limits.encoded_bytes),
    ] {
        if let Some(value) = fields.remove(name) {
            let Some(value) = value.as_int() else {
                return Err(DriverError::InvalidInput(format!(
                    "state list {name} must be a positive integer"
                )));
            };
            *target = usize::try_from(value)
                .ok()
                .and_then(std::num::NonZeroUsize::new)
                .ok_or_else(|| {
                    DriverError::InvalidInput(format!(
                        "state list {name} must be a positive integer"
                    ))
                })?;
        }
    }
    if !fields.is_empty() {
        return Err(DriverError::InvalidInput(
            "unknown state list option".into(),
        ));
    }
    Ok(query)
}

fn compare_set_input(input: Value) -> Result<(Option<Value>, Value), DriverError> {
    let mut fields = crate::input::map(input, "state compare_set")?;
    let value = fields
        .remove("value")
        .ok_or_else(|| DriverError::InvalidInput("state compare_set requires value".into()))?;
    let expected = fields.remove("expected");
    if !fields.is_empty() {
        return Err(DriverError::InvalidInput(
            "unknown state compare_set option".into(),
        ));
    }
    Ok((expected, value))
}

#[cfg(test)]
mod tests;
