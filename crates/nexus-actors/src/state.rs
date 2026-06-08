//! State Driver (§12): exposes `state://**` as a Resource so a Process reads
//! and writes durable state through ordinary Operations — `Value.read` /
//! `Value.write` / `Sequence.append` — instead of a privileged side channel.
//!
//! This is the §12 "读写就是 Operation" contract made real: state access now
//! traverses the same Handle → Policy → Fact path as any effect, so capability
//! checks, taint propagation, and audit apply uniformly. The concrete path the
//! Process targets arrives in [`DriverContext::target_path`] (the registered
//! Resource is the `state://` prefix; the handle records the real path, §5.3).
//!
//! Taint persists with the value: a write carries the operation's input taint
//! (§4.4/§21.5) into the backend envelope, so provenance is never silently
//! dropped at the state boundary.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{MethodId, Outcome, OutputMode, Purity, TaintSet, Value};

/// Method names in registration order for `state://**`. The kernel derives the
/// rights-bitmap bit and ReplayClass from each; `read` is an Observation,
/// `write`/`append`/`delete` are effects on durable state.
pub const STATE_METHODS: &[MethodSpec] = &[
    MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("write", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("append", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("delete", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("list", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
];

/// Drives `state://**` over the kernel's state [`Backend`] (§12).
pub struct StateDriver {
    state: Backend,
}

impl StateDriver {
    /// Create a state driver over `state`.
    pub fn new(state: Backend) -> Self {
        Self { state }
    }
}

#[async_trait]
impl Driver for StateDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        // The concrete path comes from the handle's bound path (§12); the
        // Operation itself carries no path (§11). Refuse if absent — a state op
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
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                let (value, taint) = match tv {
                    Some(tv) => (tv.value, tv.taint),
                    None => (Value::Null, TaintSet::pristine()),
                };
                ctx.set_output_taint(taint);
                Ok(Outcome::Done(value))
            }
            // write: set the value, persisting the operation's input taint
            // alongside it (§4.4/§21.5) — provenance is never dropped here.
            1 => {
                if let Some((expected, new_value)) = parse_cas_write(input.clone()) {
                    self.state
                        .write_cas_tainted(&path, expected, new_value, ctx.taint.clone())
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                } else {
                    self.state
                        .write_set_tainted(&path, input, ctx.taint.clone())
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                Ok(Outcome::Done(Value::Bool(true)))
            }
            // append: push onto the sequence at `path`, carrying taint.
            2 => {
                self.state
                    .write_append_tainted(&path, input, ctx.taint.clone())
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Bool(true)))
            }
            // delete.
            3 => {
                self.state
                    .write_delete(&path)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Null))
            }
            // list: return `{ path: value }` entries under the bound prefix.
            4 => {
                let rows = self
                    .state
                    .read_prefix_tainted(&path)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                let mut taint = TaintSet::pristine();
                let values = rows
                    .into_iter()
                    .map(|(p, tv)| {
                        taint.union(&tv.taint);
                        let mut m = std::collections::BTreeMap::new();
                        m.insert("path".into(), Value::Str(p.to_string()));
                        m.insert("value".into(), tv.value);
                        Value::Map(m)
                    })
                    .collect();
                ctx.set_output_taint(taint);
                Ok(Outcome::Done(Value::List(values)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn parse_cas_write(input: Value) -> Option<(Option<Value>, Value)> {
    let Value::Map(mut m) = input else {
        return None;
    };
    let value = m.remove("value")?;
    if m.remove("cas") != Some(Value::Bool(true)) {
        return None;
    }
    let expected = match m.remove("expected") {
        Some(Value::Null) | None => None,
        Some(v) => Some(v),
    };
    Some((expected, value))
}
