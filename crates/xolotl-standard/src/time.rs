//! Time provider: `effect://time/now`, `effect://time/sleep`,
//! `effect://time/cron`.
//!
//! `now` is an Observation;
//! `sleep` is an Idempotent delay on the Kernel host's monotonic clock; `cron`
//! computes the next Unix timestamp from a positive interval without registering
//! a schedule. Observations and waits use the same installed HostRuntime.

use async_trait::async_trait;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, MethodSpec, host::HostRuntime,
};
use xolotl_types::{MethodId, Outcome, OutputMode, Value};
use xolotl_types::{ValueMap, ValueView};

/// Drives the time actions. Internally methods are registered in this order:
/// `0 = now`, `1 = sleep`, `2 = cron` (the [`MethodId`] is the registration
/// index). `install_standard` exposes each as a separate Resource with public
/// method `invoke`.
pub(crate) struct TimeDriver {
    host_runtime: HostRuntime,
}

impl TimeDriver {
    pub(crate) fn new(host_runtime: HostRuntime) -> Self {
        Self { host_runtime }
    }
}

/// Method names in registration order (index = MethodId).
pub(crate) const TIME_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "now",
        xolotl_types::MethodAuthority::Perform,
        xolotl_types::Purity::Pure,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
    MethodSpec::new(
        "sleep",
        xolotl_types::MethodAuthority::Perform,
        xolotl_types::Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "cron",
        xolotl_types::MethodAuthority::Perform,
        xolotl_types::Purity::Pure,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
];

#[async_trait]
impl Driver for TimeDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match method.get() {
            // sleep
            1 => {
                let ms = sleep_millis(input)?;
                if ms != 0 {
                    let deadline = self
                        .host_runtime
                        .deadline_after(std::time::Duration::from_millis(ms))
                        .ok_or_else(|| {
                            DriverError::InvalidInput(
                                "time.sleep deadline is not representable".into(),
                            )
                        })?;
                    self.host_runtime
                        .sleep_until(deadline)
                        .await
                        .map_err(|error| DriverError::Other(error.to_string()))?;
                }
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            }
            2 => {
                let m = crate::input::map(input, "time.cron")?;
                let interval_ms = cron_interval_ms(&m)?;
                let next_millis = self
                    .host_runtime
                    .now_millis()
                    .checked_add(interval_ms)
                    .ok_or_else(|| {
                        DriverError::InvalidInput("time.cron next_millis overflowed i64".into())
                    })?;
                let mut out = std::collections::BTreeMap::new();
                out.insert("next_millis".into(), Value::integer(next_millis));
                out.insert("interval_ms".into(), Value::integer(interval_ms));
                Ok(DriverOutput::new(Outcome::Done(Value::map(out))))
            }
            // now
            0 => Ok(DriverOutput::new(Outcome::Done(Value::integer(
                self.host_runtime.now_millis(),
            )))),
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn sleep_millis(input: Value) -> Result<u64, DriverError> {
    let millis = match input.view() {
        ValueView::Int(value) => value,
        ValueView::Map(map) => match map.get("millis").map(Value::view) {
            Some(ValueView::Int(value)) => value,
            Some(_) => {
                return Err(DriverError::InvalidInput(
                    "time.sleep millis must be an integer".into(),
                ));
            }
            None => {
                return Err(DriverError::InvalidInput(
                    "time.sleep requires `millis`".into(),
                ));
            }
        },
        _ => {
            return Err(DriverError::InvalidInput(
                "time.sleep requires integer input or `{millis}`".into(),
            ));
        }
    };
    if millis < 0 {
        return Err(DriverError::InvalidInput(
            "time.sleep millis must be nonnegative".into(),
        ));
    }
    Ok(millis as u64)
}

/// Resolve a recurring interval (millis) from a cron input map. Accepts either
/// `{interval_ms: N}` or `{every: N, unit: "s"|"m"|"h"|"d"}`.
fn cron_interval_ms(m: &ValueMap) -> Result<i64, DriverError> {
    if let Some(value) = m.get("interval_ms") {
        if m.contains_key("every") || m.contains_key("unit") {
            return Err(DriverError::InvalidInput(
                "time.cron interval_ms cannot be combined with every or unit".into(),
            ));
        }
        return match value.view() {
            ValueView::Int(ms) if ms > 0 => Ok(ms),
            ValueView::Int(_) => Err(DriverError::InvalidInput(
                "time.cron interval_ms must be positive".into(),
            )),
            _ => Err(DriverError::InvalidInput(
                "time.cron interval_ms must be an integer".into(),
            )),
        };
    }
    let every = match m.get("every").map(Value::view) {
        Some(ValueView::Int(value)) => value,
        Some(_) => {
            return Err(DriverError::InvalidInput(
                "time.cron every must be an integer".into(),
            ));
        }
        None => {
            return Err(DriverError::InvalidInput(
                "time.cron requires `interval_ms` or `every`".into(),
            ));
        }
    };
    if every <= 0 {
        return Err(DriverError::InvalidInput(
            "time.cron every must be positive".into(),
        ));
    }
    let unit = match m.get("unit").map(Value::view) {
        Some(ValueView::Str(unit)) => unit,
        Some(_) => {
            return Err(DriverError::InvalidInput(
                "time.cron unit must be a string".into(),
            ));
        }
        None => "s",
    };
    let unit_ms = match unit {
        "s" | "sec" | "second" | "seconds" => 1000,
        "m" | "min" | "minute" | "minutes" => 60_000,
        "h" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => {
            return Err(DriverError::InvalidInput(
                "time.cron unit is unsupported".into(),
            ));
        }
    };
    every
        .checked_mul(unit_ms)
        .ok_or_else(|| DriverError::InvalidInput("time.cron interval overflowed i64".into()))
}

#[cfg(test)]
mod tests {
    mod host;

    use super::*;
    use anyhow::{Result, bail, ensure};
    use std::collections::BTreeMap;
    use xolotl_types::{IdentityRef, ProcessId};

    #[tokio::test]
    async fn sleep_rejects_missing_or_malformed_duration() -> Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for input in [
            Value::null(),
            Value::map(BTreeMap::new()),
            Value::map(BTreeMap::from([(
                "millis".into(),
                Value::string("0".into()),
            )])),
            Value::integer(-1),
            Value::map(BTreeMap::from([("millis".into(), Value::integer(-1))])),
        ] {
            let out = TimeDriver::new(HostRuntime::default())
                .call(MethodId::new(1), input, OutputMode::Unary, &ctx)
                .await;
            ensure!(
                matches!(out, Err(DriverError::InvalidInput(_))),
                "malformed sleep input should fail closed"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn cron_rejects_missing_or_malformed_spec() -> Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for fields in [
            BTreeMap::new(),
            BTreeMap::from([("interval_ms".into(), Value::string("5".into()))]),
            BTreeMap::from([("interval_ms".into(), Value::integer(0))]),
            BTreeMap::from([("interval_ms".into(), Value::integer(-1))]),
            BTreeMap::from([("every".into(), Value::string("5".into()))]),
            BTreeMap::from([("every".into(), Value::integer(0))]),
            BTreeMap::from([("every".into(), Value::integer(-1))]),
            BTreeMap::from([
                ("interval_ms".into(), Value::integer(5)),
                ("every".into(), Value::integer(10)),
            ]),
            BTreeMap::from([
                ("interval_ms".into(), Value::integer(5)),
                ("unit".into(), Value::string("m".into())),
            ]),
            BTreeMap::from([
                ("every".into(), Value::integer(5)),
                ("unit".into(), Value::integer(1)),
            ]),
            BTreeMap::from([
                ("every".into(), Value::integer(5)),
                ("unit".into(), Value::string("fortnight".into())),
            ]),
        ] {
            let out = TimeDriver::new(HostRuntime::default())
                .call(
                    MethodId::new(2),
                    Value::map(fields),
                    OutputMode::Unary,
                    &ctx,
                )
                .await;
            ensure!(
                matches!(out, Err(DriverError::InvalidInput(_))),
                "malformed cron spec should fail closed"
            );
        }
        Ok(())
    }
}
