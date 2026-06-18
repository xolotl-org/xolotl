//! Time provider: `effect://time/now`, `effect://time/sleep`,
//! `effect://time/cron`.
//!
//! `now` is an Observation;
//! `sleep` is an Idempotent delay; `cron` registers a recurring schedule by
//! computing the next fire time from a cron spec. Wall clock here is real; the
//! Sim executor swaps in a virtual clock for deterministic replay.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Value};

/// Drives the time actions. Internally methods are registered in this order:
/// `0 = now`, `1 = sleep`, `2 = cron` (the [`MethodId`] is the registration
/// index). `install_standard` exposes each as a separate Resource with public
/// method `invoke`.
pub(crate) struct TimeDriver;

/// Method names in registration order (index = MethodId).
pub(crate) const TIME_METHODS: &[MethodSpec] = &[
    MethodSpec::new("now", nexus_types::Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new(
        "sleep",
        nexus_types::Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new("cron", nexus_types::Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
];

#[async_trait]
impl Driver for TimeDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            // sleep
            1 => {
                let ms = input
                    .as_map()
                    .and_then(|m| m.get("millis"))
                    .and_then(|v| v.as_int())
                    .or_else(|| input.as_int())
                    .unwrap_or(0)
                    .max(0) as u64;
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                Ok(Outcome::Done(Value::Null))
            }
            // cron: compute the next fire time (millis since epoch) for the given
            // spec. Returns `{next_millis}`; the Scheduler Driver
            // consumes this to spawn the recurring Process. The spine
            // supports the common `every <n> <unit>` form and an explicit
            // `interval_ms`; a full 5-field cron parser belongs in a broader
            // scheduler implementation.
            2 => {
                let m = crate::input::map(input, "time.cron")?;
                let now = now_millis();
                let interval_ms = cron_interval_ms(&m).ok_or_else(|| {
                    DriverError::Other("cron requires `interval_ms` or `every`/`unit`".into())
                })?;
                let mut out = std::collections::BTreeMap::new();
                out.insert("next_millis".into(), Value::Int(now + interval_ms));
                out.insert("interval_ms".into(), Value::Int(interval_ms));
                Ok(Outcome::Done(Value::Map(out)))
            }
            // now
            0 => Ok(Outcome::Done(Value::Int(now_millis()))),
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

/// Resolve a recurring interval (millis) from a cron input map. Accepts either
/// `{interval_ms: N}` or `{every: N, unit: "s"|"m"|"h"|"d"}`.
fn cron_interval_ms(m: &std::collections::BTreeMap<String, Value>) -> Option<i64> {
    if let Some(ms) = m.get("interval_ms").and_then(|v| v.as_int()) {
        return (ms > 0).then_some(ms);
    }
    let every = m.get("every").and_then(|v| v.as_int())?;
    if every <= 0 {
        return None;
    }
    let unit_ms = match m.get("unit").and_then(|v| v.as_str()).unwrap_or("s") {
        "s" | "sec" | "second" | "seconds" => 1000,
        "m" | "min" | "minute" | "minutes" => 60_000,
        "h" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => return None,
    };
    Some(every * unit_ms)
}

/// Current wall clock in millis since epoch.
pub(crate) fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use nexus_types::{IdentityRef, ProcessId};
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn now_returns_a_timestamp() -> Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = TimeDriver
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .context("read current time")?;
        match out {
            Outcome::Done(Value::Int(t)) if t >= 0 => Ok(()),
            other => bail!("expected timestamp, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sleep_zero_returns_immediately() -> Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut m = BTreeMap::new();
        m.insert("millis".into(), Value::Int(0));
        let out = TimeDriver
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx)
            .await
            .context("sleep zero milliseconds")?;
        ensure!(
            out == Outcome::Done(Value::Null),
            "expected null sleep result, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cron_computes_next_fire_from_every_unit() -> Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut m = BTreeMap::new();
        m.insert("every".into(), Value::Int(5));
        m.insert("unit".into(), Value::Str("m".into()));
        let out = TimeDriver
            .call(MethodId::new(2), Value::Map(m), OutputMode::Unary, &ctx)
            .await
            .context("compute cron fire time")?;
        match out {
            Outcome::Done(Value::Map(r)) => {
                ensure!(
                    r.get("interval_ms") == Some(&Value::Int(300_000)),
                    "unexpected interval: {:?}",
                    r.get("interval_ms")
                );
                ensure!(
                    matches!(r.get("next_millis"), Some(Value::Int(t)) if *t > 0),
                    "unexpected next_millis: {:?}",
                    r.get("next_millis")
                );
                Ok(())
            }
            other => bail!("expected cron map, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cron_rejects_missing_spec() -> Result<()> {
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = TimeDriver
            .call(
                MethodId::new(2),
                Value::Map(BTreeMap::new()),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "cron with no interval spec is a caller error");
        Ok(())
    }
}
