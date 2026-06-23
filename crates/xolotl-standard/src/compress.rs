//! Token Compressor: `effect://compress/summarize`,
//! `effect://compress/trim-plan`.
//!
//! Context windows are bounded by a token budget; when a Sequence (a chat log,
//! a plan transcript) grows past budget, the compressor shrinks it. `summarize`
//! delegates to an inference backend to produce a shorter rendition of the
//! input text under a target token budget; `trim-plan` drops the
//! lowest-priority steps of a plan to fit a step budget. The summarizer is
//! supplied by the configured inference backend; the offline baseline uses the
//! deterministic echo backend summary + a structural trim.

use crate::inference::InferenceBackend;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;
use xolotl_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, Value};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://compress/<method>` Resource with public method
/// `invoke`.
pub(crate) const COMPRESS_METHODS: &[MethodSpec] = &[
    // summarize: model-backed; not safely replayable by default.
    MethodSpec::new("summarize", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    // trim-plan: pure structural truncation.
    MethodSpec::new("trim-plan", Purity::Pure, MethodSpec::UNARY_ASYNC),
];

/// Drives the compression actions. Holds an embedding/inference backend used to
/// produce summaries.
pub(crate) struct CompressDriver {
    backend: Arc<dyn InferenceBackend>,
}

impl CompressDriver {
    /// Create a compression driver using `backend` for model-backed summaries.
    pub(crate) fn new(backend: Arc<dyn InferenceBackend>) -> Self {
        Self { backend }
    }
}

/// Roughly estimate tokens for a text.
fn approx_tokens(text: &str) -> usize {
    (text.chars().count() / 4).max(1)
}

#[async_trait]
impl Driver for CompressDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            // summarize({text, max_tokens?}) → {summary, original_tokens,
            // summary_tokens}. If the text already fits, it passes through
            // unchanged (no spurious model call).
            0 => {
                let (text, max_tokens) = match &input {
                    Value::Str(text) => (text.as_str(), 512usize),
                    Value::Map(m) => (
                        required_string(m, "text", "compress.summarize")?,
                        optional_positive_usize(m, "max_tokens", 512, "compress.summarize")?,
                    ),
                    _ => {
                        return Err(DriverError::InvalidInput(
                            "compress.summarize input must be a map or string text".into(),
                        ));
                    }
                };
                let original_tokens = approx_tokens(text);
                let summary = if original_tokens <= max_tokens {
                    text.to_string()
                } else {
                    // Delegate to the model to summarize under budget.
                    let prompt = format!(
                        "Summarize the following in at most {max_tokens} tokens:\n\n{text}"
                    );
                    self.backend
                        .infer(&Value::Str(prompt))
                        .await
                        .map_err(DriverError::Other)?
                        .as_str()
                        .map(String::from)
                        .ok_or_else(|| {
                            DriverError::Other(
                                "compress.summarize backend returned non-string summary".into(),
                            )
                        })?
                };
                let mut out = BTreeMap::new();
                out.insert("summary".into(), Value::Str(summary.clone()));
                out.insert("original_tokens".into(), Value::Int(original_tokens as i64));
                out.insert(
                    "summary_tokens".into(),
                    Value::Int(approx_tokens(&summary) as i64),
                );
                Ok(Outcome::Done(Value::Map(out)))
            }
            // trim-plan({steps:[...], max_steps}) → {steps} keeping the
            // highest-priority `max_steps` (by an optional per-step `priority`,
            // else original order). Structural, pure.
            1 => {
                let Value::Map(m) = input else {
                    return Err(DriverError::InvalidInput(
                        "compress.trim-plan input must be a map".into(),
                    ));
                };
                let max_steps = required_non_negative_usize(&m, "max_steps", "compress.trim-plan")?;
                let steps = match m.get("steps") {
                    Some(Value::List(s)) => s,
                    Some(_) => {
                        return Err(DriverError::InvalidInput(
                            "compress.trim-plan `steps` must be a list".into(),
                        ));
                    }
                    None => {
                        return Err(DriverError::InvalidInput(
                            "compress.trim-plan requires `steps`".into(),
                        ));
                    }
                };
                let priorities = steps
                    .iter()
                    .map(step_priority)
                    .collect::<Result<Vec<_>, _>>()?;
                let kept = if max_steps == 0 || steps.len() <= max_steps {
                    steps.clone()
                } else {
                    // Sort by descending priority (default 0), keep top max_steps,
                    // preserving relative order among kept steps.
                    let mut indexed: Vec<(usize, i64)> =
                        priorities.into_iter().enumerate().collect();
                    indexed.sort_by_key(|(_, priority)| std::cmp::Reverse(*priority));
                    let mut keep: Vec<usize> = indexed
                        .into_iter()
                        .take(max_steps)
                        .map(|(i, _)| i)
                        .collect();
                    keep.sort_unstable();
                    keep.into_iter().map(|i| steps[i].clone()).collect()
                };
                let mut out = BTreeMap::new();
                out.insert("steps".into(), Value::List(kept));
                Ok(Outcome::Done(Value::Map(out)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn required_string<'a>(
    m: &'a BTreeMap<String, Value>,
    field: &'static str,
    op: &'static str,
) -> Result<&'a str, DriverError> {
    match m.get(field) {
        Some(Value::Str(value)) => Ok(value),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be a string"
        ))),
        None => Err(DriverError::InvalidInput(format!(
            "{op} requires `{field}`"
        ))),
    }
}

fn optional_positive_usize(
    m: &BTreeMap<String, Value>,
    field: &'static str,
    default: usize,
    op: &'static str,
) -> Result<usize, DriverError> {
    match m.get(field) {
        None => Ok(default),
        Some(Value::Int(value)) if *value > 0 => usize::try_from(*value)
            .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range"))),
        Some(Value::Int(_)) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be positive"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        ))),
    }
}

fn required_non_negative_usize(
    m: &BTreeMap<String, Value>,
    field: &'static str,
    op: &'static str,
) -> Result<usize, DriverError> {
    match m.get(field) {
        Some(Value::Int(value)) if *value >= 0 => usize::try_from(*value)
            .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range"))),
        Some(Value::Int(_)) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be non-negative"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        ))),
        None => Err(DriverError::InvalidInput(format!(
            "{op} requires `{field}`"
        ))),
    }
}

fn step_priority(step: &Value) -> Result<i64, DriverError> {
    let Some(priority) = step.as_map().and_then(|m| m.get("priority")) else {
        return Ok(0);
    };
    match priority {
        Value::Int(value) => Ok(*value),
        _ => Err(DriverError::InvalidInput(
            "compress.trim-plan step `priority` must be an integer".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::EchoBackend;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

    fn driver() -> CompressDriver {
        CompressDriver::new(Arc::new(EchoBackend))
    }
    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    #[tokio::test]
    async fn summarize_passes_through_when_within_budget() -> Result<()> {
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::Str("short".into()));
        m.insert("max_tokens".into(), Value::Int(100));
        let out = driver()
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("summarize short text")?;
        match out {
            Outcome::Done(Value::Map(r)) => {
                ensure!(
                    r.get("summary").and_then(|v| v.as_str()) == Some("short"),
                    "unexpected summary: {:?}",
                    r.get("summary")
                );
                Ok(())
            }
            other => bail!("expected summary map, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn summarize_invokes_model_when_over_budget() -> Result<()> {
        let long = "word ".repeat(500);
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::Str(long.clone()));
        m.insert("max_tokens".into(), Value::Int(10));
        let out = driver()
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("summarize long text")?;
        match out {
            Outcome::Done(Value::Map(r)) => {
                let summary = r
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .context("summary missing")?;
                ensure!(summary != long, "summary should differ from original input");
                ensure!(
                    matches!(r.get("original_tokens"), Some(Value::Int(t)) if *t > 10),
                    "unexpected original_tokens: {:?}",
                    r.get("original_tokens")
                );
                Ok(())
            }
            other => bail!("expected summary map, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn summarize_rejects_malformed_input() -> Result<()> {
        let mut missing_text = BTreeMap::new();
        missing_text.insert("max_tokens".into(), Value::Int(10));
        let out = driver()
            .call(
                MethodId::new(0),
                Value::Map(missing_text),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "summarize accepted missing text");

        let mut bad_budget = BTreeMap::new();
        bad_budget.insert("text".into(), Value::Str("hello".into()));
        bad_budget.insert("max_tokens".into(), Value::Str("many".into()));
        let out = driver()
            .call(
                MethodId::new(0),
                Value::Map(bad_budget),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "summarize accepted malformed max_tokens");
        Ok(())
    }

    #[tokio::test]
    async fn trim_plan_keeps_highest_priority_steps() -> Result<()> {
        let step = |id: i64, prio: i64| {
            let mut s = BTreeMap::new();
            s.insert("id".into(), Value::Int(id));
            s.insert("priority".into(), Value::Int(prio));
            Value::Map(s)
        };
        let mut m = BTreeMap::new();
        m.insert(
            "steps".into(),
            Value::List(vec![step(1, 1), step(2, 5), step(3, 2)]),
        );
        m.insert("max_steps".into(), Value::Int(2));
        let out = driver()
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("trim plan")?;
        match out {
            Outcome::Done(Value::Map(r)) => match r.get("steps") {
                Some(Value::List(kept)) => {
                    ensure!(kept.len() == 2, "expected 2 steps, got {}", kept.len());
                    let ids: Vec<i64> = kept
                        .iter()
                        .filter_map(|s| s.as_map()?.get("id")?.as_int())
                        .collect();
                    ensure!(ids == vec![2, 3], "unexpected step ids: {ids:?}");
                    Ok(())
                }
                other => bail!("expected steps list, got {other:?}"),
            },
            other => bail!("expected trim map, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn trim_plan_rejects_malformed_input() -> Result<()> {
        let mut missing_steps = BTreeMap::new();
        missing_steps.insert("max_steps".into(), Value::Int(1));
        let out = driver()
            .call(
                MethodId::new(1),
                Value::Map(missing_steps),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "trim-plan accepted missing steps");

        let mut step = BTreeMap::new();
        step.insert("priority".into(), Value::Str("high".into()));
        let mut bad_priority = BTreeMap::new();
        bad_priority.insert("steps".into(), Value::List(vec![Value::Map(step)]));
        bad_priority.insert("max_steps".into(), Value::Int(1));
        let out = driver()
            .call(
                MethodId::new(1),
                Value::Map(bad_priority),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "trim-plan accepted malformed priority");
        Ok(())
    }
}
