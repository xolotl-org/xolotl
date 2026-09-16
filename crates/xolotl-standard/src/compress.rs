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
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, TaintSet, TaintSource, Value};
use xolotl_types::{ValueMap, ValueText, ValueView};

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
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match method.get() {
            // summarize({text, max_tokens?}) → {summary, original_tokens,
            // summary_tokens}. If the text already fits, it passes through
            // unchanged (no spurious model call).
            0 => {
                if self.backend.requires_unprotected_input() && ctx.taint.has_protected() {
                    return Err(DriverError::InvalidInput(
                        "compression backend requires unprotected input".into(),
                    ));
                }
                let (text, max_tokens) = match input.view() {
                    ValueView::Str(_) => (
                        required_text(Some(&input), "text", "compress.summarize")?,
                        512usize,
                    ),
                    ValueView::Map(m) => (
                        required_text(m.get("text"), "text", "compress.summarize")?,
                        optional_positive_usize(m, "max_tokens", 512, "compress.summarize")?,
                    ),
                    _ => {
                        return Err(DriverError::InvalidInput(
                            "compress.summarize input must be a map or string text".into(),
                        ));
                    }
                };
                let original_tokens = approx_tokens(&text);
                let mut taint = TaintSet::pristine();
                let summary = if original_tokens <= max_tokens {
                    text
                } else {
                    taint = TaintSet::of(TaintSource::ModelOutput);
                    // Delegate to the model to summarize under budget.
                    let prompt = format!(
                        "Summarize the following in at most {max_tokens} tokens:\n\n{}",
                        text.as_str()
                    );
                    self.backend
                        .infer(&Value::string(prompt))
                        .await
                        .map_err(DriverError::Other)?
                        .into_text()
                        .ok_or_else(|| {
                            DriverError::Other(
                                "compress.summarize backend returned non-string summary".into(),
                            )
                        })?
                };
                let summary_tokens = approx_tokens(&summary);
                let mut out = BTreeMap::new();
                out.insert("summary".into(), Value::from(summary));
                out.insert(
                    "original_tokens".into(),
                    Value::integer(original_tokens as i64),
                );
                out.insert(
                    "summary_tokens".into(),
                    Value::integer(summary_tokens as i64),
                );
                Ok(DriverOutput::new(Outcome::Done(Value::map(out))).with_taint(taint))
            }
            // trim-plan({steps:[...], max_steps}) → {steps} keeping the
            // highest-priority `max_steps` (by an optional per-step `priority`,
            // else original order). Structural, pure.
            1 => {
                let Some(m) = input.as_map() else {
                    return Err(DriverError::InvalidInput(
                        "compress.trim-plan input must be a map".into(),
                    ));
                };
                let max_steps = required_non_negative_usize(m, "max_steps", "compress.trim-plan")?;
                let steps = match m.get("steps").map(Value::view) {
                    Some(ValueView::List(s)) => s,
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
                    let mut keep = keep.into_iter().peekable();
                    steps
                        .iter()
                        .enumerate()
                        .filter_map(|(index, value)| {
                            if keep.peek() == Some(&index) {
                                keep.next();
                                Some(value.clone())
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                let mut out = BTreeMap::new();
                out.insert("steps".into(), Value::from(kept));
                Ok(DriverOutput::new(Outcome::Done(Value::map(out))))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn required_text(
    value: Option<&Value>,
    field: &'static str,
    op: &'static str,
) -> Result<ValueText, DriverError> {
    let value =
        value.ok_or_else(|| DriverError::InvalidInput(format!("{op} requires `{field}`")))?;
    value
        .clone()
        .into_text()
        .ok_or_else(|| DriverError::InvalidInput(format!("{op} `{field}` must be a string")))
}

fn optional_positive_usize(
    m: &ValueMap,
    field: &'static str,
    default: usize,
    op: &'static str,
) -> Result<usize, DriverError> {
    match m.get(field).map(Value::view) {
        None => Ok(default),
        Some(ValueView::Int(value)) if value > 0 => usize::try_from(value)
            .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range"))),
        Some(ValueView::Int(_)) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be positive"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        ))),
    }
}

fn required_non_negative_usize(
    m: &ValueMap,
    field: &'static str,
    op: &'static str,
) -> Result<usize, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => usize::try_from(value)
            .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range"))),
        Some(ValueView::Int(_)) => Err(DriverError::InvalidInput(format!(
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
    match priority.view() {
        ValueView::Int(value) => Ok(value),
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

    struct SharedSummary(Value);

    #[async_trait]
    impl InferenceBackend for SharedSummary {
        async fn infer(&self, _input: &Value) -> std::result::Result<Value, String> {
            Ok(self.0.clone())
        }
        async fn embed(&self, _input: &Value) -> std::result::Result<Value, String> {
            Err("unsupported".into())
        }
    }

    #[tokio::test]
    async fn summary_preserves_text_ownership_from_input_or_backend() -> Result<()> {
        let text = Value::string("shared text".repeat(1024));
        let expected_pointer = text.as_str().context("text missing")?.as_ptr();
        for (driver, input, expected_taint) in [
            (
                driver(),
                Value::map(BTreeMap::from([
                    ("text".into(), text.clone()),
                    ("max_tokens".into(), Value::integer(100_000)),
                ])),
                TaintSet::pristine(),
            ),
            (
                CompressDriver::new(Arc::new(SharedSummary(text))),
                Value::map(BTreeMap::from([
                    ("text".into(), Value::string("summarize me".into())),
                    ("max_tokens".into(), Value::integer(1)),
                ])),
                TaintSet::of(TaintSource::ModelOutput),
            ),
        ] {
            let output = driver
                .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
                .await?;
            ensure!(output.taint == expected_taint);
            let Outcome::Done(value) = output.outcome else {
                bail!("missing summary");
            };
            let summary = value
                .as_map()
                .and_then(|fields| fields.get("summary"))
                .and_then(Value::as_str)
                .context("missing summary text")?;
            ensure!(summary.as_ptr() == expected_pointer);
        }
        Ok(())
    }

    #[tokio::test]
    async fn summarize_passes_through_when_within_budget() -> Result<()> {
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::string("short".into()));
        m.insert("max_tokens".into(), Value::integer(100));
        let out = driver()
            .call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("summarize short text")?;
        ensure!(out.taint.is_pristine());
        match out.outcome {
            Outcome::Done(value) => {
                let r = value.as_map().context("expected compression map")?;
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
        m.insert("text".into(), Value::string(long.clone()));
        m.insert("max_tokens".into(), Value::integer(10));
        let out = driver()
            .call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("summarize long text")?;
        ensure!(out.taint == TaintSet::of(TaintSource::ModelOutput));
        match out.outcome {
            Outcome::Done(value) => {
                let r = value.as_map().context("expected compression map")?;
                let summary = r
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .context("summary missing")?;
                ensure!(summary != long, "summary should differ from original input");
                ensure!(
                    r.get("original_tokens")
                        .and_then(Value::as_int)
                        .is_some_and(|t| t > 10),
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
        missing_text.insert("max_tokens".into(), Value::integer(10));
        let out = driver()
            .call(
                MethodId::new(0),
                Value::map(missing_text),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "summarize accepted missing text");

        let mut bad_budget = BTreeMap::new();
        bad_budget.insert("text".into(), Value::string("hello".into()));
        bad_budget.insert("max_tokens".into(), Value::string("many".into()));
        let out = driver()
            .call(
                MethodId::new(0),
                Value::map(bad_budget),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "summarize accepted malformed max_tokens");
        Ok(())
    }

    struct RemoteBackend;

    #[async_trait]
    impl InferenceBackend for RemoteBackend {
        fn requires_unprotected_input(&self) -> bool {
            true
        }

        async fn infer(&self, _input: &Value) -> std::result::Result<Value, String> {
            Err("remote backend was invoked".into())
        }

        async fn embed(&self, _input: &Value) -> std::result::Result<Value, String> {
            Err("unsupported".into())
        }
    }

    #[tokio::test]
    async fn protected_input_is_rejected_before_remote_summary_but_structural_trim_remains_local()
    -> Result<()> {
        let driver = CompressDriver::new(Arc::new(RemoteBackend));
        let context = ctx().with_taint(TaintSet::of(TaintSource::Protected {
            path: xolotl_types::Path::parse("state://vault/private")?,
        }));
        let result = driver
            .call(
                MethodId::new(0),
                Value::string("private".repeat(500)),
                OutputMode::Unary,
                &context,
            )
            .await;
        ensure!(
            matches!(result, Err(DriverError::InvalidInput(message)) if message.contains("unprotected"))
        );
        driver
            .call(
                MethodId::new(1),
                Value::map(BTreeMap::from([
                    ("steps".into(), Value::list(vec![])),
                    ("max_steps".into(), Value::integer(1)),
                ])),
                OutputMode::Unary,
                &context,
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn trim_plan_keeps_highest_priority_steps() -> Result<()> {
        let step = |id: i64, prio: i64| {
            let mut s = BTreeMap::new();
            s.insert("id".into(), Value::integer(id));
            s.insert("priority".into(), Value::integer(prio));
            Value::map(s)
        };
        let mut m = BTreeMap::new();
        m.insert(
            "steps".into(),
            Value::list(vec![step(1, 1), step(2, 5), step(3, 2)]),
        );
        m.insert("max_steps".into(), Value::integer(2));
        let out = driver()
            .call(MethodId::new(1), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("trim plan")?;
        match out.outcome {
            Outcome::Done(value) => match value
                .as_map()
                .and_then(|map| map.get("steps"))
                .and_then(Value::as_list)
            {
                Some(kept) => {
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
        missing_steps.insert("max_steps".into(), Value::integer(1));
        let out = driver()
            .call(
                MethodId::new(1),
                Value::map(missing_steps),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "trim-plan accepted missing steps");

        let mut step = BTreeMap::new();
        step.insert("priority".into(), Value::string("high".into()));
        let mut bad_priority = BTreeMap::new();
        bad_priority.insert("steps".into(), Value::list(vec![Value::map(step)]));
        bad_priority.insert("max_steps".into(), Value::integer(1));
        let out = driver()
            .call(
                MethodId::new(1),
                Value::map(bad_priority),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "trim-plan accepted malformed priority");
        Ok(())
    }
}
