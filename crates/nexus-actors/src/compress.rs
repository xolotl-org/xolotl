//! Token Compressor (§17 / §19.1): `effect://compress/summarize`,
//! `effect://compress/trim-plan`.
//!
//! Context windows are bounded by a token budget; when a Sequence (a chat log,
//! a plan transcript) grows past budget, the compressor shrinks it. `summarize`
//! delegates to an inference backend to produce a shorter rendition of the
//! input text under a target token budget; `trim-plan` drops the
//! lowest-priority steps of a plan to fit a step budget. Both are the seam where
//! a real model summarizer plugs in (§17.1); the offline baseline uses the
//! deterministic [`EchoBackend`] summary + a structural trim.

use crate::inference::InferenceBackend;
use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://compress/<method>` Resource with public method
/// `invoke`.
pub const COMPRESS_METHODS: &[MethodSpec] = &[
    // summarize: model-backed; not safely replayable by default (§9.3).
    MethodSpec::new("summarize", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    // trim-plan: pure structural truncation.
    MethodSpec::new("trim-plan", Purity::Pure, MethodSpec::UNARY_ASYNC),
];

/// Drives the compression actions. Holds an embedding/inference backend used to
/// produce summaries (§17.1).
pub struct CompressDriver {
    backend: Arc<dyn InferenceBackend>,
}

impl CompressDriver {
    pub fn new(backend: Arc<dyn InferenceBackend>) -> Self {
        Self { backend }
    }
}

/// Roughly estimate tokens for a text (the ~4-chars/token heuristic, §21.2).
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
        let m = input.as_map().cloned().unwrap_or_default();
        match method.get() {
            // summarize({text, max_tokens?}) → {summary, original_tokens,
            // summary_tokens}. If the text already fits, it passes through
            // unchanged (no spurious model call).
            0 => {
                let text = m
                    .get("text")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| input.as_str().map(String::from))
                    .unwrap_or_default();
                let max_tokens = m
                    .get("max_tokens")
                    .and_then(|v| v.as_int())
                    .unwrap_or(512)
                    .max(1) as usize;
                let original_tokens = approx_tokens(&text);
                let summary = if original_tokens <= max_tokens {
                    text.clone()
                } else {
                    // Delegate to the model to summarize under budget (§17.1).
                    let prompt = format!(
                        "Summarize the following in at most {max_tokens} tokens:\n\n{text}"
                    );
                    self.backend
                        .infer(&Value::Str(prompt))
                        .await
                        .map_err(DriverError::Other)?
                        .as_str()
                        .map(String::from)
                        .unwrap_or(text)
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
            // else original order). Structural, pure (§19).
            1 => {
                let max_steps = m
                    .get("max_steps")
                    .and_then(|v| v.as_int())
                    .unwrap_or(0)
                    .max(0) as usize;
                let steps = match m.get("steps") {
                    Some(Value::List(s)) => s.clone(),
                    _ => vec![],
                };
                let kept = if max_steps == 0 || steps.len() <= max_steps {
                    steps
                } else {
                    // Sort by descending priority (default 0), keep top max_steps,
                    // preserving relative order among kept steps.
                    let mut indexed: Vec<(usize, &Value)> = steps.iter().enumerate().collect();
                    indexed.sort_by_key(|(_, v)| std::cmp::Reverse(step_priority(v)));
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

fn step_priority(step: &Value) -> i64 {
    step.as_map()
        .and_then(|m| m.get("priority"))
        .and_then(|v| v.as_int())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::EchoBackend;
    use nexus_types::{IdentityRef, ProcessId};

    fn driver() -> CompressDriver {
        CompressDriver::new(Arc::new(EchoBackend))
    }
    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    #[tokio::test]
    async fn summarize_passes_through_when_within_budget() {
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::Str("short".into()));
        m.insert("max_tokens".into(), Value::Int(100));
        let out = driver()
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(r)) => {
                assert_eq!(r.get("summary").and_then(|v| v.as_str()), Some("short"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn summarize_invokes_model_when_over_budget() {
        let long = "word ".repeat(500);
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::Str(long.clone()));
        m.insert("max_tokens".into(), Value::Int(10));
        let out = driver()
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(r)) => {
                let summary = r.get("summary").and_then(|v| v.as_str()).unwrap();
                // EchoBackend produced a (deterministic) summary distinct from the input.
                assert_ne!(summary, long);
                assert!(matches!(r.get("original_tokens"), Some(Value::Int(t)) if *t > 10));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn trim_plan_keeps_highest_priority_steps() {
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
            .unwrap();
        match out {
            Outcome::Done(Value::Map(r)) => match r.get("steps") {
                Some(Value::List(kept)) => {
                    assert_eq!(kept.len(), 2);
                    // Kept the priority-5 (id 2) and priority-2 (id 3) steps, in order.
                    let ids: Vec<i64> = kept
                        .iter()
                        .filter_map(|s| s.as_map()?.get("id")?.as_int())
                        .collect();
                    assert_eq!(ids, vec![2, 3]);
                }
                _ => panic!("expected steps list"),
            },
            other => panic!("got {other:?}"),
        }
    }
}
