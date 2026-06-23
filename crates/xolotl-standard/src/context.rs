//! Context Assembly: `effect://context/assemble`.
//!
//! Context assembly selects prompt material within a finite token budget.
//! Callers provide prepared layers; this driver renders them in priority order
//! and keeps persona/environment anchors even under tight budgets.

use async_trait::async_trait;
use std::borrow::Cow;
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, Value};

/// Method names for `effect://context/assemble`; the public method is `invoke`
/// after standard installation. Pure: assembly is a deterministic function of
/// its input layers (no I/O).
pub(crate) const CONTEXT_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "assemble",
    Purity::Pure,
    MethodSpec::UNARY_ASYNC,
)];

/// Priority order of layers. Index zero is highest. The first two are anchors
/// that are never evicted.
const LAYER_ORDER: &[&str] = &[
    "persona",
    "environment",
    "skills",
    "recall",
    "recent",
    "summary",
    "tools",
];
const NEVER_EVICT: usize = 2; // persona + environment

/// Estimate tokens for a text fragment.
fn est_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

/// Render one layer's value to its text contribution.
fn layer_text<'a>(v: &'a Value, layer: &str) -> Result<Cow<'a, str>, DriverError> {
    match v {
        Value::Str(s) => Ok(Cow::Borrowed(s.as_str())),
        Value::List(items) => {
            let mut rendered = String::new();
            for item in items {
                let text = layer_text(item, layer)?;
                if !rendered.is_empty() {
                    rendered.push('\n');
                }
                rendered.push_str(text.as_ref());
            }
            Ok(Cow::Owned(rendered))
        }
        Value::Map(m) => {
            let text = m.get("text").ok_or_else(|| {
                DriverError::InvalidInput(format!("context layer {layer:?} missing text"))
            })?;
            layer_text(text, layer)
        }
        _ => Err(DriverError::InvalidInput(format!(
            "context layer {layer:?} must be text, list, or map with text"
        ))),
    }
}

fn parse_budget(value: Option<&Value>) -> Result<usize, DriverError> {
    match value {
        Some(Value::Int(value)) if *value >= 0 => usize::try_from(*value).map_err(|_error| {
            DriverError::InvalidInput("context token_budget is too large for this platform".into())
        }),
        Some(Value::Int(_)) => Err(DriverError::InvalidInput(
            "context token_budget must be nonnegative".into(),
        )),
        Some(_) => Err(DriverError::InvalidInput(
            "context token_budget must be an integer".into(),
        )),
        None => Err(DriverError::InvalidInput(
            "context.assemble requires token_budget".into(),
        )),
    }
}

fn required_layers(m: &BTreeMap<String, Value>) -> Result<&BTreeMap<String, Value>, DriverError> {
    match m.get("layers") {
        Some(Value::Map(layers)) => Ok(layers),
        Some(_) => Err(DriverError::InvalidInput(
            "context.assemble layers must be a map".into(),
        )),
        None => Err(DriverError::InvalidInput(
            "context.assemble requires layers".into(),
        )),
    }
}

/// Drives `effect://context/assemble`. Stateless.
#[derive(Clone, Default)]
pub(crate) struct ContextDriver;

impl ContextDriver {
    /// Create a stateless context assembly driver.
    pub(crate) fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Driver for ContextDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let m = crate::input::map(input, "context.assemble")?;
        let budget = parse_budget(m.get("token_budget"))?;
        let layers = required_layers(&m)?;

        // Fill layers high-priority-first until the budget is exhausted.
        let mut included: Vec<(&str, Cow<'_, str>, usize)> = Vec::new();
        let mut used = 0usize;
        for (i, layer) in LAYER_ORDER.iter().enumerate() {
            let Some(v) = layers.get(*layer) else {
                continue;
            };
            let text = layer_text(v, layer)?;
            if text.as_ref().is_empty() {
                continue;
            }
            let cost = est_tokens(text.as_ref());
            if i < NEVER_EVICT {
                // Anchors are always included even if they alone exceed budget.
                included.push((*layer, text, cost));
                used += cost;
            } else if used + cost <= budget {
                included.push((*layer, text, cost));
                used += cost;
            }
            // else: this lower-priority layer doesn't fit; skip it (it would be
            // the first evicted anyway).
        }

        // If anchors alone overflowed, evict from the back of the non-anchor
        // layers until within budget.
        while used > budget && included.len() > NEVER_EVICT {
            if let Some((_, _, cost)) = included.pop() {
                used = used.saturating_sub(cost);
            }
        }

        // Compose the one-shot prompt in priority order.
        let mut prompt = String::new();
        for (name, text, _) in &included {
            if !prompt.is_empty() {
                prompt.push_str("\n\n");
            }
            prompt.push_str("## ");
            prompt.push_str(name);
            prompt.push('\n');
            prompt.push_str(text.as_ref());
        }
        let layers_used: Vec<Value> = included
            .iter()
            .map(|(name, _, _)| Value::Str((*name).to_string()))
            .collect();

        let mut out = BTreeMap::new();
        out.insert("prompt".into(), Value::Str(prompt));
        out.insert("token_count".into(), Value::Int(used as i64));
        out.insert("budget".into(), Value::Int(budget as i64));
        out.insert("layers_used".into(), Value::List(layers_used));
        Ok(Outcome::Done(Value::Map(out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn assemble_input(budget: i64, layers: Vec<(&str, &str)>) -> Value {
        let mut lm = BTreeMap::new();
        for (k, v) in layers {
            lm.insert(k.to_string(), Value::Str(v.into()));
        }
        let mut m = BTreeMap::new();
        m.insert("token_budget".into(), Value::Int(budget));
        m.insert("layers".into(), Value::Map(lm));
        Value::Map(m)
    }

    fn output_map(outcome: Outcome) -> Result<BTreeMap<String, Value>> {
        match outcome {
            Outcome::Done(Value::Map(map)) => Ok(map),
            other => bail!("expected assembled map, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assembles_in_priority_order() -> Result<()> {
        let d = ContextDriver::new();
        let input = assemble_input(
            1000,
            vec![
                ("persona", "I am a helpful assistant."),
                ("recent", "user: hi\nbot: hello"),
                ("summary", "earlier they discussed coffee"),
            ],
        );
        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .context("assemble context")?;
        let map = output_map(out)?;
        let prompt = map
            .get("prompt")
            .and_then(|v| v.as_str())
            .context("prompt must be a string")?;
        let p = prompt
            .find("persona")
            .context("prompt missing persona layer")?;
        let r = prompt
            .find("recent")
            .context("prompt missing recent layer")?;
        let s = prompt
            .find("summary")
            .context("prompt missing summary layer")?;
        ensure!(
            p < r && r < s,
            "layers were not assembled in priority order"
        );
        Ok(())
    }

    #[tokio::test]
    async fn keeps_skills_before_recall() -> Result<()> {
        let d = ContextDriver::new();
        let input = assemble_input(
            1000,
            vec![
                ("persona", "anchor"),
                ("skills", "coffee checklist"),
                ("recall", "likes coffee"),
            ],
        );
        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .context("assemble context")?;
        let map = output_map(out)?;
        let prompt = map
            .get("prompt")
            .and_then(Value::as_str)
            .context("prompt must be a string")?;
        let skills = prompt
            .find("skills")
            .context("prompt missing skills layer")?;
        let recall = prompt
            .find("recall")
            .context("prompt missing recall layer")?;
        ensure!(skills < recall, "skills layer must precede recall layer");
        Ok(())
    }

    #[tokio::test]
    async fn evicts_low_priority_under_tight_budget() -> Result<()> {
        let d = ContextDriver::new();
        let input = assemble_input(
            8, // ~32 chars
            vec![
                ("persona", "anchor stays"),
                (
                    "summary",
                    "this older summary is quite long and should not fit at all here",
                ),
            ],
        );
        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .context("assemble context")?;
        let map = output_map(out)?;
        let layers: Vec<String> = match map.get("layers_used") {
            Some(Value::List(l)) => l
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => Vec::new(),
        };
        ensure!(
            layers.contains(&"persona".to_string()),
            "persona layer missing"
        );
        ensure!(
            !layers.contains(&"summary".to_string()),
            "low-priority evicted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn anchors_survive_even_over_budget() -> Result<()> {
        let d = ContextDriver::new();
        let input = assemble_input(1, vec![("persona", "core identity must persist")]);
        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .context("assemble context")?;
        let map = output_map(out)?;
        let prompt = map
            .get("prompt")
            .and_then(Value::as_str)
            .context("prompt must be a string")?;
        ensure!(
            prompt.contains("core identity"),
            "anchor layer missing from prompt"
        );
        Ok(())
    }

    #[tokio::test]
    async fn assemble_rejects_malformed_input() -> Result<()> {
        let d = ContextDriver::new();
        let mut missing_layers = BTreeMap::new();
        missing_layers.insert("token_budget".into(), Value::Int(10));

        let mut missing_budget = BTreeMap::new();
        missing_budget.insert("layers".into(), Value::Map(BTreeMap::new()));

        let mut malformed_layer = BTreeMap::new();
        malformed_layer.insert("persona".into(), Value::Map(BTreeMap::new()));
        let mut malformed_layer_input = BTreeMap::new();
        malformed_layer_input.insert("token_budget".into(), Value::Int(10));
        malformed_layer_input.insert("layers".into(), Value::Map(malformed_layer));

        for input in [
            Value::Map(missing_layers),
            Value::Map(missing_budget),
            Value::Map(BTreeMap::from([
                ("token_budget".into(), Value::Str("10".into())),
                ("layers".into(), Value::Map(BTreeMap::new())),
            ])),
            Value::Map(BTreeMap::from([
                ("token_budget".into(), Value::Int(-1)),
                ("layers".into(), Value::Map(BTreeMap::new())),
            ])),
            Value::Map(BTreeMap::from([
                ("token_budget".into(), Value::Int(10)),
                ("layers".into(), Value::Str("bad".into())),
            ])),
            Value::Map(malformed_layer_input),
        ] {
            let out = d
                .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
                .await;
            ensure!(out.is_err(), "malformed context input was accepted");
        }
        Ok(())
    }
}
