//! Context Assembly: `effect://context/assemble`.
//!
//! Context assembly selects prompt material within a finite token budget.
//! Callers provide prepared layers; this driver renders them in priority order
//! and keeps persona/environment anchors even under tight budgets.
//! Known layers are validated and their rendered byte lengths memoized by live
//! resident identity before selection. Rejected shared graphs are never expanded.
//! List separators depend on preceding rendered bytes, including empty children;
//! malformed known layers fail even when they would not fit the budget.
//! Length arithmetic saturates at the platform maximum; such non-anchor layers
//! are rejected. Selected layers require checked prompt sizing and fallible
//! buffer reservation, with no intermediate per-layer text copies.

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, Value};
use xolotl_types::{ValueIdentity, ValueMap, ValueView};

/// Method names for `effect://context/assemble`; the public method is `invoke`
/// after standard installation. Pure: assembly is a deterministic function of
/// its input layers (no I/O).
pub(crate) const CONTEXT_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "assemble",
    xolotl_types::MethodAuthority::Perform,
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

fn allocation_error(error: impl std::fmt::Display) -> DriverError {
    DriverError::InvalidInput(format!("context materialization failed: {error}"))
}

#[derive(Default)]
struct Lengths {
    memo: HashMap<ValueIdentity, usize>,
    #[cfg(test)]
    visits: usize,
    #[cfg(test)]
    rendered: usize,
}

impl Lengths {
    fn measure(&mut self, root: &Value, layer: &str) -> Result<usize, DriverError> {
        let mut frames: Vec<(&Value, Option<xolotl_types::value::ListIter<'_>>, usize)> =
            Vec::new();
        let mut next = Some(root);
        let mut length = 0;
        loop {
            if let Some(value) = next.take() {
                if let Some(cached) = value.identity().and_then(|key| self.memo.get(&key)) {
                    length = *cached;
                } else {
                    #[cfg(test)]
                    {
                        self.visits += 1;
                    }
                    match value.view() {
                        ValueView::Str(text) => length = text.len(),
                        ValueView::List(items) => {
                            let mut children = items.iter();
                            if let Some(child) = children.next() {
                                frames.try_reserve(1).map_err(allocation_error)?;
                                frames.push((value, Some(children), 0));
                                next = Some(child);
                                continue;
                            }
                            length = 0;
                        }
                        ValueView::Map(map) => {
                            let child = map.get("text").ok_or_else(|| {
                                DriverError::InvalidInput(format!(
                                    "context layer {layer:?} missing text"
                                ))
                            })?;
                            frames.try_reserve(1).map_err(allocation_error)?;
                            frames.push((value, None, 0));
                            next = Some(child);
                            continue;
                        }
                        _ => {
                            return Err(DriverError::InvalidInput(format!(
                                "context layer {layer:?} must be text, list, or map with text"
                            )));
                        }
                    }
                    self.remember(value, length)?;
                }
            }
            loop {
                let Some((value, children, accumulated)) = frames.last_mut() else {
                    return Ok(length);
                };
                if let Some(children) = children {
                    *accumulated = accumulated.saturating_add(length);
                    if let Some(child) = children.next() {
                        if *accumulated > 0 {
                            *accumulated = accumulated.saturating_add(1);
                        }
                        next = Some(child);
                        break;
                    }
                    length = *accumulated;
                }
                self.remember(value, length)?;
                frames.pop();
            }
        }
    }

    fn remember(&mut self, value: &Value, length: usize) -> Result<(), DriverError> {
        if let Some(key) = value.identity() {
            self.memo.try_reserve(1).map_err(allocation_error)?;
            self.memo.insert(key, length);
        }
        Ok(())
    }
}

fn render_into(
    root: &Value,
    rendered: &mut String,
    lengths: &mut Lengths,
) -> Result<(), DriverError> {
    let mut frames = Vec::new();
    let mut next = Some(root);
    loop {
        if let Some(value) = next.take() {
            #[cfg(test)]
            {
                lengths.rendered += 1;
            }
            if value.identity().and_then(|key| lengths.memo.get(&key)) == Some(&0) {
                continue;
            }
            match value.view() {
                ValueView::Str(text) => rendered.push_str(text),
                ValueView::List(items) => {
                    frames.try_reserve(1).map_err(allocation_error)?;
                    frames.push((items.iter(), rendered.len()));
                }
                ValueView::Map(map) => {
                    next = Some(map.get("text").ok_or_else(|| {
                        DriverError::InvalidInput("validated context layer lost text".into())
                    })?);
                    continue;
                }
                _ => {
                    return Err(DriverError::InvalidInput(
                        "validated context layer must be text, list, or map with text".into(),
                    ));
                }
            }
        }
        let Some((items, start)) = frames.last_mut() else {
            break;
        };
        if let Some(child) = items.next() {
            if rendered.len() > *start {
                rendered.push('\n');
            }
            next = Some(child);
        } else {
            frames.pop();
        }
    }
    Ok(())
}

fn parse_budget(value: Option<&Value>) -> Result<usize, DriverError> {
    match value.map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => usize::try_from(value).map_err(|_error| {
            DriverError::InvalidInput("context token_budget is too large for this platform".into())
        }),
        Some(ValueView::Int(_)) => Err(DriverError::InvalidInput(
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

fn required_layers(m: &ValueMap) -> Result<&ValueMap, DriverError> {
    match m.get("layers").map(Value::view) {
        Some(ValueView::Map(layers)) => Ok(layers),
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
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let m = crate::input::map(input, "context.assemble")?;
        let budget = parse_budget(m.get("token_budget"))?;
        let layers = required_layers(&m)?;

        // Fill layers high-priority-first until the budget is exhausted.
        let mut included = Vec::new();
        included
            .try_reserve(LAYER_ORDER.len())
            .map_err(allocation_error)?;
        let mut lengths = Lengths::default();
        let mut used = 0usize;
        for (i, layer) in LAYER_ORDER.iter().enumerate() {
            let Some(v) = layers.get(layer) else {
                continue;
            };
            let length = lengths.measure(v, layer)?;
            if length == 0 {
                continue;
            }
            let cost = if length == usize::MAX {
                usize::MAX
            } else {
                length.div_ceil(4)
            };
            if i < NEVER_EVICT {
                // Anchors are always included even if they alone exceed budget.
                included.push((*layer, v, length));
                used = used.saturating_add(cost);
            } else if cost <= budget.saturating_sub(used) && used <= budget {
                included.push((*layer, v, length));
                used = used.saturating_add(cost);
            }
            // else: this lower-priority layer doesn't fit; skip it (it would be
            // the first evicted anyway).
        }

        // Compose the one-shot prompt in priority order.
        let capacity =
            included
                .iter()
                .enumerate()
                .try_fold(0usize, |total, (index, (name, _, length))| {
                    total
                        .checked_add(if index == 0 { 0 } else { 2 })
                        .and_then(|total| total.checked_add(4))
                        .and_then(|total| total.checked_add(name.len()))
                        .and_then(|total| total.checked_add(*length))
                        .ok_or_else(|| allocation_error("rendered length overflow"))
                })?;
        let mut prompt = String::new();
        prompt
            .try_reserve_exact(capacity)
            .map_err(allocation_error)?;
        for (name, text, _) in &included {
            if !prompt.is_empty() {
                prompt.push_str("\n\n");
            }
            prompt.push_str("## ");
            prompt.push_str(name);
            prompt.push('\n');
            render_into(text, &mut prompt, &mut lengths)?;
        }
        let layers_used: Vec<Value> = included
            .iter()
            .map(|(name, _, _)| Value::string((*name).to_string()))
            .collect();

        let mut out = BTreeMap::new();
        out.insert("prompt".into(), Value::string(prompt));
        out.insert(
            "token_count".into(),
            Value::integer(i64::try_from(used).unwrap_or(i64::MAX)),
        );
        out.insert(
            "budget".into(),
            Value::integer(i64::try_from(budget).unwrap_or(i64::MAX)),
        );
        out.insert("layers_used".into(), Value::list(layers_used));
        Ok(DriverOutput::new(Outcome::Done(Value::map(out))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

    #[test]
    fn shared_graph_lengths_visit_resident_nodes_not_occurrences() -> Result<()> {
        let mut value = Value::string("x".into());
        for _ in 0..60 {
            value = Value::list(vec![value.clone(), value]);
        }
        let mut lengths = Lengths::default();
        let measured = lengths.measure(&value, "recall")?;
        ensure!(measured > 1_000_000);
        ensure!(lengths.visits == 61);
        ensure!(lengths.rendered == 0);
        ensure!(lengths.measure(&value, "tools")? == measured);
        ensure!(lengths.visits == 61, "memo missed shared layer root");
        Ok(())
    }

    #[test]
    fn empty_shared_graph_rendering_skips_zero_length_expansion() -> Result<()> {
        let mut value = Value::string(String::new());
        for _ in 0..60 {
            value = Value::list(vec![value.clone(), value]);
        }
        let mut lengths = Lengths::default();
        ensure!(lengths.measure(&value, "recall")? == 0);
        let mut rendered = String::new();
        render_into(&value, &mut rendered, &mut lengths)?;
        ensure!(rendered.is_empty() && lengths.rendered == 1);
        Ok(())
    }

    #[tokio::test]
    async fn rejected_overflowing_graph_is_validated_without_materialization() -> Result<()> {
        let mut value = Value::string("x".into());
        for _ in 0..100 {
            value = Value::list(vec![value.clone(), value]);
        }
        let layers = BTreeMap::from([
            ("persona".into(), Value::string("anchor".into())),
            ("recall".into(), value.clone()),
            ("tools".into(), Value::string("ok".into())),
        ]);
        let input = Value::map(BTreeMap::from([
            ("token_budget".into(), Value::integer(3)),
            ("layers".into(), Value::map(layers)),
        ]));
        let output = output_map(
            ContextDriver::new()
                .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
                .await?,
        )?;
        ensure!(
            output.get("prompt").and_then(Value::as_str)
                == Some("## persona\nanchor\n\n## tools\nok")
        );
        let malformed = Value::list(vec![value, Value::integer(1)]);
        let mut lengths = Lengths::default();
        ensure!(lengths.measure(&malformed, "recall").is_err());
        ensure!(lengths.visits <= 103 && lengths.rendered == 0);
        Ok(())
    }

    #[tokio::test]
    async fn overflowing_anchor_fails_before_expansion() -> Result<()> {
        let mut anchor = Value::string("x".into());
        for _ in 0..100 {
            anchor = Value::list(vec![anchor.clone(), anchor]);
        }
        let input = Value::map(BTreeMap::from([
            ("token_budget".into(), Value::integer(0)),
            (
                "layers".into(),
                Value::map(BTreeMap::from([("environment".into(), anchor)])),
            ),
        ]));
        let error = ContextDriver::new()
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .err()
            .context("overflowing anchor was materialized")?;
        ensure!(error.to_string().contains("rendered length overflow"));
        Ok(())
    }

    #[test]
    fn nested_empty_layers_preserve_separator_behavior() -> Result<()> {
        let value = Value::list(vec![
            Value::string(String::new()),
            Value::list(vec![
                Value::string("a".into()),
                Value::string(String::new()),
            ]),
            Value::list(vec![]),
            Value::map(BTreeMap::from([("text".into(), Value::string("b".into()))])),
        ]);
        let mut lengths = Lengths::default();
        ensure!(lengths.measure(&value, "recall")? == 5);
        let mut rendered = String::new();
        rendered.try_reserve_exact(5)?;
        render_into(&value, &mut rendered, &mut lengths)?;
        ensure!(rendered == "a\n\n\nb");
        Ok(())
    }

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn assemble_input(budget: i64, layers: Vec<(&str, &str)>) -> Value {
        let mut lm = BTreeMap::new();
        for (k, v) in layers {
            lm.insert(k.to_string(), Value::string(v.into()));
        }
        let mut m = BTreeMap::new();
        m.insert("token_budget".into(), Value::integer(budget));
        m.insert("layers".into(), Value::map(lm));
        Value::map(m)
    }

    fn output_map(output: DriverOutput) -> Result<ValueMap> {
        match output.outcome {
            Outcome::Done(value) => value.into_map().context("expected assembled map"),
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
        let layers: Vec<String> = match map.get("layers_used").map(Value::view) {
            Some(ValueView::List(l)) => l
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
        missing_layers.insert("token_budget".into(), Value::integer(10));

        let mut missing_budget = BTreeMap::new();
        missing_budget.insert("layers".into(), Value::map(BTreeMap::new()));

        let mut malformed_layer = BTreeMap::new();
        malformed_layer.insert("persona".into(), Value::map(BTreeMap::new()));
        let mut malformed_layer_input = BTreeMap::new();
        malformed_layer_input.insert("token_budget".into(), Value::integer(10));
        malformed_layer_input.insert("layers".into(), Value::map(malformed_layer));

        for input in [
            Value::map(missing_layers),
            Value::map(missing_budget),
            Value::map(BTreeMap::from([
                ("token_budget".into(), Value::string("10".into())),
                ("layers".into(), Value::map(BTreeMap::new())),
            ])),
            Value::map(BTreeMap::from([
                ("token_budget".into(), Value::integer(-1)),
                ("layers".into(), Value::map(BTreeMap::new())),
            ])),
            Value::map(BTreeMap::from([
                ("token_budget".into(), Value::integer(10)),
                ("layers".into(), Value::string("bad".into())),
            ])),
            Value::map(malformed_layer_input),
        ] {
            let out = d
                .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
                .await;
            ensure!(out.is_err(), "malformed context input was accepted");
        }
        Ok(())
    }
}
