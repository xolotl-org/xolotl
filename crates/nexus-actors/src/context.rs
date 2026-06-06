//! Context Assembly (§20.5): `effect://context/assemble`.
//!
//! The hardest part of a chat agent is not *reading* a Sequence but deciding —
//! within a finite token budget — what to inject, in what order, when to
//! summarize, and when to evict. This Driver implements the §20.5 algorithm:
//! fill layers high-priority-first until the budget runs out, and on overflow
//! evict in reverse priority (oldest summary first; persona/environment anchors
//! are never evicted). It is a pure function over its input layers — the caller
//! pre-fetches each layer (persona, env anchor, recall, recent turns, summary,
//! tool results) and this driver composes the final one-shot prompt.
//!
//! Layers (priority high→low, §20.5):
//!   1. System / persona anchor (never evicted)
//!   2. Environment anchor: time, available capabilities (never evicted)
//!   3. Task Skills + recall (vector search + rerank), taint-tagged
//!   4. Recent N raw turns
//!   5. Rolling summary of older history
//!   6. Tool results (large → summary + BlobRef)

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;

/// Method names for `effect://context/assemble`; the public method is `invoke`
/// after standard installation. Pure: assembly is a deterministic function of
/// its input layers (no I/O).
pub const CONTEXT_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "assemble",
    Purity::Pure,
    MethodSpec::UNARY_ASYNC,
)];

/// Priority order of layers — index 0 is highest. The first two are anchors
/// that are never evicted (§20.5).
const LAYER_ORDER: &[&str] = &[
    "persona",
    "environment",
    "skills",
    "recent",
    "summary",
    "tools",
];
const NEVER_EVICT: usize = 2; // persona + environment

/// Estimate tokens for a text fragment (≈ 4 chars/token, the §20.5 heuristic).
fn est_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

/// Render one layer's value to its text contribution.
fn layer_text(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::List(items) => items.iter().map(layer_text).collect::<Vec<_>>().join("\n"),
        Value::Map(m) => m.get("text").map(layer_text).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Drives `effect://context/assemble`. Stateless.
#[derive(Clone, Default)]
pub struct ContextDriver;

impl ContextDriver {
    pub fn new() -> Self {
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
        let m = input.as_map().cloned().unwrap_or_default();
        let budget = m
            .get("token_budget")
            .and_then(|v| v.as_int())
            .unwrap_or(4096)
            .max(0) as usize;
        let layers = m
            .get("layers")
            .and_then(|v| v.as_map())
            .cloned()
            .unwrap_or_default();

        // Fill layers high-priority-first until the budget is exhausted (§20.5).
        let mut included: Vec<(String, String, usize)> = Vec::new();
        let mut used = 0usize;
        for (i, layer) in LAYER_ORDER.iter().enumerate() {
            let Some(v) = layers.get(*layer) else {
                continue;
            };
            let text = layer_text(v);
            if text.is_empty() {
                continue;
            }
            let cost = est_tokens(&text);
            if i < NEVER_EVICT {
                // Anchors are always included even if they alone exceed budget.
                included.push((layer.to_string(), text, cost));
                used += cost;
            } else if used + cost <= budget {
                included.push((layer.to_string(), text, cost));
                used += cost;
            }
            // else: this lower-priority layer doesn't fit; skip it (it would be
            // the first evicted anyway).
        }

        // If anchors alone overflowed, evict from the back of the non-anchor
        // layers until within budget (reverse-priority eviction, §20.5).
        while used > budget && included.len() > NEVER_EVICT {
            if let Some((_, _, cost)) = included.pop() {
                used = used.saturating_sub(cost);
            }
        }

        // Compose the one-shot prompt in priority order (not persisted, §20.5).
        let prompt = included
            .iter()
            .map(|(name, text, _)| format!("## {name}\n{text}"))
            .collect::<Vec<_>>()
            .join("\n\n");
        let layers_used: Vec<Value> = included
            .iter()
            .map(|(name, _, _)| Value::Str(name.clone()))
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
    use nexus_types::{IdentityRef, ProcessId};

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

    #[tokio::test]
    async fn assembles_in_priority_order() {
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
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => {
                let prompt = m.get("prompt").and_then(|v| v.as_str()).unwrap();
                // persona appears before recent appears before summary.
                let p = prompt.find("persona").unwrap();
                let r = prompt.find("recent").unwrap();
                let s = prompt.find("summary").unwrap();
                assert!(p < r && r < s);
            }
            _ => panic!("expected assembled map"),
        }
    }

    #[tokio::test]
    async fn evicts_low_priority_under_tight_budget() {
        let d = ContextDriver::new();
        // Budget only fits the persona anchor; summary/tools should be dropped.
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
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => {
                let layers: Vec<String> = match m.get("layers_used") {
                    Some(Value::List(l)) => l
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    _ => vec![],
                };
                assert!(layers.contains(&"persona".to_string()));
                assert!(
                    !layers.contains(&"summary".to_string()),
                    "low-priority evicted"
                );
            }
            _ => panic!("expected assembled map"),
        }
    }

    #[tokio::test]
    async fn anchors_survive_even_over_budget() {
        let d = ContextDriver::new();
        // Budget is 1 token but the persona anchor is never evicted (§20.5).
        let input = assemble_input(1, vec![("persona", "core identity must persist")]);
        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => {
                assert!(
                    m.get("prompt")
                        .and_then(|v| v.as_str())
                        .unwrap()
                        .contains("core identity")
                );
            }
            _ => panic!("expected assembled map"),
        }
    }
}
