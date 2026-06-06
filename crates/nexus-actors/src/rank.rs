//! Ranker (§17.2): `effect://rank/score`, `effect://rank/fuse`.
//!
//! Ranking is a pluggable Ranker, not a hard-coded constant (§17.2). `score`
//! fuses multiple signals (semantic similarity / weight / recency / confidence)
//! by **policy-configurable** weights; `fuse` combines several recall lists by
//! Reciprocal Rank Fusion (RRF). The default weights `0.4/0.3/0.2/0.1` are just
//! the default config — production stores them in `state://kernel/rank/*` and
//! hot-tunes them, rather than burying them in code.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{FloatBits, MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://rank/<method>` Resource with public method
/// `invoke`.
pub const RANK_METHODS: &[MethodSpec] = &[
    MethodSpec::new("score", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("fuse", Purity::Pure, MethodSpec::UNARY_ASYNC),
];

/// Default signal weights (§17.2) — overridable via input `weights`.
const DEFAULT_WEIGHTS: [(&str, f64); 4] = [
    ("semantic_sim", 0.4),
    ("weight", 0.3),
    ("recency", 0.2),
    ("confidence", 0.1),
];

/// RRF constant (standard k=60).
const RRF_K: f64 = 60.0;

/// Drives the rank actions. Weights resolve in precedence order: per-call
/// `weights` input → `state://kernel/rank/weights` (hot-tunable config, §17.2)
/// → the built-in [`DEFAULT_WEIGHTS`]. The state backend is optional so the
/// driver works standalone (tests) without config.
#[derive(Clone, Default)]
pub struct RankerDriver {
    state: Option<nexus_state::Backend>,
}

impl RankerDriver {
    pub fn new() -> Self {
        Self { state: None }
    }

    /// Attach a state backend so default weights are read from
    /// `state://kernel/rank/weights` (hot-tunable, §17.2).
    pub fn with_state(mut self, state: nexus_state::Backend) -> Self {
        self.state = Some(state);
        self
    }

    /// Resolve the signal weights for a `score` call (§17.2): per-call override,
    /// else hot-tunable state config, else the built-in defaults.
    async fn resolve_weights(&self, m: &BTreeMap<String, Value>) -> Vec<(String, f64)> {
        if let Some(w) = m.get("weights").and_then(|v| v.as_map()) {
            return w
                .iter()
                .map(|(k, v)| (k.clone(), as_f64(Some(v))))
                .collect();
        }
        if let Some(state) = &self.state
            && let Ok(path) = nexus_types::Path::parse("state://kernel/rank/weights")
            && let Ok(Some(Value::Map(w))) = state.read(&path).await
        {
            return w
                .iter()
                .map(|(k, v)| (k.clone(), as_f64(Some(v))))
                .collect();
        }
        DEFAULT_WEIGHTS
            .iter()
            .map(|(k, w)| (k.to_string(), *w))
            .collect()
    }
}

fn as_f64(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Float(FloatBits(f))) => *f,
        Some(Value::Int(i)) => *i as f64,
        _ => 0.0,
    }
}

#[async_trait]
impl Driver for RankerDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = input.as_map().cloned().unwrap_or_default();
        match method.get() {
            // score(signals, [weights]): weighted-sum fuse of per-candidate
            // signals. `signals` is a list of maps each with an `id` and signal
            // values; returns `[{id, score}]` sorted descending.
            0 => {
                // Resolve weights: input override → state config → default.
                let weights = self.resolve_weights(&m).await;
                let signals = match m.get("signals") {
                    Some(Value::List(s)) => s.clone(),
                    _ => vec![],
                };
                let mut scored: Vec<(Value, f64)> = signals
                    .iter()
                    .map(|cand| {
                        let cm = cand.as_map().cloned().unwrap_or_default();
                        let id = cm.get("id").cloned().unwrap_or(Value::Null);
                        let score: f64 =
                            weights.iter().map(|(sig, w)| w * as_f64(cm.get(sig))).sum();
                        (id, score)
                    })
                    .collect();
                scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                Ok(Outcome::Done(ranked_list(scored)))
            }
            // fuse(lists): Reciprocal Rank Fusion over several ranked id-lists.
            1 => {
                let lists = match m.get("lists") {
                    Some(Value::List(ls)) => ls.clone(),
                    _ => vec![],
                };
                let mut acc: BTreeMap<String, f64> = BTreeMap::new();
                for list in &lists {
                    if let Value::List(items) = list {
                        for (rank, item) in items.iter().enumerate() {
                            // Each item is an id (or a map with `id`).
                            let id = match item {
                                Value::Str(s) => s.clone(),
                                Value::Map(im) => im
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string(),
                                _ => continue,
                            };
                            *acc.entry(id).or_insert(0.0) += 1.0 / (RRF_K + (rank as f64) + 1.0);
                        }
                    }
                }
                let mut scored: Vec<(Value, f64)> =
                    acc.into_iter().map(|(id, s)| (Value::Str(id), s)).collect();
                scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                Ok(Outcome::Done(ranked_list(scored)))
            }
            _ => Err(DriverError::Other(format!(
                "unknown rank method {}",
                method.get()
            ))),
        }
    }
}

fn ranked_list(scored: Vec<(Value, f64)>) -> Value {
    Value::List(
        scored
            .into_iter()
            .map(|(id, score)| {
                let mut e = BTreeMap::new();
                e.insert("id".into(), id);
                e.insert("score".into(), Value::Float(FloatBits(score)));
                Value::Map(e)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{IdentityRef, ProcessId};

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn cand(id: &str, sim: f64, weight: f64) -> Value {
        let mut m = BTreeMap::new();
        m.insert("id".into(), Value::Str(id.into()));
        m.insert("semantic_sim".into(), Value::Float(FloatBits(sim)));
        m.insert("weight".into(), Value::Float(FloatBits(weight)));
        Value::Map(m)
    }

    #[tokio::test]
    async fn score_fuses_signals_by_default_weights() {
        let d = RankerDriver::new();
        let mut m = BTreeMap::new();
        m.insert(
            "signals".into(),
            Value::List(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            // b has higher semantic_sim (weight 0.4) → should rank first.
            Outcome::Done(Value::List(r)) => {
                let first = r[0]
                    .as_map()
                    .unwrap()
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap();
                assert_eq!(first, "b");
            }
            _ => panic!("expected ranked list"),
        }
    }

    #[tokio::test]
    async fn weights_come_from_state_config_when_present() {
        // §17.2: default weights are hot-tunable via state://kernel/rank/weights.
        // We flip the weighting to favor `weight` over `semantic_sim` and verify
        // the ranking changes accordingly.
        use nexus_state::{Backend, InMemoryBackend};
        use std::sync::Arc;
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut w = BTreeMap::new();
        w.insert("semantic_sim".into(), Value::Float(FloatBits(0.0)));
        w.insert("weight".into(), Value::Float(FloatBits(1.0)));
        state
            .write_set(
                &nexus_types::Path::parse("state://kernel/rank/weights").unwrap(),
                Value::Map(w),
            )
            .await
            .unwrap();
        let d = RankerDriver::new().with_state(state);
        let mut m = BTreeMap::new();
        // a has low sim but high weight; b has high sim but low weight.
        m.insert(
            "signals".into(),
            Value::List(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            // With weight=1.0 dominating, `a` (higher weight) now ranks first.
            Outcome::Done(Value::List(r)) => {
                let first = r[0]
                    .as_map()
                    .unwrap()
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap();
                assert_eq!(first, "a", "state-config weights override defaults");
            }
            _ => panic!("expected ranked list"),
        }
    }

    #[tokio::test]
    async fn fuse_combines_lists_by_rrf() {
        let d = RankerDriver::new();
        let l1 = Value::List(vec![Value::Str("x".into()), Value::Str("y".into())]);
        let l2 = Value::List(vec![Value::Str("y".into()), Value::Str("z".into())]);
        let mut m = BTreeMap::new();
        m.insert("lists".into(), Value::List(vec![l1, l2]));
        let out = d
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        match out {
            // y appears in both lists → highest RRF score.
            Outcome::Done(Value::List(r)) => {
                let first = r[0]
                    .as_map()
                    .unwrap()
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap();
                assert_eq!(first, "y");
            }
            _ => panic!("expected fused list"),
        }
    }
}
