//! Ranker: `effect://rank/score`, `effect://rank/fuse`.
//!
//! Ranking uses a Ranker implementation. `score` fuses multiple signals
//! (semantic similarity / weight / recency / confidence) by
//! **policy-configurable** weights; `fuse` combines several recall lists by
//! Reciprocal Rank Fusion (RRF). The default weights `0.4/0.3/0.2/0.1` are the
//! default config. Deployments can store rank settings in `state://kernel/rank/*`.

use async_trait::async_trait;
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use xolotl_types::{FloatBits, MethodId, Outcome, OutputMode, Purity, Value};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://rank/<method>` Resource with public method
/// `invoke`.
pub(crate) const RANK_METHODS: &[MethodSpec] = &[
    MethodSpec::new("score", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("fuse", Purity::Pure, MethodSpec::UNARY_ASYNC),
];

/// Default signal weights — overridable via input `weights`.
const DEFAULT_WEIGHTS: [(&str, f64); 4] = [
    ("semantic_sim", 0.4),
    ("weight", 0.3),
    ("recency", 0.2),
    ("confidence", 0.1),
];

/// RRF constant (standard k=60).
const RRF_K: f64 = 60.0;

/// Drives the rank actions. Weights resolve in precedence order: per-call
/// `weights` input → `state://kernel/rank/weights`
/// → the built-in default weights. The state backend is optional so the
/// driver works standalone (tests) without config.
#[derive(Clone, Default)]
pub(crate) struct RankerDriver {
    state: Option<xolotl_state::Backend>,
}

impl RankerDriver {
    /// Create a ranker driver with built-in default weights only.
    pub(crate) fn new() -> Self {
        Self { state: None }
    }

    /// Attach a state backend so default weights are read from
    /// `state://kernel/rank/weights`.
    pub(crate) fn with_state(mut self, state: xolotl_state::Backend) -> Self {
        self.state = Some(state);
        self
    }

    /// Resolve the signal weights for a `score` call: per-call override,
    /// else hot-tunable state config, else the built-in defaults.
    async fn resolve_weights(
        &self,
        m: &BTreeMap<String, Value>,
    ) -> Result<Vec<(String, f64)>, DriverError> {
        if let Some(w) = m.get("weights").and_then(|v| v.as_map()) {
            return w
                .iter()
                .map(|(k, v)| as_f64(Some(v)).map(|weight| (k.clone(), weight)))
                .collect();
        }

        if let Some(state) = &self.state {
            let path =
                xolotl_types::Path::parse("state://kernel/rank/weights").map_err(|error| {
                    DriverError::Other(format!("rank weights path is invalid: {error}"))
                })?;
            match state
                .read(&path)
                .await
                .map_err(|error| DriverError::Other(format!("rank weights read failed: {error}")))?
            {
                Some(Value::Map(w)) => {
                    return w
                        .iter()
                        .map(|(k, v)| as_f64(Some(v)).map(|weight| (k.clone(), weight)))
                        .collect();
                }
                Some(_) => {
                    return Err(DriverError::InvalidInput(
                        "state://kernel/rank/weights must be a map".into(),
                    ));
                }
                None => {}
            }
        }

        Ok(DEFAULT_WEIGHTS
            .iter()
            .map(|(k, w)| (k.to_string(), *w))
            .collect())
    }
}

fn as_f64(v: Option<&Value>) -> Result<f64, DriverError> {
    match v {
        Some(Value::Float(FloatBits(f))) if f.is_finite() => Ok(*f),
        Some(Value::Float(FloatBits(_))) => Err(DriverError::InvalidInput(
            "rank weight must be finite".into(),
        )),
        Some(Value::Int(i)) => Ok(*i as f64),
        Some(_) => Err(DriverError::InvalidInput(
            "rank weight must be numeric".into(),
        )),
        None => Ok(0.0),
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
        let m = crate::input::map(input, "rank")?;
        match method.get() {
            // score(signals, [weights]): weighted-sum fuse of per-candidate
            // signals. `signals` is a list of maps each with an `id` and signal
            // values; returns `[{id, score}]` sorted descending.
            0 => {
                // Resolve weights: input override → state config → default.
                let weights = self.resolve_weights(&m).await?;
                let signals = match m.get("signals") {
                    Some(Value::List(signals)) => signals,
                    Some(_) => {
                        return Err(DriverError::InvalidInput(
                            "rank.score signals must be a list".into(),
                        ));
                    }
                    None => {
                        return Err(DriverError::InvalidInput(
                            "rank.score requires signals".into(),
                        ));
                    }
                };
                let mut scored = Vec::with_capacity(signals.len());
                for cand in signals {
                    let Some(cm) = cand.as_map() else {
                        return Err(DriverError::InvalidInput(
                            "rank.score signals entries must be maps".into(),
                        ));
                    };
                    let id = Value::Str(required_candidate_id(cm)?);
                    let score: f64 = weights
                        .iter()
                        .map(|(sig, w)| as_f64(cm.get(sig)).map(|signal| w * signal))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .sum();
                    scored.push((id, score));
                }
                scored.sort_by(|a, b| b.1.total_cmp(&a.1));
                Ok(Outcome::Done(ranked_list(scored)))
            }
            // fuse(lists): Reciprocal Rank Fusion over several ranked id-lists.
            1 => {
                let lists = match m.get("lists") {
                    Some(Value::List(lists)) => lists,
                    Some(_) => {
                        return Err(DriverError::InvalidInput(
                            "rank.fuse lists must be a list".into(),
                        ));
                    }
                    None => {
                        return Err(DriverError::InvalidInput("rank.fuse requires lists".into()));
                    }
                };
                let mut acc: BTreeMap<String, f64> = BTreeMap::new();
                for list in lists {
                    let Value::List(items) = list else {
                        return Err(DriverError::InvalidInput(
                            "rank.fuse entries must be lists".into(),
                        ));
                    };
                    for (rank, item) in items.iter().enumerate() {
                        let id = match item {
                            Value::Str(id) if !id.is_empty() => id.clone(),
                            Value::Str(_) => {
                                return Err(DriverError::InvalidInput(
                                    "rank.fuse ids must be non-empty".into(),
                                ));
                            }
                            Value::Map(im) => required_candidate_id(im)?,
                            _ => {
                                return Err(DriverError::InvalidInput(
                                    "rank.fuse items must be ids or maps with id".into(),
                                ));
                            }
                        };
                        *acc.entry(id).or_insert(0.0) += 1.0 / (RRF_K + (rank as f64) + 1.0);
                    }
                }
                let mut scored: Vec<(Value, f64)> =
                    acc.into_iter().map(|(id, s)| (Value::Str(id), s)).collect();
                scored.sort_by(|a, b| b.1.total_cmp(&a.1));
                Ok(Outcome::Done(ranked_list(scored)))
            }
            _ => Err(DriverError::Other(format!(
                "unknown rank method {}",
                method.get()
            ))),
        }
    }
}

fn required_candidate_id(m: &BTreeMap<String, Value>) -> Result<String, DriverError> {
    match m.get("id") {
        Some(Value::Str(id)) if !id.is_empty() => Ok(id.clone()),
        Some(Value::Str(_)) => Err(DriverError::InvalidInput(
            "rank candidate id must be non-empty".into(),
        )),
        Some(_) => Err(DriverError::InvalidInput(
            "rank candidate id must be a string".into(),
        )),
        None => Err(DriverError::InvalidInput(
            "rank candidate requires id".into(),
        )),
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
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

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

    fn first_ranked_id(outcome: Outcome) -> Result<String> {
        let Outcome::Done(Value::List(ranked)) = outcome else {
            bail!("expected ranked list, got {outcome:?}");
        };
        ranked
            .first()
            .and_then(Value::as_map)
            .and_then(|map| map.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("ranked list missing first id")
    }

    fn path(value: &str) -> Result<xolotl_types::Path> {
        xolotl_types::Path::parse(value).with_context(|| format!("parse {value}"))
    }

    #[tokio::test]
    async fn score_fuses_signals_by_default_weights() -> Result<()> {
        let d = RankerDriver::new();
        let mut m = BTreeMap::new();
        m.insert(
            "signals".into(),
            Value::List(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("score rank signals")?;
        let first = first_ranked_id(out)?;
        ensure!(first == "b", "first ranked id: {first}");
        Ok(())
    }

    #[tokio::test]
    async fn weights_come_from_state_config_when_present() -> Result<()> {
        use std::sync::Arc;
        use xolotl_state::{Backend, InMemoryBackend};
        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut w = BTreeMap::new();
        w.insert("semantic_sim".into(), Value::Float(FloatBits(0.0)));
        w.insert("weight".into(), Value::Float(FloatBits(1.0)));
        state
            .write_set(&path("state://kernel/rank/weights")?, Value::Map(w))
            .await
            .context("write rank weights")?;
        let d = RankerDriver::new().with_state(state);
        let mut m = BTreeMap::new();
        m.insert(
            "signals".into(),
            Value::List(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("score rank signals")?;
        let first = first_ranked_id(out)?;
        ensure!(first == "a", "first ranked id: {first}");
        Ok(())
    }

    #[tokio::test]
    async fn malformed_state_weights_are_errors() -> Result<()> {
        use std::sync::Arc;
        use xolotl_state::{Backend, InMemoryBackend};
        let state: Backend = Arc::new(InMemoryBackend::new());
        state
            .write_set(
                &path("state://kernel/rank/weights")?,
                Value::Str("bad".into()),
            )
            .await
            .context("write malformed rank weights")?;
        let d = RankerDriver::new().with_state(state);
        let mut m = BTreeMap::new();
        m.insert(
            "signals".into(),
            Value::List(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "malformed rank weights must fail");
        Ok(())
    }

    #[tokio::test]
    async fn score_rejects_missing_or_malformed_signals() -> Result<()> {
        let d = RankerDriver::new();
        let mut missing_id = BTreeMap::new();
        missing_id.insert("semantic_sim".into(), Value::Float(FloatBits(1.0)));

        for input in [
            Value::Map(BTreeMap::new()),
            Value::Map(BTreeMap::from([(
                "signals".into(),
                Value::Str("bad".into()),
            )])),
            Value::Map(BTreeMap::from([(
                "signals".into(),
                Value::List(vec![Value::Map(missing_id)]),
            )])),
        ] {
            let out = d
                .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
                .await;
            ensure!(out.is_err(), "malformed rank.score input was accepted");
        }
        Ok(())
    }

    #[tokio::test]
    async fn fuse_combines_lists_by_rrf() -> Result<()> {
        let d = RankerDriver::new();
        let l1 = Value::List(vec![Value::Str("x".into()), Value::Str("y".into())]);
        let l2 = Value::List(vec![Value::Str("y".into()), Value::Str("z".into())]);
        let mut m = BTreeMap::new();
        m.insert("lists".into(), Value::List(vec![l1, l2]));
        let out = d
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("fuse rank lists")?;
        let first = first_ranked_id(out)?;
        ensure!(first == "y", "first ranked id: {first}");
        Ok(())
    }

    #[tokio::test]
    async fn fuse_rejects_malformed_lists() -> Result<()> {
        let d = RankerDriver::new();
        for input in [
            Value::Map(BTreeMap::new()),
            Value::Map(BTreeMap::from([("lists".into(), Value::Str("bad".into()))])),
            Value::Map(BTreeMap::from([(
                "lists".into(),
                Value::List(vec![Value::Str("bad".into())]),
            )])),
            Value::Map(BTreeMap::from([(
                "lists".into(),
                Value::List(vec![Value::List(vec![Value::Null])]),
            )])),
        ] {
            let out = d
                .call(MethodId::new(1), input, OutputMode::Unary, &ctx())
                .await;
            ensure!(out.is_err(), "malformed rank.fuse input was accepted");
        }
        Ok(())
    }
}
