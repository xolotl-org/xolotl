//! Ranker: `effect://rank/score`, `effect://rank/fuse`.
//!
//! Ranking uses a Ranker implementation. `score` fuses multiple signals
//! (semantic similarity / weight / recency / confidence) by
//! **policy-configurable** weights; `fuse` combines several recall lists by
//! Reciprocal Rank Fusion (RRF). The default weights `0.4/0.3/0.2/0.1` are the
//! default config. Deployments can store rank settings in `state://kernel/rank/*`.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{FloatBits, MethodId, Outcome, OutputMode, Purity, TaintSet, Value};
use xolotl_types::{ValueMap, ValueView};

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
        m: &ValueMap,
        observed: &mut TaintSet,
    ) -> Result<Vec<(String, f64)>, DriverError> {
        if let Some(w) = m.get("weights").and_then(|v| v.as_map()) {
            return w
                .iter()
                .map(|(k, v)| as_f64(Some(v)).map(|weight| (k.to_owned(), weight)))
                .collect();
        }

        if let Some(state) = &self.state {
            let path =
                xolotl_types::Path::parse("state://kernel/rank/weights").map_err(|error| {
                    DriverError::Other(format!("rank weights path is invalid: {error}"))
                })?;
            let stored = state.read_tainted(&path).await.map_err(|error| {
                observed.union(&error.taint);
                DriverError::Other(format!("rank weights read failed: {error}"))
            })?;
            if let Some(stored) = &stored {
                observed.union(&stored.taint);
            }
            match stored.as_ref().map(|stored| stored.value.view()) {
                Some(ValueView::Map(w)) => {
                    return w
                        .iter()
                        .map(|(k, v)| as_f64(Some(v)).map(|weight| (k.to_owned(), weight)))
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

    async fn score(&self, input: &ValueMap, observed: &mut TaintSet) -> Result<Value, DriverError> {
        let weights = self.resolve_weights(input, observed).await?;
        let signals = input
            .get("signals")
            .and_then(Value::as_list)
            .ok_or_else(|| {
                DriverError::InvalidInput("rank.score requires a signals list".into())
            })?;
        let mut scored = Vec::with_capacity(signals.len());
        for candidate in signals {
            let fields = candidate.as_map().ok_or_else(|| {
                DriverError::InvalidInput("rank.score signals entries must be maps".into())
            })?;
            let id = Value::string(required_candidate_id(fields)?);
            let score = weights
                .iter()
                .map(|(signal, weight)| as_f64(fields.get(signal)).map(|value| weight * value))
                .try_fold(0.0, |sum, value| value.map(|value| sum + value))?;
            scored.push((id, score));
        }
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        Ok(ranked_list(scored))
    }
}

fn as_f64(v: Option<&Value>) -> Result<f64, DriverError> {
    match v.map(Value::view) {
        Some(ValueView::Float(FloatBits(f))) if f.is_finite() => Ok(f),
        Some(ValueView::Float(FloatBits(_))) => Err(DriverError::InvalidInput(
            "rank weight must be finite".into(),
        )),
        Some(ValueView::Int(i)) => Ok(i as f64),
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
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let m = crate::input::map(input, "rank")?;
        match method.get() {
            // score(signals, [weights]): weighted-sum fuse of per-candidate
            // signals. `signals` is a list of maps each with an `id` and signal
            // values; returns `[{id, score}]` sorted descending.
            0 => {
                let mut observed = ctx.taint.clone();
                match self.score(&m, &mut observed).await {
                    Ok(value) => Ok(DriverOutput::new(Outcome::Done(value)).with_taint(observed)),
                    Err(error) => ObservedFailure::from(error)
                        .with_taint(&observed)
                        .into_output("rank"),
                }
            }
            // fuse(lists): Reciprocal Rank Fusion over several ranked id-lists.
            1 => {
                let lists = match m.get("lists").map(Value::view) {
                    Some(ValueView::List(lists)) => lists,
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
                    let Some(items) = list.as_list() else {
                        return Err(DriverError::InvalidInput(
                            "rank.fuse entries must be lists".into(),
                        ));
                    };
                    for (rank, item) in items.iter().enumerate() {
                        let id = match item.view() {
                            ValueView::Str(id) if !id.is_empty() => id.to_owned(),
                            ValueView::Str(_) => {
                                return Err(DriverError::InvalidInput(
                                    "rank.fuse ids must be non-empty".into(),
                                ));
                            }
                            ValueView::Map(im) => required_candidate_id(im)?,
                            _ => {
                                return Err(DriverError::InvalidInput(
                                    "rank.fuse items must be ids or maps with id".into(),
                                ));
                            }
                        };
                        *acc.entry(id).or_insert(0.0) += 1.0 / (RRF_K + (rank as f64) + 1.0);
                    }
                }
                let mut scored: Vec<(Value, f64)> = acc
                    .into_iter()
                    .map(|(id, s)| (Value::string(id), s))
                    .collect();
                scored.sort_by(|a, b| b.1.total_cmp(&a.1));
                Ok(DriverOutput::new(Outcome::Done(ranked_list(scored))))
            }
            _ => Err(DriverError::Other(format!(
                "unknown rank method {}",
                method.get()
            ))),
        }
    }
}

fn required_candidate_id(m: &ValueMap) -> Result<String, DriverError> {
    match m.get("id").map(Value::view) {
        Some(ValueView::Str(id)) if !id.is_empty() => Ok(id.to_owned()),
        Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(
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
    Value::list(
        scored
            .into_iter()
            .map(|(id, score)| {
                let mut e = BTreeMap::new();
                e.insert("id".into(), id);
                e.insert("score".into(), Value::float(FloatBits(score)));
                Value::map(e)
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
        m.insert("id".into(), Value::string(id.into()));
        m.insert("semantic_sim".into(), Value::float(FloatBits(sim)));
        m.insert("weight".into(), Value::float(FloatBits(weight)));
        Value::map(m)
    }

    fn first_ranked_id(output: DriverOutput) -> Result<String> {
        let Outcome::Done(value) = output.outcome else {
            bail!("expected ranked list, got {output:?}");
        };
        let ranked = value.as_list().context("expected ranked list")?;
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
            Value::list(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("score rank signals")?;
        let first = first_ranked_id(out)?;
        ensure!(first == "b", "first ranked id: {first}");
        Ok(())
    }

    #[tokio::test]
    async fn weights_come_from_state_config_when_present() -> Result<()> {
        use xolotl_state::{Backend, InMemoryBackend};
        let state: Backend = InMemoryBackend::new().into_backend();
        let mut w = BTreeMap::new();
        w.insert("semantic_sim".into(), Value::float(FloatBits(0.0)));
        w.insert("weight".into(), Value::float(FloatBits(1.0)));
        state
            .write_set(&path("state://kernel/rank/weights")?, Value::map(w))
            .await
            .context("write rank weights")?;
        let d = RankerDriver::new().with_state(state);
        let mut m = BTreeMap::new();
        m.insert(
            "signals".into(),
            Value::list(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("score rank signals")?;
        let first = first_ranked_id(out)?;
        ensure!(first == "a", "first ranked id: {first}");
        Ok(())
    }

    #[tokio::test]
    async fn malformed_state_weights_are_errors() -> Result<()> {
        use xolotl_state::{Backend, InMemoryBackend};
        let state: Backend = InMemoryBackend::new().into_backend();
        state
            .write_set(
                &path("state://kernel/rank/weights")?,
                Value::string("bad".into()),
            )
            .await
            .context("write malformed rank weights")?;
        let d = RankerDriver::new().with_state(state);
        let mut m = BTreeMap::new();
        m.insert(
            "signals".into(),
            Value::list(vec![cand("a", 0.2, 0.9), cand("b", 0.9, 0.1)]),
        );
        let out = d
            .call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "malformed rank weights must fail");
        Ok(())
    }

    #[tokio::test]
    async fn state_weight_sources_survive_success_and_later_validation_failures() -> Result<()> {
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let path = path("state://kernel/rank/weights")?;
        let protected = TaintSet::of(xolotl_types::TaintSource::Protected { path: path.clone() });
        let driver = RankerDriver::new().with_state(state.clone());
        let input = Value::map(BTreeMap::from([(
            "signals".into(),
            Value::list(vec![cand("a", 1.0, 0.0)]),
        )]));
        for weights in [
            Value::map(BTreeMap::from([("semantic_sim".into(), Value::integer(1))])),
            Value::string("bad".into()),
        ] {
            let valid = weights.as_map().is_some();
            state
                .write_set_tainted(&path, weights, protected.clone())
                .await?;
            let output = driver
                .call(MethodId::new(0), input.clone(), OutputMode::Unary, &ctx())
                .await?;
            ensure!(output.taint == protected);
            ensure!(matches!(output.outcome, Outcome::Done(_)) == valid);
            if valid {
                let failed = driver
                    .call(
                        MethodId::new(0),
                        Value::map(BTreeMap::new()),
                        OutputMode::Unary,
                        &ctx(),
                    )
                    .await?;
                ensure!(failed.taint == protected && matches!(failed.outcome, Outcome::Fail(_)));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn score_rejects_missing_or_malformed_signals() -> Result<()> {
        let d = RankerDriver::new();
        let mut missing_id = BTreeMap::new();
        missing_id.insert("semantic_sim".into(), Value::float(FloatBits(1.0)));

        for input in [
            Value::map(BTreeMap::new()),
            Value::map(BTreeMap::from([(
                "signals".into(),
                Value::string("bad".into()),
            )])),
            Value::map(BTreeMap::from([(
                "signals".into(),
                Value::list(vec![Value::map(missing_id)]),
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
        let l1 = Value::list(vec![Value::string("x".into()), Value::string("y".into())]);
        let l2 = Value::list(vec![Value::string("y".into()), Value::string("z".into())]);
        let mut m = BTreeMap::new();
        m.insert("lists".into(), Value::list(vec![l1, l2]));
        let out = d
            .call(MethodId::new(1), Value::map(m), OutputMode::Unary, &ctx())
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
            Value::map(BTreeMap::new()),
            Value::map(BTreeMap::from([(
                "lists".into(),
                Value::string("bad".into()),
            )])),
            Value::map(BTreeMap::from([(
                "lists".into(),
                Value::list(vec![Value::string("bad".into())]),
            )])),
            Value::map(BTreeMap::from([(
                "lists".into(),
                Value::list(vec![Value::list(vec![Value::null()])]),
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
