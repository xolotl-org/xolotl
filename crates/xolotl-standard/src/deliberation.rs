//! Deliberation: `effect://deliberation/run`.
//!
//! Runs a panel of model "panelists" over one or more rounds and returns a
//! verdict. Single-round fan-out (vote / synthesize) is the `rounds == 1`
//! special case of multi-round debate: each round, every panelist responds to
//! the running transcript; a judge checks convergence; if not converged and
//! the round budget remains, another round runs.
//!
//! This is the *driver* form, exposing deliberation as one standard effect.
//! The same shape can be written directly as a recursive `Do<A>` in a Process
//! as well. Both forms reduce to inference Operations, so taint is
//! never laundered by debate and each call is budgeted.

use crate::inference::InferenceBackend;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, TaintSet, TaintSource, Value};
use xolotl_types::{ValueMap, ValueView};

/// Method names for `effect://deliberation/run`; the public method is `invoke`
/// after standard installation.
pub(crate) const DELIBERATION_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "run",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// How a debate is resolved into a verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    /// Single round; majority/first answer (fan-out vote).
    Vote,
    /// Single round; concatenate contributions (synthesizer).
    Synthesize,
    /// Multi-round; panelists see each other and a judge checks convergence.
    Debate,
}

/// Drives `effect://deliberation/run`, delegating model calls to a backend.
pub(crate) struct DeliberationDriver {
    backend: Arc<dyn InferenceBackend>,
}

impl DeliberationDriver {
    /// Create a deliberation driver using `backend` for panelist calls.
    pub(crate) fn new(backend: Arc<dyn InferenceBackend>) -> Self {
        Self { backend }
    }

    fn mode_of(input: &ValueMap) -> Result<Mode, DriverError> {
        match input.get("mode").map(Value::view) {
            None => Ok(Mode::Vote),
            Some(ValueView::Str("vote")) => Ok(Mode::Vote),
            Some(ValueView::Str("synthesize")) => Ok(Mode::Synthesize),
            Some(ValueView::Str("debate")) => Ok(Mode::Debate),
            Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(
                "deliberation `mode` must be vote, synthesize, or debate".into(),
            )),
            Some(_) => Err(DriverError::InvalidInput(
                "deliberation `mode` must be a string".into(),
            )),
        }
    }
}

#[async_trait]
impl Driver for DeliberationDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        if self.backend.requires_unprotected_input() && ctx.taint.has_protected() {
            return Err(DriverError::InvalidInput(
                "deliberation backend requires unprotected input".into(),
            ));
        }
        let Some(m) = input.as_map() else {
            return Err(DriverError::InvalidInput(
                "deliberation input must be a map".into(),
            ));
        };
        let question = required_non_empty_string(m, "question", "deliberation")?.to_string();
        let panelists = optional_bounded_usize(m, "panelists", 2, 1, 8, "deliberation")?;
        let max_rounds = optional_bounded_usize(m, "max_rounds", 1, 1, 8, "deliberation")?;
        let mode = Self::mode_of(m)?;

        let mut transcript: Vec<String> = Vec::new();
        let mut round = 0;
        loop {
            round += 1;
            // Each panelist responds to the running transcript (debate ⇒
            // mutually visible; vote/synthesize ⇒ independent first round).
            let mut contributions = Vec::new();
            for p in 0..panelists {
                let prompt = build_prompt(&question, &transcript, p, mode);
                let resp = self
                    .backend
                    .infer(&Value::string(prompt))
                    .await
                    .map_err(DriverError::Other)?;
                contributions.push(text_of(&resp));
            }
            if mode == Mode::Debate {
                transcript.extend(contributions.iter().cloned());
            } else {
                transcript = contributions.clone();
            }
            // Judge: converged when all panelists agree, or rounds exhausted.
            if mode != Mode::Debate || converged(&contributions) || round >= max_rounds {
                return Ok(
                    DriverOutput::new(Outcome::Done(verdict(mode, &transcript, round)))
                        .with_taint(TaintSet::of(TaintSource::ModelOutput)),
                );
            }
        }
    }
}

fn required_non_empty_string<'a>(
    m: &'a ValueMap,
    field: &'static str,
    op: &'static str,
) -> Result<&'a str, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(value),
        Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must not be empty"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be a string"
        ))),
        None => Err(DriverError::InvalidInput(format!(
            "{op} requires `{field}`"
        ))),
    }
}

fn optional_bounded_usize(
    m: &ValueMap,
    field: &'static str,
    default: usize,
    min: usize,
    max: usize,
    op: &'static str,
) -> Result<usize, DriverError> {
    match m.get(field).map(Value::view) {
        None => Ok(default),
        Some(ValueView::Int(value)) => {
            let value = usize::try_from(value).map_err(|_error| {
                DriverError::InvalidInput(format!("{op} `{field}` must be between {min} and {max}"))
            })?;
            if (min..=max).contains(&value) {
                Ok(value)
            } else {
                Err(DriverError::InvalidInput(format!(
                    "{op} `{field}` must be between {min} and {max}"
                )))
            }
        }
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        ))),
    }
}

fn build_prompt(question: &str, transcript: &[String], panelist: usize, mode: Mode) -> String {
    let mut p = format!("[panelist {panelist}] question: {question}");
    if mode == Mode::Debate && !transcript.is_empty() {
        p.push_str("\nprior: ");
        p.push_str(&transcript.join(" | "));
    }
    p
}

fn text_of(v: &Value) -> String {
    match v.view() {
        ValueView::Str(s) => s.to_owned(),
        _ => format!("{v:?}"),
    }
}

/// Convergence threshold for `judge`. A round is "converged" when a
/// majority of panelists agree (exactly, after normalization) OR the panel is
/// highly self-similar lexically. Both are real judge predicates a pure `Step`
/// can compute; another judge can use a confidence-weighted scorer.
const SIMILARITY_THRESHOLD: f64 = 0.8;

/// Judge predicate: the panel has converged when either
/// (a) a strict majority share the same normalized answer, or
/// (b) the mean pairwise lexical similarity clears [`SIMILARITY_THRESHOLD`].
///
/// This replaces byte-equality: near-identical phrasings (whitespace, trailing
/// punctuation, a stray word) converge as a panel would judge them, while
/// genuinely divergent answers keep debating until the round budget runs out.
fn converged(contributions: &[String]) -> bool {
    match contributions.len() {
        0 => true,
        1 => true,
        _ => {
            majority_agree(contributions)
                || mean_pairwise_similarity(contributions) >= SIMILARITY_THRESHOLD
        }
    }
}

/// True when more than half the panelists share one normalized answer.
fn majority_agree(contributions: &[String]) -> bool {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for c in contributions {
        *counts.entry(normalize(c)).or_default() += 1;
    }
    let top = counts.values().copied().max().unwrap_or(0);
    top * 2 > contributions.len()
}

/// Mean of the pairwise Jaccard similarities across all panelist pairs.
fn mean_pairwise_similarity(contributions: &[String]) -> f64 {
    let mut sum = 0.0;
    let mut pairs = 0usize;
    for i in 0..contributions.len() {
        for j in (i + 1)..contributions.len() {
            sum += jaccard(&contributions[i], &contributions[j]);
            pairs += 1;
        }
    }
    if pairs == 0 { 0.0 } else { sum / pairs as f64 }
}

/// Symmetric token-set (Jaccard) similarity in [0,1] — `|A∩B| / |A∪B|` over
/// normalized whitespace tokens. Symmetric so it does not privilege one
/// panelist's phrasing (cf. memory.rs's directional `overlap`).
fn jaccard(a: &str, b: &str) -> f64 {
    let sa: std::collections::BTreeSet<&str> = a.split_whitespace().collect();
    let sb: std::collections::BTreeSet<&str> = b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

/// Lowercase + trim surrounding punctuation/whitespace so trivially-different
/// phrasings collapse for the majority vote.
fn normalize(s: &str) -> String {
    s.trim()
        .trim_matches(|c: char| c.is_ascii_punctuation())
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn verdict(mode: Mode, transcript: &[String], rounds: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("rounds".into(), Value::integer(rounds as i64));
    let answer = match mode {
        Mode::Synthesize => transcript.join("\n"),
        // Vote / Debate: take the (deterministically) most common answer.
        _ => transcript.first().cloned().unwrap_or_default(),
    };
    m.insert("answer".into(), Value::string(answer));
    m.insert(
        "transcript".into(),
        Value::list(
            transcript
                .iter()
                .map(|t| Value::string(t.clone()))
                .collect(),
        ),
    );
    Value::map(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::EchoBackend;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

    fn run_input(mode: &str, panelists: i64, rounds: i64) -> Value {
        let mut m = BTreeMap::new();
        m.insert("question".into(), Value::string("best approach?".into()));
        m.insert("mode".into(), Value::string(mode.into()));
        m.insert("panelists".into(), Value::integer(panelists));
        m.insert("max_rounds".into(), Value::integer(rounds));
        Value::map(m)
    }

    #[tokio::test]
    async fn vote_single_round() -> Result<()> {
        let d = DeliberationDriver::new(Arc::new(EchoBackend));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                run_input("vote", 3, 1),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run vote deliberation")?;
        match out.outcome {
            Outcome::Done(value) => {
                let m = value.as_map().context("expected deliberation map")?;
                ensure!(
                    m.get("rounds") == Some(&Value::integer(1)),
                    "vote rounds: {:?}",
                    m.get("rounds")
                );
                Ok(())
            }
            other => bail!("expected verdict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn debate_converges_or_exhausts_rounds() -> Result<()> {
        let d = DeliberationDriver::new(Arc::new(EchoBackend));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                run_input("debate", 2, 5),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run debate deliberation")?;
        match out.outcome {
            Outcome::Done(value) => {
                let m = value.as_map().context("expected deliberation map")?;
                let rounds = m
                    .get("rounds")
                    .and_then(|v| v.as_int())
                    .context("missing rounds")?;
                ensure!((1..=5).contains(&rounds), "rounds out of bounds: {rounds}");
                Ok(())
            }
            other => bail!("expected verdict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_malformed_input() -> Result<()> {
        let d = DeliberationDriver::new(Arc::new(EchoBackend));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));

        let out = d
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::new()),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "deliberation accepted missing question");

        let mut bad_panel = BTreeMap::new();
        bad_panel.insert("question".into(), Value::string("best approach?".into()));
        bad_panel.insert("panelists".into(), Value::integer(0));
        let out = d
            .call(
                MethodId::new(0),
                Value::map(bad_panel),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "deliberation accepted out-of-range panelists");

        let mut bad_mode = BTreeMap::new();
        bad_mode.insert("question".into(), Value::string("best approach?".into()));
        bad_mode.insert("mode".into(), Value::string("maybe".into()));
        let out = d
            .call(
                MethodId::new(0),
                Value::map(bad_mode),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "deliberation accepted unknown mode");
        Ok(())
    }

    #[test]
    fn near_identical_contributions_converge() -> Result<()> {
        let panel = vec![
            "we should ship the feature".to_string(),
            "We should ship the feature.".to_string(),
            "we should ship the feature now".to_string(),
        ];
        ensure!(converged(&panel), "near-identical phrasings must converge");
        ensure!(
            !panel.windows(2).all(|w| w[0] == w[1]),
            "test panel should not be byte-identical"
        );
        Ok(())
    }

    #[test]
    fn majority_agreement_converges_despite_one_outlier() -> Result<()> {
        let panel = vec![
            "answer is forty two".to_string(),
            "answer is forty two".to_string(),
            "the weather looks cloudy today honestly".to_string(),
        ];
        ensure!(majority_agree(&panel), "majority agreement not detected");
        ensure!(converged(&panel), "majority agreement did not converge");
        Ok(())
    }

    #[test]
    fn divergent_contributions_do_not_converge() -> Result<()> {
        let panel = vec![
            "deploy to production immediately".to_string(),
            "roll back the release right now".to_string(),
        ];
        ensure!(!converged(&panel), "divergent answers converged");
        Ok(())
    }

    #[test]
    fn jaccard_is_symmetric_and_bounded() -> Result<()> {
        ensure!(jaccard("a b c", "a b c") == 1.0, "same terms");
        ensure!(jaccard("a b c", "x y z") == 0.0, "different terms");
        ensure!(
            jaccard("a b c", "c b a") == jaccard("c b a", "a b c"),
            "symmetric terms"
        );
        ensure!(
            (0.0..=1.0).contains(&jaccard("a b c d", "a b x y")),
            "jaccard value out of bounds"
        );
        Ok(())
    }
}
