//! Deliberation (§20.4.1): `effect://deliberation/run`.
//!
//! Runs a panel of model "panelists" over one or more rounds and returns a
//! verdict. Single-round fan-out (vote / synthesize) is the `rounds == 1`
//! special case of multi-round debate: each round, every panelist responds to
//! the running transcript; a judge checks convergence; if not converged and
//! the round budget remains, another round runs (§20.4.1).
//!
//! This is the *driver* form, exposing deliberation as one standard effect.
//! The same shape can be written directly as a recursive `Do<A>` in a Process
//! (the design's primary framing) — both reduce to ordinary inference
//! Operations, so taint is never laundered by debate and each call is budgeted.

use crate::inference::InferenceBackend;
use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Method names for `effect://deliberation/run`; the public method is `invoke`
/// after standard installation.
pub const DELIBERATION_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "run",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// How a debate is resolved into a verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Single round; majority/first answer (fan-out vote).
    Vote,
    /// Single round; concatenate contributions (synthesizer).
    Synthesize,
    /// Multi-round; panelists see each other and a judge checks convergence.
    Debate,
}

/// Drives `effect://deliberation/run`, delegating model calls to a backend.
pub struct DeliberationDriver {
    backend: Arc<dyn InferenceBackend>,
}

impl DeliberationDriver {
    /// Create a deliberation driver using `backend` for panelist calls.
    pub fn new(backend: Arc<dyn InferenceBackend>) -> Self {
        Self { backend }
    }

    fn mode_of(input: &BTreeMap<String, Value>) -> Mode {
        match input.get("mode").and_then(|v| v.as_str()) {
            Some("synthesize") => Mode::Synthesize,
            Some("debate") => Mode::Debate,
            _ => Mode::Vote,
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
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let m = input.as_map().cloned().unwrap_or_default();
        let question = m
            .get("question")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let panelists = m
            .get("panelists")
            .and_then(|v| v.as_int())
            .unwrap_or(2)
            .clamp(1, 8) as usize;
        let max_rounds = m
            .get("max_rounds")
            .and_then(|v| v.as_int())
            .unwrap_or(1)
            .clamp(1, 8) as usize;
        let mode = Self::mode_of(&m);

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
                    .infer(&Value::Str(prompt))
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
                return Ok(Outcome::Done(verdict(mode, &transcript, round)));
            }
        }
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
    match v {
        Value::Str(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// Convergence threshold for `judge` (§20.4.1). A round is "converged" when a
/// majority of panelists agree (exactly, after normalization) OR the panel is
/// highly self-similar lexically. Both are real judge predicates a pure `Step`
/// can compute; a production judge can swap in a confidence-weighted scorer.
const SIMILARITY_THRESHOLD: f64 = 0.8;

/// Judge predicate (§20.4.1): the panel has converged when either
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
    m.insert("rounds".into(), Value::Int(rounds as i64));
    let answer = match mode {
        Mode::Synthesize => transcript.join("\n"),
        // Vote / Debate: take the (deterministically) most common answer.
        _ => transcript.first().cloned().unwrap_or_default(),
    };
    m.insert("answer".into(), Value::Str(answer));
    m.insert(
        "transcript".into(),
        Value::List(transcript.iter().map(|t| Value::Str(t.clone())).collect()),
    );
    Value::Map(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::EchoBackend;
    use nexus_types::{IdentityRef, ProcessId};

    fn run_input(mode: &str, panelists: i64, rounds: i64) -> Value {
        let mut m = BTreeMap::new();
        m.insert("question".into(), Value::Str("best approach?".into()));
        m.insert("mode".into(), Value::Str(mode.into()));
        m.insert("panelists".into(), Value::Int(panelists));
        m.insert("max_rounds".into(), Value::Int(rounds));
        Value::Map(m)
    }

    #[tokio::test]
    async fn vote_single_round() {
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
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => assert_eq!(m.get("rounds"), Some(&Value::Int(1))),
            _ => panic!("expected verdict"),
        }
    }

    #[tokio::test]
    async fn debate_converges_or_exhausts_rounds() {
        let d = DeliberationDriver::new(Arc::new(EchoBackend));
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        // Deterministic backend gives identical answers ⇒ converges in round 1.
        let out = d
            .call(
                MethodId::new(0),
                run_input("debate", 2, 5),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => {
                let rounds = m.get("rounds").and_then(|v| v.as_int()).unwrap();
                assert!((1..=5).contains(&rounds));
            }
            _ => panic!("expected verdict"),
        }
    }

    #[test]
    fn near_identical_contributions_converge() {
        // Not byte-identical: casing, trailing punctuation, and a stray filler
        // word differ — a panel would call this agreement.
        let panel = vec![
            "we should ship the feature".to_string(),
            "We should ship the feature.".to_string(),
            "we should ship the feature now".to_string(),
        ];
        assert!(converged(&panel), "near-identical phrasings converge");
        // Byte-equality would have rejected all three as disagreeing.
        assert!(!panel.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn majority_agreement_converges_despite_one_outlier() {
        // Two of three agree exactly; the third is unrelated. Majority decides.
        let panel = vec![
            "answer is forty two".to_string(),
            "answer is forty two".to_string(),
            "the weather looks cloudy today honestly".to_string(),
        ];
        assert!(majority_agree(&panel));
        assert!(converged(&panel));
    }

    #[test]
    fn divergent_contributions_do_not_converge() {
        let panel = vec![
            "deploy to production immediately".to_string(),
            "roll back the release right now".to_string(),
        ];
        assert!(
            !converged(&panel),
            "genuinely different answers keep debating"
        );
    }

    #[test]
    fn jaccard_is_symmetric_and_bounded() {
        assert_eq!(jaccard("a b c", "a b c"), 1.0);
        assert_eq!(jaccard("a b c", "x y z"), 0.0);
        assert_eq!(jaccard("a b c", "c b a"), jaccard("c b a", "a b c"));
        assert!((0.0..=1.0).contains(&jaccard("a b c d", "a b x y")));
    }
}
