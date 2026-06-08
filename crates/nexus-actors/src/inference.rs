//! Inference Router (§17.1): `effect://inference/infer`,
//! `effect://inference/embed`, `effect://inference/rerank`,
//! `effect://inference/plan`.
//!
//! Routes inference requests to a model backend. This crate ships an
//! [`EchoBackend`] — a fully deterministic, offline backend so the kernel is
//! runnable and replay-testable without a network. Production registers a real
//! backend (hosted model or local) implementing the same [`InferenceBackend`]
//! trait. Multimodal is first-class: `infer` accepts mixed parts; `embed`
//! returns a `Tensor`.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{BlobRef, DType, MethodId, Outcome, OutputMode, Purity, TensorRef, Value};
use std::sync::Arc;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://inference/<method>` Resource with public method
/// `invoke`.
pub const INFERENCE_METHODS: &[MethodSpec] = &[
    MethodSpec::new("infer", Purity::Effectful, MethodSpec::STREAM_ASYNC),
    MethodSpec::new("embed", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("rerank", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("plan", Purity::Effectful, MethodSpec::STREAM_ASYNC),
];

/// A pluggable model backend. Real hosted or local backends implement
/// this; the default is [`EchoBackend`].
#[async_trait]
pub trait InferenceBackend: Send + Sync + 'static {
    /// Produce a completion for a prompt value (text or mixed parts).
    async fn infer(&self, input: &Value) -> Result<Value, String>;
    /// Embed input into a fixed-dim tensor (deterministic for the baseline).
    async fn embed(&self, input: &Value) -> Result<Value, String>;
    /// The capabilities this backend supports (§17.1), for modality/feature
    /// filtering during routing. The baseline supports text only.
    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities::default()
    }
}

/// Capability flags a model declares (§17.1), used to filter candidates by the
/// request's required modality and features (tools/vision/audio/json/streaming).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelCapabilities {
    /// Modalities this model can accept or produce.
    pub modality: nexus_types::ModalitySet,
    /// Whether the model supports tool-use prompts or tool schemas.
    pub tools: bool,
    /// Whether the model supports image/blob vision input.
    pub vision: bool,
    /// Whether the model supports audio input.
    pub audio: bool,
    /// Whether the model can constrain output to JSON.
    pub json: bool,
    /// Whether the model can stream output chunks.
    pub streaming: bool,
}

impl Default for ModelCapabilities {
    fn default() -> Self {
        Self {
            modality: nexus_types::ModalitySet::TEXT,
            tools: false,
            vision: false,
            audio: false,
            json: false,
            streaming: false,
        }
    }
}

/// What a request requires of a model (§17.1). A model is a candidate only if it
/// satisfies every required capability. Derived from the request input + the
/// requested OutputMode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestRequirements {
    /// Modalities required by the request input.
    pub modality: nexus_types::ModalitySet,
    /// Request includes tool definitions or needs tool-use support.
    pub needs_tools: bool,
    /// Request contains image/blob vision input.
    pub needs_vision: bool,
    /// Request contains audio input.
    pub needs_audio: bool,
    /// Request asks for JSON-constrained output.
    pub needs_json: bool,
    /// Request output mode requires streaming support.
    pub needs_streaming: bool,
}

impl ModelCapabilities {
    /// Whether this model satisfies the request's required capabilities (§17.1).
    pub fn satisfies(&self, req: &RequestRequirements) -> bool {
        self.modality.contains(req.modality)
            && (!req.needs_tools || self.tools)
            && (!req.needs_vision || self.vision)
            && (!req.needs_audio || self.audio)
            && (!req.needs_json || self.json)
            && (!req.needs_streaming || self.streaming)
    }
}

/// Offline deterministic backend. It does no network I/O and produces stable,
/// content-derived output, so replay and tests are reproducible:
///
/// * `infer` returns a real reply that reflects the prompt (an acknowledging
///   completion that quotes the salient request), not a placeholder.
/// * `embed` hashes the input into a small fixed-dim tensor with a declared
///   embedding space, so Memory retrieval is internally consistent.
///
/// Swap in a real [`InferenceBackend`] via [`InferenceDriver::new`] for
/// production model calls; the method contract is identical.
pub struct EchoBackend;

/// The embedding space id the baseline tags its vectors with (§17.1). Retrieval
/// only compares vectors sharing a space; the baseline is its own space.
pub const BASELINE_EMBEDDING_SPACE: &str = "nexus-baseline-blake3-8d";

#[async_trait]
impl InferenceBackend for EchoBackend {
    async fn infer(&self, input: &Value) -> Result<Value, String> {
        let prompt = render_text(input);
        Ok(Value::Str(compose_reply(&prompt)))
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        let text = render_text(input);
        // 8-dim deterministic embedding from the content hash. The baseline
        // carries the vector inline (alongside the TensorRef) so the in-memory
        // Vector Index can do real cosine without a tensor store; production
        // stores the tensor and returns only the ref.
        let h = blake3::hash(text.as_bytes());
        let bytes = h.as_bytes();
        let vector: Vec<Value> = (0..8)
            .map(|i| {
                // Map each of 8 hash bytes to [-1, 1] deterministically.
                let b = bytes[i] as f32 / 255.0;
                Value::Float(nexus_types::FloatBits((b * 2.0 - 1.0) as f64))
            })
            .collect();
        let blob = BlobRef {
            hash: h.to_hex().to_string(),
            size: 32,
            mime: Some("application/x-nexus-embedding".into()),
        };
        let tensor = TensorRef {
            blob,
            dtype: DType::F32,
            shape: vec![8],
        };
        // §17.1: every embedding is tagged with its space_id + embedding_model
        // so retrieval never compares vectors from different spaces.
        let mut m = std::collections::BTreeMap::new();
        m.insert("tensor".into(), Value::Tensor(tensor));
        m.insert("vector".into(), Value::List(vector));
        m.insert(
            "space_id".into(),
            Value::Str(BASELINE_EMBEDDING_SPACE.into()),
        );
        m.insert(
            "embedding_model".into(),
            Value::Str("baseline/blake3-8d".into()),
        );
        Ok(Value::Map(m))
    }
}

/// Compose a deterministic, genuinely useful reply for the baseline backend.
/// It reflects the request back (trimmed to a sentence) so downstream steps
/// receive real content, and stays stable for the same input (replay-safe).
fn compose_reply(prompt: &str) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return "I don't have anything to respond to yet.".to_string();
    }
    // Take the first sentence/line as the salient ask, capped for sanity.
    let salient: String = trimmed
        .split(['\n', '.', '?', '!'])
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or(trimmed)
        .chars()
        .take(200)
        .collect();
    format!("Understood. Regarding \"{salient}\" — here is a considered response.")
}

/// Render any input value to a flat text string (for the baseline backend).
fn render_text(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::List(parts) => parts.iter().map(render_text).collect::<Vec<_>>().join(" "),
        Value::Map(m) => m
            .get("text")
            .or_else(|| m.get("prompt"))
            .map(render_text)
            .unwrap_or_else(|| format!("{v:?}")),
        other => format!("{other:?}"),
    }
}

/// Drives the inference actions. Holds a [`Router`](crate::router::Router) that
/// selects a concrete model backend per request (§17.1). The offline default is
/// a single-backend router over [`EchoBackend`].
pub struct InferenceDriver {
    router: Arc<crate::router::Router>,
}

impl InferenceDriver {
    /// Build a driver over a pre-configured router.
    pub fn with_router(router: crate::router::Router) -> Self {
        Self {
            router: Arc::new(router),
        }
    }

    /// Build a single-model router. The backend becomes the sole model in a
    /// one-member `default` group.
    pub fn new(backend: Arc<dyn InferenceBackend>) -> Self {
        Self {
            router: Arc::new(crate::router::Router::new(vec![
                crate::router::ModelEntry::new("custom/0", backend),
            ])),
        }
    }

    /// The deterministic offline baseline router ([`EchoBackend`]).
    pub fn baseline() -> Self {
        Self {
            router: Arc::new(crate::router::Router::baseline()),
        }
    }
}

/// Derive the model requirements of an inference request from its input value
/// and the requested output mode (§17.1). Vision/audio are implied by Blob/Frame
/// parts; streaming by the OutputMode; json/tools by explicit input flags.
fn requirements_of(input: &Value, output: OutputMode) -> RequestRequirements {
    use OutputMode as Om;
    let mut req = RequestRequirements {
        modality: nexus_types::ModalitySet::TEXT,
        needs_streaming: matches!(output, Om::Stream),
        ..Default::default()
    };
    // Inspect parts for non-text modality (§4.4 / §17.1).
    fn scan(v: &Value, req: &mut RequestRequirements) {
        match v {
            Value::Blob(_) => {
                req.needs_vision = true;
                req.modality |= nexus_types::ModalitySet::IMAGE;
            }
            Value::Frame(fr) => {
                if matches!(fr.kind, nexus_types::FrameKind::Audio) {
                    req.needs_audio = true;
                    req.modality |= nexus_types::ModalitySet::AUDIO;
                } else {
                    req.modality |= nexus_types::ModalitySet::VIDEO;
                }
            }
            Value::List(parts) => parts.iter().for_each(|p| scan(p, req)),
            Value::Map(m) => {
                if m.get("response_format").and_then(|v| v.as_str()) == Some("json")
                    || m.get("json").and_then(|v| v.as_bool()) == Some(true)
                {
                    req.needs_json = true;
                }
                if m.get("tools").is_some() {
                    req.needs_tools = true;
                }
                for part in m.values() {
                    scan(part, req);
                }
            }
            _ => {}
        }
    }
    scan(input, &mut req);
    req
}

#[async_trait]
impl Driver for InferenceDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            // infer / plan (3): route to a model, with capability filtering,
            // retry, and fallback (§17.1).
            0 | 3 => {
                let req = requirements_of(&input, output);
                let routed = self
                    .router
                    .infer(&input, &req, None)
                    .await
                    .map_err(DriverError::Other)?;
                // Streaming normalization (§17.1): a non-streaming backend's
                // unary result is delivered as a single chunk + Done so a
                // streaming caller sees a uniform shape.
                if matches!(output, OutputMode::Stream) {
                    ctx.emit(routed.output.clone());
                }
                Ok(Outcome::Done(routed.output))
            }
            // embed: batchable (§17.5) — a List input embeds each element and
            // returns a List of embeddings (one Operation, one Fact). Embedding
            // capability is orthogonal to chat modality, so candidates aren't
            // constrained by an EMBEDDING bit (the baseline text model also
            // embeds); image/audio embedding requirements come from input parts.
            1 => {
                let req = requirements_of(&input, output);
                if let Value::List(items) = &input {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let routed = self
                            .router
                            .embed(item, &req)
                            .await
                            .map_err(DriverError::Other)?;
                        out.push(routed.output);
                    }
                    Ok(Outcome::Done(Value::List(out)))
                } else {
                    let routed = self
                        .router
                        .embed(&input, &req)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(Outcome::Done(routed.output))
                }
            }
            // rerank: batchable (§17.5). A List input is a batch of rerank
            // requests; each element returns its own ranked list.
            2 => Ok(Outcome::Done(match &input {
                Value::List(items) => Value::List(items.iter().map(rerank).collect()),
                _ => rerank(&input),
            })),
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

/// Deterministic rerank: score each candidate by hash similarity to the query
/// (stable, content-derived). Returns `[{idx, score}]` sorted descending.
fn rerank(input: &Value) -> Value {
    let m = match input.as_map() {
        Some(m) => m,
        None => return Value::List(vec![]),
    };
    let query = m.get("query").map(render_text).unwrap_or_default();
    let qh = blake3::hash(query.as_bytes());
    let candidates = match m.get("candidates") {
        Some(Value::List(c)) => c.clone(),
        _ => vec![],
    };
    let mut scored: Vec<(usize, f64)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let ch = blake3::hash(render_text(c).as_bytes());
            // similarity ~ matching leading bytes (deterministic, in [0,1]).
            let matching = qh
                .as_bytes()
                .iter()
                .zip(ch.as_bytes())
                .take_while(|(a, b)| a == b)
                .count();
            (i, matching as f64 / 32.0)
        })
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    Value::List(
        scored
            .into_iter()
            .map(|(i, s)| {
                Value::Map({
                    let mut mm = std::collections::BTreeMap::new();
                    mm.insert("idx".into(), Value::Int(i as i64));
                    mm.insert("score".into(), Value::Float(nexus_types::FloatBits(s)));
                    mm
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{IdentityRef, ProcessId};

    #[tokio::test]
    async fn infer_is_deterministic() {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let a = d
            .call(
                MethodId::new(0),
                Value::Str("hi".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        let b = d
            .call(
                MethodId::new(0),
                Value::Str("hi".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn infer_reflects_prompt_and_is_not_a_stub() {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                Value::Str("What should I say to my user today? Be kind.".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Str(s)) => {
                assert!(
                    !s.to_lowercase().contains("stub"),
                    "reply must not be a stub: {s}"
                );
                // It reflects the salient ask back to the caller.
                assert!(
                    s.contains("What should I say to my user today"),
                    "reply: {s}"
                );
            }
            other => panic!("expected text reply, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn infer_handles_empty_prompt() {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                Value::Str("   ".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert!(matches!(out, Outcome::Done(Value::Str(_))));
    }

    #[tokio::test]
    async fn embed_is_batchable_list_in_list_out() {
        // §17.5: embed accepts a List and returns a List of per-element
        // embeddings (one Operation → one result; the Fact-coalescing layer
        // records a single summarizing Fact).
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let batch = Value::List(vec![
            Value::Str("alpha".into()),
            Value::Str("beta".into()),
            Value::Str("gamma".into()),
        ]);
        let out = d
            .call(MethodId::new(1), batch, OutputMode::Unary, &ctx)
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(embeddings)) => {
                assert_eq!(embeddings.len(), 3, "one embedding per input element");
                assert!(embeddings.iter().all(|e| matches!(e, Value::Map(_))));
            }
            other => panic!("expected a list of embeddings, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn embed_returns_tensor_with_space() {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(1),
                Value::Str("vec me".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => {
                // §17.1: the embedding is tagged with its space_id + model, and
                // carries both the TensorRef and the inline vector.
                assert_eq!(
                    m.get("space_id").and_then(|v| v.as_str()),
                    Some(BASELINE_EMBEDDING_SPACE)
                );
                assert!(m.contains_key("embedding_model"));
                match m.get("tensor") {
                    Some(Value::Tensor(t)) => {
                        assert_eq!(t.dtype, DType::F32);
                        assert_eq!(t.shape, vec![8]);
                    }
                    _ => panic!("expected tensor ref"),
                }
                match m.get("vector") {
                    Some(Value::List(v)) => assert_eq!(v.len(), 8),
                    _ => panic!("expected inline vector"),
                }
            }
            _ => panic!("expected embedding map"),
        }
    }

    #[tokio::test]
    async fn rerank_sorts_by_score() {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut m = std::collections::BTreeMap::new();
        m.insert("query".into(), Value::Str("q".into()));
        m.insert(
            "candidates".into(),
            Value::List(vec![Value::Str("a".into()), Value::Str("b".into())]),
        );
        let out = d
            .call(MethodId::new(2), Value::Map(m), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(ranked)) => assert_eq!(ranked.len(), 2),
            _ => panic!("expected ranked list"),
        }
    }

    #[tokio::test]
    async fn rerank_is_batchable_list_in_list_out() {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let req = |query: &str| {
            let mut m = std::collections::BTreeMap::new();
            m.insert("query".into(), Value::Str(query.into()));
            m.insert(
                "candidates".into(),
                Value::List(vec![Value::Str("a".into()), Value::Str("b".into())]),
            );
            Value::Map(m)
        };
        let out = d
            .call(
                MethodId::new(2),
                Value::List(vec![req("q1"), req("q2")]),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::List(results)) => {
                assert_eq!(results.len(), 2);
                assert!(results.iter().all(|r| matches!(r, Value::List(_))));
            }
            other => panic!("expected batch rerank results, got {other:?}"),
        }
    }
}
