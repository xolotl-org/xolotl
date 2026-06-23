//! Inference Router: `effect://inference/infer`,
//! `effect://inference/embed`, `effect://inference/rerank`,
//! `effect://inference/plan`.
//!
//! Routes inference requests to a model backend. This crate ships an
//! [`EchoBackend`] — a fully deterministic, offline backend so the kernel is
//! runnable and replay-testable without a network. Production registers a real
//! backend (HTTP inference provider or local) implementing the same [`InferenceBackend`]
//! trait. `infer` accepts mixed text and media parts; `embed` returns a
//! `Tensor`.

use andrias_kernel::{Driver, DriverContext, DriverError, MethodSpec};
#[cfg(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
use andrias_state::Backend;
use andrias_types::{BlobRef, DType, MethodId, Outcome, OutputMode, Purity, TensorRef, Value};
use async_trait::async_trait;
use std::sync::Arc;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://inference/<method>` Resource with public method
/// `invoke`.
pub(crate) const INFERENCE_METHODS: &[MethodSpec] = &[
    MethodSpec::new("infer", Purity::Effectful, MethodSpec::STREAM_ASYNC),
    MethodSpec::new("embed", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("rerank", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable(),
    MethodSpec::new("plan", Purity::Effectful, MethodSpec::STREAM_ASYNC),
];

/// A model backend used by the standard inference driver.
#[async_trait]
pub trait InferenceBackend: Send + Sync + 'static {
    /// Produce a completion for a prompt value (text or mixed parts).
    async fn infer(&self, input: &Value) -> Result<Value, String>;
    /// Produce a planning response. The default uses [`InferenceBackend::infer`].
    async fn plan(&self, input: &Value) -> Result<Value, String> {
        self.infer(input).await
    }
    /// Embed input into a fixed-dim tensor (deterministic for the baseline).
    async fn embed(&self, input: &Value) -> Result<Value, String>;
    /// Rerank candidate values for a query.
    async fn rerank(&self, _input: &Value) -> Result<Value, String> {
        Err("backend does not support rerank".into())
    }
    /// The capabilities this backend supports, for modality/feature
    /// filtering during routing. The baseline supports text only.
    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities::default()
    }
}

/// Which `effect://inference/*` methods a model backend can serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferenceMethodSupport {
    /// Supports `effect://inference/infer`.
    pub infer: bool,
    /// Supports `effect://inference/embed`.
    pub embed: bool,
    /// Supports `effect://inference/rerank`.
    pub rerank: bool,
    /// Supports `effect://inference/plan`.
    pub plan: bool,
}

impl Default for InferenceMethodSupport {
    fn default() -> Self {
        Self {
            infer: true,
            embed: true,
            rerank: false,
            plan: true,
        }
    }
}

/// Capability flags a model declares, used to filter candidates by the
/// request's required modality and features (tools/vision/audio/json/streaming).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelCapabilities {
    /// Inference methods this model can serve.
    pub methods: InferenceMethodSupport,
    /// Modalities this model can accept or produce.
    pub modality: andrias_types::ModalitySet,
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
            methods: InferenceMethodSupport::default(),
            modality: andrias_types::ModalitySet::TEXT,
            tools: false,
            vision: false,
            audio: false,
            json: false,
            streaming: false,
        }
    }
}

/// What a request requires of a model. A model is a candidate only if it
/// satisfies every required capability. Derived from the request input + the
/// requested OutputMode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RequestRequirements {
    /// Modalities required by the request input.
    pub(crate) modality: andrias_types::ModalitySet,
    /// Request includes tool definitions or needs tool-use support.
    pub(crate) needs_tools: bool,
    /// Request contains image/blob vision input.
    pub(crate) needs_vision: bool,
    /// Request contains audio input.
    pub(crate) needs_audio: bool,
    /// Request asks for JSON-constrained output.
    pub(crate) needs_json: bool,
    /// Request output mode requires streaming support.
    pub(crate) needs_streaming: bool,
}

impl ModelCapabilities {
    /// Whether this model satisfies the request's required capabilities.
    pub(crate) fn satisfies(&self, req: &RequestRequirements) -> bool {
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
pub struct EchoBackend;

/// The embedding space id the baseline tags its vectors with. Retrieval
/// only compares vectors sharing a space; the baseline is its own space.
pub const BASELINE_EMBEDDING_SPACE: &str = "andrias-baseline-blake3-8d";

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
        // Vector Index can do cosine search without a tensor store. Backends
        // with separate tensor storage can return only the ref.
        let h = blake3::hash(text.as_bytes());
        let bytes = h.as_bytes();
        let vector: Vec<Value> = (0..8)
            .map(|i| {
                // Map each of 8 hash bytes to [-1, 1] deterministically.
                let b = bytes[i] as f32 / 255.0;
                Value::Float(andrias_types::FloatBits((b * 2.0 - 1.0) as f64))
            })
            .collect();
        let blob = BlobRef {
            hash: h.to_hex().to_string(),
            size: 32,
            mime: Some("application/x-andrias-embedding".into()),
        };
        let tensor = TensorRef {
            blob,
            dtype: DType::F32,
            shape: vec![8],
        };
        // Every embedding is tagged with its space_id + embedding_model so
        // retrieval never compares vectors from different spaces.
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

    async fn rerank(&self, input: &Value) -> Result<Value, String> {
        rerank(input)
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            methods: InferenceMethodSupport {
                rerank: true,
                ..Default::default()
            },
            ..Default::default()
        }
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

/// Render any input value to a flat text string.
pub(crate) fn render_text(v: &Value) -> String {
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
/// selects a concrete model backend per request. The offline default is
/// a single-backend router over [`EchoBackend`].
pub(crate) struct InferenceDriver {
    router: InferenceRouterSource,
}

enum InferenceRouterSource {
    Static(Arc<crate::router::Router>),
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    State(Backend),
}

impl InferenceDriver {
    /// Build a driver over a shared pre-configured router.
    #[cfg(test)]
    pub(crate) fn with_router_arc(router: Arc<crate::router::Router>) -> Self {
        Self {
            router: InferenceRouterSource::Static(router),
        }
    }

    /// Build a driver over one host-provided backend.
    pub(crate) fn with_backend(backend: Arc<dyn InferenceBackend>) -> Self {
        Self {
            router: InferenceRouterSource::Static(Arc::new(crate::router::Router::new(vec![
                crate::router::ModelEntry::new("host/custom", backend),
            ]))),
        }
    }

    /// Build a driver that loads inference routing declarations from state.
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn with_state_config(state: Backend) -> Self {
        Self {
            router: InferenceRouterSource::State(state),
        }
    }

    /// The deterministic offline baseline router ([`EchoBackend`]).
    #[cfg(any(
        test,
        not(any(
            feature = "openai-responses",
            feature = "openai-chat",
            feature = "anthropic-messages",
            feature = "gemini-generate-content"
        ))
    ))]
    pub(crate) fn baseline() -> Self {
        Self {
            router: InferenceRouterSource::Static(Arc::new(crate::router::Router::baseline())),
        }
    }

    async fn router(&self) -> Result<Arc<crate::router::Router>, DriverError> {
        match &self.router {
            InferenceRouterSource::Static(router) => Ok(router.clone()),
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            InferenceRouterSource::State(state) => crate::http_inference::router_from_state(state)
                .await
                .and_then(|router| {
                    router.ok_or(crate::http_inference::HttpInferenceError::MissingStateConfig)
                })
                .map_err(|e| DriverError::Other(e.to_string())),
        }
    }
}

#[async_trait]
impl InferenceBackend for InferenceDriver {
    async fn infer(&self, input: &Value) -> Result<Value, String> {
        let router = self.router().await.map_err(|error| error.to_string())?;
        let req = requirements_of(input, OutputMode::Unary);
        router
            .infer(input, &req, None)
            .await
            .map(|routed| routed.output)
    }

    async fn plan(&self, input: &Value) -> Result<Value, String> {
        let router = self.router().await.map_err(|error| error.to_string())?;
        let req = requirements_of(input, OutputMode::Unary);
        router
            .plan(input, &req, None)
            .await
            .map(|routed| routed.output)
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        let router = self.router().await.map_err(|error| error.to_string())?;
        let req = requirements_of(input, OutputMode::Unary);
        router.embed(input, &req).await.map(|routed| routed.output)
    }

    async fn rerank(&self, input: &Value) -> Result<Value, String> {
        let router = self.router().await.map_err(|error| error.to_string())?;
        let req = requirements_of(input, OutputMode::Unary);
        router.rerank(input, &req).await.map(|routed| routed.output)
    }
}

/// Derive the model requirements of an inference request from its input value
/// and the requested output mode. Vision/audio are implied by Blob/Frame
/// parts; streaming by the OutputMode; json/tools by explicit input flags.
fn requirements_of(input: &Value, output: OutputMode) -> RequestRequirements {
    use OutputMode as Om;
    let mut req = RequestRequirements {
        modality: andrias_types::ModalitySet::TEXT,
        needs_streaming: matches!(output, Om::Stream),
        ..Default::default()
    };
    // Inspect parts for non-text modality.
    fn scan(v: &Value, req: &mut RequestRequirements) {
        match v {
            Value::Blob(_) => {
                req.needs_vision = true;
                req.modality |= andrias_types::ModalitySet::IMAGE;
            }
            Value::Frame(fr) => {
                if matches!(fr.kind, andrias_types::FrameKind::Audio) {
                    req.needs_audio = true;
                    req.modality |= andrias_types::ModalitySet::AUDIO;
                } else {
                    req.modality |= andrias_types::ModalitySet::VIDEO;
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
            // Text generation routes to a model with capability filtering,
            // retry, and fallback.
            0 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                let routed = router
                    .infer(&input, &req, None)
                    .await
                    .map_err(DriverError::Other)?;
                // Streaming normalization: a non-streaming backend's
                // unary result is delivered as a single chunk + Done so a
                // streaming caller sees a uniform shape.
                if matches!(output, OutputMode::Stream) {
                    ctx.emit(routed.output.clone());
                }
                Ok(Outcome::Done(routed.output))
            }
            3 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                let routed = router
                    .plan(&input, &req, None)
                    .await
                    .map_err(DriverError::Other)?;
                if matches!(output, OutputMode::Stream) {
                    ctx.emit(routed.output.clone());
                }
                Ok(Outcome::Done(routed.output))
            }
            // embed: batchable — a List input embeds each element and
            // returns a List of embeddings (one Operation, one Fact). Embedding
            // capability is orthogonal to chat modality, so candidates aren't
            // constrained by an EMBEDDING bit (the baseline text model also
            // embeds); image/audio embedding requirements come from input parts.
            1 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                if let Value::List(items) = &input {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let routed = router.embed(item, &req).await.map_err(DriverError::Other)?;
                        out.push(routed.output);
                    }
                    Ok(Outcome::Done(Value::List(out)))
                } else {
                    let routed = router
                        .embed(&input, &req)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(Outcome::Done(routed.output))
                }
            }
            // rerank: batchable. A List input is a batch of rerank
            // requests; each element returns its own ranked list.
            2 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                if let Value::List(items) = &input {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let routed = router
                            .rerank(item, &req)
                            .await
                            .map_err(DriverError::Other)?;
                        out.push(routed.output);
                    }
                    Ok(Outcome::Done(Value::List(out)))
                } else {
                    let routed = router
                        .rerank(&input, &req)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(Outcome::Done(routed.output))
                }
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

/// Deterministic rerank: score each candidate by hash similarity to the query
/// (stable, content-derived). Returns `[{idx, score}]` sorted descending.
fn rerank(input: &Value) -> Result<Value, String> {
    let m = match input.as_map() {
        Some(m) => m,
        None => return Err("inference.rerank input must be a map".into()),
    };
    let query = m
        .get("query")
        .map(render_text)
        .ok_or_else(|| "inference.rerank requires `query`".to_string())?;
    let qh = blake3::hash(query.as_bytes());
    let candidates = match m.get("candidates") {
        Some(Value::List(c)) => c,
        Some(_) => return Err("inference.rerank `candidates` must be a list".into()),
        None => return Err("inference.rerank requires `candidates`".into()),
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
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    Ok(Value::List(
        scored
            .into_iter()
            .map(|(i, s)| {
                Value::Map({
                    let mut mm = std::collections::BTreeMap::new();
                    mm.insert("idx".into(), Value::Int(i as i64));
                    mm.insert("score".into(), Value::Float(andrias_types::FloatBits(s)));
                    mm
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use andrias_types::{IdentityRef, ProcessId};
    use anyhow::{Context, Result, bail, ensure};

    #[tokio::test]
    async fn infer_is_deterministic() -> Result<()> {
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
            .context("run first inference")?;
        let b = d
            .call(
                MethodId::new(0),
                Value::Str("hi".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run second inference")?;
        ensure!(a == b, "inference is not deterministic: {a:?} != {b:?}");
        Ok(())
    }

    #[tokio::test]
    async fn infer_reflects_prompt_and_is_not_a_stub() -> Result<()> {
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
            .context("run inference")?;
        match out {
            Outcome::Done(Value::Str(s)) => {
                ensure!(
                    !s.to_lowercase().contains("stub"),
                    "reply must not be a stub: {s}"
                );
                ensure!(
                    s.contains("What should I say to my user today"),
                    "reply: {s}"
                );
                Ok(())
            }
            other => bail!("expected text reply, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn infer_handles_empty_prompt() -> Result<()> {
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
            .context("run empty-prompt inference")?;
        ensure!(
            matches!(out, Outcome::Done(Value::Str(_))),
            "expected text reply, got {out:?}"
        );
        Ok(())
    }

    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    #[tokio::test]
    async fn state_config_requires_provider_declarations() -> Result<()> {
        let state: Backend = Arc::new(andrias_state::InMemoryBackend::new());
        let d = InferenceDriver::with_state_config(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        match d
            .call(
                MethodId::new(0),
                Value::Str("hello".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
        {
            Err(DriverError::Other(message)) => {
                ensure!(
                    message == "HTTP inference provider state config is not declared",
                    "unexpected error: {message}"
                );
                Ok(())
            }
            other => bail!("expected missing provider config error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn embed_is_batchable_list_in_list_out() -> Result<()> {
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
            .context("run batch embed")?;
        match out {
            Outcome::Done(Value::List(embeddings)) => {
                ensure!(
                    embeddings.len() == 3,
                    "one embedding per input element: {}",
                    embeddings.len()
                );
                ensure!(
                    embeddings.iter().all(|e| matches!(e, Value::Map(_))),
                    "all embeddings must be maps"
                );
                Ok(())
            }
            other => bail!("expected a list of embeddings, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn embed_returns_tensor_with_space() -> Result<()> {
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
            .context("run embed")?;
        match out {
            Outcome::Done(Value::Map(m)) => {
                ensure!(
                    m.get("space_id").and_then(|v| v.as_str()) == Some(BASELINE_EMBEDDING_SPACE),
                    "unexpected space_id: {:?}",
                    m.get("space_id")
                );
                ensure!(m.contains_key("embedding_model"), "embedding_model missing");
                match m.get("tensor") {
                    Some(Value::Tensor(t)) => {
                        ensure!(t.dtype == DType::F32, "tensor dtype: {:?}", t.dtype);
                        ensure!(t.shape == vec![8], "tensor shape: {:?}", t.shape);
                    }
                    other => bail!("expected tensor ref, got {other:?}"),
                }
                match m.get("vector") {
                    Some(Value::List(v)) => {
                        ensure!(v.len() == 8, "inline vector length: {}", v.len());
                    }
                    other => bail!("expected inline vector, got {other:?}"),
                }
                Ok(())
            }
            other => bail!("expected embedding map, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rerank_sorts_by_score() -> Result<()> {
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
            .context("run rerank")?;
        match out {
            Outcome::Done(Value::List(ranked)) => {
                ensure!(ranked.len() == 2, "ranked length: {}", ranked.len());
                Ok(())
            }
            other => bail!("expected ranked list, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rerank_rejects_malformed_input() -> Result<()> {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut missing_query = std::collections::BTreeMap::new();
        missing_query.insert(
            "candidates".into(),
            Value::List(vec![Value::Str("a".into())]),
        );
        let out = d
            .call(
                MethodId::new(2),
                Value::Map(missing_query),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "rerank accepted missing query");

        let mut bad_candidates = std::collections::BTreeMap::new();
        bad_candidates.insert("query".into(), Value::Str("q".into()));
        bad_candidates.insert("candidates".into(), Value::Str("a".into()));
        let out = d
            .call(
                MethodId::new(2),
                Value::Map(bad_candidates),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "rerank accepted malformed candidates");
        Ok(())
    }

    #[tokio::test]
    async fn rerank_is_batchable_list_in_list_out() -> Result<()> {
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
            .context("run batch rerank")?;
        match out {
            Outcome::Done(Value::List(results)) => {
                ensure!(results.len() == 2, "batch rerank length: {}", results.len());
                ensure!(
                    results.iter().all(|r| matches!(r, Value::List(_))),
                    "all rerank batch results must be lists"
                );
                Ok(())
            }
            other => bail!("expected batch rerank results, got {other:?}"),
        }
    }
}
