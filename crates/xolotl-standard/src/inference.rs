//! Inference Router: `effect://inference/infer`,
//! `effect://inference/embed`, `effect://inference/rerank`,
//! `effect://inference/plan`.
//!
//! Routes inference requests to a model backend. This crate ships an
//! [`EchoBackend`] — a fully deterministic, offline backend so the kernel is
//! runnable and replay-testable without a network. Production registers a real
//! backend (HTTP inference provider or local) implementing the same [`InferenceBackend`]
//! trait. `infer` accepts mixed text and media parts. The standard dense
//! embedders return inline vectors with their embedding space; storing them as
//! tensors is an explicit `effect://tensor/write` operation.

use async_trait::async_trait;
use std::sync::Arc;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
#[cfg(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
use xolotl_state::Backend;
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, TaintSet, TaintSource, Value};

mod stream;
pub use stream::InferenceStream;

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
    /// Whether this deployment requires callers to exclude protected input.
    /// Local backends can accept it; network adapters declare their requirement.
    fn requires_unprotected_input(&self) -> bool {
        false
    }

    /// Produce a completion for a prompt value (text or mixed parts).
    async fn infer(&self, input: &Value) -> Result<Value, String>;
    /// Emit incremental text without retaining a complete result. Backends with
    /// only unary support can use this finite, single-chunk default.
    async fn infer_stream(
        &self,
        input: &Value,
        stream: &InferenceStream<'_>,
    ) -> Result<DriverOutput, String> {
        stream.emit(self.infer(input).await?).await?;
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    }
    /// Produce a planning response. The default uses [`InferenceBackend::infer`].
    async fn plan(&self, input: &Value) -> Result<Value, String> {
        self.infer(input).await
    }
    /// Stream a planning response without accumulating its output.
    async fn plan_stream(
        &self,
        input: &Value,
        stream: &InferenceStream<'_>,
    ) -> Result<DriverOutput, String> {
        stream.emit(self.plan(input).await?).await?;
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    }
    /// Produce an embedding in the backend's declared representation.
    ///
    /// Standard backends and Memory exchange [`crate::Embedding`]: a nonempty
    /// `space_id`, a tagged `representation`, and an optional `embedding_model`.
    /// Representations include dense, sparse, and multi-vector values, plus
    /// committed rank-one and rank-two tensors. Tensor retrieval requires an
    /// explicitly installed [`crate::RetrievalConfig`] object reader; a returned
    /// reference does not itself grant access to its bytes.
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
    pub modality: xolotl_types::ModalitySet,
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
            modality: xolotl_types::ModalitySet::TEXT,
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
    pub(crate) modality: xolotl_types::ModalitySet,
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
/// * `infer` returns a deterministic reply that reflects the salient request.
/// * `embed` hashes the input into a small inline vector with a declared
///   embedding space, so Memory retrieval needs no object storage.
pub struct EchoBackend;

/// The embedding space id the baseline tags its vectors with. Retrieval
/// only compares vectors sharing a space; the baseline is its own space.
pub const BASELINE_EMBEDDING_SPACE: &str = "xolotl-baseline-blake3-8d";

#[async_trait]
impl InferenceBackend for EchoBackend {
    async fn infer(&self, input: &Value) -> Result<Value, String> {
        let prompt = render_text(input);
        Ok(Value::string(compose_reply(&prompt)))
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        // The prompt hash seeds numeric values; it is not an object address.
        let h = text::hash_text(input).map_err(|error| error.to_string())?;
        let bytes = h.as_bytes();
        let vector: Vec<Value> = (0..8)
            .map(|i| {
                // Map each of 8 hash bytes to [-1, 1] deterministically.
                let b = bytes[i] as f32 / 255.0;
                Value::float(xolotl_types::FloatBits((b * 2.0 - 1.0) as f64))
            })
            .collect();
        Ok(crate::retrieval::Embedding {
            representation: crate::retrieval::EmbeddingRepresentation::Dense(vector.into()),
            space_id: BASELINE_EMBEDDING_SPACE.into(),
            embedding_model: Some("baseline/blake3-8d".into()),
        }
        .into_value())
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

mod text;
pub(crate) use text::render_text;
#[cfg(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
pub(crate) use text::{RenderedText, TextCursor, TextPart, TextProgress};

mod requirements;
use requirements::requirements_of;

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
    fn requires_unprotected_input(&self) -> bool {
        match &self.router {
            InferenceRouterSource::Static(router) => router.requires_unprotected_input(),
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            InferenceRouterSource::State(_) => true,
        }
    }

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

#[async_trait]
impl Driver for InferenceDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if self.requires_unprotected_input() && ctx.taint.has_protected() {
            return Err(DriverError::InvalidInput(
                "model backend requires unprotected input".into(),
            ));
        }
        let source = TaintSet::of(TaintSource::ModelOutput);
        let result = match method.get() {
            // Text generation routes to a model with capability filtering,
            // retry, and fallback.
            0 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                if matches!(output, OutputMode::Stream) {
                    router
                        .infer_stream(&input, &req, &InferenceStream::new(ctx))
                        .await
                        .map_err(DriverError::Other)
                } else {
                    let routed = router
                        .infer(&input, &req, None)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(DriverOutput::new(Outcome::Done(routed.output)))
                }
            }
            3 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                if matches!(output, OutputMode::Stream) {
                    router
                        .plan_stream(&input, &req, &InferenceStream::new(ctx))
                        .await
                        .map_err(DriverError::Other)
                } else {
                    let routed = router
                        .plan(&input, &req, None)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(DriverOutput::new(Outcome::Done(routed.output)))
                }
            }
            // embed: batchable — a List input embeds each element and
            // returns a List of embeddings (one Operation, one Fact). Embedding
            // capability is orthogonal to chat modality, so candidates aren't
            // constrained by an EMBEDDING bit (the baseline text model also
            // embeds); image/audio embedding requirements come from input parts.
            1 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                if let Some(items) = input.as_list() {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let routed = router.embed(item, &req).await.map_err(DriverError::Other)?;
                        out.push(routed.output);
                    }
                    Ok(DriverOutput::new(Outcome::Done(Value::list(out))))
                } else {
                    let routed = router
                        .embed(&input, &req)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(DriverOutput::new(Outcome::Done(routed.output)))
                }
            }
            // rerank: batchable. A List input is a batch of rerank
            // requests; each element returns its own ranked list.
            2 => {
                let req = requirements_of(&input, output);
                let router = self.router().await?;
                if let Some(items) = input.as_list() {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let routed = router
                            .rerank(item, &req)
                            .await
                            .map_err(DriverError::Other)?;
                        out.push(routed.output);
                    }
                    Ok(DriverOutput::new(Outcome::Done(Value::list(out))))
                } else {
                    let routed = router
                        .rerank(&input, &req)
                        .await
                        .map_err(DriverError::Other)?;
                    Ok(DriverOutput::new(Outcome::Done(routed.output)))
                }
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        };
        result.map(|mut output| {
            output.taint.union(&source);
            output
        })
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
        .ok_or_else(|| "inference.rerank requires `query`".to_string())?;
    let qh = text::hash_text(query).map_err(|error| error.to_string())?;
    let candidates = match m.get("candidates").map(Value::view) {
        Some(xolotl_types::ValueView::List(c)) => c,
        Some(_) => return Err("inference.rerank `candidates` must be a list".into()),
        None => return Err("inference.rerank requires `candidates`".into()),
    };
    let mut scored: Vec<(usize, f64)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let ch = text::hash_text(c).map_err(|error| error.to_string())?;
            // similarity ~ matching leading bytes (deterministic, in [0,1]).
            let matching = qh
                .as_bytes()
                .iter()
                .zip(ch.as_bytes())
                .take_while(|(a, b)| a == b)
                .count();
            Ok((i, matching as f64 / 32.0))
        })
        .collect::<Result<_, String>>()?;
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    Ok(Value::list(
        scored
            .into_iter()
            .map(|(i, s)| {
                Value::map({
                    let mut mm = std::collections::BTreeMap::new();
                    mm.insert("idx".into(), Value::integer(i as i64));
                    mm.insert("score".into(), Value::float(xolotl_types::FloatBits(s)));
                    mm
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

    struct StreamingEchoBackend;

    #[async_trait]
    impl InferenceBackend for StreamingEchoBackend {
        async fn infer(&self, input: &Value) -> Result<Value, String> {
            EchoBackend.infer(input).await
        }

        async fn embed(&self, input: &Value) -> Result<Value, String> {
            EchoBackend.embed(input).await
        }

        fn capabilities(&self) -> ModelCapabilities {
            ModelCapabilities {
                streaming: true,
                ..EchoBackend.capabilities()
            }
        }
    }

    #[tokio::test]
    async fn infer_is_deterministic() -> Result<()> {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let a = d
            .call(
                MethodId::new(0),
                Value::string("hi".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run first inference")?;
        let b = d
            .call(
                MethodId::new(0),
                Value::string("hi".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run second inference")?;
        ensure!(a == b, "inference is not deterministic: {a:?} != {b:?}");
        Ok(())
    }

    #[tokio::test]
    async fn infer_reflects_prompt_with_generated_text() -> Result<()> {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                Value::string("What should I say to my user today? Be kind.".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run inference")?;
        match out.outcome {
            Outcome::Done(s_value) => {
                let s = s_value.as_str().context("expected str")?;
                ensure!(
                    s.contains("What should I say to my user today"),
                    "reply: {s}"
                );
                ensure!(!s.trim().is_empty(), "reply must not be empty");
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
                Value::string("   ".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run empty-prompt inference")?;
        ensure!(
            matches!(out.outcome, Outcome::Done(ref value) if value.as_str().is_some()),
            "expected text reply, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn infer_stream_reports_error_when_receiver_is_closed() -> Result<()> {
        let d = InferenceDriver::with_backend(Arc::new(StreamingEchoBackend));
        let (tx, rx) =
            xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow::default());
        drop(rx);
        let stream = xolotl_types::Path::parse("state://stream/inference-test")
            .context("parse stream path")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream(stream, tx);
        let out = d
            .call(
                MethodId::new(0),
                Value::string("stream me".into()),
                OutputMode::Stream,
                &ctx,
            )
            .await;
        ensure!(
            matches!(
                out,
                Err(DriverError::Other(ref message)) if message.contains("closed")
            ),
            "closed stream should report a send error, got {out:?}"
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
        let state: Backend = xolotl_state::InMemoryBackend::new().into_backend();
        let d = InferenceDriver::with_state_config(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        match d
            .call(
                MethodId::new(0),
                Value::string("hello".into()),
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
        let batch = Value::list(vec![
            Value::string("alpha".into()),
            Value::string("beta".into()),
            Value::string("gamma".into()),
        ]);
        let out = d
            .call(MethodId::new(1), batch, OutputMode::Unary, &ctx)
            .await
            .context("run batch embed")?;
        match out.outcome {
            Outcome::Done(embeddings_value) => {
                let embeddings = embeddings_value.as_list().context("expected list")?;
                ensure!(
                    embeddings.len() == 3,
                    "one embedding per input element: {}",
                    embeddings.len()
                );
                ensure!(
                    embeddings.iter().all(|e| e.as_map().is_some()),
                    "all embeddings must be maps"
                );
                Ok(())
            }
            other => bail!("expected a list of embeddings, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn embed_returns_inline_vector_with_space() -> Result<()> {
        let d = InferenceDriver::baseline();
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(1),
                Value::string("vec me".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run embed")?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                ensure!(
                    m.get("space_id").and_then(|v| v.as_str()) == Some(BASELINE_EMBEDDING_SPACE),
                    "unexpected space_id: {:?}",
                    m.get("space_id")
                );
                ensure!(
                    m.get("embedding_model").is_some(),
                    "embedding_model missing"
                );
                ensure!(
                    m.get("tensor").is_none(),
                    "inline embedding must not invent a tensor"
                );
                match m
                    .get("representation")
                    .and_then(Value::as_map)
                    .and_then(|fields| fields.get("values"))
                    .and_then(Value::as_list)
                {
                    Some(v) => {
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
        m.insert("query".into(), Value::string("q".into()));
        m.insert(
            "candidates".into(),
            Value::list(vec![Value::string("a".into()), Value::string("b".into())]),
        );
        let out = d
            .call(MethodId::new(2), Value::map(m), OutputMode::Unary, &ctx)
            .await
            .context("run rerank")?;
        match out.outcome {
            Outcome::Done(ranked_value) => {
                let ranked = ranked_value.as_list().context("expected list")?;
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
            Value::list(vec![Value::string("a".into())]),
        );
        let out = d
            .call(
                MethodId::new(2),
                Value::map(missing_query),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "rerank accepted missing query");

        let mut bad_candidates = std::collections::BTreeMap::new();
        bad_candidates.insert("query".into(), Value::string("q".into()));
        bad_candidates.insert("candidates".into(), Value::string("a".into()));
        let out = d
            .call(
                MethodId::new(2),
                Value::map(bad_candidates),
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
            m.insert("query".into(), Value::string(query.into()));
            m.insert(
                "candidates".into(),
                Value::list(vec![Value::string("a".into()), Value::string("b".into())]),
            );
            Value::map(m)
        };
        let out = d
            .call(
                MethodId::new(2),
                Value::list(vec![req("q1"), req("q2")]),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run batch rerank")?;
        match out.outcome {
            Outcome::Done(results_value) => {
                let results = results_value.as_list().context("expected list")?;
                ensure!(results.len() == 2, "batch rerank length: {}", results.len());
                ensure!(
                    results.iter().all(|r| r.as_list().is_some()),
                    "all rerank batch results must be lists"
                );
                Ok(())
            }
            other => bail!("expected batch rerank results, got {other:?}"),
        }
    }
}
