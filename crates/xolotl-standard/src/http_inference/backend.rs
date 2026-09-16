use super::config::{HttpInferenceConfig, HttpInferenceDialect};
use super::dialects::{
    parse_anthropic_text, parse_gemini_embedding, parse_gemini_text, parse_openai_chat_text,
    parse_openai_embedding, parse_openai_responses_text,
};
use super::error::HttpInferenceError;
use super::request::validate_config;
use super::transport::{ResponseKind, decode_json};
use crate::inference::{InferenceBackend, InferenceStream};
use async_trait::async_trait;
use xolotl_types::Value;

/// HTTP-backed inference backend.
pub(crate) struct HttpInferenceBackend {
    pub(super) config: HttpInferenceConfig,
    pub(super) client: reqwest::Client,
}

impl HttpInferenceBackend {
    /// Build a backend using a default HTTP client.
    pub(crate) fn new(config: HttpInferenceConfig) -> Result<Self, HttpInferenceError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Self::with_client(config, client)
    }

    /// Build a backend with an injected HTTP client.
    pub(crate) fn with_client(
        config: HttpInferenceConfig,
        client: reqwest::Client,
    ) -> Result<Self, HttpInferenceError> {
        validate_config(&config)?;
        Ok(Self { config, client })
    }

    pub(super) async fn infer_inner(&self, input: &Value) -> Result<String, HttpInferenceError> {
        let response = decode_json(
            self.generate(input, ResponseKind::Json).await?,
            super::dialects::projection::generation(self.config.dialect),
            self.config.response_limits,
            self.config.io_window_bytes,
        )
        .await?;
        match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses => parse_openai_responses_text(response),
            HttpInferenceDialect::OpenAiChatCompletions => parse_openai_chat_text(response),
            HttpInferenceDialect::AnthropicMessages => parse_anthropic_text(response),
            HttpInferenceDialect::GeminiGenerateContent => parse_gemini_text(response),
        }
    }

    async fn embed_inner(&self, input: &Value) -> Result<Value, HttpInferenceError> {
        let model = self
            .config
            .embedding_model
            .as_deref()
            .ok_or(HttpInferenceError::EmbedUnsupported)?;
        let response = self.embedding(model, input).await?;
        let space_id = self.config.embedding_space_id(model);
        match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses | HttpInferenceDialect::OpenAiChatCompletions => {
                parse_openai_embedding(response, space_id.as_ref(), model)
            }
            HttpInferenceDialect::GeminiGenerateContent => {
                parse_gemini_embedding(response, space_id.as_ref(), model)
            }
            HttpInferenceDialect::AnthropicMessages => Err(HttpInferenceError::EmbedUnsupported),
        }
    }
}

#[async_trait]
impl InferenceBackend for HttpInferenceBackend {
    fn requires_unprotected_input(&self) -> bool {
        true
    }

    async fn infer(&self, input: &Value) -> Result<Value, String> {
        self.infer_inner(input)
            .await
            .map(Value::string)
            .map_err(|e| e.to_string())
    }

    async fn infer_stream(
        &self,
        input: &Value,
        stream: &InferenceStream<'_>,
    ) -> Result<xolotl_kernel::DriverOutput, String> {
        self.stream_text(input, stream)
            .await
            .map_err(|error| error.to_string())
    }

    async fn plan_stream(
        &self,
        input: &Value,
        stream: &InferenceStream<'_>,
    ) -> Result<xolotl_kernel::DriverOutput, String> {
        self.infer_stream(input, stream).await
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        self.embed_inner(input).await.map_err(|e| e.to_string())
    }

    fn capabilities(&self) -> crate::inference::ModelCapabilities {
        self.config.capabilities
    }
}
