use super::config::{HttpInferenceConfig, HttpInferenceDialect};
use super::dialects::{
    anthropic_body, gemini_body, gemini_embed_body, openai_chat_body, openai_embedding_body,
    openai_responses_body, parse_anthropic_text, parse_gemini_embedding, parse_gemini_text,
    parse_openai_chat_text, parse_openai_embedding, parse_openai_responses_text, wants_json,
};
use super::error::HttpInferenceError;
use super::request::{
    endpoint_url, headers_for, redact_body, reject_unsupported_input, validate_config,
};
use crate::inference::InferenceBackend;
use async_trait::async_trait;
use nexus_types::Value;
use serde_json::Value as JsonValue;

/// HTTP-backed inference backend.
pub(crate) struct HttpInferenceBackend {
    pub(super) config: HttpInferenceConfig,
    client: reqwest::Client,
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
        reject_unsupported_input(input)?;
        let wants_json = wants_json(input);
        let body = match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses => {
                openai_responses_body(&self.config, input, wants_json)?
            }
            HttpInferenceDialect::OpenAiChatCompletions => {
                openai_chat_body(&self.config, input, wants_json)?
            }
            HttpInferenceDialect::AnthropicMessages => anthropic_body(&self.config, input)?,
            HttpInferenceDialect::GeminiGenerateContent => gemini_body(&self.config, input)?,
        };
        let path = match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses => "responses",
            HttpInferenceDialect::OpenAiChatCompletions => "chat/completions",
            HttpInferenceDialect::AnthropicMessages => "messages",
            HttpInferenceDialect::GeminiGenerateContent => {
                return self.gemini_generate_content(body).await;
            }
        };
        let response = self.post_json(path, body).await?;
        match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses => parse_openai_responses_text(&response),
            HttpInferenceDialect::OpenAiChatCompletions => parse_openai_chat_text(&response),
            HttpInferenceDialect::AnthropicMessages => parse_anthropic_text(&response),
            HttpInferenceDialect::GeminiGenerateContent => parse_gemini_text(&response),
        }
    }

    async fn embed_inner(&self, input: &Value) -> Result<Value, HttpInferenceError> {
        reject_unsupported_input(input)?;
        let model = self
            .config
            .embedding_model
            .as_deref()
            .ok_or(HttpInferenceError::EmbedUnsupported)?;
        match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses | HttpInferenceDialect::OpenAiChatCompletions => {
                let body = openai_embedding_body(model, input);
                let response = self.post_json("embeddings", body).await?;
                let space_id = self.config.embedding_space_id(model);
                parse_openai_embedding(&response, space_id.as_ref(), model)
            }
            HttpInferenceDialect::GeminiGenerateContent => {
                let body = gemini_embed_body(model, input);
                let path = format!("models/{model}:embedContent");
                let response = self.post_json(&path, body).await?;
                let space_id = self.config.embedding_space_id(model);
                parse_gemini_embedding(&response, space_id.as_ref(), model)
            }
            HttpInferenceDialect::AnthropicMessages => Err(HttpInferenceError::EmbedUnsupported),
        }
    }

    async fn gemini_generate_content(&self, body: JsonValue) -> Result<String, HttpInferenceError> {
        let path = format!("models/{}:generateContent", self.config.model);
        let response = self.post_json(&path, body).await?;
        parse_gemini_text(&response)
    }

    async fn post_json(
        &self,
        path: &str,
        body: JsonValue,
    ) -> Result<JsonValue, HttpInferenceError> {
        let url = endpoint_url(&self.config.base_url, path)?;
        let headers = headers_for(&self.config)?;
        let payload = serde_json::to_string(&body).map_err(HttpInferenceError::RequestJson)?;
        let response = self
            .client
            .post(url)
            .headers(headers)
            .header("content-type", "application/json")
            .body(payload)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(HttpInferenceError::ProviderHttpStatus {
                status: status.as_u16(),
                body: redact_body(&text, &self.config),
            });
        }
        serde_json::from_str(&text).map_err(HttpInferenceError::ResponseJson)
    }
}

#[async_trait]
impl InferenceBackend for HttpInferenceBackend {
    async fn infer(&self, input: &Value) -> Result<Value, String> {
        self.infer_inner(input)
            .await
            .map(Value::Str)
            .map_err(|e| e.to_string())
    }

    async fn embed(&self, input: &Value) -> Result<Value, String> {
        self.embed_inner(input).await.map_err(|e| e.to_string())
    }

    fn capabilities(&self) -> crate::inference::ModelCapabilities {
        self.config.capabilities
    }
}
