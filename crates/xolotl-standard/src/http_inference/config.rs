use super::request;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use xolotl_types::InferenceApiDialect;

/// HTTP inference provider API shape.
pub(crate) type HttpInferenceDialect = InferenceApiDialect;

/// Runtime authentication material resolved before constructing a backend.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum HttpInferenceAuth {
    /// No authentication header.
    None,
    /// `Authorization: Bearer <token>`.
    BearerToken(String),
    /// A single API key header.
    ApiKeyHeader {
        /// Header name, such as `x-api-key`.
        header: String,
        /// Header value.
        value: String,
    },
}

impl fmt::Debug for HttpInferenceAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::BearerToken(_) => f.write_str("BearerToken(<redacted>)"),
            Self::ApiKeyHeader { header, .. } => f
                .debug_struct("ApiKeyHeader")
                .field("header", header)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl HttpInferenceAuth {
    /// Build a bearer token auth value from already-resolved secret material.
    pub(crate) fn bearer_token(token: impl Into<String>) -> Self {
        Self::BearerToken(token.into())
    }

    /// Build an API key header auth value from already-resolved secret material.
    pub(crate) fn api_key_header(header: impl Into<String>, value: impl Into<String>) -> Self {
        Self::ApiKeyHeader {
            header: header.into(),
            value: value.into(),
        }
    }
}

/// Optional HTTP inference provider request settings.
#[derive(Clone, Debug, Default)]
pub(crate) struct HttpInferenceOptions {
    /// Extra headers that are not authentication headers.
    pub(crate) default_headers: BTreeMap<String, String>,
    /// Provider-specific non-secret request fields.
    pub(crate) request_overrides: xolotl_types::ValueMap,
    /// Optional API version interpreted by the selected dialect.
    pub(crate) api_version: Option<String>,
    /// Maximum output tokens for APIs that require or accept it.
    pub(crate) max_output_tokens: Option<u64>,
    /// Sampling temperature.
    pub(crate) temperature: Option<f64>,
    /// Whether JSON output is enabled for requests that ask for JSON.
    pub(crate) json_mode: bool,
}

/// Configuration for one HTTP inference provider endpoint.
#[derive(Clone)]
pub(crate) struct HttpInferenceConfig {
    /// Stable backend id used in router model ids.
    pub(crate) id: String,
    /// HTTP API dialect.
    pub(crate) dialect: HttpInferenceDialect,
    /// Base URL. Include `/v1` when the provider expects it in the base.
    pub(crate) base_url: String,
    /// Provider model id passed to the API.
    pub(crate) model: String,
    /// Optional model id used for embeddings.
    pub(crate) embedding_model: Option<String>,
    /// Embedding space written into embedding results.
    pub(crate) embedding_space_id: Option<String>,
    /// Runtime auth material.
    pub(crate) auth: HttpInferenceAuth,
    /// Declared model capabilities.
    pub(crate) capabilities: crate::inference::ModelCapabilities,
    /// Request settings.
    pub(crate) options: HttpInferenceOptions,
    /// Window of encoded request bytes and cooperative JSON parsing work.
    pub(crate) io_window_bytes: core::num::NonZeroUsize,
    /// Explicit retention policy for selected unary results and atomic SSE records.
    pub(crate) response_limits: super::json::project::Limits,
}

impl fmt::Debug for HttpInferenceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpInferenceConfig")
            .field("id", &self.id)
            .field("dialect", &self.dialect)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("embedding_model", &self.embedding_model)
            .field("embedding_space_id", &self.embedding_space_id)
            .field("auth", &self.auth)
            .field("capabilities", &self.capabilities)
            .field("options", &self.options)
            .field("io_window_bytes", &self.io_window_bytes)
            .field("response_limits", &self.response_limits)
            .finish()
    }
}

impl HttpInferenceConfig {
    /// Create a text inference config with dialect defaults.
    pub(crate) fn new(
        id: impl Into<String>,
        dialect: HttpInferenceDialect,
        base_url: impl Into<String>,
        model: impl Into<String>,
        auth: HttpInferenceAuth,
    ) -> Self {
        Self {
            id: id.into(),
            dialect,
            base_url: base_url.into(),
            model: model.into(),
            embedding_model: None,
            embedding_space_id: None,
            auth,
            capabilities: request::default_capabilities(dialect),
            options: HttpInferenceOptions::default(),
            io_window_bytes: core::num::NonZeroUsize::MIN.saturating_add(16 * 1024 - 1),
            response_limits: super::json::project::Limits::default(),
        }
    }

    /// Return the embedding space id for `embedding_model`.
    pub(crate) fn embedding_space_id<'a>(&'a self, embedding_model: &str) -> Cow<'a, str> {
        self.embedding_space_id
            .as_deref()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| {
                Cow::Owned(format!("http-inference/{}/{}", self.id, embedding_model))
            })
    }

    /// Enable OpenAI-style or Gemini embedding for this backend.
    #[cfg(test)]
    pub(crate) fn with_embedding_model(mut self, model: impl Into<String>) -> Self {
        self.embedding_model = Some(model.into());
        self.capabilities.methods.embed = true;
        self
    }
}
