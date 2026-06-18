//! Inference backend, model, group, and routing configuration declarations.
//!
//! These declarations are stored in Nexus state. They describe HTTP inference
//! providers and routing without storing HTTP clients or plaintext credentials.

use crate::{ModalitySet, Path, Value, is_vault_reserved};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Maximum accepted retry count for one inference route attempt.
pub const MAX_INFERENCE_ROUTING_RETRIES: u32 = 8;

/// HTTP inference provider API shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum InferenceApiDialect {
    /// OpenAI Responses API.
    OpenAiResponses,
    /// OpenAI Chat Completions API.
    OpenAiChatCompletions,
    /// Anthropic Messages API.
    AnthropicMessages,
    /// Gemini GenerateContent API.
    GeminiGenerateContent,
}

/// Authentication reference stored in state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InferenceAuthRef {
    /// No authentication header.
    None,
    /// `Authorization: Bearer <token>`, where the token is read from `token_ref`.
    BearerToken {
        /// Vault path holding the bearer token.
        token_ref: Path,
    },
    /// API key header, where the value is read from `value_ref`.
    ApiKeyHeader {
        /// Header name, such as `x-api-key`.
        header: String,
        /// Vault path holding the header value.
        value_ref: Path,
    },
}

/// Which `effect://inference/*` methods a model can serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceMethodSet {
    /// Supports `effect://inference/infer`.
    pub infer: bool,
    /// Supports `effect://inference/embed`.
    pub embed: bool,
    /// Supports `effect://inference/rerank`.
    pub rerank: bool,
    /// Supports `effect://inference/plan`.
    pub plan: bool,
}

impl Default for InferenceMethodSet {
    fn default() -> Self {
        Self {
            infer: true,
            embed: false,
            rerank: false,
            plan: true,
        }
    }
}

/// Capability declaration used by the inference router.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceModelCapabilities {
    /// Inference methods this model can serve.
    pub methods: InferenceMethodSet,
    /// Modalities this model can accept or produce.
    pub modality: ModalitySet,
    /// Whether this model supports tool schemas authorized by Nexus.
    pub tools: bool,
    /// Whether this model supports image input.
    pub vision: bool,
    /// Whether this model supports audio input.
    pub audio: bool,
    /// Whether this model can constrain output to JSON.
    pub json: bool,
    /// Whether this model can stream output chunks.
    pub streaming: bool,
}

impl Default for InferenceModelCapabilities {
    fn default() -> Self {
        Self {
            methods: InferenceMethodSet::default(),
            modality: ModalitySet::TEXT,
            tools: false,
            vision: false,
            audio: false,
            json: false,
            streaming: false,
        }
    }
}

/// HTTP inference backend declaration stored under
/// `state://kernel/inference/backends/<id>`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceBackendDef {
    /// Backend id used by model declarations.
    pub id: String,
    /// HTTP API dialect.
    pub dialect: InferenceApiDialect,
    /// Base URL for the provider endpoint.
    pub base_url: String,
    /// Authentication reference.
    pub auth: InferenceAuthRef,
    /// Extra non-secret headers.
    #[serde(default)]
    pub default_headers: BTreeMap<String, String>,
    /// Provider-specific non-secret request fields.
    #[serde(default)]
    pub request_overrides: BTreeMap<String, Value>,
    /// Optional API version interpreted by the selected dialect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    /// Optimistic concurrency version.
    #[serde(default)]
    pub version: u64,
}

/// HTTP inference model declaration stored under
/// `state://kernel/inference/models/<id>`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceModelDef {
    /// Model path id referenced by routing groups.
    pub id: String,
    /// Backend id this model uses.
    pub backend_id: String,
    /// Provider model name sent to the HTTP API.
    pub provider_model: String,
    /// Provider embedding model name, if this model serves embed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,
    /// Declared model capabilities.
    #[serde(default)]
    pub capabilities: InferenceModelCapabilities,
    /// Relative routing weight.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Optimistic concurrency version.
    #[serde(default)]
    pub version: u64,
}

/// How a routing group picks among its members.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceGroupPolicy {
    /// Always the first candidate that satisfies the request.
    #[default]
    Priority,
    /// Rotate through candidates evenly.
    RoundRobin,
    /// Prefer the candidate with the lowest observed latency.
    Latency,
    /// Weighted random by each model's weight.
    Weighted,
}

/// Model group declaration stored under
/// `state://kernel/inference/groups/<name>`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceGroupDef {
    /// Group name.
    pub name: String,
    /// Selection policy.
    pub policy: InferenceGroupPolicy,
    /// Model ids in priority order.
    pub models: Vec<String>,
    /// Optional fallback group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
    /// Optimistic concurrency version.
    #[serde(default)]
    pub version: u64,
}

/// Global inference routing declaration stored under
/// `state://kernel/routing/inference`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceRoutingDef {
    /// Default group used when a request does not select one.
    pub default_group: String,
    /// Retry count for retryable backend errors.
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Optimistic concurrency version.
    #[serde(default)]
    pub version: u64,
}

/// Inference config admission failures.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InferenceConfigError {
    /// Required field was empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Id was not safe to use as a state path segment.
    #[error("{field} is not a safe id segment")]
    BadId {
        /// Field name.
        field: &'static str,
    },
    /// Path id and value id differed.
    #[error("{field} {value:?} does not match path id {path:?}")]
    PathIdMismatch {
        /// Field name.
        field: &'static str,
        /// Id from the value.
        value: String,
        /// Id from the state path.
        path: String,
    },
    /// Base URL was invalid.
    #[error("base_url must be http(s) without query or fragment")]
    BadBaseUrl,
    /// Header name or value was rejected.
    #[error("header is not allowed: {0}")]
    BadHeader(String),
    /// Secret reference did not point under `state://vault/`.
    #[error("secret reference must be a concrete state://vault path")]
    BadSecretRef,
    /// Request override attempted to set a reserved field.
    #[error("request field is reserved: {0}")]
    ReservedRequestField(String),
    /// Numeric option was invalid.
    #[error("numeric option is invalid: {0}")]
    InvalidNumber(&'static str),
    /// API version was set for a dialect that does not use it.
    #[error("api_version is not supported by dialect {0:?}")]
    UnsupportedApiVersion(InferenceApiDialect),
}

impl InferenceBackendDef {
    /// Validate this backend declaration against its state path id.
    pub fn validate_admission(&self, path_id: &str) -> Result<(), InferenceConfigError> {
        validate_id("id", &self.id)?;
        ensure_path_id("id", &self.id, path_id)?;
        validate_base_url(&self.base_url)?;
        validate_auth_ref(&self.auth)?;
        validate_headers(&self.default_headers)?;
        validate_overrides(&self.request_overrides)?;
        if self
            .api_version
            .as_deref()
            .is_some_and(|version| version.trim().is_empty())
        {
            return Err(InferenceConfigError::EmptyField {
                field: "api_version",
            });
        }
        if self.api_version.is_some()
            && !matches!(self.dialect, InferenceApiDialect::AnthropicMessages)
        {
            return Err(InferenceConfigError::UnsupportedApiVersion(self.dialect));
        }
        Ok(())
    }
}

impl InferenceModelDef {
    /// Validate this model declaration against its state path id.
    pub fn validate_admission(&self, path_id: &str) -> Result<(), InferenceConfigError> {
        validate_id("id", &self.id)?;
        ensure_path_id("id", &self.id, path_id)?;
        validate_id("backend_id", &self.backend_id)?;
        if self.provider_model.trim().is_empty() {
            return Err(InferenceConfigError::EmptyField {
                field: "provider_model",
            });
        }
        if self
            .embedding_model
            .as_deref()
            .is_some_and(|model| model.trim().is_empty())
        {
            return Err(InferenceConfigError::EmptyField {
                field: "embedding_model",
            });
        }
        if self.weight == 0 {
            return Err(InferenceConfigError::InvalidNumber("weight"));
        }
        Ok(())
    }
}

impl InferenceGroupDef {
    /// Validate this group declaration against its state path id.
    pub fn validate_admission(&self, path_id: &str) -> Result<(), InferenceConfigError> {
        validate_id("name", &self.name)?;
        ensure_path_id("name", &self.name, path_id)?;
        if self.models.is_empty() {
            return Err(InferenceConfigError::EmptyField { field: "models" });
        }
        for model in &self.models {
            validate_id("models[]", model)?;
        }
        if let Some(fallback) = &self.fallback {
            validate_id("fallback", fallback)?;
        }
        Ok(())
    }
}

impl InferenceRoutingDef {
    /// Validate this routing declaration.
    pub fn validate_admission(&self) -> Result<(), InferenceConfigError> {
        validate_id("default_group", &self.default_group)?;
        if self
            .max_retries
            .is_some_and(|max_retries| max_retries > MAX_INFERENCE_ROUTING_RETRIES)
        {
            return Err(InferenceConfigError::InvalidNumber("max_retries"));
        }
        Ok(())
    }
}

fn default_weight() -> u32 {
    1
}

fn ensure_path_id(
    field: &'static str,
    value: &str,
    path: &str,
) -> Result<(), InferenceConfigError> {
    if value == path {
        Ok(())
    } else {
        Err(InferenceConfigError::PathIdMismatch {
            field,
            value: value.to_string(),
            path: path.to_string(),
        })
    }
}

fn validate_id(field: &'static str, id: &str) -> Result<(), InferenceConfigError> {
    if id.trim().is_empty() {
        return Err(InferenceConfigError::EmptyField { field });
    }
    if !is_safe_id_segment(id) {
        return Err(InferenceConfigError::BadId { field });
    }
    Ok(())
}

fn is_safe_id_segment(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_base_url(url: &str) -> Result<(), InferenceConfigError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(InferenceConfigError::EmptyField { field: "base_url" });
    }
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://"))
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(InferenceConfigError::BadBaseUrl);
    }
    Ok(())
}

fn validate_auth_ref(auth: &InferenceAuthRef) -> Result<(), InferenceConfigError> {
    match auth {
        InferenceAuthRef::None => Ok(()),
        InferenceAuthRef::BearerToken { token_ref } => validate_secret_ref(token_ref),
        InferenceAuthRef::ApiKeyHeader { header, value_ref } => {
            validate_header_name(header)?;
            let lower = header.to_ascii_lowercase();
            if matches!(lower.as_str(), "authorization" | "content-type") {
                return Err(InferenceConfigError::BadHeader(header.clone()));
            }
            validate_secret_ref(value_ref)
        }
    }
}

fn validate_secret_ref(path: &Path) -> Result<(), InferenceConfigError> {
    if path.scheme() != "state" || !is_vault_reserved(path) || path.segments().len() < 2 {
        return Err(InferenceConfigError::BadSecretRef);
    }
    Ok(())
}

fn validate_headers(headers: &BTreeMap<String, String>) -> Result<(), InferenceConfigError> {
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "authorization"
                | "x-api-key"
                | "api-key"
                | "anthropic-version"
                | "content-type"
                | "content-length"
                | "host"
                | "connection"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
        ) {
            return Err(InferenceConfigError::BadHeader(name.clone()));
        }
        validate_header_name(name)?;
        validate_header_value(name, value)?;
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<(), InferenceConfigError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Err(InferenceConfigError::BadHeader(name.to_string()))
    } else {
        Ok(())
    }
}

fn validate_header_value(name: &str, value: &str) -> Result<(), InferenceConfigError> {
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n')) {
        Err(InferenceConfigError::BadHeader(name.to_string()))
    } else {
        Ok(())
    }
}

fn validate_overrides(overrides: &BTreeMap<String, Value>) -> Result<(), InferenceConfigError> {
    for (key, value) in overrides {
        let lower = key.to_ascii_lowercase();
        if is_reserved_request_field(&lower) {
            return Err(InferenceConfigError::ReservedRequestField(key.to_string()));
        }
        validate_sensitive_override_field(key, value)?;
    }
    Ok(())
}

fn validate_sensitive_override_field(key: &str, value: &Value) -> Result<(), InferenceConfigError> {
    let lower = key.to_ascii_lowercase();
    if is_sensitive_request_field(&lower) || lower.contains("secret") || lower.contains("api_key") {
        return Err(InferenceConfigError::ReservedRequestField(key.to_string()));
    }
    match value {
        Value::Map(map) => {
            for (child, child_value) in map {
                validate_sensitive_override_field(child, child_value)?;
            }
        }
        Value::List(items) => {
            for item in items {
                if let Value::Map(map) = item {
                    for (child, child_value) in map {
                        validate_sensitive_override_field(child, child_value)?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_reserved_request_field(field: &str) -> bool {
    matches!(
        field,
        "model"
            | "input"
            | "messages"
            | "contents"
            | "content"
            | "generationconfig"
            | "generation_config"
            | "text"
            | "response_format"
            | "stream"
            | "store"
            | "max_tokens"
            | "max_output_tokens"
            | "maxoutputtokens"
            | "temperature"
            | "previous_response_id"
            | "conversation"
            | "system"
            | "safetysettings"
            | "safety_settings"
    )
}

fn is_sensitive_request_field(field: &str) -> bool {
    matches!(
        field,
        "authorization"
            | "api_key"
            | "apikey"
            | "key"
            | "tools"
            | "tool_choice"
            | "functions"
            | "function_call"
            | "builtin_tools"
            | "codeexecution"
            | "code_execution"
            | "googlesearch"
            | "google_search"
            | "computer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};

    fn vault(path: &str) -> Result<Path> {
        Path::parse(path).with_context(|| format!("parse {path}"))
    }

    #[test]
    fn backend_requires_vault_secret_ref() -> Result<()> {
        let def = InferenceBackendDef {
            id: "deepseek".into(),
            dialect: InferenceApiDialect::OpenAiChatCompletions,
            base_url: "https://api.deepseek.com".into(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: vault("state://vault/inference/deepseek/api_key")?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: None,
            version: 0,
        };
        ensure!(
            def.validate_admission("deepseek").is_ok(),
            "valid backend rejected"
        );

        let mut bad = def.clone();
        bad.auth = InferenceAuthRef::BearerToken {
            token_ref: vault("state://kernel/inference/deepseek/api_key")?,
        };
        ensure!(
            bad.validate_admission("deepseek") == Err(InferenceConfigError::BadSecretRef),
            "bad secret ref was accepted"
        );
        Ok(())
    }

    #[test]
    fn backend_rejects_secret_overrides() -> Result<()> {
        let mut def = InferenceBackendDef {
            id: "openai".into(),
            dialect: InferenceApiDialect::OpenAiResponses,
            base_url: "https://api.openai.com/v1".into(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: vault("state://vault/inference/openai/api_key")?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: None,
            version: 0,
        };
        def.request_overrides
            .insert("tools".into(), Value::List(vec![]));
        ensure!(
            matches!(
                def.validate_admission("openai"),
                Err(InferenceConfigError::ReservedRequestField(_))
            ),
            "reserved request field was accepted"
        );
        Ok(())
    }

    #[test]
    fn backend_rejects_unknown_fields() -> Result<()> {
        let json = serde_json::json!({
            "id": "anthropic",
            "dialect": "anthropic_messages",
            "base_url": "https://api.anthropic.com/v1",
            "auth": {
                "kind": "api_key_header",
                "header": "x-api-key",
                "value_ref": "state://vault/inference/anthropic/api_key"
            },
            "default_headers": {},
            "request_overrides": {},
            "anthropic_version": "2023-06-01",
            "version": 1
        });

        ensure!(
            serde_json::from_value::<InferenceBackendDef>(json).is_err(),
            "unknown fields were accepted"
        );
        Ok(())
    }

    #[test]
    fn backend_rejects_unused_api_version() -> Result<()> {
        let def = InferenceBackendDef {
            id: "deepseek".into(),
            dialect: InferenceApiDialect::OpenAiChatCompletions,
            base_url: "https://api.deepseek.com".into(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: vault("state://vault/inference/deepseek/api_key")?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: Some("2023-06-01".into()),
            version: 0,
        };

        ensure!(
            def.validate_admission("deepseek")
                == Err(InferenceConfigError::UnsupportedApiVersion(
                    InferenceApiDialect::OpenAiChatCompletions
                )),
            "unused api_version was accepted"
        );
        Ok(())
    }

    #[test]
    fn model_and_group_ids_must_match_paths() -> Result<()> {
        let model = InferenceModelDef {
            id: "chat".into(),
            backend_id: "deepseek".into(),
            provider_model: "deepseek-chat".into(),
            embedding_model: None,
            capabilities: InferenceModelCapabilities::default(),
            weight: 1,
            version: 0,
        };
        ensure!(
            model.validate_admission("chat").is_ok(),
            "valid model rejected"
        );
        ensure!(
            matches!(
                model.validate_admission("other"),
                Err(InferenceConfigError::PathIdMismatch { .. })
            ),
            "model path mismatch was accepted"
        );

        let group = InferenceGroupDef {
            name: "default".into(),
            policy: InferenceGroupPolicy::Priority,
            models: vec!["chat".into()],
            fallback: None,
            version: 0,
        };
        ensure!(
            group.validate_admission("default").is_ok(),
            "valid group rejected"
        );
        Ok(())
    }

    #[test]
    fn routing_rejects_excessive_retries() -> Result<()> {
        let routing = InferenceRoutingDef {
            default_group: "default".into(),
            max_retries: Some(MAX_INFERENCE_ROUTING_RETRIES + 1),
            version: 0,
        };

        ensure!(
            routing.validate_admission() == Err(InferenceConfigError::InvalidNumber("max_retries")),
            "excessive retries were accepted"
        );
        Ok(())
    }
}
