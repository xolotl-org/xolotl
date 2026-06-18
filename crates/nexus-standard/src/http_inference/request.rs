use super::config::{HttpInferenceAuth, HttpInferenceConfig, HttpInferenceDialect};
use super::error::HttpInferenceError;
use crate::inference::{InferenceMethodSupport, ModelCapabilities};
use nexus_types::Value;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

pub(super) fn default_capabilities(dialect: HttpInferenceDialect) -> ModelCapabilities {
    let mut caps = ModelCapabilities {
        methods: InferenceMethodSupport {
            infer: true,
            embed: false,
            rerank: false,
            plan: true,
        },
        ..Default::default()
    };
    match dialect {
        HttpInferenceDialect::OpenAiResponses | HttpInferenceDialect::GeminiGenerateContent => {
            caps.json = true;
            caps.tools = false;
        }
        HttpInferenceDialect::OpenAiChatCompletions => {
            caps.json = true;
            caps.tools = false;
        }
        HttpInferenceDialect::AnthropicMessages => {
            caps.json = false;
            caps.tools = false;
        }
    }
    caps
}

pub(super) fn validate_config(config: &HttpInferenceConfig) -> Result<(), HttpInferenceError> {
    if config.id.trim().is_empty() {
        return Err(HttpInferenceError::EmptyField { field: "id" });
    }
    if config.base_url.trim().is_empty() {
        return Err(HttpInferenceError::EmptyField { field: "base_url" });
    }
    if config.model.trim().is_empty() {
        return Err(HttpInferenceError::EmptyField { field: "model" });
    }
    endpoint_url(&config.base_url, "")?;
    if let Some(model) = &config.embedding_model
        && model.trim().is_empty()
    {
        return Err(HttpInferenceError::EmptyField {
            field: "embedding_model",
        });
    }
    if config.options.max_output_tokens == Some(0) {
        return Err(HttpInferenceError::InvalidNumber("max_output_tokens"));
    }
    if config
        .options
        .temperature
        .is_some_and(|temperature| !temperature.is_finite())
    {
        return Err(HttpInferenceError::InvalidNumber("temperature"));
    }
    validate_dialect_enabled(config.dialect)?;
    validate_headers(&config.options.default_headers)?;
    validate_auth(&config.auth)?;
    validate_overrides(&config.options.request_overrides)?;
    Ok(())
}

fn validate_dialect_enabled(dialect: HttpInferenceDialect) -> Result<(), HttpInferenceError> {
    match dialect {
        HttpInferenceDialect::OpenAiResponses if !cfg!(feature = "openai-responses") => {
            Err(HttpInferenceError::DialectDisabled("openai-responses"))
        }
        HttpInferenceDialect::OpenAiChatCompletions if !cfg!(feature = "openai-chat") => {
            Err(HttpInferenceError::DialectDisabled("openai-chat"))
        }
        HttpInferenceDialect::AnthropicMessages if !cfg!(feature = "anthropic-messages") => {
            Err(HttpInferenceError::DialectDisabled("anthropic-messages"))
        }
        HttpInferenceDialect::GeminiGenerateContent
            if !cfg!(feature = "gemini-generate-content") =>
        {
            Err(HttpInferenceError::DialectDisabled(
                "gemini-generate-content",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_auth(auth: &HttpInferenceAuth) -> Result<(), HttpInferenceError> {
    match auth {
        HttpInferenceAuth::None => Ok(()),
        HttpInferenceAuth::BearerToken(token) => {
            if token.trim().is_empty() {
                Err(HttpInferenceError::EmptyField {
                    field: "auth.token",
                })
            } else {
                Ok(())
            }
        }
        HttpInferenceAuth::ApiKeyHeader { header, value } => {
            if value.trim().is_empty() {
                return Err(HttpInferenceError::EmptyField {
                    field: "auth.value",
                });
            }
            let lower = header.to_ascii_lowercase();
            if lower == "authorization" || lower == "content-type" {
                return Err(HttpInferenceError::BadHeader(header.clone()));
            }
            header_name(header)?;
            HeaderValue::from_str(value)
                .map_err(|_| HttpInferenceError::BadHeader(header.clone()))?;
            Ok(())
        }
    }
}

fn validate_headers(headers: &BTreeMap<String, String>) -> Result<(), HttpInferenceError> {
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
            return Err(HttpInferenceError::BadHeader(name.clone()));
        }
        header_name(name)?;
        HeaderValue::from_str(value).map_err(|_| HttpInferenceError::BadHeader(name.clone()))?;
    }
    Ok(())
}

pub(super) fn validate_overrides(
    overrides: &BTreeMap<String, JsonValue>,
) -> Result<(), HttpInferenceError> {
    for (key, value) in overrides {
        let lower = key.to_ascii_lowercase();
        if is_reserved_request_field(&lower) {
            return Err(HttpInferenceError::ReservedRequestField(key.to_string()));
        }
        validate_sensitive_override_field(key, value)?;
    }
    Ok(())
}

fn validate_sensitive_override_field(
    key: &str,
    value: &JsonValue,
) -> Result<(), HttpInferenceError> {
    let lower = key.to_ascii_lowercase();
    if is_sensitive_request_field(&lower) || lower.contains("secret") || lower.contains("api_key") {
        return Err(HttpInferenceError::ReservedRequestField(key.to_string()));
    }
    match value {
        JsonValue::Object(map) => {
            for (child, child_value) in map {
                validate_sensitive_override_field(child, child_value)?;
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                if let JsonValue::Object(map) = item {
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

pub(super) fn reject_unsupported_input(input: &Value) -> Result<(), HttpInferenceError> {
    fn scan(value: &Value) -> Result<(), HttpInferenceError> {
        match value {
            Value::Bytes(_) => Err(HttpInferenceError::UnsupportedPayload("inline bytes")),
            Value::Blob(_) => Err(HttpInferenceError::UnsupportedPayload("blob reference")),
            Value::Tensor(_) => Err(HttpInferenceError::UnsupportedPayload("tensor reference")),
            Value::Frame(_) => Err(HttpInferenceError::UnsupportedPayload("frame reference")),
            Value::List(items) => {
                for item in items {
                    scan(item)?;
                }
                Ok(())
            }
            Value::Map(map) => {
                for key in map.keys() {
                    let lower = key.to_ascii_lowercase();
                    if lower == "tools" || lower == "tool_choice" || lower == "functions" {
                        return Err(HttpInferenceError::UnsupportedPayload(
                            "provider-native tools",
                        ));
                    }
                }
                for value in map.values() {
                    scan(value)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    scan(input)
}

pub(super) fn headers_for(config: &HttpInferenceConfig) -> Result<HeaderMap, HttpInferenceError> {
    let mut headers = HeaderMap::new();
    for (name, value) in &config.options.default_headers {
        headers.insert(header_name(name)?, header_value(name, value)?);
    }
    match &config.auth {
        HttpInferenceAuth::None => {}
        HttpInferenceAuth::BearerToken(token) => {
            let value = format!("Bearer {token}");
            headers.insert("authorization", header_value("authorization", &value)?);
        }
        HttpInferenceAuth::ApiKeyHeader { header, value } => {
            headers.insert(header_name(header)?, header_value(header, value)?);
        }
    }
    if let HttpInferenceDialect::AnthropicMessages = config.dialect {
        let version = config
            .options
            .api_version
            .as_deref()
            .unwrap_or("2023-06-01");
        headers.insert(
            "anthropic-version",
            header_value("anthropic-version", version)?,
        );
    }
    Ok(headers)
}

fn header_name(name: &str) -> Result<HeaderName, HttpInferenceError> {
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| HttpInferenceError::BadHeader(name.into()))
}

fn header_value(name: &str, value: &str) -> Result<HeaderValue, HttpInferenceError> {
    HeaderValue::from_str(value).map_err(|_| HttpInferenceError::BadHeader(name.into()))
}

pub(super) fn endpoint_url(base_url: &str, path: &str) -> Result<String, HttpInferenceError> {
    let mut url = reqwest::Url::parse(base_url).map_err(|_| HttpInferenceError::BadBaseUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(HttpInferenceError::BadBaseUrl);
    }
    if !path.is_empty() {
        let mut base_path = url.path().trim_end_matches('/').to_string();
        base_path.push('/');
        base_path.push_str(path.trim_start_matches('/'));
        url.set_path(&base_path);
    }
    Ok(url.to_string())
}

pub(super) fn redact_body(body: &str, config: &HttpInferenceConfig) -> String {
    let mut redacted = body.to_string();
    match &config.auth {
        HttpInferenceAuth::None => {}
        HttpInferenceAuth::BearerToken(token) => {
            if !token.is_empty() {
                redacted = redacted.replace(token, "<redacted>");
            }
        }
        HttpInferenceAuth::ApiKeyHeader { value, .. } => {
            if !value.is_empty() {
                redacted = redacted.replace(value, "<redacted>");
            }
        }
    }
    redacted.chars().take(512).collect()
}
