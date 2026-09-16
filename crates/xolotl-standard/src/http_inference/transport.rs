//! Shared HTTP request dispatch and response ownership for unary and SSE calls.

use super::backend::HttpInferenceBackend;
use super::config::{HttpInferenceAuth, HttpInferenceDialect};
use super::dialects::projection;
use super::error::HttpInferenceError;
use super::json::{
    Document,
    project::{Limits, Rule},
};
use super::request::{
    encode_embedding, encode_generation, endpoint_url, headers_for, reject_unsupported_input,
};
use serde_json::Value as JsonValue;
use xolotl_types::Value;

const ERROR_BODY_BYTES: usize = 8 * 1024;
const ERROR_DISPLAY_CHARS: usize = 512;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ResponseKind {
    Json,
    EventStream,
}

impl HttpInferenceBackend {
    pub(super) async fn generate(
        &self,
        input: &Value,
        response_kind: ResponseKind,
    ) -> Result<reqwest::Response, HttpInferenceError> {
        reject_unsupported_input(input)?;
        let streaming = response_kind == ResponseKind::EventStream;
        let path = match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses => "responses".into(),
            HttpInferenceDialect::OpenAiChatCompletions => "chat/completions".into(),
            HttpInferenceDialect::AnthropicMessages => "messages".into(),
            HttpInferenceDialect::GeminiGenerateContent => format!(
                "models/{}:{}",
                self.config.model,
                if streaming {
                    "streamGenerateContent"
                } else {
                    "generateContent"
                }
            ),
        };
        self.post(
            &path,
            encode_generation(&self.config, input, streaming)?,
            response_kind,
        )
        .await
    }

    pub(super) async fn embedding(
        &self,
        model: &str,
        input: &Value,
    ) -> Result<JsonValue, HttpInferenceError> {
        reject_unsupported_input(input)?;
        let path = match self.config.dialect {
            HttpInferenceDialect::OpenAiResponses | HttpInferenceDialect::OpenAiChatCompletions => {
                "embeddings".into()
            }
            HttpInferenceDialect::GeminiGenerateContent => format!("models/{model}:embedContent"),
            HttpInferenceDialect::AnthropicMessages => {
                return Err(HttpInferenceError::EmbedUnsupported);
            }
        };
        let response = self
            .post(
                &path,
                encode_embedding(&self.config, model, input)?,
                ResponseKind::Json,
            )
            .await?;
        decode_json(
            response,
            projection::embedding(self.config.dialect),
            self.config.response_limits,
            self.config.io_window_bytes,
        )
        .await
    }

    async fn post(
        &self,
        path: &str,
        payload: super::request::Body,
        response_kind: ResponseKind,
    ) -> Result<reqwest::Response, HttpInferenceError> {
        let mut url = reqwest::Url::parse(&endpoint_url(&self.config.base_url, path)?)
            .map_err(|_error| HttpInferenceError::BadBaseUrl)?;
        if response_kind == ResponseKind::EventStream
            && self.config.dialect == HttpInferenceDialect::GeminiGenerateContent
        {
            url.query_pairs_mut().append_pair("alt", "sse");
        }
        let response = self
            .client
            .post(url)
            .headers(headers_for(&self.config)?)
            .header("content-type", "application/json")
            .header(
                "accept",
                match response_kind {
                    ResponseKind::Json => "application/json",
                    ResponseKind::EventStream => "text/event-stream",
                },
            )
            .body(reqwest::Body::wrap_stream(
                futures_util::stream::try_unfold(payload, |mut body| async move {
                    tokio::task::consume_budget().await;
                    body.next().map(|chunk| chunk.map(|chunk| (chunk, body)))
                }),
            ))
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(response);
        }
        let mut response = response;
        let status = response.status().as_u16();
        let mut prefix = Vec::new();
        while prefix.len() < ERROR_BODY_BYTES {
            let Some(chunk) = response.chunk().await? else {
                break;
            };
            let count = chunk.len().min(ERROR_BODY_BYTES - prefix.len());
            prefix.extend_from_slice(&chunk[..count]);
        }
        Err(HttpInferenceError::ProviderHttpStatus {
            status,
            body: redact_diagnostic(&prefix, &self.config.auth, prefix.len() == ERROR_BODY_BYTES),
        })
    }
}

pub(super) async fn decode_json(
    mut response: reqwest::Response,
    rule: &'static Rule,
    limits: Limits,
    window: core::num::NonZeroUsize,
) -> Result<JsonValue, HttpInferenceError> {
    let mut document = Document::new(rule, limits);
    while let Some(bytes) = response.chunk().await? {
        for window in bytes.chunks(window.get()) {
            document.push(window)?;
            tokio::task::consume_budget().await;
        }
    }
    document.finish()
}

fn redact_diagnostic(bytes: &[u8], auth: &HttpInferenceAuth, truncated: bool) -> String {
    let secret = match auth {
        HttpInferenceAuth::None => "",
        HttpInferenceAuth::BearerToken(token) => token,
        HttpInferenceAuth::ApiKeyHeader { value, .. } => value,
    };
    let secret = secret.as_bytes();
    let mut remaining = bytes;
    let display_bytes = ERROR_DISPLAY_CHARS * 4;
    let mut redacted = Vec::with_capacity(bytes.len().min(display_bytes));
    while !remaining.is_empty() && redacted.len() < display_bytes {
        // Complete matches take precedence over overlapping suffixes. A bounded
        // read may then leave a final partial credential that also needs hiding.
        let (replacement, consumed) = if !secret.is_empty() && remaining.starts_with(secret) {
            (&b"<redacted>"[..], secret.len())
        } else if truncated && !secret.is_empty() && secret.starts_with(remaining) {
            (&b"<redacted>"[..], remaining.len())
        } else {
            (&remaining[..1], 1)
        };
        let count = replacement.len().min(display_bytes - redacted.len());
        redacted.extend_from_slice(&replacement[..count]);
        remaining = &remaining[consumed..];
    }
    String::from_utf8_lossy(&redacted)
        .chars()
        .take(ERROR_DISPLAY_CHARS)
        .collect()
}
