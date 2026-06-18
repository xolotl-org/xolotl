use super::backend::HttpInferenceBackend;
use super::config::{HttpInferenceAuth, HttpInferenceConfig, HttpInferenceDialect};
use super::dialects::{
    parse_anthropic_text, parse_gemini_text, parse_openai_chat_text, parse_openai_embedding,
    parse_openai_responses_text,
};
use super::error::HttpInferenceError;
use super::request::reject_unsupported_input;
use super::routing::{HttpInferenceGroup, HttpInferenceRoute, HttpInferenceRouterConfig};
use super::state::router_from_state;
use crate::router::GroupPolicy;
use anyhow::{Context, bail, ensure};
use nexus_state::Backend;
use nexus_types::{
    BlobRef, InferenceAuthRef, InferenceBackendDef, InferenceGroupDef, InferenceGroupPolicy,
    InferenceModelCapabilities, InferenceModelDef, InferenceRoutingDef, Path, Value,
};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: String,
}

struct HttpOnce {
    base_url: String,
    rx: mpsc::Receiver<anyhow::Result<CapturedRequest>>,
    handle: JoinHandle<anyhow::Result<()>>,
}

fn state_value<T: serde::Serialize>(value: &T) -> anyhow::Result<Value> {
    let json = serde_json::to_value(value).context("serialize state value")?;
    serde_json::from_value(json).context("decode state value")
}

async fn write_state_value(state: &Backend, path: &str, value: Value) -> anyhow::Result<()> {
    state
        .write_set(
            &Path::parse(path).with_context(|| format!("parse {path}"))?,
            value,
        )
        .await
        .with_context(|| format!("write {path}"))
}

fn bearer_config(dialect: HttpInferenceDialect) -> HttpInferenceConfig {
    HttpInferenceConfig::new(
        "test",
        dialect,
        "https://example.test/v1",
        "model-1",
        HttpInferenceAuth::BearerToken("secret-token".into()),
    )
}

fn spawn_http_once(status: &'static str, response_body: &'static str) -> anyhow::Result<HttpOnce> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind HTTP test listener")?;
    let addr = listener
        .local_addr()
        .context("read HTTP test listener address")?;
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = handle_http_once(listener, status, response_body);
        tx.send(result)
            .map_err(|_| anyhow::anyhow!("HTTP test receiver dropped before request capture"))
    });
    Ok(HttpOnce {
        base_url: format!("http://{addr}/v1"),
        rx,
        handle,
    })
}

fn handle_http_once(
    listener: TcpListener,
    status: &str,
    response_body: &str,
) -> anyhow::Result<CapturedRequest> {
    let (mut stream, _) = listener.accept().context("accept HTTP test request")?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let mut needed_len = None;
    loop {
        let n = stream.read(&mut tmp).context("read HTTP test request")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if needed_len.is_none()
            && let Some(header_end) = header_end(&buf)
        {
            let head = String::from_utf8(buf[..header_end].to_vec())
                .context("decode HTTP request head")?;
            let content_len = content_length(&head)?;
            needed_len = Some(header_end + content_len);
        }
        if let Some(len) = needed_len
            && buf.len() >= len
        {
            break;
        }
    }
    let header_end = header_end(&buf).context("request headers missing")?;
    let head = String::from_utf8(buf[..header_end].to_vec()).context("decode HTTP request head")?;
    let body = String::from_utf8(buf[header_end..].to_vec()).context("decode HTTP request body")?;
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("write HTTP test response")?;
    Ok(CapturedRequest { head, body })
}

fn header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for idx in 0..=(buf.len() - 4) {
        if &buf[idx..idx + 4] == b"\r\n\r\n" {
            return Some(idx + 4);
        }
    }
    None
}

fn content_length(head: &str) -> anyhow::Result<usize> {
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .context("parse content-length");
        }
    }
    Ok(0)
}

fn recv_request(server: HttpOnce) -> anyhow::Result<CapturedRequest> {
    let request = server.rx.recv().context("receive captured HTTP request")?;
    let join_result = server
        .handle
        .join()
        .map_err(|_| anyhow::anyhow!("HTTP test server thread panicked"))?;
    join_result?;
    request
}

#[test]
fn debug_redacts_auth_material() -> anyhow::Result<()> {
    let cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    let debug = format!("{cfg:?}");
    ensure!(!debug.contains("secret-token"), "debug leaked secret");
    ensure!(
        debug.contains("<redacted>"),
        "debug missing redaction marker"
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[tokio::test]
async fn router_from_state_builds_openai_compatible_backend() -> anyhow::Result<()> {
    let server = spawn_http_once(
        "200 OK",
        r#"{"choices":[{"message":{"content":"state route ok"}}]}"#,
    )?;
    let state: Backend = Arc::new(nexus_state::InMemoryBackend::new());
    write_state_value(
        &state,
        "state://vault/inference/deepseek/api_key",
        Value::Str("secret-token".into()),
    )
    .await?;
    write_state_value(
        &state,
        "state://kernel/inference/backends/deepseek",
        state_value(&InferenceBackendDef {
            id: "deepseek".into(),
            dialect: HttpInferenceDialect::OpenAiChatCompletions,
            base_url: server.base_url.clone(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: Path::parse("state://vault/inference/deepseek/api_key")
                    .map_err(anyhow::Error::msg)?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: None,
            version: 0,
        })?,
    )
    .await?;
    write_state_value(
        &state,
        "state://kernel/inference/models/deepseek-chat",
        state_value(&InferenceModelDef {
            id: "deepseek-chat".into(),
            backend_id: "deepseek".into(),
            provider_model: "deepseek-chat".into(),
            embedding_model: None,
            capabilities: InferenceModelCapabilities::default(),
            weight: 1,
            version: 0,
        })?,
    )
    .await?;
    write_state_value(
        &state,
        "state://kernel/inference/groups/default",
        state_value(&InferenceGroupDef {
            name: "default".into(),
            policy: InferenceGroupPolicy::Priority,
            models: vec!["deepseek-chat".into()],
            fallback: None,
            version: 0,
        })?,
    )
    .await?;
    write_state_value(
        &state,
        "state://kernel/routing/inference",
        state_value(&InferenceRoutingDef {
            default_group: "default".into(),
            max_retries: Some(0),
            version: 0,
        })?,
    )
    .await?;

    let router = router_from_state(&state)
        .await
        .map_err(anyhow::Error::msg)?
        .context("expected router")?;
    let routed = router
        .infer(
            &Value::Str("hello".into()),
            &crate::inference::RequestRequirements::default(),
            None,
        )
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        routed.model_id == "deepseek/deepseek-chat",
        "routed model id: {}",
        routed.model_id
    );
    ensure!(
        routed.output == Value::Str("state route ok".into()),
        "routed output: {:?}",
        routed.output
    );

    let req = recv_request(server)?;
    ensure!(
        req.head.starts_with("POST /v1/chat/completions "),
        "request head: {}",
        req.head
    );
    ensure!(
        req.head.contains("authorization: Bearer secret-token"),
        "request missing authorization header"
    );
    let body: JsonValue = serde_json::from_str(&req.body).map_err(anyhow::Error::msg)?;
    ensure!(
        body["model"] == JsonValue::String("deepseek-chat".into()),
        "request model: {:?}",
        body["model"]
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[tokio::test]
async fn router_from_state_rejects_path_id_mismatch() -> anyhow::Result<()> {
    let state: Backend = Arc::new(nexus_state::InMemoryBackend::new());
    write_state_value(
        &state,
        "state://vault/inference/deepseek/api_key",
        Value::Str("secret-token".into()),
    )
    .await?;
    write_state_value(
        &state,
        "state://kernel/inference/backends/other",
        state_value(&InferenceBackendDef {
            id: "deepseek".into(),
            dialect: HttpInferenceDialect::OpenAiChatCompletions,
            base_url: "https://api.deepseek.com".into(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: Path::parse("state://vault/inference/deepseek/api_key")
                    .map_err(anyhow::Error::msg)?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: None,
            version: 0,
        })?,
    )
    .await?;
    write_state_value(
        &state,
        "state://kernel/inference/models/deepseek-chat",
        state_value(&InferenceModelDef {
            id: "deepseek-chat".into(),
            backend_id: "deepseek".into(),
            provider_model: "deepseek-chat".into(),
            embedding_model: None,
            capabilities: InferenceModelCapabilities::default(),
            weight: 1,
            version: 0,
        })?,
    )
    .await?;

    let result = router_from_state(&state).await;
    ensure!(
        matches!(result, Err(HttpInferenceError::StateAdmission { .. })),
        "expected state admission error"
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[test]
fn config_rejects_reserved_headers_and_request_fields() -> anyhow::Result<()> {
    let mut cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    cfg.options
        .default_headers
        .insert("authorization".into(), "bad".into());
    let result = HttpInferenceBackend::new(cfg);
    ensure!(
        matches!(result, Err(HttpInferenceError::BadHeader(_))),
        "reserved header was accepted"
    );

    let mut cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    cfg.options
        .request_overrides
        .insert("tools".into(), JsonValue::Array(vec![]));
    let result = HttpInferenceBackend::new(cfg);
    ensure!(
        matches!(result, Err(HttpInferenceError::ReservedRequestField(_))),
        "reserved request field was accepted"
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[test]
fn config_rejects_reserved_url_and_numeric_options() -> anyhow::Result<()> {
    let mut cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    cfg.base_url = "file:///tmp/model".into();
    let result = HttpInferenceBackend::new(cfg);
    ensure!(
        matches!(result, Err(HttpInferenceError::BadBaseUrl)),
        "file base url was accepted"
    );

    let mut cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    cfg.base_url = "https://example.test/v1?key=secret".into();
    let result = HttpInferenceBackend::new(cfg);
    ensure!(
        matches!(result, Err(HttpInferenceError::BadBaseUrl)),
        "base url with query was accepted"
    );

    let mut cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    cfg.options.max_output_tokens = Some(0);
    let result = HttpInferenceBackend::new(cfg);
    ensure!(
        matches!(
            result,
            Err(HttpInferenceError::InvalidNumber("max_output_tokens"))
        ),
        "zero max_output_tokens was accepted"
    );
    Ok(())
}

#[test]
fn non_text_payloads_are_rejected_before_http() -> anyhow::Result<()> {
    let blob = Value::Blob(BlobRef {
        hash: "abc".into(),
        size: 3,
        mime: Some("image/png".into()),
    });
    let result = reject_unsupported_input(&blob);
    ensure!(
        matches!(
            result,
            Err(HttpInferenceError::UnsupportedPayload("blob reference"))
        ),
        "blob payload was accepted"
    );
    Ok(())
}

#[test]
fn parses_response_dialects() -> anyhow::Result<()> {
    let openai_response = serde_json::json!({
        "output": [{
            "content": [{"type": "output_text", "text": "hello"}]
        }]
    });
    ensure!(
        matches!(
            parse_openai_responses_text(&openai_response),
            Ok(ref text) if text == "hello"
        ),
        "OpenAI Responses text parse failed"
    );

    let chat = serde_json::json!({
        "choices": [{"message": {"content": "hi"}}]
    });
    ensure!(
        matches!(parse_openai_chat_text(&chat), Ok(ref text) if text == "hi"),
        "OpenAI chat text parse failed"
    );

    let anthropic = serde_json::json!({
        "content": [{"type": "text", "text": "claude"}]
    });
    ensure!(
        matches!(parse_anthropic_text(&anthropic), Ok(ref text) if text == "claude"),
        "Anthropic text parse failed"
    );

    let gemini = serde_json::json!({
        "candidates": [{"content": {"parts": [{"text": "gemini"}]}}]
    });
    ensure!(
        matches!(parse_gemini_text(&gemini), Ok(ref text) if text == "gemini"),
        "Gemini text parse failed"
    );
    Ok(())
}

#[test]
fn embeddings_include_space_and_model() -> anyhow::Result<()> {
    let response = serde_json::json!({
        "data": [{"embedding": [0.25, -0.5, 1.0]}]
    });
    let value = parse_openai_embedding(&response, "http-inference/test/embedder", "embedder")
        .map_err(anyhow::Error::msg)?;
    let map = value.as_map().context("embedding output must be a map")?;
    ensure!(
        map.get("space_id").and_then(Value::as_str) == Some("http-inference/test/embedder"),
        "space_id mismatch"
    );
    ensure!(
        map.get("embedding_model").and_then(Value::as_str) == Some("embedder"),
        "embedding_model mismatch"
    );
    Ok(())
}

#[test]
fn embedding_capability_is_explicit() -> anyhow::Result<()> {
    let cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    ensure!(
        !cfg.capabilities.methods.embed,
        "embedding should be disabled without embedding model"
    );
    let cfg = cfg.with_embedding_model("text-embedding-3-small");
    ensure!(
        cfg.capabilities.methods.embed,
        "embedding should be enabled with embedding model"
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[test]
fn routing_config_rejects_bad_groups() -> anyhow::Result<()> {
    let cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    let result = HttpInferenceRouterConfig::new()
        .with_route(HttpInferenceRoute::new(cfg))
        .with_group(HttpInferenceGroup::new(
            "primary",
            GroupPolicy::Priority,
            ["missing-model"],
        ))
        .with_default_group("primary")
        .build();
    ensure!(
        matches!(result, Err(HttpInferenceError::UnknownGroupModel { .. })),
        "missing model group was accepted"
    );

    let cfg = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    let result = HttpInferenceRouterConfig::new()
        .with_route(HttpInferenceRoute::new(cfg))
        .with_group(
            HttpInferenceGroup::new("primary", GroupPolicy::Priority, ["test"])
                .with_fallback("missing"),
        )
        .with_default_group("primary")
        .build();
    ensure!(
        matches!(result, Err(HttpInferenceError::UnknownFallbackGroup { .. })),
        "missing fallback group was accepted"
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[tokio::test]
async fn openai_chat_posts_openai_compatible_request() -> anyhow::Result<()> {
    let server = spawn_http_once("200 OK", r#"{"choices":[{"message":{"content":"ok"}}]}"#)?;
    let cfg = HttpInferenceConfig::new(
        "deepseek-chat",
        HttpInferenceDialect::OpenAiChatCompletions,
        server.base_url.clone(),
        "deepseek-chat",
        HttpInferenceAuth::BearerToken("secret-token".into()),
    );
    let backend = HttpInferenceBackend::new(cfg).map_err(anyhow::Error::msg)?;
    let text = backend
        .infer_inner(&Value::Str("hello".into()))
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(text == "ok", "OpenAI chat text: {text}");
    let request = recv_request(server)?;
    ensure!(
        request.head.starts_with("POST /v1/chat/completions "),
        "request head: {}",
        request.head
    );
    ensure!(
        request
            .head
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-token"),
        "request missing bearer authorization"
    );
    let body: JsonValue = serde_json::from_str(&request.body).map_err(anyhow::Error::msg)?;
    ensure!(
        body.get("model").and_then(JsonValue::as_str) == Some("deepseek-chat"),
        "request model: {:?}",
        body.get("model")
    );
    ensure!(
        body.get("tools").is_none(),
        "tools override leaked into request"
    );
    Ok(())
}

#[cfg(feature = "anthropic-messages")]
#[tokio::test]
async fn anthropic_uses_versioned_base_url_and_api_key_header() -> anyhow::Result<()> {
    let server = spawn_http_once("200 OK", r#"{"content":[{"type":"text","text":"claude"}]}"#)?;
    let mut cfg = HttpInferenceConfig::new(
        "anthropic",
        HttpInferenceDialect::AnthropicMessages,
        server.base_url.clone(),
        "claude-model",
        HttpInferenceAuth::ApiKeyHeader {
            header: "x-api-key".into(),
            value: "anthropic-secret".into(),
        },
    );
    cfg.options.api_version = Some("2023-06-01".into());
    let backend = HttpInferenceBackend::new(cfg).map_err(anyhow::Error::msg)?;
    let text = backend
        .infer_inner(&Value::Str("hello".into()))
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(text == "claude", "Anthropic text: {text}");
    let request = recv_request(server)?;
    ensure!(
        request.head.starts_with("POST /v1/messages "),
        "request head: {}",
        request.head
    );
    let head = request.head.to_ascii_lowercase();
    ensure!(
        head.contains("x-api-key: anthropic-secret"),
        "request missing api key header"
    );
    ensure!(
        head.contains("anthropic-version: 2023-06-01"),
        "request missing anthropic version"
    );
    Ok(())
}

#[cfg(feature = "gemini-generate-content")]
#[tokio::test]
async fn gemini_generate_content_posts_and_parses_text() -> anyhow::Result<()> {
    let server = spawn_http_once(
        "200 OK",
        r#"{"candidates":[{"content":{"parts":[{"text":"gemini"}]}}]}"#,
    )?;
    let cfg = HttpInferenceConfig::new(
        "gemini",
        HttpInferenceDialect::GeminiGenerateContent,
        server.base_url.replace("/v1", "/v1beta"),
        "gemini-model",
        HttpInferenceAuth::ApiKeyHeader {
            header: "x-goog-api-key".into(),
            value: "gemini-secret".into(),
        },
    );
    let backend = HttpInferenceBackend::new(cfg).map_err(anyhow::Error::msg)?;
    let text = backend
        .infer_inner(&Value::Str("hello".into()))
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(text == "gemini", "Gemini text: {text}");
    let request = recv_request(server)?;
    ensure!(
        request
            .head
            .starts_with("POST /v1beta/models/gemini-model:generateContent "),
        "request head: {}",
        request.head
    );
    ensure!(
        request
            .head
            .to_ascii_lowercase()
            .contains("x-goog-api-key: gemini-secret"),
        "request missing Gemini api key header"
    );
    Ok(())
}

#[cfg(feature = "openai-chat")]
#[tokio::test]
async fn provider_status_redacts_configured_secret() -> anyhow::Result<()> {
    let server = spawn_http_once("401 Unauthorized", r#"{"error":"secret-token rejected"}"#)?;
    let cfg = HttpInferenceConfig::new(
        "openai",
        HttpInferenceDialect::OpenAiChatCompletions,
        server.base_url.clone(),
        "model-1",
        HttpInferenceAuth::BearerToken("secret-token".into()),
    );
    let backend = HttpInferenceBackend::new(cfg).map_err(anyhow::Error::msg)?;
    let err = backend
        .infer_inner(&Value::Str("hello".into()))
        .await
        .map_err(anyhow::Error::msg);
    let request = recv_request(server)?;
    ensure!(
        request.head.starts_with("POST /v1/chat/completions "),
        "request head: {}",
        request.head
    );
    let Err(error) = err else {
        bail!("provider status unexpectedly succeeded");
    };
    let message = error.to_string();
    ensure!(
        message.contains("<redacted>") && !message.contains("secret-token"),
        "provider status did not redact secret: {message}"
    );
    Ok(())
}
