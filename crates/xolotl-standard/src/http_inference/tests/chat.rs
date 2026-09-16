//! Tests whose backend and routing declarations require the Chat dialect.

use super::{
    HttpInferenceAuth, HttpInferenceBackend, HttpInferenceConfig, HttpInferenceDialect,
    HttpInferenceError, bearer_config, recv_request, spawn_http_once,
};
use crate::http_inference::routing::{
    HttpInferenceGroup, HttpInferenceRoute, HttpInferenceRouterConfig,
};
use crate::http_inference::state::router_from_state;
use crate::router::GroupPolicy;
use anyhow::{Context, bail, ensure};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use xolotl_state::Backend;
use xolotl_types::{
    InferenceAuthRef, InferenceBackendDef, InferenceGroupDef, InferenceGroupPolicy,
    InferenceModelCapabilities, InferenceModelDef, InferenceRoutingDef, Path, Value,
};

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
        .with_context(|| format!("write {path}"))?;
    Ok(())
}

#[tokio::test]
async fn router_from_state_builds_openai_compatible_backend() -> anyhow::Result<()> {
    let server = spawn_http_once(
        "200 OK",
        r#"{"choices":[{"message":{"content":"state route ok"}}]}"#,
    )?;
    let state: Backend = xolotl_state::InMemoryBackend::new().into_backend();
    write_state_value(
        &state,
        "state://vault/inference/deepseek/api_key",
        Value::string("secret-token".into()),
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
            io_window_bytes: None,
            response_limits: Default::default(),
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
            &Value::string("hello".into()),
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
        routed.output == Value::string("state route ok".into()),
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

#[tokio::test]
async fn router_from_state_rejects_path_id_mismatch() -> anyhow::Result<()> {
    let state: Backend = xolotl_state::InMemoryBackend::new().into_backend();
    write_state_value(
        &state,
        "state://vault/inference/deepseek/api_key",
        Value::string("secret-token".into()),
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
            io_window_bytes: None,
            response_limits: Default::default(),
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
        .insert("tools".into(), Value::list(vec![]))?;
    let result = HttpInferenceBackend::new(cfg);
    ensure!(
        matches!(result, Err(HttpInferenceError::ReservedRequestField(_))),
        "reserved request field was accepted"
    );
    Ok(())
}

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
        .infer_inner(&Value::string("hello".into()))
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
        .infer_inner(&Value::string("hello".into()))
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
