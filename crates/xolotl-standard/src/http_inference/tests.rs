use super::backend::HttpInferenceBackend;
use super::config::{HttpInferenceAuth, HttpInferenceConfig, HttpInferenceDialect};
use super::dialects::{
    parse_anthropic_text, parse_gemini_text, parse_openai_chat_text, parse_openai_embedding,
    parse_openai_responses_text,
};
use super::error::HttpInferenceError;
use super::request::reject_unsupported_input;
use anyhow::{Context, bail, ensure};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use xolotl_types::{BlobRef, Value};

#[cfg(feature = "openai-chat")]
mod chat;
mod transport;

#[test]
fn input_admission_visits_shared_graphs_and_preserves_field_guards() -> anyhow::Result<()> {
    let mut shared = Value::string("text".into());
    for _ in 0..80 {
        shared = Value::list(vec![shared.clone(), shared]);
    }
    reject_unsupported_input(&shared)?;
    let with_tools = Value::list(vec![
        shared,
        Value::map(BTreeMap::from([("ToOl_ChOiCe".into(), Value::null())])),
    ]);
    ensure!(matches!(
        reject_unsupported_input(&with_tools),
        Err(HttpInferenceError::UnsupportedPayload(
            "provider-native tools"
        ))
    ));
    Ok(())
}

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

fn bearer_config(dialect: HttpInferenceDialect) -> HttpInferenceConfig {
    HttpInferenceConfig::new(
        "test",
        dialect,
        "https://example.test/v1",
        "model-1",
        HttpInferenceAuth::BearerToken("secret-token".into()),
    )
}

#[cfg(any(
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
fn spawn_http_once(
    status: &'static str,
    response_body: impl Into<String>,
) -> anyhow::Result<HttpOnce> {
    spawn_http_once_with_type(status, response_body, "application/json")
}

fn spawn_http_once_with_type(
    status: &'static str,
    response_body: impl Into<String>,
    content_type: &'static str,
) -> anyhow::Result<HttpOnce> {
    let response_body = response_body.into();
    let listener = TcpListener::bind("127.0.0.1:0").context("bind HTTP test listener")?;
    let addr = listener
        .local_addr()
        .context("read HTTP test listener address")?;
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = handle_http_once(listener, status, &response_body, content_type);
        tx.send(result)
            .map_err(|_error| anyhow::anyhow!("HTTP test receiver dropped before request capture"))
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
    content_type: &str,
) -> anyhow::Result<CapturedRequest> {
    let (mut stream, _) = listener.accept().context("accept HTTP test request")?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let body = loop {
        let n = stream.read(&mut tmp).context("read HTTP test request")?;
        if n == 0 {
            bail!("HTTP test request ended before its body");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(decoded) = decode_request_body(&buf)? {
            break decoded;
        }
    };
    let header_end = header_end(&buf).context("request headers missing")?;
    let head = String::from_utf8(buf[..header_end].to_vec()).context("decode HTTP request head")?;
    let body = String::from_utf8(body).context("decode HTTP request body")?;
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("write HTTP test response")?;
    Ok(CapturedRequest { head, body })
}

mod streaming;

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

fn decode_request_body(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(end) = header_end(bytes) else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&bytes[..end])?;
    let mut bytes = &bytes[end..];
    if !head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    }) {
        let length = content_length(head)?;
        return Ok(bytes.get(..length).map(|body| body.to_vec()));
    }
    let mut output = Vec::new();
    loop {
        let Some(end) = bytes.windows(2).position(|bytes| bytes == b"\r\n") else {
            return Ok(None);
        };
        let size = std::str::from_utf8(&bytes[..end])?
            .split(';')
            .next()
            .context("missing chunk length")?;
        let size = usize::from_str_radix(size, 16)?;
        bytes = &bytes[end + 2..];
        let Some(data) = bytes.get(..size.saturating_add(2)) else {
            return Ok(None);
        };
        ensure!(&data[size..] == b"\r\n", "invalid request chunk terminator");
        if size == 0 {
            return Ok(Some(output));
        }
        output.extend_from_slice(&data[..size]);
        bytes = &bytes[size + 2..];
    }
}

fn recv_request(server: HttpOnce) -> anyhow::Result<CapturedRequest> {
    let request = server.rx.recv().context("receive captured HTTP request")?;
    let join_result = server
        .handle
        .join()
        .map_err(|_error| anyhow::anyhow!("HTTP test server thread panicked"))?;
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

#[test]
fn non_text_payloads_are_rejected_before_http() -> anyhow::Result<()> {
    let blob = Value::blob(BlobRef {
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
            parse_openai_responses_text(openai_response),
            Ok(ref text) if text == "hello"
        ),
        "OpenAI Responses text parse failed"
    );

    let chat = serde_json::json!({
        "choices": [{"message": {"content": "hi"}}]
    });
    ensure!(
        matches!(parse_openai_chat_text(chat), Ok(ref text) if text == "hi"),
        "OpenAI chat text parse failed"
    );

    let anthropic = serde_json::json!({
        "content": [{"type": "text", "text": "claude"}]
    });
    ensure!(
        matches!(parse_anthropic_text(anthropic), Ok(ref text) if text == "claude"),
        "Anthropic text parse failed"
    );

    let gemini = serde_json::json!({
        "candidates": [{"content": {"parts": [{"text": "gemini"}]}}]
    });
    ensure!(
        matches!(parse_gemini_text(gemini), Ok(ref text) if text == "gemini"),
        "Gemini text parse failed"
    );
    Ok(())
}

#[test]
fn embeddings_include_space_and_model() -> anyhow::Result<()> {
    let response = serde_json::json!({
        "data": [{"embedding": [0.25, -0.5, 1.0]}]
    });
    let value = parse_openai_embedding(response, "http-inference/test/embedder", "embedder")
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
        .infer_inner(&Value::string("hello".into()))
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
        .infer_inner(&Value::string("hello".into()))
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
