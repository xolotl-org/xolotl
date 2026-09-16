use super::super::{
    HttpInferenceBackend, HttpInferenceDialect, bearer_config, recv_request,
    spawn_http_once_with_type,
};
use crate::inference::{InferenceBackend, InferenceStream};
use anyhow::{Context, bail, ensure};
use serde_json::{Value as JsonValue, json};
use xolotl_kernel::DriverContext;
use xolotl_kernel::host::stream::{StreamItem, channel};
use xolotl_kernel::stream::StreamWindow;
use xolotl_types::{IdentityRef, InferenceResponseLimits, Outcome, ProcessId, Value};

const DIALECTS: &[HttpInferenceDialect] = &[
    #[cfg(feature = "openai-responses")]
    HttpInferenceDialect::OpenAiResponses,
    #[cfg(feature = "openai-chat")]
    HttpInferenceDialect::OpenAiChatCompletions,
    #[cfg(feature = "anthropic-messages")]
    HttpInferenceDialect::AnthropicMessages,
    #[cfg(feature = "gemini-generate-content")]
    HttpInferenceDialect::GeminiGenerateContent,
];

fn delta(dialect: HttpInferenceDialect, text: &str) -> JsonValue {
    match dialect {
        HttpInferenceDialect::OpenAiResponses => {
            json!({"delta":text,"type":"response.output_text.delta"})
        }
        HttpInferenceDialect::OpenAiChatCompletions => {
            json!({"choices":[{"delta":{"content":text}}]})
        }
        HttpInferenceDialect::AnthropicMessages => {
            json!({"delta":{"text":text},"type":"content_block_delta"})
        }
        HttpInferenceDialect::GeminiGenerateContent => {
            json!({"candidates":[{"content":{"parts":[{"text":text}]}}]})
        }
    }
}

fn completion(dialect: HttpInferenceDialect) -> &'static str {
    match dialect {
        HttpInferenceDialect::OpenAiResponses => r#"{"type":"response.completed"}"#,
        HttpInferenceDialect::OpenAiChatCompletions => "[DONE]",
        HttpInferenceDialect::AnthropicMessages => r#"{"type":"message_stop"}"#,
        HttpInferenceDialect::GeminiGenerateContent => {
            r#"{"candidates":[{"finishReason":"STOP"}]}"#
        }
    }
}

#[tokio::test]
async fn every_dialect_transfers_a_large_atomic_delta_through_small_output_windows()
-> anyhow::Result<()> {
    let text = "a中𝄞".repeat(12 * 1024);
    for &dialect in DIALECTS {
        let body = format!(
            "data: {}\n\ndata: {}\n\n",
            delta(dialect, &text),
            completion(dialect)
        );
        let server = spawn_http_once_with_type("200 OK", body, "text/event-stream")?;
        let mut config = bearer_config(dialect);
        config.base_url = server.base_url.clone();
        config.io_window_bytes = core::num::NonZeroUsize::MIN.saturating_add(30);
        let backend = HttpInferenceBackend::new(config)?;
        let (sink, mut receiver) = channel(StreamWindow {
            max_chunks: core::num::NonZeroUsize::MIN,
            max_inline_bytes: core::num::NonZeroUsize::MIN.saturating_add(1023),
        });
        let context =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
        let output = InferenceStream::new(&context);
        let input = Value::string("prompt".into());
        let read = async {
            let mut actual = String::new();
            while actual.len() < text.len() {
                let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
                    bail!("missing streamed text");
                };
                let piece = chunk.value.as_str().context("chunk was not text")?;
                ensure!(piece.len() <= 31);
                actual.push_str(piece);
            }
            ensure!(actual == text);
            Ok::<_, anyhow::Error>(())
        };
        let send = async {
            let result = backend
                .infer_stream(&input, &output)
                .await
                .map_err(anyhow::Error::msg)?;
            ensure!(result.outcome == Outcome::Done(Value::null()));
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            tokio::try_join!(send, read)
        })
        .await
        .context("large delta transfer timed out")??;
        recv_request(server)?;
    }
    Ok(())
}

#[tokio::test]
async fn selected_record_limits_reject_before_emitting_any_of_that_record() -> anyhow::Result<()> {
    for &dialect in DIALECTS {
        let body = format!(
            "data: {}\n\ndata: {}\n\n",
            delta(dialect, "four"),
            completion(dialect)
        );
        let server = spawn_http_once_with_type("200 OK", body, "text/event-stream")?;
        let mut config = bearer_config(dialect);
        config.base_url = server.base_url.clone();
        config.response_limits = InferenceResponseLimits {
            max_materialized_bytes: Some(3),
            ..InferenceResponseLimits::default()
        };
        let backend = HttpInferenceBackend::new(config)?;
        let (sink, _receiver) = channel(StreamWindow::default());
        let context =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
        let output = InferenceStream::new(&context);
        let result = backend
            .infer_stream(&Value::string("prompt".into()), &output)
            .await;
        ensure!(matches!(result, Err(error) if error.contains("materialization byte policy")));
        ensure!(!output.has_output());
        recv_request(server)?;
    }
    Ok(())
}

#[tokio::test]
async fn late_errors_and_invalid_suffixes_do_not_publish_selected_record_prefixes()
-> anyhow::Result<()> {
    for &dialect in DIALECTS {
        let encoded = delta(dialect, "must remain private").to_string();
        // Keep nested delta braces intact; only replace the outermost end.
        let with_error = format!(
            "{},\"error\":{{\"message\":\"late failure\"}}}}",
            &encoded[..encoded.len() - 1]
        );
        for record in [format!("{encoded}garbage"), with_error] {
            let server = spawn_http_once_with_type(
                "200 OK",
                format!("data: {record}\n\n"),
                "text/event-stream",
            )?;
            let mut config = bearer_config(dialect);
            config.base_url = server.base_url.clone();
            config.io_window_bytes = core::num::NonZeroUsize::MIN;
            let backend = HttpInferenceBackend::new(config)?;
            let (sink, _receiver) = channel(StreamWindow::default());
            let context =
                DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
            let output = InferenceStream::new(&context);
            ensure!(backend.infer_stream(&Value::null(), &output).await.is_err());
            ensure!(!output.has_output());
            recv_request(server)?;
        }
    }
    Ok(())
}

#[cfg(feature = "openai-responses")]
#[tokio::test]
async fn growing_completion_snapshot_ignores_its_payload_under_a_small_selected_budget()
-> anyhow::Result<()> {
    use xolotl_types::UsageDimension;
    let snapshot = "x".repeat(512 * 1024);
    let body = format!(
        "data: {{\"delta\":\"ok\",\"type\":\"response.output_text.delta\"}}\n\ndata: {{\"response\":{{\"output\":[{{\"content\":[{{\"text\":\"{snapshot}\"}}]}}],\"usage\":{{\"output_tokens\":7}}}},\"type\":\"response.completed\"}}\n\n"
    );
    let server = spawn_http_once_with_type("200 OK", body, "text/event-stream")?;
    let mut config = bearer_config(HttpInferenceDialect::OpenAiResponses);
    config.base_url = server.base_url.clone();
    config.io_window_bytes = core::num::NonZeroUsize::MIN.saturating_add(6);
    config.response_limits = InferenceResponseLimits {
        max_materialized_bytes: Some(4),
        max_materialized_nodes: Some(8),
        max_json_frames: Some(16),
    };
    let backend = HttpInferenceBackend::new(config)?;
    let (sink, mut receiver) = channel(StreamWindow::default());
    let context = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
    let result = backend
        .infer_stream(
            &Value::string("prompt".into()),
            &InferenceStream::new(&context),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(result.outcome == Outcome::Done(Value::null()));
    let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
        bail!("missing selected text");
    };
    ensure!(chunk.value.as_str() == Some("ok"));
    ensure!(
        result
            .usage
            .as_ref()
            .and_then(|usage| usage.get(&UsageDimension::OUTPUT_TOKENS))
            == Some(&7)
    );
    recv_request(server)?;
    Ok(())
}
