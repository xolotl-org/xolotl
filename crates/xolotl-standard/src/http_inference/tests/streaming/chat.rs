use super::super::{
    HttpInferenceBackend, HttpInferenceDialect, bearer_config, recv_request,
    spawn_http_once_with_type,
};
use crate::inference::{InferenceBackend, InferenceStream};
use anyhow::{bail, ensure};
use serde_json::Value as JsonValue;
use xolotl_kernel::DriverContext;
use xolotl_kernel::host::stream::{StreamItem, channel};
use xolotl_kernel::stream::StreamWindow;
use xolotl_types::{IdentityRef, Outcome, ProcessId, TaintSource, UsageDimension, Value};

#[tokio::test]
async fn chat_sse_streams_chunks_and_usage_without_returning_the_complete_text()
-> anyhow::Result<()> {
    let server = spawn_http_once_with_type(
        "200 OK",
        "data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"second\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n",
        "text/event-stream",
    )?;
    let mut config = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    config.base_url = server.base_url.clone();
    let backend = HttpInferenceBackend::new(config)?;
    let (sink, mut receiver) = channel(StreamWindow {
        max_chunks: core::num::NonZeroUsize::MIN,
        ..StreamWindow::default()
    });
    let context = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
    let output = InferenceStream::new(&context);
    let input = Value::string("prompt".into());
    let request = backend.infer_stream(&input, &output);
    let read = async {
        for expected in ["first", "second"] {
            let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
                bail!("missing SSE chunk");
            };
            ensure!(chunk.value == Value::string(expected.into()));
            ensure!(chunk.taint.sources().contains(&TaintSource::ModelOutput));
        }
        Ok::<_, anyhow::Error>(())
    };
    let (result, read) = tokio::join!(request, read);
    read?;
    let result = result.map_err(anyhow::Error::msg)?;
    ensure!(result.outcome == Outcome::Done(Value::null()));
    ensure!(
        result
            .usage
            .as_ref()
            .and_then(|usage| usage.get(&UsageDimension::OUTPUT_TOKENS))
            == Some(&2)
    );
    let captured = recv_request(server)?;
    let body: JsonValue = serde_json::from_str(&captured.body)?;
    ensure!(body.get("stream") == Some(&JsonValue::Bool(true)));
    ensure!(captured.head.contains("text/event-stream"));
    Ok(())
}

#[tokio::test]
async fn chat_sse_reports_a_truncated_response() -> anyhow::Result<()> {
    let server = spawn_http_once_with_type(
        "200 OK",
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n",
        "text/event-stream",
    )?;
    let mut config = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
    config.base_url = server.base_url.clone();
    let backend = HttpInferenceBackend::new(config)?;
    let (sink, _receiver) = channel(StreamWindow::default());
    let context = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
    let error = backend
        .infer_stream(
            &Value::string("prompt".into()),
            &InferenceStream::new(&context),
        )
        .await;
    ensure!(matches!(error, Err(message) if message.contains("completion event")));
    recv_request(server)?;
    Ok(())
}

#[tokio::test]
async fn chat_sse_handles_initial_bom_without_treating_a_second_bom_as_framing()
-> anyhow::Result<()> {
    for body in [
        "\u{feff}data: {\"choices\":[{\"delta\":{\"content\":\"text\"}}]}\n\ndata: [DONE]\n\n",
        "\u{feff}\u{feff}data: ignored\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"text\"}}]}\n\ndata: [DONE]\n\n",
    ] {
        let server = spawn_http_once_with_type("200 OK", body, "text/event-stream")?;
        let mut config = bearer_config(HttpInferenceDialect::OpenAiChatCompletions);
        config.base_url = server.base_url.clone();
        let backend = HttpInferenceBackend::new(config)?;
        let (sink, mut receiver) = channel(StreamWindow::default());
        let context =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
        let result = backend
            .infer_stream(
                &Value::string("prompt".into()),
                &InferenceStream::new(&context),
            )
            .await
            .map_err(anyhow::Error::msg)?;
        ensure!(result.outcome == Outcome::Done(Value::null()));
        let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
            bail!("missing text after BOM");
        };
        ensure!(chunk.value == Value::string("text".into()));
        recv_request(server)?;
    }
    Ok(())
}
