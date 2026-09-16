use super::*;
use anyhow::ensure;

#[test]
fn provider_deltas_preserve_usage_and_completion_without_accumulation() -> anyhow::Result<()> {
    let mut responses = StreamState::default();
    let delta = serde_json::json!({"type":"response.output_text.delta","delta":"text"});
    for _ in 0..1024 {
        ensure!(responses.accept(HttpInferenceDialect::OpenAiResponses, &delta)? == ["text"]);
    }
    let completed = serde_json::json!({"type":"response.completed","response":{"usage":{"input_tokens":9,"output_tokens":1024}}});
    ensure!(
        responses
            .accept(HttpInferenceDialect::OpenAiResponses, &completed)?
            .is_empty()
    );
    ensure!(responses.completed);
    ensure!(responses.usage.get(&UsageDimension::OUTPUT_TOKENS) == Some(&1024));

    let mut chat = StreamState::default();
    ensure!(
        chat.accept(
            HttpInferenceDialect::OpenAiChatCompletions,
            &serde_json::json!({"choices":[{"delta":{"content":"part"},"finish_reason":"length"}]})
        )? == ["part"]
    );
    ensure!(chat.short && !chat.completed);

    let mut anthropic = StreamState::default();
    ensure!(anthropic.accept(HttpInferenceDialect::AnthropicMessages,
        &serde_json::json!({"type":"content_block_delta","delta":{"type":"text_delta","text":"part"}}))? == ["part"]);
    anthropic.accept(HttpInferenceDialect::AnthropicMessages,
        &serde_json::json!({"type":"message_delta","usage":{"output_tokens":7},"delta":{"stop_reason":"end_turn"}}))?;
    anthropic.accept(
        HttpInferenceDialect::AnthropicMessages,
        &serde_json::json!({"type":"message_stop"}),
    )?;
    ensure!(anthropic.completed && anthropic.usage.get(&UsageDimension::OUTPUT_TOKENS) == Some(&7));

    let mut gemini = StreamState::default();
    ensure!(gemini.accept(HttpInferenceDialect::GeminiGenerateContent,
        &serde_json::json!({"candidates":[{"content":{"parts":[{"text":"part"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":8}}))? == ["part"]);
    ensure!(gemini.completed && gemini.usage.get(&UsageDimension::INPUT_TOKENS) == Some(&4));
    Ok(())
}
