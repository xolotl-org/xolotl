//! SSE framing and JSON selection precede atomic record materialization.

use super::backend::HttpInferenceBackend;
use super::config::HttpInferenceDialect;
use super::error::HttpInferenceError;
use super::transport::ResponseKind;
use crate::inference::InferenceStream;
use serde_json::Value as JsonValue;
use xolotl_types::{DriverOutput, DriverUsage, Outcome, UsageDimension, Value};

mod ingress;

impl HttpInferenceBackend {
    pub(super) async fn stream_text(
        &self,
        input: &Value,
        output: &InferenceStream<'_>,
    ) -> Result<DriverOutput, HttpInferenceError> {
        let response = self.generate(input, ResponseKind::EventStream).await?;
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|header| header.to_str().ok());
        if !content_type.is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        }) {
            return Err(HttpInferenceError::Stream(
                "provider did not return text/event-stream".into(),
            ));
        }
        let mut events = ingress::Reader::new(
            response,
            self.config.dialect,
            self.config.response_limits,
            self.config.io_window_bytes.get(),
        );
        let mut state = StreamState::default();
        while let Some(event) = events.next().await? {
            let value = match event {
                ingress::Record::Done => {
                    state.completed = true;
                    break;
                }
                ingress::Record::Json(value) => value,
            };
            let pieces = state.accept(self.config.dialect, &value)?;
            for piece in pieces {
                emit_text(output, piece, self.config.io_window_bytes.get()).await?;
            }
            if state.completed {
                break;
            }
        }
        if !state.completed {
            return Err(HttpInferenceError::Stream(
                "provider closed before its completion event".into(),
            ));
        }
        let mut result = DriverOutput::new(if state.short {
            Outcome::Short(Value::null())
        } else {
            Outcome::Done(Value::null())
        });
        if !state.usage.is_empty() {
            result.usage = Some(state.usage);
        }
        Ok(result)
    }
}

async fn emit_text(
    output: &InferenceStream<'_>,
    mut text: &str,
    window: usize,
) -> Result<(), HttpInferenceError> {
    loop {
        let mut end = window.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        // A Value string owns complete UTF-8 scalars. Even a one-byte working
        // window must offer a complete scalar (at most four bytes) to this port.
        if end == 0 && !text.is_empty() {
            end = text.chars().next().map_or(0, char::len_utf8);
        }
        output
            .emit(Value::string(text[..end].to_owned()))
            .await
            .map_err(HttpInferenceError::Stream)?;
        text = &text[end..];
        if text.is_empty() {
            return Ok(());
        }
    }
}

#[derive(Default)]
struct StreamState {
    completed: bool,
    short: bool,
    usage: DriverUsage,
}

impl StreamState {
    fn accept<'a>(
        &mut self,
        dialect: HttpInferenceDialect,
        value: &'a JsonValue,
    ) -> Result<Vec<&'a str>, HttpInferenceError> {
        if let Some(error) = value.get("error") {
            return Err(HttpInferenceError::Stream(
                error
                    .get("message")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("provider reported an error")
                    .to_string(),
            ));
        }
        let mut pieces = Vec::new();
        match dialect {
            HttpInferenceDialect::OpenAiChatCompletions => {
                self.usage(value.get("usage"), "prompt_tokens", "completion_tokens");
                if let Some(choice) = value
                    .get("choices")
                    .and_then(JsonValue::as_array)
                    .and_then(|choices| choices.first())
                {
                    if let Some(text) = choice.pointer("/delta/content").and_then(JsonValue::as_str)
                    {
                        pieces.push(text);
                    }
                    self.short |=
                        choice.get("finish_reason").and_then(JsonValue::as_str) == Some("length");
                }
            }
            HttpInferenceDialect::OpenAiResponses => {
                match value.get("type").and_then(JsonValue::as_str) {
                    Some("response.output_text.delta") => {
                        let text = value
                            .get("delta")
                            .and_then(JsonValue::as_str)
                            .ok_or(HttpInferenceError::MissingResponseField("delta"))?;
                        pieces.push(text);
                    }
                    Some("response.completed") => self.completed = true,
                    Some("response.incomplete") => {
                        self.completed = true;
                        self.short = true;
                    }
                    Some("response.failed") => {
                        return Err(HttpInferenceError::Stream(
                            "provider response failed".into(),
                        ));
                    }
                    _ => {}
                }
                self.usage(
                    value.pointer("/response/usage"),
                    "input_tokens",
                    "output_tokens",
                );
            }
            HttpInferenceDialect::AnthropicMessages => {
                match value.get("type").and_then(JsonValue::as_str) {
                    Some("content_block_delta") => {
                        if let Some(text) = value.pointer("/delta/text").and_then(JsonValue::as_str)
                        {
                            pieces.push(text);
                        }
                    }
                    Some("message_stop") => self.completed = true,
                    _ => {}
                }
                self.short |= value
                    .pointer("/delta/stop_reason")
                    .and_then(JsonValue::as_str)
                    == Some("max_tokens");
                self.usage(
                    value.pointer("/message/usage"),
                    "input_tokens",
                    "output_tokens",
                );
                self.usage(value.get("usage"), "input_tokens", "output_tokens");
            }
            HttpInferenceDialect::GeminiGenerateContent => {
                self.usage(
                    value.get("usageMetadata"),
                    "promptTokenCount",
                    "candidatesTokenCount",
                );
                if let Some(candidate) = value
                    .get("candidates")
                    .and_then(JsonValue::as_array)
                    .and_then(|candidates| candidates.first())
                {
                    if let Some(parts) = candidate
                        .pointer("/content/parts")
                        .and_then(JsonValue::as_array)
                    {
                        pieces.extend(
                            parts
                                .iter()
                                .filter_map(|part| part.get("text").and_then(JsonValue::as_str)),
                        );
                    }
                    if let Some(reason) = candidate.get("finishReason").and_then(JsonValue::as_str)
                    {
                        match reason {
                            "STOP" => self.completed = true,
                            "MAX_TOKENS" => {
                                self.completed = true;
                                self.short = true;
                            }
                            _ => {
                                return Err(HttpInferenceError::Stream(format!(
                                    "provider finish reason: {reason}"
                                )));
                            }
                        }
                    }
                }
            }
        }
        Ok(pieces)
    }

    fn usage(&mut self, value: Option<&JsonValue>, input: &str, output: &str) {
        let Some(value) = value else {
            return;
        };
        for (field, dimension) in [
            (input, UsageDimension::INPUT_TOKENS),
            (output, UsageDimension::OUTPUT_TOKENS),
        ] {
            if let Some(value) = value.get(field).and_then(JsonValue::as_u64) {
                self.usage
                    .entry(dimension)
                    .and_modify(|current| *current = (*current).max(value))
                    .or_insert(value);
            }
        }
    }
}

#[cfg(test)]
mod tests;
