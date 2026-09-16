//! Provider envelopes own shared inputs and are encoded only as HTTP pulls.

use super::validate_overrides;
use crate::http_inference::config::{HttpInferenceConfig, HttpInferenceDialect};
use crate::http_inference::error::HttpInferenceError;
use crate::inference::RenderedText;
use serde::{Serialize, Serializer};
use xolotl_types::Value;

mod cursor;
pub(in crate::http_inference) use cursor::Body;
use cursor::Step;

pub(in crate::http_inference) fn encode_generation(
    config: &HttpInferenceConfig,
    input: &Value,
    streaming: bool,
) -> Result<Body, HttpInferenceError> {
    validate_overrides(&config.options.request_overrides)?;
    let mut steps = vec![Step::raw("{")];
    let options = &config.options;
    let dialect = config.dialect;
    if dialect != HttpInferenceDialect::GeminiGenerateContent {
        steps.extend([
            Step::raw("\"model\":"),
            Step::string(config.model.clone()),
            Step::raw(","),
        ]);
    }
    match dialect {
        HttpInferenceDialect::OpenAiResponses => {
            steps.extend([
                Step::raw("\"input\":"),
                Step::text(input.clone()),
                Step::raw(",\"store\":false"),
            ]);
            if let Some(max) = options.max_output_tokens {
                number_field(&mut steps, ",\"max_output_tokens\":", max)?;
            }
            if wants_json(input) && options.json_mode {
                steps.push(Step::raw(
                    ",\"text\":{\"format\":{\"type\":\"json_object\"}}",
                ));
            }
        }
        HttpInferenceDialect::OpenAiChatCompletions | HttpInferenceDialect::AnthropicMessages => {
            steps.extend([
                Step::raw("\"messages\":[{\"role\":\"user\",\"content\":"),
                Step::text(input.clone()),
                Step::raw("}]"),
            ]);
            let max = if dialect == HttpInferenceDialect::AnthropicMessages {
                Some(options.max_output_tokens.unwrap_or(1024))
            } else {
                options.max_output_tokens
            };
            if let Some(max) = max {
                number_field(&mut steps, ",\"max_tokens\":", max)?;
            }
            if dialect == HttpInferenceDialect::OpenAiChatCompletions
                && wants_json(input)
                && options.json_mode
            {
                steps.push(Step::raw(",\"response_format\":{\"type\":\"json_object\"}"));
            }
        }
        HttpInferenceDialect::GeminiGenerateContent => {
            steps.extend([
                Step::raw("\"contents\":[{\"parts\":[{\"text\":"),
                Step::text(input.clone()),
                Step::raw("}]}]"),
            ]);
            if options.max_output_tokens.is_some()
                || options.temperature.is_some()
                || (options.json_mode && wants_json(input))
            {
                steps.push(Step::raw(",\"generationConfig\":{"));
                let mut comma = false;
                if let Some(max) = options.max_output_tokens {
                    number_field(&mut steps, "\"maxOutputTokens\":", max)?;
                    comma = true;
                }
                if let Some(temperature) = options.temperature.filter(|value| value.is_finite()) {
                    if comma {
                        steps.push(Step::raw(","));
                    }
                    number_field(&mut steps, "\"temperature\":", temperature)?;
                    comma = true;
                }
                if options.json_mode {
                    if comma {
                        steps.push(Step::raw(","));
                    }
                    steps.push(Step::raw("\"responseMimeType\":\"application/json\""));
                }
                steps.push(Step::raw("}"));
            }
        }
    }
    if dialect != HttpInferenceDialect::GeminiGenerateContent {
        if let Some(temperature) = options.temperature.filter(|value| value.is_finite()) {
            number_field(&mut steps, ",\"temperature\":", temperature)?;
        }
        if streaming {
            steps.push(Step::raw(",\"stream\":true"));
        }
    }
    let force_usage = streaming && dialect == HttpInferenceDialect::OpenAiChatCompletions;
    steps.push(Step::overrides(
        options.request_overrides.clone(),
        force_usage,
    ));
    if force_usage {
        steps.push(Step::raw(",\"stream_options\":{\"include_usage\":true}"));
    }
    steps.push(Step::raw("}"));
    Ok(Body::new(steps, config.io_window_bytes))
}

pub(in crate::http_inference) fn encode_embedding(
    config: &HttpInferenceConfig,
    model: &str,
    input: &Value,
) -> Result<Body, HttpInferenceError> {
    if config.dialect == HttpInferenceDialect::AnthropicMessages {
        return Err(HttpInferenceError::EmbedUnsupported);
    }
    let steps = if config.dialect == HttpInferenceDialect::GeminiGenerateContent {
        vec![
            Step::raw("{\"model\":\"models/"),
            Step::escaped(model.to_owned()),
            Step::raw("\",\"content\":{\"parts\":[{\"text\":"),
            Step::text(input.clone()),
            Step::raw("}]}}"),
        ]
    } else {
        vec![
            Step::raw("{\"model\":"),
            Step::string(model.to_owned()),
            Step::raw(",\"input\":"),
            Step::text(input.clone()),
            Step::raw("}"),
        ]
    };
    Ok(Body::new(steps, config.io_window_bytes))
}

fn number_field(
    steps: &mut Vec<Step>,
    name: &'static str,
    number: impl Serialize,
) -> Result<(), HttpInferenceError> {
    steps.extend([Step::raw(name), Step::number(number)?]);
    Ok(())
}

fn wants_json(input: &Value) -> bool {
    input.as_map().is_some_and(|map| {
        map.get("response_format").and_then(Value::as_str) == Some("json")
            || map.get("json").and_then(Value::as_bool) == Some(true)
    })
}

impl Serialize for RenderedText<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests;
