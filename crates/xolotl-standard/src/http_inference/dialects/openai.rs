use super::{append_text, take_field, take_first, vector_value};
use crate::http_inference::error::HttpInferenceError;
use serde_json::Value as JsonValue;
use xolotl_types::Value;

pub(in crate::http_inference) fn parse_responses_text(
    mut response: JsonValue,
) -> Result<String, HttpInferenceError> {
    if let Some(JsonValue::String(text)) = response.get_mut("output_text").map(JsonValue::take) {
        return Ok(text);
    }
    let Some(JsonValue::Array(output)) = take_field(response, "output") else {
        return Err(HttpInferenceError::MissingResponseField("output_text"));
    };
    let mut out = String::new();
    for item in output {
        let Some(JsonValue::Array(content)) = take_field(item, "content") else {
            continue;
        };
        for part in content {
            if let Some(JsonValue::String(text)) = take_field(part, "text") {
                append_text(&mut out, text);
            }
        }
    }
    if out.is_empty() {
        Err(HttpInferenceError::MissingResponseField(
            "output.content.text",
        ))
    } else {
        Ok(out)
    }
}

pub(in crate::http_inference) fn parse_chat_text(
    response: JsonValue,
) -> Result<String, HttpInferenceError> {
    match take_field(response, "choices")
        .and_then(take_first)
        .and_then(|choice| take_field(choice, "message"))
        .and_then(|message| take_field(message, "content"))
    {
        Some(JsonValue::String(text)) => Ok(text),
        _ => Err(HttpInferenceError::MissingResponseField(
            "choices[0].message.content",
        )),
    }
}

pub(in crate::http_inference) fn parse_embedding(
    response: JsonValue,
    space_id: &str,
    model: &str,
) -> Result<Value, HttpInferenceError> {
    let Some(JsonValue::Array(vector)) = take_field(response, "data")
        .and_then(take_first)
        .and_then(|item| take_field(item, "embedding"))
    else {
        return Err(HttpInferenceError::MissingResponseField(
            "data[0].embedding",
        ));
    };
    vector_value(vector, space_id, model)
}
