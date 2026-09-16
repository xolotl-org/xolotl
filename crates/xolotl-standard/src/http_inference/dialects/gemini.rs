use super::{append_text, take_field, take_first, vector_value};
use crate::http_inference::error::HttpInferenceError;
use serde_json::Value as JsonValue;
use xolotl_types::Value;

pub(in crate::http_inference) fn parse_text(
    response: JsonValue,
) -> Result<String, HttpInferenceError> {
    let Some(JsonValue::Array(parts)) = take_field(response, "candidates")
        .and_then(take_first)
        .and_then(|candidate| take_field(candidate, "content"))
        .and_then(|content| take_field(content, "parts"))
    else {
        return Err(HttpInferenceError::MissingResponseField(
            "candidates[0].content.parts",
        ));
    };
    let mut out = String::new();
    for part in parts {
        if let Some(JsonValue::String(text)) = take_field(part, "text") {
            append_text(&mut out, text);
        }
    }
    if out.is_empty() {
        Err(HttpInferenceError::MissingResponseField("parts[].text"))
    } else {
        Ok(out)
    }
}

pub(in crate::http_inference) fn parse_embedding(
    response: JsonValue,
    space_id: &str,
    model: &str,
) -> Result<Value, HttpInferenceError> {
    let Some(JsonValue::Array(vector)) =
        take_field(response, "embedding").and_then(|embedding| take_field(embedding, "values"))
    else {
        return Err(HttpInferenceError::MissingResponseField("embedding.values"));
    };
    vector_value(vector, space_id, model)
}
