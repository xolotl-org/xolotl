use super::{append_text, take_field};
use crate::http_inference::error::HttpInferenceError;
use serde_json::Value as JsonValue;

pub(in crate::http_inference) fn parse_text(
    response: JsonValue,
) -> Result<String, HttpInferenceError> {
    let Some(JsonValue::Array(content)) = take_field(response, "content") else {
        return Err(HttpInferenceError::MissingResponseField("content"));
    };
    let mut out = String::new();
    for part in content {
        if part.get("type").and_then(JsonValue::as_str) == Some("text")
            && let Some(JsonValue::String(text)) = take_field(part, "text")
        {
            append_text(&mut out, text);
        }
    }
    if out.is_empty() {
        Err(HttpInferenceError::MissingResponseField("content[].text"))
    } else {
        Ok(out)
    }
}
