use super::{merge_overrides, number_from_f64};
use crate::http_inference::config::HttpInferenceConfig;
use crate::http_inference::error::HttpInferenceError;
use crate::inference::render_text;
use andrias_types::Value;
use serde_json::{Map as JsonMap, Value as JsonValue};

pub(in crate::http_inference) fn messages_body(
    config: &HttpInferenceConfig,
    input: &Value,
) -> Result<JsonValue, HttpInferenceError> {
    let mut body = JsonMap::new();
    body.insert("model".into(), JsonValue::String(config.model.clone()));
    body.insert(
        "max_tokens".into(),
        JsonValue::Number(config.options.max_output_tokens.unwrap_or(1024).into()),
    );
    body.insert(
        "messages".into(),
        JsonValue::Array(vec![JsonValue::Object(JsonMap::from_iter([
            ("role".into(), JsonValue::String("user".into())),
            ("content".into(), JsonValue::String(render_text(input))),
        ]))]),
    );
    if let Some(temp) = number_from_f64(config.options.temperature) {
        body.insert("temperature".into(), JsonValue::Number(temp));
    }
    merge_overrides(&mut body, &config.options.request_overrides)?;
    Ok(JsonValue::Object(body))
}

pub(in crate::http_inference) fn parse_text(
    response: &JsonValue,
) -> Result<String, HttpInferenceError> {
    let Some(content) = response.get("content").and_then(JsonValue::as_array) else {
        return Err(HttpInferenceError::MissingResponseField("content"));
    };
    let mut out = String::new();
    for part in content {
        if part.get("type").and_then(JsonValue::as_str) == Some("text")
            && let Some(text) = part.get("text").and_then(JsonValue::as_str)
        {
            out.push_str(text);
        }
    }
    if out.is_empty() {
        Err(HttpInferenceError::MissingResponseField("content[].text"))
    } else {
        Ok(out)
    }
}
