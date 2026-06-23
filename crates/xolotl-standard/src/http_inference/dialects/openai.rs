use super::{merge_overrides, number_from_f64, vector_value};
use crate::http_inference::config::HttpInferenceConfig;
use crate::http_inference::error::HttpInferenceError;
use crate::inference::render_text;
use serde_json::{Map as JsonMap, Value as JsonValue};
use xolotl_types::Value;

pub(in crate::http_inference) fn responses_body(
    config: &HttpInferenceConfig,
    input: &Value,
    wants_json: bool,
) -> Result<JsonValue, HttpInferenceError> {
    let mut body = JsonMap::new();
    body.insert("model".into(), JsonValue::String(config.model.clone()));
    body.insert("input".into(), JsonValue::String(render_text(input)));
    body.insert("store".into(), JsonValue::Bool(false));
    if let Some(max) = config.options.max_output_tokens {
        body.insert("max_output_tokens".into(), JsonValue::Number(max.into()));
    }
    if let Some(temp) = number_from_f64(config.options.temperature) {
        body.insert("temperature".into(), JsonValue::Number(temp));
    }
    if wants_json && config.options.json_mode {
        let mut text = JsonMap::new();
        text.insert(
            "format".into(),
            JsonValue::Object(JsonMap::from_iter([(
                "type".into(),
                JsonValue::String("json_object".into()),
            )])),
        );
        body.insert("text".into(), JsonValue::Object(text));
    }
    merge_overrides(&mut body, &config.options.request_overrides)?;
    Ok(JsonValue::Object(body))
}

pub(in crate::http_inference) fn chat_body(
    config: &HttpInferenceConfig,
    input: &Value,
    wants_json: bool,
) -> Result<JsonValue, HttpInferenceError> {
    let mut body = JsonMap::new();
    body.insert("model".into(), JsonValue::String(config.model.clone()));
    body.insert(
        "messages".into(),
        JsonValue::Array(vec![JsonValue::Object(JsonMap::from_iter([
            ("role".into(), JsonValue::String("user".into())),
            ("content".into(), JsonValue::String(render_text(input))),
        ]))]),
    );
    if let Some(max) = config.options.max_output_tokens {
        body.insert("max_tokens".into(), JsonValue::Number(max.into()));
    }
    if let Some(temp) = number_from_f64(config.options.temperature) {
        body.insert("temperature".into(), JsonValue::Number(temp));
    }
    if wants_json && config.options.json_mode {
        body.insert(
            "response_format".into(),
            JsonValue::Object(JsonMap::from_iter([(
                "type".into(),
                JsonValue::String("json_object".into()),
            )])),
        );
    }
    merge_overrides(&mut body, &config.options.request_overrides)?;
    Ok(JsonValue::Object(body))
}

pub(in crate::http_inference) fn embedding_body(model: &str, input: &Value) -> JsonValue {
    JsonValue::Object(JsonMap::from_iter([
        ("model".into(), JsonValue::String(model.to_string())),
        ("input".into(), JsonValue::String(render_text(input))),
    ]))
}

pub(in crate::http_inference) fn parse_responses_text(
    response: &JsonValue,
) -> Result<String, HttpInferenceError> {
    if let Some(text) = response.get("output_text").and_then(JsonValue::as_str) {
        return Ok(text.to_string());
    }
    let Some(output) = response.get("output").and_then(JsonValue::as_array) else {
        return Err(HttpInferenceError::MissingResponseField("output_text"));
    };
    let mut out = String::new();
    for item in output {
        let Some(content) = item.get("content").and_then(JsonValue::as_array) else {
            continue;
        };
        for part in content {
            if let Some(text) = part.get("text").and_then(JsonValue::as_str) {
                out.push_str(text);
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
    response: &JsonValue,
) -> Result<String, HttpInferenceError> {
    response
        .get("choices")
        .and_then(JsonValue::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or(HttpInferenceError::MissingResponseField(
            "choices[0].message.content",
        ))
}

pub(in crate::http_inference) fn parse_embedding(
    response: &JsonValue,
    space_id: &str,
    model: &str,
) -> Result<Value, HttpInferenceError> {
    let Some(vector) = response
        .get("data")
        .and_then(JsonValue::as_array)
        .and_then(|data| data.first())
        .and_then(|item| item.get("embedding"))
        .and_then(JsonValue::as_array)
    else {
        return Err(HttpInferenceError::MissingResponseField(
            "data[0].embedding",
        ));
    };
    vector_value(vector, space_id, model)
}
