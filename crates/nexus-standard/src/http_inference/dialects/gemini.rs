use super::{merge_overrides, number_from_f64, vector_value, wants_json};
use crate::http_inference::config::HttpInferenceConfig;
use crate::http_inference::error::HttpInferenceError;
use crate::inference::render_text;
use nexus_types::Value;
use serde_json::{Map as JsonMap, Value as JsonValue};

pub(in crate::http_inference) fn generate_content_body(
    config: &HttpInferenceConfig,
    input: &Value,
) -> Result<JsonValue, HttpInferenceError> {
    let mut body = JsonMap::new();
    body.insert(
        "contents".into(),
        JsonValue::Array(vec![JsonValue::Object(JsonMap::from_iter([(
            "parts".into(),
            JsonValue::Array(vec![JsonValue::Object(JsonMap::from_iter([(
                "text".into(),
                JsonValue::String(render_text(input)),
            )]))]),
        )]))]),
    );
    if config.options.max_output_tokens.is_some()
        || config.options.temperature.is_some()
        || (config.options.json_mode && wants_json(input))
    {
        let mut generation = JsonMap::new();
        if let Some(max) = config.options.max_output_tokens {
            generation.insert("maxOutputTokens".into(), JsonValue::Number(max.into()));
        }
        if let Some(temp) = number_from_f64(config.options.temperature) {
            generation.insert("temperature".into(), JsonValue::Number(temp));
        }
        if config.options.json_mode {
            generation.insert(
                "responseMimeType".into(),
                JsonValue::String("application/json".into()),
            );
        }
        body.insert("generationConfig".into(), JsonValue::Object(generation));
    }
    merge_overrides(&mut body, &config.options.request_overrides)?;
    Ok(JsonValue::Object(body))
}

pub(in crate::http_inference) fn embed_body(model: &str, input: &Value) -> JsonValue {
    JsonValue::Object(JsonMap::from_iter([
        ("model".into(), JsonValue::String(format!("models/{model}"))),
        (
            "content".into(),
            JsonValue::Object(JsonMap::from_iter([(
                "parts".into(),
                JsonValue::Array(vec![JsonValue::Object(JsonMap::from_iter([(
                    "text".into(),
                    JsonValue::String(render_text(input)),
                )]))]),
            )])),
        ),
    ]))
}

pub(in crate::http_inference) fn parse_text(
    response: &JsonValue,
) -> Result<String, HttpInferenceError> {
    let Some(parts) = response
        .get("candidates")
        .and_then(JsonValue::as_array)
        .and_then(|candidates| candidates.first())
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(JsonValue::as_array)
    else {
        return Err(HttpInferenceError::MissingResponseField(
            "candidates[0].content.parts",
        ));
    };
    let mut out = String::new();
    for part in parts {
        if let Some(text) = part.get("text").and_then(JsonValue::as_str) {
            out.push_str(text);
        }
    }
    if out.is_empty() {
        Err(HttpInferenceError::MissingResponseField("parts[].text"))
    } else {
        Ok(out)
    }
}

pub(in crate::http_inference) fn parse_embedding(
    response: &JsonValue,
    space_id: &str,
    model: &str,
) -> Result<Value, HttpInferenceError> {
    let Some(vector) = response
        .get("embedding")
        .and_then(|embedding| embedding.get("values"))
        .and_then(JsonValue::as_array)
    else {
        return Err(HttpInferenceError::MissingResponseField("embedding.values"));
    };
    vector_value(vector, space_id, model)
}
