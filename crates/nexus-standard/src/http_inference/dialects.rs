mod anthropic;
mod gemini;
mod openai;

use super::error::HttpInferenceError;
use super::request::validate_overrides;
use nexus_types::{BlobRef, DType, TensorRef, Value};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;

pub(super) use anthropic::{messages_body as anthropic_body, parse_text as parse_anthropic_text};
pub(super) use gemini::{
    embed_body as gemini_embed_body, generate_content_body as gemini_body,
    parse_embedding as parse_gemini_embedding, parse_text as parse_gemini_text,
};
pub(super) use openai::{
    chat_body as openai_chat_body, embedding_body as openai_embedding_body,
    parse_chat_text as parse_openai_chat_text, parse_embedding as parse_openai_embedding,
    parse_responses_text as parse_openai_responses_text, responses_body as openai_responses_body,
};

pub(super) fn wants_json(input: &Value) -> bool {
    input
        .as_map()
        .map(|m| {
            m.get("response_format").and_then(Value::as_str) == Some("json")
                || m.get("json").and_then(Value::as_bool) == Some(true)
        })
        .unwrap_or(false)
}

fn merge_overrides(
    body: &mut JsonMap<String, JsonValue>,
    overrides: &BTreeMap<String, JsonValue>,
) -> Result<(), HttpInferenceError> {
    validate_overrides(overrides)?;
    for (key, value) in overrides {
        body.insert(key.clone(), value.clone());
    }
    Ok(())
}

fn number_from_f64(value: Option<f64>) -> Option<serde_json::Number> {
    value.and_then(serde_json::Number::from_f64)
}

fn vector_value(
    vector: &[JsonValue],
    space_id: &str,
    model: &str,
) -> Result<Value, HttpInferenceError> {
    let mut values = Vec::with_capacity(vector.len());
    let mut hash = blake3::Hasher::new();
    for item in vector {
        let Some(n) = item.as_f64() else {
            return Err(HttpInferenceError::MissingResponseField("embedding number"));
        };
        hash.update(&n.to_le_bytes());
        values.push(Value::Float(nexus_types::FloatBits(n)));
    }
    let digest = hash.finalize();
    let blob = BlobRef {
        hash: digest.to_hex().to_string(),
        size: (vector.len() * std::mem::size_of::<f32>()) as u64,
        mime: Some("application/x-nexus-http-inference-embedding".into()),
    };
    let tensor = TensorRef {
        blob,
        dtype: DType::F32,
        shape: vec![vector.len() as u64],
    };
    let mut map = BTreeMap::new();
    map.insert("tensor".into(), Value::Tensor(tensor));
    map.insert("vector".into(), Value::List(values));
    map.insert("space_id".into(), Value::Str(space_id.to_string()));
    map.insert("embedding_model".into(), Value::Str(model.to_string()));
    Ok(Value::Map(map))
}
