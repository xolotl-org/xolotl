mod anthropic;
mod gemini;
mod openai;

use super::error::HttpInferenceError;
use crate::retrieval::{Embedding, EmbeddingRepresentation};
use serde_json::Value as JsonValue;
use xolotl_types::Value;

pub(super) use anthropic::parse_text as parse_anthropic_text;
pub(super) use gemini::{
    parse_embedding as parse_gemini_embedding, parse_text as parse_gemini_text,
};
pub(super) use openai::{
    parse_chat_text as parse_openai_chat_text, parse_embedding as parse_openai_embedding,
    parse_responses_text as parse_openai_responses_text,
};

#[cfg(test)]
mod tests;

fn take_field(mut value: JsonValue, name: &str) -> Option<JsonValue> {
    value.as_object_mut()?.remove(name)
}

fn take_first(value: JsonValue) -> Option<JsonValue> {
    let JsonValue::Array(items) = value else {
        return None;
    };
    items.into_iter().next()
}

fn append_text(output: &mut String, text: String) {
    if output.is_empty() {
        *output = text;
    } else {
        output.push_str(&text);
    }
}

fn vector_value(
    vector: Vec<JsonValue>,
    space_id: &str,
    model: &str,
) -> Result<Value, HttpInferenceError> {
    let mut values = Vec::with_capacity(vector.len());
    for item in vector {
        let Some(n) = item.as_f64() else {
            return Err(HttpInferenceError::MissingResponseField("embedding number"));
        };
        values.push(Value::float(xolotl_types::FloatBits(n)));
    }
    Ok(Embedding {
        representation: EmbeddingRepresentation::Dense(values.into()),
        space_id: space_id.into(),
        embedding_model: Some(model.into()),
    }
    .into_value())
}
pub(super) mod projection;
