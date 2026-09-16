use super::*;
use crate::http_inference::config::HttpInferenceAuth;
use crate::inference::render_text;
use anyhow::ensure;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value as JsonValue, json};
use std::collections::BTreeMap;
use std::fmt;

mod pull;

fn config(dialect: HttpInferenceDialect) -> HttpInferenceConfig {
    HttpInferenceConfig::new(
        "test",
        dialect,
        "https://example.test/v1",
        "model-1",
        HttpInferenceAuth::None,
    )
}

fn encode_generation(
    config: &HttpInferenceConfig,
    input: &Value,
    streaming: bool,
) -> Result<Vec<u8>, HttpInferenceError> {
    collect(super::encode_generation(config, input, streaming)?)
}

fn encode_embedding(
    config: &HttpInferenceConfig,
    model: &str,
    input: &Value,
) -> Result<Vec<u8>, HttpInferenceError> {
    collect(super::encode_embedding(config, model, input)?)
}

fn collect(mut body: Body) -> Result<Vec<u8>, HttpInferenceError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next()? {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[test]
fn generation_preserves_dialect_defaults_and_configured_payloads() -> anyhow::Result<()> {
    let cases = [
        (
            HttpInferenceDialect::OpenAiResponses,
            json!({"model":"model-1","input":"prompt","store":false}),
            json!({
                "model":"model-1","input":"prompt","store":false,
                "max_output_tokens":77,"temperature":0.25,
                "text":{"format":{"type":"json_object"}},"seed":42
            }),
        ),
        (
            HttpInferenceDialect::OpenAiChatCompletions,
            json!({"model":"model-1","messages":[{"role":"user","content":"prompt"}]}),
            json!({
                "model":"model-1","messages":[{"role":"user","content":"prompt"}],
                "max_tokens":77,"temperature":0.25,
                "response_format":{"type":"json_object"},"seed":42
            }),
        ),
        (
            HttpInferenceDialect::AnthropicMessages,
            json!({"model":"model-1","max_tokens":1024,"messages":[{"role":"user","content":"prompt"}]}),
            json!({
                "model":"model-1","messages":[{"role":"user","content":"prompt"}],
                "max_tokens":77,"temperature":0.25,"seed":42
            }),
        ),
        (
            HttpInferenceDialect::GeminiGenerateContent,
            json!({"contents":[{"parts":[{"text":"prompt"}]}]}),
            json!({
                "contents":[{"parts":[{"text":"prompt"}]}],
                "generationConfig":{"maxOutputTokens":77,"temperature":0.25,"responseMimeType":"application/json"},
                "seed":42
            }),
        ),
    ];
    for (dialect, defaults, configured) in cases {
        let mut config = config(dialect);
        let encoded = encode_generation(&config, &Value::string("prompt".into()), false)?;
        ensure!(serde_json::from_slice::<JsonValue>(&encoded)? == defaults);
        config.options.max_output_tokens = Some(77);
        config.options.temperature = Some(0.25);
        config.options.json_mode = true;
        config
            .options
            .request_overrides
            .insert("seed".into(), Value::integer(42))?;
        let input = Value::map(BTreeMap::from([
            ("prompt".into(), Value::string("prompt".into())),
            ("json".into(), Value::boolean(true)),
        ]));
        for streaming in [false, true] {
            let mut expected = configured.clone();
            if streaming && dialect != HttpInferenceDialect::GeminiGenerateContent {
                expected["stream"] = json!(true);
            }
            if streaming && dialect == HttpInferenceDialect::OpenAiChatCompletions {
                expected["stream_options"] = json!({"include_usage":true});
            }
            let encoded = encode_generation(&config, &input, streaming)?;
            ensure!(
                serde_json::from_slice::<JsonValue>(&encoded)? == expected,
                "unexpected request for {dialect:?}, streaming={streaming}"
            );
        }
    }
    Ok(())
}

#[test]
fn borrowed_text_preserves_rendering_and_json_escaping() -> anyhow::Result<()> {
    let inputs = [
        (
            Value::string("quotes: \"\\ \n\t\r\0 \u{4e2d}".into()),
            "quotes: \"\\ \n\t\r\0 \u{4e2d}",
        ),
        (
            Value::list(vec![
                Value::string(String::new()),
                Value::list(vec![Value::string("nested".into()), Value::integer(7)]),
                Value::boolean(true),
                Value::list(Vec::new()),
            ]),
            " nested Int(7) Bool(true) ",
        ),
        (
            Value::map(BTreeMap::from([
                ("text".into(), Value::null()),
                ("prompt".into(), Value::string("not selected".into())),
            ])),
            "Null",
        ),
        (
            Value::map(BTreeMap::from([(
                "prompt".into(),
                Value::list(vec![Value::string("from map".into()), Value::integer(-3)]),
            )])),
            "from map Int(-3)",
        ),
        (
            Value::map(BTreeMap::from([(
                "other".into(),
                Value::string("debug\ntext".into()),
            )])),
            "Map { len: 1 }",
        ),
        (Value::null(), "Null"),
    ];
    for (input, expected) in inputs {
        let encoded = serde_json::to_vec(&RenderedText(&input))?;
        ensure!(serde_json::from_slice::<String>(&encoded)? == expected);
        ensure!(render_text(&input) == expected);
    }
    Ok(())
}

#[test]
fn json_mode_preserves_request_gating_and_gemini_sampling_behavior() -> anyhow::Result<()> {
    for dialect in [
        HttpInferenceDialect::OpenAiResponses,
        HttpInferenceDialect::OpenAiChatCompletions,
        HttpInferenceDialect::GeminiGenerateContent,
    ] {
        let mut config = config(dialect);
        let input = Value::map(BTreeMap::from([
            ("text".into(), Value::string("prompt".into())),
            ("response_format".into(), Value::string("json".into())),
        ]));
        let body: JsonValue = serde_json::from_slice(&encode_generation(&config, &input, false)?)?;
        ensure!(body.get("text").is_none());
        ensure!(body.get("response_format").is_none());
        ensure!(body.get("generationConfig").is_none());
        config.options.json_mode = true;
        let plain = Value::string("prompt".into());
        let body: JsonValue = serde_json::from_slice(&encode_generation(&config, &plain, false)?)?;
        ensure!(body.get("text").is_none());
        ensure!(body.get("response_format").is_none());
        ensure!(body.get("generationConfig").is_none());
        if dialect == HttpInferenceDialect::GeminiGenerateContent {
            config.options.temperature = Some(0.5);
            let body: JsonValue =
                serde_json::from_slice(&encode_generation(&config, &plain, false)?)?;
            ensure!(
                body["generationConfig"]
                    == json!({"temperature":0.5,"responseMimeType":"application/json"})
            );
        }
    }
    Ok(())
}

#[test]
fn chat_stream_options_are_overridden_without_duplicate_keys() -> anyhow::Result<()> {
    let mut config = config(HttpInferenceDialect::OpenAiChatCompletions);
    let overridden = json!({"include_usage":false,"vendor":true});
    config.options.request_overrides.insert(
        "stream_options".into(),
        serde_json::from_value(overridden.clone())?,
    )?;
    config.options.request_overrides.insert(
        "Stream_Options".into(),
        Value::string("case sensitive".into()),
    )?;
    let input = Value::string("prompt".into());
    let unary: JsonValue = serde_json::from_slice(&encode_generation(&config, &input, false)?)?;
    ensure!(unary["stream_options"] == overridden);
    let encoded = encode_generation(&config, &input, true)?;
    let streamed: JsonValue = serde_json::from_slice(&encoded)?;
    ensure!(streamed["stream_options"] == json!({"include_usage":true}));
    ensure!(streamed["Stream_Options"] == json!("case sensitive"));
    let keys: TopLevelKeys = serde_json::from_slice(&encoded)?;
    ensure!(keys.0.iter().filter(|key| *key == "stream_options").count() == 1);
    ensure!(keys.0.iter().filter(|key| *key == "stream").count() == 1);
    Ok(())
}

#[test]
fn generation_rejects_reserved_or_sensitive_overrides() -> anyhow::Result<()> {
    for (key, value) in [
        ("model", json!("other")),
        ("StReAm", json!(false)),
        ("vendor", json!({"api_key":"secret"})),
    ] {
        let mut config = config(HttpInferenceDialect::OpenAiResponses);
        config
            .options
            .request_overrides
            .insert(key.into(), serde_json::from_value(value)?)?;
        ensure!(matches!(
            encode_generation(&config, &Value::string("prompt".into()), false),
            Err(HttpInferenceError::ReservedRequestField(_))
        ));
    }
    Ok(())
}

#[test]
fn embedding_preserves_dialect_payloads_without_generation_options() -> anyhow::Result<()> {
    let model = "embed\"\\\n\u{4e2d}";
    let input = Value::list(vec![
        Value::string("first".into()),
        Value::string("second".into()),
    ]);
    for dialect in [
        HttpInferenceDialect::OpenAiResponses,
        HttpInferenceDialect::OpenAiChatCompletions,
        HttpInferenceDialect::GeminiGenerateContent,
    ] {
        let mut config = config(dialect);
        config.options.max_output_tokens = Some(77);
        config.options.json_mode = true;
        config
            .options
            .request_overrides
            .insert("seed".into(), Value::integer(42))?;
        let expected = match dialect {
            HttpInferenceDialect::GeminiGenerateContent => json!({
                "model":format!("models/{model}"),
                "content":{"parts":[{"text":"first second"}]}
            }),
            _ => json!({"model":model,"input":"first second"}),
        };
        let encoded = encode_embedding(&config, model, &input)?;
        ensure!(serde_json::from_slice::<JsonValue>(&encoded)? == expected);
    }
    ensure!(matches!(
        encode_embedding(
            &config(HttpInferenceDialect::AnthropicMessages),
            model,
            &input
        ),
        Err(HttpInferenceError::EmbedUnsupported)
    ));
    Ok(())
}

struct TopLevelKeys(Vec<String>);

impl<'de> Deserialize<'de> for TopLevelKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeysVisitor;

        impl<'de> Visitor<'de> for KeysVisitor {
            type Value = TopLevelKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = map.next_key()? {
                    keys.push(key);
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(TopLevelKeys(keys))
            }
        }

        deserializer.deserialize_map(KeysVisitor)
    }
}
