use super::*;
use anyhow::{Context, ensure};
use serde_json::json;

type TextParser = fn(JsonValue) -> Result<String, HttpInferenceError>;

#[test]
fn single_text_moves_its_existing_allocation() -> anyhow::Result<()> {
    let cases: [(TextParser, JsonValue, &str); 5] = [
        (
            parse_openai_responses_text,
            json!({"output_text": null}),
            "/output_text",
        ),
        (
            parse_openai_responses_text,
            json!({"output": [{"content": [{"text": null}]}]}),
            "/output/0/content/0/text",
        ),
        (
            parse_openai_chat_text,
            json!({"choices": [{"message": {"content": null}}]}),
            "/choices/0/message/content",
        ),
        (
            parse_anthropic_text,
            json!({"content": [{"type": "text", "text": null}]}),
            "/content/0/text",
        ),
        (
            parse_gemini_text,
            json!({"candidates": [{"content": {"parts": [{"text": null}]}}]}),
            "/candidates/0/content/parts/0/text",
        ),
    ];
    for (parse, mut response, path) in cases {
        let mut text = String::with_capacity(256);
        text.push_str("retained response allocation");
        let allocation = text.as_ptr();
        let capacity = text.capacity();
        *response.pointer_mut(path).context("missing text slot")? = JsonValue::String(text);

        let parsed = parse(response)?;
        ensure!(parsed == "retained response allocation");
        ensure!(parsed.as_ptr() == allocation, "copied the string at {path}");
        ensure!(parsed.capacity() == capacity, "discarded string capacity");
    }
    Ok(())
}

#[test]
fn multiple_parts_reuse_the_first_nonempty_allocation_in_order() -> anyhow::Result<()> {
    let cases: [(TextParser, JsonValue, &str); 3] = [
        (
            parse_openai_responses_text,
            json!({
                "output_text": false,
                "output": [
                    {"content": [{"text": ""}, {"text": null}]},
                    {"content": [{"refusal": "ignored"}, {"text": "second"}, {"text": " third"}]}
                ]
            }),
            "/output/0/content/1/text",
        ),
        (
            parse_anthropic_text,
            json!({"content": [
                {"type": "text", "text": ""},
                {"type": "text", "text": null},
                {"type": "tool_use", "text": "ignored"},
                {"type": "text", "text": "second"},
                {"type": "text", "text": " third"}
            ]}),
            "/content/1/text",
        ),
        (
            parse_gemini_text,
            json!({"candidates": [
                {"content": {"parts": [
                    {"text": ""}, {"text": null}, {"inlineData": {"data": "ignored"}},
                    {"text": "second"}, {"text": " third"}
                ]}},
                {"content": {"parts": [{"text": "ignored candidate"}]}}
            ]}),
            "/candidates/0/content/parts/1/text",
        ),
    ];
    for (parse, mut response, path) in cases {
        let mut text = String::with_capacity(256);
        text.push_str("first ");
        let allocation = text.as_ptr();
        *response.pointer_mut(path).context("missing text slot")? = JsonValue::String(text);

        let parsed = parse(response)?;
        ensure!(parsed == "first second third");
        ensure!(
            parsed.as_ptr() == allocation,
            "replaced the first text buffer"
        );
    }
    Ok(())
}

#[test]
fn direct_empty_text_remains_present_output() -> anyhow::Result<()> {
    ensure!(
        parse_openai_responses_text(json!({
            "output_text": "",
            "output": [{"content": [{"text": "unused fallback"}]}]
        }))?
        .is_empty()
    );
    ensure!(
        parse_openai_chat_text(json!({"choices": [
            {"message": {"content": ""}},
            {"message": {"content": "unused choice"}}
        ]}))?
        .is_empty()
    );
    Ok(())
}

#[test]
fn malformed_or_empty_text_preserves_missing_field_errors() -> anyhow::Result<()> {
    let cases: [(TextParser, JsonValue, &str); 12] = [
        (parse_openai_responses_text, json!({}), "output_text"),
        (
            parse_openai_responses_text,
            json!({"output": {"0": {"content": [{"text": "wrong array"}]}}}),
            "output_text",
        ),
        (
            parse_openai_responses_text,
            json!({"output": [{"content": [{"text": ""}, {"text": null}]}]}),
            "output.content.text",
        ),
        (
            parse_openai_chat_text,
            json!({"choices": [{}, {"message": {"content": "unused choice"}}]}),
            "choices[0].message.content",
        ),
        (
            parse_openai_chat_text,
            json!({"choices": {"0": {"message": {"content": "wrong array"}}}}),
            "choices[0].message.content",
        ),
        (
            parse_openai_chat_text,
            json!({"choices": [{"message": {"content": [{"text": "wrong type"}]}}]}),
            "choices[0].message.content",
        ),
        (parse_anthropic_text, json!({}), "content"),
        (
            parse_anthropic_text,
            json!({"content": [{"type": "text", "text": ""}, {"type": "tool_use", "text": "ignored"}]}),
            "content[].text",
        ),
        (parse_gemini_text, json!({}), "candidates[0].content.parts"),
        (
            parse_gemini_text,
            json!({"candidates": [{}, {"content": {"parts": [{"text": "unused candidate"}]}}]}),
            "candidates[0].content.parts",
        ),
        (
            parse_gemini_text,
            json!({"candidates": {"0": {"content": {"parts": [{"text": "wrong array"}]}}}}),
            "candidates[0].content.parts",
        ),
        (
            parse_gemini_text,
            json!({"candidates": [{"content": {"parts": [{"text": ""}, {"inlineData": {}}]}}]}),
            "parts[].text",
        ),
    ];
    for (parse, response, field) in cases {
        let result = parse(response);
        ensure!(
            matches!(result, Err(HttpInferenceError::MissingResponseField(actual)) if actual == field),
            "expected missing {field}, received {result:?}"
        );
    }
    Ok(())
}

#[test]
fn embeddings_keep_first_inline_vector_without_inventing_object_metadata() -> anyhow::Result<()> {
    let openai = parse_openai_embedding(
        json!({"data": [{"embedding": [1.25, -2.0, 3.5]}, {"embedding": ["ignored"]}]}),
        "embedding/test",
        "model",
    )?;
    let gemini = parse_gemini_embedding(
        json!({"embedding": {"values": [1.25, -2.0, 3.5]}}),
        "embedding/test",
        "model",
    )?;
    ensure!(openai == gemini);
    let map = openai.as_map().context("missing embedding map")?;
    let Some(representation) = map.get("representation").and_then(Value::as_map) else {
        anyhow::bail!("missing embedding representation");
    };
    ensure!(representation.get("kind").and_then(Value::as_str) == Some("dense"));
    let Some(vector) = representation.get("values").and_then(Value::as_list) else {
        anyhow::bail!("embedding vector has wrong type");
    };
    ensure!(map.get("tensor").is_none());
    ensure!(map.get("space_id").and_then(Value::as_str) == Some("embedding/test"));
    ensure!(map.get("embedding_model").and_then(Value::as_str) == Some("model"));
    ensure!(
        vector.iter().eq([1.25_f64, -2.0, 3.5]
            .map(|number| Value::float(xolotl_types::FloatBits(number)))
            .iter())
    );
    Ok(())
}

#[tokio::test]
async fn http_embeddings_materialize_the_selected_numeric_representation() -> anyhow::Result<()> {
    let expected = [
        1.0 + f64::EPSILON,
        -0.0,
        f32::MAX as f64 / 2.0,
        f64::MIN_POSITIVE,
    ];
    for embedding in [
        parse_openai_embedding(
            json!({"data": [{"embedding": expected}]}),
            "http/test",
            "model",
        )?,
        parse_gemini_embedding(
            json!({"embedding": {"values": expected}}),
            "http/test",
            "model",
        )?,
    ] {
        crate::retrieval::tests::assert_materialized_embedding(embedding, &expected).await?;
    }
    Ok(())
}

#[test]
fn embeddings_distinguish_empty_vectors_from_invalid_elements() -> anyhow::Result<()> {
    let empty = parse_openai_embedding(json!({"data": [{"embedding": []}]}), "space", "model")?;
    ensure!(
        empty
            .as_map()
            .and_then(|map| map.get("representation"))
            .and_then(Value::as_map)
            .and_then(|map| map.get("values"))
            == Some(&Value::list(Vec::new()))
    );
    for result in [
        parse_openai_embedding(
            json!({"data": [{"embedding": [1, null]}]}),
            "space",
            "model",
        ),
        parse_gemini_embedding(json!({"embedding": {"values": ["1"]}}), "space", "model"),
    ] {
        ensure!(matches!(
            result,
            Err(HttpInferenceError::MissingResponseField("embedding number"))
        ));
    }
    ensure!(matches!(
        parse_openai_embedding(json!({"data": [{}, {"embedding": []}]}), "space", "model"),
        Err(HttpInferenceError::MissingResponseField(
            "data[0].embedding"
        ))
    ));
    ensure!(matches!(
        parse_gemini_embedding(json!({"embedding": {"values": null}}), "space", "model"),
        Err(HttpInferenceError::MissingResponseField("embedding.values"))
    ));
    Ok(())
}
