use super::*;
use anyhow::Context;

#[test]
fn pull_requests_preserve_escaping_at_one_byte_windows() -> anyhow::Result<()> {
    let input = Value::list(vec![
        Value::string("a\"\\\n\t\r\0中𝄞".into()),
        Value::integer(7),
    ]);
    for dialect in [
        HttpInferenceDialect::OpenAiResponses,
        HttpInferenceDialect::OpenAiChatCompletions,
        HttpInferenceDialect::AnthropicMessages,
        HttpInferenceDialect::GeminiGenerateContent,
    ] {
        let mut config = config(dialect);
        config.options.request_overrides.insert(
            "nested".into(),
            Value::map(BTreeMap::from([(
                "key\"\\\0中".into(),
                Value::list(vec![
                    Value::float(xolotl_types::FloatBits(-0.0)),
                    Value::integer(i64::MIN),
                    Value::bytes(vec![0, 255]),
                    Value::boolean(false),
                ]),
            )])),
        )?;
        config.options.max_output_tokens = Some(u64::MAX);
        let expected: JsonValue =
            serde_json::from_slice(&encode_generation(&config, &input, true)?)?;
        for window in 1..=17 {
            config.io_window_bytes = core::num::NonZeroUsize::new(window).context("zero window")?;
            let mut body = super::super::encode_generation(&config, &input, true)?;
            let mut encoded = Vec::new();
            while let Some(bytes) = body.next()? {
                ensure!(bytes.len() <= window);
                encoded.extend_from_slice(&bytes);
            }
            ensure!(serde_json::from_slice::<JsonValue>(&encoded)? == expected);
        }
    }
    Ok(())
}

#[test]
fn large_requests_and_config_snapshots_do_not_depend_on_the_io_window() -> anyhow::Result<()> {
    let text = "plain\\\"中".repeat(128 * 1024);
    let input = Value::string(text.clone());
    let mut config = config(HttpInferenceDialect::OpenAiResponses);
    config.io_window_bytes = core::num::NonZeroUsize::MIN.saturating_add(6);
    config
        .options
        .request_overrides
        .insert("seed".into(), Value::integer(1))?;
    let mut body = super::super::encode_generation(&config, &input, false)?;
    config
        .options
        .request_overrides
        .insert("seed".into(), Value::integer(2))?;
    let mut actual = blake3::Hasher::new();
    let mut encoded_bytes = 0;
    while let Some(bytes) = body.next()? {
        ensure!(bytes.len() <= 7);
        encoded_bytes += bytes.len();
        actual.update(&bytes);
    }
    let expected = format!(
        "{{\"model\":\"model-1\",\"input\":{},\"store\":false,\"seed\":1}}",
        serde_json::to_string(&text)?
    );
    ensure!(encoded_bytes == expected.len());
    ensure!(actual.finalize() == blake3::hash(expected.as_bytes()));
    Ok(())
}

#[test]
fn deeply_wrapped_prompt_yields_before_finishing_its_projection() -> anyhow::Result<()> {
    let mut input = Value::string("text".into());
    for _ in 0..20_000 {
        input = Value::list(vec![input]);
    }
    let config = config(HttpInferenceDialect::OpenAiResponses);
    let mut body = super::super::encode_generation(&config, &input, false)?;
    let prefix = body.next()?.context("missing request prefix")?;
    ensure!(prefix == br#"{"model":"model-1","input":""#[..]);
    let mut bytes = prefix.to_vec();
    let mut pauses = 0;
    while let Some(chunk) = body.next()? {
        pauses += usize::from(chunk.is_empty());
        bytes.extend_from_slice(&chunk);
    }
    ensure!(pauses > 0, "deep traversal monopolized one body poll");
    ensure!(serde_json::from_slice::<JsonValue>(&bytes)?["input"] == "text");
    Ok(())
}

#[test]
fn typed_override_metadata_uses_its_ordinary_json_shape_in_small_windows() -> anyhow::Result<()> {
    let blob = xolotl_types::BlobRef {
        hash: "a\"b".into(),
        size: u64::MAX,
        mime: Some("application/example".into()),
    };
    let values = Value::list(vec![
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), xolotl_types::DType::F64, vec![0, u64::MAX]),
        Value::frame(blob, i64::MIN, xolotl_types::FrameKind::Video),
        Value::stream_end(xolotl_types::StreamMarker::Done),
        Value::stream_end(xolotl_types::StreamMarker::Error {
            message: "reason\n中".into(),
        }),
    ]);
    let mut config = config(HttpInferenceDialect::OpenAiResponses);
    config.io_window_bytes = core::num::NonZeroUsize::MIN;
    config
        .options
        .request_overrides
        .insert("metadata".into(), values.clone())?;
    let bytes = encode_generation(&config, &Value::null(), false)?;
    ensure!(
        serde_json::from_slice::<JsonValue>(&bytes)?["metadata"] == serde_json::to_value(&values)?
    );
    Ok(())
}

#[test]
fn sensitive_override_admission_reaches_maps_inside_nested_arrays() -> anyhow::Result<()> {
    let mut config = config(HttpInferenceDialect::OpenAiResponses);
    config.options.request_overrides.insert(
        "vendor".into(),
        serde_json::from_value(json!([[{"api_key":"secret"}]]))?,
    )?;
    ensure!(matches!(
        super::super::encode_generation(&config, &Value::null(), false),
        Err(HttpInferenceError::ReservedRequestField(_))
    ));
    Ok(())
}
