use super::project::{Limits, NUMBER, Projection, Rule, TEXT};
use super::*;
use anyhow::ensure;
use serde_json::json;

static SHAPE: Rule = Rule::Object(&[
    ("text", &TEXT),
    ("n", &NUMBER),
    (
        "items",
        &Rule::Array {
            item: &TEXT,
            first: false,
        },
    ),
]);

fn parse(bytes: &[u8], window: usize) -> Result<serde_json::Value, HttpInferenceError> {
    let mut document = Document::new(&SHAPE, Limits::default());
    for chunk in bytes.chunks(window) {
        document.push(chunk)?;
    }
    document.finish()
}

#[test]
fn selected_json_matches_serde_across_every_string_escape_and_split() -> anyhow::Result<()> {
    let bytes = br#" {"t\u0065xt":"quote:\" slash:\/ backslash:\\ \b\f\n\r\t \u0000 \ud834\udd1e", "n":-0.00125e+4,"items":["", "\u4e2d", false, ["ignored"]],"ignored":{"never":"retained"}} "#;
    let mut expected: serde_json::Value = serde_json::from_slice(bytes)?;
    expected
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("not an object"))?
        .remove("ignored");
    expected["items"][2] = serde_json::Value::Null;
    expected["items"][3] = serde_json::Value::Null;
    for window in 1..=bytes.len() {
        ensure!(parse(bytes, window)? == expected, "window={window}");
    }
    Ok(())
}

#[test]
fn invalid_grammar_is_rejected_even_in_unselected_values() -> anyhow::Result<()> {
    for bytes in [
        &b""[..],
        &b"{}{}"[..],
        &b"{\"ignored\":01}"[..],
        &b"{\"ignored\":-}"[..],
        &b"{\"ignored\":1.}"[..],
        &b"{\"ignored\":1e+}"[..],
        &b"{\"ignored\":True}"[..],
        &b"{\"ignored\":[1,]}"[..],
        &b"{\"ignored\":{\"a\":1,}}"[..],
        &b"{\"ignored\":\"\xff\"}"[..],
        &br#"{"ignored":"\ud800"}"#[..],
        &br#"{"ignored":"\udc00"}"#[..],
        &br#"{"ignored":"\ud800\u0000"}"#[..],
        &br#"{"ignored":"\x41"}"#[..],
        &b"{\"text\":\"unescaped\nnewline\"}"[..],
        &b"{\"text\":\"unfinished}"[..],
    ] {
        for window in 1..=bytes.len().max(1) {
            ensure!(
                parse(bytes, window).is_err(),
                "invalid={bytes:?}, window={window}"
            );
        }
    }
    Ok(())
}

#[test]
fn duplicate_selected_keys_replace_previous_values_and_retention() -> anyhow::Result<()> {
    let mut decoder = Decoder::new(None);
    let mut projection = Projection::new(&SHAPE, Limits::default());
    decoder.push(br#"{"text":"earlier","n":123,"text":"x","n":2}"#, |event| {
        projection.event(event)
    })?;
    decoder.finish(|event| projection.event(event))?;
    ensure!(projection.retained() == (1, 3));
    ensure!(projection.finish()? == json!({"text":"x","n":2}));
    Ok(())
}

#[test]
fn selected_materialization_is_explicit_and_unselected_bytes_are_free() -> anyhow::Result<()> {
    let mut document = Document::new(
        &SHAPE,
        Limits {
            max_materialized_bytes: Some(3),
            max_materialized_nodes: Some(3),
            max_json_frames: None,
        },
    );
    document.push(br#"{"ignored":""#)?;
    for _ in 0..4096 {
        document.push(&[b'a'; 1024])?;
    }
    document.push(br#"","text":"abc"}"#)?;
    ensure!(document.finish()? == json!({"text":"abc"}));
    let mut limited = Document::new(
        &SHAPE,
        Limits {
            max_materialized_bytes: Some(3),
            ..Limits::default()
        },
    );
    ensure!(limited.push(br#"{"text":"abcd"}"#).is_err());
    let mut width = Document::new(
        &SHAPE,
        Limits {
            max_materialized_nodes: Some(3),
            ..Limits::default()
        },
    );
    ensure!(width.push(br#"{"items":["",""]}"#).is_err());
    Ok(())
}

#[test]
fn skipped_depth_is_iterative_and_has_an_optional_active_frame_policy() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let mut document = Document::new(&SHAPE, Limits::default());
            document.push(br#"{"ignored":"#)?;
            for _ in 0..20_000 {
                document.push(b"[")?;
            }
            document.push(b"null")?;
            for _ in 0..20_000 {
                document.push(b"]")?;
            }
            document.push(br#", "text":"ok"}"#)?;
            ensure!(document.finish()? == json!({"text":"ok"}));
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("small-stack JSON worker panicked"))??;
    let mut document = Document::new(
        &SHAPE,
        Limits {
            max_json_frames: Some(2),
            ..Limits::default()
        },
    );
    ensure!(document.push(br#"{"ignored":[[[]]]}"#).is_err());
    Ok(())
}
