use super::*;
use anyhow::ensure;

fn records(input: &[u8], window: usize) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut framing = Framing::default();
    let mut records = Vec::new();
    let mut record = Vec::new();
    for mut bytes in input.chunks(window) {
        while !bytes.is_empty() {
            let (used, frame) = framing.next(bytes)?;
            ensure!(used != 0);
            bytes = &bytes[used..];
            match frame {
                Some(Frame::Data(data)) => record.extend_from_slice(data),
                Some(Frame::Byte(byte)) => record.push(byte),
                Some(Frame::End) => records.push(std::mem::take(&mut record)),
                None => {}
            }
        }
    }
    framing.finish()?;
    Ok(records)
}

#[test]
fn sse_fields_comments_line_endings_and_data_join_at_every_window() -> anyhow::Result<()> {
    let input = b": keepalive\r\nevent: sample\r\nid: 7\r\ndata: first\r\ndata: second\r\n\r\ndata: final\n\ndata\rdata:\r\rdata: unfinished";
    for window in 1..=input.len() {
        ensure!(
            records(input, window)?
                == [b"first\nsecond".to_vec(), b"final".to_vec(), b"\n".to_vec()],
            "window={window}"
        );
    }
    Ok(())
}

#[test]
fn exactly_one_initial_bom_is_framing_at_every_split() -> anyhow::Result<()> {
    for input in [
        &b"\xef\xbb\xbfdata: text\n\n"[..],
        &b"\xef\xbb\xbf\xef\xbb\xbfdata: ignored\n\ndata: text\n\n"[..],
        &b"data: text\n\n\xef\xbb\xbfdata: ignored\n\n"[..],
    ] {
        for window in 1..=input.len() {
            ensure!(records(input, window)? == [b"text".to_vec()]);
        }
    }
    for input in [&b""[..], &b"a"[..], &b"ab"[..], &b"\xef\xbb\xbf"[..]] {
        ensure!(records(input, 1)?.is_empty());
    }
    Ok(())
}

#[test]
fn invalid_utf8_is_rejected_in_data_and_ignored_fields() -> anyhow::Result<()> {
    for invalid in [
        &b"\xff"[..],
        &b"\x80"[..],
        &b"\xc0\x80"[..],
        &b"\xed\xa0\x80"[..],
        &b"\xf4\x90\x80\x80"[..],
        &b"\xe2a"[..],
        &b"\xc2"[..],
        &b"\xe2\x82"[..],
        &b"\xf0\x90\x80"[..],
    ] {
        for prefix in [&b"data: "[..], &b": "[..], &b"unknown: "[..]] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(invalid);
            for window in 1..=bytes.len() {
                ensure!(records(&bytes, window).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn strings_and_completion_markers_cross_every_record_fragment() -> anyhow::Result<()> {
    let text = br#"{"choices":[{"delta":{"content":"a\ud834\udd1e\n"}}]}"#;
    for window in 1..=text.len() {
        let mut data = Data::new(
            HttpInferenceDialect::OpenAiChatCompletions,
            Limits::default(),
        );
        for chunk in text.chunks(window) {
            data.push(chunk)?;
        }
        let Record::Json(value) = data.finish()? else {
            anyhow::bail!("expected JSON");
        };
        ensure!(
            value
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
                == Some("a𝄞\n")
        );
        let mut done = Data::new(
            HttpInferenceDialect::OpenAiChatCompletions,
            Limits::default(),
        );
        for chunk in b"[DONE]".chunks(window) {
            done.push(chunk)?;
        }
        ensure!(matches!(done.finish()?, Record::Done));
    }
    Ok(())
}

#[test]
fn enormous_ignored_snapshot_never_materializes_as_an_sse_record() -> anyhow::Result<()> {
    let limits = Limits {
        max_materialized_bytes: Some(4),
        max_materialized_nodes: Some(8),
        max_json_frames: Some(16),
    };
    let mut record = Data::new(HttpInferenceDialect::OpenAiResponses, limits);
    record.push(br#"{"response":{"output":[{"content":[{"text":""#)?;
    for _ in 0..8192 {
        record.push(&[b'x'; 1024])?;
    }
    record.push(br#""}]}],"usage":{"output_tokens":7}},"type":"response.completed"}"#)?;
    let Record::Json(value) = record.finish()? else {
        anyhow::bail!("expected JSON");
    };
    ensure!(value.pointer("/response/output").is_none());
    ensure!(
        value
            .pointer("/response/usage/output_tokens")
            .and_then(Value::as_u64)
            == Some(7)
    );
    Ok(())
}
