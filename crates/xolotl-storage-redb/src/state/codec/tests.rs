use super::*;
use anyhow::{Context, ensure};
use serde_json::json;
use xolotl_types::TaintSource;

fn protected() -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://codec/private-source")?,
    }))
}

fn framed(format: &[u8; 4], taint: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = format.to_vec();
    bytes.extend_from_slice(&(taint.len() as u64).to_le_bytes());
    bytes.extend_from_slice(taint);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn record_framing_requires_format_length_and_valid_provenance() -> anyhow::Result<()> {
    let taint = serde_json::to_vec(&TaintSet::pristine())?;
    let value = Value::bytes(vec![0, 255]);
    let encoded = encode_envelope(&value, &TaintSet::pristine())?;
    ensure!(decode_envelope(&encoded)?.value == value);
    for end in 0..PREFIX_BYTES {
        ensure!(decode_envelope(&encoded[..end]).is_err());
    }
    let mut overflow = encoded.clone();
    overflow[4..PREFIX_BYTES].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut unknown = encoded;
    unknown[..4].copy_from_slice(b"XSV2");
    for malformed in [
        overflow,
        unknown,
        framed(HISTORY_FORMAT, &taint, b"null"),
        framed(VALUE_FORMAT, b"", b"null"),
        framed(VALUE_FORMAT, b"null", b"null"),
        framed(VALUE_FORMAT, br#"{"sources":"invalid"}"#, b"null"),
        framed(VALUE_FORMAT, &taint, b""),
    ] {
        ensure!(decode_envelope(&malformed).is_err());
    }
    Ok(())
}

#[test]
fn value_payload_rejects_unknown_duplicate_and_trailing_content() -> anyhow::Result<()> {
    let taint = protected()?;
    let metadata = serde_json::to_vec(&taint)?;
    let value = serde_json::to_value(xolotl_types::tagged_value::serializable(&Value::null()))?;
    let mut unknown = value.clone();
    unknown["unknown"] = json!(0);
    let duplicate = br#"{"version":1,"nodes":["null"],"root":0,"root":0}"#.to_vec();
    let mut trailing = serde_json::to_vec(&value)?;
    trailing.extend_from_slice(b" null");
    for payload in [serde_json::to_vec(&unknown)?, duplicate, trailing] {
        let failure = decode_envelope(&framed(VALUE_FORMAT, &metadata, &payload))
            .err()
            .context("malformed value accepted")?;
        ensure!(failure.taint == taint);
        ensure!(matches!(failure.error, StateError::Serde(_)));
    }
    Ok(())
}

#[test]
fn metadata_read_does_not_traverse_large_or_malformed_payload() -> anyhow::Result<()> {
    let taint = protected()?;
    let metadata = serde_json::to_vec(&taint)?;
    // Invalid trailing bytes prove that the provenance reader does not enter
    // the payload decoder; the same property holds regardless of payload size.
    let payload = vec![0xff; 2 * 1024 * 1024];
    let bytes = framed(VALUE_FORMAT, &metadata, &payload);
    ensure!(envelope_taint(&bytes)? == taint);
    let failure = decode_envelope(&bytes)
        .err()
        .context("corrupt payload accepted")?;
    ensure!(failure.taint == taint);
    let history = framed(HISTORY_FORMAT, &metadata, &payload);
    ensure!(history_taint(&history)? == taint);
    ensure!(
        decode_history_entry(&history)
            .err()
            .context("corrupt history accepted")?
            .taint
            == taint
    );
    Ok(())
}

#[test]
fn history_requires_complete_unique_payload_fields() -> anyhow::Result<()> {
    let taint = protected()?;
    let path = Path::parse("state://codec/history")?;
    for event in [
        StateEvent::Set {
            path: path.clone(),
            value: Value::bytes(vec![1]),
            taint: taint.clone(),
        },
        StateEvent::Append {
            path,
            item: Value::bytes(vec![2]),
            taint: taint.clone(),
        },
    ] {
        let encoded = encode_history_entry(3, &event)?;
        ensure!(decode_history_entry(&encoded)?.event == event);
        let record = record(&encoded, HISTORY_FORMAT)?;
        let original: serde_json::Value = serde_json::from_slice(record.payload)?;
        let mut malformed = Vec::new();
        for field in ["at_millis", "event"] {
            let mut missing = original.clone();
            missing
                .as_object_mut()
                .context("history is not an object")?
                .remove(field);
            malformed.push(serde_json::to_vec(&missing)?);
        }
        let mut unknown = original.clone();
        unknown["unknown"] = json!(0);
        malformed.push(serde_json::to_vec(&unknown)?);
        let event_json = serde_json::to_string(&original["event"])?;
        malformed
            .push(format!(r#"{{"at_millis":3,"at_millis":3,"event":{event_json}}}"#).into_bytes());
        let mut unknown_event = original.clone();
        unknown_event["event"]["unknown"] = json!(0);
        malformed.push(serde_json::to_vec(&unknown_event)?);
        let payload_field = if matches!(event, StateEvent::Set { .. }) {
            "value"
        } else {
            "item"
        };
        let mut missing_payload = original.clone();
        missing_payload["event"]
            .as_object_mut()
            .context("event is not an object")?
            .remove(payload_field);
        malformed.push(serde_json::to_vec(&missing_payload)?);
        let mut trailing = serde_json::to_vec(&original)?;
        trailing.extend_from_slice(b" null");
        malformed.push(trailing);
        let metadata = serde_json::to_vec(&taint)?;
        for payload in malformed {
            let failure = decode_history_entry(&framed(HISTORY_FORMAT, &metadata, &payload))
                .err()
                .context("malformed history accepted")?;
            ensure!(failure.taint == taint);
        }
    }
    Ok(())
}

#[test]
fn delete_history_retains_observation_provenance_without_a_value_payload() -> anyhow::Result<()> {
    let path = Path::parse("state://codec/deleted")?;
    let event = StateEvent::Delete {
        path,
        taint: protected()?,
    };
    let bytes = encode_history_entry(i64::MIN, &event)?;
    let decoded = decode_history_entry(&bytes)?;
    ensure!(decoded.at_millis == i64::MIN && decoded.event == event);
    let record = record(&bytes, HISTORY_FORMAT)?;
    let mut invalid: serde_json::Value = serde_json::from_slice(record.payload)?;
    invalid["event"]["value"] = json!(null);
    ensure!(
        decode_history_entry(&encode(HISTORY_FORMAT, &TaintSet::pristine(), &invalid)?).is_err()
    );
    let taint = protected()?;
    let invalid = framed(HISTORY_FORMAT, &serde_json::to_vec(&taint)?, record.payload);
    ensure!(decode_history_entry(&invalid)?.event.taint() == &taint);
    Ok(())
}

#[test]
fn corrupt_payload_diagnostics_do_not_render_input_data() -> anyhow::Result<()> {
    let taint = protected()?;
    let bytes = framed(
        VALUE_FORMAT,
        &serde_json::to_vec(&taint)?,
        br#"{"version":1,"nodes":["private-unknown-variant"],"root":0}"#,
    );
    let failure = decode_envelope(&bytes)
        .err()
        .context("corrupt value accepted")?;
    ensure!(!failure.to_string().contains("private-unknown-variant"));
    ensure!(!format!("{failure:?}").contains("private-unknown-variant"));
    ensure!(!format!("{failure:?}").contains("private-source"));
    ensure!(failure.taint == taint);
    Ok(())
}
