use super::*;
use crate::value::ValueView;
use crate::{BlobRef, DType, FloatBits, FrameKind, FrameRef, StreamMarker, TensorRef};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use anyhow::{Context, ensure};
use serde_json::json;
use std::thread;

fn encode(value: &Value) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serializable(value))?)
}

fn decode(bytes: &[u8]) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice::<Decoded>(bytes)?.0)
}

#[test]
fn unit_encoding_identifies_its_node_table_version() -> anyhow::Result<()> {
    ensure!(encode(&Value::null())? == br#"{"version":1,"nodes":["null"],"root":0}"#);
    Ok(())
}

#[test]
fn every_value_variant_and_ieee_bit_pattern_round_trips() -> anyhow::Result<()> {
    let blob = BlobRef {
        hash: "unresolved-object".into(),
        size: u64::MAX,
        mime: Some("audio/pcm".into()),
    };
    let mut values = vec![
        Value::null(),
        Value::boolean(true),
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::from("a\0🙂é"),
        Value::bytes(vec![0, 1, 127, 128, 255]),
        Value::list(Vec::new()),
        Value::map(BTreeMap::new()),
        Value::blob(blob.clone()),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: "failure\0🙂".into(),
        }),
    ];
    for bits in [
        0,
        1,
        0x8000_0000_0000_0000,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff8_0000_0000_0001,
        0x7ff8_0000_0000_0002,
    ] {
        values.push(Value::float(FloatBits(f64::from_bits(bits))));
    }
    for dtype in [
        DType::F16,
        DType::Bf16,
        DType::F32,
        DType::F64,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::Bool,
    ] {
        values.push(Value::from(TensorRef {
            blob: blob.clone(),
            dtype,
            shape: vec![0, u64::MAX],
        }));
    }
    for kind in [
        FrameKind::Audio,
        FrameKind::Video,
        FrameKind::Pose,
        FrameKind::Sensor,
    ] {
        values.push(Value::from(FrameRef {
            blob: blob.clone(),
            ts_nanos: i64::MIN,
            kind,
        }));
    }
    let value = Value::map(BTreeMap::from([
        ("z".into(), Value::list(values)),
        ("é".into(), Value::from("map ordering")),
    ]));
    let restored = decode(&encode(&value)?)?;
    ensure!(restored == value);
    ensure!(restored.semantic_digest() == value.semantic_digest());
    Ok(())
}

#[test]
fn a_doubled_dag_stays_linear_and_restores_shared_children() -> anyhow::Result<()> {
    let mut value = Value::from("leaf");
    for _ in 0..192 {
        value = Value::list(vec![value.clone(), value]);
    }
    let bytes = encode(&value)?;
    let table: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(table["version"] == 1);
    ensure!(table["nodes"].as_array().context("nodes")?.len() == 193);
    ensure!(bytes.len() < 20_000);
    let restored = decode(&bytes)?;
    ensure!(restored == value);
    ensure!(restored.approx_tokens() == u64::MAX);
    let mut current = &restored;
    for _ in 0..192 {
        let ValueView::List(items) = current.view() else {
            anyhow::bail!("expected shared list");
        };
        let mut children = items.iter();
        let left = children.next().context("left child")?;
        let right = children.next().context("right child")?;
        ensure!(left.identity().is_some());
        ensure!(left.identity() == right.identity());
        current = left;
    }
    ensure!(current == &Value::from("leaf"));
    Ok(())
}

#[test]
fn encoded_sharing_is_not_confused_with_semantic_identity() -> anyhow::Result<()> {
    let make = || Value::list(vec![Value::from("same")]);
    let child = make();
    let shared = Value::list(vec![child.clone(), child]);
    let separate = Value::list(vec![make(), make()]);
    let shared_bytes = encode(&shared)?;
    let separate_bytes = encode(&separate)?;
    ensure!(shared_bytes != separate_bytes);
    ensure!(decode(&shared_bytes)? == decode(&separate_bytes)?);
    ensure!(shared.semantic_digest() == separate.semantic_digest());
    Ok(())
}

#[test]
fn malformed_tables_and_unknown_shapes_are_rejected() -> anyhow::Result<()> {
    for invalid in [
        json!({"type":"null"}),
        json!({"version":0,"nodes":["null"],"root":0}),
        json!({"version":2,"nodes":["null"],"root":0}),
        json!({"version":1,"nodes":[],"root":0}),
        json!({"version":1,"nodes":["null"],"root":u64::MAX}),
        json!({"version":1,"nodes":[{"list":[0]}],"root":0}),
        json!({"version":1,"nodes":[{"list":[1]},"null"],"root":0}),
        json!({"version":1,"nodes":[{"unknown":0}],"root":0}),
        json!({"version":1,"nodes":[{"float":-1}],"root":0}),
        json!({"version":1,"nodes":[{"null":null,"extra":1}],"root":0}),
        json!({"version":1,"nodes":["null"],"root":0,"extra":1}),
        json!({"version":1,"nodes":["null"]}),
        json!({"version":1,"root":0}),
        json!({"nodes":["null"],"root":0}),
        json!({"version":1,"nodes":["null",{"map":[["a",0],["a",0]]}],"root":1}),
        json!({"version":1,"nodes":["null",{"map":[["z",0],["a",0]]}],"root":1}),
    ] {
        ensure!(
            decode(&serde_json::to_vec(&invalid)?).is_err(),
            "accepted malformed table: {invalid}"
        );
    }
    ensure!(decode(br#"{"version":1,"version":1,"nodes":["null"],"root":0}"#).is_err());
    ensure!(decode(br#"{"version":1,"nodes":["null"],"root":0,"root":0}"#).is_err());
    Ok(())
}

#[test]
fn fields_may_arrive_in_any_order_and_eof_is_required() -> anyhow::Result<()> {
    let bytes = br#"{"root":0,"nodes":[{"str":"hello"}],"version":1}"#;
    ensure!(decode(bytes)? == Value::from("hello"));
    let mut trailing = bytes.to_vec();
    trailing.extend_from_slice(b" false");
    ensure!(decode(&trailing).is_err());
    Ok(())
}

#[test]
fn optional_absence_is_distinct_from_a_present_null() -> anyhow::Result<()> {
    #[derive(Serialize, Deserialize)]
    struct Optional {
        #[serde(with = "crate::tagged_value::optional")]
        value: Option<Value>,
    }
    for value in [
        None,
        Some(Value::null()),
        Some(Value::list(vec![Value::integer(1)])),
    ] {
        let bytes = serde_json::to_vec(&Optional {
            value: value.clone(),
        })?;
        let restored: Optional = serde_json::from_slice(&bytes)?;
        ensure!(restored.value == value);
    }
    Ok(())
}

#[test]
fn deep_values_serialize_decode_and_clean_up_truncation_on_a_small_stack() -> anyhow::Result<()> {
    let worker =
        thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let mut value = Value::null();
                for _ in 0..20_000 {
                    value = Value::list(vec![value]);
                }
                let bytes = encode(&value)?;
                let restored = decode(&bytes)?;
                ensure!(restored == value);
                ensure!(decode(&bytes[..bytes.len() - 3]).is_err());
                ensure!(format!("{restored:?}").len() < 128);
                drop((restored, value));
                Ok(())
            })?;
    worker
        .join()
        .map_err(|_error| anyhow::anyhow!("deep persistence worker panicked"))??;
    Ok(())
}

#[test]
fn deep_partial_tables_release_on_bad_references_and_duplicate_fields() -> anyhow::Result<()> {
    use core::fmt::Write;

    let worker =
        thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let mut prefix = String::from(r#"{"version":1,"nodes":["null""#);
                for id in 1..20_000 {
                    write!(prefix, ",{{\"list\":[{}]}}", id - 1)?;
                }
                // The list/map builders retain a valid deep child before discovering
                // the later error. Both partial containers and the whole table unwind.
                for suffix in [
                    r#",{"list":[19999,20001]}],"root":20000}"#,
                    r#",{"map":[["a",19999],["a",19999]]}],"root":20000}"#,
                    r#"],"root":19999,"nodes":[]}"#,
                    r#"],"root":19999,"version":1}"#,
                    r#"],"root":18446744073709551615}"#,
                    r#",{"list":[19999"#,
                ] {
                    let malformed = format!("{prefix}{suffix}");
                    ensure!(decode(malformed.as_bytes()).is_err());
                }
                Ok(())
            })?;
    worker
        .join()
        .map_err(|_error| anyhow::anyhow!("partial table cleanup worker panicked"))??;
    Ok(())
}

#[test]
fn node_tags_select_a_type_before_reading_untrusted_payloads() -> anyhow::Result<()> {
    let worker =
        thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let nested = format!("{}0{}", "[".repeat(20_000), "]".repeat(20_000));
                let unknown = format!(r#"{{"version":1,"nodes":[{{"value":{nested}}}],"root":0}}"#);
                let error = decode(unknown.as_bytes())
                    .err()
                    .context("unknown tag must reject")?;
                ensure!(error.to_string().contains("unknown variant"));

                let wrong_child =
                    format!(r#"{{"version":1,"nodes":[{{"list":{nested}}}],"root":0}}"#);
                let error = decode(wrong_child.as_bytes())
                    .err()
                    .context("nested reference must reject")?;
                ensure!(error.to_string().contains("invalid type"));
                for tag in ["blob", "tensor", "frame"] {
                    let unknown_field = format!(r#"{{"version":1,"nodes":[{{"{tag}":{{"unknown":{nested}}}}}],"root":0}}"#);
                    let error = decode(unknown_field.as_bytes()).err().context("unknown media field must reject")?;
                    ensure!(error.to_string().contains("unknown field"));
                }
                for tag in ["tensor", "frame"] {
                    let unknown_field = format!(r#"{{"version":1,"nodes":[{{"{tag}":{{"blob":{{"unknown":{nested}}}}}}}],"root":0}}"#);
                    let error = decode(unknown_field.as_bytes()).err().context("unknown backing field must reject")?;
                    ensure!(error.to_string().contains("unknown field"));
                }
                Ok(())
            })?;
    worker
        .join()
        .map_err(|_error| anyhow::anyhow!("typed node decoding worker panicked"))??;
    Ok(())
}
