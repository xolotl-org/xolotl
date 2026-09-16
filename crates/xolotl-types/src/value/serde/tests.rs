use super::*;
use crate::{BlobRef, DType, FrameKind, FrameRef, StreamMarker, TensorRef};
use ::serde::de::{
    DeserializeSeed,
    value::{
        BytesDeserializer, Error, F64Deserializer, I64Deserializer, I128Deserializer,
        MapAccessDeserializer, SeqAccessDeserializer, StrDeserializer, U64Deserializer,
        U128Deserializer,
    },
};
use alloc::{collections::BTreeMap, format, string::ToString};
use anyhow::{Context, bail, ensure};

#[test]
fn ordinary_json_roundtrips_scalar_and_container_shapes() -> anyhow::Result<()> {
    for input in [
        "null",
        "true",
        "false",
        "-9223372036854775808",
        "9223372036854775807",
        "1.25",
        "1e100",
        r#""text \u0000 字符""#,
        "[]",
        "{}",
        r#"{"a":[null,true,-7,2.5,"x"],"nested":{"z":false}}"#,
    ] {
        let expected: serde_json::Value = serde_json::from_str(input)?;
        let value: Value = serde_json::from_str(input)?;
        ensure!(
            serde_json::to_value(&value)? == expected,
            "changed JSON shape for {input}"
        );
    }
    Ok(())
}

#[test]
fn serde_integer_kinds_keep_all_i64_bits_and_reject_overflow() -> anyhow::Result<()> {
    for expected in [i64::MIN, -1, 0, 1, i64::MAX] {
        let value = Value::deserialize(I128Deserializer::<Error>::new(i128::from(expected)))
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        ensure!(matches!(value.view(), ValueView::Int(actual) if actual == expected));
    }
    let value = Value::deserialize(U128Deserializer::<Error>::new(i64::MAX as u128))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure!(matches!(value.view(), ValueView::Int(i64::MAX)));

    for out_of_range in [
        i128::MIN,
        i128::from(i64::MIN) - 1,
        i128::from(i64::MAX) + 1,
        i128::MAX,
    ] {
        let result = Value::deserialize(I128Deserializer::<Error>::new(out_of_range));
        ensure!(result.is_err(), "accepted i128 overflow {out_of_range}");
    }
    for out_of_range in [i64::MAX as u128 + 1, u128::MAX] {
        let result = Value::deserialize(U128Deserializer::<Error>::new(out_of_range));
        ensure!(result.is_err(), "accepted u128 overflow {out_of_range}");
    }
    let result = Value::deserialize(U64Deserializer::<Error>::new(u64::MAX));
    let error = result.err().context("accepted u64::MAX as an integer")?;
    ensure!(error.to_string().contains("signed 64-bit range"));
    for json in ["9223372036854775808", "18446744073709551615"] {
        ensure!(
            serde_json::from_str::<Value>(json).is_err(),
            "accepted {json}"
        );
    }
    Ok(())
}

#[test]
fn float_inputs_preserve_the_format_supplied_bits() -> anyhow::Result<()> {
    for bits in [
        0_u64,
        (-0.0_f64).to_bits(),
        f64::MAX.to_bits(),
        f64::INFINITY.to_bits(),
        0x7ff8_0000_0000_0042,
    ] {
        let value = Value::deserialize(F64Deserializer::<Error>::new(f64::from_bits(bits)))
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        ensure!(matches!(value.view(), ValueView::Float(value) if value.0.to_bits() == bits));
    }
    let value: Value = serde_json::from_str("-0.0")?;
    ensure!(
        matches!(value.view(), ValueView::Float(value) if value.0.to_bits() == (-0.0_f64).to_bits())
    );
    ensure!(serde_json::to_string(&value)? == "-0.0");
    Ok(())
}

#[test]
fn native_bytes_are_owned_and_json_arrays_remain_lists() -> anyhow::Result<()> {
    let mut source = vec![0_u8, 127, 255];
    let value = Value::deserialize(BytesDeserializer::<Error>::new(&source))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    source[0] = 42;
    ensure!(matches!(value.view(), ValueView::Bytes(bytes) if bytes == [0, 127, 255]));
    let json = serde_json::to_string(&value)?;
    ensure!(json == "[0,127,255]");
    let decoded: Value = serde_json::from_str(&json)?;
    ensure!(matches!(decoded.view(), ValueView::List(values) if values.len() == 3));
    let owned = ValueVisitor
        .visit_byte_buf::<Error>(vec![9, 8, 7])
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure!(matches!(owned.view(), ValueView::Bytes(bytes) if bytes == [9, 8, 7]));
    Ok(())
}

#[test]
fn record_variants_keep_their_dto_serialization() -> anyhow::Result<()> {
    let blob = BlobRef {
        hash: String::from("content-id"),
        size: u64::MAX,
        mime: Some(String::from("application/octet-stream")),
    };
    let tensor = TensorRef {
        blob: blob.clone(),
        dtype: DType::F32,
        shape: vec![u64::MAX, 3],
    };
    let frame = FrameRef {
        blob: blob.clone(),
        ts_nanos: i64::MIN,
        kind: FrameKind::Sensor,
    };
    let marker = StreamMarker::Error {
        message: String::from("source ended"),
    };
    let expected_blob = serde_json::to_value(&blob)?;
    let expected_tensor = serde_json::to_value(&tensor)?;
    let expected_frame = serde_json::to_value(&frame)?;
    let expected_marker = serde_json::to_value(&marker)?;
    ensure!(serde_json::to_value(Value::blob(blob))? == expected_blob);
    ensure!(serde_json::to_value(Value::from(tensor))? == expected_tensor);
    ensure!(serde_json::to_value(Value::from(frame))? == expected_frame);
    ensure!(serde_json::to_value(Value::stream_end(marker))? == expected_marker);
    ensure!(
        serde_json::to_value(Value::stream_end(StreamMarker::Done))?
            == serde_json::to_value(StreamMarker::Done)?
    );
    Ok(())
}

#[test]
fn ordinary_objects_do_not_guess_special_records() -> anyhow::Result<()> {
    for json in [
        r#"{"hash":"abc","size":7,"mime":null}"#,
        r#"{"blob":{"hash":"abc","size":7,"mime":null},"dtype":"f32","shape":[7]}"#,
        r#"{"blob":{"hash":"abc","size":7,"mime":null},"ts_nanos":4,"kind":"audio"}"#,
        r#"{"__stream_marker":"Done"}"#,
    ] {
        let value: Value = serde_json::from_str(json)?;
        ensure!(
            matches!(value.view(), ValueView::Map(_)),
            "guessed a record for {json}"
        );
        ensure!(serde_json::to_value(&value)? == serde_json::from_str::<serde_json::Value>(json)?);
    }
    Ok(())
}

#[test]
fn maps_remain_ordered_and_duplicate_entries_keep_the_last_value() -> anyhow::Result<()> {
    let value: Value = serde_json::from_str(r#"{"é":1,"z":2,"a":3,"z":4}"#)?;
    let ValueView::Map(values) = value.view() else {
        bail!("object did not produce a map");
    };
    let keys: Vec<&str> = values.iter().map(|(key, _value)| key).collect();
    ensure!(keys == ["a", "z", "é"]);
    ensure!(serde_json::to_string(&value)? == r#"{"a":3,"z":4,"é":1}"#);
    Ok(())
}

#[test]
fn ordered_map_prefix_survives_late_arbitrary_keys_and_overwrites() -> anyhow::Result<()> {
    use core::fmt::Write;

    for suffix in [
        r#", "a":-1, "k0000":-2, "z":-3}"#,
        r#", "k0000":-2, "a":-1, "z":-3}"#,
    ] {
        let mut json = String::from("{");
        for index in 0..1057 {
            if index > 0 {
                json.push(',');
            }
            write!(json, "\"k{index:04}\":{index}")?;
        }
        json.push_str(suffix);
        let value: Value = serde_json::from_str(&json)?;
        let map = value.as_map().context("map output")?;
        ensure!(map.len() == 1059);
        ensure!(map.get("a").and_then(Value::as_int) == Some(-1));
        ensure!(map.get("k0000").and_then(Value::as_int) == Some(-2));
        ensure!(map.get("z").and_then(Value::as_int) == Some(-3));
        for index in 1..1057 {
            ensure!(map.get(&format!("k{index:04}")).and_then(Value::as_int) == Some(index));
        }
    }
    Ok(())
}

#[test]
fn wide_ordinary_sequences_keep_values_and_reject_a_truncated_tail() -> anyhow::Result<()> {
    use core::fmt::Write;

    let mut json = String::from("[");
    for index in 0..1057 {
        if index > 0 {
            json.push(',');
        }
        write!(json, "{index}")?;
    }
    ensure!(serde_json::from_str::<Value>(&json).is_err());
    json.push(']');
    let value: Value = serde_json::from_str(&json)?;
    let values = value.as_list().context("list output")?;
    ensure!(values.len() == 1057);
    for (index, value) in values.iter().enumerate() {
        ensure!(value.as_int() == Some(i64::try_from(index)?));
    }
    Ok(())
}

#[test]
fn hostile_collection_size_hints_do_not_preallocate_claimed_capacity() -> anyhow::Result<()> {
    let list = Value::deserialize(SeqAccessDeserializer::new(HugeHintSequence {
        yielded: false,
    }))
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure!(serde_json::to_string(&list)? == "[7]");
    let map = Value::deserialize(MapAccessDeserializer::new(HugeHintMap { stage: 0 }))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure!(serde_json::to_string(&map)? == r#"{"entry":7}"#);
    Ok(())
}

#[test]
fn malformed_nested_input_returns_a_parser_error() -> anyhow::Result<()> {
    let complete = format!("{}0{}", "[".repeat(64), "]".repeat(64));
    let value: Value = serde_json::from_str(&complete)?;
    ensure!(matches!(value.view(), ValueView::List(_)));
    let truncated = &complete[..complete.len() - 1];
    ensure!(serde_json::from_str::<Value>(truncated).is_err());
    ensure!(serde_json::from_str::<Value>(r#"{"first":[1,2],"unfinished":"#).is_err());
    Ok(())
}

#[test]
fn serialization_expands_shared_values_using_ordinary_container_shapes() -> anyhow::Result<()> {
    let child = Value::map(BTreeMap::from([(String::from("x"), Value::integer(9))]));
    let value = Value::list(vec![child.clone(), child]);
    ensure!(serde_json::to_string(&value)? == r#"[{"x":9},{"x":9}]"#);
    Ok(())
}

struct HugeHintSequence {
    yielded: bool,
}

impl<'de> SeqAccess<'de> for HugeHintSequence {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        if core::mem::replace(&mut self.yielded, true) {
            Ok(None)
        } else {
            seed.deserialize(I64Deserializer::<Error>::new(7)).map(Some)
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(usize::MAX)
    }
}

struct HugeHintMap {
    stage: u8,
}

impl<'de> MapAccess<'de> for HugeHintMap {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        if self.stage == 0 {
            self.stage = 1;
            seed.deserialize(StrDeserializer::<Error>::new("entry"))
                .map(Some)
        } else {
            Ok(None)
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        self.stage = 2;
        seed.deserialize(I64Deserializer::<Error>::new(7))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(usize::MAX)
    }
}
