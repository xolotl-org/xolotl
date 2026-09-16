//! Ordinary, untagged Serde adaptation of resident values.
//!
//! This preserves the ordinary format's shapes, not every Xolotl variant:
//! JSON arrays decode as lists and objects as maps, including objects produced
//! by reference/stream-marker DTOs. Native Serde byte inputs become byte values.
//! Special records serialize through their DTOs. Use the lossless graph format
//! when exact variant identity, shared descendants or float bits must persist.
//!
//! Visitors construct resident values directly, without a second recursive
//! owned representation. Serde's recursive calls and the chosen parser's depth,
//! number and format restrictions still apply. The event path supplies explicit
//! traversal for documents beyond those parser/stack limits. In particular, a
//! visitor cannot recover integer spelling after a parser has classified that
//! input as an f64; explicit integer inputs outside i64 are rejected.

use super::{FloatBits, Value, ValueListBuilder, ValueMapBuilder, ValueView};
use ::serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use alloc::{string::String, vec::Vec};
use core::fmt;

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.view() {
            ValueView::Null => serializer.serialize_unit(),
            ValueView::Bool(value) => serializer.serialize_bool(value),
            ValueView::Int(value) => serializer.serialize_i64(value),
            ValueView::Float(value) => serializer.serialize_f64(value.0),
            ValueView::Str(value) => serializer.serialize_str(value),
            ValueView::Bytes(value) => serializer.serialize_bytes(value),
            ValueView::List(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values.iter() {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            ValueView::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values.iter() {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            ValueView::Blob(value) => value.serialize(serializer),
            ValueView::Tensor(value) => value.serialize(serializer),
            ValueView::Frame(value) => value.serialize(serializer),
            ValueView::StreamEnd(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("a null, boolean, signed 64-bit integer, float, string, bytes, list or map")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::null())
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::null())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        Value::deserialize(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Value, D::Error> {
        Value::deserialize(deserializer)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::boolean(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::integer(value))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<Value, E> {
        integer(value)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        integer(value)
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<Value, E> {
        integer(value)
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::float(FloatBits(value)))
    }

    fn visit_char<E: de::Error>(self, value: char) -> Result<Value, E> {
        self.visit_str(value.encode_utf8(&mut [0; 4]))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::string(String::from(value)))
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Value, E> {
        self.visit_str(value)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::string(value))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Value, E> {
        Ok(Value::bytes(value.to_vec()))
    }

    fn visit_borrowed_bytes<E: de::Error>(self, value: &'de [u8]) -> Result<Value, E> {
        self.visit_bytes(value)
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Value, E> {
        Ok(Value::bytes(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        // size_hint is untrusted. Grow only as actual elements arrive; a format
        // declaring usize::MAX items must not force an immediate allocation.
        let mut values = ValueListBuilder::new();
        while let Some(value) = sequence.next_element::<Value>()? {
            values.push(value).map_err(de::Error::custom)?;
        }
        Ok(Value::from(values.finish()))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut ordered = ValueMapBuilder::new();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            if ordered.last_key().is_some_and(|last| last >= key.as_str()) {
                // Ordinary objects allow arbitrary order and repeated keys.
                // Finalize the sorted prefix once, then use the same resident
                // map's general updates. No second full set of slots is staged.
                let mut values = ordered.finish();
                drop(values.insert(key, value).map_err(de::Error::custom)?);
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    drop(values.insert(key, value).map_err(de::Error::custom)?);
                }
                return Ok(Value::from(values));
            }
            ordered.append(key, value).map_err(de::Error::custom)?;
        }
        Ok(Value::from(ordered.finish()))
    }
}

fn integer<E: de::Error>(value: impl Copy + fmt::Display + TryInto<i64>) -> Result<Value, E> {
    value.try_into().map(Value::integer).map_err(|_error| {
        E::custom(format_args!(
            "integer {value} is outside the signed 64-bit range"
        ))
    })
}

#[cfg(test)]
#[path = "serde/tests.rs"]
mod tests;
