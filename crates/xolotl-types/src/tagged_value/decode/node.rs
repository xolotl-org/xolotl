use crate::{
    BlobRef, DType, FloatBits, FrameKind, FrameRef, StreamMarker, TensorRef, Value,
    value::{ValueListBuilder, ValueMapBuilder},
};
use alloc::{string::String, vec::Vec};
use core::fmt;
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, EnumAccess, SeqAccess, VariantAccess, Visitor},
};

/// External tags select the payload before decoding. Collection references
/// enter the resident assemblers one at a time: neither a recursive untyped
/// serde Content tree nor a second collection of IDs or member slots is staged.
pub(super) struct Node<'a> {
    pub(super) previous: &'a [Value],
}

#[derive(Deserialize)]
#[serde(variant_identifier, rename_all = "snake_case")]
enum Kind {
    Null,
    Bool,
    Int,
    Float,
    Str,
    Bytes,
    List,
    Map,
    Blob,
    Tensor,
    Frame,
    StreamDone,
    StreamError,
}

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_enum(
            "Node",
            &[
                "null",
                "bool",
                "int",
                "float",
                "str",
                "bytes",
                "list",
                "map",
                "blob",
                "tensor",
                "frame",
                "stream_done",
                "stream_error",
            ],
            self,
        )
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an externally tagged value node")
    }

    fn visit_enum<A: EnumAccess<'de>>(self, record: A) -> Result<Value, A::Error> {
        let (kind, payload) = record.variant::<Kind>()?;
        Ok(match kind {
            Kind::Null => {
                payload.unit_variant()?;
                Value::null()
            }
            Kind::Bool => Value::boolean(payload.newtype_variant()?),
            Kind::Int => Value::integer(payload.newtype_variant()?),
            Kind::Float => Value::float(FloatBits(f64::from_bits(payload.newtype_variant()?))),
            Kind::Str => Value::string(payload.newtype_variant::<String>()?),
            Kind::Bytes => Value::bytes(payload.newtype_variant::<Vec<u8>>()?),
            Kind::List => payload.newtype_variant_seed(Collection {
                previous: self.previous,
                kind: CollectionKind::List,
            })?,
            Kind::Map => payload.newtype_variant_seed(Collection {
                previous: self.previous,
                kind: CollectionKind::Map,
            })?,
            Kind::Blob => Value::blob(payload.newtype_variant::<BlobPayload>()?.0),
            Kind::Tensor => payload.newtype_variant::<TensorPayload>()?.0.into(),
            Kind::Frame => payload.newtype_variant::<FramePayload>()?.0.into(),
            Kind::StreamDone => {
                payload.unit_variant()?;
                Value::stream_end(StreamMarker::Done)
            }
            Kind::StreamError => Value::stream_end(StreamMarker::Error {
                message: payload.newtype_variant()?,
            }),
        })
    }
}

enum CollectionKind {
    List,
    Map,
}

struct Collection<'a> {
    previous: &'a [Value],
    kind: CollectionKind,
}

impl<'de> DeserializeSeed<'de> for Collection<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Collection<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            CollectionKind::List => formatter.write_str("a sequence of earlier node IDs"),
            CollectionKind::Map => {
                formatter.write_str("strictly ordered key and earlier node ID pairs")
            }
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        // Advertised size hints are untrusted. Each accepted reference enters
        // one shared resident leaf; unfinished collections release iteratively.
        match self.kind {
            CollectionKind::List => {
                let mut values = ValueListBuilder::new();
                while let Some(id) = sequence.next_element::<u64>()? {
                    values
                        .push(reference(self.previous, id)?)
                        .map_err(de::Error::custom)?;
                }
                Ok(values.finish().into())
            }
            CollectionKind::Map => {
                let mut values = ValueMapBuilder::new();
                while let Some((key, id)) = sequence.next_element::<(String, u64)>()? {
                    values
                        .append(key, reference(self.previous, id)?)
                        .map_err(de::Error::custom)?;
                }
                Ok(values.finish().into())
            }
        }
    }
}

fn reference<E: de::Error>(previous: &[Value], id: u64) -> Result<Value, E> {
    usize::try_from(id)
        .ok()
        .and_then(|index| previous.get(index))
        .cloned()
        .ok_or_else(|| {
            E::custom(format_args!(
                "value node references unavailable node {id}; only {} earlier nodes exist",
                previous.len()
            ))
        })
}

// Typed remote derives reject unknown fields before reading their payloads.
// Transparent wrappers reuse those derives without changing the wire shape.
#[derive(Deserialize)]
#[serde(transparent)]
struct BlobPayload(#[serde(with = "BlobFields")] BlobRef);

#[derive(Deserialize)]
#[serde(transparent)]
struct TensorPayload(#[serde(with = "TensorFields")] TensorRef);

#[derive(Deserialize)]
#[serde(transparent)]
struct FramePayload(#[serde(with = "FrameFields")] FrameRef);

#[derive(Deserialize)]
#[serde(remote = "BlobRef", deny_unknown_fields)]
struct BlobFields {
    hash: String,
    size: u64,
    mime: Option<String>,
}

#[derive(Deserialize)]
#[serde(remote = "TensorRef", deny_unknown_fields)]
struct TensorFields {
    #[serde(with = "BlobFields")]
    blob: BlobRef,
    dtype: DType,
    shape: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(remote = "FrameRef", deny_unknown_fields)]
struct FrameFields {
    #[serde(with = "BlobFields")]
    blob: BlobRef,
    ts_nanos: i64,
    kind: FrameKind,
}
