use super::{VERSION, ValueRoot};
use crate::Value;
use alloc::{format, vec::Vec};
use core::fmt;
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};

mod node;

struct Nodes;

impl<'de> DeserializeSeed<'de> for Nodes {
    type Value = Vec<Value>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Nodes {
    type Value = Vec<Value>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a value node table containing only references to earlier nodes")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut nodes = Vec::new();
        // Do not reserve an untrusted advertised sequence length before seeing
        // records. Every temporary root is safe to release on an error.
        while let Some(value) = sequence.next_element_seed(node::Node { previous: &nodes })? {
            nodes.try_reserve(1).map_err(de::Error::custom)?;
            nodes.push(value);
        }
        Ok(nodes)
    }
}

struct Version;

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = u32::deserialize(deserializer)?;
        if version != VERSION {
            return Err(de::Error::custom(format!(
                "unsupported value table version {version}; expected {VERSION}"
            )));
        }
        Ok(Self)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Version,
    Nodes,
    Root,
}

/// A fully validated resident node table shared by every field in one record.
///
/// Decode the whole table, then resolve each of the owning record's root IDs.
/// Returned Values independently retain their selected descendants; releasing
/// this context does not invalidate them or retain unrelated table nodes.
pub struct ValueTableDecoder {
    nodes: Vec<Value>,
}

impl ValueTableDecoder {
    /// Resolve an in-range ID to an independently owned, shared Value.
    ///
    /// An ID from another table is not valid context. The owning record must
    /// supply the matching table and reject a missing root before publishing
    /// any partially decoded application state.
    pub fn resolve(&self, root: ValueRoot) -> Option<Value> {
        usize::try_from(root.0)
            .ok()
            .and_then(|index| self.nodes.get(index))
            .cloned()
    }

    /// Number of validated resident nodes in the serialized table.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl<'de> Deserialize<'de> for ValueTableDecoder {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = deserializer.deserialize_struct(
            "ValueNodes",
            &["version", "nodes"],
            Document { with_root: false },
        )?;
        Ok(Self {
            nodes: document.nodes,
        })
    }
}

struct Document {
    with_root: bool,
}
struct ParsedDocument {
    nodes: Vec<Value>,
    root: Option<ValueRoot>,
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    let document = deserializer.deserialize_struct(
        "ValueTable",
        &["version", "nodes", "root"],
        Document { with_root: true },
    )?;
    let root = document
        .root
        .ok_or_else(|| de::Error::missing_field("root"))?;
    ValueTableDecoder {
        nodes: document.nodes,
    }
    .resolve(root)
    .ok_or_else(|| de::Error::custom("value table root references an unavailable node"))
}

impl<'de> Visitor<'de> for Document {
    type Value = ParsedDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a versioned value node table with the requested root shape")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut record: A) -> Result<ParsedDocument, A::Error> {
        let mut version = None;
        let mut nodes = None;
        let mut root = None;
        while let Some(field) = record.next_key::<Field>()? {
            match field {
                Field::Version => {
                    if version.is_some() {
                        return Err(de::Error::duplicate_field("version"));
                    }
                    version = Some(record.next_value::<Version>()?);
                }
                Field::Nodes => {
                    if nodes.is_some() {
                        return Err(de::Error::duplicate_field("nodes"));
                    }
                    nodes = Some(record.next_value_seed(Nodes)?);
                }
                Field::Root => {
                    if !self.with_root {
                        return Err(de::Error::unknown_field("root", &["version", "nodes"]));
                    }
                    if root.is_some() {
                        return Err(de::Error::duplicate_field("root"));
                    }
                    root = Some(record.next_value::<ValueRoot>()?);
                }
            }
        }
        version.ok_or_else(|| de::Error::missing_field("version"))?;
        let nodes = nodes.ok_or_else(|| de::Error::missing_field("nodes"))?;
        if self.with_root && root.is_none() {
            return Err(de::Error::missing_field("root"));
        }
        Ok(ParsedDocument { nodes, root })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut fields: A) -> Result<ParsedDocument, A::Error> {
        fields
            .next_element::<Version>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let nodes = fields
            .next_element_seed(Nodes)?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let root = if self.with_root {
            Some(
                fields
                    .next_element::<ValueRoot>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?,
            )
        } else {
            None
        };
        // Struct sequence adapters know the exact expected arity. If a format
        // exposes an extra element, reject it without visiting arbitrary data.
        if fields.next_element::<RejectExtra>()?.is_some() {
            return Err(de::Error::invalid_length(
                if self.with_root { 4 } else { 3 },
                &self,
            ));
        }
        Ok(ParsedDocument { nodes, root })
    }
}

struct RejectExtra;
impl<'de> Deserialize<'de> for RejectExtra {
    fn deserialize<D: Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        Err(de::Error::custom("unexpected extra value table field"))
    }
}
