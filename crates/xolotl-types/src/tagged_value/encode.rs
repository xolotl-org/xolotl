use super::{VERSION, ValueRoot, ValueTableEncodeError};
use crate::value::{
    ValueList, ValueMap, ValueView,
    traversal::{ValueNodeKey, ValuePostorder},
};
use crate::{BlobRef, FrameRef, StreamMarker, TensorRef, Value};
use alloc::{collections::BTreeMap, vec::Vec};
use serde::{
    Serialize, Serializer,
    ser::{Error, SerializeSeq, SerializeStruct},
};

/// Shared lossless encoding context borrowing all roots of one owning record.
///
/// Interning never clones resident payloads. Independently owned roots may
/// share descendants, and the context emits each shared allocation once.
/// Keep every borrowed root alive until serialization finishes. The temporary
/// index is proportional to the union of their resident graphs; it imposes no
/// arbitrary depth or node count limit.
#[derive(Default)]
pub struct ValueTableEncoder<'a> {
    nodes: Vec<&'a Value>,
    ids: BTreeMap<ValueNodeKey<'a>, u64>,
}

impl<'a> ValueTableEncoder<'a> {
    /// Intern one root with a conservative predescent work budget. Unique nodes,
    /// reference edges, map key bytes, and string/byte payload bytes each charge
    /// one unit. Shared nodes charge once, but every resident reference charges.
    /// Rejection happens before allocating the candidate's traversal frame;
    /// discard this encoder after an error. Exact encoded bytes are a separate
    /// writer limit, and this work budget is not an RSS ceiling.
    pub fn intern_bounded(
        &mut self,
        root: &'a Value,
        budget: usize,
    ) -> Result<ValueRoot, ValueTableEncodeError> {
        self.intern_with_budget(root, Some(budget))
    }

    /// Serialize an already indexed root in the same standalone format as
    /// [`super::serializable`], without rebuilding its node index.
    pub fn serializable_root(&self, root: ValueRoot) -> impl Serialize + '_ {
        IndexedRoot { table: self, root }
    }

    /// Construct an empty context without allocating.
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a root and its descendants, retaining only borrowed references.
    ///
    /// Calling this again for a previously interned allocation reuses its ID.
    /// Semantic equality alone does not merge independently allocated nodes.
    pub fn intern(&mut self, root: &'a Value) -> Result<ValueRoot, ValueTableEncodeError> {
        self.intern_with_budget(root, None)
    }

    fn intern_with_budget(
        &mut self,
        root: &'a Value,
        mut remaining: Option<usize>,
    ) -> Result<ValueRoot, ValueTableEncodeError> {
        let mut walk = ValuePostorder::new(root);
        while let Some(value) = walk.try_next(
            |key| self.ids.contains_key(&key),
            |value, _depth| {
                let Some(budget) = remaining.as_mut() else {
                    return Ok(());
                };
                let mut charge = |units: usize| -> Result<(), ValueTableEncodeError> {
                    *budget = budget
                        .checked_sub(units)
                        .ok_or(ValueTableEncodeError::BudgetExceeded)?;
                    Ok(())
                };
                charge(1)?;
                match value.view() {
                    ValueView::List(items) => charge(items.len())?,
                    ValueView::Map(entries) => {
                        charge(entries.len())?;
                        for (key, _) in entries.iter() {
                            charge(key.len())?;
                        }
                    }
                    ValueView::Str(text) => charge(text.len())?,
                    ValueView::StreamEnd(StreamMarker::Error { message }) => charge(message.len())?,
                    ValueView::Bytes(bytes) => charge(bytes.len())?,
                    _ => {}
                }
                Ok(())
            },
        )? {
            let id = u64::try_from(self.nodes.len())
                .map_err(|_error| ValueTableEncodeError::NodeIdOverflow)?;
            self.ids.insert(ValueNodeKey::of(value), id);
            self.nodes.push(value);
        }
        self.ids
            .get(&ValueNodeKey::of(root))
            .copied()
            .map(ValueRoot)
            .ok_or(ValueTableEncodeError::MissingRoot)
    }

    /// Number of distinct resident nodes currently represented in this table.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

struct IndexedRoot<'index, 'value> {
    table: &'index ValueTableEncoder<'value>,
    root: ValueRoot,
}

impl Serialize for IndexedRoot<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("ValueTable", 3)?;
        record.serialize_field("version", &VERSION)?;
        record.serialize_field("nodes", &Nodes(self.table))?;
        record.serialize_field("root", &self.root)?;
        record.end()
    }
}

impl Serialize for ValueTableEncoder<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("ValueNodes", 2)?;
        record.serialize_field("version", &VERSION)?;
        record.serialize_field("nodes", &Nodes(self))?;
        record.end()
    }
}

pub(super) fn serialize<S: Serializer>(value: &Value, serializer: S) -> Result<S::Ok, S::Error> {
    let mut table = ValueTableEncoder::new();
    let root = table.intern(value).map_err(S::Error::custom)?;
    let mut record = serializer.serialize_struct("ValueTable", 3)?;
    record.serialize_field("version", &VERSION)?;
    record.serialize_field("nodes", &Nodes(&table))?;
    record.serialize_field("root", &root)?;
    record.end()
}

struct Nodes<'index, 'value>(&'index ValueTableEncoder<'value>);

impl Serialize for Nodes<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.nodes.len()))?;
        for value in &self.0.nodes {
            sequence.serialize_element(&Node::of(value, &self.0.ids))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Node<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Float(u64),
    Str(&'a str),
    Bytes(&'a [u8]),
    List(List<'a>),
    Map(Map<'a>),
    Blob(&'a BlobRef),
    Tensor(&'a TensorRef),
    Frame(&'a FrameRef),
    StreamDone,
    StreamError(&'a str),
}

impl<'a> Node<'a> {
    fn of(value: &'a Value, ids: &'a BTreeMap<ValueNodeKey<'a>, u64>) -> Self {
        match value.view() {
            ValueView::Null => Self::Null,
            ValueView::Bool(value) => Self::Bool(value),
            ValueView::Int(value) => Self::Int(value),
            ValueView::Float(value) => Self::Float(value.0.to_bits()),
            ValueView::Str(value) => Self::Str(value),
            ValueView::Bytes(value) => Self::Bytes(value),
            ValueView::List(items) => Self::List(List { items, ids }),
            ValueView::Map(entries) => Self::Map(Map { entries, ids }),
            ValueView::Blob(value) => Self::Blob(value),
            ValueView::Tensor(value) => Self::Tensor(value),
            ValueView::Frame(value) => Self::Frame(value),
            ValueView::StreamEnd(StreamMarker::Done) => Self::StreamDone,
            ValueView::StreamEnd(StreamMarker::Error { message }) => Self::StreamError(message),
        }
    }
}

struct List<'a> {
    items: &'a ValueList,
    ids: &'a BTreeMap<ValueNodeKey<'a>, u64>,
}

impl Serialize for List<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.items.len()))?;
        for value in self.items.iter() {
            let id = self
                .ids
                .get(&ValueNodeKey::of(value))
                .ok_or_else(|| S::Error::custom("value table is missing a list child"))?;
            sequence.serialize_element(id)?;
        }
        sequence.end()
    }
}

struct Map<'a> {
    entries: &'a ValueMap,
    ids: &'a BTreeMap<ValueNodeKey<'a>, u64>,
}

impl Serialize for Map<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.entries.len()))?;
        for (key, value) in self.entries.iter() {
            let id = self
                .ids
                .get(&ValueNodeKey::of(value))
                .ok_or_else(|| S::Error::custom("value table is missing a map child"))?;
            sequence.serialize_element(&(key, id))?;
        }
        sequence.end()
    }
}
