//! Representation contracts shared by embedding producers and retrieval consumers.
//!
//! These are Standard capability protocols, not new kernel Value variants.
//! Parsing a reference does not read it or grant access to its content.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{TensorRef, Value, ValueList, ValueMap, ValueText};

pub(crate) mod admission;

/// Host-selected retrieval work windows and object read capability. The
/// settings bound one I/O or cooperative work window, not total vector size.
#[derive(Clone)]
pub struct RetrievalConfig {
    pub(crate) objects: ObjectStore,
    pub(crate) io_window: NonZeroUsize,
    pub(crate) work_quantum: NonZeroUsize,
}

impl Default for RetrievalConfig {
    fn default() -> Self {
        Self {
            objects: ObjectStore::new(),
            io_window: NonZeroUsize::MIN.saturating_add(16 * 1024 - 1),
            work_quantum: NonZeroUsize::MIN.saturating_add(4095),
        }
    }
}

impl RetrievalConfig {
    /// Explicitly install the object reader available to tensor consumers.
    /// References in unrelated values are never recursively loaded.
    pub fn with_object_reader(mut self, objects: ObjectStore) -> Self {
        self.objects = objects;
        self
    }

    /// Select the borrowed byte window used to decode tensor objects. Even a
    /// one-byte window supports every dtype through a scalar carry buffer.
    pub fn with_io_window(mut self, bytes: NonZeroUsize) -> Self {
        self.io_window = bytes;
        self
    }

    /// Select how many scalar operations run before yielding to the executor.
    pub fn with_work_quantum(mut self, operations: NonZeroUsize) -> Self {
        self.work_quantum = operations;
        self
    }
}

/// One explicitly selected embedding representation.
#[derive(Clone, Debug)]
pub enum EmbeddingRepresentation {
    /// One inline dense vector. The consumer chooses numeric precision.
    Dense(ValueList),
    /// A rank-one tensor, read only by an explicitly installed consumer.
    Tensor(TensorRef),
    /// Sorted unique coordinates in an explicitly dimensioned space.
    Sparse {
        /// Full logical dimension, independent of the number of nonzero values.
        dimensions: usize,
        /// Strictly increasing coordinate indices.
        indices: ValueList,
        /// One numeric value for each coordinate.
        values: ValueList,
    },
    /// A list of equally dimensioned dense vectors. Row counts may differ.
    MultiVector(ValueList),
    /// A rank-two tensor with rows representing independently scored vectors.
    MultiTensor(TensorRef),
}

impl EmbeddingRepresentation {
    /// Encode a tagged representation without reading or materializing references.
    pub fn into_value(self) -> Value {
        let (kind, mut fields) = match self {
            Self::Dense(values) => (
                "dense",
                BTreeMap::from([("values".into(), Value::from(values))]),
            ),
            Self::Tensor(tensor) => (
                "tensor",
                BTreeMap::from([("tensor".into(), Value::from(tensor))]),
            ),
            Self::Sparse {
                dimensions,
                indices,
                values,
            } => (
                "sparse",
                BTreeMap::from([
                    ("dimensions".into(), Value::string(dimensions.to_string())),
                    ("indices".into(), Value::from(indices)),
                    ("values".into(), Value::from(values)),
                ]),
            ),
            Self::MultiVector(vectors) => (
                "multi",
                BTreeMap::from([("vectors".into(), Value::from(vectors))]),
            ),
            Self::MultiTensor(tensor) => (
                "multi_tensor",
                BTreeMap::from([("tensor".into(), Value::from(tensor))]),
            ),
        };
        fields.insert("kind".into(), Value::string(kind.into()));
        Value::map(fields)
    }

    /// Parse only the explicit variant and shape envelope; numeric and storage
    /// admission belongs to the concrete consumer.
    pub fn from_value(value: Value) -> Result<Self, &'static str> {
        let fields = value
            .as_map()
            .ok_or("embedding representation must be a map")?;
        match fields.get("kind").and_then(Value::as_str) {
            Some("dense") => Ok(Self::Dense(list(fields, "values")?)),
            Some("tensor") => Ok(Self::Tensor(tensor(fields)?)),
            Some("sparse") => {
                let dimensions = match fields.get("dimensions") {
                    Some(value) if value.as_str().is_some() => {
                        value.as_str().and_then(|value| value.parse().ok())
                    }
                    Some(value) => value.as_int().and_then(|value| usize::try_from(value).ok()),
                    None => None,
                }
                .filter(|dimensions| *dimensions != 0)
                .ok_or("sparse dimensions must be a positive platform-sized integer")?;
                Ok(Self::Sparse {
                    dimensions,
                    indices: list(fields, "indices")?,
                    values: list(fields, "values")?,
                })
            }
            Some("multi") => Ok(Self::MultiVector(list(fields, "vectors")?)),
            Some("multi_tensor") => Ok(Self::MultiTensor(tensor(fields)?)),
            _ => Err(
                "embedding representation requires kind dense, tensor, sparse, multi, or multi_tensor",
            ),
        }
    }
}

/// An embedding with an explicit space and representation, shared by providers
/// and consumers without depending on a particular inference backend.
#[derive(Clone, Debug)]
pub struct Embedding {
    /// Logical space separating incompatible models or embedding conventions.
    pub space_id: ValueText,
    /// Numeric representation or an explicit tensor reference.
    pub representation: EmbeddingRepresentation,
    /// Optional producing model identifier, retained as metadata.
    pub embedding_model: Option<ValueText>,
}

impl Embedding {
    /// Encode the shared embedding capability envelope.
    pub fn into_value(self) -> Value {
        let mut fields = BTreeMap::from([
            ("representation".into(), self.representation.into_value()),
            ("space_id".into(), Value::from(self.space_id)),
        ]);
        if let Some(model) = self.embedding_model {
            fields.insert("embedding_model".into(), Value::from(model));
        }
        Value::map(fields)
    }

    /// Parse the shared envelope without granting or reading object references.
    pub fn from_value(value: Value) -> Result<Self, &'static str> {
        let fields = value.as_map().ok_or("embed output must be a map")?;
        let representation = EmbeddingRepresentation::from_value(
            fields
                .get("representation")
                .cloned()
                .ok_or("embed output requires a representation")?,
        )?;
        let space_id = fields
            .get("space_id")
            .cloned()
            .and_then(Value::into_text)
            .filter(|space| !space.trim().is_empty())
            .ok_or("embed output requires a nonempty space_id string")?;
        let embedding_model = fields
            .get("embedding_model")
            .cloned()
            .map(|model| {
                model
                    .into_text()
                    .ok_or("embed output embedding_model must be a string")
            })
            .transpose()?;
        Ok(Self {
            space_id,
            representation,
            embedding_model,
        })
    }
}

fn list(fields: &ValueMap, key: &str) -> Result<ValueList, &'static str> {
    fields
        .get(key)
        .cloned()
        .and_then(Value::into_list)
        .ok_or("embedding representation is missing a required list")
}

fn tensor(fields: &ValueMap) -> Result<TensorRef, &'static str> {
    match fields.get("tensor").map(Value::view) {
        Some(xolotl_types::ValueView::Tensor(tensor)) => Ok(tensor.clone()),
        _ => Err("embedding representation requires a typed tensor reference"),
    }
}

#[cfg(test)]
pub(crate) mod tests;
