//! Immutable resident ownership, independent of codecs, stores and executors.

use super::{
    BlobRef, DType, FloatBits, FrameKind, FrameRef, StreamMarker, TensorRef,
    collection::{CollectionRoot, ValueList, ValueMap},
    payload::{ValueBytes, ValueText},
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

/// An independently owned, immutable value used by operations and State.
///
/// Cloning shares immutable payloads in constant time. Constructing a container
/// can compose values from any source without importing their descendants or
/// retaining an allocation arena. Inspect values through [`Value::view`] and
/// update collections through their persistent, owned APIs.
///
/// Final container release walks the owned graph iteratively, using links
/// allocated with the nodes. Its stack usage does not follow value nesting.
#[derive(Clone)]
pub struct Value {
    repr: Repr,
}

#[derive(Clone)]
enum Repr {
    Null,
    Bool(bool),
    Int(i64),
    Float(FloatBits),
    Str(ValueText),
    Bytes(ValueBytes),
    List(ValueList),
    Map(ValueMap),
    Blob(Arc<BlobRef>),
    Tensor(Arc<TensorRef>),
    Frame(Arc<FrameRef>),
    StreamEnd(Arc<StreamMarker>),
}

/// Borrowed semantic variants, without exposing the resident ownership layout.
///
/// Creating and holding a view requires no allocation or lock. All referenced
/// data borrows a live [`Value`]. Collection iterators borrow the same owner;
/// cloning a selected child gives that child an independent lifetime.
#[derive(Clone, Copy, Debug)]
pub enum ValueView<'a> {
    /// Unit or absent value.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed integer.
    Int(i64),
    /// IEEE-754 bits, including signed zero and NaN payloads.
    Float(FloatBits),
    /// UTF-8 text.
    Str(&'a str),
    /// Resident bytes.
    Bytes(&'a [u8]),
    /// Ordered members.
    List(&'a ValueList),
    /// Members in strict UTF-8 key order.
    Map(&'a ValueMap),
    /// An opaque content reference.
    Blob(&'a BlobRef),
    /// A typed numeric content reference.
    Tensor(&'a TensorRef),
    /// A timestamped content reference.
    Frame(&'a FrameRef),
    /// Stream termination metadata.
    StreamEnd(&'a StreamMarker),
}

/// A temporary memoization key for a live resident allocation.
///
/// This is neither semantic equality nor a durable identifier, and grants no
/// ownership. Keep the borrowed root alive for the entire memoization scope:
/// an allocation address can be reused after its last owner is released.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValueIdentity {
    kind: u8,
    address: usize,
    len: usize,
}

impl Default for Value {
    fn default() -> Self {
        Self::null()
    }
}

impl Value {
    /// Construct the unit value without allocating.
    pub const fn null() -> Self {
        Self { repr: Repr::Null }
    }

    /// Return the unit value.
    pub const fn unit() -> Self {
        Self::null()
    }

    /// Construct an inline boolean.
    pub const fn boolean(value: bool) -> Self {
        Self {
            repr: Repr::Bool(value),
        }
    }

    /// Construct an inline signed integer.
    pub const fn integer(value: i64) -> Self {
        Self {
            repr: Repr::Int(value),
        }
    }

    /// Construct an inline float while preserving every IEEE-754 bit.
    pub const fn float(value: FloatBits) -> Self {
        Self {
            repr: Repr::Float(value),
        }
    }

    /// Move text into shared immutable ownership.
    pub fn string(value: String) -> Self {
        Self {
            repr: Repr::Str(ValueText::owned(value)),
        }
    }

    /// Retain an existing immutable text allocation without copying its bytes.
    pub fn shared_text(value: Arc<str>) -> Self {
        Self {
            repr: Repr::Str(ValueText::shared(value)),
        }
    }

    /// Move bytes into shared immutable ownership.
    pub fn bytes(value: Vec<u8>) -> Self {
        Self {
            repr: Repr::Bytes(ValueBytes::owned(value)),
        }
    }

    /// Retain an existing byte allocation without copying its contents.
    pub fn shared_bytes(value: Arc<[u8]>) -> Self {
        Self {
            repr: Repr::Bytes(ValueBytes::shared(value)),
        }
    }

    /// Build ordered members. Nested payloads are moved without traversal.
    pub fn list(values: Vec<Value>) -> Self {
        Self::from(ValueList::from(values))
    }

    /// Build a map in UTF-8 key order. Nested payloads are moved without traversal.
    pub fn map(values: BTreeMap<String, Value>) -> Self {
        Self::from(ValueMap::from(values))
    }

    /// Construct a content reference without reading its bytes.
    pub fn blob(value: BlobRef) -> Self {
        Self {
            repr: Repr::Blob(Arc::new(value)),
        }
    }

    /// Construct a typed numeric content reference.
    pub fn tensor(blob: BlobRef, dtype: DType, shape: Vec<u64>) -> Self {
        Self::from(TensorRef { blob, dtype, shape })
    }

    /// Construct a timestamped content reference.
    pub fn frame(blob: BlobRef, ts_nanos: i64, kind: FrameKind) -> Self {
        Self::from(FrameRef {
            blob,
            ts_nanos,
            kind,
        })
    }

    /// Construct stream termination metadata.
    pub fn stream_end(value: StreamMarker) -> Self {
        Self {
            repr: Repr::StreamEnd(Arc::new(value)),
        }
    }

    /// Inspect semantic type and contents without locking or allocating.
    pub fn view(&self) -> ValueView<'_> {
        match &self.repr {
            Repr::Null => ValueView::Null,
            Repr::Bool(value) => ValueView::Bool(*value),
            Repr::Int(value) => ValueView::Int(*value),
            Repr::Float(value) => ValueView::Float(*value),
            Repr::Str(value) => ValueView::Str(value),
            Repr::Bytes(value) => ValueView::Bytes(value),
            Repr::List(value) => ValueView::List(value),
            Repr::Map(value) => ValueView::Map(value),
            Repr::Blob(value) => ValueView::Blob(value),
            Repr::Tensor(value) => ValueView::Tensor(value),
            Repr::Frame(value) => ValueView::Frame(value),
            Repr::StreamEnd(value) => ValueView::StreamEnd(value),
        }
    }

    /// Borrow a list's persistent collection interface.
    pub fn as_list(&self) -> Option<&ValueList> {
        match &self.repr {
            Repr::List(value) => Some(value),
            _ => None,
        }
    }

    /// Borrow a map's persistent collection interface.
    pub fn as_map(&self) -> Option<&ValueMap> {
        match &self.repr {
            Repr::Map(value) => Some(value),
            _ => None,
        }
    }

    /// Borrow text contents.
    pub fn as_str(&self) -> Option<&str> {
        match &self.repr {
            Repr::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Borrow resident bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.repr {
            Repr::Bytes(value) => Some(value),
            _ => None,
        }
    }

    /// Return the inline signed integer.
    pub fn as_int(&self) -> Option<i64> {
        match self.repr {
            Repr::Int(value) => Some(value),
            _ => None,
        }
    }

    /// Return the inline boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self.repr {
            Repr::Bool(value) => Some(value),
            _ => None,
        }
    }

    /// Test for the unit value.
    pub fn is_null(&self) -> bool {
        matches!(self.repr, Repr::Null)
    }

    /// Consume a list root without copying its descendants.
    pub fn into_list(self) -> Option<ValueList> {
        match self.repr {
            Repr::List(value) => Some(value),
            _ => None,
        }
    }

    /// Consume a map root without copying its descendants.
    pub fn into_map(self) -> Option<ValueMap> {
        match self.repr {
            Repr::Map(value) => Some(value),
            _ => None,
        }
    }

    /// Consume text while retaining the existing immutable allocation.
    pub fn into_text(self) -> Option<ValueText> {
        match self.repr {
            Repr::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Consume bytes while retaining the existing immutable allocation.
    pub fn into_bytes(self) -> Option<ValueBytes> {
        match self.repr {
            Repr::Bytes(value) => Some(value),
            _ => None,
        }
    }

    /// Project media metadata without I/O, validation, or read authority.
    pub fn backing_blob(&self) -> Option<&BlobRef> {
        match &self.repr {
            Repr::Blob(value) => Some(value),
            Repr::Tensor(value) => Some(&value.blob),
            Repr::Frame(value) => Some(&value.blob),
            _ => None,
        }
    }

    /// Whether the root is an out-of-line blob, tensor or frame reference.
    pub fn is_large_ref(&self) -> bool {
        self.backing_blob().is_some()
    }

    /// Obtain an allocation identity scoped to this root's live ownership.
    pub fn identity(&self) -> Option<ValueIdentity> {
        let (kind, address, len) = match &self.repr {
            Repr::Str(value) => (1, value.as_ptr().addr(), value.len()),
            Repr::Bytes(value) => (2, value.as_ptr().addr(), value.len()),
            Repr::List(value) => (3, value.root_identity()?, value.len()),
            Repr::Map(value) => (4, value.root_identity()?, value.len()),
            Repr::Blob(value) => (5, Arc::as_ptr(value).addr(), 0),
            Repr::Tensor(value) => (6, Arc::as_ptr(value).addr(), 0),
            Repr::Frame(value) => (7, Arc::as_ptr(value).addr(), 0),
            Repr::StreamEnd(value) => (8, Arc::as_ptr(value).addr(), 0),
            Repr::Null | Repr::Bool(_) | Repr::Int(_) | Repr::Float(_) => return None,
        };
        Some(ValueIdentity { kind, address, len })
    }

    /// Transfer child ownership into the one iterative collection reclaimer.
    pub(super) fn into_collection_root(self) -> Option<CollectionRoot> {
        match self.repr {
            Repr::List(value) => value.into_root(),
            Repr::Map(value) => value.into_root(),
            Repr::Null
            | Repr::Bool(_)
            | Repr::Int(_)
            | Repr::Float(_)
            | Repr::Str(_)
            | Repr::Bytes(_)
            | Repr::Blob(_)
            | Repr::Tensor(_)
            | Repr::Frame(_)
            | Repr::StreamEnd(_) => None,
        }
    }
}

impl From<ValueList> for Value {
    fn from(value: ValueList) -> Self {
        Self {
            repr: Repr::List(value),
        }
    }
}
impl From<ValueText> for Value {
    fn from(value: ValueText) -> Self {
        Self {
            repr: Repr::Str(value),
        }
    }
}
impl From<ValueBytes> for Value {
    fn from(value: ValueBytes) -> Self {
        Self {
            repr: Repr::Bytes(value),
        }
    }
}
impl From<ValueMap> for Value {
    fn from(value: ValueMap) -> Self {
        Self {
            repr: Repr::Map(value),
        }
    }
}
impl From<TensorRef> for Value {
    fn from(value: TensorRef) -> Self {
        Self {
            repr: Repr::Tensor(Arc::new(value)),
        }
    }
}
impl From<FrameRef> for Value {
    fn from(value: FrameRef) -> Self {
        Self {
            repr: Repr::Frame(Arc::new(value)),
        }
    }
}
impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::shared_text(value.into())
    }
}
impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::string(value)
    }
}
impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::integer(value)
    }
}
impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::boolean(value)
    }
}
impl From<()> for Value {
    fn from((): ()) -> Self {
        Self::null()
    }
}
