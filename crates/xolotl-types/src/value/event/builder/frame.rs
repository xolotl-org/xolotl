use super::{BuilderError, keys::Keys};
use crate::{
    BlobRef, DType, FloatBits, FrameKind, Path, StreamMarker, TaintSet, TaintSource, Value,
    value::{
        ValueListBuilder, ValueMapBuilder,
        event::{Atom, KeyId, Kind},
    },
};
use alloc::{boxed::Box, string::String, vec::Vec};
use smol_str::SmolStr;

/// Typed, completed fields live only while moving to their immediate parent.
/// Metadata never passes through a temporary Value map or JSON representation.
pub(super) enum Field {
    Document(Value),
    Taint,
    Value(Value),
    Atom(Atom),
    Text(String),
    Key(String),
    Blob(BlobRef),
    Shape(Vec<u64>),
    Source(TaintSource),
    Path(Path),
    PathSegments(Vec<SmolStr>),
}

impl Field {
    fn into_value(self) -> Result<Value, BuilderError> {
        match self {
            Self::Value(value) => Ok(value),
            Self::Text(text) => Ok(Value::string(text)),
            Self::Blob(blob) => Ok(Value::blob(blob)),
            Self::Atom(atom) => match atom {
                Atom::Null => Ok(Value::null()),
                Atom::Bool(value) => Ok(Value::boolean(value)),
                Atom::I64(value) => Ok(Value::integer(value)),
                Atom::F64Bits(bits) => Ok(Value::float(FloatBits(f64::from_bits(bits)))),
                Atom::StreamDone => Ok(Value::stream_end(StreamMarker::Done)),
                _ => Err(BuilderError::Invariant("value atom")),
            },
            _ => Err(BuilderError::Invariant("value field")),
        }
    }

    fn into_source(self) -> Result<TaintSource, BuilderError> {
        match self {
            Self::Source(source) => Ok(source),
            Self::Atom(Atom::Author) => Ok(TaintSource::AuthorConstant),
            Self::Atom(Atom::Model) => Ok(TaintSource::ModelOutput),
            _ => Err(BuilderError::Invariant("taint source")),
        }
    }
}

/// Rare fixed metadata uses a separate allocation so its largest record does
/// not determine every frame's size in deeply nested ordinary lists or maps.
pub(super) enum Frame {
    Document {
        value: Option<Value>,
    },
    Taint,
    String(Vec<u8>),
    Bytes(Vec<u8>),
    Key(KeyId),
    List(ValueListBuilder),
    Map {
        entries: ValueMapBuilder,
        key: Option<String>,
    },
    Shape(Vec<u64>),
    PathSegments(Vec<SmolStr>),
    Record(Box<Record>),
}

impl Frame {
    pub(super) fn new(kind: Kind, keys: &mut Keys) -> Result<Self, BuilderError> {
        Ok(match kind {
            Kind::Document => Self::Document { value: None },
            Kind::Taint => Self::Taint,
            Kind::String => Self::String(Vec::new()),
            Kind::Bytes => Self::Bytes(Vec::new()),
            Kind::Key => Self::Key(keys.take_created()?),
            Kind::List => Self::List(ValueListBuilder::new()),
            Kind::Map => Self::Map {
                entries: ValueMapBuilder::new(),
                key: None,
            },
            Kind::Shape => Self::Shape(Vec::new()),
            Kind::PathSegments => Self::PathSegments(Vec::new()),
            _ => Self::Record(Box::new(Record::new(kind)?)),
        })
    }

    pub(super) fn data(&mut self, bytes: &[u8]) -> Result<(), BuilderError> {
        match self {
            Self::String(stored) | Self::Bytes(stored) => {
                stored.try_reserve(bytes.len())?;
                stored.extend_from_slice(bytes);
                Ok(())
            }
            // The validator has already appended this fragment to our key
            // workspace; retain it there exactly once during construction.
            Self::Key(_) => Ok(()),
            _ => Err(BuilderError::Invariant("byte field")),
        }
    }

    pub(super) fn accept(
        &mut self,
        field: Field,
        observed_taint: &mut TaintSet,
    ) -> Result<(), BuilderError> {
        match (self, field) {
            (Self::Document { .. }, Field::Taint) => Ok(()),
            (Self::Document { value, .. }, field) if value.is_none() => {
                *value = Some(field.into_value()?);
                Ok(())
            }
            (Self::Taint, field) => {
                observed_taint.push_recorded_source(field.into_source()?)?;
                Ok(())
            }
            (Self::List(values), field) => {
                values.push(field.into_value()?)?;
                Ok(())
            }
            (Self::Map { key, .. }, Field::Key(text)) if key.is_none() => {
                *key = Some(text);
                Ok(())
            }
            (Self::Map { entries, key }, field) => {
                let key = key.take().ok_or(BuilderError::Invariant("map value key"))?;
                entries.append(key, field.into_value()?)?;
                Ok(())
            }
            (Self::Shape(dimensions), Field::Atom(Atom::U64(dimension))) => {
                dimensions.try_reserve(1)?;
                dimensions.push(dimension);
                Ok(())
            }
            (Self::PathSegments(segments), Field::Text(segment)) => {
                segments.try_reserve(1)?;
                segments.push(SmolStr::from(segment));
                Ok(())
            }
            (Self::Record(record), field) => record.accept(field),
            _ => Err(BuilderError::Invariant("record field")),
        }
    }

    pub(super) fn finish(self, keys: &Keys) -> Result<Field, BuilderError> {
        Ok(match self {
            Self::Document { value: Some(value) } => Field::Document(value),
            Self::Taint => Field::Taint,
            Self::String(bytes) => Field::Text(
                String::from_utf8(bytes).map_err(|_error| BuilderError::Invariant("text UTF-8"))?,
            ),
            Self::Bytes(bytes) => Field::Value(Value::bytes(bytes)),
            Self::Key(key) => Field::Key(keys.text(key)?),
            Self::List(values) => Field::Value(Value::from(values.finish())),
            Self::Map { entries, key: None } => Field::Value(Value::from(entries.finish())),
            Self::Shape(shape) => Field::Shape(shape),
            Self::PathSegments(segments) => Field::PathSegments(segments),
            Self::Record(record) => record.finish()?,
            _ => return Err(BuilderError::Invariant("completed record")),
        })
    }
}

pub(super) enum Record {
    Blob {
        hash: Option<String>,
        size: Option<u64>,
        mime: Option<Option<String>>,
    },
    Tensor {
        blob: Option<BlobRef>,
        dtype: Option<DType>,
        shape: Option<Vec<u64>>,
    },
    Frame {
        blob: Option<BlobRef>,
        timestamp: Option<i64>,
        kind: Option<FrameKind>,
    },
    StreamError(Option<String>),
    Inbound {
        source: Option<String>,
        channel: Option<String>,
    },
    Fetched(Option<String>),
    Protected(Option<Path>),
    Path {
        cluster: Option<Option<String>>,
        scheme: Option<String>,
        segments: Option<Vec<SmolStr>>,
    },
}

impl Record {
    fn new(kind: Kind) -> Result<Self, BuilderError> {
        Ok(match kind {
            Kind::Blob => Self::Blob {
                hash: None,
                size: None,
                mime: None,
            },
            Kind::Tensor => Self::Tensor {
                blob: None,
                dtype: None,
                shape: None,
            },
            Kind::Frame => Self::Frame {
                blob: None,
                timestamp: None,
                kind: None,
            },
            Kind::StreamError => Self::StreamError(None),
            Kind::Inbound => Self::Inbound {
                source: None,
                channel: None,
            },
            Kind::Fetched => Self::Fetched(None),
            Kind::Protected => Self::Protected(None),
            Kind::Path => Self::Path {
                cluster: None,
                scheme: None,
                segments: None,
            },
            _ => return Err(BuilderError::Invariant("metadata record kind")),
        })
    }

    fn accept(&mut self, field: Field) -> Result<(), BuilderError> {
        match (self, field) {
            (Self::Blob { hash, .. }, Field::Text(text)) if hash.is_none() => {
                *hash = Some(text);
            }
            (Self::Blob { mime, .. }, Field::Text(text)) if mime.is_none() => {
                *mime = Some(Some(text));
            }
            (Self::Blob { mime, .. }, Field::Atom(Atom::Null)) if mime.is_none() => {
                *mime = Some(None);
            }
            (Self::Blob { size, .. }, Field::Atom(Atom::U64(value))) if size.is_none() => {
                *size = Some(value);
            }
            (Self::Tensor { blob, .. } | Self::Frame { blob, .. }, Field::Blob(value))
                if blob.is_none() =>
            {
                *blob = Some(value);
            }
            (Self::Tensor { dtype, .. }, Field::Atom(Atom::DType(value))) if dtype.is_none() => {
                *dtype = Some(value);
            }
            (Self::Tensor { shape, .. }, Field::Shape(value)) if shape.is_none() => {
                *shape = Some(value);
            }
            (Self::Frame { timestamp, .. }, Field::Atom(Atom::I64(value)))
                if timestamp.is_none() =>
            {
                *timestamp = Some(value);
            }
            (Self::Frame { kind, .. }, Field::Atom(Atom::FrameKind(value))) if kind.is_none() => {
                *kind = Some(value);
            }
            (Self::StreamError(message) | Self::Fetched(message), Field::Text(text))
                if message.is_none() =>
            {
                *message = Some(text);
            }
            (Self::Inbound { source, .. }, Field::Text(text)) if source.is_none() => {
                *source = Some(text);
            }
            (Self::Inbound { channel, .. }, Field::Text(text)) if channel.is_none() => {
                *channel = Some(text);
            }
            (Self::Protected(path), Field::Path(value)) if path.is_none() => {
                *path = Some(value);
            }
            (Self::Path { cluster, .. }, Field::Atom(Atom::Null)) if cluster.is_none() => {
                *cluster = Some(None);
            }
            (Self::Path { cluster, .. }, Field::Text(text)) if cluster.is_none() => {
                *cluster = Some(Some(text));
            }
            (Self::Path { scheme, .. }, Field::Text(text)) if scheme.is_none() => {
                *scheme = Some(text);
            }
            (Self::Path { segments, .. }, Field::PathSegments(value)) if segments.is_none() => {
                *segments = Some(value);
            }
            _ => return Err(BuilderError::Invariant("metadata field")),
        }
        Ok(())
    }

    fn finish(self) -> Result<Field, BuilderError> {
        Ok(match self {
            Self::Blob {
                hash: Some(hash),
                size: Some(size),
                mime: Some(mime),
            } => Field::Blob(BlobRef { hash, size, mime }),
            Self::Tensor {
                blob: Some(blob),
                dtype: Some(dtype),
                shape: Some(shape),
            } => Field::Value(Value::tensor(blob, dtype, shape)),
            Self::Frame {
                blob: Some(blob),
                timestamp: Some(timestamp),
                kind: Some(kind),
            } => Field::Value(Value::frame(blob, timestamp, kind)),
            Self::StreamError(Some(message)) => {
                Field::Value(Value::stream_end(StreamMarker::Error { message }))
            }
            Self::Inbound {
                source: Some(source),
                channel: Some(channel),
            } => Field::Source(TaintSource::Inbound {
                source: source.into(),
                channel: channel.into(),
            }),
            Self::Fetched(Some(host)) => Field::Source(TaintSource::Fetched { host: host.into() }),
            Self::Protected(Some(path)) => Field::Source(TaintSource::Protected { path }),
            Self::Path {
                cluster: Some(cluster),
                scheme: Some(scheme),
                segments: Some(segments),
            } => {
                let mut path = Path::try_new(scheme)
                    .map_err(|_error| BuilderError::Invariant("path scheme"))?;
                if let Some(cluster) = cluster {
                    path = path
                        .try_with_cluster(cluster)
                        .map_err(|_error| BuilderError::Invariant("path cluster"))?;
                }
                for segment in segments {
                    // The validator checked every segment incrementally. Move
                    // each owned component without reparsing a path string.
                    path = path.push(segment);
                }
                Field::Path(path)
            }
            _ => return Err(BuilderError::Invariant("completed metadata")),
        })
    }
}
