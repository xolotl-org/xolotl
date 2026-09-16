use super::{Atom, Event, Kind};
use crate::value::collection::{ListIter, MapIter};
use crate::{BlobRef, Failure, Path, StreamMarker, TaintSet, TaintSource, Value, ValueView};
use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::{fmt, num::NonZeroUsize, slice};
use smol_str::SmolStr;
use thiserror::Error;

mod failure;

/// Failure to retain the working frames of a borrowed value cursor.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CursorError {
    /// Opening another record would exceed the configured frame budget.
    #[error("value cursor exceeds its frame budget of {limit}")]
    FrameBudget {
        /// Maximum simultaneously open records, including the document.
        limit: usize,
    },
    /// Allocating or growing the cursor's frame storage failed.
    #[error("cannot allocate value cursor frames: {0}")]
    Allocation(#[from] TryReserveError),
}

/// Iteratively borrow one resident value or failure and its provenance as events.
///
/// The cursor never clones or owns its input. Its frames contain borrowed
/// references and iterators, so advancing and dropping the cursor do not
/// recursively walk or destroy the input. The resident Value independently
/// shares immutable payloads and releases its graph iteratively.
///
/// Map keys retain UTF-8 byte order. Provenance
/// retains the exact source sequence, including duplicates obtained through
/// deserialization. Metadata is borrowed field by field, including structured
/// path components, without constructing temporary strings or reference DTOs.
pub struct ValueCursor<'a> {
    frames: Vec<Frame<'a>>,
    chunk_bytes: NonZeroUsize,
    max_frames: Option<usize>,
    started: bool,
    failure: Option<CursorError>,
}

impl fmt::Debug for ValueCursor<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValueCursor")
            .field("open_frames", &self.frames.len())
            .field("chunk_bytes", &self.chunk_bytes)
            .field("max_frames", &self.max_frames)
            .field("started", &self.started)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl<'a> ValueCursor<'a> {
    /// Start a document borrowing the supplied value and recorded provenance.
    ///
    /// Every data event contains at most `chunk_bytes` bytes. An empty field
    /// produces its begin and end events without a data event. Splits are byte
    /// oriented and can divide a UTF-8 code point.
    ///
    /// `max_frames` bounds simultaneously open records, including document and
    /// metadata records. It does not reserve that many frames in advance.
    /// `None` permits checked growth as needed; it imposes no fixed depth limit.
    /// A zero frame budget rejects the document immediately. This is a working
    /// storage policy, not a limit on total document bytes or item count.
    pub fn new(
        value: &'a Value,
        taint: &'a TaintSet,
        chunk_bytes: NonZeroUsize,
        max_frames: Option<usize>,
    ) -> Result<Self, CursorError> {
        Self::with_root(Node::Value(value), taint, chunk_bytes, max_frames)
    }

    /// Borrow a failure as the ordinary Value shape of its Serde representation.
    ///
    /// Unit variants are strings; variants with fields are externally tagged
    /// maps, with field keys in canonical UTF-8 order. Every string and list
    /// element borrows the original failure. Paths use the same canonical text
    /// fragments as [`Path`]'s Display and Serialize implementations. No JSON,
    /// resident Value, or complete path string is assembled along this path.
    ///
    /// The supplied taint remains the document's separate provenance record.
    /// Frame and byte-window policies are identical to [`Self::new`].
    pub fn from_failure(
        failure: &'a Failure,
        taint: &'a TaintSet,
        chunk_bytes: NonZeroUsize,
        max_frames: Option<usize>,
    ) -> Result<Self, CursorError> {
        Self::with_root(Node::Failure(failure), taint, chunk_bytes, max_frames)
    }

    fn with_root(
        root: Node<'a>,
        taint: &'a TaintSet,
        chunk_bytes: NonZeroUsize,
        max_frames: Option<usize>,
    ) -> Result<Self, CursorError> {
        let mut cursor = Self {
            frames: Vec::new(),
            chunk_bytes,
            max_frames,
            started: false,
            failure: None,
        };
        cursor.push(Frame::record(
            Kind::Document,
            Node::Taint(taint),
            Some(root),
            None,
        ))?;
        Ok(cursor)
    }

    /// Return one event, then return `None` after the document's end event.
    ///
    /// Each call advances only the current frame or opens one child. Data
    /// events borrow the original input, independently of the cursor borrow.
    /// Completing the document releases the working frames. On failure the
    /// cursor also releases them, and every later call returns the same error.
    /// Dropping a partially read cursor is harmless to the borrowed input.
    pub fn next_event(&mut self) -> Result<Option<Event<'a>>, CursorError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if !self.started {
            self.started = true;
            return Ok(Some(Event::Begin(Kind::Document)));
        }
        let Some(frame) = self.frames.last_mut() else {
            return Ok(None);
        };
        let result = match frame.advance(self.chunk_bytes.get()) {
            Step::End(kind) => {
                if kind == Kind::Document {
                    self.frames = Vec::new();
                } else {
                    self.frames.truncate(self.frames.len() - 1);
                }
                Ok(Event::End(kind))
            }
            Step::Data(bytes) => Ok(Event::Data(bytes)),
            Step::Child(node) => self.open(node),
        };
        match result {
            Ok(event) => Ok(Some(event)),
            Err(error) => {
                self.frames = Vec::new();
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }

    fn push(&mut self, frame: Frame<'a>) -> Result<(), CursorError> {
        if let Some(limit) = self.max_frames
            && self.frames.len() >= limit
        {
            return Err(CursorError::FrameBudget { limit });
        }
        if self.frames.len() == self.frames.capacity() {
            let target = self.frames.capacity().saturating_mul(2).max(4);
            let target = self.max_frames.map_or(target, |limit| target.min(limit));
            self.frames.try_reserve_exact(target - self.frames.len())?;
        }
        self.frames.push(frame);
        Ok(())
    }

    fn begin(&mut self, frame: Frame<'a>) -> Result<Event<'a>, CursorError> {
        let kind = frame.kind();
        self.push(frame)?;
        Ok(Event::Begin(kind))
    }

    fn data(&mut self, kind: Kind, bytes: &'a [u8]) -> Result<Event<'a>, CursorError> {
        self.begin(Frame::Data { kind, bytes })
    }

    fn record(
        &mut self,
        kind: Kind,
        first: Node<'a>,
        second: Option<Node<'a>>,
        third: Option<Node<'a>>,
    ) -> Result<Event<'a>, CursorError> {
        self.begin(Frame::record(kind, first, second, third))
    }

    fn blob(&mut self, blob: &'a BlobRef) -> Result<Event<'a>, CursorError> {
        self.record(
            Kind::Blob,
            Node::text(&blob.hash),
            Some(Node::Atom(Atom::U64(blob.size))),
            Some(Node::optional_text(blob.mime.as_deref())),
        )
    }

    fn open(&mut self, node: Node<'a>) -> Result<Event<'a>, CursorError> {
        match node {
            Node::Atom(atom) => Ok(Event::Atom(atom)),
            Node::Data(kind, bytes) => self.data(kind, bytes),
            Node::Blob(blob) => self.blob(blob),
            Node::Taint(taint) => self.begin(Frame::Taint(taint.sources().iter())),
            Node::Shape(dimensions) => self.begin(Frame::Shape(dimensions.iter())),
            Node::Path(path) => self.record(
                Kind::Path,
                Node::optional_text(path.cluster()),
                Some(Node::text(path.scheme())),
                Some(Node::PathSegments(path.segments())),
            ),
            Node::PathSegments(segments) => self.begin(Frame::PathSegments(segments.iter())),
            Node::Strings(strings) => self.begin(Frame::Strings(strings.iter())),
            Node::PathText(path) => self.begin(Frame::PathText {
                parts: path.canonical_parts(),
                pending: &[],
            }),
            Node::Failure(source) => {
                let projection = failure::project(source);
                if projection.fields.is_none() {
                    self.data(Kind::String, projection.tag.as_bytes())
                } else {
                    self.record(
                        Kind::Map,
                        Node::Data(Kind::Key, projection.tag.as_bytes()),
                        Some(Node::FailurePayload(source)),
                        None,
                    )
                }
            }
            Node::FailurePayload(source) => {
                let projection = failure::project(source);
                match projection.fields {
                    Some(fields) => self.begin(Frame::Fields(fields)),
                    None => self.data(Kind::String, projection.tag.as_bytes()),
                }
            }
            Node::Source(source) => match source {
                TaintSource::AuthorConstant => Ok(Event::Atom(Atom::Author)),
                TaintSource::ModelOutput => Ok(Event::Atom(Atom::Model)),
                TaintSource::Inbound { source, channel } => self.record(
                    Kind::Inbound,
                    Node::text(source),
                    Some(Node::text(channel)),
                    None,
                ),
                TaintSource::Fetched { host } => {
                    self.record(Kind::Fetched, Node::text(host), None, None)
                }
                TaintSource::Protected { path } => {
                    self.record(Kind::Protected, Node::Path(path), None, None)
                }
            },
            Node::Value(value) => match value.view() {
                ValueView::Null => Ok(Event::Atom(Atom::Null)),
                ValueView::Bool(value) => Ok(Event::Atom(Atom::Bool(value))),
                ValueView::Int(value) => Ok(Event::Atom(Atom::I64(value))),
                ValueView::Float(value) => Ok(Event::Atom(Atom::F64Bits(value.0.to_bits()))),
                ValueView::Str(value) => self.data(Kind::String, value.as_bytes()),
                ValueView::Bytes(value) => self.data(Kind::Bytes, value),
                ValueView::List(values) => self.begin(Frame::List(values.iter())),
                ValueView::Map(values) => self.begin(Frame::Map {
                    entries: values.iter(),
                    pending: None,
                }),
                ValueView::Blob(blob) => self.blob(blob),
                ValueView::Tensor(tensor) => self.record(
                    Kind::Tensor,
                    Node::Blob(&tensor.blob),
                    Some(Node::Atom(Atom::DType(tensor.dtype))),
                    Some(Node::Shape(&tensor.shape)),
                ),
                ValueView::Frame(frame) => self.record(
                    Kind::Frame,
                    Node::Blob(&frame.blob),
                    Some(Node::Atom(Atom::I64(frame.ts_nanos))),
                    Some(Node::Atom(Atom::FrameKind(frame.kind))),
                ),
                ValueView::StreamEnd(StreamMarker::Done) => Ok(Event::Atom(Atom::StreamDone)),
                ValueView::StreamEnd(StreamMarker::Error { message }) => {
                    self.record(Kind::StreamError, Node::text(message), None, None)
                }
            },
        }
    }
}

#[derive(Clone, Copy)]
enum Node<'a> {
    Value(&'a Value),
    Taint(&'a TaintSet),
    Source(&'a TaintSource),
    Atom(Atom),
    Data(Kind, &'a [u8]),
    Blob(&'a BlobRef),
    Shape(&'a [u64]),
    Path(&'a Path),
    PathSegments(&'a [SmolStr]),
    Strings(&'a [String]),
    PathText(&'a Path),
    Failure(&'a Failure),
    FailurePayload(&'a Failure),
}

impl<'a> Node<'a> {
    fn text(text: &'a str) -> Self {
        Self::Data(Kind::String, text.as_bytes())
    }

    fn optional_text(text: Option<&'a str>) -> Self {
        text.map_or(Self::Atom(Atom::Null), Self::text)
    }
}

enum Frame<'a> {
    Record {
        kind: Kind,
        fields: [Option<Node<'a>>; 3],
        next: usize,
    },
    Data {
        kind: Kind,
        bytes: &'a [u8],
    },
    Taint(slice::Iter<'a, TaintSource>),
    List(ListIter<'a>),
    Map {
        entries: MapIter<'a>,
        pending: Option<&'a Value>,
    },
    Shape(slice::Iter<'a, u64>),
    PathSegments(slice::Iter<'a, SmolStr>),
    Strings(slice::Iter<'a, String>),
    Fields(failure::Fields<'a>),
    PathText {
        parts: crate::path::CanonicalParts<'a>,
        pending: &'a [u8],
    },
}

enum Step<'a> {
    Child(Node<'a>),
    Data(&'a [u8]),
    End(Kind),
}

impl<'a> Frame<'a> {
    fn record(
        kind: Kind,
        first: Node<'a>,
        second: Option<Node<'a>>,
        third: Option<Node<'a>>,
    ) -> Self {
        Self::Record {
            kind,
            fields: [Some(first), second, third],
            next: 0,
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Self::Record { kind, .. } | Self::Data { kind, .. } => *kind,
            Self::Taint(_) => Kind::Taint,
            Self::List(_) | Self::Strings(_) => Kind::List,
            Self::Map { .. } | Self::Fields(_) => Kind::Map,
            Self::Shape(_) => Kind::Shape,
            Self::PathSegments(_) => Kind::PathSegments,
            Self::PathText { .. } => Kind::String,
        }
    }

    fn advance(&mut self, chunk_bytes: usize) -> Step<'a> {
        match self {
            Self::Record { kind, fields, next } => {
                let Some(Some(node)) = fields.get(*next) else {
                    return Step::End(*kind);
                };
                *next += 1;
                Step::Child(*node)
            }
            Self::Data { kind, bytes } => {
                if bytes.is_empty() {
                    return Step::End(*kind);
                }
                let (chunk, remaining) = bytes.split_at(bytes.len().min(chunk_bytes));
                *bytes = remaining;
                Step::Data(chunk)
            }
            Self::Taint(sources) => sources.next().map_or(Step::End(Kind::Taint), |source| {
                Step::Child(Node::Source(source))
            }),
            Self::List(values) => values.next().map_or(Step::End(Kind::List), |value| {
                Step::Child(Node::Value(value))
            }),
            Self::Map { entries, pending } => {
                if let Some(value) = pending.take() {
                    return Step::Child(Node::Value(value));
                }
                match entries.next() {
                    Some((key, value)) => {
                        *pending = Some(value);
                        Step::Child(Node::Data(Kind::Key, key.as_bytes()))
                    }
                    None => Step::End(Kind::Map),
                }
            }
            Self::Shape(dimensions) => dimensions.next().map_or(Step::End(Kind::Shape), |value| {
                Step::Child(Node::Atom(Atom::U64(*value)))
            }),
            Self::PathSegments(segments) => segments
                .next()
                .map_or(Step::End(Kind::PathSegments), |segment| {
                    Step::Child(Node::text(segment))
                }),
            Self::Strings(strings) => strings
                .next()
                .map_or(Step::End(Kind::List), |text| Step::Child(Node::text(text))),
            Self::Fields(fields) => fields.next().map_or(Step::End(Kind::Map), Step::Child),
            Self::PathText { parts, pending } => loop {
                if !pending.is_empty() {
                    let (chunk, remaining) = pending.split_at(pending.len().min(chunk_bytes));
                    *pending = remaining;
                    break Step::Data(chunk);
                }
                match parts.next() {
                    Some(part) => *pending = part.as_bytes(),
                    None => break Step::End(Kind::String),
                }
            },
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "cursor/failure_tests.rs"]
mod failure_tests;
