//! One exact description of a node's local fields for equality and digest.

use super::super::{BlobRef, DType, FrameKind, StreamMarker, Value, ValueView};

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Blob<'a> {
    pub hash: &'a str,
    pub size: u64,
    pub mime: Option<&'a str>,
}

impl<'a> From<&'a BlobRef> for Blob<'a> {
    fn from(blob: &'a BlobRef) -> Self {
        Self {
            hash: &blob.hash,
            size: blob.size,
            mime: blob.mime.as_deref(),
        }
    }
}

/// Collection members are supplied separately in semantic order. These enum
/// discriminants are used only for exact local comparisons, never as wire tags.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Local<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Float(u64),
    Str(&'a str),
    Bytes(&'a [u8]),
    List(usize),
    Map(usize),
    Blob(Blob<'a>),
    Tensor {
        blob: Blob<'a>,
        dtype: u8,
        shape: &'a [u64],
    },
    Frame {
        blob: Blob<'a>,
        timestamp: i64,
        kind: u8,
    },
    StreamDone,
    StreamError(&'a str),
}

impl<'a> Local<'a> {
    pub(super) fn of(value: &'a Value) -> Self {
        match value.view() {
            ValueView::Null => Self::Null,
            ValueView::Bool(value) => Self::Bool(value),
            ValueView::Int(value) => Self::Int(value),
            ValueView::Float(value) => Self::Float(value.0.to_bits()),
            ValueView::Str(value) => Self::Str(value),
            ValueView::Bytes(value) => Self::Bytes(value),
            ValueView::List(value) => Self::List(value.len()),
            ValueView::Map(value) => Self::Map(value.len()),
            ValueView::Blob(value) => Self::Blob(value.into()),
            ValueView::Tensor(value) => Self::Tensor {
                blob: (&value.blob).into(),
                dtype: dtype_tag(value.dtype),
                shape: &value.shape,
            },
            ValueView::Frame(value) => Self::Frame {
                blob: (&value.blob).into(),
                timestamp: value.ts_nanos,
                kind: frame_tag(value.kind),
            },
            ValueView::StreamEnd(StreamMarker::Done) => Self::StreamDone,
            ValueView::StreamEnd(StreamMarker::Error { message }) => Self::StreamError(message),
        }
    }
}

fn dtype_tag(dtype: DType) -> u8 {
    match dtype {
        DType::F16 => 0,
        DType::Bf16 => 1,
        DType::F32 => 2,
        DType::F64 => 3,
        DType::I8 => 4,
        DType::I16 => 5,
        DType::I32 => 6,
        DType::I64 => 7,
        DType::U8 => 8,
        DType::Bool => 9,
    }
}

fn frame_tag(kind: FrameKind) -> u8 {
    match kind {
        FrameKind::Audio => 0,
        FrameKind::Video => 1,
        FrameKind::Pose => 2,
        FrameKind::Sensor => 3,
    }
}
