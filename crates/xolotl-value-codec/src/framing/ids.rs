use xolotl_types::value::{DType, FrameKind, event::Kind};

use super::ErrorKind;

pub(super) const fn kind_id(kind: Kind) -> u64 {
    match kind {
        Kind::Document => 0,
        Kind::Taint => 1,
        Kind::String => 2,
        Kind::Bytes => 3,
        Kind::List => 4,
        Kind::Map => 5,
        Kind::Key => 6,
        Kind::Blob => 7,
        Kind::Tensor => 8,
        Kind::Shape => 9,
        Kind::Frame => 10,
        Kind::StreamError => 11,
        Kind::Inbound => 12,
        Kind::Fetched => 13,
        Kind::Protected => 14,
        Kind::Path => 15,
        Kind::PathSegments => 16,
    }
}

pub(super) fn kind_from_id(id: u64) -> Result<Kind, ErrorKind> {
    Ok(match id {
        0 => Kind::Document,
        1 => Kind::Taint,
        2 => Kind::String,
        3 => Kind::Bytes,
        4 => Kind::List,
        5 => Kind::Map,
        6 => Kind::Key,
        7 => Kind::Blob,
        8 => Kind::Tensor,
        9 => Kind::Shape,
        10 => Kind::Frame,
        11 => Kind::StreamError,
        12 => Kind::Inbound,
        13 => Kind::Fetched,
        14 => Kind::Protected,
        15 => Kind::Path,
        16 => Kind::PathSegments,
        other => return Err(ErrorKind::UnknownKind(other)),
    })
}

pub(super) const fn dtype_id(dtype: DType) -> u64 {
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

pub(super) fn dtype_from_id(id: u64) -> Result<DType, ErrorKind> {
    Ok(match id {
        0 => DType::F16,
        1 => DType::Bf16,
        2 => DType::F32,
        3 => DType::F64,
        4 => DType::I8,
        5 => DType::I16,
        6 => DType::I32,
        7 => DType::I64,
        8 => DType::U8,
        9 => DType::Bool,
        other => return Err(ErrorKind::UnknownDType(other)),
    })
}

pub(super) const fn frame_kind_id(kind: FrameKind) -> u64 {
    match kind {
        FrameKind::Audio => 0,
        FrameKind::Video => 1,
        FrameKind::Pose => 2,
        FrameKind::Sensor => 3,
    }
}

pub(super) fn frame_kind_from_id(id: u64) -> Result<FrameKind, ErrorKind> {
    Ok(match id {
        0 => FrameKind::Audio,
        1 => FrameKind::Video,
        2 => FrameKind::Pose,
        3 => FrameKind::Sensor,
        other => return Err(ErrorKind::UnknownFrameKind(other)),
    })
}

pub(super) fn record_arity(id: u64) -> Result<usize, ErrorKind> {
    match id {
        2..=4 | 10..=12 => Ok(1),
        0..=1 | 5..=9 | 13 => Ok(2),
        other => Err(ErrorKind::UnknownEvent(other)),
    }
}
