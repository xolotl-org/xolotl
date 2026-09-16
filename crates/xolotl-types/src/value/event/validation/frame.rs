use super::{Atom, KeyId, Kind, ValidationError, utf8::Utf8};
use crate::path::identifier::{Identifier, IdentifierKind};
use core::cmp::Ordering;

#[derive(Clone, Copy, Debug)]
pub(super) struct Key {
    pub(super) id: KeyId,
    pub(super) length: u64,
}

#[derive(Debug)]
pub(super) struct KeyFrame {
    pub(super) current: Key,
    pub(super) previous: Option<Key>,
    pub(super) order: Ordering,
    pub(super) utf8: Utf8,
}

#[derive(Debug)]
pub(super) enum Frame {
    Record {
        kind: Kind,
        next: u8,
    },
    Sequence(Kind),
    Field {
        kind: Kind,
        length: u64,
        utf8: Option<Utf8>,
        identifier: Option<Identifier>,
    },
    Map {
        previous: Option<Key>,
        expects_key: bool,
    },
    Key(KeyFrame),
}

impl Frame {
    pub(super) fn new(kind: Kind, identifier: Option<IdentifierKind>) -> Self {
        match kind {
            Kind::Taint | Kind::List | Kind::Shape | Kind::PathSegments => Self::Sequence(kind),
            Kind::String | Kind::Bytes => Self::Field {
                kind,
                length: 0,
                utf8: (kind == Kind::String).then(Utf8::default),
                identifier: identifier.map(Identifier::new),
            },
            Kind::Map => Self::Map {
                previous: None,
                expects_key: true,
            },
            _ => Self::Record { kind, next: 0 },
        }
    }

    pub(super) fn kind(&self) -> Kind {
        match self {
            Self::Record { kind, .. } | Self::Field { kind, .. } | Self::Sequence(kind) => *kind,
            Self::Map { .. } => Kind::Map,
            Self::Key(_) => Kind::Key,
        }
    }

    pub(super) fn begin(&mut self, child: Kind) -> Result<Option<IdentifierKind>, ValidationError> {
        let context = self.kind();
        let mut identifier = None;
        let valid = match self {
            Self::Record { kind, next } => {
                let valid = match (*kind, *next) {
                    (Kind::Document, 0) => child == Kind::Taint,
                    (Kind::Document, 1) => value_kind(child),
                    (Kind::Blob, 0 | 2)
                    | (Kind::Inbound, 0 | 1)
                    | (Kind::Fetched | Kind::StreamError, 0) => child == Kind::String,
                    (Kind::Tensor | Kind::Frame, 0) => child == Kind::Blob,
                    (Kind::Tensor, 2) => child == Kind::Shape,
                    (Kind::Protected, 0) => child == Kind::Path,
                    (Kind::Path, position @ (0 | 1)) => {
                        identifier = Some(if position == 0 {
                            IdentifierKind::Cluster
                        } else {
                            IdentifierKind::Scheme
                        });
                        child == Kind::String
                    }
                    (Kind::Path, 2) => child == Kind::PathSegments,
                    _ => false,
                };
                if valid {
                    *next += 1;
                }
                valid
            }
            Self::Sequence(Kind::Taint) => {
                matches!(child, Kind::Inbound | Kind::Fetched | Kind::Protected)
            }
            Self::Sequence(Kind::List) => value_kind(child),
            Self::Sequence(Kind::PathSegments) => {
                identifier = Some(IdentifierKind::Segment);
                child == Kind::String
            }
            Self::Map { expects_key, .. } => {
                let valid = if *expects_key {
                    child == Kind::Key
                } else {
                    value_kind(child)
                };
                if valid {
                    *expects_key = !*expects_key;
                }
                valid
            }
            _ => false,
        };
        if valid {
            Ok(identifier)
        } else {
            Err(ValidationError::UnexpectedEvent {
                context: Some(context),
            })
        }
    }

    pub(super) fn atom(&mut self, atom: Atom) -> Result<(), ValidationError> {
        let context = self.kind();
        let valid = match self {
            Self::Record { kind, next } => {
                let valid = match (*kind, *next, atom) {
                    (Kind::Document, 1, atom) => value_atom(atom),
                    (Kind::Blob, 1, Atom::U64(_))
                    | (Kind::Blob, 2, Atom::Null)
                    | (Kind::Tensor, 1, Atom::DType(_))
                    | (Kind::Frame, 1, Atom::I64(_))
                    | (Kind::Frame, 2, Atom::FrameKind(_))
                    | (Kind::Path, 0, Atom::Null) => true,
                    _ => false,
                };
                if valid {
                    *next += 1;
                }
                valid
            }
            Self::Sequence(Kind::Taint) => matches!(atom, Atom::Author | Atom::Model),
            Self::Sequence(Kind::List) => value_atom(atom),
            Self::Sequence(Kind::Shape) => matches!(atom, Atom::U64(_)),
            Self::Map { expects_key, .. } => {
                let valid = !*expects_key && value_atom(atom);
                if valid {
                    *expects_key = true;
                }
                valid
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(ValidationError::UnexpectedEvent {
                context: Some(context),
            })
        }
    }

    pub(super) fn finish(&self) -> Result<(), ValidationError> {
        let complete = match self {
            Self::Record { kind, next } => {
                let expected = match kind {
                    Kind::Document | Kind::Inbound => 2,
                    Kind::Blob | Kind::Tensor | Kind::Frame | Kind::Path => 3,
                    Kind::StreamError | Kind::Fetched | Kind::Protected => 1,
                    _ => 0,
                };
                *next == expected
            }
            Self::Sequence(_) => true,
            Self::Field {
                utf8, identifier, ..
            } => {
                if let Some(utf8) = utf8 {
                    utf8.finish()?;
                }
                if let Some(identifier) = identifier {
                    identifier
                        .finish()
                        .map_err(|_error| ValidationError::Path)?;
                }
                true
            }
            Self::Map { expects_key, .. } => *expects_key,
            Self::Key(key) => {
                key.utf8.finish()?;
                if let Some(previous) = key.previous {
                    let order = key
                        .order
                        .then_with(|| previous.length.cmp(&key.current.length));
                    if order != Ordering::Less {
                        return Err(ValidationError::MapKeyOrder);
                    }
                }
                true
            }
        };
        if complete {
            Ok(())
        } else {
            Err(ValidationError::IncompleteRecord { kind: self.kind() })
        }
    }
}

fn value_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::String
            | Kind::Bytes
            | Kind::List
            | Kind::Map
            | Kind::Blob
            | Kind::Tensor
            | Kind::Frame
            | Kind::StreamError
    )
}

fn value_atom(atom: Atom) -> bool {
    matches!(
        atom,
        Atom::Null | Atom::Bool(_) | Atom::I64(_) | Atom::F64Bits(_) | Atom::StreamDone
    )
}
