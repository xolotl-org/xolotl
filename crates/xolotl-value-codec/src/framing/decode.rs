use ciborium_ll::{Decoder, Header};
use xolotl_types::value::event::{Atom, Event};

use super::{Error, ErrorKind, MAGIC, MAX_DATA_RECORD_BYTES, VERSION, advance_offset, ids};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodeStep<'input> {
    pub(crate) consumed: usize,
    pub(crate) status: DecodeStatus<'input>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeStatus<'input> {
    NeedInput,
    Event(Event<'input>),
    /// The envelope ended; the caller must still confirm EOF using `finish`.
    End,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Envelope,
    MagicHeader,
    Magic { matched: usize },
    Version,
    Events,
    Record,
    Tag { arity: usize },
    Argument { tag: u64 },
    Data { remaining: usize },
    Ended,
    Finished,
}

pub(crate) struct FrameDecoder {
    state: State,
    header: [u8; 9],
    header_len: usize,
    offset: u64,
    error: Option<Error>,
}

impl FrameDecoder {
    pub(crate) fn new() -> Self {
        Self {
            state: State::Envelope,
            header: [0; 9],
            header_len: 0,
            offset: 0,
            error: None,
        }
    }

    /// Returned data borrows only `input`, so it can outlive this decoder borrow.
    pub(crate) fn decode<'input>(
        &mut self,
        input: &'input [u8],
    ) -> Result<DecodeStep<'input>, Error> {
        self.check()?;
        self.decode_inner(input).map_err(|kind| self.fail(kind))
    }

    /// Confirm actual EOF, rejecting every incomplete header, payload or envelope.
    pub(crate) fn finish(&mut self) -> Result<(), Error> {
        self.check()?;
        match self.state {
            State::Ended | State::Finished => {
                self.state = State::Finished;
                Ok(())
            }
            _ => Err(self.fail(ErrorKind::Truncated)),
        }
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        self.offset
    }

    fn decode_inner<'input>(
        &mut self,
        input: &'input [u8],
    ) -> Result<DecodeStep<'input>, ErrorKind> {
        let mut consumed = 0;
        loop {
            match self.state {
                State::Magic { matched } => {
                    let count = (MAGIC.len() - matched).min(input.len() - consumed);
                    let bytes = &input[consumed..consumed + count];
                    if let Some(index) = bytes
                        .iter()
                        .zip(&MAGIC[matched..matched + count])
                        .position(|(actual, expected)| actual != expected)
                    {
                        advance_offset(&mut self.offset, index + 1)?;
                        return Err(ErrorKind::InvalidEnvelope);
                    }
                    advance_offset(&mut self.offset, count)?;
                    consumed += count;
                    let matched = matched + count;
                    if matched != MAGIC.len() {
                        self.state = State::Magic { matched };
                        return Ok(DecodeStep {
                            consumed,
                            status: DecodeStatus::NeedInput,
                        });
                    }
                    self.state = State::Version;
                    continue;
                }
                State::Data { remaining } => {
                    let count = remaining.min(input.len() - consumed);
                    if count == 0 {
                        return Ok(DecodeStep {
                            consumed,
                            status: DecodeStatus::NeedInput,
                        });
                    }
                    advance_offset(&mut self.offset, count)?;
                    let data = &input[consumed..consumed + count];
                    consumed += count;
                    self.state = if count == remaining {
                        State::Record
                    } else {
                        State::Data {
                            remaining: remaining - count,
                        }
                    };
                    return Ok(DecodeStep {
                        consumed,
                        status: DecodeStatus::Event(Event::Data(data)),
                    });
                }
                State::Ended | State::Finished => {
                    if consumed != input.len() {
                        return Err(ErrorKind::TrailingData);
                    }
                    return Ok(DecodeStep {
                        consumed,
                        status: DecodeStatus::End,
                    });
                }
                _ => {}
            }

            let Some(header) = self.pull_header(input, &mut consumed)? else {
                return Ok(DecodeStep {
                    consumed,
                    status: DecodeStatus::NeedInput,
                });
            };
            let event = match (self.state, header) {
                (State::Envelope, Header::Array(Some(3))) => {
                    self.state = State::MagicHeader;
                    None
                }
                (State::MagicHeader, Header::Bytes(Some(len))) if len == MAGIC.len() => {
                    self.state = State::Magic { matched: 0 };
                    None
                }
                (State::Version, Header::Positive(VERSION)) => {
                    self.state = State::Events;
                    None
                }
                (State::Version, Header::Positive(version)) => {
                    return Err(ErrorKind::UnsupportedVersion(version));
                }
                (State::Events, Header::Array(None)) => {
                    self.state = State::Record;
                    None
                }
                (State::Record, Header::Break) => {
                    self.state = State::Ended;
                    None
                }
                (State::Record, Header::Array(Some(arity @ 1..=2))) => {
                    self.state = State::Tag { arity };
                    None
                }
                (State::Tag { arity }, Header::Positive(tag)) => {
                    if ids::record_arity(tag)? != arity {
                        return Err(ErrorKind::InvalidRecord);
                    }
                    if arity == 2 {
                        self.state = State::Argument { tag };
                        None
                    } else {
                        self.state = State::Record;
                        Some(Event::Atom(match tag {
                            2 => Atom::Null,
                            3 => Atom::Bool(false),
                            4 => Atom::Bool(true),
                            10 => Atom::Author,
                            11 => Atom::Model,
                            12 => Atom::StreamDone,
                            _ => return Err(ErrorKind::InvalidRecord),
                        }))
                    }
                }
                (State::Argument { tag }, header) => {
                    self.state = State::Record;
                    self.argument(tag, header, &input[consumed..consumed])?
                }
                (State::Envelope | State::MagicHeader | State::Version | State::Events, _) => {
                    return Err(ErrorKind::InvalidEnvelope);
                }
                _ => return Err(ErrorKind::InvalidRecord),
            };
            if let Some(event) = event {
                return Ok(DecodeStep {
                    consumed,
                    status: DecodeStatus::Event(event),
                });
            }
        }
    }

    fn argument<'input>(
        &mut self,
        tag: u64,
        header: Header,
        empty: &'input [u8],
    ) -> Result<Option<Event<'input>>, ErrorKind> {
        Ok(Some(match (tag, header) {
            (0, Header::Positive(id)) => Event::Begin(ids::kind_from_id(id)?),
            (1, Header::Positive(id)) => Event::End(ids::kind_from_id(id)?),
            (5, Header::Positive(value)) => Event::Atom(Atom::I64(
                i64::try_from(value).map_err(|_error| ErrorKind::InvalidInteger)?,
            )),
            (5, Header::Negative(value)) => Event::Atom(Atom::I64(
                !i64::try_from(value).map_err(|_error| ErrorKind::InvalidInteger)?,
            )),
            (6, Header::Positive(value)) => Event::Atom(Atom::F64Bits(value)),
            (7, Header::Positive(value)) => Event::Atom(Atom::U64(value)),
            (8, Header::Positive(id)) => Event::Atom(Atom::DType(ids::dtype_from_id(id)?)),
            (9, Header::Positive(id)) => Event::Atom(Atom::FrameKind(ids::frame_kind_from_id(id)?)),
            (13, Header::Bytes(Some(len))) => {
                let bytes = u64::try_from(len).map_err(|_error| ErrorKind::OffsetOverflow)?;
                if bytes > MAX_DATA_RECORD_BYTES {
                    return Err(ErrorKind::DataRecordTooLarge(bytes));
                }
                if len != 0 {
                    self.state = State::Data { remaining: len };
                    return Ok(None);
                }
                Event::Data(empty)
            }
            _ => return Err(ErrorKind::InvalidRecord),
        }))
    }

    fn pull_header(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
    ) -> Result<Option<Header>, ErrorKind> {
        if self.header_len == 0 {
            let Some(&first) = input.get(*consumed) else {
                return Ok(None);
            };
            advance_offset(&mut self.offset, 1)?;
            self.header[0] = first;
            self.header_len = 1;
            *consumed += 1;
        }
        // Ciborium consumes partial headers, so only hand it a complete header.
        let needed = match self.header[0] & 31 {
            24 => 2,
            25 => 3,
            26 => 5,
            27 => 9,
            _ => 1,
        };
        let count = (needed - self.header_len).min(input.len() - *consumed);
        advance_offset(&mut self.offset, count)?;
        self.header[self.header_len..self.header_len + count]
            .copy_from_slice(&input[*consumed..*consumed + count]);
        self.header_len += count;
        *consumed += count;
        if self.header_len != needed {
            return Ok(None);
        }
        let header = Decoder::from(&self.header[..needed])
            .pull()
            .map_err(|_error| ErrorKind::InvalidCbor)?;
        self.header_len = 0;
        Ok(Some(header))
    }

    fn check(&self) -> Result<(), Error> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn fail(&mut self, kind: ErrorKind) -> Error {
        *self.error.get_or_insert(Error {
            offset: self.offset,
            kind,
        })
    }
}

#[cfg(test)]
mod tests;
