use ciborium_ll::{Encoder, Header};
use xolotl_types::value::event::{Atom, Event};

use super::{Error, ErrorKind, MAGIC, VERSION, advance_offset, ids};

const PREFIX_BYTES: usize = MAGIC.len() + 4;
const RECORD_HEADER_BYTES: usize = 11;

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Open,
    Active,
    Finishing,
    Finished,
}

pub(crate) struct FrameEncoder {
    prefix: [u8; PREFIX_BYTES],
    prefix_prepared: bool,
    prefix_written: usize,
    state: State,
    offset: u64,
    error: Option<Error>,
}

impl FrameEncoder {
    pub(crate) fn new() -> Self {
        Self {
            prefix: [0; PREFIX_BYTES],
            prefix_prepared: false,
            prefix_written: 0,
            state: State::Open,
            offset: 0,
            error: None,
        }
    }

    /// The caller must accept the event semantically before starting its write.
    pub(crate) fn start_event<'encoder, 'data>(
        &'encoder mut self,
        event: Event<'data>,
    ) -> Result<EventWriter<'encoder, 'data>, Error> {
        self.check()?;
        match self.state {
            State::Open => {}
            State::Active => return Err(self.fail(ErrorKind::IncompleteEvent)),
            State::Finishing | State::Finished => return Err(self.fail(ErrorKind::Closed)),
        }
        let (header, data, chunk_remaining) = match event {
            Event::Data(data) => {
                let chunk = data_chunk_len(data.len());
                let header = RecordHeader::data(chunk).map_err(|kind| self.fail(kind))?;
                (header, Some(data), chunk)
            }
            other => (
                RecordHeader::event(other).map_err(|kind| self.fail(kind))?,
                None,
                0,
            ),
        };
        self.state = State::Active;
        Ok(EventWriter {
            encoder: self,
            header,
            data,
            chunk_remaining,
            complete: false,
        })
    }

    /// Incrementally close the record sequence after semantic completion.
    pub(crate) fn finish(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        match self.state {
            State::Active => return Err(self.fail(ErrorKind::IncompleteEvent)),
            State::Finished => return Ok(0),
            State::Open | State::Finishing => self.state = State::Finishing,
        }
        let written = self.write_prefix(output)?;
        if written == output.len() {
            return Ok(written);
        }
        let mut ending = [0; 1];
        encode_headers(&[Header::Break], &mut ending).map_err(|kind| self.fail(kind))?;
        let ending_written = self.write_bytes(&ending, &mut output[written..])?;
        self.state = State::Finished;
        Ok(written + ending_written)
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.state == State::Finished && self.error.is_none()
    }

    pub(crate) fn bytes_written(&self) -> u64 {
        self.offset
    }

    fn write_prefix(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if !self.prefix_prepared {
            prepare_prefix(&mut self.prefix).map_err(|kind| self.fail(kind))?;
            self.prefix_prepared = true;
        }
        let count = output.len().min(PREFIX_BYTES - self.prefix_written);
        advance_offset(&mut self.offset, count).map_err(|kind| self.fail(kind))?;
        output[..count]
            .copy_from_slice(&self.prefix[self.prefix_written..self.prefix_written + count]);
        self.prefix_written += count;
        Ok(count)
    }

    fn write_bytes(&mut self, data: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let count = data.len().min(output.len());
        advance_offset(&mut self.offset, count).map_err(|kind| self.fail(kind))?;
        output[..count].copy_from_slice(&data[..count]);
        Ok(count)
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

/// Holds the data borrow until the whole event has been written.
pub(crate) struct EventWriter<'encoder, 'data> {
    encoder: &'encoder mut FrameEncoder,
    header: RecordHeader,
    data: Option<&'data [u8]>,
    chunk_remaining: usize,
    complete: bool,
}

impl EventWriter<'_, '_> {
    pub(crate) fn write(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        self.encoder.check()?;
        if self.complete {
            return Ok(0);
        }
        let mut written = self.encoder.write_prefix(output)?;
        loop {
            let count = self.encoder.write_bytes(
                &self.header.bytes[self.header.written..self.header.len],
                &mut output[written..],
            )?;
            self.header.written += count;
            written += count;
            if self.header.written != self.header.len {
                return Ok(written);
            }

            if let Some(data) = self.data {
                let count = self
                    .encoder
                    .write_bytes(&data[..self.chunk_remaining], &mut output[written..])?;
                self.data = Some(&data[count..]);
                self.chunk_remaining -= count;
                written += count;
                if self.chunk_remaining != 0 {
                    return Ok(written);
                }
                if count != data.len() {
                    let next_chunk = data_chunk_len(data.len() - count);
                    self.header =
                        RecordHeader::data(next_chunk).map_err(|kind| self.encoder.fail(kind))?;
                    self.chunk_remaining = next_chunk;
                    continue;
                }
            }

            self.complete = true;
            self.encoder.state = State::Open;
            return Ok(written);
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
}

impl Drop for EventWriter<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.encoder.fail(ErrorKind::Cancelled);
        }
    }
}

struct RecordHeader {
    bytes: [u8; RECORD_HEADER_BYTES],
    len: usize,
    written: usize,
}

impl RecordHeader {
    fn data(bytes: usize) -> Result<Self, ErrorKind> {
        Self::new(13, Some(Header::Bytes(Some(bytes))))
    }

    fn event(event: Event<'_>) -> Result<Self, ErrorKind> {
        let (id, argument) = match event {
            Event::Begin(kind) => (0, Some(Header::Positive(ids::kind_id(kind)))),
            Event::End(kind) => (1, Some(Header::Positive(ids::kind_id(kind)))),
            Event::Atom(atom) => match atom {
                Atom::Null => (2, None),
                Atom::Bool(false) => (3, None),
                Atom::Bool(true) => (4, None),
                Atom::I64(value) => (
                    5,
                    Some(if value >= 0 {
                        Header::Positive(value as u64)
                    } else {
                        Header::Negative(!(value as u64))
                    }),
                ),
                Atom::F64Bits(bits) => (6, Some(Header::Positive(bits))),
                Atom::U64(value) => (7, Some(Header::Positive(value))),
                Atom::DType(dtype) => (8, Some(Header::Positive(ids::dtype_id(dtype)))),
                Atom::FrameKind(kind) => (9, Some(Header::Positive(ids::frame_kind_id(kind)))),
                Atom::Author => (10, None),
                Atom::Model => (11, None),
                Atom::StreamDone => (12, None),
            },
            Event::Data(data) => return Self::data(data_chunk_len(data.len())),
        };
        Self::new(id, argument)
    }

    fn new(id: u64, argument: Option<Header>) -> Result<Self, ErrorKind> {
        let mut bytes = [0; RECORD_HEADER_BYTES];
        let arity = if argument.is_some() { 2 } else { 1 };
        let mut len = encode_headers(
            &[Header::Array(Some(arity)), Header::Positive(id)],
            &mut bytes,
        )?;
        if let Some(argument) = argument {
            len += encode_headers(&[argument], &mut bytes[len..])?;
        }
        Ok(Self {
            bytes,
            len,
            written: 0,
        })
    }
}

fn data_chunk_len(bytes: usize) -> usize {
    bytes.min(u32::MAX as usize)
}

fn prepare_prefix(output: &mut [u8; PREFIX_BYTES]) -> Result<(), ErrorKind> {
    let mut encoder = Encoder::from(&mut output[..]);
    encoder
        .push(Header::Array(Some(3)))
        .map_err(|_error| ErrorKind::HeaderEncoding)?;
    encoder
        .bytes(MAGIC, None)
        .map_err(|_error| ErrorKind::HeaderEncoding)?;
    encoder
        .push(Header::Positive(VERSION))
        .map_err(|_error| ErrorKind::HeaderEncoding)?;
    encoder
        .push(Header::Array(None))
        .map_err(|_error| ErrorKind::HeaderEncoding)
}

fn encode_headers(headers: &[Header], output: &mut [u8]) -> Result<usize, ErrorKind> {
    let capacity = output.len();
    let mut remaining = output;
    {
        let mut encoder = Encoder::from(&mut remaining);
        for &header in headers {
            encoder
                .push(header)
                .map_err(|_error| ErrorKind::HeaderEncoding)?;
        }
    }
    Ok(capacity - remaining.len())
}

#[cfg(test)]
mod tests;
