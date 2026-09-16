//! Version 1 CBOR event encoding for exactly one value document.
//!
//! The envelope is `[h'786f6c6f746c2e76616c7565', 1, (_ events...)]` (the
//! indefinite sequence is a CBOR array). Event records use fixed integer tags;
//! logical nesting is represented by begin/end records, so wire nesting stays
//! constant. Numeric fields preserve their full width and floating-point bits.
//! Data records may split fields anywhere, including within UTF-8 code points.
//!
//! Returned events remain tentative until [`Decoder::finish`] confirms actual
//! source EOF. Encoded-byte hashes depend on chunk boundaries and are not
//! semantic value hashes. Byte-range resume requires an external parser index
//! or checkpoint; an arbitrary object range is not a standalone document.

use xolotl_types::value::event::Event;

pub use crate::framing::{Error as WireError, ErrorKind as WireErrorKind};
use crate::{Error, framing, validation::EventValidator, validation::KeyStore};

/// Validated incremental encoder with caller-selected key storage.
pub struct Encoder<K> {
    framing: framing::FrameEncoder,
    validator: Option<EventValidator<K>>,
    closing: bool,
}

impl<K: KeyStore> Encoder<K> {
    /// Start one document with an optional limit on simultaneously open records.
    pub fn new(keys: K, max_frames: Option<usize>) -> Self {
        Self {
            framing: framing::FrameEncoder::new(),
            validator: Some(EventValidator::new(keys, max_frames)),
            closing: false,
        }
    }

    /// Accept one event before producing its encoding.
    ///
    /// Consume the returned guard completely before supplying another event.
    /// Errors, polled cancellation, and partially drained guard drops close the
    /// encoder and release its workspace. Unpolled future drops leave it usable.
    pub async fn encode<'encoder, 'data>(
        &'encoder mut self,
        event: Event<'data>,
    ) -> Result<EncodedEvent<'encoder, 'data, K>, Error<K::Error>> {
        let mut validator = self.validator.take().ok_or(Error::Closed)?;
        validator.accept(event).await?;
        let writer = self.framing.start_event(event).map_err(Error::Wire)?;
        self.validator = Some(validator);
        Ok(EncodedEvent {
            writer,
            validator: &mut self.validator,
        })
    }

    /// Confirm event-source EOF and drain the closing envelope into `output`.
    ///
    /// Repeat until [`Self::is_complete`] is true. Empty output makes no
    /// progress. Completion means bytes were generated; a sink owner must
    /// separately await all write acknowledgements before committing them.
    pub fn finish(&mut self, output: &mut [u8]) -> Result<usize, Error<K::Error>> {
        if !self.closing {
            let mut validator = self.validator.take().ok_or(Error::Closed)?;
            validator.finish()?;
            self.closing = true;
        }
        self.framing.finish(output).map_err(Error::Wire)
    }

    /// Whether a complete document and its closing envelope were generated.
    pub fn is_complete(&self) -> bool {
        self.closing && self.framing.is_complete()
    }

    /// Generated wire bytes, independently of any sink acknowledgement.
    pub fn bytes_written(&self) -> u64 {
        self.framing.bytes_written()
    }
}

/// One encoding transaction retaining the offered data borrow through drainage.
///
/// Dropping an incomplete guard also drops the key workspace. This guard owns
/// encoding progress only; callers doing asynchronous I/O need a surrounding
/// sink owner that closes when acknowledged writes fail or are cancelled.
#[must_use = "drain the event or drop it to close the encoder"]
pub struct EncodedEvent<'encoder, 'data, K> {
    writer: framing::EventWriter<'encoder, 'data>,
    validator: &'encoder mut Option<EventValidator<K>>,
}

impl<K: KeyStore> EncodedEvent<'_, '_, K> {
    /// Generate at most `output.len()` bytes. Empty output makes no progress.
    pub fn write(&mut self, output: &mut [u8]) -> Result<usize, Error<K::Error>> {
        match self.writer.write(output) {
            Ok(count) => Ok(count),
            Err(error) => {
                self.validator.take();
                Err(Error::Wire(error))
            }
        }
    }

    /// Whether every byte for this event has been generated.
    pub fn is_complete(&self) -> bool {
        self.writer.is_complete()
    }
}

impl<K> Drop for EncodedEvent<'_, '_, K> {
    fn drop(&mut self) {
        if !self.writer.is_complete() {
            self.validator.take();
        }
    }
}

/// One incremental decoder result, borrowing data only from the offered input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeStep<'input> {
    /// Input bytes consumed; retain and offer any remaining suffix again.
    pub consumed: usize,
    /// Validated event, input request, or envelope boundary.
    pub status: DecodeStatus<'input>,
}

/// Decoder progress. Neither an event nor `End` is a publication credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeStatus<'input> {
    /// The offered input was consumed; obtain another source chunk or finish EOF.
    NeedInput,
    /// A semantically accepted event. Data borrows the original input window.
    Event(Event<'input>),
    /// The envelope ended. Still read to real EOF, then call [`Decoder::finish`].
    End,
}

/// Incremental decoder whose semantic workspace is closed on cancellation.
pub struct Decoder<K> {
    framing: framing::FrameDecoder,
    validator: Option<EventValidator<K>>,
    complete: bool,
}

impl<K: KeyStore> Decoder<K> {
    /// Start one document with caller-selected workspace and frame policy.
    pub fn new(keys: K, max_frames: Option<usize>) -> Self {
        Self {
            framing: framing::FrameDecoder::new(),
            validator: Some(EventValidator::new(keys, max_frames)),
            complete: false,
        }
    }

    /// Consume input through one accepted event or a framing boundary.
    ///
    /// The input remains borrowed while key effects are pending. Only a fully
    /// accepted result advances the caller's window. Error or polled
    /// cancellation closes this decoder, including any outstanding key work.
    pub async fn decode<'input>(
        &mut self,
        input: &'input [u8],
    ) -> Result<DecodeStep<'input>, Error<K::Error>> {
        let mut validator = self.validator.take().ok_or(Error::Closed)?;
        let step: framing::DecodeStep<'input> = self.framing.decode(input).map_err(Error::Wire)?;
        let status = match step.status {
            framing::DecodeStatus::NeedInput => DecodeStatus::NeedInput,
            framing::DecodeStatus::End => DecodeStatus::End,
            framing::DecodeStatus::Event(event) => {
                validator.accept(event).await?;
                DecodeStatus::Event(event)
            }
        };
        self.validator = Some(validator);
        Ok(DecodeStep {
            consumed: step.consumed,
            status,
        })
    }

    /// Confirm real source EOF, rejecting truncated documents and envelopes.
    ///
    /// Call only after the enclosing transport has finished successfully. A
    /// successful finish releases workspace ownership and prevents more input.
    pub fn finish(&mut self) -> Result<(), Error<K::Error>> {
        let mut validator = self.validator.take().ok_or(Error::Closed)?;
        self.framing.finish().map_err(Error::Wire)?;
        validator.finish()?;
        self.complete = true;
        Ok(())
    }

    /// Whether actual EOF was confirmed after a complete valid document.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Consumed wire bytes; this is not a source read or publication offset.
    pub fn bytes_read(&self) -> u64 {
        self.framing.bytes_read()
    }
}

#[cfg(test)]
mod tests;
