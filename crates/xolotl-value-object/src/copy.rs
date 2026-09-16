//! Complete-document transfer with one owner for both sides of the operation.

use core::fmt;
use xolotl_state::object::{ObjectRead, ObjectWrite};
use xolotl_value_codec::validation::KeyStore;

use crate::{CommittedValue, Failure, ReadError, ValueObjectReader, ValueObjectWriter, WriteError};

/// The input or output side of a failed structured document transfer.
#[derive(Debug)]
pub enum CopyError<ReadE, WriteE> {
    /// Input failed canonical object or complete document validation.
    Read(ReadError<ReadE>),
    /// Output failed encoding, storage, or publication validation.
    Write(WriteError<WriteE>),
}

impl<ReadE: fmt::Display, WriteE: fmt::Display> fmt::Display for CopyError<ReadE, WriteE> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => error.fmt(formatter),
            Self::Write(error) => error.fmt(formatter),
        }
    }
}

impl<ReadE: core::error::Error + 'static, WriteE: core::error::Error + 'static> core::error::Error
    for CopyError<ReadE, WriteE>
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Write(error) => Some(error),
        }
    }
}

/// A transfer failure retaining all sources observed by either owned side.
pub type CopyFailure<ReadE, WriteE> = Failure<CopyError<ReadE, WriteE>>;

/// Forward one complete document into an independently configured object writer.
///
/// Moving both owners into this operation retains their selected ports, scratch
/// windows, key workspaces, and policies without materializing a resident Value.
/// Each borrowed event is accepted by the writer before another read. Wire
/// records may be rechunked, so the resulting object hash can differ while the
/// represented value and recorded source claims remain unchanged.
///
/// Every event's actual read sources reach the writer before encoding or sink
/// I/O. Final sources, including sources observed only at EOF, reach publication
/// only after the reader returns its validated completion receipt. Any failure
/// combines both sides' observed sources and releases unfinished staging.
/// Cancellation drops both owners without requiring an async abort. It never
/// deletes immutable content after successful or uncertain publication.
///
/// Both ports must already be admitted for this operation. Copying the document
/// neither dereferences its nested descriptors nor issues read/disclosure grants.
pub async fn copy_value<R, W, ReadK, WriteK>(
    mut reader: ValueObjectReader<'_, '_, R, ReadK>,
    mut writer: ValueObjectWriter<'_, '_, W, WriteK>,
) -> Result<CommittedValue, CopyFailure<ReadK::Error, WriteK::Error>>
where
    R: ObjectRead + ?Sized,
    W: ObjectWrite + ?Sized,
    ReadK: KeyStore,
    WriteK: KeyStore,
{
    loop {
        match reader.next_event().await {
            Ok(Some(event)) => {
                writer
                    .write(event.event, event.taint)
                    .await
                    .map_err(|mut failure| {
                        failure.taint.union(event.taint);
                        Failure::new(CopyError::Write(failure.error), failure.taint)
                    })?;
            }
            Ok(None) => break,
            Err(mut failure) => {
                failure.taint.union(writer.observed_taint());
                return Err(Failure::new(CopyError::Read(failure.error), failure.taint));
            }
        }
    }
    let receipt = reader.finish().map_err(|mut failure| {
        failure.taint.union(writer.observed_taint());
        Failure::new(CopyError::Read(failure.error), failure.taint)
    })?;
    writer.finish(receipt.taint()).await.map_err(|mut failure| {
        failure.taint.union(receipt.taint());
        Failure::new(CopyError::Write(failure.error), failure.taint)
    })
}
