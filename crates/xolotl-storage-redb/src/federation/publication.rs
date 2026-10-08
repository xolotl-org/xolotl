//! Publisher retry ranges and exact identity release share the append domain.

use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use xolotl_federation::{
    FederationError, MAX_PUBLICATION_RETIRE_IDS, Position, PublicationReceipt, StreamRef,
};

use super::{
    FEDERATION_PUBLISH_REQUESTS_TABLE, FEDERATION_STREAMS_TABLE, StoredPosition, StreamRow, decode,
    encode, publish_request_key, storage, stream_key,
};

pub(crate) fn available_identity_slots(txn: &WriteTransaction) -> Result<usize, FederationError> {
    use redb::ReadableTableMetadata as _;
    let meta = txn
        .open_table(super::FEDERATION_NODE_TABLE)
        .map_err(storage)?;
    let limit = meta
        .get(super::PUBLISH_ID_LIMIT_KEY)
        .map_err(storage)?
        .ok_or(FederationError::Corrupt)?;
    let limit = u64::from_be_bytes(
        limit
            .value()
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    if limit == 0 {
        return Err(FederationError::Corrupt);
    }
    let charged = txn
        .open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
        .map_err(storage)?
        .len()
        .map_err(storage)?;
    usize::try_from(limit.saturating_sub(charged)).map_err(|_error| FederationError::Capacity)
}

pub(crate) fn epoch_read(txn: &ReadTransaction, stream: StreamRef) -> Result<u64, FederationError> {
    let key = stream_key(stream);
    let row = txn
        .open_table(FEDERATION_STREAMS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StreamRow>(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    row.validate()?;
    Ok(row.retry_epoch)
}

pub(crate) fn epoch_write(
    txn: &WriteTransaction,
    stream: StreamRef,
) -> Result<u64, FederationError> {
    let key = stream_key(stream);
    let row = txn
        .open_table(FEDERATION_STREAMS_TABLE)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StreamRow>(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    row.validate()?;
    Ok(row.retry_epoch)
}

pub(crate) fn close_epoch(
    txn: &WriteTransaction,
    stream: StreamRef,
    expected: u64,
) -> Result<u64, FederationError> {
    let key = stream_key(stream);
    let mut table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
    let mut row = table
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode::<StreamRow>(saved.value()))
        .transpose()?
        .ok_or(FederationError::NotFound)?;
    row.validate()?;
    if expected == 0 || expected != row.retry_epoch {
        return Err(FederationError::Conflict);
    }
    row.retry_epoch = expected.checked_add(1).ok_or(FederationError::Capacity)?;
    table
        .insert(key.as_slice(), encode(&row)?.as_slice())
        .map_err(storage)?;
    Ok(row.retry_epoch)
}

pub(crate) fn retire_identities(
    txn: &WriteTransaction,
    receipts: &[PublicationReceipt],
) -> Result<usize, FederationError> {
    if receipts.len() > MAX_PUBLICATION_RETIRE_IDS {
        return Err(FederationError::Capacity);
    }
    let mut table = txn
        .open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
        .map_err(storage)?;
    for receipt in receipts {
        if receipt.retry_epoch == 0 || receipt.retry_epoch >= epoch_write(txn, receipt.stream)? {
            return Err(FederationError::Conflict);
        }
        let key = publish_request_key(receipt.stream, receipt.retry_epoch, receipt.publish_id);
        if let Some(saved) = table.get(key.as_slice()).map_err(storage)? {
            let position = Position::try_from(decode::<StoredPosition>(saved.value())?)?;
            if position != receipt.position {
                return Err(FederationError::Conflict);
            }
        }
    }
    let mut removed = 0;
    for receipt in receipts {
        let key = publish_request_key(receipt.stream, receipt.retry_epoch, receipt.publish_id);
        removed += usize::from(table.remove(key.as_slice()).map_err(storage)?.is_some());
    }
    Ok(removed)
}

pub(crate) fn require_receipts(
    txn: &WriteTransaction,
    receipts: &[PublicationReceipt],
) -> Result<(), FederationError> {
    let table = txn
        .open_table(FEDERATION_PUBLISH_REQUESTS_TABLE)
        .map_err(storage)?;
    for receipt in receipts {
        let key = publish_request_key(receipt.stream, receipt.retry_epoch, receipt.publish_id);
        let position = table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| Position::try_from(decode::<StoredPosition>(saved.value())?))
            .transpose()?
            .ok_or(FederationError::Conflict)?;
        if position != receipt.position {
            return Err(FederationError::Conflict);
        }
    }
    Ok(())
}
