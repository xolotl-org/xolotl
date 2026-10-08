//! State owns top-level Lists as one current marker and independently stored items.
//! The marker is private to this backend; State ports return ordinary Values.

use super::{backend_error, codec, decode_envelope};
use crate::schema::{NEXT_STATE_LIST_ID, STATE_LIST_ITEMS_TABLE, STATE_LIST_META_TABLE};
use redb::{ReadableTable, Table, WriteTransaction};
use xolotl_state::{StateError, StateFailure, StateResult, TaintedValue};
use xolotl_types::{TaintSet, Value, ValueListBuilder};

const FORMAT: &[u8; 4] = b"XSL1";
const FIXED_BYTES: usize = 44;
const MIN_ITEM_BYTES: u64 = b"[1,[\"null\"],0]".len() as u64;
pub(super) const ITEM_KEY_BYTES: usize = 16;

fn corruption(reason: &str) -> StateFailure {
    StateError::Serde(reason.into()).into()
}

fn valid_item_layout(first: u64, count: u64, item_bytes: u64) -> bool {
    first.checked_add(count).is_some()
        && count
            .checked_mul(MIN_ITEM_BYTES)
            .is_some_and(|minimum| minimum <= item_bytes)
        && (count != 0 || item_bytes == 0)
}

#[derive(Clone)]
pub(super) struct ListMarker {
    pub id: u64,
    pub first: u64,
    pub count: u64,
    pub item_bytes: u64,
    pub taint: TaintSet,
}

impl ListMarker {
    pub fn end(&self) -> StateResult<u64> {
        self.first
            .checked_add(self.count)
            .ok_or_else(|| backend_error("State List item sequence overflow"))
    }

    pub fn encode(&self) -> StateResult<Vec<u8>> {
        if self.id == 0 && (self.first != 0 || self.count != 0 || self.item_bytes != 0) {
            return Err(backend_error("State List unallocated marker is not empty"));
        }
        if !valid_item_layout(self.first, self.count, self.item_bytes) {
            return Err(backend_error(
                "State List item count or byte total is invalid",
            ));
        }
        self.end()?;
        let mut bytes = vec![0; FIXED_BYTES];
        bytes[..4].copy_from_slice(FORMAT);
        bytes[4..12].copy_from_slice(&self.id.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.first.to_be_bytes());
        bytes[20..28].copy_from_slice(&self.count.to_be_bytes());
        bytes[28..36].copy_from_slice(&self.item_bytes.to_be_bytes());
        serde_json::to_writer(&mut bytes, &self.taint)?;
        let taint_bytes = u64::try_from(bytes.len() - FIXED_BYTES)
            .map_err(|_error| backend_error("State List provenance length overflow"))?;
        bytes[36..44].copy_from_slice(&taint_bytes.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Copy)]
struct Layout {
    id: u64,
    first: u64,
    count: u64,
    item_bytes: u64,
}

fn u64_at(bytes: &[u8], start: usize) -> StateResult<u64> {
    let field: [u8; 8] = bytes
        .get(start..start + 8)
        .and_then(|field| field.try_into().ok())
        .ok_or_else(|| corruption("State List marker is truncated"))?;
    Ok(u64::from_be_bytes(field))
}

fn layout(bytes: &[u8]) -> StateResult<Option<Layout>> {
    if bytes.get(..4) != Some(FORMAT.as_slice()) {
        return Ok(None);
    }
    let id = u64_at(bytes, 4)?;
    let first = u64_at(bytes, 12)?;
    let count = u64_at(bytes, 20)?;
    let item_bytes = u64_at(bytes, 28)?;
    let taint_bytes = usize::try_from(u64_at(bytes, 36)?)
        .map_err(|_error| corruption("State List provenance length overflow"))?;
    if (id == 0 && (first != 0 || count != 0 || item_bytes != 0))
        || !valid_item_layout(first, count, item_bytes)
        || FIXED_BYTES.checked_add(taint_bytes) != Some(bytes.len())
    {
        return Err(corruption("State List marker is invalid"));
    }
    Ok(Some(Layout {
        id,
        first,
        count,
        item_bytes,
    }))
}

pub(super) fn is_segmented(bytes: &[u8]) -> StateResult<bool> {
    Ok(layout(bytes)?.is_some())
}

pub(super) fn marker(bytes: &[u8]) -> StateResult<Option<ListMarker>> {
    let Some(layout) = layout(bytes)? else {
        return Ok(None);
    };
    let taint = serde_json::from_slice(&bytes[FIXED_BYTES..])?;
    Ok(Some(ListMarker {
        id: layout.id,
        first: layout.first,
        count: layout.count,
        item_bytes: layout.item_bytes,
        taint,
    }))
}

/// The budget counts the exact current physical keys and value bytes. It is
/// additive across items, unlike a whole-List tagged encoding with interning.
pub(super) fn record_size(bytes: &[u8], path_bytes: usize) -> StateResult<usize> {
    let base = path_bytes
        .checked_add(bytes.len())
        .ok_or_else(|| backend_error("state record size overflow"))?;
    let Some(layout) = layout(bytes)? else {
        return Ok(base);
    };
    let count = usize::try_from(layout.count)
        .map_err(|_error| backend_error("State List count exceeds address space"))?;
    let item_bytes = usize::try_from(layout.item_bytes)
        .map_err(|_error| backend_error("State List bytes exceed address space"))?;
    base.checked_add(
        count
            .checked_mul(ITEM_KEY_BYTES)
            .and_then(|keys| keys.checked_add(item_bytes))
            .ok_or_else(|| backend_error("State List byte count overflow"))?,
    )
    .ok_or_else(|| backend_error("state record size overflow"))
}

pub(super) fn taint_if_header_fits(
    bytes: &[u8],
    max_header_bytes: usize,
) -> StateResult<Option<TaintSet>> {
    if layout(bytes)?.is_none() {
        return codec::envelope_taint_if_header_fits(bytes, max_header_bytes);
    }
    if bytes.len() > max_header_bytes {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&bytes[FIXED_BYTES..])?))
}

pub(super) fn provenance_size(bytes: &[u8], path_bytes: usize) -> StateResult<usize> {
    let header_bytes = if layout(bytes)?.is_some() {
        bytes.len()
    } else {
        codec::envelope_header_size(bytes)?
    };
    path_bytes
        .checked_add(header_bytes)
        .ok_or_else(|| backend_error("state metadata size overflow"))
}

pub(super) fn taint(bytes: &[u8]) -> StateResult<TaintSet> {
    if layout(bytes)?.is_some() {
        return Ok(serde_json::from_slice(&bytes[FIXED_BYTES..])?);
    }
    codec::envelope_taint(bytes)
}

pub(super) fn item_key(id: u64, index: u64) -> [u8; ITEM_KEY_BYTES] {
    let mut key = [0; ITEM_KEY_BYTES];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key[8..].copy_from_slice(&index.to_be_bytes());
    key
}

pub(super) fn encode_item(value: &Value) -> StateResult<Vec<u8>> {
    serde_json::to_vec(&xolotl_types::tagged_value::serializable(value)).map_err(Into::into)
}

pub(super) enum EncodedValue {
    Inline(Vec<u8>),
    List(Vec<Vec<u8>>),
}

impl EncodedValue {
    pub(super) fn prepare(value: &Value, taint: &TaintSet) -> StateResult<Self> {
        if let Some(values) = value.as_list() {
            values
                .iter()
                .map(encode_item)
                .collect::<StateResult<Vec<_>>>()
                .map(Self::List)
        } else {
            codec::encode_envelope(value, taint).map(Self::Inline)
        }
    }

    pub(super) fn store(self, txn: &WriteTransaction, taint: TaintSet) -> StateResult<Vec<u8>> {
        let values = match self {
            Self::Inline(bytes) => return Ok(bytes),
            Self::List(values) => values,
        };
        let id = if values.is_empty() {
            0
        } else {
            allocate_id(txn)?
        };
        let mut marker = ListMarker {
            id,
            first: 0,
            count: 0,
            item_bytes: 0,
            taint,
        };
        let mut table = item_table(txn)?;
        for bytes in values {
            let key = item_key(id, marker.count);
            marker.count = marker
                .count
                .checked_add(1)
                .ok_or_else(|| backend_error("State List count overflow"))?;
            marker.item_bytes = marker
                .item_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| backend_error("State List byte count overflow"))?;
            if table
                .insert(key.as_slice(), bytes.as_slice())
                .map_err(backend_error)?
                .is_some()
            {
                return Err(backend_error("State List item already exists"));
            }
        }
        marker.encode()
    }
}

pub(super) fn append_item(
    txn: &WriteTransaction,
    marker: &mut ListMarker,
    bytes: &[u8],
) -> StateResult<()> {
    let end = marker.end()?;
    let count = marker
        .count
        .checked_add(1)
        .ok_or_else(|| backend_error("State List count overflow"))?;
    marker
        .first
        .checked_add(count)
        .ok_or_else(|| backend_error("State List sequence exhausted"))?;
    let item_bytes = marker
        .item_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| backend_error("State List byte count overflow"))?;
    if marker.id == 0 {
        if marker.first != 0 || marker.count != 0 || marker.item_bytes != 0 {
            return Err(backend_error("State List unallocated marker is not empty"));
        }
        marker.id = allocate_id(txn)?;
    }
    let key = item_key(marker.id, end);
    if item_table(txn)?
        .insert(key.as_slice(), bytes)
        .map_err(backend_error)?
        .is_some()
    {
        return Err(backend_error("State List next item already exists"));
    }
    marker.count = count;
    marker.item_bytes = item_bytes;
    Ok(())
}

fn decode_item(bytes: &[u8]) -> StateResult<Value> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = xolotl_types::tagged_value::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(value)
}

pub(super) fn materialize<T>(table: &T, bytes: &[u8]) -> StateResult<TaintedValue>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let Some(marker) = marker(bytes)? else {
        return decode_envelope(bytes);
    };
    materialize_marker(table, marker)
}

pub(super) fn materialize_admitted<T>(
    table: &T,
    bytes: &[u8],
    taint: TaintSet,
) -> StateResult<TaintedValue>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let Some(layout) = layout(bytes)? else {
        return codec::decode_admitted_envelope(bytes, taint);
    };
    materialize_marker(
        table,
        ListMarker {
            id: layout.id,
            first: layout.first,
            count: layout.count,
            item_bytes: layout.item_bytes,
            taint,
        },
    )
}

fn materialize_marker<T>(table: &T, marker: ListMarker) -> StateResult<TaintedValue>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let result = (|| -> StateResult<Value> {
        let end_index = marker.end()?;
        let start = item_key(marker.id, marker.first);
        let end = item_key(marker.id, end_index);
        let mut expected = marker.first;
        let mut measured = 0u64;
        for row in table
            .range::<&[u8]>(start.as_slice()..end.as_slice())
            .map_err(backend_error)?
        {
            let (key, guard) = row.map_err(backend_error)?;
            if key.value() != item_key(marker.id, expected).as_slice()
                || (guard.value().len() as u64) < MIN_ITEM_BYTES
            {
                return Err(corruption(
                    "State List item range or encoding length is invalid",
                ));
            }
            measured = measured
                .checked_add(guard.value().len() as u64)
                .filter(|bytes| *bytes <= marker.item_bytes)
                .ok_or_else(|| corruption("State List item bytes exceed marker"))?;
            expected = expected
                .checked_add(1)
                .ok_or_else(|| corruption("State List item range overflow"))?;
        }
        if expected != end_index || measured != marker.item_bytes {
            return Err(corruption(
                "State List item range or byte count differs from marker",
            ));
        }
        let mut values = ValueListBuilder::new();
        for row in table
            .range::<&[u8]>(start.as_slice()..end.as_slice())
            .map_err(backend_error)?
        {
            let (_, guard) = row.map_err(backend_error)?;
            values.push(decode_item(guard.value())?)?;
        }
        Ok(Value::from(values.finish()))
    })();
    let values = result.map_err(|failure| failure.with_taint(&marker.taint))?;
    Ok(TaintedValue::new(values, marker.taint))
}

pub(super) fn remove_items(
    table: &mut Table<'_, &'static [u8], &'static [u8]>,
    marker: &ListMarker,
) -> StateResult<()> {
    for index in marker.first..marker.end()? {
        let key = item_key(marker.id, index);
        if table
            .remove(key.as_slice())
            .map_err(backend_error)?
            .is_none()
        {
            return Err(backend_error("State List item is missing"));
        }
    }
    Ok(())
}

pub(super) fn allocate_id(txn: &WriteTransaction) -> StateResult<u64> {
    let mut meta = txn
        .open_table(STATE_LIST_META_TABLE)
        .map_err(backend_error)?;
    let last = meta
        .get(NEXT_STATE_LIST_ID)
        .map_err(backend_error)?
        .ok_or_else(|| backend_error("State List id metadata missing"))?
        .value();
    let next = last
        .checked_add(1)
        .ok_or_else(|| backend_error("State List ids exhausted"))?;
    meta.insert(NEXT_STATE_LIST_ID, next)
        .map_err(backend_error)?;
    Ok(next)
}

pub(super) fn item_table(
    txn: &WriteTransaction,
) -> StateResult<Table<'_, &'static [u8], &'static [u8]>> {
    txn.open_table(STATE_LIST_ITEMS_TABLE)
        .map_err(backend_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn forged_counts_and_impossible_ranges_are_typed_corruption() -> anyhow::Result<()> {
        let encoded_item = encode_item(&Value::null())?;
        let marker = ListMarker {
            id: 1,
            first: 0,
            count: 1,
            item_bytes: encoded_item.len() as u64,
            taint: TaintSet::author(),
        };
        let original = marker.encode()?;
        for (first, count, bytes) in [
            (0, u64::MAX, 1),
            (u64::MAX, 2, 2 * MIN_ITEM_BYTES),
            (0, 0, 1),
            (0, 1, MIN_ITEM_BYTES - 1),
        ] {
            let mut forged = original.clone();
            forged[12..20].copy_from_slice(&first.to_be_bytes());
            forged[20..28].copy_from_slice(&count.to_be_bytes());
            forged[28..36].copy_from_slice(&bytes.to_be_bytes());
            let failure = super::marker(&forged)
                .err()
                .ok_or_else(|| backend_error("forged marker accepted"))?;
            ensure!(matches!(failure.error, StateError::Serde(_)));
            let failure = record_size(&forged, 7)
                .err()
                .ok_or_else(|| backend_error("forged marker charge accepted"))?;
            ensure!(matches!(failure.error, StateError::Serde(_)));
        }
        ensure!(decode_item(b"[1,[\"null\"],0]")? == Value::null());
        Ok(())
    }

    #[test]
    fn materialization_validates_real_rows_before_allocating_members() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let store = crate::RedbStore::open(directory.path().join("forged-list.redb"))?;
        let txn = store.db.begin_write()?;
        let mut items = item_table(&txn)?;
        let huge = ListMarker {
            id: 1,
            first: 0,
            count: 1_000_000_000,
            item_bytes: 1_000_000_000 * MIN_ITEM_BYTES,
            taint: TaintSet::author(),
        };
        let failure = materialize(&items, &huge.encode()?)
            .err()
            .ok_or_else(|| backend_error("missing huge item range accepted"))?;
        ensure!(
            matches!(failure.error, StateError::Serde(ref message) if message.contains("range"))
        );
        ensure!(failure.taint == huge.taint);
        let first = item_key(1, 0);
        let invalid_payload = vec![b'x'; usize::try_from(MIN_ITEM_BYTES)?];
        items.insert(first.as_slice(), invalid_payload.as_slice())?;
        let failure = materialize(&items, &huge.encode()?)
            .err()
            .ok_or_else(|| backend_error("short huge item range accepted"))?;
        ensure!(
            matches!(failure.error, StateError::Serde(ref message) if message.contains("range"))
        );
        ensure!(failure.taint == huge.taint);
        let last = item_key(1, 2);
        let valid_payload = encode_item(&Value::null())?;
        items.insert(last.as_slice(), valid_payload.as_slice())?;
        let gap = ListMarker {
            count: 3,
            item_bytes: invalid_payload.len() as u64 + valid_payload.len() as u64,
            ..huge.clone()
        };
        let failure = materialize(&items, &gap.encode()?)
            .err()
            .ok_or_else(|| backend_error("gapped range accepted"))?;
        ensure!(
            matches!(failure.error, StateError::Serde(ref message) if message.contains("range"))
        );
        ensure!(failure.taint == gap.taint);
        items.insert(first.as_slice(), valid_payload.as_slice())?;
        let valid = ListMarker {
            count: 1,
            item_bytes: valid_payload.len() as u64,
            ..huge
        };
        let value = materialize(&items, &valid.encode()?)?;
        ensure!(value.value == Value::list(vec![Value::null()]));
        ensure!(value.taint == valid.taint);
        Ok(())
    }

    #[test]
    fn unallocated_empty_marker_cannot_alias_item_ownership() -> anyhow::Result<()> {
        let marker = ListMarker {
            id: 0,
            first: 0,
            count: 0,
            item_bytes: 0,
            taint: TaintSet::author(),
        };
        let bytes = marker.encode()?;
        let decoded = super::marker(&bytes)?.ok_or_else(|| backend_error("marker missing"))?;
        ensure!(decoded.id == 0 && decoded.count == 0);
        for invalid in [
            ListMarker {
                first: 1,
                ..marker.clone()
            },
            ListMarker {
                count: 1,
                ..marker.clone()
            },
            ListMarker {
                item_bytes: 1,
                ..marker
            },
        ] {
            ensure!(invalid.encode().is_err());
        }
        Ok(())
    }

    #[test]
    fn list_marker_has_structural_not_source_admission_limits() -> anyhow::Result<()> {
        let marker = ListMarker {
            id: 1,
            first: 17,
            count: xolotl_source::MAX_SINK_EVENTS as u64 + 1,
            item_bytes: xolotl_source::MAX_DECLARED_SINK_BYTES as u64 + 1,
            taint: TaintSet::author(),
        };
        let bytes = marker.encode()?;
        let decoded = super::marker(&bytes)?.ok_or_else(|| backend_error("marker missing"))?;
        ensure!(decoded.count == marker.count && decoded.item_bytes == marker.item_bytes);
        ensure!(decoded.taint == marker.taint);
        ensure!(
            record_size(&bytes, 11)?
                == 11
                    + bytes.len()
                    + usize::try_from(marker.count)? * ITEM_KEY_BYTES
                    + usize::try_from(marker.item_bytes)?
        );
        for invalid in [
            ListMarker {
                id: 0,
                ..marker.clone()
            },
            ListMarker {
                first: u64::MAX,
                ..marker
            },
        ] {
            ensure!(invalid.encode().is_err());
        }
        let mut invalid = bytes;
        invalid[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        ensure!(super::marker(&invalid).is_err());
        Ok(())
    }
}
