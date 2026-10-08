//! Business replication windows, never execution checkpoints. A persisted
//! window fixes high/continuation/retry epoch before append. Page commitment
//! validates every exact receipt, closes that epoch, retires only confirmed
//! identities and advances the history pin in one redb transaction. Explicit
//! prefix settlement returns shared quota without reserving a whole page; any
//! retained suffix attempt rejects settlement. Uncertain append keeps its
//! original epoch; reopen resumes the same durable window.

use std::ops::Bound;
use std::sync::Arc;

use crate::database::Database;
use redb::{ReadableTable as _, ReadableTableMetadata as _, WriteTransaction};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    FederationError, FederationNodeId, PublicationReceipt, RequestId, StreamRef,
};
use xolotl_state::StateHistoryEntry;
use xolotl_types::Path;

use crate::{
    RedbHistory, RedbStore, STATE_HISTORY_TABLE,
    schema::{
        FEDERATION_STATE_PROJECTION_TABLE, HISTORY_FLOOR_MILLIS, LAST_HISTORY_MILLIS,
        STATE_HISTORY_TIME_INDEX_TABLE, STATE_META_TABLE,
    },
    state::{history_key_parts, indexed_history_entry},
};

/// redb cursor that links stock State-history scans to exact federation
/// publication receipts without an all-path rescan on every poll.
/// At most 64 publishers may pin history. State trim checks all pins under its
/// own write transaction; each row is bounded by a 4 MiB continuation plus
/// 16 KiB metadata and the scan by 64 such rows. Invalid rows fail closed.
/// Registration checks the current trim floor under the same write lock. A new
/// full-history publisher cannot reconstruct an already trimmed prefix; it
/// rejects unless an existing registered cursor covers that floor. Other
/// consumers remain subject to the host's explicit retention-window policy.
/// Removing stock publisher configuration does not release its persisted pin.
/// Trusted hosts must settle pending pages, then call `release_publication`
/// with the exact completed cursor. There is no TTL or inferred abandonment.
#[derive(Clone)]
pub struct RedbFederationStateProjection {
    db: Arc<Database>,
    node: FederationNodeId,
}

/// A bounded page in global commit-time order. `next` is an opaque,
/// transaction-independent continuation through a fixed high watermark.
pub struct FederationStateHistoryPage {
    pub entries: Vec<StateHistoryEntry>,
    pub next: Option<Vec<u8>>,
}

/// Read-only snapshot of one registered State-history publication pin.
/// This is not append evidence or authority to release a pin; release still
/// requires settlement and an exact completed-cursor comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStatePublicationStatus {
    /// Last fully published State-history timestamp, if a scan has completed.
    pub completed_cursor: Option<i64>,
    /// Fixed high watermark of the persisted, unfinished publication window.
    /// Partial page settlement does not advance `completed_cursor` to this high.
    pub pending_high: Option<i64>,
}

const PAGE_CANDIDATES: usize = 1024;
const PAGE_ENTRIES: usize = 128;
const PAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PINS: usize = 64;
const MAX_PIN_BYTES: usize = PAGE_BYTES + 16 * 1024;
const MAX_PIN_SCAN_BYTES: usize = MAX_PINS * MAX_PIN_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CursorRow {
    prefix: String,
    cursor: Option<i64>,
    window: Option<WindowRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowRow {
    from: i64,
    high: i64,
    after: Option<Vec<u8>>,
    retry_epoch: u64,
    max_records: usize,
}

/// Exact persisted publication page intent. Its retry epoch is immutable for
/// all appends on this page; a closed range never upgrades itself on reload.
#[derive(Clone, Debug)]
pub struct FederationStatePublicationPage {
    /// Immutable source events in this bounded page.
    entries: Vec<StateHistoryEntry>,
    stream: StreamRef,
    row: CursorRow,
    next: Option<Vec<u8>>,
    entry_cursors: Vec<Vec<u8>>,
}

impl FederationStatePublicationPage {
    /// Immutable source page; it cannot be shortened to waive missing receipts.
    pub fn entries(&self) -> &[StateHistoryEntry] {
        &self.entries
    }

    /// Fixed publication high watermark, unaffected by later source writes.
    pub fn high(&self) -> i64 {
        self.row.window.as_ref().map_or(0, |window| window.high)
    }
    /// Fixed native retry range for every event in this page.
    pub fn retry_epoch(&self) -> u64 {
        self.row
            .window
            .as_ref()
            .map_or(0, |window| window.retry_epoch)
    }

    /// Continuation after the complete page; prefix settlement returns its own
    /// earlier continuation. `None` finishes the fixed high watermark.
    pub fn next(&self) -> Option<&[u8]> {
        self.next.as_deref()
    }
}

impl RedbStore {
    /// Obtain a durable projection cursor bound to the database's existing
    /// federation node. History capability is mandatory, but a registered
    /// publisher may reopen after safe trim; this does not reconstruct events.
    pub fn federation_state_projection(
        &self,
        node: FederationNodeId,
    ) -> Result<RedbFederationStateProjection, FederationError> {
        if self.history != RedbHistory::Full {
            return Err(FederationError::Invalid(
                "State publication requires history capability",
            ));
        }
        self.federation_store(node)?;
        Ok(RedbFederationStateProjection {
            db: self.db.clone(),
            node,
        })
    }
}

impl RedbFederationStateProjection {
    /// Validate the canonical prefix size required by durable publication cursors.
    pub fn validate_publication_prefix(prefix: &Path) -> Result<(), FederationError> {
        if !prefix
            .canonical_len()
            .is_some_and(|length| (1..=MAX_PREFIX_BYTES).contains(&length))
        {
            return Err(FederationError::Invalid("invalid State publication prefix"));
        }
        Ok(())
    }

    /// The highest committed State-history timestamp at this read transaction.
    /// Later mutations receive a higher timestamp, so a bounded history query
    /// through this watermark has a stable completeness fence.
    pub fn high_watermark(&self) -> Result<i64, FederationError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(STATE_META_TABLE).map_err(storage)?;
        let high = meta
            .get(LAST_HISTORY_MILLIS)
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?
            .value();
        if high < 0 || high == i64::MAX {
            return Err(FederationError::Corrupt);
        }
        Ok(high)
    }

    /// Read new history via its commit-time index. Path-keyed `StateHistory`
    /// pages must inspect all older rows below a prefix on every poll, even
    /// when a lower timestamp is supplied; this index gives true incremental
    /// work while bounding rows examined and encoded input, including filtered keys.
    pub fn history_page(
        &self,
        prefix: &Path,
        from: i64,
        through: i64,
        after: Option<&[u8]>,
    ) -> Result<FederationStateHistoryPage, FederationError> {
        self.history_page_limited(prefix, from, through, after, PAGE_ENTRIES, None)
    }

    fn history_page_limited(
        &self,
        prefix: &Path,
        from: i64,
        through: i64,
        after: Option<&[u8]>,
        max_records: usize,
        mut entry_cursors: Option<&mut Vec<Vec<u8>>>,
    ) -> Result<FederationStateHistoryPage, FederationError> {
        if from > through || through < 0 || through == i64::MAX {
            return Err(FederationError::Invalid("invalid State history interval"));
        }
        let lower = history_time_bound(from);
        let upper = history_time_bound(through + 1);
        let start = match after {
            Some(after)
                if after.len() <= PAGE_BYTES
                    && after >= lower.as_slice()
                    && after < upper.as_slice() =>
            {
                Bound::Excluded(after)
            }
            Some(_) => return Err(FederationError::Invalid("invalid State history cursor")),
            None => Bound::Included(lower.as_slice()),
        };
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(STATE_META_TABLE).map_err(storage)?;
        if meta
            .get(HISTORY_FLOOR_MILLIS)
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?
            .value()
            > from
        {
            return Err(FederationError::Conflict);
        }
        let time_index = txn
            .open_table(STATE_HISTORY_TIME_INDEX_TABLE)
            .map_err(storage)?;
        let history = txn.open_table(STATE_HISTORY_TABLE).map_err(storage)?;
        let mut rows = time_index
            .range::<&[u8]>((start, Bound::Excluded(upper.as_slice())))
            .map_err(storage)?;
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut previous = after.map(ToOwned::to_owned);
        let mut examined = 0usize;
        loop {
            if examined == PAGE_CANDIDATES || entries.len() == max_records || bytes == PAGE_BYTES {
                return Ok(FederationStateHistoryPage {
                    entries,
                    next: previous,
                });
            }
            let Some(row) = rows.next() else {
                return Ok(FederationStateHistoryPage {
                    entries,
                    next: None,
                });
            };
            let (key, value) = row.map_err(storage)?;
            let index_key = key.value();
            let index_bytes = index_key
                .len()
                .checked_add(value.value().len())
                .ok_or(FederationError::Corrupt)?;
            if index_bytes > PAGE_BYTES {
                if examined == 0 {
                    return Err(FederationError::Invalid(
                        "State history index exceeds projection page limit",
                    ));
                }
                return Ok(FederationStateHistoryPage {
                    entries,
                    next: previous,
                });
            }
            let mut next_bytes = bytes
                .checked_add(index_bytes)
                .ok_or(FederationError::Corrupt)?;
            if next_bytes > PAGE_BYTES {
                return Ok(FederationStateHistoryPage {
                    entries,
                    next: previous,
                });
            }
            if !value.value().is_empty() || index_key.len() <= 8 {
                return Err(FederationError::Corrupt);
            }
            let primary_key = &index_key[8..];
            let (path, at_millis) = history_key_parts(primary_key).map_err(storage)?;
            if index_key[..8] != history_time_bound(at_millis) {
                return Err(FederationError::Corrupt);
            }
            if prefix == &path || prefix.is_prefix_of(&path) {
                let record = history
                    .get(primary_key)
                    .map_err(storage)?
                    .ok_or(FederationError::Corrupt)?;
                next_bytes = next_bytes
                    .checked_add(record.value().len())
                    .ok_or(FederationError::Corrupt)?;
                if next_bytes > PAGE_BYTES {
                    if examined == 0 {
                        return Err(FederationError::Invalid(
                            "State history event exceeds projection page limit",
                        ));
                    }
                    return Ok(FederationStateHistoryPage {
                        entries,
                        next: previous,
                    });
                }
                entries.push(
                    indexed_history_entry(record.value(), &path, at_millis).map_err(storage)?,
                );
                if let Some(cursors) = &mut entry_cursors {
                    cursors.push(index_key.to_vec());
                }
            }
            bytes = next_bytes;
            previous = Some(index_key.to_vec());
            examined += 1;
        }
    }

    /// Last fully published State-history timestamp for this exact stream and
    /// source prefix, or `None` before the first completed scan.
    pub fn cursor(&self, stream: StreamRef, prefix: &Path) -> Result<Option<i64>, FederationError> {
        let key = self.stream_key(stream)?;
        let txn = self.db.begin_read().map_err(storage)?;
        let table = txn
            .open_table(FEDERATION_STATE_PROJECTION_TABLE)
            .map_err(storage)?;
        table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|row| {
                let row = decode_row(row.value())?;
                if row.prefix != prefix.to_string() {
                    return Err(FederationError::Conflict);
                }
                Ok(row.cursor)
            })
            .transpose()
            .map(Option::flatten)
    }

    /// Inspect one publication pin through a bounded point lookup in exactly
    /// one consistent read transaction. Validates the prefix, local stream
    /// identity and stream existence, and checks any pending window against
    /// the current stream retry epoch. A different registered prefix or stale
    /// window conflicts. Decodes at most one existing bounded cursor row;
    /// does not scan history, register, append, mutate or record an audit.
    ///
    /// `None` means this known stream has no retained pin. It is not evidence
    /// that the supplied prefix was released or completely published. Unknown
    /// streams return `NotFound`, not absence. The snapshot does not reserve
    /// the pin or prevent a subsequent writer from changing it.
    pub fn publication_status(
        &self,
        stream: StreamRef,
        prefix: &Path,
    ) -> Result<Option<FederationStatePublicationStatus>, FederationError> {
        Self::validate_publication_prefix(prefix)?;
        let key = self.stream_key(stream)?;
        let txn = self.db.begin_read().map_err(storage)?;
        let epoch = crate::federation::publication::epoch_read(&txn, stream)?;
        let table = txn
            .open_table(FEDERATION_STATE_PROJECTION_TABLE)
            .map_err(storage)?;
        table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| {
                let row = decode_row(saved.value())?;
                if row.prefix != prefix.to_string()
                    || row
                        .window
                        .as_ref()
                        .is_some_and(|window| window.retry_epoch != epoch)
                {
                    return Err(FederationError::Conflict);
                }
                Ok(FederationStatePublicationStatus {
                    completed_cursor: row.cursor,
                    pending_high: row.window.map(|window| window.high),
                })
            })
            .transpose()
    }

    /// Register or resume an exact bounded business publication window. Its
    /// high/after/epoch is persisted before any append and the source history
    /// is pinned. A writer whose epoch was closed elsewhere conflicts instead
    /// of silently rebinding old unknown attempts. Registration and trim share
    /// the redb write lock; an already missing initial prefix is rejected.
    /// Page sizing observes shared identity capacity but reserves no slots.
    /// If another publisher consumes capacity, explicitly settle the confirmed
    /// prefix rather than waiting for the entire page to fit. Exact event keys
    /// retained for that handoff are bounded by the page's encoded input budget.
    pub fn publication_page(
        &self,
        stream: StreamRef,
        prefix: &Path,
        high: i64,
    ) -> Result<Option<FederationStatePublicationPage>, FederationError> {
        Self::validate_publication_prefix(prefix)?;
        let key = self.stream_key(stream)?;
        if high < 0 || high == i64::MAX {
            return Err(FederationError::Invalid(
                "invalid State publication high watermark",
            ));
        }
        let txn = self.db.begin_write().map_err(storage)?;
        let (floor, committed) = history_bounds(&txn)?;
        if high > committed {
            return Err(FederationError::Conflict);
        }
        let epoch = crate::federation::publication::epoch_write(&txn, stream)?;
        let mut table = txn
            .open_table(FEDERATION_STATE_PROJECTION_TABLE)
            .map_err(storage)?;
        if table.len().map_err(storage)? > MAX_PINS as u64 {
            return Err(FederationError::Corrupt);
        }
        let saved = table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode_row(saved.value()))
            .transpose()?;
        let mut row = match saved {
            Some(row) => row,
            None => {
                if table.len().map_err(storage)? >= MAX_PINS as u64 {
                    return Err(FederationError::Capacity);
                }
                if epoch != 1 {
                    return Err(FederationError::Conflict);
                }
                CursorRow {
                    prefix: prefix.to_string(),
                    cursor: None,
                    window: None,
                }
            }
        };
        if row.prefix != prefix.to_string() || floor > row.retained_from()? {
            return Err(FederationError::Conflict);
        }
        if let Some(window) = &row.window {
            if window.retry_epoch != epoch || window.high > high {
                return Err(FederationError::Conflict);
            }
        } else {
            if row.cursor.is_some_and(|cursor| cursor >= high) {
                return Ok(None);
            }
            let max_records = crate::federation::publication::available_identity_slots(&txn)?
                .clamp(1, PAGE_ENTRIES);
            row.window = Some(WindowRow {
                from: row.cursor.map_or(i64::MIN, |cursor| cursor + 1),
                high,
                after: None,
                retry_epoch: epoch,
                max_records,
            });
            table
                .insert(key.as_slice(), encode_row(&row)?.as_slice())
                .map_err(storage)?;
        }
        drop(table);
        txn.commit()
            .map_err(|_error| FederationError::Indeterminate)?;
        let window = row.window.as_ref().ok_or(FederationError::Corrupt)?;
        let mut entry_cursors = Vec::new();
        let page = self.history_page_limited(
            prefix,
            row.retained_from()?,
            window.high,
            window.after.as_deref(),
            window.max_records,
            Some(&mut entry_cursors),
        )?;
        Ok(Some(FederationStatePublicationPage {
            entries: page.entries,
            stream,
            row,
            next: page.next,
            entry_cursors,
        }))
    }

    /// Atomically commit an exact page continuation, close its fixed epoch and
    /// release its observed append identities. Every source event needs one
    /// exact retained receipt from the page's still-active epoch; missing,
    /// changed or foreign receipts reject the whole transaction. Closure and
    /// identity retirement occur only after validating the entire page.
    /// An unknown append leaves the original
    /// window/epoch/identities intact. After an unknown page commit, reopen and
    /// reload the durable window; never reuse its receipts in a newer epoch.
    pub fn commit_publication_page(
        &self,
        page: &FederationStatePublicationPage,
        receipts: &[PublicationReceipt],
    ) -> Result<(), FederationError> {
        if receipts.len() != page.entries.len() || receipts.len() > PAGE_ENTRIES {
            return Err(FederationError::Conflict);
        }
        self.commit_publication_prefix(page, receipts).map(|_| ())
    }

    /// Atomically settle an exact, nonempty leading prefix of a page, or the
    /// complete page (including an empty filtered page). Receipts must match
    /// each leading source event and its retained position. The omitted suffix
    /// is not waived: continuation stops at the last confirmed event, leaving
    /// every later event pinned and pending under the same fixed high watermark.
    ///
    /// The transaction rejects any retained identity for an omitted event,
    /// including an uncertain append whose receipt was not observed. Only then
    /// does it close the page epoch, retire the confirmed identities and persist
    /// the continuation with the successor epoch. In-flight old-epoch appends
    /// serialize before this check or reject after closure. Callers stop at a
    /// definite quota rejection; other append failures require reconciliation
    /// in the original epoch, not inferred prefix settlement.
    ///
    /// Returns the committed continuation, not necessarily `page.next()`; `None`
    /// completes the window. No slots are reserved or oversubscribed. An unknown
    /// settlement outcome requires reopen and reload before further appends.
    pub fn commit_publication_prefix(
        &self,
        page: &FederationStatePublicationPage,
        receipts: &[PublicationReceipt],
    ) -> Result<Option<Vec<u8>>, FederationError> {
        let key = self.stream_key(page.stream)?;
        if receipts.len() > page.entries.len()
            || receipts.len() > PAGE_ENTRIES
            || (receipts.is_empty() && !page.entries.is_empty())
        {
            return Err(FederationError::Conflict);
        }
        for (entry, receipt) in page.entries.iter().zip(receipts) {
            if receipt.stream != page.stream
                || receipt.retry_epoch != page.retry_epoch()
                || receipt.publish_id != Self::publish_id(page.stream, entry)
            {
                return Err(FederationError::Conflict);
            }
        }
        let txn = self.db.begin_write().map_err(storage)?;
        let mut table = txn
            .open_table(FEDERATION_STATE_PROJECTION_TABLE)
            .map_err(storage)?;
        let mut row = table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode_row(saved.value()))
            .transpose()?
            .ok_or(FederationError::Conflict)?;
        if row != page.row {
            return Err(FederationError::Conflict);
        }
        let (floor, _) = history_bounds(&txn)?;
        if floor > row.retained_from()? {
            return Err(FederationError::Conflict);
        }
        crate::federation::publication::require_receipts(&txn, receipts)?;
        let partial = receipts.len() < page.entries.len();
        if partial {
            let identities = txn
                .open_table(crate::schema::FEDERATION_PUBLISH_REQUESTS_TABLE)
                .map_err(storage)?;
            let mut identity_key = [0; 88];
            identity_key[..64].copy_from_slice(&key);
            identity_key[64..72].copy_from_slice(&page.retry_epoch().to_be_bytes());
            for entry in &page.entries[receipts.len()..] {
                identity_key[72..].copy_from_slice(Self::publish_id(page.stream, entry).as_bytes());
                if identities
                    .get(identity_key.as_slice())
                    .map_err(storage)?
                    .is_some()
                {
                    return Err(FederationError::Conflict);
                }
            }
        }
        let continuation = if partial {
            Some(
                page.entry_cursors
                    .get(receipts.len() - 1)
                    .ok_or(FederationError::Corrupt)?
                    .clone(),
            )
        } else {
            page.next.clone()
        };
        let next_epoch =
            crate::federation::publication::close_epoch(&txn, page.stream, page.retry_epoch())?;
        crate::federation::publication::retire_identities(&txn, receipts)?;
        let window = row.window.as_mut().ok_or(FederationError::Corrupt)?;
        if continuation.is_some() {
            window.after = continuation;
            window.retry_epoch = next_epoch;
            window.max_records = crate::federation::publication::available_identity_slots(&txn)?
                .clamp(1, PAGE_ENTRIES);
        } else {
            row.cursor = Some(window.high);
            row.window = None;
        }
        table
            .insert(key.as_slice(), encode_row(&row)?.as_slice())
            .map_err(storage)?;
        drop(table);
        txn.commit()
            .map_err(|_error| FederationError::Indeterminate)?;
        Ok(row.window.and_then(|window| window.after))
    }

    /// Explicit trusted-host release of a completed publisher's retention pin.
    /// Removing stock configuration alone does not call this method. A pending
    /// page, including unknown appends, always rejects: settle its exact window
    /// first. Compare the source prefix and fully completed cursor before
    /// deleting the pin. Old page epochs remain permanently closed in the
    /// native stream row, so re-registration of that retired stream is rejected;
    /// a new full-history publisher needs a new stream and intact source prefix.
    /// Returns false on an already absent pin; absence is not prefix evidence.
    pub fn release_publication(
        &self,
        stream: StreamRef,
        prefix: &Path,
        expected_cursor: i64,
    ) -> Result<bool, FederationError> {
        let key = self.stream_key(stream)?;
        let txn = self.db.begin_write().map_err(storage)?;
        let mut table = txn
            .open_table(FEDERATION_STATE_PROJECTION_TABLE)
            .map_err(storage)?;
        let Some(row) = table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode_row(saved.value()))
            .transpose()?
        else {
            return Ok(false);
        };
        if row.prefix != prefix.to_string()
            || row.cursor != Some(expected_cursor)
            || row.window.is_some()
        {
            return Err(FederationError::Conflict);
        }
        if crate::federation::publication::epoch_write(&txn, stream)? <= 1 {
            return Err(FederationError::Corrupt);
        }
        table.remove(key.as_slice()).map_err(storage)?;
        drop(table);
        txn.commit()
            .map_err(|_error| FederationError::Indeterminate)?;
        Ok(true)
    }

    /// Stable source event identity, separate from its immutable retry epoch.
    pub fn publish_id(stream: StreamRef, entry: &StateHistoryEntry) -> RequestId {
        let mut hash = Sha384::new();
        hash.update(b"xolotl.federation.state-history-publish-id.v1\0");
        hash.update(stream.publisher.as_bytes());
        hash.update(stream.id.as_bytes());
        let path = entry.event.path().to_string();
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update(entry.at_millis.to_be_bytes());
        let digest = hash.finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        RequestId::from_bytes(id)
    }

    fn stream_key(&self, stream: StreamRef) -> Result<[u8; 64], FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        let mut key = [0; 64];
        key[..48].copy_from_slice(self.node.as_bytes());
        key[48..].copy_from_slice(stream.id.as_bytes());
        Ok(key)
    }
}

fn history_time_bound(timestamp: i64) -> [u8; 8] {
    (timestamp as u64 ^ (1_u64 << 63)).to_be_bytes()
}

fn storage(error: impl ToString) -> FederationError {
    FederationError::Storage(error.to_string())
}

const MAX_PREFIX_BYTES: usize = 4096;

impl CursorRow {
    fn retained_from(&self) -> Result<i64, FederationError> {
        if let Some(window) = &self.window {
            if let Some(after) = &window.after {
                return cursor_time(after);
            }
            return Ok(window.from);
        }
        self.cursor.map_or(Ok(i64::MIN), |cursor| {
            cursor.checked_add(1).ok_or(FederationError::Corrupt)
        })
    }

    fn validate(&self) -> Result<(), FederationError> {
        let prefix = Path::parse(&self.prefix).map_err(|_error| FederationError::Corrupt)?;
        RedbFederationStateProjection::validate_publication_prefix(&prefix)
            .map_err(|_error| FederationError::Corrupt)?;
        if prefix.to_string() != self.prefix
            || self
                .cursor
                .is_some_and(|cursor| cursor < 0 || cursor == i64::MAX)
        {
            return Err(FederationError::Corrupt);
        }
        if let Some(window) = &self.window {
            let from = self.cursor.map_or(i64::MIN, |cursor| cursor + 1);
            if window.retry_epoch == 0
                || !(1..=PAGE_ENTRIES).contains(&window.max_records)
                || window.from != from
                || window.high < 0
                || window.high == i64::MAX
                || window.from > window.high
            {
                return Err(FederationError::Corrupt);
            }
            if let Some(after) = &window.after {
                if after.len() > PAGE_BYTES
                    || after.len() <= 8
                    || after.as_slice() < history_time_bound(window.from).as_slice()
                    || after.as_slice() >= history_time_bound(window.high + 1).as_slice()
                {
                    return Err(FederationError::Corrupt);
                }
                cursor_time(after)?;
                let (_, at_millis) =
                    history_key_parts(&after[8..]).map_err(|_error| FederationError::Corrupt)?;
                if cursor_time(after)? != at_millis {
                    return Err(FederationError::Corrupt);
                }
            }
        }
        Ok(())
    }
}

fn cursor_time(cursor: &[u8]) -> Result<i64, FederationError> {
    let bytes: [u8; 8] = cursor
        .get(..8)
        .ok_or(FederationError::Corrupt)?
        .try_into()
        .map_err(|_error| FederationError::Corrupt)?;
    Ok((u64::from_be_bytes(bytes) ^ (1_u64 << 63)) as i64)
}

fn history_bounds(txn: &WriteTransaction) -> Result<(i64, i64), FederationError> {
    let meta = txn.open_table(STATE_META_TABLE).map_err(storage)?;
    let floor = meta
        .get(HISTORY_FLOOR_MILLIS)
        .map_err(storage)?
        .ok_or(FederationError::Corrupt)?
        .value();
    let high = meta
        .get(LAST_HISTORY_MILLIS)
        .map_err(storage)?
        .ok_or(FederationError::Corrupt)?
        .value();
    Ok((floor, high))
}

fn encode_row(row: &CursorRow) -> Result<Vec<u8>, FederationError> {
    row.validate()?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(row.prefix.len() as u32).to_be_bytes());
    encoded.extend_from_slice(row.prefix.as_bytes());
    encoded.extend_from_slice(&row.cursor.unwrap_or(i64::MIN).to_be_bytes());
    encoded.push(u8::from(row.window.is_some()));
    if let Some(window) = &row.window {
        encoded.extend_from_slice(&window.from.to_be_bytes());
        encoded.extend_from_slice(&window.high.to_be_bytes());
        encoded.extend_from_slice(&window.retry_epoch.to_be_bytes());
        encoded.extend_from_slice(&(window.max_records as u32).to_be_bytes());
        let after = window.after.as_deref().unwrap_or_default();
        encoded.extend_from_slice(&(after.len() as u32).to_be_bytes());
        encoded.extend_from_slice(after);
    }
    if encoded.len() > MAX_PIN_BYTES {
        return Err(FederationError::Capacity);
    }
    Ok(encoded)
}

fn decode_row(bytes: &[u8]) -> Result<CursorRow, FederationError> {
    if bytes.len() < 14 || bytes.len() > MAX_PIN_BYTES {
        return Err(FederationError::Corrupt);
    }
    let length = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    if length == 0 || length > MAX_PREFIX_BYTES || bytes.len() < 4 + length + 9 {
        return Err(FederationError::Corrupt);
    }
    let prefix = std::str::from_utf8(&bytes[4..4 + length])
        .map_err(|_error| FederationError::Corrupt)?
        .to_owned();
    let rest = &bytes[4 + length..];
    let cursor = i64::from_be_bytes(
        rest[..8]
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let window = match rest[8] {
        0 if rest.len() == 9 => None,
        1 if rest.len() >= 41 => {
            let from = i64::from_be_bytes(
                rest[9..17]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            );
            let high = i64::from_be_bytes(
                rest[17..25]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            );
            let retry_epoch = u64::from_be_bytes(
                rest[25..33]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            );
            let max_records = u32::from_be_bytes(
                rest[33..37]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            ) as usize;
            let length = u32::from_be_bytes(
                rest[37..41]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            ) as usize;
            if length > PAGE_BYTES || rest.len() != 41 + length {
                return Err(FederationError::Corrupt);
            }
            Some(WindowRow {
                from,
                high,
                retry_epoch,
                max_records,
                after: (length != 0).then(|| rest[41..].to_vec()),
            })
        }
        _ => return Err(FederationError::Corrupt),
    };
    let row = CursorRow {
        prefix,
        cursor: (cursor != i64::MIN).then_some(cursor),
        window,
    };
    row.validate()?;
    Ok(row)
}

/// State retention's same-write-transaction gate. No global reader registry is
/// implied: only explicitly registered publishers pin source history. The host
/// still owns unregistered consumer windows. Invalid metadata, more than 64
/// pins, or more than the bounded encoded scan budget rejects before deletion.
pub(crate) fn check_state_history_retirement(
    txn: &WriteTransaction,
    floor: i64,
) -> Result<(), FederationError> {
    let table = txn
        .open_table(FEDERATION_STATE_PROJECTION_TABLE)
        .map_err(storage)?;
    if table.len().map_err(storage)? > MAX_PINS as u64 {
        return Err(FederationError::Corrupt);
    }
    let mut scanned = 0usize;
    for entry in table.iter().map_err(storage)? {
        let (key, saved) = entry.map_err(storage)?;
        if key.value().len() != 64 {
            return Err(FederationError::Corrupt);
        }
        scanned = scanned
            .checked_add(saved.value().len())
            .ok_or(FederationError::Capacity)?;
        if scanned > MAX_PIN_SCAN_BYTES {
            return Err(FederationError::Capacity);
        }
        if floor > decode_row(saved.value())?.retained_from()? {
            return Err(FederationError::Conflict);
        }
    }
    Ok(())
}

#[cfg(test)]
mod commit_fault_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context as _, Result, ensure};
    use xolotl_types::Value;

    fn fixture() -> Result<(tempfile::TempDir, RedbStore, RedbFederationStateProjection)> {
        let directory = tempfile::tempdir()?;
        let store = RedbStore::open_with_history(
            directory.path().join("projection.redb"),
            RedbHistory::Full,
        )?;
        let projection =
            store.federation_state_projection(FederationNodeId::from_bytes([1; 48]))?;
        Ok((directory, store, projection))
    }

    #[test]
    fn publication_status_reads_committed_pin_under_active_writer() -> Result<()> {
        use xolotl_federation::{ExportName, FederationStore as _, StreamId, StreamSpec};
        let (_directory, store, projection) = fixture()?;
        let stream = StreamRef {
            publisher: projection.node,
            id: StreamId::from_bytes([1; 16]),
        };
        store
            .federation_store(projection.node)?
            .declare_stream(StreamSpec {
                stream,
                export: ExportName::new("published")?,
            })?;
        let prefix = Path::parse("state://published")?;
        let high = projection.high_watermark()?;
        let page = projection
            .publication_page(stream, &prefix, high)?
            .context("page")?;
        let transaction = store.db.begin_write()?;
        transaction
            .open_table(FEDERATION_STATE_PROJECTION_TABLE)?
            .remove(projection.stream_key(stream)?.as_slice())?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _sent = sender.send(projection.publication_status(stream, &prefix));
        });
        let observed = receiver.recv_timeout(std::time::Duration::from_secs(2));
        drop(transaction);
        reader
            .join()
            .map_err(|_error| anyhow::anyhow!("status reader failed"))?;
        ensure!(
            observed??
                == Some(FederationStatePublicationStatus {
                    completed_cursor: None,
                    pending_high: Some(page.high()),
                })
        );
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_pin_rejects_trim_without_deleting_history() -> Result<()> {
        use xolotl_state::StateHistoryTrimLimits;
        let (_directory, store, projection) = fixture()?;
        let state = store.state_backend().into_backend();
        let path = Path::parse("state://published/item")?;
        state.write_set(&path, Value::integer(1)).await?;
        let high = projection.high_watermark()?;
        let txn = store.db.begin_write()?;
        txn.open_table(FEDERATION_STATE_PROJECTION_TABLE)?
            .insert([1_u8; 64].as_slice(), b"invalid".as_slice())?;
        txn.commit()?;
        ensure!(
            state
                .trim_history_before(high + 1, StateHistoryTrimLimits::default())
                .await
                .is_err()
        );
        ensure!(
            projection
                .history_page(&Path::parse("state://published")?, i64::MIN, high, None)?
                .entries
                .len()
                == 1
        );
        Ok(())
    }

    #[test]
    fn publication_prefix_validation_matches_cursor_boundary() -> Result<()> {
        let base = "state://federation/public/";
        let accepted = Path::parse(&format!(
            "{base}{}",
            "x".repeat(MAX_PREFIX_BYTES - base.len())
        ))?;
        RedbFederationStateProjection::validate_publication_prefix(&accepted)?;
        let row = CursorRow {
            prefix: accepted.to_string(),
            cursor: Some(0),
            window: None,
        };
        ensure!(decode_row(&encode_row(&row)?)? == row);
        let rejected = Path::parse(&format!("{accepted}x"))?;
        ensure!(matches!(
            RedbFederationStateProjection::validate_publication_prefix(&rejected),
            Err(FederationError::Invalid("invalid State publication prefix"))
        ));
        ensure!(
            encode_row(&CursorRow {
                prefix: rejected.to_string(),
                ..row
            })
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn filtered_index_keys_charge_budget_without_skipping() -> Result<()> {
        let (_directory, store, projection) = fixture()?;
        let state = store.state_backend().into_backend();
        let prefix = Path::parse("state://published")?;
        for suffix in ["a", "b"] {
            let path = Path::parse(&format!(
                "state://other/{}{suffix}",
                "x".repeat(PAGE_BYTES / 2)
            ))?;
            state.write_set(&path, Value::null()).await?;
        }
        let target = Path::parse("state://published/entry")?;
        state.write_set(&target, Value::integer(7)).await?;
        let high = projection.high_watermark()?;
        let first = projection.history_page(&prefix, i64::MIN, high, None)?;
        ensure!(first.entries.is_empty());
        let cursor = first.next.context("filtered page did not advance")?;
        let second = projection.history_page(&prefix, i64::MIN, high, Some(&cursor))?;
        ensure!(second.entries.len() == 1 && second.next.is_none());
        ensure!(second.entries[0].event.path() == &target);
        Ok(())
    }

    #[tokio::test]
    async fn oversized_index_after_consumed_page_preserves_delivered_entries() -> Result<()> {
        let (_directory, store, projection) = fixture()?;
        let state = store.state_backend().into_backend();
        let prefix = Path::parse("state://published")?;
        let target = Path::parse("state://published/entry")?;
        state.write_set(&target, Value::integer(7)).await?;
        let oversized = Path::parse(&format!("state://other/{}", "x".repeat(PAGE_BYTES)))?;
        state.write_set(&oversized, Value::null()).await?;
        let high = projection.high_watermark()?;
        let first = projection.history_page(&prefix, i64::MIN, high, None)?;
        ensure!(first.entries.len() == 1 && first.entries[0].event.path() == &target);
        let cursor = first.next.context("consumed prefix was not delivered")?;
        ensure!(matches!(
            projection.history_page(&prefix, i64::MIN, high, Some(&cursor)),
            Err(FederationError::Invalid(
                "State history index exceeds projection page limit"
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_first_index_key_is_rejected_before_path_parsing() -> Result<()> {
        let (_directory, store, projection) = fixture()?;
        let timestamp = 1;
        let mut key = history_time_bound(timestamp).to_vec();
        key.resize(PAGE_BYTES + 1, 0);
        let txn = store.db.begin_write()?;
        txn.open_table(STATE_HISTORY_TIME_INDEX_TABLE)?
            .insert(key.as_slice(), &[] as &[u8])?;
        txn.commit()?;
        ensure!(matches!(
            projection.history_page(
                &Path::parse("state://published")?,
                i64::MIN,
                timestamp,
                None
            ),
            Err(FederationError::Invalid(
                "State history index exceeds projection page limit"
            ))
        ));
        Ok(())
    }

    #[test]
    fn oversized_history_cursor_is_rejected_before_copying() -> Result<()> {
        let (_directory, _store, projection) = fixture()?;
        let mut cursor = history_time_bound(1).to_vec();
        cursor.resize(PAGE_BYTES + 1, 0);
        ensure!(matches!(
            projection.history_page(
                &Path::parse("state://published")?,
                i64::MIN,
                1,
                Some(&cursor),
            ),
            Err(FederationError::Invalid("invalid State history cursor"))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn matched_payload_after_filtered_candidate_continues_without_loss() -> Result<()> {
        let (_directory, store, projection) = fixture()?;
        let state = store.state_backend().into_backend();
        let prefix = Path::parse("state://published")?;
        let unrelated = Path::parse(&format!("state://other/{}", "x".repeat(PAGE_BYTES - 256)))?;
        state.write_set(&unrelated, Value::null()).await?;
        let target = Path::parse("state://published/entry")?;
        state
            .write_set(&target, Value::string("x".repeat(512)))
            .await?;
        let high = projection.high_watermark()?;
        let first = projection.history_page(&prefix, i64::MIN, high, None)?;
        ensure!(first.entries.is_empty());
        let cursor = first.next.context("payload boundary did not advance")?;
        let second = projection.history_page(&prefix, i64::MIN, high, Some(&cursor))?;
        ensure!(second.entries.len() == 1 && second.next.is_none());
        ensure!(second.entries[0].event.path() == &target);
        let oversized = Path::parse("state://published/oversized")?;
        state
            .write_set(&oversized, Value::string("x".repeat(PAGE_BYTES)))
            .await?;
        ensure!(matches!(
            projection.history_page(&prefix, high + 1, projection.high_watermark()?, None),
            Err(FederationError::Invalid(
                "State history event exceeds projection page limit"
            ))
        ));
        Ok(())
    }
}
