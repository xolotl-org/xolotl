//! Source-private decisions and receipts share one redb transaction with the
//! declared State sink. Ordinary State ports cannot address these tables.

use super::*;
use crate::schema::{
    EXTERNAL_INSTALLATIONS_META_TABLE, EXTERNAL_INSTALLATIONS_TABLE, EXTERNAL_SOURCE_SCOPES_TABLE,
    NEXT_EXTERNAL_AUTHORITY_EPOCH, SOURCE_META_TABLE, SOURCE_RECEIPTS_TABLE,
    SOURCE_SEQUENCE_META_TABLE, SOURCE_STREAM_COUNT,
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use xolotl_kernel::host::blocking::dispatch;
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, ExternalInstallationRecord,
    ExternalInstallationRevision, MAX_DECLARED_SINK_BYTES, MAX_ID_BYTES,
    MAX_INSTALLATION_RECORD_BYTES, MAX_MAINTENANCE_BATCH, MAX_RATE_HITS, MAX_RECEIPT_BYTES,
    MAX_SINK_EVENTS, SourceAdmissionError, SourceClaim, SourceClaimEvidence, SourceClaimId,
    SourceClaimInspection, SourceCommit, SourceCommitOutcome, SourceCommitRejection,
    SourceDeclarationAdmission, SourceEventCommit, SourceEventDecisionInspection,
    SourceEventMaintenance, SourceEvidenceInspection, SourceFuture, SourceMaintenance,
    SourceMaintenanceResult, SourceReceipt, SourceScopeAdmission, SourceStoreError,
    SourceStreamLifecycle, SourceStreamOpen, SourceStreamOpenOutcome, SourceStreamPosition,
    SourceStreamRetire, SourceStreamRetireOutcome, SourceStreamScope, SourceStreamSnapshot,
    SourceStreamState,
};
use xolotl_types::external::{
    EventSource, ExternalInstallationDef, OverflowPolicy, SourceRateLimit, StreamCapacity,
};

// A 256-byte stream id can expand to 1536 bytes through JSON escaping.
const MAX_EVENT_ROW_BYTES: usize = 2048;
const MAX_SEQUENCE_ROW_BYTES: usize = 26 + MAX_ID_BYTES;
const MAX_RATE_ROW_BYTES: usize = 8 + MAX_RATE_HITS * 8;
const MAX_CURSOR_BYTES: usize = 4096;
const MAX_SOURCE_SCOPE_ROW_BYTES: usize = 16 * 1024;
const MAINTENANCE_CURSOR_KEY: &[u8] = b"G";

// Accepted work owns only its storage and notification resources. In particular,
// it must not retain the spawner whose queue may own this same job.
struct SourceOwner {
    db: Arc<Database>,
    publication: Arc<Publication>,
    history: RedbHistory,
    source_stream_limit: NonZeroUsize,
    source_retention_limit: NonZeroUsize,
    absence_limits: xolotl_state::AbsenceLimits,
}

impl SourceOwner {
    fn from_backend(backend: &RedbStateBackend) -> Self {
        Self {
            db: Arc::clone(&backend.db),
            publication: Arc::clone(&backend.publication),
            history: backend.history,
            source_stream_limit: backend.source_stream_limit,
            source_retention_limit: backend.source_retention_limit,
            absence_limits: backend.absence_limits,
        }
    }
}

async fn source_job<T: Send + 'static>(
    backend: &RedbStateBackend,
    operation: &'static str,
    work: impl FnOnce(SourceOwner) -> Result<T, SourceStoreError> + Send + 'static,
) -> Result<T, SourceStoreError> {
    let owner = SourceOwner::from_backend(backend);
    let task = dispatch(backend.blocking_spawner.as_ref(), move || work(owner))
        .map_err(|error| aborted(format!("Source {operation} admission failed: {error}")))?;
    task.await.map_err(|error| {
        SourceStoreError::Indeterminate(format!(
            "Source {operation} worker outcome unknown: {error}"
        ))
    })?
}

struct OwnedClaim {
    installation_id: String,
    projection_id: String,
    scope_epoch: u64,
    stream_epoch: Option<u64>,
    event_id: String,
    claim_id: SourceClaimId,
}

impl OwnedClaim {
    fn from_borrowed(claim: SourceClaim<'_>) -> Self {
        Self {
            installation_id: claim.installation_id.to_owned(),
            projection_id: claim.projection_id.to_owned(),
            scope_epoch: claim.scope_epoch,
            stream_epoch: claim.stream_epoch,
            event_id: claim.event_id.to_owned(),
            claim_id: claim.claim_id,
        }
    }

    fn borrow(&self) -> SourceClaim<'_> {
        SourceClaim {
            installation_id: &self.installation_id,
            projection_id: &self.projection_id,
            scope_epoch: self.scope_epoch,
            stream_epoch: self.stream_epoch,
            event_id: &self.event_id,
            claim_id: self.claim_id,
        }
    }
}

struct OwnedStreamPosition {
    stream_id: String,
    stream_epoch: u64,
    seq: u64,
}

impl OwnedStreamPosition {
    fn from_borrowed(position: SourceStreamPosition<'_>) -> Self {
        Self {
            stream_id: position.stream_id.to_owned(),
            stream_epoch: position.stream_epoch,
            seq: position.seq,
        }
    }

    fn borrow(&self) -> SourceStreamPosition<'_> {
        SourceStreamPosition {
            stream_id: &self.stream_id,
            stream_epoch: self.stream_epoch,
            seq: self.seq,
        }
    }
}

struct OwnedCommit {
    claim: OwnedClaim,
    received_at_ms: i64,
    decision_clock: Arc<dyn xolotl_source::SourceClock>,
    dedupe_window_ms: u64,
    sink: Path,
    capacity: StreamCapacity,
    max_inline_payload_bytes: usize,
    payload: Value,
    taint: TaintSet,
    stream: Option<OwnedStreamPosition>,
    rate_limit: Option<SourceRateLimit>,
}

impl OwnedCommit {
    fn from_borrowed(request: SourceCommit<'_>) -> Self {
        Self {
            claim: OwnedClaim::from_borrowed(request.claim),
            received_at_ms: request.received_at_ms,
            decision_clock: request.decision_clock,
            dedupe_window_ms: request.dedupe_window_ms,
            sink: request.sink.clone(),
            capacity: request.capacity.clone(),
            max_inline_payload_bytes: request.max_inline_payload_bytes,
            // Value is immutable and shares its resident payload on clone.
            payload: request.payload.clone(),
            taint: request.taint.clone(),
            stream: request.stream.map(OwnedStreamPosition::from_borrowed),
            rate_limit: request.rate_limit.cloned(),
        }
    }

    fn borrow(&self) -> SourceCommit<'_> {
        SourceCommit {
            claim: self.claim.borrow(),
            received_at_ms: self.received_at_ms,
            decision_clock: Arc::clone(&self.decision_clock),
            dedupe_window_ms: self.dedupe_window_ms,
            sink: &self.sink,
            capacity: &self.capacity,
            max_inline_payload_bytes: self.max_inline_payload_bytes,
            payload: &self.payload,
            taint: &self.taint,
            stream: self.stream.as_ref().map(OwnedStreamPosition::borrow),
            rate_limit: self.rate_limit.as_ref(),
        }
    }
}

struct OwnedStreamScope {
    installation_id: String,
    projection_id: String,
    scope_epoch: u64,
    stream_id: String,
}

impl OwnedStreamScope {
    fn from_borrowed(scope: SourceStreamScope<'_>) -> Self {
        Self {
            installation_id: scope.installation_id.to_owned(),
            projection_id: scope.projection_id.to_owned(),
            scope_epoch: scope.scope_epoch,
            stream_id: scope.stream_id.to_owned(),
        }
    }

    fn borrow(&self) -> SourceStreamScope<'_> {
        SourceStreamScope {
            installation_id: &self.installation_id,
            projection_id: &self.projection_id,
            scope_epoch: self.scope_epoch,
            stream_id: &self.stream_id,
        }
    }
}

struct OwnedEvidenceInspection {
    claim: OwnedClaim,
}

impl OwnedEvidenceInspection {
    fn from_borrowed(request: SourceEvidenceInspection<'_>) -> Self {
        Self {
            claim: OwnedClaim::from_borrowed(request.claim),
        }
    }

    fn borrow(&self) -> SourceEvidenceInspection<'_> {
        SourceEvidenceInspection {
            claim: self.claim.borrow(),
        }
    }
}

struct OwnedEventDecisionInspection {
    installation_id: String,
    projection_id: String,
    scope_epoch: u64,
    stream_epoch: Option<u64>,
    event_id: String,
}

impl OwnedEventDecisionInspection {
    fn from_borrowed(request: SourceEventDecisionInspection<'_>) -> Self {
        Self {
            installation_id: request.installation_id.to_owned(),
            projection_id: request.projection_id.to_owned(),
            scope_epoch: request.scope_epoch,
            stream_epoch: request.stream_epoch,
            event_id: request.event_id.to_owned(),
        }
    }

    fn borrow(&self) -> SourceEventDecisionInspection<'_> {
        SourceEventDecisionInspection {
            installation_id: &self.installation_id,
            projection_id: &self.projection_id,
            scope_epoch: self.scope_epoch,
            stream_epoch: self.stream_epoch,
            event_id: &self.event_id,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptedEvent {
    claim_id: SourceClaimId,
    decision_at_ms: i64,
    expires_at_ms: i64,
    payload_digest: [u8; 32],
    stream: Option<AcceptedStream>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptedStream {
    stream_id: String,
    seq: u64,
}

struct RateRecord {
    window_ms: u64,
    hits: Vec<i64>,
}

enum MaintenanceCandidate {
    Event {
        key: Vec<u8>,
        claim_id: SourceClaimId,
        expired: bool,
    },
    Rate {
        key: Vec<u8>,
        expired: bool,
    },
    Stream {
        key: Vec<u8>,
        obsolete: bool,
    },
}

impl MaintenanceCandidate {
    fn key(&self) -> &[u8] {
        match self {
            Self::Event { key, .. } | Self::Rate { key, .. } | Self::Stream { key, .. } => key,
        }
    }
}

fn rate_record_parts(bytes: &[u8]) -> Result<(u64, &[[u8; 8]]), SourceStoreError> {
    if bytes.len() > MAX_RATE_ROW_BYTES {
        return Err(aborted("Source rate row exceeds byte maximum"));
    }
    let Some(window) = bytes.get(..8) else {
        return Err(aborted("Source rate row is corrupt"));
    };
    let window_ms = u64::from_be_bytes(
        window
            .try_into()
            .map_err(|_error| aborted("Source rate row is corrupt"))?,
    );
    let (times, remainder) = bytes[8..].as_chunks::<8>();
    if window_ms == 0 || times.is_empty() || !remainder.is_empty() || times.len() > MAX_RATE_HITS {
        return Err(aborted("Source rate row is corrupt"));
    }
    Ok((window_ms, times))
}

fn decode_rate_record(bytes: &[u8]) -> Result<RateRecord, SourceStoreError> {
    let (window_ms, times) = rate_record_parts(bytes)?;
    let mut hits = Vec::with_capacity(times.len());
    for time in times {
        let hit = i64::from_be_bytes(*time);
        if hits.last().is_some_and(|previous| *previous > hit) {
            return Err(aborted("Source rate row is corrupt"));
        }
        hits.push(hit);
    }
    Ok(RateRecord { window_ms, hits })
}

fn encode_rate_record(record: &RateRecord) -> Result<Vec<u8>, SourceStoreError> {
    if record.window_ms == 0 || record.hits.is_empty() || record.hits.len() > MAX_RATE_HITS {
        return Err(aborted("Source rate row is invalid"));
    }
    let mut bytes = Vec::with_capacity(8 + record.hits.len() * 8);
    bytes.extend_from_slice(&record.window_ms.to_be_bytes());
    for hit in &record.hits {
        bytes.extend_from_slice(&hit.to_be_bytes());
    }
    Ok(bytes)
}

fn rate_record_expired(bytes: &[u8], now_millis: i64) -> Result<bool, SourceStoreError> {
    let (window_ms, times) = rate_record_parts(bytes)?;
    let mut previous = None;
    for time in times {
        let hit = i64::from_be_bytes(*time);
        if previous.is_some_and(|previous| previous > hit) {
            return Err(aborted("Source rate row is corrupt"));
        }
        previous = Some(hit);
    }
    Ok(previous
        .is_some_and(|last| i128::from(now_millis) >= i128::from(last) + i128::from(window_ms)))
}

fn decode_event(bytes: &[u8]) -> Result<AcceptedEvent, SourceStoreError> {
    let record: AcceptedEvent = decode_private(bytes, "Source event decision is corrupt")?;
    if record.expires_at_ms < record.decision_at_ms
        || record.stream.as_ref().is_some_and(|stream| {
            stream.stream_id.is_empty()
                || stream.stream_id.len() > MAX_ID_BYTES
                || stream.seq == 0
                || stream.seq > i64::MAX as u64
        })
    {
        return Err(aborted("Source event decision is corrupt"));
    }
    Ok(record)
}

fn aborted(message: impl Into<String>) -> SourceStoreError {
    SourceStoreError::Aborted(message.into())
}

fn db_error(error: impl std::fmt::Display) -> SourceStoreError {
    aborted(format!("Source database operation failed: {error}"))
}

fn commit_error(operation: &str, error: redb::CommitError) -> SourceStoreError {
    // redb returns TransactionPoisoned only after its rollback succeeds. An
    // I/O failure while committing or rolling back remains indeterminate.
    match error {
        redb::CommitError::TransactionPoisoned => {
            aborted(format!("Source {operation} transaction rolled back"))
        }
        error => {
            SourceStoreError::Indeterminate(format!("Source {operation} commit failed: {error}"))
        }
    }
}

fn segment(key: &mut Vec<u8>, segment: &str) -> Result<(), SourceStoreError> {
    if segment.is_empty() || segment.len() > MAX_ID_BYTES {
        return Err(aborted("Source identity is invalid"));
    }
    let len = u32::try_from(segment.len()).map_err(|_error| aborted("Source identity too long"))?;
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(segment.as_bytes());
    Ok(())
}

fn scope_key(
    kind: u8,
    installation_id: &str,
    projection_id: &str,
) -> Result<Vec<u8>, SourceStoreError> {
    if installation_id.is_empty()
        || projection_id.is_empty()
        || installation_id.len() > MAX_ID_BYTES
        || projection_id.len() > MAX_ID_BYTES
    {
        return Err(aborted("Source scope identity is invalid"));
    }
    let mut key = Vec::with_capacity(1 + 8 + installation_id.len() + projection_id.len());
    key.push(kind);
    segment(&mut key, installation_id)?;
    segment(&mut key, projection_id)?;
    Ok(key)
}

fn stream_key(stream: SourceStreamScope<'_>) -> Result<Vec<u8>, SourceStoreError> {
    xolotl_source::validate_stream_scope(stream)?;
    let mut key = scope_key(b'S', stream.installation_id, stream.projection_id)?;
    key.extend_from_slice(&stream.scope_epoch.to_be_bytes());
    segment(&mut key, stream.stream_id)?;
    Ok(key)
}

fn decode_stream_state(bytes: &[u8]) -> Result<SourceStreamState, SourceStoreError> {
    if bytes.len() > MAX_SEQUENCE_ROW_BYTES || bytes.len() < 27 {
        return Err(aborted("Source stream row is corrupt"));
    }
    let epoch = u64::from_be_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|_error| aborted("Source stream row is corrupt"))?,
    );
    let opened_at_revision = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_error| aborted("Source stream row is corrupt"))?,
    );
    let last_seq = u64::from_be_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_error| aborted("Source stream row is corrupt"))?,
    );
    let open_id_len = u16::from_be_bytes(
        bytes[24..26]
            .try_into()
            .map_err(|_error| aborted("Source stream row is corrupt"))?,
    ) as usize;
    if epoch == 0
        || last_seq > i64::MAX as u64
        || open_id_len == 0
        || open_id_len > MAX_ID_BYTES
        || bytes.len() != 26 + open_id_len
    {
        return Err(aborted("Source stream row is corrupt"));
    }
    let open_id = std::str::from_utf8(&bytes[26..])
        .map_err(|_error| aborted("Source stream row is corrupt"))?
        .to_owned();
    Ok(SourceStreamState {
        stream_epoch: epoch,
        opened_at_revision,
        last_seq,
        open_id,
    })
}

fn encode_stream_state(state: &SourceStreamState) -> Result<Vec<u8>, SourceStoreError> {
    if state.stream_epoch == 0
        || state.last_seq > i64::MAX as u64
        || state.open_id.is_empty()
        || state.open_id.len() > MAX_ID_BYTES
    {
        return Err(aborted("Source stream row is invalid"));
    }
    let len = u16::try_from(state.open_id.len())
        .map_err(|_error| aborted("Source stream open identity too long"))?;
    let mut bytes = Vec::with_capacity(26 + state.open_id.len());
    bytes.extend_from_slice(&state.stream_epoch.to_be_bytes());
    bytes.extend_from_slice(&state.opened_at_revision.to_be_bytes());
    bytes.extend_from_slice(&state.last_seq.to_be_bytes());
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(state.open_id.as_bytes());
    Ok(bytes)
}

fn parse_source_scope(key: &[u8]) -> Result<(&str, &str, u64), SourceStoreError> {
    fn take_segment<'a>(key: &mut &'a [u8]) -> Result<&'a str, SourceStoreError> {
        let length = key
            .get(..4)
            .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
        let length = u32::from_be_bytes(
            length
                .try_into()
                .map_err(|_error| aborted("Source metadata key is corrupt"))?,
        ) as usize;
        if length == 0 || length > MAX_ID_BYTES {
            return Err(aborted("Source metadata key is corrupt"));
        }
        let bytes = key
            .get(4..4 + length)
            .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_error| aborted("Source metadata key is corrupt"))?;
        *key = &key[4 + length..];
        Ok(value)
    }
    let mut rest = key
        .get(1..)
        .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
    let installation = take_segment(&mut rest)?;
    let projection = take_segment(&mut rest)?;
    let epoch = rest
        .get(..8)
        .ok_or_else(|| aborted("Source metadata key is corrupt"))?;
    let epoch = u64::from_be_bytes(
        epoch
            .try_into()
            .map_err(|_error| aborted("Source metadata key is corrupt"))?,
    );
    rest = &rest[8..];
    match key.first() {
        Some(b'E') => {
            let ordered = *rest
                .first()
                .ok_or_else(|| aborted("Source event key is corrupt"))?;
            rest = &rest[1..];
            match ordered {
                0 => {}
                1 => {
                    let stream_epoch = rest
                        .get(..8)
                        .ok_or_else(|| aborted("Source event key is corrupt"))?;
                    if stream_epoch == [0; 8] {
                        return Err(aborted("Source event key is corrupt"));
                    }
                    rest = &rest[8..];
                }
                _ => return Err(aborted("Source event key is corrupt")),
            }
            take_segment(&mut rest)?;
        }
        Some(b'S') => {
            take_segment(&mut rest)?;
        }
        Some(b'R') => {}
        _ => return Err(aborted("Source metadata key is corrupt")),
    }
    if epoch == 0 || !rest.is_empty() {
        return Err(aborted("Source metadata key is corrupt"));
    }
    Ok((installation, projection, epoch))
}

fn event_key(claim: SourceClaim<'_>) -> Result<Vec<u8>, SourceStoreError> {
    let mut key = scope_key(b'E', claim.installation_id, claim.projection_id)?;
    key.extend_from_slice(&claim.scope_epoch.to_be_bytes());
    key.push(u8::from(claim.stream_epoch.is_some()));
    if let Some(epoch) = claim.stream_epoch {
        key.extend_from_slice(&epoch.to_be_bytes());
    }
    segment(&mut key, claim.event_id)?;
    Ok(key)
}

fn claim_key(claim: SourceClaim<'_>) -> Result<Vec<u8>, SourceStoreError> {
    let mut key = scope_key(b'C', claim.installation_id, claim.projection_id)?;
    key.extend_from_slice(&claim.scope_epoch.to_be_bytes());
    key.push(u8::from(claim.stream_epoch.is_some()));
    if let Some(epoch) = claim.stream_epoch {
        key.extend_from_slice(&epoch.to_be_bytes());
    }
    segment(&mut key, claim.event_id)?;
    key.extend_from_slice(claim.claim_id.as_bytes());
    Ok(key)
}

fn receipt_key_for_event(event_key: &[u8], claim_id: SourceClaimId) -> Vec<u8> {
    let mut key = Vec::with_capacity(event_key.len() + 16);
    key.push(b'C');
    key.extend_from_slice(&event_key[1..]);
    key.extend_from_slice(claim_id.as_bytes());
    key
}

fn cutoff(now_millis: i64, window_ms: u64) -> i128 {
    i128::from(now_millis) - i128::from(window_ms)
}

fn get_private(
    txn: &WriteTransaction,
    table: TableDefinition<&[u8], &[u8]>,
    key: &[u8],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, SourceStoreError> {
    let table = txn.open_table(table).map_err(db_error)?;
    let found = table.get(key).map_err(db_error)?;
    found
        .map(|guard| {
            if guard.value().len() > max_bytes {
                return Err(aborted("Source private row exceeds byte maximum"));
            }
            Ok(guard.value().to_vec())
        })
        .transpose()
}

fn get_read_private(
    txn: &redb::ReadTransaction,
    table: TableDefinition<&[u8], &[u8]>,
    key: &[u8],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, SourceStoreError> {
    let table = txn.open_table(table).map_err(db_error)?;
    let found = table.get(key).map_err(db_error)?;
    found
        .map(|guard| {
            if guard.value().len() > max_bytes {
                return Err(aborted("Source private row exceeds byte maximum"));
            }
            Ok(guard.value().to_vec())
        })
        .transpose()
}

fn decode_private<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
    label: &'static str,
) -> Result<T, SourceStoreError> {
    serde_json::from_slice(bytes).map_err(|_error| aborted(label))
}

fn encode_private<T: Serialize>(value: &T, max_bytes: usize) -> Result<Vec<u8>, SourceStoreError> {
    struct BoundedBytes {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for BoundedBytes {
        fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
            if chunk.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other(
                    "Source private row exceeds byte maximum",
                ));
            }
            self.bytes.extend_from_slice(chunk);
            Ok(chunk.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BoundedBytes {
        bytes: Vec::with_capacity(max_bytes.min(128)),
        limit: max_bytes,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        if error.is_io() {
            aborted("Source private row exceeds byte maximum")
        } else {
            aborted("Source private record encoding failed")
        }
    })?;
    Ok(writer.bytes)
}

fn installation_record_in_txn(
    txn: &WriteTransaction,
    id: &str,
) -> Result<Option<ExternalInstallationRecord>, SourceStoreError> {
    let table = txn
        .open_table(EXTERNAL_INSTALLATIONS_TABLE)
        .map_err(db_error)?;
    let found = table.get(id).map_err(db_error)?;
    found
        .map(|guard| {
            if guard.value().len() > MAX_INSTALLATION_RECORD_BYTES {
                return Err(aborted("external installation record exceeds byte maximum"));
            }
            let record: ExternalInstallationRecord =
                decode_private(guard.value(), "external installation record is corrupt")?;
            if record.definition.id != id {
                return Err(aborted("external installation record id mismatch"));
            }
            Ok(record)
        })
        .transpose()
}

fn active_stream_scope_in_write(
    txn: &WriteTransaction,
    stream: SourceStreamScope<'_>,
) -> Result<Option<SourceScopeAdmission>, SourceStoreError> {
    let scope_id = format!("{}/{}", stream.installation_id, stream.projection_id);
    let table = txn
        .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
        .map_err(db_error)?;
    let found = table.get(scope_id.as_str()).map_err(db_error)?;
    let admission = found
        .map(|guard| {
            if guard.value().len() > MAX_SOURCE_SCOPE_ROW_BYTES {
                return Err(aborted("external Source scope row exceeds byte maximum"));
            }
            decode_private::<SourceScopeAdmission>(
                guard.value(),
                "external Source scope row is corrupt",
            )
        })
        .transpose()?;
    Ok(admission.filter(|admission| admission.epoch == stream.scope_epoch))
}

impl SourceOwner {
    fn commit_source(
        &self,
        request: SourceCommit<'_>,
    ) -> Result<SourceCommitOutcome, SourceStoreError> {
        let Some((_payload_bytes, payload_digest)) =
            xolotl_state::host::source_payload_fingerprint_bounded(
                request.payload,
                request.max_inline_payload_bytes,
            )
            .map_err(|_error| aborted("Source payload could not be encoded"))?
        else {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::PayloadTooLarge,
            ));
        };
        let max_events = usize::try_from(request.capacity.max_events)
            .map_err(|_error| aborted("Source capacity exceeds address space"))?;
        if max_events == 0 {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::CapacityExceeded,
            ));
        }
        if max_events > MAX_SINK_EVENTS
            || request.max_inline_payload_bytes == 0
            || max_events
                .checked_mul(request.max_inline_payload_bytes)
                .is_none_or(|bytes| bytes > MAX_DECLARED_SINK_BYTES)
        {
            return Err(aborted("Source declared sink budget exceeds maximum"));
        }
        if request
            .stream
            .is_some_and(|stream| stream.seq > i64::MAX as u64)
        {
            return Err(aborted("Source sequence exceeds supported range"));
        }
        let event_key = event_key(request.claim)?;
        let receipt_key = claim_key(request.claim)?;
        let sequence_key = request
            .stream
            .map(|stream| {
                stream_key(SourceStreamScope {
                    installation_id: request.claim.installation_id,
                    projection_id: request.claim.projection_id,
                    scope_epoch: request.claim.scope_epoch,
                    stream_id: stream.stream_id,
                })
            })
            .transpose()?;
        let rate_key = request
            .rate_limit
            .map(|_rule| {
                let mut key = scope_key(
                    b'R',
                    request.claim.installation_id,
                    request.claim.projection_id,
                )?;
                key.extend_from_slice(&request.claim.scope_epoch.to_be_bytes());
                Ok::<_, SourceStoreError>(key)
            })
            .transpose()?;
        let txn = self.db.begin_write().map_err(db_error)?;
        let decision_at_ms = request.decision_clock.now_millis();
        let scope_id = format!(
            "{}/{}",
            request.claim.installation_id, request.claim.projection_id
        );
        let mut active_scope = txn
            .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
            .map_err(db_error)?
            .get(scope_id.as_str())
            .map_err(db_error)?
            .map(|scope| {
                if scope.value().len() > MAX_SOURCE_SCOPE_ROW_BYTES {
                    return Err(aborted("external Source scope row exceeds byte maximum"));
                }
                decode_private::<SourceScopeAdmission>(
                    scope.value(),
                    "external Source scope row is corrupt",
                )
            })
            .transpose()?;
        if active_scope.as_ref().map(|scope| scope.epoch) != Some(request.claim.scope_epoch) {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::ScopeInactive,
            ));
        }
        if !active_scope
            .as_ref()
            .is_some_and(|scope| scope.matches_commit(&request))
        {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::DeclarationMismatch,
            ));
        }
        if active_scope
            .as_ref()
            .and_then(|scope| scope.decision_time_floor_ms)
            .is_some_and(|floor| decision_at_ms < floor)
        {
            return Err(aborted("Source decision clock regressed"));
        }
        let stream_state = sequence_key
            .as_ref()
            .map(|key| {
                get_private(&txn, SOURCE_META_TABLE, key, MAX_SEQUENCE_ROW_BYTES)?
                    .map(|bytes| decode_stream_state(&bytes))
                    .transpose()
            })
            .transpose()?
            .flatten();
        if let Some(stream) = request.stream {
            match stream_state.as_ref() {
                None => {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::StreamInactive,
                    ));
                }
                Some(active) if active.stream_epoch != stream.stream_epoch => {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::StreamEpochMismatch {
                            active_epoch: active.stream_epoch,
                        },
                    ));
                }
                Some(_) => {}
            }
        }
        let previous_event = get_private(&txn, SOURCE_META_TABLE, &event_key, MAX_EVENT_ROW_BYTES)?
            .map(|bytes| decode_event(&bytes))
            .transpose()?;
        if let Some(record) = previous_event.as_ref()
            && decision_at_ms <= record.expires_at_ms
        {
            let accepted_stream = record
                .stream
                .as_ref()
                .map(|stream| (stream.stream_id.as_str(), stream.seq));
            let attempted_stream = request.stream.map(|stream| (stream.stream_id, stream.seq));
            return Ok(
                if record.payload_digest == payload_digest && accepted_stream == attempted_stream {
                    SourceCommitOutcome::Duplicate
                } else {
                    SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict)
                },
            );
        }
        if get_private(&txn, SOURCE_RECEIPTS_TABLE, &receipt_key, MAX_RECEIPT_BYTES)?.is_some() {
            return Err(aborted("Source claim identity already exists"));
        }
        if let (Some(stream), Some(state)) = (request.stream, stream_state.as_ref()) {
            let expected = state
                .last_seq
                .checked_add(1)
                .ok_or_else(|| aborted("Source sequence exhausted"))?;
            if stream.seq < expected {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::SequenceReplay {
                        last: state.last_seq,
                        seq: stream.seq,
                    },
                ));
            }
            if stream.seq > expected {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::SequenceGap {
                        expected,
                        seq: stream.seq,
                    },
                ));
            }
        }
        let (next_rate, rate_added) =
            if let (Some(rule), Some(key)) = (request.rate_limit, rate_key.as_ref()) {
                if rule.window_ms == 0 || rule.max_events == 0 {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::RateLimited,
                    ));
                }
                let max_hits = usize::try_from(rule.max_events)
                    .map_err(|_error| aborted("Source rate count exceeds address space"))?;
                if max_hits > MAX_RATE_HITS {
                    return Err(aborted("Source rate record exceeds maximum"));
                }
                let (mut record, rate_added) = {
                    let table = txn.open_table(SOURCE_META_TABLE).map_err(db_error)?;
                    let found = table.get(key.as_slice()).map_err(db_error)?;
                    match found {
                        Some(guard) => (decode_rate_record(guard.value())?, false),
                        None => (
                            RateRecord {
                                window_ms: rule.window_ms,
                                hits: Vec::new(),
                            },
                            true,
                        ),
                    }
                };
                if record.window_ms != rule.window_ms {
                    record.window_ms = rule.window_ms;
                    record.hits.clear();
                }
                let cutoff = cutoff(decision_at_ms, rule.window_ms);
                record.hits.retain(|time| i128::from(*time) > cutoff);
                if record.hits.len() >= max_hits {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::RateLimited,
                    ));
                }
                let position = record.hits.partition_point(|time| *time <= decision_at_ms);
                record.hits.insert(position, decision_at_ms);
                (Some(record), rate_added)
            } else {
                (None, false)
            };
        let sink_key = request.sink.to_string();
        enum CurrentSink {
            Missing(TaintSet),
            NonList,
            Segmented(list::ListMarker),
        }
        let current = {
            let table = txn.open_table(STATE_VALUES_TABLE).map_err(db_error)?;
            let found = table.get(sink_key.as_str()).map_err(db_error)?;
            match found {
                None => CurrentSink::Missing(TaintSet::pristine()),
                Some(guard) => {
                    let size = list::record_size(guard.value(), sink_key.len())
                        .map_err(|_error| aborted("Source sink row is corrupt"))?;
                    let segmented = list::is_segmented(guard.value())
                        .map_err(|_error| aborted("Source sink marker is corrupt"))?;
                    if guard.value().len() > MAX_DECLARED_SINK_BYTES
                        || (!segmented && size > MAX_DECLARED_SINK_BYTES)
                    {
                        return Err(aborted("Source sink row exceeds byte maximum"));
                    }
                    if let Some(taint) = codec::decode_absence(guard.value())
                        .map_err(|_error| aborted("Source sink absence row is corrupt"))?
                    {
                        CurrentSink::Missing(taint)
                    } else {
                        match list::marker(guard.value())
                            .map_err(|_error| aborted("Source sink marker is corrupt"))?
                        {
                            Some(marker) => CurrentSink::Segmented(marker),
                            None => {
                                let stored = decode_envelope(guard.value())
                                    .map_err(|_error| aborted("Source sink row is corrupt"))?;
                                if stored.value.as_list().is_some() {
                                    return Err(aborted("State List is not segmented"));
                                }
                                CurrentSink::NonList
                            }
                        }
                    }
                }
            }
        };
        let count = match &current {
            CurrentSink::Missing(_) => 0,
            CurrentSink::Segmented(marker) => usize::try_from(marker.count)
                .map_err(|_error| aborted("Source sink length exceeds supported range"))?,
            CurrentSink::NonList => {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::SinkTypeMismatch,
                ));
            }
        };
        let replace = match &request.capacity.on_overflow {
            OverflowPolicy::DropOldest => count >= max_events,
            OverflowPolicy::Backpressure {
                pause_threshold, ..
            } => {
                let pause = usize::try_from(*pause_threshold)
                    .map_err(|_error| aborted("Source pause threshold exceeds address space"))?;
                if count >= pause || count >= max_events {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::Backpressured,
                    ));
                }
                false
            }
            OverflowPolicy::DisconnectBridge => {
                if count >= max_events {
                    return Ok(SourceCommitOutcome::Rejected(
                        SourceCommitRejection::CapacityExceeded,
                    ));
                }
                false
            }
        };
        let (retained, added) = {
            let metadata = txn.open_table(SOURCE_META_TABLE).map_err(db_error)?;
            let streams = txn
                .open_table(SOURCE_SEQUENCE_META_TABLE)
                .map_err(db_error)?
                .get(SOURCE_STREAM_COUNT)
                .map_err(db_error)?
                .ok_or_else(|| aborted("Source stream count metadata missing"))?
                .value();
            let cursor = u64::from(
                metadata
                    .get(MAINTENANCE_CURSOR_KEY)
                    .map_err(db_error)?
                    .is_some(),
            );
            let retained = metadata
                .len()
                .map_err(db_error)?
                .checked_sub(streams)
                .and_then(|count| count.checked_sub(cursor))
                .ok_or_else(|| aborted("Source retention count metadata is corrupt"))?;
            (
                retained,
                u64::from(previous_event.is_none()) + u64::from(rate_added),
            )
        };
        if added != 0
            && retained
                .checked_add(added)
                .is_none_or(|next| next > self.source_retention_limit.get() as u64)
        {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::RetentionCapacityExceeded,
            ));
        }
        let removed = if replace { count - (max_events - 1) } else { 0 };
        let mut sink_taint = match &current {
            CurrentSink::Missing(taint) => taint.clone(),
            CurrentSink::NonList => {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::SinkTypeMismatch,
                ));
            }
            CurrentSink::Segmented(marker) => marker.taint.clone(),
        };
        sink_taint.union(request.taint);
        let event = if replace {
            StateEvent::DropPrefixAppend {
                path: request.sink.clone(),
                removed: u64::try_from(removed)
                    .map_err(|_error| aborted("Source sink length exceeds supported range"))?,
                item: request.payload.clone(),
                taint: sink_taint.clone(),
            }
        } else {
            StateEvent::Append {
                path: request.sink.clone(),
                item: request.payload.clone(),
                taint: sink_taint.clone(),
            }
        };
        let item_bytes = list::encode_item(request.payload)
            .map_err(|_error| aborted("Source sink item encoding failed"))?;
        let mut marker = match &current {
            CurrentSink::Segmented(existing) => {
                let mut marker = existing.clone();
                let end = marker
                    .end()
                    .map_err(|_error| aborted("Source sink sequence is corrupt"))?;
                let mut items = list::item_table(&txn)
                    .map_err(|_error| aborted("Source sink item table unavailable"))?;
                let removed = u64::try_from(removed)
                    .map_err(|_error| aborted("Source sink length exceeds supported range"))?;
                let retained_first = marker
                    .first
                    .checked_add(removed)
                    .filter(|first| *first <= end)
                    .ok_or_else(|| aborted("Source sink prefix exceeds sequence"))?;
                for index in marker.first..retained_first {
                    let key = list::item_key(marker.id, index);
                    let old = items
                        .remove(key.as_slice())
                        .map_err(db_error)?
                        .ok_or_else(|| aborted("Source sink item is missing"))?;
                    marker.item_bytes = marker
                        .item_bytes
                        .checked_sub(old.value().len() as u64)
                        .ok_or_else(|| aborted("Source sink item byte count is corrupt"))?;
                }
                marker.first = retained_first;
                marker.count = end - marker.first;
                drop(items);
                list::append_item(&txn, &mut marker, &item_bytes)
                    .map_err(|_error| aborted("Source sink append failed"))?;
                marker
            }
            CurrentSink::Missing(_) => {
                let mut marker = list::ListMarker {
                    id: 0,
                    first: 0,
                    count: 0,
                    item_bytes: 0,
                    taint: TaintSet::pristine(),
                };
                list::append_item(&txn, &mut marker, &item_bytes)
                    .map_err(|_error| aborted("Source sink append failed"))?;
                marker
            }
            CurrentSink::NonList => {
                return Ok(SourceCommitOutcome::Rejected(
                    SourceCommitRejection::SinkTypeMismatch,
                ));
            }
        };
        marker.taint = sink_taint;
        let sink_bytes = marker
            .encode()
            .map_err(|_error| aborted("Source sink marker encoding failed"))?;
        if list::record_size(&sink_bytes, sink_key.len())
            .map_err(|_error| aborted("Source sink byte count overflow"))?
            > MAX_DECLARED_SINK_BYTES
        {
            return Ok(SourceCommitOutcome::Rejected(
                SourceCommitRejection::CapacityExceeded,
            ));
        }
        let receipt = SourceReceipt {
            installation_id: request.claim.installation_id.to_owned(),
            projection_id: request.claim.projection_id.to_owned(),
            scope_epoch: request.claim.scope_epoch,
            stream_epoch: request.claim.stream_epoch,
            event_id: request.claim.event_id.to_owned(),
            claim_id: request.claim.claim_id,
            sink: request.sink.clone(),
            received_at_ms: request.received_at_ms,
        };
        let receipt_bytes = encode_private(&receipt, MAX_RECEIPT_BYTES)?;
        let event_bytes = encode_private(
            &AcceptedEvent {
                claim_id: request.claim.claim_id,
                decision_at_ms,
                expires_at_ms: xolotl_source::event_expires_at(
                    decision_at_ms,
                    request.dedupe_window_ms,
                ),
                payload_digest,
                stream: request.stream.map(|stream| AcceptedStream {
                    stream_id: stream.stream_id.to_owned(),
                    seq: stream.seq,
                }),
            },
            MAX_EVENT_ROW_BYTES,
        )?;
        let rate_bytes = next_rate.as_ref().map(encode_rate_record).transpose()?;
        let scope = active_scope
            .as_mut()
            .ok_or_else(|| aborted("Source scope missing"))?;
        scope.decision_time_floor_ms = Some(decision_at_ms);
        let scope_bytes = encode_private(scope, MAX_SOURCE_SCOPE_ROW_BYTES)?;
        txn.open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
            .map_err(db_error)?
            .insert(scope_id.as_str(), scope_bytes.as_slice())
            .map_err(db_error)?;
        {
            let mut table = txn.open_table(STATE_VALUES_TABLE).map_err(db_error)?;
            super::absence::replacing(
                &txn,
                &table,
                &sink_key,
                Some(&sink_bytes),
                self.absence_limits,
            )
            .map_err(|error| aborted(error.to_string()))?;
            table
                .insert(sink_key.as_str(), sink_bytes.as_slice())
                .map_err(db_error)?;
        }
        {
            let mut table = txn.open_table(SOURCE_META_TABLE).map_err(db_error)?;
            table
                .insert(event_key.as_slice(), event_bytes.as_slice())
                .map_err(db_error)?;
            if let (Some(key), Some(stream), Some(mut state)) =
                (sequence_key.as_ref(), request.stream, stream_state)
            {
                state.last_seq = stream.seq;
                let bytes = encode_stream_state(&state)?;
                table
                    .insert(key.as_slice(), bytes.as_slice())
                    .map_err(db_error)?;
            }
            if let (Some(key), Some(bytes)) = (rate_key.as_ref(), rate_bytes.as_ref()) {
                table
                    .insert(key.as_slice(), bytes.as_slice())
                    .map_err(db_error)?;
            }
        }
        {
            let mut table = txn.open_table(SOURCE_RECEIPTS_TABLE).map_err(db_error)?;
            if let Some(previous_event) = previous_event {
                let old = receipt_key_for_event(&event_key, previous_event.claim_id);
                table.remove(old.as_slice()).map_err(db_error)?;
            }
            table
                .insert(receipt_key.as_slice(), receipt_bytes.as_slice())
                .map_err(db_error)?;
        }
        if self.history == RedbHistory::Full && xolotl_state::history_retains_path(request.sink) {
            RedbStateBackend::record_history_in_txn(&txn, &event)
                .map_err(|_error| aborted("Source sink history write failed"))?;
        }
        self.publication
            .commit(txn, event)
            .map_err(|failure| match failure {
                PublishFailure::Backpressure => aborted("Source publication capacity exceeded"),
                PublishFailure::Commit(error) => commit_error("database", error),
            })?;
        Ok(SourceCommitOutcome::Accepted)
    }
}

impl SourceOwner {
    fn inspect_source(
        &self,
        request: SourceEvidenceInspection<'_>,
    ) -> Result<SourceClaimEvidence, SourceStoreError> {
        let key = claim_key(request.claim)?;
        let txn = self.db.begin_read().map_err(db_error)?;
        let receipt = get_read_private(&txn, SOURCE_RECEIPTS_TABLE, &key, MAX_RECEIPT_BYTES)?
            .map(|bytes| decode_private::<SourceReceipt>(&bytes, "Source receipt is corrupt"))
            .transpose()?;
        if receipt.as_ref().is_some_and(|receipt| {
            receipt.installation_id != request.claim.installation_id
                || receipt.projection_id != request.claim.projection_id
                || receipt.scope_epoch != request.claim.scope_epoch
                || receipt.stream_epoch != request.claim.stream_epoch
                || receipt.event_id != request.claim.event_id
                || receipt.claim_id != request.claim.claim_id
        }) {
            return Err(aborted("Source receipt identity does not match its key"));
        }
        Ok(receipt.map_or(
            SourceClaimEvidence::Unproven,
            SourceClaimEvidence::Committed,
        ))
    }

    fn inspect_source_event(
        &self,
        request: SourceEventDecisionInspection<'_>,
    ) -> Result<SourceClaimEvidence, SourceStoreError> {
        if request.scope_epoch == 0 {
            return Err(aborted("Source scope epoch is invalid"));
        }
        let mut event_key = scope_key(b'E', request.installation_id, request.projection_id)?;
        event_key.extend_from_slice(&request.scope_epoch.to_be_bytes());
        if request.stream_epoch == Some(0) {
            return Err(aborted("Source stream epoch is invalid"));
        }
        event_key.push(u8::from(request.stream_epoch.is_some()));
        if let Some(epoch) = request.stream_epoch {
            event_key.extend_from_slice(&epoch.to_be_bytes());
        }
        segment(&mut event_key, request.event_id)?;
        let txn = self.db.begin_read().map_err(db_error)?;
        let decision = get_read_private(&txn, SOURCE_META_TABLE, &event_key, MAX_EVENT_ROW_BYTES)?
            .map(|bytes| decode_event(&bytes))
            .transpose()?;
        let receipt = if let Some(decision) = &decision {
            let key = receipt_key_for_event(&event_key, decision.claim_id);
            let bytes = get_read_private(&txn, SOURCE_RECEIPTS_TABLE, &key, MAX_RECEIPT_BYTES)?
                .ok_or_else(|| aborted("retained Source event has no claim receipt"))?;
            let receipt = decode_private::<SourceReceipt>(&bytes, "Source receipt is corrupt")?;
            if receipt.installation_id != request.installation_id
                || receipt.projection_id != request.projection_id
                || receipt.scope_epoch != request.scope_epoch
                || receipt.stream_epoch != request.stream_epoch
                || receipt.event_id != request.event_id
                || receipt.claim_id != decision.claim_id
            {
                return Err(aborted(
                    "Source receipt identity does not match event decision",
                ));
            }
            Some(receipt)
        } else {
            None
        };
        Ok(receipt.map_or(
            SourceClaimEvidence::Unproven,
            SourceClaimEvidence::Committed,
        ))
    }

    fn maintain_source(
        &self,
        request: SourceMaintenance,
    ) -> Result<SourceMaintenanceResult, SourceStoreError> {
        if request.limit.get() > MAX_MAINTENANCE_BATCH {
            return Err(aborted("Source maintenance batch exceeds maximum"));
        }
        let txn = self.db.begin_write().map_err(db_error)?;
        let decision_at_ms = request.decision_clock.now_millis();
        let cursor = get_private(
            &txn,
            SOURCE_META_TABLE,
            MAINTENANCE_CURSOR_KEY,
            MAX_CURSOR_BYTES,
        )?;
        if cursor.as_ref().is_some_and(|cursor| {
            !cursor.starts_with(b"E") && !cursor.starts_with(b"R") && !cursor.starts_with(b"S")
        }) {
            return Err(aborted("Source maintenance cursor is corrupt"));
        }
        let mut candidates = Vec::with_capacity(request.limit.get());
        let mut has_more = false;
        {
            let table = txn.open_table(SOURCE_META_TABLE).map_err(db_error)?;
            let scopes = txn
                .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
                .map_err(db_error)?;
            let start = cursor.as_deref().unwrap_or(b"E");
            let rows = table.range::<&[u8]>(start..).map_err(db_error)?;
            for row in rows {
                let (key, value) = row.map_err(db_error)?;
                if cursor
                    .as_ref()
                    .is_some_and(|cursor| key.value() <= cursor.as_slice())
                {
                    continue;
                }
                match key.value().first() {
                    Some(b'E') => {
                        if candidates.len() == request.limit.get() {
                            has_more = true;
                            break;
                        }
                        if value.value().len() > MAX_EVENT_ROW_BYTES {
                            return Err(aborted("Source event decision exceeds byte maximum"));
                        }
                        let record = decode_event(value.value())?;
                        candidates.push(MaintenanceCandidate::Event {
                            key: key.value().to_vec(),
                            claim_id: record.claim_id,
                            expired: record.expires_at_ms < decision_at_ms,
                        });
                    }
                    Some(b'G') if key.value() == MAINTENANCE_CURSOR_KEY => {}
                    Some(b'R') => {
                        if candidates.len() == request.limit.get() {
                            has_more = true;
                            break;
                        }
                        candidates.push(MaintenanceCandidate::Rate {
                            key: key.value().to_vec(),
                            expired: rate_record_expired(value.value(), decision_at_ms)?,
                        });
                    }
                    Some(b'S') => {
                        if candidates.len() == request.limit.get() {
                            has_more = true;
                            break;
                        }
                        let (installation, projection, epoch) = parse_source_scope(key.value())?;
                        let scope_id = format!("{installation}/{projection}");
                        let active = scopes
                            .get(scope_id.as_str())
                            .map_err(db_error)?
                            .map(|scope| {
                                if scope.value().len() > MAX_SOURCE_SCOPE_ROW_BYTES {
                                    return Err(aborted(
                                        "external Source scope row exceeds byte maximum",
                                    ));
                                }
                                decode_private::<SourceScopeAdmission>(
                                    scope.value(),
                                    "external Source scope row is corrupt",
                                )
                            })
                            .transpose()?;
                        candidates.push(MaintenanceCandidate::Stream {
                            key: key.value().to_vec(),
                            obsolete: active.as_ref().map(|scope| scope.epoch) != Some(epoch),
                        });
                    }
                    _ => return Err(aborted("Source maintenance key is invalid")),
                }
            }
        }
        {
            let mut scopes = txn
                .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
                .map_err(db_error)?;
            for candidate in &candidates {
                let (installation, projection, epoch) = parse_source_scope(candidate.key())?;
                let scope_id = format!("{installation}/{projection}");
                let scope = scopes
                    .get(scope_id.as_str())
                    .map_err(db_error)?
                    .map(|row| {
                        if row.value().len() > MAX_SOURCE_SCOPE_ROW_BYTES {
                            return Err(aborted("external Source scope row exceeds byte maximum"));
                        }
                        decode_private::<SourceScopeAdmission>(
                            row.value(),
                            "external Source scope row is corrupt",
                        )
                    })
                    .transpose()?;
                if let Some(mut scope) = scope.filter(|scope| scope.epoch == epoch) {
                    if scope
                        .decision_time_floor_ms
                        .is_some_and(|floor| decision_at_ms < floor)
                    {
                        return Err(aborted("Source decision clock regressed"));
                    }
                    scope.decision_time_floor_ms = Some(decision_at_ms);
                    let bytes = encode_private(&scope, MAX_SOURCE_SCOPE_ROW_BYTES)?;
                    scopes
                        .insert(scope_id.as_str(), bytes.as_slice())
                        .map_err(db_error)?;
                }
            }
        }
        let mut result = SourceMaintenanceResult {
            examined: candidates.len(),
            removed: 0,
            reached_end: !has_more,
        };
        {
            let mut table = txn.open_table(SOURCE_META_TABLE).map_err(db_error)?;
            for candidate in &candidates {
                let expired = match candidate {
                    MaintenanceCandidate::Event { expired, .. }
                    | MaintenanceCandidate::Rate { expired, .. } => *expired,
                    MaintenanceCandidate::Stream { obsolete, .. } => *obsolete,
                };
                if expired {
                    table.remove(candidate.key()).map_err(db_error)?;
                    result.removed += 1;
                }
            }
            if has_more {
                if let Some(last) = candidates.last() {
                    table
                        .insert(MAINTENANCE_CURSOR_KEY, last.key())
                        .map_err(db_error)?;
                }
            } else {
                table.remove(MAINTENANCE_CURSOR_KEY).map_err(db_error)?;
            }
        }
        {
            let mut table = txn.open_table(SOURCE_RECEIPTS_TABLE).map_err(db_error)?;
            for candidate in &candidates {
                if let MaintenanceCandidate::Event {
                    key,
                    claim_id,
                    expired: true,
                } = candidate
                {
                    let receipt = receipt_key_for_event(key, *claim_id);
                    table.remove(receipt.as_slice()).map_err(db_error)?;
                }
            }
        }
        let removed_streams = candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate,
                    MaintenanceCandidate::Stream { obsolete: true, .. }
                )
            })
            .count();
        if removed_streams != 0 {
            let mut table = txn
                .open_table(SOURCE_SEQUENCE_META_TABLE)
                .map_err(db_error)?;
            let retained = table
                .get(SOURCE_STREAM_COUNT)
                .map_err(db_error)?
                .ok_or_else(|| aborted("Source stream count metadata missing"))?
                .value();
            let removed = u64::try_from(removed_streams)
                .map_err(|_error| aborted("Source stream count overflow"))?;
            let next = retained
                .checked_sub(removed)
                .ok_or_else(|| aborted("Source stream count metadata is corrupt"))?;
            table.insert(SOURCE_STREAM_COUNT, next).map_err(db_error)?;
        }
        txn.commit()
            .map_err(|error| commit_error("maintenance", error))?;
        Ok(result)
    }
}

impl SourceEventCommit for RedbStateBackend {
    fn commit<'a>(&'a self, request: SourceCommit<'a>) -> SourceFuture<'a, SourceCommitOutcome> {
        Box::pin(async move {
            xolotl_source::validate_commit(&request)?;
            let request = OwnedCommit::from_borrowed(request);
            source_job(self, "event commit", move |owner| {
                owner.commit_source(request.borrow())
            })
            .await
        })
    }
}

impl SourceOwner {
    fn inspect_stream(
        &self,
        stream: SourceStreamScope<'_>,
    ) -> Result<Option<SourceStreamSnapshot>, SourceStoreError> {
        let key = stream_key(stream)?;
        let scope_id = format!("{}/{}", stream.installation_id, stream.projection_id);
        let txn = self.db.begin_read().map_err(db_error)?;
        let scope = {
            let table = txn
                .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
                .map_err(db_error)?;
            let found = table.get(scope_id.as_str()).map_err(db_error)?;
            found
                .map(|guard| {
                    if guard.value().len() > MAX_SOURCE_SCOPE_ROW_BYTES {
                        return Err(aborted("external Source scope row exceeds byte maximum"));
                    }
                    decode_private::<SourceScopeAdmission>(
                        guard.value(),
                        "external Source scope row is corrupt",
                    )
                })
                .transpose()?
        };
        let Some(scope) = scope.filter(|scope| scope.epoch == stream.scope_epoch) else {
            return Ok(None);
        };
        let active = {
            let table = txn.open_table(SOURCE_META_TABLE).map_err(db_error)?;
            let found = table.get(key.as_slice()).map_err(db_error)?;
            found
                .map(|guard| decode_stream_state(guard.value()))
                .transpose()?
        };
        Ok(Some(SourceStreamSnapshot {
            revision: scope.stream_revision,
            active,
        }))
    }

    fn open_stream(
        &self,
        request: SourceStreamOpen<'_>,
    ) -> Result<SourceStreamOpenOutcome, SourceStoreError> {
        let key = stream_key(request.stream)?;
        if request.open_id.is_empty() || request.open_id.len() > MAX_ID_BYTES {
            return Err(aborted("Source stream open identity is invalid"));
        }
        let txn = self.db.begin_write().map_err(db_error)?;
        let Some(mut scope) = active_stream_scope_in_write(&txn, request.stream)? else {
            return Ok(SourceStreamOpenOutcome::ScopeInactive);
        };
        let active = get_private(&txn, SOURCE_META_TABLE, &key, MAX_SEQUENCE_ROW_BYTES)?
            .map(|bytes| decode_stream_state(&bytes))
            .transpose()?;
        if let Some(active) = active {
            let snapshot = SourceStreamSnapshot {
                revision: scope.stream_revision,
                active: Some(active.clone()),
            };
            return Ok(
                if active.open_id == request.open_id
                    && active.opened_at_revision == request.expected_revision
                {
                    SourceStreamOpenOutcome::Opened(snapshot)
                } else {
                    SourceStreamOpenOutcome::AlreadyOpen(snapshot)
                },
            );
        }
        if scope.stream_revision != request.expected_revision {
            return Ok(SourceStreamOpenOutcome::RevisionConflict {
                current_revision: scope.stream_revision,
            });
        }
        let retained = txn
            .open_table(SOURCE_SEQUENCE_META_TABLE)
            .map_err(db_error)?
            .get(SOURCE_STREAM_COUNT)
            .map_err(db_error)?
            .ok_or_else(|| aborted("Source stream count metadata missing"))?
            .value();
        let limit = u64::try_from(self.source_stream_limit.get())
            .map_err(|_error| aborted("Source stream quota exceeds address space"))?;
        if retained >= limit {
            return Ok(SourceStreamOpenOutcome::QuotaExceeded);
        }
        let stream_epoch = {
            let mut meta = txn
                .open_table(EXTERNAL_INSTALLATIONS_META_TABLE)
                .map_err(db_error)?;
            let current = meta
                .get(NEXT_EXTERNAL_AUTHORITY_EPOCH)
                .map_err(db_error)?
                .ok_or_else(|| aborted("external authority epoch metadata missing"))?
                .value();
            let next = current
                .checked_add(1)
                .ok_or_else(|| aborted("Source stream epoch exhausted"))?;
            meta.insert(NEXT_EXTERNAL_AUTHORITY_EPOCH, next)
                .map_err(db_error)?;
            next
        };
        scope.stream_revision = scope
            .stream_revision
            .checked_add(1)
            .ok_or_else(|| aborted("Source stream revision exhausted"))?;
        let active = SourceStreamState {
            stream_epoch,
            opened_at_revision: request.expected_revision,
            last_seq: 0,
            open_id: request.open_id.to_owned(),
        };
        let state_bytes = encode_stream_state(&active)?;
        let scope_bytes = encode_private(&scope, MAX_SOURCE_SCOPE_ROW_BYTES)?;
        let scope_id = format!(
            "{}/{}",
            request.stream.installation_id, request.stream.projection_id
        );
        txn.open_table(SOURCE_META_TABLE)
            .map_err(db_error)?
            .insert(key.as_slice(), state_bytes.as_slice())
            .map_err(db_error)?;
        txn.open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
            .map_err(db_error)?
            .insert(scope_id.as_str(), scope_bytes.as_slice())
            .map_err(db_error)?;
        txn.open_table(SOURCE_SEQUENCE_META_TABLE)
            .map_err(db_error)?
            .insert(SOURCE_STREAM_COUNT, retained + 1)
            .map_err(db_error)?;
        txn.commit()
            .map_err(|error| commit_error("stream open", error))?;
        Ok(SourceStreamOpenOutcome::Opened(SourceStreamSnapshot {
            revision: scope.stream_revision,
            active: Some(active),
        }))
    }

    fn retire_stream(
        &self,
        request: SourceStreamRetire<'_>,
    ) -> Result<SourceStreamRetireOutcome, SourceStoreError> {
        let key = stream_key(request.stream)?;
        if request.stream_epoch == 0 {
            return Err(aborted("Source stream epoch is invalid"));
        }
        let txn = self.db.begin_write().map_err(db_error)?;
        let Some(mut scope) = active_stream_scope_in_write(&txn, request.stream)? else {
            return Ok(SourceStreamRetireOutcome::ScopeInactive);
        };
        let active = get_private(&txn, SOURCE_META_TABLE, &key, MAX_SEQUENCE_ROW_BYTES)?
            .map(|bytes| decode_stream_state(&bytes))
            .transpose()?;
        let Some(active) = active else {
            return Ok(SourceStreamRetireOutcome::Inactive {
                revision: scope.stream_revision,
            });
        };
        if active.stream_epoch != request.stream_epoch {
            return Ok(SourceStreamRetireOutcome::Stale {
                active_epoch: active.stream_epoch,
            });
        }
        scope.stream_revision = scope
            .stream_revision
            .checked_add(1)
            .ok_or_else(|| aborted("Source stream revision exhausted"))?;
        let retained = txn
            .open_table(SOURCE_SEQUENCE_META_TABLE)
            .map_err(db_error)?
            .get(SOURCE_STREAM_COUNT)
            .map_err(db_error)?
            .ok_or_else(|| aborted("Source stream count metadata missing"))?
            .value();
        let next_count = retained
            .checked_sub(1)
            .ok_or_else(|| aborted("Source stream count metadata is corrupt"))?;
        let scope_bytes = encode_private(&scope, MAX_SOURCE_SCOPE_ROW_BYTES)?;
        let scope_id = format!(
            "{}/{}",
            request.stream.installation_id, request.stream.projection_id
        );
        txn.open_table(SOURCE_META_TABLE)
            .map_err(db_error)?
            .remove(key.as_slice())
            .map_err(db_error)?;
        txn.open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
            .map_err(db_error)?
            .insert(scope_id.as_str(), scope_bytes.as_slice())
            .map_err(db_error)?;
        txn.open_table(SOURCE_SEQUENCE_META_TABLE)
            .map_err(db_error)?
            .insert(SOURCE_STREAM_COUNT, next_count)
            .map_err(db_error)?;
        txn.commit()
            .map_err(|error| commit_error("stream retirement", error))?;
        Ok(SourceStreamRetireOutcome::Retired {
            revision: scope.stream_revision,
        })
    }
}

impl SourceStreamLifecycle for RedbStateBackend {
    fn inspect_stream<'a>(
        &'a self,
        stream: SourceStreamScope<'a>,
    ) -> SourceFuture<'a, Option<SourceStreamSnapshot>> {
        Box::pin(async move {
            let stream = OwnedStreamScope::from_borrowed(stream);
            source_job(self, "stream inspection", move |owner| {
                owner.inspect_stream(stream.borrow())
            })
            .await
        })
    }

    fn open_stream<'a>(
        &'a self,
        request: SourceStreamOpen<'a>,
    ) -> SourceFuture<'a, SourceStreamOpenOutcome> {
        Box::pin(async move {
            let stream = OwnedStreamScope::from_borrowed(request.stream);
            let open_id = request.open_id.to_owned();
            let expected_revision = request.expected_revision;
            source_job(self, "stream open", move |owner| {
                owner.open_stream(SourceStreamOpen {
                    stream: stream.borrow(),
                    open_id: &open_id,
                    expected_revision,
                })
            })
            .await
        })
    }

    fn retire_stream<'a>(
        &'a self,
        request: SourceStreamRetire<'a>,
    ) -> SourceFuture<'a, SourceStreamRetireOutcome> {
        Box::pin(async move {
            let stream = OwnedStreamScope::from_borrowed(request.stream);
            let stream_epoch = request.stream_epoch;
            source_job(self, "stream retirement", move |owner| {
                owner.retire_stream(SourceStreamRetire {
                    stream: stream.borrow(),
                    stream_epoch,
                })
            })
            .await
        })
    }
}

impl SourceDeclarationAdmission for RedbStateBackend {
    fn validate_source(
        &self,
        installation_id: &str,
        projection_id: &str,
        source: &EventSource,
    ) -> Result<(), SourceAdmissionError> {
        xolotl_source::validate_builtin_source(installation_id, projection_id, source)
    }
}

impl SourceOwner {
    fn load_installation(
        &self,
        id: &str,
    ) -> Result<Option<ExternalInstallationRecord>, SourceStoreError> {
        let txn = self.db.begin_read().map_err(db_error)?;
        let table = txn
            .open_table(EXTERNAL_INSTALLATIONS_TABLE)
            .map_err(db_error)?;
        let found = table.get(id).map_err(db_error)?;
        found
            .map(|guard| {
                if guard.value().len() > MAX_INSTALLATION_RECORD_BYTES {
                    return Err(aborted("external installation record exceeds byte maximum"));
                }
                let record: ExternalInstallationRecord =
                    decode_private(guard.value(), "external installation record is corrupt")?;
                if record.definition.id != id {
                    return Err(aborted("external installation record id mismatch"));
                }
                Ok(record)
            })
            .transpose()
    }

    fn list_installations(
        &self,
        after_id: Option<&str>,
        limit: NonZeroUsize,
    ) -> Result<Vec<ExternalInstallationRecord>, SourceStoreError> {
        let txn = self.db.begin_read().map_err(db_error)?;
        let table = txn
            .open_table(EXTERNAL_INSTALLATIONS_TABLE)
            .map_err(db_error)?;
        let mut rows = Vec::new();
        match after_id {
            Some(after) => {
                for entry in table.range(after..).map_err(db_error)? {
                    let (key, value) = entry.map_err(db_error)?;
                    if key.value() <= after {
                        continue;
                    }
                    if rows.len() == limit.get() {
                        break;
                    }
                    if value.value().len() > MAX_INSTALLATION_RECORD_BYTES {
                        return Err(aborted("external installation record exceeds byte maximum"));
                    }
                    let record: ExternalInstallationRecord =
                        decode_private(value.value(), "external installation record is corrupt")?;
                    if record.definition.id != key.value() {
                        return Err(aborted("external installation record id mismatch"));
                    }
                    rows.push(record);
                }
            }
            None => {
                for entry in table.iter().map_err(db_error)? {
                    if rows.len() == limit.get() {
                        break;
                    }
                    let (key, value) = entry.map_err(db_error)?;
                    if value.value().len() > MAX_INSTALLATION_RECORD_BYTES {
                        return Err(aborted("external installation record exceeds byte maximum"));
                    }
                    let record: ExternalInstallationRecord =
                        decode_private(value.value(), "external installation record is corrupt")?;
                    if record.definition.id != key.value() {
                        return Err(aborted("external installation record id mismatch"));
                    }
                    rows.push(record);
                }
            }
        }
        Ok(rows)
    }

    fn compare_install(
        &self,
        mut definition: ExternalInstallationDef,
        expected: Option<ExternalInstallationRevision>,
    ) -> Result<ExternalInstallationMutation, SourceStoreError> {
        definition
            .validate_admission()
            .map_err(|error| aborted(format!("installation admission failed: {error}")))?;
        for projection in &definition.projections {
            if let Some(source) = projection.emits.as_ref() {
                xolotl_source::validate_builtin_source(&definition.id, &projection.id, source)
                    .map_err(|error| aborted(error.to_string()))?;
            }
        }
        let txn = self.db.begin_write().map_err(db_error)?;
        let current = installation_record_in_txn(&txn, &definition.id)?;
        let current_revision = current.as_ref().map(ExternalInstallationRecord::revision);
        if current_revision != expected {
            return Ok(ExternalInstallationMutation::Conflict {
                current: current_revision,
            });
        }
        definition.version = expected
            .map_or(0, |revision| revision.version)
            .checked_add(1)
            .ok_or_else(|| aborted("installation version exhausted"))?;
        let mut meta = txn
            .open_table(EXTERNAL_INSTALLATIONS_META_TABLE)
            .map_err(db_error)?;
        let last_epoch = meta
            .get(NEXT_EXTERNAL_AUTHORITY_EPOCH)
            .map_err(db_error)?
            .ok_or_else(|| aborted("external authority epoch metadata missing"))?
            .value();
        let source_count = definition
            .projections
            .iter()
            .filter(|projection| projection.emits.is_some())
            .count();
        let new_installation = current.is_none();
        let allocated = u64::try_from(source_count)
            .ok()
            .and_then(|count| count.checked_add(u64::from(new_installation)))
            .ok_or_else(|| aborted("installation epoch range exhausted"))?;
        let high = last_epoch
            .checked_add(allocated)
            .ok_or_else(|| aborted("installation epoch exhausted"))?;
        let installation_epoch = match current.as_ref() {
            Some(record) => record.installation_epoch,
            None => last_epoch + 1,
        };
        let mut next_epoch = if new_installation {
            installation_epoch
        } else {
            last_epoch
        };
        let mut scope_epochs = std::collections::BTreeMap::new();
        for projection in &definition.projections {
            if projection.emits.is_some() {
                next_epoch += 1;
                scope_epochs.insert(projection.id.clone(), next_epoch);
            }
        }
        let record = ExternalInstallationRecord {
            definition,
            installation_epoch,
            scope_epochs,
        };
        let bytes = encode_private(&record, MAX_INSTALLATION_RECORD_BYTES)?;
        {
            let mut scopes = txn
                .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
                .map_err(db_error)?;
            if let Some(current) = &current {
                for projection in current.scope_epochs.keys() {
                    let key = format!("{}/{projection}", current.definition.id);
                    scopes.remove(key.as_str()).map_err(db_error)?;
                }
            }
            for (projection, epoch) in &record.scope_epochs {
                let key = format!("{}/{projection}", record.definition.id);
                let source = record
                    .definition
                    .projection(projection)
                    .and_then(|projection| projection.emits.as_ref())
                    .ok_or_else(|| aborted("active Source declaration missing"))?;
                let admission = SourceScopeAdmission::from_declaration(*epoch, source);
                let bytes = encode_private(&admission, MAX_SOURCE_SCOPE_ROW_BYTES)?;
                scopes
                    .insert(key.as_str(), bytes.as_slice())
                    .map_err(db_error)?;
            }
        }
        txn.open_table(EXTERNAL_INSTALLATIONS_TABLE)
            .map_err(db_error)?
            .insert(record.definition.id.as_str(), bytes.as_slice())
            .map_err(db_error)?;
        meta.insert(NEXT_EXTERNAL_AUTHORITY_EPOCH, high)
            .map_err(db_error)?;
        drop(meta);
        txn.commit()
            .map_err(|error| commit_error("installation", error))?;
        Ok(ExternalInstallationMutation::Applied(Some(record)))
    }

    fn compare_retire(
        &self,
        id: &str,
        expected: ExternalInstallationRevision,
    ) -> Result<ExternalInstallationMutation, SourceStoreError> {
        let txn = self.db.begin_write().map_err(db_error)?;
        let current = installation_record_in_txn(&txn, id)?;
        let current_revision = current.as_ref().map(ExternalInstallationRecord::revision);
        if current_revision != Some(expected) {
            return Ok(ExternalInstallationMutation::Conflict {
                current: current_revision,
            });
        }
        let current = current.ok_or_else(|| aborted("installation record missing"))?;
        {
            let mut scopes = txn
                .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)
                .map_err(db_error)?;
            for projection in current.scope_epochs.keys() {
                let key = format!("{id}/{projection}");
                scopes.remove(key.as_str()).map_err(db_error)?;
            }
        }
        txn.open_table(EXTERNAL_INSTALLATIONS_TABLE)
            .map_err(db_error)?
            .remove(id)
            .map_err(db_error)?;
        txn.commit()
            .map_err(|error| commit_error("installation retirement", error))?;
        Ok(ExternalInstallationMutation::Applied(None))
    }
}

impl ExternalInstallationAuthority for RedbStateBackend {
    fn load_installation<'a>(
        &'a self,
        id: &'a str,
    ) -> SourceFuture<'a, Option<ExternalInstallationRecord>> {
        Box::pin(async move {
            let id = id.to_owned();
            source_job(self, "installation load", move |owner| {
                owner.load_installation(&id)
            })
            .await
        })
    }

    fn list_installations<'a>(
        &'a self,
        after_id: Option<&'a str>,
        limit: NonZeroUsize,
    ) -> SourceFuture<'a, Vec<ExternalInstallationRecord>> {
        Box::pin(async move {
            let after_id = after_id.map(str::to_owned);
            source_job(self, "installation list", move |owner| {
                owner.list_installations(after_id.as_deref(), limit)
            })
            .await
        })
    }

    fn compare_install<'a>(
        &'a self,
        definition: ExternalInstallationDef,
        expected: Option<ExternalInstallationRevision>,
    ) -> SourceFuture<'a, ExternalInstallationMutation> {
        Box::pin(async move {
            source_job(self, "installation commit", move |owner| {
                owner.compare_install(definition, expected)
            })
            .await
        })
    }

    fn compare_retire<'a>(
        &'a self,
        id: &'a str,
        expected: ExternalInstallationRevision,
    ) -> SourceFuture<'a, ExternalInstallationMutation> {
        Box::pin(async move {
            let id = id.to_owned();
            source_job(self, "installation retirement", move |owner| {
                owner.compare_retire(&id, expected)
            })
            .await
        })
    }
}

impl SourceClaimInspection for RedbStateBackend {
    fn inspect<'a>(
        &'a self,
        request: SourceEvidenceInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence> {
        Box::pin(async move {
            xolotl_source::validate_claim(request.claim)?;
            let request = OwnedEvidenceInspection::from_borrowed(request);
            source_job(self, "claim inspection", move |owner| {
                owner.inspect_source(request.borrow())
            })
            .await
        })
    }

    fn inspect_event<'a>(
        &'a self,
        request: SourceEventDecisionInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence> {
        Box::pin(async move {
            let request = OwnedEventDecisionInspection::from_borrowed(request);
            source_job(self, "event inspection", move |owner| {
                owner.inspect_source_event(request.borrow())
            })
            .await
        })
    }
}

impl SourceEventMaintenance for RedbStateBackend {
    fn maintain<'a>(
        &'a self,
        request: SourceMaintenance,
    ) -> SourceFuture<'a, SourceMaintenanceResult> {
        Box::pin(async move {
            source_job(self, "maintenance", move |owner| {
                owner.maintain_source(request)
            })
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn admission_clock_is_sampled_after_acquiring_the_writer() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicI64, Ordering};
        let directory = tempfile::tempdir()?;
        let store = crate::RedbStore::open(directory.path().join("serialized-clock.redb"))?;
        let backend = store.state_backend();
        let sink = Path::parse("state://events/source")?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let declaration = EventSource {
            sink: sink.clone(),
            purity: xolotl_types::Purity::Effectful,
            event_schema: None,
            max_inline_payload_bytes: 1024,
            capacity: capacity.clone(),
            rate_limit: None,
            commands: false,
            command_schema: None,
            command_result_schema: None,
        };
        let scope = SourceScopeAdmission::from_declaration(2, &declaration);
        let bytes = encode_private(&scope, MAX_SOURCE_SCOPE_ROW_BYTES)?;
        let txn = backend.db.begin_write()?;
        txn.open_table(EXTERNAL_SOURCE_SCOPES_TABLE)?
            .insert("installation/source", bytes.as_slice())?;
        txn.commit()?;
        let writer = backend.db.begin_write()?;
        let time = Arc::new(AtomicI64::new(100));
        let (sampled, sample) = mpsc::channel();
        let clock: Arc<dyn xolotl_source::SourceClock> = {
            let time = Arc::clone(&time);
            Arc::new(move || {
                let decision_at_ms = time.load(Ordering::SeqCst);
                let _send_result = sampled.send(decision_at_ms);
                decision_at_ms
            })
        };
        let owner = SourceOwner::from_backend(&backend);
        let (started, start) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let payload = Value::integer(42);
            let taint = TaintSet::pristine();
            let _send_result = started.send(());
            owner.commit_source(SourceCommit {
                claim: SourceClaim {
                    installation_id: "installation",
                    projection_id: "source",
                    scope_epoch: 2,
                    stream_epoch: None,
                    event_id: "event",
                    claim_id: SourceClaimId::from_bytes([1; 16]),
                },
                received_at_ms: 10,
                decision_clock: clock,
                dedupe_window_ms: 1000,
                sink: &sink,
                capacity: &capacity,
                max_inline_payload_bytes: 1024,
                payload: &payload,
                taint: &taint,
                stream: None,
                rate_limit: None,
            })
        });
        start.recv_timeout(Duration::from_secs(5))?;
        let premature_sample = sample.recv_timeout(Duration::from_millis(100));
        time.store(200, Ordering::SeqCst);
        drop(writer);
        ensure!(
            worker
                .join()
                .map_err(|_panic| anyhow::anyhow!("commit worker panicked"))??
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            matches!(premature_sample, Err(mpsc::RecvTimeoutError::Timeout)),
            "clock sampled before acquiring the writer"
        );
        ensure!(sample.recv_timeout(Duration::from_secs(5))? == 200);
        ensure!(
            matches!(sample.try_recv(), Err(mpsc::TryRecvError::Disconnected)),
            "one decision must have one clock sample"
        );
        let txn = backend.db.begin_read()?;
        let row = txn
            .open_table(EXTERNAL_SOURCE_SCOPES_TABLE)?
            .get("installation/source")?
            .ok_or_else(|| anyhow::anyhow!("Source scope missing"))?
            .value()
            .to_vec();
        let scope: SourceScopeAdmission = decode_private(&row, "scope")?;
        ensure!(scope.decision_time_floor_ms == Some(200));
        Ok(())
    }

    #[test]
    fn evidence_reads_do_not_acquire_the_writer_or_change_private_rows() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let store = crate::RedbStore::open(directory.path().join("read-only.redb"))?;
        let backend = store.state_backend();
        let claim = SourceClaim {
            installation_id: "installation",
            projection_id: "source",
            scope_epoch: 2,
            stream_epoch: None,
            event_id: "accepted",
            claim_id: SourceClaimId::from_bytes([7; 16]),
        };
        let receipt = SourceReceipt {
            installation_id: claim.installation_id.into(),
            projection_id: claim.projection_id.into(),
            scope_epoch: claim.scope_epoch,
            stream_epoch: claim.stream_epoch,
            event_id: claim.event_id.into(),
            claim_id: claim.claim_id,
            sink: Path::parse("state://events/source")?,
            received_at_ms: 10,
        };
        let receipt_key = claim_key(claim)?;
        let event_key = event_key(claim)?;
        let receipt_bytes = encode_private(&receipt, MAX_RECEIPT_BYTES)?;
        let event_bytes = encode_private(
            &AcceptedEvent {
                claim_id: claim.claim_id,
                decision_at_ms: 100,
                expires_at_ms: 1100,
                payload_digest: [0; 32],
                stream: None,
            },
            MAX_EVENT_ROW_BYTES,
        )?;
        let txn = backend.db.begin_write()?;
        txn.open_table(SOURCE_RECEIPTS_TABLE)?
            .insert(receipt_key.as_slice(), receipt_bytes.as_slice())?;
        txn.open_table(SOURCE_META_TABLE)?
            .insert(event_key.as_slice(), event_bytes.as_slice())?;
        txn.commit()?;
        let writer = backend.db.begin_write()?;
        let owner = SourceOwner::from_backend(&backend);
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let exact = owner.inspect_source(SourceEvidenceInspection { claim });
            let event = owner.inspect_source_event(SourceEventDecisionInspection {
                installation_id: claim.installation_id,
                projection_id: claim.projection_id,
                scope_epoch: claim.scope_epoch,
                stream_epoch: claim.stream_epoch,
                event_id: claim.event_id,
            });
            let unknown = owner.inspect_source(SourceEvidenceInspection {
                claim: SourceClaim {
                    claim_id: SourceClaimId::from_bytes([9; 16]),
                    ..claim
                },
            });
            drop(send.send((exact, event, unknown)));
        });
        let observed = receive.recv_timeout(Duration::from_secs(5));
        drop(writer);
        worker
            .join()
            .map_err(|_panic| anyhow::anyhow!("inspection worker panicked"))?;
        let (exact, event, unknown) = observed?;
        ensure!(exact? == SourceClaimEvidence::Committed(receipt.clone()));
        ensure!(event? == SourceClaimEvidence::Committed(receipt));
        ensure!(unknown? == SourceClaimEvidence::Unproven);
        let txn = backend.db.begin_read()?;
        ensure!(
            get_read_private(&txn, SOURCE_RECEIPTS_TABLE, &receipt_key, MAX_RECEIPT_BYTES)?
                == Some(receipt_bytes)
        );
        ensure!(
            get_read_private(&txn, SOURCE_META_TABLE, &event_key, MAX_EVENT_ROW_BYTES)?
                == Some(event_bytes)
        );
        ensure!(txn.open_table(SOURCE_RECEIPTS_TABLE)?.len()? == 1);
        ensure!(txn.open_table(SOURCE_META_TABLE)?.len()? == 1);
        Ok(())
    }
}
