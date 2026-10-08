//! Origin-owned intent and CallRef mapping. A source commits the input before
//! Prepare, the target receipt before Invoke, and the may-send bit before
//! putting Invoke on a session.

use std::sync::Arc;

use redb::{
    ReadTransaction, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallCancelled, CallFailureCode, CallInspection, CallPrepared, CallRef, CallStatus, Digest,
    FederationError, FederationNodeId, FederationOutboundCallStore, MAX_CALL_INPUT_BYTES,
    MAX_OUTBOUND_PAGE_INPUT_BYTES, MAX_OUTBOUND_RESULT_BYTES, OutboundCallIntent,
    OutboundCallRecord, OutboundOriginEvidence, OutboundOriginState, PersistedCallResult,
    PrepareCallRequest, RequestId,
};
use xolotl_types::OperationId;

use super::super::KERNEL_CALL_NAMESPACE_KEY;
use super::{
    MAX_ROWS, PeerRow, RedbFederationStore, StoredRequest, StoredResult, StoredStatus,
    TRUSTED_TIME_KEY, check_time, decode, decode_trusted_time, encode, storage,
};
use crate::schema::{FEDERATION_NODE_TABLE, FEDERATION_PEERS_TABLE};

const OUTBOUND_CALLS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_calls_v1");
const OUTBOUND_INPUTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_inputs_v1");
const OUTBOUND_RESULTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_results_v1");
const OUTBOUND_UNSETTLED: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_unsettled_v1");
const OUTBOUND_ORIGINS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_origins_v1");
const OUTBOUND_CANCEL_PENDING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_cancel_pending_v1");
const OUTBOUND_CANCEL_BARRIERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_outbound_cancel_barriers_v1");
const REQUEST_DOMAIN: &[u8] = b"xolotl/federation/v1/kernel-call-request\0";
const ORIGIN_BYTES: usize = 1 + 32 + 48;

#[derive(Clone, Copy)]
enum SourceReader<'txn> {
    Read(&'txn ReadTransaction),
    Write(&'txn WriteTransaction),
}

impl SourceReader<'_> {
    fn load<Value>(
        self,
        definition: TableDefinition<&[u8], &[u8]>,
        request_id: RequestId,
        parse: impl FnOnce(&[u8]) -> Result<Value, FederationError>,
    ) -> Result<Option<Value>, FederationError> {
        match self {
            Self::Read(txn) => {
                let table = txn.open_table(definition).map_err(storage)?;
                table
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| parse(value.value()))
                    .transpose()
            }
            Self::Write(txn) => {
                let table = txn.open_table(definition).map_err(storage)?;
                table
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| parse(value.value()))
                    .transpose()
            }
        }
    }
}

#[derive(Clone, Copy)]
struct StoredOrigin {
    state: OutboundOriginState,
    released: bool,
    operation: [u8; 32],
    binding: Digest,
}

impl StoredOrigin {
    fn encode(self) -> [u8; ORIGIN_BYTES] {
        let mut bytes = [0; ORIGIN_BYTES];
        bytes[0] = if self.state == OutboundOriginState::Retired {
            1
        } else if self.released {
            2
        } else {
            0
        };
        bytes[1..33].copy_from_slice(&self.operation);
        bytes[33..].copy_from_slice(self.binding.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, FederationError> {
        if bytes.len() != ORIGIN_BYTES {
            return Err(FederationError::Corrupt);
        }
        let state = match bytes[0] {
            0 | 2 => OutboundOriginState::Active,
            1 => OutboundOriginState::Retired,
            _ => return Err(FederationError::Corrupt),
        };
        let operation = bytes[1..33]
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?;
        let binding = Digest::from_bytes(
            bytes[33..]
                .try_into()
                .map_err(|_error| FederationError::Corrupt)?,
        );
        if binding.as_bytes() == &[0; 48] {
            return Err(FederationError::Corrupt);
        }
        Ok(Self {
            state,
            released: bytes[0] == 2,
            operation,
            binding,
        })
    }
}

fn kernel_request_id(
    txn: &WriteTransaction,
    node: FederationNodeId,
    operation: [u8; 32],
) -> Result<RequestId, FederationError> {
    let node_table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
    let namespace = node_table
        .get(KERNEL_CALL_NAMESPACE_KEY)
        .map_err(storage)?
        .ok_or(FederationError::Corrupt)?;
    request_id_from_namespace(namespace.value(), node, operation)
}

fn request_id_from_namespace(
    namespace: &[u8],
    node: FederationNodeId,
    operation: [u8; 32],
) -> Result<RequestId, FederationError> {
    let namespace: [u8; 32] = namespace
        .try_into()
        .map_err(|_error| FederationError::Corrupt)?;
    if namespace == [0; 32] {
        return Err(FederationError::Corrupt);
    }
    let mut digest = Sha384::new();
    digest.update(REQUEST_DOMAIN);
    digest.update(namespace);
    digest.update(node.as_bytes());
    digest.update(operation);
    let digest = digest.finalize();
    let mut request = [0; 16];
    request.copy_from_slice(&digest[..16]);
    Ok(RequestId::from_bytes(request))
}

#[cfg(test)]
mod tests;

pub(super) fn init_tables(txn: &WriteTransaction) -> Result<(), FederationError> {
    drop(txn.open_table(OUTBOUND_CALLS).map_err(storage)?);
    drop(txn.open_table(OUTBOUND_INPUTS).map_err(storage)?);
    drop(txn.open_table(OUTBOUND_RESULTS).map_err(storage)?);
    drop(txn.open_table(OUTBOUND_UNSETTLED).map_err(storage)?);
    drop(txn.open_table(OUTBOUND_ORIGINS).map_err(storage)?);
    drop(txn.open_table(OUTBOUND_CANCEL_PENDING).map_err(storage)?);
    drop(txn.open_table(OUTBOUND_CANCEL_BARRIERS).map_err(storage)?);
    Ok(())
}

fn stored_status(status: CallStatus) -> Result<StoredStatus, FederationError> {
    Ok(match status {
        CallStatus::Reserved => StoredStatus::Reserved,
        CallStatus::Preparing => StoredStatus::Preparing,
        CallStatus::Accepted => StoredStatus::Accepted,
        CallStatus::Finished => StoredStatus::Finished,
        CallStatus::Closed => StoredStatus::Closed,
        CallStatus::Unproven => {
            return Err(FederationError::Invalid(
                "unproven call cannot be a receipt",
            ));
        }
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredPrepared {
    call_id: [u8; 32],
    status: StoredStatus,
    reserved_until_ms: u64,
    execution_deadline_ms: u64,
    result_retention_ms: u64,
    authority_revision: u64,
    control_revision: u64,
}

impl StoredPrepared {
    fn new(value: &CallPrepared) -> Result<Self, FederationError> {
        Ok(Self {
            call_id: value.call.id,
            status: stored_status(value.status)?,
            reserved_until_ms: value.reserved_until_ms,
            execution_deadline_ms: value.execution_deadline_ms,
            result_retention_ms: value.result_retention_ms,
            authority_revision: value.authority_revision,
            control_revision: value.control_revision,
        })
    }

    fn restore(
        self,
        target: FederationNodeId,
        request_id: RequestId,
    ) -> Result<CallPrepared, FederationError> {
        Ok(CallPrepared {
            origin_request_id: request_id,
            call: CallRef::new(target, self.call_id).map_err(|_error| FederationError::Corrupt)?,
            status: self.status.into(),
            reserved_until_ms: self.reserved_until_ms,
            execution_deadline_ms: self.execution_deadline_ms,
            result_retention_ms: self.result_retention_ms,
            authority_revision: self.authority_revision,
            control_revision: self.control_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredTerminal {
    status: StoredStatus,
    control_revision: u64,
    authority_revision: u64,
    reserved_until_ms: u64,
    execution_deadline_ms: u64,
    result_retained_until_ms: u64,
    result: Option<StoredResult>,
    unresolved_effect_ids: Vec<[u8; 32]>,
    cancellation_requested: bool,
    kernel_cancel_accepted: bool,
    execution_stopped: bool,
}

impl StoredTerminal {
    fn new(value: &CallInspection) -> Result<Self, FederationError> {
        Ok(Self {
            status: stored_status(value.status)?,
            control_revision: value.control_revision,
            authority_revision: value.authority_revision,
            reserved_until_ms: value.reserved_until_ms,
            execution_deadline_ms: value.execution_deadline_ms,
            result_retained_until_ms: value.result_retained_until_ms,
            result: value.result.as_ref().map(|result| StoredResult {
                succeeded: result.succeeded,
                digest: result.output_digest.as_bytes().to_vec(),
                failure_code: result
                    .failure_code
                    .as_ref()
                    .map(|code| code.as_str().to_owned()),
                retained_until_ms: value.result_retained_until_ms,
            }),
            unresolved_effect_ids: value.unresolved_effect_ids.clone(),
            cancellation_requested: value.cancellation_requested,
            kernel_cancel_accepted: value.kernel_cancel_accepted,
            execution_stopped: value.execution_stopped,
        })
    }

    fn restore(
        self,
        reader: SourceReader<'_>,
        request_id: RequestId,
        call: CallRef,
    ) -> Result<CallInspection, FederationError> {
        let result = if let Some(meta) = self.result {
            let output = reader
                .load(OUTBOUND_RESULTS, request_id, |bytes| {
                    if bytes.len() > MAX_OUTBOUND_RESULT_BYTES {
                        return Err(FederationError::Corrupt);
                    }
                    Ok(Arc::<[u8]>::from(bytes))
                })?
                .ok_or(FederationError::Corrupt)?;
            let result = PersistedCallResult {
                succeeded: meta.succeeded,
                output,
                output_digest: Digest::from_bytes(
                    meta.digest
                        .try_into()
                        .map_err(|_error| FederationError::Corrupt)?,
                ),
                failure_code: meta
                    .failure_code
                    .map(|value| {
                        CallFailureCode::new(value).map_err(|_error| FederationError::Corrupt)
                    })
                    .transpose()?,
            };
            Some(result)
        } else {
            None
        };
        Ok(CallInspection {
            call,
            status: self.status.into(),
            control_revision: self.control_revision,
            authority_revision: self.authority_revision,
            reserved_until_ms: self.reserved_until_ms,
            execution_deadline_ms: self.execution_deadline_ms,
            result_retained_until_ms: self.result_retained_until_ms,
            result,
            unresolved_effect_ids: self.unresolved_effect_ids,
            cancellation_requested: self.cancellation_requested,
            kernel_cancel_accepted: self.kernel_cancel_accepted,
            execution_stopped: self.execution_stopped,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredCancelled {
    control_request_id: [u8; 16],
    status: StoredStatus,
    control_revision: u64,
    cancellation_requested: bool,
    kernel_cancel_accepted: bool,
    execution_stopped: bool,
}

impl StoredCancelled {
    fn new(value: CallCancelled) -> Result<Self, FederationError> {
        Ok(Self {
            control_request_id: *value.control_request_id.as_bytes(),
            status: stored_status(value.status)?,
            control_revision: value.control_revision,
            cancellation_requested: value.cancellation_requested,
            kernel_cancel_accepted: value.kernel_cancel_accepted,
            execution_stopped: value.execution_stopped,
        })
    }

    fn restore(self, call: CallRef) -> CallCancelled {
        CallCancelled {
            control_request_id: RequestId::from_bytes(self.control_request_id),
            call,
            status: self.status.into(),
            control_revision: self.control_revision,
            cancellation_requested: self.cancellation_requested,
            kernel_cancel_accepted: self.kernel_cancel_accepted,
            execution_stopped: self.execution_stopped,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredOutbound {
    target_node: Vec<u8>,
    request: StoredRequest,
    source_peer_revision: u64,
    prepared: Option<StoredPrepared>,
    invoke_possible: bool,
    terminal: Option<StoredTerminal>,
    cancellation_requested: bool,
    cancel_acknowledged: Option<StoredCancelled>,
}

impl StoredOutbound {
    fn new(record: &OutboundCallRecord, peer_revision: u64) -> Result<Self, FederationError> {
        Ok(Self {
            target_node: record.intent.target_node.as_bytes().to_vec(),
            request: (&record.intent.request).into(),
            source_peer_revision: peer_revision,
            prepared: record
                .prepared
                .as_ref()
                .map(StoredPrepared::new)
                .transpose()?,
            invoke_possible: record.invoke_possible,
            terminal: record
                .terminal
                .as_ref()
                .map(StoredTerminal::new)
                .transpose()?,
            cancellation_requested: record.cancellation_requested,
            cancel_acknowledged: record
                .cancel_acknowledged
                .map(StoredCancelled::new)
                .transpose()?,
        })
    }
}

fn read_record(
    txn: &WriteTransaction,
    request_id: RequestId,
    local: FederationNodeId,
) -> Result<Option<(OutboundCallRecord, u64)>, FederationError> {
    read_source_record(SourceReader::Write(txn), request_id, local)
}

fn read_source_record(
    reader: SourceReader<'_>,
    request_id: RequestId,
    local: FederationNodeId,
) -> Result<Option<(OutboundCallRecord, u64)>, FederationError> {
    let row = reader.load(OUTBOUND_CALLS, request_id, decode::<StoredOutbound>)?;
    let Some(row) = row else {
        return Ok(None);
    };
    restore_record(reader, request_id, local, row).map(Some)
}

fn restore_record(
    reader: SourceReader<'_>,
    request_id: RequestId,
    local: FederationNodeId,
    row: StoredOutbound,
) -> Result<(OutboundCallRecord, u64), FederationError> {
    if row.source_peer_revision == 0 {
        return Err(FederationError::Corrupt);
    }
    let peer_revision = row.source_peer_revision;
    let target_node = FederationNodeId::from_bytes(
        row.target_node
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let request: PrepareCallRequest = row.request.try_into()?;
    if request.origin_request_id != request_id
        || request.authenticated_origin != local
        || target_node == local
    {
        return Err(FederationError::Corrupt);
    }
    let input = reader
        .load(OUTBOUND_INPUTS, request_id, |bytes| {
            if bytes.len() > MAX_CALL_INPUT_BYTES
                || bytes.len() as u64 != request.input_bytes
                || request.input_digest.as_bytes() != Sha384::digest(bytes).as_slice()
            {
                return Err(FederationError::Corrupt);
            }
            Ok(Arc::<[u8]>::from(bytes))
        })?
        .ok_or(FederationError::Corrupt)?;
    let intent = OutboundCallIntent {
        target_node,
        request,
        input,
    };
    let mut record = OutboundCallRecord {
        intent,
        prepared: None,
        invoke_possible: false,
        terminal: None,
        cancellation_requested: false,
        cancel_acknowledged: None,
    };
    if let Some(prepared) = row.prepared {
        record
            .bind(prepared.restore(target_node, request_id)?)
            .map_err(|_error| FederationError::Corrupt)?;
    }
    if row.invoke_possible {
        if record.prepared.is_none() {
            return Err(FederationError::Corrupt);
        }
        record.invoke_possible = true;
    }
    if row.cancellation_requested {
        record.request_cancellation();
    }
    if let Some(cancelled) = row.cancel_acknowledged {
        let call = record
            .prepared
            .as_ref()
            .ok_or(FederationError::Corrupt)?
            .call;
        record
            .record_cancellation(cancelled.restore(call))
            .map_err(|_error| FederationError::Corrupt)?;
    }
    if let Some(terminal) = row.terminal {
        let call = record
            .prepared
            .as_ref()
            .ok_or(FederationError::Corrupt)?
            .call;
        record
            .settle(terminal.restore(reader, request_id, call)?)
            .map_err(|_error| FederationError::Corrupt)?;
    }
    if record.cancellation_requested != row.cancellation_requested {
        return Err(FederationError::Corrupt);
    }
    Ok((record, peer_revision))
}

fn write_record(
    txn: &WriteTransaction,
    record: &OutboundCallRecord,
    peer_revision: u64,
) -> Result<(), FederationError> {
    let value = encode(&StoredOutbound::new(record, peer_revision)?)?;
    txn.open_table(OUTBOUND_CALLS)
        .map_err(storage)?
        .insert(
            record.intent.request_id().as_bytes().as_slice(),
            value.as_slice(),
        )
        .map_err(storage)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum SourcePage {
    Unsettled,
    Cancellations,
}

fn read_source_page(
    txn: &ReadTransaction,
    local: FederationNodeId,
    after: Option<RequestId>,
    max: usize,
    kind: SourcePage,
) -> Result<Vec<OutboundCallRecord>, FederationError> {
    if max == 0 || max > 32 {
        return Err(FederationError::Invalid("invalid outbound page size"));
    }
    let definition = match kind {
        SourcePage::Unsettled => OUTBOUND_UNSETTLED,
        SourcePage::Cancellations => OUTBOUND_CANCEL_PENDING,
    };
    let table = txn.open_table(definition).map_err(storage)?;
    let start = after
        .as_ref()
        .map_or(&[][..], |id| id.as_bytes().as_slice());
    let reader = SourceReader::Read(txn);
    let mut page = Vec::with_capacity(max);
    let mut remaining = MAX_OUTBOUND_PAGE_INPUT_BYTES;
    for entry in table.range(start..).map_err(storage)? {
        let (key, _value) = entry.map_err(storage)?;
        let request_id = RequestId::from_bytes(
            key.value()
                .try_into()
                .map_err(|_error| FederationError::Corrupt)?,
        );
        if after == Some(request_id) {
            continue;
        }
        let row = reader
            .load(OUTBOUND_CALLS, request_id, decode::<StoredOutbound>)?
            .ok_or(FederationError::Corrupt)?;
        if row.terminal.is_some()
            || (matches!(kind, SourcePage::Cancellations)
                && (!row.cancellation_requested || row.cancel_acknowledged.is_some()))
        {
            return Err(FederationError::Corrupt);
        }
        let input_bytes =
            usize::try_from(row.request.input_bytes).map_err(|_error| FederationError::Corrupt)?;
        if input_bytes > MAX_CALL_INPUT_BYTES {
            return Err(FederationError::Corrupt);
        }
        if input_bytes > remaining {
            break;
        }
        let (record, _revision) = restore_record(reader, request_id, local, row)?;
        remaining -= input_bytes;
        page.push(record);
        if page.len() == max {
            break;
        }
    }
    Ok(page)
}

// Outbound calls are authorized by the host's exact local Kernel binding and
// the target's CallAuthority. Source-side stream export rights are unrelated;
// only the configured peer admission revision fences a staged wire effect.
fn active_peer_revision(
    txn: &WriteTransaction,
    peer: FederationNodeId,
) -> Result<u64, FederationError> {
    let row: PeerRow = txn
        .open_table(FEDERATION_PEERS_TABLE)
        .map_err(storage)?
        .get(peer.as_bytes().as_slice())
        .map_err(storage)?
        .map(|value| decode(value.value()))
        .transpose()?
        .ok_or(FederationError::Unauthorized)?;
    if row.revision == 0 {
        return Err(FederationError::Corrupt);
    }
    if !row.enabled {
        return Err(FederationError::Unauthorized);
    }
    Ok(row.revision)
}

// A Session handshake or another source task can commit a later clock sample
// before this operation obtains its write transaction. Take the later trusted
// observation for all deadline checks; that can only shorten call validity.
fn source_time(txn: &WriteTransaction, sampled_now_ms: u64) -> Result<u64, FederationError> {
    let high_water = txn
        .open_table(FEDERATION_NODE_TABLE)
        .map_err(storage)?
        .get(TRUSTED_TIME_KEY)
        .map_err(storage)?
        .map(|value| decode_trusted_time(value.value()))
        .transpose()?
        .unwrap_or(0);
    let now_ms = sampled_now_ms.max(high_water);
    check_time(txn, now_ms)?;
    Ok(now_ms)
}

fn cancellation_barrier(
    txn: &WriteTransaction,
    request_id: RequestId,
    operation: [u8; 32],
) -> Result<bool, FederationError> {
    let table = txn.open_table(OUTBOUND_CANCEL_BARRIERS).map_err(storage)?;
    let Some(saved) = table
        .get(request_id.as_bytes().as_slice())
        .map_err(storage)?
    else {
        return Ok(false);
    };
    if saved.value() != operation {
        return Err(FederationError::Corrupt);
    }
    Ok(true)
}

fn record_cancellation_barrier(
    txn: &WriteTransaction,
    request_id: RequestId,
    operation: [u8; 32],
) -> Result<(), FederationError> {
    if cancellation_barrier(txn, request_id, operation)? {
        return Ok(());
    }
    let mut table = txn.open_table(OUTBOUND_CANCEL_BARRIERS).map_err(storage)?;
    if table.len().map_err(storage)? >= MAX_ROWS {
        return Err(FederationError::Capacity);
    }
    table
        .insert(request_id.as_bytes().as_slice(), operation.as_slice())
        .map_err(storage)?;
    Ok(())
}

fn responsibility_can_end(record: &StoredOutbound) -> bool {
    record.terminal.as_ref().is_some_and(|terminal| {
        matches!(
            terminal.status,
            StoredStatus::Finished | StoredStatus::Closed
        ) && terminal.execution_stopped
            && terminal.unresolved_effect_ids.is_empty()
            && (!record.cancellation_requested || record.cancel_acknowledged.is_some())
    })
}

impl RedbFederationStore {
    /// End the source owner's responsibility after consuming the retained
    /// result and completing local cleanup. The caller must ensure no live
    /// consumer still needs these payloads; settlement alone is not release.
    /// Unknown outcomes, unresolved effects and unacknowledged cancellation
    /// cannot be released. Repeating a committed release is safe after reopen
    /// or retirement. An indeterminate commit must be retried with the same IDs.
    pub fn release_outbound_responsibility(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<(), FederationError> {
        self.with_decision_write(|txn, _| {
            let mut origin = {
                let table = txn.open_table(OUTBOUND_ORIGINS).map_err(storage)?;
                let value = table
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                StoredOrigin::decode(value.value())?
            };
            if origin.operation != operation.to_bytes()
                || kernel_request_id(txn, self.node, origin.operation)? != request_id
            {
                return Err(FederationError::Conflict);
            }
            if origin.state == OutboundOriginState::Retired {
                return Ok(());
            }
            let record = {
                let table = txn.open_table(OUTBOUND_CALLS).map_err(storage)?;
                let value = table
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Conflict)?;
                decode::<StoredOutbound>(value.value())?
            };
            if !responsibility_can_end(&record) {
                return Err(FederationError::Conflict);
            }
            origin.released = true;
            txn.open_table(OUTBOUND_ORIGINS)
                .map_err(storage)?
                .insert(request_id.as_bytes().as_slice(), origin.encode().as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)
        })
    }

    /// Retire at most `max` source call rows from one keyset page. A call is
    /// eligible only after a proven terminal and explicit responsibility
    /// release for the same OperationId coexist in this database. No Kernel
    /// Fact is required. The 81-byte origin
    /// tombstone is retained for the lifetime of this database; restoring an
    /// older backup must not reuse its node identity or operation namespace.
    /// The returned cursor is `None` after the final page; callers then restart
    /// scanning at the beginning on their next maintenance pass.
    pub fn retire_completed_outbound(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<(usize, Option<RequestId>), FederationError> {
        if max == 0 || max > 256 {
            return Err(FederationError::Invalid(
                "invalid outbound retirement page size",
            ));
        }
        self.with_decision_write(|txn, _| {
            let ids = {
                let table = txn.open_table(OUTBOUND_CALLS).map_err(storage)?;
                let start = after
                    .as_ref()
                    .map_or(&[][..], |id| id.as_bytes().as_slice());
                let mut ids = Vec::with_capacity(max);
                for entry in table.range(start..).map_err(storage)? {
                    let (key, _value) = entry.map_err(storage)?;
                    let id = RequestId::from_bytes(
                        key.value()
                            .try_into()
                            .map_err(|_error| FederationError::Corrupt)?,
                    );
                    if after == Some(id) {
                        continue;
                    }
                    ids.push(id);
                    if ids.len() == max {
                        break;
                    }
                }
                ids
            };
            let next = (ids.len() == max).then(|| ids[ids.len() - 1]);
            let mut retired = 0;
            for id in ids {
                let can_end = {
                    let table = txn.open_table(OUTBOUND_CALLS).map_err(storage)?;
                    let value = table
                        .get(id.as_bytes().as_slice())
                        .map_err(storage)?
                        .ok_or(FederationError::Corrupt)?;
                    responsibility_can_end(&decode::<StoredOutbound>(value.value())?)
                };
                if !can_end {
                    continue;
                }
                let origin = {
                    let table = txn.open_table(OUTBOUND_ORIGINS).map_err(storage)?;
                    table
                        .get(id.as_bytes().as_slice())
                        .map_err(storage)?
                        .map(|value| StoredOrigin::decode(value.value()))
                        .transpose()?
                };
                let Some(mut origin) = origin else {
                    continue;
                };
                if origin.state != OutboundOriginState::Active
                    || kernel_request_id(txn, self.node, origin.operation)? != id
                {
                    return Err(FederationError::Corrupt);
                }
                if !origin.released {
                    continue;
                }
                origin.state = OutboundOriginState::Retired;
                txn.open_table(OUTBOUND_ORIGINS)
                    .map_err(storage)?
                    .insert(id.as_bytes().as_slice(), origin.encode().as_slice())
                    .map_err(storage)?;
                for table in [
                    OUTBOUND_CALLS,
                    OUTBOUND_INPUTS,
                    OUTBOUND_RESULTS,
                    OUTBOUND_UNSETTLED,
                    OUTBOUND_CANCEL_PENDING,
                ] {
                    txn.open_table(table)
                        .map_err(storage)?
                        .remove(id.as_bytes().as_slice())
                        .map_err(storage)?;
                }
                retired += 1;
            }
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok((retired, next))
        })
    }
}

impl FederationOutboundCallStore for RedbFederationStore {
    fn bind_outbound_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationOutboundCallStore>, FederationError> {
        Ok(Arc::new(self.with_decision(decision)?))
    }

    fn release_outbound_responsibility(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<(), FederationError> {
        RedbFederationStore::release_outbound_responsibility(self, request_id, operation)
    }

    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn outbound_origin_evidence(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<OutboundOriginEvidence, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let nodes = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
        let namespace = nodes
            .get(KERNEL_CALL_NAMESPACE_KEY)
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?;
        if request_id_from_namespace(namespace.value(), self.node, operation.to_bytes())?
            != request_id
        {
            return Err(FederationError::Conflict);
        }
        let origins = txn.open_table(OUTBOUND_ORIGINS).map_err(storage)?;
        let origin = origins
            .get(request_id.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| StoredOrigin::decode(value.value()))
            .transpose()?;
        if origin
            .as_ref()
            .is_some_and(|saved| saved.operation != operation.to_bytes())
        {
            return Err(FederationError::Corrupt);
        }
        let barriers = txn.open_table(OUTBOUND_CANCEL_BARRIERS).map_err(storage)?;
        let barrier = barriers
            .get(request_id.as_bytes().as_slice())
            .map_err(storage)?;
        if barrier
            .as_ref()
            .is_some_and(|saved| saved.value() != operation.to_bytes())
        {
            return Err(FederationError::Corrupt);
        }
        if barrier.is_some()
            || origin
                .as_ref()
                .is_some_and(|saved| saved.state == OutboundOriginState::Retired)
        {
            return Ok(OutboundOriginEvidence::Retired);
        }
        let calls = txn.open_table(OUTBOUND_CALLS).map_err(storage)?;
        Ok(
            if origin.is_some()
                || calls
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                    .is_some()
            {
                OutboundOriginEvidence::Recorded
            } else {
                OutboundOriginEvidence::Fresh
            },
        )
    }

    fn bind_outbound_origin(
        &self,
        request_id: RequestId,
        operation: OperationId,
        binding: Digest,
    ) -> Result<OutboundOriginState, FederationError> {
        if binding.as_bytes() == &[0; 48] {
            return Err(FederationError::Invalid("zero outbound binding digest"));
        }
        self.with_decision_write(|txn, _| {
            let operation = operation.to_bytes();
            if kernel_request_id(txn, self.node, operation)? != request_id {
                return Err(FederationError::Conflict);
            }
            let cancelled = cancellation_barrier(txn, request_id, operation)?;
            let state;
            {
                let mut table = txn.open_table(OUTBOUND_ORIGINS).map_err(storage)?;
                if let Some(existing) = table
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                {
                    let existing = StoredOrigin::decode(existing.value())?;
                    if existing.operation != operation || existing.binding != binding {
                        return Err(FederationError::Conflict);
                    }
                    state = if cancelled {
                        OutboundOriginState::Retired
                    } else {
                        existing.state
                    };
                } else {
                    if cancelled {
                        return Ok(OutboundOriginState::Retired);
                    }
                    let origin = StoredOrigin {
                        state: OutboundOriginState::Active,
                        released: false,
                        operation,
                        binding,
                    };
                    table
                        .insert(request_id.as_bytes().as_slice(), origin.encode().as_slice())
                        .map_err(storage)?;
                    state = OutboundOriginState::Active;
                }
            }
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(state)
        })
    }

    fn stage_outbound_cancellation(
        &self,
        operation: OperationId,
    ) -> Result<Option<RequestId>, FederationError> {
        self.with_decision_write(|txn, _| {
            let request_id = kernel_request_id(txn, self.node, operation.to_bytes())?;
            let origin = {
                let table = txn.open_table(OUTBOUND_ORIGINS).map_err(storage)?;
                table
                    .get(request_id.as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| StoredOrigin::decode(value.value()))
                    .transpose()?
            };
            if let Some(origin) = origin {
                if origin.operation != operation.to_bytes() {
                    return Err(FederationError::Corrupt);
                }
                if origin.state == OutboundOriginState::Retired {
                    return Ok(None);
                }
            }
            let live = if origin.is_some() {
                read_record(txn, request_id, self.node)?
                    .filter(|(record, _revision)| record.terminal.is_none())
            } else {
                None
            };
            record_cancellation_barrier(txn, request_id, operation.to_bytes())?;
            let has_live_call = live.is_some();
            if let Some((mut record, peer_revision)) = live {
                record.request_cancellation();
                write_record(txn, &record, peer_revision)?;
                if record.cancel_acknowledged.is_none() {
                    txn.open_table(OUTBOUND_CANCEL_PENDING)
                        .map_err(storage)?
                        .insert(request_id.as_bytes().as_slice(), &[][..])
                        .map_err(storage)?;
                }
            }
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(has_live_call.then_some(request_id))
        })
    }

    fn pending_outbound_cancellations(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        read_source_page(&txn, self.node, after, max, SourcePage::Cancellations)
    }

    fn record_outbound_cancellation(
        &self,
        request_id: RequestId,
        response: CallCancelled,
    ) -> Result<OutboundCallRecord, FederationError> {
        self.with_decision_write(|txn, _| {
            let (mut record, peer_revision) =
                read_record(txn, request_id, self.node)?.ok_or(FederationError::NotFound)?;
            record.record_cancellation(response)?;
            write_record(txn, &record, peer_revision)?;
            txn.open_table(OUTBOUND_CANCEL_PENDING)
                .map_err(storage)?
                .remove(request_id.as_bytes().as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(record)
        })
    }

    fn stage_outbound(
        &self,
        intent: OutboundCallIntent,
        now_ms: u64,
    ) -> Result<OutboundCallRecord, FederationError> {
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            let now_ms = source_time(txn, now_ms)?;
            intent.validate(self.node, now_ms)?;
            let barrier: Option<[u8; 32]> = {
                let table = txn.open_table(OUTBOUND_CANCEL_BARRIERS).map_err(storage)?;
                table
                    .get(intent.request_id().as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| {
                        value
                            .value()
                            .try_into()
                            .map_err(|_error| FederationError::Corrupt)
                    })
                    .transpose()?
            };
            if let Some(operation) = barrier {
                let origin = txn
                    .open_table(OUTBOUND_ORIGINS)
                    .map_err(storage)?
                    .get(intent.request_id().as_bytes().as_slice())
                    .map_err(storage)?
                    .map(|value| StoredOrigin::decode(value.value()))
                    .transpose()?;
                if origin.is_some_and(|origin| origin.operation != operation) {
                    return Err(FederationError::Corrupt);
                }
                return Err(FederationError::Conflict);
            }
            if let Some(origin) = txn
                .open_table(OUTBOUND_ORIGINS)
                .map_err(storage)?
                .get(intent.request_id().as_bytes().as_slice())
                .map_err(storage)?
                && StoredOrigin::decode(origin.value())?.state == OutboundOriginState::Retired
            {
                return Err(FederationError::Conflict);
            }
            let peer_revision = active_peer_revision(txn, intent.target_node)?;
            if let Some((existing, pinned)) = read_record(txn, intent.request_id(), self.node)? {
                if existing.intent != intent {
                    return Err(FederationError::Conflict);
                }
                if peer_revision != pinned {
                    return Err(FederationError::Conflict);
                }
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
                return Ok(existing);
            }
            if txn
                .open_table(OUTBOUND_CALLS)
                .map_err(storage)?
                .len()
                .map_err(storage)?
                >= MAX_ROWS
            {
                return Err(FederationError::Capacity);
            }
            let record = OutboundCallRecord {
                intent,
                prepared: None,
                invoke_possible: false,
                terminal: None,
                cancellation_requested: false,
                cancel_acknowledged: None,
            };
            txn.open_table(OUTBOUND_INPUTS)
                .map_err(storage)?
                .insert(
                    record.intent.request_id().as_bytes().as_slice(),
                    record.intent.input.as_ref(),
                )
                .map_err(storage)?;
            write_record(txn, &record, peer_revision)?;
            txn.open_table(OUTBOUND_UNSETTLED)
                .map_err(storage)?
                .insert(record.intent.request_id().as_bytes().as_slice(), &[][..])
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(record)
        })
    }

    fn bind_outbound_prepared(
        &self,
        request_id: RequestId,
        prepared: CallPrepared,
    ) -> Result<OutboundCallRecord, FederationError> {
        self.with_decision_write(|txn, _| {
            let (mut record, peer_revision) =
                read_record(txn, request_id, self.node)?.ok_or(FederationError::NotFound)?;
            record.bind(prepared)?;
            write_record(txn, &record, peer_revision)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(record)
        })
    }

    fn mark_outbound_invoke_possible(
        &self,
        request_id: RequestId,
        now_ms: u64,
    ) -> Result<OutboundCallRecord, FederationError> {
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            let now_ms = source_time(txn, now_ms)?;
            let (mut record, peer_revision) =
                read_record(txn, request_id, self.node)?.ok_or(FederationError::NotFound)?;
            let current = active_peer_revision(txn, record.intent.target_node)?;
            if current != peer_revision {
                return Err(FederationError::Conflict);
            }
            record.mark_invoke_possible(now_ms)?;
            write_record(txn, &record, peer_revision)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(record)
        })
    }

    fn settle_outbound(
        &self,
        request_id: RequestId,
        terminal: CallInspection,
    ) -> Result<OutboundCallRecord, FederationError> {
        self.with_decision_write(|txn, _| {
            let (mut record, peer_revision) =
                read_record(txn, request_id, self.node)?.ok_or(FederationError::NotFound)?;
            record.settle(terminal)?;
            if let Some(result) = record
                .terminal
                .as_ref()
                .and_then(|terminal| terminal.result.as_ref())
            {
                txn.open_table(OUTBOUND_RESULTS)
                    .map_err(storage)?
                    .insert(request_id.as_bytes().as_slice(), result.output.as_ref())
                    .map_err(storage)?;
            }
            write_record(txn, &record, peer_revision)?;
            txn.open_table(OUTBOUND_UNSETTLED)
                .map_err(storage)?
                .remove(request_id.as_bytes().as_slice())
                .map_err(storage)?;
            txn.open_table(OUTBOUND_CANCEL_PENDING)
                .map_err(storage)?
                .remove(request_id.as_bytes().as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(record)
        })
    }

    fn outbound_call(&self, request_id: RequestId) -> Result<OutboundCallRecord, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        read_source_record(SourceReader::Read(&txn), request_id, self.node)?
            .map(|(record, _authority)| record)
            .ok_or(FederationError::NotFound)
    }

    fn unsettled_outbound(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        read_source_page(&txn, self.node, after, max, SourcePage::Unsettled)
    }
}
