//! Same-database durable call directory. A prepared call is an inert
//! reservation; only the original idempotent Kernel bridge may report
//! acceptance and completion.

use std::sync::Arc;

use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    CallAuthorityEntry, CallAuthorityKey, CallAuthorityRule, CallCancelled, CallFailureCode,
    CallInspection, CallInvoked, CallKernelBinding, CallKernelView, CallMethod, CallPath,
    CallPrepared, CallRef, CallStatus, CallTarget, CancelCallRequest, Digest, FederationCallStore,
    FederationError, FederationNodeId, FederationSubject, HostedSubject, InspectCallRequest,
    InvokeCallRequest, MAX_CALL_INPUT_BYTES, MAX_CALL_UNRESOLVED_EFFECT_IDS, PersistedCallResult,
    PrepareCallRequest, RequestId, SubjectIssuerId,
};

use super::{
    FEDERATION_NODE_TABLE, FEDERATION_PEERS_TABLE, PeerRow, RedbFederationStore, TRUSTED_TIME_KEY,
    authority_in_read, authority_in_write, decode_trusted_time, storage,
};

mod source;

const CALL_GRANTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_call_grants_v1");
const CALLS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("federation_calls_v1");
const CALL_REQUESTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_call_requests_v1");
const CALL_RESULTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_call_results_v1");
const CALL_INPUTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_call_inputs_v1");
const CALL_PENDING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("federation_call_pending_v1");
const MAX_ROWS: u64 = 100_000;
const MAX_META_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const MAX_CANCEL_RECEIPTS: usize = 128;

pub(super) fn init_tables(txn: &WriteTransaction) -> Result<(), FederationError> {
    drop(txn.open_table(CALL_GRANTS).map_err(storage)?);
    drop(txn.open_table(CALLS).map_err(storage)?);
    drop(txn.open_table(CALL_REQUESTS).map_err(storage)?);
    drop(txn.open_table(CALL_RESULTS).map_err(storage)?);
    drop(txn.open_table(CALL_INPUTS).map_err(storage)?);
    drop(txn.open_table(CALL_PENDING).map_err(storage)?);
    source::init_tables(txn)?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum StoredSubject {
    Node(Vec<u8>),
    Hosted {
        issuer: Vec<u8>,
        namespace: String,
        subject: String,
    },
}

impl From<&FederationSubject> for StoredSubject {
    fn from(value: &FederationSubject) -> Self {
        match value {
            FederationSubject::Node(node) => Self::Node(node.as_bytes().to_vec()),
            FederationSubject::Hosted(hosted) => Self::Hosted {
                issuer: hosted.issuer.as_bytes().to_vec(),
                namespace: hosted.namespace.clone(),
                subject: hosted.subject.clone(),
            },
        }
    }
}

impl TryFrom<StoredSubject> for FederationSubject {
    type Error = FederationError;

    fn try_from(value: StoredSubject) -> Result<Self, Self::Error> {
        Ok(match value {
            StoredSubject::Node(node) => Self::Node(FederationNodeId::from_bytes(
                node.try_into().map_err(|_error| FederationError::Corrupt)?,
            )),
            StoredSubject::Hosted {
                issuer,
                namespace,
                subject,
            } => Self::Hosted(HostedSubject {
                issuer: SubjectIssuerId::from_bytes(
                    issuer
                        .try_into()
                        .map_err(|_error| FederationError::Corrupt)?,
                ),
                namespace,
                subject,
            }),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredTarget {
    export: String,
    path: String,
    method: String,
    contract_digest: [u8; 32],
}

impl From<&CallTarget> for StoredTarget {
    fn from(value: &CallTarget) -> Self {
        Self {
            export: value.export.as_str().to_owned(),
            path: value.path.as_str().to_owned(),
            method: value.method.as_str().to_owned(),
            contract_digest: value.contract_digest,
        }
    }
}

impl TryFrom<StoredTarget> for CallTarget {
    type Error = FederationError;

    fn try_from(value: StoredTarget) -> Result<Self, Self::Error> {
        Ok(Self {
            export: xolotl_federation::ExportName::new(value.export)
                .map_err(|_error| FederationError::Corrupt)?,
            path: CallPath::new(value.path).map_err(|_error| FederationError::Corrupt)?,
            method: CallMethod::new(value.method).map_err(|_error| FederationError::Corrupt)?,
            contract_digest: value.contract_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredRequest {
    origin: Vec<u8>,
    subject: StoredSubject,
    request_id: [u8; 16],
    target: StoredTarget,
    input_digest: Vec<u8>,
    input_bytes: u64,
    prepare_deadline_ms: u64,
    execution_deadline_ms: u64,
    result_retention_ms: u64,
}

impl From<&PrepareCallRequest> for StoredRequest {
    fn from(value: &PrepareCallRequest) -> Self {
        Self {
            origin: value.authenticated_origin.as_bytes().to_vec(),
            subject: (&value.subject).into(),
            request_id: *value.origin_request_id.as_bytes(),
            target: (&value.target).into(),
            input_digest: value.input_digest.as_bytes().to_vec(),
            input_bytes: value.input_bytes,
            prepare_deadline_ms: value.prepare_deadline_ms,
            execution_deadline_ms: value.execution_deadline_ms,
            result_retention_ms: value.result_retention_ms,
        }
    }
}

impl TryFrom<StoredRequest> for PrepareCallRequest {
    type Error = FederationError;

    fn try_from(value: StoredRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            authenticated_origin: FederationNodeId::from_bytes(
                value
                    .origin
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            ),
            subject: value.subject.try_into()?,
            origin_request_id: RequestId::from_bytes(value.request_id),
            target: value.target.try_into()?,
            input_digest: Digest::from_bytes(
                value
                    .input_digest
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            ),
            input_bytes: value.input_bytes,
            prepare_deadline_ms: value.prepare_deadline_ms,
            execution_deadline_ms: value.execution_deadline_ms,
            result_retention_ms: value.result_retention_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredGrant {
    revision: u64,
    subject: StoredSubject,
    presenter: Vec<u8>,
    target: StoredTarget,
    enabled: bool,
    expires_ms: u64,
    max_input_bytes: u64,
    max_prepare_window_ms: u64,
    max_result_retention_ms: u64,
}

impl StoredGrant {
    fn new(revision: u64, rule: &CallAuthorityRule) -> Self {
        Self {
            revision,
            subject: (&rule.subject).into(),
            presenter: rule.presenter.as_bytes().to_vec(),
            target: (&rule.target).into(),
            enabled: rule.enabled,
            expires_ms: rule.expires_ms,
            max_input_bytes: rule.max_input_bytes,
            max_prepare_window_ms: rule.max_prepare_window_ms,
            max_result_retention_ms: rule.max_result_retention_ms,
        }
    }

    fn entry(&self) -> Result<CallAuthorityEntry, FederationError> {
        if self.revision == 0 {
            return Err(FederationError::Corrupt);
        }
        let rule = CallAuthorityRule {
            subject: self.subject.clone().try_into()?,
            presenter: FederationNodeId::from_bytes(
                self.presenter
                    .as_slice()
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            ),
            target: self.target.clone().try_into()?,
            enabled: self.enabled,
            expires_ms: self.expires_ms,
            max_input_bytes: self.max_input_bytes,
            max_prepare_window_ms: self.max_prepare_window_ms,
            max_result_retention_ms: self.max_result_retention_ms,
        };
        rule.validate().map_err(|_error| FederationError::Corrupt)?;
        Ok(CallAuthorityEntry {
            revision: self.revision,
            rule,
        })
    }

    fn matches(&self, request: &PrepareCallRequest, now_ms: u64) -> Result<(), FederationError> {
        if self.revision == 0 || self.presenter.len() != 48 {
            return Err(FederationError::Corrupt);
        }
        if self.subject != StoredSubject::from(&request.subject)
            || self.presenter.as_slice() != request.authenticated_origin.as_bytes().as_slice()
            || self.target != StoredTarget::from(&request.target)
        {
            return Err(FederationError::Corrupt);
        }
        if !self.enabled || now_ms >= self.expires_ms || request.input_bytes > self.max_input_bytes
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum StoredStatus {
    Reserved,
    Preparing,
    Accepted,
    Finished,
    Closed,
}

impl From<StoredStatus> for CallStatus {
    fn from(value: StoredStatus) -> Self {
        match value {
            StoredStatus::Reserved => Self::Reserved,
            StoredStatus::Preparing => Self::Preparing,
            StoredStatus::Accepted => Self::Accepted,
            StoredStatus::Finished => Self::Finished,
            StoredStatus::Closed => Self::Closed,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredResult {
    succeeded: bool,
    digest: Vec<u8>,
    failure_code: Option<String>,
    retained_until_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredCancel {
    request_id: [u8; 16],
    expected_revision: Option<u64>,
    status: StoredStatus,
    control_revision: u64,
    cancellation_requested: bool,
    kernel_cancel_accepted: bool,
    execution_stopped: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredCall {
    request: StoredRequest,
    status: StoredStatus,
    reserved_until_ms: u64,
    execution_deadline_ms: u64,
    result_retention_ms: u64,
    authority_revision: u64,
    peer_revision: u64,
    export_revision: u64,
    control_revision: u64,
    binding: Option<CallKernelBindingRow>,
    accepted_digest: Option<Vec<u8>>,
    result: Option<StoredResult>,
    unresolved_effect_ids: Vec<[u8; 32]>,
    cancellation_requested: bool,
    kernel_cancel_accepted: bool,
    execution_stopped: bool,
    cancellations: Vec<StoredCancel>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CallKernelBindingRow {
    process: u64,
    lifecycle: u64,
}

impl From<CallKernelBinding> for CallKernelBindingRow {
    fn from(value: CallKernelBinding) -> Self {
        Self {
            process: value.process,
            lifecycle: value.lifecycle,
        }
    }
}

impl TryFrom<CallKernelBindingRow> for CallKernelBinding {
    type Error = FederationError;

    fn try_from(value: CallKernelBindingRow) -> Result<Self, Self::Error> {
        let binding = Self {
            process: value.process,
            lifecycle: value.lifecycle,
        };
        binding
            .validate()
            .map_err(|_error| FederationError::Corrupt)?;
        Ok(binding)
    }
}

impl StoredCall {
    fn request(&self) -> Result<PrepareCallRequest, FederationError> {
        self.request.clone().try_into()
    }

    fn prepared(&self, call: CallRef) -> Result<CallPrepared, FederationError> {
        if self.authority_revision == 0 || self.control_revision == 0 {
            return Err(FederationError::Corrupt);
        }
        Ok(CallPrepared {
            origin_request_id: RequestId::from_bytes(self.request.request_id),
            call,
            status: self.status.into(),
            reserved_until_ms: self.reserved_until_ms,
            execution_deadline_ms: self.execution_deadline_ms,
            result_retention_ms: self.result_retention_ms,
            authority_revision: self.authority_revision,
            control_revision: self.control_revision,
        })
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, FederationError> {
    let bytes = serde_json::to_vec(value).map_err(storage)?;
    if bytes.len() > MAX_META_BYTES {
        return Err(FederationError::Capacity);
    }
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, FederationError> {
    if bytes.len() > MAX_META_BYTES {
        return Err(FederationError::Corrupt);
    }
    serde_json::from_slice(bytes).map_err(|_error| FederationError::Corrupt)
}

fn grant_key(
    subject: &FederationSubject,
    presenter: FederationNodeId,
    target: &CallTarget,
) -> Result<Vec<u8>, FederationError> {
    CallAuthorityKey {
        subject: subject.clone(),
        presenter,
        target: target.clone(),
    }
    .encoded()
}

fn source_key(origin: FederationNodeId, request: RequestId) -> [u8; 64] {
    let mut key = [0; 64];
    key[..48].copy_from_slice(origin.as_bytes());
    key[48..].copy_from_slice(request.as_bytes());
    key
}

fn check_time(txn: &WriteTransaction, now_ms: u64) -> Result<(), FederationError> {
    let mut table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
    let previous = table
        .get(TRUSTED_TIME_KEY)
        .map_err(storage)?
        .map(|value| decode_trusted_time(value.value()))
        .transpose()?;
    if previous.is_some_and(|last| now_ms < last) {
        return Err(FederationError::ClockRollback);
    }
    if previous != Some(now_ms) {
        table
            .insert(TRUSTED_TIME_KEY, now_ms.to_be_bytes().as_slice())
            .map_err(storage)?;
    }
    Ok(())
}

fn grant_in_write(
    txn: &WriteTransaction,
    request: &PrepareCallRequest,
    now_ms: u64,
) -> Result<StoredGrant, FederationError> {
    let key = grant_key(
        &request.subject,
        request.authenticated_origin,
        &request.target,
    )?;
    let row = txn
        .open_table(CALL_GRANTS)
        .map_err(storage)?
        .get(key.as_slice())
        .map_err(storage)?
        .map(|value| decode::<StoredGrant>(value.value()))
        .transpose()?
        .ok_or(FederationError::Unauthorized)?;
    row.matches(request, now_ms)?;
    Ok(row)
}

fn current_authority(
    txn: &WriteTransaction,
    row: &StoredCall,
    now_ms: u64,
) -> Result<(), FederationError> {
    let request = row.request()?;
    let grant = grant_in_write(txn, &request, now_ms)?;
    let authority = authority_in_write(
        txn,
        request.authenticated_origin,
        &request.target.export,
        true,
    )?;
    check_authority_revisions(row, grant.revision, authority)
}

fn check_authority_revisions(
    row: &StoredCall,
    grant_revision: u64,
    authority: xolotl_federation::AuthorityRevision,
) -> Result<(), FederationError> {
    if grant_revision != row.authority_revision
        || authority.peer != row.peer_revision
        || authority.export != row.export_revision
    {
        return Err(FederationError::Conflict);
    }
    Ok(())
}

fn current_peer(txn: &WriteTransaction, peer: FederationNodeId) -> Result<(), FederationError> {
    let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
    let value = table
        .get(peer.as_bytes().as_slice())
        .map_err(storage)?
        .ok_or(FederationError::Unauthorized)?;
    let row: PeerRow = decode(value.value())?;
    if row.revision == 0 {
        return Err(FederationError::Corrupt);
    }
    if !row.enabled {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

fn read_call(txn: &WriteTransaction, id: &[u8; 32]) -> Result<Option<StoredCall>, FederationError> {
    txn.open_table(CALLS)
        .map_err(storage)?
        .get(id.as_slice())
        .map_err(storage)?
        .map(|value| decode::<StoredCall>(value.value()))
        .transpose()
}

fn write_call(
    txn: &WriteTransaction,
    id: &[u8; 32],
    row: &StoredCall,
) -> Result<(), FederationError> {
    txn.open_table(CALLS)
        .map_err(storage)?
        .insert(id.as_slice(), encode(row)?.as_slice())
        .map_err(storage)?;
    Ok(())
}

fn set_pending(
    txn: &WriteTransaction,
    id: &[u8; 32],
    pending: bool,
) -> Result<(), FederationError> {
    let mut table = txn.open_table(CALL_PENDING).map_err(storage)?;
    if pending {
        table.insert(id.as_slice(), &[][..]).map_err(storage)?;
    } else {
        table.remove(id.as_slice()).map_err(storage)?;
    }
    Ok(())
}

fn input_in_write(
    txn: &WriteTransaction,
    call: CallRef,
    row: &StoredCall,
) -> Result<Option<Arc<[u8]>>, FederationError> {
    let table = txn.open_table(CALL_INPUTS).map_err(storage)?;
    let input = table
        .get(call.id.as_slice())
        .map_err(storage)?
        .map(|value| {
            if value.value().len() as u64 != row.request.input_bytes {
                return Err(FederationError::Corrupt);
            }
            Ok(Arc::<[u8]>::from(value.value()))
        })
        .transpose()?;
    if matches!(row.status, StoredStatus::Preparing | StoredStatus::Accepted) && input.is_none() {
        return Err(FederationError::Corrupt);
    }
    Ok(input)
}

fn require_input_in_write(
    txn: &WriteTransaction,
    call: CallRef,
    row: &StoredCall,
) -> Result<(), FederationError> {
    let table = txn.open_table(CALL_INPUTS).map_err(storage)?;
    let input = table
        .get(call.id.as_slice())
        .map_err(storage)?
        .ok_or(FederationError::Corrupt)?;
    if input.value().len() as u64 != row.request.input_bytes {
        return Err(FederationError::Corrupt);
    }
    Ok(())
}

fn kernel_view(
    txn: &WriteTransaction,
    call: CallRef,
    row: &StoredCall,
) -> Result<CallKernelView, FederationError> {
    let accepted_digest = row
        .accepted_digest
        .as_ref()
        .map(|bytes| {
            <[u8; 48]>::try_from(bytes.as_slice())
                .map(Digest::from_bytes)
                .map_err(|_error| FederationError::Corrupt)
        })
        .transpose()?;
    Ok(CallKernelView {
        call,
        request: row.request()?,
        status: row.status.into(),
        input: input_in_write(txn, call, row)?,
        binding: row.binding.map(TryInto::try_into).transpose()?,
        accepted_digest,
        cancellation_requested: row.cancellation_requested,
        kernel_cancel_accepted: row.kernel_cancel_accepted,
        execution_stopped: row.execution_stopped,
    })
}

fn result_in_write(
    txn: &WriteTransaction,
    call: CallRef,
    row: &StoredCall,
    now_ms: u64,
) -> Result<Option<PersistedCallResult>, FederationError> {
    let Some(meta) = &row.result else {
        return Ok(None);
    };
    if now_ms >= meta.retained_until_ms {
        return Ok(None);
    }
    let table = txn.open_table(CALL_RESULTS).map_err(storage)?;
    let value = table
        .get(call.id.as_slice())
        .map_err(storage)?
        .ok_or(FederationError::Corrupt)?;
    let output = Arc::<[u8]>::from(value.value());
    let result = PersistedCallResult {
        succeeded: meta.succeeded,
        output,
        output_digest: Digest::from_bytes(
            meta.digest
                .clone()
                .try_into()
                .map_err(|_error| FederationError::Corrupt)?,
        ),
        failure_code: meta
            .failure_code
            .as_ref()
            .map(|code| {
                CallFailureCode::new(code.clone()).map_err(|_error| FederationError::Corrupt)
            })
            .transpose()?,
    };
    result.verify()?;
    Ok(Some(result))
}

fn inspection(
    txn: &WriteTransaction,
    call: CallRef,
    row: &StoredCall,
    now_ms: u64,
) -> Result<CallInspection, FederationError> {
    Ok(CallInspection {
        call,
        status: row.status.into(),
        control_revision: row.control_revision,
        authority_revision: row.authority_revision,
        reserved_until_ms: row.reserved_until_ms,
        execution_deadline_ms: row.execution_deadline_ms,
        result_retained_until_ms: row
            .result
            .as_ref()
            .map_or(0, |result| result.retained_until_ms),
        result: result_in_write(txn, call, row, now_ms)?,
        unresolved_effect_ids: row.unresolved_effect_ids.clone(),
        cancellation_requested: row.cancellation_requested,
        kernel_cancel_accepted: row.kernel_cancel_accepted,
        execution_stopped: row.execution_stopped,
    })
}

fn actor_matches(
    row: &StoredCall,
    origin: FederationNodeId,
    subject: &FederationSubject,
) -> Result<(), FederationError> {
    let request = row.request()?;
    if request.authenticated_origin != origin || &request.subject != subject {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

impl FederationCallStore for RedbFederationStore {
    fn bind_local_call_clock(
        &self,
        clock: std::sync::Arc<dyn xolotl_federation::FederationObjectClock>,
    ) -> Result<std::sync::Arc<dyn FederationCallStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_local_clock(clock)?))
    }

    fn bind_call_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationCallStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn set_call_authority(
        &self,
        expected_revision: Option<u64>,
        rule: CallAuthorityRule,
    ) -> Result<u64, FederationError> {
        rule.validate()?;
        if rule.presenter == self.node {
            return Err(FederationError::Invalid("call presenter is the local node"));
        }
        let key = grant_key(&rule.subject, rule.presenter, &rule.target)?;
        self.with_decision_write(|txn, _| {
            // A new or enabled method grant needs a currently authorized export.
            // Revoking an existing grant must remain possible after its peer or
            // export has already been disabled.
            if rule.enabled || expected_revision.is_none() {
                authority_in_write(txn, rule.presenter, &rule.target.export, true)?;
            }
            let current = {
                let table = txn.open_table(CALL_GRANTS).map_err(storage)?;
                table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .map(|value| decode::<StoredGrant>(value.value()))
                    .transpose()?
            };
            if current.is_none()
                && txn
                    .open_table(CALL_GRANTS)
                    .map_err(storage)?
                    .len()
                    .map_err(storage)?
                    >= MAX_ROWS
            {
                return Err(FederationError::Capacity);
            }
            let previous = current.as_ref().map(|row| row.revision);
            let revision = super::next_revision(previous, expected_revision)?;
            let row = StoredGrant::new(revision, &rule);
            txn.open_table(CALL_GRANTS)
                .map_err(storage)?
                .insert(key.as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(revision)
        })
    }

    fn call_authority(
        &self,
        key: &CallAuthorityKey,
    ) -> Result<Option<CallAuthorityEntry>, FederationError> {
        let encoded = key.encoded()?;
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(CALL_GRANTS).map_err(storage)?;
        let entry = table
            .get(encoded.as_slice())
            .map_err(storage)?
            .map(|value| decode::<StoredGrant>(value.value())?.entry())
            .transpose()?;
        if let Some(entry) = &entry
            && CallAuthorityKey::from_rule(&entry.rule).encoded()? != encoded
        {
            return Err(FederationError::Corrupt);
        }
        Ok(entry)
    }

    fn scan_call_authorities(
        &self,
        after: Option<&CallAuthorityKey>,
        max: usize,
    ) -> Result<Vec<CallAuthorityEntry>, FederationError> {
        if max == 0 || max > 256 {
            return Err(FederationError::Invalid("invalid call authority page size"));
        }
        let after = after.map(CallAuthorityKey::encoded).transpose()?;
        let start = after.as_deref().unwrap_or_default();
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(CALL_GRANTS).map_err(storage)?;
        let mut entries = Vec::with_capacity(max);
        for result in table.range(start..).map_err(storage)? {
            let (key, value) = result.map_err(storage)?;
            if after.as_deref() == Some(key.value()) {
                continue;
            }
            let entry = decode::<StoredGrant>(value.value())?.entry()?;
            if CallAuthorityKey::from_rule(&entry.rule).encoded()? != key.value() {
                return Err(FederationError::Corrupt);
            }
            entries.push(entry);
            if entries.len() == max {
                break;
            }
        }
        Ok(entries)
    }

    fn prepared_call_for_request(
        &self,
        request: &PrepareCallRequest,
    ) -> Result<Option<CallPrepared>, FederationError> {
        self.decision_peer(request.authenticated_origin)?;
        self.with_decision_write(|txn, _| {
            let source = source_key(request.authenticated_origin, request.origin_request_id);
            let previous = txn
                .open_table(CALL_REQUESTS)
                .map_err(storage)?
                .get(source.as_slice())
                .map_err(storage)?
                .map(|value| {
                    <[u8; 32]>::try_from(value.value()).map_err(|_error| FederationError::Corrupt)
                })
                .transpose()?;
            let Some(id) = previous else {
                return Ok(None);
            };
            let row = read_call(txn, &id)?.ok_or(FederationError::Corrupt)?;
            if row.request()? != *request {
                return Err(FederationError::Conflict);
            }
            Ok(Some(row.prepared(CallRef::new(self.node, id)?)?))
        })
    }

    fn prepare_call(
        &self,
        request: PrepareCallRequest,
        now_ms: u64,
    ) -> Result<CallPrepared, FederationError> {
        self.decision_peer(request.authenticated_origin)?;
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let source = source_key(request.authenticated_origin, request.origin_request_id);
            let previous = {
                let table = txn.open_table(CALL_REQUESTS).map_err(storage)?;
                table
                    .get(source.as_slice())
                    .map_err(storage)?
                    .map(|value| {
                        <[u8; 32]>::try_from(value.value())
                            .map_err(|_error| FederationError::Corrupt)
                    })
                    .transpose()?
            };
            if let Some(id) = previous {
                let row = read_call(txn, &id)?.ok_or(FederationError::Corrupt)?;
                // This exact reservation was authorized at its first commit.
                // Reconciliation must remain possible after its deadline or a
                // later grant revocation, so the source can recover its CallRef
                // and issue a cancellation. It creates no new execution right.
                if row.request()? != request {
                    return Err(FederationError::Conflict);
                }
                let prepared = row.prepared(CallRef::new(self.node, id)?)?;
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
                return Ok(prepared);
            }
            request.validate(self.node, now_ms)?;
            let grant = grant_in_write(txn, &request, now_ms)?;
            let authority = authority_in_write(
                txn,
                request.authenticated_origin,
                &request.target.export,
                true,
            )?;
            if txn
                .open_table(CALLS)
                .map_err(storage)?
                .len()
                .map_err(storage)?
                >= MAX_ROWS
            {
                return Err(FederationError::Capacity);
            }
            let reserved_until_ms = request
                .prepare_deadline_ms
                .min(grant.expires_ms)
                .min(now_ms.saturating_add(grant.max_prepare_window_ms));
            if reserved_until_ms <= now_ms {
                return Err(FederationError::Unauthorized);
            }
            let call = (0..4)
                .find_map(|_attempt| {
                    let candidate = CallRef::random(self.node).ok()?;
                    match read_call(txn, &candidate.id) {
                        Ok(None) => Some(candidate),
                        _ => None,
                    }
                })
                .ok_or(FederationError::Capacity)?;
            let row = StoredCall {
                request: (&request).into(),
                status: StoredStatus::Reserved,
                reserved_until_ms,
                execution_deadline_ms: request.execution_deadline_ms,
                result_retention_ms: request
                    .result_retention_ms
                    .min(grant.max_result_retention_ms),
                authority_revision: grant.revision,
                peer_revision: authority.peer,
                export_revision: authority.export,
                control_revision: 1,
                binding: None,
                accepted_digest: None,
                result: None,
                unresolved_effect_ids: Vec::new(),
                cancellation_requested: false,
                kernel_cancel_accepted: false,
                execution_stopped: false,
                cancellations: Vec::new(),
            };
            write_call(txn, &call.id, &row)?;
            txn.open_table(CALL_REQUESTS)
                .map_err(storage)?
                .insert(source.as_slice(), call.id.as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.prepared(call)
        })
    }

    fn invoke_call(
        &self,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Result<CallInvoked, FederationError> {
        self.decision_peer(request.authenticated_origin)?;
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        if request.input.len() > MAX_CALL_INPUT_BYTES {
            return Err(FederationError::Capacity);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &request.call.id)?.ok_or(FederationError::NotFound)?;
            actor_matches(&row, request.authenticated_origin, &request.subject)?;
            current_authority(txn, &row, now_ms)?;
            if row.request.request_id != *request.origin_request_id.as_bytes()
                || row.request.input_bytes != request.input.len() as u64
                || row.request.input_digest.as_slice()
                    != request.input_digest().as_bytes().as_slice()
            {
                return Err(FederationError::Conflict);
            }
            if row.status == StoredStatus::Reserved {
                if now_ms >= row.reserved_until_ms {
                    row.status = StoredStatus::Closed;
                    row.execution_stopped = true;
                    row.control_revision = row
                        .control_revision
                        .checked_add(1)
                        .ok_or(FederationError::Capacity)?;
                    write_call(txn, &request.call.id, &row)?;
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)?;
                    return Err(FederationError::Conflict);
                }
                row.status = StoredStatus::Preparing;
                row.control_revision = row
                    .control_revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?;
                txn.open_table(CALL_INPUTS)
                    .map_err(storage)?
                    .insert(request.call.id.as_slice(), request.input.as_ref())
                    .map_err(storage)?;
                set_pending(txn, &request.call.id, true)?;
                write_call(txn, &request.call.id, &row)?;
            } else if matches!(row.status, StoredStatus::Preparing | StoredStatus::Accepted) {
                require_input_in_write(txn, request.call, &row)?;
            }
            if row.status == StoredStatus::Closed {
                return Err(FederationError::Conflict);
            }
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(CallInvoked {
                call: request.call,
                status: row.status.into(),
                control_revision: row.control_revision,
            })
        })
    }

    fn bind_kernel_identity(
        &self,
        call: CallRef,
        binding: CallKernelBinding,
        now_ms: u64,
    ) -> Result<CallKernelBinding, FederationError> {
        binding.validate()?;
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            current_authority(txn, &row, now_ms)?;
            match row.binding.map(TryInto::try_into).transpose()? {
                Some(existing) if existing == binding => {
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)?;
                    Ok(existing)
                }
                Some(_) => Err(FederationError::Conflict),
                None if row.status == StoredStatus::Preparing
                    && !row.cancellation_requested
                    && now_ms < row.execution_deadline_ms =>
                {
                    require_input_in_write(txn, call, &row)?;
                    row.binding = Some(binding.into());
                    write_call(txn, &call.id, &row)?;
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)?;
                    Ok(binding)
                }
                None => Err(FederationError::Conflict),
            }
        })
    }

    fn kernel_call(&self, call: CallRef, now_ms: u64) -> Result<CallKernelView, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            let view = kernel_view(txn, call, &row)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(view)
        })
    }

    fn authorize_kernel_execution(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if !matches!(row.status, StoredStatus::Preparing | StoredStatus::Accepted)
                || row.binding.is_none()
                || row.cancellation_requested
                || now_ms >= row.execution_deadline_ms
            {
                return Err(FederationError::Conflict);
            }
            current_authority(txn, &row, now_ms)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(())
        })
    }

    fn close_unaccepted_call(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if row.status == StoredStatus::Closed {
                let result = inspection(txn, call, &row, now_ms)?;
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
                return Ok(result);
            }
            if row.status != StoredStatus::Preparing || row.accepted_digest.is_some() {
                return Err(FederationError::Conflict);
            }
            row.status = StoredStatus::Closed;
            row.execution_stopped = true;
            row.control_revision = row
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            txn.open_table(CALL_INPUTS)
                .map_err(storage)?
                .remove(call.id.as_slice())
                .map_err(storage)?;
            set_pending(txn, &call.id, false)?;
            write_call(txn, &call.id, &row)?;
            let result = inspection(txn, call, &row, now_ms)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    fn scan_pending_kernel_calls(
        &self,
        after: Option<[u8; 32]>,
        max: usize,
    ) -> Result<Vec<CallRef>, FederationError> {
        if max == 0 || max > 256 {
            return Err(FederationError::Invalid("invalid pending call page size"));
        }
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(CALL_PENDING).map_err(storage)?;
        let start = after.as_ref().map_or(&[][..], |id| id.as_slice());
        let mut calls = Vec::new();
        for entry in table.range(start..).map_err(storage)? {
            let (key, _value) = entry.map_err(storage)?;
            let id: [u8; 32] = key
                .value()
                .try_into()
                .map_err(|_error| FederationError::Corrupt)?;
            if after == Some(id) {
                continue;
            }
            calls.push(CallRef::new(self.node, id).map_err(|_error| FederationError::Corrupt)?);
            if calls.len() >= max {
                break;
            }
        }
        Ok(calls)
    }

    fn request_call_deadline_stop(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if now_ms < row.execution_deadline_ms
                || !matches!(row.status, StoredStatus::Preparing | StoredStatus::Accepted)
            {
                return Err(FederationError::Conflict);
            }
            if !row.cancellation_requested {
                row.cancellation_requested = true;
                row.control_revision = row
                    .control_revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?;
                write_call(txn, &call.id, &row)?;
            }
            let result = inspection(txn, call, &row, now_ms)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    fn record_kernel_acceptance(
        &self,
        call: CallRef,
        acceptance_digest: Digest,
    ) -> Result<CallInvoked, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, _| {
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if row.status == StoredStatus::Preparing && row.binding.is_some() {
                row.status = StoredStatus::Accepted;
                row.accepted_digest = Some(acceptance_digest.as_bytes().to_vec());
                row.control_revision = row
                    .control_revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?;
                write_call(txn, &call.id, &row)?;
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
            } else if row.accepted_digest.as_deref()
                != Some(acceptance_digest.as_bytes().as_slice())
            {
                return Err(FederationError::Conflict);
            }
            Ok(CallInvoked {
                call,
                status: row.status.into(),
                control_revision: row.control_revision,
            })
        })
    }

    fn record_kernel_cancel_accepted(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if !row.cancellation_requested || row.binding.is_none() {
                return Err(FederationError::Conflict);
            }
            if !row.kernel_cancel_accepted {
                row.kernel_cancel_accepted = true;
                row.control_revision = row
                    .control_revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?;
                write_call(txn, &call.id, &row)?;
            }
            let result = inspection(txn, call, &row, now_ms)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    fn record_execution_stopped(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if row.binding.is_none()
                || matches!(row.status, StoredStatus::Reserved | StoredStatus::Closed)
            {
                return Err(FederationError::Conflict);
            }
            if !row.execution_stopped {
                row.execution_stopped = true;
                row.control_revision = row
                    .control_revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?;
                write_call(txn, &call.id, &row)?;
                if row.status == StoredStatus::Finished {
                    set_pending(txn, &call.id, false)?;
                }
            }
            let result = inspection(txn, call, &row, now_ms)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    fn record_call_result(
        &self,
        call: CallRef,
        result: PersistedCallResult,
        unresolved_effect_ids: Vec<[u8; 32]>,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        result.verify()?;
        if result.output.len() > MAX_RESULT_BYTES
            || unresolved_effect_ids.len() > MAX_CALL_UNRESOLVED_EFFECT_IDS
        {
            return Err(FederationError::Capacity);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &call.id)?.ok_or(FederationError::NotFound)?;
            if row.status == StoredStatus::Finished {
                let previous = row.result.as_ref().ok_or(FederationError::Corrupt)?;
                if previous.succeeded != result.succeeded
                    || previous.digest.as_slice() != result.output_digest.as_bytes().as_slice()
                    || previous.failure_code.as_deref()
                        != result.failure_code.as_ref().map(CallFailureCode::as_str)
                    || row.unresolved_effect_ids != unresolved_effect_ids
                {
                    return Err(FederationError::Conflict);
                }
                let result = inspection(txn, call, &row, now_ms)?;
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
                return Ok(result);
            }
            if row.status != StoredStatus::Accepted {
                return Err(FederationError::Conflict);
            }
            let retained_until_ms = now_ms.saturating_add(row.result_retention_ms);
            row.result = Some(StoredResult {
                succeeded: result.succeeded,
                digest: result.output_digest.as_bytes().to_vec(),
                failure_code: result
                    .failure_code
                    .as_ref()
                    .map(|code| code.as_str().to_owned()),
                retained_until_ms,
            });
            row.unresolved_effect_ids = unresolved_effect_ids;
            row.status = StoredStatus::Finished;
            row.control_revision = row
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            txn.open_table(CALL_RESULTS)
                .map_err(storage)?
                .insert(call.id.as_slice(), result.output.as_ref())
                .map_err(storage)?;
            txn.open_table(CALL_INPUTS)
                .map_err(storage)?
                .remove(call.id.as_slice())
                .map_err(storage)?;
            write_call(txn, &call.id, &row)?;
            if row.execution_stopped {
                set_pending(txn, &call.id, false)?;
            }
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(CallInspection {
                call,
                status: CallStatus::Finished,
                control_revision: row.control_revision,
                authority_revision: row.authority_revision,
                reserved_until_ms: row.reserved_until_ms,
                execution_deadline_ms: row.execution_deadline_ms,
                result_retained_until_ms: retained_until_ms,
                result: Some(result),
                unresolved_effect_ids: row.unresolved_effect_ids,
                cancellation_requested: row.cancellation_requested,
                kernel_cancel_accepted: row.kernel_cancel_accepted,
                execution_stopped: row.execution_stopped,
            })
        })
    }

    fn authorize_call_delivery(
        &self,
        request: &InspectCallRequest,
        retained_output_until_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(request.authenticated_origin)?;
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, now_ms) = self.begin_delivery_read(now_ms)?;
        let row = txn
            .open_table(CALLS)
            .map_err(storage)?
            .get(request.call.id.as_slice())
            .map_err(storage)?
            .map(|value| decode::<StoredCall>(value.value()))
            .transpose()?
            .ok_or(FederationError::NotFound)?;
        actor_matches(&row, request.authenticated_origin, &request.subject)?;
        if retained_output_until_ms.is_some_and(|deadline| {
            row.result
                .as_ref()
                .is_none_or(|result| result.retained_until_ms != deadline)
                || now_ms >= deadline
        }) {
            return Err(FederationError::Unauthorized);
        }
        let prepare = row.request()?;
        let key = grant_key(
            &prepare.subject,
            prepare.authenticated_origin,
            &prepare.target,
        )?;
        let grant = txn
            .open_table(CALL_GRANTS)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|value| decode::<StoredGrant>(value.value()))
            .transpose()?
            .ok_or(FederationError::Unauthorized)?;
        grant.matches(&prepare, now_ms)?;
        let authority = authority_in_read(
            &txn,
            prepare.authenticated_origin,
            &prepare.target.export,
            true,
        )?;
        check_authority_revisions(&row, grant.revision, authority)
    }

    fn inspect_call(
        &self,
        request: InspectCallRequest,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        self.decision_peer(request.authenticated_origin)?;
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let Some(row) = read_call(txn, &request.call.id)? else {
                let result = CallInspection {
                    call: request.call,
                    status: CallStatus::Unproven,
                    control_revision: 0,
                    authority_revision: 0,
                    reserved_until_ms: 0,
                    execution_deadline_ms: 0,
                    result_retained_until_ms: 0,
                    result: None,
                    unresolved_effect_ids: Vec::new(),
                    cancellation_requested: false,
                    kernel_cancel_accepted: false,
                    execution_stopped: false,
                };
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
                return Ok(result);
            };
            actor_matches(&row, request.authenticated_origin, &request.subject)?;
            if row.cancellations.is_empty() && row.status != StoredStatus::Closed {
                current_authority(txn, &row, now_ms)?;
            } else {
                // A recorded cancellation or already closed reservation is a
                // control obligation for the original actor. Method revocation
                // must not hide that specific call's terminal evidence.
                current_peer(txn, request.authenticated_origin)?;
            }
            let result = inspection(txn, request.call, &row, now_ms)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(result)
        })
    }

    fn cancel_call(
        &self,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Result<CallCancelled, FederationError> {
        self.decision_peer(request.authenticated_origin)?;
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            check_time(txn, now_ms)?;
            let mut row = read_call(txn, &request.call.id)?.ok_or(FederationError::NotFound)?;
            actor_matches(&row, request.authenticated_origin, &request.subject)?;
            current_peer(txn, request.authenticated_origin)?;
            if let Some(receipt) = row
                .cancellations
                .iter()
                .find(|receipt| receipt.request_id == *request.control_request_id.as_bytes())
            {
                return if receipt.expected_revision == request.expected_control_revision {
                    let result = CallCancelled {
                        control_request_id: request.control_request_id,
                        call: request.call,
                        status: receipt.status.into(),
                        control_revision: receipt.control_revision,
                        cancellation_requested: receipt.cancellation_requested,
                        kernel_cancel_accepted: receipt.kernel_cancel_accepted,
                        execution_stopped: receipt.execution_stopped,
                    };
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)?;
                    Ok(result)
                } else {
                    Err(FederationError::Conflict)
                };
            }
            if row.cancellations.len() >= MAX_CANCEL_RECEIPTS {
                return Err(FederationError::Capacity);
            }
            if request
                .expected_control_revision
                .is_some_and(|expected| expected != row.control_revision)
            {
                return Err(FederationError::Conflict);
            }
            match row.status {
                StoredStatus::Reserved => {
                    row.status = StoredStatus::Closed;
                    row.execution_stopped = true;
                }
                StoredStatus::Preparing | StoredStatus::Accepted => {
                    row.cancellation_requested = true
                }
                StoredStatus::Finished | StoredStatus::Closed => {}
            }
            row.control_revision = row
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            let cancelled = CallCancelled {
                control_request_id: request.control_request_id,
                call: request.call,
                status: row.status.into(),
                control_revision: row.control_revision,
                cancellation_requested: row.cancellation_requested,
                kernel_cancel_accepted: row.kernel_cancel_accepted,
                execution_stopped: row.execution_stopped,
            };
            row.cancellations.push(StoredCancel {
                request_id: *request.control_request_id.as_bytes(),
                expected_revision: request.expected_control_revision,
                status: row.status,
                control_revision: row.control_revision,
                cancellation_requested: row.cancellation_requested,
                kernel_cancel_accepted: row.kernel_cancel_accepted,
                execution_stopped: row.execution_stopped,
            });
            write_call(txn, &request.call.id, &row)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(cancelled)
        })
    }
}
