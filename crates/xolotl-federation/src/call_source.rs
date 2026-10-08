//! Durable source-side ordering for effectful federated calls. The target
//! directory alone cannot recover an origin that forgot its request or CallRef.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::{Arc, Mutex};

use sha2::{Digest as _, Sha384};

use crate::{
    CallCancelled, CallInspection, CallPrepared, CallStatus, CancelCallRequest, Digest,
    FederationError, FederationNodeId, MAX_CALL_INPUT_BYTES, MAX_CALL_UNRESOLVED_EFFECT_IDS,
    PersistedCallResult, PrepareCallRequest, RequestId,
};
use xolotl_types::OperationId;

const CANCEL_REQUEST_DOMAIN: &[u8] = b"xolotl/federation/v1/source-cancel-request\0";

/// Maximum aggregate input payload bytes returned by one outbound page.
pub const MAX_OUTBOUND_PAGE_INPUT_BYTES: usize = MAX_CALL_INPUT_BYTES;
/// Maximum terminal output payload bytes retained by one outbound call.
pub const MAX_OUTBOUND_RESULT_BYTES: usize = 1024 * 1024;

/// A permanent origin marker survives removal of the larger settled call row.
/// Retired operations must never emit another Prepare when an application
/// presents their original OperationId again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundOriginState {
    /// The origin binding is live and may resume its one call.
    Active,
    /// The operation is fenced permanently against a new Prepare.
    Retired,
}

/// Read-only evidence for one original source operation in a consistent view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundOriginEvidence {
    /// No binding, call row, retirement marker or cancellation fence exists.
    Fresh,
    /// Original identity evidence exists; absence of a call row is not fresh work.
    Recorded,
    /// Retirement or cancellation permanently fences a new Prepare.
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Immutable source-side intent to invoke one target method.
pub struct OutboundCallIntent {
    /// Node that owns the target export and call identity.
    pub target_node: FederationNodeId,
    /// Preparation request with the stable origin identity and deadlines.
    pub request: PrepareCallRequest,
    /// Input retained for retries and crash reconciliation.
    pub input: Arc<[u8]>,
}

impl OutboundCallIntent {
    /// Verify origin identity, input size and digest against preparation.
    pub fn validate(
        &self,
        local_node: FederationNodeId,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        if self.request.authenticated_origin != local_node {
            return Err(FederationError::Unauthorized);
        }
        self.request.validate(self.target_node, now_ms)?;
        if self.input.len() > MAX_CALL_INPUT_BYTES {
            return Err(FederationError::Capacity);
        }
        if self.input.len() as u64 != self.request.input_bytes
            || self.request.input_digest.as_bytes() != Sha384::digest(&self.input).as_slice()
        {
            return Err(FederationError::Invalid(
                "outbound input differs from preparation",
            ));
        }
        Ok(())
    }

    /// Return the stable request identity used for all source retries.
    pub fn request_id(&self) -> RequestId {
        self.request.origin_request_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Durable source-side progress for one effectful remote call.
pub struct OutboundCallRecord {
    /// Immutable intent bound to this source record.
    pub intent: OutboundCallIntent,
    /// Target reservation, once its response is durably bound.
    pub prepared: Option<CallPrepared>,
    /// Persisted before the first Invoke send. Once true, recovery may only
    /// retry or inspect the same CallRef, never prepare a replacement.
    pub invoke_possible: bool,
    /// Retained terminal inspection, once the outcome is known.
    pub terminal: Option<CallInspection>,
    /// Fixed before acknowledging a Kernel cancellation handoff. A missing
    /// CallRef still requires reconciling the original Prepare request.
    pub cancellation_requested: bool,
    /// The target's answer to this source's stable Cancel control request.
    pub cancel_acknowledged: Option<CallCancelled>,
}

impl OutboundCallRecord {
    /// A proven business terminal has ended remote execution and effects.
    /// This does not prove local consumption or cleanup has completed.
    fn responsibility_can_end(&self) -> bool {
        self.terminal.as_ref().is_some_and(|terminal| {
            matches!(terminal.status, CallStatus::Finished | CallStatus::Closed)
                && terminal.execution_stopped
                && terminal.unresolved_effect_ids.is_empty()
                && (!self.cancellation_requested || self.cancel_acknowledged.is_some())
        })
    }

    /// Mark this live record for cancellation without losing its identity.
    pub fn request_cancellation(&mut self) {
        if self.terminal.is_none() {
            self.cancellation_requested = true;
        }
    }

    /// Build the same control request after every restart or lost response.
    /// There is no CallRef to address until the original Prepare is reconciled.
    pub fn cancel_request(&self) -> Option<CancelCallRequest> {
        if !self.cancellation_requested
            || self.cancel_acknowledged.is_some()
            || self.terminal.is_some()
        {
            return None;
        }
        let prepared = self.prepared.as_ref()?;
        if prepared.status == CallStatus::Closed {
            return None;
        }
        let mut digest = Sha384::new();
        digest.update(CANCEL_REQUEST_DOMAIN);
        digest.update(self.intent.request.authenticated_origin.as_bytes());
        digest.update(self.intent.request_id().as_bytes());
        let hash = digest.finalize();
        let mut control = [0; 16];
        control.copy_from_slice(&hash[..16]);
        Some(CancelCallRequest {
            authenticated_origin: self.intent.request.authenticated_origin,
            subject: self.intent.request.subject.clone(),
            control_request_id: RequestId::from_bytes(control),
            call: prepared.call,
            // Invoke and Kernel acceptance may already have advanced the
            // target revision beyond the Prepare receipt. Cancellation is
            // unconditional for the original authorized CallRef; the stable
            // control ID still makes a lost response safe to replay.
            expected_control_revision: None,
        })
    }

    /// Accept the target response to this record’s stable control request.
    pub fn record_cancellation(&mut self, response: CallCancelled) -> Result<(), FederationError> {
        if let Some(existing) = self.cancel_acknowledged {
            return if existing == response {
                Ok(())
            } else {
                Err(FederationError::Conflict)
            };
        }
        let request = self.cancel_request().ok_or(FederationError::Conflict)?;
        let prepared_revision = self
            .prepared
            .as_ref()
            .ok_or(FederationError::Conflict)?
            .control_revision;
        if response.control_request_id != request.control_request_id
            || response.call != request.call
            || response.status == CallStatus::Unproven
            || response.control_revision <= prepared_revision
        {
            return Err(FederationError::Conflict);
        }
        self.cancel_acknowledged = Some(response);
        Ok(())
    }

    /// Bind an exact target reservation, rejecting a conflicting replay.
    pub fn bind(&mut self, prepared: CallPrepared) -> Result<(), FederationError> {
        if prepared.origin_request_id != self.intent.request_id()
            || prepared.call.target != self.intent.target_node
            || prepared.call.id == [0; 32]
            || prepared.reserved_until_ms > self.intent.request.prepare_deadline_ms
            || prepared.execution_deadline_ms > self.intent.request.execution_deadline_ms
            || prepared.result_retention_ms > self.intent.request.result_retention_ms
            || prepared.authority_revision == 0
            || prepared.control_revision == 0
            || prepared.status == CallStatus::Unproven
        {
            return Err(FederationError::Conflict);
        }
        if let Some(existing) = &self.prepared {
            if existing != &prepared {
                return Err(FederationError::Conflict);
            }
        } else {
            self.prepared = Some(prepared);
        }
        Ok(())
    }

    /// Persist that an Invoke may have been sent before sending it.
    pub fn mark_invoke_possible(&mut self, now_ms: u64) -> Result<(), FederationError> {
        if self.cancellation_requested {
            return Err(FederationError::Conflict);
        }
        let prepared = self.prepared.as_ref().ok_or(FederationError::Conflict)?;
        if self.terminal.is_some() || prepared.status == CallStatus::Closed {
            return Err(FederationError::Conflict);
        }
        if !self.invoke_possible {
            if now_ms >= prepared.reserved_until_ms || now_ms >= prepared.execution_deadline_ms {
                return Err(FederationError::Conflict);
            }
            self.invoke_possible = true;
        }
        Ok(())
    }

    /// Persist a verified terminal inspection for this call.
    pub fn settle(&mut self, mut terminal: CallInspection) -> Result<(), FederationError> {
        let prepared = self.prepared.as_ref().ok_or(FederationError::Conflict)?;
        if terminal.call != prepared.call
            || !matches!(terminal.status, CallStatus::Finished | CallStatus::Closed)
            || terminal.control_revision < prepared.control_revision
            || (terminal.status == CallStatus::Finished && !self.invoke_possible)
            || (terminal.status == CallStatus::Finished && terminal.result.is_none())
        {
            return Err(FederationError::Conflict);
        }
        if terminal.unresolved_effect_ids.len() > MAX_CALL_UNRESOLVED_EFFECT_IDS {
            return Err(FederationError::Capacity);
        }
        if let Some(result) = &terminal.result {
            validate_terminal_result(result)?;
        }
        if let Some(existing) = &self.terminal {
            if existing != &terminal {
                return Err(FederationError::Conflict);
            }
        } else {
            terminal.unresolved_effect_ids =
                terminal.unresolved_effect_ids.into_boxed_slice().into_vec();
            self.terminal = Some(terminal);
        }
        Ok(())
    }
}

fn validate_terminal_result(result: &PersistedCallResult) -> Result<(), FederationError> {
    if result.output.len() > MAX_OUTBOUND_RESULT_BYTES {
        return Err(FederationError::Capacity);
    }
    result.verify()
}

#[derive(Default)]
struct MemoryOutboundCalls {
    records: BTreeMap<RequestId, OutboundCallRecord>,
    unsettled: BTreeSet<RequestId>,
    cancellations: BTreeSet<RequestId>,
    charged_payload_bytes: usize,
}

impl MemoryOutboundCalls {
    fn refresh_work(&mut self, request_id: RequestId) -> Result<(), FederationError> {
        let row = self
            .records
            .get(&request_id)
            .ok_or(FederationError::Corrupt)?;
        if row.terminal.is_none() {
            self.unsettled.insert(request_id);
        } else {
            self.unsettled.remove(&request_id);
        }
        if row.terminal.is_none() && row.cancellation_requested && row.cancel_acknowledged.is_none()
        {
            self.cancellations.insert(request_id);
        } else {
            self.cancellations.remove(&request_id);
        }
        Ok(())
    }

    fn page(
        &self,
        index: &BTreeSet<RequestId>,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError> {
        let mut page = Vec::new();
        let mut remaining = MAX_OUTBOUND_PAGE_INPUT_BYTES;
        for request_id in index
            .range((after.map_or(Unbounded, Excluded), Unbounded))
            .take(max)
        {
            let row = self
                .records
                .get(request_id)
                .ok_or(FederationError::Corrupt)?;
            let bytes = row.intent.input.len();
            if bytes > remaining {
                break;
            }
            remaining -= bytes;
            page.push(row.clone());
        }
        Ok(page)
    }
}

/// Implementations commit each transition before the caller emits the next
/// wire message. Indeterminate writes are reconciled by loading the same ID.
pub trait FederationOutboundCallStore: Send + Sync {
    /// Bind remote response evidence to the source ledger's commit domain.
    fn bind_outbound_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<Arc<dyn FederationOutboundCallStore>, FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Release the original operation only after consuming its result and
    /// completing local cleanup, with no live consumer needing its payloads.
    /// Implementations require a proven, stopped terminal, no unresolved
    /// effects and no unacknowledged source cancellation. This is idempotent;
    /// an indeterminate commit is retried with the same identity. Release may
    /// permit later payload retirement, but must retain the replay barrier.
    fn release_outbound_responsibility(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<(), FederationError>;
    /// Return the local origin node owned by this store.
    fn local_node(&self) -> FederationNodeId;
    /// Observe the exact operation's binding and replay fences without mutation
    /// or payload reads. Evidence is not authorization for subsequent dispatch.
    fn outbound_origin_evidence(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<OutboundOriginEvidence, FederationError>;
    /// Pin a source operation to its exact local binding before preparing it.
    /// This record outlives the call result: replaying the same operation after
    /// a binding or route change must not create a second remote effect.
    fn bind_outbound_origin(
        &self,
        request_id: RequestId,
        operation: OperationId,
        binding: Digest,
    ) -> Result<OutboundOriginState, FederationError>;
    /// Durably fence this OperationId before acknowledging the Kernel signal.
    /// None means there is no live source call to control; the fence still
    /// prevents a racing driver from starting one under the same identity.
    fn stage_outbound_cancellation(
        &self,
        operation: OperationId,
    ) -> Result<Option<RequestId>, FederationError>;
    /// Keyset page of accepted controls still requiring target reconciliation,
    /// bounded by 32 rows and MAX_OUTBOUND_PAGE_INPUT_BYTES. Short pages continue
    /// after their last request ID; only an empty page ends the current scan.
    fn pending_outbound_cancellations(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError>;
    /// Persist the target's idempotent response to the fixed control ID.
    fn record_outbound_cancellation(
        &self,
        request_id: RequestId,
        response: CallCancelled,
    ) -> Result<OutboundCallRecord, FederationError>;
    /// Stage the original call intent before sending Prepare.
    fn stage_outbound(
        &self,
        intent: OutboundCallIntent,
        now_ms: u64,
    ) -> Result<OutboundCallRecord, FederationError>;
    /// Bind the target’s Prepare receipt to the staged source record.
    fn bind_outbound_prepared(
        &self,
        request_id: RequestId,
        prepared: CallPrepared,
    ) -> Result<OutboundCallRecord, FederationError>;
    /// Fence the record before a possible first Invoke send.
    fn mark_outbound_invoke_possible(
        &self,
        request_id: RequestId,
        now_ms: u64,
    ) -> Result<OutboundCallRecord, FederationError>;
    /// Persist the terminal target inspection for this source call.
    fn settle_outbound(
        &self,
        request_id: RequestId,
        terminal: CallInspection,
    ) -> Result<OutboundCallRecord, FederationError>;
    /// Load one source call by its stable origin request ID.
    fn outbound_call(&self, request_id: RequestId) -> Result<OutboundCallRecord, FederationError>;
    /// Lexicographic keyset page, max 32 rows and MAX_OUTBOUND_PAGE_INPUT_BYTES.
    /// The last returned request ID is the next page's exclusive cursor;
    /// settled records are omitted, and a short nonempty page is not scan end.
    fn unsettled_outbound(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError>;
}

/// In-memory implementation for tests and ephemeral embeddings.
pub struct MemoryFederationOutboundCallStore {
    node: FederationNodeId,
    payload_budget: NonZeroUsize,
    calls: Mutex<MemoryOutboundCalls>,
    origins: Mutex<BTreeMap<RequestId, (OperationId, Digest, bool)>>,
    cancel_barriers: Mutex<BTreeSet<OperationId>>,
    trusted_time_ms: Mutex<u64>,
}

impl MemoryFederationOutboundCallStore {
    /// Create a transient source with a logical input/output byte budget.
    pub fn new(node: FederationNodeId, payload_budget: NonZeroUsize) -> Self {
        Self {
            node,
            payload_budget,
            calls: Mutex::new(MemoryOutboundCalls::default()),
            origins: Mutex::new(BTreeMap::new()),
            cancel_barriers: Mutex::new(BTreeSet::new()),
            trusted_time_ms: Mutex::new(0),
        }
    }

    fn time(&self, now_ms: u64) -> Result<(), FederationError> {
        let mut last = self
            .trusted_time_ms
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if now_ms < *last {
            return Err(FederationError::ClockRollback);
        }
        *last = now_ms;
        Ok(())
    }
}

impl FederationOutboundCallStore for MemoryFederationOutboundCallStore {
    fn release_outbound_responsibility(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<(), FederationError> {
        let mut origins = self
            .origins
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let origin = origins
            .get_mut(&request_id)
            .ok_or(FederationError::NotFound)?;
        if origin.0 != operation {
            return Err(FederationError::Conflict);
        }
        if origin.2 {
            return Ok(());
        }
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let record = calls
            .records
            .get(&request_id)
            .ok_or(FederationError::Conflict)?;
        if !record.responsibility_can_end() {
            return Err(FederationError::Conflict);
        }
        let payload_bytes = record.intent.input.len()
            + record
                .terminal
                .as_ref()
                .and_then(|terminal| terminal.result.as_ref())
                .map_or(0, |result| result.output.len());
        let remaining = calls
            .charged_payload_bytes
            .checked_sub(payload_bytes)
            .ok_or(FederationError::Corrupt)?;
        calls.records.remove(&request_id);
        calls.unsettled.remove(&request_id);
        calls.cancellations.remove(&request_id);
        calls.charged_payload_bytes = remaining;
        origin.2 = true;
        Ok(())
    }

    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn outbound_origin_evidence(
        &self,
        request_id: RequestId,
        operation: OperationId,
    ) -> Result<OutboundOriginEvidence, FederationError> {
        let barriers = self
            .cancel_barriers
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let origins = self
            .origins
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let origin = origins.get(&request_id);
        if origin.is_some_and(|(saved, _binding, _released)| *saved != operation) {
            return Err(FederationError::Conflict);
        }
        Ok(
            if barriers.contains(&operation)
                || origin.is_some_and(|(_saved, _binding, retired)| *retired)
            {
                OutboundOriginEvidence::Retired
            } else if origin.is_some() || calls.records.contains_key(&request_id) {
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
        let barriers = self
            .cancel_barriers
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let mut origins = self
            .origins
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if let Some(existing) = origins.get(&request_id) {
            return if (existing.0, existing.1) == (operation, binding) {
                Ok(if existing.2 || barriers.contains(&operation) {
                    OutboundOriginState::Retired
                } else {
                    OutboundOriginState::Active
                })
            } else {
                Err(FederationError::Conflict)
            };
        }
        if barriers.contains(&operation) {
            return Ok(OutboundOriginState::Retired);
        }
        if origins.len() >= 100_000 {
            return Err(FederationError::Capacity);
        }
        origins.insert(request_id, (operation, binding, false));
        Ok(OutboundOriginState::Active)
    }

    fn stage_outbound_cancellation(
        &self,
        operation: OperationId,
    ) -> Result<Option<RequestId>, FederationError> {
        let mut barriers = self
            .cancel_barriers
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if !barriers.contains(&operation) {
            if barriers.len() >= 100_000 {
                return Err(FederationError::Capacity);
            }
            barriers.insert(operation);
        }
        let origins = self
            .origins
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let request_id = origins
            .iter()
            .find_map(|(id, (saved, _binding, _released))| (*saved == operation).then_some(*id));
        let Some(request_id) = request_id else {
            return Ok(None);
        };
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let Some(row) = calls.records.get_mut(&request_id) else {
            return Ok(None);
        };
        if row.terminal.is_some() {
            return Ok(None);
        }
        row.request_cancellation();
        calls.refresh_work(request_id)?;
        Ok(Some(request_id))
    }

    fn pending_outbound_cancellations(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError> {
        if max == 0 || max > 32 {
            return Err(FederationError::Invalid(
                "invalid outbound cancellation page size",
            ));
        }
        let calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        calls.page(&calls.cancellations, after, max)
    }

    fn record_outbound_cancellation(
        &self,
        request_id: RequestId,
        response: CallCancelled,
    ) -> Result<OutboundCallRecord, FederationError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let row = calls
            .records
            .get_mut(&request_id)
            .ok_or(FederationError::NotFound)?;
        row.record_cancellation(response)?;
        let result = row.clone();
        calls.refresh_work(request_id)?;
        Ok(result)
    }

    fn stage_outbound(
        &self,
        intent: OutboundCallIntent,
        now_ms: u64,
    ) -> Result<OutboundCallRecord, FederationError> {
        intent.validate(self.node, now_ms)?;
        self.time(now_ms)?;
        let barriers = self
            .cancel_barriers
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let origins = self
            .origins
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if origins
            .get(&intent.request_id())
            .is_some_and(|(operation, _binding, retired)| *retired || barriers.contains(operation))
        {
            return Err(FederationError::Conflict);
        }
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if let Some(existing) = calls.records.get(&intent.request_id()) {
            return if existing.intent == intent {
                Ok(existing.clone())
            } else {
                Err(FederationError::Conflict)
            };
        }
        if calls.records.len() >= 100_000 {
            return Err(FederationError::Capacity);
        }
        let charge = intent
            .input
            .len()
            .checked_add(MAX_OUTBOUND_RESULT_BYTES)
            .ok_or(FederationError::Capacity)?;
        let charged_payload_bytes = calls
            .charged_payload_bytes
            .checked_add(charge)
            .filter(|bytes| *bytes <= self.payload_budget.get())
            .ok_or(FederationError::Capacity)?;
        let record = OutboundCallRecord {
            intent,
            prepared: None,
            invoke_possible: false,
            terminal: None,
            cancellation_requested: false,
            cancel_acknowledged: None,
        };
        calls
            .records
            .insert(record.intent.request_id(), record.clone());
        calls.charged_payload_bytes = charged_payload_bytes;
        calls.refresh_work(record.intent.request_id())?;
        Ok(record)
    }

    fn bind_outbound_prepared(
        &self,
        request_id: RequestId,
        prepared: CallPrepared,
    ) -> Result<OutboundCallRecord, FederationError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let row = calls
            .records
            .get_mut(&request_id)
            .ok_or(FederationError::NotFound)?;
        row.bind(prepared)?;
        Ok(row.clone())
    }

    fn mark_outbound_invoke_possible(
        &self,
        request_id: RequestId,
        now_ms: u64,
    ) -> Result<OutboundCallRecord, FederationError> {
        self.time(now_ms)?;
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let row = calls
            .records
            .get_mut(&request_id)
            .ok_or(FederationError::NotFound)?;
        row.mark_invoke_possible(now_ms)?;
        Ok(row.clone())
    }

    fn settle_outbound(
        &self,
        request_id: RequestId,
        terminal: CallInspection,
    ) -> Result<OutboundCallRecord, FederationError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let charged = calls.charged_payload_bytes;
        let row = calls
            .records
            .get_mut(&request_id)
            .ok_or(FederationError::NotFound)?;
        let charge_without_reserve = if row.terminal.is_none() {
            Some(
                charged
                    .checked_sub(MAX_OUTBOUND_RESULT_BYTES)
                    .ok_or(FederationError::Corrupt)?,
            )
        } else {
            None
        };
        let result_bytes = terminal
            .result
            .as_ref()
            .map_or(0, |result| result.output.len());
        row.settle(terminal)?;
        let result = row.clone();
        if let Some(base) = charge_without_reserve {
            calls.charged_payload_bytes = base + result_bytes;
        }
        calls.refresh_work(request_id)?;
        Ok(result)
    }

    fn outbound_call(&self, request_id: RequestId) -> Result<OutboundCallRecord, FederationError> {
        let calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        calls
            .records
            .get(&request_id)
            .cloned()
            .ok_or(FederationError::NotFound)
    }

    fn unsettled_outbound(
        &self,
        after: Option<RequestId>,
        max: usize,
    ) -> Result<Vec<OutboundCallRecord>, FederationError> {
        if max == 0 || max > 32 {
            return Err(FederationError::Invalid("invalid outbound page size"));
        }
        let calls = self
            .calls
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        calls.page(&calls.unsettled, after, max)
    }
}
