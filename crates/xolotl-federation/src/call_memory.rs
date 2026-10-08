//! Volatile reference directory for call state-machine contract tests.
//! Production callers need the same transitions in a durable store and an
//! idempotent Kernel acceptance bridge.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

use crate::{
    CallAuthorityEntry, CallAuthorityKey, CallAuthorityRule, CallCancelled, CallInspection,
    CallInvoked, CallKernelBinding, CallKernelView, CallPrepared, CallRef, CallStatus,
    CancelCallRequest, Digest, FederationCallStore, FederationError, FederationNodeId,
    InspectCallRequest, InvokeCallRequest, MAX_CALL_INPUT_BYTES, MAX_CALL_UNRESOLVED_EFFECT_IDS,
    PersistedCallResult, PrepareCallRequest, RequestId,
};

const MAX_CALL_ROWS: usize = 100_000;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

#[cfg(test)]
mod local_clock_tests {
    use super::*;
    use anyhow::{Result, ensure};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn bound_call_clock_is_sampled_under_shared_lock_and_rejects_rollback() -> Result<()> {
        let node = FederationNodeId::from_bytes([93; 48]);
        let store = Arc::new(MemoryFederationCallStore::new(node));
        store.lock()?.time(200)?;
        let time = Arc::new(AtomicU64::new(210));
        let clock_store = Arc::clone(&store);
        let clock_time = Arc::clone(&time);
        let bound = store.bind_local_call_clock(Arc::new(move || {
            if clock_store.state.try_lock().is_ok() {
                return Err(FederationError::Corrupt);
            }
            Ok(clock_time.load(Ordering::SeqCst))
        }))?;
        let request = InspectCallRequest {
            authenticated_origin: FederationNodeId::from_bytes([94; 48]),
            subject: crate::FederationSubject::Node(FederationNodeId::from_bytes([94; 48])),
            call: CallRef::new(node, [95; 32])?,
        };
        ensure!(matches!(
            store.inspect_call(request.clone(), 100),
            Err(FederationError::ClockRollback)
        ));
        ensure!(bound.inspect_call(request.clone(), 100)?.status == CallStatus::Unproven);
        ensure!(store.lock()?.last_time_ms == 210);
        time.store(209, Ordering::SeqCst);
        ensure!(matches!(
            bound.inspect_call(request, 100),
            Err(FederationError::ClockRollback)
        ));
        ensure!(matches!(
            bound.bind_local_call_clock(Arc::new(|| Ok(210))),
            Err(FederationError::Unauthorized)
        ));
        Ok(())
    }
}

struct GrantRow {
    rule: CallAuthorityRule,
    revision: u64,
}

struct CallRow {
    request: PrepareCallRequest,
    prepared: CallPrepared,
    input: Option<std::sync::Arc<[u8]>>,
    binding: Option<CallKernelBinding>,
    accepted_digest: Option<Digest>,
    result: Option<PersistedCallResult>,
    result_retained_until_ms: u64,
    unresolved_effect_ids: Vec<[u8; 32]>,
    cancellation_requested: bool,
    kernel_cancel_accepted: bool,
    execution_stopped: bool,
    cancellations: HashMap<RequestId, (CancelCallRequest, CallCancelled)>,
}

impl CallRow {
    fn inspect(&self, now_ms: u64) -> CallInspection {
        CallInspection {
            call: self.prepared.call,
            status: self.prepared.status,
            control_revision: self.prepared.control_revision,
            authority_revision: self.prepared.authority_revision,
            reserved_until_ms: self.prepared.reserved_until_ms,
            execution_deadline_ms: self.prepared.execution_deadline_ms,
            result_retained_until_ms: self.result_retained_until_ms,
            result: if now_ms < self.result_retained_until_ms {
                self.result.clone()
            } else {
                None
            },
            unresolved_effect_ids: self.unresolved_effect_ids.clone(),
            cancellation_requested: self.cancellation_requested,
            kernel_cancel_accepted: self.kernel_cancel_accepted,
            execution_stopped: self.execution_stopped,
        }
    }

    fn check_actor(
        &self,
        origin: FederationNodeId,
        subject: &crate::FederationSubject,
    ) -> Result<(), FederationError> {
        if self.request.authenticated_origin != origin || &self.request.subject != subject {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Default)]
struct State {
    grants: BTreeMap<Vec<u8>, GrantRow>,
    calls: BTreeMap<[u8; 32], CallRow>,
    source_requests: HashMap<(FederationNodeId, RequestId), [u8; 32]>,
    last_time_ms: u64,
}

impl State {
    fn time(&mut self, now_ms: u64) -> Result<(), FederationError> {
        if now_ms < self.last_time_ms {
            return Err(FederationError::ClockRollback);
        }
        self.last_time_ms = now_ms;
        Ok(())
    }

    fn grant(
        &self,
        request: &PrepareCallRequest,
        now_ms: u64,
    ) -> Result<&GrantRow, FederationError> {
        let key = CallAuthorityKey {
            subject: request.subject.clone(),
            presenter: request.authenticated_origin,
            target: request.target.clone(),
        }
        .encoded()?;
        let grant = self.grants.get(&key).ok_or(FederationError::Unauthorized)?;
        if !grant.rule.enabled
            || now_ms >= grant.rule.expires_ms
            || request.input_bytes > grant.rule.max_input_bytes
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(grant)
    }

    fn current_grant(&self, row: &CallRow, now_ms: u64) -> Result<(), FederationError> {
        let grant = self.grant(&row.request, now_ms)?;
        if grant.revision != row.prepared.authority_revision {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }
}

/// Memory-only call directory. A complete host must install a durable store
/// before advertising calls that survive process restart.
pub struct MemoryFederationCallStore {
    node: FederationNodeId,
    state: Arc<Mutex<State>>,
    local_clock: Option<Arc<dyn crate::FederationObjectClock>>,
}

impl MemoryFederationCallStore {
    /// Create a transient call directory bound to one node for contract tests.
    pub fn new(node: FederationNodeId) -> Self {
        Self {
            node,
            state: Arc::new(Mutex::new(State::default())),
            local_clock: None,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, FederationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        if let Some(clock) = &self.local_clock {
            state.time(clock.now_ms()?)?;
        }
        Ok(state)
    }

    fn lock_at(&self, fallback_ms: u64) -> Result<(MutexGuard<'_, State>, u64), FederationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| FederationError::Corrupt)?;
        let now_ms = if let Some(clock) = &self.local_clock {
            clock.now_ms()?
        } else {
            fallback_ms
        };
        state.time(now_ms)?;
        Ok((state, now_ms))
    }
}

impl FederationCallStore for MemoryFederationCallStore {
    fn bind_local_call_clock(
        &self,
        clock: Arc<dyn crate::FederationObjectClock>,
    ) -> Result<Arc<dyn FederationCallStore>, FederationError> {
        if self.local_clock.is_some() {
            return Err(FederationError::Unauthorized);
        }
        Ok(Arc::new(Self {
            node: self.node,
            state: Arc::clone(&self.state),
            local_clock: Some(clock),
        }))
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
        let key = CallAuthorityKey::from_rule(&rule).encoded()?;
        let mut state = self.lock()?;
        let current = state.grants.get(&key).map(|row| row.revision);
        if current.is_none() && state.grants.len() >= MAX_CALL_ROWS {
            return Err(FederationError::Capacity);
        }
        if current != expected_revision {
            return Err(FederationError::Conflict);
        }
        let next = current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        state.grants.insert(
            key,
            GrantRow {
                rule,
                revision: next,
            },
        );
        Ok(next)
    }

    fn call_authority(
        &self,
        key: &CallAuthorityKey,
    ) -> Result<Option<CallAuthorityEntry>, FederationError> {
        let key = key.encoded()?;
        let state = self.lock()?;
        Ok(state.grants.get(&key).map(|row| CallAuthorityEntry {
            revision: row.revision,
            rule: row.rule.clone(),
        }))
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
        let state = self.lock()?;
        let mut entries = Vec::with_capacity(max);
        for (key, row) in &state.grants {
            if after.as_ref().is_some_and(|after| key <= after) {
                continue;
            }
            entries.push(CallAuthorityEntry {
                revision: row.revision,
                rule: row.rule.clone(),
            });
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
        let state = self.lock()?;
        let Some(id) = state
            .source_requests
            .get(&(request.authenticated_origin, request.origin_request_id))
        else {
            return Ok(None);
        };
        let saved = state.calls.get(id).ok_or(FederationError::Corrupt)?;
        if saved.request != *request {
            return Err(FederationError::Conflict);
        }
        Ok(Some(saved.prepared.clone()))
    }

    fn prepare_call(
        &self,
        request: PrepareCallRequest,
        now_ms: u64,
    ) -> Result<CallPrepared, FederationError> {
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        if let Some(id) = state
            .source_requests
            .get(&(request.authenticated_origin, request.origin_request_id))
        {
            let saved = state.calls.get(id).ok_or(FederationError::Corrupt)?;
            return if saved.request == request {
                Ok(saved.prepared.clone())
            } else {
                Err(FederationError::Conflict)
            };
        }
        request.validate(self.node, now_ms)?;
        let grant = state.grant(&request, now_ms)?;
        let grant_revision = grant.revision;
        let reserved_until_ms = request
            .prepare_deadline_ms
            .min(grant.rule.expires_ms)
            .min(now_ms.saturating_add(grant.rule.max_prepare_window_ms));
        let result_retention_ms = request
            .result_retention_ms
            .min(grant.rule.max_result_retention_ms);
        if reserved_until_ms <= now_ms {
            return Err(FederationError::Unauthorized);
        }
        if state.calls.len() >= MAX_CALL_ROWS {
            return Err(FederationError::Capacity);
        }
        let rng = SystemRandom::new();
        let id = (0..4)
            .find_map(|_attempt| {
                let mut id = [0; 32];
                rng.fill(&mut id).ok()?;
                (id != [0; 32] && !state.calls.contains_key(&id)).then_some(id)
            })
            .ok_or(FederationError::Capacity)?;
        let call = CallRef::new(self.node, id)?;
        let prepared = CallPrepared {
            origin_request_id: request.origin_request_id,
            call,
            status: CallStatus::Reserved,
            reserved_until_ms,
            execution_deadline_ms: request.execution_deadline_ms,
            result_retention_ms,
            authority_revision: grant_revision,
            control_revision: 1,
        };
        state.source_requests.insert(
            (request.authenticated_origin, request.origin_request_id),
            id,
        );
        state.calls.insert(
            id,
            CallRow {
                request,
                prepared: prepared.clone(),
                input: None,
                binding: None,
                accepted_digest: None,
                result: None,
                result_retained_until_ms: 0,
                unresolved_effect_ids: Vec::new(),
                cancellation_requested: false,
                kernel_cancel_accepted: false,
                execution_stopped: false,
                cancellations: HashMap::new(),
            },
        );
        Ok(prepared)
    }

    fn invoke_call(
        &self,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Result<CallInvoked, FederationError> {
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        if request.input.len() > MAX_CALL_INPUT_BYTES {
            return Err(FederationError::Capacity);
        }
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        {
            let row = state
                .calls
                .get(&request.call.id)
                .ok_or(FederationError::NotFound)?;
            row.check_actor(request.authenticated_origin, &request.subject)?;
            state.current_grant(row, now_ms)?;
            if row.request.origin_request_id != request.origin_request_id
                || row.request.input_bytes != request.input.len() as u64
                || row.request.input_digest != request.input_digest()
            {
                return Err(FederationError::Conflict);
            }
        }
        let row = state
            .calls
            .get_mut(&request.call.id)
            .ok_or(FederationError::Corrupt)?;
        if row.prepared.status == CallStatus::Reserved {
            if now_ms >= row.prepared.reserved_until_ms {
                row.prepared.status = CallStatus::Closed;
                row.execution_stopped = true;
                row.prepared.control_revision = row
                    .prepared
                    .control_revision
                    .checked_add(1)
                    .ok_or(FederationError::Capacity)?;
                return Err(FederationError::Conflict);
            }
            row.prepared.status = CallStatus::Preparing;
            row.prepared.control_revision = row
                .prepared
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            row.input = Some(request.input);
        }
        if row.prepared.status == CallStatus::Closed {
            return Err(FederationError::Conflict);
        }
        Ok(CallInvoked {
            call: request.call,
            status: row.prepared.status,
            control_revision: row.prepared.control_revision,
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
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        {
            let row = state.calls.get(&call.id).ok_or(FederationError::NotFound)?;
            state.current_grant(row, now_ms)?;
        }
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::Corrupt)?;
        match row.binding {
            Some(existing) if existing == binding => Ok(existing),
            Some(_) => Err(FederationError::Conflict),
            None if row.prepared.status == CallStatus::Preparing
                && row.input.is_some()
                && !row.cancellation_requested
                && now_ms < row.prepared.execution_deadline_ms =>
            {
                row.binding = Some(binding);
                Ok(binding)
            }
            None => Err(FederationError::Conflict),
        }
    }

    fn kernel_call(&self, call: CallRef, now_ms: u64) -> Result<CallKernelView, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (state, _decision_time) = self.lock_at(now_ms)?;
        let row = state.calls.get(&call.id).ok_or(FederationError::NotFound)?;
        Ok(CallKernelView {
            call,
            request: row.request.clone(),
            status: row.prepared.status,
            input: row.input.clone(),
            binding: row.binding,
            accepted_digest: row.accepted_digest,
            cancellation_requested: row.cancellation_requested,
            kernel_cancel_accepted: row.kernel_cancel_accepted,
            execution_stopped: row.execution_stopped,
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
        let (state, now_ms) = self.lock_at(now_ms)?;
        let row = state.calls.get(&call.id).ok_or(FederationError::NotFound)?;
        if !matches!(
            row.prepared.status,
            CallStatus::Preparing | CallStatus::Accepted
        ) || row.binding.is_none()
            || row.cancellation_requested
            || now_ms >= row.prepared.execution_deadline_ms
        {
            return Err(FederationError::Conflict);
        }
        state.current_grant(row, now_ms)
    }

    fn close_unaccepted_call(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::NotFound)?;
        if row.prepared.status == CallStatus::Closed {
            return Ok(row.inspect(now_ms));
        }
        if row.prepared.status != CallStatus::Preparing || row.accepted_digest.is_some() {
            return Err(FederationError::Conflict);
        }
        row.prepared.status = CallStatus::Closed;
        row.execution_stopped = true;
        row.prepared.control_revision = row
            .prepared
            .control_revision
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        row.input = None;
        Ok(row.inspect(now_ms))
    }

    fn scan_pending_kernel_calls(
        &self,
        after: Option<[u8; 32]>,
        max: usize,
    ) -> Result<Vec<CallRef>, FederationError> {
        if max == 0 || max > 256 {
            return Err(FederationError::Invalid("invalid pending call page size"));
        }
        let state = self.lock()?;
        let ids: Vec<_> = state
            .calls
            .range((
                after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                std::ops::Bound::Unbounded,
            ))
            .filter(|(_, row)| {
                matches!(
                    row.prepared.status,
                    CallStatus::Preparing | CallStatus::Accepted
                ) || (row.prepared.status == CallStatus::Finished && !row.execution_stopped)
            })
            .take(max)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .map(|id| CallRef::new(self.node, id))
            .collect()
    }

    fn request_call_deadline_stop(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::NotFound)?;
        if now_ms < row.prepared.execution_deadline_ms
            || !matches!(
                row.prepared.status,
                CallStatus::Preparing | CallStatus::Accepted
            )
        {
            return Err(FederationError::Conflict);
        }
        if !row.cancellation_requested {
            row.cancellation_requested = true;
            row.prepared.control_revision = row
                .prepared
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
        }
        Ok(row.inspect(now_ms))
    }

    fn record_kernel_acceptance(
        &self,
        call: CallRef,
        acceptance_digest: Digest,
    ) -> Result<CallInvoked, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let mut state = self.lock()?;
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::NotFound)?;
        if row.prepared.status == CallStatus::Preparing && row.binding.is_some() {
            row.prepared.status = CallStatus::Accepted;
            row.prepared.control_revision = row
                .prepared
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            row.accepted_digest = Some(acceptance_digest);
        } else if row.accepted_digest != Some(acceptance_digest) {
            return Err(FederationError::Conflict);
        }
        Ok(CallInvoked {
            call,
            status: row.prepared.status,
            control_revision: row.prepared.control_revision,
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
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::NotFound)?;
        if !row.cancellation_requested || row.binding.is_none() {
            return Err(FederationError::Conflict);
        }
        if !row.kernel_cancel_accepted {
            row.kernel_cancel_accepted = true;
            row.prepared.control_revision = row
                .prepared
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
        }
        Ok(row.inspect(now_ms))
    }

    fn record_execution_stopped(
        &self,
        call: CallRef,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::NotFound)?;
        if row.binding.is_none()
            || row.prepared.status == CallStatus::Reserved
            || row.prepared.status == CallStatus::Closed
        {
            return Err(FederationError::Conflict);
        }
        if !row.execution_stopped {
            row.execution_stopped = true;
            row.prepared.control_revision = row
                .prepared
                .control_revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
        }
        Ok(row.inspect(now_ms))
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
        let (mut state, now_ms) = self.lock_at(now_ms)?;
        let row = state
            .calls
            .get_mut(&call.id)
            .ok_or(FederationError::NotFound)?;
        if row.prepared.status == CallStatus::Finished {
            return if row.result.as_ref() == Some(&result)
                && row.unresolved_effect_ids == unresolved_effect_ids
            {
                Ok(row.inspect(now_ms))
            } else {
                Err(FederationError::Conflict)
            };
        }
        if row.prepared.status != CallStatus::Accepted {
            return Err(FederationError::Conflict);
        }
        row.result_retained_until_ms = now_ms.saturating_add(row.prepared.result_retention_ms);
        row.result = Some(result);
        row.input = None;
        row.unresolved_effect_ids = unresolved_effect_ids;
        row.prepared.status = CallStatus::Finished;
        row.prepared.control_revision = row
            .prepared
            .control_revision
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        Ok(row.inspect(now_ms))
    }

    fn authorize_call_delivery(
        &self,
        request: &InspectCallRequest,
        retained_output_until_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let state = self.lock()?;
        if now_ms < state.last_time_ms {
            return Err(FederationError::ClockRollback);
        }
        let row = state
            .calls
            .get(&request.call.id)
            .ok_or(FederationError::NotFound)?;
        row.check_actor(request.authenticated_origin, &request.subject)?;
        if retained_output_until_ms.is_some_and(|deadline| {
            row.result.is_none() || row.result_retained_until_ms != deadline || now_ms >= deadline
        }) {
            return Err(FederationError::Unauthorized);
        }
        state.current_grant(row, now_ms)
    }

    fn inspect_call(
        &self,
        request: InspectCallRequest,
        now_ms: u64,
    ) -> Result<CallInspection, FederationError> {
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (state, now_ms) = self.lock_at(now_ms)?;
        let Some(row) = state.calls.get(&request.call.id) else {
            return Ok(CallInspection {
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
            });
        };
        row.check_actor(request.authenticated_origin, &request.subject)?;
        if row.cancellations.is_empty() && row.prepared.status != CallStatus::Closed {
            state.current_grant(row, now_ms)?;
        }
        Ok(row.inspect(now_ms))
    }

    fn cancel_call(
        &self,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Result<CallCancelled, FederationError> {
        if request.call.target != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (mut state, _decision_time) = self.lock_at(now_ms)?;
        {
            let row = state
                .calls
                .get(&request.call.id)
                .ok_or(FederationError::NotFound)?;
            row.check_actor(request.authenticated_origin, &request.subject)?;
        }
        let row = state
            .calls
            .get_mut(&request.call.id)
            .ok_or(FederationError::Corrupt)?;
        if let Some((previous, result)) = row.cancellations.get(&request.control_request_id) {
            return if previous == &request {
                Ok(*result)
            } else {
                Err(FederationError::Conflict)
            };
        }
        if request
            .expected_control_revision
            .is_some_and(|revision| revision != row.prepared.control_revision)
        {
            return Err(FederationError::Conflict);
        }
        match row.prepared.status {
            CallStatus::Reserved => {
                row.prepared.status = CallStatus::Closed;
                row.execution_stopped = true;
            }
            CallStatus::Preparing | CallStatus::Accepted => row.cancellation_requested = true,
            CallStatus::Finished | CallStatus::Closed => {}
            CallStatus::Unproven => return Err(FederationError::Corrupt),
        }
        row.prepared.control_revision = row
            .prepared
            .control_revision
            .checked_add(1)
            .ok_or(FederationError::Capacity)?;
        let result = CallCancelled {
            control_request_id: request.control_request_id,
            call: request.call,
            status: row.prepared.status,
            control_revision: row.prepared.control_revision,
            cancellation_requested: row.cancellation_requested,
            kernel_cancel_accepted: row.kernel_cancel_accepted,
            execution_stopped: row.execution_stopped,
        };
        row.cancellations
            .insert(request.control_request_id, (request, result));
        Ok(result)
    }
}
