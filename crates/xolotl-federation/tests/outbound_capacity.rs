use std::{num::NonZeroUsize, sync::Arc};

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallCancelled, CallInspection, CallMethod, CallPath, CallPrepared, CallRef, CallStatus,
    CallTarget, Digest, ExportName, FederationError, FederationNodeId, FederationOutboundCallStore,
    FederationSubject, MAX_CALL_INPUT_BYTES, MAX_CALL_UNRESOLVED_EFFECT_IDS,
    MAX_OUTBOUND_RESULT_BYTES, MemoryFederationOutboundCallStore, OutboundCallIntent,
    OutboundOriginEvidence, PersistedCallResult, PrepareCallRequest, RequestId,
};

fn intent(
    local: FederationNodeId,
    peer: FederationNodeId,
    id: u8,
    input: Arc<[u8]>,
) -> Result<OutboundCallIntent> {
    Ok(OutboundCallIntent {
        target_node: peer,
        request: PrepareCallRequest {
            authenticated_origin: local,
            subject: FederationSubject::Node(local),
            origin_request_id: RequestId::from_bytes([id; 16]),
            target: CallTarget {
                export: ExportName::new("tools")?,
                path: CallPath::new("/echo")?,
                method: CallMethod::new("echo")?,
                contract_digest: [3; 32],
            },
            input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
            input_bytes: input.len() as u64,
            prepare_deadline_ms: 200,
            execution_deadline_ms: 800,
            result_retention_ms: 300,
        },
        input,
    })
}

fn prepared(peer: FederationNodeId, id: u8) -> Result<CallPrepared> {
    Ok(CallPrepared {
        origin_request_id: RequestId::from_bytes([id; 16]),
        call: CallRef::new(peer, [id; 32])?,
        status: CallStatus::Reserved,
        reserved_until_ms: 200,
        execution_deadline_ms: 800,
        result_retention_ms: 300,
        authority_revision: 1,
        control_revision: 1,
    })
}

fn terminal(prepared: &CallPrepared, result: Option<PersistedCallResult>) -> CallInspection {
    CallInspection {
        call: prepared.call,
        status: if result.is_some() {
            CallStatus::Finished
        } else {
            CallStatus::Closed
        },
        control_revision: 2,
        authority_revision: 1,
        reserved_until_ms: prepared.reserved_until_ms,
        execution_deadline_ms: prepared.execution_deadline_ms,
        result_retained_until_ms: 1000,
        result,
        unresolved_effect_ids: Vec::new(),
        cancellation_requested: false,
        kernel_cancel_accepted: false,
        execution_stopped: true,
    }
}

#[test]
fn full_source_reserves_maximum_terminal_and_keeps_rejected_origin_evidence() -> Result<()> {
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let source = MemoryFederationOutboundCallStore::new(
        local,
        NonZeroUsize::new(MAX_CALL_INPUT_BYTES + MAX_OUTBOUND_RESULT_BYTES).context("budget")?,
    );
    let original = intent(local, peer, 10, Arc::from(vec![13; MAX_CALL_INPUT_BYTES]))?;
    let request_id = original.request_id();
    let staged = source.stage_outbound(original.clone(), 100)?;
    ensure!(source.stage_outbound(original.clone(), 100)? == staged);
    let changed = intent(local, peer, 10, Arc::from([]))?;
    ensure!(matches!(
        source.stage_outbound(changed, 100),
        Err(FederationError::Conflict)
    ));
    let shared = intent(local, peer, 11, Arc::clone(&original.input))?;
    ensure!(matches!(
        source.stage_outbound(shared, 100),
        Err(FederationError::Capacity)
    ));
    let rejected_id = RequestId::from_bytes([12; 16]);
    let operation = "1/2/3/4/5".parse()?;
    source.bind_outbound_origin(rejected_id, operation, Digest::from_bytes([4; 48]))?;
    let rejected: Arc<[u8]> = Arc::from(b"rejected".as_slice());
    let weak = Arc::downgrade(&rejected);
    ensure!(matches!(
        source.stage_outbound(intent(local, peer, 12, rejected)?, 100),
        Err(FederationError::Capacity)
    ));
    ensure!(weak.upgrade().is_none());
    ensure!(matches!(
        source.outbound_call(rejected_id),
        Err(FederationError::NotFound)
    ));
    ensure!(
        source.outbound_origin_evidence(rejected_id, operation)?
            == OutboundOriginEvidence::Recorded
    );
    ensure!(source.stage_outbound_cancellation(operation)?.is_none());
    ensure!(
        source.outbound_origin_evidence(rejected_id, operation)? == OutboundOriginEvidence::Retired
    );
    let prepared = prepared(peer, 10)?;
    source.bind_outbound_prepared(request_id, prepared.clone())?;
    source.mark_outbound_invoke_possible(request_id, 100)?;
    let output =
        PersistedCallResult::new(true, Arc::from(vec![17; MAX_OUTBOUND_RESULT_BYTES]), None)?;
    let mut result = terminal(&prepared, Some(output));
    result.unresolved_effect_ids = Vec::with_capacity(8192);
    result
        .unresolved_effect_ids
        .extend((0..MAX_CALL_UNRESOLVED_EFFECT_IDS).map(|index| [index as u8 + 1; 32]));
    let mut oversized = result.clone();
    oversized.result = Some(PersistedCallResult::new(
        true,
        Arc::from(vec![17; MAX_OUTBOUND_RESULT_BYTES + 1]),
        None,
    )?);
    ensure!(matches!(
        source.settle_outbound(request_id, oversized),
        Err(FederationError::Capacity)
    ));
    let mut unbounded = result.clone();
    unbounded.unresolved_effect_ids.push([255; 32]);
    ensure!(matches!(
        source.settle_outbound(request_id, unbounded),
        Err(FederationError::Capacity)
    ));
    ensure!(source.outbound_call(request_id)?.terminal.is_none());
    let mut retained = source.outbound_call(request_id)?;
    retained.settle(result)?;
    let result = retained.terminal.take().context("validated terminal")?;
    ensure!(result.unresolved_effect_ids.capacity() == MAX_CALL_UNRESOLVED_EFFECT_IDS);
    let settled = source.settle_outbound(request_id, result.clone())?;
    ensure!(source.settle_outbound(request_id, result)? == settled);
    ensure!(
        settled.intent == original
            && settled
                .terminal
                .as_ref()
                .and_then(|result| result.result.as_ref())
                .is_some_and(|result| result.output.len() == MAX_OUTBOUND_RESULT_BYTES)
    );
    ensure!(matches!(
        source.stage_outbound(intent(local, peer, 13, Arc::from([]))?, 100),
        Err(FederationError::Capacity)
    ));
    ensure!(source.unsettled_outbound(None, 32)?.is_empty());
    Ok(())
}

#[test]
fn source_releases_only_unused_reserve_once_and_acknowledgment_keeps_it() -> Result<()> {
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let source = MemoryFederationOutboundCallStore::new(
        local,
        NonZeroUsize::new(2 * MAX_OUTBOUND_RESULT_BYTES + 6).context("budget")?,
    );
    let first = intent(local, peer, 20, Arc::from(b"input".as_slice()))?;
    let second = intent(local, peer, 21, Arc::from([]))?;
    let second_operation = "1/2/3/4/6".parse()?;
    source.bind_outbound_origin(
        second.request_id(),
        second_operation,
        Digest::from_bytes([4; 48]),
    )?;
    source.stage_outbound(first.clone(), 100)?;
    source.stage_outbound(second.clone(), 100)?;
    let first_prepared = prepared(peer, 20)?;
    let second_prepared = prepared(peer, 21)?;
    source.bind_outbound_prepared(first.request_id(), first_prepared.clone())?;
    source.mark_outbound_invoke_possible(first.request_id(), 100)?;
    source.bind_outbound_prepared(second.request_id(), second_prepared.clone())?;
    ensure!(source.stage_outbound_cancellation(second_operation)? == Some(second.request_id()));
    let cancel = source
        .outbound_call(second.request_id())?
        .cancel_request()
        .context("cancel request")?;
    let acknowledged = CallCancelled {
        control_request_id: cancel.control_request_id,
        call: cancel.call,
        status: CallStatus::Closed,
        control_revision: 2,
        cancellation_requested: true,
        kernel_cancel_accepted: false,
        execution_stopped: true,
    };
    source.record_outbound_cancellation(second.request_id(), acknowledged)?;
    let third = intent(local, peer, 22, Arc::from([]))?;
    ensure!(matches!(
        source.stage_outbound(third.clone(), 100),
        Err(FederationError::Capacity)
    ));
    let first_result = terminal(
        &first_prepared,
        Some(PersistedCallResult::new(true, Arc::from([23]), None)?),
    );
    let mut conflicting = first_result.clone();
    conflicting.call = second_prepared.call;
    ensure!(matches!(
        source.settle_outbound(first.request_id(), conflicting),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        source.stage_outbound(third.clone(), 100),
        Err(FederationError::Capacity)
    ));
    let first_settled = source.settle_outbound(first.request_id(), first_result.clone())?;
    source.stage_outbound(third.clone(), 100)?;
    ensure!(source.settle_outbound(first.request_id(), first_result)? == first_settled);
    let fourth = intent(local, peer, 24, Arc::from([]))?;
    ensure!(matches!(
        source.stage_outbound(fourth.clone(), 100),
        Err(FederationError::Capacity)
    ));
    ensure!(source.stage_outbound(third.clone(), 100)?.intent == third);
    let mut second_result = terminal(&second_prepared, None);
    second_result.cancellation_requested = true;
    let second_settled = source.settle_outbound(second.request_id(), second_result.clone())?;
    source.stage_outbound(fourth, 100)?;
    ensure!(source.settle_outbound(second.request_id(), second_result)? == second_settled);
    ensure!(
        source.record_outbound_cancellation(second.request_id(), acknowledged)? == second_settled
    );
    ensure!(
        source
            .stage_outbound_cancellation(second_operation)?
            .is_none()
    );
    ensure!(
        source.outbound_origin_evidence(second.request_id(), second_operation)?
            == OutboundOriginEvidence::Retired
    );
    ensure!(matches!(
        source.stage_outbound(intent(local, peer, 25, Arc::from([]))?, 100),
        Err(FederationError::Capacity)
    ));
    ensure!(source.outbound_call(first.request_id())? == first_settled);
    ensure!(source.pending_outbound_cancellations(None, 32)?.is_empty());
    ensure!(source.unsettled_outbound(None, 32)?.len() == 2);
    Ok(())
}
