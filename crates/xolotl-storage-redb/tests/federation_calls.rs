#![cfg(feature = "federation")]

use std::{num::NonZeroUsize, sync::Arc};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallAuthorityKey, CallAuthorityRule, CallCancelled, CallInspection, CallKernelBinding,
    CallMethod, CallPath, CallPrepared, CallRef, CallStatus, CallTarget, CancelCallRequest, Digest,
    ExportAccess, ExportName, FederationCallStore, FederationError, FederationNodeId,
    FederationOutboundCallStore, FederationStore, FederationSubject, InspectCallRequest,
    InvokeCallRequest, MAX_CALL_UNRESOLVED_EFFECT_IDS, MAX_OUTBOUND_PAGE_INPUT_BYTES,
    MAX_OUTBOUND_RESULT_BYTES, MemoryFederationOutboundCallStore, OutboundCallIntent,
    OutboundOriginEvidence, OutboundOriginState, PersistedCallResult, PrepareCallRequest,
    RequestId,
};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{ExecutionId, InvocationId, NodeId, OperationId, ProcessId};

fn kernel_request_id(namespace: [u8; 32], node: FederationNodeId, op: OperationId) -> RequestId {
    let mut hash = Sha384::new();
    hash.update(b"xolotl/federation/v1/kernel-call-request\0");
    hash.update(namespace);
    hash.update(node.as_bytes());
    hash.update(op.to_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    RequestId::from_bytes(bytes)
}

fn target() -> Result<CallTarget> {
    Ok(CallTarget {
        export: ExportName::new("tools")?,
        path: CallPath::new("/albums/one")?,
        method: CallMethod::new("render")?,
        contract_digest: [3; 32],
    })
}

fn prepare(peer: FederationNodeId, target: CallTarget, id: u8) -> PrepareCallRequest {
    PrepareCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: RequestId::from_bytes([id; 16]),
        target,
        input_digest: Digest::from_bytes(Sha384::digest(b"input").into()),
        input_bytes: 5,
        prepare_deadline_ms: 500,
        execution_deadline_ms: 800,
        result_retention_ms: 300,
    }
}

fn invoke(request: &PrepareCallRequest, call: xolotl_federation::CallRef) -> InvokeCallRequest {
    InvokeCallRequest {
        authenticated_origin: request.authenticated_origin,
        subject: request.subject.clone(),
        origin_request_id: request.origin_request_id,
        call,
        input: Arc::from(b"input".as_slice()),
    }
}

#[test]
fn call_authority_scan_exposes_removed_grants_for_restart_reconciliation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("authority.redb");
    let node = FederationNodeId::from_bytes([91; 48]);
    let peer = FederationNodeId::from_bytes([92; 48]);
    let first = target()?;
    let mut second = first.clone();
    second.method = CallMethod::new("summarize")?;
    let rule = |target| CallAuthorityRule {
        subject: FederationSubject::Node(peer),
        presenter: peer,
        target,
        enabled: true,
        expires_ms: 1000,
        max_input_bytes: 1024,
        max_prepare_window_ms: 100,
        max_result_retention_ms: 300,
    };
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    store.set_peer_authority(peer, None, true)?;
    store.set_export_authority(
        peer,
        first.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    let first_rule = rule(first.clone());
    let second_rule = rule(second);
    store.set_call_authority(None, first_rule.clone())?;
    store.set_call_authority(None, second_rule)?;
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = store.scan_call_authorities(after.as_ref(), 1)?;
        let Some(entry) = page.into_iter().next() else {
            break;
        };
        after = Some(CallAuthorityKey::from_rule(&entry.rule));
        seen.push(entry.rule.target.method.as_str().to_owned());
    }
    ensure!(
        seen.len() == 2
            && seen.contains(&"render".to_owned())
            && seen.contains(&"summarize".to_owned())
    );
    let key = CallAuthorityKey::from_rule(&first_rule);
    ensure!(
        store
            .call_authority(&key)?
            .as_ref()
            .map(|entry| entry.revision)
            == Some(1)
    );
    let mut disabled = first_rule;
    disabled.enabled = false;
    store.set_peer_authority(peer, Some(1), false)?;
    store.set_call_authority(Some(1), disabled)?;
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    let entry = store
        .call_authority(&key)?
        .ok_or_else(|| anyhow::anyhow!("disabled grant not visible"))?;
    ensure!(entry.revision == 2 && !entry.rule.enabled);
    ensure!(matches!(
        store.prepare_call(prepare(peer, first, 93), 100),
        Err(FederationError::Unauthorized)
    ));
    ensure!(store.scan_call_authorities(None, 2)?.len() == 2);
    Ok(())
}

#[test]
fn local_call_receipts_sample_current_time_without_reauthorizing_remote_work() -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let dir = tempfile::tempdir()?;
    let node = FederationNodeId::from_bytes([81; 48]);
    let peer = FederationNodeId::from_bytes([82; 48]);
    let db = RedbStore::open(dir.path().join("receipt-clock.redb"))?;
    let store = db.federation_store(node)?;
    let target = target()?;
    store.set_peer_authority(peer, None, true)?;
    store.set_export_authority(
        peer,
        target.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    let rule = CallAuthorityRule {
        subject: FederationSubject::Node(peer),
        presenter: peer,
        target: target.clone(),
        enabled: true,
        expires_ms: 1000,
        max_input_bytes: 1024,
        max_prepare_window_ms: 100,
        max_result_retention_ms: 300,
    };
    store.set_call_authority(None, rule.clone())?;
    let request = prepare(peer, target, 83);
    let prepared = store.prepare_call(request.clone(), 100)?;
    store.invoke_call(invoke(&request, prepared.call), 100)?;
    store.bind_kernel_identity(
        prepared.call,
        CallKernelBinding {
            process: 84,
            lifecycle: 85,
        },
        100,
    )?;
    store.record_kernel_acceptance(prepared.call, Digest::from_bytes([86; 48]))?;
    let now = Arc::new(AtomicU64::new(200));
    let clock = Arc::clone(&now);
    let local = store.bind_local_call_clock(Arc::new(move || Ok(clock.load(Ordering::SeqCst))))?;
    store.checked_time_ms(190)?;
    ensure!(matches!(
        store.record_execution_stopped(prepared.call, 100),
        Err(FederationError::ClockRollback)
    ));
    let mut revoked = rule;
    revoked.enabled = false;
    store.set_call_authority(Some(1), revoked)?;
    store.set_peer_authority(peer, Some(1), false)?;
    ensure!(
        local
            .record_execution_stopped(prepared.call, 100)?
            .execution_stopped
    );
    store.checked_time_ms(210)?;
    now.store(220, Ordering::SeqCst);
    let result = PersistedCallResult::new(true, Arc::from(b"done".as_slice()), None)?;
    let terminal = local.record_call_result(prepared.call, result.clone(), vec![], 100)?;
    ensure!(terminal.status == CallStatus::Finished && terminal.result == Some(result));
    ensure!(terminal.execution_stopped && terminal.result_retained_until_ms == 520);
    ensure!(store.scan_pending_kernel_calls(None, 8)?.is_empty());
    now.store(219, Ordering::SeqCst);
    ensure!(matches!(
        local.record_execution_stopped(prepared.call, 100),
        Err(FederationError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn call_reservations_and_results_survive_restart_without_reacceptance() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("calls.redb");
    let node = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let target = target()?;
    let request = prepare(peer, target.clone(), 4);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    store.set_peer_authority(peer, None, true)?;
    store.set_export_authority(
        peer,
        target.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    ensure!(matches!(
        store.prepare_call(request.clone(), 100),
        Err(FederationError::Unauthorized)
    ));
    store.set_call_authority(
        None,
        CallAuthorityRule {
            subject: FederationSubject::Node(peer),
            presenter: peer,
            target,
            enabled: true,
            expires_ms: 1000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 100,
            max_result_retention_ms: 300,
        },
    )?;
    let prepared = store.prepare_call(request.clone(), 101)?;
    ensure!(prepared.status == CallStatus::Reserved);
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    ensure!(store.prepare_call(request.clone(), 102)? == prepared);
    let first = store.invoke_call(invoke(&request, prepared.call), 103)?;
    ensure!(first.status == CallStatus::Preparing);
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    ensure!(store.invoke_call(invoke(&request, prepared.call), 104)? == first);
    ensure!(store.scan_pending_kernel_calls(None, 8)? == vec![prepared.call]);
    ensure!(store.kernel_call(prepared.call, 104)?.input.as_deref() == Some(b"input".as_slice()));
    let binding = CallKernelBinding {
        process: 55,
        lifecycle: 56,
    };
    ensure!(store.bind_kernel_identity(prepared.call, binding, 104)? == binding);
    let replacement = CallKernelBinding {
        process: 57,
        lifecycle: 58,
    };
    ensure!(store.kernel_call(prepared.call, 104)?.binding == Some(binding));
    ensure!(matches!(
        store.bind_kernel_identity(prepared.call, replacement, 104),
        Err(FederationError::Conflict)
    ));
    ensure!(store.bind_kernel_identity(prepared.call, binding, 104)? == binding);
    store.authorize_kernel_execution(prepared.call, 104)?;
    let acceptance = Digest::from_bytes([7; 48]);
    ensure!(
        store
            .record_kernel_acceptance(prepared.call, acceptance)?
            .status
            == CallStatus::Accepted
    );
    let result = PersistedCallResult::new(true, Arc::from(b"done".as_slice()), None)?;
    store.record_call_result(prepared.call, result.clone(), vec![[9; 32]], 105)?;
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    let inspected = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call: prepared.call,
        },
        106,
    )?;
    ensure!(inspected.status == CallStatus::Finished);
    ensure!(inspected.result == Some(result));
    ensure!(inspected.unresolved_effect_ids == vec![[9; 32]]);
    ensure!(store.kernel_call(prepared.call, 106)?.input.is_none());
    ensure!(store.scan_pending_kernel_calls(None, 8)? == vec![prepared.call]);
    ensure!(
        store
            .record_execution_stopped(prepared.call, 106)?
            .execution_stopped
    );
    ensure!(store.scan_pending_kernel_calls(None, 8)?.is_empty());
    ensure!(
        store
            .invoke_call(invoke(&request, prepared.call), 107)?
            .status
            == CallStatus::Finished
    );
    ensure!(matches!(
        store.record_kernel_acceptance(prepared.call, Digest::from_bytes([8; 48])),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn original_prepare_id_recovers_call_ref_after_deadline_and_method_revocation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("prepare-replay.redb");
    let node = FederationNodeId::from_bytes([131; 48]);
    let peer = FederationNodeId::from_bytes([132; 48]);
    let target = target()?;
    let request = prepare(peer, target.clone(), 133);
    let rule = CallAuthorityRule {
        subject: FederationSubject::Node(peer),
        presenter: peer,
        target,
        enabled: true,
        expires_ms: 1000,
        max_input_bytes: 1024,
        max_prepare_window_ms: 100,
        max_result_retention_ms: 300,
    };
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    store.set_peer_authority(peer, None, true)?;
    store.set_export_authority(
        peer,
        request.target.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    store.set_call_authority(None, rule.clone())?;
    let prepared = store.prepare_call(request.clone(), 100)?;
    let mut disabled = rule;
    disabled.enabled = false;
    store.set_call_authority(Some(1), disabled)?;
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    ensure!(store.prepare_call(request.clone(), 900)? == prepared);
    let mut different = request.clone();
    different.input_bytes += 1;
    ensure!(matches!(
        store.prepare_call(different, 901),
        Err(FederationError::Conflict)
    ));
    let fresh = prepare(peer, request.target, 134);
    ensure!(store.prepare_call(fresh, 902).is_err());
    Ok(())
}

#[test]
fn cancelled_reservation_stays_closed_and_authority_revision_fences_old_call() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("cancel.redb");
    let node = FederationNodeId::from_bytes([11; 48]);
    let peer = FederationNodeId::from_bytes([12; 48]);
    let target = target()?;
    let request = prepare(peer, target.clone(), 13);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    store.set_peer_authority(peer, None, true)?;
    store.set_export_authority(
        peer,
        target.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    let rule = CallAuthorityRule {
        subject: FederationSubject::Node(peer),
        presenter: peer,
        target,
        enabled: true,
        expires_ms: 1000,
        max_input_bytes: 1024,
        max_prepare_window_ms: 100,
        max_result_retention_ms: 300,
    };
    store.set_call_authority(None, rule.clone())?;
    let prepared = store.prepare_call(request.clone(), 100)?;
    let cancel = CancelCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        control_request_id: RequestId::from_bytes([14; 16]),
        call: prepared.call,
        expected_control_revision: Some(1),
    };
    let closed = store.cancel_call(cancel.clone(), 101)?;
    ensure!(closed.status == CallStatus::Closed);
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    ensure!(store.cancel_call(cancel, 102)? == closed);
    ensure!(matches!(
        store.invoke_call(invoke(&request, prepared.call), 103),
        Err(FederationError::Conflict)
    ));
    let new_revision = store.set_call_authority(Some(1), rule)?;
    ensure!(new_revision == 2);
    ensure!(matches!(
        store.invoke_call(invoke(&request, prepared.call), 104),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn outbound_pages_bound_input_bytes_and_preserve_keyset_for_both_backends() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let owner = RedbStore::open(directory.path().join("source-page-budget.redb"))?;
    let local = FederationNodeId::from_bytes([11; 48]);
    let peer = FederationNodeId::from_bytes([12; 48]);
    let persistent = owner.federation_store(local)?;
    persistent.set_peer_authority(peer, None, true)?;
    let namespace = persistent.kernel_call_namespace()?;
    let base: OperationId = "4/5/6/7/8".parse()?;
    let mut identities = (0..4)
        .map(|attempt| {
            let operation = OperationId { attempt, ..base };
            (kernel_request_id(namespace, local, operation), operation)
        })
        .collect::<Vec<_>>();
    identities.sort_by_key(|(request_id, _operation)| *request_id);
    let expected = identities
        .iter()
        .map(|(request_id, _operation)| *request_id)
        .collect::<Vec<_>>();
    let sources: [Arc<dyn FederationOutboundCallStore>; 2] = [
        Arc::new(MemoryFederationOutboundCallStore::new(
            local,
            NonZeroUsize::new(32 * 1024 * 1024).ok_or(FederationError::Capacity)?,
        )),
        Arc::new(persistent),
    ];
    for source in sources {
        for ((request_id, operation), size) in identities.iter().zip([
            MAX_OUTBOUND_PAGE_INPUT_BYTES / 2 + 1,
            MAX_OUTBOUND_PAGE_INPUT_BYTES / 2 + 1,
            0,
            MAX_OUTBOUND_PAGE_INPUT_BYTES,
        ]) {
            let input: Arc<[u8]> = Arc::from(vec![37; size]);
            let mut request = prepare(local, target()?, 13);
            request.origin_request_id = *request_id;
            request.input_bytes = size as u64;
            request.input_digest = Digest::from_bytes(Sha384::digest(&input).into());
            source.bind_outbound_origin(*request_id, *operation, Digest::from_bytes([14; 48]))?;
            source.stage_outbound(
                OutboundCallIntent {
                    target_node: peer,
                    request,
                    input,
                },
                100,
            )?;
            ensure!(source.stage_outbound_cancellation(*operation)? == Some(*request_id));
        }
        for max in [1, 32] {
            for cancellations in [false, true] {
                let mut cursor = None;
                let mut observed = Vec::new();
                let mut page_sizes = Vec::new();
                loop {
                    let page = if cancellations {
                        source.pending_outbound_cancellations(cursor, max)?
                    } else {
                        source.unsettled_outbound(cursor, max)?
                    };
                    if page.is_empty() {
                        break;
                    }
                    ensure!(
                        page.iter().map(|row| row.intent.input.len()).sum::<usize>()
                            <= MAX_OUTBOUND_PAGE_INPUT_BYTES
                    );
                    page_sizes.push(page.len());
                    observed.extend(page.iter().map(|row| row.intent.request_id()));
                    cursor = page.last().map(|row| row.intent.request_id());
                    ensure!(page_sizes.len() <= expected.len());
                }
                ensure!(observed == expected);
                ensure!(
                    page_sizes
                        == if max == 1 {
                            vec![1, 1, 1, 1]
                        } else {
                            vec![1, 2, 1]
                        }
                );
            }
        }
        for invalid in [0, 33] {
            ensure!(matches!(
                source.unsettled_outbound(None, invalid),
                Err(FederationError::Invalid(_))
            ));
            ensure!(matches!(
                source.pending_outbound_cancellations(None, invalid),
                Err(FederationError::Invalid(_))
            ));
        }
        for (index, acknowledged) in [(0, true), (1, false)] {
            let request_id = expected[index];
            let row = source.outbound_call(request_id)?;
            let prepared = CallPrepared {
                origin_request_id: request_id,
                call: CallRef::new(peer, [index as u8 + 1; 32])?,
                status: CallStatus::Reserved,
                reserved_until_ms: row.intent.request.prepare_deadline_ms,
                execution_deadline_ms: row.intent.request.execution_deadline_ms,
                result_retention_ms: row.intent.request.result_retention_ms,
                authority_revision: 1,
                control_revision: 1,
            };
            let bound = source.bind_outbound_prepared(request_id, prepared.clone())?;
            ensure!(source.bind_outbound_prepared(request_id, prepared.clone())? == bound);
            if acknowledged {
                let request = bound.cancel_request().ok_or(FederationError::Corrupt)?;
                let response = CallCancelled {
                    control_request_id: request.control_request_id,
                    call: request.call,
                    status: CallStatus::Closed,
                    control_revision: 2,
                    cancellation_requested: true,
                    kernel_cancel_accepted: false,
                    execution_stopped: true,
                };
                ensure!(matches!(
                    source.record_outbound_cancellation(
                        request_id,
                        CallCancelled {
                            control_revision: 1,
                            ..response
                        }
                    ),
                    Err(FederationError::Conflict)
                ));
                ensure!(
                    source.pending_outbound_cancellations(None, 1)?[0]
                        .intent
                        .request_id()
                        == request_id
                );
                let accepted = source.record_outbound_cancellation(request_id, response)?;
                ensure!(source.record_outbound_cancellation(request_id, response)? == accepted);
                ensure!(
                    source.pending_outbound_cancellations(None, 1)?[0]
                        .intent
                        .request_id()
                        == expected[index + 1]
                );
                ensure!(
                    source.stage_outbound_cancellation(identities[index].1)? == Some(request_id)
                );
            }
            ensure!(source.unsettled_outbound(None, 1)?[0].intent.request_id() == request_id);
            let terminal = CallInspection {
                call: prepared.call,
                status: CallStatus::Closed,
                control_revision: 2,
                authority_revision: 1,
                reserved_until_ms: prepared.reserved_until_ms,
                execution_deadline_ms: prepared.execution_deadline_ms,
                result_retained_until_ms: 0,
                result: None,
                unresolved_effect_ids: Vec::new(),
                cancellation_requested: true,
                kernel_cancel_accepted: false,
                execution_stopped: true,
            };
            ensure!(matches!(
                source.settle_outbound(
                    request_id,
                    CallInspection {
                        unresolved_effect_ids: vec![[29; 32]; MAX_CALL_UNRESOLVED_EFFECT_IDS + 1],
                        ..terminal.clone()
                    }
                ),
                Err(FederationError::Capacity)
            ));
            ensure!(matches!(
                source.settle_outbound(
                    request_id,
                    CallInspection {
                        status: CallStatus::Finished,
                        ..terminal.clone()
                    }
                ),
                Err(FederationError::Conflict)
            ));
            ensure!(source.unsettled_outbound(None, 1)?[0].intent.request_id() == request_id);
            let settled = source.settle_outbound(request_id, terminal.clone())?;
            ensure!(source.settle_outbound(request_id, terminal)? == settled);
            ensure!(source.outbound_call(request_id)? == settled);
            ensure!(
                source
                    .stage_outbound_cancellation(identities[index].1)?
                    .is_none()
            );
            ensure!(
                source.outbound_origin_evidence(request_id, identities[index].1)?
                    == OutboundOriginEvidence::Retired
            );
            ensure!(
                source.unsettled_outbound(None, 1)?[0].intent.request_id() == expected[index + 1]
            );
            ensure!(
                source.pending_outbound_cancellations(None, 1)?[0]
                    .intent
                    .request_id()
                    == expected[index + 1]
            );
        }
        let remaining = &expected[2..];
        for page in [
            source.unsettled_outbound(None, 32)?,
            source.pending_outbound_cancellations(None, 32)?,
            source.unsettled_outbound(Some(expected[1]), 32)?,
            source.pending_outbound_cancellations(Some(expected[1]), 32)?,
        ] {
            ensure!(
                page.iter()
                    .map(|row| row.intent.request_id())
                    .collect::<Vec<_>>()
                    == remaining
            );
        }
    }
    Ok(())
}

#[test]
fn outbound_intent_is_durable_before_prepare_and_old_call_is_never_rebound() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("outbound.redb");
    let origin = FederationNodeId::from_bytes([61; 48]);
    let target_node = FederationNodeId::from_bytes([62; 48]);
    let target = target()?;
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(origin)?;
    let operation: OperationId = "4/5/6/7/8".parse()?;
    let mut request = prepare(origin, target.clone(), 63);
    request.origin_request_id =
        kernel_request_id(store.kernel_call_namespace()?, origin, operation);
    let intent = OutboundCallIntent {
        target_node,
        request: request.clone(),
        input: Arc::from(b"input".as_slice()),
    };
    store.set_peer_authority(target_node, None, true)?;
    // A source call is allowed by its host binding and the target's exact
    // CallAuthority, not by the unrelated stream receive export bit.
    store.checked_time_ms(101)?;
    let staged = store.stage_outbound(intent, 100)?;
    ensure!(staged.prepared.is_none() && !staged.invoke_possible);
    ensure!(
        store.outbound_origin_evidence(request.origin_request_id, operation)?
            == OutboundOriginEvidence::Recorded
    );
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(origin)?;
    ensure!(store.outbound_call(request.origin_request_id)? == staged);
    ensure!(
        store.outbound_origin_evidence(request.origin_request_id, operation)?
            == OutboundOriginEvidence::Recorded
    );
    let prepared = CallPrepared {
        origin_request_id: request.origin_request_id,
        call: CallRef::new(target_node, [64; 32])?,
        status: CallStatus::Reserved,
        reserved_until_ms: 200,
        execution_deadline_ms: request.execution_deadline_ms,
        result_retention_ms: request.result_retention_ms,
        authority_revision: 1,
        control_revision: 1,
    };
    store.bind_outbound_prepared(request.origin_request_id, prepared.clone())?;
    ensure!(matches!(
        store.bind_outbound_prepared(
            request.origin_request_id,
            CallPrepared {
                call: CallRef::new(target_node, [65; 32])?,
                ..prepared
            }
        ),
        Err(FederationError::Conflict)
    ));
    store.mark_outbound_invoke_possible(request.origin_request_id, 101)?;
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(origin)?;
    let recovered = store.unsettled_outbound(None, 8)?;
    ensure!(recovered.len() == 1 && recovered[0].invoke_possible);
    ensure!(recovered[0].prepared == Some(prepared.clone()));
    let result = PersistedCallResult::new(true, Arc::from(b"result".as_slice()), None)?;
    let terminal = CallInspection {
        call: prepared.call,
        status: CallStatus::Finished,
        control_revision: 3,
        authority_revision: 1,
        reserved_until_ms: prepared.reserved_until_ms,
        execution_deadline_ms: prepared.execution_deadline_ms,
        result_retained_until_ms: 500,
        result: Some(result),
        unresolved_effect_ids: vec![[66; 32]],
        cancellation_requested: false,
        kernel_cancel_accepted: false,
        execution_stopped: false,
    };
    store.settle_outbound(request.origin_request_id, terminal.clone())?;
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(origin)?;
    ensure!(store.outbound_call(request.origin_request_id)?.terminal == Some(terminal));
    ensure!(store.unsettled_outbound(None, 8)?.is_empty());
    let later = prepare(origin, target, 67);
    store.stage_outbound(
        OutboundCallIntent {
            target_node,
            request: later.clone(),
            input: Arc::from(b"input".as_slice()),
        },
        102,
    )?;
    store.bind_outbound_prepared(
        later.origin_request_id,
        CallPrepared {
            origin_request_id: later.origin_request_id,
            call: CallRef::new(target_node, [68; 32])?,
            ..prepared
        },
    )?;
    store.set_peer_authority(target_node, Some(1), true)?;
    ensure!(matches!(
        store.mark_outbound_invoke_possible(later.origin_request_id, 103),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn outbound_source_uses_trusted_high_water_for_expiry_after_concurrent_clock_advance() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("clock.redb"))?;
    let origin = FederationNodeId::from_bytes([71; 48]);
    let peer = FederationNodeId::from_bytes([72; 48]);
    let store = db.federation_store(origin)?;
    store.set_peer_authority(peer, None, true)?;
    let request = prepare(origin, target()?, 73);
    store.checked_time_ms(101)?;
    store.stage_outbound(
        OutboundCallIntent {
            target_node: peer,
            request: request.clone(),
            input: Arc::from(b"input".as_slice()),
        },
        100,
    )?;
    store.bind_outbound_prepared(
        request.origin_request_id,
        CallPrepared {
            origin_request_id: request.origin_request_id,
            call: CallRef::new(peer, [74; 32])?,
            status: CallStatus::Reserved,
            reserved_until_ms: 200,
            execution_deadline_ms: request.execution_deadline_ms,
            result_retention_ms: request.result_retention_ms,
            authority_revision: 1,
            control_revision: 1,
        },
    )?;
    store.checked_time_ms(201)?;
    ensure!(matches!(
        store.mark_outbound_invoke_possible(request.origin_request_id, 102),
        Err(FederationError::Conflict)
    ));
    ensure!(
        !store
            .outbound_call(request.origin_request_id)?
            .invoke_possible
    );

    store.checked_time_ms(501)?;
    let expired = prepare(origin, target()?, 75);
    ensure!(matches!(
        store.stage_outbound(
            OutboundCallIntent {
                target_node: peer,
                request: expired.clone(),
                input: Arc::from(b"input".as_slice()),
            },
            100,
        ),
        Err(FederationError::Invalid(_))
    ));
    ensure!(matches!(
        store.outbound_call(expired.origin_request_id),
        Err(FederationError::NotFound)
    ));
    Ok(())
}

#[test]
fn outbound_origin_binding_and_operation_namespace_survive_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("outbound-identity.redb");
    let local = FederationNodeId::from_bytes([41; 48]);
    let operation: OperationId = "4/5/6/7/8".parse()?;
    let original = Digest::from_bytes([43; 48]);
    let changed = Digest::from_bytes([44; 48]);
    let namespace = {
        let db = RedbStore::open(&path)?;
        let source = db.federation_store(local)?;
        let namespace = source.kernel_call_namespace()?;
        let request = kernel_request_id(namespace, local, operation);
        ensure!(namespace != [0; 32]);
        source.bind_outbound_origin(request, operation, original)?;
        source.bind_outbound_origin(request, operation, original)?;
        ensure!(matches!(
            source.bind_outbound_origin(request, operation, changed),
            Err(FederationError::Conflict)
        ));
        namespace
    };
    let db = RedbStore::open(&path)?;
    let source = db.federation_store(local)?;
    ensure!(source.kernel_call_namespace()? == namespace);
    let request = kernel_request_id(namespace, local, operation);
    ensure!(matches!(
        source.bind_outbound_origin(request, operation, changed),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        source.bind_outbound_origin(request, operation, Digest::from_bytes([0; 48])),
        Err(FederationError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn outbound_retirement_requires_explicit_release_without_facts_and_keeps_replay_barrier()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("retired-outbound.redb");
    let local = FederationNodeId::from_bytes([81; 48]);
    let remote = FederationNodeId::from_bytes([82; 48]);
    let operation = OperationId::new(
        ProcessId::new(4),
        ExecutionId::FIRST,
        InvocationId::new(1),
        NodeId::new(2),
        0,
    );
    let binding = Digest::from_bytes([83; 48]);
    let (request_id, intent) = {
        let db = RedbStore::open(&path)?;
        let source = db.federation_store(local)?;
        source.set_peer_authority(remote, None, true)?;
        let request_id = kernel_request_id(source.kernel_call_namespace()?, local, operation);
        ensure!(
            source.outbound_origin_evidence(request_id, operation)?
                == OutboundOriginEvidence::Fresh
        );
        ensure!(
            source.bind_outbound_origin(request_id, operation, binding)?
                == OutboundOriginState::Active
        );
        let mut request = prepare(local, target()?, 84);
        ensure!(
            source.outbound_origin_evidence(request_id, operation)?
                == OutboundOriginEvidence::Recorded
        );
        request.origin_request_id = request_id;
        let intent = OutboundCallIntent {
            target_node: remote,
            request,
            input: Arc::from(b"input".as_slice()),
        };
        source.stage_outbound(intent.clone(), 100)?;
        let prepared = CallPrepared {
            origin_request_id: request_id,
            call: CallRef::new(remote, [85; 32])?,
            status: CallStatus::Reserved,
            reserved_until_ms: 200,
            execution_deadline_ms: 800,
            result_retention_ms: 300,
            authority_revision: 1,
            control_revision: 1,
        };
        source.bind_outbound_prepared(request_id, prepared.clone())?;
        source.mark_outbound_invoke_possible(request_id, 101)?;
        source.settle_outbound(
            request_id,
            CallInspection {
                call: prepared.call,
                status: CallStatus::Finished,
                control_revision: 2,
                authority_revision: 1,
                reserved_until_ms: prepared.reserved_until_ms,
                execution_deadline_ms: prepared.execution_deadline_ms,
                result_retained_until_ms: 500,
                result: Some(PersistedCallResult::new(
                    true,
                    Arc::from(b"done".as_slice()),
                    None,
                )?),
                unresolved_effect_ids: Vec::new(),
                cancellation_requested: false,
                kernel_cancel_accepted: false,
                execution_stopped: true,
            },
        )?;
        ensure!(source.retire_completed_outbound(None, 1)? == (0, Some(request_id)));

        let consumed = source.outbound_call(request_id)?;
        let terminal = consumed.terminal.context("missing terminal")?;
        let result = terminal.result.context("missing result")?;
        ensure!(result.output.as_ref() == b"done");
        source.release_outbound_responsibility(request_id, operation)?;
        source.release_outbound_responsibility(request_id, operation)?;
        ensure!(source.unsettled_outbound(None, 8)?.is_empty());
        (request_id, intent)
    };

    let db = RedbStore::open(&path)?;
    let source = db.federation_store(local)?;
    ensure!(source.outbound_call(request_id)?.terminal.is_some());
    ensure!(source.retire_completed_outbound(None, 1)? == (1, Some(request_id)));
    ensure!(source.retire_completed_outbound(Some(request_id), 1)? == (0, None));
    source.release_outbound_responsibility(request_id, operation)?;
    ensure!(
        source.bind_outbound_origin(request_id, operation, binding)?
            == OutboundOriginState::Retired
    );
    ensure!(
        source.outbound_origin_evidence(request_id, operation)? == OutboundOriginEvidence::Retired
    );
    let other_operation = OperationId::new(
        ProcessId::new(4),
        ExecutionId::FIRST,
        InvocationId::new(1),
        NodeId::new(3),
        0,
    );
    ensure!(matches!(
        source.bind_outbound_origin(request_id, other_operation, binding),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        source.bind_outbound_origin(RequestId::from_bytes([87; 16]), operation, binding),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        source.bind_outbound_origin(request_id, operation, Digest::from_bytes([86; 48])),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        source.stage_outbound(intent, 102),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        source.outbound_call(request_id),
        Err(FederationError::NotFound)
    ));
    ensure!(source.retire_completed_outbound(None, 1)? == (0, None));
    drop(source);
    drop(db);
    let reopened = RedbStore::open(&path)?;
    let source = reopened.federation_store(local)?;
    ensure!(
        source.outbound_origin_evidence(request_id, operation)? == OutboundOriginEvidence::Retired
    );
    source.release_outbound_responsibility(request_id, operation)?;
    Ok(())
}

#[test]
fn outbound_retirement_preserves_unknown_and_incomplete_responsibilities() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("incomplete-outbound.redb");
    let local = FederationNodeId::from_bytes([91; 48]);
    let remote = FederationNodeId::from_bytes([92; 48]);
    let mut identities = Vec::new();
    {
        let db = RedbStore::open(&path)?;
        let source = db.federation_store(local)?;
        source.set_peer_authority(remote, None, true)?;
        let memory = MemoryFederationOutboundCallStore::new(
            local,
            NonZeroUsize::new(16 * 1024 * 1024).context("zero payload budget")?,
        );
        for case in 0..5 {
            let operation = OperationId::new(
                ProcessId::new(5),
                ExecutionId::FIRST,
                InvocationId::new(case + 1),
                NodeId::new(2),
                0,
            );
            let request_id = kernel_request_id(source.kernel_call_namespace()?, local, operation);
            for source in [&source as &dyn FederationOutboundCallStore, &memory] {
                source.bind_outbound_origin(request_id, operation, Digest::from_bytes([93; 48]))?;
                let mut request = prepare(local, target()?, 94);
                request.origin_request_id = request_id;
                source.stage_outbound(
                    OutboundCallIntent {
                        target_node: remote,
                        request,
                        input: Arc::from(b"input".as_slice()),
                    },
                    100,
                )?;
                if case != 0 {
                    let prepared = CallPrepared {
                        origin_request_id: request_id,
                        call: CallRef::new(remote, [95; 32])?,
                        status: CallStatus::Reserved,
                        reserved_until_ms: 200,
                        execution_deadline_ms: 800,
                        result_retention_ms: 300,
                        authority_revision: 1,
                        control_revision: 1,
                    };
                    source.bind_outbound_prepared(request_id, prepared.clone())?;
                    source.mark_outbound_invoke_possible(request_id, 100)?;
                    if case == 4 {
                        ensure!(source.stage_outbound_cancellation(operation)? == Some(request_id));
                    }
                    let terminal = CallInspection {
                        call: prepared.call,
                        status: CallStatus::Finished,
                        control_revision: 2,
                        authority_revision: 1,
                        reserved_until_ms: 200,
                        execution_deadline_ms: 800,
                        result_retained_until_ms: 500,
                        result: Some(PersistedCallResult::new(
                            true,
                            Arc::from(b"done".as_slice()),
                            None,
                        )?),
                        unresolved_effect_ids: if case == 3 {
                            vec![[96; 32]]
                        } else {
                            Vec::new()
                        },
                        cancellation_requested: case == 4,
                        kernel_cancel_accepted: false,
                        execution_stopped: case != 2,
                    };
                    if case == 1 {
                        let mut unknown = terminal.clone();
                        unknown.status = CallStatus::Unproven;
                        ensure!(matches!(
                            source.settle_outbound(request_id, unknown),
                            Err(FederationError::Conflict)
                        ));
                        let mut accepted = terminal;
                        accepted.status = CallStatus::Accepted;
                        ensure!(matches!(
                            source.settle_outbound(request_id, accepted),
                            Err(FederationError::Conflict)
                        ));
                    } else {
                        source.settle_outbound(request_id, terminal)?;
                    }
                }
                ensure!(matches!(
                    source.release_outbound_responsibility(request_id, operation),
                    Err(FederationError::Conflict)
                ));
            }
            let expected_evidence = if case == 4 {
                OutboundOriginEvidence::Retired
            } else {
                OutboundOriginEvidence::Recorded
            };
            identities.push((request_id, operation, expected_evidence));
        }
    }
    let db = RedbStore::open(&path)?;
    let source = db.federation_store(local)?;
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let (retired, next) = source.retire_completed_outbound(cursor, 1)?;
        ensure!(retired == 0);
        pages += 1;
        if next.is_none() {
            break;
        }
        ensure!(next != cursor);
        cursor = next;
    }
    ensure!(pages == identities.len() + 1);
    for (request_id, operation, expected_evidence) in identities {
        ensure!(source.outbound_call(request_id)?.intent.input.as_ref() == b"input");
        ensure!(source.outbound_origin_evidence(request_id, operation)? == expected_evidence);
        ensure!(matches!(
            source.release_outbound_responsibility(request_id, operation),
            Err(FederationError::Conflict)
        ));
    }
    Ok(())
}

#[test]
fn outbound_release_matches_memory_for_safe_terminals_and_identity_checks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("release-parity.redb"))?;
    let local = FederationNodeId::from_bytes([97; 48]);
    let remote = FederationNodeId::from_bytes([98; 48]);
    let redb = db.federation_store(local)?;
    redb.set_peer_authority(remote, None, true)?;
    let memory = MemoryFederationOutboundCallStore::new(
        local,
        NonZeroUsize::new(MAX_OUTBOUND_RESULT_BYTES + 5).context("zero payload budget")?,
    );
    for (case, status) in [CallStatus::Finished, CallStatus::Closed, CallStatus::Closed]
        .into_iter()
        .enumerate()
    {
        let operation = OperationId::new(
            ProcessId::new(6),
            ExecutionId::FIRST,
            InvocationId::new(case as u64 + 1),
            NodeId::new(2),
            0,
        );
        let request_id = kernel_request_id(redb.kernel_call_namespace()?, local, operation);
        for source in [&redb as &dyn FederationOutboundCallStore, &memory] {
            ensure!(matches!(
                source.release_outbound_responsibility(request_id, operation),
                Err(FederationError::NotFound)
            ));
            source.bind_outbound_origin(request_id, operation, Digest::from_bytes([99; 48]))?;
            let mut request = prepare(local, target()?, 100);
            request.origin_request_id = request_id;
            source.stage_outbound(
                OutboundCallIntent {
                    target_node: remote,
                    request,
                    input: Arc::from(b"input".as_slice()),
                },
                100,
            )?;
            let prepared = CallPrepared {
                origin_request_id: request_id,
                call: CallRef::new(remote, [101; 32])?,
                status: CallStatus::Reserved,
                reserved_until_ms: 200,
                execution_deadline_ms: 800,
                result_retention_ms: 300,
                authority_revision: 1,
                control_revision: 1,
            };
            source.bind_outbound_prepared(request_id, prepared.clone())?;
            source.mark_outbound_invoke_possible(request_id, 100)?;
            if case == 2 {
                ensure!(source.stage_outbound_cancellation(operation)? == Some(request_id));
                let cancel = source
                    .outbound_call(request_id)?
                    .cancel_request()
                    .context("missing cancellation request")?;
                source.record_outbound_cancellation(
                    request_id,
                    CallCancelled {
                        call: prepared.call,
                        control_request_id: cancel.control_request_id,
                        status: CallStatus::Closed,
                        control_revision: 2,
                        cancellation_requested: true,
                        kernel_cancel_accepted: false,
                        execution_stopped: true,
                    },
                )?;
            }
            source.settle_outbound(
                request_id,
                CallInspection {
                    call: prepared.call,
                    status,
                    control_revision: 2,
                    authority_revision: 1,
                    reserved_until_ms: 200,
                    execution_deadline_ms: 800,
                    result_retained_until_ms: 500,
                    result: if status == CallStatus::Finished {
                        Some(PersistedCallResult::new(
                            true,
                            Arc::from(b"done".as_slice()),
                            None,
                        )?)
                    } else {
                        None
                    },
                    unresolved_effect_ids: Vec::new(),
                    cancellation_requested: case == 2,
                    kernel_cancel_accepted: false,
                    execution_stopped: true,
                },
            )?;
            let different = OperationId::new(
                ProcessId::new(7),
                ExecutionId::FIRST,
                InvocationId::new(1),
                NodeId::new(2),
                0,
            );
            ensure!(matches!(
                source.release_outbound_responsibility(request_id, different),
                Err(FederationError::Conflict)
            ));
            ensure!(source.outbound_call(request_id)?.terminal.is_some());
            source.release_outbound_responsibility(request_id, operation)?;
            source.release_outbound_responsibility(request_id, operation)?;
            ensure!(
                source.bind_outbound_origin(request_id, operation, Digest::from_bytes([102; 48]))
                    == Err(FederationError::Conflict)
            );
        }
    }
    Ok(())
}

#[test]
fn outbound_cancel_handoff_survives_prepare_gap_and_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("outbound-cancel.redb");
    let local = FederationNodeId::from_bytes([111; 48]);
    let peer = FederationNodeId::from_bytes([112; 48]);
    let operation = OperationId::new(
        ProcessId::new(113),
        ExecutionId::FIRST,
        InvocationId::new(114),
        NodeId::new(115),
        0,
    );
    let db = RedbStore::open(&path)?;
    let source = db.federation_store(local)?;
    source.set_peer_authority(peer, None, true)?;
    let request_id = kernel_request_id(source.kernel_call_namespace()?, local, operation);
    let mut request = prepare(local, target()?, 116);
    request.origin_request_id = request_id;
    source.bind_outbound_origin(request_id, operation, Digest::from_bytes([117; 48]))?;
    source.stage_outbound(
        OutboundCallIntent {
            target_node: peer,
            request: request.clone(),
            input: Arc::from(b"input".as_slice()),
        },
        100,
    )?;
    let late_operation = OperationId {
        attempt: 1,
        ..operation
    };
    ensure!(
        source
            .stage_outbound_cancellation(late_operation)?
            .is_none()
    );
    let late_request = kernel_request_id(source.kernel_call_namespace()?, local, late_operation);
    ensure!(
        source.outbound_origin_evidence(late_request, late_operation)?
            == OutboundOriginEvidence::Retired
    );
    ensure!(
        source.bind_outbound_origin(late_request, late_operation, Digest::from_bytes([117; 48]))?
            == OutboundOriginState::Retired
    );
    let bound_operation = OperationId {
        attempt: 2,
        ..operation
    };
    let bound_request = kernel_request_id(source.kernel_call_namespace()?, local, bound_operation);
    source.bind_outbound_origin(
        bound_request,
        bound_operation,
        Digest::from_bytes([117; 48]),
    )?;
    ensure!(
        source
            .stage_outbound_cancellation(bound_operation)?
            .is_none()
    );
    let mut bound_prepare = request.clone();
    bound_prepare.origin_request_id = bound_request;
    ensure!(matches!(
        source.stage_outbound(
            OutboundCallIntent {
                target_node: peer,
                request: bound_prepare,
                input: Arc::from(b"input".as_slice()),
            },
            100
        ),
        Err(FederationError::Conflict)
    ));
    ensure!(source.stage_outbound_cancellation(operation)? == Some(request_id));
    let pending = source.pending_outbound_cancellations(None, 1)?;
    ensure!(pending.len() == 1 && pending[0].cancel_request().is_none());
    ensure!(matches!(
        source.mark_outbound_invoke_possible(request_id, 101),
        Err(FederationError::Conflict)
    ));
    drop(source);
    drop(db);

    let db = RedbStore::open(&path)?;
    let source = db.federation_store(local)?;
    let prepared = CallPrepared {
        origin_request_id: request_id,
        call: CallRef::new(peer, [118; 32])?,
        status: CallStatus::Reserved,
        reserved_until_ms: 200,
        execution_deadline_ms: request.execution_deadline_ms,
        result_retention_ms: request.result_retention_ms,
        authority_revision: 1,
        control_revision: 1,
    };
    source.bind_outbound_prepared(request_id, prepared.clone())?;
    let pending = source.pending_outbound_cancellations(None, 1)?;
    let control = pending[0]
        .cancel_request()
        .ok_or_else(|| anyhow::anyhow!("prepared cancellation has no control request"))?;
    ensure!(control.call == prepared.call);
    ensure!(control.subject == request.subject);
    drop(source);
    drop(db);

    let db = RedbStore::open(&path)?;
    let source = db.federation_store(local)?;
    let again = source.pending_outbound_cancellations(None, 1)?[0]
        .cancel_request()
        .ok_or_else(|| anyhow::anyhow!("reopened cancellation has no control request"))?;
    ensure!(again == control);
    let response = CallCancelled {
        control_request_id: control.control_request_id,
        call: control.call,
        status: CallStatus::Closed,
        control_revision: 2,
        cancellation_requested: false,
        kernel_cancel_accepted: false,
        execution_stopped: true,
    };
    source.record_outbound_cancellation(request_id, response)?;
    source.record_outbound_cancellation(request_id, response)?;
    ensure!(source.pending_outbound_cancellations(None, 1)?.is_empty());
    ensure!(source.stage_outbound_cancellation(operation)? == Some(request_id));
    ensure!(source.pending_outbound_cancellations(None, 1)?.is_empty());
    ensure!(matches!(
        source.record_outbound_cancellation(
            request_id,
            CallCancelled {
                control_revision: 3,
                ..response
            }
        ),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn outbound_cancel_controls_a_call_after_invoke_advanced_target_revision() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source_db = RedbStore::open(dir.path().join("source.redb"))?;
    let target_db = RedbStore::open(dir.path().join("target.redb"))?;
    let local = FederationNodeId::from_bytes([121; 48]);
    let peer = FederationNodeId::from_bytes([122; 48]);
    let exported = target()?;
    let target_store = target_db.federation_store(peer)?;
    target_store.set_peer_authority(local, None, true)?;
    target_store.set_export_authority(
        local,
        exported.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    target_store.set_call_authority(
        None,
        CallAuthorityRule {
            subject: FederationSubject::Node(local),
            presenter: local,
            target: exported.clone(),
            enabled: true,
            expires_ms: 1000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 100,
            max_result_retention_ms: 300,
        },
    )?;
    let source = source_db.federation_store(local)?;
    source.set_peer_authority(peer, None, true)?;
    let operation = OperationId::new(
        ProcessId::new(123),
        ExecutionId::FIRST,
        InvocationId::new(124),
        NodeId::new(125),
        0,
    );
    let request_id = kernel_request_id(source.kernel_call_namespace()?, local, operation);
    let mut request = prepare(local, exported, 126);
    request.origin_request_id = request_id;
    source.bind_outbound_origin(request_id, operation, Digest::from_bytes([127; 48]))?;
    source.stage_outbound(
        OutboundCallIntent {
            target_node: peer,
            request: request.clone(),
            input: Arc::from(b"input".as_slice()),
        },
        100,
    )?;
    let prepared = target_store.prepare_call(request.clone(), 100)?;
    source.bind_outbound_prepared(request_id, prepared.clone())?;
    source.mark_outbound_invoke_possible(request_id, 101)?;
    let invoked = target_store.invoke_call(invoke(&request, prepared.call), 101)?;
    ensure!(invoked.control_revision > prepared.control_revision);
    ensure!(source.stage_outbound_cancellation(operation)? == Some(request_id));
    let control = source.pending_outbound_cancellations(None, 1)?[0]
        .cancel_request()
        .ok_or_else(|| anyhow::anyhow!("missing control request"))?;
    ensure!(control.expected_control_revision.is_none());
    let cancelled = target_store.cancel_call(control, 102)?;
    ensure!(cancelled.cancellation_requested);
    source.record_outbound_cancellation(request_id, cancelled)?;
    ensure!(source.pending_outbound_cancellations(None, 1)?.is_empty());
    Ok(())
}
