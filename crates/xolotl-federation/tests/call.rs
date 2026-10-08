use std::sync::Arc;

use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallAuthorityRule, CallKernelBinding, CallMethod, CallPath, CallStatus, CallTarget,
    CancelCallRequest, Digest, ExportName, FederationCallStore, FederationError, FederationNodeId,
    FederationSubject, InspectCallRequest, InvokeCallRequest, MemoryFederationCallStore,
    PersistedCallResult, PrepareCallRequest, RequestId,
};

fn setup() -> Result<(MemoryFederationCallStore, FederationNodeId, CallTarget)> {
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let target = CallTarget {
        export: ExportName::new("image-tools")?,
        path: CallPath::new("/render/items/42")?,
        method: CallMethod::new("render")?,
        contract_digest: [3; 32],
    };
    let store = MemoryFederationCallStore::new(local);
    ensure!(
        store.set_call_authority(
            None,
            CallAuthorityRule {
                subject: FederationSubject::Node(peer),
                presenter: peer,
                target: target.clone(),
                enabled: true,
                expires_ms: 1000,
                max_input_bytes: 1024,
                max_prepare_window_ms: 100,
                max_result_retention_ms: 300,
            }
        )? == 1
    );
    Ok((store, peer, target))
}

fn request(peer: FederationNodeId, target: CallTarget, id: u8) -> PrepareCallRequest {
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

#[test]
fn prepare_is_effect_free_and_cancel_fences_late_invoke() -> Result<()> {
    let (store, peer, target) = setup()?;
    let prepare = request(peer, target, 4);
    let prepared = store.prepare_call(prepare.clone(), 100)?;
    ensure!(prepared.status == CallStatus::Reserved);
    ensure!(prepared.reserved_until_ms == 200);
    ensure!(store.prepare_call(prepare.clone(), 101)? == prepared);
    let mut changed = prepare.clone();
    changed.input_bytes = 6;
    ensure!(matches!(
        store.prepare_call(changed, 102),
        Err(FederationError::Conflict)
    ));
    let other = FederationNodeId::from_bytes([9; 48]);
    ensure!(matches!(
        store.inspect_call(
            InspectCallRequest {
                authenticated_origin: other,
                subject: FederationSubject::Node(other),
                call: prepared.call,
            },
            103
        ),
        Err(FederationError::Unauthorized)
    ));
    let cancel = CancelCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        control_request_id: RequestId::from_bytes([5; 16]),
        call: prepared.call,
        expected_control_revision: Some(1),
    };
    let closed = store.cancel_call(cancel.clone(), 104)?;
    ensure!(closed.status == CallStatus::Closed);
    ensure!(store.cancel_call(cancel, 105)? == closed);
    ensure!(matches!(
        store.invoke_call(
            InvokeCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                origin_request_id: prepare.origin_request_id,
                call: prepared.call,
                input: Arc::from(b"input".as_slice()),
            },
            106
        ),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn original_prepare_can_be_reconciled_after_deadline_and_grant_revocation() -> Result<()> {
    let (store, peer, target) = setup()?;
    let original = request(peer, target.clone(), 41);
    let prepared = store.prepare_call(original.clone(), 100)?;
    store.set_call_authority(
        Some(1),
        CallAuthorityRule {
            subject: FederationSubject::Node(peer),
            presenter: peer,
            target,
            enabled: false,
            expires_ms: 1000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 100,
            max_result_retention_ms: 300,
        },
    )?;
    ensure!(store.prepare_call(original.clone(), 900)? == prepared);
    let mut changed = original.clone();
    changed.input_bytes += 1;
    ensure!(matches!(
        store.prepare_call(changed, 901),
        Err(FederationError::Conflict)
    ));
    ensure!(
        store
            .prepare_call(request(peer, original.target, 42), 902)
            .is_err()
    );
    Ok(())
}

#[test]
fn accepted_work_reuses_one_locator_and_retains_unresolved_effect_evidence() -> Result<()> {
    let (store, peer, target) = setup()?;
    let prepare = request(peer, target, 6);
    let prepared = store.prepare_call(prepare.clone(), 100)?;
    let invoke = InvokeCallRequest {
        authenticated_origin: peer,
        subject: FederationSubject::Node(peer),
        origin_request_id: prepare.origin_request_id,
        call: prepared.call,
        input: Arc::from(b"input".as_slice()),
    };
    let first = store.invoke_call(invoke.clone(), 101)?;
    ensure!(first.status == CallStatus::Preparing);
    ensure!(store.invoke_call(invoke, 102)? == first);
    ensure!(
        store
            .inspect_call(
                InspectCallRequest {
                    authenticated_origin: peer,
                    subject: FederationSubject::Node(peer),
                    call: prepared.call,
                },
                103
            )?
            .status
            == CallStatus::Preparing
    );
    let binding = CallKernelBinding {
        process: 9,
        lifecycle: 10,
    };
    ensure!(store.bind_kernel_identity(prepared.call, binding, 103)? == binding);
    ensure!(store.kernel_call(prepared.call, 103)?.input.as_deref() == Some(b"input".as_slice()));
    store.authorize_kernel_execution(prepared.call, 103)?;
    let accepted = store.record_kernel_acceptance(prepared.call, Digest::from_bytes([7; 48]))?;
    ensure!(accepted.status == CallStatus::Accepted);
    ensure!(
        store.record_kernel_acceptance(prepared.call, Digest::from_bytes([7; 48]))? == accepted
    );
    let result = PersistedCallResult::new(true, Arc::from(b"done".as_slice()), None)?;
    let finished = store.record_call_result(prepared.call, result.clone(), vec![[8; 32]], 104)?;
    ensure!(finished.status == CallStatus::Finished);
    ensure!(finished.result == Some(result));
    let hidden = store.inspect_call(
        InspectCallRequest {
            authenticated_origin: peer,
            subject: FederationSubject::Node(peer),
            call: prepared.call,
        },
        404,
    )?;
    ensure!(hidden.result.is_none());
    ensure!(hidden.unresolved_effect_ids == vec![[8; 32]]);
    Ok(())
}
