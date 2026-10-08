use super::*;
use anyhow::{Result, ensure};
use xolotl_federation::{
    CallMethod, CallPath, CallTarget, ExportName, FederationStore, FederationSubject,
};

fn source_fixture(
    input_bytes: usize,
) -> Result<(
    tempfile::TempDir,
    Arc<RedbFederationStore>,
    RequestId,
    OperationId,
)> {
    let directory = tempfile::tempdir()?;
    let owner = crate::RedbStore::open(directory.path().join("source-query.redb"))?;
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let source = Arc::new(owner.federation_store(local)?);
    source.set_peer_authority(peer, None, true)?;
    let operation: OperationId = "4/5/6/7/8".parse()?;
    let request_id = {
        let txn = source.db.begin_write()?;
        kernel_request_id(&txn, local, operation.to_bytes())?
    };
    let input: Arc<[u8]> = Arc::from(vec![19; input_bytes]);
    source.bind_outbound_origin(request_id, operation, Digest::from_bytes([3; 48]))?;
    source.stage_outbound(
        OutboundCallIntent {
            target_node: peer,
            request: PrepareCallRequest {
                authenticated_origin: local,
                subject: FederationSubject::Node(local),
                origin_request_id: request_id,
                target: CallTarget {
                    export: ExportName::new("source")?,
                    path: CallPath::new("/one")?,
                    method: CallMethod::new("run")?,
                    contract_digest: [4; 32],
                },
                input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                input_bytes: input_bytes as u64,
                prepare_deadline_ms: 200,
                execution_deadline_ms: 800,
                result_retention_ms: 300,
            },
            input,
        },
        100,
    )?;
    source.bind_outbound_prepared(
        request_id,
        CallPrepared {
            origin_request_id: request_id,
            call: CallRef::new(peer, [5; 32])?,
            status: CallStatus::Reserved,
            reserved_until_ms: 200,
            execution_deadline_ms: 800,
            result_retention_ms: 300,
            authority_revision: 1,
            control_revision: 1,
        },
    )?;
    source.mark_outbound_invoke_possible(request_id, 101)?;
    Ok((directory, source, request_id, operation))
}

#[test]
fn complete_source_queries_do_not_wait_for_writer_and_restore_one_snapshot() -> Result<()> {
    let (_directory, source, request_id, operation) = source_fixture(64 * 1024)?;
    source.stage_outbound_cancellation(operation)?;
    let expected = source.outbound_call(request_id)?;
    let writer = source.db.begin_write()?;
    writer
        .open_table(OUTBOUND_INPUTS)?
        .remove(request_id.as_bytes().as_slice())?;
    writer
        .open_table(OUTBOUND_UNSETTLED)?
        .remove(request_id.as_bytes().as_slice())?;
    writer
        .open_table(OUTBOUND_CANCEL_PENDING)?
        .remove(request_id.as_bytes().as_slice())?;
    let reader = Arc::clone(&source);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = (|| {
            Ok::<_, FederationError>((
                reader.outbound_call(request_id)?,
                reader.unsettled_outbound(None, 32)?,
                reader.pending_outbound_cancellations(None, 32)?,
            ))
        })();
        let _sent = send.send(result);
    });
    let observed = receive.recv_timeout(std::time::Duration::from_secs(5));
    drop(writer);
    worker
        .join()
        .map_err(|_panic| anyhow::anyhow!("source reader panicked"))?;
    let (point, unsettled, cancellations) = observed??;
    ensure!(
        point == expected && unsettled == [expected.clone()] && cancellations == [expected.clone()]
    );
    let prepared = expected.prepared.as_ref().ok_or(FederationError::Corrupt)?;
    let settled = source.settle_outbound(
        request_id,
        CallInspection {
            call: prepared.call,
            status: CallStatus::Finished,
            control_revision: 2,
            authority_revision: 1,
            reserved_until_ms: 200,
            execution_deadline_ms: 800,
            result_retained_until_ms: 500,
            result: Some(PersistedCallResult::new(
                true,
                Arc::from(vec![23; 64 * 1024]),
                None,
            )?),
            unresolved_effect_ids: Vec::new(),
            cancellation_requested: true,
            kernel_cancel_accepted: false,
            execution_stopped: true,
        },
    )?;
    let snapshot = source.db.begin_read()?;
    let writer = source.db.begin_write()?;
    writer.open_table(OUTBOUND_INPUTS)?.insert(
        request_id.as_bytes().as_slice(),
        b"corrupt input".as_slice(),
    )?;
    writer.open_table(OUTBOUND_RESULTS)?.insert(
        request_id.as_bytes().as_slice(),
        b"corrupt result".as_slice(),
    )?;
    writer.commit()?;
    ensure!(
        read_source_record(SourceReader::Read(&snapshot), request_id, source.node)?
            .ok_or(FederationError::Corrupt)?
            .0
            == settled
    );
    ensure!(matches!(
        source.outbound_call(request_id),
        Err(FederationError::Corrupt)
    ));
    let writer = source.db.begin_write()?;
    writer.open_table(OUTBOUND_INPUTS)?.insert(
        request_id.as_bytes().as_slice(),
        settled.intent.input.as_ref(),
    )?;
    writer.commit()?;
    ensure!(matches!(
        source.outbound_call(request_id),
        Err(FederationError::Corrupt)
    ));
    let output = &settled
        .terminal
        .as_ref()
        .and_then(|terminal| terminal.result.as_ref())
        .ok_or(FederationError::Corrupt)?
        .output;
    let writer = source.db.begin_write()?;
    writer
        .open_table(OUTBOUND_RESULTS)?
        .insert(request_id.as_bytes().as_slice(), output.as_ref())?;
    writer
        .open_table(OUTBOUND_UNSETTLED)?
        .insert(request_id.as_bytes().as_slice(), &[][..])?;
    writer
        .open_table(OUTBOUND_CANCEL_PENDING)?
        .insert(request_id.as_bytes().as_slice(), &[][..])?;
    writer.commit()?;
    ensure!(source.outbound_call(request_id)? == settled);
    ensure!(matches!(
        source.unsettled_outbound(None, 32),
        Err(FederationError::Corrupt)
    ));
    ensure!(matches!(
        source.pending_outbound_cancellations(None, 32),
        Err(FederationError::Corrupt)
    ));
    Ok(())
}

#[test]
fn source_page_stops_before_hydrating_excluded_payload() -> Result<()> {
    let (_directory, source, request_id, _operation) =
        source_fixture(MAX_OUTBOUND_PAGE_INPUT_BYTES / 2 + 1)?;
    let later = RequestId::from_bytes([255; 16]);
    ensure!(request_id < later);
    let mut intent = source.outbound_call(request_id)?.intent;
    intent.request.origin_request_id = later;
    source.stage_outbound(intent, 101)?;
    let writer = source.db.begin_write()?;
    writer.open_table(OUTBOUND_INPUTS)?.insert(
        later.as_bytes().as_slice(),
        b"corrupt later payload".as_slice(),
    )?;
    writer.commit()?;
    let page = source.unsettled_outbound(None, 32)?;
    ensure!(page.len() == 1 && page[0].intent.request_id() == request_id);
    ensure!(matches!(
        source.unsettled_outbound(Some(request_id), 32),
        Err(FederationError::Corrupt)
    ));
    Ok(())
}

#[test]
fn origin_evidence_reads_committed_snapshot_without_waiting_for_writer() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = crate::RedbStore::open(directory.path().join("origin-evidence.redb"))?;
    let node = FederationNodeId::from_bytes([1; 48]);
    let source = Arc::new(store.federation_store(node)?);
    let operation: OperationId = "4/5/6/7/8".parse()?;
    let txn = source.db.begin_write()?;
    let request_id = kernel_request_id(&txn, node, operation.to_bytes())?;
    let origin = StoredOrigin {
        operation: operation.to_bytes(),
        binding: Digest::from_bytes([2; 48]),
        state: OutboundOriginState::Active,
        released: false,
    };
    txn.open_table(OUTBOUND_ORIGINS)?
        .insert(request_id.as_bytes().as_slice(), origin.encode().as_slice())?;
    let reader = Arc::clone(&source);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _sent = send.send(reader.outbound_origin_evidence(request_id, operation));
    });
    let observed = receive.recv_timeout(std::time::Duration::from_secs(5));
    txn.commit()?;
    worker
        .join()
        .map_err(|_panic| anyhow::anyhow!("origin evidence reader panicked"))?;
    ensure!(observed?? == OutboundOriginEvidence::Fresh);
    ensure!(
        source.outbound_origin_evidence(request_id, operation)? == OutboundOriginEvidence::Recorded
    );
    ensure!(matches!(
        source.outbound_origin_evidence(RequestId::from_bytes([3; 16]), operation),
        Err(FederationError::Conflict)
    ));
    Ok(())
}
