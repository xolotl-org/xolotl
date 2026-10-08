use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallStatus, Digest, FederationCallStore as _, FederationOutboundCallStore, FederationSubject,
    OutboundCallIntent, PrepareCallRequest, SubjectAssertion, SubjectHolderKey, SubjectIssuerKey,
    SubjectPurpose,
};
use xolotl_federation_grpc::{DurableOperationIdHash, FederationCallIdentity};
use xolotl_kernel::{
    Bootstrap,
    driver::{DriverError, RemoteEndpoint, RemoteInvokeDispatch},
};
use xolotl_types::{
    IdentityRef, Invoke, InvokeResult, MethodId, OperationId, OutputMode, Path, ResourceName, Value,
};

use crate::federation::tests::{
    CA_CERT, configured_publisher, hex_bytes, live_test_boot, live_test_boot_with_host,
    online_digest_hex, private_file, wall_ms,
};
use crate::{
    config::{
        FederationCallAuthorityConfig, FederationCallSubjectConfig, FederationMethodCodecConfig,
        FederationMethodConfig, FederationOutboundCallConfig, FederationOutboundCodecConfig,
        FederationOutboundHostedSubjectConfig, FederationOutboundTimingConfig,
        FederationPeerDialConfig, FederationSubjectIssuerConfig, FederationSubjectPurposeConfig,
    },
    federation::{prepare as prepare_publisher, start},
};

fn bound_invoke(
    boot: &Bootstrap,
    operation: OperationId,
    acting: IdentityRef,
) -> Result<(Arc<dyn RemoteEndpoint>, RemoteInvokeDispatch, Invoke)> {
    let path = Path::parse("effect://federation/peer-echo")?;
    let registry = boot.kernel().registry();
    let resource_id = registry.resolve_resource(&ResourceName::new(path.clone()))?;
    let resource = registry
        .resource(resource_id)
        .context("outbound Resource absent")?;
    let binding = registry
        .binding(resource.binding)
        .context("outbound Binding absent")?;
    let endpoint_id = binding.endpoint.context("outbound Endpoint absent")?;
    let endpoint = registry
        .remote_endpoint(endpoint_id)
        .context("outbound Endpoint unregistered")?;
    Ok((
        endpoint,
        RemoteInvokeDispatch {
            endpoint_id,
            resource_id,
            method_id: MethodId::new(0),
            binding_generation: binding.generation,
            acting,
            output_mode: OutputMode::Unary,
        },
        Invoke {
            invocation_id: operation.to_string(),
            effect_path: path,
            method_id: MethodId::new(0),
            input: Value::shared_bytes(Arc::from(b"hello federation".as_slice())),
            deadline_ms: None,
            output_stream_to: None,
        },
    ))
}

#[tokio::test]
async fn stock_outbound_call_reuses_original_ref_after_source_restart() -> Result<()> {
    use xolotl_sdk::{Expression, Program};

    let directory = tempfile::tempdir()?;
    let target_dir = directory.path().join("target");
    let source_dir = directory.path().join("source");
    std::fs::create_dir(&target_dir)?;
    std::fs::create_dir(&source_dir)?;
    let mut target_config = configured_publisher(&target_dir)?;
    let mut source_config = configured_publisher(&source_dir)?;
    let target_node = prepare_publisher(&target_config)?
        .context("target disabled")?
        .node_id();
    let source_node = prepare_publisher(&source_config)?
        .context("source disabled")?
        .node_id();
    for config in [&mut target_config, &mut source_config] {
        config.federation.streams.clear();
        config.federation.state_history_publications.clear();
        config.federation.peers[0].exports[0].name = "tools".into();
    }
    target_config.federation.peers[0].node_id = hex_bytes(source_node.as_bytes());
    target_config.federation.peers[0].allowed_authorization_digests =
        vec![online_digest_hex(&source_config)?];
    source_config.federation.peers[0].node_id = hex_bytes(target_node.as_bytes());
    source_config.federation.peers[0].allowed_authorization_digests =
        vec![online_digest_hex(&target_config)?];
    source_config.server.federation_grpc_addr = None;

    let program = Program::new(Expression::Input);
    let program_path = private_file(
        &target_dir.join("echo-program.json"),
        &serde_json::to_vec(&program)?,
    )?;
    let mut method = FederationMethodConfig {
        export: "tools".into(),
        path: "/echo".into(),
        method: "echo".into(),
        contract_digest: String::new(),
        program_path,
        program_id: String::new(),
        identity_path: "identity://federation/echo".into(),
        codec: FederationMethodCodecConfig::BytesV1,
        grants: Vec::new(),
    };
    crate::federation_catalog::commit_test_method(&mut method)?;
    target_config
        .federation
        .call_authorities
        .push(FederationCallAuthorityConfig {
            presenter: hex_bytes(source_node.as_bytes()),
            subject: FederationCallSubjectConfig::Node,
            export: method.export.clone(),
            path: method.path.clone(),
            method: method.method.clone(),
            contract_digest: method.contract_digest.clone(),
            enabled: true,
            expires_ms: wall_ms()? + 120_000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 30_000,
            max_result_retention_ms: 30_000,
            expected_revision: None,
        });
    source_config
        .federation
        .outbound_calls
        .push(FederationOutboundCallConfig {
            local_path: "effect://federation/peer-echo".into(),
            local_method: "invoke".into(),
            binding_generation: 1,
            peer_node: hex_bytes(target_node.as_bytes()),
            export: method.export.clone(),
            path: method.path.clone(),
            method: method.method.clone(),
            contract_digest: method.contract_digest.clone(),
            allowed_acting: vec!["root".into()],
            allowed_hosted: Vec::new(),
            codec: FederationOutboundCodecConfig::BytesV1,
            timing: FederationOutboundTimingConfig::default(),
        });
    target_config.federation.methods.push(method);

    let target_db = xolotl_storage_redb::RedbStore::open_with_history(
        target_dir.join("calls.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let target_store = target_db.federation_store(target_node)?;
    let target_runtime = start(
        prepare_publisher(&target_config)?.context("target disabled")?,
        target_store,
        None,
        live_test_boot(&target_db)?,
    )
    .await?;
    let address = target_runtime.address.context("target did not listen")?;
    source_config.federation.peers[0].dial = Some(FederationPeerDialConfig {
        uri: format!("http://{address}"),
        server_name: "localhost".into(),
        trust_root_path: private_file(&source_dir.join("peer-ca.pem"), CA_CERT)?,
    });

    let source_path = source_dir.join("calls.redb");
    let source_db = xolotl_storage_redb::RedbStore::open_with_history(
        &source_path,
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let source_store = source_db.federation_store(source_node)?;
    let source_boot = live_test_boot(&source_db)?;
    let source_publisher = prepare_publisher(&source_config)?.context("source disabled")?;
    source_publisher.install_outbound(&source_boot, &source_store)?;
    let operation: OperationId = "4/5/6/7/8".parse()?;
    let (endpoint, dispatch, request) = bound_invoke(&source_boot, operation, IdentityRef::ROOT)?;
    let outcome =
        tokio::time::timeout(Duration::from_secs(20), endpoint.invoke(dispatch, request)).await??;
    ensure!(
        outcome.outcome
            == Ok(Value::shared_bytes(Arc::from(
                b"hello federation".as_slice()
            )))
    );
    let request_id = DurableOperationIdHash::new(source_store.kernel_call_namespace()?)?
        .request_id(source_node, operation)?;
    let original = source_store.outbound_call(request_id)?;
    let call = original.prepared.context("CallRef not persisted")?.call;
    ensure!(original.invoke_possible && original.terminal.is_some());

    target_runtime.task.abort();
    drop(target_runtime.task.await);
    drop(endpoint);
    drop(source_boot);
    drop(source_store);

    // A fresh Bootstrap and store handle model daemon restart. The separate
    // redb source test reopens the file itself; retaining this handle avoids
    // racing kernel-owned background task teardown while the target is offline.
    let reopened_store = source_db.federation_store(source_node)?;
    let blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(8)?);
    let reopened_boot = live_test_boot_with_host(
        &source_db,
        xolotl_kernel::host::HostRuntime::tokio_with_blocking(blocking.clone()),
    )?;
    let reopened_publisher = prepare_publisher(&source_config)?.context("source disabled")?;
    reopened_publisher.install_outbound(&reopened_boot, &reopened_store)?;
    let (endpoint, dispatch, request) = bound_invoke(&reopened_boot, operation, IdentityRef::ROOT)?;
    let replayed: InvokeResult = endpoint.invoke(dispatch, request).await?;
    ensure!(replayed.outcome == outcome.outcome);
    ensure!(
        reopened_store
            .outbound_call(request_id)?
            .prepared
            .context("replayed CallRef absent")?
            .call
            == call
    );

    let (endpoint, dispatch, request) =
        bound_invoke(&reopened_boot, "4/5/6/7/9".parse()?, IdentityRef(991))?;
    ensure!(matches!(
        endpoint.invoke(dispatch, request).await,
        Err(DriverError::Transport(_))
    ));
    blocking.close();
    blocking.wait_idle().await;
    let (endpoint, dispatch, request) = bound_invoke(&reopened_boot, operation, IdentityRef::ROOT)?;
    ensure!(matches!(
        endpoint.invoke(dispatch, request).await,
        Err(DriverError::OutcomeUnknown { operation_id, reason })
            if operation_id == operation.to_string()
                && reason == "source call ledger job not admitted: host unavailable; reconcile original identity"
    ));
    ensure!(
        reopened_store
            .outbound_call(request_id)?
            .prepared
            .context("closed host lost original CallRef")?
            .call
            == call
    );
    drop(endpoint);
    drop(reopened_boot);
    drop(reopened_store);

    source_config.federation.outbound_calls[0].binding_generation = 2;
    let changed_store = source_db.federation_store(source_node)?;
    let changed_boot = live_test_boot(&source_db)?;
    let changed_publisher = prepare_publisher(&source_config)?.context("source disabled")?;
    changed_publisher.install_outbound(&changed_boot, &changed_store)?;
    let (endpoint, dispatch, request) = bound_invoke(&changed_boot, operation, IdentityRef::ROOT)?;
    ensure!(matches!(
        endpoint.invoke(dispatch, request).await,
        Err(DriverError::OutcomeUnknown { .. })
    ));
    ensure!(
        changed_store
            .outbound_call(request_id)?
            .prepared
            .context("original CallRef absent")?
            .call
            == call
    );
    Ok(())
}

#[tokio::test]
async fn stock_hosted_outbound_call_and_cancel_use_holder_proof_over_tls() -> Result<()> {
    use xolotl_sdk::{Expression, Program};

    let directory = tempfile::tempdir()?;
    let target_dir = directory.path().join("hosted-target");
    let source_dir = directory.path().join("hosted-source");
    std::fs::create_dir(&target_dir)?;
    std::fs::create_dir(&source_dir)?;
    let mut target_config = configured_publisher(&target_dir)?;
    let mut source_config = configured_publisher(&source_dir)?;
    let target_node = prepare_publisher(&target_config)?
        .context("Hosted target disabled")?
        .node_id();
    let source_node = prepare_publisher(&source_config)?
        .context("Hosted source disabled")?
        .node_id();
    for config in [&mut target_config, &mut source_config] {
        config.federation.streams.clear();
        config.federation.state_history_publications.clear();
        config.federation.peers[0].exports[0].name = "tools".into();
    }
    target_config.federation.peers[0].node_id = hex_bytes(source_node.as_bytes());
    target_config.federation.peers[0].allowed_authorization_digests =
        vec![online_digest_hex(&source_config)?];
    source_config.federation.peers[0].node_id = hex_bytes(target_node.as_bytes());
    source_config.federation.peers[0].allowed_authorization_digests =
        vec![online_digest_hex(&target_config)?];
    source_config.server.federation_grpc_addr = None;

    let issuer_key = SubjectIssuerKey::generate()?;
    let issuer = issuer_key.issuer()?;
    let holder = SubjectHolderKey::generate()?;
    let now = wall_ms()?;
    let assertion = SubjectAssertion::new(
        issuer.id(),
        "people",
        "caller",
        target_node,
        source_node,
        SubjectPurpose::Invoke,
        now - 1_000,
        now + 120_000,
        holder.public_key(),
    )?;
    source_config
        .federation
        .outbound_hosted_subjects
        .push(FederationOutboundHostedSubjectConfig {
            name: "caller".into(),
            acting: "identity://federation/hosted-caller".into(),
            peer_node: hex_bytes(target_node.as_bytes()),
            issuer: hex_bytes(&issuer.id().as_bytes()),
            namespace: "people".into(),
            subject: "caller".into(),
            issuer_descriptor_path: private_file(&source_dir.join("issuer.bin"), &issuer.encode())?,
            assertion_path: private_file(&source_dir.join("assertion.bin"), &assertion.encode())?,
            issuer_signature_path: private_file(
                &source_dir.join("assertion.sig"),
                &issuer_key.sign_assertion(&assertion)?,
            )?,
            holder_key_path: private_file(
                &source_dir.join("holder.pk8"),
                holder.to_pkcs8()?.as_ref(),
            )?,
        });
    target_config
        .federation
        .subject_issuers
        .push(FederationSubjectIssuerConfig {
            issuer: hex_bytes(&issuer.id().as_bytes()),
            namespace: "people".into(),
            presenter: hex_bytes(source_node.as_bytes()),
            purposes: vec![FederationSubjectPurposeConfig::Invoke],
        });
    let program = Program::new(Expression::Input);
    let mut method = FederationMethodConfig {
        export: "tools".into(),
        path: "/echo".into(),
        method: "echo".into(),
        contract_digest: String::new(),
        program_path: private_file(
            &target_dir.join("echo-program.json"),
            &serde_json::to_vec(&program)?,
        )?,
        program_id: String::new(),
        identity_path: "identity://federation/echo".into(),
        codec: FederationMethodCodecConfig::BytesV1,
        grants: Vec::new(),
    };
    crate::federation_catalog::commit_test_method(&mut method)?;
    target_config
        .federation
        .call_authorities
        .push(FederationCallAuthorityConfig {
            presenter: hex_bytes(source_node.as_bytes()),
            subject: FederationCallSubjectConfig::Hosted {
                issuer: hex_bytes(&issuer.id().as_bytes()),
                namespace: "people".into(),
                subject: "caller".into(),
            },
            export: method.export.clone(),
            path: method.path.clone(),
            method: method.method.clone(),
            contract_digest: method.contract_digest.clone(),
            enabled: true,
            expires_ms: now + 120_000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 30_000,
            max_result_retention_ms: 30_000,
            expected_revision: None,
        });
    source_config
        .federation
        .outbound_calls
        .push(FederationOutboundCallConfig {
            local_path: "effect://federation/peer-echo".into(),
            local_method: "invoke".into(),
            binding_generation: 1,
            peer_node: hex_bytes(target_node.as_bytes()),
            export: method.export.clone(),
            path: method.path.clone(),
            method: method.method.clone(),
            contract_digest: method.contract_digest.clone(),
            allowed_acting: Vec::new(),
            allowed_hosted: vec!["caller".into()],
            codec: FederationOutboundCodecConfig::BytesV1,
            timing: FederationOutboundTimingConfig::default(),
        });
    target_config.federation.methods.push(method);

    let target_db = xolotl_storage_redb::RedbStore::open_with_history(
        target_dir.join("calls.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let target_store = target_db.federation_store(target_node)?;
    let target_runtime = start(
        prepare_publisher(&target_config)?.context("Hosted target disabled")?,
        target_store.clone(),
        None,
        live_test_boot(&target_db)?,
    )
    .await?;
    let address = target_runtime
        .address
        .context("Hosted target did not listen")?;
    source_config.federation.peers[0].dial = Some(FederationPeerDialConfig {
        uri: format!("http://{address}"),
        server_name: "localhost".into(),
        trust_root_path: private_file(&source_dir.join("peer-ca.pem"), CA_CERT)?,
    });
    let original_subject = std::mem::replace(
        &mut source_config.federation.outbound_hosted_subjects[0].subject,
        "another-caller".into(),
    );
    ensure!(prepare_publisher(&source_config).is_err());
    source_config.federation.outbound_hosted_subjects[0].subject = original_subject;
    let signature_path =
        &source_config.federation.outbound_hosted_subjects[0].issuer_signature_path;
    std::fs::write(
        signature_path,
        vec![0; xolotl_federation::FederationRoot::SIGNATURE_LEN],
    )?;
    ensure!(prepare_publisher(&source_config).is_err());
    std::fs::write(signature_path, issuer_key.sign_assertion(&assertion)?)?;
    let source_db = xolotl_storage_redb::RedbStore::open_with_history(
        source_dir.join("calls.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let source_store = source_db.federation_store(source_node)?;
    let source_boot = live_test_boot(&source_db)?;
    let prepared_source = prepare_publisher(&source_config)?.context("Hosted source disabled")?;
    prepared_source.install_outbound(&source_boot, &source_store)?;
    let acting = source_boot
        .kernel()
        .identities()
        .resolve_or_register(&Path::parse("identity://federation/hosted-caller")?)?;
    let operation: OperationId = "41/42/43/44/45".parse()?;
    let (endpoint, dispatch, request) = bound_invoke(&source_boot, operation, acting)?;
    let result =
        tokio::time::timeout(Duration::from_secs(20), endpoint.invoke(dispatch, request)).await??;
    ensure!(
        result.outcome
            == Ok(Value::shared_bytes(Arc::from(
                b"hello federation".as_slice()
            )))
    );
    let (endpoint, dispatch, request) =
        bound_invoke(&source_boot, "41/42/43/44/46".parse()?, IdentityRef::ROOT)?;
    ensure!(matches!(
        endpoint.invoke(dispatch, request).await,
        Err(DriverError::Transport(_))
    ));

    // Model a lost Prepare response, then let the independent cancellation
    // worker recover the exact Hosted request under a newly registered context.
    let cancelled_operation: OperationId = "41/42/43/44/47".parse()?;
    let cancelled_id = DurableOperationIdHash::new(source_store.kernel_call_namespace()?)?
        .request_id(source_node, cancelled_operation)?;
    source_store.bind_outbound_origin(
        cancelled_id,
        cancelled_operation,
        Digest::from_bytes([0x42; 48]),
    )?;
    let input: Arc<[u8]> = Arc::from(b"cancel hosted".as_slice());
    let request = PrepareCallRequest {
        authenticated_origin: source_node,
        subject: FederationSubject::Hosted(assertion.subject().clone()),
        origin_request_id: cancelled_id,
        target: xolotl_federation::CallTarget {
            export: xolotl_federation::ExportName::new("tools")?,
            path: xolotl_federation::CallPath::new("/echo")?,
            method: xolotl_federation::CallMethod::new("echo")?,
            contract_digest: super::decode_hex::<32>(
                &source_config.federation.outbound_calls[0].contract_digest,
                "contract digest",
            )?,
        },
        input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
        input_bytes: input.len() as u64,
        prepare_deadline_ms: wall_ms()? + 30_000,
        execution_deadline_ms: wall_ms()? + 60_000,
        result_retention_ms: 30_000,
    };
    source_store.stage_outbound(
        OutboundCallIntent {
            target_node,
            request: request.clone(),
            input,
        },
        wall_ms()?,
    )?;
    let sessions = prepared_source
        .outbound_sessions(source_boot.kernel().host_runtime(), source_store.clone())?;
    let session = sessions
        .session(target_node, &request.subject)
        .await
        .context("register Hosted cancellation subject")?;
    // A caller can drop its registration future after the peer has accepted
    // the frame. The unobserved acknowledgement must evict that Session so
    // the next attempt cannot collide with the same context ID.
    let ambiguous = Arc::new(tokio::sync::Mutex::new(super::PeerClient {
        client: Some(session.client.clone()),
        registered: HashSet::new(),
    }));
    let entered = Arc::new(tokio::sync::Notify::new());
    let pending = tokio::spawn({
        let ambiguous = Arc::clone(&ambiguous);
        let entered = Arc::clone(&entered);
        async move {
            let mut peer = ambiguous.lock().await;
            let attempt = super::RegistrationAttempt::new(&mut peer);
            entered.notify_one();
            std::future::pending::<()>().await;
            drop(attempt);
        }
    });
    entered.notified().await;
    pending.abort();
    drop(pending.await);
    let ambiguous = ambiguous.lock().await;
    ensure!(ambiguous.client.is_none() && ambiguous.registered.is_empty());
    drop(ambiguous);
    let prepared = session
        .client
        .prepare_call_as(session.context_id, request.clone())
        .await?;
    ensure!(prepared.status == CallStatus::Reserved);
    ensure!(target_store.prepared_call_for_request(&request)? == Some(prepared.clone()));
    ensure!(source_store.stage_outbound_cancellation(cancelled_operation)? == Some(cancelled_id));
    let pending = source_store.outbound_call(cancelled_id)?;
    ensure!(pending.prepared.is_none() && pending.cancellation_requested);
    crate::federation_cancellation::retry_cancellation(
        source_boot.kernel().host_runtime(),
        &source_store,
        sessions.as_ref(),
        pending.into(),
    )
    .await?;
    let cancelled = source_store.outbound_call(cancelled_id)?;
    ensure!(
        cancelled
            .prepared
            .as_ref()
            .is_some_and(|row| row.call == prepared.call)
            && cancelled.cancel_acknowledged.is_some()
            && !cancelled.invoke_possible
    );
    let terminal = session
        .client
        .inspect_call_persisted(
            session.context_id,
            cancelled_id,
            Arc::new(source_store.clone()),
        )
        .await?;
    ensure!(terminal.status == CallStatus::Closed);
    target_runtime.task.abort();
    drop(target_runtime.task.await);
    target_runtime.runtime.shutdown().await;

    // The same signed local identity mapping is loaded before recovery and
    // replays a settled Hosted call from the source ledger with the peer down.
    drop(session);
    drop(sessions);
    prepared_source
        .transport_runtime(source_boot.kernel().host_runtime())?
        .shutdown()
        .await;
    drop(source_boot);
    let reopened_boot = live_test_boot(&source_db)?;
    prepare_publisher(&source_config)?
        .context("Hosted source disabled after restart")?
        .install_outbound(&reopened_boot, &source_store)?;
    let acting = reopened_boot
        .kernel()
        .identities()
        .resolve_or_register(&Path::parse("identity://federation/hosted-caller")?)?;
    let (endpoint, dispatch, request) = bound_invoke(&reopened_boot, operation, acting)?;
    let replay = endpoint.invoke(dispatch, request).await?;
    ensure!(replay.outcome == result.outcome);
    Ok(())
}
