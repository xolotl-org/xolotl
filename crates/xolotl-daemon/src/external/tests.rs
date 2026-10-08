use super::source::SourceDispatchError;
use super::*;
use anyhow::Context as _;
#[cfg(feature = "external-grpc")]
use anyhow::bail;
#[cfg(feature = "external-grpc")]
use serde_json::json;
#[cfg(feature = "external-grpc")]
use std::sync::{Mutex, MutexGuard};
#[cfg(feature = "external-grpc")]
use xolotl_gateway::external::EnvelopeAad;

macro_rules! assert {
    ($condition:expr $(,)?) => {
        anyhow::ensure!($condition, "assertion failed: {}", stringify!($condition));
    };
    ($condition:expr, $($arg:tt)+) => {
        anyhow::ensure!($condition, $($arg)+);
    };
}

macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => anyhow::ensure!(
                left == right,
                "assertion failed: left != right\nleft: {left:?}\nright: {right:?}"
            ),
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        anyhow::ensure!($left == $right, $($arg)+);
    };
}

#[cfg(feature = "external-grpc")]
macro_rules! assert_ne {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => anyhow::ensure!(
                left != right,
                "assertion failed: left == right\nleft: {left:?}\nright: {right:?}"
            ),
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        anyhow::ensure!($left != $right, $($arg)+);
    };
}

#[cfg(feature = "external-grpc")]
const TEST_EXTERNAL_PSK: [u8; 32] = [0x41; 32];

#[cfg(feature = "external-grpc")]
fn lock_test<'a, T>(mutex: &'a Mutex<T>, name: &str) -> anyhow::Result<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|error| anyhow::anyhow!("{name} mutex poisoned: {error}"))
}

#[cfg(feature = "external-grpc")]
fn parse_test_path(path: &str) -> anyhow::Result<Path> {
    Path::parse(path).map_err(|error| anyhow::anyhow!("parsing test path {path}: {error}"))
}

#[cfg(feature = "external-grpc")]
fn install_test_external_credential(
    handler: &DaemonExternalSessionHandler,
    credential: ExternalCredential,
) -> anyhow::Result<()> {
    let mut credentials = lock_test(&handler.external_credentials, "external_credentials")?;
    credentials.insert(
        (
            credential.installation_id().to_owned(),
            credential.generation(),
        ),
        credential,
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn external_installation_value() -> anyhow::Result<Value> {
    source_external_installation_value(false)
}

#[cfg(feature = "external-grpc")]
fn source_external_installation_value(commands: bool) -> anyhow::Result<Value> {
    serde_json::from_value(source_external_installation_json(commands))
        .context("building source external installation value")
}

#[cfg(feature = "external-grpc")]
fn source_external_installation_json(commands: bool) -> serde_json::Value {
    json!({
        "id": "chat",
        "platform": "chat",
        "transport": { "grpc": { "endpoint": null } },
        "trust": "sandboxed",
        "config_schema": null,
        "config": null,
        "projections": [{
            "id": "source",
            "role": "source",
            "namespace": null,
            "provides": [],
            "emits": {
                "sink": "state://events/external/chat/source",
                "purity": "effectful",
                "event_schema": null,
                "max_inline_payload_bytes": 65536,
                "capacity": { "max_events": 1024, "on_overflow": "drop_oldest" },
                "rate_limit": null,
                "commands": commands,
                "command_schema": if commands { json!({ "type": "string" }) } else { serde_json::Value::Null },
                "command_result_schema": if commands { json!({ "type": "string" }) } else { serde_json::Value::Null }
            },
            "version": 7
        }],
        "version": 11
    })
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_store_rejects_declaration_it_cannot_commit() -> anyhow::Result<()> {
    let (_boot, source_store) = external_test_boot();
    let mut installation = source_external_installation_json(false);
    installation["projections"][0]["emits"]["rate_limit"] =
        json!({ "window_ms": 1000, "max_events": 65_537 });
    assert!(
        write_chat_installation(source_store.as_ref(), serde_json::from_value(installation)?)
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn provider_external_installation_value() -> anyhow::Result<Value> {
    serde_json::from_value(json!({
        "id": "chat",
        "platform": "chat",
        "transport": { "grpc": { "endpoint": null } },
        "trust": "sandboxed",
        "config_schema": null,
        "config": null,
        "projections": [{
            "id": "provider",
            "role": "provider",
            "namespace": "effect://external-provider/chat",
            "provides": [{
                "effect_path": "effect://external-provider/chat/search",
                "purity": "idempotent",
                "input_schema": { "type": "string" },
                "output_schema": { "type": "string" }
            }, {
                "effect_path": "effect://external-provider/chat/summarize",
                "purity": "effectful"
            }],
            "emits": null,
            "version": 13
        }],
        "version": 17
    }))
    .context("building provider external installation value")
}

#[cfg(feature = "external-grpc")]
fn provider_external_installation_without_capabilities_value() -> anyhow::Result<Value> {
    serde_json::from_value(json!({
        "id": "chat",
        "platform": "chat",
        "transport": { "grpc": { "endpoint": null } },
        "trust": "sandboxed",
        "config_schema": null,
        "config": null,
        "projections": [{
            "id": "provider",
            "role": "provider",
            "namespace": "effect://external-provider/chat",
            "provides": [],
            "emits": null,
            "version": 13
        }],
        "version": 17
    }))
    .context("building provider installation without capabilities value")
}

#[cfg(feature = "external-grpc")]
async fn write_external_session(
    state: &Backend,
    source_store: &dyn SourceStore,
    installation_id: &str,
    role: &str,
    credential_generation: i64,
) -> anyhow::Result<()> {
    write_external_session_with_key_epoch(
        state,
        source_store,
        installation_id,
        role,
        credential_generation,
        0,
    )
    .await
}

#[cfg(feature = "external-grpc")]
async fn write_external_session_with_key_epoch(
    state: &Backend,
    source_store: &dyn SourceStore,
    installation_id: &str,
    role: &str,
    credential_generation: i64,
    key_epoch: i64,
) -> anyhow::Result<()> {
    let installation_epoch = source_store
        .load_installation(installation_id)
        .await?
        .context("installed external declaration")?
        .installation_epoch;
    state
        .write_set(
            &parse_test_path(&format!(
                "state://kernel/external-sessions/{installation_id}/{role}"
            ))?,
            serde_json::from_value(json!({
                "installation_id": installation_id,
                "role": role,
                "pairing_id": "pair-1",
                "credential_generation": credential_generation,
                "installation_epoch": installation_epoch.to_string(),
                "key_epoch": key_epoch,
                "state": "ready"
            }))
            .context("building external session state value")?,
        )
        .await
        .map_err(|error| anyhow::anyhow!("writing external session state: {error}"))?;
    state
        .write_set(
            &parse_test_path("state://kernel/external-pairings/pair-1")?,
            serde_json::from_value(json!({
                "pairing_id": "pair-1",
                "installation_id": installation_id,
                "installation_epoch": installation_epoch.to_string(),
                "credential_generation": credential_generation,
                "approved_roles": ["provider", "source"],
                "state": "approved"
            }))?,
        )
        .await
        .map_err(|error| anyhow::anyhow!("writing external pairing state: {error}"))?;
    Ok(())
}

#[cfg(feature = "external-grpc")]
async fn write_chat_installation(store: &dyn SourceStore, value: Value) -> anyhow::Result<()> {
    let definition: ExternalInstallationDef = serde_json::from_value(serde_json::to_value(value)?)?;
    let expected = store
        .load_installation("chat")
        .await?
        .map(|record| record.revision());
    let result = store.compare_install(definition, expected).await?;
    anyhow::ensure!(
        matches!(
            result,
            xolotl_source::ExternalInstallationMutation::Applied(Some(_))
        ),
        "installing chat external declaration conflicted"
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn external_outbound_channel() -> (
    ExternalSessionOutboundHandle,
    tokio::sync::mpsc::Receiver<
        Result<xolotl_proto::xolotl::v1::external::ExternalFrame, tonic::Status>,
    >,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    (Arc::new(TestExternalOutbound { tx }), rx)
}

#[cfg(feature = "external-grpc")]
async fn recv_external_frame(
    rx: &mut tokio::sync::mpsc::Receiver<
        Result<xolotl_proto::xolotl::v1::external::ExternalFrame, tonic::Status>,
    >,
    label: &'static str,
) -> anyhow::Result<xolotl_proto::xolotl::v1::external::ExternalFrame> {
    rx.recv()
        .await
        .with_context(|| format!("receiving {label} frame"))?
        .map_err(|status| anyhow::anyhow!("receiving {label} frame: {status}"))
}

#[cfg(feature = "external-grpc")]
fn expect_outbound_command_frame(
    frame: xolotl_proto::xolotl::v1::external::ExternalFrame,
) -> anyhow::Result<xolotl_proto::xolotl::v1::external::OutboundCommand> {
    match frame.frame {
        Some(xolotl_proto::xolotl::v1::external::external_frame::Frame::OutboundCommand(
            command,
        )) => Ok(command),
        Some(other) => bail!("expected source outbound command frame, got {other:?}"),
        None => bail!("expected source outbound command frame, got empty frame"),
    }
}

#[cfg(feature = "external-grpc")]
fn expect_invoke_frame(
    frame: xolotl_proto::xolotl::v1::external::ExternalFrame,
) -> anyhow::Result<xolotl_proto::xolotl::v1::external::Invoke> {
    match frame.frame {
        Some(xolotl_proto::xolotl::v1::external::external_frame::Frame::Invoke(invoke)) => {
            Ok(invoke)
        }
        Some(other) => bail!("expected provider invoke frame, got {other:?}"),
        None => bail!("expected provider invoke frame, got empty frame"),
    }
}

#[cfg(feature = "external-grpc")]
fn expect_control_frame(
    frame: xolotl_proto::xolotl::v1::external::ExternalFrame,
) -> anyhow::Result<xolotl_proto::xolotl::v1::external::ControlFrame> {
    match frame.frame {
        Some(xolotl_proto::xolotl::v1::external::external_frame::Frame::Control(control)) => {
            Ok(control)
        }
        Some(other) => bail!("expected provider control frame, got {other:?}"),
        None => bail!("expected provider control frame, got empty frame"),
    }
}

#[cfg(feature = "external-grpc")]
struct TestExternalOutbound {
    tx: tokio::sync::mpsc::Sender<
        Result<xolotl_proto::xolotl::v1::external::ExternalFrame, tonic::Status>,
    >,
}

#[cfg(feature = "external-grpc")]
impl TestExternalOutbound {
    async fn send_frame(
        &self,
        frame: xolotl_proto::xolotl::v1::external::external_frame::Frame,
    ) -> Result<(), tonic::Status> {
        self.tx
            .send(Ok(xolotl_proto::xolotl::v1::external::ExternalFrame {
                frame: Some(frame),
            }))
            .await
            .map_err(|error| {
                tonic::Status::unavailable(format!("test external session closed: {error}"))
            })
    }
}

#[cfg(feature = "external-grpc")]
#[async_trait::async_trait]
impl ExternalSessionOutbound for TestExternalOutbound {
    type Error = tonic::Status;

    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Self::Error> {
        self.send_frame(
            xolotl_proto::xolotl::v1::external::external_frame::Frame::Invoke(
                xolotl_proto::invoke_to_pb(&invoke),
            ),
        )
        .await
    }

    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Self::Error> {
        self.send_frame(
            xolotl_proto::xolotl::v1::external::external_frame::Frame::OutboundCommand(
                xolotl_proto::outbound_command_to_pb(&command),
            ),
        )
        .await
    }

    fn enqueue_cancel(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        self.tx
            .try_send(Ok(xolotl_proto::xolotl::v1::external::ExternalFrame {
                frame: Some(
                    xolotl_proto::xolotl::v1::external::external_frame::Frame::Control(
                        xolotl_proto::control_frame_to_pb(&frame),
                    ),
                ),
            }))
            .map_err(|_send_error| {
                tonic::Status::unavailable("test cancellation queue unavailable")
            })
    }

    async fn send_control(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        self.send_frame(
            xolotl_proto::xolotl::v1::external::external_frame::Frame::Control(
                xolotl_proto::control_frame_to_pb(&frame),
            ),
        )
        .await
    }
}

#[cfg(feature = "external-grpc")]
async fn write_external_revocation(
    state: &Backend,
    installation_id: &str,
    credential_generation_floor: i64,
) -> anyhow::Result<()> {
    state
        .write_set(
            &parse_test_path(&format!(
                "state://kernel/external-credential-revocations/{installation_id}"
            ))?,
            serde_json::from_value(json!({
                "installation_id": installation_id,
                "state": "revoked",
                "credential_generation_floor": credential_generation_floor
            }))
            .context("building external revocation state value")?,
        )
        .await
        .map_err(|error| anyhow::anyhow!("writing external revocation state: {error}"))?;
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn hello_from_context(context: &SessionContext) -> RoleSessionClientHello {
    RoleSessionClientHello {
        role: context.role,
        installation_id: context.installation_id.clone(),
        projection_id: context.projection_id.clone(),
        registry_hash: context.registry_hash.clone(),
        observed: xolotl_types::external::ObservedGenerations {
            presentation_config_generation: context.presentation_config_generation,
            alias_catalog_generation: context.alias_catalog_generation,
        },
        config_schema: None,
    }
}

#[cfg(feature = "external-grpc")]
struct ExternalTestFixture {
    boot: Arc<Bootstrap>,
    handler: DaemonExternalSessionHandler,
    session: EndpointSession,
    context: SessionContext,
}

#[cfg(feature = "external-grpc")]
fn external_test_boot() -> (Arc<Bootstrap>, Arc<dyn SourceStore>) {
    let (state, source_store) = xolotl_sdk::InMemoryBackend::new().into_source_parts();
    let boot = Bootstrap::from_kernel(
        KernelBuilder::new(state)
            .with_fact_sink(FactSink::in_memory().0)
            .build(),
    );
    (Arc::new(boot), source_store)
}

#[cfg(feature = "external-grpc")]
async fn ready_source_fixture(
    commands: bool,
    limits: Option<config::ExternalGatewaySessionLimits>,
) -> anyhow::Result<ExternalTestFixture> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(
        source_store.as_ref(),
        source_external_installation_value(commands)?,
    )
    .await?;
    write_external_session(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "source",
        5,
    )
    .await?;
    ready_fixture(boot, source_store, Role::Source, "source", limits).await
}

#[cfg(feature = "external-grpc")]
async fn ready_provider_fixture(
    installation: Value,
    limits: Option<config::ExternalGatewaySessionLimits>,
    key_epoch: i64,
) -> anyhow::Result<ExternalTestFixture> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(source_store.as_ref(), installation).await?;
    write_external_session_with_key_epoch(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "provider",
        9,
        key_epoch,
    )
    .await?;
    ready_fixture(boot, source_store, Role::Provider, "provider", limits).await
}

#[cfg(feature = "external-grpc")]
async fn ready_fixture(
    boot: Arc<Bootstrap>,
    source_store: Arc<dyn SourceStore>,
    role: Role,
    projection_id: &'static str,
    limits: Option<config::ExternalGatewaySessionLimits>,
) -> anyhow::Result<ExternalTestFixture> {
    let handler = match limits {
        Some(limits) => DaemonExternalSessionHandler::with_limits(
            boot.kernel().state().clone(),
            source_store,
            boot.kernel().registry().clone(),
            limits,
        ),
        None => DaemonExternalSessionHandler::new(
            boot.kernel().state().clone(),
            source_store,
            boot.kernel().registry().clone(),
            60_000,
        ),
    };
    let hello = hello_from_context(
        &handler
            .load_authority("chat", projection_id, role)
            .await
            .with_context(|| format!("loading {projection_id} authority"))?
            .context,
    );
    let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
        .await
        .with_context(|| format!("adjudicating {projection_id} session"))?;
    let mut session = EndpointSession::new();
    session
        .on_hello(&hello, |_| context.clone())
        .with_context(|| format!("accepting {projection_id} hello"))?;
    session
        .on_authenticated_ready(&xolotl_types::external::RoleReady {
            accepted_context: context.clone(),
        })
        .with_context(|| format!("marking {projection_id} session ready"))?;
    Ok(ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    })
}

#[cfg(feature = "external-grpc")]
fn secure_envelope_aad(context: &SessionContext, seq: u64) -> EnvelopeAad {
    secure_envelope_aad_with(context, seq, "control.config_ack", 0)
}

#[cfg(feature = "external-grpc")]
fn secure_envelope_aad_with(
    context: &SessionContext,
    seq: u64,
    frame_type: &str,
    key_epoch: u64,
) -> EnvelopeAad {
    EnvelopeAad {
        projection_id: context.projection_id.clone(),
        role: context.role.as_str().into(),
        session_id: context.session_id.clone(),
        seq,
        frame_type: frame_type.into(),
        binding_generation: context.binding_generation,
        credential_generation: context.credential_generation,
        transcript_hash: xolotl_gateway::external::external_session_transcript_hash(
            &hello_from_context(context),
            context,
        )
        .to_vec(),
        key_epoch,
        ..EnvelopeAad::default()
    }
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_adjudicates_from_typed_installation() -> anyhow::Result<()> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(source_store.as_ref(), external_installation_value()?).await?;
    boot.kernel()
        .state()
        .write_set(
            &parse_test_path("state://kernel/external-installations/chat")?,
            Value::string("forged-state-installation".into()),
        )
        .await?;
    write_external_session(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "source",
        5,
    )
    .await?;
    let handler = DaemonExternalSessionHandler::new(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        60_000,
    );

    let hello = RoleSessionClientHello {
        role: Role::Source,
        installation_id: "chat".into(),
        projection_id: "source".into(),
        registry_hash: "client-observed".into(),
        observed: Default::default(),
        config_schema: None,
    };
    let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
        .await
        .context("adjudicating source session")?;

    assert_eq!(context.installation_id, "chat");
    assert_eq!(context.projection_id, "source");
    assert_eq!(context.role, Role::Source);
    assert_eq!(context.credential_generation, 5);
    assert_eq!(context.binding_generation, 7);
    assert_eq!(context.installation_config_version, 1);
    assert!(context.installation_epoch > 0 && context.scope_epoch > 0);
    assert_ne!(context.registry_hash, "client-observed");
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_requires_approved_role_session() -> anyhow::Result<()> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(source_store.as_ref(), external_installation_value()?).await?;
    let handler = DaemonExternalSessionHandler::new(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        60_000,
    );

    let hello = RoleSessionClientHello {
        role: Role::Source,
        installation_id: "chat".into(),
        projection_id: "source".into(),
        registry_hash: String::new(),
        observed: Default::default(),
        config_schema: None,
    };
    let err = match ExternalSessionHandler::adjudicate_session(&handler, &hello).await {
        Ok(_context) => bail!("expected unauthenticated source session"),
        Err(error) => error,
    };

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_rejects_revoked_role_session() -> anyhow::Result<()> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(source_store.as_ref(), external_installation_value()?).await?;
    write_external_session(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "source",
        2,
    )
    .await?;
    write_external_revocation(boot.kernel().state(), "chat", 2).await?;
    let handler = DaemonExternalSessionHandler::new(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        60_000,
    );

    let hello = RoleSessionClientHello {
        role: Role::Source,
        installation_id: "chat".into(),
        projection_id: "source".into(),
        registry_hash: String::new(),
        observed: Default::default(),
        config_schema: None,
    };
    let err = match ExternalSessionHandler::adjudicate_session(&handler, &hello).await {
        Ok(_context) => bail!("expected revoked source session rejection"),
        Err(error) => error,
    };

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_authority_rejects_malformed_revocation_records() -> anyhow::Result<()> {
    let (boot, _source_store) = external_test_boot();
    let state = boot.kernel().state();
    let path = parse_test_path("state://kernel/external-credential-revocations/chat")?;
    for malformed in [
        json!({ "state": "revoked", "credential_generation_floor": 1 }),
        json!({ "installation_id": "other", "state": "revoked", "credential_generation_floor": 1 }),
        json!({ "installation_id": "chat", "credential_generation_floor": 1 }),
        json!({ "installation_id": "chat", "state": "ready", "credential_generation_floor": 1 }),
        json!({ "installation_id": "chat", "state": "revoked", "credential_generation_floor": 0 }),
    ] {
        state
            .write_set(&path, serde_json::from_value(malformed)?)
            .await?;
        let error = match super::authority::ensure_external_not_revoked(state, "chat", 2).await {
            Ok(()) => bail!("malformed revocation record must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }
    write_external_revocation(state, "chat", 1).await?;
    super::authority::ensure_external_not_revoked(state, "chat", 2).await?;
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_ingests_source_event() -> anyhow::Result<()> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(source_store.as_ref(), external_installation_value()?).await?;
    write_external_session(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "source",
        5,
    )
    .await?;
    let handler = DaemonExternalSessionHandler::new(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        60_000,
    );
    let hello = hello_from_context(
        &handler
            .load_authority("chat", "source", Role::Source)
            .await
            .context("loading source authority")?
            .context,
    );
    let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
        .await
        .context("adjudicating source session")?;
    let mut session = EndpointSession::new();
    session
        .on_hello(&hello, |_| context.clone())
        .context("accepting source hello")?;
    session
        .on_authenticated_ready(&xolotl_types::external::RoleReady {
            accepted_context: context.clone(),
        })
        .context("marking source session ready")?;

    let ack = ExternalSessionHandler::on_inbound_event(
        &handler,
        InboundEvent {
            id: "evt-1".into(),
            payload: Value::string("hello".into()),
            observed: Default::default(),
            timestamp_ms: 1,
            stream_id: None,
            seq: None,
            stream_epoch: None,
        },
        &session,
        &context,
    )
    .await
    .context("ingesting source event")?;

    assert_eq!(ack.status, xolotl_types::external::AckStatus::Accepted);
    let rows = boot
        .kernel()
        .state()
        .query(&xolotl_sdk::StateScan::new(parse_test_path(
            "state://events/external/chat/source",
        )?))
        .await
        .map_err(|error| anyhow::anyhow!("reading source event sink: {error}"))?;
    assert_eq!(rows.entries.len(), 1);
    assert!(rows.next.is_none());
    assert_eq!(
        rows.entries[0].1.value,
        Value::list(vec![Value::string("hello".into())])
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_source_stream_lifecycle_uses_current_ready_scope() -> anyhow::Result<()> {
    use xolotl_types::external::{SourceStreamOperation, SourceStreamOutcome};

    let fixture = ready_source_fixture(false, None).await?;
    let inspect = ExternalSessionHandler::on_source_stream_request(
        &fixture.handler,
        SourceStreamRequest {
            request_id: "inspect-1".into(),
            stream_id: "records".into(),
            operation: SourceStreamOperation::Inspect,
        },
        &fixture.session,
        &fixture.context,
    )
    .await?;
    let SourceStreamOutcome::Inspected(snapshot) = inspect.outcome else {
        bail!("source stream inspection failed: {:?}", inspect.outcome);
    };
    assert!(snapshot.active.is_none());
    let opened = ExternalSessionHandler::on_source_stream_request(
        &fixture.handler,
        SourceStreamRequest {
            request_id: "open-1".into(),
            stream_id: "records".into(),
            operation: SourceStreamOperation::Open {
                expected_revision: snapshot.revision,
            },
        },
        &fixture.session,
        &fixture.context,
    )
    .await?;
    assert!(matches!(opened.outcome, SourceStreamOutcome::Opened(_)));

    let installed = fixture
        .handler
        .source_store
        .load_installation("chat")
        .await?
        .context("Source installation missing")?;
    let expected = installed.revision();
    let mut definition = installed.definition;
    let source = definition
        .projections
        .iter_mut()
        .find(|projection| projection.id == "source")
        .context("Source projection missing")?;
    source.version += 1;
    assert!(matches!(
        fixture
            .handler
            .source_store
            .compare_install(definition, Some(expected))
            .await?,
        xolotl_source::ExternalInstallationMutation::Applied(Some(_))
    ));
    let stale = ExternalSessionHandler::on_source_stream_request(
        &fixture.handler,
        SourceStreamRequest {
            request_id: "inspect-2".into(),
            stream_id: "records".into(),
            operation: SourceStreamOperation::Inspect,
        },
        &fixture.session,
        &fixture.context,
    )
    .await
    .err()
    .context("old ready scope admitted a stream request")?;
    assert_eq!(stale.code(), tonic::Code::PermissionDenied);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn source_ingest_errors_distinguish_rejection_from_unknown_commit() -> anyhow::Result<()> {
    let retention = source_ingest_error_ack(
        "evt-retention".into(),
        Some(7),
        &SourceIngestError::RetentionCapacityExceeded,
    )
    .context("retention limit must be a definite rejection")?;
    assert_eq!(retention.status, AckStatus::Rejected);
    assert_eq!(
        retention.reject_reason.as_deref(),
        Some("retention_capacity_exceeded")
    );
    assert_eq!(retention.stream_epoch, Some(7));
    assert_eq!(
        source_ingest_status(SourceIngestError::RetentionCapacityExceeded).code(),
        tonic::Code::ResourceExhausted,
    );
    let policy = source_ingest_error_ack(
        "evt-1".into(),
        None,
        &SourceIngestError::Policy("private detail".into()),
    )
    .context("policy ingest error should map to rejected ack")?;
    assert_eq!(
        policy,
        EventAck {
            id: "evt-1".into(),
            status: AckStatus::Rejected,
            reject_reason: Some("policy_rejected".into()),
            stream_epoch: None,
        }
    );

    assert_eq!(
        source_ingest_error_ack("evt-2".into(), None, &SourceIngestError::RateLimited)
            .context("rate limit ingest error should map to rejected ack")?
            .reject_reason,
        Some("rate_limited".into())
    );
    assert_eq!(
        source_ingest_error_ack("evt-3".into(), None, &SourceIngestError::PayloadTooLarge)
            .context("payload size ingest error should map to rejected ack")?
            .reject_reason,
        Some("payload_too_large".into())
    );
    assert_eq!(
        source_ingest_error_ack(
            "evt-conflict".into(),
            Some(9),
            &SourceIngestError::EventIdConflict
        )
        .context("event identity conflict should map to rejected ack")?,
        EventAck {
            id: "evt-conflict".into(),
            status: AckStatus::Rejected,
            reject_reason: Some("event_id_conflict".into()),
            stream_epoch: Some(9),
        }
    );
    assert_eq!(
        source_ingest_error_ack(
            "evt-4".into(),
            None,
            &SourceIngestError::ForbiddenPayloadField {
                field: "access_token".into()
            }
        )
        .context("forbidden field ingest error should map to rejected ack")?
        .reject_reason,
        Some("forbidden_payload_field".into())
    );
    assert_eq!(
        source_ingest_error_ack(
            "evt-5".into(),
            None,
            &SourceIngestError::RegistryHashMismatch
        ),
        None
    );
    assert_eq!(
        source_ingest_error_ack(
            "evt-6".into(),
            Some(17),
            &SourceIngestError::CommitOutcomeUnknown,
        ),
        Some(EventAck {
            id: "evt-6".into(),
            status: AckStatus::OutcomeUnknown,
            reject_reason: None,
            stream_epoch: Some(17),
        })
    );
    assert_eq!(
        source_ingest_status(SourceIngestError::CommitOutcomeUnknown).code(),
        tonic::Code::Unknown
    );
    assert_eq!(
        source_ingest_error_ack("evt-7".into(), None, &SourceIngestError::SinkTypeMismatch),
        Some(EventAck {
            id: "evt-7".into(),
            status: AckStatus::Rejected,
            reject_reason: Some("sink_type_mismatch".into()),
            stream_epoch: None,
        })
    );
    assert_eq!(
        source_ingest_status(SourceIngestError::SinkTypeMismatch).code(),
        tonic::Code::FailedPrecondition
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_public_state_cannot_spoof_private_source_dedup() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(false, None).await?;
    let path = parse_test_path("state://kernel/source-events/chat/source/evt-pending")?;
    let pending: Value = serde_json::from_value(json!({
        "status": "pending",
        "received_at_ms": 1,
        "claim_id": "0123456789abcdef0123456789abcdef",
    }))?;
    boot.kernel()
        .state()
        .write_set(&path, pending.clone())
        .await?;

    let ack = ExternalSessionHandler::on_inbound_event(
        &handler,
        InboundEvent {
            id: "evt-pending".into(),
            payload: Value::string("hello".into()),
            observed: Default::default(),
            timestamp_ms: 1,
            stream_id: None,
            seq: None,
            stream_epoch: None,
        },
        &session,
        &context,
    )
    .await?;
    assert_eq!(ack.status, AckStatus::Accepted);
    assert_eq!(ack.reject_reason, None);
    assert_eq!(boot.kernel().state().read(&path).await?, Some(pending));
    assert_eq!(
        boot.kernel()
            .state()
            .read(&parse_test_path("state://events/external/chat/source")?)
            .await?,
        Some(Value::list(vec![Value::string("hello".into())]))
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_returns_rejected_ack_for_source_schema_error() -> anyhow::Result<()>
{
    let (boot, source_store) = external_test_boot();
    let mut install = source_external_installation_json(false);
    install["projections"][0]["emits"]["event_schema"] = json!({ "type": "string" });
    write_chat_installation(
        source_store.as_ref(),
        serde_json::from_value(install)
            .context("building source installation with event schema")?,
    )
    .await?;
    write_external_session(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "source",
        5,
    )
    .await?;
    let handler = DaemonExternalSessionHandler::new(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        60_000,
    );
    let hello = hello_from_context(
        &handler
            .load_authority("chat", "source", Role::Source)
            .await
            .context("loading source authority")?
            .context,
    );
    let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
        .await
        .context("adjudicating source session")?;
    let mut session = EndpointSession::new();
    session
        .on_hello(&hello, |_| context.clone())
        .context("accepting source hello")?;
    session
        .on_authenticated_ready(&xolotl_types::external::RoleReady {
            accepted_context: context.clone(),
        })
        .context("marking source session ready")?;

    let ack = ExternalSessionHandler::on_inbound_event(
        &handler,
        InboundEvent {
            id: "evt-schema".into(),
            payload: Value::integer(1),
            observed: Default::default(),
            timestamp_ms: 1,
            stream_id: None,
            seq: None,
            stream_epoch: None,
        },
        &session,
        &context,
    )
    .await
    .context("ingesting schema-invalid source event")?;

    assert_eq!(ack.status, AckStatus::Rejected);
    assert_eq!(ack.reject_reason, Some("schema_rejected".into()));
    assert_eq!(
        boot.kernel()
            .state()
            .read(&parse_test_path("state://events/external/chat/source")?)
            .await
            .map_err(|error| anyhow::anyhow!("reading source event sink: {error}"))?,
        None
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_gates_external_control_frames() -> anyhow::Result<()> {
    let (boot, source_store) = external_test_boot();
    write_chat_installation(source_store.as_ref(), external_installation_value()?).await?;
    write_external_session(
        boot.kernel().state(),
        source_store.as_ref(),
        "chat",
        "source",
        5,
    )
    .await?;
    let handler = DaemonExternalSessionHandler::new(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        60_000,
    );
    let hello = hello_from_context(
        &handler
            .load_authority("chat", "source", Role::Source)
            .await
            .context("loading source authority")?
            .context,
    );
    let context = ExternalSessionHandler::adjudicate_session(&handler, &hello)
        .await
        .context("adjudicating source session")?;
    let mut session = EndpointSession::new();
    session
        .on_hello(&hello, |_| context.clone())
        .context("accepting source hello")?;
    session
        .on_authenticated_ready(&xolotl_types::external::RoleReady {
            accepted_context: context.clone(),
        })
        .context("marking source session ready")?;

    ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::Heartbeat { timestamp_ms: 10 },
        &session,
        &context,
    )
    .await
    .context("accepting heartbeat control frame")?;
    ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::ConfigAck {
            axis: ConfigAxis::InstallationConfig,
            version: context.installation_config_version,
            status: xolotl_types::external::ApplyStatus::Applied,
        },
        &session,
        &context,
    )
    .await
    .context("accepting matching config ack")?;

    let err = match ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::ConfigAck {
            axis: ConfigAxis::InstallationConfig,
            version: context.installation_config_version + 1,
            status: xolotl_types::external::ApplyStatus::Applied,
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected mismatched config ack rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = match ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::InstallationConfigUpdate {
            config_version: context.installation_config_version + 1,
            config: Value::null(),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected installation config update rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = match ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::Shutdown {
            graceful: true,
            timeout_ms: 1_000,
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected shutdown control frame rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = match ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::FlowControl(xolotl_types::external::FlowSignal::Pause),
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected flow-control frame rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = match ExternalSessionHandler::on_control(
        &handler,
        ControlFrame::PresentationProfileUpdate {
            profile_generation: 1,
            profile_hash: String::new(),
            profile: Value::null(),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected presentation update validation rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_command_expired_before_send_does_not_publish_or_fence_id() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut receiver) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let command = || xolotl_types::external::OutboundCommand {
        id: "expired-before-send".into(),
        action: Value::string("sync".into()),
        observed: Default::default(),
    };
    let deadline = now_millis() + 200;
    let mut pending = handler
        .source_hub
        .begin_for_session(command(), &session, &context, Some(deadline))
        .await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while now_millis() <= deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("wall clock did not reach the pre-send deadline")?;
    match pending.send().await {
        Err(SourceDispatchError::Rejected(status)) => {
            assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
        }
        other => bail!("expired command must reject before sending: {other:?}"),
    }
    assert!(receiver.try_recv().is_err());
    drop(pending);
    assert_eq!(handler.source_hub.counts()?.1, 0);
    let retry = handler
        .send_source_command(command(), &session, &context, None)
        .await?;
    recv_external_frame(&mut receiver, "retry after pre-send expiry").await?;
    drop(retry);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test(start_paused = true)]
async fn source_command_send_deadline_uses_admission_monotonic_time() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut receiver) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let mut pending = handler
        .source_hub
        .begin_for_session(
            xolotl_types::external::OutboundCommand {
                id: "monotonic-send-deadline".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            Some(now_millis() + 60_000),
        )
        .await?;
    tokio::time::advance(Duration::from_millis(60_001)).await;
    match pending.send().await {
        Err(SourceDispatchError::Rejected(status)) => {
            assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
        }
        other => bail!("elapsed monotonic deadline must reject before sending: {other:?}"),
    }
    assert!(receiver.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_maintenance_shares_batches_and_resumes_both_owners() -> anyhow::Result<()> {
    use crate::source_maintenance::{MaintenanceTurn, maintain_tick};

    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let commands = SharedSourceCommands {
        hub: handler.source_hub.clone(),
        publisher: handler.source_bindings.clone(),
    };
    let (outbound, mut receiver) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    for index in 0..130 {
        let pending = handler
            .send_source_command(
                OutboundCommand {
                    id: format!("maintenance-{index:03}"),
                    action: Value::string("sync".into()),
                    observed: Default::default(),
                },
                &session,
                &context,
                None,
            )
            .await?;
        recv_external_frame(&mut receiver, "command retained for maintenance").await?;
        drop(pending);
    }
    for index in 0..130 {
        let ack = ExternalSessionHandler::on_inbound_event(
            &handler,
            InboundEvent {
                id: format!("maintenance-event-{index:03}"),
                payload: Value::string("event".into()),
                observed: Default::default(),
                timestamp_ms: 1,
                stream_id: None,
                seq: None,
                stream_epoch: None,
            },
            &session,
            &context,
        )
        .await?;
        assert_eq!(ack.status, AckStatus::Accepted);
    }
    let at_millis = now_millis() + 60_001;
    let settings = config::SourceMaintenanceConfig {
        interval_ms: 10_000,
        max_batches_per_tick: 1,
    };
    let mut turn = MaintenanceTurn::default();
    let before = handler.source_hub.occupied()?;
    let first = maintain_tick(
        handler.source_store.as_ref(),
        &commands,
        settings,
        &mut turn,
        Arc::new(move || at_millis),
    )
    .await?;
    assert_eq!(first.batches, 1);
    assert_eq!(first.examined, 64);
    assert!(first.removed > 0);
    assert_eq!(handler.source_hub.occupied()?, before);
    let second = maintain_tick(
        handler.source_store.as_ref(),
        &commands,
        settings,
        &mut turn,
        Arc::new(move || at_millis),
    )
    .await?;
    assert_eq!(second.batches, 1);
    assert_eq!(second.examined, 64);
    assert_eq!(handler.source_hub.occupied()?, before - second.removed);
    let remaining = maintain_tick(
        handler.source_store.as_ref(),
        &commands,
        config::SourceMaintenanceConfig {
            max_batches_per_tick: 64,
            ..settings
        },
        &mut turn,
        Arc::new(move || at_millis),
    )
    .await?;
    assert!(remaining.batches <= 64 && remaining.examined <= 64 * 64);
    assert_eq!(handler.source_hub.occupied()?, 0);
    assert_eq!(commands.expire_retained(at_millis)?.examined, 0);
    let sink = boot
        .kernel()
        .state()
        .read(&parse_test_path("state://events/external/chat/source")?)
        .await?;
    assert!(sink.is_some());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test(start_paused = true)]
async fn provider_accepted_result_is_not_replaced_by_an_elapsed_wait_deadline() -> anyhow::Result<()>
{
    use std::future::Future as _;

    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, mut receiver) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let (endpoint, dispatch) = registered_search_endpoint(&boot)?;
    let mut pending = Box::pin(endpoint.invoke(
        dispatch,
        Invoke {
            invocation_id: "accepted-before-deadline".into(),
            effect_path: parse_test_path("effect://external-provider/chat/search")?,
            method_id: MethodId::new(0),
            input: Value::string("query".into()),
            deadline_ms: Some(now_millis() + 60_000),
            output_stream_to: None,
        },
    ));
    assert!(
        std::future::poll_fn(|context| std::task::Poll::Ready(pending.as_mut().poll(context)))
            .await
            .is_pending()
    );
    expect_invoke_frame(recv_external_frame(&mut receiver, "provider invoke").await?)?;
    let expected = InvokeResult {
        invocation_id: "accepted-before-deadline".into(),
        outcome: Ok(Value::string("accepted".into())),
    };
    ExternalSessionHandler::on_invoke_result(&handler, expected.clone(), &session, &context)
        .await?;
    tokio::time::advance(Duration::from_millis(60_001)).await;
    assert_eq!(pending.await?, expected);
    assert!(receiver.try_recv().is_err());
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test(start_paused = true)]
async fn provider_deadline_covers_blocked_outbound_send() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, mut receiver) = external_outbound_channel();
    for index in 0..8 {
        outbound
            .send_control(ControlFrame::ProviderCancel {
                invocation_id: format!("occupy-{index}"),
                reason: "test queue backpressure".into(),
            })
            .await?;
    }
    ExternalSessionHandler::on_ready(&handler, &session, context, outbound).await?;
    let (endpoint, dispatch) = registered_search_endpoint(&boot)?;
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.invoke(
            dispatch,
            Invoke {
                invocation_id: "blocked-send".into(),
                effect_path: parse_test_path("effect://external-provider/chat/search")?,
                method_id: MethodId::new(0),
                input: Value::string("query".into()),
                deadline_ms: Some(now_millis() + 100),
                output_stream_to: None,
            },
        ),
    )
    .await
    .context("provider deadline did not cover outbound send")?;
    assert_eq!(
        outcome,
        Err(DriverError::OutcomeUnknown {
            operation_id: "blocked-send".into(),
            reason: "deadline_exceeded".into(),
        })
    );
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    for _ in 0..8 {
        expect_control_frame(recv_external_frame(&mut receiver, "queued control").await?)?;
    }
    assert!(receiver.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn shared_source_capacity_rejects_before_send_and_idle_expiry_releases() -> anyhow::Result<()>
{
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let commands = SharedSourceCommands::new(
        boot.kernel().state().clone(),
        handler.source_store.clone(),
        boot.kernel().registry().clone(),
        std::num::NonZeroUsize::MIN.saturating_add(1),
    );
    let handler = DaemonExternalSessionHandler::with_shared_source_commands(
        boot.kernel().state().clone(),
        handler.source_store.clone(),
        boot.kernel().registry().clone(),
        config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            ..Default::default()
        },
        PairingDisplayEdge::default(),
        commands.clone(),
        Arc::new(now_millis),
    );
    let other = DaemonExternalSessionHandler::with_shared_source_commands(
        boot.kernel().state().clone(),
        handler.source_store.clone(),
        boot.kernel().registry().clone(),
        config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            ..Default::default()
        },
        PairingDisplayEdge::default(),
        commands.clone(),
        Arc::new(now_millis),
    );
    let (outbound, mut receiver) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let command = |id: &str| xolotl_types::external::OutboundCommand {
        id: id.into(),
        action: Value::string("sync".into()),
        observed: Default::default(),
    };
    let pending = handler
        .send_source_command(command("first"), &session, &context, None)
        .await?;
    recv_external_frame(&mut receiver, "first command").await?;
    drop(pending);
    let rejected = match other
        .send_source_command(command("second"), &session, &context, None)
        .await
    {
        Ok(_) => bail!("shared Source capacity should reject before send"),
        Err(error) => error,
    };
    assert_eq!(rejected.code(), tonic::Code::ResourceExhausted);
    assert!(receiver.try_recv().is_err());
    assert_eq!(commands.expire_retained(now_millis() + 60_001)?.removed, 2);
    let pending = other
        .send_source_command(command("second"), &session, &context, None)
        .await?;
    recv_external_frame(&mut receiver, "command after idle expiry").await?;
    drop(pending);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_resolves_only_registered_source_commands() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering source outbound channel")?;

    let command = xolotl_types::external::OutboundCommand {
        id: "cmd-1".into(),
        action: Value::string("sync".into()),
        observed: Default::default(),
    };
    let mut receiver = handler
        .send_source_command(command, &session, &context, None)
        .await
        .context("sending source command")?;
    let sent = expect_outbound_command_frame(
        recv_external_frame(&mut outbound_rx, "source command").await?,
    )?;
    let sent =
        xolotl_proto::outbound_command_from_pb(&sent).context("decoding outbound command frame")?;
    assert_eq!(sent.id, "cmd-1");
    assert_eq!(sent.action, Value::string("sync".into()));
    assert_eq!(
        sent.observed.presentation_config_generation,
        context.presentation_config_generation
    );

    let expected = CommandResult {
        id: "cmd-1".into(),
        outcome: Ok(Value::string("ok".into())),
    };
    ExternalSessionHandler::on_command_result(&handler, expected.clone(), &session, &context)
        .await
        .context("resolving source command result")?;
    assert_eq!(
        receiver
            .wait()
            .await
            .context("awaiting source command receiver")?,
        expected
    );

    let err = match ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "cmd-1".into(),
            outcome: Ok(Value::string("again".into())),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected duplicate command result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = match handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-bad-action".into(),
                action: Value::integer(7),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
    {
        Ok(_receiver) => bail!("expected invalid source command action rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(outbound_rx.try_recv().is_err());

    let mut receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-bad-result".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
        .context("sending source command with invalid result payload")?;
    recv_external_frame(&mut outbound_rx, "source command with invalid result").await?;
    let err = match ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "cmd-bad-result".into(),
            outcome: Ok(Value::integer(7)),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected invalid command result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(receiver.wait().await.is_err());
    drop(receiver);
    assert!(handler.source_hub.counts()?.1 == 0);
    assert!(handler.source_hub.counts()?.2 == 0);

    let mut receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-large-result".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
        .context("sending source command with oversized result payload")?;
    recv_external_frame(&mut outbound_rx, "source command with oversized result").await?;
    let err = match ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "cmd-large-result".into(),
            outcome: Ok(Value::string("x".repeat(
                config::DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES + 1,
            ))),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected oversized command result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert!(receiver.wait().await.is_err());
    assert!(handler.source_hub.counts()?.1 == 0);
    assert!(handler.source_hub.counts()?.2 == 0);

    let mut receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-large-error".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
        .context("sending source command with oversized error result")?;
    recv_external_frame(&mut outbound_rx, "source command with oversized error").await?;
    let err = match ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "cmd-large-error".into(),
            outcome: Err(xolotl_types::ErrorInfo {
                kind: "remote".into(),
                message: "x"
                    .repeat(config::DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES),
            }),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected oversized command error result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert!(receiver.wait().await.is_err());
    assert!(handler.source_hub.counts()?.1 == 0);
    assert!(handler.source_hub.counts()?.2 == 0);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_expires_pending_source_commands() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering source outbound channel")?;

    let deadline_ms = now_millis() + 200;
    let mut receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-timeout".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            Some(deadline_ms),
        )
        .await
        .context("sending source command with deadline")?;
    let sent = expect_outbound_command_frame(
        recv_external_frame(&mut outbound_rx, "timed source command").await?,
    )?;
    assert_eq!(
        xolotl_proto::outbound_command_from_pb(&sent)
            .context("decoding timed source command frame")?
            .id,
        "cmd-timeout"
    );

    assert!(receiver.wait().await.is_err());
    drop(receiver);
    assert!(handler.source_hub.counts()?.1 == 0);
    assert!(handler.source_hub.counts()?.2 == 0);

    let err = match ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "cmd-timeout".into(),
            outcome: Ok(Value::string("late".into())),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected late command result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_enforces_source_command_in_flight_limit() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(
        true,
        Some(config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            source_max_in_flight_commands: 1,
            ..Default::default()
        }),
    )
    .await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering source outbound channel")?;

    let _receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-1".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
        .context("sending first source command")?;
    recv_external_frame(&mut outbound_rx, "first source command").await?;

    let err = match handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-2".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
    {
        Ok(_receiver) => bail!("expected source command in-flight limit rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert_eq!(handler.source_hub.counts()?.1, 1);
    assert_eq!(handler.source_hub.counts()?.2, 1);
    assert!(outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_enforces_source_command_rate_limit() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(
        true,
        Some(config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            source_command_rate_limit_window_ms: 60_000,
            source_command_rate_limit_max: 1,
            ..Default::default()
        }),
    )
    .await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering source outbound channel")?;

    let _receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-1".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
        .context("sending first source command")?;
    recv_external_frame(&mut outbound_rx, "first source command").await?;

    let err = match handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-2".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
    {
        Ok(_receiver) => bail!("expected source command rate limit rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert_eq!(handler.source_hub.counts()?.1, 1);
    assert!(outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_rejects_source_commands_when_projection_disables_them()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(false, None).await?;
    let (outbound, _outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering source outbound channel")?;

    let err = match handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-1".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
    {
        Ok(_receiver) => bail!("expected disabled source commands rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_drains_source_commands_on_close() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, _outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering source outbound channel")?;

    let mut receiver = handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-close".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
        .context("sending source command before close")?;

    ExternalSessionHandler::on_closed(&handler, &session, context.clone())
        .context("closing source session")?;

    assert!(receiver.wait().await.is_err());
    assert!(handler.source_hub.counts()?.0 == 0);
    assert!(handler.source_hub.counts()?.1 == 0);
    assert!(handler.source_hub.counts()?.2 == 0);

    let err = match handler
        .send_source_command(
            xolotl_types::external::OutboundCommand {
                id: "cmd-after-close".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            &session,
            &context,
            None,
        )
        .await
    {
        Ok(_receiver) => bail!("expected source command after close rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_command_hub_routes_across_handlers_and_rejects_ambiguous_sessions()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let (duplicate_outbound, mut duplicate_outbound_rx) = external_outbound_channel();
    let duplicate = match ExternalSessionHandler::on_ready(
        &handler,
        &session,
        context.clone(),
        duplicate_outbound,
    )
    .await
    {
        Ok(_) => bail!("the same connection cannot become Ready twice"),
        Err(error) => error,
    };
    assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);

    // This mirrors separate gRPC and WebSocket handlers sharing one Source hub.
    let shared = SharedSourceCommands {
        hub: handler.source_hub.clone(),
        publisher: handler.source_bindings.clone(),
    };
    let second_handler = DaemonExternalSessionHandler::with_shared_source_commands(
        boot.kernel().state().clone(),
        handler.source_store.clone(),
        boot.kernel().registry().clone(),
        config::ExternalGatewaySessionLimits::default(),
        PairingDisplayEdge::default(),
        shared,
        Arc::new(now_millis),
    );
    let hub = second_handler.source_hub.clone();
    let first_call = tokio::spawn(async move {
        hub.dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: "cross-handler".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            None,
        )
        .await
    });
    let sent = expect_outbound_command_frame(
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_external_frame(&mut outbound_rx, "cross-handler source command"),
        )
        .await
        .context("cross-handler source command was not dispatched")??,
    )?;
    assert_eq!(sent.id, "cross-handler");
    ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "cross-handler".into(),
            outcome: Ok(Value::string("ok".into())),
        },
        &session,
        &context,
    )
    .await?;
    assert_eq!(first_call.await??.outcome, Ok(Value::string("ok".into())));
    assert!(duplicate_outbound_rx.try_recv().is_err());

    let hello = hello_from_context(&context);
    let second_context =
        ExternalSessionHandler::adjudicate_session(&second_handler, &hello).await?;
    assert_ne!(second_context.session_id, context.session_id);
    let mut second_session = EndpointSession::new();
    second_session.on_hello(&hello, |_| second_context.clone())?;
    second_session.on_authenticated_ready(&xolotl_types::external::RoleReady {
        accepted_context: second_context.clone(),
    })?;
    let (second_outbound, mut second_outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(
        &second_handler,
        &second_session,
        second_context.clone(),
        second_outbound,
    )
    .await?;

    let err = match second_handler
        .source_hub
        .dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: "ambiguous".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            None,
        )
        .await
    {
        Ok(_) => bail!("two current Source sessions must be ambiguous"),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        SourceDispatchError::Rejected(status) if status.code() == tonic::Code::FailedPrecondition
    ));
    assert!(outbound_rx.try_recv().is_err());
    assert!(second_outbound_rx.try_recv().is_err());

    ExternalSessionHandler::on_closed(&handler, &session, context)?;
    assert_eq!(second_handler.source_hub.counts()?.0, 1);
    ExternalSessionHandler::on_closed(&second_handler, &second_session, second_context)?;
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_command_cancellation_cannot_remove_a_new_same_id_registration() -> anyhow::Result<()>
{
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(
        true,
        Some(config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 1,
            ..Default::default()
        }),
    )
    .await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let command = || OutboundCommand {
        id: "same-id".into(),
        action: Value::string("sync".into()),
        observed: Default::default(),
    };

    let old = handler
        .send_source_command(command(), &session, &context, None)
        .await?;
    recv_external_frame(&mut outbound_rx, "old source command").await?;
    ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "same-id".into(),
            outcome: Ok(Value::string("old".into())),
        },
        &session,
        &context,
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut new = handler
        .send_source_command(command(), &session, &context, None)
        .await?;
    recv_external_frame(&mut outbound_rx, "new source command").await?;
    drop(old);
    assert_eq!(handler.source_hub.counts()?.1, 1);
    assert_eq!(handler.source_hub.counts()?.2, 1);
    ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: "same-id".into(),
            outcome: Ok(Value::string("new".into())),
        },
        &session,
        &context,
    )
    .await?;
    assert_eq!(new.wait().await?.outcome, Ok(Value::string("new".into())));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn cancelled_source_command_future_fences_the_sent_id() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context, outbound).await?;
    let hub = handler.source_hub.clone();
    let command = || OutboundCommand {
        id: "cancelled-id".into(),
        action: Value::string("sync".into()),
        observed: Default::default(),
    };
    let call = tokio::spawn(async move {
        hub.dispatch_for_projection("chat", "source", command(), None)
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        recv_external_frame(&mut outbound_rx, "Source command before cancellation"),
    )
    .await
    .context("Source command was not dispatched before cancellation")??;
    call.abort();
    let join_error = match call.await {
        Ok(_) => bail!("cancelled call completed"),
        Err(error) => error,
    };
    assert!(join_error.is_cancelled());
    assert_eq!(handler.source_hub.counts()?.1, 0);
    assert_eq!(handler.source_hub.counts()?.2, 0);
    let retry = handler
        .source_hub
        .dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: "cancelled-id".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            None,
        )
        .await;
    assert!(matches!(
        retry,
        Err(SourceDispatchError::Rejected(status))
            if status.code() == tonic::Code::InvalidArgument
    ));
    assert!(outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_command_disconnect_and_deadline_preserve_unknown_outcome() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let hub = handler.source_hub.clone();
    let call = tokio::spawn(async move {
        hub.dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: "disconnect-id".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            None,
        )
        .await
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        recv_external_frame(&mut outbound_rx, "source command before disconnect"),
    )
    .await
    .context("Source command before disconnect was not dispatched")??;
    ExternalSessionHandler::on_closed(&handler, &session, context.clone())?;
    assert!(matches!(
        call.await?,
        Err(SourceDispatchError::OutcomeUnknown { command_id, cause })
            if command_id == "disconnect-id" && cause.code() == tonic::Code::Unavailable
    ));
    assert_eq!(handler.source_hub.counts()?, (0, 0, 0));

    let hello = hello_from_context(&context);
    let next_context = ExternalSessionHandler::adjudicate_session(&handler, &hello).await?;
    assert_ne!(next_context.session_id, context.session_id);
    let mut next_session = EndpointSession::new();
    next_session.on_hello(&hello, |_| next_context.clone())?;
    next_session.on_authenticated_ready(&xolotl_types::external::RoleReady {
        accepted_context: next_context.clone(),
    })?;
    let (new_outbound, mut new_outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &next_session, next_context, new_outbound).await?;
    let hub = handler.source_hub.clone();
    let timed = tokio::spawn(async move {
        hub.dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: "timed-id".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            Some(now_millis() + 500),
        )
        .await
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        recv_external_frame(&mut new_outbound_rx, "source command before deadline"),
    )
    .await
    .context("Source command before deadline was not dispatched")??;
    assert!(matches!(
        timed.await?,
        Err(SourceDispatchError::OutcomeUnknown { command_id, cause })
            if command_id == "timed-id" && cause.code() == tonic::Code::DeadlineExceeded
    ));
    assert_eq!(handler.source_hub.counts()?.1, 0);
    let retry = handler
        .source_hub
        .dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: "timed-id".into(),
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            None,
        )
        .await;
    assert!(matches!(
        retry,
        Err(SourceDispatchError::Rejected(status))
            if status.code() == tonic::Code::InvalidArgument
    ));
    assert!(new_outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn source_command_operation(
    effect: &Path,
) -> anyhow::Result<(
    xolotl_sdk::PreparedProgram,
    xolotl_kernel::CompiledRequestGrantTemplate,
)> {
    use xolotl_sdk::{Expression, OperationTemplate, PreparedProgram, Program};
    use xolotl_types::{GrantMethods, GrantRights, OutputMode, RightFlags};

    let prepared = PreparedProgram::new(
        &Program::new(Expression::Invoke {
            operation: OperationTemplate {
                target: ResourceName::new(effect.clone()),
                method: "dispatch".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            },
        })
        .compile()?,
    )?;
    let grant = xolotl_kernel::CompiledRequestGrantTemplate {
        selector: ResourceSelector::exact("perform", effect)?,
        rights: GrantRights::new(GrantMethods::name("dispatch"), RightFlags::empty()),
    };
    Ok((prepared, grant))
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn kernel_operation_dispatches_source_command_and_tags_result() -> anyhow::Result<()> {
    use xolotl_sdk::TaintedValue;
    use xolotl_types::TaintSource;

    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let effect = xolotl_types::external::external_source_command_path("chat", "source")?;
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(&ResourceName::new(effect.clone()))?;
    let resource = boot
        .kernel()
        .registry()
        .resource(resource_id)
        .context("Source command effect resource missing")?;
    let binding = boot
        .kernel()
        .registry()
        .binding(resource.binding)
        .context("Source command effect binding missing")?;
    assert!(binding.endpoint.is_some());

    let (prepared, grant) = source_command_operation(&effect)?;
    let run_boot = boot.clone();
    let execution = tokio::spawn(async move {
        let request = run_boot.request_under(run_boot.root(), IdentityRef::ROOT, &[grant])?;
        let output = request
            .executor()
            .with_fact_recording(true)
            .eval_prepared(
                &prepared,
                TaintedValue::pristine(Value::string("sync".into())),
            )
            .await;
        request.finish(&output).await?;
        Ok::<_, anyhow::Error>(output)
    });
    let sent = expect_outbound_command_frame(
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_external_frame(&mut outbound_rx, "Kernel Source command"),
        )
        .await
        .context("Kernel Source command was not dispatched")??,
    )?;
    let sent = xolotl_proto::outbound_command_from_pb(&sent)?;
    assert_eq!(sent.action, Value::string("sync".into()));
    ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: sent.id,
            outcome: Ok(Value::string("done".into())),
        },
        &session,
        &context,
    )
    .await?;
    let (result, unresolved) = execution.await??.into_parts();
    assert!(unresolved.is_empty());
    let result = result.map_err(|failure| {
        anyhow::anyhow!("Kernel Source command invocation failed: {failure:?}")
    })?;
    assert_eq!(result.value, Value::string("done".into()));
    let effect_label = effect.to_string();
    assert!(result.taint.sources().iter().any(|source| {
        matches!(source, TaintSource::Inbound { channel, .. } if channel.as_str() == effect_label.as_str())
    }));
    let fact = boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .find(|fact| fact.resource == resource_id)
        .context("Kernel did not retain a Source command operation Fact")?;
    assert_eq!(fact.outcome, Some(Value::string("done".into())));
    assert!(fact.taint.sources().iter().any(|source| {
        matches!(source, TaintSource::Inbound { channel, .. } if channel.as_str() == effect_label.as_str())
    }));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn kernel_source_command_disconnect_is_trusted_outcome_unknown() -> anyhow::Result<()> {
    use xolotl_sdk::TaintedValue;
    use xolotl_types::{Failure, Outcome, TaintSource};

    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let effect = xolotl_types::external::external_source_command_path("chat", "source")?;
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(&ResourceName::new(effect.clone()))?;
    let (prepared, grant) = source_command_operation(&effect)?;
    let run_boot = boot.clone();
    let execution = tokio::spawn(async move {
        let request = run_boot.request_under(run_boot.root(), IdentityRef::ROOT, &[grant])?;
        let output = request
            .executor()
            .with_fact_recording(true)
            .eval_prepared(
                &prepared,
                TaintedValue::pristine(Value::string("sync".into())),
            )
            .await;
        request.finish(&output).await?;
        Ok::<_, anyhow::Error>(output)
    });
    let sent = expect_outbound_command_frame(
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_external_frame(&mut outbound_rx, "Kernel Source command before disconnect"),
        )
        .await
        .context("Kernel Source command was not dispatched")??,
    )?;
    let sent = xolotl_proto::outbound_command_from_pb(&sent)?;
    ExternalSessionHandler::on_closed(&handler, &session, context)?;
    let output = execution.await??;
    let Outcome::Fail(Failure::OutcomeUnknown {
        operation_ids,
        reason,
    }) = &output.outcome
    else {
        bail!("expected trusted OutcomeUnknown after Source disconnect: {output:?}");
    };
    assert_eq!(operation_ids, &[sent.id]);
    assert_eq!(reason, "delivery_or_session_lost");
    let effect_label = effect.to_string();
    assert!(!output.taint.sources().iter().any(|source| {
        matches!(source, TaintSource::Inbound { channel, .. } if channel.as_str() == effect_label.as_str())
    }));
    let fact = boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .find(|fact| fact.resource == resource_id)
        .context("Kernel did not retain the unknown Source command Fact")?;
    assert!(fact.outcome.is_none());
    assert!(!fact.taint.sources().iter().any(|source| {
        matches!(source, TaintSource::Inbound { channel, .. } if channel.as_str() == effect_label.as_str())
    }));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn kernel_source_command_deadline_is_trusted_outcome_unknown() -> anyhow::Result<()> {
    use xolotl_sdk::TaintedValue;
    use xolotl_types::{Failure, Outcome, TaintSource};

    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context, outbound).await?;
    let effect = xolotl_types::external::external_source_command_path("chat", "source")?;
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(&ResourceName::new(effect.clone()))?;
    let (prepared, grant) = source_command_operation(&effect)?;
    let run_boot = boot.clone();
    let execution = tokio::spawn(async move {
        let request = run_boot.request_under(run_boot.root(), IdentityRef::ROOT, &[grant])?;
        let deadline = run_boot
            .kernel()
            .host_runtime()
            .deadline_after(Duration::from_secs(2))
            .context("Source command executor deadline")?;
        let output = request
            .executor()
            .with_fact_recording(true)
            .with_deadline(deadline)?
            .eval_prepared(
                &prepared,
                TaintedValue::pristine(Value::string("sync".into())),
            )
            .await;
        request.finish(&output).await?;
        Ok::<_, anyhow::Error>(output)
    });
    let sent = expect_outbound_command_frame(
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_external_frame(&mut outbound_rx, "Kernel Source command before deadline"),
        )
        .await
        .context("Kernel Source command was not dispatched before deadline")??,
    )?;
    let sent = xolotl_proto::outbound_command_from_pb(&sent)?;
    // Keep the Source session open and send no CommandResult. The executor's
    // explicit deadline must settle this already-dispatched operation.
    let output = tokio::time::timeout(Duration::from_secs(5), execution)
        .await
        .context("Kernel Source command did not settle at its deadline")???;
    let Outcome::Fail(Failure::OutcomeUnknown {
        operation_ids,
        reason,
    }) = &output.outcome
    else {
        bail!("expected trusted OutcomeUnknown after Source deadline: {output:?}");
    };
    assert_eq!(operation_ids.as_slice(), std::slice::from_ref(&sent.id));
    assert_eq!(reason, "deadline_exceeded");
    assert!(
        !output
            .taint
            .sources()
            .iter()
            .any(|source| { matches!(source, TaintSource::Inbound { .. }) })
    );
    let fact = boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .find(|fact| fact.resource == resource_id)
        .context("Kernel did not retain the timed-out Source command Fact")?;
    assert!(fact.outcome.is_none());
    assert!(
        !fact
            .taint
            .sources()
            .iter()
            .any(|source| { matches!(source, TaintSource::Inbound { .. }) })
    );
    assert_eq!(handler.source_hub.counts()?, (1, 0, 0));
    let retry = handler
        .source_hub
        .dispatch_for_projection(
            "chat",
            "source",
            OutboundCommand {
                id: sent.id,
                action: Value::string("sync".into()),
                observed: Default::default(),
            },
            None,
        )
        .await;
    assert!(matches!(
        retry,
        Err(SourceDispatchError::Rejected(status))
            if status.code() == tonic::Code::InvalidArgument
    ));
    assert!(outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn source_error_cannot_spoof_trusted_outcome_unknown() -> anyhow::Result<()> {
    use xolotl_sdk::TaintedValue;
    use xolotl_types::{Failure, Outcome, TaintSource};

    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let effect = xolotl_types::external::external_source_command_path("chat", "source")?;
    let (prepared, grant) = source_command_operation(&effect)?;
    let run_boot = boot.clone();
    let execution = tokio::spawn(async move {
        let request = run_boot.request_under(run_boot.root(), IdentityRef::ROOT, &[grant])?;
        let output = request
            .executor()
            .eval_prepared(
                &prepared,
                TaintedValue::pristine(Value::string("sync".into())),
            )
            .await;
        request.finish(&output).await?;
        Ok::<_, anyhow::Error>(output)
    });
    let sent = expect_outbound_command_frame(
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_external_frame(
                &mut outbound_rx,
                "Kernel Source command before spoofed error",
            ),
        )
        .await
        .context("Kernel Source command was not dispatched")??,
    )?;
    let sent = xolotl_proto::outbound_command_from_pb(&sent)?;
    ExternalSessionHandler::on_command_result(
        &handler,
        CommandResult {
            id: sent.id,
            outcome: Err(xolotl_types::ErrorInfo {
                kind: "outcome_unknown".into(),
                message: "forged by Source".into(),
            }),
        },
        &session,
        &context,
    )
    .await?;
    let output = execution.await??;
    let Outcome::Fail(Failure::HandlerError { kind, message }) = &output.outcome else {
        bail!("Source error escaped its untrusted HandlerError type: {output:?}");
    };
    assert_eq!(kind, "outcome_unknown");
    assert_eq!(message, "forged by Source");
    let effect_label = effect.to_string();
    assert!(output.taint.sources().iter().any(|source| {
        matches!(source, TaintSource::Inbound { channel, .. } if channel.as_str() == effect_label.as_str())
    }));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn disabling_source_commands_retires_the_effect_and_fences_old_endpoint() -> anyhow::Result<()>
{
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_source_fixture(true, None).await?;
    let (outbound, _outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;
    let effect = xolotl_types::external::external_source_command_path("chat", "source")?;
    let name = ResourceName::new(effect.clone());
    let registry = boot.kernel().registry();
    let resource_id = registry.resolve_resource(&name)?;
    let resource = registry
        .resource(resource_id)
        .context("published Source effect missing")?;
    let binding = registry
        .binding(resource.binding)
        .context("Source binding missing")?;
    let endpoint_id = binding.endpoint.context("Source endpoint missing")?;
    let old_endpoint = registry
        .remote_endpoint(endpoint_id)
        .context("Source endpoint implementation missing")?;
    let dispatch = RemoteInvokeDispatch {
        endpoint_id,
        resource_id,
        method_id: MethodId::new(0),
        binding_generation: binding.generation,
        acting: IdentityRef::ROOT,
        output_mode: xolotl_types::OutputMode::Unary,
    };

    write_chat_installation(
        handler.source_store.as_ref(),
        source_external_installation_value(false)?,
    )
    .await?;
    let current = handler
        .load_authority("chat", "source", Role::Source)
        .await?;
    let hello = hello_from_context(&current.context);
    let new_context = ExternalSessionHandler::adjudicate_session(&handler, &hello).await?;
    let mut new_session = EndpointSession::new();
    new_session.on_hello(&hello, |_| new_context.clone())?;
    new_session.on_authenticated_ready(&xolotl_types::external::RoleReady {
        accepted_context: new_context.clone(),
    })?;
    let (new_outbound, mut new_outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &new_session, new_context, new_outbound).await?;
    assert!(registry.resolve_resource(&name).is_err());

    let stale = old_endpoint
        .invoke(
            dispatch,
            Invoke {
                invocation_id: "stale-source-command".into(),
                effect_path: effect,
                method_id: MethodId::new(0),
                input: Value::string("sync".into()),
                deadline_ms: Some(now_millis() + 200),
                output_stream_to: None,
            },
        )
        .await;
    assert!(stale.is_err());
    assert!(new_outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_resolves_only_registered_provider_invocations()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;

    let invoke = xolotl_types::external::Invoke {
        invocation_id: "invoke-1".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let receiver = handler
        .register_provider_invoke(&invoke, &session, &context)
        .await
        .context("registering provider invocation")?;

    let expected = InvokeResult {
        invocation_id: "invoke-1".into(),
        outcome: Ok(Value::string("result".into())),
    };
    ExternalSessionHandler::on_invoke_result(&handler, expected.clone(), &session, &context)
        .await
        .context("resolving provider invocation result")?;
    assert_eq!(
        receiver
            .await
            .context("awaiting provider invocation receiver")?,
        expected
    );

    let err = match ExternalSessionHandler::on_invoke_result(
        &handler,
        InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: Ok(Value::string("again".into())),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected duplicate provider invoke result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let invoke = xolotl_types::external::Invoke {
        invocation_id: "invoke-large".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let receiver = handler
        .register_provider_invoke(&invoke, &session, &context)
        .await
        .context("registering provider invocation with oversized result payload")?;
    let err = match ExternalSessionHandler::on_invoke_result(
        &handler,
        InvokeResult {
            invocation_id: "invoke-large".into(),
            outcome: Ok(Value::string("x".repeat(
                config::DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES + 1,
            ))),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected oversized provider invoke result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert!(receiver.await.is_err());
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());

    let invoke = xolotl_types::external::Invoke {
        invocation_id: "invoke-large-error".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let receiver = handler
        .register_provider_invoke(&invoke, &session, &context)
        .await
        .context("registering provider invocation with oversized error result")?;
    let err = match ExternalSessionHandler::on_invoke_result(
        &handler,
        InvokeResult {
            invocation_id: "invoke-large-error".into(),
            outcome: Err(xolotl_types::ErrorInfo {
                kind: "remote".into(),
                message: "x".repeat(config::DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES),
            }),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected oversized provider invoke error result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert!(receiver.await.is_err());
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());

    let invoke = xolotl_types::external::Invoke {
        invocation_id: "invoke-schema".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let receiver = handler
        .register_provider_invoke(&invoke, &session, &context)
        .await
        .context("registering provider invocation with invalid result payload")?;
    let err = match ExternalSessionHandler::on_invoke_result(
        &handler,
        InvokeResult {
            invocation_id: "invoke-schema".into(),
            outcome: Ok(Value::integer(7)),
        },
        &session,
        &context,
    )
    .await
    {
        Ok(()) => bail!("expected invalid provider invoke result rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(receiver.await.is_err());
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_rolls_back_provider_invocation_on_waiter_duplicate()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;

    let (stale_tx, _stale_rx) = oneshot::channel();
    lock_test(&handler.provider_waiters, "provider_waiters")?
        .insert("invoke-stale".into(), stale_tx);
    let invoke = xolotl_types::external::Invoke {
        invocation_id: "invoke-stale".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };

    let err = match handler
        .register_provider_invoke(&invoke, &session, &context)
        .await
    {
        Ok(_receiver) => bail!("expected duplicate provider waiter rejection"),
        Err(error) => error,
    };

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert_eq!(
        lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
        1
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_enforces_provider_invocation_in_flight_limit() -> anyhow::Result<()>
{
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(
        provider_external_installation_value()?,
        Some(config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            provider_max_in_flight_invocations: 1,
            ..Default::default()
        }),
        0,
    )
    .await?;

    let first = xolotl_types::external::Invoke {
        invocation_id: "invoke-1".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let _receiver = handler
        .register_provider_invoke(&first, &session, &context)
        .await
        .context("registering first provider invocation")?;

    let second = xolotl_types::external::Invoke {
        invocation_id: "invoke-2".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let err = match handler
        .register_provider_invoke(&second, &session, &context)
        .await
    {
        Ok(_receiver) => bail!("expected provider invocation in-flight limit rejection"),
        Err(error) => error,
    };

    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert_eq!(
        lock_test(&handler.provider_invocations, "provider_invocations")?.len(),
        1
    );
    assert_eq!(
        lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
        1
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_enforces_provider_identity_in_flight_limit() -> anyhow::Result<()>
{
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(
        provider_external_installation_value()?,
        Some(config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            provider_max_in_flight_per_identity: 1,
            ..Default::default()
        }),
        0,
    )
    .await?;

    let first = xolotl_types::external::Invoke {
        invocation_id: "invoke-1".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let _receiver = handler
        .register_provider_invoke(&first, &session, &context)
        .await
        .context("registering first provider invocation")?;

    let second = xolotl_types::external::Invoke {
        invocation_id: "invoke-2".into(),
        effect_path: parse_test_path("effect://external-provider/chat/summarize")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let err = match handler
        .register_provider_invoke(&second, &session, &context)
        .await
    {
        Ok(_receiver) => bail!("expected provider identity in-flight limit rejection"),
        Err(error) => error,
    };

    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert_eq!(
        lock_test(&handler.provider_invocations, "provider_invocations")?.len(),
        1
    );
    assert_eq!(
        lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
        1
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_enforces_provider_effect_in_flight_limit() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(
        provider_external_installation_value()?,
        Some(config::ExternalGatewaySessionLimits {
            source_dedupe_window_ms: 60_000,
            provider_max_in_flight_per_effect: 1,
            ..Default::default()
        }),
        0,
    )
    .await?;

    let first = xolotl_types::external::Invoke {
        invocation_id: "invoke-1".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let _receiver = handler
        .register_provider_invoke(&first, &session, &context)
        .await
        .context("registering first provider invocation")?;

    let second = xolotl_types::external::Invoke {
        invocation_id: "invoke-2".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: xolotl_types::MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let err = match handler
        .register_provider_invoke(&second, &session, &context)
        .await
    {
        Ok(_receiver) => bail!("expected provider effect in-flight limit rejection"),
        Err(error) => error,
    };

    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    assert_eq!(
        lock_test(&handler.provider_invocations, "provider_invocations")?.len(),
        1
    );
    assert_eq!(
        lock_test(&handler.provider_waiters, "provider_waiters")?.len(),
        1
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_opens_secure_envelope_with_installed_credential()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let credential =
        ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
    let envelope = credential
        .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
        .context("sealing secure envelope")?;
    install_test_external_credential(&handler, credential)?;

    let plaintext =
        ExternalSessionHandler::open_secure_envelope(&handler, &envelope, &session, &context)
            .await
            .context("opening secure envelope")?;
    assert_eq!(plaintext, b"frame-bytes");

    let err =
        match ExternalSessionHandler::open_secure_envelope(&handler, &envelope, &session, &context)
            .await
        {
            Ok(_plaintext) => bail!("expected replayed secure envelope rejection"),
            Err(error) => error,
        };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_rejects_old_epoch_business_envelope_after_rekey()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 1).await?;
    let credential =
        ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
    let envelope = credential
        .seal_with_aad(
            b"frame-bytes",
            secure_envelope_aad_with(&context, 0, "invoke", 0),
        )
        .context("sealing old-epoch invoke envelope")?;
    let generic_control_envelope = credential
        .seal_with_aad(
            b"frame-bytes",
            secure_envelope_aad_with(&context, 0, "control", 0),
        )
        .context("sealing old-epoch control envelope")?;
    install_test_external_credential(&handler, credential)?;

    let err =
        match ExternalSessionHandler::open_secure_envelope(&handler, &envelope, &session, &context)
            .await
        {
            Ok(_plaintext) => bail!("expected old-epoch business envelope rejection"),
            Err(error) => error,
        };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let session_context = session
        .context()
        .context("session context should remain available")?
        .clone();
    let err = match ExternalSessionHandler::open_secure_envelope(
        &handler,
        &generic_control_envelope,
        &session,
        &session_context,
    )
    .await
    {
        Ok(_plaintext) => bail!("expected old-epoch generic control envelope rejection"),
        Err(error) => error,
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_clears_secure_replay_state_on_close() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let credential =
        ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
    let envelope = credential
        .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
        .context("sealing secure envelope")?;
    install_test_external_credential(&handler, credential)?;

    ExternalSessionHandler::open_secure_envelope(&handler, &envelope, &session, &context)
        .await
        .context("opening secure envelope")?;
    assert_eq!(
        lock_test(&handler.secure_replay_windows, "secure_replay_windows")?.len(),
        1
    );

    ExternalSessionHandler::on_closed(&handler, &session, context)
        .context("closing provider session")?;
    assert!(lock_test(&handler.secure_replay_windows, "secure_replay_windows")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_external_handler_rejects_secure_envelope_without_credential() -> anyhow::Result<()>
{
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let credential =
        ExternalCredential::new("chat", context.credential_generation, TEST_EXTERNAL_PSK);
    let envelope = credential
        .seal_with_aad(b"frame-bytes", secure_envelope_aad(&context, 0))
        .context("sealing secure envelope")?;

    let err =
        match ExternalSessionHandler::open_secure_envelope(&handler, &envelope, &session, &context)
            .await
        {
            Ok(_plaintext) => bail!("expected missing credential rejection"),
            Err(error) => error,
        };
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_ready_provider_registers_declared_projection_bindings() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, _rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering provider outbound channel")?;

    let search = ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
    let summarize = ResourceName::new(parse_test_path(
        "effect://external-provider/chat/summarize",
    )?);
    let admin = ResourceName::new(parse_test_path("effect://external-provider/chat/admin")?);

    let search_id = boot
        .kernel()
        .registry()
        .resolve_resource(&search)
        .context("search resource should be registered")?;
    let summarize_id = boot
        .kernel()
        .registry()
        .resolve_resource(&summarize)
        .context("summarize resource should be registered")?;
    assert!(boot.kernel().registry().resolve_resource(&admin).is_err());

    let search_binding = boot
        .kernel()
        .registry()
        .binding(
            boot.kernel()
                .registry()
                .resource(search_id)
                .context("search resource descriptor should exist")?
                .binding,
        )
        .context("search binding should exist")?;
    let summarize_binding = boot
        .kernel()
        .registry()
        .binding(
            boot.kernel()
                .registry()
                .resource(summarize_id)
                .context("summarize resource descriptor should exist")?
                .binding,
        )
        .context("summarize binding should exist")?;
    assert_eq!(search_binding.endpoint, summarize_binding.endpoint);
    let endpoint_id = search_binding
        .endpoint
        .context("search binding should expose remote endpoint")?;
    assert!(
        boot.kernel()
            .registry()
            .remote_endpoint(endpoint_id)
            .is_some()
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn daemon_provider_binding_relink_keeps_resource_id() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let registry = boot.kernel().registry();
    let path = parse_test_path("effect://external-provider/chat/search")?;
    let declaration = ProviderBindingDeclaration {
        path: path.clone(),
        purity: xolotl_types::Purity::Effectful,
        finalize_allowed: true,
        selector: ResourceSelector::parse("perform://effect/external-provider/chat/search")?,
    };

    let endpoint = registry.next_endpoint_id();
    let (first, _) = register_provider_binding(registry, &declaration, endpoint, 1)
        .map_err(|error| anyhow::anyhow!("first provider binding failed: {error}"))?;
    let counts_after_first = registry.counts();
    let mut second = first;
    for generation in 2..=32 {
        (second, _) = register_provider_binding(registry, &declaration, endpoint, generation)
            .map_err(|error| anyhow::anyhow!("provider relink failed: {error}"))?;
        let counts = registry.counts();
        assert_eq!(counts.resources, counts_after_first.resources);
        assert_eq!(counts.interfaces, counts_after_first.interfaces);
        assert_eq!(counts.drivers, counts_after_first.drivers);
        assert_eq!(counts.bindings, counts_after_first.bindings);
    }

    assert_eq!(first.resource_id, second.resource_id);
    assert_eq!(second.binding_generation, 32);
    let resource_name = ResourceName::new(path);
    let resource_id = registry
        .resolve_resource(&resource_name)
        .context("provider resource should resolve after relink")?;
    assert_eq!(resource_id, first.resource_id);
    let binding = registry
        .binding(
            registry
                .resource(resource_id)
                .context("provider resource descriptor should exist")?
                .binding,
        )
        .context("provider binding should exist")?;
    assert_eq!(binding.generation, 32);
    let resource = registry
        .resource(resource_id)
        .context("provider resource descriptor should exist")?;
    let iface_id = resource
        .interfaces
        .interfaces
        .first()
        .copied()
        .context("provider resource should expose an interface")?;
    let iface = registry
        .interface(iface_id)
        .context("provider interface should exist")?;
    assert!(
        iface
            .methods
            .first()
            .is_some_and(|method| method.finalize_allowed),
        "provider binding did not carry finalizer metadata"
    );

    let stale = register_provider_binding(registry, &declaration, endpoint, 1);
    assert!(
        stale.is_err(),
        "stale provider binding generation should be rejected"
    );
    let counts_after_stale = registry.counts();
    assert_eq!(counts_after_stale.resources, counts_after_first.resources);
    assert_eq!(counts_after_stale.interfaces, counts_after_first.interfaces);
    assert_eq!(counts_after_stale.drivers, counts_after_first.drivers);
    assert_eq!(counts_after_stale.bindings, counts_after_first.bindings);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn daemon_provider_batch_rejects_late_stale_binding_without_partial_publication()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let registry = boot.kernel().registry();
    let search = parse_test_path("effect://external-provider/chat/search")?;
    let summarize = parse_test_path("effect://external-provider/chat/summarize")?;
    let declarations = [
        ProviderBindingDeclaration {
            path: search.clone(),
            purity: xolotl_types::Purity::Effectful,
            finalize_allowed: false,
            selector: ResourceSelector::parse("perform://effect/external-provider/chat/search")?,
        },
        ProviderBindingDeclaration {
            path: summarize.clone(),
            purity: xolotl_types::Purity::Effectful,
            finalize_allowed: false,
            selector: ResourceSelector::parse("perform://effect/external-provider/chat/summarize")?,
        },
    ];
    let endpoint = registry.next_endpoint_id();
    let (summarize_key, _) = register_provider_binding(registry, &declarations[1], endpoint, 3)
        .map_err(|error| anyhow::anyhow!("initial binding failed: {error}"))?;
    let baseline = registry.counts();

    let rejected = register_provider_bindings_at_generation(registry, &declarations, endpoint, 2);
    assert!(rejected.is_err());
    assert!(
        registry
            .resolve_resource(&ResourceName::new(search))
            .is_err()
    );
    assert_eq!(
        registry.resource_binding_generation(&ResourceName::new(summarize))?,
        3
    );
    let after_rejection = registry.counts();
    assert_eq!(after_rejection.resources, baseline.resources);
    assert_eq!(after_rejection.interfaces, baseline.interfaces);
    assert_eq!(after_rejection.drivers, baseline.drivers);
    assert_eq!(after_rejection.bindings, baseline.bindings);

    let published = register_provider_bindings_at_generation(registry, &declarations, endpoint, 4)
        .map_err(|error| anyhow::anyhow!("batch publication failed: {error}"))?;
    assert_eq!(published.len(), 2);
    assert!(
        published
            .keys()
            .any(|key| key.resource_id == summarize_key.resource_id)
    );
    let after_publication = registry.counts();
    assert_eq!(after_publication.resources, baseline.resources + 1);
    assert_eq!(after_publication.interfaces, baseline.interfaces + 1);
    assert_eq!(after_publication.drivers, baseline.drivers + 1);
    assert_eq!(after_publication.bindings, baseline.bindings + 1);

    register_provider_bindings_at_generation(registry, &declarations, endpoint, 5)
        .map_err(|error| anyhow::anyhow!("batch relink failed: {error}"))?;
    let after_relink = registry.counts();
    assert_eq!(after_relink.resources, after_publication.resources);
    assert_eq!(after_relink.interfaces, after_publication.interfaces);
    assert_eq!(after_relink.drivers, after_publication.drivers);
    assert_eq!(after_relink.bindings, after_publication.bindings);
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn storage_catalog_rejects_provider_projection_without_declared_bindings_before_ready()
-> anyhow::Result<()> {
    let (boot, source_store) = external_test_boot();
    let rejected = write_chat_installation(
        source_store.as_ref(),
        provider_external_installation_without_capabilities_value()?,
    )
    .await;
    assert!(rejected.is_err());
    assert!(source_store.load_installation("chat").await?.is_none());
    let search = ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
    assert!(boot.kernel().registry().resolve_resource(&search).is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_ready_provider_routes_declared_remote_endpoint_binding() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering provider outbound channel")?;

    let resource_name =
        ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(&resource_name)
        .context("search resource should be registered")?;
    let resource = boot
        .kernel()
        .registry()
        .resource(resource_id)
        .context("search resource descriptor should exist")?;
    let binding = boot
        .kernel()
        .registry()
        .binding(resource.binding)
        .context("search binding should exist")?;
    let endpoint_id = binding
        .endpoint
        .context("search binding should expose remote endpoint")?;
    let dispatch = RemoteInvokeDispatch {
        endpoint_id,
        resource_id,
        method_id: MethodId::new(0),
        binding_generation: binding.generation,
        acting: IdentityRef::ROOT,
        output_mode: xolotl_types::OutputMode::Unary,
    };
    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("remote endpoint should be registered")?;

    let invoke = Invoke {
        invocation_id: "invoke-remote".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let pending = tokio::spawn(async move { endpoint.invoke(dispatch, invoke).await });
    let sent =
        expect_invoke_frame(recv_external_frame(&mut outbound_rx, "provider invoke").await?)?;
    let sent = xolotl_proto::invoke_from_pb(&sent).context("decoding provider invoke frame")?;
    assert_eq!(sent.invocation_id, "invoke-remote");
    assert_eq!(
        sent.effect_path,
        parse_test_path("effect://external-provider/chat/search")?
    );

    let expected = InvokeResult {
        invocation_id: "invoke-remote".into(),
        outcome: Ok(Value::string("result".into())),
    };
    ExternalSessionHandler::on_invoke_result(&handler, expected.clone(), &session, &context)
        .await
        .context("resolving remote provider invocation")?;
    let pending = pending.await.context("joining remote invoke task")?;
    assert_eq!(
        pending.map_err(|error| anyhow::anyhow!("remote invoke failed: {error:?}"))?,
        expected
    );

    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("remote endpoint should remain registered")?;
    let err = match endpoint
        .invoke(
            dispatch,
            Invoke {
                invocation_id: "invoke-undeclared-effect".into(),
                effect_path: parse_test_path("effect://external-provider/chat/admin")?,
                method_id: MethodId::new(0),
                input: Value::string("query".into()),
                deadline_ms: Some(now_millis() + 200),
                output_stream_to: None,
            },
        )
        .await
    {
        Ok(result) => bail!("expected undeclared effect rejection, got {result:?}"),
        Err(error) => error,
    };
    assert_eq!(
        err,
        DriverError::Transport("provider invoke effect rejected".into())
    );
    assert!(outbound_rx.try_recv().is_err());

    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("remote endpoint should remain registered")?;
    let wrong_method_dispatch = RemoteInvokeDispatch {
        method_id: MethodId::new(99),
        ..dispatch
    };
    let err = match endpoint
        .invoke(
            wrong_method_dispatch,
            Invoke {
                invocation_id: "invoke-wrong-method".into(),
                effect_path: parse_test_path("effect://external-provider/chat/search")?,
                method_id: MethodId::new(99),
                input: Value::string("query".into()),
                deadline_ms: Some(now_millis() + 200),
                output_stream_to: None,
            },
        )
        .await
    {
        Ok(result) => bail!("expected wrong method rejection, got {result:?}"),
        Err(error) => error,
    };
    assert_eq!(
        err,
        DriverError::Transport("provider invoke method rejected".into())
    );
    assert!(outbound_rx.try_recv().is_err());

    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("remote endpoint should remain registered")?;
    let stale_generation_dispatch = RemoteInvokeDispatch {
        binding_generation: binding.generation + 1,
        ..dispatch
    };
    let err = match endpoint
        .invoke(
            stale_generation_dispatch,
            Invoke {
                invocation_id: "invoke-stale-generation".into(),
                effect_path: parse_test_path("effect://external-provider/chat/search")?,
                method_id: MethodId::new(0),
                input: Value::string("query".into()),
                deadline_ms: Some(now_millis() + 200),
                output_stream_to: None,
            },
        )
        .await
    {
        Ok(result) => bail!("expected stale generation rejection, got {result:?}"),
        Err(error) => error,
    };
    assert_eq!(
        err,
        DriverError::Transport("provider invoke effect rejected".into())
    );
    assert!(outbound_rx.try_recv().is_err());

    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("remote endpoint should remain registered")?;
    let err = match endpoint
        .invoke(
            dispatch,
            Invoke {
                invocation_id: "invoke-bad-input".into(),
                effect_path: parse_test_path("effect://external-provider/chat/search")?,
                method_id: MethodId::new(0),
                input: Value::integer(7),
                deadline_ms: Some(now_millis() + 200),
                output_stream_to: None,
            },
        )
        .await
    {
        Ok(result) => bail!("expected invalid input rejection, got {result:?}"),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        DriverError::Transport(message)
            if message.starts_with("provider invoke input rejected:")
                && message.contains("expected `string`")
    ));
    assert!(outbound_rx.try_recv().is_err());
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());

    ExternalSessionHandler::on_closed(&handler, &session, context)
        .context("closing provider session")?;
    assert!(
        boot.kernel()
            .registry()
            .remote_endpoint(endpoint_id)
            .is_none()
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
fn registered_search_endpoint(
    boot: &Bootstrap,
) -> anyhow::Result<(
    xolotl_kernel::driver::DynRemoteEndpoint,
    RemoteInvokeDispatch,
)> {
    let resource_name =
        ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
    let registry = boot.kernel().registry();
    let resource_id = registry.resolve_resource(&resource_name)?;
    let resource = registry.resource(resource_id).context("search resource")?;
    let binding = registry
        .binding(resource.binding)
        .context("search binding")?;
    let endpoint_id = binding.endpoint.context("search remote endpoint")?;
    let endpoint = registry
        .remote_endpoint(endpoint_id)
        .context("registered search endpoint")?;
    let dispatch = RemoteInvokeDispatch {
        endpoint_id,
        resource_id,
        method_id: MethodId::new(0),
        binding_generation: binding.generation,
        acting: IdentityRef::ROOT,
        output_mode: xolotl_types::OutputMode::Unary,
    };
    Ok((endpoint, dispatch))
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn daemon_provider_endpoint_times_out_pending_invocation() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound)
        .await
        .context("registering provider outbound channel")?;

    let resource_name =
        ResourceName::new(parse_test_path("effect://external-provider/chat/search")?);
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(&resource_name)
        .context("search resource should be registered")?;
    let resource = boot
        .kernel()
        .registry()
        .resource(resource_id)
        .context("search resource descriptor should exist")?;
    let binding = boot
        .kernel()
        .registry()
        .binding(resource.binding)
        .context("search binding should exist")?;
    let endpoint_id = binding
        .endpoint
        .context("search binding should expose remote endpoint")?;
    let dispatch = RemoteInvokeDispatch {
        endpoint_id,
        resource_id,
        method_id: MethodId::new(0),
        binding_generation: binding.generation,
        acting: IdentityRef::ROOT,
        output_mode: xolotl_types::OutputMode::Unary,
    };
    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("remote endpoint should be registered")?;

    let deadline_ms = now_millis() + 200;
    let invoke = Invoke {
        invocation_id: "invoke-timeout".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: Some(deadline_ms),
        output_stream_to: None,
    };
    let pending = tokio::spawn(async move { endpoint.invoke(dispatch, invoke).await });
    let sent =
        expect_invoke_frame(recv_external_frame(&mut outbound_rx, "timed provider invoke").await?)?;
    let sent =
        xolotl_proto::invoke_from_pb(&sent).context("decoding timed provider invoke frame")?;
    assert_eq!(sent.invocation_id, "invoke-timeout");
    assert_eq!(sent.deadline_ms, Some(deadline_ms));

    let error = match pending
        .await
        .context("joining timed provider invoke task")?
    {
        Ok(result) => bail!("expected provider invocation timeout, got {result:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        DriverError::OutcomeUnknown {
            operation_id: "invoke-timeout".into(),
            reason: "deadline_exceeded".into(),
        }
    );
    let control = expect_control_frame(
        recv_external_frame(&mut outbound_rx, "provider cancel control").await?,
    )?;
    let control = xolotl_proto::control_frame_from_pb(&control)
        .context("decoding provider cancel control frame")?;
    assert_eq!(
        control,
        ControlFrame::ProviderCancel {
            invocation_id: "invoke-timeout".into(),
            reason: "deadline_exceeded".into(),
        }
    );
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn provider_send_failure_preserves_unknown_invocation_identity() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context, outbound).await?;
    drop(outbound_rx);

    let (endpoint, dispatch) = registered_search_endpoint(&boot)?;
    let error = match endpoint
        .invoke(
            dispatch,
            Invoke {
                invocation_id: "invoke-send-failed".into(),
                effect_path: parse_test_path("effect://external-provider/chat/search")?,
                method_id: MethodId::new(0),
                input: Value::string("query".into()),
                deadline_ms: None,
                output_stream_to: None,
            },
        )
        .await
    {
        Ok(result) => bail!("expected provider send failure, got {result:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        DriverError::OutcomeUnknown {
            operation_id: "invoke-send-failed".into(),
            reason: "delivery_or_session_lost".into(),
        }
    );
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn provider_session_close_preserves_unknown_invocation_identity() -> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;

    let (endpoint, dispatch) = registered_search_endpoint(&boot)?;
    let effect_path = parse_test_path("effect://external-provider/chat/search")?;
    let pending = tokio::spawn(async move {
        endpoint
            .invoke(
                dispatch,
                Invoke {
                    invocation_id: "invoke-session-closed".into(),
                    effect_path,
                    method_id: MethodId::new(0),
                    input: Value::string("query".into()),
                    deadline_ms: None,
                    output_stream_to: None,
                },
            )
            .await
    });
    let sent = expect_invoke_frame(
        recv_external_frame(&mut outbound_rx, "provider invoke before session close").await?,
    )?;
    assert_eq!(sent.invocation_id, "invoke-session-closed");

    ExternalSessionHandler::on_closed(&handler, &session, context)?;
    let error = match tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .context("waiting for provider invocation after session close")??
    {
        Ok(result) => bail!("expected unknown provider outcome, got {result:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        DriverError::OutcomeUnknown {
            operation_id: "invoke-session-closed".into(),
            reason: "delivery_or_session_lost".into(),
        }
    );
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    assert!(outbound_rx.try_recv().is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn cancelled_provider_invoke_without_runtime_releases_and_enqueues_cancel()
-> anyhow::Result<()> {
    let ExternalTestFixture {
        boot,
        handler,
        session,
        context,
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let (outbound, mut outbound_rx) = external_outbound_channel();
    ExternalSessionHandler::on_ready(&handler, &session, context.clone(), outbound).await?;

    let target = parse_test_path("effect://external-provider/chat/search")?;
    let resource_id = boot
        .kernel()
        .registry()
        .resolve_resource(&ResourceName::new(target.clone()))?;
    let resource = boot
        .kernel()
        .registry()
        .resource(resource_id)
        .context("resource")?;
    let binding = boot
        .kernel()
        .registry()
        .binding(resource.binding)
        .context("binding")?;
    let endpoint_id = binding.endpoint.context("remote endpoint")?;
    let dispatch = RemoteInvokeDispatch {
        endpoint_id,
        resource_id,
        method_id: MethodId::new(0),
        binding_generation: binding.generation,
        acting: IdentityRef::ROOT,
        output_mode: xolotl_types::OutputMode::Unary,
    };
    let endpoint = boot
        .kernel()
        .registry()
        .remote_endpoint(endpoint_id)
        .context("registered remote endpoint")?;

    let invoke = Invoke {
        invocation_id: "cancelled-invoke".into(),
        effect_path: target,
        method_id: MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: Some(now_millis() + 30_000),
        output_stream_to: None,
    };
    let retry = invoke.clone();
    let retry_endpoint = endpoint.clone();
    let mut pending = Box::pin(async move { endpoint.invoke(dispatch, invoke).await });
    let (invocation_pending, sent) = std::future::poll_fn(|context| {
        let invocation_pending = std::future::Future::poll(pending.as_mut(), context).is_pending();
        if !invocation_pending {
            return std::task::Poll::Ready((false, None));
        }
        outbound_rx
            .poll_recv(context)
            .map(|sent| (invocation_pending, sent))
    })
    .await;
    anyhow::ensure!(
        invocation_pending,
        "provider invocation completed before cancellation"
    );
    let sent = sent.context("provider invocation missing")??;
    let sent = expect_invoke_frame(sent)?;
    assert_eq!(sent.invocation_id, "cancelled-invoke");
    std::thread::spawn(move || drop(pending))
        .join()
        .map_err(|_panic_payload| anyhow::anyhow!("provider future drop panicked"))?;
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());

    let cancel = outbound_rx
        .try_recv()
        .context("Drop did not synchronously enqueue cancellation without a runtime")??;
    let cancel = expect_control_frame(cancel)?;
    assert_eq!(
        xolotl_proto::control_frame_from_pb(&cancel)?,
        ControlFrame::ProviderCancel {
            invocation_id: "cancelled-invoke".into(),
            reason: "cancelled".into(),
        }
    );

    let pending = tokio::spawn(async move { retry_endpoint.invoke(dispatch, retry).await });
    let sent = expect_invoke_frame(recv_external_frame(&mut outbound_rx, "retry invoke").await?)?;
    assert_eq!(sent.invocation_id, "cancelled-invoke");
    let expected = InvokeResult {
        invocation_id: "cancelled-invoke".into(),
        outcome: Ok(Value::string("retried".into())),
    };
    ExternalSessionHandler::on_invoke_result(&handler, expected.clone(), &session, &context)
        .await?;
    assert_eq!(pending.await??, expected);
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn provider_result_and_same_id_reregistration_are_atomic() -> anyhow::Result<()> {
    let ExternalTestFixture {
        handler,
        session,
        context,
        ..
    } = ready_provider_fixture(provider_external_installation_value()?, None, 0).await?;
    let handler = Arc::new(handler);
    let invoke = Invoke {
        invocation_id: "reused-invoke".into(),
        effect_path: parse_test_path("effect://external-provider/chat/search")?,
        method_id: MethodId::new(0),
        input: Value::string("query".into()),
        deadline_ms: None,
        output_stream_to: None,
    };
    let first_rx = handler
        .register_provider_invoke(&invoke, &session, &context)
        .await?;

    // Stop result handling at the second lock. It must keep the invocation
    // registry locked until it has removed the old waiter as well.
    let waiters = lock_test(&handler.provider_waiters, "provider_waiters")?;
    let first = InvokeResult {
        invocation_id: invoke.invocation_id.clone(),
        outcome: Ok(Value::string("first".into())),
    };
    let result_handler = Arc::clone(&handler);
    let result_session = session.clone();
    let result_context = context.clone();
    let result = first.clone();
    let resolving = tokio::spawn(async move {
        result_handler
            .handle_invoke_result(result, &result_session, &result_context)
            .await
    });

    let started = std::time::Instant::now();
    loop {
        match handler.provider_invocations.try_lock() {
            Err(std::sync::TryLockError::WouldBlock) => break,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                anyhow::bail!("provider invocation registry poisoned")
            }
            Ok(guard) if started.elapsed() < Duration::from_secs(2) => {
                drop(guard);
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(_guard) => anyhow::bail!("result handler did not acquire invocation registry"),
        }
    }
    std::thread::sleep(Duration::from_millis(20));
    assert!(matches!(
        handler.provider_invocations.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));

    let retry_handler = Arc::clone(&handler);
    let retry_session = session.clone();
    let retry_context = context.clone();
    let retry_invoke = invoke.clone();
    let retry = tokio::spawn(async move {
        retry_handler
            .register_provider_invoke(&retry_invoke, &retry_session, &retry_context)
            .await
    });
    std::thread::sleep(Duration::from_millis(20));
    assert!(!retry.is_finished());
    drop(waiters);

    resolving.await??;
    assert_eq!(first_rx.await?, first);
    let retry_rx = retry.await??;
    let second = InvokeResult {
        invocation_id: invoke.invocation_id.clone(),
        outcome: Ok(Value::string("second".into())),
    };
    handler
        .handle_invoke_result(second.clone(), &session, &context)
        .await?;
    assert_eq!(retry_rx.await?, second);
    assert!(lock_test(&handler.provider_invocations, "provider_invocations")?.is_empty());
    assert!(lock_test(&handler.provider_waiters, "provider_waiters")?.is_empty());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[tokio::test]
async fn provider_waiter_drop_reports_unknown_outcome() -> anyhow::Result<()> {
    let (tx, rx) = oneshot::channel();
    drop(tx);

    let error = match await_provider_result(rx).await {
        Ok(result) => bail!("expected unknown provider outcome, got {result:?}"),
        Err(error) => error,
    };

    assert_eq!(
        error.into_driver_error("invoke-waiter-dropped".into()),
        DriverError::OutcomeUnknown {
            operation_id: "invoke-waiter-dropped".into(),
            reason: "delivery_or_session_lost".into(),
        }
    );
    Ok(())
}
