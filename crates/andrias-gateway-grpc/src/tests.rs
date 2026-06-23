use super::*;
use crate::session::{ExternalOutbound, drive_external_session};
use andrias_gateway::GatewayTransportSecurityMode;
use andrias_gateway::external::{
    EndpointSession, ExternalSessionHandler, ExternalSessionOutbound, SecureEnvelope,
};
use andrias_proto::andrias::v1 as pb;
use andrias_proto::{
    control_frame_from_pb, control_frame_to_pb, inbound_event_to_pb, invoke_result_to_pb,
    role_ready_to_pb, role_session_client_hello_to_pb,
};
use andrias_types::Value;
use andrias_types::external::{
    AckStatus, CommandResult, ControlFrame, EventAck, InboundEvent, InvokeResult,
    ObservedGenerations, Role, RoleReady, RoleSessionClientHello, SessionContext,
};
use anyhow::{Context, bail, ensure};
use prost::Message;
use std::sync::{Arc, Mutex, MutexGuard};
use tonic::Code;
use tonic::transport::server::TcpConnectInfo;

struct TestExternalHandler {
    context: SessionContext,
    events: Mutex<Vec<InboundEvent>>,
    controls: Mutex<Vec<ControlFrame>>,
    envelopes: Mutex<Vec<SecureEnvelope>>,
    envelope_plaintext: Mutex<Option<Vec<u8>>>,
    closed: Mutex<Vec<SessionContext>>,
}

impl TestExternalHandler {
    fn new(role: Role) -> Self {
        Self {
            context: test_session_context(role),
            events: std::sync::Mutex::new(Vec::new()),
            controls: std::sync::Mutex::new(Vec::new()),
            envelopes: std::sync::Mutex::new(Vec::new()),
            envelope_plaintext: std::sync::Mutex::new(None),
            closed: std::sync::Mutex::new(Vec::new()),
        }
    }
}

fn lock_status<'a, T>(mutex: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>, Status> {
    mutex
        .lock()
        .map_err(|_| Status::internal(format!("{name} mutex poisoned")))
}

fn lock_test<'a, T>(mutex: &'a Mutex<T>, name: &str) -> anyhow::Result<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| anyhow::anyhow!("{name} mutex poisoned"))
}

#[tonic::async_trait]
impl ExternalSessionHandler for TestExternalHandler {
    type Error = Status;
    type OutboundError = Status;

    async fn adjudicate_session(
        &self,
        _hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, Status> {
        Ok(self.context.clone())
    }

    async fn on_ready(
        &self,
        _session: &EndpointSession,
        _context: SessionContext,
        _outbound: Arc<dyn ExternalSessionOutbound<Error = Status>>,
    ) -> Result<(), Status> {
        Ok(())
    }

    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<EventAck, Status> {
        lock_status(&self.events, "events")?.push(event.clone());
        Ok(EventAck {
            id: event.id,
            status: AckStatus::Accepted,
            reject_reason: None,
        })
    }

    async fn on_control(
        &self,
        frame: ControlFrame,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        lock_status(&self.controls, "controls")?.push(frame);
        Ok(())
    }

    async fn on_command_result(
        &self,
        _result: CommandResult,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    async fn on_invoke_result(
        &self,
        _result: InvokeResult,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    async fn on_closed(
        &self,
        _session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), Status> {
        lock_status(&self.closed, "closed")?.push(context);
        Ok(())
    }

    async fn open_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<Vec<u8>, Status> {
        lock_status(&self.envelopes, "envelopes")?.push(envelope.clone());
        lock_status(&self.envelope_plaintext, "envelope_plaintext")?
            .clone()
            .ok_or_else(|| Status::permission_denied("secure envelope rejected"))
    }
}

fn test_session_context(role: Role) -> SessionContext {
    SessionContext {
        installation_id: "install-1".into(),
        projection_id: "projection-1".into(),
        role,
        registry_hash: "registry-hash".into(),
        credential_generation: 1,
        binding_generation: 2,
        installation_config_version: 3,
        projection_version: 4,
        presentation_config_generation: 5,
        alias_catalog_generation: 6,
        session_id: "session-1".into(),
    }
}

fn external_hello(role: Role) -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::RoleSessionClientHello(
            role_session_client_hello_to_pb(&RoleSessionClientHello {
                role,
                installation_id: "install-1".into(),
                projection_id: "projection-1".into(),
                registry_hash: "registry-hash".into(),
                observed: ObservedGenerations {
                    presentation_config_generation: 5,
                    alias_catalog_generation: 6,
                },
                config_schema: None,
            }),
        )),
    }
}

fn external_ready(context: &SessionContext) -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::RoleReady(role_ready_to_pb(
            &RoleReady {
                accepted_context: context.clone(),
            },
        ))),
    }
}

fn external_event(id: &str) -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InboundEvent(
            inbound_event_to_pb(&InboundEvent {
                id: id.into(),
                payload: Value::Str("hello".into()),
                observed: ObservedGenerations::default(),
                timestamp_ms: 1234,
                stream_id: None,
                seq: None,
            }),
        )),
    }
}

fn external_invoke_result() -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InvokeResult(
            invoke_result_to_pb(&InvokeResult {
                invocation_id: "invoke-1".into(),
                outcome: Ok(Value::Str("ok".into())),
            }),
        )),
    }
}

fn external_secure_envelope(context: &SessionContext) -> ext::ExternalFrame {
    external_secure_envelope_with_type(context, "control.heartbeat")
}

fn external_secure_envelope_with_type(
    context: &SessionContext,
    frame_type: &str,
) -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::SecureEnvelope(
            ext::SecureEnvelope {
                installation_id: context.installation_id.clone(),
                generation: context.credential_generation,
                aad: Some(ext::EnvelopeAad {
                    version: 1,
                    projection_id: context.projection_id.clone(),
                    role: test_external_role_slug(context.role).into(),
                    session_id: "session-1".into(),
                    seq: 0,
                    frame_type: frame_type.into(),
                    binding_generation: context.binding_generation,
                    credential_generation: context.credential_generation,
                    transcript_hash: vec![0x42; 32],
                    key_epoch: 0,
                }),
                nonce_prefix: vec![0; 12],
                ciphertext: vec![1, 2, 3],
            },
        )),
    }
}

fn test_external_role_slug(role: Role) -> &'static str {
    match role {
        Role::Provider => "provider",
        Role::Source => "source",
    }
}

async fn run_external_frames(
    handler: Arc<TestExternalHandler>,
    frames: Vec<ext::ExternalFrame>,
) -> Vec<Result<ext::ExternalFrame, Status>> {
    let (tx, mut rx) = mpsc::channel(8);
    let input = tonic::codegen::tokio_stream::iter(frames.into_iter().map(Ok));
    drive_external_session(input, tx, handler).await;
    let mut out = Vec::new();
    while let Some(frame) = rx.recv().await {
        out.push(frame);
    }
    out
}

fn ok_frame(
    out: &[Result<ext::ExternalFrame, Status>],
    index: usize,
) -> anyhow::Result<&ext::external_frame::Frame> {
    let frame = out
        .get(index)
        .with_context(|| format!("missing output frame {index}"))?
        .as_ref()
        .map_err(|status| anyhow::anyhow!("output frame {index} failed: {status}"))?;
    frame
        .frame
        .as_ref()
        .with_context(|| format!("output frame {index} has no payload"))
}

fn err_status(out: &[Result<ext::ExternalFrame, Status>], index: usize) -> anyhow::Result<&Status> {
    match out
        .get(index)
        .with_context(|| format!("missing output frame {index}"))?
    {
        Ok(_) => bail!("output frame {index} unexpectedly succeeded"),
        Err(status) => Ok(status),
    }
}

#[tokio::test]
async fn external_outbound_reports_backpressure_when_queue_is_full() -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel(1);
    let outbound = ExternalOutbound::from_sender(tx);

    outbound
        .send_control(ControlFrame::Heartbeat { timestamp_ms: 1 })
        .await?;
    let err = match outbound
        .send_control(ControlFrame::Heartbeat { timestamp_ms: 2 })
        .await
    {
        Ok(()) => bail!("second outbound control frame unexpectedly fit in full queue"),
        Err(err) => err,
    };

    ensure!(
        err.code() == Code::ResourceExhausted,
        "backpressure used wrong status"
    );
    let sent = rx.recv().await.context("missing queued outbound frame")??;
    let Some(ext::external_frame::Frame::Control(control)) = sent.frame else {
        bail!("expected control frame");
    };
    ensure!(
        control_frame_from_pb(&control)? == ControlFrame::Heartbeat { timestamp_ms: 1 },
        "queued control frame mismatch"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_handshake_and_source_event_ack() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Source),
            external_ready(&context),
            external_event("event-1"),
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    match ok_frame(&out, 0)? {
        ext::external_frame::Frame::SessionContext(ctx) => {
            ensure!(
                ctx.installation_id == "install-1",
                "installation id mismatch"
            );
            ensure!(
                ctx.role == ext::ExternalRole::Source as i32,
                "external role mismatch"
            );
        }
        other => bail!("expected SessionContext, got {other:?}"),
    }
    match ok_frame(&out, 1)? {
        ext::external_frame::Frame::EventAck(ack) => {
            ensure!(ack.id == "event-1", "ack id mismatch");
            ensure!(
                ack.status == ext::AckStatus::Accepted as i32,
                "ack status mismatch"
            );
        }
        other => bail!("expected EventAck, got {other:?}"),
    }
    ensure!(
        lock_test(&handler.events, "events")?.len() == 1,
        "handler did not receive exactly one event"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_malformed_value_before_handler() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let malformed = pb::Value {
        kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
            blob: Some(pb::BlobRef {
                hash: "tensor-hash".into(),
                size: 8,
                mime: None,
            }),
            dtype: "complex64".into(),
            shape: vec![1],
        })),
    };
    let event = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InboundEvent(
            ext::InboundEvent {
                id: "event-1".into(),
                payload: Some(malformed),
                timestamp_ms: 1234,
                observed: Some(ext::ObservedGenerations::default()),
                stream_id: None,
                seq: None,
            },
        )),
    };
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Source),
            external_ready(&context),
            event,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    let status = err_status(&out, 1)?;
    ensure!(
        status.code() == Code::InvalidArgument,
        "malformed value used wrong status"
    );
    ensure!(
        status.message() == "invalid wire value",
        "malformed value used wrong message"
    );
    ensure!(
        lock_test(&handler.events, "events")?.is_empty(),
        "malformed event reached handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_close_hook_runs_after_ready_eof() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler.clone(),
        vec![external_hello(Role::Provider), external_ready(&context)],
    )
    .await;

    ensure!(out.len() == 1, "unexpected output frame count");
    let closed = lock_test(&handler.closed, "closed")?.clone();
    ensure!(closed == vec![context], "close hook context mismatch");
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_business_before_ready() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let out = run_external_frames(
        handler,
        vec![external_hello(Role::Source), external_event("event-1")],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::FailedPrecondition,
        "business-before-ready used wrong status"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_wrong_role_business_frame() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler,
        vec![
            external_hello(Role::Source),
            external_ready(&context),
            external_invoke_result(),
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "wrong-role business frame used wrong status"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_admits_secure_envelope_with_matching_context() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
            &ControlFrame::Heartbeat { timestamp_ms: 1234 },
        ))),
    };
    *lock_test(&handler.envelope_plaintext, "envelope_plaintext")? = Some(inner.encode_to_vec());
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context),
            external_secure_envelope_with_type(&context, "control.heartbeat"),
        ],
    )
    .await;

    ensure!(out.len() == 1, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        lock_test(&handler.envelopes, "envelopes")?.len() == 1,
        "secure envelope was not opened"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.len() == 1,
        "secure control frame did not reach handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_accepts_secure_control_frame_type() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
            &ControlFrame::ConfigAck {
                axis: andrias_types::external::ConfigAxis::InstallationConfig,
                version: context.installation_config_version,
                status: andrias_types::external::ApplyStatus::Applied,
            },
        ))),
    };
    *lock_test(&handler.envelope_plaintext, "envelope_plaintext")? = Some(inner.encode_to_vec());
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context),
            external_secure_envelope_with_type(&context, "control.config_ack"),
        ],
    )
    .await;

    ensure!(out.len() == 1, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.len() == 1,
        "secure config ack did not reach handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_generic_secure_control_frame_type() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
            &ControlFrame::ConfigAck {
                axis: andrias_types::external::ConfigAxis::InstallationConfig,
                version: context.installation_config_version,
                status: andrias_types::external::ApplyStatus::Applied,
            },
        ))),
    };
    *lock_test(&handler.envelope_plaintext, "envelope_plaintext")? = Some(inner.encode_to_vec());
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context),
            external_secure_envelope_with_type(&context, "control"),
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "generic secure control type used wrong status"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.is_empty(),
        "generic secure control frame reached handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_secure_envelope_frame_type_mismatch() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InvokeResult(
            invoke_result_to_pb(&InvokeResult {
                invocation_id: "invoke-1".into(),
                outcome: Ok(Value::Str("ok".into())),
            }),
        )),
    };
    *lock_test(&handler.envelope_plaintext, "envelope_plaintext")? = Some(inner.encode_to_vec());
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context),
            external_secure_envelope_with_type(&context, "control"),
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "secure envelope frame type mismatch used wrong status"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.is_empty(),
        "mismatched secure envelope frame reached control handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_secure_envelope_context_mismatch() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let mut envelope = external_secure_envelope(&context);
    if let Some(ext::external_frame::Frame::SecureEnvelope(envelope)) = envelope.frame.as_mut() {
        envelope.generation = envelope.generation.saturating_add(1);
    }
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context),
            envelope,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "secure envelope context mismatch used wrong status"
    );
    ensure!(
        lock_test(&handler.envelopes, "envelopes")?.is_empty(),
        "context-mismatched secure envelope reached handler"
    );
    Ok(())
}

fn request_with_peer(peer: &str) -> anyhow::Result<Request<()>> {
    let mut request = Request::new(());
    request.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(peer.parse()?),
    });
    Ok(request)
}

#[test]
fn external_grpc_default_transport_rejects_non_loopback_peer() -> anyhow::Result<()> {
    let svc = ExternalGrpcService::new(TestExternalHandler::new(Role::Source));

    let request = request_with_peer("10.0.0.8:7443")?;
    let err = match svc.source_addr_for_request(&request) {
        Ok(_) => bail!("non-loopback peer was accepted in default transport mode"),
        Err(err) => err,
    };
    ensure!(
        err.code() == Code::PermissionDenied,
        "non-loopback peer used wrong status"
    );
    ensure!(
        svc.source_addr_for_request(&request_with_peer("127.0.0.1:7443")?)?
            == Some("127.0.0.1".into()),
        "loopback source address mismatch"
    );
    Ok(())
}

#[test]
fn external_grpc_trusted_proxy_uses_forwarded_source_only_from_trusted_peer() -> anyhow::Result<()>
{
    let transport = GatewayTransportSecurityConfig {
        mode: GatewayTransportSecurityMode::TrustedReverseProxy,
        trusted_proxy: andrias_gateway::GatewayTrustedProxyConfig {
            peers: vec!["127.0.0.1".parse()?],
            ..Default::default()
        },
        unsafe_relaxations: Vec::new(),
    };
    let svc = ExternalGrpcService::with_config(
        TestExternalHandler::new(Role::Source),
        ExternalGrpcConfig {
            transport_security: transport,
        },
    );

    let mut trusted = request_with_peer("127.0.0.1:7443")?;
    trusted
        .metadata_mut()
        .insert("x-forwarded-for", "203.0.113.9, 10.0.0.4".parse()?);
    trusted
        .metadata_mut()
        .insert("x-forwarded-proto", "https".parse()?);
    ensure!(
        svc.source_addr_for_request(&trusted)? == Some("203.0.113.9".into()),
        "trusted proxy forwarded source mismatch"
    );

    let mut untrusted = request_with_peer("127.0.0.2:7443")?;
    untrusted
        .metadata_mut()
        .insert("x-forwarded-for", "203.0.113.10".parse()?);
    let err = match svc.source_addr_for_request(&untrusted) {
        Ok(_) => bail!("untrusted proxy peer was accepted"),
        Err(err) => err,
    };
    ensure!(
        err.code() == Code::PermissionDenied,
        "untrusted proxy used wrong status"
    );
    Ok(())
}
