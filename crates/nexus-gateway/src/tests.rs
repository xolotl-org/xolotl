use super::*;
use crate::external::{
    EnvelopeAad, ExternalFrameError, SecureEnvelope, external_role_slug,
    secure_external_inner_frame_type, validate_secure_external_envelope_context,
};
use anyhow::{Context, bail, ensure};
use nexus_proto::nexus::v1::external as external_pb;
use nexus_types::external::{Role as ExternalRole, SessionContext as ExternalSessionContext};
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const TEST_TOKEN: &str = "test-token-for-alice-0001";

#[test]
fn secure_external_frame_types_are_canonical() -> anyhow::Result<()> {
    ensure!(
        secure_external_inner_frame_type(&external_pb::external_frame::Frame::InboundEvent(
            external_pb::InboundEvent::default()
        ))? == "inbound_event",
        "unexpected inbound event frame type"
    );
    ensure!(
        secure_external_inner_frame_type(&external_pb::external_frame::Frame::CommandResult(
            external_pb::CommandResult::default()
        ))? == "command_result",
        "unexpected command result frame type"
    );
    ensure!(
        secure_external_inner_frame_type(&external_pb::external_frame::Frame::InvokeResult(
            external_pb::InvokeResult::default()
        ))? == "invoke_result",
        "unexpected invoke result frame type"
    );
    ensure!(
        secure_external_inner_frame_type(&external_pb::external_frame::Frame::Control(
            external_pb::ControlFrame {
                kind: Some(external_pb::control_frame::Kind::ConfigAck(
                    external_pb::ConfigAck::default()
                )),
            }
        ))? == "control.config_ack",
        "unexpected control frame type"
    );
    Ok(())
}

#[test]
fn gateway_state_paths_are_structural() -> anyhow::Result<()> {
    let hash = "a".repeat(64);
    ensure!(
        blob_path(&hash)?.to_string() == format!("state://blob/{hash}"),
        "unexpected blob path"
    );
    ensure!(
        idempotency_path(&hash)?.to_string() == format!("state://gateway/idempotency/{hash}"),
        "unexpected idempotency path"
    );
    ensure!(
        upload_ticket_path("ticket/1").is_err(),
        "ticket id with path delimiter was accepted"
    );
    ensure!(
        blob_path(&format!("{hash}/tail")).is_err(),
        "blob hash with path delimiter was accepted"
    );
    Ok(())
}

#[test]
fn upload_ticket_records_require_security_state_fields() -> anyhow::Result<()> {
    let ticket = GatewayObjectUploadTicket {
        ticket_id: "ticket_regression".into(),
        principal_id: "alice".into(),
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: None,
        expected_digest: None,
        allowed_media_types: Vec::new(),
        expires_at_ms: now_millis().saturating_add(60_000),
        single_use: true,
        committed: false,
        used: false,
    };

    for field in ["single_use", "committed", "used"] {
        let mut value = ticket.to_value();
        let Value::Map(map) = &mut value else {
            bail!("ticket did not serialize to a map");
        };
        map.remove(field);
        ensure!(
            matches!(GatewayObjectUploadTicket::from_value(&value), Err(GatewayError::Rejected(message)) if message.contains(field)),
            "ticket missing {field} should be rejected"
        );
    }

    let mut value = ticket.to_value();
    let Value::Map(map) = &mut value else {
        bail!("ticket did not serialize to a map");
    };
    map.insert("used".into(), Value::Str("false".into()));
    ensure!(
        matches!(GatewayObjectUploadTicket::from_value(&value), Err(GatewayError::Rejected(message)) if message.contains("used")),
        "ticket with malformed used field should be rejected"
    );
    Ok(())
}

#[test]
fn secure_external_envelope_context_must_match_session() -> anyhow::Result<()> {
    let context = ExternalSessionContext {
        installation_id: "install".into(),
        projection_id: "source".into(),
        role: ExternalRole::Source,
        registry_hash: "hash".into(),
        credential_generation: 2,
        binding_generation: 3,
        installation_config_version: 4,
        projection_version: 5,
        presentation_config_generation: 6,
        alias_catalog_generation: 7,
        session_id: "session".into(),
    };
    let envelope = SecureEnvelope::from_parts(
        context.installation_id.clone(),
        context.credential_generation,
        EnvelopeAad {
            version: 1,
            projection_id: context.projection_id.clone(),
            role: external_role_slug(context.role).into(),
            session_id: context.session_id.clone(),
            frame_type: "inbound_event".into(),
            binding_generation: context.binding_generation,
            credential_generation: context.credential_generation,
            transcript_hash: vec![0; 32],
            ..EnvelopeAad::default()
        },
        [0; 12],
        Vec::new(),
    );
    validate_secure_external_envelope_context(&envelope, &context)?;

    let rejected_envelope = SecureEnvelope::from_parts(
        context.installation_id.clone(),
        context.credential_generation,
        EnvelopeAad {
            version: 1,
            projection_id: context.projection_id.clone(),
            role: "provider".into(),
            session_id: context.session_id.clone(),
            frame_type: "inbound_event".into(),
            binding_generation: context.binding_generation,
            credential_generation: context.credential_generation,
            transcript_hash: vec![0; 32],
            ..EnvelopeAad::default()
        },
        [0; 12],
        Vec::new(),
    );
    let err = expect_error(validate_secure_external_envelope_context(
        &rejected_envelope,
        &context,
    ))?;
    ensure!(
        err == ExternalFrameError::SecureEnvelopeContextRejected,
        "unexpected envelope context error: {err:?}"
    );
    Ok(())
}

struct BlockingCountingDriver {
    count: Arc<AtomicUsize>,
    released: Arc<AtomicBool>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl nexus_kernel::Driver for BlockingCountingDriver {
    async fn call(
        &self,
        _method: nexus_types::MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &nexus_kernel::DriverContext,
    ) -> Result<Outcome, nexus_kernel::DriverError> {
        self.count.fetch_add(1, Ordering::AcqRel);
        while !self.released.load(Ordering::Acquire) {
            self.release.notified().await;
        }
        Ok(Outcome::Done(input))
    }
}

struct FailingDriver;

#[async_trait::async_trait]
impl nexus_kernel::Driver for FailingDriver {
    async fn call(
        &self,
        _method: nexus_types::MethodId,
        _input: Value,
        _output: OutputMode,
        _ctx: &nexus_kernel::DriverContext,
    ) -> Result<Outcome, nexus_kernel::DriverError> {
        Ok(Outcome::Fail(Failure::InvalidInput {
            reason: "bad input".into(),
        }))
    }
}

fn identity_profile() -> anyhow::Result<GatewayProfile> {
    Ok(GatewayProfile::new("gateway-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    )?)
}

fn client_certificate_profile() -> GatewayProfile {
    GatewayProfile::new("gateway-test")
        .with_credential(GatewayCredential::client_certificate_der_sha256(
            "cert-alice",
            "alice",
            ClientCertificateDerSha256::from_der(b"alice-client-cert-der"),
        ))
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
}

#[test]
fn gateway_host_matching_requires_exact_host_and_port() -> anyhow::Result<()> {
    let registered = vec![
        GatewayAllowedHost::parse("Api.Example.com")?,
        GatewayAllowedHost::parse("[2001:db8::10]:7443")?,
    ];
    ensure!(
        gateway_host_allowed("api.example.com", &registered),
        "registered host should match"
    );
    ensure!(
        gateway_host_allowed("[2001:db8::10]:7443", &registered),
        "registered IPv6 host should match"
    );
    ensure!(
        !gateway_host_allowed("api.example.com:443", &registered),
        "implicit port must not match explicit port"
    );
    ensure!(
        !gateway_host_allowed("other.example.com", &registered),
        "unregistered host should not match"
    );
    ensure!(
        !gateway_host_allowed("https://api.example.com", &registered),
        "URL string should not match host"
    );
    ensure!(
        GatewayAllowedHost::parse("api.example.com:443:bad").is_err(),
        "invalid host should be rejected"
    );
    ensure!(
        GatewayAllowedHost::parse("*.example.com").is_err(),
        "wildcard host should be rejected"
    );
    Ok(())
}

#[test]
fn browser_origin_matching_is_exact_except_configured_port_relaxation() -> anyhow::Result<()> {
    let registered = vec![GatewayAllowedOrigin::parse("https://App.Example.com:443")?];
    ensure!(
        browser_origin_allowed("https://app.example.com", &registered, false),
        "registered origin should match"
    );
    ensure!(
        !browser_origin_allowed("https://app.example.com:8443", &registered, false),
        "port mismatch should be rejected without relaxation"
    );
    ensure!(
        browser_origin_allowed("https://app.example.com:8443", &registered, true),
        "port relaxation should allow matching host and scheme"
    );
    ensure!(
        !browser_origin_allowed("http://app.example.com:8443", &registered, true),
        "scheme mismatch should be rejected"
    );
    ensure!(
        !browser_origin_allowed("https://evil.example.com:8443", &registered, true),
        "host mismatch should be rejected"
    );
    ensure!(
        !browser_origin_allowed("https://app.example.com/path", &registered, true),
        "origin with path should be rejected"
    );
    Ok(())
}

#[test]
fn profile_rejects_duplicate_registered_origins() -> anyhow::Result<()> {
    let profile = GatewayProfile::new("gateway-test")
        .with_registered_origin("https://app.example.com")?
        .with_registered_origin("https://APP.example.com:443")?;
    let err = match GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile) {
        Ok(_) => bail!("duplicate origin should fail"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected duplicate origin error: {err:?}"
    );
    Ok(())
}

#[test]
fn profile_rejects_duplicate_registered_hosts() -> anyhow::Result<()> {
    let profile = GatewayProfile::new("gateway-test")
        .with_registered_host("api.example.com")?
        .with_registered_host("API.example.com")?;
    let err = match GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile) {
        Ok(_) => bail!("duplicate host should fail"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected duplicate host error: {err:?}"
    );
    Ok(())
}

fn schema_type(kind: &str) -> Value {
    Value::Map(BTreeMap::from([("type".into(), Value::from(kind))]))
}

fn array_schema(item: Value) -> Value {
    Value::Map(BTreeMap::from([
        ("type".into(), Value::from("array")),
        ("items".into(), item),
    ]))
}

fn text_object_schema() -> Value {
    Value::Map(BTreeMap::from([
        ("type".into(), Value::from("object")),
        ("required".into(), Value::List(vec![Value::from("text")])),
        (
            "properties".into(),
            Value::Map(BTreeMap::from([("text".into(), schema_type("string"))])),
        ),
    ]))
}

fn direct_input_with_provenance(
    surface_id: &str,
    payload: Value,
    provenance: GatewayPayloadProvenance,
) -> GatewaySubmission {
    GatewaySubmission::direct_input(surface_id, payload).with_provenance(provenance)
}

fn direct_input_with_ticket(
    surface_id: &str,
    payload: Value,
    ticket_id: &str,
) -> GatewaySubmission {
    direct_input_with_provenance(
        surface_id,
        payload,
        GatewayPayloadProvenance {
            upload_ticket: Some(ticket_id.into()),
            store_proof: None,
        },
    )
}

fn input_stream_open_request() -> GatewayStreamOpenRequest {
    GatewayStreamOpenRequest {
        stream_id: "input".into(),
        direction: GatewayStreamDirection::ClientToKernel,
        modality: GatewayModality::Text,
        item_schema_id: String::new(),
        max_inline_item_bytes: 16,
        max_items: Some(4),
        max_bytes: Some(64),
    }
}

fn input_stream_submission(surface_id: &str) -> GatewaySubmission {
    GatewaySubmission::input_stream(surface_id, input_stream_open_request())
}

fn echo_profile(name: ResourceName) -> anyhow::Result<GatewayProfile> {
    Ok(identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        )))
}

fn bind_alice_to_echo(profile: GatewayProfile) -> GatewayProfile {
    profile.with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/echo/say"],
    ))
}

fn assert_limit_contains(err: GatewayError, needle: &str) -> anyhow::Result<()> {
    match err {
        GatewayError::LimitExceeded(message) => ensure!(
            message.contains(needle),
            "limit message {message:?} did not contain {needle:?}"
        ),
        other => bail!("expected limit error, got {other:?}"),
    }
    Ok(())
}

fn restricted_anchor(boot: &Bootstrap, selector: &str) -> anyhow::Result<ProcessId> {
    boot.spawn_request_process_under_with_request_grants(
        boot.root,
        nexus_types::IdentityRef::ROOT,
        &[nexus_kernel::RequestGrantTemplate {
            literal: selector,
            methods: nexus_types::MethodBitmap::ALL,
        }],
    )
    .map_err(Into::into)
}

fn expect_error<T: Debug, E>(result: Result<T, E>) -> anyhow::Result<E> {
    match result {
        Ok(value) => bail!("expected error, got {value:?}"),
        Err(err) => Ok(err),
    }
}

fn expect_gateway_error<T>(result: Result<T, GatewayError>) -> anyhow::Result<GatewayError> {
    match result {
        Ok(_) => bail!("expected gateway error"),
        Err(err) => Ok(err),
    }
}

fn expect_accepted_stream(
    start: GatewayInputStreamStart,
) -> anyhow::Result<Box<GatewayAcceptedInputStream>> {
    match start {
        GatewayInputStreamStart::Accepted(stream) => Ok(stream),
        GatewayInputStreamStart::Replay(replay) => {
            bail!("expected fresh stream admission, got replay: {replay:?}")
        }
    }
}

#[tokio::test]
async fn unknown_bearer_is_unauthenticated() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(boot, identity_profile()?)?;
    ensure!(
        matches!(
            gw.authenticate(PresentedCredential::bearer("unknown-token-for-test"))
                .await,
            Err(GatewayError::Unauthenticated)
        ),
        "unknown bearer should be unauthenticated"
    );
    Ok(())
}

#[tokio::test]
async fn bearer_maps_to_profile_identity() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(boot, identity_profile()?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        session.principal.principal_id == "alice",
        "unexpected principal: {:?}",
        session.principal
    );
    ensure!(
        session.identity_path == "process://alice",
        "unexpected identity path: {}",
        session.identity_path
    );
    Ok(())
}

#[tokio::test]
async fn client_certificate_fingerprint_maps_to_profile_identity() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(boot, client_certificate_profile())?;
    ensure!(gw.is_ready(), "gateway should be ready");
    let session = gw
        .authenticate(PresentedCredential::client_certificate_der(
            b"alice-client-cert-der",
        ))
        .await?;
    ensure!(
        session.principal.principal_id == "alice",
        "unexpected principal: {:?}",
        session.principal
    );
    ensure!(
        session.principal.auth_method == GatewayAuthMethod::ClientCertificate,
        "unexpected auth method: {:?}",
        session.principal.auth_method
    );
    ensure!(
        session.identity_path == "process://alice",
        "unexpected identity path: {}",
        session.identity_path
    );
    Ok(())
}

#[tokio::test]
async fn unknown_client_certificate_is_unauthenticated() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(boot, client_certificate_profile())?;
    ensure!(
        matches!(
            gw.authenticate(PresentedCredential::client_certificate_der(
                b"unknown-client-cert-der",
            ))
            .await,
            Err(GatewayError::Unauthenticated)
        ),
        "unknown client certificate should be unauthenticated"
    );
    Ok(())
}

#[test]
fn public_error_messages_are_redacted() -> anyhow::Result<()> {
    ensure!(
        GatewayError::Unauthorized("alice".into()).public_message() == "authorization failed",
        "unauthorized public message should be redacted"
    );
    ensure!(
        GatewayError::Rejected("reserved path state://vault/console/root/password".into())
            .public_message()
            == "request rejected",
        "rejected public message should be redacted"
    );
    Ok(())
}

#[test]
fn credential_debug_output_is_redacted() -> anyhow::Result<()> {
    let token_hash = BearerTokenHash::from_token(TEST_TOKEN)?;
    let debug_hash = format!("{token_hash:?}");
    ensure!(
        debug_hash.contains("<redacted>"),
        "token hash debug output should be redacted"
    );
    ensure!(
        !debug_hash.contains(TEST_TOKEN),
        "token hash debug output leaked token"
    );
    ensure!(
        !debug_hash.contains(&hash_bearer_token(TEST_TOKEN)),
        "token hash debug output leaked hash"
    );

    let credential = GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?;
    let debug_credential = format!("{credential:?}");
    ensure!(
        debug_credential.contains("<redacted>"),
        "credential debug output should be redacted"
    );
    ensure!(
        !debug_credential.contains(TEST_TOKEN),
        "credential debug output leaked token"
    );
    ensure!(
        !debug_credential.contains(&hash_bearer_token(TEST_TOKEN)),
        "credential debug output leaked hash"
    );
    Ok(())
}

#[tokio::test]
async fn submit_runs_direct_input_surface() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot, echo_profile(name)?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::Int(7)),
        )
        .await?;
    ensure!(
        out == Outcome::Done(Value::Int(7)),
        "unexpected gateway output: {out:?}"
    );
    ensure!(
        out.accepted.submission_id.starts_with("gw-submission-"),
        "unexpected submission id: {}",
        out.accepted.submission_id
    );
    ensure!(
        out.accepted.trace_root.starts_with("gw-trace-"),
        "unexpected trace root: {}",
        out.accepted.trace_root
    );
    ensure!(
        out.accepted.submission_id != out.accepted.trace_root,
        "submission id and trace root should differ"
    );
    ensure!(
        out.accepted.profile_rev == 1,
        "unexpected profile revision: {}",
        out.accepted.profile_rev
    );
    Ok(())
}

#[tokio::test]
async fn cancel_requires_owner_and_trace_root() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://slow/echo",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Effectful,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: Arc::new(AtomicUsize::new(0)),
            released: Arc::new(AtomicBool::new(false)),
            release: Arc::new(tokio::sync::Notify::new()),
        }),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("slow", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["slow"],
            ["perform://effect/slow/echo"],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot.clone(), profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::Str("work".into())).with_options(
                    SubmitOptions {
                        idempotency_key: Some("slow-cancel".into()),
                        ..SubmitOptions::default()
                    },
                ),
            )
            .await
        })
    };
    let entry = loop {
        if let Some(entry) = gw
            .requests
            .inner
            .lock()
            .entries
            .values()
            .find(|entry| entry.state == GatewayRequestState::Running)
            .cloned()
        {
            break entry;
        }
        tokio::task::yield_now().await;
    };

    let mut wrong_owner = session.clone();
    wrong_owner.principal.principal_id = "bob".into();
    let cancelled = gw.cancel(
        &wrong_owner,
        GatewayCancelRequest {
            submission_id: entry.accepted.submission_id.clone(),
            trace_root: entry.accepted.trace_root.clone(),
            reason: None,
        },
    )?;
    ensure!(!cancelled, "wrong owner should not cancel request");
    let cancelled = gw.cancel(
        &session,
        GatewayCancelRequest {
            submission_id: entry.accepted.submission_id.clone(),
            trace_root: "wrong-trace-root".into(),
            reason: None,
        },
    )?;
    ensure!(!cancelled, "wrong trace root should not cancel request");
    let cancelled = gw.cancel(
        &session,
        GatewayCancelRequest {
            submission_id: entry.accepted.submission_id.clone(),
            trace_root: entry.accepted.trace_root.clone(),
            reason: Some("client_cancel".into()),
        },
    )?;
    ensure!(
        cancelled,
        "owner with matching trace root should cancel request"
    );
    ensure!(
        boot.kernel.processes.status(entry.request_process) == Some(ProcessStatus::Cancelled),
        "request process should be cancelled"
    );
    ensure!(
        gw.requests
            .inner
            .lock()
            .entries
            .get(&entry.accepted.submission_id)
            .map(|entry| entry.state)
            == Some(GatewayRequestState::Cancelled),
        "request registry should record cancellation"
    );

    running.abort();
    Ok(())
}

#[tokio::test]
async fn cancel_releases_admission_and_budget_before_driver_returns() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let slow = boot.register_effect(
        "effect://cancel/slow",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Effectful,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let fast = boot.register_effect(
        "effect://cancel/fast",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let limits = GatewayLimitProfile {
        max_in_flight_requests: 1,
        budget: GatewayBudgetProfile {
            max_inflight_ops: Some(1),
            ..GatewayBudgetProfile::default()
        },
        ..GatewayLimitProfile::default()
    };
    let profile = identity_profile()?
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("slow", slow))
        .with_surface(GatewaySurface::effect_invoke("fast", fast))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["slow", "fast"],
            [
                "perform://effect/cancel/slow",
                "perform://effect/cancel/fast",
            ],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot.clone(), profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::Str("work".into())).with_options(
                    SubmitOptions {
                        idempotency_key: Some("cancel-slow-once".into()),
                        ..SubmitOptions::default()
                    },
                ),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    let entry = gw
        .requests
        .inner
        .lock()
        .entries
        .values()
        .find(|entry| entry.state == GatewayRequestState::Running)
        .cloned()
        .context("missing running request entry")?;

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("before".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "fast request should be rejected before cancellation"
    );
    let cancelled = gw.cancel(
        &session,
        GatewayCancelRequest {
            submission_id: entry.accepted.submission_id,
            trace_root: entry.accepted.trace_root,
            reason: Some("client_cancel".into()),
        },
    )?;
    ensure!(cancelled, "running request should cancel");

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("fast", Value::Str("after".into())),
        )
        .await?;
    ensure!(
        out.outcome == Outcome::Done(Value::Str("after".into())),
        "unexpected output after cancellation: {:?}",
        out.outcome
    );

    released.store(true, Ordering::Release);
    release.notify_waiters();
    let completed = running
        .await
        .context("running submission task join failed")??;
    drop(completed);
    Ok(())
}

#[tokio::test]
async fn request_runs_as_attenuated_child_not_root() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let root = boot.root;
    let gw = GatewayRuntime::new(boot.clone(), identity_profile()?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let profile = gw.profile_snapshot();
    let p1 = gw.spawn_gateway_request_process(&profile, &session, &BTreeSet::new())?;
    let p2 = gw.spawn_gateway_request_process(&profile, &session, &BTreeSet::new())?;
    ensure!(p1 != root, "request process should not be root");
    ensure!(p2 != root, "request process should not be root");
    ensure!(p1 != p2, "each request gets its own attenuated process");
    Ok(())
}

#[test]
fn malformed_profile_rejects_unmapped_principal() -> anyhow::Result<()> {
    let profile = GatewayProfile::new("gateway-test").with_credential(
        GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?,
    );
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected malformed profile error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_identity_path_rejects_profile() -> anyhow::Result<()> {
    let profile = GatewayProfile::new("gateway-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "state://alice",
    )?;
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected identity path error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_zero_revision() -> anyhow::Result<()> {
    let profile = identity_profile()?.with_revision(0);
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected zero revision error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_duplicate_names() -> anyhow::Result<()> {
    let duplicate_credential = GatewayProfile::new("gateway-test")
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
        .with_credential(GatewayCredential::bearer_token(
            "cred-alice",
            "alice",
            TEST_TOKEN,
        )?)
        .with_credential(GatewayCredential::bearer_token(
            "cred-alice",
            "alice",
            "other-token-for-alice-01",
        )?);
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        duplicate_credential,
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected duplicate credential error: {err:?}"
    );

    let target = ResourceName::new(Path::parse("effect://echo/say")?);
    let duplicate_surface = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("echo", target.clone()))
        .with_surface(GatewaySurface::effect_invoke("echo", target));
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        duplicate_surface,
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected duplicate surface error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_surface_exceeding_authority_anchor() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let anchor = restricted_anchor(&boot, "perform://effect/inference/**")?;
    let profile = echo_profile(name)?.with_authority_anchor(anchor);
    let err = expect_gateway_error(GatewayRuntime::new(boot, profile))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected authority anchor error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_surface_exceeding_principal_ceiling() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/inference/**"],
        ));
    let err = expect_gateway_error(GatewayRuntime::new(boot, profile))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected principal ceiling error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_invalid_surface_schemas() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(
            GatewaySurface::effect_invoke("echo", name)
                .with_schema(Some(Value::from("not-a-schema-object")), None),
        ),
    );
    let err = expect_gateway_error(GatewayRuntime::new(boot, profile))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected input schema error: {err:?}"
    );

    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(
            GatewaySurface::effect_invoke("echo", name)
                .with_schema(None, Some(Value::from("not-a-schema-object"))),
        ),
    );
    let err = expect_gateway_error(GatewayRuntime::new(boot, profile))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected output schema error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn submit_uses_restricted_authority_anchor_when_configured() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let anchor = restricted_anchor(&boot, "perform://effect/echo/**")?;
    let profile = echo_profile(name.clone())?.with_authority_anchor(anchor);
    let gw = GatewayRuntime::new(boot.clone(), profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let result = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::Str("ok".into())),
        )
        .await?;
    ensure!(
        result == Outcome::Done(Value::Str("ok".into())),
        "unexpected restricted authority output: {result:?}"
    );

    let children = boot.kernel.processes.children_of(anchor);
    ensure!(
        children.len() == 1,
        "unexpected child count: {}",
        children.len()
    );
    ensure!(
        boot.kernel.registry.grants_of(children[0]).is_empty(),
        "child should not retain root grants"
    );
    ensure!(
        boot.kernel.processes.attached_grants(children[0]).len() == 1,
        "child should have one attached grant"
    );
    Ok(())
}

#[tokio::test]
async fn profile_replace_rejects_old_session_and_keeps_bad_reload_closed() -> anyhow::Result<()> {
    const NEW_TOKEN: &str = "test-token-for-bob-000002";
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot.clone(), echo_profile(name.clone())?)?;
    let old_session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let new_profile = GatewayProfile::new("gateway-test")
        .with_revision(2)
        .with_bearer_identity("cred-bob", "bob", NEW_TOKEN, "process://bob")?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "bob",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let profile_rev = gw.replace_profile(new_profile)?;
    ensure!(
        profile_rev == 2,
        "unexpected profile revision: {profile_rev}"
    );
    ensure!(
        gw.profile_rev() == 2,
        "runtime profile revision should be 2"
    );

    ensure!(
        matches!(
            gw.submit(
                &old_session,
                GatewaySubmission::direct_input("echo", Value::Int(1))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "old session should be rejected after profile replacement"
    );
    ensure!(
        matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ),
        "old token should not authenticate after replacement"
    );
    let new_session = gw
        .authenticate(PresentedCredential::bearer(NEW_TOKEN))
        .await?;
    ensure!(
        new_session.identity_path == "process://bob",
        "unexpected new identity path: {}",
        new_session.identity_path
    );

    let bad_profile = GatewayProfile::new("gateway-test")
        .with_revision(3)
        .with_bearer_identity(
            "cred-eve",
            "eve",
            "test-token-for-eve-000003",
            "state://eve",
        )?;
    ensure!(
        matches!(
            gw.replace_profile(bad_profile),
            Err(GatewayError::InvalidProfile(_))
        ),
        "bad profile should be rejected"
    );
    ensure!(
        gw.profile_rev() == 2,
        "profile revision should remain on LKG"
    );
    ensure!(
        gw.authenticate(PresentedCredential::bearer(NEW_TOKEN))
            .await
            .is_ok(),
        "new token should still authenticate under LKG"
    );
    let status = gw.status();
    ensure!(
        status.profile_rev == 2,
        "unexpected status revision: {}",
        status.profile_rev
    );
    ensure!(status.ready, "gateway should remain ready");
    ensure!(
        status.readiness == GatewayReadiness::DegradedLastKnownGood,
        "unexpected readiness: {:?}",
        status.readiness
    );
    ensure!(status.lkg_active, "LKG should be active");
    ensure!(
        status.consecutive_failed_reloads == 1,
        "unexpected failed reload count: {}",
        status.consecutive_failed_reloads
    );
    ensure!(
        status.last_reload_failure.as_ref().map(|failure| {
            (
                failure.attempted_profile_rev,
                failure.code.as_str(),
                failure.public_message.as_str(),
            )
        }) == Some((3, "invalid_profile", "profile reload rejected")),
        "unexpected reload failure: {:?}",
        status.last_reload_failure
    );
    Ok(())
}

#[tokio::test]
async fn profile_replace_requires_monotonic_revision() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(boot, identity_profile()?.with_revision(2))?;
    ensure!(
        matches!(
            gw.replace_profile(identity_profile()?.with_revision(2)),
            Err(GatewayError::InvalidProfile(_))
        ),
        "same revision should be rejected"
    );
    ensure!(
        matches!(
            gw.replace_profile(identity_profile()?.with_revision(1)),
            Err(GatewayError::InvalidProfile(_))
        ),
        "older revision should be rejected"
    );
    let profile_rev = gw.replace_profile(identity_profile()?.with_revision(3))?;
    ensure!(
        profile_rev == 3,
        "unexpected profile revision: {profile_rev}"
    );
    let status = gw.status();
    ensure!(
        status.profile_rev == 3,
        "unexpected status revision: {}",
        status.profile_rev
    );
    ensure!(
        status.readiness == GatewayReadiness::Ready,
        "unexpected readiness: {:?}",
        status.readiness
    );
    ensure!(!status.lkg_active, "LKG should not be active");
    ensure!(
        status.consecutive_failed_reloads == 0,
        "unexpected failed reload count: {}",
        status.consecutive_failed_reloads
    );
    ensure!(
        status.last_reload_failure.is_none(),
        "reload failure should be cleared"
    );
    Ok(())
}

#[tokio::test]
async fn disabled_credentials_and_principals_do_not_authenticate() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let disabled_credential = GatewayProfile::new("gateway-test")
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
        .with_credential(
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?.with_enabled(false),
        );
    let gw = GatewayRuntime::new(boot.clone(), disabled_credential)?;
    ensure!(
        matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ),
        "disabled credential should not authenticate"
    );

    let disabled_principal = GatewayProfile::new("gateway-test")
        .with_identity_mapping(
            GatewayIdentityMapping::new("alice", "process://alice").with_enabled(false),
        )
        .with_credential(GatewayCredential::bearer_token(
            "cred-alice",
            "alice",
            TEST_TOKEN,
        )?);
    let gw = GatewayRuntime::new(boot, disabled_principal)?;
    ensure!(
        matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ),
        "disabled principal should not authenticate"
    );
    Ok(())
}

#[tokio::test]
async fn credential_revocation_floor_blocks_revoked_generations() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let revoked = identity_profile()?.with_credential_revocation_floor(1);
    let gw = GatewayRuntime::new(boot.clone(), revoked)?;
    ensure!(
        matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ),
        "revoked credential should not authenticate"
    );
    ensure!(
        gw.status().readiness == GatewayReadiness::NotReadyClosed,
        "unexpected readiness after revoked credential"
    );

    let rotated = GatewayProfile::new("gateway-test")
        .with_credential_revocation_floor(1)
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
        .with_credential(
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?.with_generation(2),
        );
    let gw = GatewayRuntime::new(boot, rotated)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        session.principal.credential_generation == 2,
        "unexpected credential generation: {}",
        session.principal.credential_generation
    );
    ensure!(
        gw.status().readiness == GatewayReadiness::Ready,
        "rotated credential should be ready"
    );
    Ok(())
}

#[tokio::test]
async fn generation_bump_invalidates_existing_session() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot, echo_profile(name.clone())?)?;
    let old_session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let bumped = GatewayProfile::new("gateway-test")
        .with_revision(2)
        .with_identity_mapping(
            GatewayIdentityMapping::new("alice", "process://alice").with_generation(2),
        )
        .with_credential(
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?.with_generation(2),
        )
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    gw.replace_profile(bumped)?;

    ensure!(
        matches!(
            gw.submit(
                &old_session,
                GatewaySubmission::direct_input("echo", Value::Int(1))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "old session should be rejected after generation bump"
    );
    let new_session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        new_session.principal.credential_generation == 2,
        "unexpected credential generation: {}",
        new_session.principal.credential_generation
    );
    ensure!(
        new_session.principal.principal_generation == 2,
        "unexpected principal generation: {}",
        new_session.principal.principal_generation
    );
    ensure!(
        gw.submit(
            &new_session,
            GatewaySubmission::direct_input("echo", Value::Int(2))
        )
        .await
        .is_ok(),
        "new session should submit successfully"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_lowers_through_surface_not_client_target() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::Str("direct text".into())),
        )
        .await?;

    ensure!(
        out == Outcome::Done(Value::Str("direct text".into())),
        "unexpected direct input output: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn surface_input_schema_validates_direct_input() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(identity_profile()?.with_surface(
        GatewaySurface::effect_invoke("echo", name).with_schema(Some(text_object_schema()), None),
    ));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let valid = Value::Map(BTreeMap::from([(
        "text".into(),
        Value::Str("schema-ok".into()),
    )]));

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", valid.clone()),
        )
        .await?;
    ensure!(
        out == Outcome::Done(valid),
        "unexpected valid schema output: {out:?}"
    );

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Map(BTreeMap::new()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "invalid schema input should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn surface_output_schema_rejects_success_payload_and_replays_failure() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(true));
    let release = Arc::new(tokio::sync::Notify::new());
    let name = boot.register_effect(
        "effect://payment/charge",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Effectful,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released,
            release,
        }),
    )?;
    let profile = identity_profile()?
        .with_surface(
            GatewaySurface::effect_invoke("charge", name)
                .with_schema(Some(schema_type("any")), Some(schema_type("string"))),
        )
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/payment/charge"],
        ));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission =
        GatewaySubmission::direct_input("charge", Value::Int(42)).with_options(SubmitOptions {
            idempotency_key: Some("charge-output-schema".into()),
            ..SubmitOptions::default()
        });

    let first = gw.submit(&session, submission.clone()).await?;
    ensure!(
        matches!(
        first.outcome,
        Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "gateway_output_schema"
        ),
        "first outcome should be output schema failure: {:?}",
        first.outcome
    );
    ensure!(count.load(Ordering::Acquire) == 1, "driver should run once");

    let replay = gw.submit(&session, submission).await?;
    ensure!(
        matches!(
        replay.outcome,
        Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "gateway_output_schema"
        ),
        "replay outcome should be output schema failure: {:?}",
        replay.outcome
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should not rerun replay"
    );
    Ok(())
}

#[tokio::test]
async fn surface_output_schema_does_not_validate_sink_only_delivery() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::SINK_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(
            GatewaySurface::effect_invoke("echo", name)
                .with_schema(Some(schema_type("any")), Some(schema_type("string"))),
        ),
    );
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("echo", Value::Int(42))
        .with_requested_output(OutputMode::SinkOnly);

    let out = gw.submit(&session, submission).await?;
    ensure!(
        out == Outcome::Done(Value::Null),
        "unexpected sink-only output: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_open_registers_request_before_chunks() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot, echo_profile(name)?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let stream = expect_accepted_stream(
        gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
            .await?,
    )?;
    let accepted = stream.accepted().clone();

    ensure!(
        accepted.submission_id.starts_with("gw-submission-"),
        "unexpected submission id: {}",
        accepted.submission_id
    );
    ensure!(
        accepted.trace_root.starts_with("gw-trace-"),
        "unexpected trace root: {}",
        accepted.trace_root
    );
    ensure!(
        accepted.surface_id == "echo",
        "unexpected surface id: {}",
        accepted.surface_id
    );
    ensure!(
        stream.open_request().stream_id == "input",
        "unexpected stream id: {}",
        stream.open_request().stream_id
    );
    let cancelled = gw.cancel(
        &session,
        GatewayCancelRequest {
            submission_id: accepted.submission_id,
            trace_root: accepted.trace_root,
            reason: Some("test".into()),
        },
    )?;
    ensure!(cancelled, "accepted stream request should cancel");
    Ok(())
}

#[tokio::test]
async fn deadline_sweep_releases_stream_admission_once() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let slow = boot.register_effect(
        "effect://deadline/slow",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let fast = boot.register_effect(
        "effect://deadline/fast",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let limits = GatewayLimitProfile {
        max_in_flight_requests: 1,
        budget: GatewayBudgetProfile {
            max_inflight_ops: Some(1),
            ..GatewayBudgetProfile::default()
        },
        ..GatewayLimitProfile::default()
    };
    let profile = identity_profile()?
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("slow", slow))
        .with_surface(GatewaySurface::effect_invoke("fast", fast))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["slow", "fast"],
            [
                "perform://effect/deadline/slow",
                "perform://effect/deadline/fast",
            ],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot.clone(), profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let deadline_ms = now_millis().saturating_add(25);
    let stream = expect_accepted_stream(
        gw.accept_input_stream_submission(
            &session,
            input_stream_submission("slow").with_options(SubmitOptions {
                deadline_ms: Some(u64::try_from(deadline_ms)?),
                ..SubmitOptions::default()
            }),
        )
        .await?,
    )?;
    let stream_process = stream.request_process;

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("before".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "fast request should be limited before deadline sweep"
    );
    tokio::time::sleep(std::time::Duration::from_millis(35)).await;
    let swept = gw.sweep_deadline_expired_requests();
    ensure!(
        swept > 0,
        "deadline sweep should cancel at least one request"
    );
    ensure!(
        boot.kernel.processes.status(stream_process) == Some(ProcessStatus::Cancelled),
        "stream process should be cancelled"
    );

    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::Str("running".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    drop(stream);
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("still-limited".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "fast request should remain limited while slow request runs"
    );

    released.store(true, Ordering::Release);
    release.notify_waiters();
    let out = running
        .await
        .context("running submission task join failed")??;
    ensure!(
        out.outcome == Outcome::Done(Value::Str("running".into())),
        "unexpected running output: {:?}",
        out.outcome
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_open_rejects_client_item_schema_selection() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot.clone(), echo_profile(name)?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let mut open = input_stream_open_request();
    open.item_schema_id = "client-schema".into();
    let submission = GatewaySubmission::input_stream("echo", open);
    let before = boot.kernel.processes.all_ids().len();

    ensure!(
        matches!(
            gw.accept_input_stream_submission(&session, submission)
                .await,
            Err(GatewayError::Rejected(_))
        ),
        "client item schema selection should be rejected"
    );
    ensure!(
        boot.kernel.processes.all_ids().len() == before,
        "process count should not change"
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_open_rejects_profile_stream_budget_overrun_before_process_spawn()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let limits = GatewayLimitProfile {
        max_stream_items: 2,
        max_stream_bytes: 32,
        max_stream_inline_item_bytes: 8,
        ..GatewayLimitProfile::default()
    };
    let gw = GatewayRuntime::new(boot.clone(), echo_profile(name)?.with_limits(limits))?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let before = boot.kernel.processes.all_ids().len();

    ensure!(
        matches!(
            gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
                .await,
            Err(GatewayError::Rejected(_))
        ),
        "profile stream budget overrun should be rejected"
    );
    ensure!(
        boot.kernel.processes.all_ids().len() == before,
        "process count should not change"
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_chunks_use_profile_item_schema() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("echo", name).with_schema(
            Some(array_schema(schema_type("string"))),
            Some(schema_type("any")),
        ))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let mut open = input_stream_open_request();
    open.modality = GatewayModality::Value;
    let submission = GatewaySubmission::input_stream("echo", open);
    let stream = expect_accepted_stream(
        gw.accept_input_stream_submission(&session, submission)
            .await?,
    )?;

    ensure!(
        stream
            .validate_chunk_item(&Value::Str("chunk".into()))
            .is_ok(),
        "valid stream chunk should pass"
    );
    ensure!(
        matches!(
            stream.validate_chunk_item(&Value::Int(1)),
            Err(GatewayError::Rejected(_))
        ),
        "invalid stream chunk should be rejected"
    );

    gw.fail_input_stream_submission(*stream, "test").await?;
    Ok(())
}

#[tokio::test]
async fn input_stream_completion_reuses_accepted_request() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot, echo_profile(name)?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let stream = expect_accepted_stream(
        gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
            .await?,
    )?;
    let accepted = stream.accepted().clone();
    let result = gw
        .complete_input_stream_submission(*stream, Value::Str("stream text".into()), None)
        .await?;

    ensure!(
        result.accepted == accepted,
        "accepted metadata should be reused"
    );
    ensure!(
        result.outcome == Outcome::Done(Value::Str("stream text".into())),
        "unexpected stream completion outcome: {:?}",
        result.outcome
    );
    Ok(())
}

#[tokio::test]
async fn surface_without_principal_binding_is_not_callable() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?.with_surface(GatewaySurface::effect_invoke("echo", name));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let descriptor = gw.describe(&session)?;
    ensure!(
        descriptor.surfaces.is_empty(),
        "unbound surface should not be visible"
    );
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Str("denied".into()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "unbound surface should not be callable"
    );
    Ok(())
}

#[tokio::test]
async fn submit_deadline_is_clamped_by_server_profile() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot, echo_profile(name)?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let options = SubmitOptions {
        deadline_ms: Some(u64::try_from(
            now_millis().saturating_add(
                GatewayLimitProfile::default()
                    .max_deadline_ms_from_now
                    .saturating_add(60_000),
            ),
        )?),
        ..SubmitOptions::default()
    };

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Int(1)).with_options(options)
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "deadline beyond server profile should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn submit_deadline_out_of_range_is_rejected_before_admission() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(boot, echo_profile(name)?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let result = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::Int(1)).with_options(SubmitOptions {
                deadline_ms: Some(u64::MAX),
                ..SubmitOptions::default()
            }),
        )
        .await;

    ensure!(
        matches!(
        result,
        Err(GatewayError::Rejected(message)) if message == "deadline_ms is out of range"
        ),
        "out-of-range deadline should be rejected"
    );
    ensure!(
        gw.requests.inner.lock().global_running == 0,
        "deadline rejection should not leave running requests"
    );
    Ok(())
}

#[tokio::test]
async fn submit_deadline_timeout_is_recorded_for_idempotency_replay() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let name = boot.register_effect(
        "effect://slow/charge",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Effectful,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: Arc::new(AtomicBool::new(false)),
            release: Arc::new(tokio::sync::Notify::new()),
        }),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("charge", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/slow/charge"],
        ));
    let gw = GatewayRuntime::new(boot.clone(), profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("charge", Value::Str("42".into()))
        .with_options(SubmitOptions {
            idempotency_key: Some("charge-deadline-timeout".into()),
            deadline_ms: Some(u64::try_from(now_millis().saturating_add(100))?),
            ..SubmitOptions::default()
        });

    let first = gw.submit(&session, submission.clone()).await?;
    ensure!(
        matches!(first.outcome, Outcome::Fail(Failure::Timeout)),
        "first outcome should be timeout: {:?}",
        first.outcome
    );
    let entry = gw
        .requests
        .inner
        .lock()
        .entries
        .get(&first.accepted.submission_id)
        .cloned()
        .context("missing retained request entry")?;
    ensure!(
        boot.kernel.processes.status(entry.request_process) == Some(ProcessStatus::Cancelled),
        "deadline timeout should cancel request process"
    );
    ensure!(count.load(Ordering::Acquire) == 1, "driver should run once");

    let replay = gw.submit(&session, submission).await?;
    ensure!(
        replay.outcome == first.outcome,
        "replay should return retained outcome"
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should not rerun replay"
    );
    Ok(())
}

#[tokio::test]
async fn non_idempotent_effect_requires_submission_idempotency() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://payment/charge",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Effectful,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("charge", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/payment/charge"],
        ));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("charge", Value::Str("42".into()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "non-idempotent effect should require idempotency key"
    );

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("charge", Value::Str("42".into())).with_options(
                SubmitOptions {
                    idempotency_key: Some("charge-42".into()),
                    ..SubmitOptions::default()
                },
            ),
        )
        .await?;
    ensure!(
        out == Outcome::Done(Value::Str("42".into())),
        "unexpected idempotent output: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn idempotency_key_replays_without_reexecuting_non_idempotent_effect() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name = boot.register_effect(
        "effect://payment/charge",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Effectful,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("charge", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/payment/charge"],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot, profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("charge", Value::Str("42".into()))
        .with_options(SubmitOptions {
            idempotency_key: Some("charge-42-once".into()),
            ..SubmitOptions::default()
        });

    let first_gw = gw.clone();
    let first_session = session.clone();
    let first_submission = submission.clone();
    let first =
        tokio::spawn(async move { first_gw.submit(&first_session, first_submission).await });
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }

    let second = expect_gateway_error(gw.submit(&session, submission.clone()).await)?;
    ensure!(
        matches!(second, GatewayError::LimitExceeded(_)),
        "second in-flight submission should be limited: {second:?}"
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should run once while first is blocked"
    );

    released.store(true, Ordering::Release);
    release.notify_waiters();
    let first = first.await.context("first submission task join failed")??;
    ensure!(
        first == Outcome::Done(Value::Str("42".into())),
        "unexpected first output: {first:?}"
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should not rerun while completing first"
    );

    let replay = gw.submit(&session, submission).await?;
    ensure!(
        replay == Outcome::Done(Value::Str("42".into())),
        "unexpected replay output: {replay:?}"
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should not rerun replay"
    );
    Ok(())
}

#[tokio::test]
async fn idempotency_key_replays_fail_outcome_variant() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://fail/input",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(FailingDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("fail", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["fail"],
            ["perform://effect/fail/input"],
        ));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission =
        GatewaySubmission::direct_input("fail", Value::Null).with_options(SubmitOptions {
            idempotency_key: Some("fail-once".into()),
            ..SubmitOptions::default()
        });

    let first = gw.submit(&session, submission.clone()).await?;
    let replay = gw.submit(&session, submission).await?;

    ensure!(first == replay, "replay should equal first result");
    ensure!(
        matches!(
        replay.outcome,
        Outcome::Fail(Failure::InvalidInput { ref reason }) if reason == "bad input"
        ),
        "unexpected replay failure outcome: {:?}",
        replay.outcome
    );
    Ok(())
}

#[tokio::test]
async fn idempotency_reservation_is_released_after_admission_rejection() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let limits = GatewayLimitProfile {
        max_literal_bytes: 4,
        ..GatewayLimitProfile::default()
    };
    let profile = bind_alice_to_echo(
        identity_profile()?
            .with_limits(limits)
            .with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(boot.clone(), profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("echo", Value::Str("too-large".into()))
        .with_options(SubmitOptions {
            idempotency_key: Some("reject-and-release".into()),
            ..SubmitOptions::default()
        });
    let prefix = Path::parse("state://gateway/idempotency")?;
    let before = boot.kernel.processes.all_ids().len();

    ensure!(
        matches!(
            gw.submit(&session, submission.clone()).await,
            Err(GatewayError::Rejected(_))
        ),
        "oversized submission should be rejected"
    );
    ensure!(
        boot.kernel.state.read_prefix(&prefix).await?.is_empty(),
        "admission rejection must release the idempotency reservation"
    );
    ensure!(
        boot.kernel.processes.all_ids().len() == before,
        "process count should not change"
    );

    ensure!(
        matches!(
            gw.submit(&session, submission).await,
            Err(GatewayError::Rejected(_))
        ),
        "retry of oversized submission should be rejected"
    );
    ensure!(
        boot.kernel.state.read_prefix(&prefix).await?.is_empty(),
        "retry rejection must release idempotency reservation"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_large_ref_requires_provenance() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let blob = Value::Blob(nexus_types::BlobRef {
        hash: "abc".into(),
        size: 3,
        mime: Some("text/plain".into()),
    });
    let mut nested = BTreeMap::new();
    nested.insert("file".into(), blob.clone());

    ensure!(
        matches!(
            gw.submit(&session, GatewaySubmission::direct_input("echo", blob))
                .await,
            Err(GatewayError::Rejected(_))
        ),
        "large blob ref without provenance should be rejected"
    );
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Map(nested))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "nested large blob ref without provenance should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_large_ref_requires_blob_store_match() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let bytes = b"stored image bytes".to_vec();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let profile = echo_profile(name)?;
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let ticket = gw
        .issue_object_upload_ticket(
            &session,
            IssueObjectUploadTicketRequest {
                surface_id: "echo".into(),
                submission_token: None,
                modality: GatewayModality::Bytes,
                expected_size: Some(bytes.len() as u64),
                expected_digest: Some(hash.clone()),
                allowed_media_types: vec!["image/png".into()],
                expires_in_ms: Some(60_000),
                single_use: false,
            },
        )
        .await?;
    let committed = gw
        .commit_object_upload(
            &session,
            CommitObjectUploadRequest {
                ticket_id: ticket.ticket_id,
                bytes,
                media_type: Some("image/png".into()),
                item: None,
                submission_token: None,
            },
        )
        .await?;
    let blob = committed.item.clone();

    let out = gw
        .submit(
            &session,
            direct_input_with_provenance("echo", blob.clone(), committed.provenance.clone()),
        )
        .await?;
    ensure!(
        out == Outcome::Done(blob),
        "unexpected blob output: {out:?}"
    );

    let wrong_size = Value::Blob(BlobRef {
        hash,
        size: 999,
        mime: None,
    });
    ensure!(
        matches!(
            gw.submit(
                &session,
                direct_input_with_provenance("echo", wrong_size, committed.provenance)
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "mismatched blob store proof should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_upload_ticket_is_bound_and_single_use() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let bytes = b"ticketed bytes".to_vec();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    boot.kernel
        .state
        .write_set(&blob_path(&hash)?, Value::Bytes(bytes.clone()))
        .await?;
    let ticket_id = "ticket_1";
    let ticket = GatewayObjectUploadTicket {
        ticket_id: ticket_id.into(),
        principal_id: "alice".into(),
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: Some(bytes.len() as u64),
        expected_digest: Some(hash.clone()),
        allowed_media_types: vec!["image/*".into()],
        expires_at_ms: now_millis().saturating_add(60_000),
        single_use: true,
        committed: false,
        used: false,
    };
    boot.kernel
        .state
        .write_set(&upload_ticket_path(ticket_id)?, ticket.to_value())
        .await?;
    let blob = Value::Blob(BlobRef {
        hash,
        size: bytes.len() as u64,
        mime: Some("image/png".into()),
    });
    let profile = echo_profile(name)?;
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let out = gw
        .submit(
            &session,
            direct_input_with_ticket("echo", blob.clone(), ticket_id),
        )
        .await?;
    ensure!(
        out == Outcome::Done(blob.clone()),
        "unexpected ticketed blob output: {out:?}"
    );
    ensure!(
        matches!(
            gw.submit(&session, direct_input_with_ticket("echo", blob, ticket_id))
                .await,
            Err(GatewayError::Rejected(_))
        ),
        "single-use ticket should reject reuse"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_upload_ticket_rejects_expired_or_wrong_surface() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let bytes = b"rejected ticket bytes".to_vec();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    boot.kernel
        .state
        .write_set(&blob_path(&hash)?, Value::Bytes(bytes.clone()))
        .await?;
    let mut ticket = GatewayObjectUploadTicket {
        ticket_id: "ticket_expired".into(),
        principal_id: "alice".into(),
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: Some(bytes.len() as u64),
        expected_digest: Some(hash.clone()),
        allowed_media_types: Vec::new(),
        expires_at_ms: now_millis().saturating_sub(1),
        single_use: true,
        committed: false,
        used: false,
    };
    boot.kernel
        .state
        .write_set(&upload_ticket_path(&ticket.ticket_id)?, ticket.to_value())
        .await?;
    ticket.ticket_id = "ticket_surface".into();
    ticket.expires_at_ms = now_millis().saturating_add(60_000);
    ticket.surface_id = "other".into();
    boot.kernel
        .state
        .write_set(&upload_ticket_path(&ticket.ticket_id)?, ticket.to_value())
        .await?;
    let blob = Value::Blob(BlobRef {
        hash,
        size: bytes.len() as u64,
        mime: None,
    });
    let profile = echo_profile(name)?;
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    ensure!(
        matches!(
            gw.submit(
                &session,
                direct_input_with_ticket("echo", blob.clone(), "ticket_expired")
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "expired ticket should be rejected"
    );
    ensure!(
        matches!(
            gw.submit(
                &session,
                direct_input_with_ticket("echo", blob, "ticket_surface")
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "wrong-surface ticket should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn object_upload_issue_commit_returns_bound_single_use_store_proof() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = echo_profile(name)?;
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let bytes = b"committed image bytes".to_vec();
    let digest = blake3::hash(&bytes).to_hex().to_string();
    let ticket = gw
        .issue_object_upload_ticket(
            &session,
            IssueObjectUploadTicketRequest {
                surface_id: "echo".into(),
                submission_token: None,
                modality: GatewayModality::Bytes,
                expected_size: Some(bytes.len() as u64),
                expected_digest: Some(digest.clone()),
                allowed_media_types: vec!["image/*".into()],
                expires_in_ms: Some(60_000),
                single_use: true,
            },
        )
        .await?;

    let committed = gw
        .commit_object_upload(
            &session,
            CommitObjectUploadRequest {
                ticket_id: ticket.ticket_id,
                bytes,
                media_type: Some("image/png".into()),
                item: None,
                submission_token: None,
            },
        )
        .await?;
    ensure!(
        committed.digest == digest,
        "unexpected committed digest: {}",
        committed.digest
    );
    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", committed.item.clone())
                .with_provenance(committed.provenance.clone()),
        )
        .await?;
    ensure!(
        out == Outcome::Done(committed.item.clone()),
        "unexpected committed object output: {out:?}"
    );
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", committed.item)
                    .with_provenance(committed.provenance),
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "single-use store proof should reject reuse"
    );
    Ok(())
}

#[tokio::test]
async fn describe_requires_current_session_and_returns_redacted_surface_catalog()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_revision(7).with_surface(
            GatewaySurface::effect_invoke("echo", name.clone())
                .with_schema(Some(schema_type("string")), Some(schema_type("string"))),
        ),
    );
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let descriptor = gw.describe(&session)?;
    ensure!(
        descriptor.profile_name == "gateway-test",
        "unexpected profile name: {}",
        descriptor.profile_name
    );
    ensure!(
        descriptor.profile_rev == 7,
        "unexpected profile revision: {}",
        descriptor.profile_rev
    );
    ensure!(
        descriptor.surfaces.len() == 1,
        "unexpected surface count: {}",
        descriptor.surfaces.len()
    );
    ensure!(
        descriptor.surfaces[0].surface_id == "echo",
        "unexpected surface id: {}",
        descriptor.surfaces[0].surface_id
    );
    ensure!(
        descriptor.surfaces[0].target == name,
        "unexpected surface target: {:?}",
        descriptor.surfaces[0].target
    );
    ensure!(
        !descriptor.surfaces[0].allows_publish_capability("publish://effect/echo/say"),
        "surface catalog should not expose publish capability"
    );
    ensure!(
        descriptor.surfaces[0].input_schema == Some(schema_type("string")),
        "unexpected input schema"
    );
    ensure!(
        descriptor.surfaces[0].output_schema == Some(schema_type("string")),
        "unexpected output schema"
    );
    ensure!(
        descriptor.limits.max_literal_bytes == GatewayLimitProfile::default().max_literal_bytes,
        "unexpected literal byte limit"
    );

    let mut stale = session;
    stale.profile_rev = 6;
    ensure!(
        matches!(gw.describe(&stale), Err(GatewayError::Rejected(_))),
        "stale session should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn operation_not_exposed_by_profile_is_rejected() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(boot, identity_profile()?)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Null)
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "operation not exposed by profile should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_large_literal_is_rejected_before_process_spawn() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let limits = GatewayLimitProfile {
        max_literal_bytes: 16,
        ..GatewayLimitProfile::default()
    };
    let name = boot.register_effect(
        "effect://echo/say",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?
            .with_limits(limits)
            .with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(boot.clone(), profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let before = boot.kernel.processes.all_ids().len();
    let prefix = Path::parse("state://gateway/idempotency")?;
    let submission = GatewaySubmission::direct_input(
        "echo",
        Value::Str("this direct input is too large".into()),
    )
    .with_options(SubmitOptions {
        idempotency_key: Some("direct-input-too-large".into()),
        ..SubmitOptions::default()
    });

    ensure!(
        matches!(
            gw.submit(&session, submission).await,
            Err(GatewayError::Rejected(_))
        ),
        "large literal should be rejected"
    );
    ensure!(
        boot.kernel.processes.all_ids().len() == before,
        "process count should not change"
    );
    ensure!(
        boot.kernel.state.read_prefix(&prefix).await?.is_empty(),
        "direct input admission rejection must release the idempotency reservation"
    );
    Ok(())
}

#[tokio::test]
async fn gateway_budget_rejects_inflight_ops_and_releases() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name = boot.register_effect(
        "effect://budget/slow",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let limits = GatewayLimitProfile {
        max_in_flight_requests: 4,
        budget: GatewayBudgetProfile {
            max_inflight_ops: Some(1),
            ..GatewayBudgetProfile::default()
        },
        ..GatewayLimitProfile::default()
    };
    let profile = identity_profile()?
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("budget", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["budget"],
            ["perform://effect/budget/slow"],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot, profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("budget", Value::Str("one".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }

    let retry = GatewaySubmission::direct_input("budget", Value::Str("two".into()));
    ensure!(
        matches!(
        gw.submit(&session, retry.clone()).await,
        Err(GatewayError::LimitExceeded(message))
            if message == "gateway budget in-flight ops limit"
        ),
        "in-flight ops budget should reject retry"
    );

    released.store(true, Ordering::Release);
    release.notify_waiters();
    let completed = running
        .await
        .context("budget submission task join failed")??;
    drop(completed);

    let out = gw.submit(&session, retry).await?;
    ensure!(
        out.outcome == Outcome::Done(Value::Str("two".into())),
        "unexpected retry output: {:?}",
        out.outcome
    );
    Ok(())
}

#[tokio::test]
async fn gateway_budget_rejects_estimated_cost_before_dispatch() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let name = boot.register_effect_with_cost(
        "effect://budget/costed",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: Arc::new(AtomicBool::new(true)),
            release: Arc::new(tokio::sync::Notify::new()),
        }),
        CostModel {
            flat_micro_usd: 500,
            per_1k_in_micro_usd: 0,
            per_1k_out_micro_usd: 0,
        },
    )?;
    let limits = GatewayLimitProfile {
        budget: GatewayBudgetProfile {
            max_estimated_cost_micro_usd: Some(499),
            ..GatewayBudgetProfile::default()
        },
        ..GatewayLimitProfile::default()
    };
    let profile = identity_profile()?
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("budget", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["budget"],
            ["perform://effect/budget/costed"],
        ));
    let gw = GatewayRuntime::new(boot, profile)?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    ensure!(
        matches!(
        gw.submit(
            &session,
            GatewaySubmission::direct_input("budget", Value::Str("costed".into()))
        )
        .await,
        Err(GatewayError::LimitExceeded(message))
            if message == "gateway budget estimated cost limit"
        ),
        "estimated cost budget should reject before dispatch"
    );
    ensure!(
        count.load(Ordering::Acquire) == 0,
        "driver should not run after estimated cost rejection"
    );
    Ok(())
}

#[tokio::test]
async fn profile_replace_keeps_global_in_flight_limit() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name = boot.register_effect(
        "effect://profile/slow",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let limits = GatewayLimitProfile {
        max_in_flight_requests: 2,
        ..GatewayLimitProfile::default()
    };
    let profile = identity_profile()?
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("slow", name.clone()))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["slow"],
            ["perform://effect/profile/slow"],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot, profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::Str("running".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }

    let limits = GatewayLimitProfile {
        max_in_flight_requests: 1,
        ..GatewayLimitProfile::default()
    };
    let new_profile = identity_profile()?
        .with_revision(2)
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("slow", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["slow"],
            ["perform://effect/profile/slow"],
        ));
    let profile_rev = gw.replace_profile(new_profile)?;
    ensure!(
        profile_rev == 2,
        "unexpected profile revision: {profile_rev}"
    );
    let new_session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        matches!(
            gw.submit(
                &new_session,
                GatewaySubmission::direct_input("slow", Value::Int(1))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "new tighter profile should keep running request counted"
    );

    released.store(true, Ordering::Release);
    release.notify_waiters();
    let completed = running
        .await
        .context("profile replacement submission task join failed")?;
    ensure!(
        completed.is_ok(),
        "running request should complete: {completed:?}"
    );
    ensure!(
        gw.submit(
            &new_session,
            GatewaySubmission::direct_input("slow", Value::Int(2))
        )
        .await
        .is_ok(),
        "new session should submit after running request completes"
    );
    Ok(())
}

#[tokio::test]
async fn fair_admission_enforces_principal_limit() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name_a = boot.register_effect(
        "effect://slow/a",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let name_b = boot.register_effect(
        "effect://slow/b",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;
    let limits = GatewayLimitProfile {
        max_in_flight_requests: 4,
        max_principal_in_flight_requests: 1,
        max_surface_in_flight_requests: 4,
        max_risk_class_in_flight_requests: 4,
        ..GatewayLimitProfile::default()
    };
    let profile = identity_profile()?
        .with_limits(limits)
        .with_surface(GatewaySurface::effect_invoke("slow-a", name_a))
        .with_surface(GatewaySurface::effect_invoke("slow-b", name_b))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["slow-a", "slow-b"],
            ["perform://effect/slow/a", "perform://effect/slow/b"],
        ));
    let gw = Arc::new(GatewayRuntime::new(boot, profile)?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow-a", Value::Str("one".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }

    let err = expect_gateway_error(
        gw.submit(
            &session,
            GatewaySubmission::direct_input("slow-b", Value::Str("two".into())),
        )
        .await,
    )?;
    assert_limit_contains(err, "principal")?;

    released.store(true, Ordering::Release);
    release.notify_waiters();
    let completed = running
        .await
        .context("principal limit submission task join failed")?;
    ensure!(
        completed.is_ok(),
        "running request should complete: {completed:?}"
    );
    ensure!(
        gw.submit(
            &session,
            GatewaySubmission::direct_input("slow-b", Value::Str("after".into())),
        )
        .await
        .is_ok(),
        "submission after release should succeed"
    );
    Ok(())
}

#[tokio::test]
async fn fair_admission_enforces_surface_and_risk_limits() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name_a = boot.register_effect(
        "effect://fair/a",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let name_b = boot.register_effect(
        "effect://fair/b",
        &[nexus_kernel::MethodSpec::new(
            "invoke",
            nexus_types::Purity::Pure,
            nexus_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(nexus_kernel::EchoDriver),
    )?;

    let surface_limits = GatewayLimitProfile {
        max_in_flight_requests: 4,
        max_principal_in_flight_requests: 4,
        max_surface_in_flight_requests: 1,
        max_risk_class_in_flight_requests: 4,
        ..GatewayLimitProfile::default()
    };
    let surface_profile = identity_profile()?
        .with_limits(surface_limits)
        .with_surface(GatewaySurface::effect_invoke("fair-a", name_a.clone()))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["fair-a"],
            ["perform://effect/fair/a"],
        ));
    let surface_gw = Arc::new(GatewayRuntime::new(boot.clone(), surface_profile)?);
    let surface_session = surface_gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = surface_gw.clone();
        let session = surface_session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fair-a", Value::Str("one".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    let err = expect_gateway_error(
        surface_gw
            .submit(
                &surface_session,
                GatewaySubmission::direct_input("fair-a", Value::Str("two".into())),
            )
            .await,
    )?;
    assert_limit_contains(err, "surface")?;
    released.store(true, Ordering::Release);
    release.notify_waiters();
    let completed = running
        .await
        .context("surface limit submission task join failed")?;
    ensure!(
        completed.is_ok(),
        "surface-limited request should complete: {completed:?}"
    );

    count.store(0, Ordering::Release);
    released.store(false, Ordering::Release);
    let risk_limits = GatewayLimitProfile {
        max_in_flight_requests: 4,
        max_principal_in_flight_requests: 4,
        max_surface_in_flight_requests: 4,
        max_risk_class_in_flight_requests: 1,
        ..GatewayLimitProfile::default()
    };
    let risk_profile = identity_profile()?
        .with_limits(risk_limits)
        .with_surface(GatewaySurface::effect_invoke("fair-a", name_a))
        .with_surface(GatewaySurface::effect_invoke("fair-b", name_b))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["fair-a", "fair-b"],
            ["perform://effect/fair/a", "perform://effect/fair/b"],
        ));
    let risk_gw = Arc::new(GatewayRuntime::new(boot, risk_profile)?);
    let risk_session = risk_gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = risk_gw.clone();
        let session = risk_session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fair-a", Value::Str("one".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    let err = expect_gateway_error(
        risk_gw
            .submit(
                &risk_session,
                GatewaySubmission::direct_input("fair-b", Value::Str("two".into())),
            )
            .await,
    )?;
    assert_limit_contains(err, "risk-class")?;
    released.store(true, Ordering::Release);
    release.notify_waiters();
    let completed = running
        .await
        .context("risk limit submission task join failed")?;
    ensure!(
        completed.is_ok(),
        "risk-limited request should complete: {completed:?}"
    );
    ensure!(
        risk_gw
            .submit(
                &risk_session,
                GatewaySubmission::direct_input("fair-b", Value::Str("after".into())),
            )
            .await
            .is_ok(),
        "submission after risk limit release should succeed"
    );
    Ok(())
}
