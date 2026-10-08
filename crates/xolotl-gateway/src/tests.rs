use super::*;
use crate::external::{
    EndpointSession, EnvelopeAad, ExternalFrameError, SecureEnvelope,
    authenticated_external_inbound_frame_from_pb, secure_external_envelope_from_pb,
    secure_external_envelope_to_pb, secure_external_inner_frame_type,
    secure_external_outbound_frame_type, validate_secure_external_envelope_context,
    validate_secure_external_envelope_session,
};
use anyhow::{Context, bail, ensure};
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use xolotl_proto::xolotl::v1::external as external_pb;
use xolotl_types::external::{
    ObservedGenerations, Role as ExternalRole, RoleSessionClientHello,
    SessionContext as ExternalSessionContext,
};

mod authority;
mod output;
mod surfaces;

pub(super) const TEST_TOKEN: &str = "test-token-for-alice-0001-32-bytes";

pub(super) fn test_request_scope(
    gateway: &GatewayRuntime,
    session: &GatewaySession,
    surface_id: &str,
) -> anyhow::Result<String> {
    gateway
        .describe(session)?
        .surfaces
        .into_iter()
        .find(|surface| surface.surface_id == surface_id)
        .map(|surface| surface.request_scope)
        .context("test surface must be visible")
}

#[test]
fn submission_hash_preserves_value_types_and_float_bits() -> anyhow::Result<()> {
    let blob = xolotl_types::BlobRef {
        hash: "0123456789abcdef".repeat(6),
        size: 64,
        mime: None,
    };
    let mut values = vec![
        Value::null(),
        Value::integer(0),
        Value::bytes(vec![1, 2]),
        Value::list(vec![Value::integer(1), Value::integer(2)]),
        Value::map(BTreeMap::from([
            ("hash".into(), Value::string(blob.hash.clone())),
            ("size".into(), Value::integer(64)),
            ("mime".into(), Value::null()),
        ])),
        Value::blob(blob),
        Value::stream_end(xolotl_types::StreamMarker::Done),
        Value::map(BTreeMap::from([(
            "__stream_marker".into(),
            Value::string("Done".into()),
        )])),
    ];
    values.extend(
        [
            0,
            0x8000_0000_0000_0000,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0x7ff8_1234_5678_9abc,
            0x7ff8_1234_5678_9abd,
            0xfff8_1234_5678_9abc,
        ]
        .into_iter()
        .map(|bits| Value::float(xolotl_types::FloatBits(f64::from_bits(bits)))),
    );

    let mut hashes = BTreeSet::new();
    for value in values {
        for payload in [
            value.clone(),
            Value::map(BTreeMap::from([(
                "nested".into(),
                Value::list(vec![value]),
            )])),
        ] {
            let submission = GatewaySubmission::direct_input("echo", payload.clone());
            let replay = GatewaySubmission::direct_input("echo", payload);
            let hash = submission_hash(&submission)?;
            ensure!(hash == submission_hash(&replay)?, "hash changed on replay");
            ensure!(
                hashes.insert(hash),
                "distinct typed submission collided: {submission:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn secure_external_frame_types_are_canonical() -> anyhow::Result<()> {
    ensure!(
        secure_external_inner_frame_type(&external_pb::external_frame::Frame::RoleReady(
            external_pb::RoleReady::default()
        ))? == "role_ready",
        "unexpected authenticated ready frame type"
    );
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
    ensure!(
        secure_external_outbound_frame_type(&external_pb::external_frame::Frame::Invoke(
            external_pb::Invoke::default()
        ))? == "invoke"
    );
    ensure!(matches!(
        secure_external_outbound_frame_type(&external_pb::external_frame::Frame::RoleReady(
            external_pb::RoleReady::default()
        )),
        Err(ExternalFrameError::ExternalFrameDirectionRejected)
    ));
    Ok(())
}

#[test]
fn authenticated_external_parser_rejects_wrong_direction() -> anyhow::Result<()> {
    let frame = external_pb::external_frame::Frame::Invoke(external_pb::Invoke::default());
    ensure!(matches!(
        authenticated_external_inbound_frame_from_pb(frame),
        Err(ExternalFrameError::SecureEnvelopePayloadRejected)
    ));
    Ok(())
}

#[test]
fn gateway_request_keys_are_structural() -> anyhow::Result<()> {
    let hash = "a".repeat(64);
    crate::GatewayIdempotencyRecord::validate_key(&hash)?;
    ensure!(
        crate::GatewayIdempotencyRecord::validate_key(&format!("{hash}/tail")).is_err(),
        "idempotency hash with path delimiter was accepted"
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
        installation_epoch: 1,
        scope_epoch: 2,
        key_epoch: 1,
    };
    let hello = RoleSessionClientHello {
        installation_id: context.installation_id.clone(),
        projection_id: context.projection_id.clone(),
        role: context.role,
        registry_hash: context.registry_hash.clone(),
        observed: ObservedGenerations {
            presentation_config_generation: context.presentation_config_generation,
            alias_catalog_generation: context.alias_catalog_generation,
        },
        config_schema: None,
    };
    let mut session = EndpointSession::new();
    session.on_hello(&hello, |_| context.clone())?;
    let transcript = *session.transcript_hash().context("session transcript")?;
    let envelope = SecureEnvelope::from_parts(
        context.installation_id.clone(),
        context.credential_generation,
        EnvelopeAad {
            version: 1,
            projection_id: context.projection_id.clone(),
            role: context.role.as_str().into(),
            session_id: context.session_id.clone(),
            frame_type: "inbound_event".into(),
            binding_generation: context.binding_generation,
            credential_generation: context.credential_generation,
            transcript_hash: transcript.to_vec(),
            direction: "client_to_daemon".into(),
            key_epoch: context.key_epoch,
            ..EnvelopeAad::default()
        },
        [0; 12],
        Vec::new(),
    );
    validate_secure_external_envelope_context(&envelope, &context)?;
    validate_secure_external_envelope_session(&envelope, &session)?;
    let wire = secure_external_envelope_to_pb(envelope.clone());
    let round_trip = secure_external_envelope_from_pb(wire)?;
    ensure!(round_trip == envelope);
    for key_epoch in [0, 2] {
        let mut wire = secure_external_envelope_to_pb(envelope.clone());
        let Some(aad) = wire.aad.as_mut() else {
            bail!("encoded envelope has no AAD");
        };
        aad.key_epoch = key_epoch;
        let changed = secure_external_envelope_from_pb(wire)?;
        ensure!(matches!(
            validate_secure_external_envelope_session(&changed, &session),
            Err(ExternalFrameError::SecureEnvelopeContextRejected)
        ));
    }

    let mut changed_transcript = transcript.to_vec();
    changed_transcript[0] ^= 1;
    let changed_envelope = SecureEnvelope::from_parts(
        context.installation_id.clone(),
        context.credential_generation,
        EnvelopeAad {
            version: 1,
            projection_id: context.projection_id.clone(),
            role: context.role.as_str().into(),
            session_id: context.session_id.clone(),
            frame_type: "inbound_event".into(),
            binding_generation: context.binding_generation,
            credential_generation: context.credential_generation,
            transcript_hash: changed_transcript,
            direction: "client_to_daemon".into(),
            key_epoch: context.key_epoch,
            ..EnvelopeAad::default()
        },
        [0; 12],
        Vec::new(),
    );
    ensure!(matches!(
        validate_secure_external_envelope_session(&changed_envelope, &session),
        Err(ExternalFrameError::SecureEnvelopeContextRejected)
    ));

    let reflected_envelope = SecureEnvelope::from_parts(
        context.installation_id.clone(),
        context.credential_generation,
        EnvelopeAad {
            version: 1,
            projection_id: context.projection_id.clone(),
            role: context.role.as_str().into(),
            session_id: context.session_id.clone(),
            frame_type: "control.heartbeat".into(),
            binding_generation: context.binding_generation,
            credential_generation: context.credential_generation,
            transcript_hash: transcript.to_vec(),
            direction: "daemon_to_client".into(),
            key_epoch: context.key_epoch,
            ..EnvelopeAad::default()
        },
        [0; 12],
        Vec::new(),
    );
    ensure!(matches!(
        validate_secure_external_envelope_session(&reflected_envelope, &session),
        Err(ExternalFrameError::SecureEnvelopeContextRejected)
    ));

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
            direction: "client_to_daemon".into(),
            key_epoch: context.key_epoch,
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
impl xolotl_kernel::Driver for BlockingCountingDriver {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &xolotl_kernel::DriverContext,
    ) -> Result<xolotl_kernel::DriverOutput, xolotl_kernel::DriverError> {
        self.count.fetch_add(1, Ordering::AcqRel);
        while !self.released.load(Ordering::Acquire) {
            self.release.notified().await;
        }
        Ok(xolotl_kernel::DriverOutput::new(Outcome::Done(input)))
    }
}

struct FailingDriver;

#[async_trait::async_trait]
impl xolotl_kernel::Driver for FailingDriver {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        _input: Value,
        _output: OutputMode,
        _ctx: &xolotl_kernel::DriverContext,
    ) -> Result<xolotl_kernel::DriverOutput, xolotl_kernel::DriverError> {
        Ok(xolotl_kernel::DriverOutput::new(Outcome::Fail(
            Failure::InvalidInput {
                reason: "bad input".into(),
            },
        )))
    }
}

fn identity_profile() -> anyhow::Result<GatewayProfile> {
    Ok(GatewayProfile::new("gateway-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "identity://alice",
    )?)
}

fn client_certificate_profile() -> GatewayProfile {
    GatewayProfile::new("gateway-test")
        .with_credential(GatewayCredential::client_certificate_der_sha384(
            "cert-alice",
            "alice",
            ClientCertificateDerSha384::from_der(b"alice-client-cert-der"),
        ))
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "identity://alice"))
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
    let err = match GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    ) {
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
    let err = match GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    ) {
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
    Value::map(BTreeMap::from([("type".into(), Value::from(kind))]))
}

fn array_schema(item: Value) -> Value {
    Value::map(BTreeMap::from([
        ("type".into(), Value::from("array")),
        ("items".into(), item),
    ]))
}

fn text_object_schema() -> Value {
    Value::map(BTreeMap::from([
        ("type".into(), Value::from("object")),
        ("required".into(), Value::list(vec![Value::from("text")])),
        (
            "properties".into(),
            Value::map(BTreeMap::from([("text".into(), schema_type("string"))])),
        ),
    ]))
}

pub(super) fn direct_input_with_provenance(
    surface_id: &str,
    payload: Value,
    provenance: GatewayPayloadProvenance,
) -> GatewaySubmission {
    static NEXT_OBJECT_KEY: AtomicUsize = AtomicUsize::new(1);
    let key = NEXT_OBJECT_KEY.fetch_add(1, Ordering::Relaxed);
    GatewaySubmission::direct_input(surface_id, payload)
        .with_provenance(provenance)
        .with_options(SubmitOptions {
            idempotency_key: Some(format!("object-test-{key}")),
            ..SubmitOptions::default()
        })
}

pub(super) fn direct_input_with_ticket(
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

pub(super) fn echo_profile(name: ResourceName) -> anyhow::Result<GatewayProfile> {
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
        boot.root(),
        xolotl_types::IdentityRef::ROOT,
        &[xolotl_kernel::RequestGrantTemplate {
            literal: selector,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                xolotl_types::RightFlags::empty(),
            ),
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
    start: Box<GatewayAcceptedInputStream>,
) -> anyhow::Result<Box<GatewayAcceptedInputStream>> {
    Ok(start)
}

#[tokio::test]
async fn unknown_bearer_is_unauthenticated() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(
        boot,
        identity_profile()?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
    let path = Path::parse("identity://alice")?;
    ensure!(boot.kernel().identities().lookup(&path)?.is_none());
    let gw = GatewayRuntime::new(
        boot.clone(),
        identity_profile()?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let registered = boot
        .kernel()
        .identities()
        .lookup(&path)?
        .context("profile identity was not registered before publication")?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        session.principal.principal_id == "alice",
        "unexpected principal: {:?}",
        session.principal
    );
    ensure!(
        session.identity_path == "identity://alice",
        "unexpected identity path: {}",
        session.identity_path
    );
    ensure!(gw.profile_snapshot().session_identity_ref(&session)? == registered);
    Ok(())
}

#[tokio::test]
async fn client_certificate_fingerprint_maps_to_profile_identity() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(
        boot,
        client_certificate_profile(),
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
        session.identity_path == "identity://alice",
        "unexpected identity path: {}",
        session.identity_path
    );
    Ok(())
}

#[tokio::test]
async fn unknown_client_certificate_is_unauthenticated() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(
        boot,
        client_certificate_profile(),
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
    ensure!(
        GatewayError::Indeterminate("private commit detail".into()).public_message()
            == "outcome unknown; reconcile before retrying",
        "indeterminate result must stay redacted and distinct from rejection"
    );
    Ok(())
}

#[test]
fn credential_verifier_rejects_short_bearer_and_legacy_certificate_hash() -> anyhow::Result<()> {
    ensure!(
        BearerTokenHash::from_token(&"x".repeat(31)).is_err(),
        "bearer material shorter than 32 bytes must be rejected"
    );
    ensure!(BearerTokenHash::from_token(&"x".repeat(32)).is_ok());
    ensure!(BearerTokenHash::from_token(&"x".repeat(1025)).is_err());

    let certificate = ClientCertificateDerSha384::from_der(b"certificate DER");
    ensure!(certificate.0.len() == 96);
    ensure!(ClientCertificateDerSha384::from_hex(certificate.0).is_ok());
    ensure!(
        ClientCertificateDerSha384::from_hex("0".repeat(64)).is_err(),
        "legacy SHA-256 certificate pin must be rejected"
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::integer(7)),
        )
        .await?;
    ensure!(
        out.output.outcome == Outcome::Done(Value::integer(7)),
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
async fn pure_token_only_submission_lookup_is_unproven_without_retention_or_reexecution()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: Arc::new(AtomicBool::new(true)),
            release: Arc::new(tokio::sync::Notify::new()),
        }),
    )?;
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let gateway = GatewayRuntime::new(boot, echo_profile(name)?, requests.clone())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let request_scope = test_request_scope(&gateway, &session, "echo")?;
    let before = requests.usage().await?;
    ensure!(before.records == 0);
    let result = gateway
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::integer(7)).with_options(
                SubmitOptions {
                    expected_request_scope: Some(request_scope.clone()),
                    submission_token: Some("pure-token-only".into()),
                    ..Default::default()
                },
            ),
        )
        .await?;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(7)));
    ensure!(count.load(Ordering::Acquire) == 1);
    ensure!(requests.usage().await? == before);
    ensure!(matches!(
        gateway
            .lookup_request(
                &session,
                GatewayRequestLookup {
                    surface_id: "echo".into(),
                    expected_request_scope: request_scope,
                    retry_epoch: 0,
                    identity: GatewayRequestIdentity::SubmissionToken("pure-token-only".into()),
                },
            )
            .await?,
        GatewayRequestEvidence::Unproven
    ));
    ensure!(requests.usage().await? == before);
    ensure!(count.load(Ordering::Acquire) == 1);
    Ok(())
}

#[tokio::test]
async fn cancel_requires_owner_and_trace_root() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://slow/echo",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = Arc::new(GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::string("work".into())).with_options(
                    SubmitOptions {
                        expected_request_scope: Some(crate::tests::test_request_scope(
                            &gw, &session, "slow",
                        )?),
                        idempotency_key: Some("slow-cancel".into()),
                        ..SubmitOptions::default()
                    },
                ),
            )
            .await
            .map_err(anyhow::Error::from)
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
        boot.kernel().processes().status(entry.request_process) == Some(ProcessStatus::Cancelled),
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
async fn cancel_retains_admission_and_budget_until_request_owner_drops() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let slow = boot.register_effect(
        "effect://cancel/slow",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let fast = boot.register_effect(
        "effect://cancel/fast",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
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
    let gw = Arc::new(GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::string("work".into())).with_options(
                    SubmitOptions {
                        expected_request_scope: Some(crate::tests::test_request_scope(
                            &gw, &session, "slow",
                        )?),
                        idempotency_key: Some("cancel-slow-once".into()),
                        ..SubmitOptions::default()
                    },
                ),
            )
            .await
            .map_err(anyhow::Error::from)
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
                GatewaySubmission::direct_input("fast", Value::string("before".into()))
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
    {
        let requests = gw.requests.inner.lock();
        ensure!(
            requests.global_running == 1,
            "cancel released a resident request"
        );
        ensure!(requests.budget_running.inflight_ops == 1);
    }
    running.abort();
    ensure!(
        running.await.is_err(),
        "aborted submission unexpectedly completed"
    );

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("fast", Value::string("after".into())),
        )
        .await?;
    ensure!(
        out.output.outcome == Outcome::Done(Value::string("after".into())),
        "unexpected output after cancellation: {:?}",
        out.output.outcome
    );

    Ok(())
}

#[tokio::test]
async fn request_runs_as_attenuated_child_not_root() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let root = boot.root();
    let gw = GatewayRuntime::new(
        boot.clone(),
        identity_profile()?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let profile = gw.profile_snapshot();
    let p1 = gw.spawn_gateway_request_process(&profile, &session, &BTreeSet::new())?;
    let p2 = gw.spawn_gateway_request_process(&profile, &session, &BTreeSet::new())?;
    ensure!(p1.id() != root, "request process should not be root");
    ensure!(p2.id() != root, "request process should not be root");
    ensure!(
        p1.id() != p2.id(),
        "each request gets its own attenuated process"
    );
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
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected malformed profile error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_identity_path_rejects_profile() -> anyhow::Result<()> {
    for identity in [
        "state://alice",
        "identity://alice/*",
        "process://alice",
        "path://remote/identity/alice",
    ] {
        let profile = GatewayProfile::new("gateway-test").with_bearer_identity(
            "cred-alice",
            "alice",
            TEST_TOKEN,
            identity,
        )?;
        let err = expect_gateway_error(GatewayRuntime::new(
            Arc::new(Bootstrap::in_memory()),
            profile,
            Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
        ))?;
        ensure!(
            matches!(err, GatewayError::InvalidProfile(_)),
            "unexpected identity path error for {identity}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn malformed_profile_rejects_zero_revision() -> anyhow::Result<()> {
    let profile = identity_profile()?.with_revision(0);
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected zero revision error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_duplicate_names() -> anyhow::Result<()> {
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let duplicate_credential = GatewayProfile::new("gateway-test")
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "identity://alice"))
        .with_credential(GatewayCredential::bearer_token(
            "cred-alice",
            "alice",
            TEST_TOKEN,
        )?)
        .with_credential(GatewayCredential::bearer_token(
            "cred-alice",
            "alice",
            "other-token-for-alice-01-32-bytes",
        )?);
    let err = expect_gateway_error(GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        duplicate_credential,
        requests.clone(),
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
        requests,
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let anchor = restricted_anchor(&boot, "perform://effect/inference/**")?;
    let profile = echo_profile(name)?.with_authority_anchor(anchor);
    let err = expect_gateway_error(GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected authority anchor error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn authority_anchor_expiry_uses_the_kernel_host_clock() -> anyhow::Result<()> {
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicI64;
    use std::time::Instant;
    use xolotl_kernel::host::{
        AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
    };
    use xolotl_types::{ConstraintSet, Expiry, Grant, IdentityRef, ResourceSelector, RightFlags};

    struct Clock(AtomicI64);

    impl HostClock for Clock {
        fn monotonic_now(&self) -> Instant {
            Instant::now()
        }

        fn unix_millis(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }

        fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    let clock = Arc::new(Clock(AtomicI64::new(1_000)));
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(TokioBlockingSpawner::default()),
            ))
            .build(),
    ));
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let anchor =
        boot.spawn_request_process_under_with_request_grants(boot.root(), IdentityRef::ROOT, &[])?;
    boot.kernel().registry().register_grant(Grant {
        id: boot.kernel().registry().next_grant_id(),
        holder: anchor,
        selector: ResourceSelector::parse("perform://effect/echo/**")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::default(),
        expires: Expiry::At(1_500),
    });
    let profile = echo_profile(name)?.with_authority_anchor(anchor);
    let no_scheduler = expect_gateway_error(GatewayRuntime::new(
        boot.clone(),
        profile.clone(),
        requests.clone(),
    ))?;
    ensure!(
        no_scheduler
            .to_string()
            .contains("request deadline maintenance requires host task scheduler"),
        "automatic maintenance silently skipped its scheduler: {no_scheduler:?}"
    );
    let active = GatewayRuntime::new_manual(boot.clone(), profile.clone(), requests.clone())?;
    active
        .maintain_once(&mut GatewayMaintenanceCursor::default())
        .await?;
    clock.0.store(1_501, Ordering::SeqCst);
    ensure!(matches!(
        GatewayRuntime::new_manual(boot, profile, requests),
        Err(GatewayError::InvalidProfile(_))
    ));
    Ok(())
}

#[test]
fn transport_deadline_composes_with_client_deadline_in_one_clock_domain() -> anyhow::Result<()> {
    use xolotl_kernel::host::HostRuntime;

    let host = HostRuntime::tokio();
    let server = host
        .deadline_after(Duration::from_millis(40))
        .context("server deadline overflow")?;
    let options = SubmitOptions {
        deadline_ms: Some(u64::try_from(host.now_millis().saturating_add(1_000))?),
        ..SubmitOptions::default()
    };
    let submission = GatewaySubmission::direct_input("echo", Value::null())
        .with_server_deadline(server)
        .with_options(options.clone());
    ensure!(submission.server_deadline == Some(server));
    ensure!(
        request_deadline(
            &options,
            submission.server_deadline,
            host.now(),
            host.now_millis()
        )? == Some(server)
    );
    let limits = GatewayLimitProfile {
        max_deadline_ms_from_now: 100,
        ..GatewayLimitProfile::default()
    };
    let now = host.now();
    let effective = request_deadline(&options, submission.server_deadline, now, host.now_millis())?;
    validate_request_deadline(effective, now, &limits)?;
    ensure!(request_wall_ms(effective, now)? <= 40);
    let long = request_deadline(&options, None, now, host.now_millis())?;
    ensure!(matches!(
        validate_request_deadline(long, now, &limits),
        Err(GatewayError::Rejected(_))
    ));

    let foreign = HostRuntime::tokio()
        .deadline_after(Duration::from_millis(10))
        .context("foreign deadline overflow")?;
    ensure!(matches!(
        request_deadline(&options, Some(foreign), host.now(), host.now_millis()),
        Err(GatewayError::Rejected(_))
    ));
    Ok(())
}

#[test]
fn manual_gateway_admits_and_expires_requests_without_tokio_runtime() -> anyhow::Result<()> {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicI64, AtomicU64};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Instant;
    use xolotl_kernel::host::{
        AbortTask, BlockingJob, BlockingSpawnError, BlockingSpawner, HostClock, HostRuntime,
        TaskSpawnError, TaskSpawner,
    };

    struct Clock {
        base: Instant,
        monotonic_ms: AtomicU64,
        wall_ms: AtomicI64,
    }

    impl HostClock for Clock {
        fn monotonic_now(&self) -> Instant {
            self.base + Duration::from_millis(self.monotonic_ms.load(Ordering::SeqCst))
        }

        fn unix_millis(&self) -> i64 {
            self.wall_ms.load(Ordering::SeqCst)
        }

        fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    struct PlainThreads;

    impl BlockingSpawner for PlainThreads {
        fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
            std::thread::spawn(job);
            Ok(())
        }
    }

    struct ThreadWake(std::thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        let timeout = Instant::now() + Duration::from_secs(2);
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return Ok(value);
            }
            let remaining = timeout.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("manual host future did not complete");
            }
            std::thread::park_timeout(remaining);
        }
    }

    ensure!(tokio::runtime::Handle::try_current().is_err());
    let clock = Arc::new(Clock {
        base: Instant::now(),
        monotonic_ms: AtomicU64::new(0),
        wall_ms: AtomicI64::new(1_000),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(PlainThreads),
            ))
            .build(),
    ));
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gateway = GatewayRuntime::new_manual(
        boot.clone(),
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let before = gateway.status().maintenance;
    ensure!(before.request_deadlines.state == GatewayMaintenanceState::Manual);
    ensure!(before.object_records.state == GatewayMaintenanceState::Manual);
    ensure!(before.request_deadlines.since_last_success.is_none());
    ensure!(before.object_records.since_last_success.is_none());
    let session = block_on(gateway.authenticate(PresentedCredential::bearer(TEST_TOKEN)))??;
    let mut cursor = GatewayMaintenanceCursor::default();
    let first = block_on(gateway.maintain_once(&mut cursor))??;
    ensure!(first.object_scans_available);
    let after = gateway.status().maintenance;
    ensure!(after.request_deadlines.since_last_success == Some(Duration::ZERO));
    ensure!(after.object_records.since_last_success == Some(Duration::ZERO));
    let submission = input_stream_submission("echo").with_options(SubmitOptions {
        deadline_ms: Some(1_025),
        ..SubmitOptions::default()
    });
    let stream = block_on(gateway.accept_input_stream_submission(&session, submission))??;
    let process = stream.request_process;
    let cleanup_ticket = boot.cleanup_ticket(process)?;
    ensure!(
        boot.kernel().processes().status(process) == Some(ProcessStatus::Running),
        "manual host did not admit the request"
    );
    clock.wall_ms.store(-100_000, Ordering::SeqCst);
    clock.monotonic_ms.store(25, Ordering::SeqCst);
    let report = block_on(gateway.maintain_once(&mut cursor))??;
    ensure!(report.expired_requests == 1);
    ensure!(report.failed_request_cancellations == 0);
    let progress = gateway.status().maintenance;
    ensure!(progress.request_deadlines.since_last_success == Some(Duration::ZERO));
    ensure!(progress.object_records.since_last_success == Some(Duration::ZERO));
    ensure!(
        boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled),
        "manual maintenance did not cancel the expired request"
    );
    drop(stream);
    ensure!(gateway.requests.inner.lock().entries.is_empty());
    let cleanup = block_on(boot.drain_cleanup())?;
    ensure!(cleanup.failures.is_empty(), "{cleanup:?}");
    ensure!(
        cleanup_ticket.is_complete(),
        "manual host left request cleanup pending"
    );
    Ok(())
}

#[tokio::test]
async fn gateway_maintenance_tasks_abort_on_drop_and_partial_start_failure() -> anyhow::Result<()> {
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Instant;
    use xolotl_kernel::host::{
        AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
    };

    struct FrozenClock(Instant);

    impl HostClock for FrozenClock {
        fn monotonic_now(&self) -> Instant {
            self.0
        }

        fn unix_millis(&self) -> i64 {
            xolotl_kernel::host::system_now_millis()
        }

        fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct CountingTasks {
        attempts: AtomicUsize,
        aborts: Arc<AtomicUsize>,
        fail_on: Option<usize>,
    }

    struct CountedAbort {
        handle: tokio::task::AbortHandle,
        aborts: Arc<AtomicUsize>,
    }

    impl AbortTask for CountedAbort {
        fn abort(&self) {
            self.handle.abort();
            self.aborts.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl TaskSpawner for CountingTasks {
        fn spawn(
            &self,
            future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on == Some(attempt) {
                return Err(TaskSpawnError::Unavailable);
            }
            let task = tokio::spawn(future);
            Ok(Arc::new(CountedAbort {
                handle: task.abort_handle(),
                aborts: self.aborts.clone(),
            }))
        }
    }

    for fail_on in [None, Some(2)] {
        let tasks = Arc::new(CountingTasks {
            attempts: AtomicUsize::new(0),
            aborts: Arc::new(AtomicUsize::new(0)),
            fail_on,
        });
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::in_memory()
                .with_host_runtime(HostRuntime::new(
                    Arc::new(FrozenClock(Instant::now())),
                    tasks.clone(),
                    Arc::new(TokioBlockingSpawner::default()),
                ))
                .build(),
        ));
        ensure!(boot.kernel().state().has_query());
        ensure!(boot.kernel().state().has_bounded_write());
        let name = boot.register_effect(
            "effect://echo/say",
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                xolotl_types::Purity::Pure,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(xolotl_kernel::EchoDriver),
        )?;
        let profile = echo_profile(name)?;
        if fail_on.is_some() {
            let error = expect_gateway_error(GatewayRuntime::new(boot, profile, requests.clone()))?;
            ensure!(error.to_string().contains("requires host task scheduler"));
            ensure!(tasks.aborts.load(Ordering::SeqCst) == 1);
        } else {
            let runtime = GatewayRuntime::new(boot, profile, requests.clone())?;
            ensure!(tasks.attempts.load(Ordering::SeqCst) == 2);
            drop(runtime);
            ensure!(tasks.aborts.load(Ordering::SeqCst) == 2);
        }
    }
    Ok(())
}

#[test]
fn gateway_maintenance_status_tracks_lost_tasks_and_manual_ownership() -> anyhow::Result<()> {
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    use parking_lot::Mutex;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Instant;
    use xolotl_kernel::host::{
        AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
    };
    use xolotl_state::Backend;

    type HeldFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    struct FrozenClock {
        base: Instant,
        millis: AtomicUsize,
    }

    impl FrozenClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                millis: AtomicUsize::new(0),
            }
        }

        fn advance_to(&self, millis: usize) {
            self.millis.store(millis, Ordering::SeqCst);
        }
    }

    impl HostClock for FrozenClock {
        fn monotonic_now(&self) -> Instant {
            self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst) as u64)
        }

        fn unix_millis(&self) -> i64 {
            xolotl_kernel::host::system_now_millis()
        }

        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::poll_fn(move |_| {
                if self.monotonic_now() >= deadline {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            }))
        }
    }

    #[derive(Default)]
    struct HeldTasks {
        slots: Arc<Mutex<Vec<Option<HeldFuture>>>>,
    }

    impl HeldTasks {
        fn len(&self) -> usize {
            self.slots.lock().len()
        }

        fn poll_once(&self, index: usize) -> anyhow::Result<()> {
            let mut slots = self.slots.lock();
            let task = slots
                .get_mut(index)
                .and_then(Option::as_mut)
                .context("accepted maintenance task missing")?;
            ensure!(matches!(
                task.as_mut()
                    .poll(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                std::task::Poll::Pending
            ));
            Ok(())
        }

        fn stop(&self, index: usize) -> bool {
            let task = self.slots.lock().get_mut(index).and_then(Option::take);
            let stopped = task.is_some();
            drop(task);
            stopped
        }
    }

    struct HeldTaskHandle {
        slots: Arc<Mutex<Vec<Option<HeldFuture>>>>,
        index: usize,
    }

    impl AbortTask for HeldTaskHandle {
        fn abort(&self) {
            HeldTasks {
                slots: Arc::clone(&self.slots),
            }
            .stop(self.index);
        }
    }

    impl TaskSpawner for HeldTasks {
        fn spawn(&self, future: HeldFuture) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            let mut slots = self.slots.lock();
            let index = slots.len();
            slots.push(Some(future));
            Ok(Arc::new(HeldTaskHandle {
                slots: Arc::clone(&self.slots),
                index,
            }))
        }
    }

    let tasks = Arc::new(HeldTasks::default());
    let clock = Arc::new(FrozenClock::new());
    let runtime = HostRuntime::new(
        clock.clone(),
        tasks.clone(),
        Arc::new(TokioBlockingSpawner::default()),
    );
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    let gateway = GatewayRuntime::new(Arc::clone(&boot), identity_profile()?, requests.clone())?;
    ensure!(tasks.len() == 2);
    let initial = gateway.status().maintenance;
    ensure!(initial.request_deadlines.state == GatewayMaintenanceState::Active);
    ensure!(initial.object_records.state == GatewayMaintenanceState::Active);
    ensure!(initial.request_deadlines.since_last_success.is_none());
    ensure!(initial.object_records.since_last_success.is_none());
    tasks.poll_once(0)?;
    clock.advance_to(50);
    tasks.poll_once(0)?;
    let progressed = gateway.status().maintenance;
    ensure!(progressed.request_deadlines.since_last_success == Some(Duration::ZERO));
    ensure!(progressed.request_deadlines.active_attempts == 0);
    ensure!(progressed.object_records.since_last_success.is_none());
    clock.advance_to(1_050);
    let frozen = gateway.status().maintenance;
    ensure!(frozen.request_deadlines.state == GatewayMaintenanceState::Overdue);
    ensure!(frozen.request_deadlines.since_last_success == Some(Duration::from_secs(1)));
    ensure!(frozen.object_records.state == GatewayMaintenanceState::Active);
    clock.advance_to(5_000);
    tasks.poll_once(1)?;
    let object_progress = gateway.status().maintenance.object_records;
    ensure!(object_progress.since_last_success == Some(Duration::ZERO));
    ensure!(object_progress.active_attempts == 0);
    clock.advance_to(25_000);
    ensure!(gateway.status().maintenance.object_records.state == GatewayMaintenanceState::Overdue);
    ensure!(tasks.stop(0), "request maintenance task missing");
    ensure!(
        gateway.status().maintenance.request_deadlines.state == GatewayMaintenanceState::Stopped
    );
    ensure!(gateway.status().readiness == GatewayReadiness::Ready);
    ensure!(tasks.stop(1), "object maintenance task missing");
    let stopped = gateway.status().maintenance;
    ensure!(stopped.request_deadlines.state == GatewayMaintenanceState::Stopped);
    ensure!(stopped.object_records.state == GatewayMaintenanceState::Stopped);
    let manual = GatewayRuntime::new_manual(boot, identity_profile()?, requests.clone())?;
    let manual = manual.status().maintenance;
    ensure!(manual.request_deadlines.state == GatewayMaintenanceState::Manual);
    ensure!(manual.object_records.state == GatewayMaintenanceState::Manual);

    let tasks = Arc::new(HeldTasks::default());
    let runtime = HostRuntime::new(
        Arc::new(FrozenClock::new()),
        tasks.clone(),
        Arc::new(TokioBlockingSpawner::default()),
    );
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(Backend::new())
            .with_host_runtime(runtime)
            .build(),
    ));
    let gateway = GatewayRuntime::new(Arc::clone(&boot), identity_profile()?, requests.clone())?;
    ensure!(tasks.len() == 1);
    let unavailable = gateway.status().maintenance;
    ensure!(unavailable.request_deadlines.state == GatewayMaintenanceState::Active);
    ensure!(unavailable.object_records.state == GatewayMaintenanceState::Unavailable);
    let manual = GatewayRuntime::new_manual(boot, identity_profile()?, requests)?;
    ensure!(
        manual.status().maintenance.object_records.state == GatewayMaintenanceState::Unavailable
    );
    Ok(())
}

#[tokio::test]
async fn manual_maintenance_reports_failed_object_pass_and_recovery() -> anyhow::Result<()> {
    use std::{future::Future, pin::Pin};
    use xolotl_state::{
        Backend, InMemoryBackend, StateError, StateFailure, StatePage, StateQuery, StateResult,
        StateScan,
    };

    struct FlakyQuery {
        mode: AtomicUsize,
        queries: AtomicUsize,
    }

    impl StateQuery for FlakyQuery {
        type Query<'a> = Pin<Box<dyn Future<Output = StateResult<StatePage>> + Send + 'a>>;

        fn query<'a>(&'a self, _query: &'a StateScan) -> Self::Query<'a> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            let mode = self.mode.load(Ordering::SeqCst);
            Box::pin(async move {
                match mode {
                    0 => Err(StateFailure::new(
                        StateError::Backend("maintenance query failed".into()),
                        TaintSet::pristine(),
                    )),
                    1 => Ok(StatePage::empty()),
                    _ => std::future::pending().await,
                }
            })
        }
    }

    let query = Arc::new(FlakyQuery {
        mode: AtomicUsize::new(0),
        queries: AtomicUsize::new(0),
    });
    let state = Backend::new()
        .with_query(query.clone())
        .with_bounded_write(Arc::new(InMemoryBackend::new()));
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(state).build(),
    ));
    let gateway = GatewayRuntime::new_manual(
        boot,
        identity_profile()?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let mut cursor = GatewayMaintenanceCursor::default();
    let failure = gateway
        .maintain_once(&mut cursor)
        .await
        .err()
        .context("query should fail")?;
    ensure!(failure.to_string().contains("maintenance query failed"));
    ensure!(query.queries.load(Ordering::SeqCst) == 2);
    let failed = gateway.status().maintenance;
    ensure!(failed.request_deadlines.since_last_success.is_some());
    ensure!(failed.object_records.state == GatewayMaintenanceState::Manual);
    ensure!(failed.object_records.since_last_attempt.is_some());
    ensure!(failed.object_records.since_last_success.is_none());
    ensure!(failed.object_records.consecutive_failures == 1);
    ensure!(failed.object_records.active_attempts == 0);

    query.mode.store(1, Ordering::SeqCst);
    let report = gateway.maintain_once(&mut cursor).await?;
    ensure!(report.object_scans_available);
    ensure!(query.queries.load(Ordering::SeqCst) == 4);
    let recovered = gateway.status().maintenance;
    ensure!(recovered.object_records.since_last_success.is_some());
    ensure!(recovered.object_records.consecutive_failures == 0);

    query.mode.store(2, Ordering::SeqCst);
    let mut second_cursor = GatewayMaintenanceCursor::default();
    let mut first = Box::pin(gateway.maintain_once(&mut cursor));
    ensure!(
        tokio::time::timeout(Duration::from_millis(10), &mut first)
            .await
            .is_err()
    );
    let pending = gateway.status().maintenance;
    ensure!(pending.object_records.active_attempts == 1);
    ensure!(pending.object_records.consecutive_failures == 0);
    query.mode.store(1, Ordering::SeqCst);
    gateway.maintain_once(&mut second_cursor).await?;
    let overlapping = gateway.status().maintenance;
    ensure!(overlapping.object_records.active_attempts == 1);
    ensure!(overlapping.object_records.consecutive_failures == 0);
    ensure!(overlapping.object_records.since_last_success.is_some());
    drop(first);
    let cancelled = gateway.status().maintenance;
    ensure!(cancelled.object_records.active_attempts == 0);
    ensure!(cancelled.object_records.consecutive_failures == 1);

    gateway.maintain_once(&mut cursor).await?;
    ensure!(
        gateway
            .status()
            .maintenance
            .object_records
            .consecutive_failures
            == 0
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_surface_exceeding_principal_ceiling() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/inference/**"],
        ));
    let err = expect_gateway_error(GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    ))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected principal ceiling error: {err:?}"
    );
    Ok(())
}

#[test]
fn malformed_profile_rejects_invalid_surface_schemas() -> anyhow::Result<()> {
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(
            GatewaySurface::effect_invoke("echo", name)
                .with_schema(Some(Value::from("not-a-schema-object")), None),
        ),
    );
    let err = expect_gateway_error(GatewayRuntime::new(boot, profile, requests.clone()))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected input schema error: {err:?}"
    );

    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(
            GatewaySurface::effect_invoke("echo", name)
                .with_schema(None, Some(Value::from("not-a-schema-object"))),
        ),
    );
    let err = expect_gateway_error(GatewayRuntime::new(boot, profile, requests))?;
    ensure!(
        matches!(err, GatewayError::InvalidProfile(_)),
        "unexpected output schema error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn submit_uses_restricted_authority_anchor_when_configured() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let anchor = restricted_anchor(&boot, "perform://effect/echo/**")?;
    let profile = echo_profile(name.clone())?.with_authority_anchor(anchor);
    let gw = Arc::new(GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let mut running = Box::pin(gw.submit(
        &session,
        GatewaySubmission::direct_input("echo", Value::string("ok".into())),
    ));
    // Admission and Fact I/O may suspend before the driver starts. Keep
    // driving the submission until the driver is actually held at its gate.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while count.load(Ordering::Acquire) == 0 {
            tokio::select! {
                result = &mut running => bail!("submission finished before driver entry: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("driver did not start before timeout")??;
    ensure!(count.load(Ordering::Acquire) == 1);

    let children = boot.kernel().processes().children_of(anchor);
    ensure!(
        children.len() == 1,
        "unexpected child count: {}",
        children.len()
    );
    ensure!(
        boot.kernel().registry().grants_of(children[0]).is_empty(),
        "child should not retain root grants"
    );
    let grants = boot.kernel().processes().attached_grants(children[0]);
    ensure!(
        grants.len() == 1,
        "running child should have one attached grant"
    );
    ensure!(grants[0].holder == children[0]);
    ensure!(
        grants[0].selector == xolotl_types::ResourceSelector::parse("perform://effect/echo/say")?
    );
    released.store(true, Ordering::Release);
    release.notify_waiters();
    let result = running.await?;
    ensure!(
        result.output.outcome == Outcome::Done(Value::string("ok".into())),
        "unexpected restricted authority output: {result:?}"
    );
    ensure!(
        boot.kernel()
            .processes()
            .attached_grants(children[0])
            .is_empty(),
        "finished child should release attached grants"
    );
    Ok(())
}

#[tokio::test]
async fn profile_replace_rejects_old_session_and_keeps_bad_reload_closed() -> anyhow::Result<()> {
    const NEW_TOKEN: &str = "test-token-for-bob-000002-32-bytes";
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot.clone(),
        echo_profile(name.clone())?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let old_session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let new_profile = GatewayProfile::new("gateway-test")
        .with_revision(2)
        .with_bearer_identity("cred-bob", "bob", NEW_TOKEN, "identity://bob")?
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
                GatewaySubmission::direct_input("echo", Value::integer(1))
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
        new_session.identity_path == "identity://bob",
        "unexpected new identity path: {}",
        new_session.identity_path
    );

    let bad_profile = GatewayProfile::new("gateway-test")
        .with_revision(3)
        .with_bearer_identity(
            "cred-eve",
            "eve",
            "test-token-for-eve-000003-32-bytes",
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
    let gw = GatewayRuntime::new(
        boot.clone(),
        identity_profile()?.with_revision(2),
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let unused = Path::parse("identity://unused-stale-profile")?;
    let stale = GatewayProfile::new("gateway-test")
        .with_revision(2)
        .with_bearer_identity(
            "cred-stale",
            "stale",
            "test-token-stale-000002-32-bytes",
            unused.to_string(),
        )?;
    ensure!(
        matches!(
            gw.replace_profile(stale),
            Err(GatewayError::InvalidProfile(_))
        ),
        "same revision should be rejected before identity registration"
    );
    ensure!(boot.kernel().identities().lookup(&unused)?.is_none());
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
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let boot = Arc::new(Bootstrap::in_memory());
    let disabled_credential = GatewayProfile::new("gateway-test")
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "identity://alice"))
        .with_credential(
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?.with_enabled(false),
        );
    let gw = GatewayRuntime::new(boot.clone(), disabled_credential, requests.clone())?;
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
            GatewayIdentityMapping::new("alice", "identity://alice").with_enabled(false),
        )
        .with_credential(GatewayCredential::bearer_token(
            "cred-alice",
            "alice",
            TEST_TOKEN,
        )?);
    let gw = GatewayRuntime::new(boot, disabled_principal, requests)?;
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
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let boot = Arc::new(Bootstrap::in_memory());
    let revoked = identity_profile()?.with_credential_revocation_floor(1);
    let gw = GatewayRuntime::new(boot.clone(), revoked, requests.clone())?;
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
        .with_identity_mapping(GatewayIdentityMapping::new("alice", "identity://alice"))
        .with_credential(
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)?.with_generation(2),
        );
    let gw = GatewayRuntime::new(boot, rotated, requests)?;
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name.clone())?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let old_session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let bumped = GatewayProfile::new("gateway-test")
        .with_revision(2)
        .with_identity_mapping(
            GatewayIdentityMapping::new("alice", "identity://alice").with_generation(2),
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
                GatewaySubmission::direct_input("echo", Value::integer(1))
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
            GatewaySubmission::direct_input("echo", Value::integer(2))
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::string("direct text".into())),
        )
        .await?;

    ensure!(
        out.output.outcome == Outcome::Done(Value::string("direct text".into())),
        "unexpected direct input output: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn surface_input_schema_validates_direct_input() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(identity_profile()?.with_surface(
        GatewaySurface::effect_invoke("echo", name).with_schema(Some(text_object_schema()), None),
    ));
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let valid = Value::map(BTreeMap::from([(
        "text".into(),
        Value::string("schema-ok".into()),
    )]));

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", valid.clone()),
        )
        .await?;
    ensure!(
        out.output.outcome == Outcome::Done(valid),
        "unexpected valid schema output: {out:?}"
    );

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::map(BTreeMap::new()))
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission =
        GatewaySubmission::direct_input("charge", Value::integer(42)).with_options(SubmitOptions {
            expected_request_scope: Some(crate::tests::test_request_scope(
                &gw, &session, "charge",
            )?),
            idempotency_key: Some("charge-output-schema".into()),
            ..SubmitOptions::default()
        });

    let first = gw.submit(&session, submission.clone()).await?;
    ensure!(
        matches!(
        first.output.outcome,
        Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "gateway_output_schema"
        ),
        "first outcome should be output schema failure: {:?}",
        first.output.outcome
    );
    ensure!(count.load(Ordering::Acquire) == 1, "driver should run once");

    let replay = gw.submit(&session, submission).await?;
    ensure!(
        matches!(
        replay.output.outcome,
        Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "gateway_output_schema"
        ),
        "replay outcome should be output schema failure: {:?}",
        replay.output.outcome
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::SINK_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(
            GatewaySurface::effect_invoke("echo", name)
                .with_schema(Some(schema_type("any")), Some(schema_type("string"))),
        ),
    );
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("echo", Value::integer(42))
        .with_requested_output(OutputMode::SinkOnly);

    let out = gw.submit(&session, submission).await?;
    ensure!(
        out.output.outcome == Outcome::Done(Value::null()),
        "unexpected sink-only output: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_open_registers_request_before_chunks() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
    ensure!(gw.requests.inner.lock().deadlines.is_empty());
    ensure!(gw.sweep_deadline_expired_requests() == 0);
    ensure!(
        gw.requests
            .inner
            .lock()
            .entries
            .contains_key(&accepted.submission_id)
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
async fn recent_cancellations_are_bounded_and_preserve_identity() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = echo_profile(name.clone())?.with_limits(GatewayLimitProfile {
        max_recent_cancellations: 2,
        ..GatewayLimitProfile::default()
    });
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let mut requests = Vec::new();
    for _ in 0..3 {
        let stream = expect_accepted_stream(
            gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
                .await?,
        )?;
        let accepted = stream.accepted().clone();
        let request = GatewayCancelRequest {
            submission_id: accepted.submission_id,
            trace_root: accepted.trace_root,
            reason: None,
        };
        ensure!(gw.cancel(&session, request.clone())?);
        drop(stream);
        requests.push(request);
    }
    {
        let registry = gw.requests.inner.lock();
        ensure!(registry.entries.is_empty());
        ensure!(registry.deadlines.is_empty());
        ensure!(registry.history.len() == 2);
        ensure!(registry.history_expirations.len() == 2);
        ensure!(!registry.history.contains_key(&requests[0].submission_id));
    }
    ensure!(!gw.cancel(&session, requests[0].clone())?);
    ensure!(gw.cancel(&session, requests[1].clone())?);
    ensure!(gw.cancel(&session, requests[2].clone())?);
    let mut wrong_session = session.clone();
    wrong_session.principal.principal_id = "bob".into();
    ensure!(!gw.cancel(&wrong_session, requests[2].clone())?);
    let mut wrong_trace = requests[2].clone();
    wrong_trace.trace_root = "wrong-trace".into();
    ensure!(!gw.cancel(&session, wrong_trace)?);

    gw.replace_profile(echo_profile(name.clone())?.with_revision(2).with_limits(
        GatewayLimitProfile {
            max_recent_cancellations: 1,
            ..GatewayLimitProfile::default()
        },
    ))?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(gw.requests.inner.lock().history.len() == 1);
    ensure!(!gw.cancel(&session, requests[1].clone())?);
    ensure!(gw.cancel(&session, requests[2].clone())?);

    {
        let mut registry = gw.requests.inner.lock();
        let after_retention = gw
            .requests
            .host
            .deadline_after(COMPLETED_REQUEST_RETENTION)
            .context("cancellation retention deadline overflow")?;
        prune_request_history(&mut registry, after_retention, gw.requests.clock_epoch);
        ensure!(registry.history.is_empty());
        ensure!(registry.history_expirations.is_empty());
    }
    ensure!(!gw.cancel(&session, requests[2].clone())?);

    gw.replace_profile(
        echo_profile(name)?
            .with_revision(3)
            .with_limits(GatewayLimitProfile {
                max_recent_cancellations: 0,
                ..GatewayLimitProfile::default()
            }),
    )?;
    ensure!(gw.requests.inner.lock().history.is_empty());
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let stream = expect_accepted_stream(
        gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
            .await?,
    )?;
    let accepted = stream.accepted().clone();
    let request = GatewayCancelRequest {
        submission_id: accepted.submission_id,
        trace_root: accepted.trace_root,
        reason: None,
    };
    ensure!(gw.cancel(&session, request.clone())?);
    drop(stream);
    ensure!(!gw.cancel(&session, request)?);
    Ok(())
}

#[tokio::test]
async fn deadline_sweep_retains_admission_until_stream_owner_drops() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let slow = boot.register_effect(
        "effect://deadline/slow",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let fast = boot.register_effect(
        "effect://deadline/fast",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
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
    let gw = Arc::new(GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
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
    ensure!(gw.requests.inner.lock().deadlines.len() == 1);

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::string("before".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "fast request should be limited before deadline sweep"
    );
    tokio::time::sleep(std::time::Duration::from_millis(35)).await;
    let swept = gw.sweep_deadline_expired_requests();
    ensure!(gw.requests.inner.lock().deadlines.is_empty());
    ensure!(
        swept > 0,
        "deadline sweep should cancel at least one request"
    );
    ensure!(
        boot.kernel().processes().status(stream_process) == Some(ProcessStatus::Cancelled),
        "stream process should be cancelled"
    );
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::string("expired-but-owned".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ),
        "an expired stream still owns its admission until dropped"
    );
    drop(stream);

    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::string("running".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::string("still-limited".into()))
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
        out.output.outcome == Outcome::Done(Value::string("running".into())),
        "unexpected running output: {:?}",
        out.output.outcome
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_open_rejects_client_item_schema_selection() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot.clone(),
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let mut open = input_stream_open_request();
    open.item_schema_id = "client-schema".into();
    let submission = GatewaySubmission::input_stream("echo", open);
    let before = boot.kernel().processes().all_ids().len();

    ensure!(
        matches!(
            gw.accept_input_stream_submission(&session, submission)
                .await,
            Err(GatewayError::Rejected(_))
        ),
        "client item schema selection should be rejected"
    );
    ensure!(
        boot.kernel().processes().all_ids().len() == before,
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let limits = GatewayLimitProfile {
        max_stream_items: 2,
        max_stream_bytes: 32,
        max_stream_inline_item_bytes: 8,
        ..GatewayLimitProfile::default()
    };
    let gw = GatewayRuntime::new(
        boot.clone(),
        echo_profile(name)?.with_limits(limits),
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let before = boot.kernel().processes().all_ids().len();

    ensure!(
        matches!(
            gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
                .await,
            Err(GatewayError::Rejected(_))
        ),
        "profile stream budget overrun should be rejected"
    );
    ensure!(
        boot.kernel().processes().all_ids().len() == before,
        "process count should not change"
    );
    Ok(())
}

#[tokio::test]
async fn input_stream_chunks_use_profile_item_schema() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
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
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
            .validate_chunk_item(&Value::string("chunk".into()))
            .is_ok(),
        "valid stream chunk should pass"
    );
    ensure!(
        matches!(
            stream.validate_chunk_item(&Value::integer(1)),
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let stream = expect_accepted_stream(
        gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
            .await?,
    )?;
    let accepted = stream.accepted().clone();
    let result = gw
        .complete_input_stream_submission(*stream, Value::string("stream text".into()), None)
        .await?;

    ensure!(
        result.accepted == accepted,
        "accepted metadata should be reused"
    );
    ensure!(
        result.output.outcome == Outcome::Done(Value::string("stream text".into())),
        "unexpected stream completion outcome: {:?}",
        result.output.outcome
    );
    Ok(())
}

#[tokio::test]
async fn stream_idempotency_binds_folded_payload_before_replay() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let original_submission = input_stream_submission("echo").with_options(SubmitOptions {
        expected_request_scope: Some(test_request_scope(&gw, &session, "echo")?),
        idempotency_key: Some("same-folded-stream".into()),
        ..SubmitOptions::default()
    });
    let open = || original_submission.clone();
    let first = expect_accepted_stream(gw.accept_input_stream_submission(&session, open()).await?)?;
    let first = gw
        .complete_input_stream_submission(*first, Value::string("one".into()), None)
        .await?;
    let retry = expect_accepted_stream(gw.accept_input_stream_submission(&session, open()).await?)?;
    let retry = gw
        .complete_input_stream_submission(*retry, Value::string("one".into()), None)
        .await?;
    ensure!(retry.origin == CompletionOrigin::CachedOutcome);
    ensure!(retry.accepted == first.accepted && retry.output == first.output);
    let changed =
        expect_accepted_stream(gw.accept_input_stream_submission(&session, open()).await?)?;
    ensure!(
        gw.complete_input_stream_submission(*changed, Value::string("two".into()), None)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn surface_without_principal_binding_is_not_callable() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?.with_surface(GatewaySurface::effect_invoke("echo", name));
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let descriptor = gw.describe(&session)?;
    ensure!(
        descriptor.surfaces.is_empty(),
        "unbound surface should not be visible"
    );
    for (surface_id, expected) in [
        ("echo", "surface echo is not callable by principal"),
        ("missing", "unknown gateway surface missing"),
    ] {
        ensure!(matches!(
            gw.prepare_submission(&session, GatewaySubmissionHead::direct_input(surface_id), None),
            Err(GatewayError::Rejected(message)) if message == expected
        ));
        let requests = gw.requests.inner.lock();
        ensure!(requests.global_running == 0);
        ensure!(requests.principal_running.is_empty());
        ensure!(requests.surface_running.is_empty());
        ensure!(requests.risk_running.is_empty());
        ensure!(requests.entries.is_empty());
        ensure!(requests.budget_running == GatewayBudgetCharge::default());
    }
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::string("denied".into()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "unbound surface should not be callable"
    );
    Ok(())
}

#[tokio::test]
async fn visible_surface_without_submit_grant_cannot_disclose_submission_evidence()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::new(
            "alice",
            ["echo"],
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
        ));
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    ensure!(gw.describe(&session)?.surfaces.len() == 1);
    ensure!(matches!(
        gw.validate_submission_access(&session, "echo"),
        Err(GatewayError::Unauthorized(_))
    ));
    Ok(())
}

#[tokio::test]
async fn submit_deadline_is_clamped_by_server_profile() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
                GatewaySubmission::direct_input("echo", Value::integer(1)).with_options(options)
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let gw = GatewayRuntime::new(
        boot,
        echo_profile(name)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let result = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", Value::integer(1)).with_options(
                SubmitOptions {
                    deadline_ms: Some(u64::MAX),
                    ..SubmitOptions::default()
                },
            ),
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
async fn submit_deadline_preserves_unresolved_effect_for_idempotency_replay() -> anyhow::Result<()>
{
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let name = boot.register_effect(
        "effect://slow/charge",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = Arc::new(GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("charge", Value::string("42".into()))
        .with_options(SubmitOptions {
            expected_request_scope: Some(crate::tests::test_request_scope(
                &gw, &session, "charge",
            )?),
            idempotency_key: Some("charge-deadline-timeout".into()),
            deadline_ms: Some(u64::try_from(now_millis().saturating_add(2_000))?),
            ..SubmitOptions::default()
        });

    let first_attempt = {
        let gw = gw.clone();
        let session = session.clone();
        let submission = submission.clone();
        tokio::spawn(async move { gw.submit(&session, submission).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("slow effect did not start before Gateway deadline")?;
    let process = gw
        .requests
        .inner
        .lock()
        .entries
        .values()
        .next()
        .context("missing running request")?
        .request_process;
    let first = first_attempt.await??;
    ensure!(
        matches!(first.output.outcome, Outcome::Fail(Failure::Timeout)),
        "first outcome should be timeout: {:?}",
        first.output.outcome
    );
    let unresolved = &first.output.unresolved_operations;
    ensure!(
        unresolved.operation_ids.len() == 1 && !unresolved.identities_incomplete,
        "deadline lost the in-flight Kernel operation: {unresolved:?}"
    );
    let pending_id: xolotl_types::OperationId = unresolved.operation_ids[0].parse()?;
    ensure!(
        pending_id.process == process,
        "deadline retained an unrelated operation: {pending_id}"
    );
    ensure!(
        boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled),
        "deadline timeout should cancel request process"
    );
    ensure!(count.load(Ordering::Acquire) == 1, "driver should run once");

    // Retry carries a fresh request deadline; the idempotency identity is
    // bound to the body and key, not the previous attempt's timeout.
    let original_scope = submission.options.expected_request_scope.clone();
    let replay = gw
        .submit(
            &session,
            submission.with_options(SubmitOptions {
                expected_request_scope: original_scope,
                idempotency_key: Some("charge-deadline-timeout".into()),
                deadline_ms: Some(u64::try_from(now_millis().saturating_add(2_000))?),
                ..SubmitOptions::default()
            }),
        )
        .await?;
    ensure!(
        replay.output.outcome == first.output.outcome,
        "replay should return retained outcome"
    );
    ensure!(
        replay.output.unresolved_operations == *unresolved,
        "idempotency replay lost the unresolved Kernel operation"
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("charge", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/payment/charge"],
        ));
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("charge", Value::string("42".into()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "non-idempotent effect should require idempotency key"
    );

    let out = gw
        .submit(
            &session,
            GatewaySubmission::direct_input("charge", Value::string("42".into())).with_options(
                SubmitOptions {
                    expected_request_scope: Some(crate::tests::test_request_scope(
                        &gw, &session, "charge",
                    )?),
                    idempotency_key: Some("charge-42".into()),
                    ..SubmitOptions::default()
                },
            ),
        )
        .await?;
    ensure!(
        out.output.outcome == Outcome::Done(Value::string("42".into())),
        "unexpected idempotent output: {out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn original_request_scope_rejects_missing_and_replaced_identity_before_effects()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let target = boot.register_effect(
        "effect://payment/charge",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: Arc::new(AtomicBool::new(true)),
            release: Arc::new(tokio::sync::Notify::new()),
        }),
    )?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("charge", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/payment/charge"],
        ));
    let store: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let gateway = GatewayRuntime::new(boot.clone(), profile.clone(), store.clone())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let initial_usage = store.usage().await?;
    for options in [
        SubmitOptions {
            idempotency_key: Some("missing-key-scope".into()),
            ..SubmitOptions::default()
        },
        SubmitOptions {
            submission_token: Some("missing-token-scope".into()),
            ..SubmitOptions::default()
        },
        SubmitOptions {
            idempotency_key: Some(String::new()),
            ..SubmitOptions::default()
        },
        SubmitOptions {
            submission_token: Some(String::new()),
            ..SubmitOptions::default()
        },
    ] {
        let request =
            GatewaySubmission::direct_input("charge", Value::integer(42)).with_options(options);
        let error = expect_gateway_error(gateway.submit(&session, request).await)?;
        ensure!(matches!(error, GatewayError::Rejected(_)));
        ensure!(store.usage().await? == initial_usage);
        ensure!(count.load(Ordering::Acquire) == 0);
        ensure!(gateway.requests.inner.lock().entries.is_empty());
    }

    let request =
        GatewaySubmission::direct_input("charge", Value::integer(42)).with_options(SubmitOptions {
            expected_request_scope: Some(test_request_scope(&gateway, &session, "charge")?),
            idempotency_key: Some("original-scope-once".into()),
            ..SubmitOptions::default()
        });
    let first = gateway.submit(&session, request.clone()).await?;
    ensure!(first.output.outcome == Outcome::Done(Value::integer(42)));
    ensure!(count.load(Ordering::Acquire) == 1);
    let committed_usage = store.usage().await?;

    let replica = GatewayRuntime::new(boot.clone(), profile.clone(), store.clone())?;
    let replica_session = replica
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        test_request_scope(&replica, &replica_session, "charge")?
            == request
                .options
                .expected_request_scope
                .clone()
                .context("original scope missing")?
    );
    let replay = replica.submit(&replica_session, request.clone()).await?;
    ensure!(replay.origin == CompletionOrigin::CachedOutcome);
    ensure!(replay.accepted == first.accepted && replay.output == first.output);
    ensure!(store.usage().await? == committed_usage);
    ensure!(count.load(Ordering::Acquire) == 1);

    let replacement_store: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let replacement = GatewayRuntime::new(boot, profile.clone(), replacement_store.clone())?;
    let replacement_session = replacement
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let replacement_usage = replacement_store.usage().await?;
    let error = expect_gateway_error(
        replacement
            .submit(&replacement_session, request.clone())
            .await,
    )?;
    ensure!(matches!(error, GatewayError::Rejected(_)));
    ensure!(replacement_store.usage().await? == replacement_usage);
    ensure!(count.load(Ordering::Acquire) == 1);
    ensure!(replacement.requests.inner.lock().entries.is_empty());

    gateway.replace_profile(profile.with_revision(2))?;
    let current_session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let error = expect_gateway_error(gateway.submit(&current_session, request).await)?;
    ensure!(matches!(error, GatewayError::Rejected(_)));
    ensure!(store.usage().await? == committed_usage);
    ensure!(count.load(Ordering::Acquire) == 1);
    ensure!(gateway.requests.inner.lock().entries.is_empty());
    Ok(())
}

#[tokio::test]
async fn idempotency_key_replays_without_reexecuting_non_idempotent_effect() -> anyhow::Result<()> {
    for revision in [1, u64::MAX] {
        assert_idempotency_key_replays_without_reexecuting_non_idempotent_effect(revision).await?;
    }
    Ok(())
}

async fn assert_idempotency_key_replays_without_reexecuting_non_idempotent_effect(
    revision: GatewayProfileRev,
) -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name = boot.register_effect(
        "effect://payment/charge",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let profile = identity_profile()?
        .with_revision(revision)
        .with_limits(GatewayLimitProfile {
            max_in_flight_requests: 1,
            ..Default::default()
        })
        .with_surface(GatewaySurface::effect_invoke("charge", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/payment/charge"],
        ));
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let replica = GatewayRuntime::new(boot.clone(), profile.clone(), requests.clone())?;
    let replica_session = replica
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let gw = Arc::new(GatewayRuntime::new(boot, profile, requests.clone())?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("charge", Value::string("42".into()))
        .with_options(SubmitOptions {
            expected_request_scope: Some(crate::tests::test_request_scope(
                &gw, &session, "charge",
            )?),
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

    let lookup = GatewayRequestLookup {
        surface_id: "charge".into(),
        expected_request_scope: submission
            .options
            .expected_request_scope
            .clone()
            .context("missing scope")?,
        retry_epoch: 0,
        identity: GatewayRequestIdentity::IdempotencyKey("charge-42-once".into()),
    };
    ensure!(matches!(
        gw.prepare_submission(
            &session,
            GatewaySubmissionHead {
                surface_id: submission.surface_id.clone(),
                requested_output: submission.requested_output,
                options: submission.options.clone(),
                server_deadline: submission.server_deadline,
            },
            None
        ),
        Err(GatewayError::LimitExceeded(_))
    ));
    let before_lookup = requests.usage().await?;
    ensure!(matches!(
        gw.lookup_request(&session, lookup.clone()).await?,
        GatewayRequestEvidence::Reserved
    ));
    ensure!(requests.usage().await? == before_lookup);

    let second = expect_gateway_error(replica.submit(&replica_session, submission.clone()).await)?;
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
    ensure!(first.accepted.profile_rev == revision);
    ensure!(
        first.output.outcome == Outcome::Done(Value::string("42".into())),
        "unexpected first output: {first:?}"
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should not rerun while completing first"
    );

    let usage = requests.usage().await?;
    let GatewayRequestEvidence::Settled(evidence) =
        gw.lookup_request(&session, lookup.clone()).await?
    else {
        bail!("completed request did not provide settled evidence");
    };
    ensure!(evidence.accepted == first.accepted);
    ensure!(evidence.result_class == crate::GatewayRequestResultClass::Done);
    let crate::GatewayRetainedRequestResult::Available(retained) =
        gw.read_retained_request_result(&session, lookup).await?
    else {
        bail!("retained delivery result unavailable");
    };
    ensure!(retained.output == first.output);
    ensure!(retained.origin == xolotl_types::CompletionOrigin::CachedOutcome);
    ensure!(count.load(Ordering::Acquire) == 1);
    ensure!(requests.usage().await? == usage);
    let replay = replica.submit(&replica_session, submission).await?;
    ensure!(
        replay.output.outcome == Outcome::Done(Value::string("42".into())),
        "unexpected replay output: {replay:?}"
    );
    ensure!(
        count.load(Ordering::Acquire) == 1,
        "driver should not rerun replay"
    );
    ensure!(
        replay.accepted == first.accepted,
        "replica changed acceptance identity"
    );
    ensure!(
        replay.output == first.output,
        "replica lost result or provenance"
    );
    ensure!(replay.origin == xolotl_types::CompletionOrigin::CachedOutcome);
    ensure!(
        requests.usage().await? == usage,
        "replay changed storage accounting"
    );
    Ok(())
}

#[tokio::test]
async fn idempotency_key_replays_fail_outcome_variant() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://fail/input",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission =
        GatewaySubmission::direct_input("fail", Value::null()).with_options(SubmitOptions {
            expected_request_scope: Some(crate::tests::test_request_scope(&gw, &session, "fail")?),
            idempotency_key: Some("fail-once".into()),
            ..SubmitOptions::default()
        });

    let first = gw.submit(&session, submission.clone()).await?;
    let replay = gw.submit(&session, submission).await?;

    ensure!(
        first.accepted == replay.accepted,
        "replay changed acceptance"
    );
    ensure!(
        first.output == replay.output,
        "replay changed execution output"
    );
    ensure!(first.origin == CompletionOrigin::CurrentAttempt);
    ensure!(replay.origin == CompletionOrigin::CachedOutcome);
    ensure!(
        matches!(
        replay.output.outcome,
        Outcome::Fail(Failure::InvalidInput { ref reason }) if reason == "bad input"
        ),
        "unexpected replay failure outcome: {:?}",
        replay.output.outcome
    );
    Ok(())
}

#[tokio::test]
async fn idempotency_reservation_is_released_after_admission_rejection() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
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
    let gw = GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let submission = GatewaySubmission::direct_input("echo", Value::string("too-large".into()))
        .with_options(SubmitOptions {
            expected_request_scope: Some(crate::tests::test_request_scope(&gw, &session, "echo")?),
            idempotency_key: Some("reject-and-release".into()),
            ..SubmitOptions::default()
        });
    let before = boot.kernel().processes().all_ids().len();

    let rejected = expect_error(gw.submit(&session, submission.clone()).await)?;
    ensure!(
        matches!(&rejected, GatewayError::Rejected(_)),
        "oversized submission should be rejected"
    );
    let released = gw.idempotency.usage().await?;
    ensure!(
        released == crate::GatewayIdempotencyUsage::default(),
        "admission rejection must remove its idempotency reservation"
    );
    ensure!(
        boot.kernel().processes().all_ids().len() == before,
        "process count should not change"
    );

    let retried = expect_error(gw.submit(&session, submission).await)?;
    ensure!(
        rejected.to_string() == retried.to_string(),
        "retry must reach the same admission check"
    );
    let retried = gw.idempotency.usage().await?;
    ensure!(
        retried == crate::GatewayIdempotencyUsage::default(),
        "retry rejection must remove its idempotency reservation"
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_large_ref_requires_provenance() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let blob = Value::blob(xolotl_types::BlobRef {
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
                GatewaySubmission::direct_input("echo", Value::map(nested))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ),
        "nested large blob ref without provenance should be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn describe_requires_current_session_and_returns_redacted_surface_catalog()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let name = boot.register_effect(
        "effect://echo/say",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?.with_revision(7).with_surface(
            GatewaySurface::effect_invoke("echo", name.clone())
                .with_schema(Some(schema_type("string")), Some(schema_type("string"))),
        ),
    );
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
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
    gw.validate_submission_access(&session, "echo")?;
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
    ensure!(
        matches!(
            gw.validate_submission_access(&stale, "echo"),
            Err(GatewayError::Rejected(_))
        ),
        "stale session must not receive submission evidence"
    );
    Ok(())
}

#[tokio::test]
async fn operation_not_exposed_by_profile_is_rejected() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let gw = GatewayRuntime::new(
        boot,
        identity_profile()?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::null())
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    let profile = bind_alice_to_echo(
        identity_profile()?
            .with_limits(limits)
            .with_surface(GatewaySurface::effect_invoke("echo", name)),
    );
    let gw = GatewayRuntime::new(
        boot.clone(),
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let before = boot.kernel().processes().all_ids().len();
    let submission = GatewaySubmission::direct_input(
        "echo",
        Value::string("this direct input is too large".into()),
    )
    .with_options(SubmitOptions {
        expected_request_scope: Some(crate::tests::test_request_scope(&gw, &session, "echo")?),
        idempotency_key: Some("direct-input-too-large".into()),
        ..SubmitOptions::default()
    });

    let rejected = expect_error(gw.submit(&session, submission.clone()).await)?;
    ensure!(
        matches!(&rejected, GatewayError::Rejected(_)),
        "large literal should be rejected"
    );
    let retried = expect_error(gw.submit(&session, submission).await)?;
    ensure!(
        rejected.to_string() == retried.to_string(),
        "retry must reach the same literal limit"
    );
    ensure!(
        boot.kernel().processes().all_ids().len() == before,
        "process count should not change"
    );
    let released = gw.idempotency.usage().await?;
    ensure!(
        released == crate::GatewayIdempotencyUsage::default(),
        "direct input admission rejection must remove its idempotency reservation"
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = Arc::new(GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("budget", Value::string("one".into())),
            )
            .await
        })
    };
    while count.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }

    let retry = GatewaySubmission::direct_input("budget", Value::string("two".into()));
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
        out.output.outcome == Outcome::Done(Value::string("two".into())),
        "unexpected retry output: {:?}",
        out.output.outcome
    );
    Ok(())
}

#[tokio::test]
async fn gateway_budget_rejects_estimated_cost_before_dispatch() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let name = boot.register_effect_with_cost(
        "effect://budget/costed",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    ensure!(
        matches!(
        gw.submit(
            &session,
            GatewaySubmission::direct_input("budget", Value::string("costed".into()))
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
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
    let gw = Arc::new(GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow", Value::string("running".into())),
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
                GatewaySubmission::direct_input("slow", Value::integer(1))
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
        matches!(completed, Err(GatewayError::Indeterminate(_))),
        "running request must settle but withhold delivery to the stale session: {completed:?}"
    );
    ensure!(
        gw.submit(
            &new_session,
            GatewaySubmission::direct_input("slow", Value::integer(2))
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
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let name_b = boot.register_effect(
        "effect://slow/b",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
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
    let gw = Arc::new(GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?);
    let session = gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;

    let running = {
        let gw = gw.clone();
        let session = session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow-a", Value::string("one".into())),
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
            GatewaySubmission::direct_input("slow-b", Value::string("two".into())),
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
            GatewaySubmission::direct_input("slow-b", Value::string("after".into())),
        )
        .await
        .is_ok(),
        "submission after release should succeed"
    );
    Ok(())
}

#[tokio::test]
async fn fair_admission_enforces_surface_and_risk_limits() -> anyhow::Result<()> {
    let requests: Arc<dyn crate::GatewayIdempotencyStore> =
        Arc::new(crate::MemoryGatewayIdempotencyStore::default());
    let boot = Arc::new(Bootstrap::in_memory());
    let count = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let name_a = boot.register_effect(
        "effect://fair/a",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BlockingCountingDriver {
            count: count.clone(),
            released: released.clone(),
            release: release.clone(),
        }),
    )?;
    let name_b = boot.register_effect(
        "effect://fair/b",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
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
    let surface_gw = Arc::new(GatewayRuntime::new(
        boot.clone(),
        surface_profile,
        requests.clone(),
    )?);
    let surface_session = surface_gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = surface_gw.clone();
        let session = surface_session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fair-a", Value::string("one".into())),
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
                GatewaySubmission::direct_input("fair-a", Value::string("two".into())),
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
    let risk_gw = Arc::new(GatewayRuntime::new(boot, risk_profile, requests)?);
    let risk_session = risk_gw
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let running = {
        let gw = risk_gw.clone();
        let session = risk_session.clone();
        tokio::spawn(async move {
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fair-a", Value::string("one".into())),
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
                GatewaySubmission::direct_input("fair-b", Value::string("two".into())),
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
                GatewaySubmission::direct_input("fair-b", Value::string("after".into())),
            )
            .await
            .is_ok(),
        "submission after risk limit release should succeed"
    );
    Ok(())
}
