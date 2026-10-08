//! Exercise public route composition through Axum, including extractors and limits.

#[path = "support/console_config.rs"]
mod console_config;
#[path = "support/sealer.rs"]
mod sealer;

#[path = "http/authentication.rs"]
mod authentication;

#[path = "http/provider_usage.rs"]
mod provider_usage;

#[path = "http/enrollment_input.rs"]
mod enrollment_input;

#[path = "http/verified_peer.rs"]
mod verified_peer;

#[cfg(target_os = "linux")]
#[path = "http/non_tcp.rs"]
mod non_tcp;

use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
    response::Response,
};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use xolotl_console::{
    AuthenticationResponse, ConsoleConfig, ConsoleErrorCode, ConsoleFailure, ConsoleState,
    LoginResponse, RootProvisioning, bootstrap_root_account,
    http::{self, HttpApi, HttpConfig, HttpEndpoint, HttpGroup, HttpState, router},
    mfa::{MfaEnrollmentProgress, MfaResponse},
};
use xolotl_console_protocol::pb;
use xolotl_kernel::Bootstrap;
use xolotl_standard::{StandardConfig, install_standard};

const TEST_RUNTIME_INPUT_NODES: usize = 1_024;

async fn fixture() -> anyhow::Result<Arc<HttpState>> {
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(&boot, &StandardConfig::default())?;
    boot.kernel()
        .state()
        .write_set(
            &xolotl_types::Path::parse("state://example/ready")?,
            xolotl_types::Value::bytes(vec![11, 255]),
        )
        .await?;
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some("Ar7!cVN23#pxQe$Lr9".into()),
            additional_grants: vec![
                "perform://effect/example/**".into(),
                "act-as://identity/example/worker".into(),
            ],
            ..Default::default()
        },
    )
    .await?;
    boot.register_effect(
        "effect://example/echo",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_types::OutputModeSet::UNARY,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    boot.register_subtree_resource_at(
        "effect://example/custom",
        "perform://effect/example/custom",
        xolotl_types::InterfaceFamily::Callable,
        &[xolotl_kernel::MethodSpec::new(
            "read",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_types::OutputModeSet::UNARY,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    Ok(HttpState::new(
        ConsoleState::with_config(
            boot,
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    xolotl_console::session_store::MemoryConsoleSessionStore::new(
                        xolotl_console::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                auth: crate::console_config::auth(),
                modules: public_modules()?,
                runtime: xolotl_console::ConsoleRuntimeConfig {
                    enabled: true,
                    max_input_nodes: TEST_RUNTIME_INPUT_NODES,
                    executions: xolotl_console::ConsoleExecutionConfig {
                        enabled: true,
                        ..Default::default()
                    },
                    capabilities: vec![
                        "perform://effect/example/**".into(),
                        "act-as://identity/example/worker".into(),
                        "subscribe://state/example/**".into(),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        )?,
        HttpConfig::default(),
    ))
}

fn public_modules() -> anyhow::Result<xolotl_console::runtime::ConsoleModules> {
    use xolotl_console::runtime::{ConsoleModule, ConsoleModules, ModuleManifest, ModuleOperation};
    use xolotl_graph::{
        OperationTemplate, StepRef,
        portable::{Expression, Program},
    };
    use xolotl_types::{OutputMode, Path, ResourceName};
    let operation = ModuleOperation {
        target: ResourceName::new(Path::parse("effect://example/echo")?),
        method: "invoke".into(),
        output: OutputMode::Unary,
    };
    let target = operation.target.clone();
    let inner = ConsoleModule::new(
        ModuleManifest {
            identities: Vec::new(),
            signals: Vec::new(),
            name: "example.inner".into(),
            revision: [1; 32],
            operations: vec![operation],
            modules: Vec::new(),
        },
        move |_input, _argument| {
            Ok(Program::new(Expression::Invoke {
                operation: OperationTemplate {
                    target: target.clone(),
                    method: "invoke".into(),
                    method_id: None,
                    output: OutputMode::Unary,
                    literal_input: None,
                },
            }))
        },
    );
    let identity = Path::parse("identity://example/worker")?;
    let outer = ConsoleModule::new(
        ModuleManifest {
            identities: vec![identity.clone()],
            signals: Vec::new(),
            name: "example.echo".into(),
            revision: [2; 32],
            operations: Vec::new(),
            modules: vec!["example.inner".into()],
        },
        move |_input, _argument| {
            Ok(Program::new(Expression::Acting {
                identity: identity.clone(),
                body: Box::new(Expression::Module {
                    module: StepRef::new("example.inner"),
                }),
            }))
        },
    );
    let modules =
        ConsoleModules::compose([ConsoleModules::new([outer])?, ConsoleModules::new([inner])?])?;
    ensure!(modules.manifests().count() == 2);
    Ok(modules)
}

async fn send(
    app: &Router,
    path: &str,
    method: &str,
    media: &str,
    body: Vec<u8>,
    token: Option<&str>,
) -> anyhow::Result<Response> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "console.local")
        .header(header::ORIGIN, "https://console.local")
        .header(header::CONTENT_TYPE, media)
        .extension(ConnectInfo("127.0.0.1:12345".parse::<SocketAddr>()?));
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    Ok(app.clone().oneshot(request.body(Body::from(body))?).await?)
}

async fn json_request(
    app: &Router,
    path: &str,
    method: &str,
    body: Value,
    token: Option<&str>,
) -> anyhow::Result<Response> {
    send(
        app,
        path,
        method,
        "application/json",
        serde_json::to_vec(&body)?,
        token,
    )
    .await
}

async fn decode<T: serde::de::DeserializeOwned>(
    response: Response,
    expected: StatusCode,
) -> anyhow::Result<T> {
    ensure!(
        response.status() == expected,
        "unexpected HTTP status {}",
        response.status()
    );
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    ensure!(response.headers()[header::CONTENT_TYPE] == "application/json");
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?,
    )?)
}

fn totp(setup: &Value) -> anyhow::Result<String> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(setup["secret"].as_str().context("secret")?.as_bytes())?;
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[hash.len() - 1] & 15);
    let value = u32::from_be_bytes(hash[offset..offset + 4].try_into()?) & 0x7fffffff;
    Ok(format!("{:06}", value % 1_000_000))
}

#[tokio::test]
async fn default_and_custom_mounts_support_login_enrollment_refresh_and_calls() -> anyhow::Result<()>
{
    for prefix in [http::API_BASE_PATH, "/internal/admin"] {
        let state = fixture().await?;
        let service = state.service();
        let app = Router::new().nest(prefix, router(state));
        let path = |suffix: &str| format!("{prefix}{suffix}");
        let methods: Vec<Value> = decode(
            json_request(
                &app,
                &path("/auth/factor-providers"),
                "GET",
                Value::Null,
                None,
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        ensure!(methods.iter().any(|m| {
            m["descriptor"]["provider_id"] == "totp"
                && m["usage"] == json!({"allow_enrollment":true,"allow_authentication":true})
        }));
        ensure!(methods.iter().all(|m| m.get("factor_id").is_none()));
        ensure!(
            json_request(&app, &path("/auth/factors"), "GET", Value::Null, None)
                .await?
                .status()
                == StatusCode::NOT_FOUND
        );
        let login = decode::<AuthenticationResponse>(
            json_request(
                &app,
                &path("/auth/password/login"),
                "POST",
                json!({"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}),
                None,
            )
            .await?,
            StatusCode::OK,
        )
        .await?
        .into_session()
        .ok()
        .context("authenticated session")?;
        let enrollment: MfaResponse = decode(
            json_request(
                &app,
                &path("/credentials/factors"),
                "POST",
                json!({"operation":"begin","provider_id":"totp","label":"HTTP authenticator"}),
                Some(&login.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        let MfaResponse::Enrollment {
            challenge_id,
            factor_id,
            step: MfaEnrollmentProgress::Challenge { setup, .. },
            ..
        } = enrollment
        else {
            anyhow::bail!("enrollment")
        };
        let updated: MfaResponse = decode(json_request(&app, &path("/credentials/factors"), "POST", json!({"operation":"continue","challenge_id":challenge_id,"input":{"kind":"response","response":{"code":totp(&setup)?}}}), Some(&login.token)).await?, StatusCode::OK).await?;
        let MfaResponse::Updated {
            session,
            recovery_codes,
        } = updated
        else {
            anyhow::bail!("confirmation")
        };
        ensure!(
            session.authentication == login.authentication
                && session.authentication.mfa_level() == 1
        );
        let code = recovery_codes
            .and_then(|mut codes| codes.pop())
            .context("recovery proof")?;
        let session = decode::<AuthenticationResponse>(
            json_request(
                &app,
                &path("/session/step-up"),
                "POST",
                json!({"proof":{"kind":"recovery_code","code":code}}),
                Some(&session.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?
        .into_session()
        .map_err(|_continuation| anyhow::anyhow!("completed step-up"))?;
        ensure!(session.authentication.primary == login.authentication.primary);
        ensure!(session.authentication.mfa_level() == 2);
        let invalid: ConsoleFailure = decode(
            json_request(
                &app,
                &path("/session/refresh"),
                "POST",
                Value::Null,
                Some(&login.token),
            )
            .await?,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        ensure!(invalid.code == ConsoleErrorCode::NotAuthenticated);
        let refreshed: LoginResponse = decode(
            json_request(
                &app,
                &path("/session/refresh"),
                "POST",
                Value::Null,
                Some(&session.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        ensure!(refreshed.sid == session.sid && refreshed.token != session.token);
        // The same session composes with a transport-independent execution stream.
        let mut input = std::collections::BTreeMap::new();
        input.insert(
            "target".into(),
            xolotl_types::Value::string("effect://example/echo".into()),
        );
        input.insert(
            "method".into(),
            xolotl_types::Value::string("invoke".into()),
        );
        input.insert("output".into(), xolotl_types::Value::string("unary".into()));
        input.insert(
            "input".into(),
            xolotl_types::Value::bytes(vec![0, 128, 255]),
        );
        let mut subscription = service
            .subscribe(
                &refreshed.token,
                Some("trusted-peer"),
                xolotl_console::StreamCall {
                    stream: xolotl_console_protocol::STREAM_RUNTIME_OPERATION.into(),
                    input: xolotl_types::Value::map(input),
                    scope: Some("external echo".into()),
                    justification: Some("public host composition".into()),
                    ttl_ms: Some(30_000),
                    ..Default::default()
                },
            )
            .await?;
        for expected in ["started", "finished"] {
            let event =
                tokio::time::timeout(std::time::Duration::from_secs(2), subscription.recv())
                    .await??
                    .context("runtime event")?;
            let xolotl_console::ConsoleEvent::Runtime { event } = event else {
                anyhow::bail!("runtime event")
            };
            let event = event.as_map().context("event envelope")?;
            ensure!(event.get("kind").and_then(xolotl_types::Value::as_str) == Some(expected));
            if expected == "finished" {
                ensure!(event.get("value") == Some(&xolotl_types::Value::bytes(vec![0, 128, 255])));
            }
        }
        ensure!(subscription.recv().await?.is_none());

        // Independently assembled native loaders compose through only public
        // manifests and service APIs; portable bytes retain their exact value.
        let program =
            xolotl_graph::portable::Program::new(xolotl_graph::portable::Expression::Module {
                module: xolotl_graph::StepRef::new("example.echo"),
            });
        let result = service
            .call(
                &refreshed.token,
                Some("trusted-peer"),
                xolotl_console::ActionCall {
                    action: xolotl_console_protocol::ACTION_RUNTIME_PROGRAM_RUN.into(),
                    input: xolotl_types::Value::map(std::collections::BTreeMap::from([
                        (
                            "source".into(),
                            xolotl_types::Value::string(serde_json::to_string(&program)?),
                        ),
                        (
                            "input".into(),
                            xolotl_types::Value::bytes(vec![0, 128, 255]),
                        ),
                    ])),
                    scope: Some("host module composition".into()),
                    justification: Some("external API verification".into()),
                    ttl_ms: Some(30_000),
                    ..Default::default()
                },
            )
            .await?;
        ensure!(
            result
                .output
                .as_ref()
                .and_then(xolotl_types::Value::as_map)
                .and_then(|map| map.get("value"))
                == Some(&xolotl_types::Value::bytes(vec![0, 128, 255]))
        );

        let status: MfaResponse = decode(
            json_request(
                &app,
                &path("/credentials/factors"),
                "GET",
                Value::Null,
                Some(&refreshed.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        let MfaResponse::Status {
            factors,
            max_factors,
            recovery_codes_remaining,
            ..
        } = status
        else {
            anyhow::bail!("factor status");
        };
        ensure!(recovery_codes_remaining == 9 && max_factors >= 1);
        ensure!(factors.len() == 1 && factors[0].factor_id == factor_id);
        ensure!(factors[0].provider_id == "totp" && factors[0].label == "HTTP authenticator");
        let renamed: MfaResponse = decode(
            json_request(
                &app,
                &path("/credentials/factors"),
                "POST",
                json!({"operation":"rename","factor_id":factor_id,"label":"Travel authenticator"}),
                Some(&refreshed.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        ensure!(matches!(renamed, MfaResponse::Renamed { factor }
            if factor.factor_id == factor_id && factor.label == "Travel authenticator"));
        for stale in [
            json!({"operation":"begin","method":"totp"}),
            json!({"operation":"remove","method":"totp"}),
        ] {
            let failure: ConsoleFailure = decode(
                json_request(
                    &app,
                    &path("/credentials/factors"),
                    "POST",
                    stale,
                    Some(&refreshed.token),
                )
                .await?,
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await?;
            ensure!(failure.code == ConsoleErrorCode::BadRequest);
        }
        for (action, has_catalog) in [
            ("protocol.describe", false),
            ("protocol.registry.snapshot", true),
        ] {
            let request = pb::ConsoleFrame {
                frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
                    id: 18,
                    action: action.into(),
                    ..Default::default()
                })),
            }
            .encode_to_vec();
            let response = send(
                &app,
                &path("/calls"),
                "POST",
                "application/protobuf",
                request,
                Some(&refreshed.token),
            )
            .await?;
            ensure!(response.status() == StatusCode::OK);
            ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
            let frame = pb::ConsoleFrame::decode(
                to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?,
            )?;
            let Some(pb::console_frame::Frame::Reply(reply)) = frame.frame else {
                anyhow::bail!("expected discovery reply");
            };
            ensure!(reply.id == 18);
            let output = xolotl_proto::convert::value_from_pb(
                &reply.result.context("result")?.output.context("output")?,
            )?;
            let map = output.as_map().context("discovery map")?;
            ensure!(
                map.get("protocol_version")
                    .and_then(xolotl_types::Value::as_int)
                    == Some(1)
            );
            ensure!(
                map.get("transport_security_mode").is_none()
                    && map.get("unsafe_transport").is_none()
            );
            ensure!(map.get("actions").is_some() == has_catalog);
            ensure!(map.get("streams").is_some() == has_catalog);
        }
        let input = xolotl_types::Value::map(std::collections::BTreeMap::from([
            (
                "target".into(),
                xolotl_types::Value::string("effect://example/custom".into()),
            ),
            ("method".into(), xolotl_types::Value::string("read".into())),
            ("input".into(), xolotl_types::Value::bytes(vec![1, 255])),
        ]));
        let request = pb::ConsoleFrame {
            frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
                id: 19,
                action: "runtime.operation.invoke".into(),
                input: Some(xolotl_proto::convert::value_to_pb(&input)),
                scope: Some("echo data".into()),
                justification: Some("HTTP resource invocation test".into()),
                ttl_ms: Some(30_000),
                ..Default::default()
            })),
        }
        .encode_to_vec();
        let response = send(
            &app,
            &path("/calls"),
            "POST",
            "application/protobuf",
            request,
            Some(&refreshed.token),
        )
        .await?;
        ensure!(response.status() == StatusCode::OK);
        let frame =
            pb::ConsoleFrame::decode(to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
        let Some(pb::console_frame::Frame::Reply(reply)) = frame.frame else {
            anyhow::bail!("runtime reply");
        };
        ensure!(reply.id == 19);
        let output = xolotl_proto::convert::value_from_pb(
            reply
                .result
                .as_ref()
                .and_then(|result| result.output.as_ref())
                .context("runtime output")?,
        )?;
        ensure!(
            output.as_map().and_then(|m| m.get("value"))
                == Some(&xolotl_types::Value::bytes(vec![1, 255]))
        );
        assert_runtime_input_budget(&app, &path("/calls"), &refreshed.token).await?;
        let signal = xolotl_types::Path::parse("state://example/ready")?;
        let source =
            xolotl_graph::portable::Program::new(xolotl_graph::portable::Expression::Acting {
                identity: xolotl_types::Path::parse("identity://example/worker")?,
                body: Box::new(xolotl_graph::portable::Expression::Wait {
                    wait: xolotl_graph::WaitSpec::Signal(signal),
                }),
            });
        let input = xolotl_types::Value::map(std::collections::BTreeMap::from([(
            "source".into(),
            xolotl_types::Value::string(serde_json::to_string(&source)?),
        )]));
        let request = pb::ConsoleFrame {
            frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
                id: 20,
                action: "runtime.program.run".into(),
                input: Some(xolotl_proto::convert::value_to_pb(&input)),
                scope: Some("signal observation".into()),
                justification: Some("HTTP delegated signal test".into()),
                ttl_ms: Some(30_000),
                ..Default::default()
            })),
        }
        .encode_to_vec();
        let response = send(
            &app,
            &path("/calls"),
            "POST",
            "application/protobuf",
            request,
            Some(&refreshed.token),
        )
        .await?;
        ensure!(response.status() == StatusCode::OK);
        let frame =
            pb::ConsoleFrame::decode(to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
        let Some(pb::console_frame::Frame::Reply(reply)) = frame.frame else {
            anyhow::bail!("signal reply")
        };
        ensure!(reply.id == 20);
        let result = reply.result.context("signal result")?;
        ensure!(result.execution.is_some());
        let output =
            xolotl_proto::convert::value_from_pb(&result.output.context("signal output")?)?;
        ensure!(
            output.as_map().and_then(|map| map.get("value"))
                == Some(&xolotl_types::Value::bytes(vec![11, 255]))
        );
        independent_submission(&app, &service, &path("/calls"), &refreshed.token).await?;
        let credentials: xolotl_console::credentials::CredentialResponse = decode(
            json_request(
                &app,
                &path("/credentials"),
                "GET",
                Value::Null,
                Some(&refreshed.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        ensure!(matches!(
            credentials,
            xolotl_console::credentials::CredentialResponse::Current {
                password_enabled: true,
                ..
            }
        ));
        let changed: xolotl_console::credentials::CredentialResponse = decode(
            json_request(
                &app,
                &path("/credentials"),
                "POST",
                json!({"operation":{"action":"set_password","password":"sQ4!Xe8#Vt2$Lu6Np9Jr"}}),
                Some(&refreshed.token),
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        ensure!(matches!(
            changed,
            xolotl_console::credentials::CredentialResponse::Updated {
                sessions_invalidated: true,
                session: Some(ref session),
            } if session.authentication.mfa_level() == 2
        ));
        let invalidated: ConsoleFailure = decode(
            json_request(
                &app,
                &path("/session/refresh"),
                "POST",
                Value::Null,
                Some(&refreshed.token),
            )
            .await?,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        ensure!(invalidated.code == ConsoleErrorCode::NotAuthenticated);
        ensure!(
            json_request(&app, &path("/rpc"), "POST", json!({}), None)
                .await?
                .status()
                == StatusCode::NOT_FOUND
        );
        for old in ["/api/auth/login", "/api/console/call", "/ws"] {
            ensure!(
                json_request(&app, old, "POST", json!({}), None)
                    .await?
                    .status()
                    == StatusCode::NOT_FOUND
            );
        }
        ensure!(
            json_request(&app, &path("/health"), "GET", Value::Null, None)
                .await?
                .status()
                == StatusCode::OK
        );
    }
    Ok(())
}

async fn assert_runtime_input_budget(app: &Router, path: &str, token: &str) -> anyhow::Result<()> {
    // A flat list has one more logical node than the configured ceiling while
    // avoiding protobuf nesting limits and staying below the HTTP frame limit.
    let node_limit = TEST_RUNTIME_INPUT_NODES;
    let input = xolotl_types::Value::map(std::collections::BTreeMap::from([
        (
            "target".into(),
            xolotl_types::Value::string("effect://example/custom".into()),
        ),
        ("method".into(), xolotl_types::Value::string("read".into())),
        (
            "input".into(),
            xolotl_types::Value::list(vec![xolotl_types::Value::null(); node_limit]),
        ),
    ]));
    let body = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
            id: 21,
            action: "runtime.operation.invoke".into(),
            input: Some(xolotl_proto::convert::value_to_pb(&input)),
            scope: Some("input budget".into()),
            justification: Some("HTTP runtime admission test".into()),
            ttl_ms: Some(30_000),
            ..Default::default()
        })),
    }
    .encode_to_vec();
    ensure!(body.len() < http::MAX_CALL_BYTES);
    let response = send(app, path, "POST", "application/protobuf", body, Some(token)).await?;
    ensure!(response.status() == StatusCode::BAD_REQUEST);
    ensure!(response.headers()[header::CONTENT_TYPE] == "application/protobuf");
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let frame =
        pb::ConsoleFrame::decode(to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
    let Some(pb::console_frame::Frame::Error(error)) = frame.frame else {
        anyhow::bail!("expected runtime input admission failure");
    };
    ensure!(error.request_id == Some(21));
    ensure!(error.code == pb::ConsoleErrorCode::ValidationFailed as i32);
    ensure!(error.message == "runtime input exceeds host logical value limits");
    ensure!(error.execution.is_none());
    Ok(())
}

async fn independent_submission(
    app: &Router,
    service: &xolotl_console::ConsoleService,
    path: &str,
    token: &str,
) -> anyhow::Result<()> {
    use xolotl_types::Value as RuntimeValue;
    let input = RuntimeValue::map(std::collections::BTreeMap::from([
        (
            "target".into(),
            RuntimeValue::string("effect://example/echo".into()),
        ),
        ("method".into(), RuntimeValue::string("invoke".into())),
        ("output".into(), RuntimeValue::string("unary".into())),
        ("input".into(), RuntimeValue::bytes(vec![2, 255])),
    ]));
    let frame = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
            id: 77,
            action: xolotl_console_protocol::ACTION_RUNTIME_OPERATION_SUBMIT.into(),
            input: Some(xolotl_proto::value_to_pb(&input)),
            scope: Some("submitted echo".into()),
            justification: Some("adapter composition".into()),
            ttl_ms: Some(30_000),
            ..Default::default()
        })),
    };
    let response = send(
        app,
        path,
        "POST",
        "application/protobuf",
        frame.encode_to_vec(),
        Some(token),
    )
    .await?;
    ensure!(response.status() == StatusCode::OK);
    let frame =
        pb::ConsoleFrame::decode(to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
    let Some(pb::console_frame::Frame::Reply(reply)) = frame.frame else {
        anyhow::bail!("submission reply");
    };
    let reference = reply
        .result
        .context("result")?
        .execution
        .context("reference")?;
    let id = reference.execution_id.context("managed execution ID")?;
    // The HTTP submission's ownership and result are shared with embedded Rust callers.
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let result = service
                .call(
                    token,
                    None,
                    xolotl_console::ActionCall {
                        action: xolotl_console_protocol::ACTION_RUNTIME_EXECUTION_RESULT.into(),
                        input: RuntimeValue::map(std::collections::BTreeMap::from([(
                            "execution_id".into(),
                            RuntimeValue::string(id.clone()),
                        )])),
                        scope: Some("submitted result".into()),
                        justification: Some("adapter composition".into()),
                        ttl_ms: Some(30_000),
                        ..Default::default()
                    },
                )
                .await?
                .output
                .context("output")?;
            let output = result
                .as_map()
                .and_then(|map| map.get("output"))
                .context("result output")?;
            if !output.is_null() {
                return Ok::<_, anyhow::Error>(output.clone());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(
        result.as_map().and_then(|map| map.get("value"))
            == Some(&RuntimeValue::bytes(vec![2, 255]))
    );
    Ok(())
}

#[tokio::test]
async fn discovery_advertises_only_the_selected_mounted_endpoints() -> anyhow::Result<()> {
    let state = fixture().await?;
    let api = http::HttpApi::new()
        .with_group(http::HttpGroup::Authentication)
        .with_endpoint(http::HttpEndpoint::Calls)
        .with_endpoint(http::HttpEndpoint::Calls);
    let app = Router::new().nest("/chosen", api.router(state.clone()));
    let manifest: Value = decode(
        json_request(&app, "/chosen", "GET", Value::Null, None).await?,
        StatusCode::OK,
    )
    .await?;
    ensure!(manifest["protocol_version"] == 1);
    let entries = manifest["endpoints"].as_array().context("endpoints")?;
    ensure!(entries.len() == 10);
    for path in ["/auth/continue", "/auth/cancel"] {
        let endpoint = entries
            .iter()
            .find(|entry| entry["path"] == path)
            .context("shared authentication endpoint")?;
        ensure!(endpoint["authentication"] == "continuation");
        ensure!(endpoint["method"] == "POST");
        ensure!(endpoint["encoding"] == "application/json");
    }
    for endpoint in entries {
        let path = endpoint["path"].as_str().context("path")?;
        let method = endpoint["method"].as_str().context("method")?;
        let response =
            json_request(&app, &format!("/chosen{path}"), method, json!({}), None).await?;
        ensure!(!matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
    }
    for path in [
        "/ws",
        "/health",
        "/session/refresh",
        "/credentials/factors",
        "/rpc",
    ] {
        ensure!(
            json_request(&app, &format!("/chosen{path}"), "GET", Value::Null, None)
                .await?
                .status()
                == StatusCode::NOT_FOUND
        );
    }

    let narrowed = http::HttpApi::all()
        .without_group(http::HttpGroup::Authentication)
        .without_endpoint(http::HttpEndpoint::WebSocket);
    let app = Router::new().nest("/narrowed", narrowed.router(state));
    let manifest: Value = decode(
        json_request(&app, "/narrowed", "GET", Value::Null, None).await?,
        StatusCode::OK,
    )
    .await?;
    ensure!(manifest["endpoints"].as_array().context("endpoints")?.len() == 10);
    ensure!(
        json_request(
            &app,
            "/narrowed/auth/password/login",
            "POST",
            json!({}),
            None
        )
        .await?
        .status()
            == StatusCode::NOT_FOUND
    );
    ensure!(
        json_request(&app, "/narrowed/ws", "GET", Value::Null, None)
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    ensure!(
        json_request(&app, "/narrowed/health", "GET", Value::Null, None)
            .await?
            .status()
            == StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn selected_get_routes_serve_head_without_a_response_body() -> anyhow::Result<()> {
    let state = fixture().await?;
    let api = http::HttpApi::new()
        .with_endpoint(http::HttpEndpoint::Health)
        .with_endpoint(http::HttpEndpoint::FactorProviders)
        .with_endpoint(http::HttpEndpoint::CredentialStatus);
    let app = Router::new().nest("/chosen", api.router(state));
    for path in ["/", "/health", "/auth/factor-providers", "/credentials"] {
        let url = format!("/chosen{path}");
        let get = json_request(&app, &url, "GET", Value::Null, None).await?;
        let head = json_request(&app, &url, "HEAD", Value::Null, None).await?;
        ensure!(
            head.status() == get.status(),
            "HEAD status differs for {path}"
        );
        ensure!(
            to_bytes(head.into_body(), http::MAX_CALL_BYTES)
                .await?
                .is_empty(),
            "HEAD returned a body for {path}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn selected_routes_merge_with_host_root_and_host_owned_discovery() -> anyhow::Result<()> {
    let state = fixture().await?;
    let api = http::HttpApi::new()
        .with_group(http::HttpGroup::Authentication)
        .with_endpoint(http::HttpEndpoint::Health);
    let manifest = api.manifest(&state);
    let app = Router::new()
        .route("/", axum::routing::get(|| async { "host root" }))
        .route(
            "/console-discovery",
            axum::routing::get(move || {
                let manifest = manifest.clone();
                async move { ([(header::CACHE_CONTROL, "no-store")], axum::Json(manifest)) }
            }),
        )
        .merge(api.routes(state));

    let root = json_request(&app, "/", "GET", Value::Null, None).await?;
    ensure!(root.status() == StatusCode::OK);
    ensure!(to_bytes(root.into_body(), http::MAX_CALL_BYTES).await? == "host root");
    let manifest: Value = decode(
        json_request(&app, "/console-discovery", "GET", Value::Null, None).await?,
        StatusCode::OK,
    )
    .await?;
    let endpoints = manifest["endpoints"].as_array().context("endpoints")?;
    ensure!(endpoints.len() == 10);
    ensure!(
        endpoints
            .iter()
            .any(|endpoint| endpoint["path"] == "/health")
    );
    ensure!(
        json_request(&app, "/health", "GET", Value::Null, None)
            .await?
            .status()
            == StatusCode::OK
    );
    let providers: Value = decode(
        json_request(&app, "/auth/factor-providers", "GET", Value::Null, None).await?,
        StatusCode::OK,
    )
    .await?;
    ensure!(providers.is_array());
    ensure!(
        json_request(&app, "/calls", "POST", Value::Null, None)
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn groups_can_be_selected_and_every_authentication_route_has_a_safe_contract()
-> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new().nest(
        "/custom",
        HttpApi::new()
            .with_group(HttpGroup::Authentication)
            .with_group(HttpGroup::Credentials)
            .with_group(HttpGroup::Session)
            .routes(state.clone()),
    );
    for path in [
        "/auth/password/login",
        "/auth/keys/challenges",
        "/auth/keys/login",
        "/auth/passkeys/challenges",
        "/auth/passkeys/login",
        "/auth/continue",
        "/auth/cancel",
        "/credentials",
        "/credentials/passkeys/registration",
        "/credentials/passkeys/registration/confirm",
        "/credentials/factors",
        "/session/step-up",
        "/session/refresh",
    ] {
        let response =
            json_request(&app, &format!("/custom{path}"), "POST", json!({}), None).await?;
        ensure!(response.status().is_client_error());
        ensure!(!matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
        ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
        let _failure: ConsoleFailure =
            serde_json::from_slice(&to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
    }
    ensure!(
        json_request(&app, "/custom/calls", "POST", json!({}), None)
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    ensure!(
        json_request(&app, "/custom/ws", "GET", Value::Null, None)
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    for (media, body, status) in [
        ("application/json", b"{".to_vec(), StatusCode::BAD_REQUEST),
        (
            "text/plain",
            b"private-credential".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "application/json",
            vec![b'x'; http::MAX_AUTH_BYTES + 1],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let failure: ConsoleFailure = decode(
            send(
                &app,
                "/custom/auth/password/login",
                "POST",
                media,
                body,
                None,
            )
            .await?,
            status,
        )
        .await?;
        ensure!(!failure.message.contains("private-credential"));
    }
    let ws_app = Router::new().nest(
        "/custom",
        HttpApi::new()
            .with_endpoint(HttpEndpoint::WebSocket)
            .routes(state.clone()),
    );
    // No upgrade headers => a WebSocket extraction rejection, not an absent route.
    ensure!(
        json_request(&ws_app, "/custom/ws", "GET", Value::Null, None)
            .await?
            .status()
            == StatusCode::BAD_REQUEST
    );
    let rpc_app = Router::new().nest(
        "/custom",
        HttpApi::new()
            .with_endpoint(HttpEndpoint::Calls)
            .routes(state),
    );
    let response = send(
        &rpc_app,
        "/custom/calls",
        "POST",
        "application/protobuf",
        vec![0; http::MAX_CALL_BYTES + 1],
        Some("syntactically-valid"),
    )
    .await?;
    ensure!(response.status() == StatusCode::PAYLOAD_TOO_LARGE);
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let frame =
        pb::ConsoleFrame::decode(to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
    ensure!(matches!(
        frame.frame,
        Some(pb::console_frame::Frame::Error(_))
    ));
    Ok(())
}
