use super::*;
use crate::auth::{BootstrapOutcome, LoginRequest, RootProvisioning, bootstrap_root_account};
use crate::http::{
    ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode, ConsoleTrustedProxyConfig,
    ConsoleUnsafeTransportRelaxation, ConsoleWsConfig, ConsoleWsRuntime, HttpConfig, HttpState,
};
use crate::mgmt::MgmtError;
use crate::protocol::*;
use crate::recipes::{self, StateMethod as RecipeStateMethod};
use crate::state::HARD_MAX_QUERY_FACT_LIMIT;
use crate::state::PairingSecretDisplay;
use anyhow::{Context, bail, ensure};
use axum::http::header;
use std::collections::BTreeMap;
use xolotl_kernel::{Bootstrap, FactSink, KernelBuilder};
use xolotl_standard::{PairingDisplayEdge, StandardConfig, install_standard};
use xolotl_state::InMemoryBackend;
use xolotl_types::{
    EffectCapability, ExternalProjectionDef, InferenceApiDialect, InferenceAuthRef,
    InferenceBackendDef, Purity, Role, Transport, TrustLevel,
};
use xolotl_types::{ExternalInstallationDef, OperationId, ProcessId, Value, ValueView};

impl PairingSecretDisplay for PairingDisplayEdge {
    fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        PairingDisplayEdge::take_display_secret(self, pairing_id)
    }
}

fn json_bytes(value: &Value) -> anyhow::Result<Value> {
    Ok(value.clone())
}

fn decode_json_bytes(value: Value) -> anyhow::Result<Value> {
    Ok(value)
}

fn invalid_header_value() -> anyhow::Result<axum::http::HeaderValue> {
    Ok(axum::http::HeaderValue::from_bytes(b"\xff")?)
}

#[derive(Default)]
struct FailingFactStore(xolotl_kernel::InMemoryExecutionIdSource);

impl xolotl_kernel::ExecutionIdSource for FailingFactStore {
    fn reserve(
        &self,
        count: std::num::NonZeroU64,
    ) -> Result<xolotl_kernel::ExecutionIdRange, xolotl_kernel::ExecutionIdError> {
        self.0.reserve(count)
    }
}

impl xolotl_kernel::FactStore for FailingFactStore {
    fn scan(
        &self,
        _query: xolotl_kernel::FactQuery,
    ) -> Result<xolotl_kernel::FactPage, xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new("unexpected fact scan".into()))
    }

    fn lookup(
        &self,
        _query: xolotl_kernel::FactLookup,
    ) -> Result<xolotl_kernel::FactLookupResult, xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new(
            "unexpected fact lookup".into(),
        ))
    }

    fn append(&self, _fact: xolotl_types::Fact) -> Result<u64, xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new(
            "simulated append failure".into(),
        ))
    }

    fn complete(&self, _fact: xolotl_types::Fact) -> Result<(), xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new(
            "simulated complete failure".into(),
        ))
    }

    fn facts_of(
        &self,
        _process: xolotl_types::ProcessId,
    ) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new(
            "unexpected unbounded fact read".into(),
        ))
    }

    fn all_facts(&self) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new(
            "unexpected unbounded fact read".into(),
        ))
    }

    fn cursor(&self) -> u64 {
        0
    }

    fn observed_cursor(&self) -> Result<u64, xolotl_kernel::FactError> {
        Err(xolotl_kernel::FactError::new(
            "uncertain-fact-revision-sensitive-sentinel".into(),
        ))
    }
}

#[test]
fn live_fact_projection_hides_storage_diagnostics() -> anyhow::Result<()> {
    use xolotl_types::{
        DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
        ReplayClass, ResourceId, TaintSet, Timestamp,
    };

    let sink = FactSink::new(Arc::new(FailingFactStore::default()));
    let mut project = crate::service::facts::live_projection(
        sink,
        None,
        std::num::NonZeroUsize::new(1024).context("byte budget")?,
    );
    let notification = Fact {
        id: OperationId::new(
            ProcessId::new(1),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(1),
        caller_identity: Some(IdentityRef::ROOT),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: Value::null(),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome: None,
        batch: None,
        replay: ReplayClass::Observation,
        timestamp: Timestamp::millis(0),
    };
    let error = project(Arc::new(notification))
        .err()
        .context("failed fact lookup")?;
    ensure!(error == "bounded fact read failed; resynchronize with bounded fact pages");
    ensure!(!error.contains("unexpected fact lookup"));
    Ok(())
}

struct GatedSocket {
    incoming: tokio::sync::mpsc::UnboundedReceiver<Message>,
    outgoing: tokio::sync::mpsc::UnboundedSender<Message>,
    readiness: tokio::sync::oneshot::Receiver<()>,
    waiting: Option<tokio::sync::oneshot::Sender<()>>,
    ready: bool,
}

impl Stream for GatedSocket {
    type Item = Result<Message, axum::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.incoming
            .poll_recv(context)
            .map(|message| message.map(Ok))
    }
}

impl Sink<Message> for GatedSocket {
    type Error = &'static str;
    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        use std::{future::Future, task::Poll};
        if self.ready {
            return Poll::Ready(Ok(()));
        }
        if let Some(waiting) = self.waiting.take() {
            let _notified = waiting.send(());
        }
        match std::pin::Pin::new(&mut self.readiness).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                self.ready = true;
                Poll::Ready(Ok(()))
            }
        }
    }
    fn start_send(self: std::pin::Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        self.outgoing
            .send(message)
            .map_err(|_error| "receiver closed")
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn session_revalidates_at_underlying_socket_readiness_not_a_split_buffer()
-> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let principal = service.authenticate_session(&token).await?.principal;
    let sess = test_session_for_token(state, principal, &token);
    let (incoming, receiver) = tokio::sync::mpsc::unbounded_channel();
    let (outgoing, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let (release, readiness) = tokio::sync::oneshot::channel();
    let (waiting, blocked) = tokio::sync::oneshot::channel();
    let socket = GatedSocket {
        incoming: receiver,
        outgoing,
        readiness,
        waiting: Some(waiting),
        ready: false,
    };
    let actor = tokio::spawn(session(socket, sess));
    let call = ClientFrame::Call {
        id: 71,
        call: ActionCall {
            action: ACTION_PROTOCOL_DESCRIBE.into(),
            ..Default::default()
        },
    };
    incoming.send(Message::Binary(
        crate::wire::encode_client_frame(&call).into(),
    ))?;
    tokio::time::timeout(Duration::from_secs(5), blocked).await??;
    service
        .call(
            &token,
            None,
            ActionCall {
                action: ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                ..Default::default()
            },
        )
        .await?;
    release
        .send(())
        .map_err(|_error| anyhow::anyhow!("socket readiness lost"))?;
    let message = tokio::time::timeout(Duration::from_secs(5), observed.recv())
        .await?
        .context("reply")?;
    let Message::Binary(bytes) = message else {
        bail!("unexpected reply type")
    };
    let Some(xolotl_console_protocol::pb::console_frame::Frame::Error(error)) =
        crate::wire::decode_server_frame(&bytes)
            .map_err(anyhow::Error::msg)?
            .frame
    else {
        bail!("stale private reply disclosed")
    };
    ensure!(error.request_id == Some(71));
    ensure!(error.code == xolotl_console_protocol::pb::ConsoleErrorCode::Unauthenticated as i32);
    drop(incoming);
    tokio::time::timeout(Duration::from_secs(5), actor).await??;
    Ok(())
}

#[derive(Default)]
struct RevisionFault {
    inner: xolotl_kernel::InMemoryFactStore,
    fail: std::sync::atomic::AtomicBool,
}

impl xolotl_kernel::ExecutionIdSource for RevisionFault {
    fn reserve(
        &self,
        count: std::num::NonZeroU64,
    ) -> Result<xolotl_kernel::ExecutionIdRange, xolotl_kernel::ExecutionIdError> {
        self.inner.reserve(count)
    }
}

impl xolotl_kernel::FactStore for RevisionFault {
    fn append(&self, fact: xolotl_types::Fact) -> Result<u64, xolotl_kernel::FactError> {
        self.inner.append(fact)
    }
    fn complete(&self, fact: xolotl_types::Fact) -> Result<(), xolotl_kernel::FactError> {
        self.inner.complete(fact)
    }
    fn scan(
        &self,
        query: xolotl_kernel::FactQuery,
    ) -> Result<xolotl_kernel::FactPage, xolotl_kernel::FactError> {
        self.inner.scan(query)
    }
    fn lookup(
        &self,
        query: xolotl_kernel::FactLookup,
    ) -> Result<xolotl_kernel::FactLookupResult, xolotl_kernel::FactError> {
        self.inner.lookup(query)
    }
    fn facts_of(
        &self,
        process: ProcessId,
    ) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
        self.inner.facts_of(process)
    }
    fn all_facts(&self) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
        self.inner.all_facts()
    }
    fn cursor(&self) -> u64 {
        self.inner.cursor()
    }
    fn observed_cursor(&self) -> Result<u64, xolotl_kernel::FactError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(xolotl_kernel::FactError::new(
                "private revision diagnostic".into(),
            ))
        } else {
            Ok(self.inner.cursor())
        }
    }
}

#[tokio::test]
async fn committed_self_revocation_survives_revision_failure() -> anyhow::Result<()> {
    for revoke in [false, true] {
        let facts = Arc::new(RevisionFault::default());
        let boot = Arc::new(Bootstrap::from_kernel(
            KernelBuilder::in_memory()
                .with_fact_sink(FactSink::new(facts.clone()))
                .build(),
        ));
        let (state, service, token, _) = crate::service::tests::fixture_with_boot(boot).await?;
        let token = if revoke {
            let enrolled = state.auth.enroll_test_totp(&state.boot, &token).await?;
            service
                .step_up(
                    &enrolled.token,
                    crate::StepUpRequest {
                        proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
                    },
                    "test".into(),
                )
                .await?
                .into_session()
                .ok()
                .context("step-up")?
                .token
        } else {
            token
        };
        let authenticated = service.authenticate_session(&token).await?;
        let mut sess = test_session_for_token(state, authenticated.principal, &token);
        facts.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let call = if revoke {
            ActionCall {
                action: ACTION_ACCESS_SESSION_REVOKE.into(),
                input: map_value([("sid", Value::string(authenticated.sid))]),
                ..Default::default()
            }
        } else {
            ActionCall {
                action: ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                ..Default::default()
            }
        };
        let reply = handle_frame(&mut sess, ClientFrame::Call { id: 9, call }).await;
        ensure!(sess.sid.is_none() && sess.principal.is_none());
        ensure!(sess.pending_delivery.is_none());
        let ServerFrame::Error { id, failure } = reply else {
            bail!("missing revision failure")
        };
        ensure!(id == Some(9) && failure.code == ConsoleErrorCode::Internal);
        ensure!(!failure.message.contains("private revision"));
        ensure!(service.authenticate_session(&token).await.is_err());
    }
    Ok(())
}

fn console_state() -> anyhow::Result<Arc<ConsoleState>> {
    let pairing_display = PairingDisplayEdge::default();
    let (state, source_store) = InMemoryBackend::new().into_source_parts();
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(state)
            .with_fact_sink(FactSink::in_memory().0)
            .build(),
    ));
    let config = StandardConfig::default()
        .with_pairing_display(pairing_display.clone())
        .with_external_installations(source_store.clone());
    install_standard(&boot, &config).context("install standard package")?;
    ConsoleState::shared_with_pairing_display_and_config(
        boot,
        Arc::new(pairing_display),
        crate::ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            source_management: Some(source_store),
            config_admissions: vec![crate::ConfigNamespaceAdmission::new(
                Path::parse("state://kernel/inference/backends")?,
                |path, value| {
                    let id = xolotl_types::inference::InferenceDeclarationKind::Backend
                        .id(path)
                        .ok_or_else(|| "invalid inference backend path".to_string())?;
                    let document: xolotl_types::inference::InferenceBackendDef =
                        serde_json::from_value(
                            serde_json::to_value(value)
                                .map_err(|_error| "malformed inference backend")?,
                        )
                        .map_err(|_error| "malformed inference backend")?;
                    document
                        .validate_admission(id)
                        .map_err(|_error| "invalid inference backend".into())
                },
            )],
            ..Default::default()
        },
    )
    .context("create console state")
}

fn audit_outcomes(st: &ConsoleState, event: &str) -> anyhow::Result<Vec<String>> {
    Ok(st
        .boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .filter_map(|fact| match fact.outcome {
            Some(value)
                if value
                    .as_map()
                    .and_then(|m| m.get("event"))
                    .and_then(Value::as_str)
                    == Some(event) =>
            {
                value
                    .as_map()
                    .and_then(|m| m.get("outcome"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }
            _ => None,
        })
        .collect())
}

fn test_session(st: Arc<ConsoleState>, principal: ConsolePrincipal) -> WsSession {
    let adapter = HttpState::new(st, HttpConfig::default());
    assert!(adapter.ws.try_acquire_source("test").is_ok());
    let subscriptions = Subscriptions::new(adapter.ws.config());
    WsSession {
        adapter,
        principal: Some(principal),
        sid: Some("not-used".into()),
        hello_accepted: true,
        source_addr: "test".into(),
        counted_account: None,
        subscriptions,
        rate: FrameRate::default(),
        pending_delivery: None,
    }
}

fn test_session_for_token(
    st: Arc<ConsoleState>,
    principal: ConsolePrincipal,
    token: &str,
) -> WsSession {
    let mut sess = test_session(st, principal);
    sess.sid = bearer_sid(Some(token)).map(str::to_string);
    sess
}

fn unauth_session(st: Arc<ConsoleState>) -> WsSession {
    let adapter = HttpState::new(st, HttpConfig::default());
    assert!(adapter.ws.try_acquire_source("test").is_ok());
    let subscriptions = Subscriptions::new(adapter.ws.config());
    WsSession {
        adapter,
        principal: None,
        sid: None,
        hello_accepted: false,
        source_addr: "test".into(),
        counted_account: None,
        subscriptions,
        rate: FrameRate::default(),
        pending_delivery: None,
    }
}

#[tokio::test]
async fn abandoned_upgrade_releases_connection_reservation() -> anyhow::Result<()> {
    let st = HttpState::new(
        console_state()?,
        HttpConfig {
            ws: ConsoleWsConfig {
                max_connections_global: 1,
                ..Default::default()
            },
            ..HttpConfig::default()
        },
    );
    let pending = WsSession::acquire(st.clone(), "pending".into())
        .map_err(|_error| anyhow::anyhow!("initial reservation failed"))?;
    ensure!(matches!(
        WsSession::acquire(st.clone(), "other".into()),
        Err(ConsoleWsLimit::Global)
    ));
    let upgrade_callback = move || pending;
    drop(upgrade_callback);
    let connected = WsSession::acquire(st.clone(), "connected".into())
        .map_err(|_error| anyhow::anyhow!("abandoned upgrade leaked its reservation"))?;
    drop(connected);
    ensure!(st.ws.try_acquire_source("next").is_ok());
    st.ws.release_source("next");
    Ok(())
}

#[tokio::test]
async fn unauthenticated_subscribe_preserves_request_id() -> anyhow::Result<()> {
    let mut sess = unauth_session(console_state()?);
    sess.hello_accepted = true;
    let stream = StreamCall {
        stream: STREAM_STATE_WATCH.into(),
        input: Value::null(),
        scope: None,
        justification: None,
        ttl_ms: None,
        registry_rev: None,
    };
    let reply = handle_frame(&mut sess, ClientFrame::Subscribe { id: 42, stream }).await;
    ensure!(matches!(
        reply,
        ServerFrame::Error {
            id: Some(42),
            failure: crate::ConsoleFailure {
                code: ConsoleErrorCode::NotAuthenticated,
                ..
            },
            ..
        }
    ));
    Ok(())
}

#[tokio::test]
async fn websocket_auth_and_call_capacity_precede_session_state_lookup() -> anyhow::Result<()> {
    let st = console_state()?;
    let mut sess = unauth_session(st.clone());
    sess.hello_accepted = true;
    let auth_capacity = st
        .authentications
        .try_acquire_many(u32::try_from(st.authentications.available_permits())?)?;
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Auth {
            token: "invalid".into(),
        },
    )
    .await;
    ensure!(matches!(
        reply,
        ServerFrame::Error {
            failure: ConsoleFailure {
                code: ConsoleErrorCode::RateLimited,
                ..
            },
            ..
        }
    ));
    drop(auth_capacity);
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Auth {
            token: "invalid".into(),
        },
    )
    .await;
    ensure!(matches!(
        reply,
        ServerFrame::Error {
            failure: ConsoleFailure {
                code: ConsoleErrorCode::NotAuthenticated,
                ..
            },
            ..
        }
    ));

    sess.sid = Some("invalid".into());
    let call_capacity = st
        .calls
        .try_acquire_many(u32::try_from(st.calls.available_permits())?)?;
    let call = ActionCall {
        action: ACTION_PROTOCOL_DESCRIBE.into(),
        ..Default::default()
    };
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Call {
            id: 23,
            call: call.clone(),
        },
    )
    .await;
    ensure!(matches!(
        reply,
        ServerFrame::Error {
            id: Some(23),
            failure: ConsoleFailure {
                code: ConsoleErrorCode::RateLimited,
                ..
            }
        }
    ));
    drop(call_capacity);
    let reply = handle_frame(&mut sess, ClientFrame::Call { id: 23, call }).await;
    ensure!(matches!(
        reply,
        ServerFrame::Error {
            id: Some(23),
            failure: ConsoleFailure {
                code: ConsoleErrorCode::NotAuthenticated,
                ..
            }
        }
    ));
    Ok(())
}

#[tokio::test]
async fn default_snapshot_succeeds_and_rejects_fake_incremental_reads() -> anyhow::Result<()> {
    let st = console_state()?;
    let principal = root_principal()?;
    let mut sess = test_session(st, principal.clone());
    let result = dispatch_call(
        &mut sess,
        &principal,
        call(ACTION_STATE_SNAPSHOT, Value::null())?,
    )
    .await?;
    let output = result
        .output
        .as_ref()
        .and_then(Value::as_map)
        .context("snapshot must be a map")?;
    ensure!(output.contains_key("sessions") && output.contains_key("runtime"));
    ensure!(matches!(
        dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_STATE_SNAPSHOT,
                map_value([("since_rev", Value::integer(0))])
            )?
        )
        .await,
        Err(ConsoleError::BadRequest(_))
    ));
    Ok(())
}

#[tokio::test]
async fn snapshot_reports_config_continuations_and_list_action_resumes() -> anyhow::Result<()> {
    let st = console_state()?;
    let principal = root_principal()?;
    let prefix = "state://kernel/page-test";
    for id in 0..3 {
        st.state
            .write_set(&Path::parse(&format!("{prefix}/{id}"))?, Value::integer(id))
            .await?;
    }
    let mut sess = test_session(st, principal.clone());
    let result = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_STATE_SNAPSHOT,
            map_value([(
                "sections",
                Value::list(vec![map_value([
                    ("kind", Value::string("kernel_config".into())),
                    ("prefix", Value::string(prefix.into())),
                    ("limit", Value::integer(1)),
                ])]),
            )]),
        )?,
    )
    .await?;
    let output = result
        .output
        .as_ref()
        .and_then(Value::as_map)
        .context("snapshot must be a map")?;
    ensure!(output.get("truncated") == Some(&Value::list(vec![Value::string(prefix.into())])));
    let page = output
        .get(prefix)
        .and_then(Value::as_map)
        .context("missing config page")?;
    let cursor = page.get("next_cursor").context("missing cursor")?.clone();
    let result = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_CONFIG_LIST,
            map_value([
                ("prefix", Value::string(prefix.into())),
                ("cursor", cursor),
                ("limit", Value::integer(2)),
            ]),
        )?,
    )
    .await?;
    let page = result
        .output
        .as_ref()
        .and_then(Value::as_map)
        .context("missing continuation page")?;
    let entries = page
        .get("entries")
        .and_then(Value::as_list)
        .context("missing entries")?;
    ensure!(entries.len() == 2);
    // A backend may stop exactly at its row budget without probing the next
    // record. Follow the cursor even when the last nonempty page was full.
    if let Some(cursor) = page.get("next_cursor").filter(|cursor| !cursor.is_null()) {
        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_CONFIG_LIST,
                map_value([
                    ("prefix", Value::string(prefix.into())),
                    ("cursor", cursor.clone()),
                ]),
            )?,
        )
        .await?;
        let page = result
            .output
            .as_ref()
            .and_then(Value::as_map)
            .context("missing terminal page")?;
        ensure!(
            page.get("entries")
                .and_then(Value::as_list)
                .is_some_and(|entries| entries.is_empty())
        );
        ensure!(page.get("next_cursor").is_some_and(Value::is_null));
    }
    Ok(())
}

fn root_principal() -> anyhow::Result<ConsolePrincipal> {
    Ok(ConsolePrincipal {
        authority_id: "local".into(),
        username: "root".into(),
        account_id: "root-account".into(),
        identity_path: "identity://console/accounts/root-account".into(),
        grants: xolotl_types::CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    })
}

#[test]
fn refreshed_authority_cannot_inherit_a_previous_session() -> anyhow::Result<()> {
    let st = console_state()?;
    let previous = root_principal()?;
    let mut candidates = vec![previous.clone(); 4];
    candidates[0].username = "another-user".into();
    candidates[1].identity_path = "identity://another-user".into();
    candidates[2].grants = xolotl_types::CapSet::default();
    candidates[3].authentication.secondary = None;
    for principal in candidates {
        let mut sess = test_session(st.clone(), previous.clone());
        let frame = match refresh_principal(&mut sess, principal, Some(7)) {
            Ok(_) => bail!("changed authority was accepted"),
            Err(frame) => frame,
        };
        ensure!(matches!(
            *frame,
            ServerFrame::Error {
                id: Some(7),
                failure: crate::ConsoleFailure {
                    code: ConsoleErrorCode::Forbidden,
                    ..
                },
                ..
            }
        ));
        ensure!(sess.sid.is_none());
        ensure!(should_close_after_reply(&sess, &frame));
        ensure!(sess.principal.as_ref() == Some(&previous));
    }
    let mut sess = test_session(st, previous.clone());
    ensure!(refresh_principal(&mut sess, previous, None).is_ok());
    ensure!(sess.sid.is_some());
    Ok(())
}

#[tokio::test]
async fn connection_audit_does_not_reuse_a_revoked_sessions_authentication() -> anyhow::Result<()> {
    let state = console_state()?;
    let (token, _, password) = root_login(&state).await?;
    let (token, principal) = step_up_login(&state, &token, password).await?;
    ensure!(principal.authentication.mfa_level() == 2);
    let mut session = test_session_for_token(state.clone(), principal, &token);
    let sid = session.sid.as_deref().context("authenticated SID")?;
    state
        .auth
        .logout_sid_from_source(&state.boot, sid, Some("test"))
        .await?;
    ensure!(
        authenticated_principal(&mut session, Some(1), true)
            .await
            .is_err()
    );
    ensure!(session.sid.is_none() && session.principal.is_some());
    let protocol_error = hello_sequence_error(&session, Some(2), "repeated hello");
    ensure!(matches!(protocol_error, ServerFrame::Error { .. }));
    let records = state.boot.kernel().facts().all_facts()?;
    let events: Vec<_> = records
        .iter()
        .filter_map(|fact| fact.outcome.as_ref()?.as_map())
        .filter(|event| event.get("event").and_then(Value::as_str) == Some("console_ws"))
        .collect();
    ensure!(events.len() == 2);
    for event in events {
        ensure!(event.get("username").and_then(Value::as_str) == Some("root"));
        ensure!(event.get("mfa_level").is_none());
        ensure!(event.get("details").is_none());
    }
    Ok(())
}

#[tokio::test]
async fn successful_auth_joins_and_clears_previous_subscriptions() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, mut previous, _password) = root_login(&st).await?;
    previous.username = "previous-user".into();
    let mut sess = test_session(st, previous);
    let (source, receiver) = tokio::sync::broadcast::channel(2);
    sess.subscriptions
        .replace(
            9,
            receiver,
            |_| {
                Ok(Some(ConsoleEvent::Audit {
                    fact: Value::integer(1),
                }))
            },
            "test",
            tokio::time::Instant::now() + Duration::from_secs(60),
            None,
        )
        .await?;
    source.send(())?;
    let reply = handle_frame(&mut sess, ClientFrame::Auth { token }).await;
    ensure!(matches!(reply, ServerFrame::Authenticated { .. }));
    ensure!(
        source.receiver_count() == 0,
        "previous worker survived authentication"
    );
    ensure!(sess.subscriptions.len() == 0);
    ensure!(
        tokio::time::timeout(Duration::from_millis(10), sess.subscriptions.next())
            .await
            .is_err(),
        "old queued data survived authentication"
    );
    Ok(())
}

#[test]
fn visibility_audit_fact_failure_is_not_swallowed() -> anyhow::Result<()> {
    let facts = xolotl_kernel::FactSink::new(Arc::new(FailingFactStore::default()));
    let state: xolotl_state::Backend = xolotl_state::InMemoryBackend::new().into_backend();
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(state)
            .with_fact_sink(facts)
            .build(),
    ));
    let st = ConsoleState::shared(
        boot,
        std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
            crate::session_store::ConsoleSessionPolicy::default(),
        )),
    )
    .context("create console state")?;
    let principal = root_principal()?;

    let err = match record_visibility_audit(
        &st,
        &principal,
        Some("test"),
        "state_read",
        VisibilityAuditDetails::action(
            &ActionCall {
                scope: Some("scope".into()),
                justification: Some("justification".into()),
                ttl_ms: Some(1000),
                ..Default::default()
            },
            Some("state://chat/source/messages/1"),
        ),
    ) {
        Ok(()) => bail!("visibility audit unexpectedly succeeded"),
        Err(err) => err,
    };

    ensure!(
        matches!(err, ConsoleError::Operation(ref message) if message.contains("simulated complete failure")),
        "unexpected visibility audit error: {err:?}"
    );
    Ok(())
}

async fn root_login(st: &Arc<ConsoleState>) -> anyhow::Result<(String, ConsolePrincipal, String)> {
    let outcome =
        bootstrap_root_account(&st.boot, st.blocking_spawner(), RootProvisioning::default())
            .await?;
    let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
        bail!("expected root bootstrap, got {outcome:?}");
    };
    let login = st
        .auth
        .login(
            &st.boot,
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("authenticated session")?;
    let principal = st.auth.authenticate_token(&st.boot, &login.token).await?;
    Ok((login.token, principal, password))
}

async fn step_up_principal(
    st: &Arc<ConsoleState>,
    token: &str,
    _password: String,
) -> anyhow::Result<ConsolePrincipal> {
    let elevated = st.auth.enroll_test_totp(&st.boot, token).await?;
    Ok(st
        .auth
        .authenticate_token(&st.boot, &elevated.token)
        .await?)
}

async fn step_up_login(
    st: &Arc<ConsoleState>,
    token: &str,
    _password: String,
) -> anyhow::Result<(String, ConsolePrincipal)> {
    let elevated = st.auth.enroll_test_totp(&st.boot, token).await?;
    let principal = st
        .auth
        .authenticate_token(&st.boot, &elevated.token)
        .await?;
    Ok((elevated.token, principal))
}

fn extension_installation(id: &str, version: u64) -> anyhow::Result<Value> {
    let provider_namespace = Path::try_new("effect")?
        .try_push("external-provider")?
        .try_push_literal(id)?;
    let search_effect = provider_namespace.clone().try_push("search")?.to_string();
    let def = ExternalInstallationDef {
        id: id.into(),
        platform: id.into(),
        transport: Transport::Stdio {
            command: Some("/bin/sh".into()),
            args: vec![],
        },
        trust: TrustLevel::Sandboxed,
        config_schema: Value::null(),
        config: Value::null(),
        projections: vec![ExternalProjectionDef {
            id: "provider".into(),
            role: Role::Provider,
            namespace: Some(provider_namespace),
            provides: vec![EffectCapability::new(search_effect, Purity::Idempotent)],
            emits: None,
            version: 1,
        }],
        version,
    };
    Ok(serde_json::from_value(serde_json::to_value(def)?)?)
}

fn inference_backend(id: &str) -> anyhow::Result<Value> {
    let def = InferenceBackendDef {
        id: id.into(),
        dialect: InferenceApiDialect::OpenAiChatCompletions,
        base_url: "https://api.deepseek.com".into(),
        auth: InferenceAuthRef::BearerToken {
            token_ref: Path::parse("state://vault/inference/deepseek/api_key")?,
        },
        default_headers: BTreeMap::new(),
        request_overrides: BTreeMap::new(),
        api_version: None,
        io_window_bytes: None,
        response_limits: Default::default(),
        version: 0,
    };
    Ok(serde_json::from_value(serde_json::to_value(def)?)?)
}

fn call(action: &str, input: Value) -> anyhow::Result<ActionCall> {
    Ok(ActionCall {
        action: action.into(),
        input: json_bytes(&input)?,
        scope: None,
        justification: None,
        ttl_ms: None,
        ..Default::default()
    })
}

fn visibility_call(action: &str, input: Value) -> anyhow::Result<ActionCall> {
    Ok(ActionCall {
        action: action.into(),
        input: json_bytes(&input)?,
        scope: Some("test".into()),
        justification: Some("test visibility inspection".into()),
        ttl_ms: Some(60_000),
        ..Default::default()
    })
}

fn output_value(result: ActionResult) -> anyhow::Result<Value> {
    decode_json_bytes(result.output.context("expected action output")?)
}

fn fact_count(st: &ConsoleState) -> anyhow::Result<usize> {
    let mut count = 0usize;
    for pid in st.boot.kernel().processes().all_ids() {
        count = count
            .checked_add(st.boot.kernel().facts().facts_of(pid)?.len())
            .context("fact count overflow")?;
    }
    Ok(count)
}

#[test]
fn frame_rate_limits_frames_and_bytes_per_second() {
    let mut rate = FrameRate::default();
    assert!(rate.observe(10, 2, 25));
    assert!(rate.observe(10, 2, 25));
    assert!(!rate.observe(1, 2, 25));

    let mut rate = FrameRate::default();
    assert!(rate.observe(20, 10, 25));
    assert!(!rate.observe(6, 10, 25));
}

#[test]
fn ws_runtime_enforces_connection_limits_and_releases() {
    let runtime = ConsoleWsRuntime::new(ConsoleWsConfig {
        max_connections_global: 2,
        max_connections_per_source: 1,
        max_connections_per_account: 1,
        ..Default::default()
    });
    assert!(runtime.try_acquire_source("a").is_ok());
    assert_eq!(runtime.try_acquire_source("a"), Err(ConsoleWsLimit::Source));
    assert!(runtime.try_acquire_source("b").is_ok());
    assert_eq!(runtime.try_acquire_source("c"), Err(ConsoleWsLimit::Global));
    runtime.release_source("a");
    assert!(runtime.try_acquire_source("c").is_ok());

    assert!(
        runtime
            .try_replace_account(None, &crate::auth::AccountKey::local("root-instance-1"))
            .is_ok()
    );
    assert_eq!(
        runtime.try_replace_account(None, &crate::auth::AccountKey::local("root-instance-1")),
        Err(ConsoleWsLimit::Account)
    );
    // A replacement account with the same display name has a separate quota.
    assert!(
        runtime
            .try_replace_account(None, &crate::auth::AccountKey::local("root-instance-2"))
            .is_ok()
    );
    runtime.release_account(&crate::auth::AccountKey::local("root-instance-1"));
    assert!(
        runtime
            .try_replace_account(None, &crate::auth::AccountKey::local("root-instance-1"))
            .is_ok()
    );
}

#[test]
fn pairing_input_rejects_secret_fields_inside_lists() {
    let input = Value::list(vec![map_value([(
        "nested",
        Value::list(vec![map_value([(
            "pairing_secret",
            Value::string("do-not-accept".into()),
        )])]),
    )])]);
    assert!(matches!(
        reject_secret_fields(&input),
        Err(ConsoleError::BadRequest(_))
    ));
}

#[test]
fn pairing_input_rejects_untrusted_claim_field() {
    let input = map_value([("sas_verified", Value::boolean(true))]);
    assert!(matches!(
        reject_secret_fields(&input),
        Err(ConsoleError::BadRequest(_))
    ));
}

#[test]
fn console_frame_roundtrips_on_protobuf_wire() -> anyhow::Result<()> {
    let frame = ClientFrame::Call {
        id: 7,
        call: call(
            ACTION_STATE_SNAPSHOT,
            map_value([
                (
                    "sections",
                    Value::list(vec![
                        map_value([
                            ("kind", Value::string("kernel_config".into())),
                            ("prefix", Value::string("state://kernel/audit".into())),
                        ]),
                        map_value([
                            ("kind", Value::string("runtime".into())),
                            ("limit", Value::integer(8)),
                        ]),
                    ]),
                ),
                ("since_rev", Value::integer(3)),
            ]),
        )?,
    };
    let bytes = crate::wire::encode_client_frame(&frame);
    let decoded = decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES)
        .map_err(|message| anyhow::anyhow!(message))?;
    ensure!(decoded == frame, "decoded frame did not match original");

    // The server frame path also encodes to a decodable protobuf envelope.
    let reply = ServerFrame::Reply {
        id: 7,
        result: ActionResult::value(Value::string("ok".into()), 11, 7),
    };
    let server_bytes = crate::wire::encode_server_frame(&reply, HARD_MAX_WS_FRAME_BYTES)?;
    let server_frame = crate::wire::decode_server_frame(&server_bytes)
        .map_err(|message| anyhow::anyhow!(message))?;
    ensure!(
        server_frame.frame.is_some(),
        "server frame did not encode a frame payload"
    );
    Ok(())
}

#[tokio::test]
async fn hello_rejects_unsupported_protocol_version() -> anyhow::Result<()> {
    let st = console_state()?;
    let mut sess = unauth_session(st.clone());
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Hello {
            hello: ClientHello {
                protocol_version: PROTOCOL_VERSION + 1,
                client_name: Some("test-client".into()),
            },
        },
    )
    .await;
    ensure!(
        matches!(
            reply,
            ServerFrame::Error {
                id: None,
                failure: crate::ConsoleFailure {
                    code: ConsoleErrorCode::BadRequest,
                    ..
                },
                ..
            }
        ),
        "unsupported protocol version was accepted"
    );
    let outcomes = audit_outcomes(&st, "console_ws")?;
    ensure!(
        outcomes.iter().any(|outcome| outcome == "protocol_error"),
        "missing protocol_error audit outcome"
    );

    let reply = handle_frame(
        &mut sess,
        ClientFrame::Hello {
            hello: ClientHello::default(),
        },
    )
    .await;
    ensure!(
        matches!(reply, ServerFrame::HelloAccepted { .. }),
        "default hello was rejected"
    );
    Ok(())
}

#[tokio::test]
async fn uncertain_fact_revision_does_not_advertise_stale_console_metadata() -> anyhow::Result<()> {
    let facts = xolotl_kernel::FactSink::new(Arc::new(FailingFactStore::default()));
    let backend: xolotl_state::Backend = xolotl_state::InMemoryBackend::new().into_backend();
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(backend)
            .with_fact_sink(facts)
            .build(),
    ));
    let state = ConsoleState::shared(
        boot,
        std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
            crate::session_store::ConsoleSessionPolicy::default(),
        )),
    )
    .context("console state")?;
    let mut sess = unauth_session(state);
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Hello {
            hello: ClientHello::default(),
        },
    )
    .await;
    ensure!(
        matches!(
            reply,
            ServerFrame::Error {
                id: None,
                failure: ConsoleFailure {
                    code: ConsoleErrorCode::Internal,
                    ref message,
                    ..
                },
            } if !message.contains("sensitive-sentinel")
        ),
        "uncertain revision must fail without exposing backend details"
    );
    ensure!(!sess.hello_accepted);
    Ok(())
}

#[tokio::test]
async fn hello_reports_only_the_connected_adapters_transport_policy() -> anyhow::Result<()> {
    let console = console_state()?;
    for mode in [
        ConsoleTransportSecurityMode::ProductionTls,
        ConsoleTransportSecurityMode::UnsafePlaintext,
    ] {
        let adapter = HttpState::new(
            console.clone(),
            HttpConfig {
                transport_security: ConsoleTransportSecurityConfig {
                    mode,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let expected = adapter.transport_summary();
        let mut session = WsSession::acquire(adapter, "same-peer".into())
            .map_err(|error| anyhow::anyhow!("connection admission: {error:?}"))?;
        let reply = handle_frame(
            &mut session,
            ClientFrame::Hello {
                hello: ClientHello::default(),
            },
        )
        .await;
        let ServerFrame::HelloAccepted {
            metadata,
            transport,
        } = reply
        else {
            bail!("expected successful Hello");
        };
        ensure!(transport == expected);
        ensure!(metadata.protocol_version == 1);
        ensure!(
            serde_json::to_value(metadata)?
                .get("transport_security_mode")
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn auth_and_calls_require_accepted_hello() -> anyhow::Result<()> {
    let st = console_state()?;
    let mut sess = unauth_session(st.clone());
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Auth {
            token: "bad-token".into(),
        },
    )
    .await;
    ensure!(
        matches!(
            reply,
            ServerFrame::Error {
                id: None,
                failure: crate::ConsoleFailure {
                    code: ConsoleErrorCode::BadFrame,
                    ..
                },
                ..
            }
        ),
        "auth before hello was accepted"
    );

    let reply = handle_frame(
        &mut sess,
        ClientFrame::Call {
            id: 42,
            call: call(ACTION_PROTOCOL_DESCRIBE, Value::null())?,
        },
    )
    .await;
    ensure!(
        matches!(
            reply,
            ServerFrame::Error {
                id: Some(42),
                failure: crate::ConsoleFailure {
                    code: ConsoleErrorCode::BadFrame,
                    ..
                },
                ..
            }
        ),
        "call before hello was accepted"
    );
    let outcomes = audit_outcomes(&st, "console_ws")?;
    ensure!(
        outcomes.iter().any(|outcome| outcome == "protocol_error"),
        "missing protocol_error audit outcome"
    );
    Ok(())
}

#[tokio::test]
async fn unsubscribe_requires_authenticated_session() -> anyhow::Result<()> {
    let st = console_state()?;
    let mut sess = unauth_session(st);
    sess.hello_accepted = true;
    let reply = handle_frame(&mut sess, ClientFrame::Unsubscribe { id: 99 }).await;
    ensure!(
        matches!(
            reply,
            ServerFrame::Error {
                id: Some(99),
                failure: crate::ConsoleFailure {
                    code: ConsoleErrorCode::NotAuthenticated,
                    ..
                },
                ..
            }
        ),
        "unauthenticated unsubscribe was accepted"
    );
    let outcomes = audit_outcomes(&sess.adapter.console, "console_ws")?;
    ensure!(
        outcomes
            .iter()
            .any(|outcome| outcome == "not_authenticated"),
        "missing not_authenticated audit outcome"
    );
    Ok(())
}

#[test]
fn rejected_upgrade_writes_gateway_audit() -> anyhow::Result<()> {
    let st = console_state()?;
    let headers = HeaderMap::new();

    let err = match validate_upgrade_headers_audited(
        &HttpState::new(st.clone(), HttpConfig::default()),
        &headers,
        None,
    ) {
        Ok(()) => bail!("upgrade without headers unexpectedly succeeded"),
        Err(err) => err,
    };

    ensure!(err.contains("origin"), "unexpected upgrade error: {err}");
    let outcomes = audit_outcomes(&st, "console_ws")?;
    ensure!(
        outcomes.iter().any(|outcome| outcome == "origin_denied"),
        "missing origin_denied audit outcome"
    );
    Ok(())
}

#[tokio::test]
async fn websocket_mutations_do_not_create_audit_records() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let (token, principal) = step_up_login(&st, &token, password).await?;
    let mut sess = test_session_for_token(st.clone(), principal, &token);
    let reply = handle_frame(
        &mut sess,
        ClientFrame::Call {
            id: 73,
            call: call(
                ACTION_ACCESS_ROLE_WRITE_CAS,
                map_value([
                    ("role", Value::string("ws-audit".into())),
                    ("value", map_value([("grants", Value::list(Vec::new()))])),
                    ("expected_version", Value::null()),
                ]),
            )?,
        },
    )
    .await;
    let ServerFrame::Reply { id: 73, result } = reply else {
        bail!("mutation failed: {reply:?}");
    };
    ensure!(result.output.is_none());
    ensure!(result.server_rev == st.boot.kernel().facts().cursor());
    ensure!(audit_outcomes(&st, "console_mutation")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn step_up_required_writes_specific_gateway_audit() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session_for_token(st.clone(), principal, &token);

    let reply = handle_frame(
        &mut sess,
        ClientFrame::Call {
            id: 11,
            call: call(
                ACTION_PAIRING_DENY,
                map_value([("pairing_id", Value::string("pair-ws".into()))]),
            )?,
        },
    )
    .await;

    let ServerFrame::Error {
        id: Some(11),
        failure,
    } = reply
    else {
        bail!("step-up-only action was not rejected");
    };
    ensure!(failure.code == ConsoleErrorCode::StepUpRequired);
    ensure!(&*failure.message == "step-up required");
    ensure!(failure.required_mfa_level == Some(2));
    let outcomes = audit_outcomes(&st, "console_call")?;
    ensure!(
        outcomes.iter().any(|outcome| outcome == "step_up_required"),
        "missing step_up_required audit outcome"
    );
    Ok(())
}

#[tokio::test]
async fn forbidden_management_path_is_redacted_and_audited() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session_for_token(st.clone(), principal, &token);

    let reply = handle_frame(
        &mut sess,
        ClientFrame::Call {
            id: 12,
            call: call(
                ACTION_CONFIG_READ,
                map_value([(
                    "path",
                    Value::string("state://vault/console/root/password".into()),
                )]),
            )?,
        },
    )
    .await;

    let ServerFrame::Error {
        id: Some(12),
        failure,
    } = reply
    else {
        bail!("vault management path was not forbidden");
    };
    ensure!(failure.code == ConsoleErrorCode::Forbidden);
    ensure!(&*failure.message == "management path is not allowed");
    let outcomes = audit_outcomes(&st, "console_call")?;
    ensure!(
        outcomes
            .iter()
            .any(|outcome| outcome == "permission_denied"),
        "missing permission_denied audit outcome"
    );
    Ok(())
}

#[test]
fn configured_limits_are_bounded_by_backend_hard_caps() -> anyhow::Result<()> {
    let config = crate::ConsoleQueryConfig {
        max_fact_limit: usize::MAX,
        ..Default::default()
    }
    .bounded();
    ensure!(config.max_fact_limit == HARD_MAX_QUERY_FACT_LIMIT);

    let frame = ClientFrame::Ping { nonce: 9 };
    let bytes = crate::wire::encode_client_frame(&frame);
    ensure!(
        decode_frame(&bytes, bytes.len()).is_ok(),
        "frame did not decode within exact limit"
    );
    ensure!(
        decode_frame(&bytes, bytes.len().saturating_sub(1)).is_err(),
        "frame decoded despite too-small limit"
    );
    Ok(())
}

#[test]
fn protocol_action_calls_are_protobuf_frames() -> anyhow::Result<()> {
    let actions = vec![
        call(ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE, Value::null())?,
        call(ACTION_AUTHORITY_ACTION_MATRIX, Value::null())?,
        call(
            ACTION_AUTHORITY_ACTION_EXPLAIN,
            map_value([("action", Value::string(ACTION_CONFIG_WRITE_CAS.into()))]),
        )?,
        call(ACTION_ACCESS_USER_LIST, Value::null())?,
        call(ACTION_ACCESS_ROLE_LIST, Value::null())?,
        call(ACTION_ACCESS_SESSION_LIST, Value::null())?,
        call(
            ACTION_AUDIT_FACTS_RECENT,
            map_value([("limit", Value::integer(10))]),
        )?,
        call(
            ACTION_LINEAGE_TRACE_READ,
            map_value([
                ("process", Value::integer(1)),
                ("from", Value::integer(0)),
                ("limit", Value::integer(10)),
            ]),
        )?,
        call(
            ACTION_LINEAGE_FACT_READ,
            map_value([("op_id", Value::string("1/1/1/0/0".into()))]),
        )?,
        call(ACTION_HEALTH_SUMMARY, Value::null())?,
        call(
            ACTION_EXTERNAL_INSTALLATION_START,
            map_value([("id", Value::string("acme".into()))]),
        )?,
        call(
            ACTION_PAIRING_DENY,
            map_value([("pairing_id", Value::string("pair-a".into()))]),
        )?,
    ];
    for (idx, call) in actions.into_iter().enumerate() {
        let frame = ClientFrame::Call {
            id: idx as u64,
            call,
        };
        let bytes = crate::wire::encode_client_frame(&frame);
        ensure!(
            decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES)
                .map_err(|message| anyhow::anyhow!(message))?
                == frame,
            "call frame {idx} did not roundtrip"
        );
    }
    let sub = ClientFrame::Subscribe {
        id: 1,
        stream: StreamCall {
            stream: STREAM_STATE_WATCH.into(),
            input: map_value([("pattern", Value::string("state://kernel/**".into()))]),
            scope: Some("test".into()),
            justification: Some("test stream".into()),
            ttl_ms: Some(60_000),
            registry_rev: None,
        },
    };
    let bytes = crate::wire::encode_client_frame(&sub);
    ensure!(
        decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES)
            .map_err(|message| anyhow::anyhow!(message))?
            == sub,
        "subscription frame did not roundtrip"
    );
    Ok(())
}

#[tokio::test]
async fn dispatches_config_and_runtime_actions() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("def", extension_installation("acme", 0)?),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await?;
    let out = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_RUNTIME_PROCESS_INSPECT,
            map_value([
                ("process", Value::string("7".into())),
                ("include_recent_facts", Value::boolean(true)),
                ("limit", Value::integer(8)),
            ]),
        )?,
    )
    .await?;
    ensure!(out.output.is_some(), "runtime inspect output is missing");
    let facts = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_AUDIT_FACTS_RECENT,
            map_value([("limit", Value::integer(16))]),
        )?,
    )
    .await?;
    ensure!(
        matches!((output_value(facts)?).view(), ValueView::Map(page) if matches!(page.get("items").map(Value::view), Some(ValueView::List(_)))),
        "recent facts output was not a page"
    );
    Ok(())
}

#[tokio::test]
async fn discovery_separates_compact_greeting_from_registry_catalog() -> anyhow::Result<()> {
    let pairing_display = PairingDisplayEdge::default();
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(&boot, &StandardConfig::default()).context("install standard package")?;
    let st = ConsoleState::shared_with_pairing_display_and_config(
        boot,
        Arc::new(pairing_display),
        crate::ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            ..Default::default()
        },
    )
    .context("create console state")?;
    let principal = root_principal()?;
    let mut sess = test_session(st, principal.clone());
    let result = dispatch_call(
        &mut sess,
        &principal,
        call(ACTION_PROTOCOL_DESCRIBE, Value::null())?,
    )
    .await
    .map_err(|error| anyhow::anyhow!("metadata action failed: {error:?}"))?;
    let output = result.output.context("metadata output is missing")?;
    let map = output.as_map().context("metadata output must be a map")?;
    ensure!(
        map.get("transport_security_mode").is_none(),
        "service metadata must not infer a transport"
    );
    ensure!(
        map.get("unsafe_transport").is_none(),
        "service metadata must not infer transport relaxations"
    );
    ensure!(map.len() == 6 && map.get("actions").is_none());
    let compact_rev = map
        .get("registry_rev")
        .context("registry revision")?
        .clone();
    let snapshot = dispatch_call(
        &mut sess,
        &principal,
        call(protocol::ACTION_PROTOCOL_REGISTRY_SNAPSHOT, Value::null())?,
    )
    .await?
    .output
    .context("registry snapshot")?;
    let snapshot = snapshot.as_map().context("snapshot map")?;
    ensure!(snapshot.len() == 11);
    for (key, value) in map {
        if key != "server_time_ms" && key != "server_rev" {
            ensure!(snapshot.get(key) == Some(value), "greeting mismatch: {key}");
        }
    }
    ensure!(snapshot.get("registry_rev") == Some(&compact_rev));
    ensure!(
        snapshot
            .get("actions")
            .and_then(Value::as_list)
            .is_some_and(|actions| !actions.is_empty())
    );
    ensure!(
        snapshot
            .get("streams")
            .and_then(Value::as_list)
            .is_some_and(|streams| !streams.is_empty())
    );
    Ok(())
}

#[tokio::test]
async fn authority_matrix_explains_step_up_and_visibility_gate() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, principal, password) = root_login(&st).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_AUTHORITY_ACTION_MATRIX,
            map_value([("domain", Value::string("visibility".into()))]),
        )?,
    )
    .await?;
    let Some(rows) = (output_value(out)?).into_list() else {
        bail!("expected matrix rows");
    };
    ensure!(
        rows.iter().any(|row| {
            row.as_map().is_some_and(
                |m| matches!(m.get("status").map(Value::view), Some(ValueView::Str(s)) if s == "step_up_required"),
            )
        }),
        "matrix did not report step_up_required"
    );

    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_AUTHORITY_ACTION_MATRIX,
            map_value([("domain", Value::string("visibility".into()))]),
        )?,
    )
    .await?;
    let Some(rows) = (output_value(out)?).into_list() else {
        bail!("expected matrix rows");
    };
    ensure!(
        rows.iter().any(|row| {
        row.as_map().is_some_and(|m| {
            matches!(m.get("action").map(Value::view), Some(ValueView::Str(a)) if a == ACTION_VISIBILITY_STATE_READ)
                && matches!(m.get("status").map(Value::view), Some(ValueView::Str(s)) if s == "visibility_gate_required")
        })
        }),
        "matrix did not report visibility gate"
    );
    Ok(())
}

#[tokio::test]
async fn authority_hints_do_not_deny_narrow_grants_or_optional_sections() -> anyhow::Result<()> {
    let state = console_state()?;
    let mut principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "limited".into(),
        account_id: "limited-account".into(),
        identity_path: "identity://console/accounts/limited-account".into(),
        grants: xolotl_types::CapSet::from_strs(["read://state/kernel/inference/backends/one"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let mut session = test_session(state.clone(), principal.clone());
    let explanation = output_value(
        dispatch_call(
            &mut session,
            &principal,
            call(
                ACTION_AUTHORITY_ACTION_EXPLAIN,
                map_value([(
                    "action",
                    Value::string(ACTION_INFERENCE_BACKEND_READ.into()),
                )]),
            )?,
        )
        .await?,
    )?;
    let row = explanation.as_map().context("authority hint")?;
    ensure!(row.get("status").and_then(Value::as_str) == Some("input_required"));
    ensure!(row.get("templates_covered").and_then(Value::as_bool) == Some(false));
    ensure!(!row.contains_key("authority_ok"));
    let out = dispatch_call(
        &mut session,
        &principal,
        call(
            ACTION_INFERENCE_BACKEND_READ,
            map_value([("id", Value::string("one".into()))]),
        )?,
    )
    .await?;
    ensure!(output_value(out)?.is_null());
    let denied = dispatch_call(
        &mut session,
        &principal,
        call(
            ACTION_INFERENCE_BACKEND_READ,
            map_value([("id", Value::string("two".into()))]),
        )?,
    )
    .await;
    ensure!(matches!(
        denied,
        Err(ConsoleError::Mgmt(MgmtError::Auth(
            auth::AuthError::PermissionDenied
        )))
    ));

    principal.grants =
        xolotl_types::CapSet::from_strs(["perform://effect/kernel/process/inspect"])?;
    let mut session = test_session(state, principal.clone());
    let explanation = output_value(
        dispatch_call(
            &mut session,
            &principal,
            call(
                ACTION_AUTHORITY_ACTION_EXPLAIN,
                map_value([("action", Value::string(ACTION_STATE_SNAPSHOT.into()))]),
            )?,
        )
        .await?,
    )?;
    ensure!(
        explanation
            .as_map()
            .and_then(|map| map.get("status"))
            .and_then(Value::as_str)
            == Some("input_required")
    );
    dispatch_call(
        &mut session,
        &principal,
        call(
            ACTION_STATE_SNAPSHOT,
            map_value([(
                "sections",
                Value::list(vec![map_value([("kind", Value::string("runtime".into()))])]),
            )]),
        )?,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn dispatches_shape_independent_descriptor_actions() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session(st, principal.clone());

    let list = output_value(
        dispatch_call(
            &mut sess,
            &principal,
            call(ACTION_RESOURCE_TYPE_LIST, Value::null())?,
        )
        .await?,
    )?;
    ensure!(
        matches!(list.view(), ValueView::List(items) if !items.is_empty()),
        "resource type list was empty or not a list"
    );

    let descriptor = output_value(
        dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_RESOURCE_TYPE_DESCRIBE,
                map_value([("resource_type", Value::string("access.user".into()))]),
            )?,
        )
        .await?,
    )?;
    let Some(descriptor) = (descriptor).into_map() else {
        bail!("expected resource descriptor map");
    };
    let Some(fields) = descriptor.get("fields").and_then(Value::as_list) else {
        bail!("resource descriptor fields missing");
    };
    ensure!(
        fields.iter().any(|field| {
            field.as_map().is_some_and(|map| {
            matches!(map.get("semantic_kind").map(Value::view), Some(ValueView::Str(kind)) if kind == "resource_ref")
        })
        }),
        "resource descriptor did not include a resource_ref field"
    );

    let view = output_value(
        dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_RESOURCE_VIEW_DESCRIBE,
                map_value([("view", Value::string("access.users".into()))]),
            )?,
        )
        .await?,
    )?;
    ensure!(
        matches!(view.view(), ValueView::Map(map) if map.get("resource_type") == Some(&Value::string("access.user".into()))),
        "resource view descriptor did not target access.user"
    );
    Ok(())
}

#[tokio::test]
async fn unimplemented_names_are_absent_from_discovery_and_rejected() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st, principal.clone());
    let result = dispatch_call(
        &mut sess,
        &principal,
        call("change_set.create", Value::null())?,
    )
    .await;
    ensure!(matches!(result, Err(ConsoleError::BadRequest(_))));
    ensure!(
        crate::protocol::action_descriptors()
            .iter()
            .all(|descriptor| !descriptor.id.starts_with("change_set."))
    );
    Ok(())
}

#[tokio::test]
async fn authority_resource_access_keeps_vault_on_secret_custody_path() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session(st, principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_AUTHORITY_RESOURCE_ACCESS,
            map_value([
                (
                    "target",
                    Value::string("state://chat/source/messages/1".into()),
                ),
                ("verb", Value::string("read".into())),
            ]),
        )?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        row.get("allowed") == Some(&Value::boolean(true)),
        "business state read should be allowed"
    );

    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_AUTHORITY_RESOURCE_ACCESS,
            map_value([
                (
                    "target",
                    Value::string("state://vault/console/root/password".into()),
                ),
                ("verb", Value::string("read".into())),
            ]),
        )?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        row.get("allowed") == Some(&Value::boolean(false)),
        "vault read should not be allowed"
    );
    ensure!(
        row.get("why_not") == Some(&Value::string("secret_custody_required".into())),
        "vault read should require secret custody"
    );
    Ok(())
}

#[tokio::test]
async fn authority_action_explain_explains_single_action_gate() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session(st, principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_AUTHORITY_ACTION_EXPLAIN,
            map_value([("action", Value::string(ACTION_PAIRING_DENY.into()))]),
        )?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        row.get("status") == Some(&Value::string("step_up_required".into())),
        "action explanation did not report step_up_required"
    );
    Ok(())
}

#[tokio::test]
async fn health_summary_reports_kernel_registry_and_fact_status() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session(st, principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(ACTION_HEALTH_SUMMARY, Value::null())?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        row.get("status") == Some(&Value::string("ok".into())),
        "health status was not ok"
    );
    ensure!(
        matches!(
            row.get("registry").map(Value::view),
            Some(ValueView::Map(_))
        ),
        "health summary missing registry map"
    );
    ensure!(
        matches!(
            row.get("process_count").map(Value::view),
            Some(ValueView::Int(_))
        ),
        "health summary missing process count"
    );
    ensure!(
        matches!(
            row.get("fact_cursor").map(Value::view),
            Some(ValueView::Str(_))
        ),
        "health summary missing fact_cursor"
    );
    let sample = row
        .get("fact_sample")
        .and_then(Value::as_map)
        .context("health fact sample")?;
    ensure!(sample.get("order").and_then(Value::as_str) == Some("reverse"));
    ensure!(sample.contains_key("sampled_facts") && sample.contains_key("decisions"));
    ensure!(sample.contains_key("next") && sample.contains_key("complete"));
    ensure!(!row.contains_key("fact_count") && !row.contains_key("fact_decisions"));
    Ok(())
}

#[tokio::test]
async fn lineage_fact_read_uses_visibility_gate_and_operation_id() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    st.state
        .write_set(
            &Path::parse("state://chat/source/messages/lineage")?,
            Value::string("lineage fact source".into()),
        )
        .await?;
    let mut sess = test_session(st.clone(), principal.clone());
    dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://chat/source/messages/lineage".into()),
            )]),
        )?,
    )
    .await?;

    let facts = st.boot.kernel().facts().all_facts()?;
    let op_id = facts
        .last()
        .map(|fact| fact.id.to_string())
        .context("expected at least one fact")?;
    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_LINEAGE_FACT_READ,
            map_value([("op_id", Value::string(op_id.clone()))]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("lineage fact read without visibility gate unexpectedly succeeded"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected lineage fact read error: {err:?}"
    );

    let out = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_LINEAGE_FACT_READ,
            map_value([("op_id", Value::string(op_id.clone()))]),
        )?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        row.get("op_id") == Some(&Value::string(op_id)),
        "lineage fact op_id mismatch"
    );
    ensure!(row.contains_key("input"), "lineage fact missing input");
    ensure!(row.contains_key("outcome"), "lineage fact missing outcome");
    ensure!(
        row.get("partial") == Some(&Value::boolean(true)),
        "lineage fact should be marked partial"
    );
    ensure!(
        matches!(
            row.get("partial_reason").map(Value::view),
            Some(ValueView::Str(_))
        ),
        "lineage fact missing partial_reason"
    );
    Ok(())
}

#[tokio::test]
async fn lineage_fact_read_authorizes_and_filters_the_current_caller() -> anyhow::Result<()> {
    use xolotl_types::{
        DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
        ReplayClass, ResourceId, TaintSet, Timestamp,
    };

    let state = console_state()?;
    let op_id = OperationId::new(
        ProcessId::new(7),
        ExecutionId::FIRST,
        InvocationId::new(1),
        NodeId::new(0),
        0,
    );
    state.boot.kernel().facts().complete(Fact {
        id: op_id,
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(8),
        caller_identity: Some(IdentityRef::ROOT),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: Value::string("x".repeat(2048)),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome: Some(Value::integer(42)),
        batch: None,
        replay: ReplayClass::Observation,
        timestamp: Timestamp::millis(0),
    })?;
    let mut principal = root_principal()?;
    principal.identity_path = "identity://console/accounts/reader-account".into();
    principal.grants = xolotl_types::CapSet::from_strs(["read://state/fact/7"])?;
    let mut sess = test_session(state, principal.clone());
    let op_id = op_id.to_string();
    let default_scope = visibility_call(
        ACTION_LINEAGE_FACT_READ,
        map_value([
            ("op_id", Value::string(op_id.clone())),
            ("max_bytes", Value::integer(1024)),
        ]),
    )?;
    ensure!(matches!(
        dispatch_call(&mut sess, &principal, default_scope.clone()).await,
        Err(ConsoleError::BadRequest(message)) if message == format!("unknown operation id: {op_id}")
    ));
    let selected_scope = visibility_call(
        ACTION_LINEAGE_FACT_READ,
        map_value([
            ("op_id", Value::string(op_id.clone())),
            ("process", Value::string("8".into())),
        ]),
    )?;
    ensure!(matches!(
        dispatch_call(&mut sess, &principal, selected_scope.clone()).await,
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    ));

    principal.grants = xolotl_types::CapSet::from_strs(["read://state/fact/8"])?;
    ensure!(matches!(
        dispatch_call(&mut sess, &principal, default_scope).await,
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    ));
    let oversized = visibility_call(
        ACTION_LINEAGE_FACT_READ,
        map_value([
            ("op_id", Value::string(op_id.clone())),
            ("process", Value::string("8".into())),
            ("max_bytes", Value::integer(1024)),
        ]),
    )?;
    ensure!(matches!(
        dispatch_call(&mut sess, &principal, oversized).await,
        Err(ConsoleError::Operation(_))
    ));
    let output = dispatch_call(&mut sess, &principal, selected_scope).await?;
    let Some(row) = (output_value(output)?).into_map() else {
        bail!("expected fact detail map");
    };
    ensure!(row.get("op_id") == Some(&Value::string(op_id)));
    ensure!(row.get("caller") == Some(&Value::string("8".into())));
    ensure!(row.get("input") == Some(&Value::string("x".repeat(2048))));
    ensure!(row.get("outcome") == Some(&Value::integer(42)));
    Ok(())
}

#[tokio::test]
async fn lineage_trace_read_explicitly_marks_partial_projection() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    st.state
        .write_set(
            &Path::parse("state://chat/source/messages/trace")?,
            Value::string("trace source".into()),
        )
        .await?;
    let mut sess = test_session(st.clone(), principal.clone());
    dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://chat/source/messages/trace".into()),
            )]),
        )?,
    )
    .await?;
    let facts = st.boot.kernel().facts().all_facts()?;
    let process = facts
        .last()
        .map(|fact| fact.caller.get())
        .context("expected at least one fact")?;

    let out = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_LINEAGE_TRACE_READ,
            map_value([
                ("process", Value::integer(process as i64)),
                ("from", Value::integer(0)),
                ("limit", Value::integer(8)),
            ]),
        )?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        row.get("partial") == Some(&Value::boolean(true)),
        "lineage trace should be partial"
    );
    ensure!(
        matches!(
            row.get("partial_reason").map(Value::view),
            Some(ValueView::Str(_))
        ),
        "lineage trace missing partial_reason"
    );
    ensure!(
        matches!(row.get("items").map(Value::view), Some(ValueView::List(items)) if !items.is_empty()),
        "lineage trace items missing or empty"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_create_can_return_one_time_display_secret() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            map_value([
                ("id", Value::string("pairable".into())),
                ("def", extension_installation("pairable", 0)?),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await?;
    let missing_id = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_PAIRING_CREATE,
            map_value([("installation_id", Value::string("pairable".into()))]),
        )?,
    )
    .await;
    ensure!(
        matches!(missing_id, Err(ConsoleError::BadRequest(message)) if message.contains("pairing_id")),
        "pairing create accepted a missing caller-selected id"
    );
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_PAIRING_CREATE,
            map_value([
                ("pairing_id", Value::string("pair-ws".into())),
                ("installation_id", Value::string("pairable".into())),
                ("reveal_display_secret", Value::boolean(true)),
            ]),
        )?,
    )
    .await?;
    let Some(m) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        matches!(m.get("display_secret").map(Value::view), Some(ValueView::Str(s)) if !s.is_empty()),
        "pairing display secret was missing"
    );
    ensure!(
        st.pairing_display.take_display_secret("pair-ws").is_none(),
        "pairing display secret was not one-time"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_deny_requires_step_up() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session(st, principal.clone());
    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_PAIRING_DENY,
            map_value([("pairing_id", Value::string("pair-ws".into()))]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("pairing deny unexpectedly succeeded without step-up"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::StepUpRequired),
        "unexpected pairing deny error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn generic_config_write_rejects_typed_runtime_prefixes() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st, principal.clone());
    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_CONFIG_WRITE_CAS,
            map_value([
                (
                    "path",
                    Value::string("state://kernel/external-installations/acme".into()),
                ),
                ("value", extension_installation("acme", 0)?),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("generic config write unexpectedly accepted runtime prefix"),
        Err(err) => err,
    };
    ensure!(
        matches!(err.kind(), ConsoleError::BadRequest(message) if message == "management path must use its dedicated console action"),
        "unexpected generic config write error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn external_installation_action_validates_admission_before_state_write() -> anyhow::Result<()>
{
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    let mut root = extension_installation("acme", 0)?
        .into_map()
        .context("installation map")?;
    let mut projections = root
        .remove("projections")
        .and_then(Value::into_list)
        .context("projections")?;
    let mut provider = projections
        .get(0)
        .and_then(Value::as_map)
        .cloned()
        .context("provider projection")?;
    provider.insert(
        "namespace".into(),
        Value::string("effect://external-provider/other".into()),
    )?;
    projections.set(0, Value::from(provider))?;
    root.insert("projections".into(), Value::from(projections))?;
    let bad = Value::from(root);

    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("def", bad.clone()),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("bad external installation unexpectedly passed admission"),
        Err(err) => err,
    };
    ensure!(
        matches!(err.kind(), ConsoleError::BadRequest(_)),
        "unexpected external installation error: {err:?}"
    );
    ensure!(
        st.state
            .read(&Path::parse("state://kernel/external-installations/acme")?)
            .await?
            .is_none(),
        "bad external installation was written"
    );

    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_CONFIG_WRITE_CAS,
            map_value([
                (
                    "path",
                    Value::string("state://kernel/external-installations/acme".into()),
                ),
                ("value", bad),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("generic config write unexpectedly accepted external installation path"),
        Err(err) => err,
    };
    ensure!(
        matches!(err.kind(), ConsoleError::BadRequest(message) if message == "management path must use its dedicated console action"),
        "unexpected generic config write error: {err:?}"
    );
    ensure!(
        st.state
            .read(&Path::parse("state://kernel/external-installations/acme")?)
            .await?
            .is_none(),
        "generic config write stored external installation"
    );
    Ok(())
}

#[tokio::test]
async fn external_catalog_ignores_forged_state_and_fences_reinstalled_ids() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    let definition = extension_installation("acme", 0)?;
    dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("def", definition.clone()),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await?;
    let installed = st
        .source_management
        .as_ref()
        .context("catalog")?
        .load_installation("acme")
        .await?
        .context("installed record")?;
    ensure!(installed.definition.version == 1 && installed.installation_epoch > 0);

    // A plain State writer can no longer replace the definition used by Ready.
    st.state
        .write_set(
            &Path::parse("state://kernel/external-installations/acme")?,
            Value::string("forged-old-state".into()),
        )
        .await?;
    let read = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_READ,
            map_value([("id", Value::string("acme".into()))]),
        )?,
    )
    .await?;
    let read = output_value(read)?;
    ensure!(
        read.as_map()
            .and_then(|m| m.get("definition"))
            .and_then(Value::as_map)
            .and_then(|m| m.get("id"))
            .and_then(Value::as_str)
            == Some("acme")
    );
    ensure!(
        read.as_map()
            .and_then(|m| m.get("installation_epoch"))
            .and_then(Value::as_int)
            == Some(i64::try_from(installed.installation_epoch)?)
    );
    let list = dispatch_call(
        &mut sess,
        &principal,
        call(ACTION_EXTERNAL_INSTALLATION_LIST, map_value([]))?,
    )
    .await?;
    ensure!(
        matches!(output_value(list)?.as_map().and_then(|m| m.get("entries")).map(Value::view), Some(ValueView::List(rows)) if rows.len() == 1)
    );

    let conflict = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_UNINSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("expected_version", Value::integer(0)),
                (
                    "expected_installation_epoch",
                    Value::integer(i64::try_from(installed.installation_epoch)?),
                ),
            ]),
        )?,
    )
    .await;
    ensure!(
        matches!(
            conflict.as_ref().map_err(ConsoleError::kind),
            Err(ConsoleError::Mgmt(MgmtError::InstallationConflict {
                current: Some(revision),
                ..
            })) if *revision == installed.revision()
        ),
        "stale uninstall returned {conflict:?}"
    );
    dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_UNINSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("expected_version", Value::integer(1)),
                (
                    "expected_installation_epoch",
                    Value::integer(i64::try_from(installed.installation_epoch)?),
                ),
            ]),
        )?,
    )
    .await?;
    ensure!(
        st.source_management
            .as_ref()
            .context("catalog")?
            .load_installation("acme")
            .await?
            .is_none()
    );
    let read = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_READ,
            map_value([("id", Value::string("acme".into()))]),
        )?,
    )
    .await?;
    ensure!(output_value(read)? == Value::null());
    dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("def", definition),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await?;
    let reinstalled = st
        .source_management
        .as_ref()
        .context("catalog")?
        .load_installation("acme")
        .await?
        .context("reinstalled record")?;
    ensure!(reinstalled.installation_epoch != installed.installation_epoch);
    let stale = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_UNINSTALL,
            map_value([
                ("id", Value::string("acme".into())),
                ("expected_version", Value::integer(1)),
                (
                    "expected_installation_epoch",
                    Value::integer(i64::try_from(installed.installation_epoch)?),
                ),
            ]),
        )?,
    )
    .await;
    ensure!(matches!(
        stale.as_ref().map_err(ConsoleError::kind),
        Err(ConsoleError::Mgmt(MgmtError::InstallationConflict {
            current: Some(revision),
            ..
        })) if *revision == reinstalled.revision()
    ));
    ensure!(
        st.source_management
            .as_ref()
            .context("catalog")?
            .load_installation("acme")
            .await?
            == Some(reinstalled)
    );
    Ok(())
}

#[tokio::test]
async fn external_lifecycle_actions_require_installed_declaration() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());

    let stop = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_STOP,
            map_value([("id", Value::string("missing".into()))]),
        )?,
    )
    .await;
    ensure!(
        matches!(stop.as_ref().map_err(ConsoleError::kind), Err(ConsoleError::Operation(message)) if message.contains("unknown proc id")),
        "stop must reach proc kill even after an installation is retired: {stop:?}"
    );

    let before_revoke = fact_count(&st)?;
    let revoke = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_REVOKE,
            map_value([("installation_id", Value::string("missing".into()))]),
        )?,
    )
    .await;
    ensure!(
        matches!(revoke.as_ref().map_err(ConsoleError::kind), Err(ConsoleError::BadRequest(message)) if message == "external installation is not installed"),
        "missing external installation revoke was not rejected"
    );
    ensure!(
        fact_count(&st)? == before_revoke,
        "rejected revoke must not create mutation audit records"
    );

    let before_bad_floor = fact_count(&st)?;
    let bad_floor = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_EXTERNAL_INSTALLATION_REVOKE,
            map_value([
                ("installation_id", Value::string("missing".into())),
                ("credential_generation_floor", Value::integer(0)),
            ]),
        )?,
    )
    .await;
    ensure!(
        matches!(bad_floor.as_ref().map_err(ConsoleError::kind), Err(ConsoleError::BadRequest(message)) if message == "credential_generation_floor must be at least 1"),
        "invalid credential_generation_floor was not rejected"
    );
    ensure!(
        fact_count(&st)? == before_bad_floor,
        "invalid generation must not create mutation audit records"
    );
    ensure!(audit_outcomes(&st, "console_mutation")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn inference_backend_action_validates_admission_before_state_write() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());

    dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_INFERENCE_BACKEND_WRITE_CAS,
            map_value([
                ("id", Value::string("deepseek".into())),
                ("def", inference_backend("deepseek")?),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await?;
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_INFERENCE_BACKEND_READ,
            map_value([("id", Value::string("deepseek".into()))]),
        )?,
    )
    .await?;
    ensure!(
        matches!((output_value(out)?).view(), ValueView::Map(_)),
        "inference backend read did not return a map"
    );

    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_INFERENCE_BACKEND_WRITE_CAS,
            map_value([
                ("id", Value::string("other".into())),
                ("def", inference_backend("deepseek")?),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("mismatched inference backend unexpectedly passed admission"),
        Err(err) => err,
    };
    ensure!(
        matches!(err.kind(), ConsoleError::Mgmt(MgmtError::Admission(_))),
        "unexpected inference admission error: {err:?}"
    );
    ensure!(
        st.state
            .read(&Path::parse("state://kernel/inference/backends/other")?)
            .await?
            .is_none(),
        "mismatched inference backend was written"
    );

    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_CONFIG_WRITE_CAS,
            map_value([
                (
                    "path",
                    Value::string("state://kernel/inference/backends/other".into()),
                ),
                ("value", inference_backend("deepseek")?),
                ("expected_version", Value::null()),
            ]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("generic config write unexpectedly accepted inference path"),
        Err(err) => err,
    };
    ensure!(
        matches!(err.kind(), ConsoleError::BadRequest(message) if message == "management path must use its dedicated console action"),
        "unexpected generic config write error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn visibility_read_allows_root_business_state_after_step_up() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    st.state
        .write_set(
            &Path::parse("state://chat/source/messages/1")?,
            Value::string("hello from chat".into()),
        )
        .await?;
    let before = fact_count(&st)?;
    let mut sess = test_session(st.clone(), principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://chat/source/messages/1".into()),
            )]),
        )?,
    )
    .await?;
    ensure!(
        output_value(out)? == Value::string("hello from chat".into()),
        "visibility read returned unexpected value"
    );
    let after = fact_count(&st)?;
    ensure!(
        after > before,
        "visibility read must execute through Operation/Fact, not backend side channel"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_principal_identity_rejects_visibility_without_root_fallback()
-> anyhow::Result<()> {
    let st = console_state()?;
    st.state
        .write_set(
            &Path::parse("state://chat/source/messages/1")?,
            Value::string("hello from chat".into()),
        )
        .await?;
    let before = st.boot.kernel().processes().all_ids().len();
    let mut principal = root_principal()?;
    principal.identity_path = "not-a-path".into();
    let mut sess = test_session(st.clone(), principal.clone());

    let err = match dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://chat/source/messages/1".into()),
            )]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("visibility read unexpectedly accepted malformed principal"),
        Err(err) => err,
    };

    ensure!(
        matches!(err, ConsoleError::InvalidPrincipalIdentity(_)),
        "unexpected malformed principal error: {err:?}"
    );
    ensure!(
        st.boot.kernel().processes().all_ids().len() == before,
        "malformed console principals must not fall back to root or spawn a process"
    );

    let mut wildcard_principal = root_principal()?;
    wildcard_principal.identity_path = "identity://console/**".into();
    let mut sess = test_session(st.clone(), wildcard_principal.clone());
    let err = match dispatch_call(
        &mut sess,
        &wildcard_principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://chat/source/messages/1".into()),
            )]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("visibility read unexpectedly accepted wildcard principal"),
        Err(err) => err,
    };

    ensure!(
        matches!(err, ConsoleError::InvalidPrincipalIdentity(_)),
        "unexpected wildcard principal error: {err:?}"
    );
    ensure!(
        st.boot.kernel().processes().all_ids().len() == before,
        "wildcard console principals must not spawn a process"
    );
    Ok(())
}

#[tokio::test]
async fn visibility_rejects_vault_and_requires_justification() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://chat/source/messages/1".into()),
            )]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("visibility read without justification unexpectedly succeeded"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected missing-justification error: {err:?}"
    );

    let err = match dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("state://vault/console/root/password".into()),
            )]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("vault visibility read unexpectedly succeeded"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected vault visibility error: {err:?}"
    );

    let err = match dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_VISIBILITY_STATE_READ,
            map_value([(
                "path",
                Value::string("path://remote/state/chat/source/messages/1".into()),
            )]),
        )?,
    )
    .await
    {
        Ok(_) => bail!("clustered visibility read unexpectedly succeeded"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected clustered visibility error: {err:?}"
    );
    let outcomes = audit_outcomes(&st, "console_visibility")?;
    ensure!(
        outcomes
            .iter()
            .any(|outcome| outcome == "state_read_blocked"),
        "missing state_read_blocked audit outcome"
    );
    let visibility_facts = st
        .boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .filter(|fact| match &fact.outcome {
            Some(value) => {
                value
                    .as_map()
                    .and_then(|m| m.get("event"))
                    .and_then(Value::as_str)
                    == Some("console_visibility")
            }
            _ => false,
        })
        .map(|fact| Ok(serde_json::to_string(&fact)?))
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(
        visibility_facts
            .iter()
            .any(|fact| fact.contains("state://vault/**")),
        "visibility audit did not include redacted vault scope"
    );
    ensure!(
        !visibility_facts
            .iter()
            .any(|fact| fact.contains("state://vault/console/root/password")),
        "visibility audit leaked concrete vault path"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_action_input_is_rejected() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let mut sess = test_session(st, principal.clone());
    let err = match dispatch_call(
        &mut sess,
        &principal,
        ActionCall {
            action: ACTION_CONFIG_READ.into(),
            input: Value::string("not-a-map".into()),
            ..Default::default()
        },
    )
    .await
    {
        Ok(_) => bail!("non-map action input unexpectedly accepted"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected malformed input error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn process_metadata_does_not_read_fact_storage() -> anyhow::Result<()> {
    let facts = xolotl_kernel::FactSink::new(Arc::new(FailingFactStore::default()));
    let backend: xolotl_state::Backend = xolotl_state::InMemoryBackend::new().into_backend();
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(backend)
            .with_fact_sink(facts)
            .build(),
    ));
    let state = ConsoleState::shared(
        boot,
        std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
            crate::session_store::ConsoleSessionPolicy::default(),
        )),
    )
    .context("console state")?;
    let mut principal = root_principal()?;
    principal.grants =
        xolotl_types::CapSet::from_strs(["perform://effect/kernel/process/inspect"])?;
    let sess = test_session(state, principal.clone());
    let output = actions::process_inspect(
        &sess.action_context(),
        &principal,
        map_value([("process", Value::string("7".into()))]),
    )
    .await?;
    let Some(rows) = output
        .as_map()
        .and_then(|m| m.get("entries"))
        .and_then(Value::as_list)
    else {
        bail!("expected process rows");
    };
    let row = rows
        .first()
        .and_then(Value::as_map)
        .context("process row")?;
    ensure!(!row.contains_key("fact_count") && !row.contains_key("recent_facts"));
    ensure!(matches!(
        actions::process_inspect(
            &sess.action_context(),
            &principal,
            map_value([
                ("process", Value::string("7".into())),
                ("include_recent_facts", Value::boolean(true))
            ])
        )
        .await,
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    ));
    Ok(())
}

#[tokio::test]
async fn embedded_recent_facts_require_the_requested_fact_scope() -> anyhow::Result<()> {
    let state = console_state()?;
    let mut principal = root_principal()?;
    principal.identity_path = "identity://console/accounts/reader-account".into();
    principal.grants = xolotl_types::CapSet::from_strs([
        "perform://effect/kernel/process/inspect",
        "read://state/fact/7",
    ])?;
    let mut sess = test_session(state, principal.clone());
    let output = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(
            ACTION_RUNTIME_PROCESS_INSPECT,
            map_value([
                ("process", Value::string("7".into())),
                ("include_recent_facts", Value::boolean(true)),
            ]),
        )?,
    )
    .await?;
    let output = output_value(output)?;
    let Some(rows) = output
        .as_map()
        .and_then(|m| m.get("entries"))
        .and_then(Value::as_list)
    else {
        bail!("expected process rows");
    };
    let row = rows
        .first()
        .and_then(Value::as_map)
        .context("process row")?;
    ensure!(
        matches!(row.get("recent_facts").map(Value::view), Some(ValueView::Map(page)) if page.contains_key("next") && page.contains_key("items"))
    );
    ensure!(matches!(
        actions::process_inspect(
            &sess.action_context(),
            &principal,
            map_value([("include_recent_facts", Value::boolean(true))])
        )
        .await,
        Err(ConsoleError::BadRequest(_))
    ));
    ensure!(matches!(
        actions::process_inspect(
            &sess.action_context(),
            &principal,
            map_value([
                ("process", Value::string("8".into())),
                ("include_recent_facts", Value::boolean(true))
            ])
        )
        .await,
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    ));
    let snapshot = visibility_call(
        ACTION_STATE_SNAPSHOT,
        map_value([(
            "sections",
            Value::list(vec![map_value([
                ("kind", Value::string("runtime".into())),
                ("process", Value::string("8".into())),
                ("include_recent_facts", Value::boolean(true)),
            ])]),
        )]),
    )?;
    ensure!(matches!(
        dispatch_call(&mut sess, &principal, snapshot).await,
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    ));
    Ok(())
}

#[tokio::test]
async fn snapshot_runtime_facts_require_visibility_gate() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, principal, password) = root_login(&st).await?;
    let mut sess = test_session(st.clone(), principal.clone());
    let out = dispatch_call(
        &mut sess,
        &principal,
        call(
            ACTION_STATE_SNAPSHOT,
            map_value([(
                "sections",
                Value::list(vec![map_value([("kind", Value::string("runtime".into()))])]),
            )]),
        )?,
    )
    .await?;
    let Some(row) = (output_value(out)?).into_map() else {
        bail!("expected map");
    };
    ensure!(
        matches!(
            row.get("server_rev").map(Value::view),
            Some(ValueView::Int(_))
        ),
        "snapshot missing server_rev"
    );
    ensure!(
        matches!(
            row.get("registry_rev").map(Value::view),
            Some(ValueView::Int(_))
        ),
        "snapshot missing registry_rev"
    );
    ensure!(
        matches!(
            row.get("fact_cursor").map(Value::view),
            Some(ValueView::Str(_))
        ),
        "snapshot missing fact_cursor"
    );
    ensure!(
        matches!(
            row.get("truncated").map(Value::view),
            Some(ValueView::List(_))
        ),
        "snapshot missing truncated list"
    );

    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st, principal.clone());
    let input = map_value([(
        "sections",
        Value::list(vec![map_value([
            ("kind", Value::string("runtime".into())),
            ("process", Value::string("7".into())),
            ("include_recent_facts", Value::boolean(true)),
        ])]),
    )]);
    let err = match dispatch_call(
        &mut sess,
        &principal,
        call(ACTION_STATE_SNAPSHOT, input.clone())?,
    )
    .await
    {
        Ok(_) => bail!("runtime snapshot with recent facts bypassed visibility gate"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected snapshot visibility error: {err:?}"
    );

    let out = dispatch_call(
        &mut sess,
        &principal,
        visibility_call(ACTION_STATE_SNAPSHOT, input)?,
    )
    .await?;
    ensure!(
        matches!((output_value(out)?).view(), ValueView::Map(_)),
        "visibility-gated snapshot output was not a map"
    );
    let runtime = map_value([
        ("kind", Value::string("runtime".into())),
        ("process", Value::string("7".into())),
        ("include_recent_facts", Value::boolean(true)),
    ]);
    let duplicate = visibility_call(
        ACTION_STATE_SNAPSHOT,
        map_value([("sections", Value::list(vec![runtime.clone(), runtime]))]),
    )?;
    ensure!(matches!(
        dispatch_call(&mut sess, &principal, duplicate).await,
        Err(ConsoleError::BadRequest(message)) if message.contains("only once")
    ));
    Ok(())
}

#[tokio::test]
async fn subscription_rejects_duplicate_id_and_invalid_ttl_without_replacing_existing_subscription()
-> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st, principal.clone());
    let (_source, receiver) = tokio::sync::broadcast::channel(1);
    sess.subscriptions
        .replace(
            7,
            receiver,
            subscriptions::state_event,
            "state",
            tokio::time::Instant::now() + Duration::from_secs(60),
            None,
        )
        .await?;

    let err = match subscribe(
        &mut sess,
        &principal,
        7,
        StreamCall {
            stream: STREAM_STATE_WATCH.into(),
            input: json_bytes(&map_value([(
                "pattern",
                Value::string("state://kernel/**".into()),
            )]))?,
            scope: Some("test".into()),
            justification: Some("test stream".into()),
            ttl_ms: Some(60_000),
            registry_rev: None,
        },
    )
    .await
    {
        Ok(_) => bail!("duplicate subscription unexpectedly replaced existing subscription"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected duplicate subscription error: {err:?}"
    );
    ensure!(
        sess.subscriptions.contains(7),
        "failed duplicate subscription removed existing subscription"
    );
    for ttl_ms in [None, Some(0), Some(u64::MAX)] {
        let result = subscribe(
            &mut sess,
            &principal,
            8,
            StreamCall {
                stream: STREAM_STATE_WATCH.into(),
                input: map_value([("pattern", Value::string("state://kernel/**".into()))]),
                scope: Some("test".into()),
                justification: Some("test stream".into()),
                ttl_ms,
                registry_rev: None,
            },
        )
        .await;
        ensure!(matches!(result, Err(ConsoleError::BadRequest(_))));
        ensure!(sess.subscriptions.contains(7) && _source.receiver_count() == 1);
    }
    sess.subscriptions.stop(7).await?;
    Ok(())
}

#[tokio::test]
async fn subscription_rejects_vault_or_global_state_patterns() -> anyhow::Result<()> {
    let st = console_state()?;
    let (token, _principal, password) = root_login(&st).await?;
    let principal = step_up_principal(&st, &token, password).await?;
    let mut sess = test_session(st, principal.clone());
    let err = match subscribe(
        &mut sess,
        &principal,
        1,
        StreamCall {
            stream: STREAM_STATE_WATCH.into(),
            input: json_bytes(&map_value([(
                "pattern",
                Value::string("state://vault/**".into()),
            )]))?,
            scope: Some("test".into()),
            justification: Some("test stream".into()),
            ttl_ms: Some(60_000),
            registry_rev: None,
        },
    )
    .await
    {
        Ok(_) => bail!("vault subscription pattern unexpectedly succeeded"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected vault subscription error: {err:?}"
    );

    let err = match subscribe(
        &mut sess,
        &principal,
        2,
        StreamCall {
            stream: STREAM_STATE_WATCH.into(),
            input: json_bytes(&map_value([(
                "pattern",
                Value::string("state://**".into()),
            )]))?,
            scope: Some("test".into()),
            justification: Some("test stream".into()),
            ttl_ms: Some(60_000),
            registry_rev: None,
        },
    )
    .await
    {
        Ok(_) => bail!("global state subscription pattern unexpectedly succeeded"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::BadRequest(_)),
        "unexpected global subscription error: {err:?}"
    );
    Ok(())
}

#[test]
fn origin_host_and_port_must_match_by_default() -> anyhow::Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "console.local:9443".parse()?);
    headers.insert(header::ORIGIN, "https://console.local:9443".parse()?);
    let cfg = crate::http::console_transport_default();
    validate_upgrade_headers(&headers, None, &cfg).map_err(|message| anyhow::anyhow!(message))?;
    headers.insert(header::ORIGIN, "https://console.local:8080".parse()?);
    ensure!(
        validate_upgrade_headers(&headers, None, &cfg).is_err(),
        "origin port mismatch was accepted"
    );
    headers.insert(header::ORIGIN, "https://attacker.local:9443".parse()?);
    ensure!(
        validate_upgrade_headers(&headers, None, &cfg).is_err(),
        "origin host mismatch was accepted"
    );
    Ok(())
}

#[test]
fn ignore_origin_port_relaxation_allows_only_port_mismatch() -> anyhow::Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "console.local:9443".parse()?);
    headers.insert(header::ORIGIN, "https://console.local:8080".parse()?);
    let cfg = ConsoleTransportSecurityConfig {
        unsafe_relaxations: vec![ConsoleUnsafeTransportRelaxation::IgnoreOriginPort],
        ..ConsoleTransportSecurityConfig::default()
    };
    validate_upgrade_headers(&headers, None, &cfg).map_err(|message| anyhow::anyhow!(message))?;
    headers.insert(header::ORIGIN, "https://attacker.local:8080".parse()?);
    ensure!(
        validate_upgrade_headers(&headers, None, &cfg).is_err(),
        "origin host mismatch was accepted by port relaxation"
    );
    Ok(())
}

#[test]
fn trusted_proxy_uses_forwarded_external_host() -> anyhow::Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "127.0.0.1:9000".parse()?);
    headers.insert(header::ORIGIN, "https://console.example.com".parse()?);
    headers.insert("x-forwarded-host", "console.example.com".parse()?);
    headers.insert("x-forwarded-proto", "https".parse()?);
    let proxy_ip = "127.0.0.1".parse()?;
    let cfg = ConsoleTransportSecurityConfig {
        mode: ConsoleTransportSecurityMode::TrustedReverseProxy,
        trusted_proxy: ConsoleTrustedProxyConfig {
            peers: vec![proxy_ip],
            ..ConsoleTrustedProxyConfig::default()
        },
        unsafe_relaxations: Vec::new(),
    };
    let peer = SocketAddr::new(proxy_ip, 12345);
    validate_upgrade_headers(&headers, Some(peer), &cfg)
        .map_err(|message| anyhow::anyhow!(message))?;
    let untrusted_peer = SocketAddr::new("127.0.0.2".parse()?, 12345);
    ensure!(
        validate_upgrade_headers(&headers, Some(untrusted_peer), &cfg).is_err(),
        "untrusted proxy peer was accepted"
    );
    Ok(())
}

#[test]
fn invalid_origin_headers_are_rejected() -> anyhow::Result<()> {
    let cfg = crate::http::console_transport_default();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::HOST,
        axum::http::HeaderValue::from_static("console.local:9443"),
    );
    headers.insert(header::ORIGIN, invalid_header_value()?);
    let message = match validate_upgrade_headers(&headers, None, &cfg) {
        Ok(()) => bail!("invalid origin header was accepted"),
        Err(message) => message,
    };
    ensure!(
        message.contains("origin header is malformed"),
        "unexpected invalid origin message: {message}"
    );

    headers.insert(
        header::ORIGIN,
        axum::http::HeaderValue::from_static("https://console.local:9443"),
    );
    headers.insert(header::HOST, invalid_header_value()?);
    let message = match validate_upgrade_headers(&headers, None, &cfg) {
        Ok(()) => bail!("invalid host header was accepted"),
        Err(message) => message,
    };
    ensure!(
        message.contains("host header is malformed"),
        "unexpected invalid host message: {message}"
    );

    headers.insert(
        header::HOST,
        axum::http::HeaderValue::from_static("console.local:999999"),
    );
    let message = match validate_upgrade_headers(&headers, None, &cfg) {
        Ok(()) => bail!("invalid host port was accepted"),
        Err(message) => message,
    };
    ensure!(
        message.contains("host header is malformed"),
        "unexpected invalid host port message: {message}"
    );
    Ok(())
}

#[test]
fn invalid_forwarded_headers_are_rejected() -> anyhow::Result<()> {
    let proxy_ip = std::net::IpAddr::from([127, 0, 0, 1]);
    let peer = SocketAddr::new(proxy_ip, 12345);
    let cfg = ConsoleTransportSecurityConfig {
        mode: ConsoleTransportSecurityMode::TrustedReverseProxy,
        trusted_proxy: ConsoleTrustedProxyConfig {
            peers: vec![proxy_ip],
            ..ConsoleTrustedProxyConfig::default()
        },
        unsafe_relaxations: Vec::new(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::HOST,
        axum::http::HeaderValue::from_static("127.0.0.1:9000"),
    );
    headers.insert(
        header::ORIGIN,
        axum::http::HeaderValue::from_static("https://console.example.com"),
    );
    headers.insert("x-forwarded-host", invalid_header_value()?);
    headers.insert(
        "x-forwarded-proto",
        axum::http::HeaderValue::from_static("https"),
    );
    let message = match validate_upgrade_headers(&headers, Some(peer), &cfg) {
        Ok(()) => bail!("invalid forwarded host header was accepted"),
        Err(message) => message,
    };
    ensure!(
        message.contains("x-forwarded-host header is malformed"),
        "unexpected forwarded host message: {message}"
    );

    headers.insert(
        "x-forwarded-host",
        axum::http::HeaderValue::from_static("console.example.com"),
    );
    headers.insert("x-forwarded-proto", invalid_header_value()?);
    let message = match validate_upgrade_headers(&headers, Some(peer), &cfg) {
        Ok(()) => bail!("invalid forwarded proto header was accepted"),
        Err(message) => message,
    };
    ensure!(
        message.contains("x-forwarded-proto header is malformed"),
        "unexpected forwarded proto message: {message}"
    );

    headers.insert(
        "x-forwarded-proto",
        axum::http::HeaderValue::from_static("ftp"),
    );
    let message = match validate_upgrade_headers(&headers, Some(peer), &cfg) {
        Ok(()) => bail!("unsupported forwarded proto header was accepted"),
        Err(message) => message,
    };
    ensure!(
        message.contains("x-forwarded-proto header is unsupported"),
        "unexpected unsupported forwarded proto message: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn recipe_state_write_commits_without_implicit_call_facts() -> anyhow::Result<()> {
    let st = console_state()?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "root".into(),
        account_id: "root-account".into(),
        identity_path: "identity://console/accounts/root-account".into(),
        grants: xolotl_types::CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let sess = test_session(st.clone(), principal.clone());

    let before = st.boot.kernel().facts().cursor();
    let path = Path::parse("state://chat/source/messages/recipe_probe")?;
    let compiled = recipes::CompiledRecipe::state(
        path.clone(),
        RecipeStateMethod::Append,
        Value::string("probe-value".into()),
    )
    .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
    recipes::execute(&sess.adapter.console, &principal, compiled)
        .await
        .context("recipe execute")?;

    let after = st.boot.kernel().facts().cursor();
    ensure!(
        after == before,
        "recipe write recorded an implicit call fact"
    );
    ensure!(
        st.boot.kernel().state().read(&path).await?
            == Some(Value::list(vec![Value::string("probe-value".into())])),
        "recipe write did not commit its value"
    );
    Ok(())
}

#[tokio::test]
async fn recipe_denies_principal_without_matching_grant() -> anyhow::Result<()> {
    let st = console_state()?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "limited".into(),
        account_id: "limited-account".into(),
        identity_path: "identity://console/accounts/limited-account".into(),
        grants: xolotl_types::CapSet::from_strs(["read://state/other/**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let sess = test_session(st.clone(), principal.clone());
    let before = st.boot.kernel().facts().cursor();

    let path = Path::parse("state://chat/source/messages/bridge_probe")?;
    let compiled = recipes::CompiledRecipe::state(path, RecipeStateMethod::Read, Value::null())
        .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
    let err = match recipes::execute(&sess.adapter.console, &principal, compiled).await {
        Ok(value) => bail!("read without matching principal grant succeeded: {value:?}"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::Auth(auth::AuthError::PermissionDenied)),
        "missing grant should fail at the principal bridge, got {err:?}"
    );
    ensure!(
        st.boot.kernel().facts().cursor() == before,
        "principal-bridge denial should not spawn or finalize a request process"
    );
    Ok(())
}

#[tokio::test]
async fn recipe_read_grant_cannot_write() -> anyhow::Result<()> {
    let st = console_state()?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "reader".into(),
        account_id: "reader-account".into(),
        identity_path: "identity://console/accounts/reader-account".into(),
        grants: xolotl_types::CapSet::from_strs(["read://state/chat/source/messages/**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let sess = test_session(st.clone(), principal.clone());
    let before = st.boot.kernel().facts().cursor();

    let path = Path::parse("state://chat/source/messages/bridge_write_probe")?;
    let compiled = recipes::CompiledRecipe::state(
        path,
        RecipeStateMethod::Append,
        Value::string("should-not-write".into()),
    )
    .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
    let err = match recipes::execute(&sess.adapter.console, &principal, compiled).await {
        Ok(value) => bail!("write with only read grant succeeded: {value:?}"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::Auth(auth::AuthError::PermissionDenied)),
        "write with read grant should fail at the principal bridge, got {err:?}"
    );
    ensure!(
        st.boot.kernel().facts().cursor() == before,
        "principal-bridge denial should not spawn or finalize a request process"
    );
    Ok(())
}

#[tokio::test]
async fn recipe_principal_grant_allows_state_read() -> anyhow::Result<()> {
    let st = console_state()?;
    let path = Path::parse("state://chat/source/messages/bridge_read_probe")?;
    st.boot
        .kernel()
        .state()
        .write_set(&path, Value::string("readable".into()))
        .await?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "reader".into(),
        account_id: "reader-account".into(),
        identity_path: "identity://console/accounts/reader-account".into(),
        grants: xolotl_types::CapSet::from_strs(["read://state/chat/source/messages/**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let sess = test_session(st, principal.clone());
    let compiled = recipes::CompiledRecipe::state(path, RecipeStateMethod::Read, Value::null())
        .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
    let value = recipes::execute(&sess.adapter.console, &principal, compiled)
        .await
        .context("read recipe with matching principal grant")?;
    ensure!(
        value == Value::string("readable".into()),
        "unexpected read recipe output: {value:?}"
    );
    Ok(())
}

#[tokio::test]
async fn recipe_effect_requires_perform_grant() -> anyhow::Result<()> {
    let st = console_state()?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "reader".into(),
        account_id: "reader-account".into(),
        identity_path: "identity://console/accounts/reader-account".into(),
        grants: xolotl_types::CapSet::from_strs(["read://state/**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let sess = test_session(st.clone(), principal.clone());
    let before = st.boot.kernel().facts().cursor();

    let path = Path::parse("effect://kernel/process/inspect")?;
    let compiled = recipes::CompiledRecipe::effect(path, Value::null())
        .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
    let err = match recipes::execute(&sess.adapter.console, &principal, compiled).await {
        Ok(value) => bail!("effect invoke without perform grant succeeded: {value:?}"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::Auth(auth::AuthError::PermissionDenied)),
        "effect without perform grant should fail at the principal bridge, got {err:?}"
    );
    ensure!(
        st.boot.kernel().facts().cursor() == before,
        "principal-bridge denial should not spawn or finalize a request process"
    );
    Ok(())
}

#[tokio::test]
async fn recipe_open_for_denial_returns_operation_error() -> anyhow::Result<()> {
    let st = console_state()?;
    let (_token, principal, _password) = root_login(&st).await?;
    let sess = test_session(st.clone(), principal.clone());

    // A path the root request grant does not cover: a reserved vault path.
    let path = Path::parse("state://vault/unreachable/recipe_probe")?;
    let compiled = recipes::CompiledRecipe::state(path, RecipeStateMethod::Read, Value::null())
        .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
    let err = match recipes::execute(&sess.adapter.console, &principal, compiled).await {
        Ok(value) => bail!("vault read should be denied by open_for, got {value:?}"),
        Err(err) => err,
    };
    ensure!(
        matches!(err, ConsoleError::Operation(ref m) if !m.is_empty()),
        "denied recipe should surface an operation error, got {err:?}"
    );
    Ok(())
}
