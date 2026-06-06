//! Console WebSocket management RPC (§24.3).
//!
//! This is the post-login management path. Frames are fixed bincode DTOs and
//! actions dispatch through the kernel/auth management surfaces, not through a
//! raw `{target, method, input}` shell.

use crate::auth::{self, ConsolePrincipal, SessionSummary};
use crate::mgmt::{self, MgmtError};
use crate::state::{
    ConsoleState, ConsoleWsLimit, HARD_MAX_WS_FACT_LIMIT, HARD_MAX_WS_FRAME_BYTES,
    HARD_MAX_WS_SUBSCRIPTIONS, HARD_MAX_WS_TRACE_LIMIT,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use nexus_graph::{DoNode, OperationTemplate};
use nexus_state::StateEvent;
use nexus_types::{
    ExtensionDef, IdentityRef, Outcome, OutputMode, Path, ProcSpec, ResourceName, RestartPolicy,
    TaintSet, Transport, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard()
    .with_little_endian()
    .with_variable_int_encoding();

pub async fn upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(st): State<Arc<ConsoleState>>,
) -> Response {
    if let Err(message) = validate_upgrade_headers(&headers) {
        return (StatusCode::FORBIDDEN, message).into_response();
    }
    let source_addr = crate::source_addr(&headers, Some(peer));
    if let Err(limit) = st.ws.try_acquire_source(&source_addr) {
        let message = ws_limit_message(limit);
        record_ws_audit(&st, None, Some(&source_addr), "rate_limited");
        return (StatusCode::TOO_MANY_REQUESTS, message).into_response();
    }
    let max_frame_bytes = st.ws.config().max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    ws.max_message_size(max_frame_bytes)
        .max_frame_size(max_frame_bytes)
        .on_upgrade(move |socket| session(socket, st, source_addr))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalSummary {
    pub username: String,
    pub identity_path: String,
    pub mfa_level: u8,
}

impl From<&ConsolePrincipal> for PrincipalSummary {
    fn from(p: &ConsolePrincipal) -> Self {
        Self {
            username: p.username.clone(),
            identity_path: p.identity_path.clone(),
            mfa_level: p.mfa_level,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClientFrame {
    Auth { token: String },
    Rpc { id: u64, action: ConsoleAction },
    Subscribe { id: u64, stream: ConsoleStream },
    Unsubscribe { id: u64 },
    Ping { nonce: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsoleAction {
    Snapshot {
        sections: Vec<SnapshotSection>,
        since_rev: Option<u64>,
    },
    ConfigRead {
        path: String,
    },
    ConfigList {
        prefix: String,
    },
    ConfigWriteCas {
        path: String,
        value: Value,
        expected_version: Option<u64>,
    },
    UserRead {
        username: String,
    },
    UserList,
    UserWriteCas {
        username: String,
        value: Value,
        expected_version: Option<u64>,
    },
    UserDisable {
        username: String,
        expected_version: Option<u64>,
    },
    RoleRead {
        role: String,
    },
    RoleList,
    RoleWriteCas {
        role: String,
        value: Value,
        expected_version: Option<u64>,
    },
    CurrentSessionLogout,
    SessionList,
    SessionRevoke {
        sid: String,
    },
    SessionRevokeUser {
        username: String,
    },
    ProcessInspect {
        process: Option<u64>,
        include_recent_facts: bool,
        limit: usize,
    },
    RecentFacts {
        process: Option<u64>,
        limit: usize,
    },
    TraceRead {
        process: u64,
        from: usize,
        limit: usize,
    },
    ExtensionInstall {
        id: String,
        def: Value,
        expected_version: Option<u64>,
    },
    ExtensionUpdate {
        id: String,
        def: Value,
        expected_version: Option<u64>,
    },
    ExtensionStart {
        id: String,
    },
    ExtensionStop {
        id: String,
    },
    ExtensionRevoke {
        extension_id: String,
        credential_generation_floor: Option<i64>,
    },
    PairingCreate {
        input: Value,
        reveal_display_secret: bool,
    },
    PairingApprove {
        pairing_id: String,
        approved_roles: Vec<String>,
    },
    PairingDeny {
        pairing_id: String,
    },
    PairingReplace {
        input: Value,
        reveal_display_secret: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum SnapshotSection {
    KernelConfig { prefix: String },
    Sessions,
    Runtime { limit: usize },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsoleStream {
    Config { pattern: String },
    Runtime { pattern: String },
    Audit { process: Option<u64> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServerFrame {
    Authenticated {
        principal: PrincipalSummary,
        server_rev: u64,
    },
    Reply {
        id: u64,
        result: ConsoleResult,
    },
    Event {
        stream: u64,
        event: ConsoleEvent,
    },
    Pong {
        nonce: u64,
    },
    Error {
        id: Option<u64>,
        code: ConsoleErrorCode,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConsoleResult {
    Empty,
    Value(Option<Value>),
    Entries(Vec<(String, Value)>),
    Snapshot(BTreeMap<String, Value>),
    Sessions(Vec<SessionSummary>),
    Revoked { count: usize },
}

impl Eq for ConsoleResult {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConsoleEvent {
    StateSet { path: String, value: Value },
    StateAppend { path: String, item: Value },
    StateDelete { path: String },
    Audit { fact: Value },
    SubscriptionClosed { reason: String },
}

impl Eq for ConsoleEvent {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsoleErrorCode {
    BadFrame,
    NotAuthenticated,
    Unauthorized,
    Forbidden,
    Conflict,
    BadRequest,
    RateLimited,
    Internal,
}

struct WsSession {
    state: Arc<ConsoleState>,
    principal: Option<ConsolePrincipal>,
    sid: Option<String>,
    source_addr: String,
    counted_user: Option<String>,
    subscriptions: BTreeMap<u64, SubscriptionHandle>,
    event_tx: mpsc::Sender<SubscriptionMessage>,
    rate: FrameRate,
}

struct SubscriptionHandle {
    shutdown: tokio::sync::oneshot::Sender<()>,
}

struct SubscriptionMessage {
    stream: u64,
    event: ConsoleEvent,
}

impl Drop for WsSession {
    fn drop(&mut self) {
        self.state.ws.release_source(&self.source_addr);
        if let Some(username) = self.counted_user.take() {
            self.state.ws.release_user(&username);
        }
    }
}

#[derive(Clone, Debug)]
struct FrameRate {
    window_started: Instant,
    frames: usize,
    bytes: usize,
}

impl Default for FrameRate {
    fn default() -> Self {
        Self {
            window_started: Instant::now(),
            frames: 0,
            bytes: 0,
        }
    }
}

impl FrameRate {
    fn observe(&mut self, bytes: usize, max_frames: usize, max_bytes: usize) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.frames = 0;
            self.bytes = 0;
        }
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        self.frames <= max_frames && self.bytes <= max_bytes
    }
}

async fn session(socket: WebSocket, state: Arc<ConsoleState>, source_addr: String) {
    let (mut tx, mut rx) = socket.split();
    let (event_tx, mut event_rx) = mpsc::channel::<SubscriptionMessage>(256);
    let mut sess = WsSession {
        state,
        principal: None,
        sid: None,
        source_addr,
        counted_user: None,
        subscriptions: BTreeMap::new(),
        event_tx,
        rate: FrameRate::default(),
    };
    let mut idle = Box::pin(tokio::time::sleep(sess.state.ws.config().idle_timeout));

    loop {
        tokio::select! {
            _ = &mut idle => {
                record_ws_audit(&sess.state, sess.principal.as_ref(), Some(&sess.source_addr), "idle_timeout");
                break;
            }
            msg = rx.next() => {
                idle.as_mut().reset(tokio::time::Instant::now() + sess.state.ws.config().idle_timeout);
                let Some(msg) = msg else { break };
                let Ok(msg) = msg else { break };
                let Some(reply) = receive_client_message(&mut sess, msg).await else {
                    break;
                };
                let close_after = should_close_after_reply(&sess, &reply);
                if send(&mut tx, reply).await.is_err() {
                    break;
                }
                if close_after {
                    break;
                }
            }
            Some(msg) = event_rx.recv() => {
                let Some(sid) = sess.sid.clone() else {
                    break;
                };
                match sess.state.auth.authenticate_sid(&sess.state.boot, &sid).await {
                    Ok(principal) => {
                        sess.principal = Some(principal);
                    }
                    Err(e) => {
                        record_ws_audit(&sess.state, sess.principal.as_ref(), Some(&sess.source_addr), "invalid_session");
                        let _ = send(&mut tx, auth_error_frame(None, e)).await;
                        break;
                    }
                }
                if send_with_timeout(
                    &mut tx,
                    ServerFrame::Event {
                        stream: msg.stream,
                        event: msg.event,
                    },
                    sess.state.ws.config().event_send_timeout,
                )
                .await
                .is_err()
                {
                    record_ws_audit(&sess.state, sess.principal.as_ref(), Some(&sess.source_addr), "backpressure_close");
                    break;
                }
            }
        }
    }

    for (_, handle) in std::mem::take(&mut sess.subscriptions) {
        let _ = handle.shutdown.send(());
    }
}

async fn receive_client_message(sess: &mut WsSession, msg: Message) -> Option<ServerFrame> {
    let msg_len = message_len(&msg);
    if !sess.rate.observe(
        msg_len,
        sess.state.ws.config().max_frames_per_second,
        sess.state.ws.config().max_bytes_per_second,
    ) {
        record_ws_audit(
            &sess.state,
            sess.principal.as_ref(),
            Some(&sess.source_addr),
            "rate_limited",
        );
        return Some(ServerFrame::Error {
            id: None,
            code: ConsoleErrorCode::RateLimited,
            message: "console websocket frame rate limit exceeded".into(),
        });
    }

    let frame = match msg {
        Message::Binary(bytes) => decode_frame(&bytes, sess.state.ws.config().max_frame_bytes),
        Message::Close(_) => return None,
        Message::Ping(_) | Message::Pong(_) => return Some(ServerFrame::Pong { nonce: 0 }),
        _ => {
            record_ws_audit(
                &sess.state,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "protocol_error",
            );
            return Some(ServerFrame::Error {
                id: None,
                code: ConsoleErrorCode::BadFrame,
                message: "console websocket only accepts binary bincode frames".into(),
            });
        }
    };
    let frame = match frame {
        Ok(frame) => frame,
        Err(message) => {
            record_ws_audit(
                &sess.state,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "protocol_error",
            );
            return Some(ServerFrame::Error {
                id: None,
                code: ConsoleErrorCode::BadFrame,
                message,
            });
        }
    };
    Some(handle_frame(sess, frame).await)
}

fn should_close_after_reply(sess: &WsSession, reply: &ServerFrame) -> bool {
    sess.sid.is_none()
        && (sess.counted_user.is_some()
            || matches!(
                reply,
                ServerFrame::Reply {
                    result: ConsoleResult::Empty,
                    ..
                } | ServerFrame::Error {
                    code: ConsoleErrorCode::Unauthorized | ConsoleErrorCode::Forbidden,
                    ..
                }
            ))
}

async fn handle_frame(sess: &mut WsSession, frame: ClientFrame) -> ServerFrame {
    match frame {
        ClientFrame::Auth { token } => match sess
            .state
            .auth
            .authenticate_token(&sess.state.boot, &token)
            .await
        {
            Ok(principal) => {
                let Some(sid) = bearer_sid(Some(&token)).map(str::to_string) else {
                    return ServerFrame::Error {
                        id: None,
                        code: ConsoleErrorCode::Unauthorized,
                        message: "invalid session".into(),
                    };
                };
                if let Err(limit) = sess
                    .state
                    .ws
                    .try_replace_user(sess.counted_user.as_deref(), &principal.username)
                {
                    record_ws_audit(
                        &sess.state,
                        Some(&principal),
                        Some(&sess.source_addr),
                        "rate_limited",
                    );
                    return ServerFrame::Error {
                        id: None,
                        code: ConsoleErrorCode::RateLimited,
                        message: ws_limit_message(limit),
                    };
                }
                let summary = PrincipalSummary::from(&principal);
                sess.counted_user = Some(principal.username.clone());
                sess.principal = Some(principal);
                sess.sid = Some(sid);
                ServerFrame::Authenticated {
                    principal: summary,
                    server_rev: sess.state.boot.kernel.facts.cursor(),
                }
            }
            Err(e) => {
                record_ws_audit(&sess.state, None, Some(&sess.source_addr), "auth_failed");
                auth_error_frame(None, e)
            }
        },
        ClientFrame::Ping { nonce } => ServerFrame::Pong { nonce },
        ClientFrame::Rpc { id, action } => {
            let principal = match authenticated_principal(sess, Some(id)).await {
                Ok(p) => p,
                Err(frame) => return frame,
            };
            match dispatch_action(sess, &principal, action).await {
                Ok(result) => ServerFrame::Reply { id, result },
                Err(e) => {
                    record_console_error_audit(
                        &sess.state,
                        Some(&principal),
                        Some(&sess.source_addr),
                        &e,
                    );
                    console_error_frame(Some(id), e)
                }
            }
        }
        ClientFrame::Subscribe { id, stream } => {
            let principal = match authenticated_principal(sess, None).await {
                Ok(p) => p,
                Err(frame) => return frame,
            };
            match subscribe(sess, &principal, id, stream).await {
                Ok(()) => ServerFrame::Reply {
                    id,
                    result: ConsoleResult::Empty,
                },
                Err(e) => {
                    record_console_error_audit(
                        &sess.state,
                        Some(&principal),
                        Some(&sess.source_addr),
                        &e,
                    );
                    console_error_frame(Some(id), e)
                }
            }
        }
        ClientFrame::Unsubscribe { id } => {
            if let Some(handle) = sess.subscriptions.remove(&id) {
                let _ = handle.shutdown.send(());
            }
            ServerFrame::Reply {
                id,
                result: ConsoleResult::Empty,
            }
        }
    }
}

async fn authenticated_principal(
    sess: &mut WsSession,
    id: Option<u64>,
) -> Result<ConsolePrincipal, ServerFrame> {
    let Some(sid) = sess.sid.clone() else {
        return Err(ServerFrame::Error {
            id,
            code: ConsoleErrorCode::NotAuthenticated,
            message: "not authenticated".into(),
        });
    };
    match sess
        .state
        .auth
        .authenticate_sid(&sess.state.boot, &sid)
        .await
    {
        Ok(p) => {
            sess.principal = Some(p.clone());
            Ok(p)
        }
        Err(e) => {
            record_ws_audit(
                &sess.state,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "invalid_session",
            );
            Err(auth_error_frame(id, e))
        }
    }
}

async fn dispatch_action(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    action: ConsoleAction,
) -> Result<ConsoleResult, ConsoleError> {
    match action {
        ConsoleAction::Snapshot {
            sections,
            since_rev,
        } => {
            let mut out = BTreeMap::new();
            out.insert(
                "server_rev".into(),
                Value::Int(sess.state.boot.kernel.facts.cursor() as i64),
            );
            if let Some(since_rev) = since_rev {
                out.insert("since_rev".into(), Value::Int(since_rev as i64));
            }
            for section in sections {
                match section {
                    SnapshotSection::KernelConfig { prefix } => {
                        let entries = mgmt::inspect_prefix(&sess.state, principal, &prefix).await?;
                        out.insert(prefix, entries_value(entries));
                    }
                    SnapshotSection::Sessions => {
                        let sessions = sess
                            .state
                            .auth
                            .list_sessions(&sess.state.boot, principal)
                            .await?;
                        out.insert("sessions".into(), sessions_value(&sessions));
                    }
                    SnapshotSection::Runtime { limit } => {
                        let runtime =
                            process_inspect(sess, principal, None, true, limit.min(64)).await?;
                        out.insert("runtime".into(), runtime);
                    }
                }
            }
            Ok(ConsoleResult::Snapshot(out))
        }
        ConsoleAction::ConfigRead { path } => {
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            Ok(ConsoleResult::Value(value))
        }
        ConsoleAction::ConfigList { prefix } => {
            let entries = mgmt::inspect_prefix(&sess.state, principal, &prefix).await?;
            Ok(ConsoleResult::Entries(entries))
        }
        ConsoleAction::ConfigWriteCas {
            path,
            value,
            expected_version,
        } => {
            require_config_write_safety(principal, &path)?;
            mgmt::write_config(&sess.state, principal, &path, value, expected_version).await?;
            Ok(ConsoleResult::Empty)
        }
        ConsoleAction::UserRead { username } => {
            auth::validate_username(&username)?;
            let value = mgmt::inspect(
                &sess.state,
                principal,
                &format!("state://kernel/console/users/{username}"),
            )
            .await?;
            Ok(ConsoleResult::Value(value))
        }
        ConsoleAction::UserList => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/console/users")
                    .await?;
            Ok(ConsoleResult::Entries(entries))
        }
        ConsoleAction::UserWriteCas {
            username,
            value,
            expected_version,
        } => {
            require_step_up(principal)?;
            auth::validate_username(&username)?;
            mgmt::write_config(
                &sess.state,
                principal,
                &format!("state://kernel/console/users/{username}"),
                value,
                expected_version,
            )
            .await?;
            Ok(ConsoleResult::Empty)
        }
        ConsoleAction::UserDisable {
            username,
            expected_version,
        } => {
            require_step_up(principal)?;
            auth::validate_username(&username)?;
            let path = format!("state://kernel/console/users/{username}");
            let Some(mut value) = mgmt::inspect(&sess.state, principal, &path).await? else {
                return Err(ConsoleError::BadRequest("unknown console user".into()));
            };
            match &mut value {
                Value::Map(m) => {
                    m.insert("status".into(), Value::Str("disabled".into()));
                }
                _ => {
                    return Err(ConsoleError::BadRequest(
                        "console user must be an object".into(),
                    ));
                }
            }
            mgmt::write_config(&sess.state, principal, &path, value, expected_version).await?;
            Ok(ConsoleResult::Empty)
        }
        ConsoleAction::RoleRead { role } => {
            auth::validate_username(&role)?;
            let value = mgmt::inspect(
                &sess.state,
                principal,
                &format!("state://kernel/console/roles/{role}"),
            )
            .await?;
            Ok(ConsoleResult::Value(value))
        }
        ConsoleAction::RoleList => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/console/roles")
                    .await?;
            Ok(ConsoleResult::Entries(entries))
        }
        ConsoleAction::RoleWriteCas {
            role,
            value,
            expected_version,
        } => {
            require_step_up(principal)?;
            auth::validate_username(&role)?;
            mgmt::write_config(
                &sess.state,
                principal,
                &format!("state://kernel/console/roles/{role}"),
                value,
                expected_version,
            )
            .await?;
            Ok(ConsoleResult::Empty)
        }
        ConsoleAction::CurrentSessionLogout => {
            let Some(sid) = sess.sid.take() else {
                return Err(ConsoleError::NotAuthenticated);
            };
            sess.state.auth.logout_sid(&sess.state.boot, &sid).await?;
            sess.principal = None;
            Ok(ConsoleResult::Empty)
        }
        ConsoleAction::SessionList => {
            let sessions = sess
                .state
                .auth
                .list_sessions(&sess.state.boot, principal)
                .await?;
            Ok(ConsoleResult::Sessions(sessions))
        }
        ConsoleAction::SessionRevoke { sid } => {
            require_step_up(principal)?;
            sess.state
                .auth
                .revoke_session_by_id(&sess.state.boot, principal, &sid)
                .await?;
            if sess.sid.as_deref() == Some(sid.as_str()) {
                sess.sid = None;
                sess.principal = None;
            }
            Ok(ConsoleResult::Revoked { count: 1 })
        }
        ConsoleAction::SessionRevokeUser { username } => {
            require_step_up(principal)?;
            let count = sess
                .state
                .auth
                .revoke_user_sessions(&sess.state.boot, principal, &username)
                .await?;
            if principal.username == username {
                sess.sid = None;
                sess.principal = None;
            }
            Ok(ConsoleResult::Revoked { count })
        }
        ConsoleAction::ProcessInspect {
            process,
            include_recent_facts,
            limit,
        } => {
            let value = process_inspect(
                sess,
                principal,
                process,
                include_recent_facts,
                bounded_limit(
                    limit,
                    sess.state.ws.config().max_fact_limit,
                    HARD_MAX_WS_FACT_LIMIT,
                ),
            )
            .await?;
            Ok(ConsoleResult::Value(Some(value)))
        }
        ConsoleAction::RecentFacts { process, limit } => {
            let value = recent_facts(
                sess,
                principal,
                process,
                bounded_limit(
                    limit,
                    sess.state.ws.config().max_fact_limit,
                    HARD_MAX_WS_FACT_LIMIT,
                ),
            )
            .await?;
            Ok(ConsoleResult::Value(Some(value)))
        }
        ConsoleAction::TraceRead {
            process,
            from,
            limit,
        } => {
            let value = trace_read(
                sess,
                principal,
                process,
                from,
                bounded_limit(
                    limit,
                    sess.state.ws.config().max_trace_limit,
                    HARD_MAX_WS_TRACE_LIMIT,
                ),
            )
            .await?;
            Ok(ConsoleResult::Value(Some(value)))
        }
        ConsoleAction::ExtensionInstall {
            id,
            def,
            expected_version,
        }
        | ConsoleAction::ExtensionUpdate {
            id,
            def,
            expected_version,
        } => {
            require_step_up(principal)?;
            validate_path_segment(&id, "extension id")?;
            mgmt::write_config(
                &sess.state,
                principal,
                &format!("state://kernel/extensions/{id}"),
                def,
                expected_version,
            )
            .await?;
            Ok(ConsoleResult::Empty)
        }
        ConsoleAction::ExtensionStart { id } => {
            require_step_up(principal)?;
            let spec = proc_spec_from_extension(sess, principal, &id).await?;
            let value = serde_json::from_value(serde_json::to_value(spec).map_err(|e| {
                ConsoleError::BadRequest(format!("proc spec serialization failed: {e}"))
            })?)
            .map_err(|e| ConsoleError::BadRequest(format!("proc spec conversion failed: {e}")))?;
            let out = invoke_effect(sess, principal, "effect://proc/spawn", value).await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
        ConsoleAction::ExtensionStop { id } => {
            require_step_up(principal)?;
            validate_path_segment(&id, "extension id")?;
            let out = invoke_effect(
                sess,
                principal,
                "effect://proc/kill",
                map_value([("id", Value::Str(id))]),
            )
            .await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
        ConsoleAction::ExtensionRevoke {
            extension_id,
            credential_generation_floor,
        } => {
            require_step_up(principal)?;
            validate_path_segment(&extension_id, "extension id")?;
            let mut m = BTreeMap::new();
            m.insert("extension_id".into(), Value::Str(extension_id));
            if let Some(floor) = credential_generation_floor {
                m.insert("credential_generation_floor".into(), Value::Int(floor));
            }
            let out =
                invoke_effect(sess, principal, "effect://extension/revoke", Value::Map(m)).await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
        ConsoleAction::PairingCreate {
            input,
            reveal_display_secret,
        } => {
            require_step_up(principal)?;
            let out = pairing_action(
                sess,
                principal,
                "effect://extension/pairing/create",
                input,
                reveal_display_secret,
            )
            .await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
        ConsoleAction::PairingApprove {
            pairing_id,
            approved_roles,
        } => {
            require_step_up(principal)?;
            validate_path_segment(&pairing_id, "pairing id")?;
            let out = invoke_effect(
                sess,
                principal,
                "effect://extension/pairing/approve",
                map_value([
                    ("pairing_id", Value::Str(pairing_id)),
                    (
                        "approved_roles",
                        Value::List(approved_roles.into_iter().map(Value::Str).collect()),
                    ),
                ]),
            )
            .await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
        ConsoleAction::PairingDeny { pairing_id } => {
            require_step_up(principal)?;
            validate_path_segment(&pairing_id, "pairing id")?;
            let out = invoke_effect(
                sess,
                principal,
                "effect://extension/pairing/deny",
                map_value([("pairing_id", Value::Str(pairing_id))]),
            )
            .await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
        ConsoleAction::PairingReplace {
            input,
            reveal_display_secret,
        } => {
            require_step_up(principal)?;
            let out = pairing_action(
                sess,
                principal,
                "effect://extension/pairing/replace",
                input,
                reveal_display_secret,
            )
            .await?;
            Ok(ConsoleResult::Value(Some(out)))
        }
    }
}

async fn subscribe(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    id: u64,
    stream: ConsoleStream,
) -> Result<(), ConsoleError> {
    let max_subscriptions = sess
        .state
        .ws
        .config()
        .max_subscriptions
        .min(HARD_MAX_WS_SUBSCRIPTIONS);
    if sess.subscriptions.len() >= max_subscriptions && !sess.subscriptions.contains_key(&id) {
        return Err(ConsoleError::RateLimited);
    }
    if let Some(handle) = sess.subscriptions.remove(&id) {
        let _ = handle.shutdown.send(());
    }

    match stream {
        ConsoleStream::Config { pattern } => {
            let pattern = Path::parse(&pattern)?;
            ensure_kernel_pattern(&pattern)?;
            auth::authorize_path(&sess.state.state, principal, "subscribe", &pattern, None).await?;
            let mut rx = sess.state.state.subscribe(&pattern).await?;
            let event_tx = sess.event_tx.clone();
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        ev = rx.recv() => {
                            let Ok(ev) = ev else { break };
                            let event = state_event(ev);
                            if event_tx.send(SubscriptionMessage { stream: id, event }).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            sess.subscriptions.insert(
                id,
                SubscriptionHandle {
                    shutdown: shutdown_tx,
                },
            );
            Ok(())
        }
        ConsoleStream::Runtime { pattern } => {
            let pattern = Path::parse(&pattern)?;
            ensure_kernel_pattern(&pattern)?;
            auth::authorize_path(&sess.state.state, principal, "subscribe", &pattern, None).await?;
            let mut rx = sess.state.state.subscribe(&pattern).await?;
            let event_tx = sess.event_tx.clone();
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        ev = rx.recv() => {
                            let Ok(ev) = ev else { break };
                            let event = state_event(ev);
                            if event_tx.send(SubscriptionMessage { stream: id, event }).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            sess.subscriptions.insert(
                id,
                SubscriptionHandle {
                    shutdown: shutdown_tx,
                },
            );
            Ok(())
        }
        ConsoleStream::Audit { process } => {
            authorize_fact_read(principal, process)?;
            let event_tx = sess.event_tx.clone();
            let state = sess.state.clone();
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let mut seen = 0usize;
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        _ = interval.tick() => {
                            let facts = state.boot.kernel.facts.all_facts();
                            for fact in facts.iter().skip(seen).filter(|fact| {
                                process.is_none_or(|pid| fact.caller.get() == pid)
                            }) {
                                if event_tx
                                    .send(SubscriptionMessage {
                                        stream: id,
                                        event: ConsoleEvent::Audit {
                                            fact: fact_value(fact.clone()),
                                        },
                                    })
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            seen = facts.len();
                        }
                    }
                }
            });
            sess.subscriptions.insert(
                id,
                SubscriptionHandle {
                    shutdown: shutdown_tx,
                },
            );
            Ok(())
        }
    }
}

async fn process_inspect(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    process: Option<u64>,
    include_recent_facts: bool,
    limit: usize,
) -> Result<Value, ConsoleError> {
    require_process_inspect(principal)?;
    let mut input = BTreeMap::new();
    if let Some(process) = process {
        input.insert("process".into(), Value::Int(process as i64));
    }
    input.insert(
        "include_recent_facts".into(),
        Value::Bool(include_recent_facts),
    );
    input.insert(
        "limit".into(),
        Value::Int(bounded_limit(
            limit,
            sess.state.ws.config().max_fact_limit,
            HARD_MAX_WS_FACT_LIMIT,
        ) as i64),
    );
    invoke_effect(
        sess,
        principal,
        "effect://kernel/process/inspect",
        Value::Map(input),
    )
    .await
}

async fn recent_facts(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    process: Option<u64>,
    limit: usize,
) -> Result<Value, ConsoleError> {
    authorize_fact_read(principal, process)?;
    let facts = sess
        .state
        .boot
        .kernel
        .facts
        .all_facts()
        .into_iter()
        .filter(|fact| process.is_none_or(|pid| fact.caller.get() == pid))
        .rev()
        .take(bounded_limit(
            limit,
            sess.state.ws.config().max_fact_limit,
            HARD_MAX_WS_FACT_LIMIT,
        ))
        .collect();
    Ok(facts_value(facts))
}

async fn trace_read(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    process: u64,
    from: usize,
    limit: usize,
) -> Result<Value, ConsoleError> {
    authorize_fact_read(principal, Some(process))?;
    let rows = sess
        .state
        .boot
        .kernel
        .facts
        .all_facts()
        .into_iter()
        .filter(|fact| fact.caller.get() == process)
        .skip(from)
        .take(bounded_limit(
            limit,
            sess.state.ws.config().max_trace_limit,
            HARD_MAX_WS_TRACE_LIMIT,
        ))
        .collect();
    Ok(facts_value(rows))
}

async fn pairing_action(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    effect: &str,
    input: Value,
    reveal_display_secret: bool,
) -> Result<Value, ConsoleError> {
    reject_secret_fields(&input)?;
    let mut out = invoke_effect(sess, principal, effect, input).await?;
    if reveal_display_secret {
        let pairing_id = out
            .as_map()
            .and_then(|m| m.get("pairing_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ConsoleError::Operation("pairing result has no pairing_id".into()))?;
        if let Some(secret) = sess.state.pairing_display.take_display_secret(&pairing_id) {
            match &mut out {
                Value::Map(m) => {
                    m.insert("display_secret".into(), Value::Str(secret));
                }
                _ => {
                    return Err(ConsoleError::Operation(
                        "pairing result is not an object".into(),
                    ));
                }
            }
        }
    }
    Ok(out)
}

async fn proc_spec_from_extension(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    id: &str,
) -> Result<ProcSpec, ConsoleError> {
    validate_path_segment(id, "extension id")?;
    let path = format!("state://kernel/extensions/{id}");
    let value = mgmt::inspect(&sess.state, principal, &path)
        .await?
        .ok_or_else(|| ConsoleError::BadRequest("extension is not installed".into()))?;
    let json = serde_json::to_value(&value)
        .map_err(|e| ConsoleError::BadRequest(format!("ExtensionDef serialization failed: {e}")))?;
    let def: ExtensionDef = serde_json::from_value(json)
        .map_err(|e| ConsoleError::BadRequest(format!("ExtensionDef is malformed: {e}")))?;
    if def.id != id {
        return Err(ConsoleError::BadRequest(
            "ExtensionDef id does not match requested extension id".into(),
        ));
    }
    def.validate_admission()
        .map_err(|e| ConsoleError::BadRequest(format!("ExtensionDef admission failed: {e}")))?;
    let command = match &def.transport {
        Transport::Stdio { command, args } => command.as_ref().map(|cmd| {
            std::iter::once(cmd.clone())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>()
        }),
        _ => None,
    };
    Ok(ProcSpec {
        id: def.id,
        transport: def.transport,
        command,
        env: BTreeMap::new(),
        cwd: None,
        restart: RestartPolicy::default(),
    })
}

async fn invoke_effect(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    effect: &str,
    input: Value,
) -> Result<Value, ConsoleError> {
    let path = Path::parse(effect)?;
    auth::authorize_path(&sess.state.state, principal, "perform", &path, Some(&input)).await?;
    let identity = Path::parse(&principal.identity_path)
        .ok()
        .map(|p| nexus_kernel::intern_identity(&p))
        .unwrap_or(IdentityRef::ROOT);
    let process = sess.state.boot.spawn_request_process(
        identity,
        &[&format!("perform://{}", capability_target(&path))],
    );
    let target = ResourceName::new(path);
    let handle = sess
        .state
        .boot
        .open_for(process, &target, "perform")
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    let ex = sess.state.boot.kernel.executor_for(process);
    ex.bind_handle(target.clone(), handle);
    let op = DoNode::Op(OperationTemplate {
        target,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(input),
    });
    match ex.eval_tainted(&op, TaintSet::author()).await {
        Outcome::Done(v) | Outcome::Short(v) => Ok(v),
        Outcome::Fail(f) => Err(ConsoleError::Operation(f.to_string())),
    }
}

fn decode_frame(bytes: &[u8], configured_max_frame_bytes: usize) -> Result<ClientFrame, String> {
    let max_frame_bytes = configured_max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    if bytes.len() > max_frame_bytes {
        return Err("frame exceeds console websocket limit".into());
    }
    let (frame, used) = bincode::serde::decode_from_slice(bytes, BINCODE_CONFIG)
        .map_err(|e| format!("bad bincode frame: {e}"))?;
    if used != bytes.len() {
        return Err("bad bincode frame: trailing bytes".into());
    }
    Ok(frame)
}

fn bounded_limit(requested: usize, configured: usize, hard: usize) -> usize {
    requested.min(configured).min(hard)
}

async fn send<S>(tx: &mut S, frame: ServerFrame) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    let bytes = bincode::serde::encode_to_vec(&frame, BINCODE_CONFIG).map_err(|_| ())?;
    tx.send(Message::Binary(bytes.into())).await.map_err(|_| ())
}

async fn send_with_timeout<S>(tx: &mut S, frame: ServerFrame, timeout: Duration) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    tokio::time::timeout(timeout, send(tx, frame))
        .await
        .map_err(|_| ())?
}

fn message_len(msg: &Message) -> usize {
    match msg {
        Message::Text(s) => s.len(),
        Message::Binary(bytes) => bytes.len(),
        Message::Ping(bytes) | Message::Pong(bytes) => bytes.len(),
        Message::Close(_) => 0,
    }
}

#[derive(Debug)]
enum ConsoleError {
    Auth(auth::AuthError),
    Mgmt(MgmtError),
    NotAuthenticated,
    RateLimited,
    BadRequest(String),
    Operation(String),
}

impl From<auth::AuthError> for ConsoleError {
    fn from(e: auth::AuthError) -> Self {
        Self::Auth(e)
    }
}

impl From<MgmtError> for ConsoleError {
    fn from(e: MgmtError) -> Self {
        Self::Mgmt(e)
    }
}

impl From<nexus_types::PathError> for ConsoleError {
    fn from(e: nexus_types::PathError) -> Self {
        Self::BadRequest(e.to_string())
    }
}

impl From<nexus_state::StateError> for ConsoleError {
    fn from(e: nexus_state::StateError) -> Self {
        Self::Operation(e.to_string())
    }
}

fn auth_error_frame(id: Option<u64>, e: auth::AuthError) -> ServerFrame {
    let (status, message) = crate::auth_error(e);
    ServerFrame::Error {
        id,
        code: status_to_code(status),
        message,
    }
}

fn console_error_frame(id: Option<u64>, e: ConsoleError) -> ServerFrame {
    match e {
        ConsoleError::Auth(e) => auth_error_frame(id, e),
        ConsoleError::Mgmt(e) => {
            let (code, message) = match e {
                MgmtError::Conflict { .. } => (ConsoleErrorCode::Conflict, e.to_string()),
                MgmtError::NotManageable(_) => (ConsoleErrorCode::Forbidden, e.to_string()),
                MgmtError::Auth(e) => {
                    let (status, message) = crate::auth_error(e);
                    (status_to_code(status), message)
                }
                MgmtError::Path(_) | MgmtError::Admission(_) | MgmtError::Operation(_) => {
                    (ConsoleErrorCode::BadRequest, e.to_string())
                }
            };
            ServerFrame::Error { id, code, message }
        }
        ConsoleError::NotAuthenticated => ServerFrame::Error {
            id,
            code: ConsoleErrorCode::NotAuthenticated,
            message: "not authenticated".into(),
        },
        ConsoleError::RateLimited => ServerFrame::Error {
            id,
            code: ConsoleErrorCode::RateLimited,
            message: "too many active console subscriptions".into(),
        },
        ConsoleError::BadRequest(message) => ServerFrame::Error {
            id,
            code: ConsoleErrorCode::BadRequest,
            message,
        },
        ConsoleError::Operation(message) => ServerFrame::Error {
            id,
            code: ConsoleErrorCode::Internal,
            message,
        },
    }
}

fn status_to_code(status: StatusCode) -> ConsoleErrorCode {
    match status {
        StatusCode::UNAUTHORIZED => ConsoleErrorCode::Unauthorized,
        StatusCode::FORBIDDEN => ConsoleErrorCode::Forbidden,
        StatusCode::CONFLICT => ConsoleErrorCode::Conflict,
        StatusCode::BAD_REQUEST => ConsoleErrorCode::BadRequest,
        StatusCode::TOO_MANY_REQUESTS => ConsoleErrorCode::RateLimited,
        _ => ConsoleErrorCode::Internal,
    }
}

fn record_console_error_audit(
    state: &Arc<ConsoleState>,
    principal: Option<&ConsolePrincipal>,
    source_addr: Option<&str>,
    err: &ConsoleError,
) {
    match err {
        ConsoleError::Auth(auth::AuthError::PermissionDenied) => {
            record_ws_audit(state, principal, source_addr, "permission_denied")
        }
        ConsoleError::NotAuthenticated => {
            record_ws_audit(state, principal, source_addr, "not_authenticated")
        }
        ConsoleError::RateLimited => record_ws_audit(state, principal, source_addr, "rate_limited"),
        ConsoleError::BadRequest(_) => {
            record_ws_audit(state, principal, source_addr, "bad_request")
        }
        _ => {}
    }
}

fn record_ws_audit(
    state: &Arc<ConsoleState>,
    principal: Option<&ConsolePrincipal>,
    source_addr: Option<&str>,
    outcome: &'static str,
) {
    let _ = state.boot.record_gateway_audit(nexus_kernel::GatewayAudit {
        event: "console_ws",
        username: principal.map(|p| p.username.as_str()),
        source_addr,
        outcome,
        mfa_level: principal.map(|p| p.mfa_level),
    });
}

fn ws_limit_message(limit: ConsoleWsLimit) -> String {
    match limit {
        ConsoleWsLimit::Global => "too many active console websocket connections".into(),
        ConsoleWsLimit::Source => {
            "too many active console websocket connections from this source".into()
        }
        ConsoleWsLimit::User => {
            "too many active console websocket connections for this user".into()
        }
    }
}

fn entries_value(entries: Vec<(String, Value)>) -> Value {
    Value::List(
        entries
            .into_iter()
            .map(|(path, value)| {
                let mut m = BTreeMap::new();
                m.insert("path".into(), Value::Str(path));
                m.insert("value".into(), value);
                Value::Map(m)
            })
            .collect(),
    )
}

fn sessions_value(sessions: &[SessionSummary]) -> Value {
    Value::List(
        sessions
            .iter()
            .map(|s| {
                let mut m = BTreeMap::new();
                m.insert("sid".into(), Value::Str(s.sid.clone()));
                m.insert("username".into(), Value::Str(s.username.clone()));
                m.insert("identity_path".into(), Value::Str(s.identity_path.clone()));
                m.insert("issued_at".into(), Value::Int(s.issued_at));
                m.insert("expires_at".into(), Value::Int(s.expires_at));
                m.insert("idle_expires_at".into(), Value::Int(s.idle_expires_at));
                m.insert("mfa_level".into(), Value::Int(s.mfa_level as i64));
                m.insert("last_seen".into(), Value::Int(s.last_seen));
                m.insert("source_addr".into(), Value::Str(s.source_addr.clone()));
                Value::Map(m)
            })
            .collect(),
    )
}

fn facts_value(facts: Vec<nexus_types::Fact>) -> Value {
    Value::List(facts.into_iter().map(fact_value).collect())
}

fn fact_value(f: nexus_types::Fact) -> Value {
    let mut m = BTreeMap::new();
    m.insert("op_id".into(), Value::Str(f.id.to_string()));
    m.insert("caller".into(), Value::Int(f.caller.get() as i64));
    m.insert("acting".into(), Value::Int(f.acting.get() as i64));
    m.insert("resource".into(), Value::Int(f.resource.get() as i64));
    m.insert("method".into(), Value::Int(f.method.get() as i64));
    m.insert("decision".into(), Value::Str(format!("{:?}", f.decision)));
    m.insert("replay".into(), Value::Str(format!("{:?}", f.replay)));
    m.insert("timestamp".into(), Value::Int(f.timestamp.get()));
    m.insert("tainted".into(), Value::Bool(!f.taint.is_pristine()));
    m.insert("protected".into(), Value::Bool(f.taint.has_protected()));
    if let Some(batch) = f.batch {
        m.insert("batch".into(), batch.to_value());
    }
    Value::Map(m)
}

fn state_event(ev: StateEvent) -> ConsoleEvent {
    match ev {
        StateEvent::Set { path, value, .. } => ConsoleEvent::StateSet {
            path: path.to_string(),
            value,
        },
        StateEvent::Append { path, item, .. } => ConsoleEvent::StateAppend {
            path: path.to_string(),
            item,
        },
        StateEvent::Delete { path } => ConsoleEvent::StateDelete {
            path: path.to_string(),
        },
    }
}

fn validate_upgrade_headers(headers: &HeaderMap) -> Result<(), String> {
    if let Some(path) = headers.get(":path").and_then(|h| h.to_str().ok())
        && path != "/ws"
    {
        return Err("unexpected console websocket path".into());
    }
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "console websocket origin header is required".to_string())?;
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "console websocket host header is required".to_string())?;
    let origin_host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| "console websocket origin is malformed".to_string())?;
    if origin_host.eq_ignore_ascii_case(host) {
        Ok(())
    } else {
        Err("console websocket origin is not allowed".into())
    }
}

fn ensure_kernel_pattern(path: &Path) -> Result<(), ConsoleError> {
    let segs = path.segments();
    if path.scheme() != "state" || segs.first().map(|s| s.as_str()) != Some("kernel") {
        return Err(ConsoleError::BadRequest(
            "console subscriptions are limited to state://kernel/*".into(),
        ));
    }
    Ok(())
}

fn require_process_inspect(principal: &ConsolePrincipal) -> Result<(), ConsoleError> {
    let path = Path::parse("effect://kernel/process/inspect")?;
    if principal.grants.contains("perform", &path) {
        Ok(())
    } else {
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    }
}

fn authorize_fact_read(
    principal: &ConsolePrincipal,
    process: Option<u64>,
) -> Result<(), ConsoleError> {
    let path = match process {
        Some(process) => Path::parse(&format!("state://fact/{process}"))?,
        None => Path::parse("state://fact")?,
    };
    if principal.grants.contains("read", &path) {
        Ok(())
    } else {
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    }
}

fn require_step_up(principal: &ConsolePrincipal) -> Result<(), ConsoleError> {
    if principal.mfa_level >= 2 {
        Ok(())
    } else {
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    }
}

fn require_config_write_safety(
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<(), ConsoleError> {
    let parsed = Path::parse(path)?;
    let segs = parsed.segments();
    let high_risk = parsed.scheme() == "state"
        && segs.first().map(|s| s.as_str()) == Some("kernel")
        && matches!(
            segs.get(1).map(|s| s.as_str()),
            Some("console" | "extensions" | "extension-pairings" | "procs")
        );
    if high_risk {
        require_step_up(principal)?;
    }
    Ok(())
}

fn validate_path_segment(raw: &str, label: &str) -> Result<(), ConsoleError> {
    if raw.is_empty()
        || raw.contains('/')
        || raw.contains('@')
        || raw.contains('.')
        || !raw.is_ascii()
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ConsoleError::BadRequest(format!("invalid {label}")));
    }
    Ok(())
}

fn reject_secret_fields(input: &Value) -> Result<(), ConsoleError> {
    let denied = ["pairing_secret", "secret", "raw_secret", "sas_verified"];
    let mut stack = vec![input];
    while let Some(value) = stack.pop() {
        match value {
            Value::Map(map) => {
                for (k, v) in map {
                    if denied.iter().any(|field| field == k) {
                        return Err(ConsoleError::BadRequest(format!(
                            "{k} is not accepted in console pairing input"
                        )));
                    }
                    stack.push(v);
                }
            }
            Value::List(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn map_value(items: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Map(
        items
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn capability_target(path: &Path) -> String {
    path.to_string().replacen("://", "/", 1)
}

fn bearer_sid(bearer: Option<&str>) -> Option<&str> {
    bearer?.split_once('.').map(|(sid, _)| sid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        BootstrapOutcome, LoginRequest, RootProvisioning, StepUpRequest, bootstrap_root_account,
    };
    use crate::state::{ConsoleWsConfig, ConsoleWsRuntime};
    use nexus_actors::{PairingDisplayEdge, StandardConfig, install_standard};
    use nexus_kernel::Bootstrap;
    use nexus_types::{EffectCapability, Purity, Role, Transport, TrustLevel};
    use std::collections::BTreeMap;

    fn console_state() -> Arc<ConsoleState> {
        let pairing_display = PairingDisplayEdge::default();
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(
            &boot,
            &StandardConfig {
                pairing_display: pairing_display.clone(),
                ..Default::default()
            },
        );
        ConsoleState::shared_with_pairing_display(boot, pairing_display)
    }

    fn test_session(st: Arc<ConsoleState>, principal: ConsolePrincipal) -> WsSession {
        WsSession {
            state: st,
            principal: Some(principal),
            sid: Some("not-used".into()),
            source_addr: "test".into(),
            counted_user: None,
            subscriptions: BTreeMap::new(),
            event_tx: mpsc::channel(1).0,
            rate: FrameRate::default(),
        }
    }

    async fn root_login(st: &Arc<ConsoleState>) -> (String, ConsolePrincipal, String) {
        let outcome = bootstrap_root_account(&st.boot, RootProvisioning::default())
            .await
            .unwrap();
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            panic!("expected root bootstrap");
        };
        let login = st
            .auth
            .login(
                &st.boot,
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    totp_code: None,
                },
                "test".into(),
            )
            .await
            .unwrap();
        let principal = st
            .auth
            .authenticate_token(&st.boot, &login.token)
            .await
            .unwrap();
        (login.token, principal, password)
    }

    async fn step_up_principal(
        st: &Arc<ConsoleState>,
        token: &str,
        password: String,
    ) -> ConsolePrincipal {
        let elevated = st
            .auth
            .step_up(
                &st.boot,
                token,
                StepUpRequest {
                    password: Some(password),
                    totp_code: None,
                },
                "test".into(),
            )
            .await
            .unwrap();
        st.auth
            .authenticate_token(&st.boot, &elevated.token)
            .await
            .unwrap()
    }

    fn extension_def(id: &str, version: u64) -> Value {
        let def = nexus_types::ExtensionDef {
            id: id.into(),
            role: Role::Provider,
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            provides: vec![EffectCapability::new(
                format!("effect://plugin/{id}/search"),
                Purity::Idempotent,
            )],
            emits: None,
            namespace: Path::parse(&format!("effect://plugin/{id}")).unwrap(),
            config_schema: Value::Null,
            config: Value::Null,
            version,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
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
            max_connections_per_user: 1,
            ..Default::default()
        });
        assert!(runtime.try_acquire_source("a").is_ok());
        assert_eq!(runtime.try_acquire_source("a"), Err(ConsoleWsLimit::Source));
        assert!(runtime.try_acquire_source("b").is_ok());
        assert_eq!(runtime.try_acquire_source("c"), Err(ConsoleWsLimit::Global));
        runtime.release_source("a");
        assert!(runtime.try_acquire_source("c").is_ok());

        assert!(runtime.try_replace_user(None, "root").is_ok());
        assert_eq!(
            runtime.try_replace_user(None, "root"),
            Err(ConsoleWsLimit::User)
        );
        runtime.release_user("root");
        assert!(runtime.try_replace_user(None, "root").is_ok());
    }

    #[test]
    fn pairing_input_rejects_secret_fields_inside_lists() {
        let input = Value::List(vec![map_value([(
            "nested",
            Value::List(vec![map_value([(
                "pairing_secret",
                Value::Str("do-not-accept".into()),
            )])]),
        )])]);
        assert!(matches!(
            reject_secret_fields(&input),
            Err(ConsoleError::BadRequest(_))
        ));
    }

    #[test]
    fn console_frame_roundtrips_with_bincode() {
        let frame = ClientFrame::Rpc {
            id: 7,
            action: ConsoleAction::Snapshot {
                sections: vec![
                    SnapshotSection::KernelConfig {
                        prefix: "state://kernel/audit".into(),
                    },
                    SnapshotSection::Runtime { limit: 8 },
                ],
                since_rev: Some(3),
            },
        };
        let bytes = bincode::serde::encode_to_vec(&frame, BINCODE_CONFIG).unwrap();
        let decoded = decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn configured_limits_are_bounded_by_backend_hard_caps() {
        assert_eq!(
            bounded_limit(
                HARD_MAX_WS_FACT_LIMIT + 1,
                HARD_MAX_WS_FACT_LIMIT + 2,
                HARD_MAX_WS_FACT_LIMIT,
            ),
            HARD_MAX_WS_FACT_LIMIT
        );
        assert_eq!(bounded_limit(100, 12, HARD_MAX_WS_FACT_LIMIT), 12);

        let frame = ClientFrame::Ping { nonce: 9 };
        let bytes = bincode::serde::encode_to_vec(&frame, BINCODE_CONFIG).unwrap();
        assert!(decode_frame(&bytes, bytes.len()).is_ok());
        assert!(decode_frame(&bytes, bytes.len().saturating_sub(1)).is_err());
    }

    #[test]
    fn all_action_variants_are_bincode_frames() {
        let actions = vec![
            ConsoleAction::UserList,
            ConsoleAction::RoleList,
            ConsoleAction::SessionList,
            ConsoleAction::RecentFacts {
                process: None,
                limit: 10,
            },
            ConsoleAction::TraceRead {
                process: 1,
                from: 0,
                limit: 10,
            },
            ConsoleAction::ExtensionStart { id: "acme".into() },
            ConsoleAction::PairingDeny {
                pairing_id: "pair-a".into(),
            },
        ];
        for (idx, action) in actions.into_iter().enumerate() {
            let frame = ClientFrame::Rpc {
                id: idx as u64,
                action,
            };
            let bytes = bincode::serde::encode_to_vec(&frame, BINCODE_CONFIG).unwrap();
            assert_eq!(
                decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES).unwrap(),
                frame
            );
        }
        let sub = ClientFrame::Subscribe {
            id: 1,
            stream: ConsoleStream::Config {
                pattern: "state://kernel/**".into(),
            },
        };
        let bytes = bincode::serde::encode_to_vec(&sub, BINCODE_CONFIG).unwrap();
        assert_eq!(decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES).unwrap(), sub);
    }

    #[tokio::test]
    async fn dispatches_config_and_runtime_actions() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st, principal.clone());
        dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::ExtensionInstall {
                id: "acme".into(),
                def: extension_def("acme", 0),
                expected_version: None,
            },
        )
        .await
        .unwrap();
        let out = dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::ProcessInspect {
                process: None,
                include_recent_facts: true,
                limit: 8,
            },
        )
        .await
        .unwrap();
        assert!(matches!(out, ConsoleResult::Value(Some(Value::List(_)))));
        let facts = dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::RecentFacts {
                process: None,
                limit: 16,
            },
        )
        .await
        .unwrap();
        assert!(matches!(facts, ConsoleResult::Value(Some(Value::List(_)))));
    }

    #[tokio::test]
    async fn pairing_create_can_return_one_time_display_secret() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st.clone(), principal.clone());
        dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::ExtensionInstall {
                id: "pairable".into(),
                def: extension_def("pairable", 0),
                expected_version: None,
            },
        )
        .await
        .unwrap();
        let out = dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::PairingCreate {
                input: map_value([
                    ("pairing_id", Value::Str("pair-ws".into())),
                    ("extension_id", Value::Str("pairable".into())),
                ]),
                reveal_display_secret: true,
            },
        )
        .await
        .unwrap();
        let ConsoleResult::Value(Some(Value::Map(m))) = out else {
            panic!("expected pairing map");
        };
        assert!(matches!(m.get("display_secret"), Some(Value::Str(s)) if !s.is_empty()));
        assert_eq!(st.pairing_display.take_display_secret("pair-ws"), None);
    }

    #[tokio::test]
    async fn pairing_deny_requires_step_up() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let err = dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::PairingDeny {
                pairing_id: "pair-ws".into(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ConsoleError::Auth(auth::AuthError::PermissionDenied)
        ));
    }

    #[tokio::test]
    async fn generic_config_write_enforces_step_up_for_sensitive_prefixes() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let err = dispatch_action(
            &mut sess,
            &principal,
            ConsoleAction::ConfigWriteCas {
                path: "state://kernel/extensions/acme".into(),
                value: extension_def("acme", 0),
                expected_version: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ConsoleError::Auth(auth::AuthError::PermissionDenied)
        ));
    }

    #[tokio::test]
    async fn subscription_rejects_non_kernel_patterns() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let (tx, _rx) = mpsc::channel(1);
        let mut sess = WsSession {
            state: st,
            principal: Some(principal.clone()),
            sid: Some("not-used".into()),
            source_addr: "test".into(),
            counted_user: None,
            subscriptions: BTreeMap::new(),
            event_tx: tx,
            rate: FrameRate::default(),
        };
        let err = subscribe(
            &mut sess,
            &principal,
            1,
            ConsoleStream::Config {
                pattern: "state://fact/**".into(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));
    }

    #[test]
    fn origin_host_must_match() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local".parse().unwrap());
        headers.insert(header::ORIGIN, "https://console.local".parse().unwrap());
        assert!(validate_upgrade_headers(&headers).is_ok());
        headers.insert(header::ORIGIN, "https://attacker.local".parse().unwrap());
        assert!(validate_upgrade_headers(&headers).is_err());
    }

    #[test]
    fn origin_and_host_are_required() {
        let mut headers = HeaderMap::new();
        assert!(validate_upgrade_headers(&headers).is_err());
        headers.insert(header::ORIGIN, "https://console.local".parse().unwrap());
        assert!(validate_upgrade_headers(&headers).is_err());
    }
}
