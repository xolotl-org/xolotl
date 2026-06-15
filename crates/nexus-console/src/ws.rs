//! Console WebSocket protocol endpoint.
//!
//! This is the post-login control path. Frames carry descriptor-named protocol
//! actions (`ActionCall`) and streams (`StreamCall`). Dispatch goes through
//! kernel/auth management surfaces and audited runtime helpers, not through a
//! raw `{target, method, input}` shell.

use crate::auth::{self, ConsolePrincipal, SessionSummary};
use crate::mgmt::{self, MgmtError};
use crate::protocol::{
    self, ACTION_ACCESS_ROLE_LIST, ACTION_ACCESS_ROLE_READ, ACTION_ACCESS_ROLE_WRITE_CAS,
    ACTION_ACCESS_SESSION_CURRENT_LOGOUT, ACTION_ACCESS_SESSION_LIST, ACTION_ACCESS_SESSION_REVOKE,
    ACTION_ACCESS_SESSION_REVOKE_USER, ACTION_ACCESS_USER_DISABLE, ACTION_ACCESS_USER_LIST,
    ACTION_ACCESS_USER_READ, ACTION_ACCESS_USER_WRITE_CAS, ACTION_AUDIT_FACTS_RECENT,
    ACTION_AUTHORITY_ACTION_MATRIX, ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
    ACTION_AUTHORITY_RESOURCE_ACCESS, ACTION_AUTHORITY_WHY_DENIED, ACTION_CHANGE_SET_APPLY,
    ACTION_CHANGE_SET_CREATE, ACTION_CHANGE_SET_DIFF, ACTION_CHANGE_SET_DISCARD,
    ACTION_CHANGE_SET_DRY_RUN, ACTION_CHANGE_SET_UPDATE, ACTION_CHANGE_SET_VALIDATE,
    ACTION_CONFIG_LIST, ACTION_CONFIG_READ, ACTION_CONFIG_WRITE_CAS,
    ACTION_EXTERNAL_INSTALLATION_INSTALL, ACTION_EXTERNAL_INSTALLATION_REVOKE,
    ACTION_EXTERNAL_INSTALLATION_START, ACTION_EXTERNAL_INSTALLATION_STOP,
    ACTION_EXTERNAL_INSTALLATION_UPDATE, ACTION_GRAPH_TYPE_DESCRIBE, ACTION_HEALTH_SUMMARY,
    ACTION_LINEAGE_FACT_BY_OPERATION, ACTION_LINEAGE_FACT_READ, ACTION_LINEAGE_TRACE_READ,
    ACTION_PAIRING_APPROVE, ACTION_PAIRING_CREATE, ACTION_PAIRING_DENY, ACTION_PAIRING_REPLACE,
    ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET, ACTION_PROTOCOL_DESCRIBE,
    ACTION_PROTOCOL_REGISTRY_SNAPSHOT, ACTION_PROTOCOL_SCHEMA_GET, ACTION_REGISTRY_COVERAGE_REPORT,
    ACTION_RESOURCE_TYPE_DESCRIBE, ACTION_RESOURCE_TYPE_LIST, ACTION_RESOURCE_VIEW_DESCRIBE,
    ACTION_RUNTIME_PROCESS_INSPECT, ACTION_SECRET_CATALOG, ACTION_SECRET_REVEAL,
    ACTION_STATE_SNAPSHOT, ACTION_VISIBILITY_AUTHORITY_DESCRIBE, ACTION_VISIBILITY_STATE_LIST,
    ACTION_VISIBILITY_STATE_READ, ActionCall, ActionDescriptor, ActionResult, ClientFrame,
    ConsoleErrorCode, ConsoleEvent, JsonBytes, PrincipalSummary, RequiredAuthority,
    STREAM_AUDIT_FACTS, STREAM_STATE_WATCH, ServerFrame, StreamCall,
};
use crate::state::{
    ConsoleState, ConsoleWsLimit, HARD_MAX_WS_FACT_LIMIT, HARD_MAX_WS_FRAME_BYTES,
    HARD_MAX_WS_STATE_LIST_LIMIT, HARD_MAX_WS_SUBSCRIPTIONS, HARD_MAX_WS_TRACE_LIMIT,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use nexus_graph::{DoNode, OperationTemplate};
use nexus_kernel::RequestGrantTemplate;
use nexus_state::StateEvent;
use nexus_types::{
    Capability, ExternalInstallationDef, NodeId, OperationId, Outcome, OutputMode, Path, ProcSpec,
    ProcessId, ResourceName, RestartPolicy, TaintSet, Transport, Value,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const MAX_VISIBILITY_TTL_MS: u64 = 10 * 60 * 1000;

/// Upgrade an authenticated HTTP request path to the Console Protocol
/// WebSocket endpoint.
pub async fn upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(st): State<Arc<ConsoleState>>,
) -> Response {
    let source_addr = crate::verified_source_addr(&headers, Some(peer), &st.transport_security);
    if let Err(message) = validate_upgrade_headers_audited(&st, &headers, Some(peer)) {
        return (StatusCode::FORBIDDEN, message).into_response();
    }
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

impl From<&ConsolePrincipal> for PrincipalSummary {
    fn from(p: &ConsolePrincipal) -> Self {
        Self {
            username: p.username.clone(),
            identity_path: p.identity_path.clone(),
            mfa_level: p.mfa_level,
        }
    }
}

struct WsSession {
    state: Arc<ConsoleState>,
    principal: Option<ConsolePrincipal>,
    sid: Option<String>,
    hello_accepted: bool,
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
        hello_accepted: false,
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
                message: "console websocket only accepts binary MessagePack frames".into(),
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
                    result: ActionResult { output: None, .. },
                    ..
                } | ServerFrame::Error {
                    code: ConsoleErrorCode::Unauthorized | ConsoleErrorCode::Forbidden,
                    ..
                }
            ))
}

fn require_hello(sess: &WsSession, id: Option<u64>) -> Option<ServerFrame> {
    if sess.hello_accepted {
        None
    } else {
        Some(hello_sequence_error(
            sess,
            id,
            "console websocket hello is required before authentication or calls",
        ))
    }
}

fn hello_sequence_error(sess: &WsSession, id: Option<u64>, message: &str) -> ServerFrame {
    record_ws_audit(
        &sess.state,
        sess.principal.as_ref(),
        Some(&sess.source_addr),
        "protocol_error",
    );
    ServerFrame::Error {
        id,
        code: ConsoleErrorCode::BadFrame,
        message: message.into(),
    }
}

async fn handle_frame(sess: &mut WsSession, frame: ClientFrame) -> ServerFrame {
    match frame {
        ClientFrame::Hello { hello } => {
            if sess.hello_accepted {
                return hello_sequence_error(
                    sess,
                    None,
                    "console websocket hello already accepted",
                );
            }
            if hello.protocol_version != protocol::PROTOCOL_VERSION {
                record_ws_audit(
                    &sess.state,
                    sess.principal.as_ref(),
                    Some(&sess.source_addr),
                    "protocol_error",
                );
                return ServerFrame::Error {
                    id: None,
                    code: ConsoleErrorCode::BadRequest,
                    message: format!(
                        "unsupported console protocol version {}; expected {}",
                        hello.protocol_version,
                        protocol::PROTOCOL_VERSION
                    ),
                };
            }
            if !hello
                .accepted_encodings
                .iter()
                .any(|encoding| encoding == protocol::WIRE_ENCODING)
            {
                record_ws_audit(
                    &sess.state,
                    sess.principal.as_ref(),
                    Some(&sess.source_addr),
                    "protocol_error",
                );
                return ServerFrame::Error {
                    id: None,
                    code: ConsoleErrorCode::BadRequest,
                    message: format!(
                        "unsupported console wire encoding; expected {}",
                        protocol::WIRE_ENCODING
                    ),
                };
            }
            sess.hello_accepted = true;
            ServerFrame::HelloAccepted {
                metadata: protocol_metadata(sess),
            }
        }
        ClientFrame::Auth { token } => {
            if let Some(frame) = require_hello(sess, None) {
                return frame;
            }
            match sess
                .state
                .auth
                .authenticate_token(&sess.state.boot, &token)
                .await
            {
                Ok(principal) => {
                    let Some(sid) = bearer_sid(Some(&token)).map(str::to_string) else {
                        record_ws_audit(&sess.state, None, Some(&sess.source_addr), "auth_failed");
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
                        metadata: protocol_metadata(sess),
                    }
                }
                Err(e) => {
                    record_ws_audit(&sess.state, None, Some(&sess.source_addr), "auth_failed");
                    auth_error_frame(None, e)
                }
            }
        }
        ClientFrame::Ping { nonce } => ServerFrame::Pong { nonce },
        ClientFrame::Call { id, call } => {
            if let Some(frame) = require_hello(sess, Some(id)) {
                return frame;
            }
            let principal = match authenticated_principal(sess, Some(id)).await {
                Ok(p) => p,
                Err(frame) => return frame,
            };
            match dispatch_call(sess, &principal, call).await {
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
            if let Some(frame) = require_hello(sess, Some(id)) {
                return frame;
            }
            let principal = match authenticated_principal(sess, None).await {
                Ok(p) => p,
                Err(frame) => return frame,
            };
            match subscribe(sess, &principal, id, stream).await {
                Ok(()) => ServerFrame::Reply {
                    id,
                    result: ActionResult::empty(server_rev(sess)),
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
            if let Some(frame) = require_hello(sess, Some(id)) {
                return frame;
            }
            if let Err(frame) = authenticated_principal(sess, Some(id)).await {
                return frame;
            }
            if let Some(handle) = sess.subscriptions.remove(&id) {
                let _ = handle.shutdown.send(());
            }
            ServerFrame::Reply {
                id,
                result: ActionResult::empty(server_rev(sess)),
            }
        }
    }
}

async fn authenticated_principal(
    sess: &mut WsSession,
    id: Option<u64>,
) -> Result<ConsolePrincipal, ServerFrame> {
    let Some(sid) = sess.sid.clone() else {
        record_ws_audit(
            &sess.state,
            None,
            Some(&sess.source_addr),
            "not_authenticated",
        );
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

async fn dispatch_call(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let action = call.action.clone();
    let out = match action.as_str() {
        ACTION_PROTOCOL_DESCRIBE | ACTION_PROTOCOL_REGISTRY_SNAPSHOT => {
            protocol::protocol_metadata_to_value(protocol_metadata(sess))
        }
        ACTION_PROTOCOL_SCHEMA_GET | ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET => {
            let mut input = input_map(input_value(&call.input)?)?;
            let action_id = string_arg(&mut input, "action")?;
            protocol::descriptor_value(&action_id).ok_or_else(|| {
                ConsoleError::BadRequest(format!("unknown action descriptor: {action_id}"))
            })?
        }
        ACTION_REGISTRY_COVERAGE_REPORT => {
            protocol::coverage_report_value(server_rev(sess), registry_rev(sess))
        }
        ACTION_RESOURCE_TYPE_LIST => protocol::resource_type_list_value(),
        ACTION_RESOURCE_TYPE_DESCRIBE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let resource_type = string_arg(&mut input, "resource_type")?;
            protocol::resource_type_descriptor_value(&resource_type).ok_or_else(|| {
                ConsoleError::BadRequest(format!("unknown resource type: {resource_type}"))
            })?
        }
        ACTION_RESOURCE_VIEW_DESCRIBE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let view = string_arg(&mut input, "view")?;
            protocol::resource_view_descriptor_value(&view)
                .ok_or_else(|| ConsoleError::BadRequest(format!("unknown resource view: {view}")))?
        }
        ACTION_GRAPH_TYPE_DESCRIBE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let graph_type = string_arg(&mut input, "graph_type")?;
            protocol::graph_type_descriptor_value(&graph_type).ok_or_else(|| {
                ConsoleError::BadRequest(format!("unknown graph type: {graph_type}"))
            })?
        }
        ACTION_CHANGE_SET_CREATE
        | ACTION_CHANGE_SET_UPDATE
        | ACTION_CHANGE_SET_VALIDATE
        | ACTION_CHANGE_SET_DIFF
        | ACTION_CHANGE_SET_DRY_RUN
        | ACTION_CHANGE_SET_APPLY
        | ACTION_CHANGE_SET_DISCARD => {
            return Err(ConsoleError::BadRequest(format!(
                "planned console action is not implemented: {action}"
            )));
        }
        ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE => authority_principal_effective(principal),
        ACTION_AUTHORITY_ACTION_MATRIX => {
            let mut input = input_map(input_value(&call.input)?)?;
            let domain = optional_string_arg(&mut input, "domain")?;
            authority_action_matrix(principal, domain.as_deref())
        }
        ACTION_AUTHORITY_RESOURCE_ACCESS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let target = string_arg(&mut input, "target")?;
            let verb = string_arg(&mut input, "verb")?;
            authority_resource_access(sess, principal, &target, &verb).await?
        }
        ACTION_AUTHORITY_WHY_DENIED => {
            let mut input = input_map(input_value(&call.input)?)?;
            let action_id = string_arg(&mut input, "action")?;
            authority_why_denied(principal, &action_id)?
        }
        ACTION_VISIBILITY_AUTHORITY_DESCRIBE => protocol::visibility_authority_value(),
        ACTION_SECRET_CATALOG => protocol::secret_catalog_value(),
        ACTION_SECRET_REVEAL => {
            require_visibility_access(principal, &call)?;
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "secret_reveal_blocked",
                VisibilityAuditDetails::action(&call, None),
            )?;
            return Err(ConsoleError::BadRequest(
                "no revealable secret custody backend is registered; non-recoverable and one-time secrets must be reset, rotated, or recreated".into(),
            ));
        }
        ACTION_VISIBILITY_STATE_READ => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            if let Err(e) = ensure_observable_state_path_str(&path) {
                let target = blocked_visibility_target(&path);
                record_visibility_audit(
                    &sess.state,
                    principal,
                    Some(&sess.source_addr),
                    "state_read_blocked",
                    VisibilityAuditDetails::action(&call, Some(&target)),
                )?;
                return Err(e);
            }
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "state_read",
                VisibilityAuditDetails::action(&call, Some(&path)),
            )?;
            visibility_state_read(sess, principal, &path).await?
        }
        ACTION_VISIBILITY_STATE_LIST => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let prefix = string_arg(&mut input, "prefix")?;
            let limit = optional_usize_arg(&mut input, "limit")?.unwrap_or(256);
            if let Err(e) = ensure_observable_state_path_str(&prefix) {
                let target = blocked_visibility_target(&prefix);
                record_visibility_audit(
                    &sess.state,
                    principal,
                    Some(&sess.source_addr),
                    "state_list_blocked",
                    VisibilityAuditDetails::action(&call, Some(&target)),
                )?;
                return Err(e);
            }
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "state_list",
                VisibilityAuditDetails::action(&call, Some(&prefix)),
            )?;
            visibility_state_list(sess, principal, &prefix, limit).await?
        }
        ACTION_STATE_SNAPSHOT => snapshot(sess, principal, &call).await?,
        ACTION_CONFIG_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::Null)
        }
        ACTION_CONFIG_LIST => {
            let mut input = input_map(input_value(&call.input)?)?;
            let prefix = string_arg(&mut input, "prefix")?;
            let entries = mgmt::inspect_prefix(&sess.state, principal, &prefix).await?;
            entries_value(entries)
        }
        ACTION_CONFIG_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_config_write_safety(principal, &path)?;
            validate_config_write_value_for_path(&path, &value)?;
            mgmt::write_config(&sess.state, principal, &path, value, expected_version).await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_USER_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            auth::validate_username(&username)?;
            let value = mgmt::inspect(
                &sess.state,
                principal,
                &format!("state://kernel/console/users/{username}"),
            )
            .await?;
            value.unwrap_or(Value::Null)
        }
        ACTION_ACCESS_USER_LIST => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/console/users")
                    .await?;
            entries_value(entries)
        }
        ACTION_ACCESS_USER_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
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
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_USER_DISABLE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
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
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_ROLE_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let role = string_arg(&mut input, "role")?;
            auth::validate_username(&role)?;
            let value = mgmt::inspect(
                &sess.state,
                principal,
                &format!("state://kernel/console/roles/{role}"),
            )
            .await?;
            value.unwrap_or(Value::Null)
        }
        ACTION_ACCESS_ROLE_LIST => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/console/roles")
                    .await?;
            entries_value(entries)
        }
        ACTION_ACCESS_ROLE_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let role = string_arg(&mut input, "role")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
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
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_SESSION_CURRENT_LOGOUT => {
            let Some(sid) = sess.sid.take() else {
                return Err(ConsoleError::NotAuthenticated);
            };
            sess.state
                .auth
                .logout_sid_from_source(&sess.state.boot, &sid, Some(&sess.source_addr))
                .await?;
            sess.principal = None;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_SESSION_LIST => {
            let sessions = sess
                .state
                .auth
                .list_sessions(&sess.state.boot, principal)
                .await?;
            sessions_value(&sessions)
        }
        ACTION_ACCESS_SESSION_REVOKE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let sid = string_arg(&mut input, "sid")?;
            require_step_up(principal)?;
            sess.state
                .auth
                .revoke_session_by_id_from_source(
                    &sess.state.boot,
                    principal,
                    &sid,
                    Some(&sess.source_addr),
                )
                .await?;
            if sess.sid.as_deref() == Some(sid.as_str()) {
                sess.sid = None;
                sess.principal = None;
            }
            map_value([("count", Value::Int(1))])
        }
        ACTION_ACCESS_SESSION_REVOKE_USER => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            require_step_up(principal)?;
            let count = sess
                .state
                .auth
                .revoke_user_sessions_from_source(
                    &sess.state.boot,
                    principal,
                    &username,
                    Some(&sess.source_addr),
                )
                .await?;
            if principal.username == username {
                sess.sid = None;
                sess.principal = None;
            }
            map_value([("count", Value::Int(count as i64))])
        }
        ACTION_RUNTIME_PROCESS_INSPECT => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = optional_u64_arg(&mut input, "process")?;
            let include_recent_facts =
                optional_bool_arg(&mut input, "include_recent_facts")?.unwrap_or(true);
            let limit = optional_usize_arg(&mut input, "limit")?.unwrap_or(64);
            let target = process.map(|pid| format!("process:{pid}"));
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "runtime_process_inspect",
                VisibilityAuditDetails::action(&call, target.as_deref()),
            )?;
            process_inspect(
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
            .await?
        }
        ACTION_AUDIT_FACTS_RECENT => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = optional_u64_arg(&mut input, "process")?;
            let limit = optional_usize_arg(&mut input, "limit")?.unwrap_or(64);
            let target = process
                .map(|pid| format!("state://fact/{pid}"))
                .unwrap_or_else(|| "state://fact".into());
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "audit_facts_recent",
                VisibilityAuditDetails::action(&call, Some(&target)),
            )?;
            recent_facts(
                sess,
                principal,
                process,
                bounded_limit(
                    limit,
                    sess.state.ws.config().max_fact_limit,
                    HARD_MAX_WS_FACT_LIMIT,
                ),
            )
            .await?
        }
        ACTION_LINEAGE_TRACE_READ => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = u64_arg(&mut input, "process")?;
            let from = optional_usize_arg(&mut input, "from")?.unwrap_or(0);
            let limit = optional_usize_arg(&mut input, "limit")?.unwrap_or(128);
            let target = format!("state://fact/{process}");
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "lineage_trace_read",
                VisibilityAuditDetails::action(&call, Some(&target)),
            )?;
            trace_read(
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
            .await?
        }
        ACTION_LINEAGE_FACT_READ | ACTION_LINEAGE_FACT_BY_OPERATION => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let op_id = parse_operation_id(&string_arg(&mut input, "op_id")?)?;
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "lineage_fact_read",
                VisibilityAuditDetails::action(&call, Some(&format!("operation:{op_id}"))),
            )?;
            lineage_fact_read(sess, principal, op_id).await?
        }
        ACTION_HEALTH_SUMMARY => health_summary(sess, principal).await?,
        ACTION_EXTERNAL_INSTALLATION_INSTALL | ACTION_EXTERNAL_INSTALLATION_UPDATE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            validate_path_segment(&id, "external installation id")?;
            validate_extension_installation_def(&id, &def)?;
            mgmt::write_config(
                &sess.state,
                principal,
                &format!("state://kernel/external-installations/{id}"),
                def,
                expected_version,
            )
            .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_EXTERNAL_INSTALLATION_START => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            require_step_up(principal)?;
            let spec = proc_spec_from_installation(sess, principal, &id).await?;
            let value = serde_json::from_value(serde_json::to_value(spec).map_err(|e| {
                ConsoleError::BadRequest(format!("proc spec serialization failed: {e}"))
            })?)
            .map_err(|e| ConsoleError::BadRequest(format!("proc spec conversion failed: {e}")))?;
            invoke_effect(sess, principal, "effect://proc/spawn", value).await?
        }
        ACTION_EXTERNAL_INSTALLATION_STOP => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            require_step_up(principal)?;
            validate_path_segment(&id, "external installation id")?;
            invoke_effect(
                sess,
                principal,
                "effect://proc/kill",
                map_value([("id", Value::Str(id))]),
            )
            .await?
        }
        ACTION_EXTERNAL_INSTALLATION_REVOKE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let installation_id = string_arg(&mut input, "installation_id")?;
            let credential_generation_floor =
                optional_i64_arg(&mut input, "credential_generation_floor")?;
            require_step_up(principal)?;
            validate_path_segment(&installation_id, "external installation id")?;
            let mut m = BTreeMap::new();
            m.insert("installation_id".into(), Value::Str(installation_id));
            if let Some(floor) = credential_generation_floor {
                m.insert("credential_generation_floor".into(), Value::Int(floor));
            }
            invoke_effect(sess, principal, "effect://external/revoke", Value::Map(m)).await?
        }
        ACTION_PAIRING_CREATE => {
            let mut input_map = input_map(input_value(&call.input)?)?;
            let input = value_arg(&mut input_map, "input")?;
            let reveal_display_secret =
                optional_bool_arg(&mut input_map, "reveal_display_secret")?.unwrap_or(false);
            require_step_up(principal)?;
            pairing_action(
                sess,
                principal,
                "effect://external/pairing/create",
                input,
                reveal_display_secret,
            )
            .await?
        }
        ACTION_PAIRING_APPROVE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let pairing_id = string_arg(&mut input, "pairing_id")?;
            let approved_roles = string_list_arg(&mut input, "approved_roles")?;
            require_step_up(principal)?;
            validate_path_segment(&pairing_id, "pairing id")?;
            invoke_effect(
                sess,
                principal,
                "effect://external/pairing/approve",
                map_value([
                    ("pairing_id", Value::Str(pairing_id)),
                    (
                        "approved_roles",
                        Value::List(approved_roles.into_iter().map(Value::Str).collect()),
                    ),
                ]),
            )
            .await?
        }
        ACTION_PAIRING_DENY => {
            let mut input = input_map(input_value(&call.input)?)?;
            let pairing_id = string_arg(&mut input, "pairing_id")?;
            require_step_up(principal)?;
            validate_path_segment(&pairing_id, "pairing id")?;
            invoke_effect(
                sess,
                principal,
                "effect://external/pairing/deny",
                map_value([("pairing_id", Value::Str(pairing_id))]),
            )
            .await?
        }
        ACTION_PAIRING_REPLACE => {
            let mut input_map = input_map(input_value(&call.input)?)?;
            let input = value_arg(&mut input_map, "input")?;
            let reveal_display_secret =
                optional_bool_arg(&mut input_map, "reveal_display_secret")?.unwrap_or(false);
            require_step_up(principal)?;
            pairing_action(
                sess,
                principal,
                "effect://external/pairing/replace",
                input,
                reveal_display_secret,
            )
            .await?
        }
        other => {
            return Err(ConsoleError::BadRequest(format!(
                "unknown console action: {other}"
            )));
        }
    };
    Ok(ActionResult::value(out, server_rev(sess)))
}

async fn subscribe(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    id: u64,
    stream: StreamCall,
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
    if stream.since_rev.is_some() {
        return Err(ConsoleError::BadRequest(
            "since_rev is invalid for live-only console streams".into(),
        ));
    }

    match stream.stream.as_str() {
        STREAM_STATE_WATCH => {
            require_stream_visibility_access(principal, &stream)?;
            let mut input = input_map(input_value(&stream.input)?)?;
            let pattern = Path::parse(&string_arg(&mut input, "pattern")?)?;
            ensure_observable_state_path(&pattern)?;
            auth::authorize_path(&sess.state.state, principal, "subscribe", &pattern, None).await?;
            let mut rx = sess.state.state.subscribe(&pattern).await?;
            let target = pattern.to_string();
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "state_watch",
                VisibilityAuditDetails::stream(&stream, Some(&target)),
            )?;
            let event_tx = sess.event_tx.clone();
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
            if let Some(handle) = sess.subscriptions.remove(&id) {
                let _ = handle.shutdown.send(());
            }
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
        STREAM_AUDIT_FACTS => {
            require_stream_visibility_access(principal, &stream)?;
            let mut input = input_map(input_value(&stream.input)?)?;
            let process = optional_u64_arg(&mut input, "process")?;
            authorize_fact_read(principal, process)?;
            let target = process
                .map(|pid| format!("state://fact/{pid}"))
                .unwrap_or_else(|| "state://fact".into());
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "audit_facts_stream",
                VisibilityAuditDetails::stream(&stream, Some(&target)),
            )?;
            let event_tx = sess.event_tx.clone();
            let state = sess.state.clone();
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
            if let Some(handle) = sess.subscriptions.remove(&id) {
                let _ = handle.shutdown.send(());
            }
            tokio::spawn(async move {
                let mut seen = 0usize;
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        _ = interval.tick() => {
                            let facts = match state.boot.kernel.facts.all_facts() {
                                Ok(facts) => facts,
                                Err(e) => {
                                    let _ = event_tx
                                        .send(SubscriptionMessage {
                                            stream: id,
                                            event: ConsoleEvent::SubscriptionClosed {
                                                reason: e.to_string(),
                                            },
                                        })
                                        .await;
                                    break;
                                }
                            };
                            for fact in facts.iter().skip(seen).filter(|fact| {
                                process.is_none_or(|pid| fact.caller.get() == pid)
                            }) {
                                if event_tx
                                    .send(SubscriptionMessage {
                                        stream: id,
                                        event: ConsoleEvent::Audit {
                                            fact: JsonBytes::from_value(&fact_value(fact.clone())),
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
        other => Err(ConsoleError::BadRequest(format!(
            "unknown console stream: {other}"
        ))),
    }
}

async fn snapshot(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<Value, ConsoleError> {
    let mut input = input_map(input_value(&call.input)?)?;
    let since_rev = optional_u64_arg(&mut input, "since_rev")?;
    let sections = match input.remove("sections") {
        Some(Value::List(items)) => items,
        Some(_) => {
            return Err(ConsoleError::BadRequest(
                "sections must be a list of section maps".into(),
            ));
        }
        None => vec![
            map_value([
                ("kind", Value::Str("kernel_config".into())),
                ("prefix", Value::Str("state://kernel".into())),
            ]),
            map_value([("kind", Value::Str("sessions".into()))]),
            map_value([
                ("kind", Value::Str("runtime".into())),
                ("limit", Value::Int(64)),
            ]),
        ],
    };

    let mut out = BTreeMap::new();
    out.insert("server_rev".into(), Value::Int(server_rev(sess) as i64));
    out.insert("registry_rev".into(), Value::Int(registry_rev(sess) as i64));
    out.insert(
        "fact_cursor".into(),
        Value::Int(sess.state.boot.kernel.facts.cursor() as i64),
    );
    out.insert("truncated".into(), Value::List(Vec::new()));
    if let Some(since_rev) = since_rev {
        out.insert("since_rev".into(), Value::Int(since_rev as i64));
    }
    for section in sections {
        let mut section = input_map(section)?;
        let kind = string_arg(&mut section, "kind")?;
        match kind.as_str() {
            "kernel_config" => {
                let prefix = string_arg(&mut section, "prefix")?;
                let entries = mgmt::inspect_prefix(&sess.state, principal, &prefix).await?;
                out.insert(prefix, entries_value(entries));
            }
            "sessions" => {
                let sessions = sess
                    .state
                    .auth
                    .list_sessions(&sess.state.boot, principal)
                    .await?;
                out.insert("sessions".into(), sessions_value(&sessions));
            }
            "runtime" => {
                let include_recent_facts =
                    optional_bool_arg(&mut section, "include_recent_facts")?.unwrap_or(false);
                if include_recent_facts {
                    require_visibility_access(principal, call)?;
                }
                let limit = optional_usize_arg(&mut section, "limit")?.unwrap_or(64);
                if include_recent_facts {
                    record_visibility_audit(
                        &sess.state,
                        principal,
                        Some(&sess.source_addr),
                        "state_snapshot_runtime_facts",
                        VisibilityAuditDetails::action(call, Some("runtime.processes")),
                    )?;
                }
                let runtime =
                    process_inspect(sess, principal, None, include_recent_facts, limit).await?;
                out.insert("runtime".into(), runtime);
            }
            other => {
                return Err(ConsoleError::BadRequest(format!(
                    "unknown snapshot section kind: {other}"
                )));
            }
        }
    }
    Ok(Value::Map(out))
}

async fn visibility_state_read(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<Value, ConsoleError> {
    let path = Path::parse(path)?;
    ensure_observable_state_path(&path)?;
    auth::authorize_path(&sess.state.state, principal, "read", &path, None).await?;
    run_state_op(sess, principal, path, "read", Value::Null).await
}

async fn visibility_state_list(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    prefix: &str,
    limit: usize,
) -> Result<Value, ConsoleError> {
    let prefix = Path::parse(prefix)?;
    ensure_observable_state_path(&prefix)?;
    auth::authorize_path(&sess.state.state, principal, "read", &prefix, None).await?;
    let mut out = run_state_op(sess, principal, prefix, "list", Value::Null).await?;
    if let Value::List(items) = &mut out {
        let max = bounded_limit(
            limit,
            sess.state.ws.config().max_state_list_limit,
            HARD_MAX_WS_STATE_LIST_LIMIT,
        );
        items.truncate(max);
    }
    Ok(out)
}

async fn run_state_op(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    path: Path,
    method: &str,
    input: Value,
) -> Result<Value, ConsoleError> {
    let target = ResourceName::new(path.clone());
    let identity_path = Path::parse(&principal.identity_path)
        .map_err(|e| ConsoleError::Operation(format!("invalid principal identity path: {e}")))?;
    if identity_path.segments().is_empty() {
        return Err(ConsoleError::Operation(
            "invalid principal identity path: identity path must include at least one segment"
                .into(),
        ));
    }
    let identity = nexus_kernel::intern_identity(&identity_path);
    let verb = capability_verb_for_state_method(method);
    let cap = format!("{verb}://{}", capability_target(&path));
    let methods = sess
        .state
        .boot
        .request_method_bitmap(&target, verb)
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    let process = sess
        .state
        .boot
        .spawn_request_process_under_with_request_grants(
            sess.state.boot.root,
            identity,
            &[RequestGrantTemplate {
                literal: &cap,
                methods,
            }],
        )
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    let handle = sess
        .state
        .boot
        .open_for(process, &target, verb)
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    let ex = sess.state.boot.kernel.executor_for(process);
    ex.bind_handle(target.clone(), handle);
    let op = DoNode::Op(OperationTemplate {
        target,
        method: method.into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(input),
    });
    match ex.eval_tainted(&op, TaintSet::author()).await {
        Outcome::Done(v) | Outcome::Short(v) => Ok(v),
        Outcome::Fail(f) => Err(ConsoleError::Operation(f.to_string())),
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
    let limit = bounded_limit(
        limit,
        sess.state.ws.config().max_fact_limit,
        HARD_MAX_WS_FACT_LIMIT,
    );
    let process_ids = match process {
        Some(process) => vec![ProcessId::new(process)],
        None => sess.state.boot.kernel.processes.all_ids(),
    };
    let mut rows = Vec::with_capacity(process_ids.len());
    for process in process_ids {
        let mut row = BTreeMap::new();
        row.insert(
            "process".into(),
            Value::Int(u64_to_i64_saturating(process.get())),
        );
        if let Some(status) = sess.state.boot.kernel.processes.status(process) {
            row.insert("status".into(), Value::Str(format!("{status:?}")));
            row.insert("terminal".into(), Value::Bool(status.is_terminal()));
        } else {
            row.insert("status".into(), Value::Str("Unknown".into()));
        }
        if let Some(identity) = sess.state.boot.kernel.processes.identity(process) {
            row.insert(
                "identity".into(),
                Value::Int(u64_to_i64_saturating(identity.get())),
            );
        }
        let children = sess
            .state
            .boot
            .kernel
            .processes
            .children_of(process)
            .into_iter()
            .map(|child| Value::Int(u64_to_i64_saturating(child.get())))
            .collect();
        row.insert("children".into(), Value::List(children));
        let facts = sess.state.boot.kernel.facts.facts_of(process)?;
        row.insert("fact_count".into(), Value::Int(facts.len() as i64));
        if include_recent_facts {
            row.insert(
                "recent_facts".into(),
                Value::List(
                    facts
                        .into_iter()
                        .rev()
                        .take(limit)
                        .map(fact_value)
                        .collect(),
                ),
            );
        }
        rows.push(Value::Map(row));
    }
    Ok(Value::List(rows))
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
        .all_facts()?
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
    let all = sess
        .state
        .boot
        .kernel
        .facts
        .all_facts()?
        .into_iter()
        .filter(|fact| fact.caller.get() == process)
        .collect::<Vec<_>>();
    let limit = bounded_limit(
        limit,
        sess.state.ws.config().max_trace_limit,
        HARD_MAX_WS_TRACE_LIMIT,
    );
    let rows = all
        .iter()
        .skip(from)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let partial = from.saturating_add(rows.len()) < all.len();
    let mut out = BTreeMap::new();
    out.insert("process".into(), Value::Int(u64_to_i64_saturating(process)));
    out.insert("from".into(), Value::Int(usize_to_i64_saturating(from)));
    out.insert("limit".into(), Value::Int(usize_to_i64_saturating(limit)));
    out.insert(
        "total_facts".into(),
        Value::Int(usize_to_i64_saturating(all.len())),
    );
    out.insert("items".into(), facts_value(rows));
    out.insert("partial".into(), Value::Bool(true));
    out.insert(
        "partial_reason".into(),
        Value::Str(if partial {
            "trace result is paged; request the next page to continue reconstruction".into()
        } else {
            "trace result is a fact-order projection; use lineage fact and operation indexes for detailed records".into()
        }),
    );
    Ok(Value::Map(out))
}

async fn lineage_fact_read(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    op_id: OperationId,
) -> Result<Value, ConsoleError> {
    authorize_fact_read(principal, Some(op_id.process.get()))?;
    let fact = sess
        .state
        .boot
        .kernel
        .facts
        .all_facts()?
        .into_iter()
        .find(|fact| fact.id == op_id)
        .ok_or_else(|| ConsoleError::BadRequest(format!("unknown operation id: {op_id}")))?;
    Ok(fact_detail_value(fact))
}

async fn health_summary(
    sess: &WsSession,
    principal: &ConsolePrincipal,
) -> Result<Value, ConsoleError> {
    let kernel_path = Path::parse("state://kernel")?;
    auth::authorize_path(&sess.state.state, principal, "read", &kernel_path, None).await?;

    let process_ids = sess.state.boot.kernel.processes.all_ids();
    let mut process_status = BTreeMap::new();
    for pid in &process_ids {
        let status = sess
            .state
            .boot
            .kernel
            .processes
            .status(*pid)
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| "Unknown".into());
        let next = process_status
            .get(&status)
            .and_then(Value::as_int)
            .unwrap_or(0)
            + 1;
        process_status.insert(status, Value::Int(next));
    }

    let facts = sess.state.boot.kernel.facts.all_facts()?;
    let mut decisions = BTreeMap::new();
    for fact in &facts {
        let key = format!("{:?}", fact.decision);
        let next = decisions.get(&key).and_then(Value::as_int).unwrap_or(0) + 1;
        decisions.insert(key, Value::Int(next));
    }

    let registry = registry_counts_value(sess.state.boot.kernel.registry.counts());
    let cfg = sess.state.ws.config();
    Ok(map_value([
        ("status", Value::Str("ok".into())),
        ("server_rev", Value::Int(server_rev(sess) as i64)),
        ("registry_rev", Value::Int(registry_rev(sess) as i64)),
        ("process_count", Value::Int(process_ids.len() as i64)),
        ("process_status", Value::Map(process_status)),
        ("fact_count", Value::Int(facts.len() as i64)),
        (
            "fact_cursor",
            Value::Int(sess.state.boot.kernel.facts.cursor() as i64),
        ),
        ("fact_decisions", Value::Map(decisions)),
        ("registry", registry),
        (
            "ws_limits",
            map_value([
                ("max_frame_bytes", Value::Int(cfg.max_frame_bytes as i64)),
                (
                    "max_connections_global",
                    Value::Int(cfg.max_connections_global as i64),
                ),
                (
                    "max_connections_per_source",
                    Value::Int(cfg.max_connections_per_source as i64),
                ),
                (
                    "max_connections_per_user",
                    Value::Int(cfg.max_connections_per_user as i64),
                ),
                (
                    "max_subscriptions",
                    Value::Int(cfg.max_subscriptions as i64),
                ),
                (
                    "max_state_list_limit",
                    Value::Int(cfg.max_state_list_limit as i64),
                ),
                ("max_fact_limit", Value::Int(cfg.max_fact_limit as i64)),
                ("max_trace_limit", Value::Int(cfg.max_trace_limit as i64)),
            ]),
        ),
    ]))
}

fn authority_principal_effective(principal: &ConsolePrincipal) -> Value {
    let grants = principal
        .grants
        .iter()
        .map(|cap| Value::Str(cap.to_string()))
        .collect::<Vec<_>>();
    map_value([
        ("username", Value::Str(principal.username.clone())),
        ("identity_path", Value::Str(principal.identity_path.clone())),
        ("mfa_level", Value::Int(i64::from(principal.mfa_level))),
        ("grant_count", Value::Int(grants.len() as i64)),
        ("grants", Value::List(grants)),
        (
            "root_data_authority",
            serde_value(protocol::protocol_metadata(0, 0).root_data_authority),
        ),
    ])
}

fn authority_action_matrix(principal: &ConsolePrincipal, domain: Option<&str>) -> Value {
    let rows = protocol::action_descriptors()
        .into_iter()
        .filter(|descriptor| domain.is_none_or(|d| descriptor.domain == d))
        .map(|descriptor| authority_action_row(principal, &descriptor))
        .collect();
    Value::List(rows)
}

fn authority_why_denied(
    principal: &ConsolePrincipal,
    action_id: &str,
) -> Result<Value, ConsoleError> {
    let descriptor = protocol::action_descriptors()
        .into_iter()
        .find(|descriptor| descriptor.id == action_id)
        .ok_or_else(|| {
            ConsoleError::BadRequest(format!("unknown action descriptor: {action_id}"))
        })?;
    Ok(authority_action_row(principal, &descriptor))
}

fn authority_action_row(principal: &ConsolePrincipal, descriptor: &ActionDescriptor) -> Value {
    let checks = descriptor
        .required_authority
        .iter()
        .map(|required| authority_required_check(principal, required))
        .collect::<Vec<_>>();
    let authority_ok = checks
        .iter()
        .all(|check| map_bool(check, "allowed").unwrap_or(false));
    let conditional_authority = !authority_ok
        && checks
            .iter()
            .any(|check| map_bool(check, "conditional").unwrap_or(false));
    let visibility_gate = action_needs_visibility_gate(descriptor);
    let status = if descriptor.status == protocol::ImplementationStatus::BlockedByCustody {
        "blocked_by_custody"
    } else if descriptor.status == protocol::ImplementationStatus::Planned {
        "planned"
    } else if !authority_ok {
        if conditional_authority {
            "conditional_authority"
        } else {
            "denied"
        }
    } else if descriptor.requires_step_up && principal.mfa_level < 2 {
        "step_up_required"
    } else if visibility_gate {
        "visibility_gate_required"
    } else {
        "available"
    };
    let why = authority_why(status, descriptor, authority_ok, conditional_authority);
    map_value([
        ("action", Value::Str(descriptor.id.clone())),
        ("domain", Value::Str(descriptor.domain.clone())),
        ("status", Value::Str(status.into())),
        ("risk", serde_value(&descriptor.risk)),
        ("visibility", serde_value(&descriptor.visibility)),
        ("implementation_status", serde_value(&descriptor.status)),
        ("authority_ok", Value::Bool(authority_ok)),
        ("requires_step_up", Value::Bool(descriptor.requires_step_up)),
        ("mfa_level", Value::Int(i64::from(principal.mfa_level))),
        ("requires_visibility_gate", Value::Bool(visibility_gate)),
        ("authority", Value::List(checks)),
        (
            "why",
            Value::List(why.into_iter().map(Value::Str).collect()),
        ),
    ])
}

fn authority_required_check(principal: &ConsolePrincipal, required: &RequiredAuthority) -> Value {
    let mut row = BTreeMap::new();
    row.insert("verb".into(), Value::Str(required.verb.clone()));
    row.insert("target".into(), Value::Str(required.target.clone()));
    match required_capability(required) {
        Ok(required_cap) => {
            let allowed = principal
                .grants
                .iter()
                .any(|grant| grant.predicate.is_none() && grant.covers_cap(&required_cap));
            let conditional = !allowed
                && principal
                    .grants
                    .iter()
                    .any(|grant| grant.predicate.is_some() && grant.covers_cap(&required_cap));
            row.insert("allowed".into(), Value::Bool(allowed));
            row.insert("conditional".into(), Value::Bool(conditional));
            if !allowed {
                row.insert(
                    "why_not".into(),
                    Value::Str(
                        if conditional {
                            "matching grant is predicate-bound; action input is required"
                        } else {
                            "missing grant"
                        }
                        .into(),
                    ),
                );
            }
        }
        Err(e) => {
            row.insert("allowed".into(), Value::Bool(false));
            row.insert("conditional".into(), Value::Bool(false));
            row.insert(
                "why_not".into(),
                Value::Str(format!("descriptor authority is malformed: {e:?}")),
            );
        }
    }
    Value::Map(row)
}

async fn authority_resource_access(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    target: &str,
    verb: &str,
) -> Result<Value, ConsoleError> {
    validate_authority_verb(verb)?;
    let path = Path::parse(target)?;
    if path
        .segments()
        .iter()
        .any(|seg| matches!(seg.as_str(), "*" | "**"))
    {
        return Err(ConsoleError::BadRequest(
            "authority.resource.access requires a concrete target path".into(),
        ));
    }
    if path.scheme() == "state" && nexus_types::is_vault_reserved(&path) {
        return Ok(map_value([
            ("target", Value::Str(path.to_string())),
            ("verb", Value::Str(verb.to_string())),
            ("allowed", Value::Bool(false)),
            ("why_not", Value::Str("secret_custody_required".into())),
        ]));
    }

    let result = if matches!(verb, "read" | "write" | "subscribe") && path.scheme() == "state" {
        auth::authorize_path(&sess.state.state, principal, verb, &path, None)
            .await
            .map(|_| "auth.authorize_path")
    } else {
        let allowed = principal.grants.contains(verb, &path);
        if allowed {
            Ok("capset.contains")
        } else {
            Err(auth::AuthError::PermissionDenied)
        }
    };
    let mut row = BTreeMap::new();
    row.insert("target".into(), Value::Str(path.to_string()));
    row.insert("verb".into(), Value::Str(verb.to_string()));
    match result {
        Ok(via) => {
            row.insert("allowed".into(), Value::Bool(true));
            row.insert("via".into(), Value::Str(via.into()));
        }
        Err(e) => {
            row.insert("allowed".into(), Value::Bool(false));
            row.insert("why_not".into(), Value::Str(e.to_string()));
        }
    }
    Ok(Value::Map(row))
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

async fn proc_spec_from_installation(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    id: &str,
) -> Result<ProcSpec, ConsoleError> {
    validate_path_segment(id, "external installation id")?;
    let installation_path = format!("state://kernel/external-installations/{id}");
    let value = mgmt::inspect(&sess.state, principal, &installation_path)
        .await?
        .ok_or_else(|| ConsoleError::BadRequest("external installation is not installed".into()))?;
    let json = serde_json::to_value(&value).map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef serialization failed: {e}"))
    })?;
    let def: ExternalInstallationDef = serde_json::from_value(json).map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef is malformed: {e}"))
    })?;
    if def.id != id {
        return Err(ConsoleError::BadRequest(
            "ExternalInstallationDef id does not match requested installation id".into(),
        ));
    }
    def.validate_admission().map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef admission failed: {e}"))
    })?;
    Ok(proc_spec_from_transport(def.id, def.transport))
}

fn proc_spec_from_transport(id: String, transport: Transport) -> ProcSpec {
    let command = match &transport {
        Transport::Stdio { command, args } => command.as_ref().map(|cmd| {
            std::iter::once(cmd.clone())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>()
        }),
        _ => None,
    };
    ProcSpec {
        id,
        transport,
        command,
        env: BTreeMap::new(),
        cwd: None,
        restart: RestartPolicy::default(),
    }
}

async fn invoke_effect(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    effect: &str,
    input: Value,
) -> Result<Value, ConsoleError> {
    let path = Path::parse(effect)?;
    auth::authorize_path(&sess.state.state, principal, "perform", &path, Some(&input)).await?;
    let identity_path = Path::parse(&principal.identity_path)
        .map_err(|e| ConsoleError::Operation(format!("invalid principal identity path: {e}")))?;
    if identity_path.segments().is_empty() {
        return Err(ConsoleError::Operation(
            "invalid principal identity path: identity path must include at least one segment"
                .into(),
        ));
    }
    let identity = nexus_kernel::intern_identity(&identity_path);
    let cap = format!("perform://{}", capability_target(&path));
    let target = ResourceName::new(path);
    let methods = sess
        .state
        .boot
        .request_method_bitmap(&target, "perform")
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    let process = sess
        .state
        .boot
        .spawn_request_process_under_with_request_grants(
            sess.state.boot.root,
            identity,
            &[RequestGrantTemplate {
                literal: &cap,
                methods,
            }],
        )
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
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
    rmp_serde::from_slice(bytes).map_err(|e| format!("bad MessagePack frame: {e}"))
}

fn bounded_limit(requested: usize, configured: usize, hard: usize) -> usize {
    requested.min(configured).min(hard)
}

fn usize_to_i64_saturating(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

async fn send<S>(tx: &mut S, frame: ServerFrame) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    let bytes = encode_frame(&frame).map_err(|_| ())?;
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

fn encode_frame<T: Serialize>(frame: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(frame)
}

#[derive(Debug)]
enum ConsoleError {
    Auth(auth::AuthError),
    Mgmt(MgmtError),
    NotAuthenticated,
    StepUpRequired,
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

impl From<nexus_kernel::FactError> for ConsoleError {
    fn from(e: nexus_kernel::FactError) -> Self {
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
                MgmtError::Conflict { expected } => (
                    ConsoleErrorCode::Conflict,
                    format!("version conflict (optimistic concurrency): expected {expected:?}"),
                ),
                MgmtError::NotManageable(_) => (
                    ConsoleErrorCode::Forbidden,
                    "management path is not allowed".into(),
                ),
                MgmtError::Auth(e) => {
                    let (status, message) = crate::auth_error(e);
                    (status_to_code(status), message)
                }
                MgmtError::Path(_) => (
                    ConsoleErrorCode::BadRequest,
                    "invalid management path".into(),
                ),
                MgmtError::Admission(reason) => (
                    ConsoleErrorCode::BadRequest,
                    format!("config admission rejected: {reason}"),
                ),
                MgmtError::Operation(_) => (
                    ConsoleErrorCode::Internal,
                    "management operation failed".into(),
                ),
            };
            ServerFrame::Error { id, code, message }
        }
        ConsoleError::NotAuthenticated => ServerFrame::Error {
            id,
            code: ConsoleErrorCode::NotAuthenticated,
            message: "not authenticated".into(),
        },
        ConsoleError::StepUpRequired => ServerFrame::Error {
            id,
            code: ConsoleErrorCode::Forbidden,
            message: "step-up required".into(),
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
            message: if message.contains("invalid principal identity path") {
                "invalid console principal".into()
            } else {
                "console operation failed".into()
            },
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
        ConsoleError::StepUpRequired => {
            record_ws_audit(state, principal, source_addr, "step_up_required")
        }
        ConsoleError::Auth(auth::AuthError::PermissionDenied) => {
            record_ws_audit(state, principal, source_addr, "permission_denied")
        }
        ConsoleError::Mgmt(MgmtError::Auth(auth::AuthError::PermissionDenied))
        | ConsoleError::Mgmt(MgmtError::NotManageable(_)) => {
            record_ws_audit(state, principal, source_addr, "permission_denied")
        }
        ConsoleError::NotAuthenticated => {
            record_ws_audit(state, principal, source_addr, "not_authenticated")
        }
        ConsoleError::RateLimited => record_ws_audit(state, principal, source_addr, "rate_limited"),
        ConsoleError::BadRequest(_)
        | ConsoleError::Mgmt(MgmtError::Path(_))
        | ConsoleError::Mgmt(MgmtError::Admission(_)) => {
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
        details: None,
    });
}

struct VisibilityAuditDetails<'a> {
    scope: Option<&'a str>,
    justification: Option<&'a str>,
    ttl_ms: Option<u64>,
    target: Option<&'a str>,
}

impl<'a> VisibilityAuditDetails<'a> {
    fn action(call: &'a ActionCall, target: Option<&'a str>) -> Self {
        Self {
            scope: call.scope.as_deref(),
            justification: call.justification.as_deref(),
            ttl_ms: call.ttl_ms,
            target,
        }
    }

    fn stream(stream: &'a StreamCall, target: Option<&'a str>) -> Self {
        Self {
            scope: stream.scope.as_deref(),
            justification: stream.justification.as_deref(),
            ttl_ms: stream.ttl_ms,
            target,
        }
    }
}

fn record_visibility_audit(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    source_addr: Option<&str>,
    outcome: &'static str,
    audit: VisibilityAuditDetails<'_>,
) -> Result<(), ConsoleError> {
    let mut details = BTreeMap::new();
    if let Some(scope) = audit.scope {
        details.insert("scope".into(), Value::Str(scope.to_string()));
    }
    if let Some(justification) = audit.justification {
        details.insert(
            "justification".into(),
            Value::Str(justification.to_string()),
        );
    }
    if let Some(ttl_ms) = audit.ttl_ms {
        details.insert("ttl_ms".into(), Value::Int(u64_to_i64_saturating(ttl_ms)));
    }
    if let Some(target) = audit.target {
        details.insert("target".into(), Value::Str(target.to_string()));
    }
    state
        .boot
        .record_gateway_audit(nexus_kernel::GatewayAudit {
            event: "console_visibility",
            username: Some(principal.username.as_str()),
            source_addr,
            outcome,
            mfa_level: Some(principal.mfa_level),
            details: Some(Value::Map(details)),
        })?;
    Ok(())
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

fn fact_detail_value(f: nexus_types::Fact) -> Value {
    let mut m = match fact_value(f.clone()) {
        Value::Map(m) => m,
        _ => BTreeMap::new(),
    };
    m.insert("schema_version".into(), Value::Int(f.schema_version as i64));
    m.insert("handle".into(), Value::Str(f.handle.to_string()));
    m.insert("input_ref".into(), serde_value(&f.input_ref));
    m.insert("outcome_ref".into(), serde_value(&f.outcome_ref));
    m.insert("partial".into(), Value::Bool(true));
    m.insert(
        "partial_reason".into(),
        Value::Str(
            "lineage fact detail excludes materialized payload, state revision, and driver endpoint projections"
                .into(),
        ),
    );
    Value::Map(m)
}

fn registry_counts_value(counts: nexus_kernel::registry::RegistryCounts) -> Value {
    map_value([
        ("resources", Value::Int(counts.resources as i64)),
        ("interfaces", Value::Int(counts.interfaces as i64)),
        ("drivers", Value::Int(counts.drivers as i64)),
        ("endpoints", Value::Int(counts.endpoints as i64)),
        ("bindings", Value::Int(counts.bindings as i64)),
        ("grants", Value::Int(counts.grants as i64)),
        ("policies", Value::Int(counts.policies as i64)),
        ("names", Value::Int(counts.names as i64)),
        (
            "open_cache_entries",
            Value::Int(counts.open_cache_entries as i64),
        ),
        ("open_cache_hits", Value::Int(counts.open_cache_hits as i64)),
        (
            "open_cache_misses",
            Value::Int(counts.open_cache_misses as i64),
        ),
    ])
}

fn state_event(ev: StateEvent) -> ConsoleEvent {
    match ev {
        StateEvent::Set { path, value, .. } => ConsoleEvent::StateSet {
            path: path.to_string(),
            value: JsonBytes::from_value(&value),
        },
        StateEvent::Append { path, item, .. } => ConsoleEvent::StateAppend {
            path: path.to_string(),
            item: JsonBytes::from_value(&item),
        },
        StateEvent::Delete { path } => ConsoleEvent::StateDelete {
            path: path.to_string(),
        },
    }
}

fn validate_upgrade_headers(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<(), String> {
    if let Some(path) = headers.get(":path").and_then(|h| h.to_str().ok())
        && path != "/ws"
    {
        return Err("unexpected console websocket path".into());
    }
    validate_origin_headers("console websocket", headers, peer, transport).map(|_| ())
}

pub(crate) fn validate_http_auth_headers(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<String, String> {
    validate_origin_headers("console http auth", headers, peer, transport)
}

fn validate_origin_headers(
    label: &str,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<String, String> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| format!("{label} origin header is required"))?;
    let parsed_origin = OriginParts::parse(origin, label)?;
    let trusted_proxy = transport.trusts_peer(peer.map(|p| p.ip()));
    let external_host = external_host(label, headers, trusted_proxy, transport)?;
    let external = OriginParts::parse_host(external_host, label)?;

    if transport.relaxed_origin() {
        return Ok(origin.into());
    }
    if !parsed_origin.host.eq_ignore_ascii_case(external.host) {
        return Err(format!("{label} origin is not allowed"));
    }
    if !transport.ignore_origin_port() && parsed_origin.port != external.port {
        return Err(format!("{label} origin port is not allowed"));
    }
    if let Some(proto) = external_forwarded_proto(headers, trusted_proxy, transport)
        && parsed_origin.scheme != proto
    {
        return Err(format!("{label} origin scheme is not allowed"));
    }
    Ok(origin.into())
}

#[derive(Debug, Eq, PartialEq)]
struct OriginParts<'a> {
    scheme: &'a str,
    host: &'a str,
    port: Option<u16>,
}

impl<'a> OriginParts<'a> {
    fn parse(origin: &'a str, label: &str) -> Result<Self, String> {
        let (scheme, rest) = origin
            .split_once("://")
            .ok_or_else(|| format!("{label} origin is malformed"))?;
        if !matches!(scheme, "http" | "https") {
            return Err(format!("{label} origin scheme is unsupported"));
        }
        if rest.contains('/') {
            return Err(format!("{label} origin is malformed"));
        }
        let mut parsed = Self::parse_host(rest, label)?;
        parsed.scheme = scheme;
        Ok(parsed)
    }

    fn parse_host(authority: &'a str, label: &str) -> Result<Self, String> {
        let authority = authority.trim();
        if authority.is_empty() {
            return Err(format!("{label} host header is required"));
        }
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let (host, rest) = stripped
                .split_once(']')
                .ok_or_else(|| format!("{label} host header is malformed"))?;
            let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            (host, port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if port.chars().all(|c| c.is_ascii_digit()) {
                (host, port.parse::<u16>().ok())
            } else {
                (authority, None)
            }
        } else {
            (authority, None)
        };
        if host.is_empty() {
            return Err(format!("{label} host header is malformed"));
        }
        Ok(Self {
            scheme: "",
            host,
            port,
        })
    }
}

fn external_host<'a>(
    label: &str,
    headers: &'a HeaderMap,
    trusted_proxy: bool,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<&'a str, String> {
    if trusted_proxy
        && transport.trusted_proxy.honor_x_forwarded_host
        && let Some(host) = headers
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok())
    {
        return Ok(host.split(',').next().unwrap_or(host).trim());
    }
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| format!("{label} host header is required"))
}

fn external_forwarded_proto<'a>(
    headers: &'a HeaderMap,
    trusted_proxy: bool,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Option<&'a str> {
    if !(trusted_proxy && transport.trusted_proxy.honor_x_forwarded_proto) {
        return None;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| matches!(*value, "http" | "https"))
}

fn server_rev(sess: &WsSession) -> u64 {
    sess.state.boot.kernel.facts.cursor()
}

fn registry_rev(_sess: &WsSession) -> u64 {
    protocol::PROTOCOL_VERSION as u64
}

fn protocol_metadata(sess: &WsSession) -> protocol::ProtocolMetadata {
    protocol::protocol_metadata_for_transport(
        server_rev(sess),
        registry_rev(sess),
        &sess.state.transport_security,
    )
}

fn ensure_observable_state_path(path: &Path) -> Result<(), ConsoleError> {
    if path.scheme() != "state" {
        return Err(ConsoleError::BadRequest(
            "visibility.state actions require state:// paths".into(),
        ));
    }
    if nexus_types::is_vault_reserved(path) {
        return Err(ConsoleError::BadRequest(
            "state://vault/* is governed by secret.* custody actions".into(),
        ));
    }
    let first = path
        .segments()
        .first()
        .map(|s| s.as_str())
        .ok_or_else(|| ConsoleError::BadRequest("state path must name a subtree".into()))?;
    if matches!(first, "*" | "**") {
        return Err(ConsoleError::BadRequest(
            "wildcard first-segment visibility reads could include state://vault; use concrete business prefixes".into(),
        ));
    }
    Ok(())
}

fn ensure_observable_state_path_str(raw: &str) -> Result<(), ConsoleError> {
    let path = Path::parse(raw)?;
    ensure_observable_state_path(&path)
}

fn blocked_visibility_target(raw: &str) -> String {
    let Ok(path) = Path::parse(raw) else {
        return "invalid_state_target".into();
    };
    if path.scheme() != "state" {
        return "non_state_target".into();
    }
    if nexus_types::is_vault_reserved(&path) {
        return "state://vault/**".into();
    }
    if path
        .segments()
        .first()
        .is_some_and(|segment| matches!(segment.as_str(), "*" | "**"))
    {
        return "state://**".into();
    }
    path.to_string()
}

fn validate_upgrade_headers_audited(
    state: &Arc<ConsoleState>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<(), String> {
    let result = validate_upgrade_headers(headers, peer, &state.transport_security);
    if result.is_err() {
        let source_addr = crate::verified_source_addr(headers, peer, &state.transport_security);
        record_ws_audit(state, None, Some(&source_addr), "origin_denied");
    }
    result
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
        Err(ConsoleError::StepUpRequired)
    }
}

fn require_visibility_access(
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<(), ConsoleError> {
    require_visibility_gate(
        principal,
        call.scope.as_deref(),
        call.justification.as_deref(),
        call.ttl_ms,
    )
}

fn require_stream_visibility_access(
    principal: &ConsolePrincipal,
    stream: &StreamCall,
) -> Result<(), ConsoleError> {
    require_visibility_gate(
        principal,
        stream.scope.as_deref(),
        stream.justification.as_deref(),
        stream.ttl_ms,
    )
}

fn require_visibility_gate(
    principal: &ConsolePrincipal,
    scope: Option<&str>,
    justification: Option<&str>,
    ttl_ms: Option<u64>,
) -> Result<(), ConsoleError> {
    require_step_up(principal)?;
    validate_principal_identity(principal)?;
    let Some(scope) = scope.map(str::trim) else {
        return Err(ConsoleError::BadRequest(
            "visibility access requires a scope".into(),
        ));
    };
    if scope.is_empty() {
        return Err(ConsoleError::BadRequest(
            "visibility access requires a scope".into(),
        ));
    }
    let Some(justification) = justification.map(str::trim) else {
        return Err(ConsoleError::BadRequest(
            "visibility access requires a justification".into(),
        ));
    };
    if justification.is_empty() {
        return Err(ConsoleError::BadRequest(
            "visibility access requires a justification".into(),
        ));
    }
    let Some(ttl_ms) = ttl_ms else {
        return Err(ConsoleError::BadRequest(
            "visibility access requires ttl_ms".into(),
        ));
    };
    if ttl_ms == 0 || ttl_ms > MAX_VISIBILITY_TTL_MS {
        return Err(ConsoleError::BadRequest(format!(
            "visibility ttl_ms must be between 1 and {MAX_VISIBILITY_TTL_MS}"
        )));
    }
    Ok(())
}

fn validate_principal_identity(principal: &ConsolePrincipal) -> Result<(), ConsoleError> {
    let identity_path = Path::parse(&principal.identity_path)
        .map_err(|e| ConsoleError::Operation(format!("invalid principal identity path: {e}")))?;
    if identity_path.segments().is_empty() {
        return Err(ConsoleError::Operation(
            "invalid principal identity path: identity path must include at least one segment"
                .into(),
        ));
    }
    Ok(())
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
            Some(
                "console"
                    | "external"
                    | "external-installations"
                    | "external-projections"
                    | "external-pairings"
                    | "external-sessions"
                    | "external-credential-revocations"
                    | "procs"
            )
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

fn serde_value<T: Serialize>(value: T) -> Value {
    serde_json::from_value(serde_json::to_value(value).unwrap_or(serde_json::Value::Null))
        .unwrap_or(Value::Null)
}

fn map_bool(value: &Value, key: &str) -> Option<bool> {
    value.as_map()?.get(key)?.as_bool()
}

fn action_needs_visibility_gate(descriptor: &ActionDescriptor) -> bool {
    matches!(
        descriptor.visibility,
        protocol::VisibilityTier::BusinessData
            | protocol::VisibilityTier::ProtectedPayload
            | protocol::VisibilityTier::SecretPlaintext
    )
}

fn authority_why(
    status: &str,
    descriptor: &ActionDescriptor,
    authority_ok: bool,
    conditional_authority: bool,
) -> Vec<String> {
    let mut why = Vec::new();
    match status {
        "blocked_by_custody" => why.push("secret custody backend is not registered".into()),
        "planned" => why.push("descriptor is planned and not executable".into()),
        "denied" if !authority_ok => why.push("principal lacks required authority".into()),
        "conditional_authority" if conditional_authority => {
            why.push("matching grant is predicate-bound and needs concrete action input".into())
        }
        "step_up_required" => why.push("mfa_level >= 2 is required".into()),
        "visibility_gate_required" => {
            why.push("scope, justification, and ttl_ms are required per call".into())
        }
        _ => {}
    }
    if descriptor.requires_step_up {
        why.push("action is marked step-up sensitive".into());
    }
    why
}

fn required_capability(required: &RequiredAuthority) -> Result<Capability, ConsoleError> {
    let path = Path::parse(&required.target)?;
    Ok(Capability {
        verb: required.verb.clone(),
        scheme: path.scheme().to_string(),
        segments: path.segments().to_vec(),
        predicate: None,
    })
}

fn validate_authority_verb(verb: &str) -> Result<(), ConsoleError> {
    if matches!(
        verb,
        "perform" | "read" | "write" | "subscribe" | "spawn" | "act-as" | "delegate"
    ) {
        Ok(())
    } else {
        Err(ConsoleError::BadRequest(format!(
            "unsupported authority verb: {verb}"
        )))
    }
}

fn input_value(input: &JsonBytes) -> Result<Value, ConsoleError> {
    input
        .try_to_value()
        .map_err(|e| ConsoleError::BadRequest(format!("invalid JSON Value envelope: {e}")))
}

fn input_map(input: Value) -> Result<BTreeMap<String, Value>, ConsoleError> {
    match input {
        Value::Null => Ok(BTreeMap::new()),
        Value::Map(m) => Ok(m),
        _ => Err(ConsoleError::BadRequest(
            "console action input must be a map".into(),
        )),
    }
}

fn string_arg(input: &mut BTreeMap<String, Value>, name: &str) -> Result<String, ConsoleError> {
    match input.remove(name) {
        Some(Value::Str(s)) if !s.is_empty() => Ok(s),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-empty string"
        ))),
        None => Err(ConsoleError::BadRequest(format!("{name} is required"))),
    }
}

fn optional_string_arg(
    input: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<String>, ConsoleError> {
    match input.remove(name) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Str(s)) if !s.is_empty() => Ok(Some(s)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-empty string"
        ))),
    }
}

fn value_arg(input: &mut BTreeMap<String, Value>, name: &str) -> Result<Value, ConsoleError> {
    input
        .remove(name)
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} is required")))
}

fn parse_operation_id(raw: &str) -> Result<OperationId, ConsoleError> {
    let mut parts = raw.split('/');
    let process = parts
        .next()
        .ok_or_else(|| ConsoleError::BadRequest("op_id must be process/position/attempt".into()))?
        .parse::<u64>()
        .map_err(|_| ConsoleError::BadRequest("op_id process must be u64".into()))?;
    let position = parts
        .next()
        .ok_or_else(|| ConsoleError::BadRequest("op_id must be process/position/attempt".into()))?
        .parse::<u32>()
        .map_err(|_| ConsoleError::BadRequest("op_id position must be u32".into()))?;
    let attempt = parts
        .next()
        .ok_or_else(|| ConsoleError::BadRequest("op_id must be process/position/attempt".into()))?
        .parse::<u32>()
        .map_err(|_| ConsoleError::BadRequest("op_id attempt must be u32".into()))?;
    if parts.next().is_some() {
        return Err(ConsoleError::BadRequest(
            "op_id must be process/position/attempt".into(),
        ));
    }
    Ok(OperationId::new(
        ProcessId::new(process),
        NodeId::new(position),
        attempt,
    ))
}

fn u64_arg(input: &mut BTreeMap<String, Value>, name: &str) -> Result<u64, ConsoleError> {
    optional_u64_arg(input, name)?
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} is required")))
}

fn optional_u64_arg(
    input: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<u64>, ConsoleError> {
    match input.remove(name) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Int(i)) if i >= 0 => Ok(Some(i as u64)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-negative integer"
        ))),
    }
}

fn optional_i64_arg(
    input: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<i64>, ConsoleError> {
    match input.remove(name) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Int(i)) => Ok(Some(i)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be an integer"
        ))),
    }
}

fn optional_usize_arg(
    input: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<usize>, ConsoleError> {
    optional_u64_arg(input, name)?
        .map(|v| {
            usize::try_from(v).map_err(|_| ConsoleError::BadRequest(format!("{name} is too large")))
        })
        .transpose()
}

fn validate_extension_installation_def(id: &str, value: &Value) -> Result<(), ConsoleError> {
    let json = serde_json::to_value(value).map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef serialization failed: {e}"))
    })?;
    let def: ExternalInstallationDef = serde_json::from_value(json).map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef is malformed: {e}"))
    })?;
    if def.id != id {
        return Err(ConsoleError::BadRequest(
            "ExternalInstallationDef id does not match requested installation id".into(),
        ));
    }
    def.validate_admission().map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef admission failed: {e}"))
    })
}

fn validate_config_write_value_for_path(path: &str, value: &Value) -> Result<(), ConsoleError> {
    let parsed = Path::parse(path)?;
    let segs = parsed.segments();
    if parsed.scheme() == "state"
        && segs.first().map(|s| s.as_str()) == Some("kernel")
        && segs.get(1).map(|s| s.as_str()) == Some("external-installations")
    {
        let Some(id) = segs.get(2) else {
            return Err(ConsoleError::BadRequest(
                "ExternalInstallationDef writes must target state://kernel/external-installations/<id>".into(),
            ));
        };
        if segs.len() != 3 {
            return Err(ConsoleError::BadRequest(
                "ExternalInstallationDef writes must target exactly one installation id".into(),
            ));
        }
        validate_extension_installation_def(id, value)?;
    }
    Ok(())
}

fn optional_bool_arg(
    input: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<bool>, ConsoleError> {
    match input.remove(name) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(_) => Err(ConsoleError::BadRequest(format!("{name} must be a bool"))),
    }
}

fn string_list_arg(
    input: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Vec<String>, ConsoleError> {
    match input.remove(name) {
        Some(Value::List(items)) => items
            .into_iter()
            .map(|item| match item {
                Value::Str(s) if !s.is_empty() => Ok(s),
                _ => Err(ConsoleError::BadRequest(format!(
                    "{name} must be a list of non-empty strings"
                ))),
            })
            .collect(),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a list of strings"
        ))),
        None => Err(ConsoleError::BadRequest(format!("{name} is required"))),
    }
}

fn capability_target(path: &Path) -> String {
    path.to_string().replacen("://", "/", 1)
}

fn capability_verb_for_state_method(method: &str) -> &'static str {
    match method {
        "read" | "list" => "read",
        "write" | "append" | "delete" => "write",
        "subscribe" => "subscribe",
        _ => "perform",
    }
}

fn bearer_sid(bearer: Option<&str>) -> Option<&str> {
    bearer?.split_once('.').map(|(sid, _)| sid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        BootstrapOutcome, ConsoleAuthConfig, LoginRequest, RootProvisioning, StepUpRequest,
        bootstrap_root_account,
    };
    use crate::protocol::*;
    use crate::state::{
        ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode, ConsoleTrustedProxyConfig,
        ConsoleUnsafeTransportRelaxation, ConsoleWsConfig, ConsoleWsRuntime,
    };
    use nexus_actors::{PairingDisplayEdge, StandardConfig, install_standard};
    use nexus_kernel::Bootstrap;
    use nexus_types::{
        EffectCapability, ExternalProjectionDef, Purity, Role, Transport, TrustLevel,
    };
    use std::collections::BTreeMap;

    struct FailingFactStore;

    impl nexus_kernel::FactStore for FailingFactStore {
        fn append(&self, _fact: nexus_types::Fact) -> Result<u64, nexus_kernel::FactError> {
            Err(nexus_kernel::FactError("simulated append failure".into()))
        }

        fn complete(&self, _fact: nexus_types::Fact) -> Result<(), nexus_kernel::FactError> {
            Err(nexus_kernel::FactError("simulated complete failure".into()))
        }

        fn sync(&self) -> Result<(), nexus_kernel::FactError> {
            Ok(())
        }

        fn facts_of(
            &self,
            _process: nexus_types::ProcessId,
        ) -> Result<Vec<nexus_types::Fact>, nexus_kernel::FactError> {
            Ok(Vec::new())
        }

        fn all_facts(&self) -> Result<Vec<nexus_types::Fact>, nexus_kernel::FactError> {
            Ok(Vec::new())
        }

        fn cursor(&self) -> u64 {
            0
        }
    }

    fn console_state() -> Arc<ConsoleState> {
        let pairing_display = PairingDisplayEdge::default();
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(
            &boot,
            &StandardConfig {
                pairing_display: pairing_display.clone(),
                ..Default::default()
            },
        )
        .expect("standard providers should install");
        ConsoleState::shared_with_pairing_display(boot, pairing_display)
    }

    fn audit_outcomes(st: &ConsoleState, event: &str) -> Vec<String> {
        st.boot
            .kernel
            .facts
            .all_facts()
            .unwrap()
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                nexus_types::OutcomeRef::Inline(Value::Map(m))
                    if m.get("event").and_then(Value::as_str) == Some(event) =>
                {
                    m.get("outcome").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect()
    }

    fn test_session(st: Arc<ConsoleState>, principal: ConsolePrincipal) -> WsSession {
        WsSession {
            state: st,
            principal: Some(principal),
            sid: Some("not-used".into()),
            hello_accepted: true,
            source_addr: "test".into(),
            counted_user: None,
            subscriptions: BTreeMap::new(),
            event_tx: mpsc::channel(1).0,
            rate: FrameRate::default(),
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
        let (tx, _rx) = mpsc::channel(1);
        WsSession {
            state: st,
            principal: None,
            sid: None,
            hello_accepted: false,
            source_addr: "test".into(),
            counted_user: None,
            subscriptions: BTreeMap::new(),
            event_tx: tx,
            rate: FrameRate::default(),
        }
    }

    fn root_principal() -> ConsolePrincipal {
        ConsolePrincipal {
            username: "root".into(),
            identity_path: "process://root".into(),
            grants: nexus_types::CapSet::from_strs(["*://**"]).unwrap(),
            mfa_level: 2,
        }
    }

    #[test]
    fn visibility_audit_fact_failure_is_not_swallowed() {
        let facts = nexus_kernel::FactSink::new(Arc::new(FailingFactStore));
        let state: nexus_state::Backend = Arc::new(nexus_state::InMemoryBackend::new());
        let boot = Arc::new(Bootstrap::from_kernel(nexus_kernel::Kernel::with_backends(
            state, facts,
        )));
        let st = ConsoleState::shared(boot);
        let principal = root_principal();

        let err = record_visibility_audit(
            &st,
            &principal,
            Some("test"),
            "state_read",
            VisibilityAuditDetails {
                scope: Some("scope"),
                justification: Some("justification"),
                ttl_ms: Some(1000),
                target: Some("state://chat/source/messages/1"),
            },
        )
        .unwrap_err();

        assert!(
            matches!(err, ConsoleError::Operation(message) if message.contains("simulated complete failure"))
        );
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

    async fn step_up_login(
        st: &Arc<ConsoleState>,
        token: &str,
        password: String,
    ) -> (String, ConsolePrincipal) {
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
        let principal = st
            .auth
            .authenticate_token(&st.boot, &elevated.token)
            .await
            .unwrap();
        (elevated.token, principal)
    }

    fn extension_installation(id: &str, version: u64) -> Value {
        let def = ExternalInstallationDef {
            id: id.into(),
            platform: id.into(),
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![ExternalProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(Path::parse(&format!("effect://external-provider/{id}")).unwrap()),
                provides: vec![EffectCapability::new(
                    format!("effect://external-provider/{id}/search"),
                    Purity::Idempotent,
                )],
                emits: None,
                version: 1,
            }],
            version,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
    }

    fn call(action: &str, input: Value) -> ActionCall {
        ActionCall {
            action: action.into(),
            input: JsonBytes::from_value(&input),
            scope: None,
            justification: None,
            ttl_ms: None,
        }
    }

    fn visibility_call(action: &str, input: Value) -> ActionCall {
        ActionCall {
            action: action.into(),
            input: JsonBytes::from_value(&input),
            scope: Some("test".into()),
            justification: Some("test visibility inspection".into()),
            ttl_ms: Some(60_000),
        }
    }

    fn output_value(result: ActionResult) -> Value {
        result.output.expect("expected action output").to_value()
    }

    fn fact_count(st: &ConsoleState) -> usize {
        st.boot
            .kernel
            .processes
            .all_ids()
            .into_iter()
            .map(|pid| st.boot.kernel.facts.facts_of(pid).unwrap().len())
            .sum()
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
    fn pairing_input_rejects_untrusted_claim_field() {
        let input = map_value([("sas_verified", Value::Bool(true))]);
        assert!(matches!(
            reject_secret_fields(&input),
            Err(ConsoleError::BadRequest(_))
        ));
    }

    #[test]
    fn console_frame_roundtrips_with_msgpack() {
        let frame = ClientFrame::Call {
            id: 7,
            call: call(
                ACTION_STATE_SNAPSHOT,
                map_value([
                    (
                        "sections",
                        Value::List(vec![
                            map_value([
                                ("kind", Value::Str("kernel_config".into())),
                                ("prefix", Value::Str("state://kernel/audit".into())),
                            ]),
                            map_value([
                                ("kind", Value::Str("runtime".into())),
                                ("limit", Value::Int(8)),
                            ]),
                        ]),
                    ),
                    ("since_rev", Value::Int(3)),
                ]),
            ),
        };
        let bytes = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES).unwrap();
        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn hello_rejects_unsupported_wire_encoding() {
        let st = console_state();
        let mut sess = unauth_session(st.clone());
        let reply = handle_frame(
            &mut sess,
            ClientFrame::Hello {
                hello: ClientHello {
                    protocol_version: PROTOCOL_VERSION,
                    client_name: Some("test-client".into()),
                    accepted_encodings: vec!["json".into()],
                },
            },
        )
        .await;
        assert!(matches!(
            reply,
            ServerFrame::Error {
                id: None,
                code: ConsoleErrorCode::BadRequest,
                ..
            }
        ));
        assert!(audit_outcomes(&st, "console_ws").contains(&"protocol_error".into()));

        let reply = handle_frame(
            &mut sess,
            ClientFrame::Hello {
                hello: ClientHello::default(),
            },
        )
        .await;
        assert!(matches!(reply, ServerFrame::HelloAccepted { .. }));
    }

    #[tokio::test]
    async fn auth_and_calls_require_accepted_hello() {
        let st = console_state();
        let mut sess = unauth_session(st.clone());
        let reply = handle_frame(
            &mut sess,
            ClientFrame::Auth {
                token: "bad-token".into(),
            },
        )
        .await;
        assert!(matches!(
            reply,
            ServerFrame::Error {
                id: None,
                code: ConsoleErrorCode::BadFrame,
                ..
            }
        ));

        let reply = handle_frame(
            &mut sess,
            ClientFrame::Call {
                id: 42,
                call: call(ACTION_PROTOCOL_DESCRIBE, Value::Null),
            },
        )
        .await;
        assert!(matches!(
            reply,
            ServerFrame::Error {
                id: Some(42),
                code: ConsoleErrorCode::BadFrame,
                ..
            }
        ));
        assert!(audit_outcomes(&st, "console_ws").contains(&"protocol_error".into()));
    }

    #[tokio::test]
    async fn unsubscribe_requires_authenticated_session() {
        let st = console_state();
        let mut sess = unauth_session(st);
        sess.hello_accepted = true;
        let reply = handle_frame(&mut sess, ClientFrame::Unsubscribe { id: 99 }).await;
        assert!(matches!(
            reply,
            ServerFrame::Error {
                id: Some(99),
                code: ConsoleErrorCode::NotAuthenticated,
                ..
            }
        ));
        assert!(audit_outcomes(&sess.state, "console_ws").contains(&"not_authenticated".into()));
    }

    #[test]
    fn rejected_upgrade_writes_gateway_audit() {
        let st = console_state();
        let headers = HeaderMap::new();

        let err = validate_upgrade_headers_audited(&st, &headers, None).unwrap_err();

        assert!(err.contains("origin"));
        assert!(audit_outcomes(&st, "console_ws").contains(&"origin_denied".into()));
    }

    #[tokio::test]
    async fn step_up_required_writes_specific_gateway_audit() {
        let st = console_state();
        let (token, principal, _password) = root_login(&st).await;
        let mut sess = test_session_for_token(st.clone(), principal, &token);

        let reply = handle_frame(
            &mut sess,
            ClientFrame::Call {
                id: 11,
                call: call(
                    ACTION_PAIRING_DENY,
                    map_value([("pairing_id", Value::Str("pair-ws".into()))]),
                ),
            },
        )
        .await;

        assert!(matches!(
            reply,
            ServerFrame::Error {
                id: Some(11),
                code: ConsoleErrorCode::Forbidden,
                message,
            } if message == "step-up required"
        ));
        assert!(audit_outcomes(&st, "console_ws").contains(&"step_up_required".into()));
    }

    #[tokio::test]
    async fn forbidden_management_path_is_redacted_and_audited() {
        let st = console_state();
        let (token, principal, _password) = root_login(&st).await;
        let mut sess = test_session_for_token(st.clone(), principal, &token);

        let reply = handle_frame(
            &mut sess,
            ClientFrame::Call {
                id: 12,
                call: call(
                    ACTION_CONFIG_READ,
                    map_value([(
                        "path",
                        Value::Str("state://vault/console/root/password".into()),
                    )]),
                ),
            },
        )
        .await;

        assert!(matches!(
            &reply,
            ServerFrame::Error {
                id: Some(12),
                code: ConsoleErrorCode::Forbidden,
                message,
            } if message == "management path is not allowed"
        ));
        if let ServerFrame::Error { message, .. } = &reply {
            assert!(!message.contains("state://vault"));
            assert!(!message.contains("password"));
        }
        assert!(audit_outcomes(&st, "console_ws").contains(&"permission_denied".into()));
    }

    #[tokio::test]
    async fn secret_reveal_blocked_attempt_is_audited() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let (elevated_token, principal) = step_up_login(&st, &token, password).await;
        let mut sess = test_session_for_token(st.clone(), principal, &elevated_token);

        let reply = handle_frame(
            &mut sess,
            ClientFrame::Call {
                id: 13,
                call: visibility_call(ACTION_SECRET_REVEAL, Value::Null),
            },
        )
        .await;

        assert!(matches!(
            reply,
            ServerFrame::Error {
                id: Some(13),
                code: ConsoleErrorCode::BadRequest,
                ..
            }
        ));
        assert!(
            audit_outcomes(&st, "console_visibility").contains(&"secret_reveal_blocked".into())
        );
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
        let bytes = encode_frame(&frame).unwrap();
        assert!(decode_frame(&bytes, bytes.len()).is_ok());
        assert!(decode_frame(&bytes, bytes.len().saturating_sub(1)).is_err());
    }

    #[test]
    fn protocol_action_calls_are_msgpack_frames() {
        let actions = vec![
            call(ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE, Value::Null),
            call(ACTION_AUTHORITY_ACTION_MATRIX, Value::Null),
            call(
                ACTION_AUTHORITY_WHY_DENIED,
                map_value([("action", Value::Str(ACTION_CONFIG_WRITE_CAS.into()))]),
            ),
            call(ACTION_ACCESS_USER_LIST, Value::Null),
            call(ACTION_ACCESS_ROLE_LIST, Value::Null),
            call(ACTION_ACCESS_SESSION_LIST, Value::Null),
            call(
                ACTION_AUDIT_FACTS_RECENT,
                map_value([("limit", Value::Int(10))]),
            ),
            call(
                ACTION_LINEAGE_TRACE_READ,
                map_value([
                    ("process", Value::Int(1)),
                    ("from", Value::Int(0)),
                    ("limit", Value::Int(10)),
                ]),
            ),
            call(
                ACTION_LINEAGE_FACT_READ,
                map_value([("op_id", Value::Str("1/0/0".into()))]),
            ),
            call(ACTION_HEALTH_SUMMARY, Value::Null),
            call(
                ACTION_EXTERNAL_INSTALLATION_START,
                map_value([("id", Value::Str("acme".into()))]),
            ),
            call(
                ACTION_PAIRING_DENY,
                map_value([("pairing_id", Value::Str("pair-a".into()))]),
            ),
        ];
        for (idx, call) in actions.into_iter().enumerate() {
            let frame = ClientFrame::Call {
                id: idx as u64,
                call,
            };
            let bytes = encode_frame(&frame).unwrap();
            assert_eq!(
                decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES).unwrap(),
                frame
            );
        }
        let sub = ClientFrame::Subscribe {
            id: 1,
            stream: StreamCall {
                stream: STREAM_STATE_WATCH.into(),
                input: JsonBytes::from_value(&map_value([(
                    "pattern",
                    Value::Str("state://kernel/**".into()),
                )])),
                scope: Some("test".into()),
                justification: Some("test stream".into()),
                ttl_ms: Some(60_000),
                since_rev: None,
            },
        };
        let bytes = encode_frame(&sub).unwrap();
        assert_eq!(decode_frame(&bytes, HARD_MAX_WS_FRAME_BYTES).unwrap(), sub);
    }

    #[tokio::test]
    async fn dispatches_config_and_runtime_actions() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st.clone(), principal.clone());
        dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_EXTERNAL_INSTALLATION_INSTALL,
                map_value([
                    ("id", Value::Str("acme".into())),
                    ("def", extension_installation("acme", 0)),
                    ("expected_version", Value::Null),
                ]),
            ),
        )
        .await
        .unwrap();
        let out = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_RUNTIME_PROCESS_INSPECT,
                map_value([
                    ("include_recent_facts", Value::Bool(true)),
                    ("limit", Value::Int(8)),
                ]),
            ),
        )
        .await
        .unwrap();
        assert!(out.output.is_some());
        let facts = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_AUDIT_FACTS_RECENT,
                map_value([("limit", Value::Int(16))]),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(output_value(facts), Value::List(_)));
    }

    #[tokio::test]
    async fn protocol_metadata_actions_use_session_transport_security() {
        let pairing_display = PairingDisplayEdge::default();
        let boot = Arc::new(Bootstrap::in_memory());
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());
        let st = ConsoleState::shared_with_pairing_display_and_config(
            boot,
            pairing_display,
            ConsoleAuthConfig::default(),
            ConsoleWsConfig::default(),
            ConsoleTransportSecurityConfig {
                mode: ConsoleTransportSecurityMode::UnsafePlaintext,
                ..ConsoleTransportSecurityConfig::default()
            },
        );
        let principal = root_principal();
        let mut sess = test_session(st, principal.clone());
        let result = dispatch_call(
            &mut sess,
            &principal,
            call(ACTION_PROTOCOL_DESCRIBE, Value::Null),
        )
        .await;
        let output = match result {
            Ok(result) => match result.output {
                Some(output) => match output.try_to_value() {
                    Ok(value) => value,
                    Err(error) => {
                        assert!(false, "metadata output must decode: {error}");
                        return;
                    }
                },
                None => {
                    assert!(false, "metadata output is missing");
                    return;
                }
            },
            Err(error) => {
                assert!(false, "metadata action failed: {error:?}");
                return;
            }
        };
        let Some(map) = output.as_map() else {
            assert!(false, "metadata output must be a map");
            return;
        };
        assert_eq!(
            map.get("transport_security_mode").and_then(Value::as_str),
            Some("unsafe_plaintext")
        );
        assert_eq!(
            map.get("unsafe_transport").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[tokio::test]
    async fn authority_matrix_explains_step_up_and_visibility_gate() {
        let st = console_state();
        let (token, principal, password) = root_login(&st).await;
        let mut sess = test_session(st.clone(), principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_ACTION_MATRIX,
                map_value([("domain", Value::Str("visibility".into()))]),
            ),
        )
        .await
        .unwrap();
        let Value::List(rows) = output_value(out) else {
            panic!("expected matrix rows")
        };
        assert!(rows.iter().any(|row| {
            row.as_map().is_some_and(
                |m| matches!(m.get("status"), Some(Value::Str(s)) if s == "step_up_required"),
            )
        }));

        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st.clone(), principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_ACTION_MATRIX,
                map_value([("domain", Value::Str("visibility".into()))]),
            ),
        )
        .await
        .unwrap();
        let Value::List(rows) = output_value(out) else {
            panic!("expected matrix rows")
        };
        assert!(rows.iter().any(|row| {
            row.as_map().is_some_and(|m| {
                matches!(m.get("action"), Some(Value::Str(a)) if a == ACTION_VISIBILITY_STATE_READ)
                    && matches!(m.get("status"), Some(Value::Str(s)) if s == "visibility_gate_required")
            })
        }));
    }

    #[tokio::test]
    async fn dispatches_shape_independent_descriptor_actions() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());

        let result = dispatch_call(
            &mut sess,
            &principal,
            call(ACTION_RESOURCE_TYPE_LIST, Value::Null),
        )
        .await;
        let list = match result {
            Ok(result) => match result.output {
                Some(output) => output.to_value(),
                None => panic!("resource type list output missing"),
            },
            Err(error) => panic!("resource type list failed: {error:?}"),
        };
        assert!(matches!(list, Value::List(items) if !items.is_empty()));

        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_RESOURCE_TYPE_DESCRIBE,
                map_value([("resource_type", Value::Str("access.user".into()))]),
            ),
        )
        .await;
        let descriptor = match result {
            Ok(result) => match result.output {
                Some(output) => output.to_value(),
                None => panic!("resource type descriptor output missing"),
            },
            Err(error) => panic!("resource type descriptor failed: {error:?}"),
        };
        let Value::Map(descriptor) = descriptor else {
            panic!("expected resource descriptor map")
        };
        let Some(Value::List(fields)) = descriptor.get("fields") else {
            panic!("resource descriptor fields missing")
        };
        assert!(fields.iter().any(|field| {
            field.as_map().is_some_and(|map| {
                matches!(map.get("semantic_kind"), Some(Value::Str(kind)) if kind == "resource_ref")
            })
        }));

        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_RESOURCE_VIEW_DESCRIBE,
                map_value([("view", Value::Str("access.users".into()))]),
            ),
        )
        .await;
        let view = match result {
            Ok(result) => match result.output {
                Some(output) => output.to_value(),
                None => panic!("resource view descriptor output missing"),
            },
            Err(error) => panic!("resource view descriptor failed: {error:?}"),
        };
        assert!(
            matches!(view, Value::Map(map) if map.get("resource_type") == Some(&Value::Str("access.user".into())))
        );

        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_GRAPH_TYPE_DESCRIBE,
                map_value([("graph_type", Value::Str("plan.workflow".into()))]),
            ),
        )
        .await;
        let graph = match result {
            Ok(result) => match result.output {
                Some(output) => output.to_value(),
                None => panic!("graph type descriptor output missing"),
            },
            Err(error) => panic!("graph type descriptor failed: {error:?}"),
        };
        assert!(
            matches!(graph, Value::Map(map) if matches!(map.get("node_types"), Some(Value::List(nodes)) if !nodes.is_empty()))
        );
    }

    #[tokio::test]
    async fn planned_change_set_actions_are_not_executable() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_CHANGE_SET_CREATE,
                map_value([("registry_rev", Value::Int(1))]),
            ),
        )
        .await;
        assert!(matches!(
            result,
            Err(ConsoleError::BadRequest(message))
                if message == "planned console action is not implemented: change_set.create"
        ));

        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_ACTION_MATRIX,
                map_value([("domain", Value::Str("change_set".into()))]),
            ),
        )
        .await;
        let matrix = match result {
            Ok(result) => match result.output {
                Some(output) => output.to_value(),
                None => panic!("authority matrix output missing"),
            },
            Err(error) => panic!("authority matrix failed: {error:?}"),
        };
        let Value::List(rows) = matrix else {
            panic!("expected matrix rows")
        };
        assert!(rows.iter().all(|row| {
            row.as_map()
                .is_some_and(|map| map.get("status") == Some(&Value::Str("planned".into())))
        }));
    }

    #[tokio::test]
    async fn authority_resource_access_keeps_vault_on_secret_custody_path() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_RESOURCE_ACCESS,
                map_value([
                    (
                        "target",
                        Value::Str("state://chat/source/messages/1".into()),
                    ),
                    ("verb", Value::Str("read".into())),
                ]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert_eq!(row.get("allowed"), Some(&Value::Bool(true)));

        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_RESOURCE_ACCESS,
                map_value([
                    (
                        "target",
                        Value::Str("state://vault/console/root/password".into()),
                    ),
                    ("verb", Value::Str("read".into())),
                ]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert_eq!(row.get("allowed"), Some(&Value::Bool(false)));
        assert_eq!(
            row.get("why_not"),
            Some(&Value::Str("secret_custody_required".into()))
        );
    }

    #[tokio::test]
    async fn authority_why_denied_explains_single_action_gate() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_WHY_DENIED,
                map_value([("action", Value::Str(ACTION_PAIRING_DENY.into()))]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert_eq!(
            row.get("status"),
            Some(&Value::Str("step_up_required".into()))
        );
    }

    #[tokio::test]
    async fn health_summary_reports_kernel_registry_and_fact_status() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(ACTION_HEALTH_SUMMARY, Value::Null),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert_eq!(row.get("status"), Some(&Value::Str("ok".into())));
        assert!(matches!(row.get("registry"), Some(Value::Map(_))));
        assert!(matches!(row.get("process_status"), Some(Value::Map(_))));
        assert!(matches!(row.get("fact_cursor"), Some(Value::Int(_))));
    }

    #[tokio::test]
    async fn lineage_fact_read_uses_visibility_gate_and_operation_id() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        st.state
            .write_set(
                &Path::parse("state://chat/source/messages/lineage").unwrap(),
                Value::Str("lineage fact source".into()),
            )
            .await
            .unwrap();
        let mut sess = test_session(st.clone(), principal.clone());
        dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_VISIBILITY_STATE_READ,
                map_value([(
                    "path",
                    Value::Str("state://chat/source/messages/lineage".into()),
                )]),
            ),
        )
        .await
        .unwrap();

        let op_id = st
            .boot
            .kernel
            .facts
            .all_facts()
            .unwrap()
            .last()
            .map(|fact| fact.id.to_string())
            .expect("expected at least one fact");
        let err = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_LINEAGE_FACT_READ,
                map_value([("op_id", Value::Str(op_id.clone()))]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));

        let out = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_LINEAGE_FACT_BY_OPERATION,
                map_value([("op_id", Value::Str(op_id.clone()))]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert_eq!(row.get("op_id"), Some(&Value::Str(op_id)));
        assert!(matches!(row.get("input_ref"), Some(Value::Map(_))));
        assert!(matches!(row.get("outcome_ref"), Some(Value::Map(_))));
        assert_eq!(row.get("partial"), Some(&Value::Bool(true)));
        assert!(matches!(row.get("partial_reason"), Some(Value::Str(_))));
    }

    #[tokio::test]
    async fn lineage_trace_read_explicitly_marks_partial_projection() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        st.state
            .write_set(
                &Path::parse("state://chat/source/messages/trace").unwrap(),
                Value::Str("trace source".into()),
            )
            .await
            .unwrap();
        let mut sess = test_session(st.clone(), principal.clone());
        dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_VISIBILITY_STATE_READ,
                map_value([(
                    "path",
                    Value::Str("state://chat/source/messages/trace".into()),
                )]),
            ),
        )
        .await
        .unwrap();
        let process = st
            .boot
            .kernel
            .facts
            .all_facts()
            .unwrap()
            .last()
            .map(|fact| fact.caller.get())
            .expect("expected at least one fact");

        let out = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_LINEAGE_TRACE_READ,
                map_value([
                    ("process", Value::Int(process as i64)),
                    ("from", Value::Int(0)),
                    ("limit", Value::Int(8)),
                ]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert_eq!(row.get("partial"), Some(&Value::Bool(true)));
        assert!(matches!(row.get("partial_reason"), Some(Value::Str(_))));
        assert!(matches!(row.get("items"), Some(Value::List(items)) if !items.is_empty()));
    }

    #[tokio::test]
    async fn pairing_create_can_return_one_time_display_secret() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st.clone(), principal.clone());
        dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_EXTERNAL_INSTALLATION_INSTALL,
                map_value([
                    ("id", Value::Str("pairable".into())),
                    ("def", extension_installation("pairable", 0)),
                    ("expected_version", Value::Null),
                ]),
            ),
        )
        .await
        .unwrap();
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_PAIRING_CREATE,
                map_value([
                    (
                        "input",
                        map_value([
                            ("pairing_id", Value::Str("pair-ws".into())),
                            ("installation_id", Value::Str("pairable".into())),
                        ]),
                    ),
                    ("reveal_display_secret", Value::Bool(true)),
                ]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(m) = output_value(out) else {
            panic!("expected map")
        };
        assert!(matches!(m.get("display_secret"), Some(Value::Str(s)) if !s.is_empty()));
        assert_eq!(st.pairing_display.take_display_secret("pair-ws"), None);
    }

    #[tokio::test]
    async fn pairing_deny_requires_step_up() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let err = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_PAIRING_DENY,
                map_value([("pairing_id", Value::Str("pair-ws".into()))]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::StepUpRequired));
    }

    #[tokio::test]
    async fn generic_config_write_enforces_step_up_for_sensitive_prefixes() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let err = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_CONFIG_WRITE_CAS,
                map_value([
                    (
                        "path",
                        Value::Str("state://kernel/external-installations/acme".into()),
                    ),
                    ("value", extension_installation("acme", 0)),
                    ("expected_version", Value::Null),
                ]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::StepUpRequired));
    }

    #[tokio::test]
    async fn extension_installation_write_validates_admission_before_state_write() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st.clone(), principal.clone());
        let mut bad = extension_installation("acme", 0);
        let Value::Map(root) = &mut bad else {
            panic!("expected installation map")
        };
        let Some(Value::List(projections)) = root.get_mut("projections") else {
            panic!("expected projections")
        };
        let Some(Value::Map(provider)) = projections.first_mut() else {
            panic!("expected provider projection")
        };
        provider.insert(
            "namespace".into(),
            Value::Str("effect://external-provider/other".into()),
        );

        let err = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_EXTERNAL_INSTALLATION_INSTALL,
                map_value([
                    ("id", Value::Str("acme".into())),
                    ("def", bad.clone()),
                    ("expected_version", Value::Null),
                ]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));
        assert_eq!(
            st.state
                .read(&Path::parse("state://kernel/external-installations/acme").unwrap())
                .await
                .unwrap(),
            None
        );

        let err = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_CONFIG_WRITE_CAS,
                map_value([
                    (
                        "path",
                        Value::Str("state://kernel/external-installations/acme".into()),
                    ),
                    ("value", bad),
                    ("expected_version", Value::Null),
                ]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));
        assert_eq!(
            st.state
                .read(&Path::parse("state://kernel/external-installations/acme").unwrap())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn visibility_read_allows_root_business_state_after_step_up() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        st.state
            .write_set(
                &Path::parse("state://chat/source/messages/1").unwrap(),
                Value::Str("hello from chat".into()),
            )
            .await
            .unwrap();
        let before = fact_count(&st);
        let mut sess = test_session(st.clone(), principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_VISIBILITY_STATE_READ,
                map_value([("path", Value::Str("state://chat/source/messages/1".into()))]),
            ),
        )
        .await
        .unwrap();
        assert_eq!(output_value(out), Value::Str("hello from chat".into()));
        let after = fact_count(&st);
        assert!(
            after > before,
            "visibility read must execute through Operation/Fact, not backend side channel"
        );
    }

    #[tokio::test]
    async fn malformed_principal_identity_rejects_visibility_without_root_fallback() {
        let st = console_state();
        st.state
            .write_set(
                &Path::parse("state://chat/source/messages/1").unwrap(),
                Value::Str("hello from chat".into()),
            )
            .await
            .unwrap();
        let before = st.boot.kernel.processes.all_ids().len();
        let mut principal = root_principal();
        principal.identity_path = "not-a-path".into();
        let mut sess = test_session(st.clone(), principal.clone());

        let err = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_VISIBILITY_STATE_READ,
                map_value([("path", Value::Str("state://chat/source/messages/1".into()))]),
            ),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConsoleError::Operation(message) if message.contains("invalid principal identity path"))
        );
        assert_eq!(
            st.boot.kernel.processes.all_ids().len(),
            before,
            "malformed console principals must not fall back to root or spawn a process"
        );
    }

    #[tokio::test]
    async fn visibility_rejects_vault_and_requires_justification() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st.clone(), principal.clone());
        let err = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_VISIBILITY_STATE_READ,
                map_value([("path", Value::Str("state://chat/source/messages/1".into()))]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));

        let err = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(
                ACTION_VISIBILITY_STATE_READ,
                map_value([(
                    "path",
                    Value::Str("state://vault/console/root/password".into()),
                )]),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));
        assert!(audit_outcomes(&st, "console_visibility").contains(&"state_read_blocked".into()));
        let visibility_facts = st
            .boot
            .kernel
            .facts
            .all_facts()
            .unwrap()
            .into_iter()
            .filter(|fact| match &fact.outcome_ref {
                nexus_types::OutcomeRef::Inline(Value::Map(m)) => {
                    m.get("event").and_then(Value::as_str) == Some("console_visibility")
                }
                _ => false,
            })
            .map(|fact| serde_json::to_string(&fact).unwrap())
            .collect::<Vec<_>>();
        assert!(
            visibility_facts
                .iter()
                .any(|fact| fact.contains("state://vault/**"))
        );
        assert!(
            !visibility_facts
                .iter()
                .any(|fact| fact.contains("state://vault/console/root/password"))
        );
    }

    #[tokio::test]
    async fn invalid_json_envelope_is_rejected() {
        let st = console_state();
        let (_token, principal, _password) = root_login(&st).await;
        let mut sess = test_session(st, principal.clone());
        let err = dispatch_call(
            &mut sess,
            &principal,
            ActionCall {
                action: ACTION_CONFIG_READ.into(),
                input: JsonBytes("{".into()),
                scope: None,
                justification: None,
                ttl_ms: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ConsoleError::BadRequest(message) if message.contains("invalid JSON Value envelope")
        ));
    }

    #[tokio::test]
    async fn snapshot_runtime_facts_require_visibility_gate() {
        let st = console_state();
        let (token, principal, password) = root_login(&st).await;
        let mut sess = test_session(st.clone(), principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_STATE_SNAPSHOT,
                map_value([(
                    "sections",
                    Value::List(vec![map_value([("kind", Value::Str("runtime".into()))])]),
                )]),
            ),
        )
        .await
        .unwrap();
        let Value::Map(row) = output_value(out) else {
            panic!("expected map")
        };
        assert!(matches!(row.get("server_rev"), Some(Value::Int(_))));
        assert!(matches!(row.get("registry_rev"), Some(Value::Int(_))));
        assert!(matches!(row.get("fact_cursor"), Some(Value::Int(_))));
        assert!(matches!(row.get("truncated"), Some(Value::List(_))));

        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st, principal.clone());
        let input = map_value([(
            "sections",
            Value::List(vec![map_value([
                ("kind", Value::Str("runtime".into())),
                ("include_recent_facts", Value::Bool(true)),
            ])]),
        )]);
        let err = dispatch_call(
            &mut sess,
            &principal,
            call(ACTION_STATE_SNAPSHOT, input.clone()),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));

        let out = dispatch_call(
            &mut sess,
            &principal,
            visibility_call(ACTION_STATE_SNAPSHOT, input),
        )
        .await
        .unwrap();
        assert!(matches!(output_value(out), Value::Map(_)));
    }

    #[tokio::test]
    async fn subscription_rejects_resume_without_replacing_existing_subscription() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let mut sess = test_session(st, principal.clone());
        let (shutdown, _rx) = tokio::sync::oneshot::channel();
        sess.subscriptions
            .insert(7, SubscriptionHandle { shutdown });

        let err = subscribe(
            &mut sess,
            &principal,
            7,
            StreamCall {
                stream: STREAM_STATE_WATCH.into(),
                input: JsonBytes::from_value(&map_value([(
                    "pattern",
                    Value::Str("state://kernel/**".into()),
                )])),
                scope: Some("test".into()),
                justification: Some("test stream".into()),
                ttl_ms: Some(60_000),
                since_rev: Some(1),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));
        assert!(sess.subscriptions.contains_key(&7));
    }

    #[tokio::test]
    async fn subscription_rejects_vault_or_global_state_patterns() {
        let st = console_state();
        let (token, _principal, password) = root_login(&st).await;
        let principal = step_up_principal(&st, &token, password).await;
        let (tx, _rx) = mpsc::channel(1);
        let mut sess = WsSession {
            state: st,
            principal: Some(principal.clone()),
            sid: Some("not-used".into()),
            hello_accepted: true,
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
            StreamCall {
                stream: STREAM_STATE_WATCH.into(),
                input: JsonBytes::from_value(&map_value([(
                    "pattern",
                    Value::Str("state://vault/**".into()),
                )])),
                scope: Some("test".into()),
                justification: Some("test stream".into()),
                ttl_ms: Some(60_000),
                since_rev: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));

        let err = subscribe(
            &mut sess,
            &principal,
            2,
            StreamCall {
                stream: STREAM_STATE_WATCH.into(),
                input: JsonBytes::from_value(&map_value([(
                    "pattern",
                    Value::Str("state://**".into()),
                )])),
                scope: Some("test".into()),
                justification: Some("test stream".into()),
                ttl_ms: Some(60_000),
                since_rev: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConsoleError::BadRequest(_)));
    }

    #[test]
    fn origin_host_and_port_must_match_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local:9443".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "https://console.local:9443".parse().unwrap(),
        );
        let cfg = ConsoleTransportSecurityConfig::default();
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_ok());
        headers.insert(
            header::ORIGIN,
            "https://console.local:8080".parse().unwrap(),
        );
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_err());
        headers.insert(
            header::ORIGIN,
            "https://attacker.local:9443".parse().unwrap(),
        );
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_err());
    }

    #[test]
    fn ignore_origin_port_relaxation_allows_only_port_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local:9443".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "https://console.local:8080".parse().unwrap(),
        );
        let cfg = ConsoleTransportSecurityConfig {
            unsafe_relaxations: vec![ConsoleUnsafeTransportRelaxation::IgnoreOriginPort],
            ..ConsoleTransportSecurityConfig::default()
        };
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_ok());
        headers.insert(
            header::ORIGIN,
            "https://attacker.local:8080".parse().unwrap(),
        );
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_err());
    }

    #[test]
    fn trusted_proxy_uses_forwarded_external_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:9000".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "https://console.example.com".parse().unwrap(),
        );
        headers.insert("x-forwarded-host", "console.example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let proxy_ip = "127.0.0.1".parse().unwrap();
        let cfg = ConsoleTransportSecurityConfig {
            mode: ConsoleTransportSecurityMode::TrustedReverseProxy,
            trusted_proxy: ConsoleTrustedProxyConfig {
                peers: vec![proxy_ip],
                ..ConsoleTrustedProxyConfig::default()
            },
            unsafe_relaxations: Vec::new(),
        };
        let peer = SocketAddr::new(proxy_ip, 12345);
        assert!(validate_upgrade_headers(&headers, Some(peer), &cfg).is_ok());
        let untrusted_peer = SocketAddr::new("127.0.0.2".parse().unwrap(), 12345);
        assert!(validate_upgrade_headers(&headers, Some(untrusted_peer), &cfg).is_err());
    }

    #[test]
    fn origin_and_host_are_required() {
        let mut headers = HeaderMap::new();
        let cfg = ConsoleTransportSecurityConfig::default();
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_err());
        headers.insert(header::ORIGIN, "https://console.local".parse().unwrap());
        assert!(validate_upgrade_headers(&headers, None, &cfg).is_err());
    }
}
