//! Console WebSocket protocol endpoint.

mod facts;
mod outbound;
mod subscriptions;

use subscriptions::{SubscriptionEvent, Subscriptions};

use crate::auth::{self, ConsolePrincipal, SessionSummary};
use crate::mgmt::{self, MgmtError};
use crate::protocol::{
    self, ACTION_ACCESS_ROLE_LIST, ACTION_ACCESS_ROLE_READ, ACTION_ACCESS_ROLE_WRITE_CAS,
    ACTION_ACCESS_SESSION_CURRENT_LOGOUT, ACTION_ACCESS_SESSION_LIST, ACTION_ACCESS_SESSION_REVOKE,
    ACTION_ACCESS_SESSION_REVOKE_USER, ACTION_ACCESS_USER_DISABLE, ACTION_ACCESS_USER_LIST,
    ACTION_ACCESS_USER_READ, ACTION_ACCESS_USER_WRITE_CAS, ACTION_AUDIT_FACTS_RECENT,
    ACTION_AUTHORITY_ACTION_MATRIX, ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
    ACTION_AUTHORITY_RESOURCE_ACCESS, ACTION_AUTHORITY_WHY_DENIED, ACTION_CONFIG_LIST,
    ACTION_CONFIG_READ, ACTION_CONFIG_WRITE_CAS, ACTION_EXTERNAL_INSTALLATION_INSTALL,
    ACTION_EXTERNAL_INSTALLATION_LIST, ACTION_EXTERNAL_INSTALLATION_READ,
    ACTION_EXTERNAL_INSTALLATION_REVOKE, ACTION_EXTERNAL_INSTALLATION_START,
    ACTION_EXTERNAL_INSTALLATION_STOP, ACTION_EXTERNAL_INSTALLATION_UPDATE,
    ACTION_EXTERNAL_MANIFEST_LIST, ACTION_EXTERNAL_MANIFEST_READ,
    ACTION_EXTERNAL_MANIFEST_WRITE_CAS, ACTION_HEALTH_SUMMARY, ACTION_INFERENCE_BACKEND_LIST,
    ACTION_INFERENCE_BACKEND_READ, ACTION_INFERENCE_BACKEND_WRITE_CAS, ACTION_INFERENCE_GROUP_LIST,
    ACTION_INFERENCE_GROUP_READ, ACTION_INFERENCE_GROUP_WRITE_CAS, ACTION_INFERENCE_MODEL_LIST,
    ACTION_INFERENCE_MODEL_READ, ACTION_INFERENCE_MODEL_WRITE_CAS, ACTION_INFERENCE_ROUTING_READ,
    ACTION_INFERENCE_ROUTING_WRITE_CAS, ACTION_LINEAGE_FACT_READ, ACTION_LINEAGE_TRACE_READ,
    ACTION_PAIRING_APPROVE, ACTION_PAIRING_CREATE, ACTION_PAIRING_DENY, ACTION_PAIRING_REPLACE,
    ACTION_PROJECTION_IN_PROCESS_STATUS_LIST, ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
    ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET, ACTION_PROTOCOL_DESCRIBE,
    ACTION_PROTOCOL_REGISTRY_SNAPSHOT, ACTION_REGISTRY_COVERAGE_REPORT,
    ACTION_RESOURCE_TYPE_DESCRIBE, ACTION_RESOURCE_TYPE_LIST, ACTION_RESOURCE_VIEW_DESCRIBE,
    ACTION_RUNTIME_PROCESS_INSPECT, ACTION_SECRET_CATALOG, ACTION_SECRET_REVEAL,
    ACTION_STATE_SNAPSHOT, ACTION_VISIBILITY_AUTHORITY_DESCRIBE, ACTION_VISIBILITY_STATE_LIST,
    ACTION_VISIBILITY_STATE_READ, ActionCall, ActionDescriptor, ActionResult, ClientFrame,
    ConsoleErrorCode, PrincipalSummary, RequiredAuthority, STREAM_AUDIT_FACTS, STREAM_STATE_WATCH,
    ServerFrame, StreamCall,
};
use crate::recipes::{self, StateMethod as RecipeStateMethod};
use crate::state::{
    ConsoleState, ConsoleWsLimit, HARD_MAX_WS_FACT_LIMIT, HARD_MAX_WS_FRAME_BYTES,
    HARD_MAX_WS_STATE_LIST_LIMIT, HARD_MAX_WS_SUBSCRIPTIONS,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use xolotl_types::{
    Capability, ExternalInstallationDef, OperationId, Path, ProcSpec, ProcessId, RestartPolicy,
    Transport, Value, ValueMap, ValueView,
};

const MAX_VISIBILITY_TTL_MS: u64 = 10 * 60 * 1000;

/// Upgrade an authenticated HTTP request path to the Console Protocol
/// WebSocket endpoint.
pub(crate) async fn upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(st): State<Arc<ConsoleState>>,
) -> Response {
    let source_addr = crate::verified_source_addr(&headers, Some(peer), &st.transport_security);
    if let Err(message) = validate_upgrade_headers_audited(&st, &headers, Some(peer)) {
        return (StatusCode::FORBIDDEN, message).into_response();
    }
    // Downgrade protection: if the client offers any subprotocol, exactly the
    // protobuf console subprotocol must be among them. A client offering only a
    // unknown subprotocol is rejected.
    if let Some(offered) = headers.get("sec-websocket-protocol")
        && !offered
            .to_str()
            .map(|raw| raw.split(',').any(|p| p.trim() == protocol::SUBPROTOCOL))
            .unwrap_or(false)
    {
        record_ws_audit(&st, None, Some(&source_addr), "unsupported_subprotocol");
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "console websocket requires the {} subprotocol",
                protocol::SUBPROTOCOL
            ),
        )
            .into_response();
    }
    if let Err(limit) = st.ws.try_acquire_source(&source_addr) {
        let message = ws_limit_message(limit);
        record_ws_audit(&st, None, Some(&source_addr), "rate_limited");
        return (StatusCode::TOO_MANY_REQUESTS, message).into_response();
    }
    let max_frame_bytes = st.ws.config().max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    ws.protocols([protocol::SUBPROTOCOL])
        .max_message_size(max_frame_bytes)
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

pub(crate) struct WsSession {
    pub(crate) state: Arc<ConsoleState>,
    principal: Option<ConsolePrincipal>,
    sid: Option<String>,
    hello_accepted: bool,
    source_addr: String,
    counted_user: Option<String>,
    subscriptions: Subscriptions,
    rate: FrameRate,
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
    let subscriptions = Subscriptions::new(state.ws.config());
    let mut sess = WsSession {
        state,
        principal: None,
        sid: None,
        hello_accepted: false,
        source_addr,
        counted_user: None,
        subscriptions,
        rate: FrameRate::default(),
    };
    let mut idle = Box::pin(tokio::time::sleep(sess.state.ws.config().idle_timeout));

    loop {
        if sess.subscriptions.failed() {
            break;
        }
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
                if let Err(error) = outbound::send_frame(&mut tx, reply, sess.state.ws.config()).await {
                    record_ws_send_error(&sess, &error);
                    break;
                }
                if close_after {
                    break;
                }
            }
            event = sess.subscriptions.next() => {
                let SubscriptionEvent { stream, bytes, budget, deadline } = match event {
                    Ok(event) => event,
                    Err(error) => {
                        record_ws_send_error(&sess, &outbound::SendError::Encode(error));
                        break;
                    }
                };
                if let Err(frame) = authenticated_principal(&mut sess, None).await {
                    if let Err(error) = outbound::send_frame(&mut tx, *frame, sess.state.ws.config()).await {
                        record_ws_send_error(&sess, &error);
                    }
                    break;
                }
                if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
                    tracing::debug!(stream, "console subscription event expired before delivery");
                    continue;
                }
                let send_deadline = tokio::time::Instant::now() + sess.state.ws.config().send_timeout;
                let send_deadline = deadline.map_or(send_deadline, |expiry| expiry.min(send_deadline));
                let delivered = outbound::send_encoded_until(&mut tx, bytes, send_deadline).await;
                drop(budget);
                if let Err(error) = delivered {
                    record_ws_send_error(&sess, &error);
                    record_ws_audit(&sess.state, sess.principal.as_ref(), Some(&sess.source_addr), "backpressure_close");
                    break;
                }
            }
        }
    }

    sess.subscriptions.shutdown().await;
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
                message: "console websocket only accepts binary protobuf frames".into(),
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
                    sess.counted_user = Some(principal.username.clone());
                    sess.subscriptions.shutdown().await;
                    if sess.subscriptions.failed() {
                        sess.sid = None;
                        return ServerFrame::Error {
                            id: None,
                            code: ConsoleErrorCode::Internal,
                            message: "previous subscriptions could not be stopped".into(),
                        };
                    }
                    let summary = PrincipalSummary::from(&principal);
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
                Err(frame) => return *frame,
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
                Err(frame) => return *frame,
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
                return *frame;
            }
            if let Err(error) = sess.subscriptions.stop(id).await {
                return console_error_frame(Some(id), ConsoleError::Operation(error.to_string()));
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
) -> Result<ConsolePrincipal, Box<ServerFrame>> {
    let Some(sid) = sess.sid.clone() else {
        record_ws_audit(
            &sess.state,
            None,
            Some(&sess.source_addr),
            "not_authenticated",
        );
        return Err(Box::new(ServerFrame::Error {
            id,
            code: ConsoleErrorCode::NotAuthenticated,
            message: "not authenticated".into(),
        }));
    };
    match sess
        .state
        .auth
        .authenticate_sid(&sess.state.boot, &sid)
        .await
    {
        Ok(p) => refresh_principal(sess, p, id),
        Err(e) => {
            record_ws_audit(
                &sess.state,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "invalid_session",
            );
            sess.sid = None;
            Err(Box::new(auth_error_frame(id, e)))
        }
    }
}

fn refresh_principal(
    sess: &mut WsSession,
    principal: ConsolePrincipal,
    id: Option<u64>,
) -> Result<ConsolePrincipal, Box<ServerFrame>> {
    if sess
        .principal
        .as_ref()
        .is_some_and(|previous| previous != &principal)
    {
        record_ws_audit(
            &sess.state,
            sess.principal.as_ref(),
            Some(&sess.source_addr),
            "authority_changed",
        );
        sess.sid = None;
        return Err(Box::new(ServerFrame::Error {
            id,
            code: ConsoleErrorCode::Forbidden,
            message: "console session authority changed; reconnect and authorize new subscriptions"
                .into(),
        }));
    }
    sess.principal = Some(principal.clone());
    Ok(principal)
}

async fn dispatch_call(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let action = call.action.clone();
    if matches!(
        protocol::action_status(&action),
        Some(protocol::ImplementationStatus::Planned)
    ) {
        return Err(ConsoleError::BadRequest(format!(
            "console action is not executable: {action}"
        )));
    }
    let out = match action.as_str() {
        ACTION_PROTOCOL_DESCRIBE | ACTION_PROTOCOL_REGISTRY_SNAPSHOT => {
            protocol::protocol_metadata_to_value(protocol_metadata(sess))
        }
        ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET => {
            let mut input = input_map(input_value(&call.input)?)?;
            let action_id = string_arg(&mut input, "action")?;
            sess.state
                .registry
                .action_by_id(&action_id)
                .map(protocol::action_descriptor_to_value)
                .ok_or_else(|| {
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
        ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE => authority_principal_effective(principal)?,
        ACTION_AUTHORITY_ACTION_MATRIX => {
            let mut input = input_map(input_value(&call.input)?)?;
            let domain = optional_string_arg(&mut input, "domain")?;
            authority_action_matrix(principal, domain.as_deref())?
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
            let value = mgmt::inspect_config(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_CONFIG_LIST => {
            let mut input = input_map(input_value(&call.input)?)?;
            let prefix = string_arg(&mut input, "prefix")?;
            let entries = mgmt::inspect_config_prefix(&sess.state, principal, &prefix).await?;
            entries_value(entries)
        }
        ACTION_CONFIG_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let path = string_arg(&mut input, "path")?;
            let value = value_arg(&mut input, "value")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_config_write_safety(principal, &path)?;
            mgmt::write_config(&sess.state, principal, &path, value, expected_version).await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_USER_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let path = console_user_path(&username)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
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
            let path = console_user_path(&username)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, value, expected_version)
                .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_USER_DISABLE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let username = string_arg(&mut input, "username")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = console_user_path(&username)?;
            let Some(mut value) = mgmt::inspect(&sess.state, principal, &path).await? else {
                return Err(ConsoleError::BadRequest("unknown console user".into()));
            };
            match value.as_map().cloned() {
                Some(mut m) => {
                    m.insert("status".into(), Value::string("disabled".into()))
                        .map_err(|error| ConsoleError::BadRequest(error.to_string()))?;
                    value = Value::from(m);
                }
                _ => {
                    return Err(ConsoleError::BadRequest(
                        "console user must be an object".into(),
                    ));
                }
            }
            mgmt::write_dedicated_config(&sess.state, principal, &path, value, expected_version)
                .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_ACCESS_ROLE_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let role = string_arg(&mut input, "role")?;
            let path = console_role_path(&role)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
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
            let path = console_role_path(&role)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, value, expected_version)
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
            map_value([("count", Value::integer(1))])
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
            map_value([("count", Value::integer(count as i64))])
        }
        ACTION_RUNTIME_PROCESS_INSPECT => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?;
            let include_recent_facts =
                optional_bool_arg(&mut input, "include_recent_facts")?.unwrap_or(false);
            let limit = optional_usize_arg(&mut input, "limit")?.unwrap_or(64);
            let target = process.map(|pid| format!("process:{pid}"));
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "runtime_process_inspect",
                VisibilityAuditDetails::action(&call, target.as_deref()),
            )?;
            process_inspect(sess, principal, process, include_recent_facts, limit).await?
        }
        ACTION_AUDIT_FACTS_RECENT => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?;
            authorize_fact_read(principal, process)?;
            let query = facts::query(
                sess.state.ws.config(),
                facts::ReadKind::Recent,
                process,
                &mut input,
            )?;
            let target = process
                .map(|pid| fact_path(pid).map(|path| path.to_string()))
                .transpose()?
                .unwrap_or_else(|| "state://fact".into());
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "audit_facts_recent",
                VisibilityAuditDetails::action(&call, Some(&target)),
            )?;
            facts::read_page(
                &sess.state.boot.kernel.facts,
                query,
                facts::ReadKind::Recent,
            )?
        }
        ACTION_LINEAGE_TRACE_READ => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?
                .ok_or_else(|| ConsoleError::BadRequest("process is required".into()))?;
            authorize_fact_read(principal, Some(process))?;
            let query = facts::query(
                sess.state.ws.config(),
                facts::ReadKind::Trace,
                Some(process),
                &mut input,
            )?;
            let target = fact_path(process)?.to_string();
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "lineage_trace_read",
                VisibilityAuditDetails::action(&call, Some(&target)),
            )?;
            facts::read_page(&sess.state.boot.kernel.facts, query, facts::ReadKind::Trace)?
        }
        ACTION_LINEAGE_FACT_READ => {
            require_visibility_access(principal, &call)?;
            let mut input = input_map(input_value(&call.input)?)?;
            let op_id = parse_operation_id(&string_arg(&mut input, "op_id")?)?;
            let process =
                facts::optional_cursor_arg(&mut input, "process")?.unwrap_or(op_id.process.get());
            authorize_fact_read(principal, Some(process))?;
            let max_bytes = facts::byte_limit(
                sess.state.ws.config(),
                optional_usize_arg(&mut input, "max_bytes")?,
            )?;
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "lineage_fact_read",
                VisibilityAuditDetails::action(&call, Some(&format!("operation:{op_id}"))),
            )?;
            facts::read_detail(
                &sess.state.boot.kernel.facts,
                xolotl_kernel::FactLookup {
                    id: op_id,
                    process: Some(ProcessId::new(process)),
                    max_encoded_bytes: max_bytes,
                },
            )?
        }
        ACTION_HEALTH_SUMMARY => health_summary(sess, principal).await?,
        ACTION_EXTERNAL_INSTALLATION_LIST => {
            let entries = mgmt::inspect_prefix(
                &sess.state,
                principal,
                "state://kernel/external-installations",
            )
            .await?;
            entries_value(entries)
        }
        ACTION_EXTERNAL_INSTALLATION_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = external_installation_path(&id)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_EXTERNAL_INSTALLATION_INSTALL | ACTION_EXTERNAL_INSTALLATION_UPDATE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = external_installation_path(&id)?;
            validate_external_installation_def(&id, &def)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, def, expected_version)
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
            let installation = read_external_installation(sess, principal, &id).await?;
            invoke_effect(
                sess,
                principal,
                "effect://proc/kill",
                map_value([("id", Value::string(installation.id))]),
            )
            .await?
        }
        ACTION_EXTERNAL_INSTALLATION_REVOKE => {
            let mut input = input_map(input_value(&call.input)?)?;
            let installation_id = string_arg(&mut input, "installation_id")?;
            let credential_generation_floor =
                optional_i64_arg(&mut input, "credential_generation_floor")?;
            require_step_up(principal)?;
            if matches!(credential_generation_floor, Some(floor) if floor < 1) {
                return Err(ConsoleError::BadRequest(
                    "credential_generation_floor must be at least 1".into(),
                ));
            }
            let installation =
                read_external_installation(sess, principal, &installation_id).await?;
            let mut m = BTreeMap::new();
            m.insert("installation_id".into(), Value::string(installation.id));
            if let Some(floor) = credential_generation_floor {
                m.insert("credential_generation_floor".into(), Value::integer(floor));
            }
            invoke_effect(sess, principal, "effect://external/revoke", Value::map(m)).await?
        }
        ACTION_EXTERNAL_MANIFEST_LIST => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/manifests").await?;
            entries_value(entries)
        }
        ACTION_EXTERNAL_MANIFEST_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let platform = string_arg(&mut input, "platform")?;
            let path = external_manifest_path(&platform)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_EXTERNAL_MANIFEST_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let platform = string_arg(&mut input, "platform")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = external_manifest_path(&platform)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_PROJECTION_IN_PROCESS_STATUS_LIST => {
            let entries = mgmt::inspect_prefix(
                &sess.state,
                principal,
                "state://kernel/projection-status/in-process",
            )
            .await?;
            entries_value(entries)
        }
        ACTION_PROJECTION_IN_PROCESS_STATUS_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = projection_status_path(&id)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_BACKEND_LIST => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/inference/backends")
                    .await?;
            entries_value(entries)
        }
        ACTION_INFERENCE_BACKEND_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = inference_backend_path(&id)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_BACKEND_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = inference_backend_path(&id)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_INFERENCE_MODEL_LIST => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/inference/models")
                    .await?;
            entries_value(entries)
        }
        ACTION_INFERENCE_MODEL_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let path = inference_model_path(&id)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_MODEL_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let id = string_arg(&mut input, "id")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = inference_model_path(&id)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_INFERENCE_GROUP_LIST => {
            let entries =
                mgmt::inspect_prefix(&sess.state, principal, "state://kernel/inference/groups")
                    .await?;
            entries_value(entries)
        }
        ACTION_INFERENCE_GROUP_READ => {
            let mut input = input_map(input_value(&call.input)?)?;
            let name = string_arg(&mut input, "name")?;
            let path = inference_group_path(&name)?;
            let value = mgmt::inspect(&sess.state, principal, &path).await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_GROUP_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let name = string_arg(&mut input, "name")?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            let path = inference_group_path(&name)?;
            mgmt::write_dedicated_config(&sess.state, principal, &path, def, expected_version)
                .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
        }
        ACTION_INFERENCE_ROUTING_READ => {
            let value =
                mgmt::inspect(&sess.state, principal, "state://kernel/routing/inference").await?;
            value.unwrap_or(Value::null())
        }
        ACTION_INFERENCE_ROUTING_WRITE_CAS => {
            let mut input = input_map(input_value(&call.input)?)?;
            let def = value_arg(&mut input, "def")?;
            let expected_version = optional_u64_arg(&mut input, "expected_version")?;
            require_step_up(principal)?;
            mgmt::write_dedicated_config(
                &sess.state,
                principal,
                "state://kernel/routing/inference",
                def,
                expected_version,
            )
            .await?;
            return Ok(ActionResult::empty(server_rev(sess)));
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
                    ("pairing_id", Value::string(pairing_id)),
                    (
                        "approved_roles",
                        Value::list(approved_roles.into_iter().map(Value::string).collect()),
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
                map_value([("pairing_id", Value::string(pairing_id))]),
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
    sess.subscriptions.reap_finished();
    let max_subscriptions = sess
        .state
        .ws
        .config()
        .max_subscriptions
        .min(HARD_MAX_WS_SUBSCRIPTIONS);
    if sess.subscriptions.len() >= max_subscriptions && !sess.subscriptions.contains(id) {
        return Err(ConsoleError::RateLimited);
    }
    if stream.since_rev.is_some() {
        return Err(ConsoleError::BadRequest(
            "since_rev is invalid for live-only console streams".into(),
        ));
    }
    if !matches!(
        stream.stream.as_str(),
        STREAM_STATE_WATCH | STREAM_AUDIT_FACTS
    ) {
        return Err(ConsoleError::BadRequest(format!(
            "unknown console stream: {}",
            stream.stream
        )));
    }
    require_stream_visibility_access(principal, &stream)?;
    let ttl_ms = stream
        .ttl_ms
        .ok_or_else(|| ConsoleError::BadRequest("visibility access requires ttl_ms".into()))?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ttl_ms);

    match stream.stream.as_str() {
        STREAM_STATE_WATCH => {
            let mut input = input_map(input_value(&stream.input)?)?;
            let pattern = Path::parse(&string_arg(&mut input, "pattern")?)?;
            ensure_observable_state_path(&pattern)?;
            auth::authorize_path(&sess.state.state, principal, "subscribe", &pattern, None).await?;
            let rx = sess.state.state.subscribe(&pattern).await?;
            let target = pattern.to_string();
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "state_watch",
                VisibilityAuditDetails::stream(&stream, Some(&target)),
            )?;
            sess.subscriptions
                .replace(id, rx, subscriptions::state_event, "state", deadline)
                .await
                .map_err(|error| ConsoleError::Operation(error.to_string()))?;
            Ok(())
        }
        STREAM_AUDIT_FACTS => {
            let mut input = input_map(input_value(&stream.input)?)?;
            let process = facts::optional_cursor_arg(&mut input, "process")?;
            authorize_fact_read(principal, process)?;
            let max_bytes = facts::byte_limit(
                sess.state.ws.config(),
                optional_usize_arg(&mut input, "max_bytes")?,
            )?;
            let target = process
                .map(|pid| fact_path(pid).map(|path| path.to_string()))
                .transpose()?
                .unwrap_or_else(|| "state://fact".into());
            record_visibility_audit(
                &sess.state,
                principal,
                Some(&sess.source_addr),
                "audit_facts_stream",
                VisibilityAuditDetails::stream(&stream, Some(&target)),
            )?;
            let sink = sess.state.boot.kernel.facts.clone();
            let receiver = sink.store().subscribe_facts();
            let project = facts::live_projection(sink, process, max_bytes);
            sess.subscriptions
                .replace(id, receiver, project, "fact", deadline)
                .await
                .map_err(|error| ConsoleError::Operation(error.to_string()))?;
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
        Some(value) => value.into_list().ok_or_else(|| {
            ConsoleError::BadRequest("sections must be a list of section maps".into())
        })?,
        None => vec![
            map_value([
                ("kind", Value::string("kernel_config".into())),
                ("prefix", Value::string("state://kernel".into())),
            ]),
            map_value([("kind", Value::string("sessions".into()))]),
            map_value([
                ("kind", Value::string("runtime".into())),
                ("limit", Value::integer(64)),
            ]),
        ]
        .into(),
    };

    let mut out = BTreeMap::new();
    out.insert("server_rev".into(), Value::integer(server_rev(sess) as i64));
    out.insert(
        "registry_rev".into(),
        Value::integer(registry_rev(sess) as i64),
    );
    out.insert(
        "fact_cursor".into(),
        facts::cursor_value(sess.state.boot.kernel.facts.cursor()),
    );
    out.insert("truncated".into(), Value::list(Vec::new()));
    if let Some(since_rev) = since_rev {
        out.insert("since_rev".into(), Value::integer(since_rev as i64));
    }
    for section in &sections {
        let mut section = input_map(section.clone())?;
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
                if out.contains_key("runtime") {
                    return Err(ConsoleError::BadRequest(
                        "runtime snapshot section may be requested only once".into(),
                    ));
                }
                let process = facts::optional_cursor_arg(&mut section, "process")?;
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
                    process_inspect(sess, principal, process, include_recent_facts, limit).await?;
                out.insert("runtime".into(), runtime);
            }
            other => {
                return Err(ConsoleError::BadRequest(format!(
                    "unknown snapshot section kind: {other}"
                )));
            }
        }
    }
    Ok(Value::map(out))
}

async fn visibility_state_read(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<Value, ConsoleError> {
    let path = Path::parse(path)?;
    ensure_observable_state_path(&path)?;
    auth::authorize_path(&sess.state.state, principal, "read", &path, None).await?;
    run_state_op(sess, principal, path, "read", Value::null()).await
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
    let mut out = run_state_op(sess, principal, prefix, "list", Value::null()).await?;
    if let Some(items) = out.as_list() {
        let max = bounded_limit(
            limit,
            sess.state.ws.config().max_state_list_limit,
            HARD_MAX_WS_STATE_LIST_LIMIT,
        );
        if items.len() > max {
            out = Value::list(items.iter().take(max).cloned().collect());
        }
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
    let state_method = match method {
        "read" => RecipeStateMethod::Read,
        "list" => RecipeStateMethod::List,
        "write" => RecipeStateMethod::Write,
        "append" => RecipeStateMethod::Append,
        "delete" => RecipeStateMethod::Delete,
        other => {
            return Err(ConsoleError::Operation(format!(
                "unsupported state method: {other}"
            )));
        }
    };
    let compiled = recipes::CompiledRecipe::state(path, state_method, input)
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    recipes::execute(sess, principal, compiled).await
}

async fn process_inspect(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    process: Option<u64>,
    include_recent_facts: bool,
    limit: usize,
) -> Result<Value, ConsoleError> {
    require_process_inspect(principal)?;
    if include_recent_facts {
        if process.is_none() {
            return Err(ConsoleError::BadRequest(
                "include_recent_facts requires an explicit process".into(),
            ));
        }
        authorize_fact_read(principal, process)?;
    }
    let limit = bounded_limit(
        limit,
        sess.state.ws.config().max_fact_limit,
        HARD_MAX_WS_FACT_LIMIT,
    );
    let recent_query = if include_recent_facts {
        Some(facts::query(
            sess.state.ws.config(),
            facts::ReadKind::Recent,
            process,
            &mut ValueMap::from(BTreeMap::from([(
                "limit".into(),
                Value::integer(limit as i64),
            )])),
        )?)
    } else {
        None
    };
    let process_ids = match process {
        Some(process) => vec![ProcessId::new(process)],
        None => sess.state.boot.kernel.processes.all_ids(),
    };
    let mut rows = Vec::with_capacity(process_ids.len());
    for process in process_ids {
        let mut row = BTreeMap::new();
        row.insert("process".into(), facts::cursor_value(process.get()));
        if let Some(status) = sess.state.boot.kernel.processes.status(process) {
            row.insert("status".into(), Value::string(format!("{status:?}")));
            row.insert("terminal".into(), Value::boolean(status.is_terminal()));
        } else {
            row.insert("status".into(), Value::string("Unknown".into()));
        }
        if let Some(identity) = sess.state.boot.kernel.processes.identity(process) {
            row.insert("identity".into(), facts::cursor_value(identity.get()));
        }
        let children = sess
            .state
            .boot
            .kernel
            .processes
            .children_of(process)
            .into_iter()
            .map(|child| facts::cursor_value(child.get()))
            .collect();
        row.insert("children".into(), Value::list(children));
        if let Some(mut query) = recent_query {
            query.process = Some(process);
            row.insert(
                "recent_facts".into(),
                facts::read_page(
                    &sess.state.boot.kernel.facts,
                    query,
                    facts::ReadKind::Recent,
                )?,
            );
        }
        rows.push(Value::map(row));
    }
    Ok(Value::list(rows))
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
        process_status.insert(status, Value::integer(next));
    }

    let registry = registry_counts_value(sess.state.boot.kernel.registry.counts());
    let cfg = sess.state.ws.config();
    Ok(map_value([
        ("status", Value::string("ok".into())),
        ("server_rev", Value::integer(server_rev(sess) as i64)),
        ("registry_rev", Value::integer(registry_rev(sess) as i64)),
        ("process_count", Value::integer(process_ids.len() as i64)),
        ("process_status", Value::map(process_status)),
        (
            "fact_sample",
            facts::sample(&sess.state.boot.kernel.facts, cfg)?,
        ),
        (
            "fact_cursor",
            facts::cursor_value(sess.state.boot.kernel.facts.cursor()),
        ),
        ("registry", registry),
        (
            "ws_limits",
            map_value([
                (
                    "max_frame_bytes",
                    Value::integer(cfg.max_frame_bytes as i64),
                ),
                (
                    "max_connections_global",
                    Value::integer(cfg.max_connections_global as i64),
                ),
                (
                    "max_connections_per_source",
                    Value::integer(cfg.max_connections_per_source as i64),
                ),
                (
                    "max_connections_per_user",
                    Value::integer(cfg.max_connections_per_user as i64),
                ),
                (
                    "max_subscriptions",
                    Value::integer(cfg.max_subscriptions as i64),
                ),
                (
                    "max_state_list_limit",
                    Value::integer(cfg.max_state_list_limit as i64),
                ),
                ("max_fact_limit", Value::integer(cfg.max_fact_limit as i64)),
                (
                    "max_trace_limit",
                    Value::integer(cfg.max_trace_limit as i64),
                ),
            ]),
        ),
    ]))
}

fn authority_principal_effective(principal: &ConsolePrincipal) -> Result<Value, ConsoleError> {
    let grants = principal
        .grants
        .iter()
        .map(|cap| Value::string(cap.to_string()))
        .collect::<Vec<_>>();
    let root_data_authority = serde_value(protocol::protocol_metadata(0, 0).root_data_authority)?;
    Ok(map_value([
        ("username", Value::string(principal.username.clone())),
        (
            "identity_path",
            Value::string(principal.identity_path.clone()),
        ),
        ("mfa_level", Value::integer(i64::from(principal.mfa_level))),
        ("grant_count", Value::integer(grants.len() as i64)),
        ("grants", Value::list(grants)),
        ("root_data_authority", root_data_authority),
    ]))
}

fn authority_action_matrix(
    principal: &ConsolePrincipal,
    domain: Option<&str>,
) -> Result<Value, ConsoleError> {
    let rows = protocol::action_descriptors()
        .into_iter()
        .filter(|descriptor| domain.is_none_or(|d| descriptor.domain == d))
        .map(|descriptor| authority_action_row(principal, &descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::list(rows))
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
    authority_action_row(principal, &descriptor)
}

fn authority_action_row(
    principal: &ConsolePrincipal,
    descriptor: &ActionDescriptor,
) -> Result<Value, ConsoleError> {
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
    let risk = serde_value(&descriptor.risk)?;
    let visibility = serde_value(&descriptor.visibility)?;
    let implementation_status = serde_value(&descriptor.status)?;
    Ok(map_value([
        ("action", Value::string(descriptor.id.clone())),
        ("domain", Value::string(descriptor.domain.clone())),
        ("status", Value::string(status.into())),
        ("risk", risk),
        ("visibility", visibility),
        ("implementation_status", implementation_status),
        ("authority_ok", Value::boolean(authority_ok)),
        (
            "requires_step_up",
            Value::boolean(descriptor.requires_step_up),
        ),
        ("mfa_level", Value::integer(i64::from(principal.mfa_level))),
        ("requires_visibility_gate", Value::boolean(visibility_gate)),
        ("authority", Value::list(checks)),
        (
            "why",
            Value::list(why.into_iter().map(Value::string).collect()),
        ),
    ]))
}

fn authority_required_check(principal: &ConsolePrincipal, required: &RequiredAuthority) -> Value {
    let mut row = BTreeMap::new();
    row.insert("verb".into(), Value::string(required.verb.clone()));
    row.insert("target".into(), Value::string(required.target.clone()));
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
            row.insert("allowed".into(), Value::boolean(allowed));
            row.insert("conditional".into(), Value::boolean(conditional));
            if !allowed {
                row.insert(
                    "why_not".into(),
                    Value::string(
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
            row.insert("allowed".into(), Value::boolean(false));
            row.insert("conditional".into(), Value::boolean(false));
            row.insert(
                "why_not".into(),
                Value::string(format!("descriptor authority is malformed: {e:?}")),
            );
        }
    }
    Value::map(row)
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
    let is_local_state = path.scheme() == "state" && path.cluster().is_none();
    if is_local_state && xolotl_types::is_vault_reserved(&path) {
        return Ok(map_value([
            ("target", Value::string(path.to_string())),
            ("verb", Value::string(verb.to_string())),
            ("allowed", Value::boolean(false)),
            ("why_not", Value::string("secret_custody_required".into())),
        ]));
    }

    let result = if matches!(verb, "read" | "write" | "subscribe") && is_local_state {
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
    row.insert("target".into(), Value::string(path.to_string()));
    row.insert("verb".into(), Value::string(verb.to_string()));
    match result {
        Ok(via) => {
            row.insert("allowed".into(), Value::boolean(true));
            row.insert("via".into(), Value::string(via.into()));
        }
        Err(e) => {
            row.insert("allowed".into(), Value::boolean(false));
            row.insert("why_not".into(), Value::string(e.to_string()));
        }
    }
    Ok(Value::map(row))
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
            match out.as_map().cloned() {
                Some(mut m) => {
                    m.insert("display_secret".into(), Value::string(secret))
                        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
                    out = Value::from(m);
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
    let def = read_external_installation(sess, principal, id).await?;
    Ok(proc_spec_from_transport(def.id, def.transport))
}

async fn read_external_installation(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    id: &str,
) -> Result<ExternalInstallationDef, ConsoleError> {
    let installation_path = external_installation_path(id)?;
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
    Ok(def)
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
    let compiled = recipes::CompiledRecipe::effect(path, input)
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    recipes::execute(sess, principal, compiled).await
}

fn decode_frame(bytes: &[u8], configured_max_frame_bytes: usize) -> Result<ClientFrame, String> {
    let max_frame_bytes = configured_max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    if bytes.len() > max_frame_bytes {
        return Err("frame exceeds console websocket limit".into());
    }
    crate::wire::decode_client_frame(bytes)
}

fn bounded_limit(requested: usize, configured: usize, hard: usize) -> usize {
    requested.min(configured).min(hard)
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn record_ws_send_error(sess: &WsSession, error: &outbound::SendError) {
    let username = sess.principal.as_ref().map(|p| p.username.as_str());
    match error {
        outbound::SendError::Transport(message) => {
            tracing::debug!(
                %message,
                username = username.unwrap_or("<anonymous>"),
                source_addr = sess.source_addr.as_str(),
                "console WebSocket transport send failed"
            );
        }
        outbound::SendError::Timeout | outbound::SendError::Encode(_) => {
            tracing::warn!(
                error = %error,
                username = username.unwrap_or("<anonymous>"),
                source_addr = sess.source_addr.as_str(),
                "console WebSocket frame send failed"
            );
        }
    }
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
pub(crate) enum ConsoleError {
    Auth(auth::AuthError),
    Mgmt(MgmtError),
    NotAuthenticated,
    StepUpRequired,
    RateLimited,
    BadRequest(String),
    Operation(String),
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsoleError::Auth(err) => write!(f, "auth error: {err}"),
            ConsoleError::Mgmt(err) => write!(f, "management error: {err:?}"),
            ConsoleError::NotAuthenticated => f.write_str("not authenticated"),
            ConsoleError::StepUpRequired => f.write_str("step-up required"),
            ConsoleError::RateLimited => f.write_str("rate limited"),
            ConsoleError::BadRequest(message) | ConsoleError::Operation(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for ConsoleError {}

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

impl From<xolotl_types::PathError> for ConsoleError {
    fn from(e: xolotl_types::PathError) -> Self {
        Self::BadRequest(e.to_string())
    }
}

impl From<xolotl_state::StateFailure> for ConsoleError {
    fn from(e: xolotl_state::StateFailure) -> Self {
        Self::Operation(e.to_string())
    }
}

impl From<xolotl_kernel::FactError> for ConsoleError {
    fn from(e: xolotl_kernel::FactError) -> Self {
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
    let username = principal.map(|p| p.username.as_str());
    let mfa_level = principal.map(|p| p.mfa_level);
    if let Err(error) = state
        .boot
        .record_gateway_audit(xolotl_kernel::GatewayAudit {
            event: "console_ws",
            username,
            source_addr,
            outcome,
            mfa_level,
            details: None,
        })
    {
        tracing::warn!(
            ?error,
            outcome,
            username = username.unwrap_or("<anonymous>"),
            source_addr = source_addr.unwrap_or("unknown"),
            "console WebSocket audit record failed"
        );
    }
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
        details.insert("scope".into(), Value::string(scope.to_string()));
    }
    if let Some(justification) = audit.justification {
        details.insert(
            "justification".into(),
            Value::string(justification.to_string()),
        );
    }
    if let Some(ttl_ms) = audit.ttl_ms {
        details.insert(
            "ttl_ms".into(),
            Value::integer(u64_to_i64_saturating(ttl_ms)),
        );
    }
    if let Some(target) = audit.target {
        details.insert("target".into(), Value::string(target.to_string()));
    }
    state
        .boot
        .record_gateway_audit(xolotl_kernel::GatewayAudit {
            event: "console_visibility",
            username: Some(principal.username.as_str()),
            source_addr,
            outcome,
            mfa_level: Some(principal.mfa_level),
            details: Some(Value::map(details)),
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
    Value::list(
        entries
            .into_iter()
            .map(|(path, value)| {
                let mut m = BTreeMap::new();
                m.insert("path".into(), Value::string(path));
                m.insert("value".into(), value);
                Value::map(m)
            })
            .collect(),
    )
}

fn sessions_value(sessions: &[SessionSummary]) -> Value {
    Value::list(
        sessions
            .iter()
            .map(|s| {
                let mut m = BTreeMap::new();
                m.insert("sid".into(), Value::string(s.sid.clone()));
                m.insert("username".into(), Value::string(s.username.clone()));
                m.insert(
                    "identity_path".into(),
                    Value::string(s.identity_path.clone()),
                );
                m.insert("issued_at".into(), Value::integer(s.issued_at));
                m.insert("expires_at".into(), Value::integer(s.expires_at));
                m.insert("idle_expires_at".into(), Value::integer(s.idle_expires_at));
                m.insert("mfa_level".into(), Value::integer(s.mfa_level as i64));
                m.insert("last_seen".into(), Value::integer(s.last_seen));
                m.insert("source_addr".into(), Value::string(s.source_addr.clone()));
                Value::map(m)
            })
            .collect(),
    )
}

fn registry_counts_value(counts: xolotl_kernel::registry::RegistryCounts) -> Value {
    map_value([
        ("resources", Value::integer(counts.resources as i64)),
        ("interfaces", Value::integer(counts.interfaces as i64)),
        ("drivers", Value::integer(counts.drivers as i64)),
        ("endpoints", Value::integer(counts.endpoints as i64)),
        ("bindings", Value::integer(counts.bindings as i64)),
        ("grants", Value::integer(counts.grants as i64)),
        ("policies", Value::integer(counts.policies as i64)),
        ("names", Value::integer(counts.names as i64)),
        (
            "open_cache_entries",
            Value::integer(counts.open_cache_entries as i64),
        ),
        (
            "open_cache_hits",
            Value::integer(counts.open_cache_hits as i64),
        ),
        (
            "open_cache_misses",
            Value::integer(counts.open_cache_misses as i64),
        ),
    ])
}

fn validate_upgrade_headers(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<(), String> {
    if let Some(path) = headers.get(":path") {
        let path = path
            .to_str()
            .map_err(|_error| "console websocket path header is malformed".to_string())?;
        if path != "/ws" {
            return Err("unexpected console websocket path".into());
        }
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
        .ok_or_else(|| format!("{label} origin header is required"))?
        .to_str()
        .map_err(|_error| format!("{label} origin header is malformed"))?;
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
    if let Some(proto) = external_forwarded_proto(label, headers, trusted_proxy, transport)?
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
            let port = match rest.strip_prefix(':') {
                Some(port) => Some(parse_origin_port(port, label)?),
                None if rest.is_empty() => None,
                None => return Err(format!("{label} host header is malformed")),
            };
            (host, port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.contains(':') || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("{label} host header is malformed"));
            }
            (host, Some(parse_origin_port(port, label)?))
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

fn parse_origin_port(raw: &str, label: &str) -> Result<u16, String> {
    if raw.is_empty() {
        return Err(format!("{label} host header is malformed"));
    }
    raw.parse::<u16>()
        .map_err(|_error| format!("{label} host header is malformed"))
}

fn external_host<'a>(
    label: &str,
    headers: &'a HeaderMap,
    trusted_proxy: bool,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<&'a str, String> {
    if trusted_proxy
        && transport.trusted_proxy.honor_x_forwarded_host
        && let Some(host) = headers.get("x-forwarded-host")
    {
        let host = host
            .to_str()
            .map_err(|_error| format!("{label} x-forwarded-host header is malformed"))?;
        return first_forwarded_header_value(label, "x-forwarded-host", host);
    }
    headers
        .get(header::HOST)
        .ok_or_else(|| format!("{label} host header is required"))
        .and_then(|host| {
            host.to_str()
                .map_err(|_error| format!("{label} host header is malformed"))
        })
}

fn external_forwarded_proto<'a>(
    label: &str,
    headers: &'a HeaderMap,
    trusted_proxy: bool,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<Option<&'a str>, String> {
    if !(trusted_proxy && transport.trusted_proxy.honor_x_forwarded_proto) {
        return Ok(None);
    }
    let Some(proto) = headers.get("x-forwarded-proto") else {
        return Ok(None);
    };
    let proto = proto
        .to_str()
        .map_err(|_error| format!("{label} x-forwarded-proto header is malformed"))?;
    let proto = first_forwarded_header_value(label, "x-forwarded-proto", proto)?;
    if !matches!(proto, "http" | "https") {
        return Err(format!("{label} x-forwarded-proto header is unsupported"));
    }
    Ok(Some(proto))
}

fn first_forwarded_header_value<'a>(
    label: &str,
    name: &str,
    value: &'a str,
) -> Result<&'a str, String> {
    let Some(first) = value.split(',').next() else {
        return Err(format!("{label} {name} header is malformed"));
    };
    let first = first.trim();
    if first.is_empty() {
        return Err(format!("{label} {name} header is malformed"));
    }
    Ok(first)
}

fn server_rev(sess: &WsSession) -> u64 {
    sess.state.boot.kernel.facts.cursor()
}

fn registry_rev(sess: &WsSession) -> u64 {
    sess.state.registry.current_rev()
}

fn protocol_metadata(sess: &WsSession) -> protocol::ProtocolMetadata {
    protocol::protocol_metadata_for_transport(
        server_rev(sess),
        registry_rev(sess),
        &sess.state.transport_security,
    )
}

fn ensure_observable_state_path(path: &Path) -> Result<(), ConsoleError> {
    if path.scheme() != "state" || path.cluster().is_some() {
        return Err(ConsoleError::BadRequest(
            "visibility.state actions require local state:// paths".into(),
        ));
    }
    if xolotl_types::is_vault_reserved(path) {
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
    if path.cluster().is_some() {
        return "non_local_state_target".into();
    }
    if xolotl_types::is_vault_reserved(&path) {
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
        Some(process) => fact_path(process)?,
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
    principal_identity_path(principal).map(|_| ())
}

pub(crate) fn principal_identity_path(principal: &ConsolePrincipal) -> Result<Path, ConsoleError> {
    let identity_path = Path::parse(&principal.identity_path)
        .map_err(|e| ConsoleError::Operation(format!("invalid principal identity path: {e}")))?;
    if identity_path.cluster().is_some()
        || identity_path.scheme() != "identity"
        || identity_path.segments().is_empty()
        || !identity_path.is_concrete()
    {
        return Err(ConsoleError::Operation(
            "invalid principal identity path: identity path must be a concrete local identity path"
                .into(),
        ));
    }
    Ok(identity_path)
}

fn require_config_write_safety(
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<(), ConsoleError> {
    let parsed = Path::parse(path)?;
    if mgmt::is_dedicated_runtime_config_path(&parsed) {
        return Err(ConsoleError::BadRequest(
            "runtime config path must use its dedicated console action".into(),
        ));
    }
    require_step_up(principal)?;
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

fn state_path_string(segments: &[&str]) -> Result<String, ConsoleError> {
    let mut path = Path::try_new("state")?;
    for segment in segments {
        path = path.try_push_literal(segment)?;
    }
    Ok(path.to_string())
}

fn kernel_state_path_string(segments: &[&str]) -> Result<String, ConsoleError> {
    let mut all_segments = Vec::with_capacity(segments.len().saturating_add(1));
    all_segments.push("kernel");
    all_segments.extend_from_slice(segments);
    state_path_string(&all_segments)
}

fn console_user_path(username: &str) -> Result<String, ConsoleError> {
    auth::validate_username(username)?;
    kernel_state_path_string(&["console", "users", username])
}

fn console_role_path(role: &str) -> Result<String, ConsoleError> {
    auth::validate_username(role)?;
    kernel_state_path_string(&["console", "roles", role])
}

fn external_installation_path(id: &str) -> Result<String, ConsoleError> {
    validate_path_segment(id, "external installation id")?;
    kernel_state_path_string(&["external-installations", id])
}

fn external_manifest_path(platform: &str) -> Result<String, ConsoleError> {
    validate_path_segment(platform, "external manifest platform")?;
    kernel_state_path_string(&["manifests", platform])
}

fn projection_status_path(id: &str) -> Result<String, ConsoleError> {
    validate_path_segment(id, "in-process projection id")?;
    kernel_state_path_string(&["projection-status", "in-process", id])
}

fn inference_backend_path(id: &str) -> Result<String, ConsoleError> {
    validate_path_segment(id, "inference backend id")?;
    kernel_state_path_string(&["inference", "backends", id])
}

fn inference_model_path(id: &str) -> Result<String, ConsoleError> {
    validate_path_segment(id, "inference model id")?;
    kernel_state_path_string(&["inference", "models", id])
}

fn inference_group_path(name: &str) -> Result<String, ConsoleError> {
    validate_path_segment(name, "inference group name")?;
    kernel_state_path_string(&["inference", "groups", name])
}

fn fact_path(process: u64) -> Result<Path, ConsoleError> {
    let path = Path::try_new("state")?
        .try_push_literal("fact")?
        .try_push_literal(process.to_string())?;
    Ok(path)
}

fn reject_secret_fields(input: &Value) -> Result<(), ConsoleError> {
    use std::collections::BTreeSet;
    use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
    if !matches!(input.view(), ValueView::Map(_) | ValueView::List(_)) {
        return Ok(());
    }
    let denied = ["pairing_secret", "secret", "raw_secret", "sas_verified"];
    let mut visited = BTreeSet::new();
    let mut walk = ValuePostorder::new(input);
    while let Some(node) = walk.next(|key| visited.contains(&key)) {
        if let Some(map) = node.as_map() {
            for key in map.keys() {
                if denied.contains(&key) {
                    return Err(ConsoleError::BadRequest(format!(
                        "{key} is not accepted in console pairing input"
                    )));
                }
            }
        }
        visited.insert(ValueNodeKey::of(node));
    }
    Ok(())
}

fn map_value(items: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::map(
        items
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn serde_value<T: Serialize>(value: T) -> Result<Value, ConsoleError> {
    let json = serde_json::to_value(value).map_err(|error| {
        ConsoleError::Operation(format!(
            "console value projection serialization failed: {error}"
        ))
    })?;
    serde_json::from_value(json).map_err(|error| {
        ConsoleError::Operation(format!(
            "console value projection conversion failed: {error}"
        ))
    })
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
        "planned" => why.push("descriptor is discoverable but not executable".into()),
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

fn input_value(input: &Value) -> Result<Value, ConsoleError> {
    Ok(input.clone())
}

fn input_map(input: Value) -> Result<ValueMap, ConsoleError> {
    if input.is_null() {
        return Ok(ValueMap::new());
    }
    input
        .into_map()
        .ok_or_else(|| ConsoleError::BadRequest("console action input must be a map".into()))
}

fn string_arg(input: &mut ValueMap, name: &str) -> Result<String, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Str(s)) if !s.is_empty() => Ok(s.to_owned()),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-empty string"
        ))),
        None => Err(ConsoleError::BadRequest(format!("{name} is required"))),
    }
}

fn optional_string_arg(input: &mut ValueMap, name: &str) -> Result<Option<String>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Str(s)) if !s.is_empty() => Ok(Some(s.to_owned())),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-empty string"
        ))),
    }
}

fn value_arg(input: &mut ValueMap, name: &str) -> Result<Value, ConsoleError> {
    input
        .remove(name)
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} is required")))
}

fn parse_operation_id(raw: &str) -> Result<OperationId, ConsoleError> {
    raw.parse()
        .map_err(|error| ConsoleError::BadRequest(format!("invalid op_id: {error}")))
}

fn optional_u64_arg(input: &mut ValueMap, name: &str) -> Result<Option<u64>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Int(i)) if i >= 0 => Ok(Some(i as u64)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-negative integer"
        ))),
    }
}

fn optional_i64_arg(input: &mut ValueMap, name: &str) -> Result<Option<i64>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Int(i)) => Ok(Some(i)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be an integer"
        ))),
    }
}

fn optional_usize_arg(input: &mut ValueMap, name: &str) -> Result<Option<usize>, ConsoleError> {
    optional_u64_arg(input, name)?
        .map(|v| {
            usize::try_from(v)
                .map_err(|_error| ConsoleError::BadRequest(format!("{name} is too large")))
        })
        .transpose()
}

fn validate_external_installation_def(id: &str, value: &Value) -> Result<(), ConsoleError> {
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

fn optional_bool_arg(input: &mut ValueMap, name: &str) -> Result<Option<bool>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Bool(b)) => Ok(Some(b)),
        Some(_) => Err(ConsoleError::BadRequest(format!("{name} must be a bool"))),
    }
}

fn string_list_arg(input: &mut ValueMap, name: &str) -> Result<Vec<String>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::List(items)) => items
            .iter()
            .map(|item| match item.view() {
                ValueView::Str(s) if !s.is_empty() => Ok(s.to_owned()),
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

pub(crate) fn capability_target(path: &Path) -> String {
    path.to_string().replacen("://", "/", 1)
}

pub(crate) fn capability_verb_for_state_method(method: &str) -> &'static str {
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
        ConsoleUnsafeTransportRelaxation, ConsoleWsConfig, ConsoleWsRuntime, PairingSecretDisplay,
    };
    use anyhow::{Context, bail, ensure};
    use std::collections::BTreeMap;
    use xolotl_kernel::Bootstrap;
    use xolotl_standard::{PairingDisplayEdge, StandardConfig, install_standard};
    use xolotl_types::{
        EffectCapability, ExternalProjectionDef, InferenceApiDialect, InferenceAuthRef,
        InferenceBackendDef, Purity, Role, Transport, TrustLevel,
    };

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
            Err(xolotl_kernel::FactError("unexpected fact scan".into()))
        }

        fn lookup(
            &self,
            _query: xolotl_kernel::FactLookup,
        ) -> Result<xolotl_kernel::FactLookupResult, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected fact lookup".into()))
        }

        fn append(&self, _fact: xolotl_types::Fact) -> Result<u64, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("simulated append failure".into()))
        }

        fn complete(&self, _fact: xolotl_types::Fact) -> Result<(), xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError(
                "simulated complete failure".into(),
            ))
        }

        fn sync(&self) -> Result<(), xolotl_kernel::FactError> {
            Ok(())
        }

        fn facts_of(
            &self,
            _process: xolotl_types::ProcessId,
        ) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError(
                "unexpected unbounded fact read".into(),
            ))
        }

        fn all_facts(&self) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError(
                "unexpected unbounded fact read".into(),
            ))
        }

        fn cursor(&self) -> u64 {
            0
        }
    }

    fn console_state() -> anyhow::Result<Arc<ConsoleState>> {
        let pairing_display = PairingDisplayEdge::default();
        let boot = Arc::new(Bootstrap::in_memory());
        let config = StandardConfig::default().with_pairing_display(pairing_display.clone());
        install_standard(&boot, &config).context("install standard package")?;
        ConsoleState::shared_with_pairing_display(boot, Arc::new(pairing_display))
            .context("create console state")
    }

    fn audit_outcomes(st: &ConsoleState, event: &str) -> anyhow::Result<Vec<String>> {
        Ok(st
            .boot
            .kernel
            .facts
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
        let subscriptions = Subscriptions::new(st.ws.config());
        WsSession {
            state: st,
            principal: Some(principal),
            sid: Some("not-used".into()),
            hello_accepted: true,
            source_addr: "test".into(),
            counted_user: None,
            subscriptions,
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
        let subscriptions = Subscriptions::new(st.ws.config());
        WsSession {
            state: st,
            principal: None,
            sid: None,
            hello_accepted: false,
            source_addr: "test".into(),
            counted_user: None,
            subscriptions,
            rate: FrameRate::default(),
        }
    }

    fn root_principal() -> anyhow::Result<ConsolePrincipal> {
        Ok(ConsolePrincipal {
            username: "root".into(),
            identity_path: "process://root".into(),
            grants: xolotl_types::CapSet::from_strs(["*://**"])?,
            mfa_level: 2,
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
        candidates[3].mfa_level = 1;
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
                    code: ConsoleErrorCode::Forbidden,
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
            xolotl_kernel::Kernel::with_backends(state, facts),
        ));
        let st = ConsoleState::shared(boot).context("create console state")?;
        let principal = root_principal()?;

        let err = match record_visibility_audit(
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

    async fn root_login(
        st: &Arc<ConsoleState>,
    ) -> anyhow::Result<(String, ConsolePrincipal, String)> {
        let outcome = bootstrap_root_account(&st.boot, RootProvisioning::default()).await?;
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
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        let principal = st.auth.authenticate_token(&st.boot, &login.token).await?;
        Ok((login.token, principal, password))
    }

    async fn step_up_principal(
        st: &Arc<ConsoleState>,
        token: &str,
        password: String,
    ) -> anyhow::Result<ConsolePrincipal> {
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
            .await?;
        Ok(st
            .auth
            .authenticate_token(&st.boot, &elevated.token)
            .await?)
    }

    async fn step_up_login(
        st: &Arc<ConsoleState>,
        token: &str,
        password: String,
    ) -> anyhow::Result<(String, ConsolePrincipal)> {
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
            .await?;
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
                command: Some(format!("{id}-plugin")),
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
        for pid in st.boot.kernel.processes.all_ids() {
            count = count
                .checked_add(st.boot.kernel.facts.facts_of(pid)?.len())
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
            result: ActionResult::value(Value::string("ok".into()), 11),
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
    async fn hello_rejects_unsupported_wire_encoding() -> anyhow::Result<()> {
        let st = console_state()?;
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
        ensure!(
            matches!(
                reply,
                ServerFrame::Error {
                    id: None,
                    code: ConsoleErrorCode::BadRequest,
                    ..
                }
            ),
            "unsupported encoding was accepted"
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
                    code: ConsoleErrorCode::BadFrame,
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
                    code: ConsoleErrorCode::BadFrame,
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
                    code: ConsoleErrorCode::NotAuthenticated,
                    ..
                }
            ),
            "unauthenticated unsubscribe was accepted"
        );
        let outcomes = audit_outcomes(&sess.state, "console_ws")?;
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

        let err = match validate_upgrade_headers_audited(&st, &headers, None) {
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

        ensure!(
            matches!(
            reply,
            ServerFrame::Error {
                id: Some(11),
                code: ConsoleErrorCode::Forbidden,
                message,
            } if message == "step-up required"
            ),
            "step-up-only action was not rejected"
        );
        let outcomes = audit_outcomes(&st, "console_ws")?;
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

        ensure!(
            matches!(
            &reply,
            ServerFrame::Error {
                id: Some(12),
                code: ConsoleErrorCode::Forbidden,
                message,
            } if message == "management path is not allowed"
            ),
            "vault management path was not forbidden"
        );
        if let ServerFrame::Error { message, .. } = &reply {
            ensure!(
                !message.contains("state://vault"),
                "forbidden error leaked vault path"
            );
            ensure!(
                !message.contains("password"),
                "forbidden error leaked password path segment"
            );
        }
        let outcomes = audit_outcomes(&st, "console_ws")?;
        ensure!(
            outcomes
                .iter()
                .any(|outcome| outcome == "permission_denied"),
            "missing permission_denied audit outcome"
        );
        Ok(())
    }

    #[tokio::test]
    async fn secret_reveal_blocked_attempt_is_audited() -> anyhow::Result<()> {
        let st = console_state()?;
        let (token, _principal, password) = root_login(&st).await?;
        let (elevated_token, principal) = step_up_login(&st, &token, password).await?;
        let mut sess = test_session_for_token(st.clone(), principal, &elevated_token);

        let reply = handle_frame(
            &mut sess,
            ClientFrame::Call {
                id: 13,
                call: visibility_call(ACTION_SECRET_REVEAL, Value::null())?,
            },
        )
        .await;

        ensure!(
            matches!(
                reply,
                ServerFrame::Error {
                    id: Some(13),
                    code: ConsoleErrorCode::BadRequest,
                    ..
                }
            ),
            "secret reveal was not blocked"
        );
        let outcomes = audit_outcomes(&st, "console_visibility")?;
        ensure!(
            outcomes
                .iter()
                .any(|outcome| outcome == "secret_reveal_blocked"),
            "missing secret_reveal_blocked audit outcome"
        );
        Ok(())
    }

    #[test]
    fn configured_limits_are_bounded_by_backend_hard_caps() -> anyhow::Result<()> {
        ensure!(
            bounded_limit(
                HARD_MAX_WS_FACT_LIMIT + 1,
                HARD_MAX_WS_FACT_LIMIT + 2,
                HARD_MAX_WS_FACT_LIMIT,
            ) == HARD_MAX_WS_FACT_LIMIT,
            "configured fact limit exceeded hard cap"
        );
        ensure!(
            bounded_limit(100, 12, HARD_MAX_WS_FACT_LIMIT) == 12,
            "configured fact limit did not preserve smaller configured value"
        );

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
                ACTION_AUTHORITY_WHY_DENIED,
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
                since_rev: None,
                max_batch: None,
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
    async fn protocol_metadata_actions_use_session_transport_security() -> anyhow::Result<()> {
        let pairing_display = PairingDisplayEdge::default();
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default()).context("install standard package")?;
        let st = ConsoleState::shared_with_pairing_display_and_config(
            boot,
            Arc::new(pairing_display),
            ConsoleAuthConfig::default(),
            ConsoleWsConfig::default(),
            ConsoleTransportSecurityConfig {
                mode: ConsoleTransportSecurityMode::UnsafePlaintext,
                ..ConsoleTransportSecurityConfig::default()
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
            map.get("transport_security_mode").and_then(Value::as_str) == Some("unsafe_plaintext"),
            "transport_security_mode mismatch"
        );
        ensure!(
            map.get("unsafe_transport").and_then(Value::as_bool) == Some(true),
            "unsafe_transport mismatch"
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
    async fn planned_actions_are_discoverable_not_executable() -> anyhow::Result<()> {
        let st = console_state()?;
        let (_token, principal, _password) = root_login(&st).await?;
        let mut sess = test_session(st, principal.clone());
        let result = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_CHANGE_SET_CREATE,
                map_value([("registry_rev", Value::integer(1))]),
            )?,
        )
        .await;
        ensure!(
            matches!(
                result,
                Err(ConsoleError::BadRequest(message))
                    if message == "console action is not executable: change_set.create"
            ),
            "planned action executed"
        );

        let matrix = output_value(
            dispatch_call(
                &mut sess,
                &principal,
                call(
                    ACTION_AUTHORITY_ACTION_MATRIX,
                    map_value([("domain", Value::string("change_set".into()))]),
                )?,
            )
            .await?,
        )?;
        let Some(rows) = (matrix).into_list() else {
            bail!("expected matrix rows");
        };
        ensure!(
            rows.iter().all(|row| {
                row.as_map()
                    .is_some_and(|map| map.get("status") == Some(&Value::string("planned".into())))
            }),
            "planned domain status mismatch"
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
    async fn authority_why_denied_explains_single_action_gate() -> anyhow::Result<()> {
        let st = console_state()?;
        let (_token, principal, _password) = root_login(&st).await?;
        let mut sess = test_session(st, principal.clone());
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_AUTHORITY_WHY_DENIED,
                map_value([("action", Value::string(ACTION_PAIRING_DENY.into()))]),
            )?,
        )
        .await?;
        let Some(row) = (output_value(out)?).into_map() else {
            bail!("expected map");
        };
        ensure!(
            row.get("status") == Some(&Value::string("step_up_required".into())),
            "why-denied did not report step_up_required"
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
                row.get("process_status").map(Value::view),
                Some(ValueView::Map(_))
            ),
            "health summary missing process_status map"
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

        let facts = st.boot.kernel.facts.all_facts()?;
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
        state.boot.kernel.facts.complete(Fact {
            id: op_id,
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(8),
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
        principal.identity_path = "identity://console/reader".into();
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
        let facts = st.boot.kernel.facts.all_facts()?;
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
        let out = dispatch_call(
            &mut sess,
            &principal,
            call(
                ACTION_PAIRING_CREATE,
                map_value([
                    (
                        "input",
                        map_value([
                            ("pairing_id", Value::string("pair-ws".into())),
                            ("installation_id", Value::string("pairable".into())),
                        ]),
                    ),
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
        let (_token, principal, _password) = root_login(&st).await?;
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
            matches!(err, ConsoleError::BadRequest(ref message) if message == "runtime config path must use its dedicated console action"),
            "unexpected generic config write error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn external_installation_action_validates_admission_before_state_write()
    -> anyhow::Result<()> {
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
            matches!(err, ConsoleError::BadRequest(_)),
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
            matches!(err, ConsoleError::BadRequest(ref message) if message == "runtime config path must use its dedicated console action"),
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
    async fn external_lifecycle_actions_require_installed_declaration() -> anyhow::Result<()> {
        let st = console_state()?;
        let (token, _principal, password) = root_login(&st).await?;
        let principal = step_up_principal(&st, &token, password).await?;
        let mut sess = test_session(st.clone(), principal.clone());

        let before_stop = fact_count(&st)?;
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
            matches!(stop, Err(ConsoleError::BadRequest(message)) if message == "external installation is not installed"),
            "missing external installation stop was not rejected"
        );
        ensure!(
            fact_count(&st)? == before_stop,
            "missing external installation stop recorded facts"
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
            matches!(revoke, Err(ConsoleError::BadRequest(message)) if message == "external installation is not installed"),
            "missing external installation revoke was not rejected"
        );
        ensure!(
            fact_count(&st)? == before_revoke,
            "missing external installation revoke recorded facts"
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
            matches!(bad_floor, Err(ConsoleError::BadRequest(message)) if message == "credential_generation_floor must be at least 1"),
            "invalid credential_generation_floor was not rejected"
        );
        ensure!(
            fact_count(&st)? == before_bad_floor,
            "invalid credential_generation_floor recorded facts"
        );
        Ok(())
    }

    #[tokio::test]
    async fn inference_backend_action_validates_admission_before_state_write() -> anyhow::Result<()>
    {
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
            matches!(err, ConsoleError::Mgmt(MgmtError::Admission(_))),
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
            matches!(err, ConsoleError::BadRequest(ref message) if message == "runtime config path must use its dedicated console action"),
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
        let before = st.boot.kernel.processes.all_ids().len();
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
            matches!(err, ConsoleError::Operation(ref message) if message.contains("invalid principal identity path")),
            "unexpected malformed principal error: {err:?}"
        );
        ensure!(
            st.boot.kernel.processes.all_ids().len() == before,
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
            matches!(err, ConsoleError::Operation(ref message) if message.contains("invalid principal identity path")),
            "unexpected wildcard principal error: {err:?}"
        );
        ensure!(
            st.boot.kernel.processes.all_ids().len() == before,
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
            .kernel
            .facts
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
            xolotl_kernel::Kernel::with_backends(backend, facts),
        ));
        let state = ConsoleState::shared(boot).context("console state")?;
        let mut principal = root_principal()?;
        principal.grants =
            xolotl_types::CapSet::from_strs(["perform://effect/kernel/process/inspect"])?;
        let sess = test_session(state, principal.clone());
        let output = process_inspect(&sess, &principal, Some(7), false, 0).await?;
        let Some(rows) = (output).into_list() else {
            bail!("expected process rows");
        };
        let row = rows
            .first()
            .and_then(Value::as_map)
            .context("process row")?;
        ensure!(!row.contains_key("fact_count") && !row.contains_key("recent_facts"));
        ensure!(matches!(
            process_inspect(&sess, &principal, Some(7), true, 1).await,
            Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn embedded_recent_facts_require_the_requested_fact_scope() -> anyhow::Result<()> {
        let state = console_state()?;
        let mut principal = root_principal()?;
        principal.identity_path = "identity://console/reader".into();
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
        let Some(rows) = (output_value(output)?).into_list() else {
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
            process_inspect(&sess, &principal, None, true, 1).await,
            Err(ConsoleError::BadRequest(_))
        ));
        ensure!(matches!(
            process_inspect(&sess, &principal, Some(8), true, 1).await,
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
    async fn subscription_rejects_invalid_resume_and_ttl_without_replacing_existing_subscription()
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
                since_rev: Some(1),
                max_batch: None,
            },
        )
        .await
        {
            Ok(_) => bail!("subscription resume unexpectedly replaced existing subscription"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, ConsoleError::BadRequest(_)),
            "unexpected subscription resume error: {err:?}"
        );
        ensure!(
            sess.subscriptions.contains(7),
            "failed subscription resume removed existing subscription"
        );
        for ttl_ms in [None, Some(0), Some(u64::MAX)] {
            let result = subscribe(
                &mut sess,
                &principal,
                7,
                StreamCall {
                    stream: STREAM_STATE_WATCH.into(),
                    input: map_value([("pattern", Value::string("state://kernel/**".into()))]),
                    scope: Some("test".into()),
                    justification: Some("test stream".into()),
                    ttl_ms,
                    since_rev: None,
                    max_batch: None,
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
                since_rev: None,
                max_batch: None,
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
                since_rev: None,
                max_batch: None,
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
        let cfg = crate::state::console_transport_default();
        validate_upgrade_headers(&headers, None, &cfg)
            .map_err(|message| anyhow::anyhow!(message))?;
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
        validate_upgrade_headers(&headers, None, &cfg)
            .map_err(|message| anyhow::anyhow!(message))?;
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
        let cfg = crate::state::console_transport_default();

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
    async fn recipe_state_write_lands_a_fact_via_request_process() -> anyhow::Result<()> {
        let st = console_state()?;
        let principal = ConsolePrincipal {
            username: "root".into(),
            identity_path: "identity://console/root".into(),
            grants: xolotl_types::CapSet::from_strs(["*://**"])?,
            mfa_level: 2,
        };
        let sess = test_session(st.clone(), principal.clone());

        let before = st.boot.kernel.facts.cursor();
        let path = Path::parse("state://chat/source/messages/recipe_probe")?;
        let compiled = recipes::CompiledRecipe::state(
            path,
            RecipeStateMethod::Append,
            Value::string("probe-value".into()),
        )
        .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
        recipes::execute(&sess, &principal, compiled)
            .await
            .context("recipe execute")?;

        let after = st.boot.kernel.facts.cursor();
        ensure!(
            after > before,
            "fact cursor did not advance after recipe write"
        );
        let facts = st.boot.kernel.facts.all_facts()?;
        ensure!(
            !facts.is_empty(),
            "recipe write must record at least one Fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recipe_denies_principal_without_matching_grant() -> anyhow::Result<()> {
        let st = console_state()?;
        let principal = ConsolePrincipal {
            username: "limited".into(),
            identity_path: "identity://console/limited".into(),
            grants: xolotl_types::CapSet::from_strs(["read://state/other/**"])?,
            mfa_level: 2,
        };
        let sess = test_session(st.clone(), principal.clone());
        let before = st.boot.kernel.facts.cursor();

        let path = Path::parse("state://chat/source/messages/bridge_probe")?;
        let compiled = recipes::CompiledRecipe::state(path, RecipeStateMethod::Read, Value::null())
            .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
        let err = match recipes::execute(&sess, &principal, compiled).await {
            Ok(value) => bail!("read without matching principal grant succeeded: {value:?}"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, ConsoleError::Auth(auth::AuthError::PermissionDenied)),
            "missing grant should fail at the principal bridge, got {err:?}"
        );
        ensure!(
            st.boot.kernel.facts.cursor() == before,
            "principal-bridge denial should not spawn or finalize a request process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recipe_read_grant_cannot_write() -> anyhow::Result<()> {
        let st = console_state()?;
        let principal = ConsolePrincipal {
            username: "reader".into(),
            identity_path: "identity://console/reader".into(),
            grants: xolotl_types::CapSet::from_strs(["read://state/chat/source/messages/**"])?,
            mfa_level: 2,
        };
        let sess = test_session(st.clone(), principal.clone());
        let before = st.boot.kernel.facts.cursor();

        let path = Path::parse("state://chat/source/messages/bridge_write_probe")?;
        let compiled = recipes::CompiledRecipe::state(
            path,
            RecipeStateMethod::Append,
            Value::string("should-not-write".into()),
        )
        .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
        let err = match recipes::execute(&sess, &principal, compiled).await {
            Ok(value) => bail!("write with only read grant succeeded: {value:?}"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, ConsoleError::Auth(auth::AuthError::PermissionDenied)),
            "write with read grant should fail at the principal bridge, got {err:?}"
        );
        ensure!(
            st.boot.kernel.facts.cursor() == before,
            "principal-bridge denial should not spawn or finalize a request process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recipe_principal_grant_allows_state_read() -> anyhow::Result<()> {
        let st = console_state()?;
        let path = Path::parse("state://chat/source/messages/bridge_read_probe")?;
        st.boot
            .kernel
            .state
            .write_set(&path, Value::string("readable".into()))
            .await?;
        let principal = ConsolePrincipal {
            username: "reader".into(),
            identity_path: "identity://console/reader".into(),
            grants: xolotl_types::CapSet::from_strs(["read://state/chat/source/messages/**"])?,
            mfa_level: 2,
        };
        let sess = test_session(st, principal.clone());
        let compiled = recipes::CompiledRecipe::state(path, RecipeStateMethod::Read, Value::null())
            .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
        let value = recipes::execute(&sess, &principal, compiled)
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
            username: "reader".into(),
            identity_path: "identity://console/reader".into(),
            grants: xolotl_types::CapSet::from_strs(["read://state/**"])?,
            mfa_level: 2,
        };
        let sess = test_session(st.clone(), principal.clone());
        let before = st.boot.kernel.facts.cursor();

        let path = Path::parse("effect://kernel/process/inspect")?;
        let compiled = recipes::CompiledRecipe::effect(path, Value::null())
            .map_err(|e| anyhow::anyhow!("compile recipe: {e}"))?;
        let err = match recipes::execute(&sess, &principal, compiled).await {
            Ok(value) => bail!("effect invoke without perform grant succeeded: {value:?}"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, ConsoleError::Auth(auth::AuthError::PermissionDenied)),
            "effect without perform grant should fail at the principal bridge, got {err:?}"
        );
        ensure!(
            st.boot.kernel.facts.cursor() == before,
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
        let err = match recipes::execute(&sess, &principal, compiled).await {
            Ok(value) => bail!("vault read should be denied by open_for, got {value:?}"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, ConsoleError::Operation(ref m) if !m.is_empty()),
            "denied recipe should surface an operation error, got {err:?}"
        );
        Ok(())
    }
}
