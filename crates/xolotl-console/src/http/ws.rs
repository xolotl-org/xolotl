//! Console WebSocket protocol endpoint.

mod outbound;
mod subscriptions;

use super::transport::validate_upgrade_headers;

use subscriptions::{SubscriptionEvent, Subscriptions};

#[cfg(test)]
use crate::auth;
use crate::auth::ConsolePrincipal;
use crate::http::{
    ConsoleWsLimit, HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_SUBSCRIPTIONS, HttpState,
    peer::VerifiedPeer,
};
#[cfg(test)]
use crate::protocol::ActionCall;
use crate::protocol::{
    self, ActionResult, ClientFrame, ConsoleErrorCode, ConsoleFailure, PrincipalSummary,
    ServerFrame, StreamCall,
};
use crate::service::{
    ConsoleError, protocol_greeting, record_boundary_audit, record_console_error_audit,
    registry_rev, server_rev,
};
#[cfg(test)]
use crate::service::{actions, *};
use crate::state::ConsoleState;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{Sink, Stream, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use xolotl_types::Path;

/// Upgrade an authenticated HTTP request path to the Console Protocol
/// WebSocket endpoint.
pub(crate) async fn upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    peer: VerifiedPeer,
    State(st): State<Arc<HttpState>>,
) -> Response {
    let source_addr = peer.source(&headers, &st.transport_security);
    if let Err(message) = validate_upgrade_headers_audited(&st, &headers, peer.socket_addr()) {
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
        record_ws_audit(
            &st.console,
            None,
            Some(&source_addr),
            "unsupported_subprotocol",
        );
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "console websocket requires the {} subprotocol",
                protocol::SUBPROTOCOL
            ),
        )
            .into_response();
    }
    let max_frame_bytes = st.ws.config().max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    // Own the reservation before handing control to Hyper. If the upgrade
    // fails (or its future is cancelled), dropping the callback releases it.
    let sess = match WsSession::acquire(st.clone(), source_addr.clone()) {
        Ok(sess) => sess,
        Err(limit) => {
            record_ws_audit(&st.console, None, Some(&source_addr), "rate_limited");
            return (StatusCode::TOO_MANY_REQUESTS, ws_limit_message(limit)).into_response();
        }
    };
    ws.protocols([protocol::SUBPROTOCOL])
        .max_message_size(max_frame_bytes)
        .max_frame_size(max_frame_bytes)
        .on_upgrade(move |socket| session(socket, sess))
}

impl From<&ConsolePrincipal> for PrincipalSummary {
    fn from(p: &ConsolePrincipal) -> Self {
        Self {
            username: p.username.clone(),
            identity_path: p.identity_path.clone(),
            mfa_level: p.authentication.mfa_level(),
        }
    }
}

pub(crate) struct WsSession {
    pub(crate) adapter: Arc<HttpState>,
    principal: Option<ConsolePrincipal>,
    sid: Option<String>,
    hello_accepted: bool,
    source_addr: String,
    counted_account: Option<crate::auth::AccountKey>,
    subscriptions: Subscriptions,
    rate: FrameRate,
    pending_delivery: Option<crate::ConsoleDelivery>,
}

impl Drop for WsSession {
    fn drop(&mut self) {
        self.adapter.ws.release_source(&self.source_addr);
        if let Some(account) = self.counted_account.take() {
            self.adapter.ws.release_account(&account);
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

impl WsSession {
    #[cfg(test)]
    fn action_context(&self) -> actions::ActionContext<'_> {
        actions::ActionContext {
            delivery: None,
            state: &self.adapter.console,
            source_addr: Some(&self.source_addr),
            session_id: self.sid.as_deref().unwrap_or_default(),
        }
    }

    fn acquire(adapter: Arc<HttpState>, source_addr: String) -> Result<Self, ConsoleWsLimit> {
        adapter.ws.try_acquire_source(&source_addr)?;
        let subscriptions = Subscriptions::new(adapter.ws.config());
        Ok(Self {
            adapter,
            principal: None,
            sid: None,
            hello_accepted: false,
            source_addr,
            counted_account: None,
            subscriptions,
            rate: FrameRate::default(),
            pending_delivery: None,
        })
    }
}

async fn session<S>(mut socket: S, mut sess: WsSession)
where
    S: Stream<Item = Result<Message, axum::Error>> + Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    let mut idle = Box::pin(tokio::time::sleep(sess.adapter.ws.config().idle_timeout));

    loop {
        if sess.subscriptions.failed() {
            break;
        }
        tokio::select! {
            _ = &mut idle => {
                record_ws_audit(&sess.adapter.console, sess.principal.as_ref(), Some(&sess.source_addr), "idle_timeout");
                break;
            }
            msg = socket.next() => {
                idle.as_mut().reset(tokio::time::Instant::now() + sess.adapter.ws.config().idle_timeout);
                let Some(msg) = msg else { break };
                let Ok(msg) = msg else { break };
                let Some(reply) = receive_client_message(&mut sess, msg).await else {
                    break;
                };
                let close_after = should_close_after_reply(&sess, &reply);
                let delivery = sess.pending_delivery.take();
                if let Err(error) = outbound::send_frame_guarded(&mut socket, reply, sess.adapter.ws.config(), delivery).await {
                    record_ws_send_error(&sess, &error);
                    break;
                }
                if close_after {
                    break;
                }
            }
            event = sess.subscriptions.next() => {
                let SubscriptionEvent { stream, bytes, budget, entry, deadline, delivery } = match event {
                    Ok(event) => event,
                    Err(error) => {
                        record_ws_send_error(&sess, &outbound::SendError::Encode(error));
                        break;
                    }
                };
                if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
                    tracing::debug!(stream, "console subscription event expired before delivery");
                    continue;
                }
                let send_deadline = tokio::time::Instant::now() + sess.adapter.ws.config().send_timeout;
                let send_deadline = deadline.map_or(send_deadline, |expiry| expiry.min(send_deadline));
                let delivered = outbound::send_encoded_guarded(&mut socket, bytes, send_deadline, delivery).await;
                drop(budget);
                drop(entry);
                if let Err(error) = delivered {
                    record_ws_send_error(&sess, &error);
                    record_ws_audit(&sess.adapter.console, sess.principal.as_ref(), Some(&sess.source_addr), "backpressure_close");
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
        sess.adapter.ws.config().max_frames_per_second,
        sess.adapter.ws.config().max_bytes_per_second,
    ) {
        record_ws_audit(
            &sess.adapter.console,
            sess.principal.as_ref(),
            Some(&sess.source_addr),
            "rate_limited",
        );
        return Some(ServerFrame::Error {
            id: None,
            failure: crate::ConsoleFailure::new(
                ConsoleErrorCode::RateLimited,
                "console websocket frame rate limit exceeded".into(),
            ),
        });
    }

    let frame = match msg {
        Message::Binary(bytes) => decode_frame(&bytes, sess.adapter.ws.config().max_frame_bytes),
        Message::Close(_) => return None,
        Message::Ping(_) | Message::Pong(_) => return Some(ServerFrame::Pong { nonce: 0 }),
        _ => {
            record_ws_audit(
                &sess.adapter.console,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "protocol_error",
            );
            return Some(ServerFrame::Error {
                id: None,
                failure: crate::ConsoleFailure::new(
                    ConsoleErrorCode::BadFrame,
                    "console websocket only accepts binary protobuf frames".into(),
                ),
            });
        }
    };
    let frame = match frame {
        Ok(frame) => frame,
        Err(message) => {
            record_ws_audit(
                &sess.adapter.console,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "protocol_error",
            );
            return Some(ServerFrame::Error {
                id: None,
                failure: crate::ConsoleFailure::new(ConsoleErrorCode::BadFrame, message),
            });
        }
    };
    Some(handle_frame(sess, frame).await)
}

fn should_close_after_reply(sess: &WsSession, reply: &ServerFrame) -> bool {
    sess.sid.is_none()
        && (sess.counted_account.is_some()
            || matches!(
                reply,
                ServerFrame::Reply {
                    result: ActionResult { output: None, .. },
                    ..
                } | ServerFrame::Error {
                    failure: crate::ConsoleFailure {
                        code: ConsoleErrorCode::NotAuthenticated | ConsoleErrorCode::Forbidden,
                        ..
                    },
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
        &sess.adapter.console,
        sess.principal.as_ref(),
        Some(&sess.source_addr),
        "protocol_error",
    );
    ServerFrame::Error {
        id,
        failure: crate::ConsoleFailure::new(ConsoleErrorCode::BadFrame, message.into()),
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
                    &sess.adapter.console,
                    sess.principal.as_ref(),
                    Some(&sess.source_addr),
                    "protocol_error",
                );
                return ServerFrame::Error {
                    id: None,
                    failure: crate::ConsoleFailure::new(
                        ConsoleErrorCode::BadRequest,
                        format!(
                            "unsupported console protocol version {}; expected {}",
                            hello.protocol_version,
                            protocol::PROTOCOL_VERSION
                        ),
                    ),
                };
            }
            let metadata = match protocol_greeting(&sess.adapter.console) {
                Ok(metadata) => metadata,
                Err(error) => return console_error_frame(None, error),
            };
            sess.hello_accepted = true;
            ServerFrame::HelloAccepted {
                metadata,
                transport: sess.adapter.transport_summary(),
            }
        }
        ClientFrame::Auth { token } => {
            if let Some(frame) = require_hello(sess, None) {
                return frame;
            }
            match sess.adapter.service().authenticate_session(&token).await {
                Ok(authenticated) => {
                    let principal = authenticated.principal;
                    let sid = authenticated.sid;
                    let metadata = match protocol_greeting(&sess.adapter.console) {
                        Ok(metadata) => metadata,
                        Err(error) => return console_error_frame(None, error),
                    };
                    if let Err(limit) = sess.adapter.ws.try_replace_account(
                        sess.counted_account.as_ref(),
                        &principal.account_key(),
                    ) {
                        record_ws_audit(
                            &sess.adapter.console,
                            Some(&principal),
                            Some(&sess.source_addr),
                            "rate_limited",
                        );
                        return ServerFrame::Error {
                            id: None,
                            failure: crate::ConsoleFailure::new(
                                ConsoleErrorCode::RateLimited,
                                ws_limit_message(limit),
                            ),
                        };
                    }
                    sess.counted_account = Some(principal.account_key());
                    sess.subscriptions.shutdown().await;
                    if sess.subscriptions.failed() {
                        sess.sid = None;
                        return ServerFrame::Error {
                            id: None,
                            failure: crate::ConsoleFailure::new(
                                ConsoleErrorCode::Internal,
                                "previous subscriptions could not be stopped".into(),
                            ),
                        };
                    }
                    let summary = PrincipalSummary::from(&principal);
                    sess.principal = Some(principal);
                    sess.sid = Some(sid);
                    ServerFrame::Authenticated {
                        principal: summary,
                        metadata,
                    }
                }
                Err(error) => {
                    if matches!(error, ConsoleError::RateLimited) {
                        return console_error_frame(None, error);
                    }
                    record_ws_audit(
                        &sess.adapter.console,
                        None,
                        Some(&sess.source_addr),
                        "auth_failed",
                    );
                    console_error_frame(None, error)
                }
            }
        }
        ClientFrame::Ping { nonce } => ServerFrame::Pong { nonce },
        ClientFrame::Call { id, call } => {
            if let Some(frame) = require_hello(sess, Some(id)) {
                return frame;
            }
            let capacity = match sess.adapter.service().reserve_call() {
                Ok(capacity) => capacity,
                Err(error) => return console_error_frame(Some(id), error),
            };
            let principal = match authenticated_principal(sess, Some(id), true).await {
                Ok(p) => p,
                Err(frame) => return *frame,
            };
            let sid = match sess.sid.as_deref() {
                Some(sid) => sid,
                None => return console_error_frame(Some(id), ConsoleError::NotAuthenticated),
            };
            match sess
                .adapter
                .service()
                .prepare_session_admitted(&principal, sid, Some(&sess.source_addr), call, capacity)
                .await
            {
                Ok((prepared, invalidated)) => {
                    let (result, delivery) = prepared.into_parts();
                    sess.pending_delivery = delivery;
                    if invalidated {
                        sess.sid = None;
                        sess.principal = None;
                    }
                    match result {
                        Ok(result) => ServerFrame::Reply { id, result },
                        Err(failure) => ServerFrame::Error {
                            id: Some(id),
                            failure,
                        },
                    }
                }
                Err(e) => {
                    record_console_error_audit(
                        &sess.adapter.console,
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
            let principal = match authenticated_principal(sess, Some(id), true).await {
                Ok(p) => p,
                Err(frame) => return *frame,
            };
            match subscribe(sess, &principal, id, stream).await {
                Ok(result) => ServerFrame::Reply { id, result },
                Err(e) => {
                    record_console_error_audit(
                        &sess.adapter.console,
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
            if let Err(frame) = authenticated_principal(sess, Some(id), true).await {
                return *frame;
            }
            if let Err(error) = sess.subscriptions.stop(id).await {
                return console_error_frame(Some(id), ConsoleError::Operation(error.to_string()));
            }
            let revision = match server_rev(&sess.adapter.console) {
                Ok(revision) => revision,
                Err(error) => return console_error_frame(Some(id), error),
            };
            ServerFrame::Reply {
                id,
                result: ActionResult::empty(revision, registry_rev(&sess.adapter.console)),
            }
        }
    }
}

async fn authenticated_principal(
    sess: &mut WsSession,
    id: Option<u64>,
    touch: bool,
) -> Result<ConsolePrincipal, Box<ServerFrame>> {
    let Some(sid) = sess.sid.as_deref() else {
        record_ws_audit(
            &sess.adapter.console,
            None,
            Some(&sess.source_addr),
            "not_authenticated",
        );
        return Err(Box::new(ServerFrame::Error {
            id,
            failure: crate::ConsoleFailure::new(
                ConsoleErrorCode::NotAuthenticated,
                "not authenticated".into(),
            ),
        }));
    };
    let authenticated = if touch {
        sess.adapter.service().touch_session(sid).await
    } else {
        sess.adapter.service().validate_session(sid).await
    };
    match authenticated {
        Ok(p) => refresh_principal(sess, p, id),
        Err(error) if matches!(error, ConsoleError::RateLimited) => {
            record_ws_audit(
                &sess.adapter.console,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "rate_limited",
            );
            Err(Box::new(console_error_frame(id, error)))
        }
        Err(error) => {
            record_ws_audit(
                &sess.adapter.console,
                sess.principal.as_ref(),
                Some(&sess.source_addr),
                "invalid_session",
            );
            sess.sid = None;
            Err(Box::new(console_error_frame(id, error)))
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
            &sess.adapter.console,
            sess.principal.as_ref(),
            Some(&sess.source_addr),
            "authority_changed",
        );
        sess.sid = None;
        return Err(Box::new(ServerFrame::Error {
            id,
            failure: crate::ConsoleFailure::new(
                ConsoleErrorCode::Forbidden,
                "console session authority changed; reconnect and authorize new subscriptions"
                    .into(),
            ),
        }));
    }
    // Keep the established principal for connection-level audit and authority
    // comparison. The returned principal is the freshly validated authority
    // for this frame; replacing an equal cache would clone its grant set.
    if sess.principal.is_none() {
        sess.principal = Some(principal.clone());
    }
    Ok(principal)
}

#[cfg(test)]
async fn dispatch_call(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> Result<ActionResult, ConsoleError> {
    let capacity = sess.adapter.service().reserve_call()?;
    dispatch_call_admitted(sess, principal, call, capacity).await
}

#[cfg(test)]
async fn dispatch_call_admitted(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    call: ActionCall,
    capacity: CallAdmission,
) -> Result<ActionResult, ConsoleError> {
    let execution = sess
        .adapter
        .service()
        .execute_session_admitted(
            principal,
            sess.sid.as_deref().ok_or(ConsoleError::NotAuthenticated)?,
            Some(&sess.source_addr),
            call,
            capacity,
        )
        .await?;
    if execution.session_invalidated {
        sess.sid = None;
        sess.principal = None;
    }
    Ok(execution.result)
}

async fn subscribe(
    sess: &mut WsSession,
    principal: &ConsolePrincipal,
    id: u64,
    stream: StreamCall,
) -> Result<ActionResult, ConsoleError> {
    sess.subscriptions.reap_finished();
    if sess.subscriptions.contains(id) {
        return Err(ConsoleError::BadRequest(
            "subscription id is already active; unsubscribe before reusing it".into(),
        ));
    }
    let max_subscriptions = sess
        .adapter
        .ws
        .config()
        .max_subscriptions
        .min(HARD_MAX_WS_SUBSCRIPTIONS);
    if sess.subscriptions.len() >= max_subscriptions && !sess.subscriptions.contains(id) {
        return Err(ConsoleError::RateLimited);
    }
    let subscription = sess
        .adapter
        .service()
        .open_session_subscription(
            principal,
            sess.sid.as_deref().ok_or(ConsoleError::NotAuthenticated)?,
            Some(&sess.source_addr),
            stream,
        )
        .await?;
    // WebSocket queueing uses its transport timer. The service keeps the
    // original host-clock deadline and rechecks it before returning an event.
    let deadline = tokio::time::Instant::now()
        .checked_add(
            subscription
                .remaining_visibility()
                .map_err(|error| ConsoleError::Runtime(error.into()))?,
        )
        .ok_or_else(|| {
            ConsoleError::Operation("subscription deadline is not representable".into())
        })?;
    let execution = subscription.execution().cloned();
    let delivery = subscription.delivery_authority();
    sess.pending_delivery = Some(delivery.clone());
    sess.subscriptions
        .replace(
            id,
            subscription,
            |event| Ok(Some(event)),
            "console",
            deadline,
            Some(delivery),
        )
        .await
        .map_err(|error| {
            let error = ConsoleError::Operation(error.to_string());
            match &execution {
                Some(reference) => error.with_execution(reference.clone()),
                None => error,
            }
        })?;
    let revision = match server_rev(&sess.adapter.console) {
        Ok(revision) => revision,
        Err(error) => {
            // The subscription was accepted before its response metadata was
            // built. Do not leave an unacknowledged stream running.
            drop(sess.subscriptions.stop(id).await);
            return Err(match execution {
                Some(reference) => error.with_execution(reference),
                None => error,
            });
        }
    };
    let mut result = ActionResult::empty(revision, registry_rev(&sess.adapter.console));
    result.execution = execution.map(Box::new);
    Ok(result)
}

fn decode_frame(bytes: &[u8], configured_max_frame_bytes: usize) -> Result<ClientFrame, String> {
    let max_frame_bytes = configured_max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    if bytes.len() > max_frame_bytes {
        return Err("frame exceeds console websocket limit".into());
    }
    crate::wire::decode_client_frame(bytes, max_frame_bytes).map_err(|error| error.to_string())
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
        outbound::SendError::Timeout
        | outbound::SendError::Encode(_)
        | outbound::SendError::Authority => {
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

fn ws_limit_message(limit: ConsoleWsLimit) -> String {
    match limit {
        ConsoleWsLimit::Global => "too many active console websocket connections".into(),
        ConsoleWsLimit::Source => {
            "too many active console websocket connections from this source".into()
        }
        ConsoleWsLimit::Account => {
            "too many active console websocket connections for this account".into()
        }
    }
}

fn validate_upgrade_headers_audited(
    state: &Arc<HttpState>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<(), String> {
    let result = validate_upgrade_headers(headers, peer, &state.transport_security);
    if result.is_err() {
        let source_addr =
            super::transport::verified_source_addr(headers, peer, &state.transport_security);
        record_ws_audit(&state.console, None, Some(&source_addr), "origin_denied");
    }
    result
}

fn console_error_frame(id: Option<u64>, error: ConsoleError) -> ServerFrame {
    failure_frame(id, error.into())
}

fn failure_frame(id: Option<u64>, failure: ConsoleFailure) -> ServerFrame {
    ServerFrame::Error { id, failure }
}

#[cfg(test)]
mod tests;

fn record_ws_audit(
    state: &Arc<ConsoleState>,
    principal: Option<&ConsolePrincipal>,
    source: Option<&str>,
    outcome: &'static str,
) {
    // Connection events may only know a previously authenticated username.
    // Cached session metadata is not current authentication evidence.
    record_boundary_audit(
        state,
        principal.map(|p| p.username.as_str()),
        source,
        "console_ws",
        outcome,
    );
}
