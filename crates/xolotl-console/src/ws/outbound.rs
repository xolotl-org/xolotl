//! One delivery policy for replies, protocol messages, and prepared events.

use std::fmt;
use std::future::poll_fn;
use std::time::Duration;

use axum::extract::ws::Message;
use futures_util::{Sink, SinkExt};
use tokio::time::Instant;

use crate::protocol::{ConsoleErrorCode, ServerFrame};
use crate::state::ConsoleWsConfig;
use crate::wire::{self, FrameEncodeError};

#[derive(Debug, thiserror::Error)]
pub(super) enum SendError {
    #[error("transport send failed: {0}")]
    Transport(String),
    #[error("frame send deadline elapsed")]
    Timeout,
    #[error("frame preparation failed: {0}")]
    Encode(#[from] FrameEncodeError),
}

pub(super) async fn send_frame<S>(
    tx: &mut S,
    frame: ServerFrame,
    config: &ConsoleWsConfig,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
{
    let bytes = match wire::encode_server_frame(&frame, config.max_frame_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "console response exceeded outbound encoding limits");
            // Dispatch may have committed effects before producing this reply.
            // Preserve correlation without implying rollback or a safe retry.
            let id = match &frame {
                ServerFrame::Reply { id, .. } => Some(*id),
                ServerFrame::Error { id, .. } => *id,
                _ => None,
            };
            wire::encode_server_frame(
                &ServerFrame::Error {
                    id,
                    code: ConsoleErrorCode::Internal,
                    message: "console response could not be encoded within outbound limits; the request may already have completed".into(),
                },
                config.max_frame_bytes,
            )?
        }
    };
    drop(frame);
    send_encoded_with_timeout(tx, bytes, config.send_timeout).await
}

pub(super) async fn send_encoded_with_timeout<S>(
    tx: &mut S,
    bytes: Vec<u8>,
    timeout: Duration,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
{
    send_encoded_until(tx, bytes, Instant::now() + timeout).await
}

pub(super) async fn send_encoded_until<S>(
    tx: &mut S,
    bytes: Vec<u8>,
    deadline: Instant,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
{
    let deliver = async {
        poll_fn(|cx| tx.poll_ready_unpin(cx))
            .await
            .map_err(|error| SendError::Transport(error.to_string()))?;
        // Timeout polls the inner future first. Check again after readiness so
        // an expired event cannot begin sending when the sink wakes late.
        if Instant::now() >= deadline {
            return Err(SendError::Timeout);
        }
        tx.start_send_unpin(Message::Binary(bytes.into()))
            .map_err(|error| SendError::Transport(error.to_string()))?;
        tx.flush()
            .await
            .map_err(|error| SendError::Transport(error.to_string()))
    };
    match tokio::time::timeout_at(deadline, deliver).await {
        Ok(result) => result,
        Err(_elapsed) => Err(SendError::Timeout),
    }
}

#[cfg(test)]
mod tests;
