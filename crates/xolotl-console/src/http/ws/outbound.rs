//! One delivery policy for replies, protocol messages, and prepared events.

use std::fmt;
use std::future::Future;
use std::future::poll_fn;
#[cfg(test)]
use std::time::Duration;

use axum::extract::ws::Message;
use futures_util::{Sink, SinkExt};
use tokio::time::Instant;

use crate::http::ConsoleWsConfig;
use crate::protocol::ServerFrame;
use crate::wire::{self, FrameEncodeError};

#[derive(Debug, thiserror::Error)]
pub(super) enum SendError {
    #[error("transport send failed: {0}")]
    Transport(String),
    #[error("frame send deadline elapsed")]
    Timeout,
    #[error("frame preparation failed: {0}")]
    Encode(#[from] FrameEncodeError),
    #[error("delivery authority rejected")]
    Authority,
}

#[cfg(test)]
pub(super) async fn send_frame<S>(
    tx: &mut S,
    frame: ServerFrame,
    config: &ConsoleWsConfig,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
{
    send_frame_guarded(tx, frame, config, None).await
}

pub(super) async fn send_frame_guarded<S>(
    tx: &mut S,
    frame: ServerFrame,
    config: &ConsoleWsConfig,
    delivery: Option<crate::ConsoleDelivery>,
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
            let fallback = wire::delivery_failure(&frame, config.max_frame_bytes)?;
            wire::encode_server_frame(&fallback, config.max_frame_bytes)?
        }
    };
    let evidence = match frame {
        ServerFrame::Reply { id, result } => Some((
            Some(id),
            crate::service::withheld(
                crate::ConsoleFailure::new(
                    crate::ConsoleErrorCode::Forbidden,
                    "delivery rejected".into(),
                ),
                &Ok(result),
            ),
        )),
        ServerFrame::Error { id, failure } => Some((
            id,
            crate::service::withheld(
                crate::ConsoleFailure::new(
                    crate::ConsoleErrorCode::Forbidden,
                    "delivery rejected".into(),
                ),
                &Err(failure),
            ),
        )),
        _ => None,
    };
    send_prepared_until(tx, Instant::now() + config.send_timeout, async move {
        if let Some(delivery) = delivery
            && let Err(failure) = delivery.validate().await
        {
            let (id, evidence) = evidence.ok_or(SendError::Authority)?;
            let frame = ServerFrame::Error {
                id,
                failure: crate::service::withheld(failure, &Err(evidence)),
            };
            return wire::encode_server_frame(&frame, config.max_frame_bytes).map_err(Into::into);
        }
        Ok(bytes)
    })
    .await
}

#[cfg(test)]
pub(super) async fn send_encoded_until<S>(
    tx: &mut S,
    bytes: Vec<u8>,
    deadline: Instant,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
{
    send_prepared_until(tx, deadline, std::future::ready(Ok(bytes))).await
}

pub(super) async fn send_encoded_guarded<S>(
    tx: &mut S,
    bytes: Vec<u8>,
    deadline: Instant,
    delivery: Option<crate::ConsoleDelivery>,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
{
    send_prepared_until(tx, deadline, async move {
        if let Some(delivery) = delivery {
            delivery
                .validate()
                .await
                .map_err(|_error| SendError::Authority)?;
        }
        Ok(bytes)
    })
    .await
}

async fn send_prepared_until<S, F>(
    tx: &mut S,
    deadline: Instant,
    prepare: F,
) -> Result<(), SendError>
where
    S: Sink<Message> + Unpin,
    S::Error: fmt::Display,
    F: Future<Output = Result<Vec<u8>, SendError>>,
{
    let deliver = async {
        poll_fn(|cx| tx.poll_ready_unpin(cx))
            .await
            .map_err(|error| SendError::Transport(error.to_string()))?;
        let bytes = prepare.await?;
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
