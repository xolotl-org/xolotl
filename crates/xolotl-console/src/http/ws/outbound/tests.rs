use super::*;
use crate::ConsoleErrorCode;
use anyhow::{Result, ensure};
use std::pin::Pin;
use std::task::{Context, Poll};
use xolotl_console_protocol::pb;
use xolotl_types::{UnresolvedOperations, Value};

use crate::protocol::ActionResult;

#[derive(Default)]
struct TestSink {
    frames: Vec<Message>,
    block_ready: bool,
    block_flush: bool,
    fail: bool,
    readiness: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl Sink<Message> for TestSink {
    type Error = &'static str;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(readiness) = self.readiness.as_mut() {
            match Pin::new(readiness).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => self.readiness = None,
            }
        }
        if self.block_ready {
            Poll::Pending
        } else if self.fail {
            Poll::Ready(Err("disconnected"))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.frames.push(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.block_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn revoked_during_sink_readiness_withholds_reply_and_retains_effect_identity() -> Result<()> {
    let (_, service, token, _) = crate::service::tests::fixture().await?;
    let prepared = service
        .prepare_call(
            &token,
            None,
            crate::ActionCall {
                action: crate::protocol::ACTION_PROTOCOL_DESCRIBE.into(),
                input: Value::null(),
                ..Default::default()
            },
        )
        .await?;
    let (result, delivery) = prepared.into_parts();
    let mut result = result?;
    result.execution = Some(Box::new(crate::ExecutionReference {
        execution_id: Some("execution-42".into()),
        process_id: "42".into(),
        program_id: "ab".repeat(32),
    }));
    let (ready, readiness) = tokio::sync::oneshot::channel();
    let mut tx = TestSink {
        readiness: Some(readiness),
        ..Default::default()
    };
    let config = ConsoleWsConfig::default().bounded();
    {
        let sending = send_frame_guarded(
            &mut tx,
            ServerFrame::Reply { id: 7, result },
            &config,
            delivery,
        );
        tokio::pin!(sending);
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(sending.as_mut().poll(context)))
                .await
                .is_pending()
        );
        service
            .call(
                &token,
                None,
                crate::ActionCall {
                    action: crate::protocol::ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                    input: Value::null(),
                    ..Default::default()
                },
            )
            .await?;
        ready
            .send(())
            .map_err(|_error| anyhow::anyhow!("readiness receiver lost"))?;
        sending.await?;
    }
    let Some(Message::Binary(bytes)) = tx.frames.pop() else {
        anyhow::bail!("missing denial")
    };
    let Some(pb::console_frame::Frame::Error(error)) = wire::decode_server_frame(&bytes)
        .map_err(anyhow::Error::msg)?
        .frame
    else {
        anyhow::bail!("private reply disclosed")
    };
    ensure!(error.request_id == Some(7));
    ensure!(error.code == pb::ConsoleErrorCode::Unauthenticated as i32);
    ensure!(error.runtime_completion.is_none());
    ensure!(
        error
            .execution
            .ok_or_else(|| anyhow::anyhow!("execution identity lost"))?
            .process_id
            == "42"
    );
    Ok(())
}

#[tokio::test]
async fn oversized_reply_preserves_correlation_and_does_not_offer_retry() -> Result<()> {
    let config = ConsoleWsConfig::default().bounded();
    let mut tx = TestSink::default();
    let mut result = ActionResult::value(Value::bytes(vec![0; config.max_frame_bytes + 1]), 1, 7);
    result.execution = Some(Box::new(crate::ExecutionReference {
        execution_id: Some("execution-42".into()),
        process_id: "24".into(),
        program_id: "ab".repeat(32),
    }));
    let mut unresolved = UnresolvedOperations::default();
    ensure!(unresolved.record("provider-ticket-42"));
    result.unresolved_operations = Some(Box::new(unresolved));
    send_frame(
        &mut tx,
        ServerFrame::Reply {
            id: u64::MAX,
            result,
        },
        &config,
    )
    .await?;
    let Some(Message::Binary(bytes)) = tx.frames.pop() else {
        anyhow::bail!("missing reply")
    };
    ensure!(bytes.len() <= config.max_frame_bytes);
    let Some(pb::console_frame::Frame::Error(error)) = wire::decode_server_frame(&bytes)
        .map_err(anyhow::Error::msg)?
        .frame
    else {
        anyhow::bail!("expected bounded error")
    };
    ensure!(error.request_id == Some(u64::MAX));
    ensure!(error.code == pb::ConsoleErrorCode::Internal as i32);
    ensure!(error.message.contains("effects may have occurred"));
    ensure!(error.retry_after_ms.is_none());
    ensure!(
        error
            .execution
            .ok_or_else(|| anyhow::anyhow!("execution lost during encoding failure"))?
            .process_id
            == "24"
    );
    ensure!(
        error
            .unresolved_operations
            .ok_or_else(|| anyhow::anyhow!("effect identity lost during encoding failure"))?
            .operation_ids
            == ["provider-ticket-42"]
    );
    Ok(())
}

#[tokio::test]
async fn queued_subscription_bytes_require_authority_after_readiness() -> Result<()> {
    let (_, service, token, _) = crate::service::tests::fixture().await?;
    let prepared = service
        .prepare_call(
            &token,
            None,
            crate::ActionCall {
                action: crate::protocol::ACTION_PROTOCOL_DESCRIBE.into(),
                ..Default::default()
            },
        )
        .await?;
    let (_, delivery) = prepared.into_parts();
    let (ready, readiness) = tokio::sync::oneshot::channel();
    let mut tx = TestSink {
        readiness: Some(readiness),
        ..Default::default()
    };
    {
        let sending = send_encoded_guarded(
            &mut tx,
            b"protected subscription event".to_vec(),
            Instant::now() + Duration::from_secs(5),
            delivery,
        );
        tokio::pin!(sending);
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(sending.as_mut().poll(context)))
                .await
                .is_pending()
        );
        service
            .call(
                &token,
                None,
                crate::ActionCall {
                    action: crate::protocol::ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                    ..Default::default()
                },
            )
            .await?;
        ready
            .send(())
            .map_err(|_error| anyhow::anyhow!("readiness receiver lost"))?;
        ensure!(matches!(sending.await, Err(SendError::Authority)));
    }
    ensure!(tx.frames.is_empty());
    Ok(())
}

#[tokio::test]
async fn all_frames_bound_waiting_for_sink_and_flush() -> Result<()> {
    for block_ready in [true, false] {
        let mut tx = TestSink {
            block_ready,
            block_flush: !block_ready,
            ..Default::default()
        };
        let config = ConsoleWsConfig {
            send_timeout: Duration::from_millis(5),
            ..Default::default()
        };
        for frame in [
            ServerFrame::Pong { nonce: 1 },
            ServerFrame::Reply {
                id: 2,
                result: ActionResult::empty(0, 7),
            },
            ServerFrame::Error {
                id: None,
                failure: crate::ConsoleFailure::new(
                    ConsoleErrorCode::NotAuthenticated,
                    "expired".into(),
                ),
            },
        ] {
            ensure!(matches!(
                send_frame(&mut tx, frame, &config).await,
                Err(SendError::Timeout)
            ));
        }
    }
    Ok(())
}

#[tokio::test]
async fn transport_failure_is_reported_without_retrying() -> Result<()> {
    let mut tx = TestSink {
        fail: true,
        ..Default::default()
    };
    ensure!(matches!(
        send_frame(&mut tx, ServerFrame::Pong { nonce: 1 }, &ConsoleWsConfig::default()).await,
        Err(SendError::Transport(message)) if message == "disconnected"
    ));
    ensure!(tx.frames.is_empty());
    Ok(())
}

#[tokio::test]
async fn expired_event_cannot_start_even_when_the_sink_is_ready() -> Result<()> {
    let mut tx = TestSink::default();
    ensure!(matches!(
        send_encoded_until(&mut tx, vec![1], Instant::now()).await,
        Err(SendError::Timeout)
    ));
    ensure!(tx.frames.is_empty());
    Ok(())
}
