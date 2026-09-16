use super::*;
use anyhow::{Result, ensure};
use std::pin::Pin;
use std::task::{Context, Poll};
use xolotl_console_protocol::pb;
use xolotl_types::Value;

use crate::protocol::ActionResult;

#[derive(Default)]
struct TestSink {
    frames: Vec<Message>,
    block_ready: bool,
    block_flush: bool,
    fail: bool,
}

impl Sink<Message> for TestSink {
    type Error = &'static str;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
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
async fn oversized_reply_preserves_correlation_and_does_not_offer_retry() -> Result<()> {
    let config = ConsoleWsConfig::default().bounded();
    let mut tx = TestSink::default();
    send_frame(
        &mut tx,
        ServerFrame::Reply {
            id: u64::MAX,
            result: ActionResult::value(Value::bytes(vec![0; config.max_frame_bytes + 1]), 1),
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
    ensure!(error.message.contains("may already have completed"));
    ensure!(error.retry_after_ms.is_none());
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
                result: ActionResult::empty(0),
            },
            ServerFrame::Error {
                id: None,
                code: ConsoleErrorCode::Unauthorized,
                message: "expired".into(),
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
