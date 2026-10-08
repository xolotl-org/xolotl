//! Authority travels with a reply, not with a queue admission timestamp.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use crate::runtime::WorkerPool;
use prost::Message as _;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::Status;
use xolotl_proto::xolotl::v1::federation as pb;

/// Untrusted remote failure preserved by client operations returning a tonic
/// Status. These claims are not local commit or Kernel evidence. Operation
/// identities remain those supplied by the caller, never regenerated here.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteSyncFailure {
    /// Original Session correlation reported by the remote peer.
    pub request: u64,
    /// Remote failure class, preserving unknown future numeric values.
    pub code: i32,
    /// Remote commit claim, preserving unknown future numeric values.
    pub commit_verdict: i32,
}

impl RemoteSyncFailure {
    /// Recover remote claims from a client error. Transport-only errors have
    /// no remote verdict; absence never proves non-commit.
    pub fn from_status(status: &Status) -> Option<Self> {
        if status.details().is_empty() {
            return None;
        }
        let failure = pb::SyncFailure::decode(status.details()).ok()?;
        Some(Self {
            request: failure.request,
            code: failure.code,
            commit_verdict: failure.commit_verdict,
        })
    }

    /// Unknown verdicts are unspecified, not evidence of rollback.
    pub fn verdict(&self) -> pb::CommitVerdict {
        pb::CommitVerdict::try_from(self.commit_verdict).unwrap_or(pb::CommitVerdict::Unspecified)
    }
}

pub(crate) type DeliveryCheck = Arc<dyn Fn() -> Result<(), Status> + Send + Sync>;

pub(crate) struct DeliveryFrame {
    frame: pb::SyncFrame,
    check: Option<DeliveryCheck>,
    deadline: Option<Instant>,
}

impl DeliveryFrame {
    pub(crate) fn protected(frame: pb::SyncFrame, check: DeliveryCheck) -> Self {
        Self {
            frame,
            check: Some(check),
            deadline: None,
        }
    }

    pub(crate) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |existing| existing.min(deadline)),
        );
        self
    }

    pub(crate) fn start(self, blocking: WorkerPool) -> DeliveryFuture {
        Box::pin(async move {
            let deadline = self
                .deadline
                .ok_or_else(|| Status::internal("delivery deadline missing"))?;
            let protected = self.check.is_some();
            let result = if protected {
                blocking.run(deadline, move || self.handoff()).await
            } else {
                self.handoff()
            };
            if Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(
                    "federation delivery authorization timed out",
                ));
            }
            result
        })
    }

    pub(crate) fn handoff(self) -> Result<pb::SyncFrame, Status> {
        if let Some(check) = self.check {
            check()?;
        }
        Ok(self.frame)
    }
}

impl From<pb::SyncFrame> for DeliveryFrame {
    fn from(mut frame: pb::SyncFrame) -> Self {
        use pb::sync_frame::Body;
        match frame.body.as_mut() {
            Some(Body::Failure(failure)) => {
                failure.message = "federation request failed".to_owned();
                Self {
                    frame,
                    check: None,
                    deadline: None,
                }
            }
            Some(Body::Hello(_) | Body::Authenticate(_)) => Self {
                frame,
                check: None,
                deadline: None,
            },
            _ => Self::protected(
                frame,
                Arc::new(|| {
                    Err(Status::permission_denied(
                        "federation delivery authority missing",
                    ))
                }),
            ),
        }
    }
}

pub(crate) type DeliveryFuture =
    Pin<Box<dyn Future<Output = Result<pb::SyncFrame, Status>> + Send>>;

pub(crate) struct DeliveryRequestStream {
    receiver: Option<ReceiverStream<DeliveryFrame>>,
    closed: bool,
    blocking: WorkerPool,
    pending: Option<DeliveryFuture>,
}

impl DeliveryRequestStream {
    pub(crate) fn new(
        receiver: tokio::sync::mpsc::Receiver<DeliveryFrame>,
        blocking: WorkerPool,
    ) -> Self {
        Self {
            receiver: Some(ReceiverStream::new(receiver)),
            closed: false,
            blocking,
            pending: None,
        }
    }
}

impl Stream for DeliveryRequestStream {
    type Item = pb::SyncFrame;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        if self.pending.is_none() {
            let Some(receiver) = self.receiver.as_mut() else {
                return Poll::Ready(None);
            };
            match Pin::new(receiver).poll_next(context) {
                Poll::Ready(Some(frame)) => self.pending = Some(frame.start(self.blocking.clone())),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(None);
        };
        match pending.as_mut().poll(context) {
            Poll::Ready(result) => {
                self.pending.take();
                match result {
                    Ok(frame) => Poll::Ready(Some(frame)),
                    Err(_) => {
                        self.closed = true;
                        self.receiver.take();
                        Poll::Ready(None)
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FederationGrpcPublisherStream, FederationGrpcRuntime, config::FederationGrpcConfig,
    };
    use anyhow::{Result, ensure};
    use std::{
        sync::{Mutex, mpsc},
        time::Duration,
    };
    use tokio::sync::oneshot;
    use tokio_stream::StreamExt as _;
    use xolotl_kernel::host::TokioBlockingSpawner;

    async fn poll_once<Pending: Future + ?Sized>(
        mut future: Pin<&mut Pending>,
    ) -> Poll<Pending::Output> {
        std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await
    }

    struct Gate {
        frame: DeliveryFrame,
        started: oneshot::Receiver<()>,
        released: oneshot::Receiver<()>,
        release: mpsc::Sender<()>,
    }

    fn gate(deadline: Instant) -> Gate {
        let (started, ready) = oneshot::channel();
        let started = Mutex::new(Some(started));
        let (retained, released) = oneshot::channel::<()>();
        let (release, receiver) = mpsc::channel();
        let receiver = Mutex::new(receiver);
        let check: DeliveryCheck = Arc::new(move || {
            let _capture = &retained;
            started
                .lock()
                .map_err(|_error| Status::internal("test start lock poisoned"))?
                .take()
                .ok_or_else(|| Status::internal("validator ran twice"))?
                .send(())
                .map_err(|_error| Status::internal("test start receiver lost"))?;
            receiver
                .lock()
                .map_err(|_error| Status::internal("test release lock poisoned"))?
                .recv()
                .map_err(|_error| Status::internal("test release sender lost"))?;
            Ok(())
        });
        Gate {
            frame: DeliveryFrame::protected(pb::SyncFrame { body: None }, check)
                .with_deadline(deadline),
            started: ready,
            released,
            release,
        }
    }

    #[tokio::test]
    async fn dropping_either_pending_stream_retains_accepted_validator_in_host_drain() -> Result<()>
    {
        for request_stream in [false, true] {
            let host = Arc::new(TokioBlockingSpawner::new(1)?);
            let runtime = FederationGrpcRuntime::new(
                FederationGrpcConfig {
                    max_in_flight: 1,
                    ..FederationGrpcConfig::default()
                },
                host.clone(),
            )?;
            let Gate {
                frame,
                started,
                mut released,
                release,
            } = gate(Instant::now() + Duration::from_secs(5));
            if request_stream {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                sender
                    .send(frame)
                    .await
                    .map_err(|_error| anyhow::anyhow!("queue closed"))?;
                let mut stream = DeliveryRequestStream::new(receiver, runtime.worker_pool());
                let mut next = Box::pin(stream.next());
                ensure!(poll_once(next.as_mut()).await.is_pending());
                tokio::time::timeout(Duration::from_secs(5), started).await??;
                drop(next);
                drop(stream);
                ensure!(sender.is_closed());
            } else {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                sender
                    .send(Ok(frame))
                    .await
                    .map_err(|_error| anyhow::anyhow!("queue closed"))?;
                let actor = tokio::spawn(std::future::pending::<()>());
                let mut stream = FederationGrpcPublisherStream::new(
                    receiver,
                    actor.abort_handle(),
                    runtime.worker_pool(),
                );
                let mut next = Box::pin(stream.next());
                ensure!(poll_once(next.as_mut()).await.is_pending());
                tokio::time::timeout(Duration::from_secs(5), started).await??;
                drop(next);
                drop(stream);
                ensure!(sender.is_closed());
                ensure!(
                    actor.await.is_err_and(|error| error.is_cancelled()),
                    "response drop aborts actor"
                );
            }
            ensure!(matches!(
                released.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            host.close();
            let mut drain = Box::pin(host.wait_idle());
            ensure!(poll_once(drain.as_mut()).await.is_pending());
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(5), drain).await?;
            ensure!(
                released.await.is_err(),
                "host drain released validator capture"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn validation_deadline_rejects_both_streams_without_cancelling_accepted_work()
    -> Result<()> {
        for request_stream in [false, true] {
            let host = Arc::new(TokioBlockingSpawner::new(1)?);
            let runtime =
                FederationGrpcRuntime::new(FederationGrpcConfig::default(), host.clone())?;
            let Gate {
                frame,
                started,
                mut released,
                release,
            } = gate(Instant::now() + Duration::from_millis(100));
            if request_stream {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                sender
                    .send(frame)
                    .await
                    .map_err(|_error| anyhow::anyhow!("queue closed"))?;
                let mut stream = DeliveryRequestStream::new(receiver, runtime.worker_pool());
                let mut next = Box::pin(stream.next());
                ensure!(poll_once(next.as_mut()).await.is_pending());
                tokio::time::timeout(Duration::from_secs(5), started).await??;
                ensure!(
                    tokio::time::timeout(Duration::from_secs(5), next)
                        .await?
                        .is_none()
                );
                ensure!(sender.is_closed());
            } else {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                sender
                    .send(Ok(frame))
                    .await
                    .map_err(|_error| anyhow::anyhow!("queue closed"))?;
                let actor = tokio::spawn(std::future::pending::<()>());
                let mut stream = FederationGrpcPublisherStream::new(
                    receiver,
                    actor.abort_handle(),
                    runtime.worker_pool(),
                );
                let mut next = Box::pin(stream.next());
                ensure!(poll_once(next.as_mut()).await.is_pending());
                tokio::time::timeout(Duration::from_secs(5), started).await??;
                ensure!(
                    matches!(tokio::time::timeout(Duration::from_secs(5), next).await?, Some(Err(status)) if status.code() == tonic::Code::DeadlineExceeded)
                );
                ensure!(stream.next().await.is_none());
                ensure!(sender.is_closed());
                ensure!(
                    actor.await.is_err_and(|error| error.is_cancelled()),
                    "deadline rejection aborts actor"
                );
            }
            ensure!(matches!(
                released.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            host.close();
            let mut drain = Box::pin(host.wait_idle());
            ensure!(poll_once(drain.as_mut()).await.is_pending());
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(5), drain).await?;
            ensure!(
                released.await.is_err(),
                "accepted validator finished after transport timeout"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn completed_validator_cannot_yield_after_deadline_or_extend_it_on_forwarding()
    -> Result<()> {
        let host = Arc::new(TokioBlockingSpawner::new(1)?);
        let runtime = FederationGrpcRuntime::new(FederationGrpcConfig::default(), host.clone())?;
        let deadline = Instant::now() + Duration::from_millis(100);
        let Gate {
            frame,
            started,
            released,
            release,
        } = gate(deadline);
        let frame = frame.with_deadline(deadline + Duration::from_secs(5));
        let mut pending = frame.start(runtime.worker_pool());
        ensure!(poll_once(pending.as_mut()).await.is_pending());
        tokio::time::timeout(Duration::from_secs(5), started).await??;
        release.send(())?;
        host.close();
        tokio::time::timeout(Duration::from_secs(5), host.wait_idle()).await?;
        ensure!(
            released.await.is_err(),
            "worker completed before waiting to poll its result"
        );
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        let Err(status) = pending.await else {
            anyhow::bail!("completed validation cannot disclose past deadline");
        };
        ensure!(status.code() == tonic::Code::DeadlineExceeded);
        Ok(())
    }
}
