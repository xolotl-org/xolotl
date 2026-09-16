use super::support::{Running, commit, invoke, lock, objects, read_back, record, request, stream};
use anyhow::{Context, ensure};
use async_trait::async_trait;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use xolotl_kernel::host::stream::StreamItem;
use xolotl_kernel::{DriverOutput, MethodSpec};
use xolotl_sdk::{
    Driver, DriverContext, DriverError, ExecutionOutput, Failure, OperationId, Outcome,
    PreparedProgram, ProcessId, Purity, TaintSet, TaintedValue, Value, Xolotl,
};
use xolotl_state::object::ObjectMetadata;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{FrameKind, MethodId, OutputMode, Path, TaintSource, ValueView};

const CAPTURE: &str = "perform://effect/scenario/media/capture";
const PLAY: &str = "perform://effect/scenario/media/play";
const FRAMES: u32 = 64;
const FRAME_NANOS: i64 = 20_000_000;

struct Session {
    id: OperationId,
    owner: ProcessId,
    next_timestamp: i64,
}

struct Device {
    store: FileObjectStore,
    sample: ObjectMetadata,
    session: Mutex<Option<Session>>,
    attempted: AtomicUsize,
    emitted: AtomicUsize,
    released: AtomicUsize,
    played: AtomicUsize,
}

struct Lease {
    device: Arc<Device>,
    id: OperationId,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut session = lock(&self.device.session);
        if session
            .as_ref()
            .is_some_and(|session| session.id == self.id)
        {
            *session = None;
            self.device.released.fetch_add(1, Ordering::SeqCst);
        }
    }
}

enum Direction {
    Capture,
    Play,
}

struct MediaDriver {
    device: Arc<Device>,
    direction: Direction,
}

#[async_trait]
impl Driver for MediaDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match self.direction {
            Direction::Capture => {
                if output != OutputMode::Stream {
                    return Err(DriverError::UnsupportedOutput(output));
                }
                let id = ctx.operation_id.ok_or_else(|| {
                    DriverError::Other("capture needs an admitted operation identity".into())
                })?;
                {
                    let mut session = lock(&self.device.session);
                    if session.is_some() {
                        return Err(DriverError::Other("device is already leased".into()));
                    }
                    *session = Some(Session {
                        id,
                        owner: ctx.caller,
                        next_timestamp: 0,
                    });
                }
                let _lease = Lease {
                    device: self.device.clone(),
                    id,
                };
                // The test signal repeats one committed audio sample. Capturing
                // more frames retains no history or additional payload buffers.
                for index in 0..FRAMES {
                    let frame = record([
                        ("session", Value::string(id.to_string())),
                        (
                            "frame",
                            Value::frame(
                                self.device.sample.blob.clone(),
                                i64::from(index) * FRAME_NANOS,
                                FrameKind::Audio,
                            ),
                        ),
                    ]);
                    self.device.attempted.fetch_add(1, Ordering::SeqCst);
                    ctx.emit_tainted(TaintedValue::new(frame, self.device.sample.taint.clone()))
                        .await?;
                    self.device.emitted.fetch_add(1, Ordering::SeqCst);
                }
                // A live capture session remains leased while waiting for the
                // next device sample, including outside an emit call.
                std::future::pending().await
            }
            Direction::Play => {
                let session_id = input
                    .as_map()
                    .and_then(|fields| fields.get("session"))
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<OperationId>().ok())
                    .ok_or_else(|| DriverError::InvalidInput("missing session identity".into()))?;
                let Some(ValueView::Frame(frame)) = input
                    .as_map()
                    .and_then(|fields| fields.get("frame"))
                    .map(Value::view)
                else {
                    return Err(DriverError::InvalidInput("missing media frame".into()));
                };
                let check_session = || {
                    let session = lock(&self.device.session);
                    if !session.as_ref().is_some_and(|session| {
                        session.id == session_id
                            && session.owner == ctx.caller
                            && session.next_timestamp == frame.ts_nanos
                            && frame.kind == FrameKind::Audio
                            && frame.blob == self.device.sample.blob
                    }) {
                        return Err(DriverError::InvalidInput(
                            "frame is not the next sample of this caller's live session".into(),
                        ));
                    }
                    Ok(())
                };
                check_session()?;
                let observed_failure = |message| {
                    DriverOutput::new(Outcome::Fail(Failure::HandlerError {
                        kind: "media".into(),
                        message,
                    }))
                    .with_taint(self.device.sample.taint.clone())
                };
                if let Err(error) = read_back(&self.device.store, &self.device.sample, 17).await {
                    return Ok(observed_failure(error.to_string()));
                }
                // An asynchronous read does not keep a cancelled device session
                // alive. Revalidate ownership before applying the sample.
                let mut session = lock(&self.device.session);
                let session = session.as_mut().filter(|session| {
                    session.id == session_id
                        && session.owner == ctx.caller
                        && session.next_timestamp == frame.ts_nanos
                });
                let Some(session) = session else {
                    return Ok(observed_failure(
                        "device session changed during read".into(),
                    ));
                };
                session.next_timestamp += FRAME_NANOS;
                self.device.played.fetch_add(1, Ordering::SeqCst);
                Ok(
                    DriverOutput::new(Outcome::Done(Value::integer(frame.ts_nanos)))
                        .with_taint(self.device.sample.taint.clone()),
                )
            }
        }
    }
}

async fn install(
    runtime: &Xolotl,
) -> anyhow::Result<(
    tempfile::TempDir,
    Arc<Device>,
    PreparedProgram,
    PreparedProgram,
)> {
    let (directory, store) = objects()?;
    let source = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://devices/microphone")?,
    });
    let sample = commit(&store, 8192, 17, &source).await?;
    let device = Arc::new(Device {
        store,
        sample,
        session: Mutex::new(None),
        attempted: AtomicUsize::new(0),
        emitted: AtomicUsize::new(0),
        released: AtomicUsize::new(0),
        played: AtomicUsize::new(0),
    });
    let capture = runtime.bootstrap().register_effect(
        "effect://scenario/media/capture",
        &[MethodSpec::stream_async("invoke", Purity::Effectful).observes_external()],
        Arc::new(MediaDriver {
            device: device.clone(),
            direction: Direction::Capture,
        }),
    )?;
    let play = runtime.bootstrap().register_effect(
        "effect://scenario/media/play",
        &[MethodSpec::unary_async("invoke", Purity::Effectful)],
        Arc::new(MediaDriver {
            device: device.clone(),
            direction: Direction::Play,
        }),
    )?;
    Ok((
        directory,
        device,
        invoke(capture, OutputMode::Stream)?,
        invoke(play, OutputMode::Unary)?,
    ))
}

#[tokio::test]
async fn media_directions_share_authority_with_bounded_backpressure() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let runtime = Xolotl::new();
        let (_directory, device, capture, play) = install(&runtime).await?;
        let request = request(runtime.bootstrap(), &[CAPTURE, PLAY])?;
        let playback = request.executor();
        let (route, mut receiver) = stream();
        let executor = request.executor().with_stream_router(route);
        let mut running =
            Running::new(executor.eval_prepared(&capture, TaintedValue::pristine(Value::null())));
        for index in 0..FRAMES {
            let StreamItem::Chunk(chunk) = running.next(&mut receiver).await? else {
                anyhow::bail!("capture ended before all timestamped samples were delivered");
            };
            ensure!(chunk.taint == device.sample.taint);
            if index == 0 {
                ensure!(device.attempted.load(Ordering::SeqCst) == 2);
                ensure!(device.emitted.load(Ordering::SeqCst) == 1);
                running.pending().await?;
                ensure!(
                    device.emitted.load(Ordering::SeqCst) == 1,
                    "borrowed frame lost its credit"
                );

                // Possessing the reference, or even a playback grant, cannot
                // transfer ownership of the live capture session.
                for capabilities in [&[][..], &[PLAY][..]] {
                    let other = super::support::request(runtime.bootstrap(), capabilities)?;
                    let denied = other
                        .executor()
                        .eval_prepared(&play, (*chunk).clone())
                        .await;
                    ensure!(matches!(denied.outcome, Outcome::Fail(_)));
                    ensure!(device.played.load(Ordering::SeqCst) == 0);
                    other.finish(&denied).await?;
                }
            }
            // Playback is a separately admitted invocation. Retaining chunk
            // credit across its I/O makes the capture operation wait upstream.
            let rendered = playback.eval_prepared(&play, (*chunk).clone()).await;
            ensure!(
                rendered.outcome == Outcome::Done(Value::integer(i64::from(index) * FRAME_NANOS))
            );
            ensure!(rendered.taint == device.sample.taint);
            drop(chunk);
        }
        ensure!(device.played.load(Ordering::SeqCst) == FRAMES as usize);
        ensure!(device.store.pending_uploads() == 0);
        running.pending().await?;
        ensure!(lock(&device.session).is_some());
        drop(running);
        ensure!(lock(&device.session).is_none());
        ensure!(device.released.load(Ordering::SeqCst) == 1);
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            anyhow::bail!("dropping capture did not close its stream");
        };
        ensure!(end.outcome == Err(Failure::Cancelled));
        // Cancellation has no final driver result; the terminal retains the
        // pristine invocation input. Sample sources stay on each frame above.
        ensure!(end.taint.is_pristine());
        request
            .finish(&ExecutionOutput::new(
                Outcome::Fail(Failure::Cancelled),
                end.taint,
            ))
            .await?;
        anyhow::Ok(())
    })
    .await
    .context("media composition timed out")?
}

#[tokio::test]
async fn request_cancellation_and_receiver_disconnect_release_device_leases() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(15), async {
        for disconnect in [false, true] {
            let runtime = Xolotl::new();
            let (_directory, device, capture, _play) = install(&runtime).await?;
            let request = request(runtime.bootstrap(), &[CAPTURE])?;
            let (route, mut receiver) = stream();
            let executor = request.executor().with_stream_router(route);
            let mut running = Running::new(
                executor.eval_prepared(&capture, TaintedValue::pristine(Value::null())),
            );
            let item = running.next(&mut receiver).await?;
            ensure!(matches!(item, StreamItem::Chunk(_)));
            ensure!(lock(&device.session).is_some());
            drop(item);
            if disconnect {
                drop(receiver);
                let output = running.finish().await;
                ensure!(matches!(output.outcome, Outcome::Fail(_)));
                request.finish(&output).await?;
            } else {
                drop(request);
                let output = running.finish().await;
                ensure!(output.outcome == Outcome::Fail(Failure::Cancelled));
            }
            ensure!(lock(&device.session).is_none());
            ensure!(device.released.load(Ordering::SeqCst) == 1);
        }
        anyhow::Ok(())
    })
    .await
    .context("device cancellation timed out")?
}
