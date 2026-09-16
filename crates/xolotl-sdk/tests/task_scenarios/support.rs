use anyhow::{Context, bail, ensure};
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use xolotl_kernel::CompiledRequestGrantTemplate;
use xolotl_kernel::host::stream::{DynStreamSink, StreamItem, StreamReceiver, channel};
use xolotl_kernel::stream::{StreamError, StreamRouter, StreamWindow};
use xolotl_sdk::{
    Bootstrap, ExecutionOutput, Expression, IdentityRef, OperationId, OperationTemplate,
    PreparedProgram, Program, RequestProcess, ResourceName, TaintSet, Value,
};
use xolotl_state::object::{ObjectMetadata, ObjectRead, ObjectWrite, UploadOptions};
use xolotl_storage_fs::{FileObjectOptions, FileObjectStore};
use xolotl_types::{MethodBitmap, OutputMode, ResourceSelector};

pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

pub(super) fn invoke(target: ResourceName, output: OutputMode) -> anyhow::Result<PreparedProgram> {
    Ok(PreparedProgram::new(
        &Program::new(Expression::Invoke {
            operation: OperationTemplate {
                target,
                method: "invoke".into(),
                method_id: None,
                output,
                literal_input: None,
            },
        })
        .compile()?,
    )?)
}

pub(super) fn request<'a>(
    boot: &'a Bootstrap,
    capabilities: &[&str],
) -> anyhow::Result<RequestProcess<'a>> {
    let grants = capabilities
        .iter()
        .map(|literal| {
            Ok(CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse(literal)?,
                methods: MethodBitmap::method(0),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(boot.request_under(boot.root, IdentityRef::ROOT, &grants)?)
}

/// One operation owns one stream. A second open cannot reuse its terminal slot.
pub(super) struct Route(Mutex<Option<DynStreamSink>>);

impl StreamRouter for Route {
    type Sink = DynStreamSink;

    fn open(&self, _operation: OperationId) -> Result<Self::Sink, StreamError> {
        lock(&self.0).take().ok_or(StreamError::Closed)
    }
}

pub(super) fn stream() -> (Arc<Route>, StreamReceiver) {
    let (sink, receiver) = channel(StreamWindow {
        max_chunks: NonZeroUsize::MIN,
        max_inline_bytes: NonZeroUsize::MIN.saturating_add(1023),
    });
    (Arc::new(Route(Mutex::new(Some(sink)))), receiver)
}

/// Poll the invocation and its consumer in one owned task, including when the
/// invocation completes during the poll that makes its final chunk available.
pub(super) struct Running<'a> {
    future: Pin<Box<dyn Future<Output = ExecutionOutput> + 'a>>,
    output: Option<ExecutionOutput>,
}

impl<'a> Running<'a> {
    pub(super) fn new(future: impl Future<Output = ExecutionOutput> + 'a) -> Self {
        Self {
            future: Box::pin(future),
            output: None,
        }
    }

    pub(super) async fn next(
        &mut self,
        receiver: &mut StreamReceiver,
    ) -> anyhow::Result<StreamItem> {
        poll_fn(|cx| {
            if let Poll::Ready(item) = receiver.poll_recv(cx) {
                return Poll::Ready(item.context("stream ended before expected item"));
            }
            if self.output.is_none()
                && let Poll::Ready(output) = self.future.as_mut().poll(cx)
            {
                self.output = Some(output);
            }
            match receiver.poll_recv(cx) {
                Poll::Ready(item) => Poll::Ready(item.context("stream ended before expected item")),
                Poll::Pending if self.output.is_some() => Poll::Ready(Err(anyhow::anyhow!(
                    "invocation completed without a stream terminal: {:?}",
                    self.output
                ))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    pub(super) async fn pending(&mut self) -> anyhow::Result<()> {
        ensure!(self.output.is_none(), "invocation already completed");
        poll_fn(|cx| match self.future.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(Ok(())),
            Poll::Ready(output) => {
                self.output = Some(output);
                Poll::Ready(Err(anyhow::anyhow!("invocation unexpectedly completed")))
            }
        })
        .await
    }

    pub(super) async fn finish(self) -> ExecutionOutput {
        match self.output {
            Some(output) => output,
            None => self.future.await,
        }
    }
}

pub(super) fn objects() -> anyhow::Result<(tempfile::TempDir, FileObjectStore)> {
    let directory = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        directory.path(),
        FileObjectOptions {
            chunk_bytes: NonZeroUsize::MIN.saturating_add(126),
            max_uploads: NonZeroUsize::MIN,
            max_io_tasks: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    Ok((directory, store))
}

pub(super) async fn commit(
    store: &FileObjectStore,
    length: u64,
    byte: u8,
    taint: &TaintSet,
) -> anyhow::Result<ObjectMetadata> {
    let upload = store
        .begin_upload(UploadOptions {
            expected_size: Some(length),
            mime: Some("application/octet-stream".into()),
            taint: taint.clone(),
        })
        .await?;
    let window = [byte; 127];
    let mut offset = 0;
    while offset < length {
        let count = usize::try_from((length - offset).min(window.len() as u64))?;
        offset = store
            .write_chunk(&upload, offset, &window[..count])
            .await?
            .checked_next_offset(offset, count)?;
    }
    Ok(store.commit_upload(&upload, taint).await?)
}

pub(super) async fn read_back(
    store: &FileObjectStore,
    metadata: &ObjectMetadata,
    byte: u8,
) -> anyhow::Result<()> {
    ensure!(store.metadata(&metadata.blob).await?.as_ref() == Some(metadata));
    let mut offset = 0;
    let mut window = [0; 101];
    loop {
        let chunk = store
            .read_chunk(&metadata.blob, offset, &mut window)
            .await?;
        offset = chunk.checked_next_offset(offset, window.len(), metadata.blob.size)?;
        ensure!(chunk.taint == metadata.taint);
        if !window[..chunk.bytes_read]
            .iter()
            .all(|actual| *actual == byte)
        {
            bail!("committed object contents differ from the produced sample");
        }
        if chunk.end {
            return Ok(());
        }
    }
}

pub(super) fn record<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
