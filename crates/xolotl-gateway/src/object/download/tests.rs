use super::*;
use crate::tests::{TEST_TOKEN, echo_profile};
use crate::{Gateway, GatewayObjectReadGrant, IssueObjectReadGrantRequest, PresentedCredential};
use anyhow::{Context, bail, ensure};
use parking_lot::RwLock;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use xolotl_kernel::{Bootstrap, EchoDriver, MethodSpec};
use xolotl_state::object::ObjectRead;
use xolotl_state::{StateError, StateResult};
use xolotl_types::{BlobRef, Purity, TaintSet, TaintSource, TaintedValue, Value};

type Request<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

#[derive(Clone, Copy, Default)]
enum ReadReply {
    #[default]
    Full,
    Partial(usize),
    Zero,
    Excessive,
    PrematureEnd,
    MissingEnd,
    Error,
}

struct Gate {
    entered: Semaphore,
    release: Semaphore,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }

    async fn enter(&self) -> StateResult<()> {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(|error| StateError::Backend(error.to_string()))?
            .forget();
        Ok(())
    }

    async fn wait(&self) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.entered.acquire())
            .await??
            .forget();
        Ok(())
    }
}

struct ReadProbe {
    metadata: RwLock<Option<ObjectMetadata>>,
    metadata_reads: AtomicUsize,
    reads: AtomicUsize,
    largest_window: AtomicUsize,
    buffer_address: AtomicUsize,
    reply: ReadReply,
    gate: Option<Arc<Gate>>,
}

impl ReadProbe {
    fn new(size: u64) -> Self {
        Self {
            metadata: RwLock::new(Some(ObjectMetadata {
                blob: BlobRef {
                    hash: "a".repeat(64),
                    size,
                    mime: Some("application/octet-stream".into()),
                },
                taint: TaintSet::of(TaintSource::ModelOutput),
            })),
            metadata_reads: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            largest_window: AtomicUsize::new(0),
            buffer_address: AtomicUsize::new(0),
            reply: ReadReply::Full,
            gate: None,
        }
    }
}

impl ObjectRead for ReadProbe {
    type Metadata<'a> = Request<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Request<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, _blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(async move {
            self.metadata_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.metadata.read().clone())
        })
    }

    fn read_chunk<'a>(
        &'a self,
        _blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(async move {
            let call = self.reads.fetch_add(1, Ordering::Relaxed);
            self.largest_window
                .fetch_max(buffer.len(), Ordering::Relaxed);
            self.buffer_address
                .store(buffer.as_ptr() as usize, Ordering::Relaxed);
            if let Some(gate) = &self.gate {
                gate.enter().await?;
            }
            if matches!(self.reply, ReadReply::Error) {
                return Err(StateError::Backend("read failed".into()).into());
            }
            let size = self
                .metadata
                .read()
                .as_ref()
                .ok_or_else(|| StateError::NotFound("read content".into()))?
                .blob
                .size;
            let remaining = size
                .checked_sub(offset)
                .ok_or(StateError::Unsupported("test read offset"))?;
            let mut count = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            if let ReadReply::Partial(limit) = self.reply {
                count = count.min(limit);
            }
            if matches!(self.reply, ReadReply::Zero) {
                count = 0;
            }
            for (index, byte) in buffer[..count].iter_mut().enumerate() {
                *byte = ((offset + index as u64) % 251) as u8;
            }
            let end = match self.reply {
                ReadReply::PrematureEnd => true,
                ReadReply::MissingEnd => false,
                _ => offset + count as u64 == size,
            };
            Ok(ObjectReadChunk {
                bytes_read: if matches!(self.reply, ReadReply::Excessive) {
                    buffer.len() + 1
                } else {
                    count
                },
                end,
                taint: TaintSet::of(source(&format!("chunk-{call}"))),
            })
        })
    }
}

fn source(label: &str) -> TaintSource {
    TaintSource::Inbound {
        source: label.into(),
        channel: "object-download-test".into(),
    }
}

struct Fixture {
    boot: Arc<Bootstrap>,
    gateway: GatewayRuntime,
    session: GatewaySession,
    probe: Arc<ReadProbe>,
}

impl Fixture {
    async fn new(probe: ReadProbe) -> anyhow::Result<Self> {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot.register_effect(
            "effect://echo/say",
            &[MethodSpec::unary_async("invoke", Purity::Pure)],
            Arc::new(EchoDriver),
        )?;
        let probe = Arc::new(probe);
        let gateway = GatewayRuntime::new(boot.clone(), echo_profile(name)?)?
            .with_object_store(ObjectStore::new().with_read(probe.clone()));
        let session = gateway
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        Ok(Self {
            boot,
            gateway,
            session,
            probe,
        })
    }

    async fn issue(
        &self,
        offset: u64,
        length: Option<u64>,
    ) -> anyhow::Result<GatewayObjectReadGrant> {
        let blob = self
            .probe
            .metadata
            .read()
            .as_ref()
            .context("missing test metadata")?
            .blob
            .clone();
        Ok(self
            .gateway
            .issue_object_read_grant(
                &self.session,
                IssueObjectReadGrantRequest {
                    surface_id: "echo".into(),
                    object: TaintedValue::new(Value::blob(blob), TaintSet::of(source("export"))),
                    offset,
                    length,
                    expires_in_ms: Some(60_000),
                },
            )
            .await?)
    }

    async fn open(
        &self,
        grant: &GatewayObjectReadGrant,
        offset: u64,
        length: Option<u64>,
    ) -> Result<GatewayObjectDownload, GatewayError> {
        self.gateway
            .open_object_read(
                &self.session,
                OpenObjectReadRequest {
                    grant_id: grant.grant_id().into(),
                    offset,
                    length,
                },
            )
            .await
    }

    async fn revoke(&self, grant: &GatewayObjectReadGrant) -> anyhow::Result<()> {
        ensure!(
            self.gateway
                .revoke_object_read_grant(&self.session, grant.grant_id())
                .await?
        );
        Ok(())
    }
}

#[tokio::test]
async fn partial_ranges_borrow_payload_and_keep_each_chunks_sources_separate() -> anyhow::Result<()>
{
    let mut probe = ReadProbe::new(20);
    probe.reply = ReadReply::Partial(3);
    let fixture = Fixture::new(probe).await?;
    let grant = fixture.issue(2, Some(10)).await?;
    fixture
        .probe
        .metadata
        .write()
        .as_mut()
        .context("metadata")?
        .taint
        .add(source("open"));
    let mut download = fixture.open(&grant, 5, Some(7)).await?;
    ensure!(download.start_offset() == 5 && download.end_offset() == 12);
    ensure!(download.expires_at_ms() == grant.expires_at_ms());
    let header_taint = download.metadata().taint.clone();
    ensure!(header_taint.sources().contains(&TaintSource::ModelOutput));
    ensure!(header_taint.sources().contains(&source("export")));
    ensure!(header_taint.sources().contains(&source("open")));
    let handles = fixture.boot.kernel.handles.read().len();
    let mut buffer = [0; 32];
    for (index, length) in [3, 3, 1].into_iter().enumerate() {
        let offset = download.next_offset();
        let chunk = download.read(&mut buffer).await?;
        ensure!(chunk.bytes_read == length && !chunk.end);
        for (index, byte) in buffer[..length].iter().enumerate() {
            ensure!(*byte == (offset + index as u64) as u8);
        }
        let sources = chunk.taint.sources();
        ensure!(sources.len() == header_taint.sources().len() + 1);
        ensure!(sources.contains(&source(&format!("chunk-{index}"))));
        ensure!(
            header_taint
                .sources()
                .iter()
                .all(|source| sources.contains(source))
        );
        ensure!(fixture.probe.buffer_address.load(Ordering::Relaxed) == buffer.as_ptr() as usize);
        ensure!(fixture.probe.reads.load(Ordering::Relaxed) == index + 1);
        ensure!(fixture.boot.kernel.handles.read().len() == handles);
    }
    ensure!(download.is_complete() && download.next_offset() == 12);
    let end = download.read(&mut buffer).await?;
    ensure!(end.bytes_read == 0 && !end.end);
    ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 3);
    ensure!(download.metadata().taint == header_taint);
    download.finish().await?;
    Ok(())
}

#[tokio::test]
async fn full_reads_have_bounded_windows_and_exact_object_eof() -> anyhow::Result<()> {
    let size = READ_CHUNK_BYTES as u64 + 3;
    let fixture = Fixture::new(ReadProbe::new(size)).await?;
    let grant = fixture.issue(0, None).await?;
    let mut download = fixture.open(&grant, 0, None).await?;
    let mut buffer = vec![0; READ_CHUNK_BYTES * 2];
    let first = download.read(&mut buffer).await?;
    ensure!(first.bytes_read == READ_CHUNK_BYTES && !first.end);
    ensure!(!download.is_complete());
    let last = download.read(&mut buffer).await?;
    ensure!(last.bytes_read == 3 && last.end && download.is_complete());
    ensure!(fixture.probe.largest_window.load(Ordering::Relaxed) == READ_CHUNK_BYTES);
    download.finish().await?;
    Ok(())
}

#[tokio::test]
async fn empty_windows_and_ranges_do_not_read_content() -> anyhow::Result<()> {
    for (size, offset, length) in [(0, 0, 0), (8, 3, 0), (8, 8, 0)] {
        let fixture = Fixture::new(ReadProbe::new(size)).await?;
        let grant = fixture.issue(0, None).await?;
        let mut download = fixture.open(&grant, offset, Some(length)).await?;
        ensure!(download.is_complete());
        let chunk = download.read(&mut [0; 4]).await?;
        ensure!(chunk.bytes_read == 0 && chunk.end == (offset == size));
        ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 0);
        download.finish().await?;
    }
    let fixture = Fixture::new(ReadProbe::new(8)).await?;
    let grant = fixture.issue(0, None).await?;
    let mut download = fixture.open(&grant, 0, None).await?;
    let chunk = download.read(&mut []).await?;
    ensure!(chunk.bytes_read == 0 && !chunk.end && !download.is_complete());
    ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 0);
    ensure!(download.finish().await.is_err());
    Ok(())
}

#[tokio::test]
async fn huge_offsets_and_invalid_ranges_never_allocate_for_total_size() -> anyhow::Result<()> {
    let fixture = Fixture::new(ReadProbe::new(u64::MAX)).await?;
    let grant = fixture.issue(u64::MAX - 8, None).await?;
    let metadata_reads = fixture.probe.metadata_reads.load(Ordering::Relaxed);
    for (offset, length) in [(0, Some(1)), (u64::MAX - 1, Some(2)), (u64::MAX, Some(1))] {
        ensure!(fixture.open(&grant, offset, length).await.is_err());
    }
    ensure!(fixture.probe.metadata_reads.load(Ordering::Relaxed) == metadata_reads);
    ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 0);
    let mut download = fixture.open(&grant, u64::MAX - 3, None).await?;
    let mut buffer = [0; 7];
    let chunk = download.read(&mut buffer).await?;
    ensure!(chunk.bytes_read == 3 && chunk.end);
    ensure!(download.next_offset() == u64::MAX && download.is_complete());
    ensure!(fixture.probe.largest_window.load(Ordering::Relaxed) == 3);
    download.finish().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_progress_or_read_errors_close_the_owner_without_advancing() -> anyhow::Result<()>
{
    for reply in [
        ReadReply::Zero,
        ReadReply::Excessive,
        ReadReply::PrematureEnd,
        ReadReply::MissingEnd,
        ReadReply::Error,
    ] {
        let mut probe = ReadProbe::new(4);
        probe.reply = reply;
        let fixture = Fixture::new(probe).await?;
        let grant = fixture.issue(0, None).await?;
        let mut download = fixture.open(&grant, 0, None).await?;
        let offered = if matches!(reply, ReadReply::PrematureEnd) {
            2
        } else {
            4
        };
        ensure!(download.read(&mut [0; 4][..offered]).await.is_err());
        ensure!(download.next_offset() == 0 && download.validate().is_err());
        ensure!(download.read(&mut [0; 4]).await.is_err());
        ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 1);
        ensure!(download.finish().await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_a_polled_read_closes_the_owner_but_unpolled_reads_do_not() -> anyhow::Result<()>
{
    let gate = Gate::new();
    let mut probe = ReadProbe::new(4);
    probe.gate = Some(gate.clone());
    let fixture = Fixture::new(probe).await?;
    let grant = fixture.issue(0, None).await?;
    let mut download = fixture.open(&grant, 0, None).await?;
    let mut buffer = [0; 4];
    drop(download.read(&mut buffer));
    download.validate()?;
    ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 0);
    let mut read = Box::pin(download.read(&mut buffer));
    tokio::select! {
        result = &mut read => bail!("read did not wait for storage: {result:?}"),
        ready = gate.wait() => ready?,
    }
    drop(read);
    ensure!(download.next_offset() == 0 && download.validate().is_err());
    ensure!(download.read(&mut buffer).await.is_err());
    ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 1);
    Ok(())
}

#[tokio::test]
async fn revoked_grants_fail_before_io_after_pending_io_and_at_completion() -> anyhow::Result<()> {
    for pending in [false, true] {
        let gate = Gate::new();
        let mut probe = ReadProbe::new(4);
        if pending {
            probe.gate = Some(gate.clone());
        }
        let fixture = Fixture::new(probe).await?;
        let grant = fixture.issue(0, None).await?;
        let mut download = fixture.open(&grant, 0, None).await?;
        let mut buffer = [0; 4];
        if pending {
            let mut read = Box::pin(download.read(&mut buffer));
            tokio::select! {
                result = &mut read => bail!("read did not wait for storage: {result:?}"),
                ready = gate.wait() => ready?,
            }
            fixture.revoke(&grant).await?;
            gate.release.add_permits(1);
            ensure!(read.await.is_err());
        } else {
            fixture.revoke(&grant).await?;
            ensure!(download.read(&mut buffer).await.is_err());
        }
        ensure!(download.next_offset() == 0 && download.validate().is_err());
        ensure!(fixture.probe.reads.load(Ordering::Relaxed) == usize::from(pending));
    }
    for length in [0, 4] {
        let fixture = Fixture::new(ReadProbe::new(4)).await?;
        let grant = fixture.issue(0, None).await?;
        let mut download = fixture.open(&grant, 0, Some(length)).await?;
        if length != 0 {
            download.read(&mut [0; 4]).await?;
        }
        ensure!(download.is_complete());
        fixture.revoke(&grant).await?;
        ensure!(download.finish().await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn missing_grants_and_changed_metadata_fail_before_reading_payload() -> anyhow::Result<()> {
    let fixture = Fixture::new(ReadProbe::new(4)).await?;
    ensure!(
        fixture
            .gateway
            .open_object_read(
                &fixture.session,
                OpenObjectReadRequest {
                    grant_id: format!("org_{}", "b".repeat(32)),
                    offset: 0,
                    length: None,
                }
            )
            .await
            .is_err()
    );
    ensure!(fixture.probe.metadata_reads.load(Ordering::Relaxed) == 0);
    let grant = fixture.issue(0, None).await?;
    let canonical = fixture.probe.metadata.read().clone().context("metadata")?;
    for field in ["hash", "size", "mime", "missing"] {
        let mut changed = canonical.clone();
        match field {
            "hash" => changed.blob.hash = "b".repeat(64),
            "size" => changed.blob.size += 1,
            "mime" => changed.blob.mime = None,
            _ => {}
        }
        *fixture.probe.metadata.write() = (field != "missing").then_some(changed);
        ensure!(fixture.open(&grant, 0, None).await.is_err());
        ensure!(fixture.probe.reads.load(Ordering::Relaxed) == 0);
    }
    Ok(())
}
