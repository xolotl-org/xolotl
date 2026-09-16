use super::*;
use core::pin::Pin;
use std::sync::atomic::AtomicBool;
use xolotl_state::{
    StateError, StateResult,
    object::{ObjectMetadata, ObjectRead, ObjectReadChunk},
};

type Request<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

#[derive(Clone, Copy)]
enum Behavior {
    Valid,
    InvalidFinalProgress,
    InvalidFinalEncoding,
    FailAfterLateSource,
}

struct LaterSources {
    files: Arc<FileObjectStore>,
    taint: TaintSet,
    window: u64,
    behavior: Behavior,
    observed: AtomicBool,
    reached_eof: AtomicBool,
}

impl ObjectRead for LaterSources {
    type Metadata<'a> = Request<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Request<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(async move { self.files.metadata(blob).await })
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(async move {
            if matches!(self.behavior, Behavior::FailAfterLateSource) && offset >= self.window * 2 {
                return Err(StateError::Backend("private source read failed".into()).into());
            }
            let mut chunk = self.files.read_chunk(blob, offset, buffer).await?;
            if offset != 0 {
                chunk.taint.union(&self.taint);
                self.observed.store(true, Ordering::SeqCst);
            }
            if chunk.end {
                self.reached_eof.store(true, Ordering::SeqCst);
                match self.behavior {
                    Behavior::InvalidFinalProgress => chunk.end = false,
                    Behavior::InvalidFinalEncoding if chunk.bytes_read != 0 => {
                        buffer[chunk.bytes_read - 1] ^= 0xff;
                    }
                    _ => {}
                }
            }
            Ok(chunk)
        })
    }
}

struct Outbound {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Driver for Outbound {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        _context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(DriverOutput::new(Outcome::Done(input)))
    }
}

#[tokio::test]
async fn later_read_sources_block_outbound_success_and_failure_recovery() -> anyhow::Result<()> {
    for behavior in [
        Behavior::Valid,
        Behavior::InvalidFinalProgress,
        Behavior::InvalidFinalEncoding,
        Behavior::FailAfterLateSource,
    ] {
        let directory = tempfile::tempdir()?;
        let files = Arc::new(FileObjectStore::open(directory.path())?);
        let source = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://private/later-object-read")?,
        });
        let reads = Arc::new(LaterSources {
            files: files.clone(),
            taint: source.clone(),
            window: 64,
            behavior,
            observed: AtomicBool::new(false),
            reached_eof: AtomicBool::new(false),
        });
        let boot = Bootstrap::in_memory();
        install_value_objects(
            &boot,
            ObjectStore::new()
                .with_read(reads.clone())
                .with_write(files.clone()),
            config(64)?,
            memory_key_factory(memory_options()),
        )?;
        let calls = Arc::new(AtomicUsize::new(0));
        boot.register_effect(
            "effect://test/outbound",
            &[MethodSpec::unary_async("invoke", Purity::Effectful).unprotected_input()],
            Arc::new(Outbound {
                calls: calls.clone(),
            }),
        )?;
        let executor = boot.kernel.executor_for(boot.root);
        let value = Value::string("a completed model document".repeat(512));
        let roundtrip = Program::new(
            invoke(&boot, &executor, "effect://value/write")?.then(invoke(
                &boot,
                &executor,
                "effect://value/read",
            )?),
        )
        .compile()?;
        let read = executor
            .eval_program(&roundtrip, TaintedValue::pristine(value.clone()))
            .await;
        ensure!(reads.observed.load(Ordering::SeqCst));
        ensure!(read.taint.contains_all(&source));
        if matches!(behavior, Behavior::Valid) {
            ensure!(reads.reached_eof.load(Ordering::SeqCst));
            ensure!(read.outcome == Outcome::Done(value.clone()));
        } else {
            ensure!(matches!(
                read.outcome,
                Outcome::Fail(Failure::HandlerError { ref kind, .. }) if kind == "value_read"
            ));
        }

        let read = invoke(&boot, &executor, "effect://value/read")?;
        let outbound = invoke(&boot, &executor, "effect://test/outbound")?;
        let continuation = if matches!(behavior, Behavior::Valid) {
            read.then(outbound)
        } else {
            Expression::Catch {
                body: Box::new(read),
                recover: Box::new(outbound),
            }
        };
        let program =
            Program::new(invoke(&boot, &executor, "effect://value/write")?.then(continuation))
                .compile()?;
        let result = executor
            .eval_program(&program, TaintedValue::pristine(value))
            .await;
        ensure!(matches!(
            result.outcome,
            Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "taint"
        ));
        ensure!(result.taint.contains_all(&source));
        ensure!(calls.load(Ordering::SeqCst) == 0);
        ensure!(files.pending_uploads() == 0);
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_a_call_keeps_async_factory_resources_owned_until_drop() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let files = FileObjectStore::open(directory.path())?;
    let boot = Bootstrap::in_memory();
    let dropped = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let factory = {
        let dropped = dropped.clone();
        let started = started.clone();
        move || {
            let dropped = dropped.clone();
            let started = started.clone();
            async move {
                let keys = TrackedKeys {
                    inner: MemoryKeyStore::new(memory_options()),
                    dropped,
                    _local: Cell::new(()),
                };
                started.fetch_add(1, Ordering::SeqCst);
                core::future::pending::<()>().await;
                Ok(keys)
            }
        }
    };
    install_value_objects(
        &boot,
        files.clone().into_object_store(),
        config(64)?,
        factory,
    )?;
    let executor = boot.kernel.executor_for(boot.root);
    let program = Program::new(invoke(&boot, &executor, "effect://value/write")?).compile()?;
    let original = Value::string("caller retains this shared value".repeat(1024));
    let identity = original.identity();
    let mut run =
        Box::pin(executor.eval_program(&program, TaintedValue::pristine(original.clone())));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    ensure!(run.as_mut().poll(&mut context).is_pending());
    ensure!(started.load(Ordering::SeqCst) == 1 && dropped.load(Ordering::SeqCst) == 0);
    drop(run);
    ensure!(dropped.load(Ordering::SeqCst) == 1);
    ensure!(original.identity() == identity && files.pending_uploads() == 0);
    Ok(())
}
