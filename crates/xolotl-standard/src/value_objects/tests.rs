use super::*;
use anyhow::{Context, ensure};
use std::{
    cell::Cell,
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};
use xolotl_graph::{
    OperationTemplate,
    portable::{Expression, Program},
};
use xolotl_kernel::Executor;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{
    BlobRef, DType, FloatBits, FrameKind, Path, StreamMarker, TaintSet, TaintSource,
    value::event::KeyId,
};
use xolotl_value_codec::validation::MemoryKeyError;

mod sources;

fn config(window: usize) -> anyhow::Result<ValueObjectConfig> {
    Ok(ValueObjectConfig {
        io_bytes: NonZeroUsize::new(window).context("I/O window")?,
        ..ValueObjectConfig::default()
    })
}

fn memory_options() -> MemoryKeyOptions {
    MemoryKeyOptions {
        page_bytes: NonZeroUsize::MIN.saturating_add(255),
        max_keys: None,
        max_bytes: None,
    }
}

fn invoke(boot: &Bootstrap, executor: &Executor, path: &str) -> anyhow::Result<Expression> {
    let target = ResourceName::new(Path::parse(path)?);
    let handle = boot
        .open_for(boot.root, &target, "perform")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    executor.bind_handle(target.clone(), handle);
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    })
}

fn typed_document() -> Value {
    let blob = BlobRef {
        // Successful decoding must never try to open this nested reference.
        hash: "not-present-in-the-object-store".into(),
        size: u64::MAX,
        mime: Some("application/typed-test".into()),
    };
    let shared = Value::list(vec![Value::string("model αβ".repeat(4096))]);
    Value::map(BTreeMap::from([
        (
            "".into(),
            Value::list(vec![
                Value::null(),
                Value::boolean(true),
                Value::integer(i64::MIN),
                Value::float(FloatBits(-0.0)),
                Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0042))),
                Value::bytes(vec![0, 255, 128]),
                Value::blob(blob.clone()),
                Value::tensor(blob.clone(), DType::Bf16, vec![u64::MAX, 0, 17]),
                Value::frame(blob, i64::MIN, FrameKind::Sensor),
                Value::stream_end(StreamMarker::Done),
                Value::stream_end(StreamMarker::Error {
                    message: "partial model output".into(),
                }),
            ]),
        ),
        ("shared-first".into(), shared.clone()),
        ("shared-second".into(), shared),
        ("长键".repeat(8192), Value::string("tail".into())),
    ]))
}

struct RetainInput {
    seen: Arc<parking_lot::Mutex<Option<TaintedValue>>>,
}

#[async_trait]
impl Driver for RetainInput {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        *self.seen.lock() = Some(TaintedValue::new(input.clone(), context.taint.clone()));
        Ok(DriverOutput::new(Outcome::Done(input)).with_taint(context.taint.clone()))
    }
}

// A KeyStore is exclusive per call, so a Send but deliberately non-Sync store
// must remain usable by the hosted Driver adapter.
struct TrackedKeys {
    inner: MemoryKeyStore,
    dropped: Arc<AtomicUsize>,
    _local: Cell<()>,
}

impl Drop for TrackedKeys {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl KeyStore for TrackedKeys {
    type Error = MemoryKeyError;
    type Create<'a> = <MemoryKeyStore as KeyStore>::Create<'a>;
    type ComparePrefix<'a> = <MemoryKeyStore as KeyStore>::ComparePrefix<'a>;
    type Append<'a> = <MemoryKeyStore as KeyStore>::Append<'a>;
    type Release<'a> = <MemoryKeyStore as KeyStore>::Release<'a>;

    fn create(&mut self, key: KeyId) -> Self::Create<'_> {
        self.inner.create(key)
    }

    fn compare_prefix<'a>(
        &'a mut self,
        key: KeyId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a> {
        self.inner.compare_prefix(key, offset, bytes)
    }

    fn append<'a>(&'a mut self, key: KeyId, offset: u64, bytes: &'a [u8]) -> Self::Append<'a> {
        self.inner.append(key, offset, bytes)
    }

    fn release(&mut self, key: KeyId) -> Self::Release<'_> {
        self.inner.release(key)
    }
}

#[tokio::test]
async fn kernel_write_read_pipeline_preserves_typed_values_and_resident_sharing()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let boot = Bootstrap::in_memory();
    let created = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let factory = {
        let created = created.clone();
        let dropped = dropped.clone();
        move || {
            let created = created.clone();
            let dropped = dropped.clone();
            async move {
                tokio::task::yield_now().await;
                created.fetch_add(1, Ordering::SeqCst);
                Ok(TrackedKeys {
                    inner: MemoryKeyStore::new(memory_options()),
                    dropped,
                    _local: Cell::new(()),
                })
            }
        }
    };
    let installed = install_value_objects(
        &boot,
        FileObjectStore::open(directory.path())?.into_object_store(),
        config(127)?,
        factory,
    )?;
    ensure!(installed.read.is_some() && installed.write.is_some());
    ensure!(created.load(Ordering::SeqCst) == 0);
    let seen = Arc::new(parking_lot::Mutex::new(None));
    boot.register_effect(
        "effect://test/retain",
        &[MethodSpec::unary_async("invoke", Purity::Pure)],
        Arc::new(RetainInput { seen: seen.clone() }),
    )?;
    let executor = boot.kernel.executor_for(boot.root);
    let program = Program::new(
        invoke(&boot, &executor, "effect://value/write")?
            .then(invoke(&boot, &executor, "effect://value/read")?)
            .then(invoke(&boot, &executor, "effect://test/retain")?),
    )
    .compile()?;
    let original = typed_document();
    let identity = original.identity();
    let taint = TaintSet::of(TaintSource::ModelOutput);
    let result = executor
        .eval_program(&program, TaintedValue::new(original.clone(), taint.clone()))
        .await;
    ensure!(
        result.outcome == Outcome::Done(original.clone()),
        "{result:?}"
    );
    ensure!(result.taint.contains_all(&taint));
    ensure!(original.identity() == identity);
    let observed = seen.lock();
    let observed = observed.as_ref().context("downstream provider input")?;
    ensure!(result.outcome.value().and_then(Value::identity) == observed.value.identity());
    ensure!(observed.taint == result.taint);
    ensure!(created.load(Ordering::SeqCst) == 2 && dropped.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn only_installed_object_capabilities_become_effects_and_creation_is_lazy()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let files = Arc::new(FileObjectStore::open(directory.path())?);
    for (read, write) in [(false, false), (true, false), (false, true), (true, true)] {
        let boot = Bootstrap::in_memory();
        let mut objects = ObjectStore::new();
        if read {
            objects = objects.with_read(files.clone());
        }
        if write {
            objects = objects.with_write(files.clone());
        }
        let installed =
            install_value_objects(&boot, objects, ValueObjectConfig::default(), || async {
                Err::<MemoryKeyStore, _>(DriverError::Other("factory invoked".into()))
            })?;
        ensure!(installed.read.is_some() == read && installed.write.is_some() == write);
        for (enabled, path) in [
            (read, "effect://value/read"),
            (write, "effect://value/write"),
        ] {
            let target = ResourceName::new(Path::parse(path)?);
            ensure!(boot.open_for(boot.root, &target, "perform").is_ok() == enabled);
        }
    }
    Ok(())
}

#[tokio::test]
async fn reference_shaped_maps_are_written_as_values_and_read_requires_an_explicit_descriptor()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let boot = Bootstrap::in_memory();
    install_value_objects(
        &boot,
        FileObjectStore::open(directory.path())?.into_object_store(),
        config(31)?,
        memory_key_factory(memory_options()),
    )?;
    let executor = boot.kernel.executor_for(boot.root);
    let descriptor = EncodedValueRef {
        blob: BlobRef {
            hash: "unresolvable-nested-reference".into(),
            size: u64::MAX,
            mime: None,
        },
        encoding: xolotl_value_object::ValueEncoding::CborV1,
    }
    .into_value();
    let program = Program::new(
        invoke(&boot, &executor, "effect://value/write")?.then(invoke(
            &boot,
            &executor,
            "effect://value/read",
        )?),
    )
    .compile()?;
    let result = executor
        .eval_program(&program, TaintedValue::pristine(descriptor.clone()))
        .await;
    ensure!(result.outcome == Outcome::Done(descriptor));

    let read = Program::new(invoke(&boot, &executor, "effect://value/read")?).compile()?;
    for input in [
        Value::null(),
        Value::blob(BlobRef {
            hash: "untyped-profile".into(),
            size: 0,
            mime: Some("application/vnd.xolotl.value+cbor".into()),
        }),
    ] {
        let result = executor
            .eval_program(&read, TaintedValue::pristine(input))
            .await;
        ensure!(matches!(
            result.outcome,
            Outcome::Fail(Failure::InvalidInput { .. })
        ));
    }
    Ok(())
}

#[tokio::test]
async fn read_materialization_policy_does_not_limit_writes_or_change_object_retention()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let files = FileObjectStore::open(directory.path())?;
    let boot = Bootstrap::in_memory();
    install_value_objects(
        &boot,
        files.clone().into_object_store(),
        ValueObjectConfig {
            read_limits: MaterializationLimits {
                max_payload_bytes: Some(8),
                ..MaterializationLimits::default()
            },
            ..config(29)?
        },
        memory_key_factory(memory_options()),
    )?;
    let executor = boot.kernel.executor_for(boot.root);
    let write = Program::new(invoke(&boot, &executor, "effect://value/write")?).compile()?;
    let source = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://private/encoded-value")?,
    });
    let written = executor
        .eval_program(
            &write,
            TaintedValue::new(
                Value::string("large materialized value".repeat(512)),
                source.clone(),
            ),
        )
        .await;
    let reference =
        EncodedValueRef::try_from_value(written.outcome.value().context("write output")?)?;
    let read = Program::new(invoke(&boot, &executor, "effect://value/read")?).compile()?;
    let result = executor
        .eval_program(
            &read,
            TaintedValue::pristine(reference.clone().into_value()),
        )
        .await;
    ensure!(matches!(
        result.outcome,
        Outcome::Fail(Failure::HandlerError { ref kind, ref message })
            if kind == "value_read" && message.contains("materialization")
    ));
    ensure!(result.taint.contains_all(&source));
    ensure!(
        xolotl_state::object::ObjectRead::metadata(&files, &reference.blob)
            .await?
            .is_some()
    );
    ensure!(files.pending_uploads() == 0);
    Ok(())
}
