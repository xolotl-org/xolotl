use super::*;
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, sync::Arc};
use xolotl_kernel::host::stream::{StreamItem, channel};
use xolotl_kernel::stream::StreamWindow;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{DType, FrameKind, IdentityRef, ProcessId, TaintSource};

fn ctx() -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
}

fn blob(output: DriverOutput) -> Result<BlobRef> {
    match output.outcome {
        Outcome::Done(value) => match value.view() {
            ValueView::Blob(blob) => Ok(blob.clone()),
            _ => bail!("expected blob reference"),
        },
        other => bail!("expected blob reference, got {other:?}"),
    }
}

fn views(blob: BlobRef) -> [Value; 3] {
    [
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), DType::U8, vec![blob.size]),
        Value::frame(blob, 123, FrameKind::Audio),
    ]
}

#[tokio::test]
async fn tensor_write_pipes_directly_into_blob_read() -> Result<()> {
    use crate::{StandardConfig, StandardModule, StandardModules, install_standard};
    use xolotl_graph::{
        OperationTemplate,
        portable::{Expression, Program},
    };
    use xolotl_kernel::Bootstrap;
    use xolotl_types::{Path, ResourceName};

    let directory = tempfile::tempdir()?;
    let boot = Bootstrap::in_memory();
    install_standard(
        &boot,
        &StandardConfig::default()
            .with_modules(
                StandardModules::none()
                    .with(StandardModule::Tensor)
                    .with(StandardModule::Blob),
            )
            .with_object_store(FileObjectStore::open(directory.path())?.into_object_store()),
    )?;
    let executor = boot.kernel.executor_for(boot.root);
    let invoke = |path| -> Result<Expression> {
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
    };
    let program =
        Program::new(invoke("effect://tensor/write")?.then(invoke("effect://blob/read")?))
            .compile()?;
    let result = executor
        .eval_program(
            &program,
            TaintedValue::pristine(Value::map(BTreeMap::from([
                (
                    "data".into(),
                    Value::list(vec![(-32768).into(), 17.into(), 32767.into()]),
                ),
                ("dtype".into(), "i16".into()),
            ]))),
        )
        .await;
    ensure!(
        result.outcome == Outcome::Done(Value::bytes(vec![0, 128, 17, 0, 255, 127])),
        "{result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn typed_views_compose_with_independent_object_capabilities() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let files = Arc::new(FileObjectStore::open(directory.path())?);
    let tensor = crate::tensor::TensorDriver::new(ObjectStore::new().with_write(files.clone()));
    let reader = BlobDriver::new(ObjectStore::new().with_read(files.clone()));
    let deleter = BlobDriver::new(ObjectStore::new().with_delete(files));
    let taint = TaintSet::of(TaintSource::ModelOutput);
    for index in 0..3 {
        let written = tensor
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::from([
                    ("data".into(), Value::list(vec![42.into()])),
                    ("dtype".into(), "u8".into()),
                ])),
                OutputMode::Unary,
                &ctx().with_taint(taint.clone()),
            )
            .await?;
        let Outcome::Done(reference) = written.outcome else {
            bail!("tensor write did not finish");
        };
        let read = reader
            .call(
                MethodId::new(1),
                reference.clone(),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        ensure!(read.outcome == Outcome::Done(Value::bytes(vec![42])) && read.taint == taint);
        let denied = reader
            .call(
                MethodId::new(2),
                reference.clone(),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(
            denied
                .err()
                .context("reader deleted a tensor")?
                .to_string()
                .contains("object.delete")
        );
        let reference = reference.backing_blob().context("missing tensor content")?;
        let all_views = views(reference.clone());
        let deleted = deleter
            .call(
                MethodId::new(2),
                all_views[index].clone(),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        ensure!(deleted.outcome == Outcome::Done(Value::null()));
        for view in all_views {
            let read = reader
                .call(MethodId::new(1), view, OutputMode::Unary, &ctx())
                .await?;
            ensure!(read.outcome == Outcome::Done(Value::null()));
        }
    }
    Ok(())
}

#[tokio::test]
async fn writes_and_reads_empty_and_nonempty_content() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let driver = BlobDriver::new(FileObjectStore::open(dir.path())?.into_object_store());
    for bytes in [Vec::new(), b"hello".to_vec()] {
        let written = driver
            .call(
                MethodId::new(0),
                Value::bytes(bytes.clone()),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        let reference = blob(written)?;
        ensure!(reference.size == bytes.len() as u64);
        let read = driver
            .call(
                MethodId::new(1),
                Value::blob(reference),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        ensure!(read.outcome == Outcome::Done(Value::bytes(bytes)));
    }
    Ok(())
}

#[tokio::test]
async fn deduplicated_content_keeps_all_provenance() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let driver = BlobDriver::new(FileObjectStore::open(dir.path())?.into_object_store());
    let source = TaintSet::of(TaintSource::ModelOutput);
    let protected = ctx().with_taint(source.clone());
    let first = driver
        .call(
            MethodId::new(0),
            Value::string("shared".into()),
            OutputMode::Unary,
            &protected,
        )
        .await?;
    let reference = blob(first)?;
    let repeated = driver
        .call(
            MethodId::new(0),
            Value::string("shared".into()),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(repeated.taint == source);
    let read = driver
        .call(
            MethodId::new(1),
            Value::blob(reference),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(read.taint == source);
    Ok(())
}

#[tokio::test]
async fn large_unary_read_uses_canonical_reference_and_stream_read_is_incremental() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let driver = BlobDriver::new(FileObjectStore::open(dir.path())?.into_object_store());
    let bytes = vec![41; crate::object::INLINE_BYTES * 2 + 17];
    let source = TaintSet::of(TaintSource::ModelOutput);
    let written = driver
        .call(
            MethodId::new(0),
            Value::bytes(bytes.clone()),
            OutputMode::Unary,
            &ctx().with_taint(source.clone()),
        )
        .await?;
    let reference = blob(written)?;
    let forged = BlobRef {
        size: 1,
        mime: Some("untrusted".into()),
        ..reference.clone()
    };
    for view in views(forged) {
        let unary = driver
            .call(MethodId::new(1), view, OutputMode::Unary, &ctx())
            .await?;
        ensure!(unary.taint == source);
        ensure!(blob(unary)? == reference);
    }
    let (sink, mut receiver) = channel(StreamWindow::default());
    let context = ctx().with_stream_sink(sink);
    let producer = driver.call(
        MethodId::new(1),
        Value::blob(reference),
        OutputMode::Stream,
        &context,
    );
    let consumer = async {
        let mut received = 0_usize;
        while received < bytes.len() {
            let item = receiver.recv().await.context("expected object chunk")?;
            let StreamItem::Chunk(chunk) = item else {
                bail!("unexpected terminal")
            };
            let value = chunk.into_value();
            ensure!(value.taint == source);
            let Some(part) = value.value.as_bytes() else {
                bail!("expected bytes")
            };
            ensure!(part.len() <= crate::object::CHUNK_BYTES);
            ensure!(part == &bytes[received..received + part.len()]);
            received += part.len();
        }
        Ok::<_, anyhow::Error>(())
    };
    let (result, read) = tokio::join!(producer, consumer);
    read?;
    let result = result?;
    ensure!(result.outcome == Outcome::Done(Value::null()));
    ensure!(result.taint.is_pristine());
    Ok(())
}

#[tokio::test]
async fn missing_object_capabilities_fail_explicitly() -> Result<()> {
    let driver = BlobDriver::new(ObjectStore::new());
    for (method, input) in [
        (0, Value::string("bytes".into())),
        (1, Value::string("hash".into())),
        (2, Value::string("hash".into())),
    ] {
        let error = driver
            .call(MethodId::new(method), input, OutputMode::Unary, &ctx())
            .await
            .err()
            .context("missing capability succeeded")?;
        ensure!(error.to_string().contains("capability"));
    }
    Ok(())
}

#[tokio::test]
async fn deletion_uses_the_installed_capability_and_removes_committed_content() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let objects = FileObjectStore::open(directory.path())?.into_object_store();
    let driver = BlobDriver::new(objects.clone());
    let reference = blob(
        driver
            .call(
                MethodId::new(0),
                Value::string("delete".into()),
                OutputMode::Unary,
                &ctx(),
            )
            .await?,
    )?;
    for _ in 0..2 {
        driver
            .call(
                MethodId::new(2),
                Value::blob(reference.clone()),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
    }
    ensure!(objects.metadata(&reference).await?.is_none());
    let result = driver
        .call(
            MethodId::new(1),
            Value::blob(reference),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
    ensure!(result.outcome == Outcome::Done(Value::null()));
    Ok(())
}
