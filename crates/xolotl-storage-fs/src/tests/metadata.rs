use super::*;

async fn committed(
    store: &FileObjectStore,
    mime: Option<String>,
) -> anyhow::Result<ObjectMetadata> {
    let sources = TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://private/metadata-source")?,
    });
    let upload = store
        .begin_upload(UploadOptions {
            mime,
            taint: sources,
            ..UploadOptions::default()
        })
        .await?;
    write_all(store, &upload, b"metadata fixture").await?;
    Ok(store.commit_upload(&upload, &TaintSet::pristine()).await?)
}

fn metadata_path(store: &FileObjectStore, metadata: &ObjectMetadata) -> PathBuf {
    store
        .root()
        .join("objects")
        .join(&metadata.blob.hash)
        .join("metadata")
}

fn descriptor_offset(bytes: &[u8]) -> anyhow::Result<usize> {
    let length: [u8; 8] = bytes
        .get(4..12)
        .context("source length missing")?
        .try_into()?;
    Ok(12 + usize::try_from(u64::from_le_bytes(length))?)
}

#[tokio::test]
async fn metadata_budget_rejection_keeps_sources_without_materializing_the_descriptor()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let metadata = committed(&store, Some("x".repeat(64 * 1024))).await?;
    let encoded = std::fs::read(metadata_path(&store, &metadata))?;
    let limit = descriptor_offset(&encoded)?;
    ensure!(limit < encoded.len());
    let limited = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_metadata_bytes: NonZeroUsize::new(limit).context("source header budget")?,
            ..FileObjectOptions::default()
        },
    )?;
    let failure = limited
        .metadata(&metadata.blob)
        .await
        .err()
        .context("large descriptor escaped the selected metadata budget")?;
    ensure!(failure.taint.contains_all(&metadata.taint));
    let failure = limited
        .read_chunk(&metadata.blob, 0, &mut [0; 4])
        .await
        .err()
        .context("read accepted metadata outside the selected budget")?;
    ensure!(failure.taint.contains_all(&metadata.taint));
    ensure!(store.metadata(&metadata.blob).await? == Some(metadata.clone()));
    Ok(())
}

#[tokio::test]
async fn malformed_or_mismatched_descriptors_preserve_the_same_file_source_header()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let metadata = committed(&store, None).await?;
    let path = metadata_path(&store, &metadata);
    let encoded = std::fs::read(&path)?;
    let offset = descriptor_offset(&encoded)?;
    let mut wrong_identity = metadata.blob.clone();
    wrong_identity.hash = "0".repeat(64);
    for payload in [
        b"{".to_vec(),
        b"null".to_vec(),
        Vec::new(),
        serde_json::to_vec(&wrong_identity)?,
    ] {
        let mut damaged = encoded[..offset].to_vec();
        damaged.extend_from_slice(&payload);
        std::fs::write(&path, damaged)?;
        let failure = store
            .metadata(&metadata.blob)
            .await
            .err()
            .context("damaged descriptor produced a receipt")?;
        ensure!(failure.taint.contains_all(&metadata.taint));
    }
    std::fs::write(path, encoded)?;
    ensure!(store.metadata(&metadata.blob).await? == Some(metadata));
    Ok(())
}

#[tokio::test]
async fn damaged_or_oversized_source_headers_never_produce_object_receipts() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let metadata = committed(&store, None).await?;
    let path = metadata_path(&store, &metadata);
    let encoded = std::fs::read(&path)?;
    let mut oversized = encoded.clone();
    oversized[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut malformed = encoded.clone();
    malformed[12] = b'!';
    let mut unknown_format = encoded.clone();
    unknown_format[..4].copy_from_slice(b"bad!");
    for damaged in [encoded[..8].to_vec(), oversized, malformed, unknown_format] {
        std::fs::write(&path, damaged)?;
        // The header did not establish a complete known source floor. Reject
        // both APIs, without returning any supposedly pristine object/chunk.
        ensure!(store.metadata(&metadata.blob).await.is_err());
        ensure!(
            store
                .read_chunk(&metadata.blob, 0, &mut [0; 4])
                .await
                .is_err()
        );
    }
    std::fs::write(path, encoded)?;
    ensure!(store.metadata(&metadata.blob).await? == Some(metadata));
    Ok(())
}
