use super::*;
use anyhow::{Context as _, ensure};

#[test]
fn chunks_use_exact_encoded_capacity_and_share_the_source_window() -> anyhow::Result<()> {
    let bytes = Bytes::from(vec![91; 32 * 1024]);
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/download")?,
    });
    for offset in [0, 127, 128, 16_383, u64::MAX] {
        for limit in [96, 127, 128, 255, 16_383, 16_384, 64 * 1024] {
            let (mut response, count) = chunk_to_pb(offset, bytes.clone(), &taint, limit)?;
            ensure!(response.encoded_len() <= limit);
            let Some(pb::download_object_response::Event::Chunk(chunk)) = &mut response.event
            else {
                anyhow::bail!("download chunk missing");
            };
            ensure!(chunk.offset == offset && chunk.data.len() == count);
            ensure!(chunk.data.as_ptr() == bytes.as_ptr());
            ensure!(
                chunk
                    .taint
                    .as_ref()
                    .context("chunk provenance missing")?
                    .sources
                    .len()
                    == 1
            );
            if count < bytes.len() {
                chunk.data = bytes.slice(..count + 1);
                ensure!(response.encoded_len() > limit);
            }
        }
    }
    Ok(())
}

#[test]
fn metadata_exhaustion_never_truncates_chunk_sources() {
    let taint = TaintSet::of(TaintSource::Fetched {
        host: "x".repeat(4096).into(),
    });
    let error = chunk_to_pb(0, Bytes::from_static(b"content"), &taint, 256);
    assert!(matches!(error, Err(status) if status.code() == tonic::Code::ResourceExhausted));
    assert!(chunk_to_pb(0, Bytes::from_static(b"x"), &TaintSet::pristine(), 1).is_err());
}
