//! Object download envelopes and exact per-frame byte admission.

use prost::bytes::Bytes;
use xolotl_gateway::{GatewayObjectDownload, OpenObjectReadRequest};

use super::*;

pub(in crate::application) fn request_from_pb(
    request: pb::DownloadObjectRequest,
) -> OpenObjectReadRequest {
    OpenObjectReadRequest {
        grant_id: request.read_grant_id,
        offset: request.offset,
        length: request.length,
    }
}

pub(in crate::application) fn header_to_pb(
    download: &GatewayObjectDownload,
    max_frame_bytes: usize,
) -> Result<pb::DownloadObjectResponse, Status> {
    let mut budget = ConversionBudget::new(max_frame_bytes);
    let metadata = download.metadata();
    bounded_response(
        pb::DownloadObjectResponse {
            event: Some(pb::download_object_response::Event::Header(
                pb::ObjectReadHeader {
                    blob: Some(common::BlobRef {
                        hash: budget.string(&metadata.blob.hash)?,
                        size: metadata.blob.size,
                        mime: budget.optional_string(metadata.blob.mime.as_deref())?,
                    }),
                    offset: download.start_offset(),
                    length: download.end_offset() - download.start_offset(),
                    taint: Some(budget.taint(&metadata.taint)?),
                    expires_at_ms: download.expires_at_ms(),
                },
            )),
        },
        max_frame_bytes,
    )
}

pub(in crate::application) fn chunk_to_pb(
    offset: u64,
    bytes: Bytes,
    taint: &TaintSet,
    max_frame_bytes: usize,
) -> Result<(pb::DownloadObjectResponse, usize), Status> {
    let mut budget = ConversionBudget::new(max_frame_bytes);
    let mut response = pb::DownloadObjectResponse {
        event: Some(pb::download_object_response::Event::Chunk(
            pb::ObjectReadChunk {
                offset,
                data: bytes.clone(),
                taint: Some(budget.taint(taint)?),
            },
        )),
    };
    if !bytes.is_empty() && response.encoded_len() <= max_frame_bytes {
        return Ok((response, bytes.len()));
    }
    let mut fits = 0;
    let mut remaining = bytes.len();
    // Ask the canonical encoder about each slice, including nested length
    // prefixes. Slices share the read window; no trial payload is copied.
    while fits < remaining {
        let count = fits + (remaining - fits).div_ceil(2);
        if let Some(pb::download_object_response::Event::Chunk(chunk)) = &mut response.event {
            chunk.data = bytes.slice(..count);
        }
        if response.encoded_len() <= max_frame_bytes {
            fits = count;
        } else {
            remaining = count - 1;
        }
    }
    if fits == 0 {
        return Err(response_too_large());
    }
    if let Some(pb::download_object_response::Event::Chunk(chunk)) = &mut response.event {
        chunk.data = bytes.slice(..fits);
    }
    Ok((response, fits))
}

pub(in crate::application) fn completed_to_pb(
    next_offset: u64,
    bytes_read: u64,
    max_frame_bytes: usize,
) -> Result<pb::DownloadObjectResponse, Status> {
    bounded_response(
        pb::DownloadObjectResponse {
            event: Some(pb::download_object_response::Event::Completed(
                pb::ObjectReadCompleted {
                    next_offset,
                    bytes_read,
                },
            )),
        },
        max_frame_bytes,
    )
}

#[cfg(test)]
mod tests;
