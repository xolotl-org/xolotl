//! Exact snapshot metadata and bounded chunk conversion at the wire boundary.

use std::sync::Arc;

use tonic::Status;
use xolotl_federation as domain;
use xolotl_proto::xolotl::v1::federation as pb;

use super::{
    bytes, position, position_to_pb, required, stream, stream_to_pb, subscription,
    subscription_to_pb,
};

fn manifest(value: pb::SnapshotManifest) -> Result<domain::SnapshotManifest, Status> {
    let manifest = domain::SnapshotManifest {
        id: domain::SnapshotId::from_bytes(bytes(value.snapshot_id, "snapshot id")?),
        subscription: subscription(required(value.subscription, "snapshot subscription")?)?,
        stream: stream(required(value.stream, "snapshot stream")?)?,
        subscription_revision: value.subscription_revision,
        publisher_authority: domain::AuthorityRevision {
            peer: value.publisher_peer_revision,
            export: value.publisher_export_revision,
        },
        position: position(required(value.position, "snapshot position")?)?,
        schema_revision: domain::SchemaRevision::from_bytes(bytes(
            value.schema_revision,
            "snapshot schema",
        )?),
        content_digest: domain::Digest::from_bytes(bytes(value.content_digest, "snapshot digest")?),
        content_bytes: value.content_bytes,
    };
    manifest
        .validate()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(manifest)
}

fn manifest_to_pb(value: &domain::SnapshotManifest) -> pb::SnapshotManifest {
    pb::SnapshotManifest {
        snapshot_id: value.id.as_bytes().to_vec(),
        subscription: Some(subscription_to_pb(value.subscription)),
        stream: Some(stream_to_pb(value.stream)),
        subscription_revision: value.subscription_revision,
        publisher_peer_revision: value.publisher_authority.peer,
        publisher_export_revision: value.publisher_authority.export,
        position: Some(position_to_pb(value.position)),
        schema_revision: value.schema_revision.as_bytes().to_vec(),
        content_digest: value.content_digest.as_bytes().to_vec(),
        content_bytes: value.content_bytes,
    }
}

pub(crate) fn snapshot_offer(value: pb::SnapshotOffer) -> Result<domain::SnapshotOffer, Status> {
    let publication_digest =
        domain::Digest::from_bytes(bytes(value.publication_digest, "publication digest")?);
    if publication_digest.as_bytes() == &[0; 48] {
        return Err(Status::invalid_argument("empty publication digest"));
    }
    Ok(domain::SnapshotOffer {
        manifest: manifest(required(value.manifest, "snapshot manifest")?)?,
        publication_digest,
    })
}

pub(crate) fn snapshot_offer_to_pb(
    request: u64,
    value: &domain::SnapshotOffer,
) -> pb::SnapshotOffered {
    pb::SnapshotOffered {
        request,
        offer: Some(pb::SnapshotOffer {
            manifest: Some(manifest_to_pb(&value.manifest)),
            publication_digest: value.publication_digest.as_bytes().to_vec(),
        }),
    }
}

pub(crate) fn inspect_snapshot(
    peer: domain::FederationNodeId,
    value: pb::InspectSnapshot,
) -> Result<domain::SubscriptionRef, Status> {
    let subscription = subscription(required(value.subscription, "snapshot subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "snapshot subscription owner is not the peer",
        ));
    }
    Ok(subscription)
}

pub(crate) fn inspect_snapshot_to_pb(
    request: u64,
    subscription: domain::SubscriptionRef,
) -> pb::InspectSnapshot {
    pb::InspectSnapshot {
        request,
        subscription: Some(subscription_to_pb(subscription)),
        context_id: 0,
        holder_request_signature: Vec::new(),
    }
}

pub(crate) fn read_snapshot(
    peer: domain::FederationNodeId,
    value: pb::ReadSnapshot,
) -> Result<domain::SnapshotReadRequest, Status> {
    let subscription = subscription(required(value.subscription, "snapshot subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "snapshot subscription owner is not the peer",
        ));
    }
    Ok(domain::SnapshotReadRequest {
        authenticated_subscriber: peer,
        subscription,
        manifest_digest: domain::Digest::from_bytes(bytes(
            value.manifest_digest,
            "manifest digest",
        )?),
        offset: value.offset,
        max_bytes: value.max_bytes as usize,
    })
}

pub(crate) fn read_snapshot_to_pb(
    request: u64,
    value: domain::SnapshotReadRequest,
) -> Result<pb::ReadSnapshot, Status> {
    Ok(pb::ReadSnapshot {
        request,
        subscription: Some(subscription_to_pb(value.subscription)),
        manifest_digest: value.manifest_digest.as_bytes().to_vec(),
        offset: value.offset,
        max_bytes: u32::try_from(value.max_bytes)
            .map_err(|_error| Status::invalid_argument("snapshot chunk limit overflows u32"))?,
        context_id: 0,
        holder_request_signature: Vec::new(),
    })
}

pub(crate) fn snapshot_chunk_to_pb(
    request: u64,
    value: domain::SnapshotReadChunk,
) -> pb::SnapshotChunk {
    pb::SnapshotChunk {
        request,
        subscription: Some(subscription_to_pb(value.offer.manifest.subscription)),
        manifest_digest: value.offer.manifest.binding_digest().as_bytes().to_vec(),
        offset: value.offset,
        data: value.bytes.as_ref().to_vec(),
        complete: value.complete,
    }
}

pub(crate) fn snapshot_chunk(
    value: pb::SnapshotChunk,
    offer: &domain::SnapshotOffer,
    expected_offset: u64,
    max_bytes: usize,
) -> Result<domain::SnapshotReadChunk, Status> {
    let subscription = subscription(required(value.subscription, "snapshot subscription")?)?;
    let digest = bytes::<48>(value.manifest_digest, "manifest digest")?;
    let len = value.data.len();
    let end = expected_offset
        .checked_add(len as u64)
        .ok_or_else(|| Status::invalid_argument("snapshot chunk offset overflow"))?;
    if subscription != offer.manifest.subscription
        || digest != *offer.manifest.binding_digest().as_bytes()
        || value.offset != expected_offset
        || len > max_bytes
        || end > offer.manifest.content_bytes
        || value.complete != (end == offer.manifest.content_bytes)
        || (len == 0 && !value.complete)
    {
        return Err(Status::invalid_argument(
            "snapshot chunk conflicts with offer",
        ));
    }
    Ok(domain::SnapshotReadChunk {
        offer: offer.clone(),
        offset: value.offset,
        bytes: Arc::from(value.data),
        complete: value.complete,
    })
}

pub(crate) fn receive_snapshot(
    peer: domain::FederationNodeId,
    value: pb::ReceiveSnapshot,
) -> Result<domain::SnapshotReceivedRequest, Status> {
    if value.context_id != 0 || !value.holder_request_signature.is_empty() {
        return Err(Status::permission_denied(
            "snapshot receipt requires Node-self authority",
        ));
    }
    let subscription = subscription(required(value.subscription, "snapshot subscription")?)?;
    if subscription.subscriber != peer {
        return Err(Status::permission_denied(
            "snapshot subscription owner is not the peer",
        ));
    }
    let manifest_digest = bytes(value.manifest_digest, "manifest digest")?;
    let publication_digest = bytes(value.publication_digest, "publication digest")?;
    let archive_digest = bytes(value.archive_digest, "archive digest")?;
    let install_id = bytes(value.install_id, "snapshot install ID")?;
    if manifest_digest == [0; 48]
        || publication_digest == [0; 48]
        || archive_digest == [0; 48]
        || install_id == [0; 16]
        || value.federation_generation == 0
    {
        return Err(Status::invalid_argument("empty snapshot receipt binding"));
    }
    Ok(domain::SnapshotReceivedRequest {
        authenticated_subscriber: peer,
        subscription,
        manifest_digest: domain::Digest::from_bytes(manifest_digest),
        publication_digest: domain::Digest::from_bytes(publication_digest),
        position: position(required(value.position, "snapshot position")?)?,
        install_id: domain::SnapshotId::from_bytes(install_id),
        archive_digest: domain::Digest::from_bytes(archive_digest),
        federation_generation: value.federation_generation,
        suffix: value.suffix.map(snapshot_suffix).transpose()?,
    })
}

pub(crate) fn receive_snapshot_to_pb(
    request: u64,
    value: domain::SnapshotReceivedRequest,
) -> pb::ReceiveSnapshot {
    pb::ReceiveSnapshot {
        request,
        subscription: Some(subscription_to_pb(value.subscription)),
        manifest_digest: value.manifest_digest.as_bytes().to_vec(),
        publication_digest: value.publication_digest.as_bytes().to_vec(),
        position: Some(position_to_pb(value.position)),
        context_id: 0,
        holder_request_signature: Vec::new(),
        install_id: value.install_id.as_bytes().to_vec(),
        archive_digest: value.archive_digest.as_bytes().to_vec(),
        federation_generation: value.federation_generation,
        suffix: value.suffix.map(snapshot_suffix_to_pb),
    }
}

pub(crate) fn snapshot_received_to_pb(
    request: u64,
    value: domain::SnapshotReceived,
) -> pb::SnapshotReceived {
    pb::SnapshotReceived {
        request,
        subscription: Some(subscription_to_pb(value.subscription)),
        manifest_digest: value.manifest_digest.as_bytes().to_vec(),
        publication_digest: value.publication_digest.as_bytes().to_vec(),
        position: Some(position_to_pb(value.position)),
        install_id: value.install_id.as_bytes().to_vec(),
        archive_digest: value.archive_digest.as_bytes().to_vec(),
        federation_generation: value.federation_generation,
        suffix: value.suffix.map(snapshot_suffix_to_pb),
    }
}

pub(crate) fn snapshot_received(
    value: pb::SnapshotReceived,
    expected: &domain::SnapshotReceivedRequest,
) -> Result<domain::SnapshotReceived, Status> {
    let received = domain::SnapshotReceived {
        subscription: subscription(required(value.subscription, "snapshot subscription")?)?,
        manifest_digest: domain::Digest::from_bytes(bytes(
            value.manifest_digest,
            "manifest digest",
        )?),
        publication_digest: domain::Digest::from_bytes(bytes(
            value.publication_digest,
            "publication digest",
        )?),
        position: position(required(value.position, "snapshot position")?)?,
        install_id: domain::SnapshotId::from_bytes(bytes(value.install_id, "snapshot install ID")?),
        archive_digest: domain::Digest::from_bytes(bytes(value.archive_digest, "archive digest")?),
        federation_generation: value.federation_generation,
        suffix: value.suffix.map(snapshot_suffix).transpose()?,
    };
    if received.subscription != expected.subscription
        || received.manifest_digest != expected.manifest_digest
        || received.publication_digest != expected.publication_digest
        || received.position != expected.position
        || received.install_id != expected.install_id
        || received.archive_digest != expected.archive_digest
        || received.federation_generation != expected.federation_generation
        || received.suffix != expected.suffix
    {
        return Err(Status::invalid_argument(
            "SnapshotReceived does not match ReceiveSnapshot",
        ));
    }
    Ok(received)
}

fn snapshot_suffix(
    value: pb::SnapshotSuffixCoverage,
) -> Result<domain::SnapshotSuffixCoverage, Status> {
    let after = position(required(value.after, "suffix start")?)?;
    let through = position(required(value.through, "suffix end")?)?;
    if through.sequence() <= after.sequence() {
        return Err(Status::invalid_argument(
            "empty or reversed snapshot suffix",
        ));
    }
    Ok(domain::SnapshotSuffixCoverage { after, through })
}

fn snapshot_suffix_to_pb(value: domain::SnapshotSuffixCoverage) -> pb::SnapshotSuffixCoverage {
    pb::SnapshotSuffixCoverage {
        after: Some(position_to_pb(value.after)),
        through: Some(position_to_pb(value.through)),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, ensure};

    use super::*;

    fn receipt() -> Result<domain::SnapshotReceivedRequest> {
        let subscriber = domain::FederationNodeId::from_bytes([1; 48]);
        Ok(domain::SnapshotReceivedRequest {
            authenticated_subscriber: subscriber,
            subscription: domain::SubscriptionRef {
                subscriber,
                id: domain::SubscriptionId::from_bytes([2; 16]),
            },
            manifest_digest: domain::Digest::from_bytes([3; 48]),
            publication_digest: domain::Digest::from_bytes([4; 48]),
            position: domain::Position::new(7, domain::Digest::from_bytes([5; 48]))?,
            install_id: domain::SnapshotId::from_bytes([6; 16]),
            archive_digest: domain::Digest::from_bytes([7; 48]),
            federation_generation: 1,
            suffix: None,
        })
    }

    #[test]
    fn snapshot_receipt_is_node_self_and_echoes_every_offer_binding() -> Result<()> {
        let expected = receipt()?;
        let frame = receive_snapshot_to_pb(1, expected);
        ensure!(receive_snapshot(expected.authenticated_subscriber, frame.clone())? == expected);

        let mut hosted = frame.clone();
        hosted.context_id = 1;
        ensure!(receive_snapshot(expected.authenticated_subscriber, hosted).is_err());
        let mut stale = frame.clone();
        stale.federation_generation = 0;
        ensure!(receive_snapshot(expected.authenticated_subscriber, stale).is_err());
        let wrong_peer = domain::FederationNodeId::from_bytes([9; 48]);
        ensure!(receive_snapshot(wrong_peer, frame).is_err());

        let received = snapshot_received_to_pb(1, expected.into());
        ensure!(snapshot_received(received.clone(), &expected)? == expected.into());

        let mut altered = received.clone();
        altered.manifest_digest[0] ^= 1;
        ensure!(snapshot_received(altered, &expected).is_err());
        let mut altered = received.clone();
        altered.publication_digest[0] ^= 1;
        ensure!(snapshot_received(altered, &expected).is_err());
        let mut altered = received.clone();
        altered.install_id[0] ^= 1;
        ensure!(snapshot_received(altered, &expected).is_err());
        let mut altered = received;
        altered.archive_digest[0] ^= 1;
        ensure!(snapshot_received(altered, &expected).is_err());
        Ok(())
    }

    #[test]
    fn suffix_receipt_echoes_exact_generation_and_contiguous_bounds() -> Result<()> {
        let mut expected = receipt()?;
        expected.suffix = Some(domain::SnapshotSuffixCoverage {
            after: expected.position,
            through: domain::Position::new(8, domain::Digest::from_bytes([8; 48]))?,
        });
        let frame = receive_snapshot_to_pb(1, expected);
        ensure!(receive_snapshot(expected.authenticated_subscriber, frame.clone())? == expected);
        let mut reversed = frame;
        reversed
            .suffix
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("suffix missing"))?
            .through = Some(position_to_pb(expected.position));
        ensure!(receive_snapshot(expected.authenticated_subscriber, reversed).is_err());
        let reply = snapshot_received_to_pb(1, expected.into());
        ensure!(snapshot_received(reply.clone(), &expected)? == expected.into());
        let mut stale = reply.clone();
        stale.federation_generation += 1;
        ensure!(snapshot_received(stale, &expected).is_err());
        let mut missing = reply;
        missing.suffix = None;
        ensure!(snapshot_received(missing, &expected).is_err());
        Ok(())
    }
}
