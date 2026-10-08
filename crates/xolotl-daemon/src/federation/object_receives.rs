//! Stock receiver for exact, node-subject object grants. Download completion
//! is a Verified receipt only; no application reference is implicitly bound.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::sync::Semaphore;
use xolotl_federation::{
    Digest, FederationNodeId, FederationObjectReceiver, FederationSubject, MAX_OBJECT_CHUNK_BYTES,
    ObjectGrantId, ObjectReceivePhase, ObjectReceiveSpec,
};
use xolotl_federation_grpc::{
    FederationGrpcObjectSource, FederationGrpcSubscriberClient, FederationLocalCredentials,
    FederationPeerPolicy,
    config::{FederationGrpcConfig, PeerDialConfig},
};
use xolotl_kernel::host::{BlockingSpawner, blocking::dispatch};
use xolotl_state::host::object::ObjectStore;
use xolotl_storage_redb::RedbFederationStore;
use xolotl_types::BlobRef;

use crate::config::FederationObjectReceiveConfig;

use super::{PeerDialPlan, decode_hex};

const MAX_STOCK_OBJECT_RECEIVES: usize = 64;
const MAX_STOCK_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECEIVE_JOBS: usize = 2;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FRAME_OVERHEAD: usize = 4096;

#[derive(Clone)]
pub(super) struct PreparedObjectReceive {
    spec: ObjectReceiveSpec,
    route: PeerDialConfig,
    max_chunk_bytes: usize,
}

pub(super) fn parse(
    config: &[FederationObjectReceiveConfig],
    local: FederationNodeId,
    dials: &[PeerDialPlan],
    grpc: FederationGrpcConfig,
) -> Result<Vec<PreparedObjectReceive>> {
    ensure!(
        config.len() <= MAX_STOCK_OBJECT_RECEIVES,
        "too many stock federation object receives"
    );
    let frame_space = grpc.max_frame_bytes.saturating_sub(FRAME_OVERHEAD);
    let max_chunk = MAX_OBJECT_CHUNK_BYTES
        .min(grpc.max_batch_bytes)
        .min(frame_space);
    let mut plans = Vec::with_capacity(config.len());
    for item in config {
        ensure!(
            item.size <= MAX_STOCK_OBJECT_BYTES,
            "stock federation object receive exceeds 64 MiB"
        );
        ensure!(
            (1..=max_chunk).contains(&item.max_chunk_bytes),
            "object receive chunk exceeds the negotiated frame or 512 KiB"
        );
        let provider =
            FederationNodeId::from_bytes(decode_hex::<48>(&item.provider_node, "object provider")?);
        let route = dials
            .iter()
            .find(|dial| dial.route.expected_peer == provider)
            .map(|dial| dial.route.clone())
            .context("object receive requires an enabled peer with an outbound TLS route")?;
        let spec = ObjectReceiveSpec {
            provider,
            subject: FederationSubject::Node(local),
            grant: ObjectGrantId::new(item.grant_id)?,
            grant_revision: item.grant_revision,
            blob: BlobRef {
                hash: item.hash.clone(),
                size: item.size,
                mime: item.mime.clone(),
            },
            owner: Digest::from_bytes(decode_hex::<48>(
                &item.owner_digest,
                "object receive owner digest",
            )?),
        };
        spec.validate(local)?;
        ensure!(
            plans
                .iter()
                .all(|plan: &PreparedObjectReceive| plan.spec != spec),
            "duplicate stock federation object receive"
        );
        plans.push(PreparedObjectReceive {
            spec,
            route,
            max_chunk_bytes: item.max_chunk_bytes,
        });
    }
    Ok(plans)
}

pub(super) async fn supervise_all(
    plans: Vec<PreparedObjectReceive>,
    store: RedbFederationStore,
    objects: ObjectStore,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    runtime: xolotl_federation_grpc::FederationGrpcRuntime,
) {
    if plans.is_empty() {
        std::future::pending::<()>().await;
    }
    let context = Arc::new(ReceiveContext {
        store,
        objects,
        local,
        policy,
        blocking: runtime.blocking_spawner(),
        runtime,
        slots: Arc::new(Semaphore::new(MAX_RECEIVE_JOBS)),
    });
    futures_util::future::join_all(
        plans
            .into_iter()
            .map(|plan| supervise_one(plan, Arc::clone(&context))),
    )
    .await;
    std::future::pending::<()>().await;
}

struct ReceiveContext {
    store: RedbFederationStore,
    objects: ObjectStore,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    runtime: xolotl_federation_grpc::FederationGrpcRuntime,
    blocking: Arc<dyn BlockingSpawner>,
    slots: Arc<Semaphore>,
}

async fn supervise_one(plan: PreparedObjectReceive, context: Arc<ReceiveContext>) {
    loop {
        match receive_once(&plan, &context).await {
            Ok(()) => return,
            Err(error) => {
                tracing::warn!(provider = ?plan.spec.provider, blob = %plan.spec.blob.hash, %error, "federation object receive deferred");
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}

async fn receive_once(plan: &PreparedObjectReceive, context: &ReceiveContext) -> Result<()> {
    let permit = Arc::clone(&context.slots).acquire_owned().await?;
    let client = FederationGrpcSubscriberClient::connect(
        plan.route.clone(),
        Arc::clone(&context.local),
        Arc::clone(&context.policy),
        context.runtime.clone(),
    )
    .await
    .context("connect object provider")?;
    let store = context.store.with_decision(client.decision()?)?;
    let source = FederationGrpcObjectSource::new(client, 0, plan.spec.clone())?;
    let receiver = FederationObjectReceiver::new(Arc::new(store), plan.max_chunk_bytes)?;
    let runtime = tokio::runtime::Handle::current();
    let spec = plan.spec.clone();
    let objects = context.objects.clone();
    // The receiver's redb ledger methods are synchronous. The accepted host
    // blocking job owns the entire fetch future, so those calls never occupy
    // an I/O worker. The host drains this job on graceful shutdown.
    let task = dispatch(context.blocking.as_ref(), move || {
        let _permit = permit;
        runtime.block_on(async move {
            let view =
                tokio::time::timeout(TRANSFER_TIMEOUT, receiver.fetch(&source, &objects, spec))
                    .await
                    .context("object receive timed out")??;
            Ok::<_, anyhow::Error>(view)
        })
    })?;
    let view = task.await??;
    ensure!(
        matches!(
            view.phase,
            ObjectReceivePhase::Verified | ObjectReceivePhase::Bound
        ),
        "object receiver did not commit verification"
    );
    tracing::info!(provider = ?view.spec.provider, blob = %view.spec.blob.hash, transfer = ?view.transfer, "federation object verified");
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        config::{
            FederationCallSubjectConfig, FederationObjectGrantConfig, FederationPeerDialConfig,
        },
        federation::{
            prepare, start_with_objects,
            tests::{
                CA_CERT, configured_publisher, hex_bytes, online_digest_hex, private_file,
                test_boot, wall_ms,
            },
        },
    };
    use anyhow::ensure;
    use xolotl_federation::{FederationObjectReadStore as _, FederationObjectReceiveStore as _};
    use xolotl_state::object::{ObjectRead as _, ObjectWrite as _, UploadOptions};
    use xolotl_types::TaintSet;

    #[tokio::test]
    async fn stock_receiver_verifies_exact_object_over_tls_without_binding_application_ref()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let publisher_dir = directory.path().join("publisher");
        let receiver_dir = directory.path().join("receiver");
        std::fs::create_dir(&publisher_dir)?;
        std::fs::create_dir(&receiver_dir)?;
        let mut publisher = configured_publisher(&publisher_dir)?;
        let mut receiver = configured_publisher(&receiver_dir)?;
        let publisher_node = prepare(&publisher)?
            .context("publisher disabled")?
            .node_id();
        let receiver_node = prepare(&receiver)?.context("receiver disabled")?.node_id();
        for config in [&mut publisher, &mut receiver] {
            config.federation.streams.clear();
            config.federation.state_history_publications.clear();
        }
        publisher.federation.peers[0].node_id = hex_bytes(receiver_node.as_bytes());
        publisher.federation.peers[0].allowed_authorization_digests =
            vec![online_digest_hex(&receiver)?];
        receiver.federation.peers[0].node_id = hex_bytes(publisher_node.as_bytes());
        receiver.federation.peers[0].allowed_authorization_digests =
            vec![online_digest_hex(&publisher)?];
        receiver.server.federation_grpc_addr = None;

        let bytes = b"object received and verified across nodes";
        let publisher_files =
            xolotl_storage_fs::FileObjectStore::open(publisher_dir.join("objects"))?;
        let upload = publisher_files
            .begin_upload(UploadOptions {
                expected_size: Some(bytes.len() as u64),
                mime: Some("application/octet-stream".into()),
                ..UploadOptions::default()
            })
            .await?;
        ensure!(
            publisher_files
                .write_chunk(&upload, 0, bytes)
                .await?
                .bytes_written
                == bytes.len()
        );
        let blob = publisher_files
            .commit_upload(&upload, &TaintSet::pristine())
            .await?
            .blob;
        publisher.federation.object_grants = Some(vec![FederationObjectGrantConfig {
            presenter: hex_bytes(receiver_node.as_bytes()),
            subject: FederationCallSubjectConfig::Node,
            hash: blob.hash.clone(),
            size: blob.size,
            mime: blob.mime.clone(),
            range_start: 0,
            range_end: blob.size,
            expires_at_ms: wall_ms()? + 120_000,
            max_total_bytes: 4 * blob.size,
            max_chunk_bytes: 8,
        }]);
        let publisher_db = xolotl_storage_redb::RedbStore::open(publisher_dir.join("object.redb"))?;
        let publisher_store = publisher_db.federation_store(publisher_node)?;
        let publisher_runtime = start_with_objects(
            prepare(&publisher)?.context("publisher disabled")?,
            publisher_store.clone(),
            None,
            test_boot(publisher_db.state_backend().into_backend()),
            publisher_files.into_object_store(),
        )
        .await?;
        let address = publisher_runtime
            .address
            .context("publisher did not listen")?;
        let grant = publisher_store
            .list_object_grants()?
            .into_iter()
            .next()
            .context("object grant missing")?;
        receiver.federation.peers[0].dial = Some(FederationPeerDialConfig {
            uri: format!("http://{address}"),
            server_name: "localhost".into(),
            trust_root_path: private_file(&receiver_dir.join("ca.pem"), CA_CERT)?,
        });
        receiver
            .federation
            .object_receives
            .push(FederationObjectReceiveConfig {
                provider_node: hex_bytes(publisher_node.as_bytes()),
                grant_id: grant.id.get(),
                grant_revision: grant.revision,
                hash: blob.hash.clone(),
                size: blob.size,
                mime: blob.mime.clone(),
                owner_digest: hex_bytes(&[0x77; 48]),
                max_chunk_bytes: 8,
            });
        let receiver_db = xolotl_storage_redb::RedbStore::open(receiver_dir.join("object.redb"))?;
        let receiver_store = receiver_db.federation_store(receiver_node)?;
        let receiver_files =
            xolotl_storage_fs::FileObjectStore::open(receiver_dir.join("objects"))?;
        let receiver_runtime = start_with_objects(
            prepare(&receiver)?.context("receiver disabled")?,
            receiver_store.clone(),
            None,
            test_boot(receiver_db.state_backend().into_backend()),
            receiver_files.clone().into_object_store(),
        )
        .await?;
        let spec = ObjectReceiveSpec {
            provider: publisher_node,
            subject: FederationSubject::Node(receiver_node),
            grant: grant.id,
            grant_revision: grant.revision,
            blob: blob.clone(),
            owner: Digest::from_bytes([0x77; 48]),
        };
        let first = receiver_store.begin_receive(spec.clone())?;
        let verified = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let view = receiver_store
                    .object_receive(first.transfer)?
                    .context("receive ledger row disappeared")?;
                if view.phase == ObjectReceivePhase::Verified {
                    return Ok::<_, anyhow::Error>(view);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        ensure!(verified.spec == spec && verified.revision == 2);
        let mut downloaded = vec![0; bytes.len()];
        let read = receiver_files.read_chunk(&blob, 0, &mut downloaded).await?;
        ensure!(read.bytes_read == bytes.len() && downloaded == bytes);
        ensure!(receiver_store.begin_receive(spec)?.transfer == first.transfer);
        ensure!(
            receiver_store
                .object_receive(first.transfer)?
                .context("receive missing")?
                .phase
                == ObjectReceivePhase::Verified
        );
        let prepared = prepare(&receiver)?.context("receiver disabled")?;
        let plan = prepared.object_receives[0].clone();
        let policy = Arc::new(crate::federation::PersistedPeerPolicy {
            store: receiver_store.clone(),
            local: receiver_node,
            issuer_rules: prepared.policy.issuer_rules.clone(),
        });
        let runtime = receiver_runtime.runtime.clone();
        let context = ReceiveContext {
            store: receiver_store.clone(),
            objects: receiver_files.clone().into_object_store(),
            local: prepared.local,
            policy,
            blocking: runtime.blocking_spawner(),
            runtime,
            slots: Arc::new(Semaphore::new(MAX_RECEIVE_JOBS)),
        };
        receiver_runtime.runtime.shutdown().await;
        for _ in 0..2 {
            let rejected = receive_once(&plan, &context)
                .await
                .err()
                .context("receive attempt escaped closed host transport runtime")?;
            ensure!(
                rejected
                    .downcast_ref::<tonic::Status>()
                    .is_some_and(|status| status.code() == tonic::Code::Unavailable)
            );
            ensure!(context.slots.available_permits() == MAX_RECEIVE_JOBS);
        }
        ensure!(receiver_store.object_receive(first.transfer)? == Some(verified));
        receiver_runtime.task.abort();
        drop(receiver_runtime.task.await);
        publisher_runtime.task.abort();
        drop(publisher_runtime.task.await);
        Ok(())
    }
}
