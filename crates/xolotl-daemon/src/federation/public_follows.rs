//! Stock receiver for exact public streams. It keeps an independent rolling
//! inbox and never creates private peer or subscription rows on the publisher.

use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tonic::Status;
use xolotl_federation::{
    FederationNodeId, PeerAdmission, PublicReadRequest, StreamId, StreamRef,
    VerifiedFederationPeerProof,
};
use xolotl_federation_grpc::{
    FederationGrpcSubscriberClient, FederationLocalCredentials, FederationPeerPolicy,
    config::PeerDialConfig,
};
use xolotl_storage_redb::{
    MAX_PUBLIC_FOLLOW_INBOX_BYTES, MAX_PUBLIC_FOLLOW_INBOX_RECORDS, RedbFederationStore,
    RedbPublicFollowerStore,
};

use crate::{
    config::{FederationPeerConfig, FederationPublicFollowConfig, FederationPublisherGrpcConfig},
    transport::GatewayListenerTlsMaterial,
};

use super::{decode_hex, storage_workers::StorageWorkers};

const MAX_FOLLOWS: usize = 64;

#[derive(Clone)]
pub(super) struct PreparedPublicFollow {
    stream: StreamRef,
    route: PeerDialConfig,
    admission: PeerAdmission,
    max_inbox_records: usize,
    max_inbox_bytes: usize,
}

pub(super) fn parse(
    config: &[FederationPublicFollowConfig],
    local: FederationNodeId,
    tls: &GatewayListenerTlsMaterial,
    peers: &[FederationPeerConfig],
    grpc: &FederationPublisherGrpcConfig,
) -> Result<Vec<PreparedPublicFollow>> {
    ensure!(
        config.len() <= MAX_FOLLOWS,
        "too many public federation follows"
    );
    let mut seen = HashSet::new();
    let mut plans = Vec::with_capacity(config.len());
    for item in config {
        let publisher = FederationNodeId::from_bytes(decode_hex::<48>(
            &item.publisher_node,
            "public follow publisher_node",
        )?);
        ensure!(
            publisher != local,
            "public follow cannot target the local node"
        );
        ensure!(
            !peers
                .iter()
                .any(|peer| peer.node_id.eq_ignore_ascii_case(&item.publisher_node)),
            "public follow publisher must not also have a private peer policy"
        );
        let stream = StreamRef {
            publisher,
            id: StreamId::from_bytes(decode_hex::<16>(
                &item.stream_id,
                "public follow stream_id",
            )?),
        };
        ensure!(seen.insert(stream), "duplicate public follow stream");
        let admission = PeerAdmission {
            minimum_online_generation: item.minimum_online_generation,
            allowed_authorization_digests: item
                .allowed_authorization_digests
                .iter()
                .map(|digest| decode_hex::<48>(digest, "public follow online authorization digest"))
                .collect::<Result<Vec<_>>>()?,
        };
        admission.validate()?;
        ensure!(
            !admission.allowed_authorization_digests.is_empty(),
            "public follow needs a pinned online authorization digest"
        );
        ensure!(
            (1..=MAX_PUBLIC_FOLLOW_INBOX_RECORDS).contains(&item.max_inbox_records)
                && (512 * 1024..=MAX_PUBLIC_FOLLOW_INBOX_BYTES).contains(&item.max_inbox_bytes)
                && item.max_inbox_bytes >= grpc.max_batch_bytes,
            "public follow inbox bounds must fit one federation batch"
        );
        let uri = tonic::transport::Endpoint::from_shared(item.dial.uri.clone())?;
        let uri = uri.uri();
        ensure!(
            uri.scheme_str() == Some("http")
                && uri.host().is_some()
                && uri.port_u16().is_some()
                && uri.path() == "/"
                && uri.query().is_none(),
            "public follow dial URI must be an http authority with an explicit port"
        );
        rustls::pki_types::ServerName::try_from(item.dial.server_name.as_str())
            .context("invalid public follow TLS server_name")?;
        let root = std::path::Path::new(&item.dial.trust_root_path);
        ensure!(
            root.is_absolute() && root.is_file(),
            "public follow trust_root_path must be an absolute regular file"
        );
        let peer_trust_root_pem = std::fs::read(root).with_context(|| {
            format!(
                "read public follow trust root '{}'",
                item.dial.trust_root_path
            )
        })?;
        ensure!(
            !peer_trust_root_pem.is_empty() && peer_trust_root_pem.len() <= 1024 * 1024,
            "public follow trust root must be 1 MiB or less"
        );
        plans.push(PreparedPublicFollow {
            stream,
            route: PeerDialConfig {
                uri: item.dial.uri.clone(),
                expected_peer: publisher,
                server_name: item.dial.server_name.clone(),
                peer_trust_root_pem,
                client_certificate_pem: tls.certificate_chain_pem.clone(),
                client_key_pem: tls.private_key_pem.to_vec(),
            },
            admission,
            max_inbox_records: item.max_inbox_records,
            max_inbox_bytes: item.max_inbox_bytes,
        });
    }
    Ok(plans)
}

struct PublicFollowPolicy {
    store: RedbFederationStore,
    publisher: FederationNodeId,
    admission: PeerAdmission,
}

impl FederationPeerPolicy for PublicFollowPolicy {
    fn decision_clock(
        &self,
    ) -> std::result::Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
        Ok(Arc::new(xolotl_federation::SystemObjectClock))
    }

    fn receiver_decision(
        &self,
        proof: VerifiedFederationPeerProof,
    ) -> std::result::Result<xolotl_federation::FederationDecision, Status> {
        if proof.node_id() != self.publisher {
            return Err(Status::permission_denied("unexpected follow publisher"));
        }
        xolotl_federation::FederationDecision::new(
            proof,
            xolotl_federation::FederationAdmission::Unconfigured,
            self.decision_clock()?,
        )
        .with_unconfigured_policy(self.admission.clone())
        .map_err(|error| Status::permission_denied(error.to_string()))
    }

    fn current_time_ms(&self) -> Result<u64, Status> {
        self.store
            .sample_time_ms(|| {
                xolotl_federation::FederationObjectClock::now_ms(
                    &xolotl_federation::SystemObjectClock,
                )
            })
            .map_err(|_error| Status::failed_precondition("federation trusted clock rejected"))
    }

    fn check_current_peer(
        &self,
        proof: VerifiedFederationPeerProof,
        now_ms: u64,
    ) -> Result<(), Status> {
        if proof.node_id() != self.publisher
            || now_ms >= proof.expires_ms()
            || proof.online_generation() < self.admission.minimum_online_generation
            || !self
                .admission
                .allowed_authorization_digests
                .contains(&proof.authorization_digest())
        {
            return Err(Status::permission_denied(
                "public follow publisher admission rejected",
            ));
        }
        // A configured row, including a disabled tombstone, may never fall
        // through to this independent public-only trust path.
        match self.store.peer_authority(self.publisher) {
            Ok(None) => Ok(()),
            _ => Err(Status::permission_denied(
                "configured peer cannot use public follow admission",
            )),
        }
    }
}

pub(super) fn start(
    plans: Vec<PreparedPublicFollow>,
    federation_store: RedbFederationStore,
    follow_store: RedbPublicFollowerStore,
    local: Arc<FederationLocalCredentials>,
    runtime: xolotl_federation_grpc::FederationGrpcRuntime,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let workers = StorageWorkers::new(
        runtime.config().max_blocking_verifications,
        runtime.blocking_spawner(),
    )?;
    Ok(plans
        .into_iter()
        .map(|plan| {
            let federation_store = federation_store.clone();
            let follow_store = follow_store.clone();
            let local = Arc::clone(&local);
            let runtime = runtime.clone();
            let workers = workers.clone();
            tokio::spawn(async move {
                loop {
                    let policy: Arc<dyn FederationPeerPolicy> = Arc::new(PublicFollowPolicy {
                        store: federation_store.clone(),
                        publisher: plan.stream.publisher,
                        admission: plan.admission.clone(),
                    });
                    let result = run(
                        &plan,
                        &follow_store,
                        &workers,
                        Arc::clone(&local),
                        policy,
                        runtime.clone(),
                    )
                    .await;
                    if let Err(error) = result {
                        tracing::warn!(stream = ?plan.stream, error = %format_args!("{error:#}"), "public federation follow interrupted");
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            })
        })
        .collect())
}

async fn run(
    plan: &PreparedPublicFollow,
    store: &RedbPublicFollowerStore,
    workers: &StorageWorkers,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    runtime: xolotl_federation_grpc::FederationGrpcRuntime,
) -> Result<()> {
    let grpc = runtime.config();
    let client =
        FederationGrpcSubscriberClient::connect(plan.route.clone(), local, policy, runtime)
            .await
            .context("connect public federation publisher")?;
    let remote_store = store.with_decision(client.decision()?)?;
    let store = &remote_store;
    tracing::info!(stream = ?plan.stream, "public federation follower connected");
    loop {
        let remote = client
            .inspect_public(plan.stream)
            .await
            .context("inspect public stream")?;
        let store_copy = store.clone();
        let observed = remote.clone();
        let view = workers
            .run(move || store_copy.observe(&observed))
            .await
            .context("observe public policy or history gap")?;
        let page = client
            .read_public(PublicReadRequest {
                authenticated_reader: store.local_node(),
                stream: plan.stream,
                expected_policy_revision: view.policy_revision,
                after: view.cursor,
                max_records: grpc.max_batch_records.min(remote.max_read_records),
                max_bytes: grpc.max_batch_bytes.min(remote.max_read_bytes),
            })
            .await
            .context("read public stream")?;
        let advanced = !page.records.is_empty();
        let store_copy = store.clone();
        let stream = plan.stream;
        let max_records = plan.max_inbox_records;
        let max_bytes = plan.max_inbox_bytes;
        workers
            .run(move || store_copy.accept_page(stream, &page, max_records, max_bytes))
            .await
            .context("commit public follower inbox or history gap")?;
        if !advanced {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
