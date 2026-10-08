//! Stock invitation-only Hosted Sync receiver. Its credentials and durable
//! inbox are independent of managed peer subscriptions and public follows.

use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tonic::Status;
use xolotl_federation::{
    FederationNodeId, HistoryStart, HostedSubject, InspectSubscriptionRequest, InvitationId,
    InvitationSecret, OpenRequest, PeerAdmission, ReadRequest, RequestId, StreamId, StreamRef,
    SubjectAssertion, SubjectHolderKey, SubjectIssuer, SubjectIssuerId, SubjectPurpose,
    SubscriptionId, SubscriptionRef, VerifiedFederationPeerProof,
};
use xolotl_federation_grpc::{
    FederationGrpcSubscriberClient, FederationHostedSubjectCredentials, FederationLocalCredentials,
    FederationPeerPolicy, config::PeerDialConfig,
};
use xolotl_storage_redb::{
    GuestFollowSpec, MAX_GUEST_FOLLOW_INBOX_BYTES, MAX_GUEST_FOLLOW_INBOX_RECORDS,
    RedbFederationStore, RedbGuestFollowerStore,
};

use crate::{
    config::{FederationGuestFollowConfig, FederationPeerConfig, FederationPublisherGrpcConfig},
    transport::GatewayListenerTlsMaterial,
};

use super::{decode_hex, storage_workers::StorageWorkers};

const MAX_FOLLOWS: usize = 64;
const SUBJECT_CONTEXT: u32 = 1;

#[derive(Clone)]
pub(super) struct PreparedGuestFollow {
    pub(super) spec: GuestFollowSpec,
    route: PeerDialConfig,
    admission: PeerAdmission,
    credentials: Arc<FederationHostedSubjectCredentials>,
    secret: Option<InvitationSecret>,
}

fn stable_id(domain: &str, spec: &GuestFollowSpec, generation: u64) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(spec.subscription.subscriber.as_bytes());
    hasher.update(spec.stream.publisher.as_bytes());
    hasher.update(spec.stream.id.as_bytes());
    hasher.update(&spec.invitation.as_bytes());
    hasher.update(&spec.invitation_revision.to_be_bytes());
    hasher.update(&spec.subject.issuer.as_bytes());
    for part in [&spec.subject.namespace, &spec.subject.subject] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(&generation.to_be_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

pub(super) fn parse(
    config: &[FederationGuestFollowConfig],
    local: FederationNodeId,
    tls: &GatewayListenerTlsMaterial,
    peers: &[FederationPeerConfig],
    grpc: &FederationPublisherGrpcConfig,
) -> Result<Vec<PreparedGuestFollow>> {
    ensure!(
        config.len() <= MAX_FOLLOWS,
        "too many Guest federation follows"
    );
    let mut seen = HashSet::new();
    let mut plans = Vec::with_capacity(config.len());
    for item in config {
        let publisher = FederationNodeId::from_bytes(decode_hex::<48>(
            &item.publisher_node,
            "Guest follow publisher_node",
        )?);
        ensure!(
            publisher != local,
            "Guest follow cannot target the local node"
        );
        ensure!(
            !peers
                .iter()
                .any(|peer| peer.node_id.eq_ignore_ascii_case(&item.publisher_node)),
            "Guest follow publisher must not also have a private peer policy"
        );
        let stream = StreamRef {
            publisher,
            id: StreamId::from_bytes(decode_hex::<16>(&item.stream_id, "Guest follow stream_id")?),
        };
        ensure!(seen.insert(stream), "duplicate Guest follow stream");
        ensure!(
            item.generation > 0 && item.invitation_revision > 0,
            "Guest follow generation and invitation_revision must be positive"
        );
        let invitation = InvitationId::from_bytes(decode_hex::<16>(
            &item.invitation_id,
            "Guest follow invitation_id",
        )?);
        ensure!(
            invitation.as_bytes() != [0; 16],
            "Guest invitation_id is zero"
        );
        let subject = HostedSubject {
            issuer: SubjectIssuerId::from_bytes(decode_hex::<48>(
                &item.issuer,
                "Guest follow issuer",
            )?),
            namespace: item.namespace.clone(),
            subject: item.subject.clone(),
        };
        let mut spec = GuestFollowSpec {
            stream,
            subscription: SubscriptionRef {
                subscriber: local,
                id: SubscriptionId::from_bytes([1; 16]),
            },
            invitation,
            invitation_revision: item.invitation_revision,
            redeem_request: RequestId::from_bytes([1; 16]),
            open_request: RequestId::from_bytes([2; 16]),
            subject: subject.clone(),
            max_inbox_records: item.max_inbox_records,
            max_inbox_bytes: item.max_inbox_bytes,
        };
        spec.subscription.id = SubscriptionId::from_bytes(stable_id(
            "xolotl.federation.stock-guest-subscription.v1",
            &spec,
            item.generation,
        ));
        spec.redeem_request = RequestId::from_bytes(stable_id(
            "xolotl.federation.stock-guest-redeem.v1",
            &spec,
            item.generation,
        ));
        spec.open_request = RequestId::from_bytes(stable_id(
            "xolotl.federation.stock-guest-open.v1",
            &spec,
            item.generation,
        ));
        ensure!(
            (1..=MAX_GUEST_FOLLOW_INBOX_RECORDS).contains(&item.max_inbox_records)
                && (512 * 1024..=MAX_GUEST_FOLLOW_INBOX_BYTES).contains(&item.max_inbox_bytes)
                && item.max_inbox_bytes >= grpc.max_batch_bytes,
            "Guest follow inbox bounds must fit one federation batch"
        );
        let admission = PeerAdmission {
            minimum_online_generation: item.minimum_online_generation,
            allowed_authorization_digests: item
                .allowed_authorization_digests
                .iter()
                .map(|digest| decode_hex::<48>(digest, "Guest follow authorization digest"))
                .collect::<Result<Vec<_>>>()?,
        };
        admission.validate()?;
        ensure!(
            !admission.allowed_authorization_digests.is_empty(),
            "Guest follow needs a pinned online authorization digest"
        );
        let issuer_bytes = crate::config::read_private_bounded_file(
            &item.issuer_descriptor_path,
            "Guest issuer descriptor",
            SubjectIssuer::ENCODED_LEN as u64,
        )?;
        let issuer =
            SubjectIssuer::decode(&issuer_bytes).context("decode Guest issuer descriptor")?;
        let assertion_bytes = crate::config::read_private_bounded_file(
            &item.assertion_path,
            "Guest assertion",
            4096,
        )?;
        let assertion =
            SubjectAssertion::decode(&assertion_bytes).context("decode Guest assertion")?;
        ensure!(
            issuer.id() == subject.issuer
                && assertion.subject() == &subject
                && assertion.audience() == publisher
                && assertion.presenter() == local
                && assertion.purpose() == SubjectPurpose::Sync,
            "Guest assertion differs from the pinned subject, publisher, presenter or Sync purpose"
        );
        let signature = crate::config::read_private_bounded_file(
            &item.issuer_signature_path,
            "Guest issuer signature",
            xolotl_federation::FederationRoot::SIGNATURE_LEN as u64,
        )?;
        issuer
            .verify_assertion(&assertion, &signature)
            .context("verify Guest issuer signature")?;
        let holder_bytes = crate::config::read_private_bounded_file(
            &item.holder_key_path,
            "Guest holder key",
            64 * 1024,
        )?;
        let holder = Arc::new(
            SubjectHolderKey::from_pkcs8(&holder_bytes).context("decode Guest holder key")?,
        );
        let credentials = Arc::new(
            FederationHostedSubjectCredentials::new(&issuer, assertion, signature.to_vec(), holder)
                .context("assemble Guest Hosted credentials")?,
        );
        let secret = item
            .invitation_secret_path
            .as_ref()
            .map(|path| -> Result<InvitationSecret> {
                let raw =
                    crate::config::read_private_bounded_file(path, "Guest invitation secret", 32)?;
                let bytes = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_error| {
                    anyhow::anyhow!("Guest invitation secret must be 32 bytes")
                })?;
                Ok(InvitationSecret::from_bytes(bytes))
            })
            .transpose()?;
        let uri = tonic::transport::Endpoint::from_shared(item.dial.uri.clone())?;
        let uri = uri.uri();
        ensure!(
            uri.scheme_str() == Some("http")
                && uri.host().is_some()
                && uri.port_u16().is_some()
                && uri.path() == "/"
                && uri.query().is_none(),
            "Guest follow dial URI must be an http authority with an explicit port"
        );
        rustls::pki_types::ServerName::try_from(item.dial.server_name.as_str())
            .context("invalid Guest follow TLS server_name")?;
        let trust_root = std::path::Path::new(&item.dial.trust_root_path);
        ensure!(
            trust_root.is_absolute() && trust_root.is_file(),
            "Guest follow trust_root_path must be an absolute regular file"
        );
        let peer_trust_root_pem = std::fs::read(trust_root).with_context(|| {
            format!(
                "read Guest follow trust root '{}'",
                item.dial.trust_root_path
            )
        })?;
        ensure!(
            !peer_trust_root_pem.is_empty() && peer_trust_root_pem.len() <= 1024 * 1024,
            "Guest follow trust root must be 1 MiB or less"
        );
        plans.push(PreparedGuestFollow {
            spec,
            route: PeerDialConfig {
                uri: item.dial.uri.clone(),
                expected_peer: publisher,
                server_name: item.dial.server_name.clone(),
                peer_trust_root_pem,
                client_certificate_pem: tls.certificate_chain_pem.clone(),
                client_key_pem: tls.private_key_pem.to_vec(),
            },
            admission,
            credentials,
            secret,
        });
    }
    Ok(plans)
}

struct GuestFollowPolicy {
    store: RedbFederationStore,
    publisher: FederationNodeId,
    admission: PeerAdmission,
}

impl FederationPeerPolicy for GuestFollowPolicy {
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
                "Guest follow publisher admission rejected",
            ));
        }
        match self.store.peer_authority(self.publisher) {
            Ok(None) => Ok(()),
            _ => Err(Status::permission_denied(
                "configured peer cannot use Guest follow admission",
            )),
        }
    }
}

pub(super) fn start(
    plans: Vec<PreparedGuestFollow>,
    federation_store: RedbFederationStore,
    guest_store: RedbGuestFollowerStore,
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
            let guest_store = guest_store.clone();
            let local = Arc::clone(&local);
            let runtime = runtime.clone();
            let workers = workers.clone();
            tokio::spawn(async move {
                loop {
                    let policy: Arc<dyn FederationPeerPolicy> = Arc::new(GuestFollowPolicy {
                        store: federation_store.clone(),
                        publisher: plan.spec.stream.publisher,
                        admission: plan.admission.clone(),
                    });
                    if let Err(error) = run(
                        &plan,
                        &guest_store,
                        &workers,
                        Arc::clone(&local),
                        policy,
                        runtime.clone(),
                    )
                    .await
                    {
                        tracing::warn!(stream = ?plan.spec.stream, error = %format_args!("{error:#}"), "Guest federation follow interrupted");
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            })
        })
        .collect())
}

async fn run(
    plan: &PreparedGuestFollow,
    store: &RedbGuestFollowerStore,
    workers: &StorageWorkers,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    runtime: xolotl_federation_grpc::FederationGrpcRuntime,
) -> Result<()> {
    let spec = plan.spec.clone();
    let store_copy = store.clone();
    let mut view = workers
        .run(move || store_copy.prepare(&spec))
        .await
        .context("stage Guest invitation and Open IDs")?;
    let grpc = runtime.config();
    let client =
        FederationGrpcSubscriberClient::connect(plan.route.clone(), local, policy, runtime)
            .await
            .context("connect Guest publisher")?;
    let remote_store = store.with_decision(client.decision()?)?;
    let store = &remote_store;
    ensure!(
        client
            .register_subject(SUBJECT_CONTEXT, Arc::clone(&plan.credentials))
            .await
            .context("register Guest Hosted Sync subject")?
            == SUBJECT_CONTEXT,
        "Guest subject context changed during registration"
    );
    if !view.redeemed {
        let receipt = client
            .redeem_invitation_as(
                SUBJECT_CONTEXT,
                plan.spec.invitation,
                plan.spec.redeem_request,
                plan.spec.invitation_revision,
                plan.secret.clone(),
            )
            .await
            .context("redeem Guest invitation")?;
        ensure!(
            receipt.invitation == plan.spec.invitation
                && receipt.request_id == plan.spec.redeem_request
                && receipt.subject == plan.spec.subject
                && receipt.stream == plan.spec.stream
                && receipt.currently_authorized,
            "Guest invitation receipt differs from pinned stream or subject"
        );
        let spec = plan.spec.clone();
        let store_copy = store.clone();
        view = workers
            .run(move || store_copy.mark_redeemed(&spec))
            .await
            .context("commit Guest invitation redemption")?;
    }
    if view.opened.is_none() {
        let opened = client
            .open_as(
                SUBJECT_CONTEXT,
                OpenRequest {
                    authenticated_subscriber: plan.spec.subscription.subscriber,
                    request_id: plan.spec.open_request,
                    subscription: plan.spec.subscription,
                    stream: plan.spec.stream,
                    expected_control_revision: None,
                    history: HistoryStart::All,
                },
            )
            .await
            .context("open Guest subscription")?;
        let spec = plan.spec.clone();
        let store_copy = store.clone();
        view = workers
            .run(move || store_copy.install_open(&spec, &opened))
            .await
            .context("commit Guest Open result")?;
    }
    let opened = view.opened.clone().context("Guest Open was not stored")?;
    let inspection = client
        .inspect_subscription_as(
            SUBJECT_CONTEXT,
            InspectSubscriptionRequest {
                authenticated_subscriber: plan.spec.subscription.subscriber,
                subscription: plan.spec.subscription,
            },
        )
        .await
        .context("inspect Guest subscription after reconnect")?;
    ensure!(
        !inspection.closed
            && inspection.subscription == plan.spec.subscription
            && inspection.stream == plan.spec.stream
            && inspection.export == opened.export
            && inspection.subscription_revision == opened.subscription_revision
            && inspection.start == opened.start,
        "Guest subscription changed during reconnect"
    );
    if let Some(remote_ack) = inspection.acknowledged {
        ensure!(
            view.cursor.is_some_and(|local| {
                remote_ack.sequence() < local.sequence()
                    || (remote_ack.sequence() == local.sequence() && remote_ack == local)
            }),
            "Guest publisher ACK is ahead of local durable inbox"
        );
    }
    if let Some(position) = view.cursor {
        client
            .acknowledge_as(
                SUBJECT_CONTEXT,
                xolotl_federation::AcknowledgeRequest {
                    authenticated_subscriber: plan.spec.subscription.subscriber,
                    subscription: plan.spec.subscription,
                    position,
                },
            )
            .await
            .context("replay durable Guest ACK")?;
    }
    loop {
        let after = view.cursor.or(opened.start);
        let page = client
            .read_as(
                SUBJECT_CONTEXT,
                ReadRequest {
                    authenticated_subscriber: plan.spec.subscription.subscriber,
                    subscription: plan.spec.subscription,
                    after,
                    max_records: grpc.max_batch_records.min(128),
                    max_bytes: grpc.max_batch_bytes.min(plan.spec.max_inbox_bytes),
                },
                plan.spec.stream,
            )
            .await
            .context("read Guest stream")?;
        let advanced = !page.records.is_empty();
        let spec = plan.spec.clone();
        let store_copy = store.clone();
        view = workers
            .run(move || store_copy.accept_page(&spec, &page))
            .await
            .context("commit Guest inbox page")?;
        if advanced {
            let position = view.cursor.context("Guest inbox did not advance")?;
            client
                .acknowledge_as(
                    SUBJECT_CONTEXT,
                    xolotl_federation::AcknowledgeRequest {
                        authenticated_subscriber: plan.spec.subscription.subscriber,
                        subscription: plan.spec.subscription,
                        position,
                    },
                )
                .await
                .context("acknowledge durable Guest inbox")?;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
