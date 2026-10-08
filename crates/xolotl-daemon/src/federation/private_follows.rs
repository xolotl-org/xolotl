use super::{RECORD_FRAME_OVERHEAD, RemoteSubscriptionPlan, snapshot_receiver};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;
use xolotl_federation::{
    FederationService, FederationSnapshotStore as _, FederationStore as _, FederationSubject,
    HistoryStart, InspectSubscriptionRequest, OpenRequest, Position, ReadRequest,
    SnapshotArchiveAnchor, SnapshotInstallRequest, SnapshotInstallView, SnapshotReceivedRequest,
    SubscriptionRef,
};
use xolotl_federation_grpc::FederationGrpcSubscriberClient;
use xolotl_storage_redb::RedbFederationStore;

struct RemoteSubscriptionState {
    plan: RemoteSubscriptionPlan,
    progress: StockDeliveryProgress,
}

enum StockDeliveryProgress {
    Events {
        after: Option<Position>,
    },
    Archived {
        anchor: Box<SnapshotArchiveAnchor>,
        after: Position,
    },
}

impl StockDeliveryProgress {
    fn read_after(&self) -> Option<Position> {
        match self {
            Self::Events { after } => *after,
            Self::Archived { after, .. } => Some(*after),
        }
    }

    fn generation(&self) -> u64 {
        match self {
            Self::Events { .. } => 0,
            Self::Archived { anchor, .. } => anchor.federation_generation,
        }
    }

    fn ordinary_ack(&self) -> Option<Position> {
        match self {
            Self::Events { after } => *after,
            Self::Archived { .. } => None,
        }
    }

    fn archive_anchor(&self) -> Option<&SnapshotArchiveAnchor> {
        match self {
            Self::Events { .. } => None,
            Self::Archived { anchor, .. } => Some(anchor),
        }
    }

    fn advance(&mut self, accepted: Position) {
        match self {
            Self::Events { after } => *after = Some(accepted),
            Self::Archived { after, .. } => *after = accepted,
        }
    }
}

pub(super) async fn run_subscriptions(
    client: FederationGrpcSubscriberClient,
    subscriptions: &[RemoteSubscriptionPlan],
    config: xolotl_federation_grpc::config::FederationGrpcConfig,
    service: &FederationService,
    snapshot_store: &Arc<RedbFederationStore>,
    snapshot_archive: &snapshot_receiver::StockSnapshotArchive,
) -> Result<()> {
    tracing::info!(peer = ?client.peer_node(), "federation Session ready");
    let remote_snapshot_store = Arc::new(snapshot_store.with_decision(client.decision()?)?);
    let snapshot_store = &remote_snapshot_store;
    let mut states = Vec::with_capacity(subscriptions.len());
    for plan in subscriptions {
        let opened = client
            .open_and_install(
                OpenRequest {
                    authenticated_subscriber: plan.subscription.subscriber,
                    request_id: plan.request_id,
                    subscription: plan.subscription,
                    stream: plan.stream,
                    expected_control_revision: None,
                    history: HistoryStart::All,
                },
                service,
            )
            .await
            .context("open and install federation subscription")?;
        let inspection = client
            .inspect_subscription(InspectSubscriptionRequest {
                authenticated_subscriber: plan.subscription.subscriber,
                subscription: plan.subscription,
            })
            .await
            .context("inspect federation subscription after reconnect")?;
        ensure!(
            !inspection.closed
                && inspection.subscription == plan.subscription
                && inspection.stream == plan.stream
                && inspection.start == opened.start,
            "federation subscription changed during reconnect"
        );
        if let Some(pending) = snapshot_view(snapshot_store, snapshot_archive, plan.subscription)
            .await?
            .and_then(|view| view.pending)
        {
            finish_snapshot_install(
                &client,
                snapshot_store,
                snapshot_archive,
                plan,
                pending,
                config,
            )
            .await
            .context("resume pending stock snapshot installation")?;
        }
        let progress = local_receiver_progress(snapshot_store, snapshot_archive, plan).await?;
        let after = progress.read_after();
        if let Some(anchor) = progress.archive_anchor() {
            send_snapshot_receipt(&client, anchor).await?;
            if let Some(through) = after.filter(|position| *position != anchor.manifest.position) {
                send_snapshot_suffix(&client, anchor, through).await?;
            }
        }
        ensure!(
            inspection.acknowledged.is_none_or(|remote| {
                after.is_some_and(|local| {
                    remote.sequence() < local.sequence()
                        || remote.sequence() == local.sequence() && remote == local
                })
            }),
            "publisher ACK is ahead of the local durable receiver"
        );
        if let Some(position) = progress.ordinary_ack()
            && inspection.acknowledged != Some(position)
            && opened.start != Some(position)
        {
            client
                .acknowledge(xolotl_federation::AcknowledgeRequest {
                    authenticated_subscriber: plan.subscription.subscriber,
                    subscription: plan.subscription,
                    position,
                })
                .await
                .context("replay local durable receiver ACK")?;
        }
        states.push(RemoteSubscriptionState {
            plan: plan.clone(),
            progress,
        });
    }
    if states.is_empty() {
        client.closed().await;
        return Ok(());
    }
    let (read_records, read_bytes) = client.negotiated_batch_limits();
    let read_records = read_records.min(xolotl_federation::MAX_SNAPSHOT_SUFFIX_RECORDS);
    let read_bytes = read_bytes.min(xolotl_federation::MAX_SNAPSHOT_SUFFIX_BYTES);
    loop {
        let mut advanced = false;
        for state in &mut states {
            let page = match client
                .read(
                    ReadRequest {
                        authenticated_subscriber: state.plan.subscription.subscriber,
                        subscription: state.plan.subscription,
                        after: state.progress.read_after(),
                        max_records: read_records.min(128),
                        max_bytes: read_bytes,
                    },
                    state.plan.stream,
                )
                .await
            {
                Ok(page) => page,
                Err(error) if error.code() == tonic::Code::OutOfRange => {
                    let pending = begin_snapshot_install(
                        &client,
                        snapshot_store,
                        snapshot_archive,
                        &state.plan,
                    )
                    .await
                    .context("history gap requires an offered application snapshot")?;
                    let anchor = finish_snapshot_install(
                        &client,
                        snapshot_store,
                        snapshot_archive,
                        &state.plan,
                        pending,
                        config,
                    )
                    .await
                    .context("install stock snapshot after history gap")?;
                    send_snapshot_receipt(&client, &anchor)
                        .await
                        .context("confirm sealed stock snapshot with publisher")?;
                    state.progress = StockDeliveryProgress::Archived {
                        after: anchor.manifest.position,
                        anchor: Box::new(anchor),
                    };
                    advanced = true;
                    continue;
                }
                Err(error) => return Err(error).context("read federation records"),
            };
            if !page.records.is_empty() {
                let store = Arc::clone(snapshot_store);
                let subscription = state.plan.subscription;
                let publisher = state.plan.stream.publisher;
                let generation = state.progress.generation();
                let accepted = snapshot_archive
                    .blocking(move || {
                        let mut last = None;
                        for record in page.records {
                            let request = xolotl_federation::AcceptRequest {
                                authenticated_publisher: publisher,
                                subscription,
                                record,
                            };
                            last = Some(
                                if generation == 0 {
                                    store.accept(request)?
                                } else {
                                    store.accept_in_generation(generation, request)?
                                }
                                .position,
                            );
                        }
                        Ok(last)
                    })
                    .await
                    .context("commit stock receiver inbox page")?
                    .context("nonempty federation page accepted no records")?;
                state.progress.advance(accepted);
                if let Some(anchor) = state.progress.archive_anchor() {
                    send_snapshot_suffix(&client, anchor, accepted)
                        .await
                        .context("confirm durable post-archive suffix coverage")?;
                }
                if let Some(position) = state.progress.ordinary_ack() {
                    client
                        .acknowledge(xolotl_federation::AcknowledgeRequest {
                            authenticated_subscriber: state.plan.subscription.subscriber,
                            subscription: state.plan.subscription,
                            position,
                        })
                        .await
                        .context("acknowledge durable stock receiver inbox")?;
                }
                advanced = true;
            }
        }
        if !advanced {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

async fn snapshot_view(
    store: &Arc<RedbFederationStore>,
    archive: &snapshot_receiver::StockSnapshotArchive,
    subscription: SubscriptionRef,
) -> Result<Option<SnapshotInstallView>> {
    let store = Arc::clone(store);
    archive
        .blocking(move || Ok(store.snapshot_install(subscription)?))
        .await
}

async fn send_snapshot_receipt(
    client: &FederationGrpcSubscriberClient,
    anchor: &SnapshotArchiveAnchor,
) -> Result<()> {
    send_snapshot_coverage(client, anchor, None).await
}

async fn send_snapshot_suffix(
    client: &FederationGrpcSubscriberClient,
    anchor: &SnapshotArchiveAnchor,
    through: Position,
) -> Result<()> {
    send_snapshot_coverage(
        client,
        anchor,
        Some(xolotl_federation::SnapshotSuffixCoverage {
            after: anchor.manifest.position,
            through,
        }),
    )
    .await
}

async fn send_snapshot_coverage(
    client: &FederationGrpcSubscriberClient,
    anchor: &SnapshotArchiveAnchor,
    suffix: Option<xolotl_federation::SnapshotSuffixCoverage>,
) -> Result<()> {
    let request = SnapshotReceivedRequest {
        authenticated_subscriber: anchor.manifest.subscription.subscriber,
        subscription: anchor.manifest.subscription,
        manifest_digest: anchor.manifest.binding_digest(),
        publication_digest: anchor.publication_digest,
        position: anchor.manifest.position,
        install_id: anchor.install_id,
        archive_digest: anchor.archive_digest,
        federation_generation: anchor.federation_generation,
        suffix,
    };
    let received = client
        .receive_snapshot(request)
        .await
        .context("publisher rejected stock snapshot archive receipt")?;
    ensure!(
        received == request.into(),
        "publisher returned a different snapshot receipt"
    );
    Ok(())
}

async fn local_receiver_progress(
    store: &Arc<RedbFederationStore>,
    archive: &snapshot_receiver::StockSnapshotArchive,
    plan: &RemoteSubscriptionPlan,
) -> Result<StockDeliveryProgress> {
    let view = snapshot_view(store, archive, plan.subscription).await?;
    ensure!(
        view.as_ref()
            .is_none_or(|view| !view.closed && view.pending.is_none()),
        "stock snapshot receiver is closed or has an unfinished install"
    );
    let generation = view.as_ref().map_or(0, |view| view.generation);
    let archived = view.and_then(|view| view.archived);
    if let Some(anchor) = &archived {
        ensure!(
            generation > 0 && generation == anchor.federation_generation,
            "stock snapshot archive belongs to a different delivery generation"
        );
        let completion = archive
            .completion(
                anchor.install_id,
                &anchor.manifest,
                anchor.federation_generation,
            )
            .await?
            .context("active stock snapshot bytes are missing")?;
        ensure!(
            completion.archive_digest == anchor.archive_digest,
            "active stock snapshot proof differs from federation anchor"
        );
    } else {
        ensure!(
            generation == 0,
            "stock delivery generation has no sealed archive"
        );
    }
    let store = Arc::clone(store);
    let subscription = plan.subscription;
    let cursor = archive
        .blocking(move || Ok(store.receiver_cursor_in_generation(generation, subscription)?))
        .await?;
    match archived {
        Some(anchor) => {
            let after = cursor.context("stock archive generation has no delivery baseline")?;
            ensure!(
                after.sequence() > anchor.manifest.position.sequence()
                    || after == anchor.manifest.position,
                "stock delivery cursor is before or conflicts with its archive baseline"
            );
            Ok(StockDeliveryProgress::Archived {
                anchor: Box::new(anchor),
                after,
            })
        }
        None => Ok(StockDeliveryProgress::Events { after: cursor }),
    }
}

async fn begin_snapshot_install(
    client: &FederationGrpcSubscriberClient,
    store: &Arc<RedbFederationStore>,
    archive: &snapshot_receiver::StockSnapshotArchive,
    plan: &RemoteSubscriptionPlan,
) -> Result<SnapshotInstallRequest> {
    if let Some(view) = snapshot_view(store, archive, plan.subscription).await? {
        if let Some(pending) = view.pending {
            return Ok(pending);
        }
        ensure!(
            view.active.is_none() && view.archived.is_none(),
            "stock cannot replace an existing snapshot without application projection"
        );
    }
    let offer = client
        .inspect_snapshot(plan.subscription)
        .await
        .context("publisher did not offer a snapshot for this history gap")?;
    ensure!(
        offer.manifest.subscription == plan.subscription && offer.manifest.stream == plan.stream,
        "snapshot offer targets a different stock subscription"
    );
    ensure!(
        plan.snapshot_schemas
            .contains(&offer.manifest.schema_revision),
        "stock receiver does not allow this snapshot schema"
    );
    let generation = snapshot_view(store, archive, plan.subscription)
        .await?
        .map_or(0, |view| view.generation);
    let request = SnapshotInstallRequest {
        install_id: snapshot_receiver::install_id(&offer.manifest),
        subject: FederationSubject::Node(plan.subscription.subscriber),
        manifest: offer.manifest,
        publication_digest: offer.publication_digest,
        expected_generation: generation,
    };
    let store = Arc::clone(store);
    let pending = request.clone();
    archive
        .blocking(move || Ok(store.begin_snapshot_install(pending)?))
        .await?;
    Ok(request)
}

async fn finish_snapshot_install(
    client: &FederationGrpcSubscriberClient,
    store: &Arc<RedbFederationStore>,
    archive: &snapshot_receiver::StockSnapshotArchive,
    plan: &RemoteSubscriptionPlan,
    pending: SnapshotInstallRequest,
    config: xolotl_federation_grpc::config::FederationGrpcConfig,
) -> Result<SnapshotArchiveAnchor> {
    ensure!(
        pending.manifest.subscription == plan.subscription
            && pending.manifest.stream == plan.stream
            && pending.subject == FederationSubject::Node(plan.subscription.subscriber)
            && plan
                .snapshot_schemas
                .contains(&pending.manifest.schema_revision),
        "pending snapshot belongs to a different stock subscription"
    );
    let delivery_generation = pending
        .expected_generation
        .checked_add(1)
        .context("stock snapshot generation overflow")?;
    let completion = match archive
        .completion(pending.install_id, &pending.manifest, delivery_generation)
        .await?
    {
        Some(completion) => completion,
        None => {
            archive
                .download_and_seal(
                    client,
                    &pending.manifest,
                    pending.install_id,
                    delivery_generation,
                    config
                        .max_frame_bytes
                        .saturating_sub(RECORD_FRAME_OVERHEAD)
                        .min(xolotl_federation::MAX_SNAPSHOT_CHUNK_BYTES),
                )
                .await?
        }
    };
    let store = Arc::clone(store);
    let subscription = plan.subscription;
    archive
        .blocking(move || Ok(store.commit_snapshot_archive(subscription, completion)?))
        .await
}
