//! Stock policy for publisher-side replica commitments and bounded log trim.
//! The store owns the atomic receipt, expiry and deletion decision; this module
//! only reconciles explicit host intent and schedules bounded attempts.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use xolotl_federation::{
    FederationError, FederationNodeId, FederationReplicaRetentionStore as _, FederationStore as _,
    InspectSubscriptionRequest, MAX_REPLICA_MEMBERS, MAX_RETIRE_RECORDS, ReplicaMemberSpec,
    ReplicaRetentionTerm, StreamId, StreamRef, StreamSpec, SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::RedbFederationStore;

use crate::config::FederationPublisherConfig;

use super::{decode_hex, remote_subscription, validate_revision};

const MAX_CONFIGURED_MEMBERS: usize = 1024;
const MAX_MAINTAINED_STREAMS: usize = 64;
const MAX_BATCHES_PER_TICK: usize = 8;
const MIN_INTERVAL_MS: u64 = 1_000;
const MAX_INTERVAL_MS: u64 = 86_400_000;
const MEMBER_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub(super) struct MemberPlan {
    stream: StreamRef,
    member: FederationNodeId,
    action: MemberAction,
}

#[derive(Clone, Copy)]
enum MemberAction {
    Retain {
        spec: ReplicaMemberSpec,
        expected_revision: Option<u64>,
    },
    Retire {
        expected_revision: Option<u64>,
    },
}

pub(super) struct Plan {
    pub(super) members: Vec<MemberPlan>,
    maintenance: Option<MaintenancePlan>,
}

struct MaintenancePlan {
    streams: Vec<StreamRef>,
    interval: Duration,
    max_batches_per_tick: usize,
    records_per_batch: usize,
}

#[derive(Default)]
pub(super) struct Reconciliation {
    pub(super) pending: usize,
    pending_streams: HashSet<StreamRef>,
}

pub(super) fn parse(
    config: &FederationPublisherConfig,
    local: FederationNodeId,
    declared: &[StreamSpec],
) -> Result<Plan> {
    ensure!(
        config.replica_members.len() <= MAX_CONFIGURED_MEMBERS,
        "too many configured federation replica members"
    );
    let streams: HashMap<_, _> = declared
        .iter()
        .map(|spec| (spec.stream.id, spec.stream))
        .collect();
    let mut members = Vec::with_capacity(config.replica_members.len());
    let mut seen = HashSet::new();
    let mut per_stream = HashMap::new();
    for item in &config.replica_members {
        let stream_id = StreamId::from_bytes(decode_hex::<16>(
            &item.stream_id,
            "replica member stream_id",
        )?);
        let stream = *streams
            .get(&stream_id)
            .context("replica member references an undeclared local stream")?;
        let member = FederationNodeId::from_bytes(decode_hex::<48>(
            &item.member_node,
            "replica member_node",
        )?);
        ensure!(
            member != local,
            "local node cannot be its own replica member"
        );
        ensure!(
            seen.insert((stream, member)),
            "duplicate federation replica member"
        );
        let count = per_stream.entry(stream).or_insert(0usize);
        *count += 1;
        ensure!(
            *count <= MAX_REPLICA_MEMBERS,
            "too many replica members for one stream"
        );
        validate_revision(item.expected_revision, "replica expected_revision")?;
        let action = if item.enabled {
            let id = match (&item.subscription_id, item.stock_generation) {
                (Some(explicit), None) => SubscriptionId::from_bytes(decode_hex::<16>(
                    explicit,
                    "replica subscription_id",
                )?),
                (None, Some(generation)) => {
                    remote_subscription(member, stream, generation)
                        .subscription
                        .id
                }
                _ => anyhow::bail!(
                    "enabled replica needs exactly one subscription_id or stock_generation"
                ),
            };
            let subscription = SubscriptionRef {
                subscriber: member,
                id,
            };
            MemberAction::Retain {
                spec: ReplicaMemberSpec {
                    stream,
                    member,
                    subscription,
                    term: item.lease_until_ms.map_or(
                        ReplicaRetentionTerm::Permanent,
                        ReplicaRetentionTerm::LeaseUntilMs,
                    ),
                },
                expected_revision: item.expected_revision,
            }
        } else {
            ensure!(
                item.subscription_id.is_none()
                    && item.stock_generation.is_none()
                    && item.lease_until_ms.is_none(),
                "disabled replica row only names stream, member and expected_revision"
            );
            MemberAction::Retire {
                expected_revision: item.expected_revision,
            }
        };
        members.push(MemberPlan {
            stream,
            member,
            action,
        });
    }

    let maintenance = config
        .replica_history_maintenance
        .as_ref()
        .map(|config| -> Result<MaintenancePlan> {
            let interval_ms = config.interval_ms.get();
            ensure!(
                (MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval_ms),
                "replica history maintenance interval_ms must be 1000–86400000"
            );
            ensure!(
                config.max_batches_per_tick.get() <= MAX_BATCHES_PER_TICK,
                "replica history maintenance max_batches_per_tick exceeds 8"
            );
            ensure!(
                config.records_per_batch.get() <= MAX_RETIRE_RECORDS,
                "replica history maintenance records_per_batch exceeds 256"
            );
            ensure!(
                !config.stream_ids.is_empty() && config.stream_ids.len() <= MAX_MAINTAINED_STREAMS,
                "replica history maintenance needs 1–64 streams"
            );
            let mut selected = HashSet::new();
            let mut maintain = Vec::with_capacity(config.stream_ids.len());
            for id in &config.stream_ids {
                let id = StreamId::from_bytes(decode_hex::<16>(id, "maintenance stream_id")?);
                let stream = *streams
                    .get(&id)
                    .context("replica history maintenance references an undeclared stream")?;
                ensure!(
                    selected.insert(stream),
                    "duplicate replica history maintenance stream"
                );
                maintain.push(stream);
            }
            Ok(MaintenancePlan {
                streams: maintain,
                interval: Duration::from_millis(interval_ms),
                max_batches_per_tick: config.max_batches_per_tick.get(),
                records_per_batch: config.records_per_batch.get(),
            })
        })
        .transpose()?;
    Ok(Plan {
        members,
        maintenance,
    })
}

fn reconcile_one(store: &RedbFederationStore, desired: MemberPlan, now_ms: u64) -> Result<bool> {
    let current = store.replica_member(desired.stream, desired.member)?;
    let (spec, expected_revision) = match desired.action {
        MemberAction::Retain {
            spec,
            expected_revision,
        } => (spec, expected_revision),
        MemberAction::Retire { expected_revision } => {
            match current {
                None => ensure!(
                    expected_revision.is_none(),
                    "retired replica does not exist at expected revision"
                ),
                Some(current) if current.retired => {}
                Some(current) => {
                    ensure!(
                        expected_revision == Some(current.revision),
                        "replica retirement requires its current revision"
                    );
                    store.retire_replica(
                        desired.stream,
                        desired.member,
                        current.revision,
                        now_ms,
                    )?;
                }
            }
            return Ok(false);
        }
    };
    match current {
        Some(current) if !current.retired && current.spec == spec => Ok(false),
        Some(current)
            if current.retired
                && current.spec == spec
                && matches!(spec.term, ReplicaRetentionTerm::LeaseUntilMs(deadline) if now_ms >= deadline) =>
        {
            // The configured lease has already ended. A later commitment
            // requires a new subscription and an explicit CAS re-enrollment.
            Ok(false)
        }
        Some(current) if !current.retired && current.spec.subscription == spec.subscription => {
            ensure!(
                expected_revision == Some(current.revision),
                "replica extension requires its current revision"
            );
            store.extend_replica(
                spec.stream,
                spec.member,
                current.revision,
                spec.term,
                now_ms,
            )?;
            Ok(false)
        }
        Some(current) if !current.retired => {
            anyhow::bail!(
                "replica subscription changed while active; retire revision {} first",
                current.revision
            );
        }
        Some(current) => {
            ensure!(
                expected_revision == Some(current.revision),
                "replica re-enrollment requires its retired revision"
            );
            join_when_open(store, spec, Some(current.revision), now_ms)
        }
        None => {
            ensure!(
                expected_revision.is_none(),
                "new replica cannot carry an old expected revision"
            );
            join_when_open(store, spec, None, now_ms)
        }
    }
}

fn join_when_open(
    store: &RedbFederationStore,
    spec: ReplicaMemberSpec,
    expected_revision: Option<u64>,
    now_ms: u64,
) -> Result<bool> {
    let inspected = store.inspect_subscription(InspectSubscriptionRequest {
        authenticated_subscriber: spec.member,
        subscription: spec.subscription,
    });
    let inspected = match inspected {
        Ok(inspected) => inspected,
        Err(FederationError::NotFound) => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        inspected.stream == spec.stream && !inspected.closed,
        "replica subscription is closed or belongs to a different stream"
    );
    store.join_replica(spec, expected_revision, now_ms)?;
    Ok(false)
}

pub(super) fn reconcile_members(
    store: &RedbFederationStore,
    members: &[MemberPlan],
    now_ms: u64,
) -> Result<Reconciliation> {
    let mut report = Reconciliation::default();
    for member in members {
        if reconcile_one(store, *member, now_ms).with_context(|| {
            format!(
                "reconcile replica {:?} for stream {:?}",
                member.member, member.stream.id
            )
        })? {
            report.pending += 1;
            report.pending_streams.insert(member.stream);
        }
    }
    Ok(report)
}

fn trusted_now_ms(store: &RedbFederationStore) -> Result<u64> {
    Ok(store.sample_time_ms(|| {
        xolotl_federation::FederationObjectClock::now_ms(&xolotl_federation::SystemObjectClock)
    })?)
}

fn maintain(
    store: &RedbFederationStore,
    plan: &Plan,
    now_ms: u64,
    next_stream: &mut usize,
) -> Result<()> {
    let report = reconcile_members(store, &plan.members, now_ms)?;
    let Some(maintenance) = &plan.maintenance else {
        return Ok(());
    };
    let mut attempts = 0;
    let mut stalled = 0;
    while attempts < maintenance.max_batches_per_tick && stalled < maintenance.streams.len() {
        let stream = maintenance.streams[*next_stream % maintenance.streams.len()];
        *next_stream = (*next_stream + 1) % maintenance.streams.len();
        if report.pending_streams.contains(&stream) {
            stalled += 1;
            continue;
        }
        attempts += 1;
        let retired =
            store.retire_replica_safe_history(stream, now_ms, maintenance.records_per_batch)?;
        if retired.removed != 0 {
            tracing::info!(
                stream = ?stream.id,
                removed = retired.removed,
                minimum_available = retired.minimum_available,
                "federation publisher history retired"
            );
        }
        stalled = if retired.removed < maintenance.records_per_batch {
            stalled + 1
        } else {
            0
        };
    }
    Ok(())
}

async fn run_pass(
    blocking: &dyn xolotl_kernel::host::BlockingSpawner,
    store: RedbFederationStore,
    plan: Arc<Plan>,
    cursor: usize,
    run_maintenance: bool,
) -> Result<(usize, Result<()>)> {
    xolotl_kernel::host::blocking::dispatch(blocking, move || {
        let mut next_stream = cursor;
        let outcome = (|| -> Result<()> {
            let now_ms = trusted_now_ms(&store)?;
            if run_maintenance {
                maintain(&store, &plan, now_ms, &mut next_stream)?;
            } else {
                let report = reconcile_members(&store, &plan.members, now_ms)?;
                if report.pending != 0 {
                    tracing::debug!(pending = report.pending, "replica subscriptions await Open");
                }
            }
            Ok(())
        })();
        (next_stream, outcome)
    })?
    .await
    .context("federation replica retention worker outcome indeterminate")
}

pub(super) async fn supervise(
    store: RedbFederationStore,
    plan: Plan,
    blocking: Arc<dyn xolotl_kernel::host::BlockingSpawner>,
) {
    if plan.members.is_empty() && plan.maintenance.is_none() {
        std::future::pending::<()>().await;
    }
    let maintenance_interval = plan.maintenance.as_ref().map(|item| item.interval);
    let plan = Arc::new(plan);
    let mut member_tick = tokio::time::interval(MEMBER_RETRY_INTERVAL);
    member_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut maintenance_tick = maintenance_interval.map(tokio::time::interval);
    if let Some(tick) = &mut maintenance_tick {
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    }
    let mut next_stream = 0;
    loop {
        let run_maintenance = tokio::select! {
            _ = member_tick.tick() => false,
            _ = async {
                match &mut maintenance_tick {
                    Some(tick) => { tick.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => true,
        };
        let result = run_pass(
            blocking.as_ref(),
            store.clone(),
            Arc::clone(&plan),
            next_stream,
            run_maintenance,
        )
        .await;
        match result {
            Ok((next, outcome)) => {
                next_stream = next;
                if let Err(error) = outcome {
                    tracing::error!(%error, "federation replica retention failed");
                }
            }
            Err(error) => {
                tracing::error!(error = %format_args!("{error:#}"), "federation replica retention dispatch failed")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        path::Path,
    };

    use anyhow::{Result, ensure};
    use xolotl_federation::{
        AcknowledgeRequest, EventType, ExportAccess, ExportName, HistoryStart, OpenRequest,
        PublishRequest, RequestId, SchemaRevision,
    };
    use xolotl_storage_redb::RedbStore;

    use crate::config::{FederationReplicaHistoryMaintenanceConfig, FederationReplicaMemberConfig};

    use super::*;

    const LOCAL: FederationNodeId = FederationNodeId::from_bytes([11; 48]);
    const MEMBER: FederationNodeId = FederationNodeId::from_bytes([12; 48]);
    const STREAM: StreamRef = StreamRef {
        publisher: LOCAL,
        id: StreamId::from_bytes([13; 16]),
    };
    const OTHER_STREAM: StreamRef = StreamRef {
        publisher: LOCAL,
        id: StreamId::from_bytes([24; 16]),
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn config() -> FederationPublisherConfig {
        FederationPublisherConfig {
            replica_members: vec![FederationReplicaMemberConfig {
                stream_id: hex(STREAM.id.as_bytes()),
                member_node: hex(MEMBER.as_bytes()),
                subscription_id: None,
                stock_generation: Some(7),
                enabled: true,
                lease_until_ms: None,
                expected_revision: None,
            }],
            replica_history_maintenance: Some(FederationReplicaHistoryMaintenanceConfig {
                stream_ids: vec![hex(STREAM.id.as_bytes())],
                interval_ms: NonZeroU64::MIN.saturating_add(999),
                max_batches_per_tick: NonZeroUsize::MIN,
                records_per_batch: NonZeroUsize::MIN,
            }),
            ..Default::default()
        }
    }

    fn declared() -> Result<Vec<StreamSpec>> {
        Ok(vec![StreamSpec {
            stream: STREAM,
            export: ExportName::new("notes")?,
        }])
    }

    fn store(path: &Path) -> Result<(RedbStore, RedbFederationStore)> {
        let db = RedbStore::open(path)?;
        let store = db.federation_store(LOCAL)?;
        store.set_peer_authority(MEMBER, None, true)?;
        store.set_export_authority(
            MEMBER,
            ExportName::new("notes")?,
            None,
            ExportAccess {
                serve: true,
                receive: false,
            },
        )?;
        store.declare_stream(declared()?.remove(0))?;
        Ok((db, store))
    }

    #[test]
    fn stock_membership_waits_for_open_and_gates_automatic_trim() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_db, store) = store(&dir.path().join("retention.redb"))?;
        let plan = parse(&config(), LOCAL, &declared()?)?;
        let MemberAction::Retain { spec: member, .. } = plan.members[0].action else {
            anyhow::bail!("expected an enabled member")
        };
        ensure!(member.subscription == remote_subscription(MEMBER, STREAM, 7).subscription);
        let first = store
            .append_published(PublishRequest {
                retry_epoch: 1,
                stream: STREAM,
                publish_id: RequestId::from_bytes([14; 16]),
                event_type: EventType::new("note")?,
                schema_revision: SchemaRevision::from_bytes([15; 32]),
                event_ref: None,
                payload: Arc::from([16].as_slice()),
            })?
            .position();
        ensure!(reconcile_members(&store, &plan.members, 10)?.pending == 1);
        let mut next_stream = 0;
        maintain(&store, &plan, 10, &mut next_stream)?;
        ensure!(store.replica_member(STREAM, MEMBER)?.is_none());
        store.open(OpenRequest {
            authenticated_subscriber: MEMBER,
            request_id: RequestId::from_bytes([17; 16]),
            subscription: member.subscription,
            stream: STREAM,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        ensure!(reconcile_members(&store, &plan.members, 11)?.pending == 0);
        maintain(&store, &plan, 11, &mut next_stream)?;
        let inspection = store.inspect_subscription(InspectSubscriptionRequest {
            authenticated_subscriber: MEMBER,
            subscription: member.subscription,
        })?;
        ensure!(inspection.minimum_available == 1);
        store.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: MEMBER,
            subscription: member.subscription,
            position: first,
        })?;
        maintain(&store, &plan, 12, &mut next_stream)?;
        let inspection = store.inspect_subscription(InspectSubscriptionRequest {
            authenticated_subscriber: MEMBER,
            subscription: member.subscription,
        })?;
        ensure!(inspection.minimum_available == 2);
        ensure!(store.replica_member(STREAM, MEMBER)?.is_some());
        Ok(())
    }

    #[test]
    fn manifest_retirement_requires_cas_and_omission_does_not_retire() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_db, store) = store(&dir.path().join("membership.redb"))?;
        let configured = config();
        let plan = parse(&configured, LOCAL, &declared()?)?;
        let MemberAction::Retain { spec, .. } = plan.members[0].action else {
            anyhow::bail!("expected an enabled member")
        };
        let subscription = spec.subscription;
        store.open(OpenRequest {
            authenticated_subscriber: MEMBER,
            request_id: RequestId::from_bytes([21; 16]),
            subscription,
            stream: STREAM,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        reconcile_members(&store, &plan.members, 10)?;
        let joined = store
            .replica_member(STREAM, MEMBER)?
            .context("missing member")?;
        ensure!(joined.revision == 1 && !joined.retired);
        reconcile_members(&store, &[], 11)?;
        ensure!(
            !store
                .replica_member(STREAM, MEMBER)?
                .context("missing member")?
                .retired
        );
        let mut disabled = configured;
        disabled.replica_members[0].enabled = false;
        disabled.replica_members[0].stock_generation = None;
        disabled.replica_members[0].expected_revision = Some(2);
        let stale = parse(&disabled, LOCAL, &declared()?)?;
        ensure!(reconcile_members(&store, &stale.members, 12).is_err());
        ensure!(
            !store
                .replica_member(STREAM, MEMBER)?
                .context("missing member")?
                .retired
        );
        disabled.replica_members[0].expected_revision = Some(1);
        let retirement = parse(&disabled, LOCAL, &declared()?)?;
        reconcile_members(&store, &retirement.members, 13)?;
        ensure!(
            store
                .replica_member(STREAM, MEMBER)?
                .context("missing member")?
                .retired
        );
        reconcile_members(&store, &retirement.members, 14)?;
        Ok(())
    }

    #[tokio::test]
    async fn pending_member_blocks_only_its_own_maintenance_stream() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_db, store) = store(&dir.path().join("two-streams.redb"))?;
        let other = StreamSpec {
            stream: OTHER_STREAM,
            export: ExportName::new("notes")?,
        };
        store.declare_stream(other.clone())?;
        let mut config = config();
        config
            .replica_history_maintenance
            .as_mut()
            .context("missing maintenance")?
            .stream_ids
            .push(hex(OTHER_STREAM.id.as_bytes()));
        let mut declared = declared()?;
        declared.push(other);
        let plan = Arc::new(parse(&config, LOCAL, &declared)?);
        store.append_published(PublishRequest {
            retry_epoch: 1,
            stream: OTHER_STREAM,
            publish_id: RequestId::from_bytes([25; 16]),
            event_type: EventType::new("note")?,
            schema_revision: SchemaRevision::from_bytes([26; 32]),
            event_ref: None,
            payload: Arc::from([27].as_slice()),
        })?;
        let subscription = SubscriptionRef {
            subscriber: MEMBER,
            id: SubscriptionId::from_bytes([28; 16]),
        };
        store.open(OpenRequest {
            authenticated_subscriber: MEMBER,
            request_id: RequestId::from_bytes([29; 16]),
            subscription,
            stream: OTHER_STREAM,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        let closed = xolotl_kernel::host::TokioBlockingSpawner::new(1)?;
        closed.close();
        let rejected = run_pass(&closed, store.clone(), Arc::clone(&plan), 1, true)
            .await
            .err()
            .context("closed retention host accepted a pass")?;
        ensure!(
            rejected.downcast_ref::<xolotl_kernel::host::BlockingSpawnError>()
                == Some(&xolotl_kernel::host::BlockingSpawnError::Unavailable)
        );
        ensure!(
            store
                .inspect_subscription(InspectSubscriptionRequest {
                    authenticated_subscriber: MEMBER,
                    subscription,
                })?
                .minimum_available
                == 1
        );
        let running = xolotl_kernel::host::TokioBlockingSpawner::new(1)?;
        let (next_stream, outcome) = run_pass(&running, store.clone(), plan, 1, true).await?;
        outcome?;
        ensure!(next_stream == 0);
        ensure!(store.replica_member(STREAM, MEMBER)?.is_none());
        let receipt =
            store.retire_replica_safe_history(OTHER_STREAM, trusted_now_ms(&store)?, 1)?;
        ensure!(receipt.removed == 0 && receipt.minimum_available == 2);
        Ok(())
    }

    #[test]
    fn invalid_replica_configuration_fails_before_startup() -> Result<()> {
        let mut config = config();
        config.replica_members[0].subscription_id = Some(hex(&[22; 16]));
        ensure!(parse(&config, LOCAL, &declared()?).is_err());
        config.replica_members[0].subscription_id = None;
        config
            .replica_members
            .push(config.replica_members[0].clone());
        ensure!(parse(&config, LOCAL, &declared()?).is_err());
        config.replica_members.pop();
        config
            .replica_history_maintenance
            .as_mut()
            .context("missing maintenance")?
            .stream_ids = vec![hex(&[23; 16])];
        ensure!(parse(&config, LOCAL, &declared()?).is_err());
        Ok(())
    }
}
