//! Periodic, bounded Source event and rate retention across private scopes.

use crate::config::{ExternalGatewayConfig, SourceMaintenanceConfig};
use crate::external::SharedSourceCommands;
#[cfg(test)]
use crate::now_millis;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use xolotl_source::{MAX_MAINTENANCE_BATCH, SourceMaintenance, SourceStore};

#[derive(Default)]
pub(super) struct TickReport {
    pub batches: usize,
    pub examined: usize,
    pub removed: usize,
}

#[derive(Default)]
pub(super) struct MaintenanceTurn {
    commands_next: bool,
}

pub(super) fn start(
    source_store: Arc<dyn SourceStore>,
    commands: SharedSourceCommands,
    config: &ExternalGatewayConfig,
    decision_clock: Arc<dyn xolotl_source::SourceClock>,
) -> JoinHandle<()> {
    let settings = config.source_maintenance.bounded();
    tracing::info!(
        interval_ms = settings.interval_ms,
        max_batches_per_tick = settings.max_batches_per_tick,
        "Source metadata maintenance started"
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(settings.interval_ms));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut turn = MaintenanceTurn::default();
        loop {
            // Tokio's first interval tick is immediate, including after a restart.
            interval.tick().await;
            match maintain_tick(
                source_store.as_ref(),
                &commands,
                settings,
                &mut turn,
                decision_clock.clone(),
            )
            .await
            {
                Ok(report) if report.removed != 0 => tracing::info!(
                    batches = report.batches,
                    examined = report.examined,
                    removed = report.removed,
                    "Source metadata maintenance released expired metadata or retired streams"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "Source metadata maintenance failed"),
            }
        }
    })
}

pub(super) async fn maintain_tick(
    source_store: &dyn SourceStore,
    commands: &SharedSourceCommands,
    settings: SourceMaintenanceConfig,
    turn: &mut MaintenanceTurn,
    decision_clock: Arc<dyn xolotl_source::SourceClock>,
) -> anyhow::Result<TickReport> {
    let at_millis = decision_clock.now_millis();
    let mut report = TickReport::default();
    let mut commands_done = false;
    let mut source_done = false;
    while report.batches < settings.max_batches_per_tick && !(commands_done && source_done) {
        let (examined, removed) = if !commands_done && (turn.commands_next || source_done) {
            turn.commands_next = false;
            let batch = commands.expire_retained(at_millis)?;
            commands_done = batch.reached_end;
            (batch.examined, batch.removed)
        } else {
            turn.commands_next = true;
            let batch = source_store
                .maintain(SourceMaintenance {
                    decision_clock: decision_clock.clone(),
                    limit: NonZeroUsize::MIN.saturating_add(MAX_MAINTENANCE_BATCH - 1),
                })
                .await?;
            source_done = batch.reached_end || batch.examined == 0;
            (batch.examined, batch.removed)
        };
        report.examined = report.examined.saturating_add(examined);
        report.removed = report.removed.saturating_add(removed);
        if examined != 0 {
            report.batches += 1;
            tokio::task::yield_now().await;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use xolotl_sdk::InMemoryBackend;
    use xolotl_source::{
        ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim,
        SourceClaimEvidence, SourceClaimId, SourceCommit, SourceCommitOutcome,
        SourceEvidenceInspection,
    };
    use xolotl_types::{
        TaintSet, Value,
        external::{OverflowPolicy, StreamCapacity},
    };

    async fn install_source_scopes(
        source_store: &dyn SourceStore,
        installation: &str,
        projections: &[&str],
    ) -> anyhow::Result<Vec<u64>> {
        let declarations = projections
            .iter()
            .map(|projection| -> anyhow::Result<_> {
                Ok(serde_json::json!({
                    "id": projection,
                    "role": "source",
                    "namespace": null,
                    "provides": [],
                    "emits": {
                        "sink": xolotl_types::sandboxed_source_event_sink_path(installation, projection)?.to_string(),
                        "purity": "effectful",
                        "event_schema": null,
                        "max_inline_payload_bytes": 1024,
                        "capacity": { "max_events": 8, "on_overflow": "drop_oldest" },
                        "rate_limit": null,
                        "commands": false,
                        "command_schema": null,
                        "command_result_schema": null
                    },
                    "version": 1
                }))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let definition = serde_json::from_value(serde_json::json!({
            "id": installation,
            "platform": installation,
            "transport": { "grpc": { "endpoint": null } },
            "trust": "full",
            "config_schema": null,
            "config": null,
            "projections": declarations,
            "version": 0
        }))?;
        let ExternalInstallationMutation::Applied(Some(record)) =
            source_store.compare_install(definition, None).await?
        else {
            anyhow::bail!("test Source installation was rejected");
        };
        projections
            .iter()
            .map(|projection| {
                record
                    .scope_epoch(projection)
                    .ok_or_else(|| anyhow::anyhow!("missing test Source scope {projection}"))
            })
            .collect()
    }

    async fn put_event(
        source_store: &dyn SourceStore,
        installation: &str,
        projection: &str,
        scope_epoch: u64,
        event: &str,
        claim_id: u8,
        received_at_ms: i64,
    ) -> anyhow::Result<()> {
        let sink = xolotl_types::sandboxed_source_event_sink_path(installation, projection)?;
        let capacity = StreamCapacity {
            max_events: 8,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::string(event.into());
        let taint = TaintSet::pristine();
        let outcome = source_store
            .commit(SourceCommit {
                claim: SourceClaim {
                    installation_id: installation,
                    projection_id: projection,
                    scope_epoch,
                    stream_epoch: None,
                    event_id: event,
                    claim_id: SourceClaimId::from_bytes([claim_id; 16]),
                },
                received_at_ms,
                decision_clock: Arc::new(move || received_at_ms),
                dedupe_window_ms: 60_000,
                sink: &sink,
                capacity: &capacity,
                max_inline_payload_bytes: 1024,
                payload: &payload,
                taint: &taint,
                stream: None,
                rate_limit: None,
            })
            .await?;
        ensure!(outcome == SourceCommitOutcome::Accepted);
        Ok(())
    }

    async fn evidence(
        source_store: &dyn SourceStore,
        installation: &str,
        projection: &str,
        scope_epoch: u64,
        event: &str,
        claim_id: u8,
    ) -> anyhow::Result<SourceClaimEvidence> {
        Ok(source_store
            .inspect(SourceEvidenceInspection {
                claim: SourceClaim {
                    installation_id: installation,
                    projection_id: projection,
                    scope_epoch,
                    stream_epoch: None,
                    event_id: event,
                    claim_id: SourceClaimId::from_bytes([claim_id; 16]),
                },
            })
            .await?)
    }

    #[tokio::test]
    async fn idle_maintenance_covers_removed_projections_and_stays_bounded() -> anyhow::Result<()> {
        let (state, source_store) = InMemoryBackend::new().into_source_parts();
        let commands = SharedSourceCommands::new(
            state,
            source_store.clone(),
            xolotl_kernel::Registry::new(),
            xolotl_gateway::external::DEFAULT_SOURCE_COMMAND_LIMIT,
        );
        let removed_epochs =
            install_source_scopes(source_store.as_ref(), "removed", &["one", "two"]).await?;
        let active_epoch =
            install_source_scopes(source_store.as_ref(), "active", &["one"]).await?[0];
        put_event(
            source_store.as_ref(),
            "removed",
            "one",
            removed_epochs[0],
            "expired-a",
            1,
            1,
        )
        .await?;
        for i in 0..62_u8 {
            let event = format!("extra-{i:02}");
            put_event(
                source_store.as_ref(),
                "removed",
                "one",
                removed_epochs[0],
                &event,
                i + 10,
                1,
            )
            .await?;
        }
        put_event(
            source_store.as_ref(),
            "removed",
            "two",
            removed_epochs[1],
            "expired-b",
            2,
            1,
        )
        .await?;
        put_event(
            source_store.as_ref(),
            "active",
            "one",
            active_epoch,
            "current",
            3,
            now_millis(),
        )
        .await?;
        let removed_revision = source_store
            .load_installation("removed")
            .await?
            .ok_or_else(|| anyhow::anyhow!("removed installation missing"))?
            .revision();
        ensure!(matches!(
            source_store
                .compare_retire("removed", removed_revision)
                .await?,
            ExternalInstallationMutation::Applied(None)
        ));
        let mut config = ExternalGatewayConfig::default();
        config.source_maintenance.interval_ms = 10;
        config.source_maintenance.max_batches_per_tick = 1;
        let settings = config.source_maintenance.bounded();
        let first = maintain_tick(
            source_store.as_ref(),
            &commands,
            settings,
            &mut MaintenanceTurn::default(),
            Arc::new(now_millis),
        )
        .await?;
        ensure!(
            first.batches == 1
                && first.examined == MAX_MAINTENANCE_BATCH
                && first.removed == MAX_MAINTENANCE_BATCH - 1
        );
        ensure!(matches!(
            evidence(
                source_store.as_ref(),
                "removed",
                "two",
                removed_epochs[1],
                "expired-b",
                2
            )
            .await?,
            SourceClaimEvidence::Committed(_)
        ));
        let task = start(
            source_store.clone(),
            commands,
            &config,
            Arc::new(now_millis),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if evidence(
                    source_store.as_ref(),
                    "removed",
                    "one",
                    removed_epochs[0],
                    "expired-a",
                    1,
                )
                .await?
                    == SourceClaimEvidence::Unproven
                    && evidence(
                        source_store.as_ref(),
                        "removed",
                        "two",
                        removed_epochs[1],
                        "expired-b",
                        2,
                    )
                    .await?
                        == SourceClaimEvidence::Unproven
                {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        ensure!(matches!(
            evidence(
                source_store.as_ref(),
                "active",
                "one",
                active_epoch,
                "current",
                3
            )
            .await?,
            SourceClaimEvidence::Committed(_)
        ));
        task.abort();
        ensure!(task.await.is_err_and(|error| error.is_cancelled()));
        Ok(())
    }
}
