use super::{
    StateHistoryPublication, StatePublicationWindow, decode_hex, settle_state_publication_windows,
    state_publication_prefix, storage_workers,
};
use crate::config::FederationPublisherConfig;
use anyhow::{Context, Result, ensure};
use std::collections::HashSet;
use xolotl_federation::{
    FederationError, FederationNodeId, FederationService, StreamId, StreamRef,
};
use xolotl_storage_redb::RedbFederationStateProjection;

pub(super) struct Retirement {
    publication: StateHistoryPublication,
    expected_cursor: i64,
}

impl Retirement {
    pub(super) fn stream_id(&self) -> StreamId {
        self.publication.stream.id
    }
}

pub(super) fn parse(
    config: &FederationPublisherConfig,
    local: FederationNodeId,
    active: &HashSet<StreamId>,
) -> Result<Vec<Retirement>> {
    ensure!(
        config.state_history_publication_retirements.len() <= 64,
        "at most 64 federation State publication retirements are allowed"
    );
    let mut streams = HashSet::new();
    let mut retirements = Vec::with_capacity(config.state_history_publication_retirements.len());
    for declaration in &config.state_history_publication_retirements {
        let id = StreamId::from_bytes(decode_hex::<16>(
            &declaration.stream_id,
            "publication retirement stream_id",
        )?);
        ensure!(
            streams.insert(id),
            "duplicate federation publication retirement stream_id"
        );
        ensure!(
            !active.contains(&id),
            "federation State publication cannot be active and retired together"
        );
        ensure!(
            (0..i64::MAX).contains(&declaration.expected_cursor),
            "federation publication retirement requires a nonnegative terminal cursor below i64::MAX"
        );
        let prefix = state_publication_prefix(&declaration.prefix)?;
        retirements.push(Retirement {
            publication: StateHistoryPublication {
                prefix,
                stream: StreamRef {
                    publisher: local,
                    id,
                },
            },
            expected_cursor: declaration.expected_cursor,
        });
    }
    Ok(retirements)
}

pub(super) async fn retire(
    workers: &storage_workers::StorageWorkers,
    service: &FederationService,
    projection: &RedbFederationStateProjection,
    retirements: &[Retirement],
    active: &[StateHistoryPublication],
) -> Result<usize> {
    let mut windows = Vec::new();
    let mut releasable = Vec::new();
    for retirement in retirements {
        let source = projection.clone();
        let declaration = retirement.publication.clone();
        let status = workers
            .run(move || source.publication_status(declaration.stream, &declaration.prefix))
            .await
            .context("inspect federation State publication retirement")?;
        let Some(status) = status else {
            tracing::info!(
                stream = ?retirement.publication.stream,
                prefix = %retirement.publication.prefix,
                "federation State publication pin absent; no completeness proof"
            );
            continue;
        };
        ensure!(
            status.pending_high.or(status.completed_cursor) == Some(retirement.expected_cursor),
            "federation publication retirement cursor conflict: expected {}, completed {:?}, pending {:?}",
            retirement.expected_cursor,
            status.completed_cursor,
            status.pending_high
        );
        if let Some(high) = status.pending_high {
            windows.push(StatePublicationWindow {
                publication: retirement.publication.clone(),
                expected: status.completed_cursor,
                high,
            });
        }
        releasable.push(retirement);
    }
    for publication in active {
        let source = projection.clone();
        let declaration = publication.clone();
        let status = match workers
            .run(move || source.publication_status(declaration.stream, &declaration.prefix))
            .await
        {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.downcast_ref::<FederationError>(),
                    Some(FederationError::NotFound)
                ) =>
            {
                continue;
            }
            Err(error) => {
                return Err(error).context("inspect active federation State publication window");
            }
        };
        if let Some(status) = status
            && let Some(high) = status.pending_high
        {
            windows.push(StatePublicationWindow {
                publication: publication.clone(),
                expected: status.completed_cursor,
                high,
            });
        }
    }
    settle_state_publication_windows(workers, service, projection, &windows)
        .await
        .context("settle existing federation State publication windows before retirement")?;
    let mut released = 0;
    for retirement in releasable {
        let source = projection.clone();
        let declaration = retirement.publication.clone();
        let expected = retirement.expected_cursor;
        let removed = workers
            .run(move || {
                source.release_publication(declaration.stream, &declaration.prefix, expected)
            })
            .await
            .context("release federation State publication history pin")?;
        released += usize::from(removed);
        tracing::info!(
            stream = ?retirement.publication.stream,
            prefix = %retirement.publication.prefix,
            cursor = retirement.expected_cursor,
            removed,
            "federation State publication retirement processed"
        );
    }
    Ok(released)
}

#[cfg(test)]
mod tests;
