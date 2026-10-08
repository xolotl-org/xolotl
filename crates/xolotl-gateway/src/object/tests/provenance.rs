use super::*;
use crate::object::read_grant::{maintenance as grant_maintenance, read_grant_path, record};
use std::collections::VecDeque;
use std::future::{Ready, ready};
use xolotl_state::{
    Backend, InMemoryBackend, InMemoryOptions, StateCursor, StateFailure, StatePage, StateQuery,
    StateResult, StateRowTooLarge, StateScan,
};
use xolotl_types::{BlobRef, Path, TaintedValue};

#[derive(Clone, Copy)]
enum Authorization {
    Ticket,
    ReadGrant,
}

impl Authorization {
    async fn expired(self, fixture: &Fixture) -> anyhow::Result<(Path, Value)> {
        match self {
            Self::Ticket => {
                let ticket = fixture.issue(true).await?;
                let mut record = fixture.record(ticket.ticket_id()).await?;
                record.expires_at_ms = 1;
                Ok((upload_ticket_path(ticket.ticket_id())?, record.to_value()?))
            }
            Self::ReadGrant => {
                let scope = record::ReadGrantScope::new(
                    &fixture.gateway.profile_snapshot(),
                    &fixture.session,
                    "echo",
                )?;
                let grant = GatewayObjectReadGrant {
                    grant_id: format!("org_{}", "1".repeat(32)),
                    metadata: xolotl_state::object::ObjectMetadata {
                        blob: BlobRef {
                            hash: "a".repeat(96),
                            size: 1,
                            mime: None,
                        },
                        taint: TaintSet::pristine(),
                    },
                    offset: 0,
                    length: 1,
                    expires_at_ms: 1,
                };
                Ok((
                    read_grant_path(grant.grant_id())?,
                    record::encode(scope, &grant)?,
                ))
            }
        }
    }

    async fn prune(
        self,
        state: &Backend,
        path: &Path,
        envelope: TaintedValue,
    ) -> Result<bool, GatewayError> {
        match self {
            Self::Ticket => ticket::prune_upload_ticket_entry(state, path, envelope, 1).await,
            Self::ReadGrant => {
                grant_maintenance::prune_read_grant_entry(state, path, envelope, 1).await
            }
        }
    }

    async fn maintain(
        self,
        state: &Backend,
        cursor: &mut Option<StateCursor>,
    ) -> Result<usize, GatewayError> {
        match self {
            Self::Ticket => Ok(ticket::maintain_upload_tickets_step(state, cursor, 1)
                .await?
                .removed),
            Self::ReadGrant => Ok(crate::object::read_grant::maintain_read_grants_step(
                state, cursor, 1,
            )
            .await?
            .removed),
        }
    }
}

struct ScriptedQuery {
    pages: parking_lot::Mutex<VecDeque<StateResult<StatePage>>>,
    scans: parking_lot::Mutex<Vec<StateScan>>,
}

fn memory_backend() -> Backend {
    let memory = Arc::new(InMemoryBackend::new());
    Backend::new()
        .with_read(memory.clone())
        .with_write(memory.clone())
        .with_bounded_write(memory)
}

impl StateQuery for ScriptedQuery {
    type Query<'a> = Ready<StateResult<StatePage>>;

    fn query<'a>(&'a self, scan: &'a StateScan) -> Self::Query<'a> {
        self.scans.lock().push(scan.clone());
        ready(self.pages.lock().pop_front().unwrap_or_else(|| {
            Err(xolotl_state::StateError::Backend("unexpected maintenance query".into()).into())
        }))
    }
}

fn scripted_query(
    path: &Path,
    value: Value,
    partial: bool,
    record_taint: TaintSet,
) -> anyhow::Result<Arc<ScriptedQuery>> {
    let before = StateCursor(vec![2]);
    let first = StatePage {
        taint: TaintSet::of(TaintSource::ModelOutput).merged(&record_taint),
        entries: vec![(path.clone(), TaintedValue::new(value, record_taint))],
        next: partial.then_some(before.clone()),
        examined: 1,
        encoded_bytes: 1,
    };
    let pages = if partial {
        VecDeque::from([
            Ok(first),
            Err(StateFailure::new(
                xolotl_state::StateError::RowTooLarge(Box::new(StateRowTooLarge {
                    path: path.clone().try_push("oversized")?,
                    encoded_bytes: maintenance::PAGE_BYTES + 1,
                    provenance_observed: true,
                    retry: Some(before),
                    resume: StateCursor(vec![3]),
                })),
                TaintSet::of(TaintSource::Fetched {
                    host: "failed-query".into(),
                }),
            )),
        ])
    } else {
        VecDeque::from([Ok(first)])
    };
    Ok(Arc::new(ScriptedQuery {
        pages: parking_lot::Mutex::new(pages),
        scans: parking_lot::Mutex::new(Vec::new()),
    }))
}

#[tokio::test]
async fn condition_delete_retains_observation_after_same_value_set_replaces_provenance()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for authorization in [Authorization::Ticket, Authorization::ReadGrant] {
        let (path, value) = authorization.expired(&fixture).await?;
        let state = memory_backend();
        let observed = TaintSet::of(TaintSource::ModelOutput);
        let replacement = TaintSet::of(TaintSource::Fetched {
            host: "replacement".into(),
        });
        state
            .write_set_tainted(&path, value.clone(), observed.clone())
            .await?;
        let saved = state.read_tainted(&path).await?;
        let envelope = TaintedValue::new(saved.value.context("missing record")?, saved.taint);
        state
            .write_set_tainted(&path, value, replacement.clone())
            .await?;
        ensure!(state.read_tainted(&path).await?.taint == replacement);
        ensure!(authorization.prune(&state, &path, envelope).await?);
        let absence = state.read_tainted(&path).await?;
        ensure!(absence.value.is_none());
        let expected = observed.merged(&replacement);
        ensure!(absence.taint.contains_all(&expected));
        ensure!(expected.contains_all(&absence.taint));
    }
    Ok(())
}

#[tokio::test]
async fn maintenance_delete_retains_normal_and_partial_page_provenance() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for authorization in [Authorization::Ticket, Authorization::ReadGrant] {
        for partial in [false, true] {
            let (path, value) = authorization.expired(&fixture).await?;
            let observed = TaintSet::of(TaintSource::Fetched {
                host: "record".into(),
            });
            let current = TaintSet::of(TaintSource::Fetched {
                host: "replacement".into(),
            });
            let query = scripted_query(&path, value.clone(), partial, observed.clone())?;
            let state = memory_backend().with_query(query.clone());
            state
                .write_set_tainted(&path, value, current.clone())
                .await?;
            let mut cursor = None;
            ensure!(authorization.maintain(&state, &mut cursor).await? == 1);
            let absence = state.read_tainted(&path).await?;
            ensure!(absence.value.is_none());
            let expected = observed
                .merged(&current)
                .merged(&TaintSet::of(TaintSource::ModelOutput));
            if partial {
                ensure!(cursor == Some(StateCursor(vec![2])));
                ensure!(authorization.maintain(&state, &mut cursor).await? == 0);
                ensure!(cursor == Some(StateCursor(vec![3])));
            } else {
                ensure!(cursor.is_none());
            }
            ensure!(absence.taint.contains_all(&expected));
            ensure!(expected.contains_all(&absence.taint));
            let scans = query.scans.lock();
            ensure!(scans.len() == if partial { 2 } else { 1 });
            for scan in scans.iter() {
                ensure!(scan.limits.entries.get() == maintenance::BATCH_ENTRIES);
                ensure!(scan.limits.examined.get() == maintenance::BATCH_ENTRIES);
                ensure!(scan.limits.encoded_bytes.get() == maintenance::PAGE_BYTES);
            }
            ensure!(query.pages.lock().is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn page_provenance_capacity_rejection_preserves_record_and_resets_cursor()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for authorization in [Authorization::Ticket, Authorization::ReadGrant] {
        for partial in [false, true] {
            let (path, value) = authorization.expired(&fixture).await?;
            let query = scripted_query(&path, value.clone(), partial, TaintSet::pristine())?;
            let memory = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
                absence_limits: xolotl_state::AbsenceLimits {
                    records: Some(0),
                    ..Default::default()
                },
                ..InMemoryOptions::default()
            })?);
            let state = Backend::new()
                .with_read(memory.clone())
                .with_write(memory.clone())
                .with_bounded_write(memory)
                .with_query(query);
            state.write_set(&path, value.clone()).await?;
            let mut cursor = Some(StateCursor(vec![9]));
            let error = authorization
                .maintain(&state, &mut cursor)
                .await
                .err()
                .context("delete discarded page provenance")?;
            ensure!(
                matches!(error, GatewayError::Rejected(message) if message.contains("state absence capacity exhausted"))
            );
            ensure!(cursor.is_none());
            let retained = state.read_tainted(&path).await?;
            ensure!(retained.value == Some(value) && retained.taint.is_pristine());
        }
    }
    Ok(())
}

#[tokio::test]
async fn invalid_oversized_retry_is_rejected_without_replaying_or_deleting_records()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for authorization in [Authorization::Ticket, Authorization::ReadGrant] {
        let (path, value) = authorization.expired(&fixture).await?;
        let taint = TaintSet::of(TaintSource::ModelOutput);
        let query = scripted_query(&path, value.clone(), true, taint.clone())?;
        {
            let mut pages = query.pages.lock();
            let initial = pages.pop_front().context("missing first page")?;
            pages.push_back(initial);
        }
        let state = memory_backend().with_query(query.clone());
        state
            .write_set_tainted(&path, value.clone(), taint.clone())
            .await?;
        let mut cursor = Some(StateCursor(vec![9]));
        let error = authorization
            .maintain(&state, &mut cursor)
            .await
            .err()
            .context("invalid oversized retry succeeded")?;
        ensure!(
            matches!(error, GatewayError::Rejected(message) if message.contains("oversized-row retry is invalid"))
        );
        ensure!(cursor.is_none());
        let retained = state.read_tainted(&path).await?;
        ensure!(retained.value == Some(value) && retained.taint == taint);
        ensure!(query.scans.lock().len() == 1 && query.pages.lock().len() == 1);
    }
    Ok(())
}
