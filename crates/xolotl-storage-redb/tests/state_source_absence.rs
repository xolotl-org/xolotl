use anyhow::{Context, ensure};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimEvidence,
    SourceClaimId, SourceClaimInspection, SourceCommit, SourceCommitOutcome, SourceEventCommit,
    SourceEvidenceInspection,
};
use xolotl_storage_redb::{RedbHistory, RedbOptions, RedbStateBackend, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, TaintSource, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

struct Fixture {
    sink: Path,
    capacity: StreamCapacity,
    scope_epoch: u64,
}

impl Fixture {
    async fn install(source: &RedbStateBackend) -> anyhow::Result<Self> {
        let sink = Path::parse("state://events/external/installation/source")?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let definition = ExternalInstallationDef {
            id: "installation".into(),
            platform: "test".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Full,
            config_schema: Value::map(Default::default()),
            config: Value::null(),
            projections: vec![ExternalProjectionDef {
                id: "source".into(),
                role: Role::Source,
                namespace: None,
                provides: vec![],
                emits: Some(EventSource {
                    sink: sink.clone(),
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes: 1024,
                    capacity: capacity.clone(),
                    rate_limit: None,
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            }],
            version: 0,
        };
        let ExternalInstallationMutation::Applied(Some(record)) =
            source.compare_install(definition, None).await?
        else {
            anyhow::bail!("Source test installation was not applied")
        };
        let scope_epoch = record
            .scope_epoch("source")
            .context("installed Source epoch missing")?;
        Ok(Self {
            sink,
            capacity,
            scope_epoch,
        })
    }

    fn commit<'a>(
        &'a self,
        event_id: &'a str,
        claim_id: u8,
        payload: &'a Value,
        taint: &'a TaintSet,
    ) -> SourceCommit<'a> {
        SourceCommit {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch: self.scope_epoch,
                stream_epoch: None,
                event_id,
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
            received_at_ms: 100,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = 100;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: &self.sink,
            capacity: &self.capacity,
            max_inline_payload_bytes: 1024,
            payload,
            taint,
            stream: None,
            rate_limit: None,
        }
    }
}

#[tokio::test]
async fn bounded_source_rebuild_after_lower_limit_reopen_releases_absence_transactionally()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    for history in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        let file = directory
            .path()
            .join(format!("source-budget-{history:?}.redb"));
        let fixture;
        let author = TaintSet::author();
        {
            let store = RedbStore::open_with_history(&file, history)?;
            let (state, source) = store.state_backend().into_source_parts();
            fixture = Fixture::install(source.as_ref()).await?;
            state
                .write_set_tainted(&fixture.sink, Value::list(vec![]), author.clone())
                .await?;
            state
                .write_delete_tainted(&fixture.sink, author.clone())
                .await?;
        }
        {
            let store = RedbStore::open_with_options(
                &file,
                RedbOptions {
                    history,
                    absence_limits: xolotl_state::AbsenceLimits {
                        records: Some(0),
                        encoded_bytes: Some(0),
                    },
                    ..Default::default()
                },
            )?;
            let (state, source) = store.state_backend().into_source_parts();
            let absent = state.read_tainted(&fixture.sink).await?;
            let mut events = state.subscribe(&fixture.sink).await?;
            let query = xolotl_state::StateHistoryQuery::new(fixture.sink.clone(), 0, i64::MAX);
            let before_history = if state.has_history() {
                Some(state.history(&query).await?.entries)
            } else {
                None
            };
            let mut deep = Value::null();
            for _depth in 0..4096 {
                deep = Value::list(vec![deep]);
            }
            for payload in [
                deep,
                Value::from("\n".repeat(600)),
                Value::bytes(vec![255; 600]),
            ] {
                let commit = fixture.commit("rebuild", 7, &payload, &author);
                ensure!(
                    source.commit(commit).await?
                        == SourceCommitOutcome::Rejected(
                            xolotl_source::SourceCommitRejection::PayloadTooLarge
                        )
                );
                ensure!(state.read_tainted(&fixture.sink).await? == absent);
                ensure!(matches!(
                    events.try_recv(),
                    Err(xolotl_state::StateWatchError::Empty)
                ));
                ensure!(
                    source
                        .inspect(SourceEvidenceInspection {
                            claim: fixture.commit("rebuild", 7, &payload, &author).claim,
                        })
                        .await?
                        == SourceClaimEvidence::Unproven
                );
            }
            if let Some(before_history) = before_history {
                ensure!(state.history(&query).await?.entries == before_history);
            }
            let payload = Value::integer(9);
            ensure!(
                source
                    .commit(fixture.commit("rebuild", 7, &payload, &author))
                    .await?
                    == SourceCommitOutcome::Accepted
            );
            let current = state.read_tainted(&fixture.sink).await?;
            ensure!(current.value == Some(Value::list(vec![payload])) && current.taint == author);
        }
        let store = RedbStore::open_with_options(
            &file,
            RedbOptions {
                history,
                absence_limits: xolotl_state::AbsenceLimits {
                    records: Some(1),
                    encoded_bytes: None,
                },
                ..Default::default()
            },
        )?;
        let state = store.state_backend().into_backend();
        let other = Path::parse("state://source-budget/other")?;
        state
            .write_set_tainted(&other, Value::integer(1), author.clone())
            .await?;
        state.write_delete(&other).await?;
        ensure!(state.read(&fixture.sink).await?.is_some());
    }
    Ok(())
}

#[tokio::test]
async fn current_only_source_append_inherits_deleted_sink_provenance_after_reopen()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("source-absence.redb");
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let fixture;
    let mut expected;
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::CurrentOnly)?;
        let (state, source) = store.state_backend().into_source_parts();
        ensure!(!state.has_history());
        fixture = Fixture::install(source.as_ref()).await?;
        expected = TaintSet::of(TaintSource::Protected {
            path: fixture.sink.clone(),
        });
        let original = Value::integer(1);
        ensure!(
            source
                .commit(fixture.commit("original", 1, &original, &expected))
                .await?
                == SourceCommitOutcome::Accepted
        );
        state
            .write_delete_tainted(&fixture.sink, incoming.clone())
            .await?;
        ensure!(state.read(&fixture.sink).await?.is_none());
        expected.union(&incoming);
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::CurrentOnly)?;
    let (state, source) = store.state_backend().into_source_parts();
    ensure!(!state.has_history());
    ensure!(state.read(&fixture.sink).await?.is_none());
    let payload = Value::integer(2);
    let pristine = TaintSet::pristine();
    ensure!(
        source
            .commit(fixture.commit("next", 2, &payload, &pristine))
            .await?
            == SourceCommitOutcome::Accepted
    );
    let current = state.read_tainted(&fixture.sink).await?;
    let current_value = current
        .value
        .clone()
        .context("Source append did not recreate sink")?;
    ensure!(current_value == Value::list(vec![payload]));
    ensure!(current.taint == expected);
    Ok(())
}

#[tokio::test]
async fn source_receipt_replay_preserves_absence_without_recomputing_provenance()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("source-replay-absence.redb");
    let payload = Value::integer(1);
    let pristine = TaintSet::pristine();
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let fixture;
    let expected;
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::CurrentOnly)?;
        let (state, source) = store.state_backend().into_source_parts();
        fixture = Fixture::install(source.as_ref()).await?;
        expected = TaintSet::of(TaintSource::Protected {
            path: fixture.sink.clone(),
        });
        ensure!(
            source
                .commit(fixture.commit("accepted", 1, &payload, &pristine))
                .await?
                == SourceCommitOutcome::Accepted
        );
        state
            .write_delete_tainted(&fixture.sink, expected.clone())
            .await?;
        ensure!(state.read(&fixture.sink).await?.is_none());
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::CurrentOnly)?;
    let (state, source) = store.state_backend().into_source_parts();
    ensure!(
        source
            .commit(fixture.commit("accepted", 1, &payload, &incoming))
            .await?
            == SourceCommitOutcome::Duplicate
    );
    ensure!(state.read(&fixture.sink).await?.is_none());
    let claim = fixture.commit("accepted", 1, &payload, &pristine).claim;
    let evidence = source.inspect(SourceEvidenceInspection { claim }).await?;
    ensure!(matches!(evidence, SourceClaimEvidence::Committed(receipt)
            if receipt.claim_id == claim.claim_id
                && receipt.sink == fixture.sink
                && receipt.received_at_ms == 100));
    ensure!(
        source
            .commit(fixture.commit("next", 2, &payload, &pristine))
            .await?
            == SourceCommitOutcome::Accepted
    );
    let current = state.read_tainted(&fixture.sink).await?;
    let current_value = current
        .value
        .clone()
        .context("Source append did not recreate sink")?;
    ensure!(current_value == Value::list(vec![payload]));
    ensure!(current.taint == expected);
    Ok(())
}
