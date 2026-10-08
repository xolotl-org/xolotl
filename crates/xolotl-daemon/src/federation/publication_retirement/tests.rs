use super::*;
use crate::config::FederationStateHistoryPublicationRetirementConfig;
use xolotl_types::Path;

const PREFIX: &str = "state://federation/public/notes";
const LOCAL: FederationNodeId = FederationNodeId::from_bytes([77; 48]);

fn declaration(cursor: i64) -> FederationStateHistoryPublicationRetirementConfig {
    FederationStateHistoryPublicationRetirementConfig {
        prefix: PREFIX.into(),
        stream_id: "44".repeat(16),
        expected_cursor: cursor,
    }
}

#[test]
fn parse_preserves_exact_declaration_and_rejects_active_or_duplicate_streams() -> Result<()> {
    let mut config = FederationPublisherConfig::default();
    config
        .state_history_publication_retirements
        .push(declaration(7));
    let parsed = parse(&config, LOCAL, &HashSet::new())?;
    ensure!(parsed.len() == 1);
    let retirement = parsed.first().context("retirement missing")?;
    ensure!(retirement.expected_cursor == 7);
    ensure!(retirement.publication.prefix == Path::parse(PREFIX)?);
    ensure!(retirement.publication.stream.publisher == LOCAL);
    ensure!(retirement.publication.stream.id == StreamId::from_bytes([0x44; 16]));
    let active = HashSet::from([retirement.publication.stream.id]);
    ensure!(parse(&config, LOCAL, &active).is_err());
    let mut duplicate = declaration(8);
    duplicate.prefix = "state://federation/public/other".into();
    config.state_history_publication_retirements.push(duplicate);
    ensure!(parse(&config, LOCAL, &HashSet::new()).is_err());
    Ok(())
}

#[test]
fn parse_enforces_retirement_budget() -> Result<()> {
    let mut config = FederationPublisherConfig::default();
    for identity in 0..64 {
        let mut entry = declaration(0);
        entry.stream_id = format!("{identity:032x}");
        config.state_history_publication_retirements.push(entry);
    }
    ensure!(parse(&config, LOCAL, &HashSet::new())?.len() == 64);
    let mut excess = declaration(0);
    excess.stream_id = format!("{:032x}", 64);
    config.state_history_publication_retirements.push(excess);
    ensure!(parse(&config, LOCAL, &HashSet::new()).is_err());
    Ok(())
}

#[test]
fn parse_rejects_invalid_prefix_identity_and_terminal_cursor() -> Result<()> {
    for prefix in [
        "not a path",
        "state://federation/public",
        "state://federation/private/notes",
        "state://kernel/notes",
        "object://federation/public/notes",
    ] {
        let mut entry = declaration(0);
        entry.prefix = prefix.into();
        let config = FederationPublisherConfig {
            state_history_publication_retirements: vec![entry],
            ..FederationPublisherConfig::default()
        };
        ensure!(
            parse(&config, LOCAL, &HashSet::new()).is_err(),
            "accepted {prefix}"
        );
    }
    for identity in [
        String::new(),
        "44".repeat(15),
        "44".repeat(17),
        "gg".repeat(16),
    ] {
        let mut entry = declaration(0);
        entry.stream_id = identity;
        let config = FederationPublisherConfig {
            state_history_publication_retirements: vec![entry],
            ..FederationPublisherConfig::default()
        };
        ensure!(parse(&config, LOCAL, &HashSet::new()).is_err());
    }
    for cursor in [-1, i64::MAX] {
        let config = FederationPublisherConfig {
            state_history_publication_retirements: vec![declaration(cursor)],
            ..FederationPublisherConfig::default()
        };
        ensure!(parse(&config, LOCAL, &HashSet::new()).is_err());
    }
    for cursor in [0, i64::MAX - 1] {
        let config = FederationPublisherConfig {
            state_history_publication_retirements: vec![declaration(cursor)],
            ..FederationPublisherConfig::default()
        };
        ensure!(parse(&config, LOCAL, &HashSet::new())?.len() == 1);
    }
    Ok(())
}

#[cfg(unix)]
mod redb {
    use super::*;
    use crate::config::XolotlConfig;
    use crate::federation::{
        prepare, publish_state_history_page, reconcile_policy, start_with_objects,
        tests::{configured_publisher, test_boot_with_blocking},
    };
    use std::{num::NonZeroUsize, sync::Arc};
    use xolotl_federation::{
        EventType, ExportName, FederationError, FederationLimits, FederationStore as _,
        HistoryStart, OpenRequest, PublishRequest, ReadRequest, RequestId, SchemaRevision,
        StreamSpec, SubscriptionId, SubscriptionRef,
    };
    use xolotl_kernel::host::TokioBlockingSpawner;
    use xolotl_state::{StateHistoryTrimLimits, host::object::ObjectStore};
    use xolotl_storage_redb::{
        FederationStatePublicationStatus, RedbFederationStore, RedbHistory, RedbOptions, RedbStore,
    };
    use xolotl_types::Value;

    struct Fixture {
        db: RedbStore,
        store: RedbFederationStore,
        projection: RedbFederationStateProjection,
        service: FederationService,
        publication: StateHistoryPublication,
        peer: FederationNodeId,
        subscription: SubscriptionRef,
        workers: storage_workers::StorageWorkers,
    }

    fn options() -> Result<RedbOptions> {
        Ok(RedbOptions {
            history: RedbHistory::Full,
            federation_publish_id_limit: NonZeroUsize::new(128).context("identity limit")?,
            ..RedbOptions::default()
        })
    }

    impl Fixture {
        fn open(config: &XolotlConfig) -> Result<Self> {
            Self::open_with_options(config, options()?)
        }

        fn open_with_options(config: &XolotlConfig, settings: RedbOptions) -> Result<Self> {
            let prepared = prepare(config)?.context("publisher disabled")?;
            let publication = prepared
                .policy
                .publications
                .first()
                .context("publication")?
                .clone();
            let peer = prepared.policy.peers.first().context("peer")?.node;
            let db = RedbStore::open_with_options(&config.storage.path, settings)?;
            let store = db.federation_store(prepared.node_id())?;
            reconcile_policy(&store, &prepared.policy)?;
            let projection = db.federation_state_projection(prepared.node_id())?;
            let service =
                FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
            let subscription = SubscriptionRef {
                subscriber: peer,
                id: SubscriptionId::from_bytes([0x71; 16]),
            };
            service.open(OpenRequest {
                authenticated_subscriber: peer,
                request_id: RequestId::from_bytes([0x72; 16]),
                subscription,
                stream: publication.stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            })?;
            let workers =
                storage_workers::StorageWorkers::new(1, Arc::new(TokioBlockingSpawner::new(2)?))?;
            Ok(Self {
                db,
                store,
                projection,
                service,
                publication,
                peer,
                subscription,
                workers,
            })
        }

        async fn write(&self, value: i64) -> Result<i64> {
            self.db
                .state_backend()
                .into_backend()
                .write_set(
                    &Path::parse(&format!("{PREFIX}/item"))?,
                    Value::integer(value),
                )
                .await?;
            Ok(self.projection.high_watermark()?)
        }

        fn status(&self) -> Result<Option<FederationStatePublicationStatus>> {
            Ok(self
                .projection
                .publication_status(self.publication.stream, &self.publication.prefix)?)
        }

        fn retirement(&self, high: i64) -> Retirement {
            Retirement {
                publication: self.publication.clone(),
                expected_cursor: high,
            }
        }

        async fn retire(&self, high: i64) -> Result<usize> {
            retire(
                &self.workers,
                &self.service,
                &self.projection,
                &[self.retirement(high)],
                &[],
            )
            .await
        }

        fn payloads(&self) -> Result<Vec<Vec<u8>>> {
            self.payloads_for(self.subscription)
        }

        fn payloads_for(&self, subscription: SubscriptionRef) -> Result<Vec<Vec<u8>>> {
            let mut payloads = Vec::new();
            let mut after = None;
            loop {
                let page = self.service.read(ReadRequest {
                    authenticated_subscriber: self.peer,
                    subscription,
                    after,
                    max_records: 128,
                    max_bytes: 4 * 1024 * 1024,
                })?;
                if page.records.is_empty() {
                    break;
                }
                for record in page.records {
                    after = Some(record.position());
                    payloads.push(record.payload().to_vec());
                }
            }
            Ok(payloads)
        }

        fn history_payloads(&self, high: i64) -> Result<Vec<Vec<u8>>> {
            self.history_payloads_for(&self.publication, high)
        }

        fn history_payloads_for(
            &self,
            publication: &StateHistoryPublication,
            high: i64,
        ) -> Result<Vec<Vec<u8>>> {
            let mut payloads = Vec::new();
            let mut after = None;
            loop {
                let page =
                    self.projection
                        .history_page(&publication.prefix, 0, high, after.as_deref())?;
                ensure!(page.entries.len() <= 128);
                for entry in page.entries {
                    payloads.push(serde_json::to_vec(&entry)?);
                }
                after = page.next;
                if after.is_none() {
                    break;
                }
            }
            Ok(payloads)
        }

        fn append_first(&self, high: i64) -> Result<()> {
            self.append_first_for(&self.publication, high)
        }

        fn append_first_for(&self, publication: &StateHistoryPublication, high: i64) -> Result<()> {
            let page = self
                .projection
                .publication_page(publication.stream, &publication.prefix, high)?
                .context("pending page")?;
            ensure!(!page.entries().is_empty() && page.entries().len() <= 128);
            let entry = page.entries().first().context("first entry")?;
            self.service.append_published(PublishRequest {
                stream: publication.stream,
                retry_epoch: page.retry_epoch(),
                publish_id: RedbFederationStateProjection::publish_id(publication.stream, entry),
                event_type: EventType::new("xolotl.state.mutation.v1")?,
                schema_revision: SchemaRevision::from_bytes(
                    *blake3::hash(b"xolotl.federation.state-history-schema.v1\0").as_bytes(),
                ),
                event_ref: None,
                payload: Arc::from(serde_json::to_vec(entry)?),
            })?;
            Ok(())
        }

        fn second_publication(&self) -> Result<(StateHistoryPublication, SubscriptionRef)> {
            let publication = StateHistoryPublication {
                prefix: Path::parse("state://federation/public/other")?,
                stream: StreamRef {
                    publisher: self.publication.stream.publisher,
                    id: StreamId::from_bytes([0x55; 16]),
                },
            };
            self.store.declare_stream(StreamSpec {
                stream: publication.stream,
                export: ExportName::new("notes")?,
            })?;
            let subscription = SubscriptionRef {
                subscriber: self.peer,
                id: SubscriptionId::from_bytes([0x73; 16]),
            };
            self.service.open(OpenRequest {
                authenticated_subscriber: self.peer,
                request_id: RequestId::from_bytes([0x74; 16]),
                subscription,
                stream: publication.stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            })?;
            Ok((publication, subscription))
        }
    }

    async fn retirement_windows_contract(active_second: bool) -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let settings = RedbOptions {
            federation_publish_id_limit: NonZeroUsize::MIN,
            ..options()?
        };
        let (first_high, second_high, later, first_payloads, second_payloads) = {
            let fixture = Fixture::open_with_options(&config, settings)?;
            let (second, second_subscription) = fixture.second_publication()?;
            let first_high = fixture.write(1).await?;
            ensure!(
                fixture
                    .projection
                    .publication_page(
                        fixture.publication.stream,
                        &fixture.publication.prefix,
                        first_high,
                    )?
                    .is_some()
            );
            fixture.write(2).await?;
            let state = fixture.db.state_backend().into_backend();
            let second_path = Path::parse(&format!("{}/item", second.prefix))?;
            state.write_set(&second_path, Value::integer(10)).await?;
            let second_high = fixture.projection.high_watermark()?;
            ensure!(second_high > first_high);
            let first_payloads = fixture.history_payloads(first_high)?;
            let second_payloads = fixture.history_payloads_for(&second, second_high)?;
            ensure!(first_payloads.len() == 1 && second_payloads.len() == 1);
            fixture.append_first_for(&second, second_high)?;
            ensure!(fixture.payloads()?.is_empty());
            ensure!(fixture.payloads_for(second_subscription)? == second_payloads);
            fixture.write(999).await?;
            state.write_set(&second_path, Value::integer(888)).await?;
            let later = fixture.projection.high_watermark()?;
            ensure!(later > second_high);
            (
                first_high,
                second_high,
                later,
                first_payloads,
                second_payloads,
            )
        };
        {
            let fixture = Fixture::open_with_options(&config, settings)?;
            let (second, second_subscription) = fixture.second_publication()?;
            let first_status = Some(FederationStatePublicationStatus {
                completed_cursor: None,
                pending_high: Some(first_high),
            });
            let second_status = Some(FederationStatePublicationStatus {
                completed_cursor: None,
                pending_high: Some(second_high),
            });
            ensure!(fixture.status()? == first_status);
            ensure!(
                fixture
                    .projection
                    .publication_status(second.stream, &second.prefix)?
                    == second_status
            );
            let invalid = Retirement {
                publication: second.clone(),
                expected_cursor: second_high + 1,
            };
            let rejected = retire(
                &fixture.workers,
                &fixture.service,
                &fixture.projection,
                &[fixture.retirement(first_high), invalid],
                &[],
            )
            .await
            .err()
            .context("invalid retirement terminal accepted")?;
            ensure!(rejected.to_string().contains("retirement cursor conflict"));
            ensure!(fixture.status()? == first_status);
            ensure!(fixture.payloads()?.is_empty());
            ensure!(
                fixture
                    .store
                    .publication_epoch(fixture.publication.stream)?
                    == 1
            );
            ensure!(fixture.store.publication_epoch(second.stream)? == 1);
            let isolated = retire(
                &fixture.workers,
                &fixture.service,
                &fixture.projection,
                &[fixture.retirement(first_high)],
                &[],
            )
            .await
            .err()
            .context("unconfigured capacity owner was recovered")?;
            ensure!(matches!(
                isolated.downcast_ref::<FederationError>(),
                Some(FederationError::Capacity)
            ));
            ensure!(fixture.status()? == first_status);
            ensure!(fixture.payloads()?.is_empty());
            ensure!(fixture.payloads_for(second_subscription)? == second_payloads);
            ensure!(
                fixture
                    .projection
                    .publication_status(second.stream, &second.prefix)?
                    == second_status
            );
            let mut mismatched = second.clone();
            mismatched.prefix = Path::parse("state://federation/public/mismatched")?;
            let rejected = retire(
                &fixture.workers,
                &fixture.service,
                &fixture.projection,
                &[fixture.retirement(first_high)],
                &[mismatched],
            )
            .await
            .err()
            .context("mismatched active pin prefix was ignored")?;
            ensure!(matches!(
                rejected.downcast_ref::<FederationError>(),
                Some(FederationError::Conflict)
            ));
            ensure!(fixture.status()? == first_status);
            ensure!(fixture.payloads()?.is_empty());
            let unstarted = StateHistoryPublication {
                prefix: Path::parse("state://federation/public/unstarted")?,
                stream: StreamRef {
                    publisher: fixture.publication.stream.publisher,
                    id: StreamId::from_bytes([0x56; 16]),
                },
            };
            fixture.store.declare_stream(StreamSpec {
                stream: unstarted.stream,
                export: ExportName::new("notes")?,
            })?;
            let undeclared = StateHistoryPublication {
                prefix: Path::parse("state://federation/public/undeclared")?,
                stream: StreamRef {
                    publisher: fixture.publication.stream.publisher,
                    id: StreamId::from_bytes([0x57; 16]),
                },
            };
            let mut retirements = vec![fixture.retirement(first_high)];
            let active = if active_second {
                vec![second.clone(), unstarted.clone(), undeclared.clone()]
            } else {
                retirements.push(Retirement {
                    publication: second.clone(),
                    expected_cursor: second_high,
                });
                Vec::new()
            };
            ensure!(
                retire(
                    &fixture.workers,
                    &fixture.service,
                    &fixture.projection,
                    &retirements,
                    &active,
                )
                .await?
                    == if active_second { 1 } else { 2 }
            );
            ensure!(fixture.status()?.is_none());
            ensure!(fixture.payloads()? == first_payloads);
            ensure!(fixture.payloads_for(second_subscription)? == second_payloads);
            ensure!(
                fixture
                    .store
                    .publication_epoch(fixture.publication.stream)?
                    > 1
            );
            ensure!(fixture.store.publication_epoch(second.stream)? > 1);
            ensure!(
                fixture
                    .projection
                    .publication_status(second.stream, &second.prefix)?
                    == if active_second {
                        Some(FederationStatePublicationStatus {
                            completed_cursor: Some(second_high),
                            pending_high: None,
                        })
                    } else {
                        None
                    }
            );
            ensure!(
                fixture
                    .projection
                    .publication_status(unstarted.stream, &unstarted.prefix)?
                    .is_none()
            );
            ensure!(fixture.store.publication_epoch(unstarted.stream)? == 1);
            ensure!(matches!(
                fixture
                    .projection
                    .publication_status(undeclared.stream, &undeclared.prefix),
                Err(FederationError::NotFound)
            ));
            ensure!(matches!(
                fixture.store.publication_epoch(undeclared.stream),
                Err(FederationError::NotFound)
            ));
            let trim = fixture
                .db
                .state_backend()
                .into_backend()
                .trim_history_before(later + 1, StateHistoryTrimLimits::default())
                .await;
            if active_second {
                ensure!(trim.is_err(), "active publisher pin was released");
            } else {
                trim?;
            }
        }
        let fixture = Fixture::open_with_options(&config, settings)?;
        let (second, second_subscription) = fixture.second_publication()?;
        ensure!(fixture.status()?.is_none());
        ensure!(fixture.payloads()? == first_payloads);
        ensure!(fixture.payloads_for(second_subscription)? == second_payloads);
        ensure!(
            fixture
                .projection
                .publication_status(second.stream, &second.prefix)?
                == if active_second {
                    Some(FederationStatePublicationStatus {
                        completed_cursor: Some(second_high),
                        pending_high: None,
                    })
                } else {
                    None
                }
        );
        Ok(())
    }

    #[tokio::test]
    async fn single_slot_retired_windows_reopen_and_settle_without_extending_terminal_cursors()
    -> Result<()> {
        retirement_windows_contract(false).await
    }

    #[tokio::test]
    async fn single_slot_retired_and_active_windows_reopen_without_releasing_active_pin()
    -> Result<()> {
        retirement_windows_contract(true).await
    }

    #[tokio::test]
    async fn completed_pin_release_enables_trim_and_remains_retired_after_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let high = {
            let fixture = Fixture::open(&config)?;
            let high = fixture.write(1).await?;
            let page = publish_state_history_page(
                &fixture.service,
                &fixture.projection,
                &fixture.publication,
                high,
            )?;
            ensure!(page.complete && page.published == 1);
            ensure!(
                fixture.status()?
                    == Some(FederationStatePublicationStatus {
                        completed_cursor: Some(high),
                        pending_high: None,
                    })
            );
            let later = fixture.write(2).await?;
            let state = fixture.db.state_backend().into_backend();
            ensure!(
                state
                    .trim_history_before(later + 1, StateHistoryTrimLimits::default())
                    .await
                    .is_err()
            );
            let payloads = fixture.payloads()?;
            ensure!(fixture.retire(high).await? == 1);
            ensure!(fixture.status()?.is_none());
            ensure!(fixture.payloads()? == payloads);
            ensure!(fixture.retire(high).await? == 0);
            state
                .trim_history_before(later + 1, StateHistoryTrimLimits::default())
                .await?;
            high
        };
        let fixture = Fixture::open(&config)?;
        ensure!(fixture.status()?.is_none());
        ensure!(fixture.payloads()?.len() == 1);
        ensure!(fixture.retire(high).await? == 0);
        ensure!(matches!(
            fixture.projection.publication_page(
                fixture.publication.stream,
                &fixture.publication.prefix,
                fixture.projection.high_watermark()?,
            ),
            Err(FederationError::Conflict)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn partially_appended_window_reopens_and_settles_only_its_fixed_high() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let (completed, high, expected) = {
            let fixture = Fixture::open(&config)?;
            let completed = fixture.write(0).await?;
            ensure!(
                publish_state_history_page(
                    &fixture.service,
                    &fixture.projection,
                    &fixture.publication,
                    completed
                )?
                .complete
            );
            for value in 1..=257 {
                fixture.write(value).await?;
            }
            let high = fixture.projection.high_watermark()?;
            let expected = fixture.history_payloads(high)?;
            ensure!(expected.len() == 258);
            fixture.append_first(high)?;
            ensure!(fixture.payloads()?.len() == 2);
            ensure!(
                fixture.status()?
                    == Some(FederationStatePublicationStatus {
                        completed_cursor: Some(completed),
                        pending_high: Some(high),
                    })
            );
            ensure!(fixture.write(999).await? > high);
            (completed, high, expected)
        };
        {
            let fixture = Fixture::open(&config)?;
            ensure!(fixture.projection.high_watermark()? > high);
            ensure!(
                fixture.status()?
                    == Some(FederationStatePublicationStatus {
                        completed_cursor: Some(completed),
                        pending_high: Some(high),
                    })
            );
            let state = fixture.db.state_backend().into_backend();
            ensure!(
                state
                    .trim_history_before(high + 1, StateHistoryTrimLimits::default())
                    .await
                    .is_err()
            );
            ensure!(fixture.retire(high).await? == 1);
            ensure!(
                fixture.payloads()? == expected,
                "settlement duplicated, omitted, reordered or extended the original window"
            );
            ensure!(fixture.status()?.is_none());
            state
                .trim_history_before(
                    fixture.projection.high_watermark()? + 1,
                    StateHistoryTrimLimits::default(),
                )
                .await?;
        }
        let fixture = Fixture::open(&config)?;
        ensure!(fixture.payloads()? == expected);
        ensure!(fixture.status()?.is_none());
        ensure!(matches!(
            fixture.projection.publication_page(
                fixture.publication.stream,
                &fixture.publication.prefix,
                high,
            ),
            Err(FederationError::Conflict)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn wrong_prefix_or_cursor_rejects_without_append_epoch_or_pin_changes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let fixture = Fixture::open(&config)?;
        let completed = fixture.write(0).await?;
        ensure!(
            publish_state_history_page(
                &fixture.service,
                &fixture.projection,
                &fixture.publication,
                completed
            )?
            .complete
        );
        for pending in [false, true] {
            let high = if pending {
                let high = fixture.write(1).await?;
                fixture.write(2).await?;
                let high = fixture.projection.high_watermark()?.max(high);
                fixture.append_first(high)?;
                high
            } else {
                completed
            };
            let status = fixture.status()?;
            let payloads = fixture.payloads()?;
            let epoch = fixture
                .store
                .publication_epoch(fixture.publication.stream)?;
            let mut wrong_prefix = fixture.retirement(high);
            wrong_prefix.publication.prefix = Path::parse("state://federation/public/other")?;
            for invalid in [
                wrong_prefix,
                fixture.retirement(high + 1),
                fixture.retirement(high - 1),
            ] {
                ensure!(
                    retire(
                        &fixture.workers,
                        &fixture.service,
                        &fixture.projection,
                        &[invalid],
                        &[],
                    )
                    .await
                    .is_err()
                );
                ensure!(fixture.status()? == status);
                ensure!(fixture.payloads()? == payloads);
                ensure!(
                    fixture
                        .store
                        .publication_epoch(fixture.publication.stream)?
                        == epoch
                );
            }
            if pending {
                ensure!(fixture.retire(completed).await.is_err());
                ensure!(fixture.status()? == status);
                ensure!(fixture.payloads()? == payloads);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn absent_pin_is_not_completeness_and_unknown_stream_is_not_found() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let fixture = Fixture::open(&config)?;
        let high = fixture.write(1).await?;
        ensure!(fixture.status()?.is_none());
        ensure!(fixture.retire(high).await? == 0);
        ensure!(fixture.retire(high + 100).await? == 0);
        ensure!(fixture.status()?.is_none());
        ensure!(fixture.payloads()?.is_empty());
        ensure!(
            fixture
                .store
                .publication_epoch(fixture.publication.stream)?
                == 1
        );
        let mut unknown = fixture.retirement(high);
        unknown.publication.stream.id = StreamId::from_bytes([0x99; 16]);
        let failure = retire(
            &fixture.workers,
            &fixture.service,
            &fixture.projection,
            &[unknown],
            &[],
        )
        .await
        .err()
        .context("unknown stream accepted as absent")?;
        ensure!(matches!(
            failure.downcast_ref::<FederationError>(),
            Some(FederationError::NotFound)
        ));
        ensure!(fixture.payloads()?.is_empty());
        ensure!(fixture.status()?.is_none());
        ensure!(
            fixture
                .projection
                .publication_page(
                    fixture.publication.stream,
                    &fixture.publication.prefix,
                    high
                )?
                .is_some()
        );
        ensure!(
            fixture.status()?
                == Some(FederationStatePublicationStatus {
                    completed_cursor: None,
                    pending_high: Some(high),
                })
        );
        Ok(())
    }

    #[tokio::test]
    async fn stale_pending_epoch_rejects_without_settlement_or_release_after_reopen() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let high = {
            let fixture = Fixture::open(&config)?;
            let high = fixture.write(1).await?;
            fixture.write(2).await?;
            let high = fixture.projection.high_watermark()?.max(high);
            fixture.append_first(high)?;
            fixture
                .store
                .close_publication_epoch(fixture.publication.stream, 1)?;
            high
        };
        let fixture = Fixture::open(&config)?;
        let payloads = fixture.payloads()?;
        ensure!(payloads.len() == 1);
        let failure = fixture
            .retire(high)
            .await
            .err()
            .context("stale window accepted")?;
        ensure!(matches!(
            failure.downcast_ref::<FederationError>(),
            Some(FederationError::Conflict)
        ));
        ensure!(fixture.payloads()? == payloads);
        ensure!(
            fixture
                .store
                .publication_epoch(fixture.publication.stream)?
                == 2
        );
        ensure!(matches!(
            fixture
                .projection
                .publication_status(fixture.publication.stream, &fixture.publication.prefix),
            Err(FederationError::Conflict)
        ));
        ensure!(
            fixture
                .projection
                .release_publication(
                    fixture.publication.stream,
                    &fixture.publication.prefix,
                    high
                )
                .is_err()
        );
        ensure!(
            fixture
                .db
                .state_backend()
                .into_backend()
                .trim_history_before(high + 1, StateHistoryTrimLimits::default())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn stock_start_requires_explicit_retirement_instead_of_inferring_removed_source()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        let fixture = Fixture::open(&config)?;
        let high = fixture.write(1).await?;
        fixture.append_first(high)?;
        let later = fixture.write(2).await?;
        let original = fixture.payloads()?;
        config.federation.state_history_publications.clear();
        config.federation.streams.clear();
        let blocking = Arc::new(TokioBlockingSpawner::new(4)?);
        for explicit in [false, true] {
            if explicit {
                config.server.federation_grpc_addr = None;
                config.federation.streams.clear();
                config
                    .federation
                    .state_history_publication_retirements
                    .push(declaration(high));
            }
            let mut prepared = prepare(&config)?.context("publisher disabled")?;
            ensure!(prepared.needs_projection() == explicit);
            prepared.address = None;
            let listener = start_with_objects(
                prepared,
                fixture.store.clone(),
                Some(fixture.projection.clone()),
                test_boot_with_blocking(
                    fixture.db.state_backend().into_backend(),
                    blocking.clone(),
                ),
                ObjectStore::new(),
            )
            .await?;
            listener.task.abort();
            ensure!(
                listener
                    .task
                    .await
                    .err()
                    .is_some_and(|error| error.is_cancelled())
            );
            listener.runtime.shutdown().await;
            blocking.wait_idle().await;
            ensure!(fixture.payloads()? == original);
            let state = fixture.db.state_backend().into_backend();
            if explicit {
                ensure!(fixture.status()?.is_none());
                state
                    .trim_history_before(later + 1, StateHistoryTrimLimits::default())
                    .await?;
            } else {
                ensure!(
                    fixture.status()?
                        == Some(FederationStatePublicationStatus {
                            completed_cursor: None,
                            pending_high: Some(high),
                        })
                );
                ensure!(
                    state
                        .trim_history_before(later + 1, StateHistoryTrimLimits::default())
                        .await
                        .is_err()
                );
                ensure!(
                    retire(
                        &fixture.workers,
                        &fixture.service,
                        &fixture.projection,
                        &[],
                        &[]
                    )
                    .await?
                        == 0
                );
                ensure!(fixture.status()?.is_some());
            }
        }
        blocking.close();
        blocking.wait_idle().await;
        Ok(())
    }

    #[tokio::test]
    async fn stock_retirement_accepts_retained_stream_but_never_creates_unknown_stream()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        let fixture = Fixture::open(&config)?;
        let high = fixture.write(1).await?;
        fixture.append_first(high)?;
        config.server.federation_grpc_addr = None;
        config.federation.state_history_publications.clear();
        config
            .federation
            .state_history_publication_retirements
            .push(declaration(high));
        let prepared = prepare(&config)?.context("retained declared retirement disabled")?;
        ensure!(prepared.needs_projection());
        let blocking = Arc::new(TokioBlockingSpawner::new(4)?);
        let listener = start_with_objects(
            prepared,
            fixture.store.clone(),
            Some(fixture.projection.clone()),
            test_boot_with_blocking(fixture.db.state_backend().into_backend(), blocking.clone()),
            ObjectStore::new(),
        )
        .await?;
        listener.task.abort();
        ensure!(
            listener
                .task
                .await
                .err()
                .is_some_and(|error| error.is_cancelled())
        );
        listener.runtime.shutdown().await;
        blocking.wait_idle().await;
        ensure!(fixture.status()?.is_none());
        ensure!(fixture.payloads()?.len() == 1);

        let unknown = StreamRef {
            publisher: fixture.publication.stream.publisher,
            id: StreamId::from_bytes([0x99; 16]),
        };
        config
            .federation
            .streams
            .first_mut()
            .context("stream declaration")?
            .id = "99".repeat(16);
        config
            .federation
            .state_history_publication_retirements
            .first_mut()
            .context("retirement declaration")?
            .stream_id = "99".repeat(16);
        let prepared = prepare(&config)?.context("unknown declared retirement disabled")?;
        ensure!(prepared.needs_projection());
        ensure!(matches!(
            fixture.store.publication_epoch(unknown),
            Err(FederationError::NotFound)
        ));
        let failed = start_with_objects(
            prepared,
            fixture.store.clone(),
            Some(fixture.projection.clone()),
            test_boot_with_blocking(fixture.db.state_backend().into_backend(), blocking.clone()),
            ObjectStore::new(),
        )
        .await;
        let failure = match failed {
            Err(failure) => failure,
            Ok(listener) => {
                listener.task.abort();
                let _outcome = listener.task.await;
                listener.runtime.shutdown().await;
                anyhow::bail!("startup created an unknown retired stream")
            }
        };
        ensure!(matches!(
            failure.downcast_ref::<FederationError>(),
            Some(FederationError::NotFound)
        ));
        blocking.wait_idle().await;
        ensure!(matches!(
            fixture.store.publication_epoch(unknown),
            Err(FederationError::NotFound)
        ));
        ensure!(matches!(
            fixture
                .projection
                .publication_status(unknown, &fixture.publication.prefix),
            Err(FederationError::NotFound)
        ));
        ensure!(fixture.payloads()?.len() == 1);
        ensure!(fixture.status()?.is_none());
        blocking.close();
        blocking.wait_idle().await;
        Ok(())
    }
}
