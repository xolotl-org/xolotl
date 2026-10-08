use std::ops::Deref;

use super::*;

pub(crate) struct DecisionWrite {
    transaction: Option<WriteTransaction>,
    savepoint: Option<redb::Savepoint>,
}

impl Deref for DecisionWrite {
    type Target = WriteTransaction;

    #[expect(
        clippy::expect_used,
        reason = "only an active decision exposes its transaction"
    )]
    fn deref(&self) -> &Self::Target {
        self.transaction
            .as_ref()
            .expect("decision transaction already committed")
    }
}

impl DecisionWrite {
    pub(crate) fn new(transaction: WriteTransaction) -> Self {
        Self {
            transaction: Some(transaction),
            savepoint: None,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a decision commits its transaction only once"
    )]
    pub(crate) fn commit(&mut self) -> Result<(), redb::CommitError> {
        drop(self.savepoint.take());
        self.transaction
            .take()
            .expect("decision transaction already committed")
            .commit()
    }
}

fn observe_time(txn: &WriteTransaction, now_ms: u64) -> Result<bool, FederationError> {
    let mut table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
    let previous = table
        .get(TRUSTED_TIME_KEY)
        .map_err(storage)?
        .map(|value| decode_trusted_time(value.value()))
        .transpose()?;
    if previous.is_some_and(|previous| now_ms < previous) {
        return Err(FederationError::ClockRollback);
    }
    if previous == Some(now_ms) {
        return Ok(false);
    }
    table
        .insert(TRUSTED_TIME_KEY, now_ms.to_be_bytes().as_slice())
        .map_err(storage)?;
    Ok(true)
}

impl RedbFederationStore {
    /// Delivery samples the bound trusted clock against the current durable
    /// floor and authority snapshot. It never advances that floor or acquires
    /// the writer. Unbound local callers supply decision time; zero denotes a
    /// timeless metadata check and uses the existing floor, not a new clock.
    pub(crate) fn begin_delivery_read(
        &self,
        fallback_ms: u64,
    ) -> Result<(ReadTransaction, u64), FederationError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let now_ms = if let Some(decision) = &self.decision {
            let now_ms = decision.now_ms()?;
            check_decision_rows!(self, txn, now_ms);
            now_ms
        } else {
            let floor = txn
                .open_table(FEDERATION_NODE_TABLE)
                .map_err(storage)?
                .get(TRUSTED_TIME_KEY)
                .map_err(storage)?
                .map(|value| decode_trusted_time(value.value()))
                .transpose()?
                .unwrap_or(0);
            let now_ms = if fallback_ms == 0 { floor } else { fallback_ms };
            if now_ms < floor {
                return Err(FederationError::ClockRollback);
            }
            now_ms
        };
        Ok((txn, now_ms))
    }

    /// Sample and retain trusted time after acquiring the database writer.
    /// The callback must be fast and must not reenter this database.
    pub fn sample_time_ms(
        &self,
        sample: impl FnOnce() -> Result<u64, FederationError>,
    ) -> Result<u64, FederationError> {
        let txn = self.db.begin_write().map_err(storage)?;
        let now_ms = sample()?;
        if observe_time(&txn, now_ms)? {
            txn.commit()
                .map_err(|_error| FederationError::TrustedTimeUnavailable)?;
        }
        Ok(now_ms)
    }

    pub(crate) fn begin_decision_read(
        &self,
    ) -> Result<(ReadTransaction, Option<u64>), FederationError> {
        if self.decision.is_none() && self.local_clock.is_none() {
            return Ok((self.db.begin_read().map_err(storage)?, None));
        }
        let writer = self.db.begin_write().map_err(storage)?;
        let txn = self.db.begin_read().map_err(storage)?;
        let now_ms = if let Some(decision) = &self.decision {
            decision.now_ms()?
        } else {
            self.local_clock
                .as_ref()
                .ok_or(FederationError::Corrupt)?
                .now_ms()?
        };
        let changed = observe_time(&writer, now_ms)?;
        let checked = (|| {
            if self.decision.is_some() {
                check_decision_rows!(self, txn, now_ms);
            }
            Ok(())
        })();
        if changed {
            writer
                .commit()
                .map_err(|_error| FederationError::TrustedTimeUnavailable)?;
        }
        checked?;
        Ok((txn, Some(now_ms)))
    }

    pub(crate) fn with_decision_write<Output>(
        &self,
        operation: impl FnOnce(&mut DecisionWrite, Option<u64>) -> Result<Output, FederationError>,
    ) -> Result<Output, FederationError> {
        let transaction = self.db.begin_write().map_err(storage)?;
        if self.decision.is_none() && self.local_clock.is_none() {
            return operation(&mut DecisionWrite::new(transaction), None);
        }
        let now_ms = if let Some(decision) = &self.decision {
            decision.now_ms()?
        } else {
            self.local_clock
                .as_ref()
                .ok_or(FederationError::Corrupt)?
                .now_ms()?
        };
        let snapshot = self.db.begin_read().map_err(storage)?;
        let previous = snapshot
            .open_table(FEDERATION_NODE_TABLE)
            .map_err(storage)?
            .get(TRUSTED_TIME_KEY)
            .map_err(storage)?
            .map(|value| decode_trusted_time(value.value()))
            .transpose()?;
        let changed = previous != Some(now_ms);
        let checked = (|| {
            if self.decision.is_some() {
                check_decision_rows!(self, snapshot, now_ms);
            }
            Ok(())
        })();
        drop(snapshot);
        if let Err(error) = checked {
            if changed {
                observe_time(&transaction, now_ms)?;
                transaction
                    .commit()
                    .map_err(|_error| FederationError::TrustedTimeUnavailable)?;
            }
            return Err(error);
        }
        let savepoint = if changed {
            let savepoint = transaction.ephemeral_savepoint().map_err(storage)?;
            observe_time(&transaction, now_ms)?;
            Some(savepoint)
        } else {
            None
        };
        let mut txn = DecisionWrite {
            transaction: Some(transaction),
            savepoint,
        };
        let result = operation(&mut txn, Some(now_ms));
        if let Some(savepoint) = txn.savepoint.take()
            && let Some(mut transaction) = txn.transaction.take()
        {
            transaction
                .restore_savepoint(&savepoint)
                .map_err(|_error| FederationError::TrustedTimeUnavailable)?;
            drop(savepoint);
            observe_time(&transaction, now_ms)
                .map_err(|_error| FederationError::TrustedTimeUnavailable)?;
            transaction
                .commit()
                .map_err(|_error| FederationError::TrustedTimeUnavailable)?;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, ensure};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use xolotl_federation::{
        FederationAdmission, FederationDecision, FederationOnlineKey,
        FederationOnlineKeyAuthorization, FederationRootKey, FederationSessionTranscript,
        RootSignaturePurpose, verify_federation_peer_proof,
    };

    fn proof(local: FederationNodeId) -> Result<VerifiedFederationPeerProof> {
        let root = FederationRootKey::generate()?;
        let descriptor = root.root()?;
        let peer = descriptor.node_id();
        let online = FederationOnlineKey::generate()?;
        let authorization =
            FederationOnlineKeyAuthorization::new(online.public_key(), 1, 100, 1000)?;
        let transcript =
            FederationSessionTranscript::new(peer, local, [1; 32], [2; 32], [3; 48], [4; 48])?;
        let root_signature = root.sign(
            RootSignaturePurpose::OnlineKeyAuthorization,
            &authorization.encode(),
        )?;
        let online_signature = online.sign_session(peer, &authorization, &transcript)?;
        let proof = verify_federation_peer_proof(
            &descriptor,
            peer,
            &authorization,
            &root_signature,
            &transcript,
            &online_signature,
            150,
        )?;
        Ok(proof)
    }

    #[test]
    fn local_clock_is_sampled_after_the_writer_and_preserves_rollback_rejection() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("local-clock.redb"))?;
        let store = db.federation_store(FederationNodeId::from_bytes([87; NODE_ID_LEN]))?;
        store.checked_time_ms(150)?;
        let time = Arc::new(AtomicU64::new(150));
        let sampled = Arc::new(AtomicBool::new(false));
        let clock_time = Arc::clone(&time);
        let clock_sampled = Arc::clone(&sampled);
        let local = store.with_local_clock(Arc::new(move || {
            clock_sampled.store(true, Ordering::SeqCst);
            Ok(clock_time.load(Ordering::SeqCst))
        }))?;
        let writer = store.db.begin_write()?;
        let reader = local.clone();
        let (started, waiting) = std::sync::mpsc::channel();
        let (finished, completion) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            started
                .send(())
                .map_err(|_error| FederationError::Corrupt)?;
            let result = reader.with_decision_write(|txn, now| {
                let now = now.ok_or(FederationError::Corrupt)?;
                txn.commit()
                    .map_err(|_error| FederationError::Indeterminate)?;
                Ok(now)
            });
            finished
                .send(())
                .map_err(|_error| FederationError::Corrupt)?;
            result
        });
        waiting.recv_timeout(std::time::Duration::from_secs(5))?;
        ensure!(matches!(
            completion.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        ensure!(!sampled.load(Ordering::SeqCst));
        observe_time(&writer, 200)?;
        time.store(210, Ordering::SeqCst);
        writer.commit()?;
        ensure!(
            task.join()
                .map_err(|_error| anyhow::anyhow!("local-clock worker panicked"))??
                == 210
        );
        time.store(209, Ordering::SeqCst);
        ensure!(matches!(
            local.begin_decision_read(),
            Err(FederationError::ClockRollback)
        ));
        ensure!(matches!(
            local.with_decision_write(|_, _| Ok(())),
            Err(FederationError::ClockRollback)
        ));
        Ok(())
    }

    #[test]
    fn delivery_reads_preserve_durable_floor_and_do_not_wait_for_writer() -> Result<()> {
        let local = FederationNodeId::from_bytes([79; NODE_ID_LEN]);
        let proof = proof(local)?;
        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("delivery-clock.redb"))?;
        let store = db.federation_store(local)?;
        store.checked_time_ms(150)?;
        let time = Arc::new(AtomicU64::new(170));
        let clock = Arc::clone(&time);
        let bound = store.with_decision(FederationDecision::new(
            proof,
            FederationAdmission::Unconfigured,
            Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
        ))?;
        let writer = store.db.begin_write()?;
        let reader = bound.clone();
        let (complete, completed) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let result = (|| -> Result<(u64, u64)> {
                let (snapshot, now) = reader.begin_delivery_read(0)?;
                let table = snapshot.open_table(FEDERATION_NODE_TABLE)?;
                let saved = table
                    .get(TRUSTED_TIME_KEY)?
                    .ok_or_else(|| anyhow::anyhow!("clock floor missing"))?;
                Ok((now, decode_trusted_time(saved.value())?))
            })();
            drop(complete.send(result));
        });
        let without_writer = completed.recv_timeout(std::time::Duration::from_secs(5));
        drop(writer);
        task.join()
            .map_err(|_error| anyhow::anyhow!("delivery reader panicked"))?;
        ensure!(without_writer?? == (170, 150));
        time.store(149, Ordering::SeqCst);
        ensure!(matches!(
            bound.begin_delivery_read(0),
            Err(FederationError::ClockRollback)
        ));
        time.store(1000, Ordering::SeqCst);
        ensure!(matches!(
            bound.begin_delivery_read(0),
            Err(FederationError::Unauthorized)
        ));
        time.store(170, Ordering::SeqCst);
        store.set_peer_authority(proof.node_id(), None, false)?;
        ensure!(matches!(
            bound.begin_delivery_read(0),
            Err(FederationError::Unauthorized)
        ));
        ensure!(store.checked_time_ms(150)? == 150);
        Ok(())
    }

    #[test]
    fn optionless_bound_view_uses_persisted_publish_quota() -> Result<()> {
        let local = FederationNodeId::from_bytes([72; NODE_ID_LEN]);
        let directory = tempfile::tempdir()?;
        let storage = crate::RedbStore::open_with_options(
            directory.path().join("optionless-publish-quota.redb"),
            crate::RedbOptions {
                federation_publish_id_limit: NonZeroUsize::MIN,
                ..crate::RedbOptions::default()
            },
        )?;
        let store = storage.federation_store(local)?;
        let proof = proof(local)?;
        let bound = RedbFederationStore::bound_view(
            Arc::clone(&store.db),
            local,
            FederationDecision::new(
                proof,
                FederationAdmission::Unconfigured,
                Arc::new(|| Ok(500)),
            ),
        )?;
        let stream = StreamRef {
            publisher: local,
            id: StreamId::from_bytes([1; 16]),
        };
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("quota")?,
        })?;
        let request = PublishRequest {
            retry_epoch: 1,
            stream,
            publish_id: RequestId::from_bytes([1; 16]),
            event_type: EventType::new("quota.event")?,
            schema_revision: SchemaRevision::from_bytes([2; 32]),
            event_ref: None,
            payload: Arc::from(b"first".as_slice()),
        };
        let first = store.append_published(request.clone())?;
        ensure!(bound.append_published(request.clone())? == first);
        let mut rejected = request;
        rejected.publish_id = RequestId::from_bytes([2; 16]);
        ensure!(matches!(
            bound.append_published(rejected),
            Err(FederationError::Capacity)
        ));
        Ok(())
    }

    #[test]
    fn abandoned_business_changes_are_removed_before_observed_time_is_committed() -> Result<()> {
        let local = FederationNodeId::from_bytes([71; NODE_ID_LEN]);
        let proof = proof(local)?;
        let peer = proof.node_id();
        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("abandoned-business.redb"))?;
        let store = db.federation_store(local)?;
        store.set_peer_authority(peer, None, true)?;
        store.set_peer_admission(
            peer,
            None,
            PeerAdmission {
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![proof.authorization_digest()],
            },
        )?;
        let time = Arc::new(AtomicU64::new(500));
        let clock = Arc::clone(&time);
        let remote = store.with_decision(FederationDecision::new(
            proof,
            FederationAdmission::Private,
            Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
        ))?;
        for reject in [true, false] {
            let now_ms = time.fetch_add(1, Ordering::SeqCst) + 1;
            let result = remote.with_decision_write(|txn, _| {
                txn.open_table(FEDERATION_PEERS_TABLE)
                    .map_err(storage)?
                    .insert(
                        peer.as_bytes().as_slice(),
                        encode(&PeerRow {
                            revision: 2,
                            enabled: false,
                            control_revision: 0,
                            manifest_owned: false,
                        })?
                        .as_slice(),
                    )
                    .map_err(storage)?;
                if reject {
                    Err(FederationError::Conflict)
                } else {
                    Ok(())
                }
            });
            if reject {
                ensure!(matches!(result, Err(FederationError::Conflict)));
            } else {
                result?;
            }
            ensure!(store.peer_authority(peer)? == Some((1, true)));
            ensure!(matches!(
                store.checked_time_ms(now_ms - 1),
                Err(FederationError::ClockRollback)
            ));
        }
        Ok(())
    }

    #[derive(Debug)]
    struct FailingSync {
        backend: redb::backends::InMemoryBackend,
        fail: Arc<AtomicBool>,
    }

    impl redb::StorageBackend for FailingSync {
        fn len(&self) -> std::io::Result<u64> {
            self.backend.len()
        }
        fn read(&self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
            self.backend.read(offset, output)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.backend.set_len(len)
        }
        fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.backend.write(offset, bytes)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            if self.fail.load(Ordering::SeqCst) {
                Err(std::io::Error::other("injected trusted-time sync failure"))
            } else {
                self.backend.sync_data()
            }
        }
    }

    #[test]
    fn time_only_sync_failures_are_distinct_from_uncertain_business_commits() -> Result<()> {
        let local = FederationNodeId::from_bytes([71; NODE_ID_LEN]);
        let proof = proof(local)?;
        let peer = proof.node_id();
        for (admitted, business_commit) in [(false, false), (true, false), (true, true)] {
            let fail = Arc::new(AtomicBool::new(false));
            let db = Arc::new(Database::new(
                redb::Database::builder().create_with_backend(FailingSync {
                    backend: redb::backends::InMemoryBackend::new(),
                    fail: Arc::clone(&fail),
                })?,
            ));
            let store = RedbFederationStore::bind(
                Arc::clone(&db),
                local,
                NonZeroUsize::MIN.saturating_add(65_535),
            )?;
            store.set_peer_authority(peer, None, true)?;
            store.set_peer_admission(
                peer,
                None,
                PeerAdmission {
                    minimum_online_generation: 1,
                    allowed_authorization_digests: vec![proof.authorization_digest()],
                },
            )?;
            let remote = store.with_decision(FederationDecision::new(
                proof,
                FederationAdmission::Private,
                Arc::new(move || Ok(if admitted { 500 } else { 1200 })),
            ))?;
            fail.store(true, Ordering::SeqCst);
            let mut invoked = false;
            let result = remote.with_decision_write(|txn, _| {
                invoked = true;
                txn.open_table(FEDERATION_PEERS_TABLE)
                    .map_err(storage)?
                    .insert(
                        peer.as_bytes().as_slice(),
                        encode(&PeerRow {
                            revision: 2,
                            enabled: false,
                            control_revision: 0,
                            manifest_owned: false,
                        })?
                        .as_slice(),
                    )
                    .map_err(storage)?;
                if business_commit {
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)
                } else {
                    Err(FederationError::Conflict)
                }
            });
            ensure!(invoked == admitted);
            if business_commit {
                ensure!(matches!(result, Err(FederationError::Indeterminate)));
            } else {
                ensure!(matches!(
                    result,
                    Err(FederationError::TrustedTimeUnavailable)
                ));
            }
            ensure!(
                db.begin_write().is_err(),
                "failed storage admitted another writer"
            );
            ensure!(remote.peer_authority(peer).is_err());
        }
        Ok(())
    }

    #[test]
    fn queued_time_sampling_occurs_after_the_previous_writer_commits() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = crate::RedbStore::open(directory.path().join("queued-time.redb"))?;
        let store = db.federation_store(FederationNodeId::from_bytes([71; NODE_ID_LEN]))?;
        let writer = db.db.begin_write()?;
        let time = Arc::new(AtomicU64::new(100));
        let clock = Arc::clone(&time);
        let queued_store = store.clone();
        let (started, queued) = std::sync::mpsc::channel();
        let (sampled, observed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || -> Result<u64, FederationError> {
            started.send(()).map_err(storage)?;
            queued_store.sample_time_ms(|| {
                let now_ms = clock.load(Ordering::SeqCst);
                sampled.send(now_ms).map_err(storage)?;
                Ok(now_ms)
            })
        });
        queued.recv()?;
        ensure!(
            matches!(
                observed.recv_timeout(std::time::Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "clock sampled before acquiring the writer"
        );
        observe_time(&writer, 300)?;
        time.store(300, Ordering::SeqCst);
        writer.commit()?;
        ensure!(
            worker
                .join()
                .map_err(|_error| anyhow::anyhow!("clock worker panicked"))??
                == 300
        );
        ensure!(observed.recv()? == 300);
        ensure!(matches!(
            store.checked_time_ms(299),
            Err(FederationError::ClockRollback)
        ));
        Ok(())
    }
}
