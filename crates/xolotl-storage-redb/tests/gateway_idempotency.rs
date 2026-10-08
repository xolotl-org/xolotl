#![cfg(feature = "gateway")]

use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use anyhow::{Context as _, ensure};
use redb::{ReadableDatabase, TableDefinition};
use xolotl_gateway::{
    Gateway, GatewayError, GatewayIdempotencyLimits, GatewayIdempotencyRecord,
    GatewayIdempotencyStore, GatewayIdempotencyUsage, GatewayPrincipalSurfaceBinding,
    GatewayProfile, GatewayRuntime, GatewaySession, GatewaySubmission, GatewaySurface,
    PresentedCredential, SubmitOptions, gateway_idempotency_acceptance,
};
use xolotl_kernel::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};
use xolotl_kernel::{Bootstrap, Driver, FactSink, FnDriver, KernelBuilder, MethodSpec};
use xolotl_state::{StateReadExt, StateWriteExt};
use xolotl_storage_redb::{RedbGatewayIdempotencyStore, RedbOptions, RedbStore};
use xolotl_types::{
    CompletionOrigin, MethodAuthority, Outcome, Path, Purity, TaintSet, TaintSource, TaintedValue,
    Value,
};

const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_KEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const REQUEST_TOKEN: &str = "persistent-request-replay-token-32-bytes";

async fn reopen_request_gateway(
    directory: &std::path::Path,
    driver: Arc<dyn Driver>,
) -> anyhow::Result<(
    RedbStore,
    GatewayRuntime,
    GatewaySession,
    Arc<RedbGatewayIdempotencyStore>,
)> {
    let storage = RedbStore::open(directory.join("gateway.redb"))?;
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(storage.state_backend().into_backend())
            .with_fact_sink(FactSink::new(Arc::new(storage.fact_store()?)))
            .build(),
    ));
    let target = boot.register_effect(
        "effect://echo/say",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver,
    )?;
    let profile = GatewayProfile::new("persistent-request")
        .with_bearer_identity("request-key", "alice", REQUEST_TOKEN, "identity://alice")?
        .with_surface(GatewaySurface::effect_invoke("echo", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let ledger = Arc::new(storage.gateway_idempotency_store(GatewayIdempotencyLimits::default())?);
    let gateway = GatewayRuntime::new_manual(boot, profile, ledger.clone())?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(REQUEST_TOKEN))
        .await?;
    Ok((storage, gateway, session, ledger))
}

#[test]
fn non_idempotent_request_replays_across_redb_reopen_with_original_evidence() -> anyhow::Result<()>
{
    use std::sync::atomic::{AtomicUsize, Ordering};

    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = {
        let calls = calls.clone();
        Arc::new(FnDriver(move |_, input| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        }))
    };
    let mut submission = GatewaySubmission::direct_input("echo", Value::string("charge-42".into()))
        .with_options(SubmitOptions {
            idempotency_key: Some("persistent-charge-once".into()),
            ..SubmitOptions::default()
        });
    let (first, usage, capacity) = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (storage, gateway, session, ledger) =
                reopen_request_gateway(directory.path(), driver.clone()).await?;
            submission = submission.clone().with_options(SubmitOptions {
                expected_request_scope: Some(
                    gateway
                        .describe(&session)?
                        .surfaces
                        .into_iter()
                        .find(|surface| surface.surface_id == "echo")
                        .context("echo request scope")?
                        .request_scope,
                ),
                ..submission.options().clone()
            });
            let first = gateway.submit(&session, submission.clone()).await?;
            ensure!(calls.load(Ordering::SeqCst) == 1);
            ensure!(first.origin == CompletionOrigin::CurrentAttempt);
            ensure!(first.output.outcome == Outcome::Done(Value::string("charge-42".into())));
            ensure!(
                first.output.taint != TaintSet::pristine(),
                "ingress provenance missing"
            );
            let usage = ledger.usage().await?;
            ensure!(usage.records == 1);
            let capacity = ledger.limits();
            let idle = storage.wait_idle();
            drop(gateway);
            drop(ledger);
            drop(storage);
            idle.await;
            Ok::<_, anyhow::Error>((first, usage, capacity))
        })?
    };
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (storage, gateway, session, ledger) =
                reopen_request_gateway(directory.path(), driver).await?;
            ensure!(ledger.usage().await? == usage, "reopen reset usage");
            ensure!(ledger.limits() == capacity, "reopen changed limits");
            let replay = gateway.submit(&session, submission).await?;
            ensure!(
                calls.load(Ordering::SeqCst) == 1,
                "persistent replay executed effect again"
            );
            ensure!(
                replay.accepted == first.accepted,
                "reopen changed acceptance identity"
            );
            ensure!(
                replay.output == first.output,
                "reopen changed outcome or provenance"
            );
            ensure!(
                replay.output.taint == first.output.taint,
                "reopen changed retained provenance"
            );
            ensure!(replay.origin == CompletionOrigin::CachedOutcome);
            ensure!(ledger.usage().await? == usage, "replay changed usage");
            let idle = storage.wait_idle();
            drop(gateway);
            drop(ledger);
            drop(storage);
            idle.await;
            Ok::<_, anyhow::Error>(())
        })?;
    }
    Ok(())
}

#[tokio::test]
async fn closed_request_identity_cannot_redispatch_after_redb_reopen() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = {
        let calls = calls.clone();
        Arc::new(FnDriver(move |_, input| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        }))
    };
    let mut original =
        GatewaySubmission::direct_input("echo", Value::integer(42)).with_options(SubmitOptions {
            idempotency_key: Some("gw-retry:1:literal-key".into()),
            ..SubmitOptions::default()
        });
    {
        let (storage, gateway, session, ledger) =
            reopen_request_gateway(directory.path(), driver.clone()).await?;
        original = original.clone().with_options(SubmitOptions {
            expected_request_scope: Some(
                gateway
                    .describe(&session)?
                    .surfaces
                    .into_iter()
                    .find(|surface| surface.surface_id == "echo")
                    .context("echo request scope")?
                    .request_scope,
            ),
            ..original.options().clone()
        });
        gateway.submit(&session, original.clone()).await?;
        ensure!(calls.load(Ordering::SeqCst) == 1);
        ensure!(ledger.close_retry_epoch(0).await? == 1);
        ensure!(ledger.usage().await? == GatewayIdempotencyUsage::default());
        let idle = storage.wait_idle();
        drop(gateway);
        drop(ledger);
        drop(storage);
        idle.await;
    }
    let (storage, gateway, session, ledger) =
        reopen_request_gateway(directory.path(), driver).await?;
    ensure!(ledger.retry_epoch().await? == 1);
    ensure!(matches!(
        gateway.submit(&session, original.clone()).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(calls.load(Ordering::SeqCst) == 1);
    let mut new_options = original.options().clone();
    new_options.retry_epoch = 1;
    let new_request = original.with_options(new_options);
    let first = gateway.submit(&session, new_request.clone()).await?;
    let replay = gateway.submit(&session, new_request).await?;
    ensure!(first.accepted == replay.accepted);
    ensure!(replay.origin == CompletionOrigin::CachedOutcome);
    ensure!(calls.load(Ordering::SeqCst) == 2);
    let idle = storage.wait_idle();
    drop(gateway);
    drop(ledger);
    drop(storage);
    idle.await;
    Ok(())
}

fn limits() -> GatewayIdempotencyLimits {
    GatewayIdempotencyLimits {
        max_records: NonZeroUsize::MIN,
        max_bytes: NonZeroUsize::MIN.saturating_add(8255),
        max_record_bytes: NonZeroUsize::MIN.saturating_add(8191),
    }
}

fn pending() -> TaintedValue {
    let mut map = base();
    map.insert("state".into(), Value::string("pending".into()));
    map.insert("created_at_ms".into(), Value::integer(0));
    map.insert("reservation_id".into(), Value::string("reservation".into()));
    TaintedValue::new(Value::map(map), TaintSet::of(TaintSource::ModelOutput))
}

fn completed() -> TaintedValue {
    let mut map = base();
    map.insert("state".into(), Value::string("committed".into()));
    map.insert("committed_at_ms".into(), Value::integer(1));
    map.insert(
        "accepted_submission_id".into(),
        Value::string("submission".into()),
    );
    map.insert("accepted_trace_root".into(), Value::string("trace".into()));
    map.insert("accepted_profile_rev".into(), Value::integer(1));
    map.insert(
        "accepted_surface_id".into(),
        Value::string("surface".into()),
    );
    map.insert("outcome_status".into(), Value::string("done".into()));
    map.insert("outcome_value".into(), Value::string("complete".into()));
    map.insert(
        "unresolved_operations".into(),
        Value::map(BTreeMap::from([
            ("operation_ids".into(), Value::list(Vec::new())),
            ("identities_incomplete".into(), Value::boolean(false)),
        ])),
    );
    TaintedValue::pristine(Value::map(map))
}

fn base() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "schema".into(),
            Value::string("gateway-idempotency-v1".into()),
        ),
        ("effective_key_hash".into(), Value::string(KEY.into())),
        ("submission_hash".into(), Value::string(OTHER_KEY.into())),
        (
            "caller_material_kind".into(),
            Value::string("idempotency_key".into()),
        ),
        ("caller_material_hash".into(), Value::string(KEY.into())),
        ("profile_name".into(), Value::string("profile".into())),
        ("profile_rev".into(), Value::string("1".into())),
        ("principal_id".into(), Value::string("principal".into())),
        ("surface_id".into(), Value::string("surface".into())),
    ])
}

fn pending_for(key: &str) -> anyhow::Result<TaintedValue> {
    let original = pending();
    let mut map = original.value.into_map().context("pending map")?;
    map.insert("effective_key_hash".into(), Value::string(key.into()))?;
    Ok(TaintedValue::new(Value::from(map), original.taint))
}

#[tokio::test]
async fn shared_acceptance_and_reopen_preserve_evidence() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("acceptance.redb");
    let capacity = GatewayIdempotencyLimits {
        max_records: NonZeroUsize::MIN.saturating_add(3),
        max_bytes: NonZeroUsize::new(3 * (limits().max_record_bytes.get() + 64))
            .context("acceptance byte capacity")?,
        ..limits()
    };
    let before;
    let mut retained = Vec::new();
    {
        let store = RedbStore::open(&path)?;
        let ledger = Arc::new(store.gateway_idempotency_store(capacity)?);
        gateway_idempotency_acceptance(ledger.clone()).await?;
        before = ledger.usage().await?;
        ensure!(ledger.retry_epoch().await? == 35);
        for identity in 2..=4 {
            let key = format!("{identity:064x}");
            retained.push((
                key.clone(),
                ledger.observe(&key).await?.context("acceptance evidence")?,
            ));
        }
        let idle = store.wait_idle();
        drop(ledger);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(capacity)?;
    ensure!(ledger.retry_epoch().await? == 35);
    ensure!(ledger.observe(KEY).await?.is_none());
    ensure!(matches!(
        ledger.reserve(KEY, pending()).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(ledger.usage().await? == before);
    for (key, value) in retained {
        ensure!(ledger.observe(&key).await? == Some(value.clone()));
        ensure!(ledger.reserve(&key, pending_for(&key)?).await? == Some(value));
    }
    ensure!(ledger.usage().await? == before);
    Ok(())
}

#[tokio::test]
async fn reopen_retains_limits_reservations_and_retired_identity() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("gateway.redb");
    let capacity = limits();
    {
        let store = RedbStore::open(&path)?;
        let ledger = store.gateway_idempotency_store(capacity)?;
        ensure!(ledger.reserve(KEY, pending()).await?.is_none());
        ensure!(
            ledger.usage().await?
                == GatewayIdempotencyUsage {
                    records: 1,
                    bytes: capacity.max_record_bytes.get() + 64,
                }
        );
        let idle = store.wait_idle();
        drop(ledger);
        drop(store);
        idle.await;
    }
    {
        let store = RedbStore::open(&path)?;
        for changed in [
            GatewayIdempotencyLimits {
                max_records: NonZeroUsize::MIN.saturating_add(1),
                ..capacity
            },
            GatewayIdempotencyLimits {
                max_bytes: capacity.max_bytes.saturating_add(1),
                ..capacity
            },
            GatewayIdempotencyLimits {
                max_record_bytes: NonZeroUsize::MIN.saturating_add(4095),
                ..capacity
            },
        ] {
            ensure!(matches!(
                store.gateway_idempotency_store(changed),
                Err(GatewayError::Rejected(_))
            ));
        }
        let ledger = store.gateway_idempotency_store(capacity)?;
        ensure!(ledger.limits() == capacity);
        ensure!(
            ledger
                .reserve(KEY, TaintedValue::pristine(Value::null()))
                .await?
                == Some(pending())
        );
        ensure!(matches!(
            ledger.reserve(OTHER_KEY, pending_for(OTHER_KEY)?).await,
            Err(GatewayError::LimitExceeded(_))
        ));
        ledger.complete(KEY, pending().value, completed()).await?;
        let observed = ledger.observe(KEY).await?.context("completed record")?;
        ensure!(observed.taint == pending().taint);
        let encoded = GatewayIdempotencyRecord::completed(observed.clone(), capacity)?;
        ensure!(ledger.usage().await?.bytes == encoded.charged_bytes());
        ledger.retire(KEY, observed.value).await?;
        let retired = ledger.observe(KEY).await?.context("retired record")?;
        ensure!(
            retired
                .value
                .as_map()
                .and_then(|map| map.get("state"))
                .and_then(Value::as_str)
                == Some("retired")
        );
        ensure!(ledger.usage().await?.records == 1);
        let idle = store.wait_idle();
        drop(ledger);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(capacity)?;
    let retired = ledger.observe(KEY).await?.context("durable tombstone")?;
    let usage = ledger.usage().await?;
    ensure!(ledger.reserve(KEY, pending()).await? == Some(retired.clone()));
    ensure!(
        ledger
            .complete(KEY, retired.value.clone(), completed())
            .await
            .is_err()
    );
    ensure!(ledger.release(KEY, retired.value).await.is_err());
    ensure!(matches!(
        ledger.reserve(OTHER_KEY, pending_for(OTHER_KEY)?).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(ledger.usage().await? == usage);
    Ok(())
}

#[tokio::test]
async fn failed_settlement_changes_neither_row_nor_durable_accounting() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("failure.redb");
    {
        let store = RedbStore::open(&path)?;
        let ledger = store.gateway_idempotency_store(limits())?;
        ledger.reserve(KEY, pending()).await?;
        let before = ledger.usage().await?;
        ensure!(matches!(
            ledger.complete(KEY, Value::null(), completed()).await,
            Err(GatewayError::Indeterminate(_))
        ));
        ensure!(matches!(
            ledger.release(KEY, Value::null()).await,
            Err(GatewayError::Indeterminate(_))
        ));
        ensure!(ledger.retire(KEY, pending().value).await.is_err());
        let mut oversized = completed().value.into_map().context("result map")?;
        oversized.insert(
            "outcome_value".into(),
            Value::string("x".repeat(limits().max_record_bytes.get())),
        )?;
        ensure!(matches!(
            ledger
                .complete(
                    KEY,
                    pending().value,
                    TaintedValue::pristine(Value::from(oversized))
                )
                .await,
            Err(GatewayError::LimitExceeded(_))
        ));
        ensure!(ledger.observe(KEY).await? == Some(pending()));
        ensure!(ledger.usage().await? == before);
        let idle = store.wait_idle();
        drop(ledger);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(limits())?;
    ensure!(ledger.observe(KEY).await? == Some(pending()));
    ledger.release(KEY, pending().value).await?;
    ensure!(ledger.usage().await? == GatewayIdempotencyUsage::default());
    ensure!(
        ledger
            .reserve(OTHER_KEY, pending_for(OTHER_KEY)?)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn legacy_state_rows_refuse_an_empty_gateway_ledger() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("legacy.redb"))?;
    let state = store.state_backend();
    let path = Path::parse(&format!("state://gateway/idempotency/{KEY}"))?;
    state.write_set(&path, pending().value).await?;
    ensure!(matches!(
        store.gateway_idempotency_store(limits()),
        Err(GatewayError::Rejected(_))
    ));
    ensure!(state.read(&path).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn corrupt_or_oversized_rows_fail_closed_on_access_after_reopen() -> anyhow::Result<()> {
    for oversized in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("corrupt.redb");
        {
            let store = RedbStore::open(&path)?;
            let ledger = store.gateway_idempotency_store(limits())?;
            ledger.reserve(KEY, pending()).await?;
            let idle = store.wait_idle();
            drop(ledger);
            drop(store);
            idle.await;
        }
        {
            let db = redb::Database::open(&path)?;
            let transaction = db.begin_write()?;
            {
                let definition: TableDefinition<&str, (u64, &[u8])> =
                    TableDefinition::new("gateway_idempotency_records_v1");
                let mut rows = transaction.open_table(definition)?;
                let record = GatewayIdempotencyRecord::pending(pending(), limits())?;
                if oversized {
                    rows.insert(
                        KEY,
                        (
                            record.charged_bytes() as u64,
                            vec![0; limits().max_record_bytes.get() + 1].as_slice(),
                        ),
                    )?;
                } else {
                    rows.insert(KEY, (1, record.encoded()))?;
                }
            }
            transaction.commit()?;
        }
        let store = RedbStore::open(&path)?;
        let ledger = store.gateway_idempotency_store(limits())?;
        ensure!(matches!(
            ledger.observe(KEY).await,
            Err(GatewayError::Rejected(_))
        ));
        ensure!(matches!(
            ledger.reserve(KEY, pending()).await,
            Err(GatewayError::Rejected(_))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn missing_or_inconsistent_metadata_refuses_reinitialization() -> anyhow::Result<()> {
    for failure in [
        "missing_table",
        "missing_version",
        "missing_barrier",
        "record_count",
        "byte_count",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("metadata.redb");
        {
            let store = RedbStore::open(&path)?;
            let ledger = store.gateway_idempotency_store(limits())?;
            let idle = store.wait_idle();
            drop(ledger);
            drop(store);
            idle.await;
        }
        {
            let db = redb::Database::open(&path)?;
            let transaction = db.begin_write()?;
            let definition: TableDefinition<&str, u64> =
                TableDefinition::new("gateway_idempotency_meta_v1");
            if failure == "missing_table" {
                transaction.delete_table(definition)?;
            } else {
                let mut meta = transaction.open_table(definition)?;
                match failure {
                    "missing_version" => {
                        meta.remove("version")?;
                    }
                    "missing_barrier" => {
                        meta.remove("retry_epoch")?;
                    }
                    "record_count" => {
                        meta.insert("records", 1)?;
                    }
                    "byte_count" => {
                        meta.insert("bytes", limits().max_bytes.get() as u64 + 1)?;
                    }
                    _ => anyhow::bail!("unknown metadata corruption fixture: {failure}"),
                }
            }
            transaction.commit()?;
        }
        let store = RedbStore::open(&path)?;
        ensure!(matches!(
            store.gateway_idempotency_store(limits()),
            Err(GatewayError::Rejected(_))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn evidence_namespace_is_shared_persistent_and_unique_per_database() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("namespace.redb");
    let namespace = {
        let store = RedbStore::open(&path)?;
        let ledger = store.gateway_idempotency_store(limits())?;
        let namespace = ledger.evidence_namespace()?;
        ensure!(*namespace.as_bytes() != [0; 32]);
        ensure!(ledger.clone().evidence_namespace()? == namespace);
        let adapter = store.gateway_idempotency_store(limits())?;
        ensure!(adapter.evidence_namespace()? == namespace);
        ensure!(ledger.reserve(KEY, pending()).await?.is_none());
        let idle = store.wait_idle();
        drop(adapter);
        drop(ledger);
        drop(store);
        idle.await;
        namespace
    };
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(limits())?;
    ensure!(ledger.evidence_namespace()? == namespace);
    ensure!(ledger.observe(KEY).await? == Some(pending()));
    let other = RedbStore::open(directory.path().join("other.redb"))?;
    ensure!(
        other
            .gateway_idempotency_store(limits())?
            .evidence_namespace()?
            != namespace
    );
    Ok(())
}

#[tokio::test]
async fn invalid_namespace_and_unsupported_formats_reject_without_resetting_metadata()
-> anyhow::Result<()> {
    for failure in [
        "evidence_namespace_0",
        "evidence_namespace_1",
        "evidence_namespace_2",
        "evidence_namespace_3",
        "zero",
        "version_0",
        "version_2",
        "version_3",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("invalid-namespace.redb");
        {
            let store = RedbStore::open(&path)?;
            let ledger = store.gateway_idempotency_store(limits())?;
            ensure!(ledger.reserve(KEY, pending()).await?.is_none());
            let idle = store.wait_idle();
            drop(ledger);
            drop(store);
            idle.await;
        }
        let before = {
            let db = redb::Database::open(&path)?;
            let transaction = db.begin_write()?;
            let snapshot = {
                use redb::ReadableTable;
                let mut meta = transaction.open_table(TableDefinition::<&str, u64>::new(
                    "gateway_idempotency_meta_v1",
                ))?;
                match failure {
                    "zero" => {
                        for key in [
                            "evidence_namespace_0",
                            "evidence_namespace_1",
                            "evidence_namespace_2",
                            "evidence_namespace_3",
                        ] {
                            meta.insert(key, 0)?;
                        }
                    }
                    "version_0" => {
                        meta.insert("version", 0)?;
                    }
                    "version_2" => {
                        meta.insert("version", 2)?;
                    }
                    "version_3" => {
                        meta.insert("version", 3)?;
                    }
                    key => {
                        meta.remove(key)?;
                    }
                }
                meta.iter()?
                    .map(|entry| {
                        let (key, value) = entry?;
                        Ok((key.value().to_owned(), value.value()))
                    })
                    .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?
            };
            transaction.commit()?;
            snapshot
        };
        {
            let store = RedbStore::open(&path)?;
            for _attempt in 0..2 {
                ensure!(
                    matches!(
                        store.gateway_idempotency_store(limits()),
                        Err(GatewayError::Rejected(_))
                    ),
                    "accepted {failure}"
                );
            }
            let idle = store.wait_idle();
            drop(store);
            idle.await;
        }
        let db = redb::Database::open(&path)?;
        let transaction = db.begin_read()?;
        use redb::ReadableTable;
        let meta = transaction.open_table(TableDefinition::<&str, u64>::new(
            "gateway_idempotency_meta_v1",
        ))?;
        let after = meta
            .iter()?
            .map(|entry| {
                let (key, value) = entry?;
                Ok((key.value().to_owned(), value.value()))
            })
            .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
        ensure!(
            before == after,
            "metadata changed after rejecting {failure}"
        );
        let rows = transaction.open_table(TableDefinition::<&str, (u64, &[u8])>::new(
            "gateway_idempotency_records_v1",
        ))?;
        ensure!(rows.get(KEY)?.is_some(), "evidence removed for {failure}");
    }
    Ok(())
}

#[tokio::test]
async fn retry_barrier_overflow_fails_closed_without_resetting_evidence() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retry-overflow.redb");
    {
        let store = RedbStore::open(&path)?;
        let ledger = store.gateway_idempotency_store(limits())?;
        ensure!(ledger.reserve(KEY, pending()).await?.is_none());
        let idle = store.wait_idle();
        drop(ledger);
        drop(store);
        idle.await;
    }
    {
        let db = redb::Database::open(&path)?;
        let transaction = db.begin_write()?;
        {
            let mut meta = transaction.open_table(TableDefinition::<&str, u64>::new(
                "gateway_idempotency_meta_v1",
            ))?;
            meta.insert("retry_epoch", u64::MAX)?;
        }
        transaction.commit()?;
    }
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(limits())?;
    let usage = ledger.usage().await?;
    ensure!(ledger.close_retry_epoch(u64::MAX).await.is_err());
    ensure!(ledger.retry_epoch().await? == u64::MAX);
    ensure!(ledger.usage().await? == usage);
    ensure!(ledger.reserve(KEY, pending()).await? == Some(pending()));
    Ok(())
}

#[tokio::test]
async fn misbound_rows_fail_closed_without_changing_usage() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("binding.redb");
    let before;
    {
        let store = RedbStore::open(&path)?;
        let ledger = store.gateway_idempotency_store(limits())?;
        ensure!(matches!(
            ledger.reserve(OTHER_KEY, pending()).await,
            Err(GatewayError::Rejected(_))
        ));
        ensure!(ledger.usage().await? == GatewayIdempotencyUsage::default());
        ledger.reserve(KEY, pending()).await?;
        before = ledger.usage().await?;
        let mut wrong_result = completed().value.into_map().context("result map")?;
        wrong_result.insert("submission_hash".into(), Value::string(KEY.into()))?;
        ensure!(matches!(
            ledger
                .complete(
                    KEY,
                    pending().value,
                    TaintedValue::pristine(Value::from(wrong_result))
                )
                .await,
            Err(GatewayError::Rejected(_))
        ));
        ensure!(ledger.observe(KEY).await? == Some(pending()));
        ensure!(ledger.usage().await? == before);
        let idle = store.wait_idle();
        drop(ledger);
        drop(store);
        idle.await;
    }
    {
        let db = redb::Database::open(&path)?;
        let transaction = db.begin_write()?;
        {
            let definition: TableDefinition<&str, (u64, &[u8])> =
                TableDefinition::new("gateway_idempotency_records_v1");
            let mut rows = transaction.open_table(definition)?;
            let misbound = GatewayIdempotencyRecord::pending(pending_for(OTHER_KEY)?, limits())?;
            rows.insert(KEY, (misbound.charged_bytes() as u64, misbound.encoded()))?;
        }
        transaction.commit()?;
    }
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(limits())?;
    ensure!(matches!(
        ledger.observe(KEY).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(matches!(
        ledger.release(KEY, pending_for(OTHER_KEY)?.value).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(ledger.usage().await? == before);
    Ok(())
}

#[derive(Default)]
struct HoldingSpawner(Mutex<Option<BlockingJob>>);

impl BlockingSpawner for HoldingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.is_some() {
            return Err(BlockingSpawnError::AtCapacity);
        }
        *held = Some(job);
        Ok(())
    }
}

impl HoldingSpawner {
    fn run(&self) -> anyhow::Result<()> {
        let job = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .context("accepted blocking job")?;
        job();
        Ok(())
    }

    async fn finish<Output>(&self, future: impl Future<Output = Output>) -> anyhow::Result<Output> {
        let mut future = std::pin::pin!(future);
        ensure!(poll_once(future.as_mut()).await.is_pending());
        self.run()?;
        Ok(future.await)
    }
}

async fn poll_once<Output>(mut future: Pin<&mut impl Future<Output = Output>>) -> Poll<Output> {
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await
}

#[tokio::test]
async fn gateway_and_state_share_admission_and_detached_idle_barrier() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let spawner = Arc::new(HoldingSpawner::default());
    let path = directory.path().join("blocking.redb");
    let store =
        RedbStore::open_with_options_and_spawner(&path, RedbOptions::default(), spawner.clone())?;
    let ledger = store.gateway_idempotency_store(limits())?;
    let state = store.state_backend();
    drop(ledger.reserve(KEY, pending()));
    ensure!(
        spawner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    );
    let mut reserve = Box::pin(ledger.reserve(KEY, pending()));
    ensure!(poll_once(reserve.as_mut()).await.is_pending());
    drop(reserve);
    ensure!(matches!(
        ledger.reserve(OTHER_KEY, pending_for(OTHER_KEY)?).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(
        state
            .read(&Path::parse("state://shared/slot")?)
            .await
            .is_err()
    );
    let mut idle = Box::pin(store.wait_idle());
    ensure!(poll_once(idle.as_mut()).await.is_pending());
    drop(state);
    drop(ledger);
    drop(store);
    spawner.run()?;
    idle.await;
    let store =
        RedbStore::open_with_options_and_spawner(&path, RedbOptions::default(), spawner.clone())?;
    let ledger = store.gateway_idempotency_store(limits())?;
    ensure!(spawner.finish(ledger.observe(KEY)).await?? == Some(pending()));
    let state = store.state_backend();
    let state_path = Path::parse("state://shared/slot")?;
    let mut read = Box::pin(state.read(&state_path));
    ensure!(poll_once(read.as_mut()).await.is_pending());
    ensure!(matches!(
        ledger.usage().await,
        Err(GatewayError::LimitExceeded(_))
    ));
    spawner.run()?;
    ensure!(read.await?.is_none());
    Ok(())
}

struct DiscardingSpawner;

impl BlockingSpawner for DiscardingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        drop(job);
        Ok(())
    }
}

#[tokio::test]
async fn admitted_but_lost_worker_is_unknown_and_drains_captures() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lost.redb");
    let store = RedbStore::open_with_options_and_spawner(
        &path,
        RedbOptions::default(),
        Arc::new(DiscardingSpawner),
    )?;
    let ledger = store.gateway_idempotency_store(limits())?;
    ensure!(matches!(
        ledger.reserve(KEY, pending()).await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(matches!(
        ledger.complete(KEY, pending().value, completed()).await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(matches!(
        ledger.release(KEY, pending().value).await,
        Err(GatewayError::Indeterminate(_))
    ));
    let idle = store.wait_idle();
    drop(ledger);
    drop(store);
    idle.await;
    let store = RedbStore::open(&path)?;
    let ledger = store.gateway_idempotency_store(limits())?;
    ensure!(ledger.observe(KEY).await?.is_none());
    ensure!(ledger.usage().await? == GatewayIdempotencyUsage::default());
    Ok(())
}
