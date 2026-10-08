use super::*;
use anyhow::{Context, ensure};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use xolotl_kernel::host::{AbortTask, HostClock, TaskSpawnError, TaskSpawner};
use xolotl_state::{
    InMemoryBackend, StateBoundedWrite, StateCommit, StateMutation, StateResult, StateWrite,
    TaintedValue,
};

fn public_key(username: &str) -> Binding {
    Binding::PublicKey {
        username: username.into(),
        origin: "https://console.test".into(),
    }
}

fn registration(username: &str) -> Binding {
    Binding::PasskeyRegistration {
        username: username.into(),
        sid: "registration-session".into(),
    }
}

fn authentication(username: &str) -> Binding {
    Binding::PasskeyAuthentication {
        username: username.into(),
    }
}

mod binding;

struct ManualClock(AtomicI64);

impl HostClock for ManualClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn unix_millis(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

struct NoTasks;

impl TaskSpawner for NoTasks {
    fn spawn(
        &self,
        _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        Err(TaskSpawnError::Unavailable)
    }
}

#[tokio::test]
async fn challenge_expiry_uses_the_installed_wall_clock() -> anyhow::Result<()> {
    let clock = Arc::new(ManualClock(AtomicI64::new(1_000)));
    let runtime = HostRuntime::new(
        clock.clone(),
        Arc::new(NoTasks),
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    );
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig::default();
    let id = issue(
        &runtime,
        &state,
        &config,
        public_key("alice"),
        "peer",
        2_000,
        &"proof",
    )
    .await?;
    let continuation = issue_continuation(
        &runtime,
        &state,
        &config,
        Binding::MfaLogin {
            username: "alice".into(),
            account: AccountKey::local("alice"),
        },
        "peer",
        2_000,
        &"round",
    )
    .await?;
    clock.0.store(2_000, Ordering::SeqCst);
    ensure!(matches!(
        take::<String>(&runtime, &state, &id, &public_key("alice")).await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(matches!(
        inspect::<String>(&runtime, &state, &continuation).await,
        Err(AuthError::InvalidChallenge)
    ));
    Ok(())
}

#[tokio::test]
async fn authentication_private_rows_require_both_bounded_state_ports() -> anyhow::Result<()> {
    let storage = Arc::new(InMemoryBackend::new());
    let ordinary = Backend::new()
        .with_read(storage.clone())
        .with_write(storage.clone());
    ensure!(matches!(
        credentials::read_by_key(&ordinary, &AccountKey::local("alice"), crate::auth::test_credential_sealer().as_ref()).await,
        Err(AuthError::State(detail)) if detail.contains("bounded_read")
    ));
    ensure!(matches!(
        issue(test_runtime(),
            &ordinary,
            &ConsoleChallengeConfig::default(),
            public_key("alice"),
            "peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &"proof",
        )
        .await,
        Err(AuthError::State(detail)) if detail.contains("bounded_read")
    ));
    let read_only = ordinary.with_bounded_read(storage);
    ensure!(matches!(
        credentials::write_by_key(&read_only, &AccountKey::local("alice"), &credentials::AccountCredentials::default(), crate::auth::test_credential_sealer().as_ref()).await,
        Err(AuthError::State(detail)) if detail.contains("bounded_write")
    ));
    ensure!(matches!(
        commit(&read_only, &Path::parse(LEDGER)?, None, Value::null()).await,
        Err(AuthError::State(detail)) if detail.contains("bounded_write")
    ));
    Ok(())
}

#[tokio::test]
async fn near_limit_ledger_string_fits_its_bounded_state_envelope() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = xolotl_storage_redb::RedbStore::open(directory.path().join("ledger.redb"))?;
    // Every backslash in the inner JSON is escaped again by the State value.
    // This bounds the outer encoding independently of the ledger's contents.
    let worst_case = Value::string("\\".repeat(HARD_MAX_BYTES));
    ensure!(xolotl_state::host::encoded_size(&worst_case)? + 1024 <= MAX_LEDGER_ROW_BYTES.get());
    let mut ledger = Ledger::new();
    for index in 0..69 {
        ledger.insert(
            random_token(18)?,
            Pending {
                binding: public_key(&format!("user{index}")),
                source_hash: token_hash(&format!("source{index}")),
                expires_at: xolotl_kernel::host::system_now_millis() + 60_000,
                phase: Phase::SingleUse,
                payload: serde_json::Value::String("\"".repeat(30_000)),
            },
        );
    }
    let value = encode(&ledger, HARD_MAX_BYTES)?;
    let inner = value.as_str().context("encoded ledger")?;
    ensure!(inner.len() > HARD_MAX_BYTES - 100_000 && inner.len() <= HARD_MAX_BYTES);
    let path = Path::parse(LEDGER)?;
    let memory_bytes = xolotl_state::host::encoded_size(&TaintedValue::pristine(value.clone()))?
        + path.to_string().len();
    let redb_bytes = 12
        + xolotl_state::host::encoded_size(&xolotl_types::TaintSet::pristine())?
        + xolotl_state::host::encoded_size(&value)?
        + path.to_string().len();
    ensure!(memory_bytes <= MAX_LEDGER_ROW_BYTES.get());
    ensure!(redb_bytes <= MAX_LEDGER_ROW_BYTES.get());
    for state in [
        InMemoryBackend::new().into_backend(),
        store.state_backend().into_backend(),
    ] {
        state.write_set(&path, value.clone()).await?;
        let stored = read_ledger(&state, &path).await?.context("ledger row")?;
        ensure!(decode(Some(&stored))?.len() == ledger.len());
        state
            .write_cas_bounded(
                &path,
                Some(value.clone()),
                value.clone(),
                MAX_LEDGER_ROW_BYTES,
            )
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn oversized_ledger_row_is_rejected_before_parsing_or_cas() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = xolotl_storage_redb::RedbStore::open(directory.path().join("ledger.redb"))?;
    for state in [
        InMemoryBackend::new().into_backend(),
        store.state_backend().into_backend(),
    ] {
        let path = Path::parse(LEDGER)?;
        let oversized = Value::string("x".repeat(MAX_LEDGER_ROW_BYTES.get()));
        state.write_set(&path, oversized.clone()).await?;
        ensure!(matches!(
            issue(test_runtime(),
                &state,
                &ConsoleChallengeConfig::default(),
                public_key("alice"),
                "peer",
                xolotl_kernel::host::system_now_millis() + 60_000,
                &"proof",
            )
            .await,
            Err(AuthError::State(detail)) if detail.contains("current state record exceeds encoded byte budget")
        ));
        ensure!(matches!(
            commit(&state, &path, None, Value::string("replacement".into())).await,
            Err(AuthError::State(detail)) if detail.contains("current state record exceeds encoded byte budget")
        ));
        ensure!(state.read(&path).await? == Some(oversized));
    }
    Ok(())
}

#[tokio::test]
async fn malformed_oversized_redb_auth_rows_fail_by_size_before_decode() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("malformed.redb");
    drop(xolotl_storage_redb::RedbStore::open(&file)?);
    let credential_path = Path::parse("state://vault/console/credentials/local/alice")?;
    let ledger_path = Path::parse(LEDGER)?;
    {
        let db = redb::Database::create(&file)?;
        let write = db.begin_write()?;
        {
            let mut rows =
                write.open_table(redb::TableDefinition::<&str, &[u8]>::new("state_values"))?;
            let credential_key = credential_path.to_string();
            let ledger_key = ledger_path.to_string();
            let credential_bytes = vec![b'!'; credentials::MAX_CREDENTIAL_ROW_BYTES.get() + 1];
            let ledger_bytes = vec![b'!'; MAX_LEDGER_ROW_BYTES.get() + 1];
            rows.insert(credential_key.as_str(), credential_bytes.as_slice())?;
            rows.insert(ledger_key.as_str(), ledger_bytes.as_slice())?;
        }
        write.commit()?;
    }
    let store = xolotl_storage_redb::RedbStore::open(&file)?;
    let state = store.state_backend().into_backend();
    for (path, limit) in [
        (&credential_path, credentials::MAX_CREDENTIAL_ROW_BYTES),
        (&ledger_path, MAX_LEDGER_ROW_BYTES),
    ] {
        ensure!(matches!(
            state.read_bounded(path, limit).await,
            Err(xolotl_state::StateFailure { error: xolotl_state::StateError::PointTooLarge(row), .. })
                if !row.provenance_observed
        ));
        ensure!(matches!(
            state
                .write_cas_bounded(path, None, Value::null(), limit)
                .await,
            Err(xolotl_state::StateFailure { error: xolotl_state::StateError::PointTooLarge(row), .. })
                if !row.provenance_observed
        ));
    }
    ensure!(matches!(
        credentials::read_by_key(&state, &AccountKey::local("alice"), crate::auth::test_credential_sealer().as_ref()).await,
        Err(AuthError::State(detail)) if detail.contains("current state record exceeds encoded byte budget")
    ));
    ensure!(matches!(
        issue(test_runtime(),
            &state,
            &ConsoleChallengeConfig::default(),
            public_key("alice"),
            "peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &"proof",
        )
        .await,
        Err(AuthError::State(detail)) if detail.contains("current state record exceeds encoded byte budget")
    ));
    Ok(())
}

#[tokio::test]
async fn quotas_span_methods_sources_accounts_and_reclaim_expired_entries() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig {
        max_pending_global: 3,
        max_pending_per_user: 1,
        max_pending_per_source: 2,
        ..Default::default()
    }
    .bounded();
    let expires = xolotl_kernel::host::system_now_millis() + 60_000;
    let first = issue(
        test_runtime(),
        &state,
        &config,
        public_key("alice"),
        "private-source",
        expires,
        &"a",
    )
    .await?;
    let second = issue(
        test_runtime(),
        &state,
        &config,
        registration("bob"),
        "private-source",
        expires,
        &"b",
    )
    .await?;
    for (binding, source) in [
        (authentication("carol"), "private-source"),
        (authentication("alice"), "other-source"),
    ] {
        ensure!(matches!(
            issue(
                test_runtime(),
                &state,
                &config,
                binding,
                source,
                expires,
                &"c"
            )
            .await,
            Err(AuthError::CapacityExceeded)
        ));
    }
    issue(
        test_runtime(),
        &state,
        &config,
        authentication("carol"),
        "other-source",
        expires,
        &"c",
    )
    .await?;
    ensure!(matches!(
        issue(
            test_runtime(),
            &state,
            &config,
            public_key("dave"),
            "third-source",
            expires,
            &"d"
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    let path = Path::parse(LEDGER)?;
    let stored = state.read(&path).await?.context("ledger")?;
    ensure!(
        !stored
            .as_str()
            .context("encoded")?
            .contains("private-source")
    );
    let mut ledger = decode(Some(&stored))?;
    ledger.get_mut(&first).context("first")?.expires_at =
        xolotl_kernel::host::system_now_millis() - 1;
    state
        .write_set(&path, encode(&ledger, HARD_MAX_BYTES)?)
        .await?;
    issue(
        test_runtime(),
        &state,
        &config,
        public_key("alice"),
        "third-source",
        expires,
        &"replacement",
    )
    .await?;
    ensure!(matches!(
        take::<String>(test_runtime(), &state, &first, &public_key("alice")).await,
        Err(AuthError::InvalidChallenge)
    ));
    // A ceremony ID cannot be used by a different method; the original remains usable.
    ensure!(matches!(
        take::<String>(test_runtime(), &state, &second, &public_key("bob")).await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(take::<String>(test_runtime(), &state, &second, &registration("bob")).await? == "b");
    // Reject by byte budget without altering admitted ceremonies.
    let before = state.read(&path).await?;
    let config = ConsoleChallengeConfig {
        max_bytes: 1024,
        ..config
    };
    ensure!(matches!(
        issue(
            test_runtime(),
            &state,
            &config,
            public_key("dave"),
            "fourth",
            expires,
            &"x".repeat(2048)
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    ensure!(state.read(&path).await? == before);
    Ok(())
}

struct RacingWrite {
    state: Backend,
    remaining: AtomicUsize,
    barrier: tokio::sync::Barrier,
}

impl StateWrite for RacingWrite {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if self
                .remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                self.barrier.wait().await;
            }
            self.state.mutate(path, mutation).await
        })
    }
}

impl StateBoundedWrite for RacingWrite {
    type BoundedWrite<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            if self
                .remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                self.barrier.wait().await;
            }
            self.state
                .write_cas_tainted_bounded(path, expected, value.value, value.taint, limit)
                .await
        })
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: xolotl_types::TaintSet,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(
            self.state
                .write_compare_delete_tainted_bounded(path, expected, taint, limit),
        )
    }
}

fn racing(state: &Backend) -> Backend {
    let writer = Arc::new(RacingWrite {
        state: state.clone(),
        remaining: AtomicUsize::new(2),
        barrier: tokio::sync::Barrier::new(2),
    });
    state
        .clone()
        .with_write(writer.clone())
        .with_bounded_write(writer)
}

#[tokio::test]
async fn concurrent_admission_and_consumption_each_have_exactly_one_winner() -> anyhow::Result<()> {
    let base = InMemoryBackend::new().into_backend();
    let state = racing(&base);
    let config = ConsoleChallengeConfig {
        max_pending_global: 1,
        ..Default::default()
    }
    .bounded();
    let expires = xolotl_kernel::host::system_now_millis() + 60_000;
    let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            issue(
                test_runtime(),
                &state,
                &config,
                public_key("alice"),
                "a",
                expires,
                &"proof"
            ),
            issue(
                test_runtime(),
                &state,
                &config,
                authentication("bob"),
                "b",
                expires,
                &"proof"
            )
        )
    })
    .await?;
    ensure!(usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1);
    let (id, binding, loser) = match (a, b) {
        (Ok(id), Err(error)) => (id, public_key("alice"), error),
        (Err(error), Ok(id)) => (id, authentication("bob"), error),
        _ => anyhow::bail!("expected one admitted ceremony"),
    };
    ensure!(matches!(loser, AuthError::CapacityExceeded));
    let state = racing(&base);
    let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            take::<String>(test_runtime(), &state, &id, &binding),
            take::<String>(test_runtime(), &state, &id, &binding)
        )
    })
    .await?;
    ensure!(usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1);
    ensure!(decode(base.read(&Path::parse(LEDGER)?).await?.as_ref())?.is_empty());
    Ok(())
}

#[tokio::test]
async fn independent_auth_hosts_share_capacity_and_failed_proofs_release_it() -> anyhow::Result<()>
{
    let boot = Bootstrap::in_memory();
    let config = ConsoleAuthConfig {
        challenges: ConsoleChallengeConfig {
            max_pending_global: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let first = ConsoleAuth::new(config.clone())?;
    let second = ConsoleAuth::new(config)?;
    let request = || KeyChallengeRequest {
        username: "alice".into(),
        origin: "https://console.test".into(),
    };
    let challenge = first.begin_key_login(&boot, request(), "a".into()).await?;
    ensure!(matches!(
        second.begin_key_login(&boot, request(), "b".into()).await,
        Err(AuthError::CapacityExceeded)
    ));
    let finish = KeyLoginRequest {
        username: "alice".into(),
        challenge_id: challenge.challenge_id,
        signature: "invalid".into(),
        origin: "https://console.test".into(),
        key: "ml-dsa-65:invalid".into(),
        second_factor: None,
    };
    ensure!(
        first
            .finish_key_login(&boot, finish, "a".into())
            .await
            .is_err()
    );
    second.begin_key_login(&boot, request(), "b".into()).await?;
    Ok(())
}
