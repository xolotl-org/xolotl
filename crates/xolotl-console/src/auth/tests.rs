use super::authorization::capset_covers;
use super::test_key::TestSigningKey;
use super::*;
use crate::session_store::{
    ConsoleSession, ConsoleSessionPolicy, ConsoleSessionStore, SessionPageLimits,
    SessionStoreError, SessionStorePage,
};
use anyhow::{Context, bail, ensure};
use xolotl_kernel::Bootstrap;
use xolotl_types::Fact;

async fn session_value(auth: &ConsoleAuth, path: &Path) -> Result<Option<Value>, AuthError> {
    Ok(read_session(auth.session_store.as_ref(), path)
        .await?
        .map(|record| record.to_value()))
}

async fn replace_session_for_test(
    auth: &ConsoleAuth,
    path: &Path,
    value: Value,
) -> anyhow::Result<()> {
    let sid = crate::paths::stored_session_id_from_path(path).context("session SID")?;
    auth.session_store.delete(sid, None).await?;
    auth.session_store
        .create(ConsoleSession::from_record(SessionRecord::from_value(
            sid, &value,
        )?))
        .await?;
    Ok(())
}

#[test]
fn account_grant_ceiling_rejects_broader_path_and_missing_predicate() -> anyhow::Result<()> {
    let parent = capset_from_strings(&["read://state/memory/*".into()])?;
    let broader = capset_from_strings(&["read://state/memory/**".into()])?;
    ensure!(
        !capset_covers(&parent, &broader),
        "account grant exceeded its one-segment ceiling"
    );

    let conditional = capset_from_strings(&["read://state/memory/**@account=alice".into()])?;
    let unconditional = capset_from_strings(&["read://state/memory/**".into()])?;
    ensure!(
        !capset_covers(&conditional, &unconditional),
        "account grant discarded its parent predicate"
    );
    ensure!(capset_covers(&conditional, &conditional));
    Ok(())
}

#[test]
fn session_grants_retain_the_narrower_path_and_predicate() -> anyhow::Result<()> {
    let session = CapSet::from_strs(["perform://effect/jobs/**"])?;
    let conditional = CapSet::from_strs(["perform://effect/jobs/**@tenant=alice"])?;
    let input = Value::map(BTreeMap::from([(
        "tenant".into(),
        Value::string("alice".into()),
    )]));
    let job = Path::parse("effect://jobs/echo")?;
    let narrowed = effective_session_grants(&conditional, &session)?;
    ensure!(narrowed == conditional);
    ensure!(narrowed.contains_with("perform", &job, &input, 0));
    ensure!(!narrowed.contains_with("perform", &job, &Value::null(), 0));
    ensure!(effective_session_grants(&session, &conditional)? == conditional);

    let current = CapSet::from_strs(["perform://effect/jobs/**@tenant=alice"])?;
    let ceiling = CapSet::from_strs(["perform://effect/jobs/echo"])?;
    let expected = CapSet::from_strs(["perform://effect/jobs/echo@tenant=alice"])?;
    ensure!(effective_session_grants(&current, &ceiling)? == expected);
    ensure!(effective_session_grants(&ceiling, &current)? == expected);
    ensure!(!expected.contains_with("perform", &Path::parse("effect://jobs/other")?, &input, 0,));
    Ok(())
}

#[test]
fn session_ceiling_intersects_path_and_method_restrictions() -> anyhow::Result<()> {
    let path = Path::parse("state://records/alice")?;
    let account = CapSet::from_strs(["read://state/records/**#read"])?;
    let ceiling = CapSet::from_strs(["read://state/records/alice"])?;
    let expected = CapSet::from_strs(["read://state/records/alice#read"])?;
    ensure!(effective_session_grants(&account, &ceiling)? == expected);
    ensure!(effective_session_grants(&ceiling, &account)? == expected);
    ensure!(expected.contains_method("read", &path, "read"));
    ensure!(!expected.contains_method("read", &path, "read_secret"));
    ensure!(!expected.contains_method("read", &Path::parse("state://records/bob")?, "read"));
    Ok(())
}

#[test]
fn session_grants_reject_incomparable_paths_and_predicates() -> anyhow::Result<()> {
    let alice = CapSet::from_strs(["perform://effect/jobs/**@tenant=alice"])?;
    let bob = CapSet::from_strs(["perform://effect/jobs/**@tenant=bob"])?;
    ensure!(effective_session_grants(&alice, &bob)?.is_empty());

    // The two patterns meet at jobs/alice/data, but neither contains the
    // other. The simple capability grammar cannot represent their conjunction.
    let current = CapSet::from_strs(["read://state/jobs/alice/*"])?;
    let ceiling = CapSet::from_strs(["read://state/jobs/*/data"])?;
    ensure!(effective_session_grants(&current, &ceiling)?.is_empty());
    Ok(())
}

#[test]
fn session_ceiling_is_writable_under_its_read_limits() -> anyhow::Result<()> {
    let ceiling = CapSet::from_strs(
        (0..MAX_SESSION_CEILING_CAPABILITIES).map(|index| format!("perform://effect/jobs/{index}")),
    )?;
    validate_issued_authority_ceiling(&ceiling)?;
    let encoded = Value::list(
        ceiling
            .iter()
            .map(|capability| Value::string(capability.to_string()))
            .collect(),
    );
    ensure!(read_authority_ceiling(&encoded)? == Some(ceiling.clone()));

    let mut oversized = ceiling;
    oversized.push(Capability::parse("perform://effect/jobs/extra")?);
    ensure!(validate_issued_authority_ceiling(&oversized).is_err());
    Ok(())
}

#[test]
fn effective_session_grants_reject_oversized_results() -> anyhow::Result<()> {
    let current = CapSet::from_strs((0..1025).map(|index| format!("read://state/jobs/{index}")))?;
    let ceiling = CapSet::from_strs(["*://**"])?;
    ensure!(matches!(
        effective_session_grants(&current, &ceiling),
        Err(AuthError::State(_))
    ));
    Ok(())
}

fn password_authentication(verified_at: i64) -> AuthenticationEvidence {
    AuthenticationEvidence {
        primary: PrimaryAuthentication::Password { verified_at },
        secondary: None,
    }
}

fn auth_boot() -> Bootstrap {
    Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    )
}

fn test_auth() -> anyhow::Result<ConsoleAuth> {
    Ok(ConsoleAuth::new(ConsoleAuthConfig::default())?)
}

#[tokio::test]
async fn unknown_password_user_does_not_create_persistent_lockout() -> anyhow::Result<()> {
    let boot = auth_boot();
    let auth = test_auth()?;
    let state = boot.kernel().state();
    let username = "no_such_account";
    let failure = auth
        .login_inner(
            state,
            LoginRequest {
                username: username.into(),
                password: "wrong-password".into(),
                second_factor: None,
            },
            "test-peer".into(),
        )
        .await
        .err()
        .context("unknown user login must fail")?;
    ensure!(matches!(failure, AuthError::InvalidCredentials));
    ensure!(
        state.read(&lockout_path(username)?).await?.is_none(),
        "unknown username created a permanent vault row"
    );
    let rate = auth.rate();
    ensure!(
        rate.by_user
            .get(username)
            .is_some_and(|bucket| bucket.failures == 1)
    );
    ensure!(
        rate.by_source
            .get("test-peer")
            .is_some_and(|bucket| bucket.failures == 1)
    );
    Ok(())
}

#[test]
fn local_rate_tables_reject_new_keys_at_capacity_and_reclaim_expired_keys() -> anyhow::Result<()> {
    let auth = test_auth()?;
    let now = 1_000_000;
    {
        let mut rate = auth.rate();
        for i in 0..MAX_RATE_BUCKETS {
            let bucket = FailureBucket {
                failures: 1,
                window_started_at: now,
                ..Default::default()
            };
            rate.by_user.insert(format!("user{i}"), bucket);
            rate.by_source.insert(format!("source{i}"), bucket);
        }
    }
    ensure!(matches!(
        auth.check_rate_limits("fresh", "fresh", now),
        Err(AuthError::RateLimited { .. })
    ));
    auth.check_rate_limits("user0", "source0", now)?;
    auth.record_login_failure("user0", "source0", now);
    ensure!(matches!(
        auth.check_rate_limits("user0", "source0", now),
        Err(AuthError::RateLimited { .. })
    ));
    // An attempt already in flight must never enlarge the tables when it
    // finishes after other names fill them.
    auth.record_login_failure("fresh", "fresh", now);
    {
        let rate = auth.rate();
        ensure!(rate.by_user.len() == MAX_RATE_BUCKETS);
        ensure!(rate.by_source.len() == MAX_RATE_BUCKETS);
    }
    let later = now + RATE_WINDOW_MS + 1;
    auth.check_rate_limits("fresh", "fresh", later)?;
    auth.record_login_failure("fresh", "fresh", later);
    let rate = auth.rate();
    ensure!(rate.by_user.len() == 1 && rate.by_source.len() == 1);
    Ok(())
}

struct DelayedPostPasswordRead {
    state: Backend,
    lockout: Path,
    reads: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

impl xolotl_state::StateRead for DelayedPostPasswordRead {
    type Read<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = xolotl_state::StateResult<xolotl_state::StateObservation>,
                > + Send
                + 'a,
        >,
    >;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            // Account-keyed factor admission reads this lockout only after the
            // password proof has been verified.
            if path == &self.lockout
                && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
            {
                self.entered.notify_one();
                self.release
                    .acquire()
                    .await
                    .map_err(|error| xolotl_state::StateError::Backend(error.to_string()))?
                    .forget();
            }
            self.state.read_tainted(path).await
        })
    }
}

#[tokio::test]
async fn password_evidence_time_precedes_delayed_post_verification_storage() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let root = read_user(boot.kernel().state(), "root")
        .await?
        .context("root account")?;
    let gate = std::sync::Arc::new(DelayedPostPasswordRead {
        state: boot.kernel().state().clone(),
        lockout: crate::paths::account_lockout_path("local", &root.account_id)?,
        reads: std::sync::atomic::AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    let backend = boot.kernel().state().clone().with_read(gate.clone());
    let mut work = Box::pin(auth.login_inner(
        &backend,
        LoginRequest {
            username: "root".into(),
            password,
            second_factor: None,
        },
        "test".into(),
    ));
    tokio::select! {
        output = &mut work => bail!("login bypassed the storage gate: {output:?}"),
        entered = tokio::time::timeout(Duration::from_secs(2), gate.entered.notified()) => entered?,
    }
    let blocked_at = xolotl_kernel::host::system_now_millis();
    tokio::time::timeout(Duration::from_secs(1), async {
        while xolotl_kernel::host::system_now_millis() <= blocked_at {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    let released_at = xolotl_kernel::host::system_now_millis();
    gate.release.add_permits(1);
    let login = work
        .await?
        .into_session()
        .map_err(|_continuation| anyhow::anyhow!("unexpected continuation"))?;
    let PrimaryAuthentication::Password { verified_at } = login.authentication.primary else {
        bail!("password login retained another primary method");
    };
    ensure!(verified_at <= blocked_at && verified_at < released_at);
    let session = read_session(auth.session_store.as_ref(), &session_path(&login.sid)?)
        .await?
        .context("issued session")?;
    ensure!(session.issued_at >= released_at);
    ensure!(session.authentication == login.authentication);
    Ok(())
}

async fn bootstrap_root_password(boot: &Bootstrap) -> anyhow::Result<String> {
    match bootstrap_root_account(
        boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning::default(),
    )
    .await?
    {
        BootstrapOutcome::CreatedRandomPassword { password, .. } => Ok(password),
        outcome => bail!("expected generated root password, got {outcome:?}"),
    }
}

fn audit_facts(boot: &Bootstrap) -> anyhow::Result<Vec<Fact>> {
    let mut facts = Vec::new();
    for pid in boot.kernel().processes().all_ids() {
        facts.extend(
            boot.kernel()
                .facts()
                .facts_of(pid)
                .with_context(|| format!("read audit facts for process {pid:?}"))?,
        );
    }
    Ok(facts
        .into_iter()
        .filter(|fact| match &fact.outcome {
            Some(value) => value.as_map().is_some_and(|m| m.contains_key("event")),
            _ => false,
        })
        .collect())
}

fn audit_events(boot: &Bootstrap) -> anyhow::Result<Vec<String>> {
    Ok(audit_facts(boot)?
        .into_iter()
        .filter_map(|fact| match fact.outcome {
            Some(value) => value
                .as_map()
                .and_then(|m| m.get("event"))
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        })
        .collect())
}

fn audit_outcomes(boot: &Bootstrap, event: &str) -> anyhow::Result<Vec<String>> {
    Ok(audit_facts(boot)?
        .into_iter()
        .filter_map(|fact| match fact.outcome {
            Some(value)
                if value
                    .as_map()
                    .and_then(|m| m.get("event"))
                    .and_then(Value::as_str)
                    == Some(event) =>
            {
                value
                    .as_map()
                    .and_then(|m| m.get("outcome"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }
            _ => None,
        })
        .collect())
}

#[test]
fn auth_lifetimes_and_workers_are_bounded() {
    let cfg = ConsoleAuthConfig {
        credential_sealer: Some(test_credential_sealer()),
        session_ttl_ms: i64::MAX,
        idle_ttl_ms: i64::MAX,
        argon2_concurrency: 0,
        max_external_verifications: usize::MAX,
        challenges: ConsoleChallengeConfig::default(),
        webauthn: ConsoleWebAuthnConfig::default(),
        mfa: crate::mfa::ConsoleMfaConfig::default(),
    }
    .bounded();
    assert_eq!(cfg.session_ttl_ms, MAX_SESSION_TTL_MS);
    assert_eq!(cfg.idle_ttl_ms, MAX_IDLE_TTL_MS);
    assert_eq!(cfg.argon2_concurrency, MIN_ARGON2_CONCURRENCY);
    assert_eq!(cfg.max_external_verifications, 256);

    let cfg = ConsoleAuthConfig {
        credential_sealer: Some(test_credential_sealer()),
        session_ttl_ms: 30_000,
        idle_ttl_ms: MAX_SESSION_TTL_MS,
        argon2_concurrency: 2,
        max_external_verifications: 0,
        challenges: ConsoleChallengeConfig::default(),
        webauthn: ConsoleWebAuthnConfig::default(),
        mfa: crate::mfa::ConsoleMfaConfig::default(),
    }
    .bounded();
    assert_eq!(cfg.session_ttl_ms, MIN_SESSION_TTL_MS);
    assert_eq!(cfg.idle_ttl_ms, MIN_SESSION_TTL_MS);
    assert_eq!(cfg.max_external_verifications, 1);
}

fn fact_contains_string(fact: &Fact, needle: &str) -> anyhow::Result<bool> {
    Ok(serde_json::to_string(fact)?.contains(needle))
}

fn facts_contain_string(facts: &[Fact], needle: &str) -> anyhow::Result<bool> {
    for fact in facts {
        if fact_contains_string(fact, needle)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn role_value(grants: Vec<&str>, frozen: bool) -> Value {
    let mut m = BTreeMap::new();
    m.insert(
        "grants".into(),
        Value::list(
            grants
                .into_iter()
                .map(|grant| Value::string(grant.into()))
                .collect(),
        ),
    );
    m.insert("frozen".into(), Value::boolean(frozen));
    Value::map(m)
}

#[test]
fn managed_account_identity_is_minted_and_immutable() -> anyhow::Result<()> {
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "admin".into(),
        account_id: "admin-instance".into(),
        identity_path: "identity://console/accounts/admin-instance".into(),
        grants: CapSet::new(),
        authority_ceiling: None,
        authentication: password_authentication(1),
    };
    let path = user_path("alice")?;
    let mut create = Value::map(BTreeMap::from([
        ("status".into(), Value::string("active".into())),
        ("roles".into(), Value::list(Vec::new())),
        ("grants".into(), Value::list(Vec::new())),
        ("authority_ceiling".into(), Value::list(Vec::new())),
    ]));
    prepare_user_config(
        &path,
        None,
        &mut create,
        &principal,
        xolotl_kernel::host::system_now_millis(),
    )?;
    let first = UserRecord::from_value("alice", &create)?;
    ensure!(!first.bootstrap_owner);
    ensure!(first.identity_path == local_identity_path(&first.account_id)?);
    ensure!(first.created_by == "local:admin-instance");

    let mut update = Value::map(BTreeMap::from([
        ("status".into(), Value::string("disabled".into())),
        ("roles".into(), Value::list(Vec::new())),
        ("grants".into(), Value::list(Vec::new())),
        ("authority_ceiling".into(), Value::list(Vec::new())),
    ]));
    prepare_user_config(
        &path,
        Some(&create),
        &mut update,
        &principal,
        xolotl_kernel::host::system_now_millis(),
    )?;
    let changed = UserRecord::from_value("alice", &update)?;
    ensure!(changed.account_key() == first.account_key());
    ensure!(changed.identity_path == first.identity_path);
    ensure!(changed.created_by == first.created_by);
    ensure!(changed.created_at == first.created_at);

    let mut replacement = update.into_map().context("account metadata")?;
    replacement.insert(
        "identity_path".into(),
        Value::string("identity://console/accounts/other".into()),
    )?;
    ensure!(matches!(
        prepare_user_config(
            &path,
            Some(&create),
            &mut Value::from(replacement),
            &principal,
            xolotl_kernel::host::system_now_millis(),
        ),
        Err(AuthError::InvalidCredentialRequest)
    ));
    ensure!(matches!(
        prepare_user_config(
            &user_path("root")?,
            None,
            &mut create,
            &principal,
            xolotl_kernel::host::system_now_millis()
        ),
        Err(AuthError::PermissionDenied)
    ));
    Ok(())
}

#[test]
fn execution_ownership_uses_account_instance_not_username() -> anyhow::Result<()> {
    let owner: ExecutionOwner = serde_json::from_value(serde_json::json!({
        "username": "alice", "account_id": "first-instance", "authority_id": "local", "revocation_epoch": "1", "authority_ceiling": [],
        "credential_epoch": "epoch", "identity_path": "identity://console/accounts/first-instance"
    }))?;
    let renamed: ExecutionOwner = serde_json::from_value(serde_json::json!({
        "username": "alice-renamed", "account_id": "first-instance", "authority_id": "local", "revocation_epoch": "2", "authority_ceiling": [],
        "credential_epoch": "new-epoch", "identity_path": "identity://console/accounts/first-instance"
    }))?;
    let recreated: ExecutionOwner = serde_json::from_value(serde_json::json!({
        "username": "alice", "account_id": "second-instance", "authority_id": "local", "revocation_epoch": "1", "authority_ceiling": [],
        "credential_epoch": "epoch", "identity_path": "identity://console/accounts/second-instance"
    }))?;
    ensure!(owner.same_account(&renamed));
    ensure!(!owner.same_account(&recreated));
    Ok(())
}

#[tokio::test]
async fn bootstrap_privilege_is_bound_to_the_current_account_instance() -> anyhow::Result<()> {
    let boot = auth_boot();
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning::default(),
    )
    .await?;
    let state = boot.kernel().state();
    let root = read_user(state, ROOT_USERNAME).await?.context("root")?;
    let frozen = role_path("frozen")?;
    state.write_set(&frozen, role_value(vec![], true)).await?;
    let mut principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: ROOT_USERNAME.into(),
        account_id: "different-instance".into(),
        identity_path: root.identity_path.clone(),
        grants: CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: password_authentication(1),
    };
    ensure!(matches!(
        authorize_path(
            state,
            &principal,
            "write",
            &frozen,
            Some(&role_value(vec![], false))
        )
        .await,
        Err(AuthError::PermissionDenied)
    ));
    ensure!(matches!(
        authorize_path(state, &principal, "write", &user_path(ROOT_USERNAME)?, None).await,
        Err(AuthError::PermissionDenied)
    ));
    principal.account_id = root.account_id;
    authorize_path(
        state,
        &principal,
        "write",
        &frozen,
        Some(&role_value(vec![], false)),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn random_root_password_preflight_tracks_empty_user_store() -> anyhow::Result<()> {
    let boot = auth_boot();
    ensure!(
        root_random_password_needed(&boot, &RootProvisioning::default()).await?,
        "empty user store should require a random root password"
    );
    ensure!(
        !root_random_password_needed(
            &boot,
            &RootProvisioning {
                password_hash: None,
                password: None,
                pubkeys: vec![TestSigningKey::generate().descriptor()],
                ..Default::default()
            },
        )
        .await?,
        "preseeded key material should skip random root password"
    );

    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning::default(),
    )
    .await?;
    ensure!(
        !root_random_password_needed(&boot, &RootProvisioning::default()).await?,
        "existing root account should skip random root password"
    );
    Ok(())
}

#[tokio::test]
async fn bootstraps_root_and_logs_in() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let principal = auth.authenticate_token(&boot, &login.token).await?;
    ensure!(
        principal.username == "root",
        "unexpected principal username"
    );
    ensure!(
        principal
            .grants
            .contains("write", &Path::parse("state://kernel/x")?),
        "root principal should have kernel state write access"
    );
    ensure!(
        principal
            .grants
            .contains("perform", &Path::parse("effect://external/pairing/create")?),
        "root principal should be able to create pairings"
    );
    ensure!(
        principal
            .grants
            .contains("perform", &Path::parse("effect://proc/spawn")?),
        "root principal should be able to spawn processes"
    );
    let events = audit_events(&boot)?;
    ensure!(
        events.iter().any(|event| event == "console_bootstrap"),
        "missing console bootstrap audit event"
    );
    ensure!(
        events.iter().any(|event| event == "console_login"),
        "missing console login audit event"
    );
    Ok(())
}

#[test]
fn random_tokens_are_valid_path_segments() -> anyhow::Result<()> {
    for _ in 0..128 {
        let token = random_token(18)?;
        validate_session_id(&token)?;
        session_path(&token)?;
    }
    ensure!(
        validate_session_id("-bad").is_err(),
        "leading '-' was accepted"
    );
    ensure!(
        validate_session_id("_bad").is_err(),
        "leading '_' was accepted"
    );
    Ok(())
}

#[tokio::test]
async fn username_validation_is_strict() {
    assert!(validate_username("alice_1").is_ok());
    assert!(validate_username("bad/name").is_err());
    assert!(validate_username(".bad").is_err());
    assert!(validate_username("\u{542b}").is_err());
}

#[test]
fn malformed_user_records_do_not_default_to_active() -> anyhow::Result<()> {
    let user = UserRecord {
        persisted: None,
        username: "alice".into(),
        account_id: "alice-account-id".into(),
        bootstrap_owner: false,
        identity_path: "identity://console/accounts/alice-account-id".into(),
        status: "active".into(),
        roles: Vec::new(),
        grants: Vec::new(),
        authority_ceiling: Vec::new(),
        created_by: "test".into(),
        created_at: 1,
    };

    let mut map = (user.to_value()).into_map().context("expected map")?;
    map.remove("status");
    let missing_status = Value::from(map);
    ensure!(
        UserRecord::from_value("alice", &missing_status).is_err(),
        "missing status defaulted to active"
    );

    let mut map = (user.to_value()).into_map().context("expected map")?;
    map.remove("identity_path");
    let missing_identity = Value::from(map);
    ensure!(
        UserRecord::from_value("alice", &missing_identity).is_err(),
        "missing identity_path was synthesized"
    );

    let mut map = user.to_value().into_map().context("user map")?;
    map.insert("created_at".into(), Value::integer(-1))?;
    ensure!(
        UserRecord::from_value("alice", &Value::from(map)).is_err(),
        "invalid creation time was ignored"
    );

    let mut map = (user.to_value()).into_map().context("expected map")?;
    map.insert(
        "identity_path".into(),
        Value::string("identity://console/**".into()),
    )?;
    let wildcard_identity = Value::from(map);
    ensure!(
        UserRecord::from_value("alice", &wildcard_identity).is_err(),
        "wildcard identity_path was accepted"
    );

    let mut map = (user.to_value()).into_map().context("expected map")?;
    map.insert(
        "identity_path".into(),
        Value::string("path://remote/identity/console/alice".into()),
    )?;
    let clustered_identity = Value::from(map);
    ensure!(
        UserRecord::from_value("alice", &clustered_identity).is_err(),
        "clustered identity_path was accepted"
    );

    let mut map = (user.to_value()).into_map().context("expected map")?;
    map.insert("status".into(), Value::string("locked".into()))?;
    let locked = Value::from(map);
    let locked = UserRecord::from_value("alice", &locked)?;
    ensure!(
        locked.status == "locked",
        "locked status did not round-trip"
    );
    Ok(())
}

#[tokio::test]
async fn refresh_rotates_token_and_invalidates_old_secret() -> anyhow::Result<()> {
    struct OneSessionCommit {
        store: Arc<dyn ConsoleSessionStore>,
        commits: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConsoleSessionStore for OneSessionCommit {
        fn policy(&self) -> ConsoleSessionPolicy {
            self.store.policy()
        }
        async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
            self.store.get(sid).await
        }
        async fn delete(
            &self,
            sid: &str,
            expected: Option<ConsoleSession>,
        ) -> Result<(), SessionStoreError> {
            self.store.delete(sid, expected).await
        }
        async fn list(
            &self,
            after: Option<&str>,
            limits: SessionPageLimits,
        ) -> Result<SessionStorePage, SessionStoreError> {
            self.store.list(after, limits).await
        }
        async fn revoke_account(
            &self,
            authority: &str,
            account: &str,
        ) -> Result<usize, SessionStoreError> {
            self.store.revoke_account(authority, account).await
        }
        async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
            self.store.maintain(now).await
        }
        async fn create(&self, row: ConsoleSession) -> Result<(), SessionStoreError> {
            self.store.create(row).await
        }
        async fn compare_replace(
            &self,
            expected: ConsoleSession,
            row: ConsoleSession,
        ) -> Result<(), SessionStoreError> {
            if self
                .commits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                != 0
            {
                return Err(SessionStoreError::Storage(
                    "second session commit unavailable".into(),
                ));
            }
            self.store.compare_replace(expected, row).await
        }
    }

    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let mut auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let commits = Arc::new(OneSessionCommit {
        store: auth.session_store.clone(),
        commits: std::sync::atomic::AtomicUsize::new(0),
    });
    auth.session_store = commits.clone();
    let atomic = boot.kernel().state().clone();
    let (rotated, _) = auth.refresh_session_inner(&atomic, &login.token).await?;
    ensure!(commits.commits.load(std::sync::atomic::Ordering::SeqCst) == 1);
    ensure!(
        rotated.sid == login.sid,
        "refresh must preserve the session id"
    );
    ensure!(
        rotated.token != login.token,
        "refresh must mint a new token"
    );

    auth.session_store = commits.store.clone();
    // The new token authenticates.
    auth.authenticate_token(&boot, &rotated.token).await?;
    // The old token no longer authenticates.
    ensure!(
        matches!(
            auth.authenticate_token(&boot, &login.token).await,
            Err(AuthError::InvalidSession)
        ),
        "old token still authenticated after rotation"
    );
    Ok(())
}

#[tokio::test]
async fn session_rotation_arbitrates_competing_refresh_and_activity() -> anyhow::Result<()> {
    struct CompetingCommits {
        store: Arc<dyn ConsoleSessionStore>,
        entries: std::sync::atomic::AtomicUsize,
        ready: tokio::sync::Barrier,
    }

    #[async_trait::async_trait]
    impl ConsoleSessionStore for CompetingCommits {
        fn policy(&self) -> ConsoleSessionPolicy {
            self.store.policy()
        }
        async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
            self.store.get(sid).await
        }
        async fn delete(
            &self,
            sid: &str,
            expected: Option<ConsoleSession>,
        ) -> Result<(), SessionStoreError> {
            self.store.delete(sid, expected).await
        }
        async fn list(
            &self,
            after: Option<&str>,
            limits: SessionPageLimits,
        ) -> Result<SessionStorePage, SessionStoreError> {
            self.store.list(after, limits).await
        }
        async fn revoke_account(
            &self,
            authority: &str,
            account: &str,
        ) -> Result<usize, SessionStoreError> {
            self.store.revoke_account(authority, account).await
        }
        async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
            self.store.maintain(now).await
        }

        async fn create(&self, row: ConsoleSession) -> Result<(), SessionStoreError> {
            self.store.create(row).await
        }
        async fn compare_replace(
            &self,
            expected: ConsoleSession,
            row: ConsoleSession,
        ) -> Result<(), SessionStoreError> {
            if self
                .entries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                < 2
            {
                self.ready.wait().await;
            }
            self.store.compare_replace(expected, row).await
        }
    }

    for competing_refresh in [true, false] {
        let boot = auth_boot();
        let state = boot.kernel().state();
        let password = bootstrap_root_password(&boot).await?;
        let mut auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "test".into(),
            )
            .await?
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
        let path = session_path(&login.sid)?;
        let original = read_session(auth.session_store.as_ref(), &path)
            .await?
            .context("session")?;
        let commits = Arc::new(CompetingCommits {
            store: auth.session_store.clone(),
            entries: std::sync::atomic::AtomicUsize::new(0),
            ready: tokio::sync::Barrier::new(2),
        });
        auth.session_store = commits.clone();
        let racing = state.clone();
        let rotated = if competing_refresh {
            let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    auth.refresh_session_inner(&racing, &login.token),
                    auth.refresh_session_inner(&racing, &login.token),
                )
            })
            .await?;
            match (first, second) {
                (Ok((winner, _)), Err(AuthError::InvalidSession))
                | (Err(AuthError::InvalidSession), Ok((winner, _))) => winner,
                _ => bail!("same bearer did not have exactly one rotation winner"),
            }
        } else {
            let mut activity = original.clone();
            activity.last_seen += 10;
            activity.idle_expires_at += 10;
            let (rotation, touch) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    auth.refresh_session_inner(&racing, &login.token),
                    write_session(commits.as_ref(), &path, &activity),
                )
            })
            .await?;
            let (winner, _) = rotation?;
            ensure!(matches!(touch, Ok(_) | Err(AuthError::InvalidSession)));
            if touch.is_ok() {
                let current = read_session(auth.session_store.as_ref(), &path)
                    .await?
                    .context("rotated session")?;
                ensure!(current.last_seen >= activity.last_seen);
                ensure!(current.idle_expires_at >= activity.idle_expires_at);
            }
            winner
        };
        ensure!(commits.entries.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        let current = read_session(auth.session_store.as_ref(), &path)
            .await?
            .context("rotated session")?;
        ensure!(current.idle_expires_at == rotated.idle_expires_at);
        ensure!(current.authentication == original.authentication);
        ensure!(
            current.issued_at == original.issued_at && current.expires_at == original.expires_at
        );
        auth.authenticate_token_inner(state, &rotated.token).await?;
        ensure!(matches!(
            auth.authenticate_token_inner(state, &login.token).await,
            Err(AuthError::InvalidSession)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn refresh_rejects_disabled_and_missing_accounts_without_touching_session()
-> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let state = boot.kernel().state();
    let session_path = session_path(&login.sid)?;
    let original_session = session_value(&auth, &session_path).await?;
    let mut user = read_user(state, "root").await?.context("root user")?;
    user.status = "disabled".into();
    write_user(state, &user).await?;
    ensure!(matches!(
        auth.refresh_session(&boot, &login.token, Some("test"))
            .await,
        Err(AuthError::AccountUnavailable)
    ));
    ensure!(session_value(&auth, &session_path).await? == original_session);

    state.write_delete(&user_path("root")?).await?;
    ensure!(matches!(
        auth.refresh_session(&boot, &login.token, Some("test"))
            .await,
        Err(AuthError::AccountUnavailable)
    ));
    ensure!(session_value(&auth, &session_path).await? == original_session);
    let outcomes = audit_outcomes(&boot, "console_credential")?;
    ensure!(outcomes.iter().any(|v| v == "account_unavailable"));
    ensure!(
        outcomes
            .iter()
            .filter(|v| *v == "account_unavailable")
            .count()
            >= 2
    );
    ensure!(!outcomes.iter().any(|v| v == "token_refresh"));
    Ok(())
}

#[tokio::test]
async fn bearer_logout_revokes_session() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    auth.logout_sid_from_source(&boot, &login.sid, Some("203.0.113.10"))
        .await?;
    ensure!(
        matches!(
            auth.authenticate_token(&boot, &login.token).await,
            Err(AuthError::InvalidSession)
        ),
        "revoked bearer token still authenticated"
    );
    let events = audit_events(&boot)?;
    ensure!(
        events.iter().any(|event| event == "console_credential"),
        "missing console credential audit event"
    );
    let facts = audit_facts(&boot)?;
    ensure!(
        facts.into_iter().any(|fact| {
            let Some(value) = fact.outcome else {
                return false;
            };
            let Some(m) = value.as_map() else {
                return false;
            };
            m.get("event").and_then(Value::as_str) == Some("console_credential")
                && m.get("outcome").and_then(Value::as_str) == Some("logout")
                && m.get("username").and_then(Value::as_str) == Some("root")
                && m.get("source_addr").and_then(Value::as_str) == Some("203.0.113.10")
                && m.get("mfa_level").is_none()
                && m.get("details").is_none()
        }),
        "missing logout audit fact with source address"
    );
    Ok(())
}

#[tokio::test]
async fn step_up_issues_new_session_without_reusing_token() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(
        login.authentication.mfa_level() == 1,
        "initial login should have MFA level 1"
    );
    let enrolled = auth.enroll_test_totp(&boot, &login.token).await?;
    let elevated = auth
        .step_up(
            &boot,
            &enrolled.token,
            StepUpRequest {
                proof: Some(auth.next_test_totp(&boot, "root").await?),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(
        elevated.sid != enrolled.sid,
        "step-up should issue a new session id"
    );
    ensure!(
        elevated.token != enrolled.token,
        "step-up should issue a new bearer token"
    );
    ensure!(
        elevated.authentication.mfa_level() == 2,
        "step-up should raise MFA level"
    );
    ensure!(elevated.authentication.primary == login.authentication.primary);
    ensure!(
        auth.authenticate_token(&boot, &enrolled.token)
            .await?
            .authentication
            == enrolled.authentication,
        "original session MFA level changed"
    );
    ensure!(
        auth.authenticate_token(&boot, &elevated.token)
            .await?
            .authentication
            .mfa_level()
            == 2,
        "elevated session did not authenticate at MFA level 2"
    );
    let facts = audit_facts(&boot)?;
    ensure!(
        !facts_contain_string(&facts, &login.token)?,
        "audit facts leaked original bearer token"
    );
    ensure!(
        !facts_contain_string(&facts, &elevated.token)?,
        "audit facts leaked elevated bearer token"
    );
    Ok(())
}

#[tokio::test]
async fn root_can_list_and_revoke_console_sessions() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login1 = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "test-a".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let login2 = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test-b".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let principal = auth.authenticate_token(&boot, &login1.token).await?;
    let sessions = auth
        .list_sessions(
            &boot,
            &principal,
            &xolotl_state::StateScan::new(Path::parse(SESSIONS_PREFIX)?),
        )
        .await?;
    ensure!(
        sessions.entries.iter().any(|s| s.sid == login1.sid),
        "first session missing from session list"
    );
    ensure!(
        sessions.entries.iter().any(|s| s.sid == login2.sid),
        "second session missing from session list"
    );
    let public = serde_json::to_value(&sessions.entries)?;
    ensure!(
        public
            .as_array()
            .context("session summaries")?
            .iter()
            .all(|summary| {
                summary.get("token_hash").is_none()
                    && summary.get("credential_epoch").is_none()
                    && summary.get("authority_ceiling").is_none()
            })
    );
    ensure!(
        boot.kernel()
            .state()
            .read(&crate::paths::session_path(&login1.sid)?)
            .await?
            .is_none()
    );

    auth.revoke_session_by_id_from_source(&boot, &principal, &login2.sid, None)
        .await?;
    ensure!(
        matches!(
            auth.authenticate_token(&boot, &login2.token).await,
            Err(AuthError::InvalidSession)
        ),
        "revoked session still authenticated"
    );
    let events = audit_events(&boot)?;
    ensure!(
        events.iter().any(|event| event == "console_credential"),
        "missing console credential audit event"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_console_session_state_is_rejected() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let principal = auth.authenticate_token(&boot, &login.token).await?;
    boot.kernel()
        .state()
        .write_set(&session_path("malformed")?, Value::map(BTreeMap::new()))
        .await?;

    let page = auth
        .list_sessions(
            &boot,
            &principal,
            &xolotl_state::StateScan::new(Path::parse(SESSIONS_PREFIX)?),
        )
        .await?;
    ensure!(page.entries.len() == 1 && page.entries[0].sid == login.sid);
    ensure!(
        ConsoleSession::decode(
            "malformed",
            &serde_json::to_vec(&Value::map(BTreeMap::new()))?
        )
        .is_err()
    );

    let valid = read_session(auth.session_store.as_ref(), &session_path(&login.sid)?)
        .await?
        .context("login session")?
        .to_value();
    for verifier in [
        None,
        Some(String::new()),
        Some("A".repeat(42)),
        Some(format!("{}B", "A".repeat(42))),
        Some(format!("{}=", "A".repeat(43))),
    ] {
        let mut record = valid.clone().into_map().context("session map")?;
        if let Some(verifier) = verifier {
            record.insert("token_hash".into(), Value::string(verifier))?;
        } else {
            record.remove("token_hash");
        }
        ensure!(matches!(
            SessionRecord::from_value(&login.sid, &Value::from(record)),
            Err(AuthError::InvalidSession)
        ));
    }
    let mut missing_authentication = valid.into_map().context("session map")?;
    missing_authentication.remove("authentication");
    missing_authentication.insert("mfa_level".into(), Value::integer(2))?;
    missing_authentication.insert(
        "authenticated_at".into(),
        Value::integer(xolotl_kernel::host::system_now_millis()),
    )?;
    ensure!(
        matches!(
            SessionRecord::from_value(&login.sid, &Value::from(missing_authentication)),
            Err(AuthError::InvalidSession)
        ),
        "legacy summaries must not substitute for missing authentication evidence"
    );

    let malformed_identity = SessionRecord {
        persisted: None,
        sid: "malformed-identity".into(),
        token_hash: token_hash("test-secret"),
        credential_epoch: String::new(),
        account_id: "test-account".into(),
        authority_id: "local".into(),
        revocation_epoch: "1".into(),
        username: "root".into(),
        identity_path: "identity://console/**".into(),
        issued_at: 1,
        expires_at: i64::MAX,
        idle_expires_at: i64::MAX,
        authentication: password_authentication(1),
        authority_ceiling: None,
        last_seen: 1,
        source_addr: "test".into(),
    }
    .to_value();
    ensure!(
        SessionRecord::from_value("malformed-identity", &malformed_identity).is_err(),
        "wildcard session identity was accepted"
    );
    Ok(())
}

#[tokio::test]
async fn root_can_revoke_all_sessions_for_user() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login1 = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "test-a".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let login2 = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test-b".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let principal = auth.authenticate_token(&boot, &login1.token).await?;
    let revoked = auth
        .revoke_user_sessions_from_source(&boot, &principal, "root", None)
        .await?;
    ensure!(revoked >= 2, "expected at least two revoked sessions");
    ensure!(
        matches!(
            auth.authenticate_token(&boot, &login1.token).await,
            Err(AuthError::InvalidSession)
        ),
        "first revoked session still authenticated"
    );
    ensure!(
        matches!(
            auth.authenticate_token(&boot, &login2.token).await,
            Err(AuthError::InvalidSession)
        ),
        "second revoked session still authenticated"
    );
    Ok(())
}

#[tokio::test]
async fn root_extra_authority_is_validated_and_only_applied_at_first_provisioning()
-> anyhow::Result<()> {
    let boot = auth_boot();
    let invalid = bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            additional_grants: vec!["not-a-capability".into()],
            ..Default::default()
        },
    )
    .await;
    ensure!(invalid.is_err());
    ensure!(
        read_user(boot.kernel().state(), ROOT_USERNAME)
            .await?
            .is_none()
    );
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            additional_grants: vec!["perform://effect/example/**".into()],
            ..Default::default()
        },
    )
    .await?;
    let root = read_user(boot.kernel().state(), ROOT_USERNAME)
        .await?
        .context("root")?;
    let custom = Path::parse("effect://example/run")?;
    ensure!(
        effective_grants(boot.kernel().state(), &root)
            .await?
            .contains("perform", &custom)
    );
    ensure!(capset_from_strings(&root.authority_ceiling)?.contains("perform", &custom));
    ensure!(
        bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            RootProvisioning {
                additional_grants: vec!["perform://effect/other/**".into()],
                ..Default::default()
            }
        )
        .await?
            == BootstrapOutcome::AlreadyPresent
    );
    let reloaded = read_user(boot.kernel().state(), ROOT_USERNAME)
        .await?
        .context("root")?;
    ensure!(reloaded.grants == root.grants && reloaded.authority_ceiling == root.authority_ceiling);
    Ok(())
}

#[tokio::test]
async fn root_password_and_hash_are_mutually_exclusive() -> anyhow::Result<()> {
    let boot = auth_boot();
    let phc = hash_password_with_salt("strong-root-password-9qL", &[1u8; 16])?;
    let err = match bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            password_hash: Some(phc),
            password: Some("another-strong-root-password-8pK".into()),
            pubkeys: Vec::new(),
            ..Default::default()
        },
    )
    .await
    {
        Ok(outcome) => bail!("unexpected bootstrap success: {outcome:?}"),
        Err(error) => error,
    };
    ensure!(
        matches!(err, AuthError::Crypto(ref message) if message.contains("mutually exclusive")),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn pubkey_only_root_can_use_single_use_challenge_login() -> anyhow::Result<()> {
    let boot = auth_boot();
    let signing_key = TestSigningKey::generate();
    let descriptor = signing_key.descriptor();
    let outcome = bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            password_hash: None,
            password: None,
            pubkeys: vec![descriptor.clone()],
            ..Default::default()
        },
    )
    .await?;
    let expected = BootstrapOutcome::CreatedPreseeded {
        username: "root".into(),
    };
    ensure!(
        outcome == expected,
        "unexpected bootstrap outcome: {outcome:?}"
    );

    let auth = test_auth()?;
    let challenge = auth
        .begin_key_login(
            &boot,
            KeyChallengeRequest {
                username: "root".into(),
                origin: "https://console.local".into(),
            },
            "test".into(),
        )
        .await?;
    let outcomes = audit_outcomes(&boot, "console_credential")?;
    ensure!(
        outcomes.iter().any(|outcome| outcome == "key_challenge"),
        "missing key challenge audit outcome"
    );
    let signature = signing_key.sign(challenge.transcript.as_bytes());
    let login = auth
        .finish_key_login(
            &boot,
            KeyLoginRequest {
                username: "root".into(),
                challenge_id: challenge.challenge_id.clone(),
                signature: URL_SAFE_NO_PAD.encode(signature),
                origin: "https://console.local".into(),
                key: descriptor.clone(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let principal = auth.authenticate_token(&boot, &login.token).await?;
    ensure!(principal.authentication == login.authentication);
    ensure!(matches!(
        &login.authentication.primary,
        PrimaryAuthentication::PublicKey { credential_key, verified_at }
            if credential_key == &descriptor && *verified_at <= xolotl_kernel::host::system_now_millis()
    ));
    ensure!(login.authentication.secondary.is_none());
    ensure!(
        principal.username == "root",
        "unexpected principal username"
    );

    let reused = signing_key.sign(challenge.transcript.as_bytes());
    ensure!(
        matches!(
            auth.finish_key_login(
                &boot,
                KeyLoginRequest {
                    username: "root".into(),
                    challenge_id: challenge.challenge_id,
                    signature: URL_SAFE_NO_PAD.encode(reused),
                    origin: "https://console.local".into(),
                    key: descriptor.clone(),
                    second_factor: None,
                },
                "test".into(),
            )
            .await,
            Err(AuthError::InvalidChallenge)
        ),
        "single-use key challenge was accepted twice"
    );
    let events = audit_events(&boot)?;
    ensure!(
        events.iter().any(|event| event == "console_login"),
        "missing key login audit event"
    );
    ensure!(
        events.iter().any(|event| event == "console_login_failed"),
        "missing replay failure audit event"
    );
    for fact in audit_facts(&boot)? {
        let Some(record) = fact.outcome.as_ref().and_then(Value::as_map) else {
            continue;
        };
        ensure!(record.get("mfa_level").is_none());
        match record.get("event").and_then(Value::as_str) {
            Some("console_login") => {
                ensure!(
                    record
                        .get("details")
                        .and_then(Value::as_map)
                        .and_then(|details| details.get("authentication"))
                        .and_then(Value::as_map)
                        .and_then(|authentication| authentication.get("mfa_level"))
                        .and_then(Value::as_int)
                        == Some(1)
                );
            }
            Some("console_login_failed") => ensure!(record.get("details").is_none()),
            _ => {}
        }
    }
    Ok(())
}

#[tokio::test]
async fn root_cannot_self_lock_or_self_demote() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let principal = auth.authenticate_token(&boot, &login.token).await?;
    let path = Path::parse("state://kernel/console/users/root")?;
    let mut root = read_user(state, "root")
        .await?
        .context("root user missing after bootstrap")?;

    root.status = "disabled".into();
    ensure!(
        matches!(
            authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
            Err(AuthError::PermissionDenied)
        ),
        "root was allowed to self-lock"
    );

    let mut root = read_user(state, "root")
        .await?
        .context("root user missing after disabled self-lock check")?;
    root.status = "locked".into();
    ensure!(
        matches!(
            authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
            Err(AuthError::PermissionDenied)
        ),
        "root was allowed to self-lock with locked status"
    );

    let mut root = read_user(state, "root")
        .await?
        .context("root user missing after self-lock check")?;
    root.grants = vec!["read://state/kernel/**".into()];
    root.authority_ceiling = root.grants.clone();
    ensure!(
        matches!(
            authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
            Err(AuthError::PermissionDenied)
        ),
        "root was allowed to self-demote"
    );

    Ok(())
}

#[tokio::test]
async fn locked_user_cannot_login() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state();
    let password = bootstrap_root_password(&boot).await?;
    let mut root = read_user(state, "root")
        .await?
        .context("root user missing after bootstrap")?;
    root.status = "locked".into();
    write_user(state, &root).await?;

    let auth = test_auth()?;
    ensure!(
        matches!(
            auth.login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "test".into(),
            )
            .await,
            Err(AuthError::AccountUnavailable)
        ),
        "locked user was able to login"
    );
    Ok(())
}

#[tokio::test]
async fn authentication_updates_cannot_restore_stale_account_state() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state();
    let _password = bootstrap_root_password(&boot).await?;
    let mut authentication = read_user(state, "root").await?.context("missing root")?;
    let previous_version = authentication.version();
    let mut administration = authentication.clone();
    administration.status = "disabled".into();
    write_user(state, &administration).await?;
    authentication.created_by = "stale-administrator".into();
    ensure!(matches!(
        write_user(state, &authentication).await,
        Err(AuthError::InvalidCredentials)
    ));
    let current = read_user(state, "root").await?.context("missing root")?;
    ensure!(current.status == "disabled");
    let record = current.persisted.context("missing persisted record")?;
    ensure!(
        record
            .as_map()
            .and_then(|map| map.get("version"))
            .and_then(Value::as_int)
            == Some(previous_version + 1)
    );
    Ok(())
}

#[tokio::test]
async fn session_limits_order_replacements_by_issuance_not_authentication() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state();
    bootstrap_root_password(&boot).await?;
    let mut auth = test_auth()?;
    auth.session_store = Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
        ConsoleSessionPolicy::new(2, 10)?,
    ));
    let user = read_user(state, "root").await?.context("root user")?;
    let account = auth.local_snapshot(state, &user).await?;
    let epoch = credentials::epoch(
        state,
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let now = xolotl_kernel::host::system_now_millis();
    let first = auth
        .issue_session(
            state,
            &account,
            "test".into(),
            password_authentication(now - 30_000),
            epoch.clone(),
            None,
        )
        .await?;
    let first_path = session_path(&first.sid)?;
    let mut first_record = read_session(auth.session_store.as_ref(), &first_path)
        .await?
        .context("first session")?;
    // Fix the earlier issuance without sleeps or millisecond clock races.
    first_record.issued_at = now - 30_000;
    replace_session_for_test(&auth, &first_path, first_record.to_value()).await?;

    let authenticated_at = now - 60_000;
    let replacement = auth
        .issue_session(
            state,
            &account,
            "test".into(),
            password_authentication(authenticated_at),
            epoch,
            None,
        )
        .await?;
    let replacement_path = session_path(&replacement.sid)?;
    let replacement_record = read_session(auth.session_store.as_ref(), &replacement_path)
        .await?
        .context("replacement session")?;
    ensure!(replacement_record.issued_at >= now);
    ensure!(replacement_record.authentication.authenticated_at() == Some(authenticated_at));
    let summary = SessionSummary::from(replacement_record.clone());
    ensure!(summary.issued_at == replacement_record.issued_at);
    ensure!(summary.authentication.authenticated_at() == Some(authenticated_at));

    // Reserve one slot for the next session. The recently issued replacement
    // survives even though its authentication is older than the first one.
    auth.issue_session(
        state,
        &account,
        "test".into(),
        password_authentication(now),
        replacement_record.credential_epoch.clone(),
        None,
    )
    .await?;
    ensure!(
        read_session(auth.session_store.as_ref(), &first_path)
            .await?
            .is_none()
    );
    ensure!(
        read_session(auth.session_store.as_ref(), &replacement_path)
            .await?
            .is_some()
    );

    let refreshed = auth
        .refresh_session(&boot, &replacement.token, Some("test"))
        .await?;
    let refreshed_record =
        read_session(auth.session_store.as_ref(), &session_path(&refreshed.sid)?)
            .await?
            .context("refreshed session")?;
    ensure!(refreshed_record.issued_at == replacement_record.issued_at);
    ensure!(refreshed_record.authentication.authenticated_at() == Some(authenticated_at));
    ensure!(refreshed.authentication == replacement.authentication);
    ensure!(refreshed_record.authentication == replacement_record.authentication);
    ensure!(refreshed_record.expires_at == replacement_record.expires_at);
    Ok(())
}

#[tokio::test]
async fn session_revalidation_uses_current_authority_and_completion_deadlines() -> anyhow::Result<()>
{
    struct ManualClock(std::sync::atomic::AtomicI64);

    impl xolotl_kernel::host::HostClock for ManualClock {
        fn monotonic_now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }

        fn unix_millis(&self) -> i64 {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn sleep_until(
            &self,
            _deadline: std::time::Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct NoTasks;

    impl xolotl_kernel::host::TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn xolotl_kernel::host::AbortTask>, xolotl_kernel::host::TaskSpawnError>
        {
            Err(xolotl_kernel::host::TaskSpawnError::Unavailable)
        }
    }

    enum Change {
        Revoke,
        Replace(Value),
        AdvanceClock(i64),
    }

    enum Boundary {
        AccountRead,
        SessionCommit,
    }

    struct DuringAuthentication {
        state: Backend,
        store: Arc<dyn ConsoleSessionStore>,
        account_path: Path,
        session_path: Path,
        change: Change,
        boundary: Boundary,
        clock: Arc<ManualClock>,
        armed: std::sync::atomic::AtomicBool,
    }

    impl DuringAuthentication {
        async fn apply_change(&self) -> Result<(), SessionStoreError> {
            match &self.change {
                Change::Revoke => {
                    self.store
                        .delete(
                            crate::paths::stored_session_id_from_path(&self.session_path)
                                .ok_or_else(|| {
                                    crate::session_store::storage_error("expected fixture SID")
                                })?,
                            None,
                        )
                        .await?;
                }
                Change::Replace(value) => {
                    let sid = crate::paths::stored_session_id_from_path(&self.session_path)
                        .ok_or_else(|| {
                            crate::session_store::storage_error("expected fixture SID")
                        })?;
                    let expected = self.store.get(sid).await?.ok_or_else(|| {
                        crate::session_store::storage_error("expected fixture row")
                    })?;
                    let row = ConsoleSession::decode(
                        sid,
                        &serde_json::to_vec(value).map_err(crate::session_store::storage_error)?,
                    )?;
                    self.store.compare_replace(expected, row).await?;
                }
                Change::AdvanceClock(now) => self
                    .clock
                    .0
                    .store(*now, std::sync::atomic::Ordering::SeqCst),
            }
            Ok(())
        }
    }

    impl xolotl_state::StateRead for DuringAuthentication {
        type Read<'a> = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = xolotl_state::StateResult<xolotl_state::StateObservation>,
                    > + Send
                    + 'a,
            >,
        >;

        fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
            Box::pin(async move {
                let observed = self.state.read_tainted(path).await?;
                if matches!(self.boundary, Boundary::AccountRead)
                    && path == &self.account_path
                    && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    self.apply_change()
                        .await
                        .map_err(|error| xolotl_state::StateError::Backend(error.to_string()))?;
                }
                Ok(observed)
            })
        }
    }

    impl xolotl_state::StateWrite for DuringAuthentication {
        type Write<'a> = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = xolotl_state::StateResult<xolotl_state::StateCommit>,
                    > + Send
                    + 'a,
            >,
        >;

        fn mutate<'a>(
            &'a self,
            path: &'a Path,
            mutation: xolotl_state::StateMutation,
        ) -> Self::Write<'a> {
            Box::pin(async move {
                let committed = self.state.mutate(path, mutation).await?;
                Ok(committed)
            })
        }
    }

    #[async_trait::async_trait]
    impl ConsoleSessionStore for DuringAuthentication {
        fn policy(&self) -> ConsoleSessionPolicy {
            self.store.policy()
        }
        async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
            self.store.get(sid).await
        }
        async fn delete(
            &self,
            sid: &str,
            expected: Option<ConsoleSession>,
        ) -> Result<(), SessionStoreError> {
            self.store.delete(sid, expected).await
        }
        async fn list(
            &self,
            after: Option<&str>,
            limits: SessionPageLimits,
        ) -> Result<SessionStorePage, SessionStoreError> {
            self.store.list(after, limits).await
        }
        async fn revoke_account(
            &self,
            authority: &str,
            account: &str,
        ) -> Result<usize, SessionStoreError> {
            self.store.revoke_account(authority, account).await
        }
        async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
            self.store.maintain(now).await
        }

        async fn create(&self, row: ConsoleSession) -> Result<(), SessionStoreError> {
            self.store.create(row).await?;
            if matches!(self.boundary, Boundary::SessionCommit)
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.apply_change().await?;
            }
            Ok(())
        }
        async fn compare_replace(
            &self,
            expected: ConsoleSession,
            row: ConsoleSession,
        ) -> Result<(), SessionStoreError> {
            self.store.compare_replace(expected, row).await?;
            if matches!(self.boundary, Boundary::SessionCommit)
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.apply_change().await?;
            }
            Ok(())
        }
    }

    let mut failures = Vec::new();
    for case in [
        "revoke",
        "authority",
        "idle_readonly",
        "rotate",
        "activity",
        "owner_revoke",
        "owner_idle",
        "owner_activity",
        "idle_touch",
        "idle_bearer",
        "idle_refresh",
        "commit_touch",
        "commit_bearer",
        "commit_refresh",
        "commit_issue",
    ] {
        let boot = auth_boot();
        let state = boot.kernel().state().clone();
        let password = bootstrap_root_password(&boot).await?;
        let clock = Arc::new(ManualClock(std::sync::atomic::AtomicI64::new(
            xolotl_kernel::host::system_now_millis(),
        )));
        let mut auth = test_auth()?;
        auth.host_runtime = xolotl_kernel::host::HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        );
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "test".into(),
            )
            .await?
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
        let path = session_path(&login.sid)?;
        let original = read_session(auth.session_store.as_ref(), &path)
            .await?
            .context("session")?;
        let mut changed = original.clone();
        let change = match case {
            "revoke" | "owner_revoke" => Change::Revoke,
            "authority" => {
                changed.authority_ceiling = Some(CapSet::default());
                Change::Replace(changed.to_value())
            }
            "rotate" => {
                changed.token_hash = token_hash("rotated-secret");
                Change::Replace(changed.to_value())
            }
            "activity" | "owner_activity" => {
                changed.last_seen += 10;
                changed.idle_expires_at += 10;
                Change::Replace(changed.to_value())
            }
            _ => Change::AdvanceClock(original.idle_expires_at + 1),
        };
        let mut events = state.subscribe(&path).await?;
        let gate = Arc::new(DuringAuthentication {
            state: state.clone(),
            store: auth.session_store.clone(),
            account_path: user_path("root")?,
            session_path: path,
            change,
            boundary: if case.starts_with("commit_") {
                Boundary::SessionCommit
            } else {
                Boundary::AccountRead
            },
            clock,
            armed: std::sync::atomic::AtomicBool::new(true),
        });
        let principal = auth.validate_sid(&boot, &login.sid).await?;
        auth.session_store = gate.clone();
        let checked = Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(
                state.with_read(gate.clone()).with_write(gate.clone()),
            )
            .build(),
        );
        let result = match case {
            "owner_revoke" | "owner_idle" | "owner_activity" => auth
                .execution_owner(&checked, &login.sid, &principal)
                .await
                .map(|_| ()),
            "idle_touch" | "commit_touch" => auth
                .authenticate_sid(&checked, &login.sid)
                .await
                .map(|_| ()),
            "idle_bearer" | "commit_bearer" => auth
                .authenticate_token_inner(checked.kernel().state(), &login.token)
                .await
                .map(|_| ()),
            "idle_refresh" | "commit_refresh" => auth
                .refresh_session_inner(checked.kernel().state(), &login.token)
                .await
                .map(|_| ()),
            "commit_issue" => {
                let account = auth
                    .current_account(
                        checked.kernel().state(),
                        &original.account_key(),
                        Some("root"),
                    )
                    .await?;
                auth.issue_session(
                    checked.kernel().state(),
                    &account,
                    "test".into(),
                    original.authentication.clone(),
                    original.credential_epoch.clone(),
                    original.authority_ceiling.clone(),
                )
                .await
                .map(|_| ())
            }
            _ => auth.validate_sid(&checked, &login.sid).await.map(|_| ()),
        };
        ensure!(
            !gate.armed.load(std::sync::atomic::Ordering::SeqCst),
            "{case} did not reach its awaited authentication boundary"
        );
        let expected_valid = matches!(case, "rotate" | "activity" | "owner_activity");
        let expected_result = match &result {
            Ok(()) => expected_valid,
            Err(AuthError::InvalidCredentials) => case == "commit_issue",
            Err(AuthError::InvalidSession) => !expected_valid && case != "commit_issue",
            Err(_) => false,
        };
        if !expected_result {
            failures.push(case);
        }
        if matches!(gate.boundary, Boundary::AccountRead) {
            ensure!(
                matches!(events.try_recv(), Err(xolotl_state::StateWatchError::Empty)),
                "{case} wrote during read-only or already-expired validation"
            );
        }
    }
    ensure!(
        failures.is_empty(),
        "incorrect terminal validation: {failures:?}"
    );
    Ok(())
}

#[tokio::test]
async fn session_activity_cannot_overwrite_immutable_times_or_authentication_evidence()
-> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state();
    bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let user = read_user(state, "root").await?.context("root user")?;
    let account = auth.local_snapshot(state, &user).await?;
    let login = auth
        .issue_session(
            state,
            &account,
            "test".into(),
            password_authentication(xolotl_kernel::host::system_now_millis() - 60_000),
            credentials::epoch(
                state,
                "root",
                crate::auth::test_credential_sealer().as_ref(),
            )
            .await?,
            None,
        )
        .await?;
    let path = session_path(&login.sid)?;
    for field in [
        "issued_at",
        "authentication_time",
        "authentication_method",
        "authentication_credential",
    ] {
        let mut stale = read_session(auth.session_store.as_ref(), &path)
            .await?
            .context("session")?;
        let mut changed = stale.clone();
        if field == "issued_at" {
            changed.issued_at -= 1;
        } else if field == "authentication_time" {
            changed.authentication = password_authentication(
                changed
                    .authentication
                    .authenticated_at()
                    .context("local authentication")?
                    - 1,
            );
        } else {
            let key = TestSigningKey::generate();
            changed.authentication.primary = PrimaryAuthentication::PublicKey {
                credential_key: key.descriptor(),
                verified_at: changed
                    .authentication
                    .authenticated_at()
                    .context("local authentication")?,
            };
            ensure!(changed.authentication.mfa_level() == stale.authentication.mfa_level());
            ensure!(
                changed.authentication.authenticated_at()
                    == stale.authentication.authenticated_at()
            );
        }
        let changed_value = changed.to_value();
        replace_session_for_test(&auth, &path, changed_value.clone()).await?;
        stale.last_seen += 10;
        stale.idle_expires_at += 10;
        ensure!(matches!(
            write_session(auth.session_store.as_ref(), &path, &stale).await,
            Err(AuthError::InvalidSession)
        ));
        ensure!(session_value(&auth, &path).await? == Some(changed_value));
    }
    Ok(())
}

#[tokio::test]
async fn session_activity_merges_but_cannot_resurrect_a_revoked_session() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state();
    let password = bootstrap_root_password(&boot).await?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let path = session_path(&login.sid)?;
    let mut first = read_session(auth.session_store.as_ref(), &path)
        .await?
        .context("missing session")?;
    let mut second = first.clone();
    first.last_seen += 10;
    first.idle_expires_at += 10;
    second.last_seen += 20;
    second.idle_expires_at += 20;
    // Complete the newer observation first; a stale touch must not shorten
    // the idle window, even when its original CAS fails.
    write_session(auth.session_store.as_ref(), &path, &second).await?;
    write_session(auth.session_store.as_ref(), &path, &first).await?;
    let current = read_session(auth.session_store.as_ref(), &path)
        .await?
        .context("missing session")?;
    ensure!(current.last_seen == second.last_seen);
    ensure!(current.idle_expires_at == second.idle_expires_at);
    let (rotated, _) = auth.refresh_session_inner(state, &login.token).await?;
    let after_rotation = session_value(&auth, &path)
        .await?
        .context("rotated session")?;
    ensure!(matches!(
        write_session(auth.session_store.as_ref(), &path, &first).await,
        Err(AuthError::InvalidSession)
    ));
    ensure!(session_value(&auth, &path).await? == Some(after_rotation));
    auth.authenticate_token_inner(state, &rotated.token).await?;
    ensure!(matches!(
        auth.authenticate_token_inner(state, &login.token).await,
        Err(AuthError::InvalidSession)
    ));
    revoke_session(auth.session_store.as_ref(), &login.sid).await?;
    ensure!(matches!(
        write_session(auth.session_store.as_ref(), &path, &first).await,
        Err(AuthError::InvalidSession)
    ));
    ensure!(session_value(&auth, &path).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn uncertain_creation_reconciles_only_the_original_sid() -> anyhow::Result<()> {
    struct UncertainStore {
        store: Arc<dyn ConsoleSessionStore>,
        commit: bool,
        mismatch: bool,
        authority_mismatch: bool,
        expired: bool,
        attempted: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ConsoleSessionStore for UncertainStore {
        fn policy(&self) -> ConsoleSessionPolicy {
            self.store.policy()
        }
        async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
            self.store.get(sid).await
        }
        async fn delete(
            &self,
            sid: &str,
            expected: Option<ConsoleSession>,
        ) -> Result<(), SessionStoreError> {
            self.store.delete(sid, expected).await
        }
        async fn list(
            &self,
            after: Option<&str>,
            limits: SessionPageLimits,
        ) -> Result<SessionStorePage, SessionStoreError> {
            self.store.list(after, limits).await
        }
        async fn revoke_account(
            &self,
            authority: &str,
            account: &str,
        ) -> Result<usize, SessionStoreError> {
            self.store.revoke_account(authority, account).await
        }
        async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
            self.store.maintain(now).await
        }

        async fn create(&self, mut row: ConsoleSession) -> Result<(), SessionStoreError> {
            self.attempted
                .lock()
                .map_err(crate::session_store::storage_error)?
                .push(row.sid().to_owned());
            if self.mismatch {
                row.record.token_hash = token_hash("another-secret");
            }
            if self.authority_mismatch {
                row.record.revocation_epoch = "changed".into();
            }
            if self.expired {
                row.record.idle_expires_at = 0;
            }
            if self.commit {
                self.store.create(row).await?;
            }
            Err(SessionStoreError::Unknown("injected result loss".into()))
        }
        async fn compare_replace(
            &self,
            expected: ConsoleSession,
            row: ConsoleSession,
        ) -> Result<(), SessionStoreError> {
            self.store.compare_replace(expected, row).await
        }
    }

    for (commit, mismatch, authority_mismatch, expired) in [
        (true, false, false, false),
        (false, false, false, false),
        (true, true, false, false),
        (true, false, true, false),
        (true, false, false, true),
    ] {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let mut auth = test_auth()?;
        let gate = Arc::new(UncertainStore {
            store: auth.session_store.clone(),
            commit,
            mismatch,
            authority_mismatch,
            expired,
            attempted: Mutex::new(Vec::new()),
        });
        auth.session_store = gate.clone();
        let result = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "test".into(),
            )
            .await;
        let attempted = gate
            .attempted
            .lock()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .clone();
        ensure!(attempted.len() == 1, "unknown creation retried a fresh SID");
        match result {
            Ok(AuthenticationResponse::Authenticated { session })
                if commit && !mismatch && !authority_mismatch && !expired =>
            {
                ensure!(session.sid == attempted[0]);
                auth.authenticate_token(&boot, &session.token).await?;
            }
            Err(AuthError::SessionCommitUnknown) if !commit => {}
            Err(AuthError::InvalidSession) if mismatch || authority_mismatch => {}
            Err(AuthError::InvalidCredentials) if expired => {
                ensure!(gate.store.get(&attempted[0]).await?.is_none());
            }
            result => bail!("incorrect creation reconciliation: {result:?}"),
        }
    }
    Ok(())
}

#[tokio::test]
async fn oversized_creation_and_stale_expiry_do_not_evict_retained_sessions() -> anyhow::Result<()>
{
    let boot = auth_boot();
    let password = bootstrap_root_password(&boot).await?;
    let mut auth = test_auth()?;
    auth.session_store = Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
        ConsoleSessionPolicy::new(1, 1)?,
    ));
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_challenge| anyhow::anyhow!("session"))?;
    let path = session_path(&login.sid)?;
    let original = read_session(auth.session_store.as_ref(), &path)
        .await?
        .context("original")?;
    let mut large = original.clone();
    large.sid = "oversized".into();
    large.persisted = None;
    large.source_addr = "x".repeat(crate::session_store::MAX_SESSION_ROW_BYTES);
    ensure!(matches!(
        auth.session_store
            .create(ConsoleSession::from_record(large))
            .await,
        Err(SessionStoreError::Rejected(_))
    ));
    ensure!(session_value(&auth, &path).await? == Some(original.to_value()));
    let mut renewed = original.clone();
    renewed.idle_expires_at += 10;
    write_session(auth.session_store.as_ref(), &path, &renewed).await?;
    retire_expired_session(
        auth.session_store.as_ref(),
        &original,
        original.idle_expires_at,
    )
    .await?;
    ensure!(
        read_session(auth.session_store.as_ref(), &path)
            .await?
            .context("renewed")?
            .idle_expires_at
            == renewed.idle_expires_at
    );
    Ok(())
}

#[tokio::test]
async fn frozen_roles_and_role_grants_are_enforced() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state().clone();
    let admin = ConsolePrincipal {
        authority_id: "local".into(),
        username: "admin".into(),
        account_id: "admin-account".into(),
        identity_path: "identity://console/accounts/admin-account".into(),
        grants: CapSet::from_strs([
            "write://state/kernel/console/roles/**",
            "perform://effect/kernel/console/users/**",
        ])?,
        authority_ceiling: None,
        authentication: password_authentication(1),
    };

    let role_path = Path::parse("state://kernel/console/roles/ops")?;
    state
        .write_set(&role_path, role_value(vec![], true))
        .await?;
    ensure!(
        matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &role_path,
                Some(&role_value(vec![], false))
            )
            .await,
            Err(AuthError::PermissionDenied)
        ),
        "frozen role was mutable"
    );

    let new_role = Path::parse("state://kernel/console/roles/newrole")?;
    ensure!(
        matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &new_role,
                Some(&role_value(vec![], true))
            )
            .await,
            Err(AuthError::PermissionDenied)
        ),
        "caller created a frozen role"
    );
    ensure!(
        matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &new_role,
                Some(&role_value(vec!["write://state/kernel/**"], false))
            )
            .await,
            Err(AuthError::PermissionDenied)
        ),
        "caller exceeded role grant authority"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_role_grants_are_rejected() -> anyhow::Result<()> {
    let boot = auth_boot();
    let state = boot.kernel().state().clone();
    let admin = ConsolePrincipal {
        authority_id: "local".into(),
        username: "root".into(),
        account_id: "root-account".into(),
        identity_path: "identity://console/accounts/root-account".into(),
        grants: CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: password_authentication(1),
    };
    let mut role = BTreeMap::new();
    role.insert(
        "grants".into(),
        Value::list(vec![
            Value::string("read://state/kernel/**".into()),
            Value::integer(7),
        ]),
    );
    role.insert("frozen".into(), Value::boolean(false));

    ensure!(
        matches!(
        authorize_path(
            &state,
            &admin,
            "write",
            &Path::parse("state://kernel/console/roles/bad")?,
            Some(&Value::map(role))
        )
        .await,
        Err(AuthError::State(message)) if message.contains("console role.grants[1]")
        ),
        "malformed role grant was accepted"
    );
    Ok(())
}

#[tokio::test]
async fn auth_audit_facts_are_redacted() -> anyhow::Result<()> {
    let boot = auth_boot();
    let password = "Audit!N7vQ3zL9sX2mR8cK".to_string();
    let signing_key = TestSigningKey::generate();
    let descriptor = signing_key.descriptor();
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            password: Some(password.clone()),
            pubkeys: vec![descriptor.clone()],
            ..Default::default()
        },
    )
    .await?;
    let password_hash = credentials::read(
        boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .password
    .context("missing stored password verifier")?;
    let auth = test_auth()?;
    let login = auth
        .login(
            &boot,
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "audit-source".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let challenge = auth
        .begin_key_login(
            &boot,
            KeyChallengeRequest {
                username: "root".into(),
                origin: "https://console.local".into(),
            },
            "audit-source".into(),
        )
        .await?;
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.transcript.as_bytes()));
    let key_login = auth
        .finish_key_login(
            &boot,
            KeyLoginRequest {
                username: "root".into(),
                challenge_id: challenge.challenge_id.clone(),
                signature: signature.clone(),
                origin: challenge.origin.clone(),
                key: descriptor.clone(),
                second_factor: None,
            },
            "audit-source".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;

    let facts = audit_facts(&boot)?;
    ensure!(
        facts_contain_string(&facts, "console_login")?,
        "missing console login audit fact"
    );
    for (name, secret) in [
        ("password", password.as_str()),
        ("password verifier", password_hash.as_str()),
        ("password login bearer", login.token.as_str()),
        ("public-key login bearer", key_login.token.as_str()),
        ("signature", signature.as_str()),
        ("nonce", challenge.nonce.as_str()),
        ("challenge ID", challenge.challenge_id.as_str()),
        ("transcript", challenge.transcript.as_str()),
    ] {
        let encoded_secret = serde_json::to_string(secret)?;
        ensure!(
            !facts_contain_string(&facts, &encoded_secret[1..encoded_secret.len() - 1])?,
            "audit facts leaked {name}"
        );
    }

    // Authentication methods and credential references are public evidence,
    // distinct from the password, verifier, bearer and challenge proof.
    let primaries = facts
        .iter()
        .filter_map(|fact| {
            fact.outcome
                .as_ref()?
                .as_map()?
                .get("details")?
                .as_map()?
                .get("authentication")?
                .as_map()?
                .get("primary")?
                .as_map()
        })
        .collect::<Vec<_>>();
    ensure!(
        primaries.iter().any(|primary| {
            primary.get("method").and_then(Value::as_str) == Some("password")
                && primary.get("verified_at").and_then(Value::as_int)
                    == Some(login.authentication.primary.verified_at())
        }),
        "audit facts omitted the public password authentication evidence"
    );
    ensure!(
        primaries.iter().any(|primary| {
            primary.get("method").and_then(Value::as_str) == Some("public_key")
                && primary.get("credential_key").and_then(Value::as_str)
                    == Some(descriptor.as_str())
                && primary.get("verified_at").and_then(Value::as_int)
                    == Some(key_login.authentication.primary.verified_at())
        }),
        "audit facts omitted the verified public-key credential reference"
    );
    Ok(())
}
