#![expect(
    clippy::unwrap_used,
    reason = "acceptance fixtures fail immediately on unexpected storage outcomes"
)]

use std::sync::Arc;
use xolotl_console::session_store::{
    ConsoleSession, ConsoleSessionPolicy, ConsoleSessionStore, MAINTENANCE_BYTES, MAINTENANCE_ROWS,
    MemoryConsoleSessionStore, SessionPageLimits, SessionStoreError,
};
use xolotl_types::Value;

#[path = "support/sealer.rs"]
mod sealer;

fn console_config(store: Arc<dyn ConsoleSessionStore>) -> xolotl_console::ConsoleConfig {
    xolotl_console::ConsoleConfig {
        session_store: Some(store),
        auth: xolotl_console::ConsoleAuthConfig {
            credential_sealer: Some(sealer::sealer()),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn provision(boot: &xolotl_kernel::Bootstrap) {
    xolotl_console::bootstrap_root_account(
        boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        xolotl_console::RootProvisioning {
            credential_sealer: Some(sealer::sealer()),
            password: Some("9Zm$R6!yL2#vT8qWs4e".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

fn login() -> xolotl_console::LoginRequest {
    xolotl_console::LoginRequest {
        username: "root".into(),
        password: "9Zm$R6!yL2#vT8qWs4e".into(),
        second_factor: None,
    }
}

fn row(sid: &str, account: &str, issued: i64, expiry: i64, source: &str) -> ConsoleSession {
    let authentication = Value::map(std::collections::BTreeMap::from([
        (
            "primary".into(),
            Value::map(std::collections::BTreeMap::from([
                ("method".into(), Value::string("password".into())),
                ("verified_at".into(), Value::integer(1)),
            ])),
        ),
        ("secondary".into(), Value::null()),
    ]));
    let value = Value::map(std::collections::BTreeMap::from([
        (
            "token_hash".into(),
            Value::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
        ),
        ("username".into(), Value::string(account.into())),
        ("authority_id".into(), Value::string("local".into())),
        ("account_id".into(), Value::string(account.into())),
        ("revocation_epoch".into(), Value::string("1".into())),
        (
            "identity_path".into(),
            Value::string(format!("identity://console/accounts/{account}")),
        ),
        ("issued_at".into(), Value::integer(issued)),
        ("expires_at".into(), Value::integer(expiry)),
        ("idle_expires_at".into(), Value::integer(expiry)),
        ("authentication".into(), authentication),
        ("credential_epoch".into(), Value::string("epoch".into())),
        ("authority_ceiling".into(), Value::list(Vec::new())),
        ("last_seen".into(), Value::integer(issued)),
        ("source_addr".into(), Value::string(source.into())),
    ]));
    ConsoleSession::decode(sid, &serde_json::to_vec(&value).unwrap()).unwrap()
}

fn domains(policy: ConsoleSessionPolicy) -> (tempfile::TempDir, Vec<Arc<dyn ConsoleSessionStore>>) {
    let directory = tempfile::tempdir().unwrap();
    let redb =
        xolotl_storage_redb::RedbStore::open(directory.path().join("sessions.redb")).unwrap();
    let stores: Vec<Arc<dyn ConsoleSessionStore>> = vec![
        Arc::new(MemoryConsoleSessionStore::new(policy)),
        Arc::new(redb.console_session_store(policy).unwrap()),
    ];
    (directory, stores)
}

#[tokio::test]
async fn shared_handles_enforce_atomic_account_and_domain_capacities() {
    let (_directory, stores) = domains(ConsoleSessionPolicy::new(2, 3).unwrap());
    for store in stores {
        store
            .create(row("other", "other", 0, 100, ""))
            .await
            .unwrap();
        store.create(row("b", "owner", 1, 100, "")).await.unwrap();
        store.create(row("a", "owner", 1, 100, "")).await.unwrap();
        assert!(matches!(
            store.create(row("other", "owner", 2, 100, "")).await,
            Err(SessionStoreError::Conflict)
        ));
        assert!(matches!(
            store.create(row("new", "new", 2, 100, "")).await,
            Err(SessionStoreError::Rejected(_))
        ));
        assert!(store.get("a").await.unwrap().is_some());
        assert!(store.get("other").await.unwrap().is_some());
        store.create(row("c", "owner", 3, 100, "")).await.unwrap();
        assert!(store.get("a").await.unwrap().is_none());
        assert!(store.get("b").await.unwrap().is_some());
        assert!(store.get("other").await.unwrap().is_some());
        let mut tasks = Vec::new();
        for index in 0..32 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store
                    .create(row(&format!("race-{index:02}"), "owner", 4, 100, ""))
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let page = store
            .list(
                None,
                SessionPageLimits {
                    rows: 100,
                    bytes: 1024 * 1024,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 3);
        assert_eq!(
            page.entries
                .iter()
                .filter(|row| row.account().1 == "owner")
                .count(),
            2
        );
        assert!(store.get("other").await.unwrap().is_some());
    }
}

#[tokio::test]
async fn duplicate_creates_and_rotation_have_one_winner() {
    let (_directory, stores) = domains(ConsoleSessionPolicy::new(2, 2).unwrap());
    for store in stores {
        let original = row("fixed", "owner", 1, 50, "original");
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let barrier = barrier.clone();
            let original = original.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store.create(original).await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(()) => winners += 1,
                Err(SessionStoreError::Conflict) => {}
                result => assert!(result.is_ok(), "unexpected create failure: {result:?}"),
            }
        }
        assert_eq!(winners, 1);
        let first = row("fixed", "owner", 1, 80, "first");
        let second = row("fixed", "owner", 1, 90, "second");
        let (left, right) = tokio::join!(
            store.compare_replace(original.clone(), first),
            store.compare_replace(original.clone(), second)
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert!(matches!(
            store.delete("fixed", Some(original.clone())).await,
            Err(SessionStoreError::Conflict)
        ));
        store.delete("fixed", None).await.unwrap();
        assert!(matches!(
            store.compare_replace(original.clone(), original).await,
            Err(SessionStoreError::Conflict)
        ));
        assert!(store.get("fixed").await.unwrap().is_none());
    }
}

#[tokio::test]
async fn retained_expiry_and_incremental_indexes_are_charged() {
    let (_directory, stores) = domains(ConsoleSessionPolicy::new(40, 40).unwrap());
    for store in stores {
        for index in 0..40 {
            store
                .create(row(&format!("sid-{index:02}"), "owner", index, 10, ""))
                .await
                .unwrap();
        }
        assert!(matches!(
            store.create(row("unrelated", "other", 41, 100, "")).await,
            Err(SessionStoreError::Rejected(_))
        ));
        let observed = store.get("sid-00").await.unwrap().unwrap();
        store
            .compare_replace(observed.clone(), row("sid-00", "owner", 0, 100, ""))
            .await
            .unwrap();
        assert!(matches!(
            store.delete("sid-00", Some(observed)).await,
            Err(SessionStoreError::Conflict)
        ));
        assert_eq!(store.maintain(10).await.unwrap(), MAINTENANCE_ROWS);
        assert!(store.get("sid-00").await.unwrap().is_some());
        store
            .create(row("unrelated", "other", 41, 100, ""))
            .await
            .unwrap();
        assert_eq!(
            store.revoke_account("local", "owner").await.unwrap(),
            MAINTENANCE_ROWS
        );
        assert_eq!(store.revoke_account("local", "other").await.unwrap(), 1);
        assert_eq!(store.revoke_account("local", "other").await.unwrap(), 0);
        assert_eq!(store.maintain(100).await.unwrap(), 8);
        assert!(
            store
                .list(
                    None,
                    SessionPageLimits {
                        rows: 1,
                        bytes: MAINTENANCE_BYTES
                    }
                )
                .await
                .unwrap()
                .entries
                .is_empty()
        );
    }
}

#[tokio::test]
async fn pages_and_maintenance_obey_encoded_byte_budgets() {
    let (_directory, stores) = domains(ConsoleSessionPolicy::new(4, 4).unwrap());
    for store in stores {
        let large = "x".repeat(140 * 1024);
        store
            .create(row("a", "owner", 1, 10, &large))
            .await
            .unwrap();
        store
            .create(row("b", "owner", 2, 10, &large))
            .await
            .unwrap();
        let page = store
            .list(
                None,
                SessionPageLimits {
                    rows: 16,
                    bytes: MAINTENANCE_BYTES,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.next.as_deref(), Some("a"));
        let page = store
            .list(
                page.next.as_deref(),
                SessionPageLimits {
                    rows: 16,
                    bytes: MAINTENANCE_BYTES,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(page.next.is_none());
        assert!(matches!(
            store
                .list(
                    None,
                    SessionPageLimits {
                        rows: 1,
                        bytes: 100
                    }
                )
                .await,
            Err(SessionStoreError::Rejected(_))
        ));
        assert_eq!(store.maintain(10).await.unwrap(), 1);
        assert_eq!(store.revoke_account("local", "owner").await.unwrap(), 1);
        assert!(matches!(
            store
                .list(
                    Some("bad/cursor"),
                    SessionPageLimits {
                        rows: 1,
                        bytes: 100
                    }
                )
                .await,
            Err(SessionStoreError::Rejected(_) | SessionStoreError::Storage(_))
        ));
    }
}

#[tokio::test]
async fn durable_policy_counters_and_indexes_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reopen.redb");
    let policy = ConsoleSessionPolicy::new(2, 2).unwrap();
    {
        let domain = xolotl_storage_redb::RedbStore::open(&path).unwrap();
        let store = domain.console_session_store(policy).unwrap();
        store.create(row("a", "owner", 1, 10, "")).await.unwrap();
        store.create(row("b", "other", 2, 10, "")).await.unwrap();
    }
    {
        let domain = xolotl_storage_redb::RedbStore::open(&path).unwrap();
        assert!(matches!(
            domain.console_session_store(ConsoleSessionPolicy::new(1, 1).unwrap()),
            Err(SessionStoreError::Rejected(_))
        ));
        let lowered = ConsoleSessionPolicy::new(1, 2).unwrap();
        let store = domain.console_session_store(lowered).unwrap();
        assert!(matches!(
            domain.clone().console_session_store(policy),
            Err(SessionStoreError::Rejected(_))
        ));
        assert!(matches!(
            store.create(row("c", "third", 3, 100, "")).await,
            Err(SessionStoreError::Rejected(_))
        ));
        assert_eq!(store.maintain(10).await.unwrap(), 2);
        store.create(row("c", "third", 3, 100, "")).await.unwrap();
        store.delete("c", None).await.unwrap();
    }
    let domain = xolotl_storage_redb::RedbStore::open(&path).unwrap();
    let store = domain.console_session_store(policy).unwrap();
    assert!(store.get("c").await.unwrap().is_none());
    assert_eq!(store.revoke_account("local", "third").await.unwrap(), 0);
}

#[tokio::test]
async fn offline_account_lowering_never_evicts_or_resets_retained_rows() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("account-lowering.redb");
    let original = ConsoleSessionPolicy::new(2, 4).unwrap();
    {
        let owner = xolotl_storage_redb::RedbStore::open(&path).unwrap();
        let store = owner.console_session_store(original).unwrap();
        store.create(row("a", "owner", 1, 10, "")).await.unwrap();
        store.create(row("b", "owner", 2, 10, "")).await.unwrap();
        assert!(matches!(
            owner
                .clone()
                .console_session_store(ConsoleSessionPolicy::new(2, 2).unwrap()),
            Err(SessionStoreError::Rejected(_))
        ));
    }
    {
        let owner = xolotl_storage_redb::RedbStore::open(&path).unwrap();
        assert!(matches!(
            owner.console_session_store(ConsoleSessionPolicy::new(1, 4).unwrap()),
            Err(SessionStoreError::Rejected(_))
        ));
        let store = owner
            .console_session_store(ConsoleSessionPolicy::new(2, 2).unwrap())
            .unwrap();
        assert!(store.get("a").await.unwrap().is_some());
        assert!(store.get("b").await.unwrap().is_some());
        store.delete("a", None).await.unwrap();
    }
    let owner = xolotl_storage_redb::RedbStore::open(&path).unwrap();
    let lowered = owner
        .console_session_store(ConsoleSessionPolicy::new(1, 1).unwrap())
        .unwrap();
    assert!(lowered.get("b").await.unwrap().is_some());
    assert!(matches!(
        lowered.create(row("other", "other", 3, 100, "")).await,
        Err(SessionStoreError::Rejected(_))
    ));
}

#[tokio::test]
async fn two_console_hosts_share_the_storage_domain_owner() {
    use xolotl_console::{ConsoleService, ConsoleState};
    let (_directory, stores) = domains(ConsoleSessionPolicy::new(2, 2).unwrap());
    for store in stores {
        let boot = Arc::new(xolotl_kernel::Bootstrap::in_memory());
        provision(&boot).await;
        let first = ConsoleService::new(
            ConsoleState::with_config(boot.clone(), console_config(store.clone())).unwrap(),
        );
        let second = ConsoleService::new(
            ConsoleState::with_config(boot.clone(), console_config(store.clone())).unwrap(),
        );
        let (left, right) = tokio::join!(
            first.login(login(), "first".into()),
            second.login(login(), "second".into())
        );
        let left = left.unwrap().into_session().unwrap();
        let right = right.unwrap().into_session().unwrap();
        assert!(store.get(&left.sid).await.unwrap().is_some());
        assert!(store.get(&right.sid).await.unwrap().is_some());
        let third = first
            .login(login(), "third".into())
            .await
            .unwrap()
            .into_session()
            .unwrap();
        assert!(store.get(&third.sid).await.unwrap().is_some());
        let page = store
            .list(
                None,
                SessionPageLimits {
                    rows: 3,
                    bytes: MAINTENANCE_BYTES,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 2);
        let missing = if store.get(&left.sid).await.unwrap().is_none() {
            &left
        } else {
            &right
        };
        assert!(
            second
                .refresh(&missing.token, "second".into())
                .await
                .is_err()
        );
        assert!(
            ConsoleState::with_config(
                boot,
                xolotl_console::ConsoleConfig {
                    auth: console_config(store).auth,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn service_rotation_and_logout_survive_durable_reopen_without_state_rows() {
    use xolotl_console::{ActionCall, ConsoleService, ConsoleState};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.redb");
    let policy = ConsoleSessionPolicy::new(2, 2).unwrap();
    let (original, rotated) = {
        let domain = xolotl_storage_redb::RedbStore::open_with_history(
            &path,
            xolotl_storage_redb::RedbHistory::Full,
        )
        .unwrap();
        let store = Arc::new(domain.console_session_store(policy).unwrap());
        let boot = Arc::new(xolotl_kernel::Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(domain.state_backend().into_backend())
                .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
                .build(),
        ));
        provision(&boot).await;
        let service = ConsoleService::new(
            ConsoleState::with_config(boot.clone(), console_config(store.clone())).unwrap(),
        );
        let original = service
            .login(login(), "test".into())
            .await
            .unwrap()
            .into_session()
            .unwrap();
        let rotated = service
            .refresh(&original.token, "test".into())
            .await
            .unwrap();
        assert!(
            boot.kernel()
                .state()
                .read(
                    &xolotl_types::Path::parse(&format!(
                        "state://vault/console/sessions/{}",
                        rotated.sid
                    ))
                    .unwrap()
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            boot.kernel()
                .state()
                .query(&xolotl_state::StateScan::new(
                    xolotl_types::Path::parse("state://kernel/console/sessions").unwrap()
                ))
                .await
                .unwrap()
                .entries
                .is_empty()
        );
        (original, rotated)
    };
    {
        let domain = xolotl_storage_redb::RedbStore::open_with_history(
            &path,
            xolotl_storage_redb::RedbHistory::Full,
        )
        .unwrap();
        let store = Arc::new(domain.console_session_store(policy).unwrap());
        let boot = Arc::new(xolotl_kernel::Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(domain.state_backend().into_backend())
                .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
                .build(),
        ));
        let service =
            ConsoleService::new(ConsoleState::with_config(boot, console_config(store)).unwrap());
        assert!(
            service
                .refresh(&original.token, "test".into())
                .await
                .is_err()
        );
        let current = service
            .refresh(&rotated.token, "test".into())
            .await
            .unwrap();
        service
            .call(
                &current.token,
                None,
                ActionCall {
                    action: xolotl_console::protocol::ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    let domain = xolotl_storage_redb::RedbStore::open_with_history(
        &path,
        xolotl_storage_redb::RedbHistory::Full,
    )
    .unwrap();
    assert!(
        domain
            .console_session_store(policy)
            .unwrap()
            .get(&rotated.sid)
            .await
            .unwrap()
            .is_none()
    );
}
