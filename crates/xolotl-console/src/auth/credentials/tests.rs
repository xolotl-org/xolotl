use super::*;
use crate::{ConsoleErrorCode, ConsoleService};
use anyhow::{Context, ensure};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
use xolotl_state::{StateRead, StateResult};
use xolotl_types::TaintedValue;

#[tokio::test]
async fn ready_enrollment_reserves_exact_room_for_a_confirmation_claim() -> anyhow::Result<()> {
    let sealer = crate::auth::test_credential_sealer();
    let id = "t000000000000000000000000";
    let key = AccountKey::local("alice");
    let mut record = AccountCredentials {
        authority_id: "local".into(),
        account_id: "alice".into(),
        epoch: "epoch".into(),
        password: Some(String::new()),
        pending: Some(PendingEnrollment {
            id: id.into(),
            sid: id.into(),
            factor_id: id.into(),
            provider_id: "totp".into(),
            label: "Device".into(),
            replace_factor_id: None,
            expires_at: i64::MAX,
            round: 1,
            waiting: EnrollmentWaiting::Challenge {
                private_state: serde_json::Value::Null,
                setup: serde_json::Value::Null,
                response_schema: serde_json::json!(true),
            },
            phase: EnrollmentPhase::Ready {},
        }),
        ..Default::default()
    };
    let ready_len = serde_json::to_string(&record)?.len();
    record.pending.as_mut().context("pending")?.phase = EnrollmentPhase::InFlight {
        claim_id: id.into(),
    };
    let in_flight_len = serde_json::to_string(&record)?.len();
    record.pending.as_mut().context("pending")?.phase = EnrollmentPhase::Ready {};
    let growth = in_flight_len - ready_len;
    record.password = Some("x".repeat(MAX_CREDENTIAL_BYTES - growth - ready_len));
    let state = xolotl_state::InMemoryBackend::new().into_backend();
    write_reserving_enrollment_claim_by_key(&state, &key, &record, &sealer).await?;
    let mut too_large = read_by_key(&state, &key, &sealer).await?;
    too_large.password.as_mut().context("password")?.push('x');
    ensure!(serde_json::to_string(&too_large)?.len() <= MAX_CREDENTIAL_BYTES);
    ensure!(matches!(
        write_reserving_enrollment_claim_by_key(&state, &key, &too_large, &sealer).await,
        Err(AuthError::InvalidCredentialRequest)
    ));
    let mut claimed = read_by_key(&state, &key, &sealer).await?;
    claimed.pending.as_mut().context("pending")?.phase = EnrollmentPhase::InFlight {
        claim_id: id.into(),
    };
    ensure!(serde_json::to_string(&claimed)?.len() == MAX_CREDENTIAL_BYTES);
    write_by_key(&state, &key, &claimed, &sealer).await?;
    Ok(())
}

#[tokio::test]
async fn near_limit_credential_json_survives_bounded_state_envelope() -> anyhow::Result<()> {
    let sealer = crate::auth::test_credential_sealer();
    let key = AccountKey::local("alice");
    let record = AccountCredentials {
        authority_id: "local".into(),
        account_id: "alice".into(),
        epoch: "epoch".into(),
        // Escaping expands the JSON before the sealed byte envelope is created.
        password: Some("\"".repeat(130_000)),
        ..Default::default()
    };
    let encoded = serde_json::to_string(&record)?;
    ensure!(encoded.len() > MAX_CREDENTIAL_BYTES - 4096);
    ensure!(encoded.len() <= MAX_CREDENTIAL_BYTES);
    let sealed = sealer.seal(
        "local",
        "alice",
        zeroize::Zeroizing::new(encoded.into_bytes()),
    )?;
    let row = Value::string(format!(
        "xolotl-credential-v1:{}",
        URL_SAFE_NO_PAD.encode(sealed)
    ));
    let path = Path::parse("state://vault/console/credentials/local/alice")?;
    let memory_bytes = xolotl_state::host::encoded_size(&TaintedValue::pristine(row.clone()))?
        + path.to_string().len();
    let redb_bytes = 12
        + xolotl_state::host::encoded_size(&xolotl_types::TaintSet::pristine())?
        + xolotl_state::host::encoded_size(&row)?
        + path.to_string().len();
    ensure!(memory_bytes <= MAX_CREDENTIAL_ROW_BYTES.get());
    ensure!(redb_bytes <= MAX_CREDENTIAL_ROW_BYTES.get());
    let directory = tempfile::tempdir()?;
    let store = xolotl_storage_redb::RedbStore::open(directory.path().join("vault.redb"))?;
    for state in [
        xolotl_state::InMemoryBackend::new().into_backend(),
        store.state_backend().into_backend(),
    ] {
        write_by_key(&state, &key, &record, &sealer).await?;
        ensure!(read_by_key(&state, &key, &sealer).await?.password == record.password);
        let path = Path::parse("state://vault/console/credentials/local/alice")?;
        let current = state
            .read_bounded(&path, MAX_CREDENTIAL_ROW_BYTES)
            .await?
            .context("credential row")?;
        state
            .write_cas_bounded(
                &path,
                Some(current.clone()),
                current,
                MAX_CREDENTIAL_ROW_BYTES,
            )
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn oversized_credential_row_is_rejected_before_record_parsing_or_cas() -> anyhow::Result<()> {
    let sealer = crate::auth::test_credential_sealer();
    let key = AccountKey::local("alice");
    let directory = tempfile::tempdir()?;
    let store = xolotl_storage_redb::RedbStore::open(directory.path().join("vault.redb"))?;
    for state in [
        xolotl_state::InMemoryBackend::new().into_backend(),
        store.state_backend().into_backend(),
    ] {
        let path = Path::parse("state://vault/console/credentials/local/alice")?;
        let oversized = Value::string("x".repeat(MAX_CREDENTIAL_ROW_BYTES.get()));
        state.write_set(&path, oversized.clone()).await?;
        ensure!(matches!(
            read_by_key(&state, &key, &sealer).await,
            Err(AuthError::State(detail)) if detail.contains("current state record exceeds encoded byte budget")
        ));
        ensure!(matches!(
            state
                .write_cas_bounded(
                    &path,
                    None,
                    Value::string("replacement".into()),
                    MAX_CREDENTIAL_ROW_BYTES,
                )
                .await,
            Err(xolotl_state::StateFailure {
                error: xolotl_state::StateError::PointTooLarge(_),
                ..
            })
        ));
        ensure!(state.read(&path).await? == Some(oversized));
    }
    Ok(())
}

fn request(operation: CredentialOperation) -> CredentialRequest {
    CredentialRequest {
        username: None,
        operation,
    }
}

async fn mutate(
    service: &ConsoleService,
    token: &str,
    operation: CredentialOperation,
) -> anyhow::Result<LoginResponse> {
    let response = service
        .credentials(token, request(operation), "test".into())
        .await?;
    let CredentialResponse::Updated {
        sessions_invalidated: true,
        session: Some(session),
    } = response
    else {
        anyhow::bail!("expected epoch rotation with replacement session");
    };
    Ok(session)
}

#[tokio::test]
async fn primary_credentials_share_epoch_and_protect_the_last_login_method() -> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let failure = service
        .credentials(
            &token,
            request(CredentialOperation::DisablePassword {}),
            "test".into(),
        )
        .await
        .err()
        .context("last credential must remain")?;
    ensure!(failure.code == ConsoleErrorCode::AdmissionRejected);
    let key = crate::auth::test_key::TestSigningKey::generate();
    let descriptor = key.descriptor();
    let session = mutate(
        &service,
        &token,
        CredentialOperation::AddPublicKey {
            key: descriptor.clone(),
        },
    )
    .await?;
    ensure!(matches!(
        state.auth.authenticate_token(&state.boot, &token).await,
        Err(AuthError::InvalidSession)
    ));
    let session = mutate(
        &service,
        &session.token,
        CredentialOperation::DisablePassword {},
    )
    .await?;
    let failure = service
        .credentials(
            &session.token,
            request(CredentialOperation::RemovePublicKey {
                key: descriptor.clone(),
            }),
            "test".into(),
        )
        .await
        .err()
        .context("last public key must remain")?;
    ensure!(failure.code == ConsoleErrorCode::AdmissionRejected);
    let changed = "wJ8$Te2Q!vN6#Lu9Rp4X";
    let session = mutate(
        &service,
        &session.token,
        CredentialOperation::SetPassword {
            password: changed.into(),
        },
    )
    .await?;
    let status = service
        .credentials(
            &session.token,
            request(CredentialOperation::Status {}),
            "test".into(),
        )
        .await?;
    ensure!(
        matches!(status, CredentialResponse::Current { password_enabled: true, ref public_keys, .. } if public_keys == &[descriptor])
    );
    let login = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: changed.into(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(login.authentication.mfa_level() == 1);
    mutate(
        &service,
        &session.token,
        CredentialOperation::DisablePassword {},
    )
    .await?;
    let failure = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: changed.into(),
                second_factor: None,
            },
            "test".into(),
        )
        .await
        .err()
        .context("password disabled")?;
    ensure!(failure.code == ConsoleErrorCode::NotAuthenticated);

    Ok(())
}

#[tokio::test]
async fn stale_login_updates_cannot_resurrect_revoked_credentials() -> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let store = state.boot.kernel().state();
    let stale = read(
        store,
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let authentication = state
        .auth
        .authenticate_token(&state.boot, &token)
        .await?
        .authentication;
    let changed = "uK4@Nr8S#cJ2$Mw9Ep6Z";
    mutate(
        &service,
        &token,
        CredentialOperation::SetPassword {
            password: changed.into(),
        },
    )
    .await?;
    ensure!(matches!(
        write(
            store,
            "root",
            &stale,
            crate::auth::test_credential_sealer().as_ref()
        )
        .await,
        Err(AuthError::CredentialConflict)
    ));
    ensure!(
        read(
            store,
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .epoch
            != stale.epoch
    );
    // A proof validated before a credential mutation cannot adopt the new epoch.
    let user = read_user(store, "root").await?.context("root")?;
    let account = state.auth.local_snapshot(store, &user).await?;
    ensure!(matches!(
        state
            .auth
            .issue_session(
                store,
                &account,
                "test".into(),
                authentication,
                stale.epoch,
                None
            )
            .await,
        Err(AuthError::InvalidCredentials)
    ));
    Ok(())
}

#[tokio::test]
async fn credential_rotation_preserves_the_recent_authentication_window() -> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let sid = token.split_once('.').context("token")?.0;
    let path = session_path(sid)?;
    let mut original = read_session(state.auth.session_store.as_ref(), &path)
        .await?
        .context("session")?;
    original.issued_at -= 30_000;
    let PrimaryAuthentication::Password { verified_at } = &mut original.authentication.primary
    else {
        anyhow::bail!("password authentication");
    };
    *verified_at -= 60_000;
    // The original session was issued after its preserved authentication.
    state.auth.session_store.delete(sid, None).await?;
    state
        .auth
        .session_store
        .create(crate::session_store::ConsoleSession::from_record(
            original.clone(),
        ))
        .await?;
    let session = mutate(
        &service,
        &token,
        CredentialOperation::SetPassword {
            password: "dQ7!Bs3#Xe9$Tu5Nm2Lp".into(),
        },
    )
    .await?;
    let new = read_session(
        state.auth.session_store.as_ref(),
        &session_path(&session.sid)?,
    )
    .await?
    .context("new session")?;
    ensure!(new.authentication == original.authentication);
    ensure!(session.authentication == original.authentication);
    ensure!(new.issued_at > original.issued_at);
    Ok(())
}

fn account_metadata() -> Value {
    Value::map(BTreeMap::from([
        ("status".into(), Value::string("active".into())),
        ("roles".into(), Value::list(Vec::new())),
        ("grants".into(), Value::list(Vec::new())),
        ("authority_ceiling".into(), Value::list(Vec::new())),
    ]))
}

async fn put_account(
    service: &ConsoleService,
    token: &str,
    value: Value,
    version: Option<u64>,
) -> anyhow::Result<()> {
    service
        .call(
            token,
            Some("test"),
            crate::ActionCall {
                action: xolotl_console_protocol::ACTION_ACCESS_USER_WRITE_CAS.into(),
                input: Value::map(BTreeMap::from([
                    ("username".into(), Value::string("alice".into())),
                    ("value".into(), value),
                    (
                        "expected_version".into(),
                        version.map_or(Value::null(), |v| Value::integer(v as i64)),
                    ),
                ])),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn administrative_provisioning_does_not_impersonate_or_reuse_deleted_accounts()
-> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let admin = state.auth.enroll_test_totp(&state.boot, &token).await?;
    put_account(&service, &admin.token, account_metadata(), None).await?;
    let first = read_user(state.boot.kernel().state(), "alice")
        .await?
        .context("created user")?;
    let password = "jS7!Vz3#Ec9$Tu5Xb2Ln";
    let response = service
        .credentials(
            &admin.token,
            CredentialRequest {
                username: Some("alice".into()),
                operation: CredentialOperation::SetPassword {
                    password: password.into(),
                },
            },
            "test".into(),
        )
        .await?;
    ensure!(matches!(
        response,
        CredentialResponse::Updated {
            sessions_invalidated: true,
            session: None
        }
    ));
    let alice = service
        .login(
            LoginRequest {
                username: "alice".into(),
                password: password.into(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let alice = state
        .auth
        .enroll_test_totp(&state.boot, &alice.token)
        .await?;
    let failure = service
        .credentials(
            &alice.token,
            CredentialRequest {
                username: Some("root".into()),
                operation: CredentialOperation::SetPassword {
                    password: password.into(),
                },
            },
            "test".into(),
        )
        .await
        .err()
        .context("cannot reset root")?;
    ensure!(failure.code == ConsoleErrorCode::Forbidden);
    let reset = service
        .credentials(
            &admin.token,
            CredentialRequest {
                username: Some("alice".into()),
                operation: CredentialOperation::ResetSecondFactors {},
            },
            "test".into(),
        )
        .await?;
    ensure!(matches!(
        reset,
        CredentialResponse::Updated {
            sessions_invalidated: true,
            session: None
        }
    ));
    ensure!(service.refresh(&alice.token, "test".into()).await.is_err());
    let recovered = service
        .login(
            LoginRequest {
                username: "alice".into(),
                password: password.into(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(recovered.authentication.mfa_level() == 1);
    let path = user_path("alice")?;
    // A trusted host may delete a record. A newly created account with the same
    // username must still receive a new identity and no inherited credentials.
    state.boot.kernel().state().write_delete(&path).await?;
    put_account(&service, &admin.token, account_metadata(), None).await?;
    let second = read_user(state.boot.kernel().state(), "alice")
        .await?
        .context("new user")?;
    ensure!(first.account_id != second.account_id);
    let record = read(
        state.boot.kernel().state(),
        "alice",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(!record.has_primary() && record.factors.is_empty());
    ensure!(service.refresh(&alice.token, "test".into()).await.is_err());
    let status = service
        .credentials(
            &admin.token,
            CredentialRequest {
                username: Some("alice".into()),
                operation: CredentialOperation::Status {},
            },
            "test".into(),
        )
        .await?;
    ensure!(matches!(
        status,
        CredentialResponse::Current {
            password_enabled: false,
            ..
        }
    ));
    service
        .credentials(
            &admin.token,
            CredentialRequest {
                username: Some("alice".into()),
                operation: CredentialOperation::SetPassword {
                    password: password.into(),
                },
            },
            "test".into(),
        )
        .await?;
    let fresh = service
        .login(
            LoginRequest {
                username: "alice".into(),
                password: password.into(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(fresh.authentication.mfa_level() == 1);
    Ok(())
}

#[tokio::test]
async fn metadata_updates_cannot_revive_sessions_or_replace_account_identity() -> anyhow::Result<()>
{
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let admin = state.auth.enroll_test_totp(&state.boot, &token).await?;
    put_account(&service, &admin.token, account_metadata(), None).await?;
    let password = "tB6!Xp2#Rs8$Nu4Qc9Ze";
    service
        .credentials(
            &admin.token,
            CredentialRequest {
                username: Some("alice".into()),
                operation: CredentialOperation::SetPassword {
                    password: password.into(),
                },
            },
            "test".into(),
        )
        .await?;
    let alice = service
        .login(
            LoginRequest {
                username: "alice".into(),
                password: password.into(),
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let mut disabled = account_metadata().as_map().cloned().context("metadata")?;
    disabled.insert("status".into(), Value::string("disabled".into()))?;
    put_account(&service, &admin.token, Value::from(disabled), Some(1)).await?;
    put_account(&service, &admin.token, account_metadata(), Some(2)).await?;
    // Re-enabling an account never re-enables a session from before the edit.
    ensure!(service.refresh(&alice.token, "test".into()).await.is_err());
    let mut substituted = account_metadata().as_map().cloned().context("metadata")?;
    substituted.insert(
        "account_id".into(),
        Value::string("attacker-selected-id".into()),
    )?;
    ensure!(
        put_account(&service, &admin.token, Value::from(substituted), Some(3))
            .await
            .is_err()
    );
    Ok(())
}

struct GatedTargetAuthorization {
    memory: Backend,
    role_path: Path,
    remaining_checks: AtomicUsize,
    entered: Notify,
    release: Notify,
}

impl StateRead for GatedTargetAuthorization {
    type Read<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateObservation>> + Send + 'a>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            if path == &self.role_path
                && self.remaining_checks.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                ) == Ok(1)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.memory.read_tainted(path).await
        })
    }
}

#[tokio::test]
async fn target_authority_wait_cannot_outlive_credential_management_window() -> anyhow::Result<()> {
    let (base, _, token, _) = crate::service::tests::fixture().await?;
    let memory = base.boot.kernel().state().clone();
    let gate = Arc::new(GatedTargetAuthorization {
        memory: memory.clone(),
        role_path: Path::parse("state://kernel/console/roles/target")?,
        remaining_checks: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(memory.clone().with_read(gate.clone())).build(),
    ));
    xolotl_standard::install_standard(&boot, &xolotl_standard::StandardConfig::default())?;
    let state = crate::ConsoleState::with_config(
        boot,
        crate::ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state.clone());
    let admin = state.auth.enroll_test_totp(&state.boot, &token).await?;
    memory
        .write_set(
            &gate.role_path,
            Value::map(BTreeMap::from([
                ("grants".into(), Value::list(Vec::new())),
                ("frozen".into(), Value::boolean(false)),
            ])),
        )
        .await?;
    let mut target = account_metadata().into_map().context("target metadata")?;
    target.insert(
        "roles".into(),
        Value::list(vec![Value::string("target".into())]),
    )?;
    put_account(&service, &admin.token, Value::from(target), None).await?;
    let before = read(
        &memory,
        "alice",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .persisted;
    let path = session_path(&admin.sid)?;
    let mut session = read_session(state.auth.session_store.as_ref(), &path)
        .await?
        .context("admin session")?;
    let deadline = xolotl_kernel::host::system_now_millis() + 1_000;
    let verified_at = deadline - state.auth.config.mfa.recent_auth_ttl_ms;
    let PrimaryAuthentication::Password {
        verified_at: primary_at,
    } = &mut session.authentication.primary
    else {
        anyhow::bail!("password authentication");
    };
    *primary_at = verified_at;
    let Some(crate::SecondaryAuthentication::RecoveryCode {
        verified_at: secondary_at,
    }) = &mut session.authentication.secondary
    else {
        anyhow::bail!("independent recovery authentication");
    };
    *secondary_at = verified_at;
    state.auth.session_store.delete(&admin.sid, None).await?;
    state
        .auth
        .session_store
        .create(crate::session_store::ConsoleSession::from_record(session))
        .await?;

    // Allow entry authorization, then delay the target's precommit authority read.
    gate.remaining_checks.store(2, Ordering::SeqCst);
    let key = crate::auth::test_key::TestSigningKey::generate();
    let request = CredentialRequest {
        username: Some("alice".into()),
        operation: CredentialOperation::AddPublicKey {
            key: key.descriptor(),
        },
    };
    let change = state
        .auth
        .manage_credentials(&state.boot, &admin.token, request, "test".into());
    tokio::pin!(change);
    tokio::select! {
        result = &mut change => anyhow::bail!("management completed before authority wait: {result:?}"),
        entered = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => entered?,
    }
    while xolotl_kernel::host::system_now_millis() <= deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate.release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(5), change)
        .await?
        .err()
        .context("expired management window")?;
    ensure!(matches!(error, AuthError::ReauthenticationRequired));
    ensure!(
        read(
            &memory,
            "alice",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .persisted
            == before
    );
    Ok(())
}
