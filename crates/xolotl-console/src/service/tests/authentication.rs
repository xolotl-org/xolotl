//! Authentication progress is shared by embedded hosts and HTTP adapters.

use super::*;
use crate::{
    AccountAuthority, AccountAuthorityError, AccountFuture, AccountKey, AccountSnapshot,
    AuthenticationInput, AuthenticationStep, CancelAuthenticationRequest,
    ContinueAuthenticationRequest, ExternalAssurance, ExternalAuthError, ExternalAuthFuture,
    ExternalPrimaryAuthentication, VerifiedExternalIdentity,
};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicI64, Ordering},
};
use tokio::sync::Semaphore;
use xolotl_types::{CapSet, Path};

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

pub(crate) struct TestExternal {
    valid_until: AtomicI64,
    authenticated_at: Option<i64>,
}

impl ExternalPrimaryAuthentication for TestExternal {
    fn verify<'a>(
        &'a self,
        assertion: &'a [u8],
    ) -> ExternalAuthFuture<'a, VerifiedExternalIdentity> {
        Box::pin(async move {
            if assertion == b"unavailable" {
                return Err(ExternalAuthError::Unavailable);
            }
            if assertion != b"signed-for-console" {
                return Err(ExternalAuthError::Rejected);
            }
            Ok(VerifiedExternalIdentity {
                provider: "fixture-oidc".into(),
                issuer: "https://issuer.example".into(),
                subject: "stable-subject".into(),
                verified_at: now_millis(),
                authenticated_at: self.authenticated_at,
                valid_until: self.valid_until.load(Ordering::SeqCst),
                assurance: ExternalAssurance::MultiFactor,
            })
        })
    }
}

pub(crate) struct TestAuthority {
    snapshot: Mutex<AccountSnapshot>,
    unavailable: AtomicBool,
    missing: AtomicBool,
}

impl TestAuthority {
    fn update(&self, edit: impl FnOnce(&mut AccountSnapshot)) -> anyhow::Result<()> {
        let mut snapshot = self
            .snapshot
            .lock()
            .map_err(|error| anyhow::anyhow!("test account lock poisoned: {error}"))?;
        edit(&mut snapshot);
        Ok(())
    }
}

impl AccountAuthority for TestAuthority {
    fn authority_id(&self) -> &str {
        "fixture"
    }

    fn resolve<'a>(&'a self, proof: &'a VerifiedExternalIdentity) -> AccountFuture<'a, AccountKey> {
        Box::pin(async move {
            if proof.provider != "fixture-oidc"
                || proof.issuer != "https://issuer.example"
                || proof.subject != "stable-subject"
            {
                return Err(AccountAuthorityError::NotFound);
            }
            let snapshot = self
                .snapshot
                .lock()
                .map_err(|_poisoned| AccountAuthorityError::Unavailable)?;
            Ok(snapshot.key.clone())
        })
    }

    fn current<'a>(&'a self, key: &'a AccountKey) -> AccountFuture<'a, AccountSnapshot> {
        Box::pin(async move {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(AccountAuthorityError::Unavailable);
            }
            if self.missing.load(Ordering::SeqCst) {
                return Err(AccountAuthorityError::NotFound);
            }
            let snapshot = self
                .snapshot
                .lock()
                .map_err(|_poisoned| AccountAuthorityError::Unavailable)?
                .clone();
            if &snapshot.key != key {
                return Err(AccountAuthorityError::NotFound);
            }
            Ok(snapshot)
        })
    }
}

pub(crate) async fn external_fixture(
    authenticated_at: Option<i64>,
    grants: CapSet,
    lifetime_ms: i64,
) -> anyhow::Result<(
    Arc<ConsoleState>,
    ConsoleService,
    Arc<TestExternal>,
    Arc<TestAuthority>,
)> {
    let (base, _, _, _) = fixture().await?;
    let external = Arc::new(TestExternal {
        valid_until: AtomicI64::new(now_millis() + lifetime_ms),
        authenticated_at,
    });
    let authority = Arc::new(TestAuthority {
        snapshot: Mutex::new(AccountSnapshot {
            key: AccountKey::new("fixture", "account-1")?,
            display_name: "same-display-name".into(),
            identity: Path::parse("identity://external/account-1")?,
            active: true,
            grants,
            revocation_epoch: "epoch-1".into(),
        }),
        unavailable: AtomicBool::new(false),
        missing: AtomicBool::new(false),
    });
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::new(6, 10_000)?,
                ),
            )),
            external_authentication: Some(external.clone()),
            account_authority: Some(authority.clone()),
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state.clone());
    Ok((state, service, external, authority))
}

fn full_grants() -> anyhow::Result<CapSet> {
    Ok(CapSet::from_strs(["*://**"])?)
}

struct GatedExternal {
    delegate: Arc<TestExternal>,
    entered: Semaphore,
    release: Semaphore,
}

struct GatedAuthority {
    delegate: Arc<TestAuthority>,
    entered: Semaphore,
    release: Semaphore,
}

impl AccountAuthority for GatedAuthority {
    fn authority_id(&self) -> &str {
        self.delegate.authority_id()
    }

    fn resolve<'a>(&'a self, proof: &'a VerifiedExternalIdentity) -> AccountFuture<'a, AccountKey> {
        Box::pin(async move {
            self.entered.add_permits(1);
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_error| AccountAuthorityError::Unavailable)?;
            permit.forget();
            self.delegate.resolve(proof).await
        })
    }

    fn current<'a>(&'a self, key: &'a AccountKey) -> AccountFuture<'a, AccountSnapshot> {
        self.delegate.current(key)
    }
}

#[tokio::test]
async fn external_preparation_keeps_capacity_through_account_lookup_and_releases_on_cancel()
-> anyhow::Result<()> {
    let (base, _, external, delegate) = external_fixture(None, full_grants()?, 60_000).await?;
    let authority = Arc::new(GatedAuthority {
        delegate,
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            auth: crate::ConsoleAuthConfig {
                max_external_verifications: 1,
                ..Default::default()
            },
            external_authentication: Some(external),
            account_authority: Some(authority.clone()),
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state);
    let first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .exchange_external(b"signed-for-console", "first-source".into())
            .await
    });
    let entered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        authority.entered.acquire(),
    )
    .await??;
    entered.forget();
    let full = service
        .exchange_external(b"signed-for-console", "second-source".into())
        .await
        .err()
        .context("account preparation must retain the external permit")?;
    ensure!(full.code == ConsoleErrorCode::RateLimited);
    first.abort();
    ensure!(first.await.is_err_and(|error| error.is_cancelled()));
    let next_service = service.clone();
    let next = tokio::spawn(async move {
        next_service
            .exchange_external(b"signed-for-console", "next-source".into())
            .await
    });
    let entered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        authority.entered.acquire(),
    )
    .await??;
    entered.forget();
    authority.release.add_permits(1);
    ensure!(next.await??.into_session().is_ok());
    authority.release.add_permits(1);
    ensure!(
        service
            .exchange_external(b"signed-for-console", "completed-source".into())
            .await?
            .into_session()
            .is_ok()
    );
    Ok(())
}

impl ExternalPrimaryAuthentication for GatedExternal {
    fn verify<'a>(
        &'a self,
        assertion: &'a [u8],
    ) -> ExternalAuthFuture<'a, VerifiedExternalIdentity> {
        Box::pin(async move {
            self.entered.add_permits(1);
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_error| ExternalAuthError::Unavailable)?;
            permit.forget();
            self.delegate.verify(assertion).await
        })
    }
}

#[tokio::test]
async fn external_verification_limit_rejects_concurrent_exchange() -> anyhow::Result<()> {
    let (base, _, delegate, authority) = external_fixture(None, full_grants()?, 60_000).await?;
    let external = Arc::new(GatedExternal {
        delegate,
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            auth: crate::ConsoleAuthConfig {
                max_external_verifications: 1,
                ..Default::default()
            },
            external_authentication: Some(external.clone()),
            account_authority: Some(authority),
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state);
    let first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .exchange_external(b"signed-for-console", "first-source".into())
            .await
    });
    let entered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        external.entered.acquire(),
    )
    .await??;
    entered.forget();
    let full = service
        .exchange_external(b"signed-for-console", "second-source".into())
        .await
        .err()
        .context("second exchange must be refused while verification is in flight")?;
    ensure!(full.code == ConsoleErrorCode::RateLimited);
    external.release.add_permits(1);
    ensure!(first.await??.into_session().is_ok());
    Ok(())
}

#[tokio::test]
async fn admitted_authentication_retains_shared_capacity_through_wait_and_cancellation()
-> anyhow::Result<()> {
    let (base, _, delegate, authority) = external_fixture(None, full_grants()?, 60_000).await?;
    let external = Arc::new(GatedExternal {
        delegate,
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            auth: crate::ConsoleAuthConfig {
                max_external_verifications: 2,
                ..Default::default()
            },
            external_authentication: Some(external.clone()),
            account_authority: Some(authority),
            max_concurrent_authentications: 1,
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state.clone());
    let admission = service.admit_authentication()?;
    let first = tokio::spawn(async move {
        admission
            .exchange_external(b"signed-for-console", "first-source".into())
            .await
    });
    let entered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        external.entered.acquire(),
    )
    .await??;
    entered.forget();
    ensure!(state.authentications.available_permits() == 0);
    let rejected = service
        .exchange_external(b"signed-for-console", "second-source".into())
        .await
        .err()
        .context("shared capacity must remain held during verification")?;
    ensure!(rejected.code == ConsoleErrorCode::RateLimited);
    ensure!(external.entered.available_permits() == 0);
    first.abort();
    ensure!(first.await.is_err_and(|error| error.is_cancelled()));
    ensure!(state.authentications.available_permits() == 1);
    external.release.add_permits(1);
    ensure!(
        service
            .admit_authentication()?
            .exchange_external(b"signed-for-console", "after-cancel".into())
            .await?
            .into_session()
            .is_ok()
    );
    ensure!(state.authentications.available_permits() == 1);
    Ok(())
}

#[tokio::test]
async fn external_verifier_and_account_facts_are_validated() -> anyhow::Result<()> {
    let (_, future_auth_service, _, _) =
        external_fixture(Some(now_millis() + 60_000), full_grants()?, 60_000).await?;
    let invalid_time = future_auth_service
        .exchange_external(b"signed-for-console", "time-source".into())
        .await
        .err()
        .context("user authentication must not postdate assertion verification")?;
    ensure!(invalid_time.code == ConsoleErrorCode::NotAuthenticated);

    let (_, service, _, authority) = external_fixture(None, full_grants()?, 60_000).await?;
    let invalid_identity = Path::parse("state://wrong")?;
    authority.update(|snapshot| snapshot.identity = invalid_identity)?;
    let malformed = service
        .exchange_external(b"signed-for-console", "account-source".into())
        .await
        .err()
        .context("invalid account identity must be rejected")?;
    ensure!(malformed.code == ConsoleErrorCode::Internal);
    Ok(())
}

#[tokio::test]
async fn external_assertions_use_the_installed_account_authority() -> anyhow::Result<()> {
    let (_, unconfigured, _, _) = fixture().await?;
    let missing = unconfigured
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await
        .err()
        .context("unconfigured host rejects external exchange")?;
    ensure!(missing.code == ConsoleErrorCode::AdmissionRejected);

    let (state, service, _, authority) = external_fixture(None, full_grants()?, 60_000).await?;
    for rejected in [
        b"wrong-issuer".as_slice(),
        b"wrong-audience",
        b"peer-name-only",
    ] {
        let failure = service
            .exchange_external(rejected, "host-peer".into())
            .await
            .err()
            .context("unverified assertion rejected")?;
        ensure!(failure.code == ConsoleErrorCode::NotAuthenticated);
    }
    let unavailable = service
        .exchange_external(b"unavailable", "host-peer".into())
        .await
        .err()
        .context("unavailable trusted verifier")?;
    ensure!(unavailable.code == ConsoleErrorCode::Internal);

    let exchanged = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .ok()
        .context("external session")?;
    ensure!(exchanged.authentication.mfa_level() == 1);
    ensure!(exchanged.authentication.authenticated_at().is_none());
    let account = state
        .boot
        .kernel()
        .state()
        .read(&Path::parse(
            "state://kernel/console/users/same-display-name",
        )?)
        .await?;
    ensure!(
        account.is_none(),
        "external account must not require a local user mirror"
    );
    let denied_local_login = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: "unused".into(),
                second_factor: None,
            },
            "host-peer".into(),
        )
        .await
        .err()
        .context("local primary authentication is disabled under external authority")?;
    ensure!(denied_local_login.code == ConsoleErrorCode::AdmissionRejected);

    service
        .call(
            &exchanged.token,
            None,
            action(ACTION_PROTOCOL_DESCRIBE, Value::null()),
        )
        .await?;
    let config_read = action(
        ACTION_CONFIG_READ,
        map_value([("path", Value::string("state://kernel/config".into()))]),
    );
    service
        .call(&exchanged.token, None, config_read.clone())
        .await?;
    let narrowed_grants = CapSet::from_strs(["read://state/application/**"])?;
    authority.update(|snapshot| snapshot.grants = narrowed_grants)?;
    let denied = service
        .call(&exchanged.token, None, config_read)
        .await
        .err()
        .context("current account grants must narrow an existing session")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    Ok(())
}

#[tokio::test]
async fn external_sessions_revalidate_current_authority_and_account_instance() -> anyhow::Result<()>
{
    let (_, service, _, authority) = external_fixture(None, full_grants()?, 60_000).await?;
    let first = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .ok()
        .context("first session")?;
    let describe = action(ACTION_PROTOCOL_DESCRIBE, Value::null());
    service.call(&first.token, None, describe.clone()).await?;

    authority.unavailable.store(true, Ordering::SeqCst);
    let unavailable = service
        .call(&first.token, None, describe.clone())
        .await
        .err()
        .context("authority outage closes new calls")?;
    ensure!(unavailable.code == ConsoleErrorCode::Internal);
    authority.unavailable.store(false, Ordering::SeqCst);
    service.call(&first.token, None, describe.clone()).await?;

    authority.update(|snapshot| snapshot.revocation_epoch = "epoch-2".into())?;
    let revoked = service
        .call(&first.token, None, describe.clone())
        .await
        .err()
        .context("changed revocation epoch invalidates the session")?;
    ensure!(revoked.code == ConsoleErrorCode::NotAuthenticated);
    let second = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .ok()
        .context("session under new epoch")?;

    let next_key = AccountKey::new("fixture", "account-2")?;
    let next_identity = Path::parse("identity://external/account-2")?;
    authority.update(|snapshot| {
        snapshot.key = next_key;
        snapshot.identity = next_identity;
        snapshot.revocation_epoch = "epoch-3".into();
    })?;
    let stale = service
        .call(&second.token, None, describe.clone())
        .await
        .err()
        .context("same display name must not inherit the former account instance")?;
    ensure!(matches!(
        stale.code,
        ConsoleErrorCode::Forbidden | ConsoleErrorCode::NotAuthenticated
    ));
    let third = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .ok()
        .context("replacement account session")?;
    service.call(&third.token, None, describe.clone()).await?;
    authority.missing.store(true, Ordering::SeqCst);
    let missing = service
        .call(&third.token, None, describe)
        .await
        .err()
        .context("deleted account must not authorize a session")?;
    ensure!(missing.code == ConsoleErrorCode::Forbidden);
    Ok(())
}

#[tokio::test]
async fn external_assertion_expiry_caps_refresh_and_new_admission() -> anyhow::Result<()> {
    let (_, service, external, _) =
        external_fixture(Some(now_millis()), full_grants()?, 2_200).await?;
    let session = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .ok()
        .context("external session")?;
    let hard_limit = external.valid_until.load(Ordering::SeqCst);
    ensure!(session.expires_at == hard_limit);
    let refreshed = service.refresh(&session.token, "host-peer".into()).await?;
    ensure!(refreshed.expires_at == hard_limit);
    let wait_ms = hard_limit.saturating_sub(now_millis()) + 20;
    tokio::time::sleep(std::time::Duration::from_millis(wait_ms.max(0) as u64)).await;
    ensure!(
        service
            .call(
                &refreshed.token,
                None,
                action(ACTION_PROTOCOL_DESCRIBE, Value::null())
            )
            .await
            .is_err()
    );
    ensure!(
        service
            .refresh(&refreshed.token, "host-peer".into())
            .await
            .is_err()
    );
    ensure!(
        service
            .exchange_external(b"signed-for-console", "host-peer".into())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn external_accounts_support_console_owned_second_factors() -> anyhow::Result<()> {
    let (state, service, _, _) =
        external_fixture(Some(now_millis()), full_grants()?, 60_000).await?;
    let first = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .ok()
        .context("initial external session")?;
    let stepped = state
        .auth
        .enroll_test_totp(&state.boot, &first.token)
        .await?;
    ensure!(stepped.authentication.mfa_level() == 2);
    let crate::mfa::MfaResponse::Updated {
        recovery_codes: Some(mut codes),
        ..
    } = service
        .mfa(
            &stepped.token,
            crate::mfa::MfaRequest::RegenerateRecoveryCodes {},
            "host-peer".into(),
        )
        .await?
    else {
        anyhow::bail!("expected recovery code rotation");
    };
    let pending = service
        .exchange_external(b"signed-for-console", "host-peer".into())
        .await?
        .into_session()
        .err()
        .context("external login should require the enrolled factor")?;
    ensure!(matches!(
        pending.step,
        AuthenticationStep::ChooseFactor { .. }
    ));
    let code = codes.pop().context("recovery proof")?;
    let final_session = service
        .continue_authentication(
            None,
            ContinueAuthenticationRequest {
                continuation: pending.continuation,
                input: AuthenticationInput::Proof {
                    proof: crate::mfa::MfaProof::RecoveryCode { code },
                },
            },
            "host-peer".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("second factor completes external login")?;
    ensure!(final_session.authentication.mfa_level() == 2);
    Ok(())
}

#[tokio::test]
async fn primary_login_continuation_finishes_without_a_temporary_session() -> anyhow::Result<()> {
    let (state, service, token, password) = fixture().await?;
    state.auth.enroll_test_totp(&state.boot, &token).await?;
    let next = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: password.clone(),
                second_factor: None,
            },
            "first-network".into(),
        )
        .await?
        .into_session()
        .err()
        .context("factor selection")?;
    let AuthenticationStep::ChooseFactor { options } = next.step else {
        anyhow::bail!("expected factor selection");
    };
    ensure!(options.factors.len() == 1 && options.recovery_code_available);
    let rejected = service
        .call(
            &next.continuation,
            None,
            action(ACTION_PROTOCOL_DESCRIBE, Value::null()),
        )
        .await
        .err()
        .context("continuation is not a session")?;
    ensure!(rejected.code == ConsoleErrorCode::NotAuthenticated);
    let proof = state.auth.next_test_totp(&state.boot, "root").await?;
    let session = service
        .continue_authentication(
            None,
            ContinueAuthenticationRequest {
                continuation: next.continuation.clone(),
                input: AuthenticationInput::Proof {
                    proof: proof.clone(),
                },
            },
            "second-network".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("completed authentication")?;
    ensure!(session.authentication.mfa_level() == 2);
    service
        .call(
            &session.token,
            None,
            action(ACTION_PROTOCOL_DESCRIBE, Value::null()),
        )
        .await?;
    let replay = service
        .continue_authentication(
            None,
            ContinueAuthenticationRequest {
                continuation: next.continuation,
                input: AuthenticationInput::Proof { proof },
            },
            "second-network".into(),
        )
        .await
        .err()
        .context("single-use continuation")?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    let invalid_proof = service
        .login(
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: Some(crate::mfa::MfaProof::RecoveryCode {
                    code: "invalid-recovery-proof".into(),
                }),
            },
            "second-network".into(),
        )
        .await
        .err()
        .context("an invalid proof remains an authentication failure")?;
    ensure!(invalid_proof.code == ConsoleErrorCode::NotAuthenticated);
    Ok(())
}

#[tokio::test]
async fn step_up_continuations_require_the_original_session_for_finish_and_cancel()
-> anyhow::Result<()> {
    let (base, _, token, _) = fixture().await?;
    // Login, enrollment, its recovery proof, regeneration and both step-ups
    // create six session records. Keep them all so capacity eviction cannot
    // invalidate the owner whose SID binding this test exercises.
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            auth: crate::ConsoleAuthConfig {
                ..Default::default()
            },
            max_concurrent_calls: 1,
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state.clone());
    let owner = state
        .auth
        .enroll_test_totp(&state.boot, &token)
        .await
        .context("enroll and authenticate the initial owner session")?;
    let crate::mfa::MfaResponse::Updated {
        session: owner,
        recovery_codes,
    } = service
        .mfa(
            &owner.token,
            crate::mfa::MfaRequest::RegenerateRecoveryCodes {},
            "test".into(),
        )
        .await
        .context("regenerate recovery codes and replace the owner session")?
    else {
        anyhow::bail!("recovery codes");
    };
    let code = recovery_codes
        .context("recovery codes")?
        .pop()
        .context("recovery code")?;
    let other = service
        .step_up(
            &owner.token,
            StepUpRequest {
                proof: Some(crate::mfa::MfaProof::RecoveryCode { code }),
            },
            "test".into(),
        )
        .await
        .context("issue a different session for SID mismatch checks")?
        .into_session()
        .ok()
        .context("another session")?;
    let available = state.authentications.available_permits();
    let next = service
        .admit_authentication()?
        .step_up(&owner.token, StepUpRequest { proof: None }, "test".into())
        .await
        .context("begin a continuation bound to the original owner SID")?
        .into_session()
        .err()
        .context("factor selection")?;
    ensure!(matches!(next.step, AuthenticationStep::ChooseFactor { .. }));
    ensure!(state.authentications.available_permits() == available);
    let proof = state.auth.next_test_totp(&state.boot, "root").await?;
    for bearer in [None, Some(other.token.as_str())] {
        let rejected = service
            .continue_authentication(
                bearer,
                ContinueAuthenticationRequest {
                    continuation: next.continuation.clone(),
                    input: AuthenticationInput::Proof {
                        proof: proof.clone(),
                    },
                },
                "test".into(),
            )
            .await
            .err()
            .context("step-up owner required")?;
        ensure!(rejected.code == ConsoleErrorCode::NotAuthenticated);
    }
    let completed = service
        .continue_authentication(
            Some(&owner.token),
            ContinueAuthenticationRequest {
                continuation: next.continuation,
                input: AuthenticationInput::Proof { proof },
            },
            "another-network".into(),
        )
        .await
        .context("finish the continuation with the original owner session")?
        .into_session()
        .ok()
        .context("owner completed step-up")?;
    ensure!(completed.authentication.mfa_level() == 2 && completed.sid != owner.sid);

    let next = service
        .step_up(&owner.token, StepUpRequest { proof: None }, "test".into())
        .await
        .context("begin cancellation while retaining the original owner session")?
        .into_session()
        .err()
        .context("cancelable selection")?;
    for bearer in [None, Some(other.token.as_str())] {
        let rejected = service
            .cancel_authentication(
                bearer,
                CancelAuthenticationRequest {
                    continuation: next.continuation.clone(),
                },
                "test".into(),
            )
            .await
            .err()
            .context("cancel owner required")?;
        ensure!(rejected.code == ConsoleErrorCode::NotAuthenticated);
    }
    service
        .cancel_authentication(
            Some(&owner.token),
            CancelAuthenticationRequest {
                continuation: next.continuation.clone(),
            },
            "another-network".into(),
        )
        .await
        .context("cancel the continuation with the original owner session")?;
    let canceled = service
        .continue_authentication(
            Some(&owner.token),
            ContinueAuthenticationRequest {
                continuation: next.continuation,
                input: AuthenticationInput::Proof {
                    proof: state.auth.next_test_totp(&state.boot, "root").await?,
                },
            },
            "test".into(),
        )
        .await
        .err()
        .context("canceled continuation")?;
    ensure!(canceled.code == ConsoleErrorCode::NotAuthenticated);
    Ok(())
}

#[tokio::test]
async fn cancellation_audits_success_and_rejections_without_disclosing_credentials()
-> anyhow::Result<()> {
    let (state, service, token, password) = fixture().await?;
    let owner = state.auth.enroll_test_totp(&state.boot, &token).await?;
    let other = service
        .step_up(
            &owner.token,
            StepUpRequest {
                proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("another session")?;
    let next = service
        .step_up(&owner.token, StepUpRequest { proof: None }, "test".into())
        .await?
        .into_session()
        .err()
        .context("cancelable selection")?;
    let mut wrong_secret = next.continuation.clone();
    let last = wrong_secret.pop().context("continuation secret")?;
    wrong_secret.push(if last == 'a' { 'b' } else { 'a' });
    for (source, bearer, continuation) in [
        ("cancel-missing-bearer", None, next.continuation.as_str()),
        (
            "cancel-invalid-bearer",
            Some("invalid-bearer-secret"),
            next.continuation.as_str(),
        ),
        (
            "cancel-other-session",
            Some(other.token.as_str()),
            next.continuation.as_str(),
        ),
        ("cancel-unknown-secret", None, wrong_secret.as_str()),
    ] {
        let error = service
            .cancel_authentication(
                bearer,
                CancelAuthenticationRequest {
                    continuation: continuation.into(),
                },
                source.into(),
            )
            .await
            .err()
            .context("cancellation must reject invalid authority")?;
        ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    }
    // None of the rejected cancellation attempts consumed the owner's token.
    service
        .cancel_authentication(
            Some(&owner.token),
            CancelAuthenticationRequest {
                continuation: next.continuation.clone(),
            },
            "cancel-owner".into(),
        )
        .await?;
    let replay = service
        .cancel_authentication(
            Some(&owner.token),
            CancelAuthenticationRequest {
                continuation: next.continuation.clone(),
            },
            "cancel-replay".into(),
        )
        .await
        .err()
        .context("cancellation consumed the continuation")?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);

    let facts = state.boot.kernel().facts().all_facts()?;
    for (source, outcome, username) in [
        ("cancel-missing-bearer", "missing_bearer", Some("root")),
        ("cancel-invalid-bearer", "invalid_session", Some("root")),
        ("cancel-other-session", "invalid_challenge", Some("root")),
        ("cancel-unknown-secret", "invalid_challenge", None),
        ("cancel-owner", "authentication_cancelled", Some("root")),
        ("cancel-replay", "invalid_challenge", None),
    ] {
        let audits: Vec<_> = facts
            .iter()
            .filter_map(|fact| fact.outcome.as_ref()?.as_map())
            .filter(|fields| {
                fields.get("event").and_then(Value::as_str) == Some("console_credential")
                    && fields.get("source_addr").and_then(Value::as_str) == Some(source)
            })
            .collect();
        ensure!(audits.len() == 1, "one audit per cancellation attempt");
        let audit = audits[0];
        ensure!(audit.get("outcome").and_then(Value::as_str) == Some(outcome));
        ensure!(audit.get("username").and_then(Value::as_str) == username);
        ensure!(audit.get("mfa_level").and_then(Value::as_int).is_none());
        ensure!(audit.get("details").is_none());
        let serialized = serde_json::to_string(&Value::from(audit.clone()))?;
        for secret in [
            &password,
            &owner.token,
            &other.token,
            &next.continuation,
            &wrong_secret,
        ] {
            ensure!(!serialized.contains(secret));
        }
        ensure!(!serialized.contains("invalid-bearer-secret"));
    }
    Ok(())
}
