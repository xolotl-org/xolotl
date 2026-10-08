use super::*;
use anyhow::{Context, ensure};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use xolotl_state::{
    InMemoryBackend, StateBoundedWrite, StateCommit, StateMutation, StateResult, StateWrite,
    TaintedValue,
};

fn login(username: &str) -> Binding {
    Binding::MfaLogin {
        username: username.into(),
        account: AccountKey::local(username),
    }
}

fn step_up(username: &str, sid: &str) -> Binding {
    Binding::MfaStepUp {
        username: username.into(),
        account: AccountKey::local(username),
        sid: sid.into(),
    }
}

fn public_key(username: &str) -> Binding {
    Binding::PublicKey {
        username: username.into(),
        origin: "https://console.test".into(),
    }
}

async fn stored(state: &Backend) -> anyhow::Result<Value> {
    state
        .read(&Path::parse(LEDGER)?)
        .await?
        .context("persisted ledger")
}

async fn entries(state: &Backend) -> anyhow::Result<Ledger> {
    Ok(decode(Some(&stored(state).await?))?)
}

async fn begin(
    state: &Backend,
    config: &ConsoleChallengeConfig,
    binding: Binding,
) -> anyhow::Result<String> {
    Ok(issue_continuation(
        test_runtime(),
        state,
        config,
        binding,
        "original-peer",
        xolotl_kernel::host::system_now_millis() + 60_000,
        &"first round",
    )
    .await?)
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
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_sub(1)
                })
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
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_sub(1)
                })
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
async fn two_hosts_have_one_claim_and_inflight_payload_stays_private() -> anyhow::Result<()> {
    let base = InMemoryBackend::new().into_backend();
    let binding = login("alice");
    let token = begin(&base, &ConsoleChallengeConfig::default(), binding.clone()).await?;
    let ready: Continuation<String> = inspect(test_runtime(), &base, &token).await?;
    ensure!(ready.binding == binding && ready.payload == "first round");
    let state = racing(&base);
    let first = state.clone();
    let second = state.clone();
    let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            claim::<String>(test_runtime(), &first, &token, &binding),
            claim::<String>(test_runtime(), &second, &token, &binding)
        )
    })
    .await?;
    ensure!(usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1);
    let round = match (a, b) {
        (Ok(round), Err(AuthError::InvalidChallenge))
        | (Err(AuthError::InvalidChallenge), Ok(round)) => round,
        _ => anyhow::bail!("one caller must own this round"),
    };
    ensure!(round.payload == ready.payload && round.expires_at == ready.expires_at);
    ensure!(round.ceremony_id == Token::parse(&token)?.id);
    ensure!(
        inspect::<String>(test_runtime(), &base, &token)
            .await
            .is_err()
    );
    ensure!(inspect_owner(test_runtime(), &base, &token).await? == binding);
    ensure!(
        claim::<String>(test_runtime(), &base, &token, &binding)
            .await
            .is_err()
    );
    finish(test_runtime(), &base, &round).await?;
    ensure!(entries(&base).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn cancellation_keeps_inflight_quota_until_the_owner_retires() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig {
        max_pending_global: 1,
        ..Default::default()
    }
    .bounded();
    let binding = step_up("alice", "original-session");
    let token = begin(&state, &config, binding.clone()).await?;
    let round: Round<String> = claim(test_runtime(), &state, &token, &binding).await?;
    cancel(test_runtime(), &state, &token, &binding).await?;
    let cancelled = stored(&state).await?;
    cancel(test_runtime(), &state, &token, &binding).await?;
    ensure!(stored(&state).await? == cancelled);
    ensure!(inspect_owner(test_runtime(), &state, &token).await? == binding);
    ensure!(entries(&state).await?.len() == 1);
    ensure!(begin(&state, &config, login("bob")).await.is_err());
    ensure!(matches!(
        issue(
            test_runtime(),
            &state,
            &config,
            public_key("bob"),
            "other-peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &"public-key challenge"
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    ensure!(
        advance(test_runtime(), &state, &config, &round, &"late result")
            .await
            .is_err()
    );
    ensure!(finish(test_runtime(), &state, &round).await.is_err());
    ensure!(stored(&state).await? == cancelled);
    retire(&state, &round).await?;
    retire(&state, &round).await?;
    let next = begin(&state, &config, login("bob")).await?;
    cancel(test_runtime(), &state, &next, &login("bob")).await?;
    ensure!(entries(&state).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn successors_rotate_tokens_but_keep_identity_deadline_and_source() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig {
        max_pending_per_source: 1,
        ..Default::default()
    };
    let binding = login("alice");
    let first = begin(&state, &config, binding.clone()).await?;
    let initial: Continuation<String> = inspect(test_runtime(), &state, &first).await?;
    let round: Round<String> = claim(test_runtime(), &state, &first, &binding).await?;
    let second = advance(test_runtime(), &state, &config, &round, &"second round").await?;
    ensure!(first != second);
    let next: Continuation<String> = inspect(test_runtime(), &state, &second).await?;
    ensure!(Token::parse(&first)?.id == Token::parse(&second)?.id);
    ensure!(initial.expires_at == next.expires_at && next.payload == "second round");
    let saved = stored(&state).await?;
    ensure!(
        inspect::<String>(test_runtime(), &state, &first)
            .await
            .is_err()
    );
    ensure!(inspect_owner(test_runtime(), &state, &first).await.is_err());
    ensure!(
        cancel(test_runtime(), &state, &first, &binding)
            .await
            .is_err()
    );
    ensure!(
        advance(test_runtime(), &state, &config, &round, &"stale result")
            .await
            .is_err()
    );
    ensure!(finish(test_runtime(), &state, &round).await.is_err());
    retire(&state, &round).await?;
    ensure!(stored(&state).await? == saved);
    ensure!(begin(&state, &config, login("bob")).await.is_err());
    ensure!(
        entries(&state).await?[Token::parse(&first)?.id].source_hash == token_hash("original-peer")
    );
    let current: Round<String> = claim(test_runtime(), &state, &second, &binding).await?;
    // Even a later in-flight round cannot be retired through an earlier claim.
    retire(&state, &round).await?;
    finish(test_runtime(), &state, &current).await?;
    ensure!(entries(&state).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn binding_and_phase_mismatches_never_consume_a_slot() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig::default();
    let binding = step_up("alice", "right-session");
    let token = begin(&state, &config, binding.clone()).await?;
    let saved = stored(&state).await?;
    for wrong in [
        login("alice"),
        step_up("bob", "right-session"),
        step_up("alice", "wrong-session"),
        public_key("alice"),
    ] {
        ensure!(
            claim::<String>(test_runtime(), &state, &token, &wrong)
                .await
                .is_err()
        );
        ensure!(
            cancel(test_runtime(), &state, &token, &wrong)
                .await
                .is_err()
        );
        ensure!(stored(&state).await? == saved);
    }
    let id = token.split_once('.').context("token")?.0;
    ensure!(
        take::<String>(test_runtime(), &state, id, &binding)
            .await
            .is_err()
    );
    ensure!(
        take::<String>(test_runtime(), &state, id, &public_key("alice"))
            .await
            .is_err()
    );
    ensure!(stored(&state).await? == saved);
    ensure!(
        issue(
            test_runtime(),
            &state,
            &config,
            binding.clone(),
            "peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &0
        )
        .await
        .is_err()
    );
    ensure!(begin(&state, &config, public_key("bob")).await.is_err());
    let single = issue(
        test_runtime(),
        &state,
        &config,
        public_key("bob"),
        "peer",
        xolotl_kernel::host::system_now_millis() + 60_000,
        &"single use",
    )
    .await?;
    let forged = format!("{single}.{}", random_token(32)?);
    let saved = stored(&state).await?;
    ensure!(
        inspect::<String>(test_runtime(), &state, &forged)
            .await
            .is_err()
    );
    ensure!(
        inspect_owner(test_runtime(), &state, &forged)
            .await
            .is_err()
    );
    ensure!(
        claim::<String>(test_runtime(), &state, &forged, &login("bob"))
            .await
            .is_err()
    );
    ensure!(
        cancel(test_runtime(), &state, &forged, &login("bob"))
            .await
            .is_err()
    );
    ensure!(stored(&state).await? == saved);
    ensure!(
        take::<String>(test_runtime(), &state, &single, &public_key("bob")).await? == "single use"
    );
    cancel(test_runtime(), &state, &token, &binding).await?;
    Ok(())
}

#[tokio::test]
async fn invalid_tokens_and_payload_types_do_not_change_ownership() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let binding = login("alice");
    let token = begin(&state, &ConsoleChallengeConfig::default(), binding.clone()).await?;
    let (id, secret) = token.split_once('.').context("token")?;
    let persisted = stored(&state).await?;
    let encoded = persisted.as_str().context("encoded ledger")?;
    ensure!(!encoded.contains(secret) && !encoded.contains("original-peer"));
    for invalid in [
        String::new(),
        "x".repeat(4096),
        id.into(),
        format!("{id}.{}", random_token(32)?),
        format!("{id}.{secret}.extra"),
        format!("{id}.{}", "é".repeat(22)),
    ] {
        ensure!(
            inspect::<String>(test_runtime(), &state, &invalid)
                .await
                .is_err()
        );
        ensure!(
            inspect_owner(test_runtime(), &state, &invalid)
                .await
                .is_err()
        );
        ensure!(
            claim::<String>(test_runtime(), &state, &invalid, &binding)
                .await
                .is_err()
        );
        ensure!(
            cancel(test_runtime(), &state, &invalid, &binding)
                .await
                .is_err()
        );
    }
    ensure!(
        inspect::<u64>(test_runtime(), &state, &token)
            .await
            .is_err()
    );
    ensure!(
        claim::<u64>(test_runtime(), &state, &token, &binding)
            .await
            .is_err()
    );
    ensure!(stored(&state).await? == persisted);
    let round: Round<String> = claim(test_runtime(), &state, &token, &binding).await?;
    retire(&state, &round).await?;
    Ok(())
}

#[tokio::test]
async fn quota_is_shared_across_single_use_and_continuation_kinds() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig {
        max_pending_global: 3,
        max_pending_per_user: 1,
        max_pending_per_source: 2,
        ..Default::default()
    };
    let token = begin(&state, &config, login("alice")).await?;
    let round: Round<String> = claim(test_runtime(), &state, &token, &login("alice")).await?;
    issue(
        test_runtime(),
        &state,
        &config,
        public_key("bob"),
        "original-peer",
        xolotl_kernel::host::system_now_millis() + 60_000,
        &0,
    )
    .await?;
    // MFA quota follows its stable account key; a legacy single-use challenge
    // with the same display name cannot establish that it owns the account.
    ensure!(matches!(
        issue_continuation(
            test_runtime(),
            &state,
            &config,
            step_up("alice", "other-session"),
            "other-peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &"another round",
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    ensure!(matches!(
        issue(
            test_runtime(),
            &state,
            &config,
            public_key("carol"),
            "original-peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &0,
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    issue(
        test_runtime(),
        &state,
        &config,
        public_key("alice"),
        "other-peer",
        xolotl_kernel::host::system_now_millis() + 60_000,
        &0,
    )
    .await?;
    ensure!(matches!(
        issue(
            test_runtime(),
            &state,
            &config,
            public_key("dave"),
            "third-peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &0,
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    cancel(test_runtime(), &state, &token, &login("alice")).await?;
    ensure!(matches!(
        issue_continuation(
            test_runtime(),
            &state,
            &config,
            login("carol"),
            "third-peer",
            xolotl_kernel::host::system_now_millis() + 60_000,
            &"new round",
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    retire(&state, &round).await?;
    issue_continuation(
        test_runtime(),
        &state,
        &config,
        login("carol"),
        "third-peer",
        xolotl_kernel::host::system_now_millis() + 60_000,
        &"new round",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn byte_growth_failure_keeps_the_claim_and_reservation_covers_claim_metadata()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig {
        max_bytes: 1024,
        ..Default::default()
    };
    let binding = login("alice");
    let token = begin(&state, &config, binding.clone()).await?;
    let ready = stored(&state).await?;
    let ready_length = ready.as_str().context("ready encoding")?.len();
    let reservation = claim_reservation_bytes()?;
    let round: Round<String> = claim(test_runtime(), &state, &token, &binding).await?;
    let inflight = stored(&state).await?;
    let inflight_length = inflight.as_str().context("in-flight encoding")?.len();
    ensure!(inflight_length == ready_length + reservation);
    ensure!(inflight_length <= config.max_bytes);
    for payload in ["x".repeat(1024), "x".repeat(MAX_PAYLOAD_BYTES)] {
        ensure!(matches!(
            advance(test_runtime(), &state, &config, &round, &payload).await,
            Err(AuthError::CapacityExceeded)
        ));
        ensure!(stored(&state).await? == inflight);
    }
    // An admission budget that fits Ready but not its claim is rejected up front.
    let other = InMemoryBackend::new().into_backend();
    let too_small = ConsoleChallengeConfig {
        max_bytes: inflight_length - 1,
        ..config.clone()
    };
    ensure!(matches!(
        issue_continuation(
            test_runtime(),
            &other,
            &too_small,
            binding,
            "original-peer",
            round.expires_at,
            &"first round"
        )
        .await,
        Err(AuthError::CapacityExceeded)
    ));
    ensure!(other.read(&Path::parse(LEDGER)?).await?.is_none());
    retire(&state, &round).await?;
    Ok(())
}

async fn expire(state: &Backend, id: &str) -> anyhow::Result<()> {
    let mut ledger = entries(state).await?;
    ledger.get_mut(id).context("ceremony")?.expires_at =
        xolotl_kernel::host::system_now_millis() - 1;
    state
        .write_set(&Path::parse(LEDGER)?, encode(&ledger, HARD_MAX_BYTES)?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn expired_rounds_cannot_progress_and_admission_reclaims_abandoned_work() -> anyhow::Result<()>
{
    let state = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig {
        max_pending_global: 1,
        ..Default::default()
    }
    .bounded();
    let binding = login("alice");
    let token = begin(&state, &config, binding.clone()).await?;
    expire(&state, Token::parse(&token)?.id).await?;
    ensure!(
        inspect::<String>(test_runtime(), &state, &token)
            .await
            .is_err()
    );
    ensure!(inspect_owner(test_runtime(), &state, &token).await.is_err());
    ensure!(
        claim::<String>(test_runtime(), &state, &token, &binding)
            .await
            .is_err()
    );
    ensure!(
        cancel(test_runtime(), &state, &token, &binding)
            .await
            .is_err()
    );
    let token = begin(&state, &config, binding.clone()).await?;
    let round: Round<String> = claim(test_runtime(), &state, &token, &binding).await?;
    expire(&state, &round.ceremony_id).await?;
    ensure!(
        advance(test_runtime(), &state, &config, &round, &"too late")
            .await
            .is_err()
    );
    ensure!(finish(test_runtime(), &state, &round).await.is_err());
    let replacement = begin(&state, &config, login("bob")).await?;
    retire(&state, &round).await?;
    ensure!(
        inspect::<String>(test_runtime(), &state, &replacement)
            .await?
            .binding
            == login("bob")
    );
    ensure!(entries(&state).await?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn cancellation_and_successor_publication_have_one_winner() -> anyhow::Result<()> {
    let base = InMemoryBackend::new().into_backend();
    let config = ConsoleChallengeConfig::default();
    let binding = login("alice");
    let token = begin(&base, &config, binding.clone()).await?;
    let round: Round<String> = claim(test_runtime(), &base, &token, &binding).await?;
    let state = racing(&base);
    let (canceled, advanced) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            cancel(test_runtime(), &state, &token, &binding),
            advance(test_runtime(), &state, &config, &round, &"successor")
        )
    })
    .await?;
    ensure!(usize::from(canceled.is_ok()) + usize::from(advanced.is_ok()) == 1);
    match advanced {
        Ok(next) => {
            retire(&base, &round).await?;
            ensure!(
                inspect::<String>(test_runtime(), &base, &next)
                    .await?
                    .payload
                    == "successor"
            );
            ensure!(
                cancel(test_runtime(), &base, &token, &binding)
                    .await
                    .is_err()
            );
            cancel(test_runtime(), &base, &next, &binding).await?;
        }
        Err(AuthError::InvalidChallenge) => {
            ensure!(canceled.is_ok() && entries(&base).await?.len() == 1);
            ensure!(finish(test_runtime(), &base, &round).await.is_err());
            retire(&base, &round).await?;
        }
        Err(error) => return Err(error.into()),
    }
    ensure!(entries(&base).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn cancellation_and_final_consumption_have_one_winner() -> anyhow::Result<()> {
    let base = InMemoryBackend::new().into_backend();
    let binding = login("alice");
    let token = begin(&base, &ConsoleChallengeConfig::default(), binding.clone()).await?;
    let round: Round<String> = claim(test_runtime(), &base, &token, &binding).await?;
    let state = racing(&base);
    let (canceled, finished) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            cancel(test_runtime(), &state, &token, &binding),
            finish(test_runtime(), &state, &round)
        )
    })
    .await?;
    ensure!(usize::from(canceled.is_ok()) + usize::from(finished.is_ok()) == 1);
    if canceled.is_ok() {
        ensure!(entries(&base).await?.len() == 1);
        ensure!(finish(test_runtime(), &base, &round).await.is_err());
        retire(&base, &round).await?;
    } else {
        ensure!(entries(&base).await?.is_empty());
        ensure!(
            cancel(test_runtime(), &base, &token, &binding)
                .await
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn missing_or_cross_kind_phases_are_not_legacy_compatible() -> anyhow::Result<()> {
    for entry in [
        serde_json::json!({"binding":{"kind":"mfa_login","username":"alice"},"source_hash":"x","expires_at":1,"payload":null}),
        serde_json::json!({"binding":{"kind":"mfa_login","username":"alice"},"source_hash":"x","expires_at":1,"phase":{"state":"single_use"},"payload":null}),
        serde_json::json!({"binding":{"kind":"public_key","username":"alice","origin":"https://console.test"},"source_hash":"x","expires_at":1,"phase":{"state":"ready","token_hash":"x"},"payload":null}),
    ] {
        let encoded = Value::string(serde_json::json!({"entry":entry}).to_string());
        ensure!(decode(Some(&encoded)).is_err());
    }
    Ok(())
}

struct DelayedCommit {
    state: Backend,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

impl StateWrite for DelayedCommit {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            self.entered.notify_one();
            let permit = self.release.acquire().await.map_err(|_error| {
                xolotl_state::StateError::CasFailed {
                    path: path.to_string(),
                    expected: None,
                    actual: None,
                }
            })?;
            permit.forget();
            self.state.mutate(path, mutation).await
        })
    }
}

impl StateBoundedWrite for DelayedCommit {
    type BoundedWrite<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            self.entered.notify_one();
            let permit = self.release.acquire().await.map_err(|_error| {
                xolotl_state::StateError::CasFailed {
                    path: path.to_string(),
                    expected: None,
                    actual: None,
                }
            })?;
            permit.forget();
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

#[derive(Clone, Copy)]
enum CommitBoundary {
    Admission,
    Claim,
    Advance,
    Finish,
}

#[tokio::test]
async fn a_commit_acknowledged_after_the_deadline_never_returns_authority() -> anyhow::Result<()> {
    for boundary in [
        CommitBoundary::Admission,
        CommitBoundary::Claim,
        CommitBoundary::Advance,
        CommitBoundary::Finish,
    ] {
        let base = InMemoryBackend::new().into_backend();
        let config = ConsoleChallengeConfig {
            max_pending_global: 1,
            ..Default::default()
        }
        .bounded();
        let expires_at = xolotl_kernel::host::system_now_millis() + 1_000;
        let token = if matches!(boundary, CommitBoundary::Admission) {
            None
        } else {
            Some(
                issue_continuation(
                    test_runtime(),
                    &base,
                    &config,
                    login("alice"),
                    "peer",
                    expires_at,
                    &"state",
                )
                .await?,
            )
        };
        let round = if matches!(boundary, CommitBoundary::Advance | CommitBoundary::Finish) {
            Some(
                claim::<String>(
                    test_runtime(),
                    &base,
                    token.as_deref().context("token")?,
                    &login("alice"),
                )
                .await?,
            )
        } else {
            None
        };
        let delay = Arc::new(DelayedCommit {
            state: base.clone(),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        let state = base
            .clone()
            .with_write(delay.clone())
            .with_bounded_write(delay.clone());
        let work = tokio::spawn({
            let config = config.clone();
            async move {
                match boundary {
                    CommitBoundary::Admission => issue_continuation(
                        test_runtime(),
                        &state,
                        &config,
                        login("alice"),
                        "peer",
                        expires_at,
                        &"state",
                    )
                    .await
                    .map(drop),
                    CommitBoundary::Claim => claim::<String>(
                        test_runtime(),
                        &state,
                        token.as_deref().ok_or(AuthError::InvalidChallenge)?,
                        &login("alice"),
                    )
                    .await
                    .map(drop),
                    CommitBoundary::Advance => advance(
                        test_runtime(),
                        &state,
                        &config,
                        round.as_ref().ok_or(AuthError::InvalidChallenge)?,
                        &"next",
                    )
                    .await
                    .map(drop),
                    CommitBoundary::Finish => {
                        finish(
                            test_runtime(),
                            &state,
                            round.as_ref().ok_or(AuthError::InvalidChallenge)?,
                        )
                        .await
                    }
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(5), delay.entered.notified()).await?;
        tokio::time::sleep(Duration::from_millis(
            expires_at
                .saturating_sub(xolotl_kernel::host::system_now_millis())
                .max(0) as u64
                + 5,
        ))
        .await;
        delay.release.add_permits(1);
        ensure!(matches!(work.await?, Err(AuthError::InvalidChallenge)));
        // Expired committed state is reclaimed, rather than rolled back or resumed.
        begin(&base, &config, login("bob")).await?;
    }
    Ok(())
}
