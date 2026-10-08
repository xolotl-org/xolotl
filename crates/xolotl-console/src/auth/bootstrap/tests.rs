use super::*;
use anyhow::{Context, ensure};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use xolotl_kernel::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};
use xolotl_kernel::{FactSink, KernelBuilder};
use xolotl_state::{
    InMemoryBackend, StateBoundedWrite, StateCommit, StateMutation, StateResult, StateWrite,
    TaintedValue,
};

struct RejectHash;

impl BlockingSpawner for RejectHash {
    fn spawn(&self, _job: BlockingJob) -> Result<(), BlockingSpawnError> {
        Err(BlockingSpawnError::AtCapacity)
    }
}

#[tokio::test]
async fn rejected_password_hash_leaves_no_partial_root_account() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    ensure!(matches!(
        bootstrap_root_account(&boot, &RejectHash, RootProvisioning::default()).await,
        Err(AuthError::CapacityExceeded)
    ));
    ensure!(
        read_user(boot.kernel().state(), ROOT_USERNAME)
            .await?
            .is_none()
    );
    Ok(())
}

struct PausedWrite {
    state: Backend,
    before_activation: bool,
    armed: AtomicBool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl StateWrite for PausedWrite {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let pause = if self.before_activation {
                path.to_string() == "state://kernel/console/users/root"
                    && matches!(&mutation, StateMutation::CompareSet { value, .. }
                        if value.value.as_map().and_then(|m| m.get("status")).and_then(Value::as_str) == Some("active"))
            } else {
                path.to_string()
                    .starts_with("state://vault/console/credentials/local/")
            };
            if pause && self.armed.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            self.state.mutate(path, mutation).await
        })
    }
}

impl StateBoundedWrite for PausedWrite {
    type BoundedWrite<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            if !self.before_activation
                && path
                    .to_string()
                    .starts_with("state://vault/console/credentials/local/")
                && self.armed.swap(false, Ordering::SeqCst)
            {
                self.entered.notify_one();
                self.resume.notified().await;
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

#[tokio::test]
async fn interrupted_or_displaced_bootstrap_cannot_replace_a_newly_active_account()
-> anyhow::Result<()> {
    for before_activation in [false, true] {
        for cancel in [false, true] {
            let memory = InMemoryBackend::new().into_backend();
            let write = Arc::new(PausedWrite {
                state: memory.clone(),
                before_activation,
                armed: AtomicBool::new(true),
                entered: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
            });
            let boot = Bootstrap::from_kernel(
                KernelBuilder::new(
                    memory
                        .with_write(write.clone())
                        .with_bounded_write(write.clone()),
                )
                .with_fact_sink(FactSink::in_memory().0)
                .build(),
            );
            let blocking_spawner = xolotl_kernel::host::TokioBlockingSpawner::default();
            let mut previous = Box::pin(bootstrap_root_account(
                &boot,
                &blocking_spawner,
                RootProvisioning::default(),
            ));
            tokio::select! {
                result = &mut previous => { result?; anyhow::bail!("bootstrap did not pause") },
                ready = tokio::time::timeout(Duration::from_secs(2), write.entered.notified()) => ready?,
            }
            let pending = read_user(boot.kernel().state(), ROOT_USERNAME)
                .await?
                .context("pending account")?;
            ensure!(pending.status == "provisioning");
            ensure!(root_random_password_needed(&boot, &RootProvisioning::default()).await?);
            let mut previous = Some(previous);
            if cancel {
                drop(previous.take());
            }
            let outcome =
                bootstrap_root_account(&boot, &blocking_spawner, RootProvisioning::default())
                    .await?;
            let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
                anyhow::bail!("pending bootstrap was not recovered");
            };
            let current = read_user(boot.kernel().state(), ROOT_USERNAME)
                .await?
                .context("active account")?;
            let credential = credentials::read(
                boot.kernel().state(),
                ROOT_USERNAME,
                crate::auth::test_credential_sealer().as_ref(),
            )
            .await?;
            ensure!(current.status == "active" && current.account_id != pending.account_id);
            ensure!(credential.account_id == current.account_id);
            ensure!(verify_password(
                credential.password.as_deref().context("password")?,
                &password
            ));
            if let Some(previous) = previous {
                write.resume.notify_one();
                ensure!(previous.await.is_err());
            }
            ensure!(
                read_user(boot.kernel().state(), ROOT_USERNAME)
                    .await?
                    .context("current")?
                    .persisted
                    == current.persisted
            );
            ensure!(
                credentials::read(
                    boot.kernel().state(),
                    ROOT_USERNAME,
                    crate::auth::test_credential_sealer().as_ref()
                )
                .await?
                .persisted
                    == credential.persisted
            );
            ensure!(!root_random_password_needed(&boot, &RootProvisioning::default()).await?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn an_unactivated_credential_record_does_not_block_fresh_bootstrap() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    credentials::write_by_key(
        boot.kernel().state(),
        &AccountKey::local("orphan"),
        &credentials::AccountCredentials {
            authority_id: "local".into(),
            account_id: "orphan".into(),
            epoch: "orphan".into(),
            ..Default::default()
        },
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let outcome = bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning::default(),
    )
    .await?;
    ensure!(matches!(
        outcome,
        BootstrapOutcome::CreatedRandomPassword { .. }
    ));
    let current = credentials::read(
        boot.kernel().state(),
        ROOT_USERNAME,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(current.account_id != "orphan" && current.has_primary());
    Ok(())
}

#[tokio::test]
async fn ordinary_root_name_cannot_claim_bootstrap_ownership() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let state = boot.kernel().state();
    let user = UserRecord {
        persisted: None,
        username: ROOT_USERNAME.into(),
        account_id: "ordinary-instance".into(),
        bootstrap_owner: false,
        identity_path: local_identity_path("ordinary-instance")?,
        status: "active".into(),
        roles: Vec::new(),
        grants: Vec::new(),
        authority_ceiling: Vec::new(),
        created_by: "local:another-instance".into(),
        created_at: xolotl_kernel::host::system_now_millis(),
    };
    write_user(state, &user).await?;
    ensure!(matches!(
        bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            RootProvisioning::default()
        )
        .await,
        Err(AuthError::AccountUnavailable)
    ));
    ensure!(matches!(
        root_random_password_needed(&boot, &RootProvisioning::default()).await,
        Err(AuthError::AccountUnavailable)
    ));
    let retained = read_user(state, ROOT_USERNAME)
        .await?
        .context("ordinary root")?;
    ensure!(!retained.bootstrap_owner);
    Ok(())
}
