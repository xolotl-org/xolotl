use super::*;
use crate::protocol::{ACTION_ACCESS_ROLE_WRITE_CAS, ConsoleErrorCode};
use crate::{ConsoleConfig, ConsoleState};
use anyhow::{Context, ensure};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::{future::Future, pin::Pin, time::Duration};
use xolotl_kernel::{
    Bootstrap, ExecutionIdError, ExecutionIdRange, ExecutionIdSource, FactError, FactLookup,
    FactLookupResult, FactPage, FactQuery, FactSink, FactStore, InMemoryFactStore, KernelBuilder,
};
use xolotl_state::{Backend, InMemoryBackend, StateCommit, StateMutation, StateResult, StateWrite};
use xolotl_types::{CapSet, Fact, ProcessId};

#[derive(Default)]
struct AuditStore {
    inner: InMemoryFactStore,
    fail: AtomicU8,
    mutation_writes: AtomicUsize,
}

impl ExecutionIdSource for AuditStore {
    fn reserve(&self, count: std::num::NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.inner.reserve(count)
    }
}

impl FactStore for AuditStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        self.inner.append(fact)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        let record = fact.outcome.as_ref().and_then(Value::as_map);
        if record.and_then(|m| m.get("event")).and_then(Value::as_str) == Some("console_mutation") {
            self.mutation_writes.fetch_add(1, Ordering::SeqCst);
            let outcome = record
                .and_then(|m| m.get("outcome"))
                .and_then(Value::as_str);
            let fail = self.fail.load(Ordering::SeqCst);
            if (fail == 1 && outcome == Some("started"))
                || (fail == 2 && outcome != Some("started"))
            {
                return Err(FactError::new("audit-backend-sensitive-sentinel".into()));
            }
        }
        self.inner.complete(fact)
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.inner.scan(query)
    }
    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.inner.lookup(query)
    }
    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        self.inner.facts_of(process)
    }
    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.inner.all_facts()
    }
    fn cursor(&self) -> u64 {
        self.inner.cursor()
    }
}

fn fixture() -> anyhow::Result<(Arc<ConsoleState>, Arc<AuditStore>, ConsolePrincipal)> {
    let store = Arc::new(AuditStore::default());
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(InMemoryBackend::new().into_backend())
            .with_fact_sink(FactSink::new(store.clone()))
            .build(),
    ));
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            ..Default::default()
        },
    )?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "admin".into(),
        account_id: "admin-account".into(),
        identity_path: "identity://console/accounts/admin-account".into(),
        grants: CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    Ok((state, store, principal))
}

fn context(state: &Arc<ConsoleState>) -> actions::ActionContext<'_> {
    actions::ActionContext {
        delivery: None,
        state,
        source_addr: Some("verified-peer"),
        session_id: "never-log-this-session",
    }
}

fn write_role() -> ActionCall {
    ActionCall {
        action: ACTION_ACCESS_ROLE_WRITE_CAS.into(),
        input: map_value([
            ("role", Value::string("private-role-name".into())),
            (
                "value",
                map_value([(
                    "grants",
                    Value::list(vec![Value::string("read://state/private-grant/**".into())]),
                )]),
            ),
            ("expected_version", Value::null()),
        ]),
        ..Default::default()
    }
}

fn records(state: &ConsoleState) -> anyhow::Result<Vec<Value>> {
    Ok(state
        .boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .filter_map(|fact| fact.outcome)
        .filter(|value| {
            value
                .as_map()
                .and_then(|m| m.get("event"))
                .and_then(Value::as_str)
                == Some("console_mutation")
        })
        .collect())
}

#[tokio::test]
async fn management_success_and_cas_conflict_do_not_create_mutation_audits() -> anyhow::Result<()> {
    let (state, service, token, _) = super::super::tests::fixture().await?;
    let token = state
        .auth
        .enroll_test_totp(&state.boot, &token)
        .await?
        .token;
    let result = service
        .call(&token, Some("verified-peer"), write_role())
        .await?;
    ensure!(result.output.is_none());
    let conflict = service
        .call(&token, Some("verified-peer"), write_role())
        .await
        .err()
        .context("CAS conflict")?;
    ensure!(conflict.code == ConsoleErrorCode::Conflict && conflict.current_version == Some(1));
    ensure!(records(&state)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn management_mutations_do_not_depend_on_audit_writes() -> anyhow::Result<()> {
    for failure_stage in [1, 2] {
        let (state, store, principal) = fixture()?;
        store.fail.store(failure_stage, Ordering::SeqCst);
        let result = execute(&context(&state), &principal, write_role()).await?;
        ensure!(result.result.output.is_none());
        ensure!(
            state
                .state
                .read(&Path::parse(
                    "state://kernel/console/roles/private-role-name"
                )?)
                .await?
                .is_some()
        );
        ensure!(store.mutation_writes.load(Ordering::SeqCst) == 0);
        ensure!(records(&state)?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn target_authorization_remains_required_without_audit() -> anyhow::Result<()> {
    let (state, store, mut principal) = fixture()?;
    principal.grants = CapSet::from_strs(["read://state/kernel/console/roles/**"])?;
    let error = execute(&context(&state), &principal, write_role())
        .await
        .err()
        .context("permission rejection")?;
    ensure!(ConsoleFailure::from(error).code == ConsoleErrorCode::Forbidden);
    ensure!(
        state
            .state
            .read(&Path::parse(
                "state://kernel/console/roles/private-role-name"
            )?)
            .await?
            .is_none()
    );
    ensure!(store.mutation_writes.load(Ordering::SeqCst) == 0);
    Ok(())
}

struct PendingCommit {
    state: Backend,
    target: Path,
    entered: tokio::sync::Notify,
}

impl StateWrite for PendingCommit {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let commit = self.state.mutate(path, mutation).await?;
            if path == &self.target {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(commit)
        })
    }
}

#[tokio::test]
async fn canceling_a_committed_call_releases_capacity_without_rollback() -> anyhow::Result<()> {
    let memory = InMemoryBackend::new().into_backend();
    let write = Arc::new(PendingCommit {
        state: memory.clone(),
        target: Path::parse("state://kernel/console/roles/private-role-name")?,
        entered: tokio::sync::Notify::new(),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(memory.with_write(write.clone()))
            .with_fact_sink(FactSink::in_memory().0)
            .build(),
    ));
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            max_concurrent_calls: 1,
            ..Default::default()
        },
    )?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "admin".into(),
        account_id: "admin-account".into(),
        identity_path: "identity://console/accounts/admin-account".into(),
        grants: CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let context = context(&state);
    let mut running = Box::pin(execute(&context, &principal, write_role()));
    tokio::select! {
        _result = &mut running => anyhow::bail!("call returned before pending commit"),
        ready = tokio::time::timeout(Duration::from_secs(5), write.entered.notified()) => ready?,
    }
    ensure!(state.calls.try_acquire().is_err());
    drop(running);
    let _capacity = state.calls.try_acquire().context("call capacity leaked")?;
    ensure!(state.state.read(&write.target).await?.is_some());
    ensure!(records(&state)?.is_empty());
    Ok(())
}
