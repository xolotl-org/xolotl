use super::{CompiledRecipe, StateMethod, execute};
use crate::auth::ConsolePrincipal;
use crate::protocol::{ACTION_VISIBILITY_STATE_READ, ActionCall};
use crate::service::{self, actions::ActionContext, map_value};
use crate::{ConsoleConfig, ConsoleState};
use anyhow::{Context, ensure};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use xolotl_kernel::{Bootstrap, FactSink, KernelBuilder};
use xolotl_state::{Backend, InMemoryBackend, StateRead, StateResult};
use xolotl_types::{CapSet, Path, ProcessStatus, Value};

#[tokio::test]
async fn state_recipe_opens_only_the_granted_method() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    xolotl_standard::install_standard(&boot, &xolotl_standard::StandardConfig::default())?;
    let state = ConsoleState::with_config(
        boot.clone(),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            ..Default::default()
        },
    )?;
    let path = Path::parse("state://app/public")?;
    boot.kernel()
        .state()
        .write_set(&path, Value::string("visible".into()))
        .await?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "reader".into(),
        account_id: "reader-account".into(),
        identity_path: "identity://console/accounts/reader-account".into(),
        grants: CapSet::from_strs(["read://state/app/public#read"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let read = CompiledRecipe::state(path.clone(), StateMethod::Read, Value::null())?;
    ensure!(execute(&state, &principal, read).await? == Value::string("visible".into()));
    let list = CompiledRecipe::state(path, StateMethod::List, Value::null())?;
    ensure!(execute(&state, &principal, list).await.is_err());
    Ok(())
}

struct PendingRead {
    state: Backend,
    target: Path,
    entered: tokio::sync::Notify,
}

impl StateRead for PendingRead {
    type Read<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateObservation>> + Send + 'a>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            if path == &self.target {
                self.entered.notify_one();
                std::future::pending().await
            } else {
                self.state.read_tainted(path).await
            }
        })
    }
}

#[tokio::test]
async fn canceled_service_call_revokes_request_handles_and_releases_capacity() -> anyhow::Result<()>
{
    let memory = InMemoryBackend::new().into_backend();
    let read = Arc::new(PendingRead {
        state: memory.clone(),
        target: Path::parse("state://app/pending")?,
        entered: tokio::sync::Notify::new(),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(memory.with_read(read.clone()))
            .with_fact_sink(FactSink::in_memory().0)
            .build(),
    ));
    xolotl_standard::install_standard(&boot, &xolotl_standard::StandardConfig::default())?;
    let state = ConsoleState::with_config(
        boot.clone(),
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
    let context = ActionContext {
        delivery: None,
        state: &state,
        session_id: "test-session",
        source_addr: Some("embedded"),
    };
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "reader".into(),
        account_id: "reader-account".into(),
        identity_path: "identity://console/accounts/reader-account".into(),
        grants: CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let before_processes = boot.kernel().processes().all_ids();
    let before_handles = boot.kernel().handles().len();
    let call = ActionCall {
        action: ACTION_VISIBILITY_STATE_READ.into(),
        input: map_value([("path", Value::string(read.target.to_string()))]),
        scope: Some("inspect pending state".into()),
        justification: Some("cancellation regression".into()),
        ttl_ms: Some(60_000),
        ..Default::default()
    };
    let mut running = Box::pin(service::execute(&context, &principal, call));
    tokio::select! {
        result = &mut running => {
            result.map_err(|error| anyhow::anyhow!("call failed before pending read: {error}"))?;
            anyhow::bail!("call completed before entering pending read");
        },
        ready = tokio::time::timeout(Duration::from_secs(5), read.entered.notified()) => ready?,
    }
    let processes: Vec<_> = boot
        .kernel()
        .processes()
        .all_ids()
        .into_iter()
        .filter(|id| !before_processes.contains(id))
        .collect();
    ensure!(processes.len() == 1);
    let request = processes[0];
    ensure!(boot.kernel().processes().status(request) == Some(ProcessStatus::Running));
    ensure!(boot.kernel().handles().len() > before_handles);
    ensure!(state.calls.try_acquire().is_err());
    drop(running);
    ensure!(boot.kernel().processes().status(request) == Some(ProcessStatus::Cancelled));
    ensure!(boot.kernel().handles().len() == before_handles);
    let _capacity = state.calls.try_acquire().context("call capacity leaked")?;
    let cleanup = boot.drain_cleanup().await;
    ensure!(cleanup.failures.is_empty());
    ensure!(
        boot.kernel()
            .processes()
            .attached_grants(request)
            .is_empty()
    );
    ensure!(boot.kernel().facts().facts_of(request)?.is_empty());
    Ok(())
}
