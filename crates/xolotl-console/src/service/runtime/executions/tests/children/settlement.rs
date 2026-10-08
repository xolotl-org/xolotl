use super::*;
use crate::{ConsoleConfig, ConsoleExecutionConfig, ConsoleRuntimeConfig};
use anyhow::{Context, ensure};
use xolotl_kernel::Bootstrap;

struct Fixture {
    state: Arc<ConsoleState>,
    owner: Owner,
    reference: ExecutionReference,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let state = ConsoleState::with_config(
            Arc::new(Bootstrap::in_memory()),
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                runtime: ConsoleRuntimeConfig {
                    enabled: true,
                    executions: ConsoleExecutionConfig {
                        enabled: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        let owner = serde_json::from_value::<ExecutionOwner>(serde_json::json!({
            "username": "root", "account_id": "account", "authority_id": "local", "revocation_epoch": "1", "authority_ceiling": [],
            "credential_epoch": "credentials", "identity_path": "identity://console/accounts/account",
        }))?;
        let process = state
            .boot
            .request_under(state.boot.root(), xolotl_types::IdentityRef::ROOT, &[])?
            .detach();
        let (registration, stop, reference) = state.executions.register(
            owner.clone(),
            Vec::new(),
            ExecutionReference {
                execution_id: None,
                process_id: process.get().to_string(),
                program_id: "program".into(),
            },
            xolotl_kernel::host::system_now_millis() + 60_000,
            xolotl_types::BudgetSpec::default(),
        )?;
        let owner = Owner {
            state: Arc::downgrade(&state),
            owner,
            authority: Vec::new(),
            authority_candidates: Vec::new(),
            process,
            settlement: Mutex::new(Settlement {
                registration,
                released: false,
                published: false,
            }),
            stop,
            reason: Mutex::new(None),
            max_result_bytes: state.runtime.config.executions.max_result_bytes,
        };
        Ok(Self {
            state,
            owner,
            reference,
        })
    }

    fn result(&self) -> anyhow::Result<Value> {
        Ok(self.state.executions.result(
            &self.owner.owner,
            self.reference.execution_id.as_deref().context("ID")?,
            |_| true,
        )?)
    }

    async fn complete(&self, status: ProcessStatus) -> anyhow::Result<()> {
        self.state
            .boot
            .finish_process_as(self.owner.process, status)
            .await?;
        Ok(())
    }
}

fn field<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    value
        .as_map()
        .and_then(|map| map.get(name))
        .context(name.to_owned())
}

fn body() -> ExecutionOutput {
    ExecutionOutput::new(Outcome::Done(Value::integer(37)), TaintSet::author())
}

#[tokio::test]
async fn committed_publication_replaces_release_status_without_replacing_body_or_retention()
-> anyhow::Result<()> {
    for status in [ProcessStatus::Cancelled, ProcessStatus::Failed] {
        let fixture = Fixture::new()?;
        let output = body();
        fixture
            .owner
            .released(ProcessStatus::Completed, Some(&output));
        let pending = fixture.result()?;
        ensure!(field(field(&pending, "record")?, "cleanup_status")?.as_str() == Some("pending"));
        let ticket = fixture.state.boot.cleanup_ticket(fixture.owner.process)?;
        ensure!(!ticket.is_complete());
        fixture.owner.publish(status, Some(&output)).await?;
        // Accepting publication still precedes the kernel's cleanup commit.
        ensure!(
            field(field(&fixture.result()?, "record")?, "cleanup_status")?.as_str()
                == Some("pending")
        );
        fixture.complete(status).await?;
        let published = fixture.result()?;
        let record = field(&published, "record")?;
        ensure!(field(record, "outcome")?.as_str() == Some("done"));
        ensure!(
            field(
                field(field(&published, "finalization")?, "report")?,
                "status"
            )? == &crate::service::serde_value(status)?
        );
        ensure!(field(record, "cleanup_status")?.as_str() == Some("complete"));
        ensure!(ticket.terminal_status() == Some(status));
        ensure!(ticket.is_complete());
        ensure!(field(record, "expires_at")? == field(field(&pending, "record")?, "expires_at")?);
        ensure!(field(&published, "output")? == &result_value(&output)?);
        fixture.owner.released(ProcessStatus::Cancelled, None);
        fixture
            .owner
            .publish(ProcessStatus::Completed, None)
            .await?;
        ensure!(fixture.result()? == published);
        ensure!(ticket.terminal_status() == Some(status));
        ensure!(ticket.is_complete());
    }
    Ok(())
}

#[tokio::test]
async fn release_without_body_cannot_replace_an_already_published_terminal() -> anyhow::Result<()> {
    for status in [ProcessStatus::Completed, ProcessStatus::Failed] {
        let fixture = Fixture::new()?;
        let output = body();
        fixture.owner.publish(status, Some(&output)).await?;
        // A retired process may no longer provide its status or body to release.
        fixture.owner.released(ProcessStatus::Cancelled, None);
        fixture.complete(status).await?;
        let published = fixture.result()?;
        ensure!(field(field(&published, "record")?, "outcome")?.as_str() == Some("done"));
        ensure!(
            field(
                field(field(&published, "finalization")?, "report")?,
                "status"
            )? == &crate::service::serde_value(status)?
        );
        ensure!(field(&published, "output")? == &result_value(&output)?);
        ensure!(
            field(field(&published, "record")?, "cleanup_status")?.as_str() == Some("complete")
        );
        let ticket = fixture.state.boot.cleanup_ticket(fixture.owner.process)?;
        ensure!(ticket.terminal_status() == Some(status));
        ensure!(ticket.is_complete());
    }
    Ok(())
}
