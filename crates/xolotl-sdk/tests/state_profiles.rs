#![cfg(feature = "host")]

use anyhow::{Context, ensure};
use std::num::NonZeroUsize;
use xolotl_sdk::{
    Bootstrap, DoNode, IdentityRef, KernelBuilder, Outcome, Path, StateError, StateHistoryQuery,
    Value,
};
use xolotl_state::{InMemoryBackend, InMemoryOptions, MemoryHistory};

#[tokio::test]
async fn current_only_state_composes_with_bounded_request_lifecycle() -> anyhow::Result<()> {
    for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
        let state = InMemoryBackend::with_options(InMemoryOptions {
            read_shards,
            history: MemoryHistory::Disabled,
            ..InMemoryOptions::default()
        })?
        .into_backend();
        let boot = Bootstrap::from_kernel(
            KernelBuilder::new(state.clone())
                .with_process_capacity(NonZeroUsize::MIN.saturating_add(1))
                .build(),
        );
        let application = Path::parse("state://application/value")?;
        state.write_set(&application, Value::integer(42)).await?;
        for input in 0..32 {
            let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
            let process = request.id();
            let outcome = request.executor().eval(&DoNode::pure(input)).await;
            ensure!(outcome.outcome == Outcome::Done(Value::integer(input)));
            request.finish(&outcome).await?;
            ensure!(boot.cleanup_ticket(process)?.is_complete());
            ensure!(
                boot.kernel()
                    .processes()
                    .finalization_report(process)
                    .context("missing live completion report")?
                    .status
                    == xolotl_sdk::ProcessStatus::Completed
            );
            ensure!(!state.has_history());
            ensure!(matches!(
                state
                    .history(&StateHistoryQuery::new(application.clone(), 0, i64::MAX))
                    .await,
                Err(xolotl_sdk::StateFailure {
                    error: StateError::MissingCapability("history"),
                    ..
                })
            ));
            ensure!(boot.kernel().processes().reap_finalized(1) == 1);
            ensure!(boot.kernel().processes().len() == 1);
            ensure!(state.read(&application).await? == Some(Value::integer(42)));
        }
    }
    Ok(())
}
