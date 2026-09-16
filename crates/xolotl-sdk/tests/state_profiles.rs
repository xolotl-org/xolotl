#![cfg(feature = "host")]

use anyhow::{Context, ensure};
use std::num::NonZeroUsize;
use xolotl_sdk::{
    DoNode, IdentityRef, InMemoryBackend, InMemoryOptions, MemoryHistory, Outcome, Path,
    StateError, StateHistoryQuery, Value, XolotlBuilder,
};

#[tokio::test]
async fn current_only_state_composes_with_bounded_request_lifecycle() -> anyhow::Result<()> {
    for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
        let state = InMemoryBackend::with_options(InMemoryOptions {
            read_shards,
            history: MemoryHistory::Disabled,
            ..InMemoryOptions::default()
        })?
        .into_backend();
        let boot = XolotlBuilder::new()
            .with_state_backend(state.clone())
            .with_process_capacity(NonZeroUsize::MIN.saturating_add(1))
            .build_bootstrap();
        for input in 0..32 {
            let request = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
            let process = request.id();
            let outcome = request.executor().eval(&DoNode::pure(input)).await;
            ensure!(outcome.outcome == Outcome::Done(Value::integer(input)));
            request.finish(&outcome).await?;
            let execution = boot
                .kernel
                .processes
                .lifecycle_execution(process)
                .context("finished request has no lifecycle execution")?;
            let marker = Path::parse(&format!(
                "state://kernel/process/{}/{}/finalized",
                process.get(),
                execution.get()
            ))?;
            let committed = state.read(&marker).await?;
            ensure!(committed.is_some());
            ensure!(!state.has_history());
            ensure!(matches!(
                state
                    .history(&StateHistoryQuery::new(marker.clone(), 0, i64::MAX))
                    .await,
                Err(xolotl_sdk::StateFailure {
                    error: StateError::MissingCapability("history"),
                    ..
                })
            ));
            ensure!(boot.kernel.processes.reap_finalized(1) == 1);
            ensure!(boot.kernel.processes.len() == 1);
            ensure!(state.read(&marker).await? == committed);
        }
    }
    Ok(())
}
