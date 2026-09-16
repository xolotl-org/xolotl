use super::*;
use anyhow::{Context, ensure};
use xolotl_types::Outcome;

#[tokio::test]
async fn lifecycle_recovery_requires_both_authority_counts() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = boot
        .request_under(boot.root, IdentityRef::ROOT, &[])?
        .detach();
    let execution = boot.kernel.execution_ids().allocate()?;
    boot.kernel
        .processes
        .initialize_lifecycle(process, execution);
    let saved = boot
        .kernel
        .processes
        .snapshot(process)
        .context("missing process snapshot")?;
    boot.finish_request_process(
        process,
        &xolotl_types::ExecutionOutput::new(
            Outcome::Done(Value::null()),
            xolotl_types::TaintSet::pristine(),
        ),
    )
    .await?;
    let retained = retained_finalization(&boot.kernel.facts, &saved)?
        .context("missing committed lifecycle record")?;
    ensure!(retained.released == 0 && retained.revoked == 0);

    for field in ["released_handles", "revoked_handles"] {
        for invalid in [
            None,
            Some(Value::integer(-1)),
            Some(Value::string("1".into())),
        ] {
            let mut fact = retained.fact.clone();
            let mut value = fact
                .outcome
                .as_ref()
                .and_then(Value::as_map)
                .context("missing lifecycle values")?
                .clone();
            if let Some(value_to_insert) = invalid {
                drop(value.insert(field.into(), value_to_insert)?);
            } else {
                drop(value.remove(field));
            }
            fact.outcome = Some(Value::from(value));
            let facts = crate::FactSink::in_memory().0;
            facts.complete(fact)?;
            ensure!(retained_finalization(&facts, &saved).is_err());
        }
    }
    let mut previous_schema = retained.fact;
    previous_schema.schema_version = Fact::SCHEMA_VERSION - 1;
    let facts = crate::FactSink::in_memory().0;
    facts.store().complete(previous_schema)?;
    ensure!(retained_finalization(&facts, &saved).is_err());
    Ok(())
}
