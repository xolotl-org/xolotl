use super::*;
use xolotl_types::ProcessStatus;

struct CancelAfterBody(std::sync::Weak<Bootstrap>);

#[async_trait::async_trait]
impl Driver for CancelAfterBody {
    async fn call(
        &self,
        _: MethodId,
        input: Value,
        _: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let boot = self
            .0
            .upgrade()
            .ok_or_else(|| DriverError::Other("host gone".into()))?;
        // Select cancellation in the same poll that returns the successful
        // operation. The lifecycle and retained body intentionally differ.
        boot.cancel_process(context.caller)
            .map_err(|error| DriverError::Other(error.to_string()))?;
        Ok(DriverOutput::new(Outcome::Done(input))
            .with_taint(TaintSet::of(TaintSource::ModelOutput)))
    }
}

#[tokio::test]
async fn child_publication_uses_real_cancelled_lifecycle_without_losing_done_body()
-> anyhow::Result<()> {
    let fixture = Fixture::with_propagation(config(), true, true).await?;
    fixture.state.boot.register_effect(
        "effect://jobs/child",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(CancelAfterBody(Arc::downgrade(&fixture.state.boot))),
    )?;
    let parent = fixture
        .submit(invoke()?, Value::bytes(vec![0, 255]))
        .await?;
    let (id, process) = child(&fixture, &parent).await?;
    let metadata = fixture.finished(&id).await?;
    ensure!(
        fixture.state.boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled)
    );
    ensure!(field(&metadata, "outcome")?.as_str() == Some("done"));
    ensure!(field(&metadata, "cleanup_status")?.as_str() == Some("complete"));
    let result = fixture
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("result")?;
    let retained = field(&result, "output")?;
    ensure!(
        field(field(field(&result, "finalization")?, "report")?, "status")?.as_str()
            == Some("cancelled")
    );
    ensure!(field(retained, "value")? == &Value::bytes(vec![0, 255]));
    ensure!(field(retained, "failure")?.is_null());
    let taint: TaintSet = serde_json::from_value(serde_json::to_value(field(retained, "taint")?)?)?;
    ensure!(taint.contains_all(&TaintSet::of(TaintSource::ModelOutput)));
    let ticket = fixture.state.boot.cleanup_ticket(process)?;
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Cancelled));
    ensure!(ticket.is_complete());
    ensure!(
        fixture
            .state
            .boot
            .kernel()
            .processes()
            .attached_grants(process)
            .is_empty()
    );
    Ok(())
}
