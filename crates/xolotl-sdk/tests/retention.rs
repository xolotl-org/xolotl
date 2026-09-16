#![cfg(feature = "host")]

use anyhow::{Context, anyhow, bail, ensure};
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_kernel::{CompiledRequestGrantTemplate, FnDriver, GatewayAudit, MethodSpec};
use xolotl_sdk::{
    Bootstrap, BootstrapError, DoNode, IdentityRef, Kernel, OperationTemplate, Outcome, Path,
    ProcessAdmissionError, ProcessCapacityError, Purity, StepModule, StepRef, Value, XolotlBuilder,
};
use xolotl_types::{
    ExecutionOutput, MethodBitmap, OutputMode, ProcessStatus, ResourceSelector, TaintSet,
};

fn completed() -> ExecutionOutput {
    ExecutionOutput::new(Outcome::Done(Value::null()), TaintSet::pristine())
}

fn nonzero(value: usize) -> anyhow::Result<NonZeroUsize> {
    NonZeroUsize::new(value).context("test capacity must be positive")
}

fn capped(limit: usize) -> anyhow::Result<Bootstrap> {
    Ok(XolotlBuilder::new()
        .with_process_capacity(nonzero(limit)?)
        .build_bootstrap())
}

fn expect_capacity_rejection(boot: &Bootstrap, expected: usize) -> anyhow::Result<()> {
    match boot.request_under(boot.root, IdentityRef::ROOT, &[]) {
        Err(BootstrapError::ProcessAdmission(ProcessAdmissionError::Capacity { limit })) => {
            ensure!(
                limit == expected,
                "wrong capacity in admission error: {limit}"
            );
        }
        Err(error) => bail!("expected capacity rejection, got {error}"),
        Ok(request) => bail!("full process table admitted {}", request.id()),
    }
    Ok(())
}

#[tokio::test]
async fn hundreds_of_requests_reuse_a_two_entry_table() -> anyhow::Result<()> {
    let boot = capped(2)?;
    let mut previous = boot.root;
    for input in 0..512 {
        let request = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
        let process = request.id();
        ensure!(
            process.get() > previous.get(),
            "retired process id was reused"
        );
        previous = process;
        ensure!(boot.kernel.processes.len() == 2);
        let outcome = request.executor().eval(&DoNode::pure(input)).await;
        ensure!(outcome.outcome == Outcome::Done(Value::integer(input)));
        request.finish(&outcome).await?;
        ensure!(boot.kernel.processes.reap_finalized(1) == 1);
        ensure!(boot.kernel.processes.len() == 1);
        ensure!(boot.kernel.processes.status(process).is_none());
    }
    ensure!(boot.kernel.processes.capacity() == Some(nonzero(2)?));
    ensure!(boot.kernel.processes.reap_finalized(usize::MAX) == 0);
    ensure!(boot.kernel.processes.status(boot.root) == Some(ProcessStatus::Running));
    Ok(())
}

#[tokio::test]
async fn capacity_counts_terminal_records_until_explicit_bounded_reaping() -> anyhow::Result<()> {
    let boot = capped(3)?;
    let first = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
    let second = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
    expect_capacity_rejection(&boot, 3)?;
    ensure!(
        boot.kernel.processes.set_capacity(Some(nonzero(2)?))
            == Err(ProcessCapacityError {
                limit: 2,
                retained: 3,
            })
    );
    ensure!(boot.kernel.processes.capacity() == Some(nonzero(3)?));

    first.finish(&completed()).await?;
    expect_capacity_rejection(&boot, 3)?;
    ensure!(boot.kernel.processes.reap_finalized(0) == 0);
    ensure!(boot.kernel.processes.len() == 3);
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    let replacement = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
    ensure!(boot.kernel.processes.len() == 3);

    second.finish(&completed()).await?;
    replacement.finish(&completed()).await?;
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    ensure!(boot.kernel.processes.len() == 2);
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    ensure!(boot.kernel.processes.len() == 1);
    boot.kernel.processes.set_capacity(Some(nonzero(1)?))?;
    expect_capacity_rejection(&boot, 1)?;
    boot.kernel.processes.set_capacity(None)?;
    boot.request_under(boot.root, IdentityRef::ROOT, &[])?
        .finish(&completed())
        .await?;
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    Ok(())
}

#[tokio::test]
async fn terminal_parent_is_retained_until_its_live_child_is_closed() -> anyhow::Result<()> {
    let boot = capped(3)?;
    let parent = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
    let parent_id = parent.id();
    let child = boot
        .request_under(parent_id, IdentityRef::ROOT, &[])?
        .detach();
    parent.finish(&completed()).await?;
    ensure!(boot.kernel.processes.status(parent_id) == Some(ProcessStatus::Completed));
    ensure!(boot.kernel.processes.status(child) == Some(ProcessStatus::Running));
    ensure!(boot.kernel.processes.reap_finalized(8) == 0);
    ensure!(boot.kernel.processes.len() == 3);
    ensure!(boot.kernel.processes.children_of(parent_id) == [child]);

    boot.finalize_process(parent_id).await?;
    ensure!(boot.kernel.processes.status(child) == Some(ProcessStatus::Cancelled));
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    ensure!(boot.kernel.processes.status(child).is_none());
    ensure!(boot.kernel.processes.status(parent_id) == Some(ProcessStatus::Completed));
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    ensure!(boot.kernel.processes.len() == 1);
    Ok(())
}

#[tokio::test]
async fn reaping_preserves_facts_and_state_lifecycle_evidence() -> anyhow::Result<()> {
    let boot = capped(2)?;
    let request = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
    let process = request.id();
    let application_path = Path::parse("state://retention/application")?;
    boot.kernel
        .state
        .write_set(&application_path, Value::integer(42))
        .await?;
    request.finish(&completed()).await?;
    let execution = boot
        .kernel
        .processes
        .lifecycle_execution(process)
        .context("finished process has no lifecycle scope")?;
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        execution.get()
    ))?;
    let marker_before = boot.kernel.state.read(&marker).await?;
    let facts_before = boot.kernel.facts.store().facts_of(process)?;
    let cursor_before = boot.kernel.facts.store().cursor();
    ensure!(
        marker_before.is_some(),
        "finalization marker was not committed"
    );
    ensure!(!facts_before.is_empty(), "lifecycle fact was not committed");

    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    ensure!(boot.kernel.processes.status(process).is_none());
    ensure!(boot.kernel.facts.store().facts_of(process)? == facts_before);
    ensure!(boot.kernel.facts.store().cursor() == cursor_before);
    ensure!(boot.kernel.state.read(&marker).await? == marker_before);
    ensure!(boot.kernel.state.read(&application_path).await? == Some(Value::integer(42)));
    Ok(())
}

#[tokio::test]
async fn reaped_executor_cannot_dispatch_steps_or_effects_after_new_admission() -> anyhow::Result<()>
{
    let boot = capped(2)?;
    let step_calls = Arc::new(AtomicUsize::new(0));
    let observed_steps = step_calls.clone();
    let steps = StepModule::single("count", move |input, _| {
        observed_steps.fetch_add(1, Ordering::SeqCst);
        DoNode::pure(input)
    })?;
    let effect_calls = Arc::new(AtomicUsize::new(0));
    let observed_effects = effect_calls.clone();
    let resource = boot.register_effect(
        "effect://retention/count",
        &[MethodSpec::new(
            "invoke",
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(FnDriver(move |_, input| {
            observed_effects.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    let grants = [CompiledRequestGrantTemplate {
        selector: ResourceSelector::parse("perform://effect/retention/count")?,
        methods: MethodBitmap::method(0),
    }];
    let process = boot.spawn_request_process_under_with_steps(
        boot.root,
        IdentityRef::ROOT,
        &grants,
        steps.clone(),
    )?;
    let stale = boot.kernel.executor_for(process);
    let handle = boot.open_for(process, &resource, "perform")?;
    stale.bind_handle(resource.clone(), handle);
    boot.finish_request_process(process, &completed()).await?;
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    let replacement =
        boot.spawn_request_process_under_with_steps(boot.root, IdentityRef::ROOT, &grants, steps)?;
    ensure!(replacement != process);

    let step = DoNode::pure(Value::integer(7)).and_then(StepRef::new("count"));
    let effect = DoNode::op(OperationTemplate {
        target: resource,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::integer(11)),
    });
    let step_outcome = stale.eval(&step).await;
    let effect_outcome = stale.eval(&effect).await;
    ensure!(
        matches!(step_outcome.outcome, Outcome::Fail(_)),
        "stale step: {step_outcome:?}"
    );
    ensure!(
        matches!(effect_outcome.outcome, Outcome::Fail(_)),
        "stale effect: {effect_outcome:?}"
    );
    ensure!(step_calls.load(Ordering::SeqCst) == 0);
    ensure!(effect_calls.load(Ordering::SeqCst) == 0);

    let current = boot.kernel.executor_for(replacement);
    ensure!(current.eval(&step).await.outcome == Outcome::Done(Value::integer(7)));
    ensure!(current.eval(&effect).await.outcome == Outcome::Done(Value::integer(11)));
    ensure!(step_calls.load(Ordering::SeqCst) == 1);
    ensure!(effect_calls.load(Ordering::SeqCst) == 1);
    boot.finish_request_process(replacement, &completed())
        .await?;
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    Ok(())
}

#[test]
fn concurrent_bootstrap_of_a_shared_kernel_publishes_one_root_and_grant() -> anyhow::Result<()> {
    const WORKERS: usize = 16;
    let kernel = Kernel::in_memory();
    kernel.processes.set_capacity(Some(nonzero(1)?))?;
    let barrier = Barrier::new(WORKERS);
    let roots = std::thread::scope(|scope| {
        let kernel = &kernel;
        let barrier = &barrier;
        let handles = (0..WORKERS)
            .map(|_| {
                scope.spawn(move || {
                    barrier.wait();
                    let boot = Bootstrap::from_kernel(kernel.clone());
                    let grants = boot.kernel.registry.grants_of(boot.root);
                    (boot.root, grants.len())
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|panic| anyhow!("bootstrap worker panicked: {panic:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()
    })?;
    let root = roots.first().context("no bootstrap workers returned")?.0;
    ensure!(roots.iter().all(|(id, grants)| *id == root && *grants == 1));
    ensure!(kernel.processes.len() == 1);
    for _ in 0..32 {
        let boot = Bootstrap::from_kernel(kernel.clone());
        ensure!(boot.root == root);
        ensure!(boot.kernel.processes.len() == 1);
        ensure!(boot.kernel.registry.grants_of(root).len() == 1);
        expect_capacity_rejection(&boot, 1)?;
    }
    Ok(())
}

#[test]
fn gateway_audits_share_the_root_without_consuming_process_capacity() -> anyhow::Result<()> {
    let boot = capped(1)?;
    for sequence in 0..16 {
        boot.record_gateway_audit(GatewayAudit {
            event: "retention_test",
            username: None,
            source_addr: None,
            outcome: "ok",
            mfa_level: None,
            details: Some(Value::integer(sequence)),
        })?;
        ensure!(boot.kernel.processes.len() == 1);
    }
    let facts = boot.kernel.facts.store().facts_of(boot.root)?;
    ensure!(facts.len() == 16);
    ensure!(facts.iter().all(|fact| fact.id.process == boot.root));
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id)
            .collect::<BTreeSet<_>>()
            .len()
            == 16
    );
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id.execution)
            .collect::<BTreeSet<_>>()
            .len()
            == 16
    );
    Ok(())
}
