use super::*;
use crate::{Bootstrap, Kernel, LoaderRevision, StepModule};
use anyhow::{Context, ensure};
use futures_util::FutureExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use xolotl_graph::{
    StepRef, WaitSpec,
    portable::{Expression as E, Program, Transform},
};
use xolotl_types::{IdentityRef, Outcome, Path, ProcessStatus, TaintSet, TaintSource, Value};

mod store;
use store::Store;

const REVISION: LoaderRevision = LoaderRevision::from_bytes([1; 32]);

fn module(name: &str) -> E {
    E::Module {
        module: StepRef::new(name),
    }
}

fn prepare(body: E, durable: bool) -> anyhow::Result<PreparedProgram> {
    let mut source = Program::new(body);
    source.durable = durable;
    Ok(PreparedProgram::from_compiled(source.compile()?)?)
}

fn request(boot: &Bootstrap) -> anyhow::Result<ProcessId> {
    Ok(
        boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?,
    )
}

fn protected() -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/module-recovery")?,
    }))
}

fn loader(
    name: &str,
    program: PreparedProgram,
    count: Arc<AtomicUsize>,
) -> anyhow::Result<StepModule> {
    Ok(StepModule::program(name, REVISION, move |_, _| {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(program.clone())
    })?)
}

#[tokio::test]
async fn loaded_modules_resume_from_the_saved_arena_and_reuse_retired_storage() -> anyhow::Result<()>
{
    let store = Arc::new(Store::default());
    let boot = Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(store.clone()));
    let process = request(&boot)?;
    let signal = Path::parse("state://signal/loaded-module")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let waiting = prepare(
        E::Let {
            name: "input".into(),
            value: Box::new(E::Input),
            body: Box::new(
                E::Wait {
                    wait: WaitSpec::Signal(signal.clone()),
                }
                .then(E::Use {
                    name: "input".into(),
                }),
            ),
        },
        false,
    )?;
    let cleanup = prepare(E::literal(9), true)?;
    let outer = prepare(module("wait").finally(module("cleanup")), false)?;
    let root = prepare(module("outer"), true)?;
    let limit = root.inner.nodes.len() + outer.inner.nodes.len() + waiting.inner.nodes.len();
    let steps = StepModule::compose([
        loader("outer", outer, calls.clone())?,
        loader("wait", waiting, calls.clone())?,
        loader("cleanup", cleanup, cleanup_calls.clone())?,
    ])?;
    let executor = boot
        .kernel
        .executor_for(process)
        .with_steps(steps)
        .with_execution_config(crate::ExecutionConfig {
            max_instructions: limit,
            bindings_per_task: 1,
            ..Default::default()
        });
    let sources = protected()?;
    let mut run = Box::pin(executor.eval_prepared(
        &root,
        TaintedValue::new(Value::integer(42), sources.clone()),
    ));
    ensure!(run.as_mut().now_or_never().is_none());
    drop(run);
    let saved = store.saved(process)?;
    ensure!(saved.machine.checkpoint().continuations().count() == 2);
    ensure!(saved.loader_dependencies().count() == 3);
    ensure!(calls.load(Ordering::SeqCst) == 2);
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    // Pass the original root preparation. The journal owns the linked image.
    let output = executor
        .eval_prepared(&root, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(42)),
        "{output:?}"
    );
    ensure!(output.taint.contains_all(&sources));
    ensure!(calls.load(Ordering::SeqCst) == 2 && cleanup_calls.load(Ordering::SeqCst) == 1);
    let completed = store.saved(process)?;
    ensure!(completed.program.inner.nodes.len() == root.inner.nodes.len());
    ensure!(
        completed.finished
            && completed
                .machine
                .checkpoint()
                .continuations()
                .next()
                .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn uncommitted_load_replays_its_frozen_revision_input_and_argument() -> anyhow::Result<()> {
    let store = Arc::new(Store::default());
    store.reject_linked.store(true, Ordering::SeqCst);
    let boot = Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(store.clone()));
    let process = request(&boot)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let loaded = prepare(
        E::Transform {
            operation: Transform::Add { value: 1 },
        },
        false,
    )?;
    let steps = StepModule::program("select", REVISION, move |input, arg| {
        if input.as_int() != Some(41) || arg.and_then(Value::as_str) != Some("variant-a") {
            return Err(machine_error("restored loader context changed"));
        }
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(loaded.clone())
    })?;
    let root = prepare(
        E::Module {
            module: StepRef::new("select").with_arg(Value::from("variant-a")),
        },
        true,
    )?;
    let executor = boot.kernel.executor_for(process).with_steps(steps);
    let sources = protected()?;
    let failed = executor
        .eval_prepared(
            &root,
            TaintedValue::new(Value::integer(41), sources.clone()),
        )
        .await;
    ensure!(matches!(failed.outcome, Outcome::Fail(_)) && failed.taint.contains_all(&sources));
    let saved = store.saved(process)?;
    ensure!(
        saved.pending.len() == 1 && saved.machine.checkpoint().continuations().next().is_none()
    );
    ensure!(saved.loader_dependencies().collect::<Vec<_>>() == [("select", REVISION)]);
    ensure!(calls.load(Ordering::SeqCst) == 1);
    let bytes = store.bytes(process)?;
    let changed_calls = Arc::new(AtomicUsize::new(0));
    let changed_observed = changed_calls.clone();
    let changed = StepModule::program(
        "select",
        LoaderRevision::from_bytes([2; 32]),
        move |_, _| {
            changed_observed.fetch_add(1, Ordering::SeqCst);
            Err(Failure::Cancelled)
        },
    )?;
    let native_observed = changed_calls.clone();
    let native = StepModule::single("select", move |_, _| {
        native_observed.fetch_add(1, Ordering::SeqCst);
        xolotl_graph::DoNode::pure(0)
    })?;
    for steps in [StepModule::default(), changed, native] {
        let output = boot
            .kernel
            .executor_for(process)
            .with_steps(steps)
            .eval_prepared(&root, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)));
        ensure!(
            store.bytes(process)? == bytes,
            "rejected recovery overwrote its journal"
        );
    }
    ensure!(changed_calls.load(Ordering::SeqCst) == 0);
    let output = executor
        .eval_prepared(&root, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(42)),
        "{output:?}"
    );
    ensure!(output.taint.contains_all(&sources));
    ensure!(calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn cancellation_resumes_loaded_cleanup_without_reloading_the_body() -> anyhow::Result<()> {
    let store = Arc::new(Store::default());
    let boot = Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(store.clone()));
    let process = request(&boot)?;
    let signal = Path::parse("state://signal/module-cleanup-resume")?;
    let work = prepare(
        E::Wait {
            wait: WaitSpec::Signal(Path::parse("state://signal/module-work-never")?),
        },
        false,
    )?;
    let cleanup = prepare(
        E::Wait {
            wait: WaitSpec::Signal(signal.clone()),
        },
        false,
    )?;
    let outer = prepare(module("work").finally(module("cleanup")), false)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let cleanups = Arc::new(AtomicUsize::new(0));
    let steps = StepModule::compose([
        loader("outer", outer, calls.clone())?,
        loader("work", work, calls.clone())?,
        loader("cleanup", cleanup, cleanups.clone())?,
    ])?;
    let root = prepare(module("outer"), true)?;
    let sources = protected()?;
    let executor = boot.kernel.executor_for(process).with_steps(steps);
    let mut run =
        Box::pin(executor.eval_prepared(&root, TaintedValue::new(Value::null(), sources.clone())));
    ensure!(run.as_mut().now_or_never().is_none());
    boot.cancel_process(process)?;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while cleanups.load(Ordering::SeqCst) == 0 {
            tokio::select! {
                biased;
                output = &mut run => anyhow::bail!("cleanup completed before its signal: {output:?}"),
                () = tokio::task::yield_now() => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    }).await??;
    drop(run);
    let saved = store.saved(process)?;
    ensure!(saved.machine.meta.aborting && cleanups.load(Ordering::SeqCst) == 1);
    ensure!(saved.pending.len() == 1);
    ensure!(
        saved
            .machine
            .checkpoint()
            .pending_requests(&saved.program.inner.image())
            .all(|request| request.cleanup)
    );
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let output = executor
        .eval_prepared(&root, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Fail(Failure::Cancelled),
        "{output:?}"
    );
    ensure!(output.taint.contains_all(&sources));
    ensure!(calls.load(Ordering::SeqCst) == 2 && cleanups.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn automatic_recovery_retains_the_explicit_loader_namespace() -> anyhow::Result<()> {
    let store = Arc::new(Store::default());
    let boot = Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(store.clone()));
    let process = request(&boot)?;
    let signal = Path::parse("state://signal/module-automatic")?;
    let wait = prepare(
        E::Wait {
            wait: WaitSpec::Signal(signal.clone()),
        }
        .then(module("after")),
        false,
    )?;
    let after = prepare(E::literal(42), false)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let steps = StepModule::compose([
        loader("wait", wait, calls.clone())?,
        loader("after", after, calls.clone())?,
    ])?;
    let root = prepare(module("wait"), true)?;
    let executor = boot.kernel.executor_for(process).with_steps(steps.clone());
    let mut run = Box::pin(executor.eval_prepared(&root, TaintedValue::pristine(Value::null())));
    ensure!(run.as_mut().now_or_never().is_none());
    drop(run);
    drop(executor);
    let state = boot.kernel.state.clone();
    let facts = boot.kernel.facts.clone();
    drop(boot);
    let recovered = Arc::new(Bootstrap::from_kernel(
        Kernel::with_backends(state, facts).with_checkpoint_store(store.clone()),
    ));
    let held = recovered.checkpoint_recovery()?.advance().await?;
    ensure!(held.quarantined == 1 && held.resumed == 0 && calls.load(Ordering::SeqCst) == 1);
    recovered
        .kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let report = recovered
        .checkpoint_recovery()?
        .with_steps(steps)
        .advance()
        .await?;
    ensure!(report.resumed == 1 && report.quarantined == 0);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while recovered.kernel.processes.status(process) != Some(ProcessStatus::Completed) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    ensure!(calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn malformed_module_ownership_never_dispatches_or_overwrites_the_journal()
-> anyhow::Result<()> {
    let store = Arc::new(Store::default());
    let boot = Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(store.clone()));
    let process = request(&boot)?;
    let signal = Path::parse("state://signal/module-corrupt")?;
    let wait = prepare(
        E::Wait {
            wait: WaitSpec::Signal(signal.clone()),
        },
        false,
    )?;
    let calls = Arc::new(AtomicUsize::new(0));
    let steps = loader("wait", wait, calls.clone())?;
    let root = prepare(module("wait"), true)?;
    let executor = boot.kernel.executor_for(process).with_steps(steps);
    let mut run =
        Box::pin(executor.eval_prepared(&root, TaintedValue::pristine(Value::integer(42))));
    ensure!(run.as_mut().now_or_never().is_none());
    drop(run);
    let valid = store.bytes(process)?;
    let encoded: serde_json::Value = serde_json::from_slice(&valid)?;
    for corruption in [
        "missing arena",
        "overlap",
        "missing revision",
        "invalid entry",
        "cross-module edge",
    ] {
        let mut invalid = encoded.clone();
        match corruption {
            "missing arena" => invalid["program"]["arena"] = serde_json::Value::Null,
            "overlap" => invalid["program"]["arena"]["fragments"][0]["nodes"]["start"] = 0.into(),
            "missing revision" => {
                invalid["program"]["imports"][0]["Step"]["revision"] = serde_json::Value::Null
            }
            "invalid entry" => {
                let frame = invalid["machine"]["frames"]
                    .as_array_mut()
                    .context("frames")?
                    .iter_mut()
                    .find(|frame| frame["kind"].get("Continuation").is_some())
                    .context("continuation")?;
                frame["kind"]["Continuation"]["entry"] = 0.into();
            }
            _ => {
                let index = invalid["program"]["arena"]["fragments"][0]["nodes"]["start"]
                    .as_u64()
                    .context("fragment start")? as usize;
                invalid["program"]["nodes"][index]["next"] = 0.into();
            }
        }
        let bytes = serde_json::to_vec(&invalid)?;
        store.replace(process, bytes.clone());
        let output = executor
            .eval_prepared(&root, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(
            matches!(output.outcome, Outcome::Fail(_)),
            "{corruption}: {output:?}"
        );
        ensure!(
            calls.load(Ordering::SeqCst) == 1 && store.bytes(process)? == bytes,
            "{corruption}"
        );
    }
    store.replace(process, valid);
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let output = executor
        .eval_prepared(&root, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(matches!(output.outcome, Outcome::Done(_)), "{output:?}");
    ensure!(calls.load(Ordering::SeqCst) == 1);
    Ok(())
}
