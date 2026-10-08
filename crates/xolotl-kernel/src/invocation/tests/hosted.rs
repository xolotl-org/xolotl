//! Compare shared decisions under the same externally ordered completions.

use super::*;
use crate::{LinkedExecution, MethodSpec, PendingCall, PreparedProgram, RequestDriver};
use anyhow::{Context as _, ensure};
use core::num::NonZeroU32;
use parking_lot::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_core::{
    Execution, ExecutionLimits, Handle, HandleTable, HostEvent, ImportBinding, LinkedProgram,
    Request, Task,
};
use xolotl_graph::{
    OperationTemplate,
    portable::{Expression as E, Program},
};
use xolotl_types::{ExecutionOutput, Path, Purity, TaintedFailure, TaintedValue};

#[tokio::test]
async fn hosted_and_portable_completions_agree_on_sink_projection_and_billing() -> anyhow::Result<()>
{
    for outcome in [
        Outcome::Done(Value::string("retained response".into())),
        Outcome::Short(Value::string("retained response".into())),
        Outcome::Fail(Failure::InvalidInput {
            reason: "source failure".into(),
        }),
    ] {
        for mode in [OutputMode::Unary, OutputMode::SinkOnly] {
            let mut script = Script::new(false)?;
            script.outputs[0].outcome = outcome.clone();
            script.outputs[0].origin = CompletionOrigin::CachedOutcome;
            script.release(1);
            let script = Arc::new(script);
            let mut method = contract();
            method.supports |= OutputModeSet::SINK_ONLY;
            let mut op = operation();
            op.output = mode;
            op.taint = TaintSet::author();
            let mut plan = crate::driver::DriverPlan::new(xolotl_types::DriverId::new(1), None, 0);
            plan.insert(
                op.method,
                method,
                Arc::new(Endpoint {
                    script: script.clone(),
                    slot: 0,
                }),
            );
            let handles = crate::HandleTable::new();
            op.handle = handles.insert(crate::Handle {
                open_verb: "perform".into(),
                id: op.handle,
                process: op.process,
                acting: op.acting,
                resource: grant(method).resource,
                rights: grant(method).rights,
                driver_plan: plan,
                fast_path: crate::handle::FastPath::Unconditional,
                bound_path: None,
            })?;
            let processes = crate::process::ProcessTable::new();
            let mut entry = crate::process::ProcessEntry::new(op.process, None, op.acting);
            ensure!(entry.scope.start());
            processes.insert(entry);
            let (facts, _store) = crate::FactSink::in_memory();
            let hosted = crate::DataPlane::new(
                handles,
                facts,
                xolotl_state::InMemoryBackend::new().into_backend(),
            )
            .with_host_runtime(processes.host_runtime().clone())?
            .with_processes(processes.clone())?;
            let expected = match (mode, outcome.clone()) {
                (OutputMode::SinkOnly, Outcome::Done(_)) => Outcome::Done(Value::null()),
                (OutputMode::SinkOnly, Outcome::Short(_)) => Outcome::Short(Value::null()),
                (_, outcome) => outcome,
            };
            let events = Events::default();
            let accounts = Accounts::new(&events);
            let recorder = Recorder::new(&events);
            let portable = invoke(
                op.clone(),
                grant(method),
                options(true),
                CallContext::Body,
                script.as_ref(),
                &recorder,
                &accounts,
            )?
            .await;
            let result = hosted.execute(&op, options(true)).await;
            ensure!(portable.output.outcome == expected && portable == result);
            ensure!(portable.completion_error.is_none());
            ensure!(accounts.completions.borrow()[0].2 == result.output);
            ensure!(
                processes.budget_mut(op.process, |budget| budget.clone())
                    == Some(accounts.budget())
            );
        }
    }
    Ok(())
}

struct Script {
    outputs: [DriverOutput; 2],
    released: AtomicUsize,
    waiters: Mutex<[Option<Waker>; 2]>,
    inputs: Mutex<Vec<(usize, TaintedValue)>>,
    dropped: Mutex<Vec<usize>>,
}

impl Script {
    fn new(protected: bool) -> anyhow::Result<Self> {
        let sources = if protected {
            TaintSet::of(TaintSource::Protected {
                path: Path::parse("state://parity/private")?,
            })
        } else {
            TaintSet::of(TaintSource::ModelOutput)
        };
        Ok(Self {
            outputs: [
                DriverOutput::new(Outcome::Fail(Failure::InvalidInput {
                    reason: "scripted source failure".into(),
                }))
                .with_taint(sources)
                .with_usage(
                    [
                        (UsageDimension::INPUT_TOKENS, 3),
                        (UsageDimension::OUTPUT_TOKENS, 5),
                    ]
                    .into(),
                ),
                DriverOutput::new(Outcome::Done(Value::integer(42))).with_usage(
                    [
                        (UsageDimension::INPUT_TOKENS, 2),
                        (UsageDimension::OUTPUT_TOKENS, 1),
                    ]
                    .into(),
                ),
            ],
            released: AtomicUsize::new(0),
            waiters: Mutex::default(),
            inputs: Mutex::default(),
            dropped: Mutex::default(),
        })
    }

    fn start(&self, slot: usize, input: TaintedValue) -> ScriptCall<'_> {
        self.inputs.lock().push((slot, input));
        ScriptCall { script: self, slot }
    }

    fn release(&self, completed: usize) {
        self.released.store(completed, Ordering::Release);
        let waiter = self.waiters.lock()[completed - 1].take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

struct ScriptCall<'a> {
    script: &'a Script,
    slot: usize,
}

impl Future for ScriptCall<'_> {
    type Output = DriverOutput;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.script.released.load(Ordering::Acquire) <= self.slot {
            self.script.waiters.lock()[self.slot] = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(self.script.outputs[self.slot].clone())
    }
}

impl Drop for ScriptCall<'_> {
    fn drop(&mut self) {
        self.script.waiters.lock()[self.slot] = None;
        self.script.dropped.lock().push(self.slot);
    }
}

impl InvocationDriver for Script {
    type Call<'a> = ScriptCall<'a>;

    fn call(&self, resource: ResourceId, operation: Operation) -> Self::Call<'_> {
        self.start(
            (resource.get() - 9) as usize,
            TaintedValue::new(operation.input, operation.taint),
        )
    }
}

struct Endpoint {
    script: Arc<Script>,
    slot: usize,
}

#[async_trait::async_trait]
impl crate::Driver for Endpoint {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &crate::DriverContext,
    ) -> Result<DriverOutput, crate::DriverError> {
        Ok(self
            .script
            .start(self.slot, TaintedValue::new(input, ctx.taint.clone()))
            .await)
    }
}

struct Portable<'a> {
    script: &'a Script,
    recorder: &'a Recorder,
    accounts: &'a Accounts,
}

struct PortableCall<'a>(Result<InvocationCall<'a, Script, Recorder, Accounts>, TaintedFailure>);

impl Future for PortableCall<'_> {
    type Output = crate::RequestCompletion;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(HostEvent::Complete(match &mut self.get_mut().0 {
            Ok(call) => {
                let operation = call.operation();
                let result = core::task::ready!(Pin::new(call).poll(cx));
                if let Some(error) = result.completion_error
                    && error.requires_interruption()
                {
                    return Poll::Ready(Err(TaintedFailure::new(
                        error.outcome_unknown(operation),
                        result.output.taint,
                    )));
                }
                result.output.into_result()
            }
            Err(failure) => Err(failure.clone()),
        })))
    }
}

impl RequestDriver for Portable<'_> {
    type Call<'a>
        = PortableCall<'a>
    where
        Self: 'a;

    fn collect_evidence<'a>(
        &'a self,
        call: &Self::Call<'a>,
        completion: Option<&crate::RequestCompletion>,
        unresolved: &mut xolotl_types::UnresolvedOperations,
    ) {
        if let Some(Err(failure) | Ok(HostEvent::Complete(Err(failure)))) = completion
            && let Failure::OutcomeUnknown { operation_ids, .. } = &failure.failure
        {
            for operation in operation_ids {
                unresolved.record(operation);
            }
        }
        if let Ok(invocation) = &call.0
            && (completion.is_none() || matches!(completion, Some(Err(_))))
            && invocation.effect_may_have_started()
        {
            unresolved.record(&invocation.operation().to_string());
        }
    }

    fn call(&self, resource: u32, request: Request<TaintedValue>) -> Self::Call<'_> {
        let mut operation = operation();
        operation.id.invocation = InvocationId::new(request.ticket);
        operation.id.position = CausalPosition::new(request.position as u32);
        operation.input = request.input.value;
        operation.taint = request.input.taint;
        let mut contract = contract();
        contract.requires_unprotected_input = resource == 10;
        let mut admitted = grant(contract);
        admitted.resource = ResourceId::new(u64::from(resource));
        // The embedding records pre-dispatch denials through the shared helper.
        // The invocation future owns successful admission and both Fact barriers.
        let call = invoke(
            operation.clone(),
            admitted,
            options(true),
            CallContext::Body,
            self.script,
            self.recorder,
            self.accounts,
        )
        .map_err(|failure| {
            self.recorder.facts.borrow_mut().push(denied_fact(
                &operation,
                Some(ResourceId::new(u64::from(resource))),
                contract.replay,
                options(true),
                DecisionTag::Denied,
            ));
            TaintedFailure::new(failure, operation.taint)
        });
        PortableCall(call)
    }
}

async fn poll_until_boundary<F: Future<Output = ExecutionOutput>>(
    mut run: Pin<&mut F>,
    script: &Script,
    starts: usize,
) -> anyhow::Result<Poll<ExecutionOutput>> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        std::future::poll_fn(|cx| {
            let output = run.as_mut().poll(cx);
            if output.is_ready() || script.inputs.lock().len() >= starts {
                Poll::Ready(output)
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .context("execution did not reach its scripted boundary")
}

type FactDecision = (DecisionTag, ReplayClass, Value, TaintSet, Option<Value>);

fn decisions(facts: &[Fact]) -> Vec<FactDecision> {
    facts
        .iter()
        .enumerate()
        .filter(|(index, fact)| !facts[index + 1..].iter().any(|later| later.id == fact.id))
        .map(|(_, fact)| {
            (
                fact.decision,
                fact.replay,
                fact.input.clone(),
                fact.taint.clone(),
                fact.outcome.clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn ordered_failures_share_recovery_authority_usage_and_fact_decisions() -> anyhow::Result<()>
{
    for protected in [false, true] {
        let boot = crate::fact::testing::observing_bootstrap();
        let hosted_script = Arc::new(Script::new(protected)?);
        let mut expressions = Vec::new();
        for (slot, path) in ["effect://parity/source", "effect://parity/recover"]
            .into_iter()
            .enumerate()
        {
            let mut spec = MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            );
            if slot == 1 {
                spec = spec.unprotected_input();
            }
            let target = boot.register_effect_with_cost(
                path,
                &[spec],
                Arc::new(Endpoint {
                    script: hosted_script.clone(),
                    slot,
                }),
                contract().cost,
            )?;
            expressions.push(E::Invoke {
                operation: OperationTemplate {
                    target,
                    method: "invoke".into(),
                    method_id: None,
                    output: OutputMode::Unary,
                    literal_input: None,
                },
            });
        }
        let recover = expressions.pop().context("recovery expression")?;
        let body = expressions.pop().context("body expression")?;
        let compiled = Program::new(E::Catch {
            body: Box::new(body),
            recover: Box::new(recover),
        })
        .compile()?;
        let prepared = PreparedProgram::new(&compiled)?;
        let compiled = compiled.with_provenance();
        ensure!(compiled.imports().len() == 2);

        let events = Events::default();
        let accounts = Accounts::new(&events);
        let recorder = Recorder::new(&events);
        let portable_script = Script::new(protected)?;
        let adapter = Portable {
            script: &portable_script,
            recorder: &recorder,
            accounts: &accounts,
        };
        let mut slots = core::array::from_fn::<_, 2, _>(|_| Handle::default());
        let mut handles = HandleTable::new(&mut slots);
        let bindings = [
            ImportBinding {
                handle: handles.install(1, 9, 1)?,
                method: 0,
            },
            ImportBinding {
                handle: handles.install(1, 10, 1)?,
                method: 0,
            },
        ];
        let linked = LinkedProgram::new(compiled.image(), &bindings, &handles, 1)?;
        let mut tasks = [Task::default()];
        let mut frames = core::array::from_fn::<_, 16, _>(|_| None);
        let mut pending = [PendingCall::default()];
        let input = TaintedValue::new(Value::integer(7), TaintSet::author());
        let machine = Execution::new(
            &linked.image,
            &mut tasks,
            &mut frames,
            &mut [],
            ExecutionLimits {
                frames_per_task: 16,
                bindings_per_task: 0,
                ..ExecutionLimits::default()
            },
            input.clone(),
            IdentityRef::ROOT.get(),
        )?;
        let mut unresolved = xolotl_types::UnresolvedOperations::default();
        let mut portable = LinkedExecution::new(
            machine,
            &linked,
            &mut handles,
            &adapter,
            &mut pending,
            &mut unresolved,
            NonZeroU32::MIN.saturating_add(31),
        )?;
        let executor = boot
            .kernel()
            .executor_for(boot.root())
            .with_fact_recording(true);
        let mut hosted = Box::pin(executor.eval_prepared(&prepared, input));
        ensure!(
            poll_until_boundary(Pin::new(&mut portable), &portable_script, 1)
                .await?
                .is_pending()
        );
        ensure!(
            poll_until_boundary(hosted.as_mut(), &hosted_script, 1)
                .await?
                .is_pending()
        );
        ensure!(accounts.budget().inflight_ops == 1);
        let mut result = None;
        for released in 1..=2 {
            portable_script.release(released);
            hosted_script.release(released);
            let portable =
                poll_until_boundary(Pin::new(&mut portable), &portable_script, released + 1)
                    .await?;
            let hosted = poll_until_boundary(hosted.as_mut(), &hosted_script, released + 1).await?;
            match (portable, hosted) {
                (Poll::Ready(portable), Poll::Ready(hosted)) => {
                    ensure!(
                        portable == hosted,
                        "portable={portable:?}, hosted={hosted:?}"
                    );
                    result = Some(portable);
                    break;
                }
                (Poll::Pending, Poll::Pending) => ensure!(released == 1 && !protected),
                _ => anyhow::bail!("hosts chose different scripted boundaries"),
            }
        }
        let result = result.context("missing final result")?;
        ensure!(
            result.taint
                == portable_script.outputs[0]
                    .taint
                    .clone()
                    .merged(&TaintSet::author())
        );
        if protected {
            ensure!(
                matches!(result.outcome, Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "taint")
            );
        } else {
            ensure!(result.outcome == Outcome::Done(Value::integer(42)));
        }
        ensure!(*portable_script.inputs.lock() == *hosted_script.inputs.lock());
        ensure!(*portable_script.dropped.lock() == *hosted_script.dropped.lock());
        ensure!(portable_script.inputs.lock().len() == if protected { 1 } else { 2 });
        let hosted_budget = boot
            .kernel()
            .processes()
            .budget_mut(boot.root(), |budget| budget.clone())
            .context("hosted account")?;
        ensure!(accounts.budget() == hosted_budget);
        ensure!(hosted_budget.inflight_ops == 0);
        ensure!(hosted_budget.spent_micro_usd == if protected { 24 } else { 39 });
        ensure!(hosted_budget.inference_tokens == if protected { 5 } else { 6 });
        let hosted_facts = boot.kernel().facts().facts_of(boot.root())?;
        let portable_facts = recorder.facts.borrow();
        let portable_decisions = decisions(&portable_facts);
        let hosted_decisions = decisions(&hosted_facts);
        ensure!(
            portable_decisions == hosted_decisions,
            "portable={portable_decisions:?}, hosted={hosted_decisions:?}"
        );
        ensure!(portable_decisions.len() == 2);
    }
    Ok(())
}
