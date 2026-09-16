use super::{Config, Work, resident};
use anyhow::{Context, ensure};
use std::{
    future::{Ready, ready},
    num::NonZeroU32,
};
use xolotl_core::{
    Execution, ExecutionLimits, Handle, HandleKey, HandleTable, HostEvent, ImportBinding,
    LinkedProgram, Request, Task,
};
use xolotl_graph::portable::{CompiledProgram, Expression as E, Import, Program, Transform};
use xolotl_kernel::{Bootstrap, LinkedExecution, PendingCall, PreparedProgram, RequestDriver};
use xolotl_types::{
    ExecutionOutput, IdentityRef, Outcome, TaintedFailure, TaintedValue, ValueIdentity,
};

pub struct ProgramCase {
    portable: CompiledProgram<TaintedValue, TaintedFailure>,
    hosted: PreparedProgram,
    boot: Bootstrap,
}

impl ProgramCase {
    pub fn new() -> anyhow::Result<Self> {
        let source = Program::new(E::Input.both(E::Input).then(E::Transform {
            operation: Transform::Index { index: 1 },
        }));
        let compiled = source.compile()?;
        Ok(Self {
            hosted: PreparedProgram::new(&compiled)?,
            portable: compiled.with_provenance(),
            boot: Bootstrap::in_memory(),
        })
    }

    pub async fn run_hosted(&self, config: &Config) -> anyhow::Result<Work> {
        let (input, identity) = input(config)?;
        let output = self
            .boot
            .kernel
            .executor_for(self.boot.root)
            .eval_prepared(&self.hosted, input)
            .await;
        complete(output, identity)
    }

    pub async fn run_portable(&self, config: &Config) -> anyhow::Result<Work> {
        let (input, identity) = input(config)?;
        let output = {
            let mut slots = [Handle::default()];
            let mut handles = HandleTable::new(&mut slots);
            let mut bindings = [ImportBinding {
                handle: HandleKey {
                    slot: 0,
                    generation: 0,
                },
                method: 0,
            }];
            ensure!(self.portable.imports().len() == bindings.len());
            bindings[0].handle = handles.install(1, 0, 1)?;
            let linked = LinkedProgram::new(self.portable.image(), &bindings, &handles, 1)?;
            let driver = Transforms(self.portable.imports());
            let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
            let mut frames = core::array::from_fn::<_, 8, _>(|_| None);
            let mut pending = core::array::from_fn::<_, 3, _>(|_| PendingCall::default());
            let machine = Execution::new(
                &linked.image,
                &mut tasks,
                &mut frames,
                &mut [],
                ExecutionLimits {
                    frames_per_task: 8,
                    bindings_per_task: 0,
                    max_steps: None,
                    cleanup_steps: 64,
                    durable: false,
                },
                input,
                IdentityRef::ROOT.get(),
            )?;
            let output = LinkedExecution::new(
                machine,
                &linked,
                &mut handles,
                &driver,
                &mut pending,
                NonZeroU32::MIN.saturating_add(63),
            )?
            .await;
            handles.release(bindings[0].handle, 1)?;
            output
        };
        complete(output, identity)
    }
}

fn input(config: &Config) -> anyhow::Result<(TaintedValue, ValueIdentity)> {
    let value = resident::shared(config.width.get())?;
    let identity = value.identity().context("shared input has no allocation")?;
    Ok((TaintedValue::pristine(value), identity))
}

fn complete(output: ExecutionOutput, identity: ValueIdentity) -> anyhow::Result<Work> {
    ensure!(matches!(output.outcome, Outcome::Done(_)));
    ensure!(
        output
            .outcome
            .value()
            .and_then(xolotl_types::Value::identity)
            == Some(identity)
    );
    ensure!(output.taint == xolotl_types::TaintSet::pristine());
    drop(output);
    Ok(Work {
        units: 1,
        unit: "prepared input/fork/input/projection program with fresh input and execution storage",
    })
}

struct Transforms<'a>(&'a [Import]);
impl RequestDriver for Transforms<'_> {
    type Call<'a>
        = Ready<HostEvent<TaintedValue, TaintedFailure>>
    where
        Self: 'a;
    fn call(&self, resource: u32, request: Request<TaintedValue>) -> Self::Call<'_> {
        let result = match self.0.get(resource as usize) {
            Some(Import::Transform(transform)) => transform.apply(request.input.value),
            _ => Err(xolotl_types::Failure::policy(
                "benchmark",
                "unexpected portable import",
            )),
        };
        ready(HostEvent::Complete(match result {
            Ok(value) => Ok(TaintedValue::new(value, request.input.taint)),
            Err(error) => Err(TaintedFailure::new(error, request.input.taint)),
        }))
    }
}
