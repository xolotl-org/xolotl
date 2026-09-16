#![no_std]
#![forbid(unsafe_code)]

//! Executable embedding shared by the desktop example and Cortex compilation.
//! A firmware host supplies an allocator and polls the same execution future.

extern crate alloc;

use alloc::boxed::Box;
use core::{
    cell::RefCell,
    future::{Future, Ready, ready},
    num::NonZeroU32,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use xolotl_graph::portable::Import;
use xolotl_sdk::{
    Expression as E, Program, Transform,
    core::{
        Execution, ExecutionLimits, Handle, HandleKey, HandleTable, HostEvent, ImportBinding,
        LinkedProgram, Request, Task,
    },
    runtime::{
        LinkedExecution, PendingCall, RequestDriver, Scope, ScopeFinalize,
        invocation::{
            Account, AccountPermit, AccountRequest, CallContext, GrantedMethod, InvocationCall,
            InvocationDriver, InvocationOptions, NoFacts, Settlement, invoke,
        },
    },
    types::{
        BudgetState, CausalPosition, DriverOutput, ExecutionId, ExecutionOutput, Failure, HandleId,
        IdentityRef, InvocationId, MethodBitmap, MethodContract, MethodId, Operation, OperationId,
        Outcome, OutputMode, OutputModeSet, ProcessId, ProcessStatus, ReplayClass, ResourceId,
        RightFlags, Rights, TaintedFailure, TaintedValue,
    },
};

const OWNER: ProcessId = ProcessId::new(1);
const MAX_IMPORTS: usize = 8;

struct LocalAccount(RefCell<Scope>);
struct LocalPermit<'a>(&'a LocalAccount);
impl AccountPermit for LocalPermit<'_> {
    fn settle(&mut self, settlement: Settlement) {
        settlement.apply(&mut self.0.0.borrow_mut());
    }
}
impl Account for LocalAccount {
    type Permit<'a> = LocalPermit<'a>;
    fn reserve(&self, request: AccountRequest) -> Result<Self::Permit<'_>, Failure> {
        request.reserve_scope(&mut self.0.borrow_mut())?;
        Ok(LocalPermit(self))
    }
}

struct Transforms<'a>(&'a [Import]);
impl InvocationDriver for Transforms<'_> {
    type Call<'a>
        = Ready<DriverOutput>
    where
        Self: 'a;
    fn call(&self, resource: ResourceId, operation: Operation) -> Self::Call<'_> {
        let result = match self.0.get(resource.get() as usize) {
            Some(Import::Transform(transform)) => transform.apply(operation.input),
            _ => Err(Failure::policy("imports", "unsupported resource")),
        };
        ready(DriverOutput::new(match result {
            Ok(value) => Outcome::Done(value),
            Err(failure) => Outcome::Fail(failure),
        }))
    }
}

struct Adapter<'a> {
    driver: Transforms<'a>,
    bindings: &'a [ImportBinding],
    account: LocalAccount,
}
struct Call<'a> {
    invocation: Result<InvocationCall<'a, Transforms<'a>, NoFacts, LocalAccount>, Failure>,
}
impl Future for Call<'_> {
    type Output = HostEvent<TaintedValue, TaintedFailure>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = match &mut self.get_mut().invocation {
            Ok(invocation) => {
                let result = core::task::ready!(Pin::new(invocation).poll(cx));
                result.output.into_result()
            }
            Err(failure) => Err(failure.clone().into()),
        };
        Poll::Ready(HostEvent::Complete(result))
    }
}

impl RequestDriver for Adapter<'_> {
    type Call<'a>
        = Call<'a>
    where
        Self: 'a;
    fn call<'a>(&'a self, resource: u32, request: Request<TaintedValue>) -> Self::Call<'a> {
        let invocation = (|| {
            if request.context != IdentityRef::ROOT.get() {
                return Err(Failure::policy(
                    "acting",
                    "this embedding only admits its fixed identity",
                ));
            }
            let binding = self
                .bindings
                .get(request.import as usize)
                .ok_or_else(|| Failure::policy("imports", "invalid import"))?;
            let position = u32::try_from(request.position).map_err(|_error| {
                Failure::policy("position", "source position exceeds operation identity")
            })?;
            let operation = Operation {
                id: OperationId::new(
                    OWNER,
                    ExecutionId::FIRST,
                    InvocationId::new(request.ticket),
                    CausalPosition::new(position),
                    0,
                ),
                process: OWNER,
                acting: IdentityRef::ROOT,
                handle: HandleId::new(binding.handle.slot, binding.handle.generation),
                method: MethodId::new(0),
                input: request.input.value,
                taint: request.input.taint,
                output: OutputMode::Unary,
            };
            invoke(
                operation,
                GrantedMethod {
                    owner: OWNER,
                    acting: IdentityRef::ROOT,
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    resource: ResourceId::new(resource.into()),
                    contract: MethodContract::new(
                        0,
                        ReplayClass::Deterministic,
                        OutputModeSet::UNARY,
                    ),
                },
                InvocationOptions {
                    now_millis: 0,
                    record: false,
                },
                if request.cleanup {
                    CallContext::Cleanup
                } else {
                    CallContext::Body
                },
                &self.driver,
                &NoFacts,
                &self.account,
            )
        })();
        Call { invocation }
    }
}

/// Execute a compiled Rust or JSON program using bounded, caller-owned machine
/// storage and concrete ready invocation futures. Compilation/value storage use
/// `alloc`; pending futures do not allocate. Unsupported imports fail at link.
pub fn run(
    program: &Program,
    input: TaintedValue,
) -> Result<(ExecutionOutput, BudgetState), Failure> {
    let compiled = program
        .compile()
        .map_err(|error| Failure::policy("compile", alloc::format!("{error}")))?
        .with_provenance();
    if compiled.imports().len() > MAX_IMPORTS {
        return Err(Failure::policy(
            "imports",
            "example import capacity exceeded",
        ));
    }
    let mut handle_slots = [Handle::default(); MAX_IMPORTS];
    let mut handles = HandleTable::new(&mut handle_slots);
    let mut bindings = [ImportBinding {
        handle: HandleKey {
            slot: 0,
            generation: 0,
        },
        method: 0,
    }; MAX_IMPORTS];
    for (index, import) in compiled.imports().iter().enumerate() {
        // Scope, module, wait, and external operation imports require explicit
        // adapters. A fixed-identity embedding must never silently accept them.
        if !matches!(import, Import::Transform(_)) {
            return Err(Failure::policy(
                "imports",
                "this embedding admits only transforms",
            ));
        }
        bindings[index].handle = handles
            .install(OWNER.get(), index as u32, 1)
            .map_err(|error| Failure::policy("authority", alloc::format!("{error}")))?;
    }
    let bindings = &bindings[..compiled.imports().len()];
    let linked = LinkedProgram::new(compiled.image(), bindings, &handles, OWNER.get())
        .map_err(machine_error)?;
    let mut scope = Scope::new(OWNER, IdentityRef::ROOT);
    if !scope.start() {
        return Err(Failure::policy("scope", "scope cannot start"));
    }
    let adapter = Adapter {
        driver: Transforms(compiled.imports()),
        bindings,
        account: LocalAccount(RefCell::new(scope)),
    };
    let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 32, _>(|_| None);
    let mut pending = core::array::from_fn::<_, 3, _>(|_| PendingCall::default());
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        ExecutionLimits {
            frames_per_task: 16,
            bindings_per_task: 0,
            max_steps: Some(1000),
            cleanup_steps: 64,
            durable: false,
        },
        input,
        IdentityRef::ROOT.get(),
    )
    .map_err(machine_error)?;
    let mut execution = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
        NonZeroU32::MIN.saturating_add(15),
    )
    .map_err(machine_error)?;
    // All admitted drivers return Ready; Pending can only be a bounded yield.
    let result = loop {
        if let Poll::Ready(result) =
            Pin::new(&mut execution).poll(&mut Context::from_waker(Waker::noop()))
        {
            break result;
        }
    };
    drop(execution);
    let terminal = match &result.outcome {
        Outcome::Done(_) | Outcome::Short(_) => ProcessStatus::Completed,
        Outcome::Fail(Failure::Cancelled) => ProcessStatus::Cancelled,
        Outcome::Fail(_) => ProcessStatus::Failed,
    };
    let mut scope = adapter.account.0.borrow_mut();
    if !scope.finish_body(terminal) || scope.begin_finalizing(terminal) != ScopeFinalize::Started {
        return Err(Failure::policy(
            "scope",
            "finalization could not be claimed",
        ));
    }
    for binding in bindings {
        handles
            .release(binding.handle, OWNER.get())
            .map_err(|error| Failure::policy("authority", alloc::format!("{error}")))?;
    }
    scope.mark_terminal_status(terminal);
    if !scope.complete_finalization() {
        return Err(Failure::policy("scope", "finalization did not commit"));
    }
    scope.release_finalizing();
    drop(scope);
    let budget = adapter.account.0.borrow().budget().clone();
    Ok((result, budget))
}

fn machine_error(error: xolotl_sdk::core::Fault) -> Failure {
    Failure::policy("machine", alloc::format!("{error}"))
}

/// A bounded loop in one parallel branch and an authored constant in the other.
pub fn sample_program() -> Program {
    Program::new(
        E::While {
            condition: Box::new(E::Transform {
                operation: Transform::LessThan { value: 5 },
            }),
            body: Box::new(E::Transform {
                operation: Transform::Add { value: 1 },
            }),
            max_iterations: 5,
        }
        .both(E::literal("ready")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use xolotl_sdk::types::Value;

    #[test]
    fn rust_and_json_use_the_same_machine_and_leave_no_reservations() -> Result<(), Failure> {
        let (output, budget) = run(&sample_program(), TaintedValue::pristine(Value::integer(0)))?;
        if output.outcome
            != Outcome::Done(Value::list(alloc::vec![
                Value::integer(5),
                Value::string("ready".into())
            ]))
            || budget != BudgetState::default()
        {
            return Err(Failure::policy(
                "test",
                "unexpected result or retained reservation",
            ));
        }
        let program = Program::from_json(
            br#"{"version":1,"body":{"kind":"transform","operation":{"op":"add","value":3}}}"#,
        )
        .map_err(|error| Failure::policy("test", alloc::format!("{error}")))?;
        let (output, budget) = run(&program, TaintedValue::pristine(Value::integer(4)))?;
        if output.outcome != Outcome::Done(Value::integer(7)) || budget != BudgetState::default() {
            return Err(Failure::policy("test", "JSON program disagrees"));
        }
        Ok(())
    }

    #[test]
    fn event_values_keep_shared_ownership_through_portable_fork_and_projection()
    -> Result<(), Failure> {
        use xolotl_sdk::types::value::event::{Atom, Event, Kind, ValueBuilder};
        let mut builder = ValueBuilder::default();
        let build_error = |error| Failure::policy("builder", alloc::format!("{error}"));
        for event in [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::Atom(Atom::Author),
            Event::End(Kind::Taint),
        ] {
            builder.push(event).map_err(build_error)?;
        }
        for _ in 0..20_000 {
            builder
                .push(Event::Begin(Kind::List))
                .map_err(build_error)?;
        }
        builder
            .push(Event::Atom(Atom::F64Bits(0x7ff8_0000_0000_0001)))
            .map_err(build_error)?;
        for _ in 0..20_000 {
            builder.push(Event::End(Kind::List)).map_err(build_error)?;
        }
        builder
            .push(Event::End(Kind::Document))
            .map_err(build_error)?;
        let input = builder.finish().map_err(build_error)?;
        let identity = input.value.identity();
        let program = Program::new(E::Input.both(E::Input).then(E::Transform {
            operation: Transform::Index { index: 1 },
        }));
        let (output, budget) = run(&program, input)?;
        if output.outcome.value().and_then(Value::identity) != identity
            || output.taint != xolotl_sdk::types::TaintSet::author()
            || budget != BudgetState::default()
        {
            return Err(Failure::policy(
                "test",
                "portable shared ownership or provenance changed",
            ));
        }
        drop(output);
        Ok(())
    }
}
