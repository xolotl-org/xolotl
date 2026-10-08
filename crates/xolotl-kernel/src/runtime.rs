//! Cooperative execution over caller-owned storage and statically chosen drivers.
//!
//! The embedding supplies capability linking and request adaptation. This loop
//! provides bounded polling, dispatch-time authority checks, and cancellation
//! ownership without a task scheduler, clock, thread, lock, or future allocation.

use core::{
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    task::{Context, Poll},
};
use xolotl_core::{
    Advance, Execution, Fault, HandleTable, HostEvent, LinkedProgram, Request, Values,
};
use xolotl_types::{ExecutionOutput, Failure, TaintedFailure, TaintedValue, UnresolvedOperations};

use crate::RuntimeValues;

mod cooperate;
pub use cooperate::{Cooperate, Cooperative, YieldOnce};

/// An ordinary machine event, or an interruption that cannot acknowledge the
/// pending request. `Err` stops execution without entering `Catch` or `Finally`,
/// and drops other pending calls. It is suitable for unconfirmed storage commits;
/// ordinary driver failures belong inside `Ok(HostEvent::Complete(Err(...)))`.
pub type RequestCompletion = Result<HostEvent<TaintedValue, TaintedFailure>, TaintedFailure>;

/// Trusted adaptation of a linked request to a capability call or context entry.
/// Drivers that access external resources should use [`crate::invocation::invoke`]
/// to share admission, accounting, provenance, and selected observation semantics.
/// Map an invocation's completion error to the interruption branch of
/// [`RequestCompletion`]; ordinary outcomes use its machine event branch.
pub trait RequestDriver {
    /// A call may be `Ready`, a concrete state machine, or `Pin<Box<F>>`.
    /// `Send` and heap allocation are choices of the embedding.
    type Call<'a>: Future<Output = RequestCompletion> + Unpin
    where
        Self: 'a;

    /// Called only after the linked handle is revalidated. The request context
    /// and cleanup flag come from the machine, not from program input.
    fn call<'a>(&'a self, resource: u32, request: Request<TaintedValue>) -> Self::Call<'a>;

    /// Synchronously retain unresolved effects before a completion is consumed
    /// or a call is released. `None` means cancellation, revocation, a losing
    /// race, interruption, or Drop; it does not prove that no effect occurred.
    /// Pure adapters must explicitly implement a no-op. Effect adapters inspect
    /// their call's dispatch state and the optional completion, recording only
    /// identities, never input/output history. This hook must not panic.
    fn collect_evidence<'a>(
        &'a self,
        call: &Self::Call<'a>,
        completion: Option<&RequestCompletion>,
        unresolved: &mut UnresolvedOperations,
    );
}

/// One caller-owned future slot per machine task. Vacant slots allocate nothing.
pub struct PendingCall<F> {
    import: u32,
    ticket: u64,
    cleanup: bool,
    future: Option<F>,
}

impl<F> Default for PendingCall<F> {
    fn default() -> Self {
        Self {
            import: 0,
            ticket: 0,
            cleanup: false,
            future: None,
        }
    }
}

/// A real `no_std + alloc` execution future for a linked image.
///
/// Task, frame, binding, handle, and pending-call storage belong to the caller.
/// Each poll performs at most `quantum` machine advances and one poll of each
/// previously pending call. Calls created in that turn are polled immediately.
/// The external evidence collector outlives this future, retaining unresolved
/// effects on Drop. Normal completion moves that evidence into the output and
/// leaves the collector empty. No per-call evidence buffer or payload history
/// is allocated by the loop. Drop releases pending calls after collecting their
/// evidence; cooperative [`Self::cancel`] also runs `Finally`.
pub struct LinkedExecution<
    'a,
    'storage,
    'driver,
    D: RequestDriver + 'driver,
    C: Cooperate + 'driver = Cooperative,
> {
    machine: Execution<'storage, TaintedValue, TaintedFailure>,
    program: &'a LinkedProgram<'a, TaintedValue, TaintedFailure>,
    handles: &'a mut HandleTable<'storage>,
    driver: &'driver D,
    pending: &'a mut [PendingCall<D::Call<'driver>>],
    cooperate: &'driver C,
    yielding: Option<C::Yield<'driver>>,
    quantum: NonZeroU32,
    finished: bool,
    unresolved: &'a mut UnresolvedOperations,
}

impl<'a, 'storage, 'driver, D: RequestDriver> LinkedExecution<'a, 'storage, 'driver, D> {
    /// Use a single cooperative wake at the end of each work quantum.
    pub fn new(
        machine: Execution<'storage, TaintedValue, TaintedFailure>,
        program: &'a LinkedProgram<'a, TaintedValue, TaintedFailure>,
        handles: &'a mut HandleTable<'storage>,
        driver: &'driver D,
        pending: &'a mut [PendingCall<D::Call<'driver>>],
        unresolved: &'a mut UnresolvedOperations,
        quantum: NonZeroU32,
    ) -> Result<Self, Fault> {
        Self::with_cooperate(
            machine,
            program,
            handles,
            driver,
            pending,
            unresolved,
            &Cooperative,
            quantum,
        )
    }
}

impl<'a, 'storage, 'driver, D: RequestDriver, C: Cooperate>
    LinkedExecution<'a, 'storage, 'driver, D, C>
{
    /// Attach a scheduler-specific cooperative hook without changing the loop.
    /// The machine must have no pending requests when this adapter takes ownership.
    #[expect(
        clippy::too_many_arguments,
        reason = "caller-owned machine storage, evidence, driver, and cooperation ports remain explicit"
    )]
    pub fn with_cooperate(
        machine: Execution<'storage, TaintedValue, TaintedFailure>,
        program: &'a LinkedProgram<'a, TaintedValue, TaintedFailure>,
        handles: &'a mut HandleTable<'storage>,
        driver: &'driver D,
        pending: &'a mut [PendingCall<D::Call<'driver>>],
        unresolved: &'a mut UnresolvedOperations,
        cooperate: &'driver C,
        quantum: NonZeroU32,
    ) -> Result<Self, Fault> {
        let view = machine.view();
        if view.meta.image_id != program.image.id {
            return Err(Fault::ImageMismatch);
        }
        if pending.len() != view.tasks.len() {
            return Err(Fault::Tasks);
        }
        if pending.iter().any(|slot| slot.future.is_some())
            || view.pending_tickets().next().is_some()
        {
            return Err(Fault::InvalidState);
        }
        Ok(Self {
            machine,
            program,
            handles,
            driver,
            pending,
            cooperate,
            yielding: None,
            quantum,
            finished: false,
            unresolved,
        })
    }

    /// Request cancellation and release ordinary calls before cleanup can run.
    /// Continue polling to drive structured cleanup. Repeated cancellation does
    /// not interrupt cleanup calls that the machine has already admitted.
    pub fn cancel(&mut self) {
        self.machine.cancel();
        for slot in self.pending.iter_mut().filter(|slot| !slot.cleanup) {
            if let Some(call) = &slot.future {
                self.driver.collect_evidence(call, None, self.unresolved);
            }
            slot.future = None;
        }
        self.yielding = None;
    }

    /// Trusted embedding access between polls, for release or revocation.
    /// Every subsequent dispatch observes the updated authority table.
    pub fn handles_mut(&mut self) -> &mut HandleTable<'storage> {
        self.handles
    }

    /// Number of externally pending operations, bounded by supplied task slots.
    pub fn pending_calls(&self) -> usize {
        self.pending
            .iter()
            .filter(|slot| slot.future.is_some())
            .count()
    }

    fn complete(
        &mut self,
        task: usize,
        ticket: u64,
        event: HostEvent<TaintedValue, TaintedFailure>,
    ) -> Result<(), Fault> {
        self.machine
            .complete(task, ticket, event, &self.program.image, &mut RuntimeValues)
            .or_else(|fault| {
                // A malformed context/continuation response is an ordinary call
                // failure, so the machine can still run the enclosing cleanup.
                if self.machine.is_pending(task, ticket) {
                    self.machine.complete(
                        task,
                        ticket,
                        HostEvent::Complete(Err(RuntimeValues.error(fault))),
                        &self.program.image,
                        &mut RuntimeValues,
                    )
                } else {
                    Err(fault)
                }
            })
    }

    fn poll_call(&mut self, task: usize, cx: &mut Context<'_>) -> Result<(), TaintedFailure> {
        let slot = &mut self.pending[task];
        let Some(future) = &mut slot.future else {
            return Ok(());
        };
        if !self.machine.is_pending(task, slot.ticket) {
            self.driver.collect_evidence(future, None, self.unresolved);
            slot.future = None;
            return Ok(());
        }
        if let Err(fault) = self.program.authorize(slot.import, self.handles) {
            let ticket = slot.ticket;
            self.driver.collect_evidence(future, None, self.unresolved);
            slot.future = None;
            return self
                .complete(
                    task,
                    ticket,
                    HostEvent::Complete(Err(RuntimeValues.error(fault))),
                )
                .map_err(|fault| RuntimeValues.error(fault));
        }
        if let Poll::Ready(event) = Pin::new(&mut *future).poll(cx) {
            let ticket = slot.ticket;
            self.driver
                .collect_evidence(future, Some(&event), self.unresolved);
            slot.future = None;
            self.complete(task, ticket, event?)
                .map_err(|fault| RuntimeValues.error(fault))?;
        }
        Ok(())
    }

    fn finish(&mut self, result: Result<TaintedValue, TaintedFailure>) -> Poll<ExecutionOutput> {
        for slot in self.pending.iter_mut() {
            if let Some(call) = &slot.future {
                self.driver.collect_evidence(call, None, self.unresolved);
            }
            slot.future = None;
        }
        self.yielding = None;
        self.finished = true;
        Poll::Ready(
            ExecutionOutput::from_result(result)
                .with_unresolved_operations(core::mem::take(self.unresolved)),
        )
    }

    fn fail(&mut self, fault: Fault) -> Poll<ExecutionOutput> {
        self.interrupt(RuntimeValues.error(fault))
    }

    fn interrupt(&mut self, error: TaintedFailure) -> Poll<ExecutionOutput> {
        let control = self.machine.retain_control(&mut RuntimeValues);
        let result = RuntimeValues.influence_result(Err(error), &control);
        self.finish(result)
    }
}

impl<D: RequestDriver, C: Cooperate> Future for LinkedExecution<'_, '_, '_, D, C> {
    type Output = ExecutionOutput;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.finished {
            return this.fail(Fault::StaleEvent);
        }
        if let Some(yielding) = &mut this.yielding {
            if Pin::new(yielding).poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.yielding = None;
        }
        for task in 0..this.pending.len() {
            if let Err(error) = this.poll_call(task, cx) {
                return this.interrupt(error);
            }
        }
        for _ in 0..this.quantum.get() {
            match this
                .machine
                .advance(&this.program.image, &mut RuntimeValues, 1)
            {
                Advance::Request(request) => {
                    let task = request.task;
                    let ticket = request.ticket;
                    match this.program.authorize(request.import, this.handles) {
                        Ok(resource) => {
                            let slot = &mut this.pending[task];
                            slot.import = request.import;
                            slot.ticket = ticket;
                            slot.cleanup = request.cleanup;
                            slot.future = Some(this.driver.call(resource, request));
                            if let Err(error) = this.poll_call(task, cx) {
                                return this.interrupt(error);
                            }
                        }
                        Err(fault) => {
                            if let Err(fault) = this.complete(
                                task,
                                ticket,
                                HostEvent::Complete(Err(RuntimeValues.error(fault))),
                            ) {
                                return this.fail(fault);
                            }
                        }
                    }
                }
                Advance::Cancel { task, ticket } => {
                    if this.pending[task].ticket == ticket {
                        if let Some(call) = &this.pending[task].future {
                            this.driver.collect_evidence(call, None, this.unresolved);
                        }
                        this.pending[task].future = None;
                    }
                    if let Err(fault) = this.complete(
                        task,
                        ticket,
                        HostEvent::Complete(Err(Failure::Cancelled.into())),
                    ) {
                        return this.fail(fault);
                    }
                }
                Advance::Yielded => {}
                Advance::Waiting if this.pending_calls() > 0 => return Poll::Pending,
                Advance::Waiting => {
                    return this.fail(Fault::StaleEvent);
                }
                Advance::Done(result) => return this.finish(result),
            }
        }
        let mut yielding = this.cooperate.cooperate();
        if Pin::new(&mut yielding).poll(cx).is_pending() {
            this.yielding = Some(yielding);
        } else {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl<D: RequestDriver, C: Cooperate> Drop for LinkedExecution<'_, '_, '_, D, C> {
    fn drop(&mut self) {
        for slot in self.pending.iter_mut() {
            if let Some(call) = &slot.future {
                self.driver.collect_evidence(call, None, self.unresolved);
            }
            slot.future = None;
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "typed setup failures propagate while assertions diagnose runtime contract failures"
)]
mod tests;
