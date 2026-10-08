use crate::frame::{Frame, FrameKind, FramePool, FramePoolMeta, Stack};
use crate::{Fault, Join, NodeKind, ProgramImage, Values};

mod references;

/// Host-selected bounds. All limits apply independently of source language.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionLimits {
    /// Maximum simultaneous continuations held by each task.
    pub frames_per_task: usize,
    /// Lexical binding slots reserved for each task.
    pub bindings_per_task: usize,
    /// Optional cumulative transition quota. `None` permits long-running work;
    /// [`Execution::advance`] still bounds each turn with its `fuel` argument.
    pub max_steps: Option<u64>,
    /// Additional transitions available for cancellation and cleanup.
    pub cleanup_steps: u64,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            frames_per_task: 64,
            bindings_per_task: 64,
            max_steps: None,
            cleanup_steps: 4096,
        }
    }
}

#[derive(Clone, Debug)]
enum State<V, E> {
    Free,
    Ready,
    Waiting {
        ticket: u64,
        node: u32,
    },
    Joining(JoinState),
    Returning(Result<V, E>),
    Done(Result<V, E>),
    Halted {
        outcome: Result<V, E>,
        join: Option<JoinState>,
    },
}

#[derive(Clone, Copy, Debug)]
struct JoinState {
    left: usize,
    right: usize,
    join: Join,
    node: u32,
}

impl<V, E> State<V, E> {
    fn terminal_result(&self) -> Option<&Result<V, E>> {
        match self {
            Self::Done(outcome) | Self::Halted { outcome, .. } => Some(outcome),
            _ => None,
        }
    }

    fn join(&self) -> Option<&JoinState> {
        match self {
            Self::Joining(join)
            | Self::Halted {
                join: Some(join), ..
            } => Some(join),
            _ => None,
        }
    }
}

/// One task slot. Values and frame storage are bounded by the host's slices.
#[derive(Clone, Debug)]
pub struct Task<V, E> {
    state: State<V, E>,
    pc: u32,
    // Ready/waiting states own full input; other states retain control provenance.
    input: Option<V>,
    stack: Stack,
    context: u64,
    parent: Option<usize>,
    cleaning: usize,
    cancelled: bool,
}

impl<V, E> Default for Task<V, E> {
    fn default() -> Self {
        Self {
            state: State::Free,
            pc: 0,
            input: None,
            stack: Stack::default(),
            context: 0,
            parent: None,
            cleaning: 0,
            cancelled: false,
        }
    }
}

/// A request is emitted exactly once, and matched by task plus unique ticket.
#[derive(Clone, Debug)]
pub struct Request<V> {
    /// Live task slot that must receive the response.
    pub task: usize,
    /// Execution-wide token rejecting stale or duplicate responses.
    pub ticket: u64,
    /// Index into the linked host import table.
    pub import: u32,
    /// Input value with host-defined ownership and provenance.
    pub input: V,
    /// Authorized acting context inherited by this task.
    pub context: u64,
    /// Static source position; tickets distinguish dynamic invocations.
    pub position: u64,
    /// Whether this request belongs to structured cleanup.
    pub cleanup: bool,
}

/// Result of bounded cooperative execution.
#[derive(Clone, Debug)]
pub enum Advance<V, E> {
    /// Dispatch only after the host checks the import's authority and admission.
    Request(Request<V>),
    /// Host must cancel the pending request before delivering its cancellation.
    Cancel {
        /// Task whose outstanding request must be cancelled.
        task: usize,
        /// Token of that outstanding request.
        ticket: u64,
    },
    /// The caller's work quantum ended; more local work remains.
    Yielded,
    /// Every live task is blocked on a host request.
    Waiting,
    /// The root task and its structured children have terminated.
    Done(Result<V, E>),
}

/// Response to an emitted request. Enter is only valid for a Scope instruction.
#[derive(Clone, Debug)]
pub enum HostEvent<V, E> {
    /// Complete a request with its result or error.
    Complete(Result<V, E>),
    /// Enter a context authorized by the host for a Scope instruction.
    Enter(u64),
    /// A validated, appended continuation starts at this instruction.
    Continue {
        /// Entry in the extended, validated program image.
        entry: u32,
        /// Initial input to the continuation's subprogram.
        input: V,
    },
}

/// An execution borrows all mutable storage; it never allocates or spawns work.
pub struct Execution<'a, V, E> {
    tasks: &'a mut [Task<V, E>],
    frames: FramePool<'a, V, E>,
    bindings: &'a mut [Option<V>],
    limits: ExecutionLimits,
    steps: u64,
    cleanup_steps: u64,
    ticket: u64,
    cursor: usize,
    aborting: bool,
    image_id: [u8; 32],
}

/// Live controller state retained while the host grows its storage.
/// Resume with the same values, slots and pending I/O; this is not a persisted image.
#[derive(Clone, Copy, Debug)]
pub struct SuspendedExecution {
    task_count: usize,
    frame_count: usize,
    /// Compiler-generated identity of the active image.
    pub image_id: [u8; 32],
    /// Storage layout and execution bounds; the host may increase capacities.
    pub limits: ExecutionLimits,
    /// Shared frame-pool allocation state.
    frame_pool: FramePoolMeta,
    /// Ordinary transitions already consumed.
    pub steps: u64,
    /// Cancellation transitions already consumed.
    cleanup_steps: u64,
    /// Highest request token issued before suspension.
    ticket: u64,
    /// Next scheduler slot, preserving cooperative ordering.
    cursor: usize,
    /// Whether cancellation has started.
    aborting: bool,
}

/// Allocation-free inspection of the current live machine.
/// Borrowed values and slot indices remain owned by the host.
pub struct ExecutionView<'a, V, E> {
    /// Live counters and storage bounds.
    pub meta: SuspendedExecution,
    /// Task slots, including pending requests and completed branch results.
    pub tasks: &'a [Task<V, E>],
    /// Shared continuation storage, with per-task stacks and validated free links.
    pub frames: &'a [Option<Frame<V, E>>],
    /// Value bindings, retaining the host's provenance representation.
    pub bindings: &'a [Option<V>],
}

impl<V, E> ExecutionView<'_, V, E> {
    /// Borrow the terminal root result without copying task storage.
    pub fn result(&self) -> Option<&Result<V, E>> {
        self.tasks.first()?.state.terminal_result()
    }

    /// Tickets with outstanding host evidence, without cloning input payloads.
    /// A halted machine retains these for reconciliation, not event delivery.
    pub fn pending_tickets(&self) -> impl Iterator<Item = u64> + '_ {
        self.tasks.iter().filter_map(|task| match task.state {
            State::Waiting { ticket, .. } => Some(ticket),
            _ => None,
        })
    }

    /// Opaque contexts held by live task slots and lexical frames.
    /// Zero is the host's root context.
    pub fn contexts(&self) -> impl Iterator<Item = u64> + '_ {
        self.tasks
            .iter()
            .filter(|task| !matches!(task.state, State::Free))
            .map(|task| task.context)
            .chain(
                self.frames
                    .iter()
                    .flatten()
                    .filter_map(Frame::saved_context),
            )
    }

    /// Inspect pending imports, identities and borrowed inputs without cloning.
    /// Halted requests retain effect identities, not event-delivery eligibility.
    pub fn pending_requests<'b>(
        &'b self,
        image: &'b ProgramImage<'_, V, E>,
    ) -> impl Iterator<Item = Request<&'b V>> + 'b {
        pending_requests(self.tasks, image)
    }
}

fn pending_requests<'a, V, E>(
    tasks: &'a [Task<V, E>],
    image: &'a ProgramImage<'_, V, E>,
) -> impl Iterator<Item = Request<&'a V>> + 'a {
    tasks.iter().enumerate().filter_map(move |(index, task)| {
        let State::Waiting { ticket, node } = task.state else {
            return None;
        };
        let node = image.node(node).ok()?;
        let import = match node.kind {
            NodeKind::Request(import) | NodeKind::Scope { import, .. } => import,
            _ => return None,
        };
        Some(Request {
            task: index,
            ticket,
            import,
            input: task.input.as_ref()?,
            context: task.context,
            position: node.position,
            cleanup: task.cleaning > 0,
        })
    })
}

impl<'a, V: Clone, E: Clone> Execution<'a, V, E> {
    /// Validate an image and initialize caller-owned storage for one execution.
    pub fn new(
        image: &ProgramImage<'_, V, E>,
        tasks: &'a mut [Task<V, E>],
        frames: &'a mut [Option<Frame<V, E>>],
        bindings: &'a mut [Option<V>],
        limits: ExecutionLimits,
        input: V,
        context: u64,
    ) -> Result<Self, Fault> {
        image.validate()?;
        if tasks.is_empty() || tasks.len() > u32::MAX as usize {
            return Err(Fault::Tasks);
        }
        if frames.len() > u32::MAX as usize {
            return Err(Fault::Frames);
        }
        if image.bindings > limits.bindings_per_task
            || bindings.len() / tasks.len() < limits.bindings_per_task
        {
            return Err(Fault::InvalidBinding);
        }
        tasks.fill_with(Task::default);
        bindings.fill_with(|| None);
        tasks[0].state = State::Ready;
        tasks[0].pc = image.entry;
        tasks[0].input = Some(input);
        tasks[0].context = context;
        Ok(Self {
            tasks,
            frames: FramePool::new(frames),
            bindings,
            limits,
            steps: 0,
            cleanup_steps: 0,
            ticket: 0,
            cursor: 0,
            aborting: false,
            image_id: image.id,
        })
    }

    /// Borrow live tasks, frames, bindings and counters without allocating.
    pub fn view(&self) -> ExecutionView<'_, V, E> {
        ExecutionView {
            meta: SuspendedExecution {
                task_count: self.tasks.len(),
                frame_count: self.frames.slots.len(),
                image_id: self.image_id,
                limits: self.limits,
                frame_pool: self.frames.meta,
                steps: self.steps,
                cleanup_steps: self.cleanup_steps,
                ticket: self.ticket,
                cursor: self.cursor,
                aborting: self.aborting,
            },
            tasks: self.tasks,
            frames: self.frames.slots,
            bindings: self.bindings,
        }
    }

    /// Release the controller's storage borrows and return its resume metadata.
    /// Values remain in the caller's arrays. This is an in-memory handoff, not a
    /// data commit or cancellation; hosts must keep pending I/O and its tickets.
    pub fn suspend(self) -> SuspendedExecution {
        self.view().meta
    }

    /// Resume live storage in place without cloning values or replaying requests.
    /// The host preserves existing slots and may grow task/frame arrays and remap
    /// binding rows to a larger `meta.limits.bindings_per_task` stride.
    /// New task slots are default-initialized; new frame/binding slots are empty.
    pub fn resume(
        image: &ProgramImage<'_, V, E>,
        meta: SuspendedExecution,
        tasks: &'a mut [Task<V, E>],
        frames: &'a mut [Option<Frame<V, E>>],
        bindings: &'a mut [Option<V>],
    ) -> Result<Self, Fault> {
        if image.id != meta.image_id {
            return Err(Fault::ImageMismatch);
        }
        if tasks.len() < meta.task_count || tasks.len() > u32::MAX as usize {
            return Err(Fault::Tasks);
        }
        if frames.len() < meta.frame_count || frames.len() > u32::MAX as usize {
            return Err(Fault::Frames);
        }
        if meta.limits.bindings_per_task < image.bindings
            || bindings.len() / tasks.len() < meta.limits.bindings_per_task
        {
            return Err(Fault::InvalidBinding);
        }
        Ok(Self::from_view(meta, tasks, frames, bindings))
    }

    fn from_view(
        meta: SuspendedExecution,
        tasks: &'a mut [Task<V, E>],
        frames: &'a mut [Option<Frame<V, E>>],
        bindings: &'a mut [Option<V>],
    ) -> Self {
        Self {
            tasks,
            frames: FramePool {
                slots: frames,
                meta: meta.frame_pool,
            },
            bindings,
            limits: meta.limits,
            steps: meta.steps,
            cleanup_steps: meta.cleanup_steps,
            ticket: meta.ticket,
            cursor: meta.cursor,
            aborting: meta.aborting,
            image_id: meta.image_id,
        }
    }

    /// Entries of subprograms still active after [`HostEvent::Continue`].
    /// Each invocation appears once, including duplicate entries. Iteration scans
    /// the shared frame pool without allocating; completed invocations disappear.
    pub fn continuation_entries(&self) -> impl Iterator<Item = u32> + '_ {
        references::continuations(self.frames.slots).map(|(_, entry)| entry)
    }

    /// Release values in host-owned binding slots across all tasks without moving storage.
    /// The host must ensure the slots belong to retired code: no active instruction,
    /// continuation, or lexical scope may still use or restore them.
    /// Invalid ranges leave all bindings unchanged. No values are cloned.
    pub fn clear_bindings(&mut self, slots: core::ops::Range<usize>) -> Result<(), Fault> {
        if slots.start > slots.end || slots.end > self.limits.bindings_per_task {
            return Err(Fault::InvalidBinding);
        }
        if !slots.is_empty() {
            for task in 0..self.tasks.len() {
                let base = task * self.limits.bindings_per_task;
                self.bindings[base + slots.start..base + slots.end].fill_with(|| None);
            }
        }
        Ok(())
    }

    /// Clone inputs of already-issued live requests for host-side inspection.
    /// Inspection does not authorize redispatch; use `view` to borrow inputs.
    pub fn pending_requests<'b>(
        &'b self,
        image: &'b ProgramImage<'_, V, E>,
    ) -> impl Iterator<Item = Request<V>> + 'b {
        pending_requests(self.tasks, image).map(|request| Request {
            task: request.task,
            ticket: request.ticket,
            import: request.import,
            input: request.input.clone(),
            context: request.context,
            position: request.position,
            cleanup: request.cleanup,
        })
    }

    /// True only while a host result is still eligible for delivery.
    pub fn is_pending(&self, task: usize, ticket: u64) -> bool {
        self.tasks[0].state.terminal_result().is_none()
            && self.tasks.get(task).is_some_and(
                |task| matches!(task.state, State::Waiting { ticket: live, .. } if live == ticket),
            )
    }

    /// Retain the currently live data and control dependencies for an embedding
    /// failure that prevents further machine execution. No history is collected.
    pub fn retain_control<H: Values<Value = V, Error = E>>(&self, values: &mut H) -> V {
        let mut control = values.unit();
        for task in self.tasks.iter() {
            if matches!(task.state, State::Free) {
                continue;
            }
            if let Some(input) = &task.input {
                control = values.influence(control, input);
            }
            if let State::Returning(result)
            | State::Done(result)
            | State::Halted {
                outcome: result, ..
            } = &task.state
            {
                let result = values.retain_result(result);
                control = values.influence(control, &result);
            }
        }
        for frame in self.frames.slots.iter().flatten() {
            match &frame.kind {
                FrameKind::Finally { input, .. }
                | FrameKind::Choose { input, .. }
                | FrameKind::Condition { value: input, .. } => {
                    control = values.influence(control, input);
                }
                FrameKind::Cleaned { outcome } => {
                    let result = values.retain_result(outcome);
                    control = values.influence(control, &result);
                }
                _ => {}
            }
        }
        control
    }

    /// Request structured cancellation. Cleanup still receives a bounded budget.
    pub fn cancel(&mut self) {
        if self.tasks[0].state.terminal_result().is_some() {
            return;
        }
        self.aborting = true;
        for task in self.tasks.iter_mut() {
            if !matches!(
                task.state,
                State::Free | State::Done(_) | State::Halted { .. }
            ) {
                task.cancelled = true;
            }
        }
    }

    fn push(&mut self, task: usize, frame: FrameKind<V, E>) -> Result<(), Fault> {
        self.frames.push(
            &mut self.tasks[task].stack,
            frame,
            self.limits.frames_per_task,
        )
    }

    fn pop(&mut self, task: usize) -> Option<FrameKind<V, E>> {
        self.frames.pop(&mut self.tasks[task].stack)
    }

    fn start(&mut self, task: usize, pc: u32, input: V) {
        self.tasks[task].pc = pc;
        self.tasks[task].input = Some(input);
        self.tasks[task].state = State::Ready;
    }

    fn influence_result<H: Values<Value = V, Error = E>>(
        &self,
        task: usize,
        result: Result<V, E>,
        values: &mut H,
    ) -> Result<V, E> {
        match self.tasks.get(task).and_then(|task| task.input.as_ref()) {
            Some(control) => values.influence_result(result, control),
            None => result,
        }
    }

    fn fault_result<H: Values<Value = V, Error = E>>(
        &self,
        task: usize,
        fault: Fault,
        values: &mut H,
    ) -> Result<V, E> {
        let error = values.error(fault);
        let mut result = self.influence_result(task, Err(error), values);
        if let Some(Task {
            state: State::Returning(previous) | State::Done(previous),
            ..
        }) = self.tasks.get(task)
        {
            let control = values.retain_result(previous);
            result = values.influence_result(result, &control);
        }
        result
    }

    fn terminal_fault<H: Values<Value = V, Error = E>>(
        &self,
        fault: Fault,
        values: &mut H,
    ) -> Result<V, E> {
        let control = self.retain_control(values);
        let error = values.error(fault);
        values.influence_result(Err(error), &control)
    }

    fn finish<H: Values<Value = V, Error = E>>(
        &mut self,
        task: usize,
        node: u32,
        result: Result<V, E>,
        image: &ProgramImage<'_, V, E>,
        values: &mut H,
    ) -> Result<(), Fault> {
        let instruction = image.node(node)?;
        let result = self.influence_result(task, result, values);
        let result = match result {
            Ok(value) => {
                if let Some(next) = instruction.next {
                    self.start(task, next, value);
                    return Ok(());
                }
                Ok(value)
            }
            Err(error) => Err(error),
        };
        self.tasks[task].state = State::Returning(result);
        Ok(())
    }

    /// Deliver a result with its request's control provenance. Stale, duplicate,
    /// or mismatched responses never advance a task.
    pub fn complete<H: Values<Value = V, Error = E>>(
        &mut self,
        task: usize,
        ticket: u64,
        event: HostEvent<V, E>,
        image: &ProgramImage<'_, V, E>,
        values: &mut H,
    ) -> Result<(), Fault> {
        if image.id != self.image_id {
            return Err(Fault::ImageMismatch);
        }
        if self.tasks[0].state.terminal_result().is_some() {
            return Err(Fault::StaleEvent);
        }
        let node = match self.tasks.get(task).map(|task| &task.state) {
            Some(State::Waiting { ticket: live, node }) if *live == ticket => *node,
            _ => return Err(Fault::StaleEvent),
        };
        let control = match &event {
            HostEvent::Complete(result) => Some(values.retain_result(result)),
            HostEvent::Continue { input, .. } => {
                if !matches!(image.node(node)?.kind, NodeKind::Request(_)) {
                    return Err(Fault::StaleEvent);
                }
                Some(values.retain_control(input))
            }
            HostEvent::Enter(_) => None,
        };
        // Keep a matching response's control even if accepting it fails below.
        if let Some(control) = control {
            self.tasks[task].input = Some(match self.tasks[task].input.take() {
                Some(input) => values.influence(input, &control),
                None => control,
            });
        }
        match event {
            HostEvent::Complete(result) => self.finish(task, node, result, image, values),
            HostEvent::Enter(context) => {
                let NodeKind::Scope { body, .. } = image.node(node)?.kind else {
                    return Err(Fault::StaleEvent);
                };
                self.frames
                    .check(&self.tasks[task].stack, 2, self.limits.frames_per_task)?;
                self.push(task, FrameKind::Finish(node))?;
                self.push(task, FrameKind::Context(self.tasks[task].context))?;
                self.tasks[task].context = context;
                let input = self.tasks[task].input.take().ok_or(Fault::Type)?;
                self.start(task, body, input);
                Ok(())
            }
            HostEvent::Continue { entry, input } => {
                image.node(entry)?;
                self.push(task, FrameKind::Continuation { node, entry })?;
                let input = match self.tasks[task].input.as_ref() {
                    Some(control) => values.influence(input, control),
                    None => input,
                };
                self.start(task, entry, input);
                Ok(())
            }
        }
    }

    /// Advance at most `fuel` transitions. No time or external state is sampled.
    pub fn advance<H: Values<Value = V, Error = E>>(
        &mut self,
        image: &ProgramImage<'_, V, E>,
        values: &mut H,
        fuel: u32,
    ) -> Advance<V, E> {
        if image.id != self.image_id {
            return Advance::Done(self.terminal_fault(Fault::ImageMismatch, values));
        }
        for _ in 0..fuel {
            if let Some(result) = self.tasks[0].state.terminal_result() {
                return Advance::Done(result.clone());
            }
            if !self.aborting && self.limits.max_steps.is_some_and(|max| self.steps >= max) {
                self.cancel();
            }
            let mut selected = None;
            for offset in 0..self.tasks.len() {
                let index = (self.cursor + offset) % self.tasks.len();
                if !matches!(self.tasks[index].state, State::Free | State::Done(_)) {
                    if self.tasks[index].cancelled && self.tasks[index].cleaning == 0 {
                        if let State::Waiting { ticket, .. } = self.tasks[index].state {
                            return Advance::Cancel {
                                task: index,
                                ticket,
                            };
                        }
                        if !matches!(
                            self.tasks[index].state,
                            State::Joining(_) | State::Returning(Err(_))
                        ) {
                            self.tasks[index].state = State::Returning(self.fault_result(
                                index,
                                Fault::Cancelled,
                                values,
                            ));
                        }
                    }
                    let ready = match self.tasks[index].state {
                        State::Waiting { .. } => false,
                        State::Joining(JoinState {
                            left, right, join, ..
                        }) => {
                            let a = matches!(self.tasks[left].state, State::Done(_));
                            let b = matches!(self.tasks[right].state, State::Done(_));
                            (a && b)
                                || (join == Join::Race
                                    && ((a && !self.tasks[right].cancelled)
                                        || (b && !self.tasks[left].cancelled)))
                        }
                        _ => true,
                    };
                    if ready {
                        selected = Some(index);
                        break;
                    }
                }
            }
            let Some(task) = selected else {
                return Advance::Waiting;
            };
            if self.aborting {
                if self.cleanup_steps >= self.limits.cleanup_steps {
                    let result = self.terminal_fault(Fault::Fuel, values);
                    self.tasks[0].state = State::Halted {
                        outcome: result.clone(),
                        join: self.tasks[0].state.join().copied(),
                    };
                    return Advance::Done(result);
                }
                self.cleanup_steps += 1;
            } else {
                self.steps = self.steps.saturating_add(1);
            }
            self.cursor = (task + 1) % self.tasks.len();
            match self.transition(task, image, values) {
                Ok(Some(action)) => return action,
                Ok(None) => {}
                Err(fault) => {
                    self.tasks[task].state =
                        State::Returning(self.fault_result(task, fault, values));
                }
            }
        }
        Advance::Yielded
    }

    /// Advance a capability-linked image, rejecting revoked imports before the
    /// host receives a request. Hosts recheck at dispatch if they queue requests.
    pub fn advance_linked<H: Values<Value = V, Error = E>>(
        &mut self,
        program: &crate::LinkedProgram<'_, V, E>,
        handles: &crate::HandleTable<'_>,
        values: &mut H,
        fuel: u32,
    ) -> Advance<V, E> {
        match self.advance(&program.image, values, fuel) {
            Advance::Request(request) => match program.authorize(request.import, handles) {
                Ok(_resource) => Advance::Request(request),
                Err(fault) => {
                    let result = self.complete(
                        request.task,
                        request.ticket,
                        HostEvent::Complete(Err(values.error(fault))),
                        &program.image,
                        values,
                    );
                    match result {
                        Ok(()) => Advance::Yielded,
                        Err(error) => Advance::Done(self.terminal_fault(error, values)),
                    }
                }
            },
            other => other,
        }
    }

    fn transition<H: Values<Value = V, Error = E>>(
        &mut self,
        task: usize,
        image: &ProgramImage<'_, V, E>,
        values: &mut H,
    ) -> Result<Option<Advance<V, E>>, Fault> {
        match core::mem::replace(&mut self.tasks[task].state, State::Ready) {
            State::Returning(outcome) => {
                let outcome = self.influence_result(task, outcome, values);
                let control = values.retain_result(&outcome);
                self.tasks[task].input = Some(match self.tasks[task].input.as_ref() {
                    Some(input) => values.influence(control, input),
                    None => control,
                });
                let Some(frame) = self.pop(task) else {
                    self.tasks[task].state = State::Done(outcome);
                    return Ok(None);
                };
                match frame {
                    FrameKind::Vacant => return Err(Fault::InvalidState),
                    FrameKind::Finish(node) | FrameKind::Continuation { node, .. } => {
                        self.finish(task, node, outcome, image, values)?
                    }
                    FrameKind::Then(next) => match outcome {
                        Ok(value) => self.start(task, next, value),
                        Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                    },
                    FrameKind::Catch(recover) => match outcome {
                        Err(error)
                            if !self.tasks[task].cancelled || self.tasks[task].cleaning > 0 =>
                        {
                            let value = values.error_value(error);
                            let value = match &self.tasks[task].input {
                                Some(input) => values.influence(value, input),
                                None => value,
                            };
                            self.start(task, recover, value)
                        }
                        result => self.tasks[task].state = State::Returning(result),
                    },
                    FrameKind::Finally { cleanup, input } => {
                        self.push(task, FrameKind::Cleaned { outcome })?;
                        self.tasks[task].cleaning += 1;
                        self.start(task, cleanup, input);
                    }
                    FrameKind::Cleaned { outcome: original } => {
                        self.tasks[task].cleaning = self.tasks[task].cleaning.saturating_sub(1);
                        let control = values.retain_result(&original);
                        let result = match (original, outcome) {
                            (Err(error), _) | (_, Err(error)) => Err(error),
                            (Ok(value), Ok(_)) => Ok(value),
                        };
                        // Cleanup's result is already the task's current control.
                        self.tasks[task].state =
                            State::Returning(values.influence_result(result, &control));
                    }
                    FrameKind::Context(context) => {
                        self.tasks[task].context = context;
                        self.tasks[task].state = State::Returning(outcome);
                    }
                    FrameKind::Choose { yes, no, input } => match outcome {
                        Ok(test) => match values.truth(&test) {
                            Ok(truth) => self.start(
                                task,
                                if truth { yes } else { no },
                                values.influence(input, &test),
                            ),
                            Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                        },
                        Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                    },
                    FrameKind::Bind { slot, body } => match outcome {
                        Ok(value) => {
                            if slot as usize >= self.limits.bindings_per_task {
                                return Err(Fault::InvalidBinding);
                            }
                            let index = task * self.limits.bindings_per_task + slot as usize;
                            self.frames.check(
                                &self.tasks[task].stack,
                                1,
                                self.limits.frames_per_task,
                            )?;
                            let previous = self.bindings[index].take();
                            self.push(task, FrameKind::Unbind { slot, previous })?;
                            self.bindings[index] = Some(value.clone());
                            self.start(task, body, value);
                        }
                        Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                    },
                    FrameKind::Unbind { slot, previous } => {
                        self.bindings[task * self.limits.bindings_per_task + slot as usize] =
                            previous;
                        self.tasks[task].state = State::Returning(outcome);
                    }
                    FrameKind::Condition {
                        condition,
                        body,
                        left,
                        value,
                    } => match outcome {
                        Ok(test) => match values.truth(&test) {
                            Ok(false) => {
                                self.tasks[task].state =
                                    State::Returning(Ok(values.influence(value, &test)))
                            }
                            Ok(true) if left > 0 => {
                                self.push(
                                    task,
                                    FrameKind::Iteration {
                                        condition,
                                        body,
                                        left: left - 1,
                                    },
                                )?;
                                self.start(task, body, values.influence(value, &test));
                            }
                            Ok(true) => {
                                self.tasks[task].state =
                                    State::Returning(Err(values.error(Fault::Iterations)))
                            }
                            Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                        },
                        Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                    },
                    FrameKind::Iteration {
                        condition,
                        body,
                        left,
                    } => match outcome {
                        Ok(value) => {
                            self.push(
                                task,
                                FrameKind::Condition {
                                    condition,
                                    body,
                                    left,
                                    value: value.clone(),
                                },
                            )?;
                            self.start(task, condition, value);
                        }
                        Err(error) => self.tasks[task].state = State::Returning(Err(error)),
                    },
                }
            }
            State::Joining(JoinState {
                left,
                right,
                join,
                node,
            }) => {
                self.tasks[task].state = State::Joining(JoinState {
                    left,
                    right,
                    join,
                    node,
                });
                let a = matches!(self.tasks[left].state, State::Done(_));
                let b = matches!(self.tasks[right].state, State::Done(_));
                if join == Join::Race && (a || b) {
                    let loser = if a { right } else { left };
                    self.cancel_tree(loser);
                }
                if a && b {
                    let (State::Done(a), State::Done(b)) = (
                        core::mem::replace(&mut self.tasks[left].state, State::Free),
                        core::mem::replace(&mut self.tasks[right].state, State::Free),
                    ) else {
                        return Err(Fault::Type);
                    };
                    let left_control = values.retain_result(&a);
                    let right_control = values.retain_result(&b);
                    let control = values.influence(left_control, &right_control);
                    let result = match join {
                        Join::All => match (a, b) {
                            (Ok(a), Ok(b)) => values.pair(a, b),
                            (Err(error), _) | (_, Err(error)) => Err(error),
                        },
                        Join::Race => {
                            if self.tasks[left].cancelled {
                                b
                            } else {
                                a
                            }
                        }
                    };
                    let result = values.influence_result(result, &control);
                    self.free(left);
                    self.free(right);
                    self.finish(task, node, result, image, values)?;
                }
            }
            State::Ready => {
                let pc = self.tasks[task].pc;
                let node = image.node(pc)?;
                let stored = &mut self.tasks[task].input;
                let input = stored.as_ref().ok_or(Fault::Type)?;
                let retained = match node.kind {
                    NodeKind::Request(_) | NodeKind::Scope { .. } => input.clone(),
                    _ => values.retain_control(input),
                };
                let input = stored.replace(retained).ok_or(Fault::Type)?;
                match &node.kind {
                    NodeKind::Literal(value) => {
                        let value = values.influence(value.clone(), &input);
                        self.finish(task, pc, Ok(value), image, values)?
                    }
                    NodeKind::Input => self.finish(task, pc, Ok(input), image, values)?,
                    NodeKind::Load(slot) => {
                        if *slot as usize >= self.limits.bindings_per_task {
                            return Err(Fault::InvalidBinding);
                        }
                        let value = self.bindings
                            [task * self.limits.bindings_per_task + *slot as usize]
                            .clone()
                            .ok_or(Fault::MissingBinding)?;
                        let value = values.influence(value, &input);
                        self.finish(task, pc, Ok(value), image, values)?;
                    }
                    NodeKind::Fail(error) => {
                        self.finish(task, pc, Err(error.clone()), image, values)?
                    }
                    NodeKind::Request(import) | NodeKind::Scope { import, .. } => {
                        if *import as usize >= image.imports {
                            return Err(Fault::InvalidImport);
                        }
                        self.ticket = self.ticket.checked_add(1).ok_or(Fault::SequenceExhausted)?;
                        self.tasks[task].state = State::Waiting {
                            ticket: self.ticket,
                            node: pc,
                        };
                        return Ok(Some(Advance::Request(Request {
                            task,
                            ticket: self.ticket,
                            import: *import,
                            input,
                            context: self.tasks[task].context,
                            position: node.position,
                            cleanup: self.tasks[task].cleaning > 0,
                        })));
                    }
                    NodeKind::Then { first, then } => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.push(task, FrameKind::Then(*then))?;
                        self.start(task, *first, input);
                    }
                    NodeKind::Catch { body, recover } => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.push(task, FrameKind::Catch(*recover))?;
                        self.start(task, *body, input);
                    }
                    NodeKind::Finally { body, cleanup } => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.push(
                            task,
                            FrameKind::Finally {
                                cleanup: *cleanup,
                                input: input.clone(),
                            },
                        )?;
                        self.start(task, *body, input);
                    }
                    NodeKind::If { yes, no } => match values.truth(&input) {
                        Ok(test) => {
                            self.push(task, FrameKind::Finish(pc))?;
                            self.start(task, if test { *yes } else { *no }, input);
                        }
                        Err(error) => self.finish(task, pc, Err(error), image, values)?,
                    },
                    NodeKind::Call(entry) => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.start(task, *entry, input);
                    }
                    NodeKind::Branch { condition, yes, no } => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.push(
                            task,
                            FrameKind::Choose {
                                yes: *yes,
                                no: *no,
                                input: input.clone(),
                            },
                        )?;
                        self.start(task, *condition, input);
                    }
                    NodeKind::Let { slot, value, body } => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.push(
                            task,
                            FrameKind::Bind {
                                slot: *slot,
                                body: *body,
                            },
                        )?;
                        self.start(task, *value, input);
                    }
                    NodeKind::While {
                        condition,
                        body,
                        max,
                    } => {
                        self.push(task, FrameKind::Finish(pc))?;
                        self.push(
                            task,
                            FrameKind::Condition {
                                condition: *condition,
                                body: *body,
                                left: *max,
                                value: input.clone(),
                            },
                        )?;
                        self.start(task, *condition, input);
                    }
                    NodeKind::Fork { left, right, join } => {
                        let mut free = self
                            .tasks
                            .iter()
                            .enumerate()
                            .filter(|(_, task)| matches!(task.state, State::Free))
                            .map(|(index, _)| index);
                        let a = free.next().ok_or(Fault::Tasks)?;
                        let b = free.next().ok_or(Fault::Tasks)?;
                        self.start(a, *left, input.clone());
                        self.start(b, *right, input);
                        for child in [a, b] {
                            self.tasks[child].parent = Some(task);
                            self.tasks[child].context = self.tasks[task].context;
                            self.tasks[child].cleaning = self.tasks[task].cleaning;
                            for slot in 0..self.limits.bindings_per_task {
                                self.bindings[child * self.limits.bindings_per_task + slot] = self
                                    .bindings[task * self.limits.bindings_per_task + slot]
                                    .clone();
                            }
                        }
                        self.tasks[task].state = State::Joining(JoinState {
                            left: a,
                            right: b,
                            join: *join,
                            node: pc,
                        });
                    }
                }
            }
            state @ (State::Free
            | State::Waiting { .. }
            | State::Done(_)
            | State::Halted { .. }) => self.tasks[task].state = state,
        }
        Ok(None)
    }

    fn cancel_tree(&mut self, root: usize) {
        self.tasks[root].cancelled = true;
        for candidate in 0..self.tasks.len() {
            let mut parent = self.tasks[candidate].parent;
            while let Some(index) = parent {
                if index == root {
                    self.tasks[candidate].cancelled = true;
                    break;
                }
                parent = self.tasks[index].parent;
            }
        }
    }

    fn free(&mut self, task: usize) {
        while self.pop(task).is_some() {}
        for slot in 0..self.limits.bindings_per_task {
            self.bindings[task * self.limits.bindings_per_task + slot] = None;
        }
        self.tasks[task] = Task::default();
    }
}
