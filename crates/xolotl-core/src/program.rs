//! Borrowed, linked execution images and host value semantics.

mod indices;

/// Current in-memory instruction format.
pub const IMAGE_VERSION: u32 = 1;

/// Machine failures are explicit, including all capacity limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Fault {
    /// An image or checkpoint uses an unsupported format.
    Version,
    /// A control-flow index falls outside the image.
    InvalidNode,
    /// An import index cannot be linked.
    InvalidImport,
    /// A lexical slot exceeds the admitted binding capacity.
    InvalidBinding,
    /// A lexical slot was read before being initialized.
    MissingBinding,
    /// No task slots remain for structured parallelism.
    Tasks,
    /// The continuation stack has reached its capacity.
    Frames,
    /// Resource analysis needs one caller-owned scratch slot per instruction.
    AnalysisCapacity,
    /// The transition budget is exhausted.
    Fuel,
    /// A loop remained true after its admitted iteration count.
    Iterations,
    /// A value does not satisfy an instruction's contract.
    Type,
    /// Structured cancellation stopped ordinary work.
    Cancelled,
    /// A response does not match a pending request.
    StaleEvent,
    /// Request identifiers cannot advance without wrapping.
    SequenceExhausted,
    /// The image requires journal barriers unavailable in this host.
    DurableUnavailable,
    /// A checkpoint or response was paired with another image.
    ImageMismatch,
    /// Checkpoint structure or storage layout is invalid.
    InvalidCheckpoint,
    /// A linked handle failed ownership, generation, or method validation.
    Authority,
}

impl core::fmt::Display for Fault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl core::error::Error for Fault {}

/// Structured parallel join semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Join {
    /// Wait for both branches and pair successful results in source order.
    All,
    /// Preserve the first result after cancelling and cleaning up the loser.
    Race,
}

/// One structured instruction, independent of any source language.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NodeKind<V, E> {
    /// Produce a constant with host-defined control-flow provenance.
    Literal(V),
    /// Return the incoming value unchanged.
    Input,
    /// Read a lexical binding slot.
    Load(u32),
    /// Propagate a failure to the nearest enclosing handler.
    Fail(E),
    /// Host import: effect, pure extension, stream operation, or wait.
    Request(u32),
    /// Serial composition without a native continuation.
    Then {
        /// Entry evaluated with the incoming value.
        first: u32,
        /// Continuation receiving the first result.
        then: u32,
    },
    /// Route ordinary failures to a recovery program; cancellation bypasses it.
    Catch {
        /// Guarded entry.
        body: u32,
        /// Entry receiving the host's failure representation.
        recover: u32,
    },
    /// Cleanup receives the body's input, even when the body fails or cancels.
    Finally {
        /// Guarded entry whose original result is preserved.
        body: u32,
        /// Cleanup entry executed after every cooperative exit.
        cleanup: u32,
    },
    /// Select an entry using the incoming boolean value.
    If {
        /// Entry selected by true.
        yes: u32,
        /// Entry selected by false.
        no: u32,
    },
    /// Evaluate a condition, then pass original input to the selected branch.
    Branch {
        /// Entry producing a boolean decision.
        condition: u32,
        /// Entry selected by true.
        yes: u32,
        /// Entry selected by false.
        no: u32,
    },
    /// Bind a value lexically, restoring any shadowed binding afterward.
    Let {
        /// Binding slot allocated by the compiler.
        slot: u32,
        /// Entry computing the bound value.
        value: u32,
        /// Entry running within the binding's scope.
        body: u32,
    },
    /// Re-evaluate condition on the loop-carried value before each iteration.
    While {
        /// Boolean condition evaluated on the current loop value.
        condition: u32,
        /// Entry computing the next loop value.
        body: u32,
        /// Maximum number of body executions.
        max: u64,
    },
    /// Start two child tasks with isolated copies of lexical bindings.
    Fork {
        /// Left branch entry.
        left: u32,
        /// Right branch entry.
        right: u32,
        /// Result and cancellation policy.
        join: Join,
    },
    /// Call a linked subprogram using the bounded continuation stack.
    Call(u32),
    /// Authorize a context change through a host import before entering body.
    Scope {
        /// Import authorizing a context change.
        import: u32,
        /// Entry evaluated under the authorized context.
        body: u32,
    },
}

/// Instructions use indices; names and paths are resolved by the compiler.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Node<V, E> {
    /// Structured instruction to execute.
    pub kind: NodeKind<V, E>,
    /// Optional continuation receiving a successful result.
    pub next: Option<u32>,
    /// Optional producer slot used by linked graph data dependencies.
    pub save: Option<u32>,
    /// Stable source position, separate from a particular dynamic invocation.
    pub position: u64,
}

impl<V, E> Node<V, E> {
    /// Construct an instruction with no implicit continuation or binding.
    pub const fn new(kind: NodeKind<V, E>, position: u64) -> Self {
        Self {
            kind,
            next: None,
            save: None,
            position,
        }
    }

    /// Change value representation while preserving instruction structure.
    pub fn map_value<W>(&self, map: impl FnOnce(&V) -> W) -> Node<W, E>
    where
        E: Clone,
    {
        match self.try_map_ref(
            |value| Ok::<_, core::convert::Infallible>(map(value)),
            |error| Ok(error.clone()),
        ) {
            Ok(node) => node,
            Err(never) => match never {},
        }
    }

    /// Map borrowed values and errors while preserving instruction structure.
    /// The mapped representation may borrow from this instruction.
    pub fn try_map_ref<'a, W, F, X>(
        &'a self,
        map_value: impl FnOnce(&'a V) -> Result<W, X>,
        map_error: impl FnOnce(&'a E) -> Result<F, X>,
    ) -> Result<Node<W, F>, X> {
        let kind = match &self.kind {
            NodeKind::Literal(value) => NodeKind::Literal(map_value(value)?),
            NodeKind::Input => NodeKind::Input,
            NodeKind::Load(slot) => NodeKind::Load(*slot),
            NodeKind::Fail(error) => NodeKind::Fail(map_error(error)?),
            NodeKind::Request(import) => NodeKind::Request(*import),
            NodeKind::Then { first, then } => NodeKind::Then {
                first: *first,
                then: *then,
            },
            NodeKind::Catch { body, recover } => NodeKind::Catch {
                body: *body,
                recover: *recover,
            },
            NodeKind::Finally { body, cleanup } => NodeKind::Finally {
                body: *body,
                cleanup: *cleanup,
            },
            NodeKind::If { yes, no } => NodeKind::If { yes: *yes, no: *no },
            NodeKind::Branch { condition, yes, no } => NodeKind::Branch {
                condition: *condition,
                yes: *yes,
                no: *no,
            },
            NodeKind::Let { slot, value, body } => NodeKind::Let {
                slot: *slot,
                value: *value,
                body: *body,
            },
            NodeKind::While {
                condition,
                body,
                max,
            } => NodeKind::While {
                condition: *condition,
                body: *body,
                max: *max,
            },
            NodeKind::Fork { left, right, join } => NodeKind::Fork {
                left: *left,
                right: *right,
                join: *join,
            },
            NodeKind::Call(entry) => NodeKind::Call(*entry),
            NodeKind::Scope { import, body } => NodeKind::Scope {
                import: *import,
                body: *body,
            },
        };
        Ok(Node {
            kind,
            next: self.next,
            save: self.save,
            position: self.position,
        })
    }

    /// Transfer values and errors into another representation without cloning.
    pub fn map_owned<W, F>(
        self,
        map_value: impl FnOnce(V) -> W,
        map_error: impl FnOnce(E) -> F,
    ) -> Node<W, F> {
        match self.try_map_owned(
            |value| Ok::<_, core::convert::Infallible>(map_value(value)),
            |error| Ok(map_error(error)),
        ) {
            Ok(node) => node,
            Err(never) => match never {},
        }
    }

    /// Transfer values and errors without cloning, stopping at the first error.
    pub fn try_map_owned<W, F, X>(
        self,
        map_value: impl FnOnce(V) -> Result<W, X>,
        map_error: impl FnOnce(E) -> Result<F, X>,
    ) -> Result<Node<W, F>, X> {
        let kind = match self.kind {
            NodeKind::Literal(value) => NodeKind::Literal(map_value(value)?),
            NodeKind::Input => NodeKind::Input,
            NodeKind::Load(slot) => NodeKind::Load(slot),
            NodeKind::Fail(error) => NodeKind::Fail(map_error(error)?),
            NodeKind::Request(import) => NodeKind::Request(import),
            NodeKind::Then { first, then } => NodeKind::Then { first, then },
            NodeKind::Catch { body, recover } => NodeKind::Catch { body, recover },
            NodeKind::Finally { body, cleanup } => NodeKind::Finally { body, cleanup },
            NodeKind::If { yes, no } => NodeKind::If { yes, no },
            NodeKind::Branch { condition, yes, no } => NodeKind::Branch { condition, yes, no },
            NodeKind::Let { slot, value, body } => NodeKind::Let { slot, value, body },
            NodeKind::While {
                condition,
                body,
                max,
            } => NodeKind::While {
                condition,
                body,
                max,
            },
            NodeKind::Fork { left, right, join } => NodeKind::Fork { left, right, join },
            NodeKind::Call(entry) => NodeKind::Call(entry),
            NodeKind::Scope { import, body } => NodeKind::Scope { import, body },
        };
        Ok(Node {
            kind,
            next: self.next,
            save: self.save,
            position: self.position,
        })
    }
}

/// A zero-copy view of a host-owned image. It can live in read-only flash.
pub struct ProgramImage<'a, V, E> {
    /// Instruction format accepted at admission.
    pub version: u32,
    /// Content identity computed by the compiler, checked when restoring state.
    pub id: [u8; 32],
    /// Immutable instructions, addressed by slice index.
    pub nodes: &'a [Node<V, E>],
    /// Root instruction index.
    pub entry: u32,
    /// Binding slots required by each task.
    pub bindings: usize,
    /// Number of imports the host must resolve.
    pub imports: usize,
    /// Require a host that provides persistent execution barriers.
    pub durable: bool,
}

impl<V, E> ProgramImage<'_, V, E> {
    /// Check every instruction, including unreachable instructions, at admission.
    pub fn validate(&self) -> Result<(), Fault> {
        if self.version != IMAGE_VERSION {
            return Err(Fault::Version);
        }
        self.node(self.entry)?;
        for node in self.nodes {
            node.visit_indices(
                |index| self.node(index).map(|_| ()),
                |index| {
                    if (index as usize) < self.imports {
                        Ok(())
                    } else {
                        Err(Fault::InvalidImport)
                    }
                },
                |index| {
                    if (index as usize) < self.bindings {
                        Ok(())
                    } else {
                        Err(Fault::InvalidBinding)
                    }
                },
            )?;
        }
        Ok(())
    }

    pub(crate) fn node(&self, index: u32) -> Result<&Node<V, E>, Fault> {
        self.nodes.get(index as usize).ok_or(Fault::InvalidNode)
    }
}

/// Value operations supplied by a host. Fixed-capacity values or generational
/// arena references make these operations allocation-free as well.
pub trait Values {
    /// Scalar, fixed-capacity value, arena reference, or host-owned value.
    type Value: Clone;
    /// Error representation carried through structured handlers.
    type Error: Clone;
    /// Construct the host's empty value.
    fn unit(&mut self) -> Self::Value;
    /// Validate and extract a branch condition.
    fn truth(&mut self, value: &Self::Value) -> Result<bool, Self::Error>;
    /// Combine successful parallel results in source order.
    fn pair(&mut self, left: Self::Value, right: Self::Value) -> Result<Self::Value, Self::Error>;
    /// Translate a machine rejection into the host's error representation.
    fn error(&mut self, fault: Fault) -> Self::Error;
    /// Convert a caught failure into input for a recovery program.
    fn error_value(&mut self, error: Self::Error) -> Self::Value;
    /// Preserve control-flow provenance without changing the selected value.
    fn influence(&mut self, value: Self::Value, _control: &Self::Value) -> Self::Value {
        value
    }
    /// Preserve the control dependencies of an entire result, including the
    /// decision to fail. Hosts with provenance-bearing errors override this.
    fn influence_result(
        &mut self,
        result: Result<Self::Value, Self::Error>,
        control: &Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        result.map(|value| self.influence(value, control))
    }
    /// Retain only the provenance needed when a result selects another result
    /// or starts cleanup. The snapshot never becomes the program's payload.
    fn retain_result(&mut self, result: &Result<Self::Value, Self::Error>) -> Self::Value {
        match result {
            Ok(value) => self.retain_control(value),
            Err(error) => {
                let value = self.error_value(error.clone());
                self.retain_control(&value)
            }
        }
    }
    /// Retain only the information needed when this input later influences a
    /// caught failure. The snapshot is used solely as `influence`'s control
    /// argument; it never becomes a program input or a replayed request.
    ///
    /// `influence(value, &snapshot)` must preserve the same provenance as
    /// `influence(value, input)`. Hosts may omit payloads when provenance is
    /// stored separately. The default retains the complete value.
    fn retain_control(&mut self, input: &Self::Value) -> Self::Value {
        input.clone()
    }
}
