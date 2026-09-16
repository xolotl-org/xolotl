//! Representation changes preserve every scheduler and continuation field.

use super::{State, Task};

impl<V, E> Task<V, E> {
    /// Map borrowed values and errors, preserving task state without allocating.
    /// The mapped representation may borrow from this task.
    pub fn try_map_ref<'a, W, F, X>(
        &'a self,
        map_value: impl FnMut(&'a V) -> Result<W, X>,
        map_error: impl FnMut(&'a E) -> Result<F, X>,
    ) -> Result<Task<W, F>, X> {
        let state = match &self.state {
            State::Free => State::Free,
            State::Ready => State::Ready,
            State::Waiting { ticket, node } => State::Waiting {
                ticket: *ticket,
                node: *node,
            },
            State::Joining {
                left,
                right,
                join,
                node,
            } => State::Joining {
                left: *left,
                right: *right,
                join: *join,
                node: *node,
            },
            State::Returning(outcome) => State::Returning(outcome.as_ref()),
            State::Done(outcome) => State::Done(outcome.as_ref()),
        };
        Task {
            state,
            pc: self.pc,
            input: self.input.as_ref(),
            stack: self.stack,
            context: self.context,
            parent: self.parent,
            cleaning: self.cleaning,
            cancelled: self.cancelled,
        }
        .try_map_owned(map_value, map_error)
    }

    /// Transfer values and errors into another task representation without cloning.
    /// On failure, the consumed task and any mapped fields are released.
    pub fn try_map_owned<W, F, X>(
        self,
        mut map_value: impl FnMut(V) -> Result<W, X>,
        mut map_error: impl FnMut(E) -> Result<F, X>,
    ) -> Result<Task<W, F>, X> {
        let mut outcome = |result| match result {
            Ok(value) => map_value(value).map(Ok),
            Err(error) => map_error(error).map(Err),
        };
        let state = match self.state {
            State::Free => State::Free,
            State::Ready => State::Ready,
            State::Waiting { ticket, node } => State::Waiting { ticket, node },
            State::Joining {
                left,
                right,
                join,
                node,
            } => State::Joining {
                left,
                right,
                join,
                node,
            },
            State::Returning(result) => State::Returning(outcome(result)?),
            State::Done(result) => State::Done(outcome(result)?),
        };
        Ok(Task {
            state,
            pc: self.pc,
            input: self.input.map(map_value).transpose()?,
            stack: self.stack,
            context: self.context,
            parent: self.parent,
            cleaning: self.cleaning,
            cancelled: self.cancelled,
        })
    }
}
