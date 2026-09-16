//! Borrow program addresses without exposing the private task or frame layouts.

use super::{Checkpoint, Frame, FrameKind, State};

impl<V, E> Checkpoint<'_, V, E> {
    /// Call sites and entries of host-loaded continuations still owned by this
    /// checkpoint. Validate the checkpoint before relying on this view.
    pub fn continuations(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        continuations(self.frames)
    }

    /// Every instruction address retained by a task or continuation, including
    /// cleanup and branches that have not run yet. A host with a reclaimable code
    /// arena must keep their containing modules until these references disappear.
    /// Iteration uses bounded stack storage and does not copy values.
    pub fn instruction_indices(&self) -> impl Iterator<Item = u32> + '_ {
        let tasks = self.tasks.iter().filter_map(|task| match task.state {
            State::Ready => Some(task.pc),
            State::Waiting { node, .. } | State::Joining { node, .. } => Some(node),
            State::Free | State::Returning(_) | State::Done(_) => None,
        });
        let frames = self.frames.iter().flat_map(|frame| {
            let indices = match frame.as_ref().map(|frame| &frame.kind) {
                Some(FrameKind::Continuation { node, entry }) => [Some(*node), Some(*entry)],
                Some(
                    FrameKind::Finish(node)
                    | FrameKind::Then(node)
                    | FrameKind::Catch(node)
                    | FrameKind::Finally { cleanup: node, .. }
                    | FrameKind::Bind { body: node, .. },
                ) => [Some(*node), None],
                Some(
                    FrameKind::Condition {
                        condition, body, ..
                    }
                    | FrameKind::Iteration {
                        condition, body, ..
                    },
                ) => [Some(*condition), Some(*body)],
                Some(FrameKind::Choose { yes, no, .. }) => [Some(*yes), Some(*no)],
                _ => [None, None],
            };
            indices.into_iter().flatten()
        });
        tasks.chain(frames)
    }
}

pub(super) fn continuations<V, E>(
    frames: &[Option<Frame<V, E>>],
) -> impl Iterator<Item = (u32, u32)> + '_ {
    frames
        .iter()
        .filter_map(|frame| match &frame.as_ref()?.kind {
            FrameKind::Continuation { node, entry } => Some((*node, *entry)),
            _ => None,
        })
}
