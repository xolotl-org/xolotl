//! Value adaptation keeps frame ownership and stack links opaque to hosts.

use super::{Frame, FrameKind};

impl<V, E> Frame<V, E> {
    /// Map borrowed values and errors without exposing continuation internals.
    /// The mapped representation may borrow from this frame.
    pub fn try_map_ref<'a, W, F, X>(
        &'a self,
        map_value: impl FnOnce(&'a V) -> Result<W, X>,
        map_error: impl FnOnce(&'a E) -> Result<F, X>,
    ) -> Result<Frame<W, F>, X> {
        let kind = match &self.kind {
            FrameKind::Vacant => FrameKind::Vacant,
            FrameKind::Finish(node) => FrameKind::Finish(*node),
            FrameKind::Then(node) => FrameKind::Then(*node),
            FrameKind::Catch(node) => FrameKind::Catch(*node),
            FrameKind::Finally { cleanup, input } => FrameKind::Finally {
                cleanup: *cleanup,
                input,
            },
            FrameKind::Cleaned { outcome } => FrameKind::Cleaned {
                outcome: outcome.as_ref(),
            },
            FrameKind::Condition {
                condition,
                body,
                left,
                value,
            } => FrameKind::Condition {
                condition: *condition,
                body: *body,
                left: *left,
                value,
            },
            FrameKind::Iteration {
                condition,
                body,
                left,
            } => FrameKind::Iteration {
                condition: *condition,
                body: *body,
                left: *left,
            },
            FrameKind::Context(context) => FrameKind::Context(*context),
            FrameKind::Choose { yes, no, input } => FrameKind::Choose {
                yes: *yes,
                no: *no,
                input,
            },
            FrameKind::Bind { slot, body } => FrameKind::Bind {
                slot: *slot,
                body: *body,
            },
            FrameKind::Unbind { slot, previous } => FrameKind::Unbind {
                slot: *slot,
                previous: previous.as_ref(),
            },
            FrameKind::Continuation { node, entry } => FrameKind::Continuation {
                node: *node,
                entry: *entry,
            },
        };
        Frame {
            kind,
            previous: self.previous,
            owner: self.owner,
        }
        .try_map_owned(map_value, map_error)
    }

    /// Transfer values and errors while retaining frame ownership and stack links.
    /// On failure, the consumed frame is released.
    pub fn try_map_owned<W, F, X>(
        self,
        map_value: impl FnOnce(V) -> Result<W, X>,
        map_error: impl FnOnce(E) -> Result<F, X>,
    ) -> Result<Frame<W, F>, X> {
        let kind = match self.kind {
            FrameKind::Vacant => FrameKind::Vacant,
            FrameKind::Finish(node) => FrameKind::Finish(node),
            FrameKind::Then(node) => FrameKind::Then(node),
            FrameKind::Catch(node) => FrameKind::Catch(node),
            FrameKind::Finally { cleanup, input } => FrameKind::Finally {
                cleanup,
                input: map_value(input)?,
            },
            FrameKind::Cleaned { outcome } => FrameKind::Cleaned {
                outcome: match outcome {
                    Ok(value) => Ok(map_value(value)?),
                    Err(error) => Err(map_error(error)?),
                },
            },
            FrameKind::Condition {
                condition,
                body,
                left,
                value,
            } => FrameKind::Condition {
                condition,
                body,
                left,
                value: map_value(value)?,
            },
            FrameKind::Iteration {
                condition,
                body,
                left,
            } => FrameKind::Iteration {
                condition,
                body,
                left,
            },
            FrameKind::Context(context) => FrameKind::Context(context),
            FrameKind::Choose { yes, no, input } => FrameKind::Choose {
                yes,
                no,
                input: map_value(input)?,
            },
            FrameKind::Bind { slot, body } => FrameKind::Bind { slot, body },
            FrameKind::Unbind { slot, previous } => FrameKind::Unbind {
                slot,
                previous: previous.map(map_value).transpose()?,
            },
            FrameKind::Continuation { node, entry } => FrameKind::Continuation { node, entry },
        };
        Ok(Frame {
            kind,
            previous: self.previous,
            owner: self.owner,
        })
    }
}
