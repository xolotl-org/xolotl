//! A shared, bounded continuation arena with constant-time stack operations.

use crate::Fault;

mod mapping;

const NONE: u32 = u32::MAX;

/// A continuation slot in the caller-owned shared frame pool.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Frame<V, E> {
    pub(crate) kind: FrameKind<V, E>,
    pub(crate) previous: u32,
    owner: u32,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum FrameKind<V, E> {
    Vacant,
    Finish(u32),
    Then(u32),
    Catch(u32),
    Finally {
        cleanup: u32,
        input: V,
    },
    Cleaned {
        outcome: Result<V, E>,
    },
    Condition {
        condition: u32,
        body: u32,
        left: u64,
        value: V,
    },
    Iteration {
        condition: u32,
        body: u32,
        left: u64,
    },
    Context(u64),
    Choose {
        yes: u32,
        no: u32,
        input: V,
    },
    Bind {
        slot: u32,
        body: u32,
    },
    Unbind {
        slot: u32,
        previous: Option<V>,
    },
    Continuation {
        node: u32,
        entry: u32,
    },
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Stack {
    pub(crate) top: u32,
    pub(crate) depth: u32,
}

impl Default for Stack {
    fn default() -> Self {
        Self {
            top: NONE,
            depth: 0,
        }
    }
}

/// Shared frame allocation metadata, persisted with tasks and frame slots.
/// Restoration validates ownership, free links and all counters before use.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FramePoolMeta {
    next_unused: u32,
    free_head: u32,
    free_count: u32,
}

impl Default for FramePoolMeta {
    fn default() -> Self {
        Self {
            next_unused: 0,
            free_head: NONE,
            free_count: 0,
        }
    }
}

pub(crate) struct FramePool<'a, V, E> {
    pub(crate) slots: &'a mut [Option<Frame<V, E>>],
    pub(crate) meta: FramePoolMeta,
}

impl<'a, V, E> FramePool<'a, V, E> {
    pub(crate) fn new(slots: &'a mut [Option<Frame<V, E>>]) -> Self {
        slots.fill_with(|| None);
        Self {
            slots,
            meta: FramePoolMeta::default(),
        }
    }

    pub(crate) fn check(&self, stack: &Stack, count: usize, max_depth: usize) -> Result<(), Fault> {
        let depth = (stack.depth as usize)
            .checked_add(count)
            .ok_or(Fault::Frames)?;
        let available =
            self.slots.len() - self.meta.next_unused as usize + self.meta.free_count as usize;
        if depth > max_depth || count > available {
            return Err(Fault::Frames);
        }
        Ok(())
    }

    pub(crate) fn push(
        &mut self,
        task: usize,
        stack: &mut Stack,
        kind: FrameKind<V, E>,
        max_depth: usize,
    ) -> Result<(), Fault> {
        if stack.depth as usize >= max_depth {
            return Err(Fault::Frames);
        }
        let index = if self.meta.free_head == NONE {
            if self.meta.next_unused as usize >= self.slots.len() {
                return Err(Fault::Frames);
            }
            let index = self.meta.next_unused;
            self.meta.next_unused += 1;
            index
        } else {
            let index = self.meta.free_head;
            self.meta.free_head = self.slots[index as usize]
                .as_ref()
                .ok_or(Fault::InvalidCheckpoint)?
                .previous;
            self.meta.free_count -= 1;
            index
        };
        self.slots[index as usize] = Some(Frame {
            kind,
            previous: stack.top,
            owner: task as u32,
        });
        stack.top = index;
        stack.depth += 1;
        Ok(())
    }

    pub(crate) fn pop(&mut self, stack: &mut Stack) -> Option<FrameKind<V, E>> {
        if stack.depth == 0 {
            return None;
        }
        let index = stack.top as usize;
        let frame = self.slots[index].take()?;
        stack.top = frame.previous;
        stack.depth -= 1;
        if index + 1 == self.meta.next_unused as usize {
            self.meta.next_unused -= 1;
            return Some(frame.kind);
        }
        self.slots[index] = Some(Frame {
            kind: FrameKind::Vacant,
            previous: self.meta.free_head,
            owner: NONE,
        });
        self.meta.free_head = index as u32;
        self.meta.free_count += 1;
        Some(frame.kind)
    }
}

pub(crate) fn validate<'a, V, E>(
    slots: &[Option<Frame<V, E>>],
    meta: FramePoolMeta,
    stacks: impl Iterator<Item = &'a Stack>,
    max_depth: usize,
) -> Result<(), Fault> {
    let used = usize::try_from(meta.next_unused).map_err(|_error| Fault::InvalidCheckpoint)?;
    if slots.len() > NONE as usize || used > slots.len() || meta.free_count > meta.next_unused {
        return Err(Fault::InvalidCheckpoint);
    }
    let mut live = 0usize;
    for (owner, stack) in stacks.enumerate() {
        let depth = usize::try_from(stack.depth).map_err(|_error| Fault::InvalidCheckpoint)?;
        if depth > max_depth {
            return Err(Fault::InvalidCheckpoint);
        }
        let mut index = stack.top;
        for _ in 0..depth {
            if index >= meta.next_unused {
                return Err(Fault::InvalidCheckpoint);
            }
            let frame = slots[index as usize]
                .as_ref()
                .ok_or(Fault::InvalidCheckpoint)?;
            if frame.owner != owner as u32 || matches!(frame.kind, FrameKind::Vacant) {
                return Err(Fault::InvalidCheckpoint);
            }
            live = live.checked_add(1).ok_or(Fault::InvalidCheckpoint)?;
            if live > used {
                return Err(Fault::InvalidCheckpoint);
            }
            index = frame.previous;
        }
        if index != NONE {
            return Err(Fault::InvalidCheckpoint);
        }
    }
    let mut index = meta.free_head;
    for _ in 0..meta.free_count {
        if index >= meta.next_unused {
            return Err(Fault::InvalidCheckpoint);
        }
        let frame = slots[index as usize]
            .as_ref()
            .ok_or(Fault::InvalidCheckpoint)?;
        if frame.owner != NONE || !matches!(frame.kind, FrameKind::Vacant) {
            return Err(Fault::InvalidCheckpoint);
        }
        index = frame.previous;
    }
    // Exact list lengths and distinct owners exclude cycles, aliases and orphan slots.
    if index != NONE
        || live + meta.free_count as usize != used
        || slots[used..].iter().any(Option::is_some)
    {
        return Err(Fault::InvalidCheckpoint);
    }
    Ok(())
}
