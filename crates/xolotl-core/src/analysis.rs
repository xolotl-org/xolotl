//! Structural resource bounds computed with caller-owned scratch storage.

use crate::{Fault, Node, NodeKind, ProgramImage};

/// Conservative peak storage for the instructions reachable from an image entry.
///
/// `None` means a finite bound was not established, because of recursion or
/// arithmetic overflow. Hosts must impose execution capacities in that case.
/// These bounds do not cover programs appended by [`crate::HostEvent::Continue`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceRequirements {
    /// Simultaneously occupied task slots, including suspended parents.
    pub tasks: Option<usize>,
    /// Largest continuation stack needed by any one task.
    pub frames_per_task: Option<usize>,
    /// Total simultaneous continuations across all tasks in a shared frame pool.
    pub frames: Option<usize>,
    /// Lexical storage declared by the image, including saved graph outputs.
    pub bindings_per_task: usize,
}

/// One temporary analysis slot per instruction. Reusable after analysis returns.
///
/// The traversal uses these slots as its work stack, so long instruction chains
/// do not consume the native call stack or require an allocator.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnalysisSlot {
    visit: Visit,
    parent: Option<usize>,
    edge: usize,
    usage: Usage,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Visit {
    #[default]
    Unseen,
    Active,
    Complete,
}

#[derive(Clone, Copy, Debug)]
struct Usage {
    own_frames: Option<usize>,
    child_frames: Option<usize>,
    tasks: Option<usize>,
    frames: Option<usize>,
}

impl Default for Usage {
    fn default() -> Self {
        Self {
            own_frames: Some(0),
            child_frames: Some(0),
            tasks: Some(1),
            frames: Some(0),
        }
    }
}

fn maximum(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    Some(a?.max(b?))
}

fn sum(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    a?.checked_add(b?)
}

#[derive(Clone, Copy)]
struct Edge {
    entry: u32,
    frames: usize,
    fork: bool,
}

fn edges<V, E>(node: &Node<V, E>) -> [Option<Edge>; 4] {
    let local = |entry, frames| {
        Some(Edge {
            entry,
            frames,
            fork: false,
        })
    };
    let mut edges = [None; 4];
    match &node.kind {
        NodeKind::Then { first, then } => {
            edges[0] = local(*first, 2);
            edges[1] = local(*then, 1);
        }
        NodeKind::Catch { body, recover } => {
            edges[0] = local(*body, 2);
            edges[1] = local(*recover, 1);
        }
        NodeKind::Finally { body, cleanup } => {
            edges[0] = local(*body, 2);
            edges[1] = local(*cleanup, 2);
        }
        NodeKind::If { yes, no } => {
            edges[0] = local(*yes, 1);
            edges[1] = local(*no, 1);
        }
        NodeKind::Branch { condition, yes, no } => {
            edges[0] = local(*condition, 2);
            edges[1] = local(*yes, 1);
            edges[2] = local(*no, 1);
        }
        NodeKind::Let { value, body, .. }
        | NodeKind::While {
            condition: value,
            body,
            ..
        } => {
            edges[0] = local(*value, 2);
            edges[1] = local(*body, 2);
        }
        NodeKind::Fork { left, right, .. } => {
            edges[0] = Some(Edge {
                entry: *left,
                frames: 0,
                fork: true,
            });
            edges[1] = Some(Edge {
                entry: *right,
                frames: 0,
                fork: true,
            });
        }
        NodeKind::Call(entry) => edges[0] = local(*entry, 1),
        NodeKind::Scope { body, .. } => edges[0] = local(*body, 2),
        NodeKind::Literal(_)
        | NodeKind::Input
        | NodeKind::Load(_)
        | NodeKind::Fail(_)
        | NodeKind::Request(_) => {}
    }
    edges[3] = node.next.and_then(|entry| local(entry, 0));
    edges
}

impl<V, E> ProgramImage<'_, V, E> {
    /// Validate the image and compute peak storage in linear time and scratch space.
    ///
    /// Provide at least `nodes.len()` default-initialized slots. Existing scratch
    /// contents are reset. Sequences and mutually exclusive branches share
    /// capacities; fork branches contribute simultaneous task usage. Child tasks
    /// start with empty stacks, independent of their suspended parent's stack.
    ///
    /// Reachable cycles require a host-selected frame capacity. If forks are also
    /// reachable, task capacity likewise remains a host choice. Unreachable code
    /// is validated but does not inflate these two bounds.
    pub fn resource_requirements(
        &self,
        scratch: &mut [AnalysisSlot],
    ) -> Result<ResourceRequirements, Fault> {
        self.module_requirements(self.entry, 0..self.nodes.len(), scratch)
    }

    /// Analyze one independently linked module within an instruction arena.
    /// Every code reference must stay in `nodes`; imports and bindings use the
    /// containing image's address space. Scratch needs one slot per module
    /// instruction. Other modules are neither scanned nor copied.
    pub fn module_requirements(
        &self,
        entry: u32,
        nodes: core::ops::Range<usize>,
        scratch: &mut [AnalysisSlot],
    ) -> Result<ResourceRequirements, Fault> {
        if self.version != crate::IMAGE_VERSION {
            return Err(Fault::Version);
        }
        let module = self.nodes.get(nodes.clone()).ok_or(Fault::InvalidNode)?;
        if !nodes.contains(&(entry as usize)) {
            return Err(Fault::InvalidNode);
        }
        for instruction in module {
            instruction.visit_indices(
                |index| {
                    nodes
                        .contains(&(index as usize))
                        .then_some(())
                        .ok_or(Fault::InvalidNode)
                },
                |index| {
                    ((index as usize) < self.imports)
                        .then_some(())
                        .ok_or(Fault::InvalidImport)
                },
                |index| {
                    ((index as usize) < self.bindings)
                        .then_some(())
                        .ok_or(Fault::InvalidBinding)
                },
            )?;
        }
        let scratch = scratch
            .get_mut(..module.len())
            .ok_or(Fault::AnalysisCapacity)?;
        scratch.fill(AnalysisSlot::default());
        let mut current = entry as usize - nodes.start;
        scratch[current].visit = Visit::Active;
        let mut cyclic = false;
        let mut forks = false;
        loop {
            let node = &module[current];
            let edges = edges(node);
            forks |= matches!(node.kind, NodeKind::Fork { .. });
            if scratch[current].edge < edges.len() {
                let edge = edges[scratch[current].edge];
                scratch[current].edge += 1;
                if let Some(edge) = edge {
                    let child = edge.entry as usize - nodes.start;
                    match scratch[child].visit {
                        Visit::Unseen => {
                            scratch[child].visit = Visit::Active;
                            scratch[child].parent = Some(current);
                            current = child;
                        }
                        Visit::Active => cyclic = true,
                        Visit::Complete => {}
                    }
                }
                continue;
            }

            let mut usage = Usage::default();
            let mut fork_tasks = Some(1);
            let mut fork_frames = Some(0);
            for edge in edges.into_iter().flatten() {
                let child = scratch[edge.entry as usize - nodes.start];
                let child = if child.visit == Visit::Active {
                    Usage {
                        own_frames: None,
                        child_frames: None,
                        frames: None,
                        ..Usage::default()
                    }
                } else {
                    child.usage
                };
                if edge.fork {
                    fork_tasks = sum(fork_tasks, child.tasks);
                    fork_frames = sum(fork_frames, child.frames);
                    usage.child_frames = maximum(
                        usage.child_frames,
                        maximum(child.own_frames, child.child_frames),
                    );
                } else {
                    usage.own_frames =
                        maximum(usage.own_frames, sum(Some(edge.frames), child.own_frames));
                    usage.child_frames = maximum(usage.child_frames, child.child_frames);
                    usage.tasks = maximum(usage.tasks, child.tasks);
                    usage.frames = maximum(usage.frames, sum(Some(edge.frames), child.frames));
                }
            }
            usage.tasks = maximum(usage.tasks, fork_tasks);
            usage.frames = maximum(usage.frames, fork_frames);
            scratch[current].usage = usage;
            scratch[current].visit = Visit::Complete;
            match scratch[current].parent {
                Some(parent) => current = parent,
                None => {
                    return Ok(ResourceRequirements {
                        tasks: if cyclic && forks { None } else { usage.tasks },
                        frames_per_task: if cyclic {
                            None
                        } else {
                            maximum(usage.own_frames, usage.child_frames)
                        },
                        bindings_per_task: self.bindings,
                        frames: if cyclic { None } else { usage.frames },
                    });
                }
            }
        }
    }
}
