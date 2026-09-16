//! Persist module ownership, deriving allocator gaps and analysis during restore.

use super::*;
use serde::{Deserialize, Serialize};
use xolotl_core::Checkpoint;

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::executor) struct ArenaSnapshot {
    base: Extents,
    fragments: Vec<FragmentSnapshot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FragmentSnapshot {
    id: [u8; 32],
    entry: u32,
    nodes: Range<usize>,
    imports: Range<usize>,
    bindings: Range<usize>,
}

impl MachineProgram {
    pub(in crate::executor) fn arena_snapshot(&self) -> Option<ArenaSnapshot> {
        self.arena.as_ref().map(|arena| ArenaSnapshot {
            base: arena.base,
            fragments: arena
                .fragments
                .iter()
                .map(|fragment| FragmentSnapshot {
                    id: fragment.id,
                    entry: fragment.entry,
                    nodes: fragment.nodes.clone(),
                    imports: fragment.imports.clone(),
                    bindings: fragment.bindings.clone(),
                })
                .collect(),
        })
    }

    pub(in crate::executor) fn restore_arena(
        &mut self,
        saved: Option<ArenaSnapshot>,
    ) -> Result<(), &'static str> {
        self.image()
            .validate()
            .map_err(|_invalid_image| "invalid checkpoint image")?;
        let Some(saved) = saved else {
            return Ok(());
        };
        if saved.base.nodes == 0 || self.entry as usize >= saved.base.nodes {
            return Err("checkpoint base module has an invalid entry");
        }
        let nodes = RangePool::restore(
            saved.base.nodes,
            self.nodes.len(),
            saved
                .fragments
                .iter()
                .map(|fragment| fragment.nodes.clone()),
        )?;
        let imports = RangePool::restore(
            saved.base.imports,
            self.imports.len(),
            saved
                .fragments
                .iter()
                .map(|fragment| fragment.imports.clone()),
        )?;
        let bindings = RangePool::restore(
            saved.base.bindings,
            self.bindings,
            saved
                .fragments
                .iter()
                .map(|fragment| fragment.bindings.clone()),
        )?;
        self.validate_module(
            &(0..saved.base.nodes),
            &(0..saved.base.imports),
            &(0..saved.base.bindings),
        )?;
        for gap in &nodes.free {
            if self.nodes[gap.clone()].iter().any(|node| {
                !matches!(node.kind, Code::Input)
                    || node.position != 0
                    || node.next.is_some()
                    || node.save.is_some()
            }) {
                return Err("checkpoint code gap contains instructions");
            }
        }
        for gap in &imports.free {
            if self.imports[gap.clone()]
                .iter()
                .any(|import| !matches!(import, Import::Vacant))
            {
                return Err("checkpoint import gap contains bindings");
            }
        }
        let mut fragments = Vec::with_capacity(saved.fragments.len());
        let largest = saved
            .fragments
            .iter()
            .map(|fragment| fragment.nodes.len())
            .max()
            .unwrap_or(0);
        let mut scratch = vec![AnalysisSlot::default(); largest];
        let mut previous = None;
        for fragment in saved.fragments {
            if !fragment.nodes.contains(&(fragment.entry as usize))
                || previous.is_some_and(|entry| entry >= fragment.entry)
            {
                return Err("checkpoint module entries are invalid or unordered");
            }
            previous = Some(fragment.entry);
            self.validate_module(&fragment.nodes, &fragment.imports, &fragment.bindings)?;
            let mut requirements = self
                .image()
                .module_requirements(fragment.entry, fragment.nodes.clone(), &mut scratch)
                .map_err(|_invalid_module| "invalid checkpoint module")?;
            requirements.bindings_per_task = fragment.bindings.len();
            fragments.push(Fragment {
                id: fragment.id,
                entry: fragment.entry,
                nodes: fragment.nodes,
                imports: fragment.imports,
                bindings: fragment.bindings,
                requirements,
                live: false,
            });
        }
        self.arena = Some(Box::new(ProgramArena {
            base: saved.base,
            nodes,
            imports,
            bindings,
            fragments,
        }));
        Ok(())
    }

    fn validate_module(
        &self,
        nodes: &Range<usize>,
        imports: &Range<usize>,
        bindings: &Range<usize>,
    ) -> Result<(), &'static str> {
        let contained = |range: &Range<usize>, index: u32| {
            if range.contains(&(index as usize)) {
                Ok(())
            } else {
                Err("checkpoint instruction crosses a module boundary")
            }
        };
        for node in &self.nodes[nodes.clone()] {
            node.visit_indices(
                |index| contained(nodes, index),
                |index| contained(imports, index),
                |index| contained(bindings, index),
            )?;
        }
        if self.imports[imports.clone()]
            .iter()
            .any(|import| matches!(import, Import::Vacant))
        {
            return Err("checkpoint module contains a vacant import");
        }
        Ok(())
    }

    /// Core validates the machine shape; the host validates retained code ownership.
    pub(in crate::executor) fn validate_arena_checkpoint(
        &self,
        checkpoint: &Checkpoint<'_, TaintedValue, TaintedFailure>,
    ) -> Result<(), Failure> {
        let Some(arena) = &self.arena else {
            if checkpoint.continuations().next().is_some() {
                return Err(machine_error("checkpoint is missing its module arena"));
            }
            return Ok(());
        };
        for index in checkpoint.instruction_indices() {
            let position = arena
                .fragments
                .partition_point(|fragment| fragment.nodes.start <= index as usize);
            if index as usize >= arena.base.nodes
                && !position.checked_sub(1).is_some_and(|position| {
                    arena.fragments[position].nodes.contains(&(index as usize))
                })
            {
                return Err(machine_error("checkpoint retains retired module code"));
            }
        }
        for (_, entry) in checkpoint.continuations() {
            if arena
                .fragments
                .binary_search_by_key(&entry, |fragment| fragment.entry)
                .is_err()
            {
                return Err(machine_error(
                    "checkpoint has an unknown module continuation",
                ));
            }
        }
        for gap in &arena.bindings.free {
            for row in checkpoint
                .bindings
                .chunks(checkpoint.meta.limits.bindings_per_task.max(1))
            {
                if row
                    .get(gap.clone())
                    .is_none_or(|slots| slots.iter().any(Option::is_some))
                {
                    return Err(machine_error("checkpoint retains retired module bindings"));
                }
            }
        }
        Ok(())
    }
}

impl RangePool {
    fn restore(
        base: usize,
        end: usize,
        ranges: impl Iterator<Item = Range<usize>>,
    ) -> Result<Self, &'static str> {
        if base > end || end > u32::MAX as usize {
            return Err("checkpoint module arena exceeds its address space");
        }
        let mut ranges: Vec<_> = ranges.collect();
        ranges.sort_unstable_by_key(|range| range.start);
        let mut previous = base;
        let mut free = Vec::new();
        for range in ranges {
            if range == (0..0) {
                continue;
            }
            if range.start >= range.end || range.start < previous || range.end > end {
                return Err("checkpoint module ranges overlap or exceed their arena");
            }
            if previous < range.start {
                free.push(previous..range.start);
            }
            previous = range.end;
        }
        if previous != end {
            return Err("checkpoint module arena has an unowned tail");
        }
        Ok(Self { end, free })
    }
}
