//! Link and retire continuations without moving live code or binding addresses.

use super::*;
use std::ops::Range;
use xolotl_core::Execution;

#[cfg(feature = "durable")]
mod checkpoint;
#[cfg(feature = "durable")]
pub(in crate::executor) use checkpoint::ArenaSnapshot;

#[derive(Clone)]
pub(super) struct ProgramArena {
    #[cfg(feature = "durable")]
    base: Extents,
    nodes: RangePool,
    imports: RangePool,
    bindings: RangePool,
    fragments: Vec<Fragment>,
}

#[derive(Clone)]
struct Fragment {
    #[cfg(feature = "durable")]
    id: [u8; 32],
    entry: u32,
    nodes: Range<usize>,
    imports: Range<usize>,
    bindings: Range<usize>,
    requirements: ResourceRequirements,
    live: bool,
}

#[cfg(feature = "durable")]
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Extents {
    nodes: usize,
    imports: usize,
    bindings: usize,
}

/// Sorted, coalescing gaps. Empty and tail allocations do not allocate metadata.
#[derive(Clone)]
struct RangePool {
    end: usize,
    free: Vec<Range<usize>>,
}

impl RangePool {
    fn new(end: usize) -> Self {
        Self {
            end,
            free: Vec::new(),
        }
    }

    fn reserve(&mut self, count: usize, limit: usize) -> Option<Range<usize>> {
        if count == 0 {
            return Some(0..0);
        }
        let gap = self
            .free
            .iter()
            .enumerate()
            .filter(|(_, gap)| gap.len() >= count)
            .min_by_key(|(_, gap)| gap.len())
            .map(|(index, _)| index);
        if let Some(index) = gap {
            let start = self.free[index].start;
            self.free[index].start += count;
            if self.free[index].is_empty() {
                self.free.remove(index);
            }
            return Some(start..start + count);
        }
        let end = self.end.checked_add(count).filter(|end| *end <= limit)?;
        let range = self.end..end;
        self.end = end;
        Some(range)
    }

    fn release(&mut self, mut range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        let mut index = self.free.partition_point(|gap| gap.start < range.start);
        if index > 0 && self.free[index - 1].end == range.start {
            index -= 1;
            range.start = self.free.remove(index).start;
        }
        if index < self.free.len() && range.end == self.free[index].start {
            range.end = self.free.remove(index).end;
        }
        if range.end == self.end {
            self.end = range.start;
        } else {
            self.free.insert(index, range);
        }
    }
}

impl MachineProgram {
    pub(in super::super) fn expansion_requirements(
        &self,
        entry: u32,
    ) -> Result<ResourceRequirements, Failure> {
        self.arena
            .as_ref()
            .and_then(|arena| {
                arena
                    .fragments
                    .binary_search_by_key(&entry, |fragment| fragment.entry)
                    .ok()
                    .map(|index| arena.fragments[index].requirements)
            })
            .ok_or_else(|| machine_error("unknown continuation"))
    }

    pub(in super::super) fn append(
        &mut self,
        graph: &ExecutionGraph,
        max_instructions: usize,
        max_bindings: usize,
    ) -> Result<u32, Failure> {
        // Lower and analyze independently, before reserving space in the live image.
        let fragment = Self::lower(graph, max_instructions, max_bindings)?;
        self.append_fragment(fragment, max_instructions, max_bindings)
    }

    pub(in super::super) fn load(
        &mut self,
        program: PreparedProgram,
        max_instructions: usize,
        max_bindings: usize,
    ) -> Result<u32, Failure> {
        if program.inner.durable && !self.durable {
            return Err(machine_error("a durable module requires a durable caller"));
        }
        if program.inner.arena.is_some() {
            return Err(machine_error(
                "a loaded module must be an independent program",
            ));
        }
        if program.inner.nodes.len() > max_instructions {
            return Err(machine_error("instruction capacity exceeded"));
        }
        if program.inner.bindings > max_bindings {
            return Err(machine_error("binding capacity exceeded"));
        }
        self.append_fragment(
            Arc::unwrap_or_clone(program.inner),
            max_instructions,
            max_bindings,
        )
    }

    fn append_fragment(
        &mut self,
        mut fragment: Self,
        max_instructions: usize,
        max_bindings: usize,
    ) -> Result<u32, Failure> {
        let requirements = fragment.requirements()?;
        // Cache the base requirements before any fragment becomes reachable by the host.
        self.requirements()?;
        let arena = self.arena.get_or_insert_with(|| {
            Box::new(ProgramArena {
                #[cfg(feature = "durable")]
                base: Extents {
                    nodes: self.nodes.len(),
                    imports: self.imports.len(),
                    bindings: self.bindings,
                },
                nodes: RangePool::new(self.nodes.len()),
                imports: RangePool::new(self.imports.len()),
                bindings: RangePool::new(self.bindings),
                fragments: Vec::new(),
            })
        });
        let nodes = arena
            .nodes
            .reserve(
                fragment.nodes.len(),
                max_instructions.min(u32::MAX as usize),
            )
            .ok_or_else(|| machine_error("instruction capacity exceeded"))?;
        let Some(imports) = arena.imports.reserve(
            fragment.imports.len(),
            max_instructions.min(u32::MAX as usize),
        ) else {
            arena.nodes.release(nodes);
            return Err(machine_error("import capacity exceeded"));
        };
        let Some(bindings) = arena
            .bindings
            .reserve(fragment.bindings, max_bindings.min(u32::MAX as usize))
        else {
            arena.nodes.release(nodes);
            arena.imports.release(imports);
            return Err(machine_error("binding capacity exceeded"));
        };
        let entry = fragment.entry + nodes.start as u32;
        for node in &mut fragment.nodes {
            relocate(
                node,
                nodes.start as u32,
                imports.start as u32,
                bindings.start as u32,
            );
        }
        self.nodes
            .resize_with(arena.nodes.end, || Instruction::new(Code::Input, 0));
        self.imports
            .resize_with(arena.imports.end, || Import::Vacant);
        for (target, node) in self.nodes[nodes.clone()].iter_mut().zip(fragment.nodes) {
            *target = node;
        }
        for (target, import) in self.imports[imports.clone()]
            .iter_mut()
            .zip(fragment.imports)
        {
            *target = import;
        }
        self.bindings = arena.bindings.end;
        let index = arena
            .fragments
            .partition_point(|fragment| fragment.entry < entry);
        arena.fragments.insert(
            index,
            Fragment {
                #[cfg(feature = "durable")]
                id: fragment.id,
                entry,
                nodes,
                imports,
                bindings,
                requirements,
                live: false,
            },
        );
        Ok(entry)
    }

    pub(in super::super) fn reclaim(
        &mut self,
        execution: &mut Execution<'_, TaintedValue, TaintedFailure>,
    ) -> Result<(), Failure> {
        let Some(arena) = &mut self.arena else {
            return Ok(());
        };
        if arena.fragments.is_empty() {
            return Ok(());
        }
        for fragment in &mut arena.fragments {
            fragment.live = false;
        }
        // Fragments cannot link directly to other fragments. Each invocation stays
        // rooted in its continuation until its nested calls and cleanup finish.
        for entry in execution.continuation_entries() {
            let index = arena
                .fragments
                .binary_search_by_key(&entry, |fragment| fragment.entry)
                .map_err(|_index| machine_error("unknown continuation"))?;
            arena.fragments[index].live = true;
        }
        for index in (0..arena.fragments.len()).rev() {
            if !arena.fragments[index].live {
                execution
                    .clear_bindings(arena.fragments[index].bindings.clone())
                    .map_err(|error| machine_error(format!("reclaiming bindings: {error:?}")))?;
                Self::release_fragment(arena, index, &mut self.nodes, &mut self.imports);
            }
        }
        self.bindings = arena.bindings.end;
        Ok(())
    }

    /// Roll back a fragment that never entered an execution continuation.
    pub(in super::super) fn discard(&mut self, entry: u32) {
        if let Some(arena) = &mut self.arena
            && let Ok(index) = arena
                .fragments
                .binary_search_by_key(&entry, |fragment| fragment.entry)
        {
            Self::release_fragment(arena, index, &mut self.nodes, &mut self.imports);
            self.bindings = arena.bindings.end;
        }
    }

    fn release_fragment(
        arena: &mut ProgramArena,
        index: usize,
        nodes: &mut Vec<Instruction<TaintedValue, TaintedFailure>>,
        imports: &mut Vec<Import>,
    ) {
        let fragment = arena.fragments.remove(index);
        // Vacancies remain valid image entries while later fragments are still active.
        nodes[fragment.nodes.clone()].fill_with(|| Instruction::new(Code::Input, 0));
        imports[fragment.imports.clone()].fill_with(|| Import::Vacant);
        arena.nodes.release(fragment.nodes);
        arena.imports.release(fragment.imports);
        arena.bindings.release(fragment.bindings);
        nodes.truncate(arena.nodes.end);
        imports.truncate(arena.imports.end);
    }
}

fn relocate(
    node: &mut Instruction<TaintedValue, TaintedFailure>,
    code: u32,
    imports: u32,
    bindings: u32,
) {
    if let Some(next) = &mut node.next {
        *next += code;
    }
    if let Some(save) = &mut node.save {
        *save += bindings;
    }
    match &mut node.kind {
        Code::Input | Code::Literal(_) | Code::Fail(_) => {}
        Code::Load(slot) => *slot += bindings,
        Code::Request(import) => *import += imports,
        Code::Call(entry) => *entry += code,
        Code::Then { first, then } => {
            *first += code;
            *then += code;
        }
        Code::Catch { body, recover } => {
            *body += code;
            *recover += code;
        }
        Code::Finally { body, cleanup } => {
            *body += code;
            *cleanup += code;
        }
        Code::If { yes, no } => {
            *yes += code;
            *no += code;
        }
        Code::Branch { condition, yes, no } => {
            *condition += code;
            *yes += code;
            *no += code;
        }
        Code::Let { slot, value, body } => {
            *slot += bindings;
            *value += code;
            *body += code;
        }
        Code::While {
            condition, body, ..
        } => {
            *condition += code;
            *body += code;
        }
        Code::Fork { left, right, .. } => {
            *left += code;
            *right += code;
        }
        Code::Scope { import, body } => {
            *import += imports;
            *body += code;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use xolotl_graph::{DoNode, compile_do};
    use xolotl_types::Value;

    #[test]
    fn all_release_orders_coalesce_and_recover_the_original_capacity() -> anyhow::Result<()> {
        fn release_all(pool: RangePool, active: Vec<Range<usize>>) -> anyhow::Result<()> {
            let expected_end = active.iter().map(|range| range.end).max().unwrap_or(2);
            ensure!(pool.end == expected_end);
            ensure!(pool.free.windows(2).all(|pair| pair[0].end < pair[1].start));
            let mut occupied = vec![false; pool.end];
            occupied[..2].fill(true);
            for range in active.iter().chain(&pool.free) {
                for slot in &mut occupied[range.clone()] {
                    ensure!(!*slot);
                    *slot = true;
                }
            }
            ensure!(occupied.into_iter().all(|slot| slot));
            if active.is_empty() {
                let mut pool = pool;
                ensure!(pool.reserve(10, 12) == Some(2..12));
                return Ok(());
            }
            for index in 0..active.len() {
                let mut next = pool.clone();
                let mut remaining = active.clone();
                next.release(remaining.remove(index));
                release_all(next, remaining)?;
            }
            Ok(())
        }
        let mut pool = RangePool::new(2);
        let active = [1, 4, 2, 3]
            .into_iter()
            .map(|count| pool.reserve(count, 12).context("reservation failed"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        release_all(pool, active)
    }

    #[test]
    fn gaps_split_and_failed_reservations_preserve_capacity() -> anyhow::Result<()> {
        let mut pool = RangePool::new(2);
        let first = pool.reserve(4, 10).context("first")?;
        let second = pool.reserve(4, 10).context("second")?;
        pool.release(first);
        ensure!(pool.reserve(5, 10).is_none());
        ensure!(pool.reserve(usize::MAX, usize::MAX).is_none());
        let small = pool.reserve(1, 10).context("small")?;
        let rest = pool.reserve(3, 10).context("rest")?;
        ensure!(small == (2..3) && rest == (3..6));
        pool.release(rest);
        pool.release(second);
        pool.release(small);
        ensure!(pool.end == 2 && pool.free.is_empty());
        ensure!(pool.reserve(0, 0) == Some(0..0));
        Ok(())
    }

    fn fragment(value: i64) -> anyhow::Result<ExecutionGraph> {
        Ok(compile_do(&DoNode::r#let(
            "value",
            DoNode::pure(Value::integer(value)),
            DoNode::use_("value").and_then(StepRef::new("echo")),
        ))?)
    }

    #[test]
    fn reuse_preserves_live_code_and_module_local_positions() -> anyhow::Result<()> {
        let mut program = MachineProgram::new(
            &compile_do(&DoNode::pure(Value::null()))?,
            &crate::ExecutionConfig::default(),
        )?;
        let first = program.append(&fragment(11)?, 7, 2)?;
        let second = program.append(&fragment(22)?, 7, 2)?;
        let live = program.nodes[second as usize..].to_vec();
        let position = program.nodes[first as usize].position;
        program.discard(first);
        ensure!(
            program.nodes[first as usize..second as usize]
                .iter()
                .all(|node| {
                    matches!(node.kind, Code::Input) && node.next.is_none() && node.save.is_none()
                })
        );
        ensure!(matches!(program.imports[0], Import::Vacant));
        program.image().validate()?;
        let third = program.append(&fragment(33)?, 7, 2)?;
        ensure!(third == first);
        ensure!(program.nodes[second as usize..] == live);
        ensure!(program.nodes[third as usize].position == position);
        ensure!(program.bindings == 2 && program.imports.len() == 2);
        program.image().validate()?;
        program.discard(second);
        program.discard(third);
        ensure!(program.nodes.len() == 1 && program.imports.is_empty() && program.bindings == 0);
        ensure!(
            program
                .arena
                .as_ref()
                .context("missing arena")?
                .fragments
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn rejected_binding_reservation_releases_code_and_import_reservations() -> anyhow::Result<()> {
        let mut program = MachineProgram::new(
            &compile_do(&DoNode::pure(Value::null()))?,
            &crate::ExecutionConfig::default(),
        )?;
        let first = program.append(&fragment(11)?, 7, 1)?;
        let code = program.nodes.clone();
        let error = program.append(&fragment(22)?, 7, 1);
        ensure!(
            matches!(error, Err(Failure::PolicyViolation { detail, .. }) if detail.contains("binding capacity"))
        );
        ensure!(program.nodes == code);
        let arena = program.arena.as_ref().context("missing arena")?;
        ensure!(arena.nodes.end == program.nodes.len());
        ensure!(arena.imports.end == program.imports.len());
        ensure!(arena.bindings.end == program.bindings && arena.fragments.len() == 1);
        program.discard(first);
        ensure!(program.append(&fragment(33)?, 4, 1)? == first);
        program.image().validate()?;
        Ok(())
    }

    #[test]
    fn module_reuse_does_not_consume_a_cumulative_source_position_namespace() -> anyhow::Result<()>
    {
        use xolotl_graph::portable::{Expression, Program, Transform};
        let base = xolotl_graph::compile_do_at(&DoNode::pure(Value::null()), u32::MAX)?;
        let mut program = MachineProgram::new(&base, &crate::ExecutionConfig::default())?;
        let prepared = PreparedProgram::new(
            &Program::new(Expression::Transform {
                operation: Transform::Add { value: 1 },
            })
            .compile()?,
        )?;
        for _ in 0..4096 {
            let entry = program.load(prepared.clone(), 2, 0)?;
            ensure!(entry == 1 && program.nodes[entry as usize].position == 0);
            ensure!(program.nodes[0].position == u64::from(u32::MAX));
            program.image().validate()?;
            program.discard(entry);
            ensure!(program.nodes.len() == 1 && program.imports.is_empty());
        }
        ensure!(Arc::strong_count(&prepared.inner) == 1);
        ensure!(
            program
                .arena
                .as_ref()
                .context("missing arena")?
                .fragments
                .is_empty()
        );
        Ok(())
    }
}
