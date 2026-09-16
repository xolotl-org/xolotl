use super::*;
use anyhow::{Context, ensure};
use xolotl_graph::portable::{Expression as E, Program, Transform};

fn prepared(body: E) -> anyhow::Result<PreparedProgram> {
    Ok(PreparedProgram::from_compiled(
        Program::new(body).compile()?,
    )?)
}

#[test]
fn restored_module_ranges_reuse_holes_and_reclaim_to_the_base() -> anyhow::Result<()> {
    let mut program = Arc::unwrap_or_clone(prepared(E::Input)?.inner);
    let loaded = prepared(E::Let {
        name: "input".into(),
        value: Box::new(E::Input),
        body: Box::new(E::Transform {
            operation: Transform::Add { value: 1 },
        }),
    })?;
    let code_limit = program.nodes.len() + 2 * loaded.inner.nodes.len();
    let first = program.load(loaded.clone(), code_limit, 2)?;
    let second = program.load(loaded.clone(), code_limit, 2)?;
    let second_code = program.nodes[second as usize..].to_vec();
    program.discard(first);
    let snapshot = serde_json::from_slice(&serde_json::to_vec(&program.arena_snapshot())?)?;
    let mut restored = MachineProgram::from_checkpoint(
        program.nodes,
        program.imports,
        program.entry,
        program.bindings,
        program.portable,
        program.durable,
        program.id,
    );
    restored
        .restore_arena(snapshot)
        .map_err(anyhow::Error::msg)?;
    ensure!(restored.expansion_requirements(second)?.tasks == Some(1));
    for _ in 0..256 {
        let reused = restored.load(loaded.clone(), code_limit, 2)?;
        ensure!(reused == first && restored.nodes[second as usize..] == second_code);
        restored.discard(reused);
    }
    restored.discard(second);
    ensure!(restored.nodes.len() == 1 && restored.imports.is_empty() && restored.bindings == 0);
    let arena = restored.arena.as_ref().context("restored arena")?;
    ensure!(
        arena.fragments.is_empty() && arena.nodes.free.is_empty() && arena.imports.free.is_empty()
    );
    Ok(())
}

#[test]
fn invalid_pool_ranges_and_unowned_tails_are_rejected() {
    for (base, end, ranges) in [
        (1, 3, vec![Range { start: 0, end: 1 }]),
        (1, 3, vec![1..3, 2..3]),
        (1, 3, vec![Range { start: 1, end: 2 }]),
        (1, 3, vec![Range { start: 3, end: 2 }]),
        (1, 3, vec![Range { start: 1, end: 4 }]),
        (4, 3, vec![]),
    ] {
        assert!(RangePool::restore(base, end, ranges.into_iter()).is_err());
    }
}
