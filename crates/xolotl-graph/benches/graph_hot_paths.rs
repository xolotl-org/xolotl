use anyhow::{Result, anyhow};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use xolotl_graph::{ActorSpec, DoNode, OperationTemplate, StepRef, compile_do, lint};
use xolotl_types::{MethodId, OutputMode, Path, ResourceName, Value};

const LINEAR_STEPS: usize = 128;
const DEEP_LINEAR_STEPS: usize = 512;
const PARALLEL_LEAVES: usize = 1_024;

fn step(name: impl Into<String>) -> StepRef {
    StepRef::new(name)
}

fn op_template(id: usize) -> Result<OperationTemplate> {
    Ok(OperationTemplate {
        target: ResourceName::new(
            Path::parse(&format!("effect://bench/op{id}"))
                .map_err(|error| anyhow!("operation path parse failed for op{id}: {error}"))?,
        ),
        method: "invoke".into(),
        method_id: Some(MethodId::new(0)),
        output: OutputMode::Unary,
        literal_input: Some(Value::integer(id as i64)),
    })
}

fn op_node(id: usize) -> Result<DoNode> {
    Ok(DoNode::op(op_template(id)?))
}

fn linear_program(steps: usize) -> Result<DoNode> {
    let mut node = op_node(0)?;
    for i in 0..steps {
        node = node.and_then(step(format!("step_{i}")));
    }
    Ok(node)
}

fn balanced_both_program(start: usize, leaves: usize) -> Result<DoNode> {
    if leaves == 1 {
        return op_node(start);
    }
    let left = balanced_both_program(start, leaves / 2)?;
    let right = balanced_both_program(start + leaves / 2, leaves - (leaves / 2))?;
    Ok(DoNode::both(left, right))
}

fn declared_spec(leaves: usize) -> ActorSpec {
    ActorSpec::with_capabilities(
        "bench",
        (0..leaves).map(|i| format!("perform://effect/bench/op{i}")),
    )
}

#[expect(
    clippy::panic,
    reason = "invalid benchmark fixtures must stop measurement"
)]
fn checked<T, Error: core::fmt::Display>(result: core::result::Result<T, Error>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("benchmark failed: {error}"),
    }
}

fn bench_compile(c: &mut Criterion) {
    let linear = checked(linear_program(LINEAR_STEPS));
    let parallel = checked(balanced_both_program(0, PARALLEL_LEAVES));
    let deep = checked(linear_program(DEEP_LINEAR_STEPS));
    drop(checked(compile_do(&linear)));
    drop(checked(compile_do(&parallel)));
    drop(checked(compile_do(&deep)));
    let mut group = c.benchmark_group("graph/compile");
    group.sample_size(10);

    group.bench_function("compile_linear_and_then_128", |b| {
        b.iter(|| drop(black_box(checked(compile_do(black_box(&linear))))));
    });

    group.bench_function("compile_balanced_both_1024_ops", |b| {
        b.iter(|| drop(black_box(checked(compile_do(black_box(&parallel))))));
    });

    group.bench_function("compile_linear_and_then_512", |b| {
        b.iter(|| drop(black_box(checked(compile_do(black_box(&deep))))));
    });

    group.finish();
}

fn bench_graph_queries(c: &mut Criterion) {
    let graph = checked(compile_do(&checked(balanced_both_program(
        0,
        PARALLEL_LEAVES,
    ))));
    let mut group = c.benchmark_group("graph/query");
    let mut index = 0usize;

    group.bench_function("node_lookup_2047_nodes", |b| {
        b.iter(|| {
            index = (index + 257) % graph.nodes.len();
            let id = graph.nodes[index].id;
            let node = checked(
                graph
                    .node(black_box(id))
                    .ok_or_else(|| anyhow!("node {id} missing")),
            );
            black_box(node);
        });
    });

    group.finish();
}

fn bench_lint(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph/lint");
    group.sample_size(10);

    group.bench_function("actor_spec_lint_1024_declared_ops", |b| {
        b.iter_batched(
            || {
                (
                    declared_spec(PARALLEL_LEAVES),
                    checked(balanced_both_program(0, PARALLEL_LEAVES)),
                )
            },
            |(spec, program)| {
                let findings = lint(black_box(&spec), black_box(&program), |_| {
                    Some(xolotl_types::MethodAuthority::Perform)
                });
                drop(black_box(findings));
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_compile, bench_graph_queries, bench_lint);
criterion_main!(benches);
