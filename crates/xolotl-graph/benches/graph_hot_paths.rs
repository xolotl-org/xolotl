use anyhow::{Result, anyhow};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use xolotl_graph::{ActorSpec, DoNode, OperationTemplate, StepRef, compile_do, lint};
use xolotl_types::{MethodId, OutputMode, Path, ResourceName, Value};

const LINEAR_STEPS: usize = 512;
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

fn bench_setup_failure(c: &mut Criterion, name: &'static str, error: anyhow::Error) {
    let message = error.to_string();
    c.bench_function(name, |b| b.iter(|| black_box(message.as_str())));
}

fn observe<T>(result: Result<T>) {
    match result {
        Ok(value) => drop(black_box(value)),
        Err(error) => observe_error(error),
    }
}

fn observe_error(error: anyhow::Error) {
    let message = error.to_string();
    drop(black_box(message));
}

fn bench_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph/compile");
    group.sample_size(10);

    group.bench_function("compile_linear_and_then_512", |b| {
        b.iter_batched(
            || linear_program(LINEAR_STEPS),
            |program| match program {
                Ok(program) => observe(
                    compile_do(black_box(&program))
                        .map_err(|error| anyhow!("linear program compile failed: {error}")),
                ),
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("compile_balanced_both_1024_ops", |b| {
        b.iter_batched(
            || balanced_both_program(0, PARALLEL_LEAVES),
            |program| match program {
                Ok(program) => observe(
                    compile_do(black_box(&program))
                        .map_err(|error| anyhow!("parallel program compile failed: {error}")),
                ),
                Err(error) => observe_error(error),
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_graph_queries(c: &mut Criterion) {
    let graph = match balanced_both_program(0, PARALLEL_LEAVES)
        .and_then(|program| compile_do(&program).map_err(|error| anyhow!("{error}")))
    {
        Ok(graph) => graph,
        Err(error) => {
            bench_setup_failure(c, "graph/query/setup_failed", error);
            return;
        }
    };
    let mut group = c.benchmark_group("graph/query");
    let mut index = 0usize;

    group.bench_function("node_lookup_2047_nodes", |b| {
        b.iter(|| {
            index = (index + 257) % graph.nodes.len();
            let id = graph.nodes[index].id;
            match graph.node(black_box(id)) {
                Some(node) => drop(black_box(node)),
                None => drop(black_box(format!("node {id} missing"))),
            }
        });
    });

    group.bench_function("output_is_consumed_scan_2047_nodes", |b| {
        b.iter(|| {
            index = (index + 263) % graph.nodes.len();
            let id = graph.nodes[index].id;
            black_box(graph.output_is_consumed(black_box(id)));
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
                    balanced_both_program(0, PARALLEL_LEAVES),
                )
            },
            |(spec, program)| match program {
                Ok(program) => {
                    let findings = lint(black_box(&spec), black_box(&program));
                    drop(black_box(findings));
                }
                Err(error) => observe_error(error),
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_compile, bench_graph_queries, bench_lint);
criterion_main!(benches);
