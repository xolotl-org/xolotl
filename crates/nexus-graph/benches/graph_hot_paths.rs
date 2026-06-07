use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_graph::{
    ActorSpec, DoNode, Frame, GraphCursor, OperationTemplate, StepRef, compile_do, lint,
};
use nexus_types::{MethodId, NodeId, OutputMode, Path, ProcessId, ResourceName, Value};
use std::hint::black_box;

const LINEAR_STEPS: usize = 512;
const PARALLEL_LEAVES: usize = 1_024;

fn step(name: impl Into<String>) -> StepRef {
    StepRef::new(ProcessId::new(1), name)
}

fn op_template(id: usize) -> OperationTemplate {
    OperationTemplate {
        target: ResourceName::new(
            Path::parse(&format!("effect://bench/op{id}")).expect("op path must parse"),
        ),
        method: "invoke".into(),
        method_id: Some(MethodId::new(0)),
        output: OutputMode::Unary,
        literal_input: Some(Value::Int(id as i64)),
    }
}

fn op_node(id: usize) -> DoNode {
    DoNode::op(op_template(id))
}

fn linear_program(steps: usize) -> DoNode {
    let mut node = op_node(0);
    for i in 0..steps {
        node = node.and_then(step(format!("step_{i}")));
    }
    node
}

fn balanced_both_program(start: usize, leaves: usize) -> DoNode {
    if leaves == 1 {
        return op_node(start);
    }
    let left = balanced_both_program(start, leaves / 2);
    let right = balanced_both_program(start + leaves / 2, leaves - (leaves / 2));
    DoNode::both(left, right)
}

fn declared_spec(leaves: usize) -> ActorSpec {
    ActorSpec::with_capabilities(
        "bench",
        (0..leaves).map(|i| format!("perform://effect/bench/op{i}")),
    )
}

fn bench_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph/compile");
    group.sample_size(10);

    group.bench_function("compile_linear_and_then_512", |b| {
        b.iter_batched(
            || linear_program(LINEAR_STEPS),
            |program| {
                let graph = compile_do(black_box(&program)).expect("linear program must compile");
                black_box(graph);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("compile_balanced_both_1024_ops", |b| {
        b.iter_batched(
            || balanced_both_program(0, PARALLEL_LEAVES),
            |program| {
                let graph = compile_do(black_box(&program)).expect("parallel program must compile");
                black_box(graph);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_graph_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph/query");
    let graph = compile_do(&balanced_both_program(0, PARALLEL_LEAVES))
        .expect("parallel program must compile");
    let mut index = 0usize;

    group.bench_function("node_lookup_2047_nodes", |b| {
        b.iter(|| {
            index = (index + 257) % graph.nodes.len();
            let id = graph.nodes[index].id;
            let node = graph.node(black_box(id)).expect("node must exist");
            black_box(node);
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

fn bench_cursor(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph/cursor");

    group.bench_function("cursor_push_pop_4096_frames", |b| {
        b.iter_batched(
            || GraphCursor::at_root(NodeId::new(0)),
            |mut cursor| {
                for i in 1..=4_096u32 {
                    cursor.push(Frame::new(NodeId::new(i), Value::Int(i as i64)));
                }
                while let Some(frame) = cursor.pop() {
                    black_box(frame);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("cursor_is_done_4096_done_nodes", |b| {
        b.iter_batched(
            || {
                let mut cursor = GraphCursor::at_root(NodeId::new(0));
                for i in 0..4_096u32 {
                    cursor.mark_done(NodeId::new(i));
                }
                cursor
            },
            |cursor| {
                black_box(cursor.is_done(NodeId::new(4_095)));
            },
            BatchSize::SmallInput,
        );
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
            |(spec, program)| {
                let findings = lint(black_box(&spec), black_box(&program));
                black_box(findings);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_compile,
    bench_graph_queries,
    bench_cursor,
    bench_lint
);
criterion_main!(benches);
