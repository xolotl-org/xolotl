use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_graph::{DoNode, OperationTemplate, StepRef};
use nexus_proto::nexus::v1 as pb;
use nexus_proto::{
    capability_from_pb, capability_to_pb, program_from_pb, program_to_pb, value_from_pb,
    value_to_pb,
};
use nexus_types::{
    BlobRef, Capability, DType, FloatBits, MethodId, OutputMode, Path, ProcessId, ResourceName,
    TensorRef, Value,
};
use prost::Message;
use std::collections::BTreeMap;
use std::hint::black_box;

const MAP_FIELDS: usize = 256;
const PROGRAM_OPS: usize = 256;

fn complex_value(fields: usize) -> Value {
    let mut map = BTreeMap::new();
    for i in 0..fields {
        map.insert(
            format!("k{i}"),
            Value::List(vec![
                Value::Int(i as i64),
                Value::Float(FloatBits(i as f64 / 10.0)),
                Value::Str(format!("value-{i}")),
            ]),
        );
    }
    map.insert(
        "tensor".into(),
        Value::Tensor(TensorRef {
            blob: BlobRef {
                hash: "ab".repeat(32),
                size: 128,
                mime: Some("application/x-nexus-tensor".into()),
            },
            dtype: DType::F32,
            shape: vec![8, 16],
        }),
    );
    Value::Map(map)
}

fn op_template(id: usize) -> OperationTemplate {
    OperationTemplate {
        target: ResourceName::new(
            Path::parse(&format!("effect://bench/proto{id}")).expect("path must parse"),
        ),
        method: "invoke".into(),
        method_id: Some(MethodId::new(0)),
        output: OutputMode::Unary,
        literal_input: Some(Value::Int(id as i64)),
    }
}

fn balanced_ops(start: usize, end: usize) -> DoNode {
    debug_assert!(start < end);
    if end - start == 1 {
        return DoNode::op(op_template(start));
    }

    let mid = start + (end - start) / 2;
    DoNode::both(balanced_ops(start, mid), balanced_ops(mid, end))
}

fn program(ops: usize) -> DoNode {
    assert!(
        ops > 0,
        "benchmark program must contain at least one operation"
    );
    balanced_ops(0, ops).and_then(StepRef::new(ProcessId::new(1), "finish"))
}

fn bench_values(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto/value");
    group.sample_size(10);

    group.bench_function("value_to_pb_map_256", |b| {
        let value = complex_value(MAP_FIELDS);
        b.iter(|| {
            let pb = value_to_pb(black_box(&value));
            black_box(pb);
        });
    });

    group.bench_function("value_pb_to_value_map_256", |b| {
        let pb = value_to_pb(&complex_value(MAP_FIELDS));
        b.iter(|| {
            let value = value_from_pb(black_box(&pb));
            black_box(value);
        });
    });

    group.bench_function("prost_encode_decode_value_map_256", |b| {
        let pb = value_to_pb(&complex_value(MAP_FIELDS));
        b.iter_batched(
            || pb.clone(),
            |pb| {
                let mut bytes = Vec::new();
                pb.encode(&mut bytes).expect("value encode must succeed");
                let decoded =
                    pb::Value::decode(bytes.as_slice()).expect("value decode must succeed");
                black_box(decoded);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_programs(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto/program");
    group.sample_size(10);

    group.bench_function("program_to_pb_256_ops", |b| {
        let program = program(PROGRAM_OPS);
        b.iter(|| {
            let pb = program_to_pb(black_box(&program));
            black_box(pb);
        });
    });

    group.bench_function("program_pb_to_do_256_ops", |b| {
        let pb = program_to_pb(&program(PROGRAM_OPS));
        b.iter(|| {
            let program = program_from_pb(black_box(&pb)).expect("program decode must succeed");
            black_box(program);
        });
    });

    group.bench_function("prost_encode_decode_program_256_ops", |b| {
        let pb = program_to_pb(&program(PROGRAM_OPS));
        b.iter_batched(
            || pb.clone(),
            |pb| {
                let mut bytes = Vec::new();
                pb.encode(&mut bytes).expect("program encode must succeed");
                let decoded =
                    pb::Program::decode(bytes.as_slice()).expect("program decode must succeed");
                black_box(decoded);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_capability(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto/capability");

    group.bench_function("capability_to_from_pb_predicated", |b| {
        let cap = Capability::parse("perform://effect/bench/**@tenant=acme")
            .expect("capability must parse");
        b.iter(|| {
            let pb = capability_to_pb(black_box(&cap));
            let cap = capability_from_pb(black_box(&pb)).expect("capability decode must succeed");
            black_box(cap);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_values, bench_programs, bench_capability);
criterion_main!(benches);
