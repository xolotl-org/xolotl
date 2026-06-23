use andrias_graph::{DoNode, OperationTemplate, StepRef};
use andrias_proto::andrias::v1 as pb;
use andrias_proto::{
    capability_from_pb, capability_to_pb, program_from_pb, program_to_pb, value_from_pb,
    value_to_pb,
};
use andrias_types::{
    BlobRef, Capability, DType, FloatBits, MethodId, OutputMode, Path, ProcessId, ResourceName,
    TensorRef, Value,
};
use anyhow::{Result, anyhow, bail};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
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
                mime: Some("application/x-andrias-tensor".into()),
            },
            dtype: DType::F32,
            shape: vec![8, 16],
        }),
    );
    Value::Map(map)
}

fn op_template(id: usize) -> Result<OperationTemplate> {
    Ok(OperationTemplate {
        target: ResourceName::new(
            Path::parse(&format!("effect://bench/proto{id}"))
                .map_err(|error| anyhow!("operation path parse failed for proto{id}: {error}"))?,
        ),
        method: "invoke".into(),
        method_id: Some(MethodId::new(0)),
        output: OutputMode::Unary,
        literal_input: Some(Value::Int(id as i64)),
    })
}

fn balanced_ops(start: usize, end: usize) -> Result<DoNode> {
    if start >= end {
        bail!("benchmark program range must be non-empty");
    }
    if end - start == 1 {
        return Ok(DoNode::op(op_template(start)?));
    }

    let mid = start + (end - start) / 2;
    Ok(DoNode::both(
        balanced_ops(start, mid)?,
        balanced_ops(mid, end)?,
    ))
}

fn program(ops: usize) -> Result<DoNode> {
    if ops == 0 {
        bail!("benchmark program must contain at least one operation");
    }
    Ok(balanced_ops(0, ops)?.and_then(StepRef::new(ProcessId::new(1), "finish")))
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
                let result = (|| {
                    let mut bytes = Vec::new();
                    pb.encode(&mut bytes)?;
                    Ok(pb::Value::decode(bytes.as_slice())?)
                })();
                observe(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_programs(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto/program");
    group.sample_size(10);

    group.bench_function("program_to_pb_256_ops", |b| match program(PROGRAM_OPS) {
        Ok(program) => {
            b.iter(|| {
                let pb = program_to_pb(black_box(&program));
                drop(black_box(pb));
            });
        }
        Err(error) => {
            let message = error.to_string();
            b.iter(|| black_box(message.as_str()));
        }
    });

    group.bench_function("program_pb_to_do_256_ops", |b| match program(PROGRAM_OPS) {
        Ok(program) => {
            let pb = program_to_pb(&program);
            b.iter(|| {
                observe(
                    program_from_pb(black_box(&pb))
                        .map_err(|error| anyhow!("program decode failed: {error}")),
                );
            });
        }
        Err(error) => {
            let message = error.to_string();
            b.iter(|| black_box(message.as_str()));
        }
    });

    group.bench_function("prost_encode_decode_program_256_ops", |b| {
        match program(PROGRAM_OPS) {
            Ok(program) => {
                let pb = program_to_pb(&program);
                b.iter_batched(
                    || pb.clone(),
                    |pb| {
                        let result = (|| {
                            let mut bytes = Vec::new();
                            pb.encode(&mut bytes)?;
                            Ok(pb::Program::decode(bytes.as_slice())?)
                        })();
                        observe(result);
                    },
                    BatchSize::SmallInput,
                );
            }
            Err(error) => {
                let message = error.to_string();
                b.iter(|| black_box(message.as_str()));
            }
        }
    });

    group.finish();
}

fn bench_capability(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto/capability");

    group.bench_function(
        "capability_to_from_pb_predicated",
        |b| match Capability::parse("perform://effect/bench/**@tenant=acme") {
            Ok(cap) => {
                b.iter(|| {
                    let pb = capability_to_pb(black_box(&cap));
                    observe(
                        capability_from_pb(black_box(&pb))
                            .map_err(|error| anyhow!("capability decode failed: {error}")),
                    );
                });
            }
            Err(error) => {
                let message = error.to_string();
                b.iter(|| black_box(message.as_str()));
            }
        },
    );

    group.finish();
}

criterion_group!(benches, bench_values, bench_programs, bench_capability);
criterion_main!(benches);
