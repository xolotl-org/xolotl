use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use prost::Message as _;
use std::collections::BTreeMap;
use std::hint::black_box;
use xolotl_console_protocol::pb;
use xolotl_proto::xolotl::v1 as pbv;
use xolotl_proto::{path_to_pb, value_to_pb};
use xolotl_types::{Path, Value};

const SNAPSHOT_FIELDS: usize = 256;

fn snapshot_value(fields: usize) -> Value {
    let mut map = BTreeMap::new();
    for i in 0..fields {
        map.insert(format!("state://bench/k{i}"), Value::integer(i as i64));
    }
    Value::map(map)
}

fn consume<T>(value: T) {
    drop(black_box(value));
}

fn action_call_frame() -> pb::ConsoleFrame {
    pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
            id: 42,
            action: "state.snapshot".into(),
            action_code: None,
            input: Some(value_to_pb(&snapshot_value(SNAPSHOT_FIELDS))),
            scope: Some("debug performance check".into()),
            justification: Some("benchmark".into()),
            ttl_ms: Some(60_000),
            registry_rev: None,
            idempotency_key: None,
        })),
    }
}

fn bench_path() -> pbv::Path {
    match Path::parse("state://bench/k1") {
        Ok(path) => path_to_pb(&path),
        Err(_) => pbv::Path {
            cluster: None,
            scheme: "state".into(),
            segments: vec!["bench".into(), "k1".into()],
        },
    }
}

fn event_frame() -> pb::ConsoleFrame {
    pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Event(pb::Event {
            stream: 7,
            event: Some(pb::ConsoleEvent {
                kind: Some(pb::console_event::Kind::StateSet(pb::StateSet {
                    path: Some(bench_path()),
                    value: Some(value_to_pb(&snapshot_value(SNAPSHOT_FIELDS))),
                })),
                state_rev: 0,
                fact_cursor: 0,
                coalesced: false,
            }),
        })),
    }
}

fn bench_protobuf_frames(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/protobuf");
    group.sample_size(10);

    group.bench_function("encode_client_call_snapshot", |b| {
        let frame = action_call_frame();
        b.iter(|| consume(black_box(&frame).encode_to_vec()));
    });

    group.bench_function("decode_client_call_snapshot", |b| {
        let bytes = action_call_frame().encode_to_vec();
        b.iter(|| consume(pb::ConsoleFrame::decode(black_box(bytes.as_slice()))));
    });

    group.bench_function("encode_server_event_snapshot", |b| {
        let frame = event_frame();
        b.iter(|| consume(black_box(&frame).encode_to_vec()));
    });

    group.bench_function("encode_decode_event_frame", |b| {
        b.iter_batched(
            event_frame,
            |frame| {
                let bytes = frame.encode_to_vec();
                consume(pb::ConsoleFrame::decode(bytes.as_slice()));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_protobuf_frames);
criterion_main!(benches);
