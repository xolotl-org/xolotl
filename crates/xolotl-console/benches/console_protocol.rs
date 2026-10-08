use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use prost::Message as _;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Duration;
use xolotl_console::protocol;
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
            input: Some(value_to_pb(&snapshot_value(SNAPSHOT_FIELDS))),
            scope: Some("debug performance check".into()),
            justification: Some("benchmark".into()),
            ttl_ms: Some(60_000),
            registry_rev: None,
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
                    source: Some(pb::StateSourceSummary {
                        tainted: false,
                        author_constant: false,
                        model_output: false,
                        inbound: false,
                        fetched: false,
                        protected: false,
                    }),
                })),
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

fn bench_catalog(c: &mut Criterion) {
    // Exclude lazy catalog initialization from steady-state lookup measurements.
    consume(protocol::action_descriptors());
    consume(protocol::stream_descriptors());
    consume(protocol::registry_snapshot(1, 1, 0));

    let mut group = c.benchmark_group("console/catalog");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(300));
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("action_lookup", |b| {
        b.iter(|| {
            let descriptors = protocol::action_descriptors();
            let descriptor = descriptors
                .iter()
                .find(|descriptor| descriptor.id == black_box(protocol::ACTION_STATE_SNAPSHOT));
            consume(descriptor.map(|descriptor| {
                (
                    descriptor.input.schema_id.len(),
                    descriptor.input.fields.len(),
                    descriptor.output.schema_id.len(),
                    descriptor.output.fields.len(),
                )
            }));
        });
    });

    group.bench_function("stream_lookup", |b| {
        b.iter(|| {
            let descriptors = protocol::stream_descriptors();
            let descriptor = descriptors
                .iter()
                .find(|descriptor| descriptor.id == black_box(protocol::STREAM_AUDIT_FACTS));
            consume(descriptor.map(|descriptor| {
                (
                    descriptor.input.schema_id.len(),
                    descriptor.input.fields.len(),
                    descriptor.event.schema_id.len(),
                    descriptor.event.fields.len(),
                )
            }));
        });
    });

    group.bench_function("registry_snapshot", |b| {
        b.iter(|| {
            consume(protocol::registry_snapshot(
                black_box(1),
                black_box(1),
                black_box(0),
            ));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_protobuf_frames, bench_catalog);
criterion_main!(benches);
