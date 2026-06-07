use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_console::protocol::{
    ActionCall, ActionResult, ClientFrame, ClientHello, ConsoleEvent, JsonBytes, ServerFrame,
    StreamCall, protocol_metadata,
};
use nexus_types::Value;
use std::collections::BTreeMap;
use std::hint::black_box;

const SNAPSHOT_FIELDS: usize = 256;

fn snapshot_value(fields: usize) -> Value {
    let mut map = BTreeMap::new();
    for i in 0..fields {
        map.insert(format!("state://bench/k{i}"), Value::Int(i as i64));
    }
    Value::Map(map)
}

fn action_call() -> ClientFrame {
    ClientFrame::Call {
        id: 42,
        call: ActionCall {
            action: "state.snapshot".into(),
            input: JsonBytes::from_value(&snapshot_value(SNAPSHOT_FIELDS)),
            scope: Some("debug performance check".into()),
            justification: Some("benchmark".into()),
            ttl_ms: Some(60_000),
        },
    }
}

fn subscribe_call() -> ClientFrame {
    ClientFrame::Subscribe {
        id: 7,
        stream: StreamCall {
            stream: "state.watch".into(),
            input: JsonBytes::from_value(&Value::Map(BTreeMap::from([(
                "pattern".into(),
                Value::Str("state://bench/**".into()),
            )]))),
            scope: Some("benchmark".into()),
            justification: Some("benchmark".into()),
            ttl_ms: Some(60_000),
            since_rev: Some(128),
        },
    }
}

fn event_frame() -> ServerFrame {
    ServerFrame::Event {
        stream: 7,
        event: ConsoleEvent::StateSet {
            path: "state://bench/k1".into(),
            value: JsonBytes::from_value(&snapshot_value(SNAPSHOT_FIELDS)),
        },
    }
}

fn bench_json_envelope(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/json_bytes");
    group.sample_size(10);

    group.bench_function("json_bytes_from_value_256_fields", |b| {
        let value = snapshot_value(SNAPSHOT_FIELDS);
        b.iter(|| {
            let json = JsonBytes::from_value(black_box(&value));
            black_box(json);
        });
    });

    group.bench_function("json_bytes_to_value_256_fields", |b| {
        let json = JsonBytes::from_value(&snapshot_value(SNAPSHOT_FIELDS));
        b.iter(|| {
            let value = json.try_to_value().expect("json envelope must decode");
            black_box(value);
        });
    });

    group.finish();
}

fn bench_msgpack_frames(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/msgpack");
    group.sample_size(10);

    group.bench_function("encode_client_call_snapshot", |b| {
        let frame = action_call();
        b.iter(|| {
            let bytes = rmp_serde::to_vec_named(black_box(&frame)).expect("frame encode must work");
            black_box(bytes);
        });
    });

    group.bench_function("decode_client_call_snapshot", |b| {
        let bytes = rmp_serde::to_vec_named(&action_call()).expect("frame encode must work");
        b.iter(|| {
            let frame: ClientFrame =
                rmp_serde::from_slice(black_box(&bytes)).expect("frame decode must work");
            black_box(frame);
        });
    });

    group.bench_function("encode_server_event_snapshot", |b| {
        let frame = event_frame();
        b.iter(|| {
            let bytes = rmp_serde::to_vec_named(black_box(&frame)).expect("frame encode must work");
            black_box(bytes);
        });
    });

    group.bench_function("encode_decode_subscribe_frame", |b| {
        b.iter_batched(
            subscribe_call,
            |frame| {
                let bytes = rmp_serde::to_vec_named(&frame).expect("frame encode must work");
                let decoded: ClientFrame =
                    rmp_serde::from_slice(bytes.as_slice()).expect("frame decode must work");
                black_box(decoded);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/metadata");

    group.bench_function("protocol_metadata_descriptor_build", |b| {
        b.iter(|| {
            let metadata = protocol_metadata(black_box(1), black_box(1));
            black_box(metadata);
        });
    });

    group.bench_function("encode_hello_accepted_metadata", |b| {
        b.iter_batched(
            || ServerFrame::HelloAccepted {
                metadata: protocol_metadata(1, 1),
            },
            |frame| {
                let bytes = rmp_serde::to_vec_named(&frame).expect("frame encode must work");
                black_box(bytes);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("encode_client_hello", |b| {
        let frame = ClientFrame::Hello {
            hello: ClientHello::default(),
        };
        b.iter(|| {
            let bytes = rmp_serde::to_vec_named(black_box(&frame)).expect("frame encode must work");
            black_box(bytes);
        });
    });

    group.finish();
}

fn bench_results(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/action_result");

    group.bench_function("action_result_value_256_fields", |b| {
        let value = snapshot_value(SNAPSHOT_FIELDS);
        b.iter(|| {
            let result = ActionResult::value(black_box(value.clone()), black_box(99));
            black_box(result);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_json_envelope,
    bench_msgpack_frames,
    bench_metadata,
    bench_results
);
criterion_main!(benches);
