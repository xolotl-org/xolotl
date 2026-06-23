use andrias_console::protocol::{
    ActionCall, ActionResult, ClientFrame, ClientHello, ConsoleEvent, JsonBytes, ServerFrame,
    StreamCall, protocol_metadata,
};
use andrias_types::Value;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use serde::Serialize;
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

fn json_bytes(value: &Value) -> Result<JsonBytes, String> {
    JsonBytes::try_from_value(value).map_err(|error| error.to_string())
}

fn action_result_value(value: Value, server_rev: u64) -> Result<ActionResult, String> {
    ActionResult::value(value, server_rev).map_err(|error| error.to_string())
}

fn encode_named<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec_named(value).map_err(|error| error.to_string())
}

fn decode_client_frame(bytes: &[u8]) -> Result<ClientFrame, String> {
    rmp_serde::from_slice(bytes).map_err(|error| error.to_string())
}

fn consume_result<T, E>(result: Result<T, E>) {
    match result {
        Ok(value) => drop(black_box(value)),
        Err(error) => drop(black_box(error)),
    }
}

fn action_call() -> Result<ClientFrame, String> {
    Ok(ClientFrame::Call {
        id: 42,
        call: ActionCall {
            action: "state.snapshot".into(),
            input: json_bytes(&snapshot_value(SNAPSHOT_FIELDS))?,
            scope: Some("debug performance check".into()),
            justification: Some("benchmark".into()),
            ttl_ms: Some(60_000),
        },
    })
}

fn subscribe_call() -> Result<ClientFrame, String> {
    Ok(ClientFrame::Subscribe {
        id: 7,
        stream: StreamCall {
            stream: "state.watch".into(),
            input: json_bytes(&Value::Map(BTreeMap::from([(
                "pattern".into(),
                Value::Str("state://bench/**".into()),
            )])))?,
            scope: Some("benchmark".into()),
            justification: Some("benchmark".into()),
            ttl_ms: Some(60_000),
            since_rev: Some(128),
        },
    })
}

fn event_frame() -> Result<ServerFrame, String> {
    Ok(ServerFrame::Event {
        stream: 7,
        event: ConsoleEvent::StateSet {
            path: "state://bench/k1".into(),
            value: json_bytes(&snapshot_value(SNAPSHOT_FIELDS))?,
        },
    })
}

fn bench_json_envelope(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/json_bytes");
    group.sample_size(10);

    group.bench_function("json_bytes_from_value_256_fields", |b| {
        let value = snapshot_value(SNAPSHOT_FIELDS);
        b.iter(|| {
            let json = json_bytes(black_box(&value));
            consume_result(json);
        });
    });

    group.bench_function("json_bytes_to_value_256_fields", |b| {
        let json = json_bytes(&snapshot_value(SNAPSHOT_FIELDS));
        b.iter(|| {
            let value = match &json {
                Ok(json) => json.try_to_value().map_err(|error| error.to_string()),
                Err(error) => Err(error.clone()),
            };
            consume_result(value);
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
            let bytes = match &frame {
                Ok(frame) => encode_named(black_box(frame)),
                Err(error) => Err(error.clone()),
            };
            consume_result(bytes);
        });
    });

    group.bench_function("decode_client_call_snapshot", |b| {
        let bytes = action_call().and_then(|frame| encode_named(&frame));
        b.iter(|| {
            let frame = match &bytes {
                Ok(bytes) => decode_client_frame(black_box(bytes)),
                Err(error) => Err(error.clone()),
            };
            consume_result(frame);
        });
    });

    group.bench_function("encode_server_event_snapshot", |b| {
        let frame = event_frame();
        b.iter(|| {
            let bytes = match &frame {
                Ok(frame) => encode_named(black_box(frame)),
                Err(error) => Err(error.clone()),
            };
            consume_result(bytes);
        });
    });

    group.bench_function("encode_decode_subscribe_frame", |b| {
        b.iter_batched(
            subscribe_call,
            |frame| {
                let decoded = frame
                    .and_then(|frame| encode_named(&frame))
                    .and_then(|bytes| decode_client_frame(bytes.as_slice()));
                consume_result(decoded);
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
                let bytes = encode_named(&frame);
                consume_result(bytes);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("encode_client_hello", |b| {
        let frame = ClientFrame::Hello {
            hello: ClientHello::default(),
        };
        b.iter(|| {
            let bytes = encode_named(black_box(&frame));
            consume_result(bytes);
        });
    });

    group.finish();
}

fn bench_results(c: &mut Criterion) {
    let mut group = c.benchmark_group("console/action_result");

    group.bench_function("action_result_value_256_fields", |b| {
        let value = snapshot_value(SNAPSHOT_FIELDS);
        b.iter(|| {
            let result = action_result_value(black_box(value.clone()), black_box(99));
            consume_result(result);
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
