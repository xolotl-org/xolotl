use super::*;
use crate::{BlobRef, DType, FloatBits, FrameKind, FrameRef, TensorRef};
use alloc::{collections::BTreeMap, format, string::String, vec, vec::Vec};
use anyhow::ensure;
use core::hash::Hasher;
use std::{collections::hash_map::DefaultHasher, thread};

fn doubled(depth: usize, leaf: Value) -> Value {
    let mut value = leaf;
    for _ in 0..depth {
        value = Value::list(vec![value.clone(), value]);
    }
    value
}

fn ordinary_hash(value: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn semantic_digest_version_one_has_fixed_vectors() {
    // Generated independently from the documented tag/length/child profile,
    // without invoking Value or its serializer. Changes require a new domain.
    for (value, expected) in [
        (
            Value::null(),
            "135d7d86904986a7b8dd0306b290ab3f1028655dc9b92f65b2710cd1958b3adf",
        ),
        (
            Value::integer(i64::MIN),
            "75e8b825f8aecbe1e016ffa526336598048308397603a6a8374738eb172a07e7",
        ),
        (
            Value::from("hello"),
            "8643e7eae43371b067e70b9df23e38549fbd05ed69d9d091c417545ce0973ae4",
        ),
        (
            Value::list(vec![Value::null(), Value::from("hello")]),
            "14d594e489c7fa68dc4fece0c0037c39dfd231adcc792d7268ab56d387d2ee03",
        ),
    ] {
        let actual: String = value
            .semantic_digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn doubled_dags_have_exact_equality_and_saturating_logical_tokens() {
    let left = doubled(192, Value::integer(7));
    let right = doubled(192, Value::integer(7));
    let different = doubled(192, Value::integer(8));
    assert_eq!(left, right);
    assert_ne!(left, different);
    assert_eq!(left.semantic_digest(), right.semantic_digest());
    assert_ne!(left.semantic_digest(), different.semantic_digest());
    assert_eq!(ordinary_hash(&left), ordinary_hash(&right));
    assert_eq!(left.approx_tokens(), u64::MAX);
    assert_eq!(doubled(63, Value::null()).approx_tokens(), 1u64 << 63);
    assert_eq!(doubled(64, Value::null()).approx_tokens(), u64::MAX);
}

#[test]
fn equality_and_hash_ignore_allocation_and_sharing_shapes() {
    let make = || Value::list(vec![Value::string("shared".into()), Value::integer(3)]);
    let child = make();
    let shared = Value::list(vec![child.clone(), child]);
    let separate = Value::list(vec![make(), make()]);
    assert_eq!(shared, separate);
    assert_eq!(separate, shared);
    assert_eq!(shared.semantic_digest(), separate.semantic_digest());
    assert_eq!(ordinary_hash(&shared), ordinary_hash(&separate));
}

#[test]
fn repeated_left_identity_is_compared_against_every_distinct_right_value() {
    let one = Value::list(vec![Value::integer(1)]);
    let left = Value::list(vec![one.clone(), one]);
    let right = Value::list(vec![
        Value::list(vec![Value::integer(1)]),
        Value::list(vec![Value::integer(2)]),
    ]);
    assert_ne!(left, right);
    assert_ne!(right, left);
}

#[test]
fn byte_allocation_identity_and_inline_float_equality_have_distinct_roles() {
    let bytes = Value::bytes(vec![0, 127, 255]);
    let alias = bytes.clone();
    let independent = Value::bytes(vec![0, 127, 255]);
    assert!(bytes.identity().is_some());
    assert_eq!(bytes.identity(), alias.identity());
    assert_ne!(bytes.identity(), independent.identity());
    assert_eq!(bytes, independent);
    assert_eq!(bytes.semantic_digest(), independent.semantic_digest());
    assert_ne!(bytes, Value::bytes(vec![0, 127]));
    assert_ne!(bytes, Value::bytes(vec![0, 127, 254]));

    let bits = 0x7ff8_0000_0000_0001;
    let first = Value::float(FloatBits(f64::from_bits(bits)));
    let second = Value::float(FloatBits(f64::from_bits(bits)));
    assert!(first.identity().is_none());
    assert_eq!(first, second);
    assert_ne!(first, Value::float(FloatBits(f64::from_bits(bits + 1))));
    assert_ne!(Value::float(FloatBits(0.0)), Value::float(FloatBits(-0.0)));
}

#[test]
fn scalar_types_float_bits_and_field_boundaries_are_distinct() {
    let values = [
        Value::null(),
        Value::boolean(false),
        Value::integer(0),
        Value::float(FloatBits(0.0)),
        Value::float(FloatBits(-0.0)),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0001))),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0002))),
        Value::string(String::new()),
        Value::bytes(Vec::new()),
        Value::list(Vec::new()),
        Value::map(BTreeMap::new()),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: String::new(),
        }),
    ];
    for (index, left) in values.iter().enumerate() {
        assert_eq!(left, &left.clone());
        for right in &values[index + 1..] {
            assert_ne!(left, right);
            assert_ne!(left.semantic_digest(), right.semantic_digest());
        }
    }
    let left = Value::list(vec![Value::from("ab"), Value::from("c")]);
    let right = Value::list(vec![Value::from("a"), Value::from("bc")]);
    assert_ne!(left.semantic_digest(), right.semantic_digest());
}

#[test]
fn map_order_is_semantic_and_each_key_is_distinct() {
    let left = Value::map(BTreeMap::from([
        ("é".into(), Value::integer(1)),
        ("z".into(), Value::integer(2)),
        ("aa".into(), Value::integer(3)),
    ]));
    let right = Value::map(BTreeMap::from([
        ("aa".into(), Value::integer(3)),
        ("z".into(), Value::integer(2)),
        ("é".into(), Value::integer(1)),
    ]));
    assert_eq!(left, right);
    assert_eq!(left.semantic_digest(), right.semantic_digest());
    assert_eq!(left.approx_tokens(), 6);
    assert_ne!(
        Value::map(BTreeMap::from([("ab".into(), Value::from("c"))])).semantic_digest(),
        Value::map(BTreeMap::from([("a".into(), Value::from("bc"))])).semantic_digest(),
    );
}

#[test]
fn media_references_compare_complete_metadata_without_resolving_content() {
    let blob = BlobRef {
        hash: "content-that-is-not-installed".into(),
        size: 8,
        mime: None,
    };
    let mut mime = blob.clone();
    mime.mime = Some("application/test".into());
    let values = [
        Value::blob(blob.clone()),
        Value::blob(mime),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::F32,
            shape: vec![2],
        }),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::F64,
            shape: vec![1],
        }),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::F32,
            shape: vec![1, 2],
        }),
        Value::from(FrameRef {
            blob: blob.clone(),
            ts_nanos: 0,
            kind: FrameKind::Audio,
        }),
        Value::from(FrameRef {
            blob: blob.clone(),
            ts_nanos: 1,
            kind: FrameKind::Audio,
        }),
        Value::from(FrameRef {
            blob,
            ts_nanos: 0,
            kind: FrameKind::Video,
        }),
    ];
    for (index, left) in values.iter().enumerate() {
        assert_eq!(left.approx_tokens(), 256);
        for right in &values[index + 1..] {
            assert_ne!(left, right);
            assert_ne!(left.semantic_digest(), right.semantic_digest());
        }
    }
}

#[test]
fn shared_large_leaf_is_visited_once_and_tokens_count_its_occurrences() {
    let leaf = Value::bytes(vec![7; 128 * 1024]);
    let root = Value::list(
        (0..512)
            .map(|index| Value::list(vec![Value::integer(index), leaf.clone()]))
            .collect(),
    );
    let mut visited = BTreeMap::new();
    let mut byte_nodes = 0;
    let mut walk = ValuePostorder::new(&root);
    while let Some(value) = walk.next(|key| visited.contains_key(&key)) {
        byte_nodes += usize::from(matches!(value.view(), ValueView::Bytes(_)));
        visited.insert(ValueNodeKey::of(value), ());
    }
    assert_eq!(byte_nodes, 1);
    assert_eq!(root.approx_tokens(), 512 * (1 + 128 * 1024 / 4));
    assert_eq!(Value::from("é🙂中文é🙂中文").approx_tokens(), 2);
}

#[test]
fn debug_does_not_expand_deep_or_large_values() {
    let value = doubled(192, Value::from("x".repeat(100_000)));
    assert!(format!("{value:?}").len() < 128);
    let text = Value::from("🙂".repeat(100_000));
    assert!(format!("{text:?}").len() < 400);
}

#[test]
fn deep_mixed_semantics_and_release_fit_a_small_stack() -> anyhow::Result<()> {
    let worker =
        thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let build = || {
                    let mut value = Value::null();
                    for index in 0..20_000 {
                        value = if index % 2 == 0 {
                            Value::list(vec![value])
                        } else {
                            Value::map(BTreeMap::from([("child".into(), value)]))
                        };
                    }
                    value
                };
                let left = build();
                let right = build();
                ensure!(left == right);
                ensure!(left.semantic_digest() == right.semantic_digest());
                ensure!(left.approx_tokens() == 10_001);
                ensure!(format!("{left:?}").len() < 128);
                drop((left, right));
                Ok(())
            })?;
    worker
        .join()
        .map_err(|_error| anyhow::anyhow!("deep semantics worker panicked"))??;
    Ok(())
}
