//! Version 1 Merkle profile. Tags and field layouts are explicit protocol data.
//!
//! Each node begins with DOMAIN and one byte tag. Lengths/counts are u64 LE,
//! integers use their fixed-width LE representation, and each ordered child
//! contributes its full 32-byte digest. Map keys precede their child digest.

use super::{
    Value, ValueNodeKey, ValuePostorder, ValueView, is_leaf,
    local::{Blob, Local},
};
use alloc::collections::BTreeMap;

const DOMAIN: &[u8] = b"xolotl-value-semantic-v1\0";

pub(super) fn digest(root: &Value) -> [u8; 32] {
    if is_leaf(root) {
        return finish(root, &BTreeMap::new());
    }
    let mut digests = BTreeMap::new();
    let mut walk = ValuePostorder::new(root);
    while let Some(value) = walk.next(|key| digests.contains_key(&key)) {
        let digest = finish(value, &digests);
        digests.insert(ValueNodeKey::of(value), digest);
    }
    digests[&ValueNodeKey::of(root)]
}

fn finish(value: &Value, children: &BTreeMap<ValueNodeKey<'_>, [u8; 32]>) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(DOMAIN);
    match Local::of(value) {
        Local::Null => {
            hash.update(&[0]);
        }
        Local::Bool(value) => {
            hash.update(&[1, u8::from(value)]);
        }
        Local::Int(value) => {
            hash.update(&[2]);
            hash.update(&value.to_le_bytes());
        }
        Local::Float(bits) => {
            hash.update(&[3]);
            hash.update(&bits.to_le_bytes());
        }
        Local::Str(value) => {
            hash.update(&[4]);
            bytes(&mut hash, value.as_bytes());
        }
        Local::Bytes(value) => {
            hash.update(&[5]);
            bytes(&mut hash, value);
        }
        Local::List(len) => {
            hash.update(&[6]);
            number(&mut hash, len as u64);
        }
        Local::Map(len) => {
            hash.update(&[7]);
            number(&mut hash, len as u64);
        }
        Local::Blob(value) => {
            hash.update(&[8]);
            blob(&mut hash, value);
        }
        Local::Tensor {
            blob: value,
            dtype,
            shape,
        } => {
            hash.update(&[9]);
            blob(&mut hash, value);
            hash.update(&[dtype]);
            number(&mut hash, shape.len() as u64);
            for dimension in shape {
                number(&mut hash, *dimension);
            }
        }
        Local::Frame {
            blob: value,
            timestamp,
            kind,
        } => {
            hash.update(&[10]);
            blob(&mut hash, value);
            hash.update(&timestamp.to_le_bytes());
            hash.update(&[kind]);
        }
        Local::StreamDone => {
            hash.update(&[11]);
        }
        Local::StreamError(message) => {
            hash.update(&[12]);
            bytes(&mut hash, message.as_bytes());
        }
    }
    match value.view() {
        ValueView::List(items) => {
            for child in items.iter() {
                hash.update(&children[&ValueNodeKey::of(child)]);
            }
        }
        ValueView::Map(entries) => {
            for (key, child) in entries.iter() {
                bytes(&mut hash, key.as_bytes());
                hash.update(&children[&ValueNodeKey::of(child)]);
            }
        }
        _ => {}
    }
    *hash.finalize().as_bytes()
}

fn number(hash: &mut blake3::Hasher, value: u64) {
    hash.update(&value.to_le_bytes());
}

fn bytes(hash: &mut blake3::Hasher, value: &[u8]) {
    number(hash, value.len() as u64);
    hash.update(value);
}

fn blob(hash: &mut blake3::Hasher, value: Blob<'_>) {
    bytes(hash, value.hash.as_bytes());
    number(hash, value.size);
    match value.mime {
        None => {
            hash.update(&[0]);
        }
        Some(mime) => {
            hash.update(&[1]);
            bytes(hash, mime.as_bytes());
        }
    }
}
