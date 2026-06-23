//! Idempotency key derivation.
//!
//! The default idempotency key for an operation is its [`OperationId`] —
//! `(process, CausalPosition, attempt)` — which is already stable across
//! crash-replay, so re-executing a recovered program reuses the same key
//! and a supporting handler dedupes automatically.
//!
//! Business code may override the key with an `_idem_key` field in the op input
//! to dedupe across *different* operations (e.g. an outbox). Critically, the
//! override is **not** free-form: a key derived purely from attacker-influenced
//! input would let an injected Plan forge or collide keys to suppress or bypass
//! deduplication. So the effective key is always bound to the **authenticated
//! context** — the `acting` identity and the `CausalPosition` — with the
//! business string mixed in, never replacing it. This module is the pure,
//! wasm-safe derivation; the dedup store lives in the kernel
//! (`state://idemp/<blake3(key)>`).

use crate::ids::IdentityRef;
use crate::operation::OperationId;
use crate::value::Value;

/// The reserved input field a caller sets to supply a business idempotency key.
pub const IDEM_KEY_FIELD: &str = "_idem_key";

/// Derive the effective idempotency key for an operation. If the input
/// carries `_idem_key`, the result binds it to the authenticated context
/// (`acting` + `CausalPosition`) so it cannot be forged or collided by injected
/// input alone; otherwise the key is the operation's own stable id. The return
/// is a stable string; the kernel hashes it into a legal
/// `state://idemp/<blake3(key)>` path segment.
pub fn derive_key(op_id: OperationId, acting: IdentityRef, input: &Value) -> String {
    match business_key(input) {
        Some(biz) => {
            // Bind the business key to the authenticated context. The position
            // anchors it to a specific call site; acting anchors it to a
            // specific identity — neither is attacker-controlled. The hash only
            // compacts the binding; the *security* is the binding itself, not
            // hash strength, so a fast deterministic mix (FNV-1a) suffices.
            let mut h = FNV_OFFSET;
            h = fnv_mix(h, b"andrias-idem-v1");
            h = fnv_mix(h, &acting.get().to_le_bytes());
            h = fnv_mix(h, &(op_id.position.get() as u64).to_le_bytes());
            h = fnv_mix(h, biz.as_bytes());
            format!("idem-{h:016x}")
        }
        None => format!("op-{op_id}"),
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv_mix(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Extract the business-supplied `_idem_key` string, if present and well-typed.
fn business_key(input: &Value) -> Option<&str> {
    match input {
        Value::Map(m) => match m.get(IDEM_KEY_FIELD) {
            Some(Value::Str(s)) if !s.is_empty() => Some(s),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::NodeId;
    use crate::ids::ProcessId;
    use std::collections::BTreeMap;

    fn op() -> OperationId {
        OperationId::new(ProcessId::new(1), NodeId::new(3), 0)
    }

    #[test]
    fn default_key_is_the_operation_id() {
        let k = derive_key(op(), IdentityRef::ROOT, &Value::Null);
        assert_eq!(k, "op-1/3/0");
    }

    #[test]
    fn retry_keeps_default_key_stable_only_within_attempt() {
        // The default key includes attempt, so a crash-replay (same attempt)
        // reuses the key, while an explicit retry (attempt+1) gets a new one.
        let replay = derive_key(op(), IdentityRef::ROOT, &Value::Null);
        let retried = derive_key(op().retry(), IdentityRef::ROOT, &Value::Null);
        assert_eq!(replay, "op-1/3/0");
        assert_eq!(retried, "op-1/3/1");
    }

    #[test]
    fn business_key_binds_to_auth_context() {
        let mut m = BTreeMap::new();
        m.insert(IDEM_KEY_FIELD.into(), Value::Str("order-42".into()));
        let input = Value::Map(m);
        let k_alice = derive_key(op(), IdentityRef::new(10), &input);
        let k_bob = derive_key(op(), IdentityRef::new(20), &input);
        // Same business key, different acting identity ⇒ different effective key
        // (an injected Plan acting as Bob can't collide Alice's idem record).
        assert_ne!(k_alice, k_bob);
        assert!(k_alice.starts_with("idem-"));
    }

    #[test]
    fn business_key_is_stable_for_same_context() {
        let mut m = BTreeMap::new();
        m.insert(IDEM_KEY_FIELD.into(), Value::Str("order-42".into()));
        let input = Value::Map(m);
        assert_eq!(
            derive_key(op(), IdentityRef::new(10), &input),
            derive_key(op(), IdentityRef::new(10), &input)
        );
    }

    #[test]
    fn empty_or_mistyped_business_key_falls_back_to_op_id() {
        let mut m = BTreeMap::new();
        m.insert(IDEM_KEY_FIELD.into(), Value::Int(7)); // wrong type
        assert_eq!(
            derive_key(op(), IdentityRef::ROOT, &Value::Map(m)),
            "op-1/3/0"
        );
    }
}
