//! Blob store (§17.4): `effect://blob/write`, `effect://blob/read`,
//! `effect://blob/delete`.
//!
//! Large bytes are content-addressed (blake3) and held in the state backend
//! under `state://blob/<hash>`; the Operation returns only a [`BlobRef`] /
//! [`TensorRef`] so Facts never inline payloads (§4.4). GC is retention +
//! refcount (§17.4): each `write` increments a per-hash reference count and
//! `delete` decrements it; the bytes are physically deleted only when the count
//! reaches zero. Refcounts are stored in the state backend at
//! `state://blob-refcount/<hash>` so they survive Driver restarts and are shared
//! across DataPlane instances.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{BlobRef, MethodId, Outcome, OutputMode, Path, Value};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://blob/<method>` Resource with public method
/// `invoke`.
pub const BLOB_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "write",
        nexus_types::Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new("read", nexus_types::Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new(
        "delete",
        nexus_types::Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
];

/// Drives the blob actions, backed by a state backend.
pub struct BlobDriver {
    state: Backend,
}

impl BlobDriver {
    pub fn new(state: Backend) -> Self {
        Self { state }
    }

    /// Build a content-addressed blob path. On read/delete the `hash` comes from
    /// Operation input, so an illegal path segment is a caller error (returned as
    /// `DriverError`), never a panic.
    fn blob_path(hash: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://blob/{hash}"))
            .map_err(|e| DriverError::Other(format!("invalid blob hash {hash:?}: {e}")))
    }

    fn refcount_path(hash: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://blob-refcount/{hash}"))
            .map_err(|e| DriverError::Other(format!("invalid blob hash {hash:?}: {e}")))
    }

    /// Drop one persisted reference to `hash`. Returns true when the count
    /// reached zero and the caller should physically delete the bytes.
    async fn decref(&self, hash: &str) -> Result<bool, DriverError> {
        let path = Self::refcount_path(hash)?;
        loop {
            let current = self
                .state
                .read(&path)
                .await
                .map_err(|e| DriverError::Other(e.to_string()))?;
            let n = current.as_ref().and_then(Value::as_int).unwrap_or(0);
            if n <= 1 {
                match self.state.write_cas(&path, current, Value::Int(0)).await {
                    Ok(()) => {
                        self.state
                            .write_delete(&path)
                            .await
                            .map_err(|e| DriverError::Other(e.to_string()))?;
                        return Ok(true);
                    }
                    Err(nexus_state::StateError::CasFailed { .. }) => continue,
                    Err(e) => return Err(DriverError::Other(e.to_string())),
                }
            }
            match self
                .state
                .write_cas(&path, current, Value::Int(n - 1))
                .await
            {
                Ok(()) => return Ok(false),
                Err(nexus_state::StateError::CasFailed { .. }) => continue,
                Err(e) => return Err(DriverError::Other(e.to_string())),
            }
        }
    }
}

#[async_trait]
impl Driver for BlobDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            // write: input carries the bytes (Bytes or Str); returns a BlobRef.
            // Each write takes one reference (§17.4 refcount).
            0 => {
                let bytes: Vec<u8> = match &input {
                    Value::Bytes(b) => b.clone(),
                    Value::Str(s) => s.as_bytes().to_vec(),
                    other => {
                        serde_json::to_vec(other).map_err(|e| DriverError::Other(e.to_string()))?
                    }
                };
                Ok(Outcome::Done(Value::Blob(
                    write_blob_bytes(&self.state, bytes, None).await?,
                )))
            }
            // read: input is a BlobRef (or {hash}); returns the bytes.
            1 => {
                let hash = blob_hash(&input)
                    .ok_or_else(|| DriverError::Other("read expects a blob ref".into()))?;
                let v = self
                    .state
                    .read(&Self::blob_path(&hash)?)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(v.unwrap_or(Value::Null)))
            }
            // delete: drop one reference (§17.4). The bytes are physically
            // removed only when the refcount reaches zero.
            2 => {
                if let Some(hash) = blob_hash(&input)
                    && self.decref(&hash).await?
                {
                    self.state
                        .write_delete(&Self::blob_path(&hash)?)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                Ok(Outcome::Done(Value::Null))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

/// Persist `bytes` under the standard blob content-addressed state path and
/// increment the durable per-hash refcount. This is the shared offload boundary
/// used by `effect://blob/write`, `effect://fs/read`, and `effect://fetch/get`
/// so every returned [`BlobRef`] is immediately resolvable by BlobDriver.
pub async fn write_blob_bytes(
    state: &Backend,
    bytes: Vec<u8>,
    mime: Option<String>,
) -> Result<BlobRef, DriverError> {
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let size = bytes.len() as u64;
    state
        .write_set(&BlobDriver::blob_path(&hash)?, Value::Bytes(bytes))
        .await
        .map_err(|e| DriverError::Other(e.to_string()))?;
    incref_hash(state, &hash).await?;
    Ok(BlobRef { hash, size, mime })
}

async fn incref_hash(state: &Backend, hash: &str) -> Result<(), DriverError> {
    let path = BlobDriver::refcount_path(hash)?;
    loop {
        let current = state
            .read(&path)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        let n = current.as_ref().and_then(Value::as_int).unwrap_or(0);
        let next = Value::Int(n.saturating_add(1));
        match state.write_cas(&path, current, next).await {
            Ok(()) => return Ok(()),
            Err(nexus_state::StateError::CasFailed { .. }) => continue,
            Err(e) => return Err(DriverError::Other(e.to_string())),
        }
    }
}

fn blob_hash(v: &Value) -> Option<String> {
    match v {
        Value::Blob(b) => Some(b.hash.clone()),
        Value::Str(s) => Some(s.clone()),
        Value::Map(m) => m.get("hash").and_then(|h| h.as_str()).map(str::to_string),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_state::InMemoryBackend;
    use nexus_types::{IdentityRef, ProcessId};
    use std::sync::Arc;

    #[tokio::test]
    async fn write_then_read_roundtrips_content() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let w = d
            .call(
                MethodId::new(0),
                Value::Str("hello".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        let blob = match w {
            Outcome::Done(Value::Blob(b)) => b,
            _ => panic!("expected blob ref"),
        };
        assert_eq!(blob.size, 5);
        let r = d
            .call(MethodId::new(1), Value::Blob(blob), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(r, Outcome::Done(Value::Bytes(b"hello".to_vec())));
    }

    #[tokio::test]
    async fn same_content_same_hash() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let h = |o: Outcome| match o {
            Outcome::Done(Value::Blob(b)) => b.hash,
            _ => panic!(),
        };
        let a = h(d
            .call(
                MethodId::new(0),
                Value::Str("x".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap());
        let b = h(d
            .call(
                MethodId::new(0),
                Value::Str("x".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap());
        assert_eq!(a, b, "content-addressed ⇒ deterministic hash");
    }

    #[tokio::test]
    async fn refcount_gates_physical_delete() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state.clone());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));

        // Write the same content twice ⇒ two references to one hash.
        let w = |o: Outcome| match o {
            Outcome::Done(Value::Blob(b)) => b,
            _ => panic!("expected blob ref"),
        };
        let blob = w(d
            .call(
                MethodId::new(0),
                Value::Str("dup".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap());
        let _ = w(d
            .call(
                MethodId::new(0),
                Value::Str("dup".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap());
        assert_eq!(
            state
                .read(&BlobDriver::refcount_path(&blob.hash).unwrap())
                .await
                .unwrap(),
            Some(Value::Int(2)),
            "two writes ⇒ 2 refs"
        );

        // First delete drops a ref to 1 — bytes must still be present.
        d.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            state
                .read(&BlobDriver::refcount_path(&blob.hash).unwrap())
                .await
                .unwrap(),
            Some(Value::Int(1)),
            "one ref remains"
        );
        let r = d
            .call(
                MethodId::new(1),
                Value::Blob(blob.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            r,
            Outcome::Done(Value::Bytes(b"dup".to_vec())),
            "still readable at refcount 1"
        );

        // Second delete drops to zero — bytes physically removed.
        d.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            state
                .read(&BlobDriver::refcount_path(&blob.hash).unwrap())
                .await
                .unwrap(),
            None,
            "refcount entry gone at zero"
        );
        let r = d
            .call(
                MethodId::new(1),
                Value::Blob(blob.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            r,
            Outcome::Done(Value::Null),
            "bytes gone after last ref dropped"
        );
    }

    #[tokio::test]
    async fn refcount_is_persisted_across_driver_instances() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d1 = BlobDriver::new(state.clone());
        let d2 = BlobDriver::new(state.clone());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));

        let blob = match d1
            .call(
                MethodId::new(0),
                Value::Str("shared".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap()
        {
            Outcome::Done(Value::Blob(b)) => b,
            other => panic!("expected blob ref, got {other:?}"),
        };
        d2.call(
            MethodId::new(0),
            Value::Str("shared".into()),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            state
                .read(&BlobDriver::refcount_path(&blob.hash).unwrap())
                .await
                .unwrap(),
            Some(Value::Int(2))
        );

        d1.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        let still_present = d2
            .call(
                MethodId::new(1),
                Value::Blob(blob.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            still_present,
            Outcome::Done(Value::Bytes(b"shared".to_vec()))
        );

        d2.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        let gone = d1
            .call(MethodId::new(1), Value::Blob(blob), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(gone, Outcome::Done(Value::Null));
    }

    #[tokio::test]
    async fn unregistered_unref_path_is_not_supported() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let err = d
            .call(
                MethodId::new(3),
                Value::Str("x".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap_err();
        assert_eq!(err, DriverError::NoSuchMethod(MethodId::new(3)));
    }
}
