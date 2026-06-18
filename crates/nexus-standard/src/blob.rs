//! Blob store: `effect://blob/write`, `effect://blob/read`,
//! `effect://blob/delete`.
//!
//! Large bytes are content-addressed (blake3) and held in the state backend
//! under `state://blob/<hash>`; the Operation returns only a [`BlobRef`] /
//! tensor reference so Facts never inline payloads. GC is retention +
//! refcount: each `write` increments a per-hash reference count and
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
pub(crate) const BLOB_METHODS: &[MethodSpec] = &[
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
pub(crate) struct BlobDriver {
    state: Backend,
}

impl BlobDriver {
    /// Create a blob driver backed by the state plane.
    pub(crate) fn new(state: Backend) -> Self {
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
            // Each write takes one reference.
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
            // delete: drop one reference. The bytes are physically
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
pub(crate) async fn write_blob_bytes(
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
    use anyhow::{Context, bail, ensure};
    use nexus_state::InMemoryBackend;
    use nexus_types::{IdentityRef, ProcessId};
    use std::sync::Arc;

    fn blob_from(outcome: Outcome) -> anyhow::Result<nexus_types::BlobRef> {
        match outcome {
            Outcome::Done(Value::Blob(blob)) => Ok(blob),
            other => bail!("expected blob ref, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_then_read_roundtrips_content() -> anyhow::Result<()> {
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
            .await?;
        let blob = blob_from(w)?;
        ensure!(blob.size == 5, "expected blob size 5, got {}", blob.size);
        let r = d
            .call(MethodId::new(1), Value::Blob(blob), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            r == Outcome::Done(Value::Bytes(b"hello".to_vec())),
            "unexpected blob read outcome: {r:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn same_content_same_hash() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let a = blob_from(
            d.call(
                MethodId::new(0),
                Value::Str("x".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await?,
        )?
        .hash;
        let b = blob_from(
            d.call(
                MethodId::new(0),
                Value::Str("x".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await?,
        )?
        .hash;
        ensure!(a == b, "content-addressed hash mismatch: {a} != {b}");
        Ok(())
    }

    #[tokio::test]
    async fn refcount_gates_physical_delete() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state.clone());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));

        let blob = blob_from(
            d.call(
                MethodId::new(0),
                Value::Str("dup".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await?,
        )?;
        let second = blob_from(
            d.call(
                MethodId::new(0),
                Value::Str("dup".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await?,
        )?;
        ensure!(
            second.hash == blob.hash,
            "duplicate content produced different hashes"
        );
        let refcount_path = BlobDriver::refcount_path(&blob.hash).context("build refcount path")?;
        let refs = state.read(&refcount_path).await?;
        ensure!(
            refs == Some(Value::Int(2)),
            "expected two refs, got {refs:?}"
        );

        d.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await?;
        let refs = state.read(&refcount_path).await?;
        ensure!(
            refs == Some(Value::Int(1)),
            "expected one ref, got {refs:?}"
        );
        let r = d
            .call(
                MethodId::new(1),
                Value::Blob(blob.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await?;
        ensure!(
            r == Outcome::Done(Value::Bytes(b"dup".to_vec())),
            "blob was not readable at refcount 1: {r:?}"
        );

        d.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await?;
        let refs = state.read(&refcount_path).await?;
        ensure!(refs.is_none(), "refcount entry remained at zero: {refs:?}");
        let r = d
            .call(
                MethodId::new(1),
                Value::Blob(blob.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await?;
        ensure!(
            r == Outcome::Done(Value::Null),
            "blob bytes remained after last ref dropped: {r:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn refcount_is_persisted_across_driver_instances() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d1 = BlobDriver::new(state.clone());
        let d2 = BlobDriver::new(state.clone());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));

        let blob = blob_from(
            d1.call(
                MethodId::new(0),
                Value::Str("shared".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await?,
        )?;
        d2.call(
            MethodId::new(0),
            Value::Str("shared".into()),
            OutputMode::Unary,
            &ctx,
        )
        .await?;
        let refcount_path = BlobDriver::refcount_path(&blob.hash).context("build refcount path")?;
        let refs = state.read(&refcount_path).await?;
        ensure!(
            refs == Some(Value::Int(2)),
            "expected two refs, got {refs:?}"
        );

        d1.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await?;
        let still_present = d2
            .call(
                MethodId::new(1),
                Value::Blob(blob.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await?;
        ensure!(
            still_present == Outcome::Done(Value::Bytes(b"shared".to_vec())),
            "shared blob disappeared early: {still_present:?}"
        );

        d2.call(
            MethodId::new(2),
            Value::Blob(blob.clone()),
            OutputMode::Unary,
            &ctx,
        )
        .await?;
        let gone = d1
            .call(MethodId::new(1), Value::Blob(blob), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            gone == Outcome::Done(Value::Null),
            "shared blob remained after final delete: {gone:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unregistered_unref_path_is_not_supported() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = BlobDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let err = match d
            .call(
                MethodId::new(3),
                Value::Str("x".into()),
                OutputMode::Unary,
                &ctx,
            )
            .await
        {
            Ok(outcome) => bail!("unregistered method returned {outcome:?}"),
            Err(err) => err,
        };
        ensure!(
            err == DriverError::NoSuchMethod(MethodId::new(3)),
            "unexpected unregistered method error: {err:?}"
        );
        Ok(())
    }
}
