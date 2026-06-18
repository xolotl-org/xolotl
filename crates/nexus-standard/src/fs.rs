//! Filesystem provider: `effect://fs/read`, `effect://fs/write`,
//! `effect://fs/list`, `effect://fs/delete`, `effect://fs/glob`.
//!
//! Safety: paths are canonicalized to block symlink escape; reads and
//! `glob` are `Observation` (replayed from the recorded value), writes/deletes
//! are `NonIdempotentEffect`. Large reads cross the `effect://blob/write`
//! offload boundary: a `read` of a file larger than [`INLINE_MAX`] persists the
//! bytes in the standard blob store and returns a blob reference (blake3 hash +
//! size + mime); small files are returned inline.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{MethodId, Outcome, OutputMode, Purity, Value};
use std::path::{Component, Path as FsPath, PathBuf};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://fs/<method>` Resource with public method
/// `invoke`.
pub(crate) const FS_METHODS: &[MethodSpec] = &[
    MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("write", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("list", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("glob", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
];

/// Reads at or below this size inline into the returned `Value`; larger files
/// cross the blob offload boundary and come back as a blob reference.
pub(crate) const INLINE_MAX: u64 = 1 << 20; // 1 MiB

/// Drives the filesystem actions, sandboxed to a root directory.
pub(crate) struct FsDriver {
    /// All access is confined under this canonicalized root.
    root: PathBuf,
    state: Backend,
}

impl FsDriver {
    /// Create a filesystem driver rooted at `root` and using `state` for blob
    /// offload.
    pub(crate) fn new(root: impl Into<PathBuf>, state: Backend) -> Result<Self, DriverError> {
        let root = root.into();
        let root = std::fs::canonicalize(&root)
            .map_err(|e| DriverError::Other(format!("fs root is unavailable: {e}")))?;
        Ok(Self { root, state })
    }

    /// Resolve `rel` under the sandbox root, rejecting escape via `..`/symlink.
    fn resolve(&self, rel: &str) -> Result<PathBuf, DriverError> {
        let mut candidate = self.root.clone();
        for component in FsPath::new(rel.trim_start_matches('/')).components() {
            match component {
                Component::Normal(part) => candidate.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(DriverError::Other("path escapes sandbox root".into()));
                }
            }
        }
        self.validate_existing_components(&candidate)?;
        Ok(candidate)
    }

    fn validate_existing_components(&self, candidate: &FsPath) -> Result<(), DriverError> {
        let relative = candidate
            .strip_prefix(&self.root)
            .map_err(|_| DriverError::Other("path escapes sandbox root".into()))?;
        let mut current = self.root.clone();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                continue;
            };
            current.push(part);
            if !current
                .try_exists()
                .map_err(|e| DriverError::Other(e.to_string()))?
            {
                continue;
            }
            let canonical = current
                .canonicalize()
                .map_err(|e| DriverError::Other(e.to_string()))?;
            if !canonical.starts_with(&self.root) {
                return Err(DriverError::Other("path escapes sandbox root".into()));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Driver for FsDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = match &input {
            Value::Null | Value::Str(_) => None,
            Value::Map(m) => Some(m),
            _ => {
                return Err(DriverError::InvalidInput(
                    "fs input must be a map, string path, or null".into(),
                ));
            }
        };
        let path = m
            .and_then(|m| m.get("path"))
            .and_then(|v| v.as_str())
            .or_else(|| input.as_str())
            .unwrap_or("");
        match method.get() {
            // read
            0 => {
                let p = self.resolve(path)?;
                // Stat first; a file larger than INLINE_MAX is
                // content-addressed with blake3 and returned as a BlobRef so
                // the Fact never inlines the payload. The same state-backed
                // blob store as `effect://blob/write` holds the bytes, so the
                // returned BlobRef is immediately readable.
                let meta = tokio::fs::metadata(&p)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                let bytes = tokio::fs::read(&p)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                if meta.len() > INLINE_MAX {
                    let mime = mime_for(&p);
                    return Ok(Outcome::Done(Value::Blob(
                        crate::blob::write_blob_bytes(&self.state, bytes, mime).await?,
                    )));
                }
                match String::from_utf8(bytes) {
                    Ok(s) => Ok(Outcome::Done(Value::Str(s))),
                    Err(e) => Ok(Outcome::Done(Value::Bytes(e.into_bytes()))),
                }
            }
            // write
            1 => {
                let p = self.resolve(path)?;
                let content = m.and_then(|m| m.get("content")).unwrap_or(&Value::Null);
                let bytes = match content {
                    Value::Str(s) => s.as_bytes().to_vec(),
                    Value::Bytes(b) => b.clone(),
                    other => {
                        serde_json::to_vec(&other).map_err(|e| DriverError::Other(e.to_string()))?
                    }
                };
                if let Some(parent) = p.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                tokio::fs::write(&p, bytes)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Bool(true)))
            }
            // list
            2 => {
                let p = self.resolve(path)?;
                let mut entries = Vec::new();
                let mut rd = tokio::fs::read_dir(&p)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                while let Some(e) = rd
                    .next_entry()
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?
                {
                    entries.push(Value::Str(e.file_name().to_string_lossy().into_owned()));
                }
                entries.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                Ok(Outcome::Done(Value::List(entries)))
            }
            // delete
            3 => {
                let p = self.resolve(path)?;
                match tokio::fs::remove_file(&p).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(DriverError::Other(error.to_string())),
                }
                Ok(Outcome::Done(Value::Null))
            }
            // glob: match `pattern` (relative to root) and return sandbox-relative
            // paths, sorted. Honors `*`/`**`/`?` via the `glob` crate; every hit
            // is re-checked against the sandbox root so a symlinked match cannot
            // escape.
            4 => {
                let pattern = m
                    .and_then(|m| m.get("pattern"))
                    .and_then(|v| v.as_str())
                    .or_else(|| input.as_str())
                    .unwrap_or("");
                let abs_pattern = self.root.join(pattern.trim_start_matches('/'));
                let abs_pattern = abs_pattern.to_string_lossy();
                let paths = glob::glob(&abs_pattern)
                    .map_err(|e| DriverError::Other(format!("invalid glob pattern: {e}")))?;
                let mut hits = Vec::new();
                for entry in paths {
                    let entry = entry.map_err(|e| DriverError::Other(e.to_string()))?;
                    let canon = entry
                        .canonicalize()
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                    if !canon.starts_with(&self.root) {
                        continue; // symlinked match escaping the sandbox
                    }
                    if let Ok(rel) = canon.strip_prefix(&self.root) {
                        hits.push(Value::Str(rel.to_string_lossy().into_owned()));
                    }
                }
                hits.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                hits.dedup();
                Ok(Outcome::Done(Value::List(hits)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

/// Best-effort MIME guess from the filename suffix, for the offload `BlobRef`'s
/// `mime` field. Deliberately tiny — no codec/sniffing, just the common cases a
/// driver hands to `effect://blob/write`.
fn mime_for(p: &FsPath) -> Option<String> {
    let ext = p.extension()?.to_str()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "md" | "log" => "text/plain",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "csv" => "text/csv",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "bin" | "" => "application/octet-stream",
        _ => return None,
    };
    Some(mime.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use nexus_state::{Backend, InMemoryBackend};
    use nexus_types::{IdentityRef, ProcessId};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn write_input(path: &str, content: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("path".into(), Value::Str(path.into()));
        m.insert("content".into(), Value::Str(content.into()));
        Value::Map(m)
    }

    fn read_input(path: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("path".into(), Value::Str(path.into()));
        Value::Map(m)
    }

    fn state() -> Backend {
        Arc::new(InMemoryBackend::new())
    }

    #[tokio::test]
    async fn write_then_read_within_sandbox() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let d = FsDriver::new(dir.path(), state()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        d.call(
            MethodId::new(1),
            write_input("note.txt", "hi"),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .context("write note")?;
        let out = d
            .call(
                MethodId::new(0),
                read_input("note.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("read note")?;
        ensure!(
            out == Outcome::Done(Value::Str("hi".into())),
            "read output: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn escape_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let d = FsDriver::new(dir.path(), state()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                read_input("../../../etc/passwd"),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "symlink/.. escape must be rejected");
        Ok(())
    }

    fn glob_input(pattern: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("pattern".into(), Value::Str(pattern.into()));
        Value::Map(m)
    }

    #[tokio::test]
    async fn glob_matches_within_sandbox() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let d = FsDriver::new(dir.path(), state()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for f in ["a.txt", "b.txt", "c.md"] {
            d.call(
                MethodId::new(1),
                write_input(f, "x"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .with_context(|| format!("write {f}"))?;
        }
        std::fs::create_dir_all(dir.path().join("sub")).context("create subdir")?;
        std::fs::write(dir.path().join("sub/d.txt"), b"x").context("write nested file")?;
        let top = d
            .call(
                MethodId::new(4),
                glob_input("*.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("glob top-level files")?;
        match top {
            Outcome::Done(Value::List(xs)) => {
                let names: Vec<&str> = xs.iter().filter_map(|v| v.as_str()).collect();
                ensure!(
                    names == vec!["a.txt", "b.txt"],
                    "top-level txt files: {names:?}"
                );
            }
            other => bail!("expected list, got {other:?}"),
        }
        let rec = d
            .call(
                MethodId::new(4),
                glob_input("**/*.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("glob recursive files")?;
        match rec {
            Outcome::Done(Value::List(xs)) => {
                let names: Vec<&str> = xs.iter().filter_map(|v| v.as_str()).collect();
                ensure!(
                    names.contains(&"a.txt") && names.iter().any(|n| n.ends_with("d.txt")),
                    "recursive glob missed txt files"
                );
                ensure!(
                    names.iter().any(|n| n.contains("sub")),
                    "recursive glob missed subdir path"
                );
                ensure!(
                    !names.iter().any(|n| n.ends_with(".md")),
                    "recursive glob included markdown file"
                );
            }
            other => bail!("expected list, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn large_read_offloads_to_blob_ref() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let state = state();
        let d = FsDriver::new(dir.path(), state.clone()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let big = "z".repeat((INLINE_MAX as usize) + 16);
        d.call(
            MethodId::new(1),
            write_input("big.bin", &big),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .context("write large file")?;
        let out = d
            .call(
                MethodId::new(0),
                read_input("big.bin"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("read large file")?;
        match out {
            Outcome::Done(Value::Blob(b)) => {
                ensure!(
                    b.size == big.len() as u64,
                    "large read blob size: {}",
                    b.size
                );
                ensure!(
                    b.hash == blake3::hash(big.as_bytes()).to_hex().to_string(),
                    "large read blob hash: {}",
                    b.hash
                );
                ensure!(
                    b.mime.as_deref() == Some("application/octet-stream"),
                    "large read blob mime: {:?}",
                    b.mime
                );
                let blob = crate::blob::BlobDriver::new(state);
                let read = blob
                    .call(MethodId::new(1), Value::Blob(b), OutputMode::Unary, &ctx)
                    .await
                    .context("read large blob")?;
                ensure!(
                    read == Outcome::Done(Value::Bytes(big.into_bytes())),
                    "large read blob payload: {read:?}"
                );
            }
            other => bail!("large read must offload to BlobRef, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn small_read_stays_inline() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let d = FsDriver::new(dir.path(), state()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        d.call(
            MethodId::new(1),
            write_input("small.txt", "hi"),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .context("write small file")?;
        let out = d
            .call(
                MethodId::new(0),
                read_input("small.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("read small file")?;
        ensure!(
            out == Outcome::Done(Value::Str("hi".into())),
            "small read output: {out:?}"
        );
        Ok(())
    }
}
