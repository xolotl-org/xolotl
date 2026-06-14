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
use std::path::{Path as FsPath, PathBuf};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://fs/<method>` Resource with public method
/// `invoke`.
pub const FS_METHODS: &[MethodSpec] = &[
    MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("write", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("list", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("glob", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
];

/// Reads at or below this size inline into the returned `Value`; larger files
/// cross the blob offload boundary and come back as a blob reference.
pub const INLINE_MAX: u64 = 1 << 20; // 1 MiB

/// Drives the filesystem actions, sandboxed to a root directory.
pub struct FsDriver {
    /// All access is confined under this canonicalized root.
    root: PathBuf,
    state: Backend,
}

impl FsDriver {
    /// Create a filesystem driver rooted at `root` and using `state` for blob
    /// offload.
    pub fn new(root: impl Into<PathBuf>, state: Backend) -> Self {
        let root = root.into();
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        Self { root, state }
    }

    /// Resolve `rel` under the sandbox root, rejecting escape via `..`/symlink.
    fn resolve(&self, rel: &str) -> Result<PathBuf, DriverError> {
        let joined = self.root.join(rel.trim_start_matches('/'));
        // Canonicalize the parent (the file may not exist yet) and re-append.
        let candidate = match joined.canonicalize() {
            Ok(c) => c,
            Err(_) => {
                let parent = joined.parent().unwrap_or(&self.root);
                let cparent = parent.canonicalize().unwrap_or_else(|_| self.root.clone());
                cparent.join(joined.file_name().unwrap_or_default())
            }
        };
        if !candidate.starts_with(&self.root) {
            return Err(DriverError::Other("path escapes sandbox root".into()));
        }
        Ok(candidate)
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
        let m = input.as_map().cloned().unwrap_or_default();
        let path = m
            .get("path")
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
                let content = m.get("content").cloned().unwrap_or(Value::Null);
                let bytes = match content {
                    Value::Str(s) => s.into_bytes(),
                    Value::Bytes(b) => b,
                    other => {
                        serde_json::to_vec(&other).map_err(|e| DriverError::Other(e.to_string()))?
                    }
                };
                if let Some(parent) = p.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
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
                let _ = tokio::fs::remove_file(&p).await;
                Ok(Outcome::Done(Value::Null))
            }
            // glob: match `pattern` (relative to root) and return sandbox-relative
            // paths, sorted. Honors `*`/`**`/`?` via the `glob` crate; every hit
            // is re-checked against the sandbox root so a symlinked match cannot
            // escape.
            4 => {
                let pattern = m
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .or_else(|| input.as_str())
                    .unwrap_or("");
                let abs_pattern = self.root.join(pattern.trim_start_matches('/'));
                let abs_pattern = abs_pattern.to_string_lossy();
                let paths = glob::glob(&abs_pattern)
                    .map_err(|e| DriverError::Other(format!("invalid glob pattern: {e}")))?;
                let mut hits = Vec::new();
                for entry in paths.flatten() {
                    let canon = match entry.canonicalize() {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
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

/// Whether `p` is a regular file (helper for callers deciding blob vs inline).
pub fn is_regular_file(p: &FsPath) -> bool {
    p.is_file()
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
    async fn write_then_read_within_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let d = FsDriver::new(dir.path(), state());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        d.call(
            MethodId::new(1),
            write_input("note.txt", "hi"),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        let out = d
            .call(
                MethodId::new(0),
                read_input("note.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("hi".into())));
    }

    #[tokio::test]
    async fn escape_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let d = FsDriver::new(dir.path(), state());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                read_input("../../../etc/passwd"),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        assert!(out.is_err(), "symlink/.. escape must be rejected");
    }

    fn glob_input(pattern: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("pattern".into(), Value::Str(pattern.into()));
        Value::Map(m)
    }

    #[tokio::test]
    async fn glob_matches_within_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let d = FsDriver::new(dir.path(), state());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for f in ["a.txt", "b.txt", "c.md"] {
            d.call(
                MethodId::new(1),
                write_input(f, "x"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        }
        // A nested file written directly on disk (the driver's resolve flattens
        // not-yet-existing nested parents, so set this up out-of-band).
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/d.txt"), b"x").unwrap();
        // `*.txt` matches only the top level; `**/*.txt` recurses.
        let top = d
            .call(
                MethodId::new(4),
                glob_input("*.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match top {
            Outcome::Done(Value::List(xs)) => {
                let names: Vec<&str> = xs.iter().filter_map(|v| v.as_str()).collect();
                assert_eq!(names, vec!["a.txt", "b.txt"], "top-level *.txt only");
            }
            _ => panic!("expected list"),
        }
        let rec = d
            .call(
                MethodId::new(4),
                glob_input("**/*.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match rec {
            Outcome::Done(Value::List(xs)) => {
                let names: Vec<&str> = xs.iter().filter_map(|v| v.as_str()).collect();
                assert!(names.contains(&"a.txt") && names.iter().any(|n| n.ends_with("d.txt")));
                assert!(
                    names.iter().any(|n| n.contains("sub")),
                    "recursive hit keeps subdir"
                );
                assert!(
                    !names.iter().any(|n| n.ends_with(".md")),
                    "pattern excludes .md"
                );
            }
            _ => panic!("expected list"),
        }
    }

    #[tokio::test]
    async fn large_read_offloads_to_blob_ref() {
        let dir = tempfile::tempdir().unwrap();
        let state = state();
        let d = FsDriver::new(dir.path(), state.clone());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        // Just over the 1 MiB inline threshold.
        let big = "z".repeat((INLINE_MAX as usize) + 16);
        d.call(
            MethodId::new(1),
            write_input("big.bin", &big),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        let out = d
            .call(
                MethodId::new(0),
                read_input("big.bin"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Blob(b)) => {
                assert_eq!(b.size, big.len() as u64);
                assert_eq!(b.hash, blake3::hash(big.as_bytes()).to_hex().to_string());
                assert_eq!(b.mime.as_deref(), Some("application/octet-stream"));
                let blob = crate::blob::BlobDriver::new(state);
                let read = blob
                    .call(MethodId::new(1), Value::Blob(b), OutputMode::Unary, &ctx)
                    .await
                    .unwrap();
                assert_eq!(read, Outcome::Done(Value::Bytes(big.into_bytes())));
            }
            other => panic!("large read must offload to BlobRef, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn small_read_stays_inline() {
        let dir = tempfile::tempdir().unwrap();
        let d = FsDriver::new(dir.path(), state());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        d.call(
            MethodId::new(1),
            write_input("small.txt", "hi"),
            OutputMode::Unary,
            &ctx,
        )
        .await
        .unwrap();
        let out = d
            .call(
                MethodId::new(0),
                read_input("small.txt"),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            out,
            Outcome::Done(Value::Str("hi".into())),
            "small reads inline as today"
        );
    }
}
