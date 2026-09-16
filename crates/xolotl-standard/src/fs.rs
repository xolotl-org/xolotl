//! Filesystem provider: `effect://fs/read`, `effect://fs/write`,
//! `effect://fs/list`, `effect://fs/delete`, `effect://fs/glob`.
//!
//! Safety: paths are canonicalized to block symlink escape; reads and
//! `glob` are `Observation` (replayed from the recorded value), writes/deletes
//! are `NonIdempotentEffect`. Large unary reads use the configured object
//! writer: a `read` of a file larger than [`INLINE_MAX`] uploads the
//! bytes through the installed object port and returns a blob reference (hash +
//! size + mime); small files are returned inline.

use async_trait::async_trait;
use std::borrow::Cow;
use std::path::{Component, Path as FsPath, PathBuf};
use tokio::io::AsyncReadExt;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, DriverUsage, MethodSpec, UsageDimension,
};
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, TaintedValue, Value};
use xolotl_types::{ValueMap, ValueView};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://fs/<method>` Resource with public method
/// `invoke`.
pub(crate) const FS_METHODS: &[MethodSpec] = &[
    MethodSpec::new("read", Purity::Pure, MethodSpec::STREAM_ASYNC).observes_external(),
    MethodSpec::new("write", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("list", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("delete", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("glob", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
];

/// Reads at or below this size inline into the returned `Value`; larger files
/// use the object writer and come back as a blob reference.
pub(crate) const INLINE_MAX: u64 = 1 << 20; // 1 MiB

/// Drives the filesystem actions, sandboxed to a root directory.
pub(crate) struct FsDriver {
    /// All access is confined under this canonicalized root.
    root: PathBuf,
    objects: ObjectStore,
}

impl FsDriver {
    /// Create a filesystem driver rooted at `root` and using `objects` for blob
    /// offload.
    pub(crate) fn new(root: impl Into<PathBuf>, objects: ObjectStore) -> Result<Self, DriverError> {
        let root = root.into();
        let root = std::fs::canonicalize(&root)
            .map_err(|e| DriverError::Other(format!("fs root is unavailable: {e}")))?;
        Ok(Self { root, objects })
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
            .map_err(|_error| DriverError::Other("path escapes sandbox root".into()))?;
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
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match method.get() {
            // read
            0 => {
                let path = string_input_or_field(&input, "path", "fs.read")?;
                let p = self.resolve(path)?;
                let mut file = tokio::fs::File::open(&p)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                let mut buffer = crate::object::ObjectBuffer::new(
                    self.objects.clone(),
                    INLINE_MAX as usize,
                    mime_for(&p),
                    ctx.taint.clone(),
                );
                let mut chunk = [0_u8; crate::object::CHUNK_BYTES];
                let mut bytes_read = 0_u64;
                loop {
                    let count = match file.read(&mut chunk).await {
                        Ok(count) => count,
                        Err(error) => {
                            buffer.abort().await;
                            return buffer
                                .failure(DriverError::Other(error.to_string()))
                                .into_output("fs");
                        }
                    };
                    if count == 0 {
                        break;
                    }
                    bytes_read = bytes_read
                        .checked_add(count as u64)
                        .ok_or_else(|| DriverError::Other("file byte count exceeds u64".into()))?;
                    if output == OutputMode::Stream {
                        ctx.emit(Value::bytes(chunk[..count].to_vec())).await?;
                    } else {
                        if let Err(error) = buffer.push(&chunk[..count]).await {
                            return error.into_output("fs");
                        }
                    }
                }
                let value = if output == OutputMode::Stream {
                    TaintedValue::pristine(Value::null())
                } else {
                    match buffer.finish().await {
                        Ok((value, _)) => value,
                        Err(error) => return error.into_output("fs"),
                    }
                };
                Ok(DriverOutput::new(Outcome::Done(value.value))
                    .with_taint(value.taint)
                    .with_usage(DriverUsage::from([(
                        UsageDimension::BYTES_READ,
                        bytes_read,
                    )])))
            }
            // write
            1 => {
                let m = input_map(&input, "fs.write")?;
                let path = required_string_field(m, "path", "fs.write")?;
                let p = self.resolve(path)?;
                let content = required_field(m, "content", "fs.write")?;
                let bytes = match content.view() {
                    ValueView::Str(s) => Cow::Borrowed(s.as_bytes()),
                    ValueView::Bytes(b) => Cow::Borrowed(b),
                    _ => Cow::Owned(
                        serde_json::to_vec(content)
                            .map_err(|e| DriverError::Other(e.to_string()))?,
                    ),
                };
                if let Some(parent) = p.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                let usage =
                    DriverUsage::from([(UsageDimension::BYTES_WRITTEN, bytes.len() as u64)]);
                tokio::fs::write(&p, bytes)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(DriverOutput::new(Outcome::Done(Value::boolean(true))).with_usage(usage))
            }
            // list
            2 => {
                let path = string_input_or_field(&input, "path", "fs.list")?;
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
                    entries.push(Value::string(e.file_name().to_string_lossy().into_owned()));
                }
                entries.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                Ok(DriverOutput::new(Outcome::Done(Value::list(entries))))
            }
            // delete
            3 => {
                let path = string_input_or_field(&input, "path", "fs.delete")?;
                let p = self.resolve(path)?;
                match tokio::fs::remove_file(&p).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(DriverError::Other(error.to_string())),
                }
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            }
            // glob: match `pattern` (relative to root) and return sandbox-relative
            // paths, sorted. Honors `*`/`**`/`?` via the `glob` crate; every hit
            // is re-checked against the sandbox root so a symlinked match cannot
            // escape.
            4 => {
                let pattern = string_input_or_field(&input, "pattern", "fs.glob")?;
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
                        hits.push(Value::string(rel.to_string_lossy().into_owned()));
                    }
                }
                hits.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                hits.dedup();
                Ok(DriverOutput::new(Outcome::Done(Value::list(hits))))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn input_map<'a>(input: &'a Value, op: &'static str) -> Result<&'a ValueMap, DriverError> {
    match input.view() {
        ValueView::Map(m) => Ok(m),
        _ => Err(DriverError::InvalidInput(format!(
            "{op} input must be a map"
        ))),
    }
}

fn string_input_or_field<'a>(
    input: &'a Value,
    field: &'static str,
    op: &'static str,
) -> Result<&'a str, DriverError> {
    match input.view() {
        ValueView::Str(value) => Ok(value),
        ValueView::Map(m) => required_string_field(m, field, op),
        _ => Err(DriverError::InvalidInput(format!(
            "{op} input must be a map or string {field}"
        ))),
    }
}

fn required_string_field<'a>(
    m: &'a ValueMap,
    field: &'static str,
    op: &'static str,
) -> Result<&'a str, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Str(value)) => Ok(value),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be a string"
        ))),
        None => Err(DriverError::InvalidInput(format!(
            "{op} requires `{field}`"
        ))),
    }
}

fn required_field<'a>(
    m: &'a ValueMap,
    field: &'static str,
    op: &'static str,
) -> Result<&'a Value, DriverError> {
    m.get(field)
        .ok_or_else(|| DriverError::InvalidInput(format!("{op} requires `{field}`")))
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
    use std::collections::BTreeMap;
    use xolotl_types::{IdentityRef, ProcessId};

    fn write_input(path: &str, content: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("path".into(), Value::string(path.into()));
        m.insert("content".into(), Value::string(content.into()));
        Value::map(m)
    }

    fn read_input(path: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("path".into(), Value::string(path.into()));
        Value::map(m)
    }

    fn state() -> ObjectStore {
        ObjectStore::new()
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
            out.outcome == Outcome::Done(Value::string("hi".into())),
            "read output: {out:?}"
        );
        ensure!(out.usage == Some(DriverUsage::from([(UsageDimension::BYTES_READ, 2)])));
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

    #[tokio::test]
    async fn rejects_missing_or_malformed_paths() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let d = FsDriver::new(dir.path(), state()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));

        let out = d
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::new()),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "read accepted missing path");

        let mut bad_path = BTreeMap::new();
        bad_path.insert("path".into(), Value::integer(1));
        let out = d
            .call(
                MethodId::new(2),
                Value::map(bad_path),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "list accepted non-string path");

        let out = d
            .call(
                MethodId::new(4),
                Value::map(BTreeMap::new()),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "glob accepted missing pattern");
        Ok(())
    }

    #[tokio::test]
    async fn write_requires_content() -> Result<()> {
        let dir = tempfile::tempdir().context("create temp dir")?;
        let d = FsDriver::new(dir.path(), state()).context("create fs driver")?;
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut m = BTreeMap::new();
        m.insert("path".into(), Value::string("note.txt".into()));

        let out = d
            .call(MethodId::new(1), Value::map(m), OutputMode::Unary, &ctx)
            .await;
        ensure!(out.is_err(), "write accepted missing content");
        ensure!(
            !dir.path().join("note.txt").exists(),
            "write created a file without content"
        );
        Ok(())
    }

    fn glob_input(pattern: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("pattern".into(), Value::string(pattern.into()));
        Value::map(m)
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
        match top.outcome {
            Outcome::Done(xs_value) => {
                let xs = xs_value.as_list().context("expected list")?;
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
        match rec.outcome {
            Outcome::Done(xs_value) => {
                let xs = xs_value.as_list().context("expected list")?;
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
        let object_directory = tempfile::tempdir()?;
        let objects =
            xolotl_storage_fs::FileObjectStore::open(object_directory.path())?.into_object_store();
        let d = FsDriver::new(dir.path(), objects.clone()).context("create fs driver")?;
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
        match out.outcome {
            Outcome::Done(value) => {
                let ValueView::Blob(b) = value.view() else {
                    bail!("expected blob");
                };
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
                let mut chunk = [0_u8; crate::object::CHUNK_BYTES];
                let mut offset = 0_usize;
                loop {
                    let read = objects.read_chunk(b, offset as u64, &mut chunk).await?;
                    ensure!(
                        chunk[..read.bytes_read]
                            == big.as_bytes()[offset..offset + read.bytes_read]
                    );
                    offset += read.bytes_read;
                    if read.end {
                        break;
                    }
                }
                ensure!(offset == big.len());
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
            out.outcome == Outcome::Done(Value::string("hi".into())),
            "small read output: {out:?}"
        );
        Ok(())
    }
}
