//! Optional disk-backed map-key working storage for one value document.
//!
//! Each session owns a temporary directory and one Tokio task, not a dedicated
//! operating-system thread. The task serializes file operations and performs
//! cleanup after the last command sender closes. Dropping a session never
//! synchronously removes files. [`FileKeyStore::close`] awaits cleanup explicitly.
//!
//! This is unpublished, disposable working data. Runtime destruction or process
//! failure can interrupt cleanup and leave `value-keys-*` directories behind.
//! Hosts should use a dedicated workspace root and reclaim abandoned sessions
//! only after excluding live workers that may still own that root. Opening a new
//! session never deletes another session's directory.

use crate::{Request, storage};
use std::{
    cmp::Ordering,
    collections::HashMap,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use xolotl_state::{StateError, StateFailure, StateResult};
use xolotl_types::value::event::KeyId;
use xolotl_value_codec::validation::KeyStore;

/// Resident I/O and active-file budgets, independent of total key length.
#[derive(Clone, Copy, Debug)]
pub struct FileKeyOptions {
    /// Maximum owned request or response bytes in one I/O operation.
    /// Tokio's internal file buffer is separately capped at the same size.
    pub io_bytes: NonZeroUsize,
    /// Maximum simultaneously retained keys, including a key being released.
    /// Ordered-map validation can retain a previous key and a new key together.
    pub max_keys: NonZeroUsize,
}

impl Default for FileKeyOptions {
    fn default() -> Self {
        Self {
            io_bytes: NonZeroUsize::MIN.saturating_add(64 * 1024 - 1),
            max_keys: NonZeroUsize::MIN.saturating_add(63),
        }
    }
}

/// Exclusive, incremental file workspace for one validator's key identities.
///
/// Methods require Tokio and serialize through a bounded one-request queue.
/// Only lengths and identities stay resident between requests; file buffers
/// and owned byte windows do not accumulate with the number or length of keys.
/// Key identities must arrive in their validator's increasing allocation order.
///
/// Dropping any polled, unfinished operation closes the entire session. Its
/// worker retains in-progress I/O and cleanup ownership independently of that
/// caller. A closed session cannot resume an uncertain append or read cursor.
pub struct FileKeyStore {
    commands: Option<mpsc::Sender<Command>>,
    worker: Option<JoinHandle<StateResult<()>>>,
    directory: PathBuf,
    options: FileKeyOptions,
}

impl std::fmt::Debug for FileKeyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileKeyStore")
            .field("directory", &self.directory)
            .field("options", &self.options)
            .field("closed", &self.commands.is_none())
            .finish_non_exhaustive()
    }
}

impl FileKeyStore {
    /// Create an isolated temporary session inside `root` without preallocating keys.
    ///
    /// Initialization belongs to the cleanup worker from its first filesystem
    /// operation. Cancelling construction closes its queue; a directory created
    /// after cancellation is still reclaimed while that runtime remains alive.
    /// The root itself is host-owned and is not removed during session cleanup.
    pub async fn open(root: impl AsRef<Path>, options: FileKeyOptions) -> StateResult<Self> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            StateError::Backend(format!("value key workspace requires Tokio: {error}"))
        })?;
        let root = root.as_ref().to_owned();
        let (commands, requests) = mpsc::channel(1);
        let (ready, initialized) = oneshot::channel();
        let worker = runtime.spawn(run_worker(root, options, requests, ready));
        let mut store = Self {
            commands: Some(commands),
            worker: Some(worker),
            directory: PathBuf::new(),
            options,
        };
        store.directory = initialized.await.map_err(worker_closed)??;
        Ok(store)
    }

    /// Session directory, exposed for diagnostics and abandoned-workspace recovery.
    /// The caller must not modify it while the session or cleanup worker is live.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The budgets selected when this session was created.
    pub fn options(&self) -> FileKeyOptions {
        self.options
    }

    /// Close the command queue and wait for filesystem cleanup to complete.
    ///
    /// Cancelling this wait detaches the already-closing worker; it does not
    /// cancel that worker's I/O or cleanup. Runtime shutdown can still interrupt
    /// it, as described in the module's abandoned-workspace policy.
    pub async fn close(mut self) -> StateResult<()> {
        self.close_commands();
        match self.worker.take() {
            Some(worker) => worker.await.map_err(worker_closed)?,
            None => Ok(()),
        }
    }

    fn close_commands(&mut self) {
        drop(self.commands.take());
    }

    async fn request<T>(
        &mut self,
        command: impl FnOnce(oneshot::Sender<StateResult<T>>) -> Command,
    ) -> StateResult<T> {
        let commands = self
            .commands
            .as_ref()
            .ok_or_else(|| StateError::Backend("value key workspace is closed".into()))?;
        let (reply, result) = oneshot::channel();
        commands.send(command(reply)).await.map_err(worker_closed)?;
        result.await.map_err(worker_closed)?
    }

    async fn compare(&mut self, key: KeyId, offset: u64, bytes: &[u8]) -> StateResult<Ordering> {
        checked_end(offset, bytes.len())?;
        let mut offset = offset;
        let mut remaining = bytes;
        loop {
            let length = remaining.len().min(self.options.io_bytes.get());
            let chunk = self
                .request(|reply| Command::Read {
                    key,
                    offset,
                    length,
                    reply,
                })
                .await?;
            let size = chunk.bytes.len();
            let order = chunk.bytes.as_slice().cmp(&remaining[..size]);
            if order != Ordering::Equal {
                return Ok(order);
            }
            remaining = &remaining[size..];
            if remaining.is_empty() {
                return Ok(Ordering::Equal);
            }
            if chunk.end {
                return Ok(Ordering::Less);
            }
            offset = checked_end(offset, size)?;
        }
    }

    async fn append_bytes(&mut self, key: KeyId, offset: u64, bytes: &[u8]) -> StateResult<()> {
        checked_end(offset, bytes.len())?;
        let mut offset = offset;
        if bytes.is_empty() {
            return self
                .request(|reply| Command::Append {
                    key,
                    offset,
                    bytes: Vec::new(),
                    reply,
                })
                .await;
        }
        for part in bytes.chunks(self.options.io_bytes.get()) {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(part.len())
                .map_err(allocation_error)?;
            bytes.extend_from_slice(part);
            self.request(|reply| Command::Append {
                key,
                offset,
                bytes,
                reply,
            })
            .await?;
            offset = checked_end(offset, part.len())?;
        }
        Ok(())
    }
}

impl Drop for FileKeyStore {
    fn drop(&mut self) {
        self.close_commands();
    }
}

impl KeyStore for FileKeyStore {
    type Error = StateFailure;
    type Create<'a> = Request<'a, ()>;
    type ComparePrefix<'a> = Request<'a, Ordering>;
    type Append<'a> = Request<'a, ()>;
    type Release<'a> = Request<'a, ()>;

    fn create(&mut self, key: KeyId) -> Self::Create<'_> {
        Box::pin(async move {
            let operation = Operation::new(self);
            let result = operation
                .store
                .request(|reply| Command::Create { key, reply })
                .await;
            operation.finish(result)
        })
    }

    fn compare_prefix<'a>(
        &'a mut self,
        key: KeyId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a> {
        Box::pin(async move {
            let operation = Operation::new(self);
            let result = operation.store.compare(key, offset, bytes).await;
            operation.finish(result)
        })
    }

    fn append<'a>(&'a mut self, key: KeyId, offset: u64, bytes: &'a [u8]) -> Self::Append<'a> {
        Box::pin(async move {
            let operation = Operation::new(self);
            let result = operation.store.append_bytes(key, offset, bytes).await;
            operation.finish(result)
        })
    }

    fn release(&mut self, key: KeyId) -> Self::Release<'_> {
        Box::pin(async move {
            let operation = Operation::new(self);
            let result = operation
                .store
                .request(|reply| Command::Release { key, reply })
                .await;
            operation.finish(result)
        })
    }
}

struct Operation<'a> {
    store: &'a mut FileKeyStore,
    complete: bool,
}

impl<'a> Operation<'a> {
    fn new(store: &'a mut FileKeyStore) -> Self {
        Self {
            store,
            complete: false,
        }
    }

    fn finish<T>(mut self, result: StateResult<T>) -> StateResult<T> {
        self.complete = result.is_ok();
        result
    }
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.store.close_commands();
        }
    }
}

enum Command {
    Create {
        key: KeyId,
        reply: oneshot::Sender<StateResult<()>>,
    },
    Read {
        key: KeyId,
        offset: u64,
        length: usize,
        reply: oneshot::Sender<StateResult<KeyChunk>>,
    },
    Append {
        key: KeyId,
        offset: u64,
        bytes: Vec<u8>,
        reply: oneshot::Sender<StateResult<()>>,
    },
    Release {
        key: KeyId,
        reply: oneshot::Sender<StateResult<()>>,
    },
}

struct KeyChunk {
    bytes: Vec<u8>,
    end: bool,
}

struct Workspace {
    directory: PathBuf,
    keys: HashMap<KeyId, u64>,
    last_key: Option<u64>,
    options: FileKeyOptions,
}

impl Workspace {
    async fn create(&mut self, key: KeyId) -> StateResult<()> {
        if self.last_key.is_some_and(|last| key.get() <= last) {
            return Err(StateError::Backend(
                "value key identities must be fresh and increasing".into(),
            )
            .into());
        }
        if self.keys.len() >= self.options.max_keys.get() {
            return Err(StateError::Backend(
                "value key workspace active-key budget exceeded".into(),
            )
            .into());
        }
        self.keys.try_reserve(1).map_err(allocation_error)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.key_path(key))
            .await
            .map_err(storage::io_error)?;
        file.set_max_buf_size(self.options.io_bytes.get());
        drop(file);
        if self.keys.insert(key, 0).is_some() {
            return Err(StateError::Backend("duplicate value key identity".into()).into());
        }
        self.last_key = Some(key.get());
        Ok(())
    }

    async fn read(&mut self, key: KeyId, offset: u64, length: usize) -> StateResult<KeyChunk> {
        if length > self.options.io_bytes.get() {
            return Err(StateError::Backend("value key read exceeds its I/O window".into()).into());
        }
        let size = self.size(key)?;
        let available = size.checked_sub(offset).ok_or_else(|| {
            StateError::Backend("value key read offset exceeds its length".into())
        })?;
        let length = usize::try_from(available).unwrap_or(usize::MAX).min(length);
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(allocation_error)?;
        bytes.resize(length, 0);
        let mut file = File::open(self.key_path(key))
            .await
            .map_err(storage::io_error)?;
        file.set_max_buf_size(self.options.io_bytes.get());
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(storage::io_error)?;
        file.read_exact(&mut bytes)
            .await
            .map_err(storage::io_error)?;
        Ok(KeyChunk {
            bytes,
            end: checked_end(offset, length)? == size,
        })
    }

    async fn append(&mut self, key: KeyId, offset: u64, bytes: &[u8]) -> StateResult<()> {
        if bytes.len() > self.options.io_bytes.get() {
            return Err(
                StateError::Backend("value key append exceeds its I/O window".into()).into(),
            );
        }
        if self.size(key)? != offset {
            return Err(StateError::Backend("value key append is not contiguous".into()).into());
        }
        let end = checked_end(offset, bytes.len())?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(self.key_path(key))
            .await
            .map_err(storage::io_error)?;
        file.set_max_buf_size(self.options.io_bytes.get());
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(storage::io_error)?;
        file.write_all(bytes).await.map_err(storage::io_error)?;
        file.flush().await.map_err(storage::io_error)?;
        let size = self
            .keys
            .get_mut(&key)
            .ok_or_else(|| StateError::Backend("value key disappeared during append".into()))?;
        *size = end;
        Ok(())
    }

    async fn release(&mut self, key: KeyId) -> StateResult<()> {
        self.size(key)?;
        tokio::fs::remove_file(self.key_path(key))
            .await
            .map_err(storage::io_error)?;
        if self.keys.remove(&key).is_none() {
            return Err(StateError::Backend("value key disappeared during release".into()).into());
        }
        Ok(())
    }

    fn size(&self, key: KeyId) -> StateResult<u64> {
        self.keys
            .get(&key)
            .copied()
            .ok_or_else(|| StateError::Backend("unknown or released value key".into()).into())
    }

    fn key_path(&self, key: KeyId) -> PathBuf {
        self.directory.join(format!("key-{}", key.get()))
    }

    async fn cleanup(self) -> StateResult<()> {
        tokio::fs::remove_dir_all(&self.directory)
            .await
            .map_err(storage::io_error)
    }
}

async fn run_worker(
    root: PathBuf,
    options: FileKeyOptions,
    mut commands: mpsc::Receiver<Command>,
    ready: oneshot::Sender<StateResult<PathBuf>>,
) -> StateResult<()> {
    let directory = match create_directory(root).await {
        Ok(directory) => directory,
        Err(error) => {
            drop(ready.send(Err(error)));
            return Ok(());
        }
    };
    let mut workspace = Workspace {
        directory,
        keys: HashMap::new(),
        last_key: None,
        options,
    };
    if ready.send(Ok(workspace.directory.clone())).is_err() {
        return workspace.cleanup().await;
    }
    while let Some(command) = commands.recv().await {
        let keep_running = match command {
            Command::Create { key, reply } => respond(reply, workspace.create(key).await),
            Command::Read {
                key,
                offset,
                length,
                reply,
            } => respond(reply, workspace.read(key, offset, length).await),
            Command::Append {
                key,
                offset,
                bytes,
                reply,
            } => {
                let result = workspace.append(key, offset, &bytes).await;
                drop(bytes);
                respond(reply, result)
            }
            Command::Release { key, reply } => respond(reply, workspace.release(key).await),
        };
        if !keep_running {
            break;
        }
    }
    workspace.cleanup().await
}

fn respond<T>(reply: oneshot::Sender<StateResult<T>>, result: StateResult<T>) -> bool {
    let success = result.is_ok();
    reply.send(result).is_ok() && success
}

async fn create_directory(root: PathBuf) -> StateResult<PathBuf> {
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(storage::io_error)?;
    tokio::task::spawn_blocking(move || {
        let root = root.canonicalize().map_err(storage::io_error)?;
        tempfile::Builder::new()
            .prefix("value-keys-")
            .tempdir_in(root)
            .map(tempfile::TempDir::keep)
            .map_err(storage::io_error)
    })
    .await
    .map_err(worker_closed)?
}

fn checked_end(offset: u64, length: usize) -> StateResult<u64> {
    u64::try_from(length)
        .ok()
        .and_then(|length| offset.checked_add(length))
        .ok_or_else(|| StateError::Backend("value key byte offset overflow".into()).into())
}

fn worker_closed(error: impl std::fmt::Display) -> StateFailure {
    StateError::Backend(format!("value key workspace worker closed: {error}")).into()
}

fn allocation_error(error: impl std::fmt::Display) -> StateFailure {
    StateError::Backend(format!(
        "cannot allocate value key working storage: {error}"
    ))
    .into()
}

#[cfg(test)]
mod tests;
