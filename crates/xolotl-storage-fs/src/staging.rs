//! Reclaim abandoned upload and retired-object directories without deleting
//! staging owned by another live store using the same root.

use crate::storage;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::path::Path;
use xolotl_state::StateResult;

/// A shared, process-wide filesystem lease held for the whole store lifetime.
/// The kernel keeps the store alive while accepted I/O still uses staging.
pub(crate) struct StagingUse {
    _active: File,
}

impl StagingUse {
    pub(crate) fn acquire(root: &Path) -> StateResult<Self> {
        // Serializing openers closes the gap between exclusive reclamation and
        // taking the shared lifetime lease. It does not serialize normal I/O.
        let opening = lock_file(&root.join("staging-open.lock"))?;
        opening.lock().map_err(storage::io_error)?;
        let active = lock_file(&root.join("staging-active.lock"))?;
        match active.try_lock() {
            Ok(()) => {
                reclaim_abandoned(root)?;
                active.unlock().map_err(storage::io_error)?;
                active.lock_shared().map_err(storage::io_error)?;
            }
            Err(TryLockError::WouldBlock) => {
                // Another live instance, possibly in another process, owns
                // staging. Reclamation waits until a later cold open.
                active.lock_shared().map_err(storage::io_error)?;
            }
            Err(TryLockError::Error(error)) => return Err(storage::io_error(error)),
        }
        drop(opening);
        Ok(Self { _active: active })
    }
}

fn lock_file(path: &Path) -> StateResult<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(storage::io_error)
}

fn reclaim_abandoned(root: &Path) -> StateResult<()> {
    for entry in std::fs::read_dir(root.join("staging")).map_err(storage::io_error)? {
        let entry = entry.map_err(storage::io_error)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !(name.starts_with("upload-") || name.starts_with("retired-"))
            || !entry.file_type().map_err(storage::io_error)?.is_dir()
        {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(storage::io_error(error)),
        }
    }
    Ok(())
}
