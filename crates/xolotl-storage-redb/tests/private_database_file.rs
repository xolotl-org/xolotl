#![cfg(unix)]

use anyhow::ensure;
use std::os::unix::fs::{PermissionsExt, symlink};
use xolotl_storage_redb::RedbStore;

#[test]
fn database_creation_and_reopen_keep_private_permissions() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.redb");
    RedbStore::open(&path)?;
    let metadata = std::fs::metadata(&path)?;
    ensure!(metadata.permissions().mode() & 0o777 == 0o600);
    RedbStore::open(&path)?;
    Ok(())
}

#[test]
fn existing_public_file_and_symlink_are_rejected() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.redb");
    std::fs::write(&path, [])?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    ensure!(RedbStore::open(&path).is_err());

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let link = dir.path().join("link.redb");
    symlink(&path, &link)?;
    ensure!(RedbStore::open(&link).is_err());
    Ok(())
}
