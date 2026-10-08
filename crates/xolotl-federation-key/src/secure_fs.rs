//! Descriptor-relative private file I/O. No input component may be a symlink.
//! Output stays in a private staging directory until a no-replace rename.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};

use anyhow::{Context as _, Result, bail, ensure};
use rustix::{
    fs::{
        AtFlags, CWD, FileType, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, mkdirat, openat,
        renameat_with, unlinkat,
    },
    io::Errno,
    process::getuid,
};
use zeroize::Zeroizing;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const PRIVATE_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const PRIVATE_DIRECTORY_MODE: Mode = Mode::RWXU;
const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

fn walk_absolute_directory(path: &Path) -> Result<OwnedFd> {
    ensure!(path.is_absolute(), "directory path must be absolute");
    let mut directory = openat(CWD, "/", DIRECTORY_FLAGS, Mode::empty())?;
    check_ancestor(&directory)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, DIRECTORY_FLAGS, Mode::empty()).with_context(
                    || format!("open directory component '{}'", name.to_string_lossy()),
                )?;
                check_ancestor(&directory)?;
            }
            _ => bail!("directory path contains a nonliteral component"),
        }
    }
    Ok(directory)
}

fn check_ancestor(directory: &OwnedFd) -> Result<()> {
    let stat = fstat(directory)?;
    ensure!(FileType::from_raw_mode(stat.st_mode) == FileType::Directory);
    ensure!(
        stat.st_uid == 0 || stat.st_uid == getuid().as_raw(),
        "directory path has an untrusted owner"
    );
    ensure!(
        stat.st_mode & 0o022 == 0 || stat.st_mode & 0o1000 != 0,
        "directory path is writable by others without sticky protection"
    );
    Ok(())
}

fn split_output(path: &Path) -> Result<(OwnedFd, OsString)> {
    ensure!(path.is_absolute(), "output directory path must be absolute");
    let name = path
        .file_name()
        .context("output directory needs a final name")?;
    ensure!(name != OsStr::new(".") && name != OsStr::new(".."));
    let parent = path.parent().context("output directory has no parent")?;
    Ok((walk_absolute_directory(parent)?, name.to_os_string()))
}

pub(crate) fn open_private_directory(path: &Path) -> Result<OwnedFd> {
    let directory = walk_absolute_directory(path)?;
    let stat = fstat(&directory)?;
    ensure!(FileType::from_raw_mode(stat.st_mode) == FileType::Directory);
    ensure!(
        stat.st_uid == getuid().as_raw(),
        "private directory has another owner"
    );
    ensure!(
        stat.st_mode & 0o777 == 0o700,
        "private directory must have mode 0700"
    );
    Ok(directory)
}

pub(crate) fn read_private_file(
    directory: &OwnedFd,
    name: &str,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let descriptor = openat(directory, name, PRIVATE_FILE_FLAGS, Mode::empty())
        .with_context(|| format!("open private file {name}"))?;
    let stat = fstat(&descriptor)?;
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
        "{name} is not a regular file"
    );
    ensure!(stat.st_uid == getuid().as_raw(), "{name} has another owner");
    ensure!(stat.st_mode & 0o777 == 0o600, "{name} must have mode 0600");
    ensure!(stat.st_nlink == 1, "{name} must not be hard-linked");
    ensure!(
        stat.st_size > 0 && u64::try_from(stat.st_size)? <= max_bytes,
        "{name} has invalid size"
    );
    let length = usize::try_from(stat.st_size)?;
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    let mut file = File::from(descriptor);
    file.read_exact(&mut bytes)?;
    let mut extra = [0u8; 1];
    ensure!(file.read(&mut extra)? == 0, "{name} changed while reading");
    Ok(bytes)
}

fn write_private_file(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(!name.is_empty() && name != "." && name != ".." && !name.contains('/'));
    let descriptor = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        PRIVATE_FILE_MODE,
    )?;
    fchmod(&descriptor, PRIVATE_FILE_MODE)?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_staging_directory(parent: &OwnedFd) -> Result<(OwnedFd, String)> {
    for _ in 0..8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("random staging name: {error}"))?;
        let name = format!(
            ".xolotl-federation-key-{}",
            data_encoding::HEXLOWER.encode(&random)
        );
        match mkdirat(parent, &name, PRIVATE_DIRECTORY_MODE) {
            Ok(()) => {
                let directory = match openat(parent, &name, DIRECTORY_FLAGS, Mode::empty()) {
                    Ok(directory) => directory,
                    Err(error) => {
                        unlinkat(parent, &name, AtFlags::REMOVEDIR)
                            .context("remove unopened staging directory")?;
                        return Err(error.into());
                    }
                };
                return Ok((directory, name));
            }
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a new staging directory")
}

fn remove_staging_directory(
    parent: &OwnedFd,
    directory: &OwnedFd,
    name: &str,
    files: &[(&str, &[u8])],
) -> Result<()> {
    for (file, _) in files {
        match unlinkat(directory, *file, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => return Err(error).with_context(|| format!("remove staging file {file}")),
        }
    }
    fsync(directory).context("sync removed staging files")?;
    unlinkat(parent, name, AtFlags::REMOVEDIR).context("remove staging directory")?;
    fsync(parent).context("sync removed staging directory")?;
    Ok(())
}

/// Publish an entirely new directory. A failed write or no-replace rename
/// removes the staging directory; a failed final parent fsync reports an
/// indeterminate durability outcome while leaving the already published data.
pub(crate) fn publish_new_directory(path: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    ensure!(!files.is_empty());
    let (parent, final_name) = split_output(path)?;
    let (staging, staging_name) = create_staging_directory(&parent)?;
    let mut renamed = false;
    let result = (|| {
        fchmod(&staging, PRIVATE_DIRECTORY_MODE)?;
        for (name, bytes) in files {
            write_private_file(&staging, name, bytes)
                .with_context(|| format!("write private file {name}"))?;
        }
        fsync(&staging)?;
        renameat_with(
            &parent,
            &staging_name,
            &parent,
            &final_name,
            RenameFlags::NOREPLACE,
        )
        .context("publish new directory without replacing an existing path")?;
        renamed = true;
        fsync(&parent).context("published directory exists, but parent durability is unproven")?;
        Ok(())
    })();
    if !renamed
        && let Err(cleanup) = remove_staging_directory(&parent, &staging, &staging_name, files)
    {
        return Err(anyhow::anyhow!(
            "{result:?}; staging cleanup also failed: {cleanup}"
        ));
    }
    result
}
