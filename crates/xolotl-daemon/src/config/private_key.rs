//! Private host key-file admission shared by credential stores and TLS listeners.

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
#[cfg(unix)]
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(unix)]
fn open_private_regular_file(path: &str, purpose: &str) -> Result<(std::fs::File, u64)> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    anyhow::ensure!(
        Path::new(path).is_absolute(),
        "{purpose} file path must be absolute"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {purpose} file '{path}'"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.mode() & 0o077 == 0,
        "{purpose} file must be a private regular file"
    );
    Ok((file, metadata.len()))
}

#[cfg(unix)]
pub(super) fn read_private_key_file(path: &str, purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    use std::io::Read;

    let (mut file, len) = open_private_regular_file(path, purpose)?;
    anyhow::ensure!(
        len == 32,
        "{purpose} key file must contain exactly 32 bytes"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *key)?;
    let mut extra = [0u8; 1];
    anyhow::ensure!(
        file.read(&mut extra)? == 0,
        "{purpose} key file changed while reading"
    );
    Ok(key)
}

/// Read a bounded TLS private key and erase the in-memory PEM on drop.
#[cfg(all(
    unix,
    any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    )
))]
pub(crate) fn read_private_pem_file(path: &str, purpose: &str) -> Result<Zeroizing<Vec<u8>>> {
    const MAX_PEM_BYTES: u64 = 64 * 1024;
    read_private_bounded_file(path, purpose, MAX_PEM_BYTES)
}

/// Read private binary signing material with a fixed bound and no symlink.
#[cfg(all(
    unix,
    any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    )
))]
pub(crate) fn read_private_bounded_file(
    path: &str,
    purpose: &str,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;

    let (file, len) = open_private_regular_file(path, purpose)?;
    anyhow::ensure!(
        len > 0 && len <= max_bytes,
        "{purpose} file must contain 1..={max_bytes} bytes"
    );
    let mut pem = Zeroizing::new(Vec::with_capacity(len as usize));
    file.take(max_bytes + 1).read_to_end(&mut pem)?;
    anyhow::ensure!(
        pem.len() as u64 == len,
        "{purpose} file changed while reading"
    );
    Ok(pem)
}

#[cfg(not(unix))]
pub(super) fn read_private_key_file(_path: &str, purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    anyhow::bail!("{purpose} key file loading is not implemented on this platform")
}

#[cfg(all(
    not(unix),
    any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    )
))]
pub(crate) fn read_private_pem_file(_path: &str, purpose: &str) -> Result<Zeroizing<Vec<u8>>> {
    anyhow::bail!("{purpose} PEM file loading is not implemented on this platform")
}

#[cfg(all(
    not(unix),
    any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    )
))]
pub(crate) fn read_private_bounded_file(
    _path: &str,
    purpose: &str,
    _max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    anyhow::bail!("{purpose} file loading is not implemented on this platform")
}
